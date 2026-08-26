/**
 * STF parity fixture generator (Spike S1).
 *
 * For each scenario in contracts/scenarios.json (generic=0, erc4626=1, dvp=2)
 * this script builds a real room genesis with @zkdeal/l2-engine, drives a
 * short deal (deposits / transfers / vault / dvp ops, incl. one reverting tx
 * and one empty block), and emits zkvm/fixtures/<scenario>.json with, per
 * block:
 *
 *   - the COMPLETE pre-state (every account incl. seeded Cancun precompiles
 *     at 1 wei and the genesis deployer), with storage keyed by SLOT PREIMAGE
 *     (captured by instrumenting MerkleStateManager.putStorage - the engine's
 *     own dumpState only knows hashed trie keys),
 *   - the exact block env the engine sealed (read back from the built header),
 *   - the raw signed txs, prev/post MPT state roots,
 *   - expectedTxCommitment = RAW keccak256(RLP([keccak256(rawTx)...])) -
 *     32 bytes. The protocol's header value is this reduced mod the BN254
 *     field (see packages/protocol/src/chain.ts txCommitment); the decimal
 *     field value is emitted alongside as txCommitmentField and the reduction
 *     is asserted here.
 *
 * Every captured pre/post state is self-verified: it is re-loaded into a
 * fresh MerkleStateManager and the recomputed root must equal the engine's
 * root, proving the dump is complete (nothing outside the address book /
 * recorded slots exists in the trie).
 *
 * Run from repo root:  pnpm exec tsx scripts/gen-stf-fixtures.ts
 */

import { mkdir, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'

import {
  buildGenesis,
  encodeCallHex,
  padAddress,
  padUint256,
  signL2Tx,
  type GenesisPlan,
  type Hex,
} from '../packages/l2-engine/src/index.js'
import type { Engine } from '../packages/l2-engine/src/index.js'
import {
  FIELD,
  GENESIS_DEPLOYER_PRIVKEY,
  bytesToBigint,
  bytesToHex0x,
  hexToBytes,
  keccak256,
  concatBytes,
} from '../packages/protocol/src/index.js'
import { resolveScenarioFromDisk } from '../server/src/genesis-builder.js'

const here = dirname(fileURLToPath(import.meta.url))
const folderRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const umbrellaRoot = resolve(folderRoot, '..')
const OUT_DIR = join(folderRoot, 'zkvm', 'fixtures')

/* ------------------------------------------------------------------ */
/* @ethereumjs/util + statemanager access via the l2-engine package    */
/* (they are not hoisted to the repo root node_modules)                */
/* ------------------------------------------------------------------ */

const engineRequire = createRequire(join(umbrellaRoot, 'app-node', 'packages', 'l2-engine', 'package.json'))
async function importFromEngine(spec: string): Promise<any> {
  const p = engineRequire.resolve(spec)
  const mod: any = await import(pathToFileURL(p).href)
  return mod.default && typeof mod.default === 'object' && Object.keys(mod).length <= 2
    ? mod.default
    : mod
}
const U: any = await importFromEngine('@ethereumjs/util')

/* ------------------------------------------------------------------ */
/* Storage slot preimage capture                                       */
/* ------------------------------------------------------------------ */

/** sm instance -> (addressLower -> Set<slotHex 0x + 64 nibbles>) */
const slotRecords = new WeakMap<object, Map<string, Set<string>>>()
let patched = false

function patchPutStorage(smClass: any): void {
  if (patched) return
  patched = true
  const orig = smClass.prototype.putStorage
  smClass.prototype.putStorage = async function (address: any, key: Uint8Array, value: Uint8Array) {
    let rec = slotRecords.get(this)
    if (!rec) {
      rec = new Map()
      slotRecords.set(this, rec)
    }
    const a = address.toString().toLowerCase()
    let set = rec.get(a)
    if (!set) {
      set = new Set()
      rec.set(a, set)
    }
    set.add(bytesToHex0x(key))
    return orig.call(this, address, key, value)
  }
}

/* ------------------------------------------------------------------ */
/* State capture + self-verification                                   */
/* ------------------------------------------------------------------ */

interface FixtureAccount {
  address: string
  nonce: string
  balance: string
  code?: string
  storage: Record<string, string>
}

function pad32Hex(bytes: Uint8Array): string {
  const out = new Uint8Array(32)
  out.set(bytes, 32 - bytes.length)
  return bytesToHex0x(out)
}

async function captureState(engine: Engine): Promise<FixtureAccount[]> {
  const sm: any = engine.stateManager
  await sm.flush()
  const rec = slotRecords.get(sm) ?? new Map<string, Set<string>>()
  const accounts: FixtureAccount[] = []
  for (const addrHex of engine.addressBook.list()) {
    const addr = U.createAddressFromString(addrHex)
    const account = await sm.getAccount(addr)
    if (!account) continue
    const storage: Record<string, string> = {}
    const slots = [...(rec.get(addrHex) ?? [])].sort()
    for (const slotHex of slots) {
      const value: Uint8Array = await sm.getStorage(addr, hexToBytes(slotHex))
      if (value.length > 0) storage[slotHex] = pad32Hex(value)
    }
    const entry: FixtureAccount = {
      address: addrHex,
      nonce: '0x' + account.nonce.toString(16),
      balance: '0x' + account.balance.toString(16),
      storage,
    }
    if (account.isContract()) {
      const code: Uint8Array = await sm.getCode(addr)
      if (code.length > 0) entry.code = bytesToHex0x(code)
    }
    accounts.push(entry)
  }
  return accounts
}

/** Rebuild an MPT from the captured accounts and assert the root matches. */
async function verifyCapture(
  engine: Engine,
  accounts: FixtureAccount[],
  expectedRoot: string,
  label: string,
): Promise<void> {
  const SmClass: any = (engine.stateManager as any).constructor
  const fresh = new SmClass({ common: engine.common })
  for (const acct of accounts) {
    const addr = U.createAddressFromString(acct.address)
    await fresh.putAccount(
      addr,
      U.createAccount({ nonce: BigInt(acct.nonce), balance: BigInt(acct.balance) }),
    )
    if (acct.code) await fresh.putCode(addr, hexToBytes(acct.code))
    for (const [slot, value] of Object.entries(acct.storage)) {
      await fresh.putStorage(addr, hexToBytes(slot), U.unpadBytes(hexToBytes(value)))
    }
  }
  await fresh.flush()
  const root = bytesToHex0x(await fresh.getStateRoot())
  if (root !== expectedRoot.toLowerCase()) {
    throw new Error(
      `${label}: captured state is INCOMPLETE or wrong - rebuilt root ${root} != engine root ${expectedRoot}`,
    )
  }
}

/* ------------------------------------------------------------------ */
/* Raw tx commitment (unreduced keccak)                                 */
/* ------------------------------------------------------------------ */

/** RLP([h0, h1, ...]) for 32-byte items, hand-rolled (list of 0xa0||hash). */
function rlpHashList(hashes: Uint8Array[]): Uint8Array {
  const payload = concatBytes(...hashes.map((h) => concatBytes(new Uint8Array([0xa0]), h)))
  if (payload.length <= 55) {
    return concatBytes(new Uint8Array([0xc0 + payload.length]), payload)
  }
  const lenBytes: number[] = []
  let n = payload.length
  while (n > 0) {
    lenBytes.unshift(n & 0xff)
    n >>= 8
  }
  return concatBytes(new Uint8Array([0xf7 + lenBytes.length, ...lenBytes]), payload)
}

function rawTxCommitment(rawTxs: string[]): Uint8Array {
  const hashes = rawTxs.map((raw) => keccak256(hexToBytes(raw)))
  return keccak256(rlpHashList(hashes))
}

/* ------------------------------------------------------------------ */
/* Calldata helpers (mirrors packages/l2-engine test helpers)           */
/* ------------------------------------------------------------------ */

const dataDeposit = () => encodeCallHex('deposit()')
const dataApprove = (spender: Hex, amount: bigint) =>
  encodeCallHex('approve(address,uint256)', padAddress(spender), padUint256(amount))
const dataTransfer = (to: Hex, amount: bigint) =>
  encodeCallHex('transfer(address,uint256)', padAddress(to), padUint256(amount))
const dataVaultDeposit = (assets: bigint, receiver: Hex) =>
  encodeCallHex('deposit(uint256,address)', padUint256(assets), padAddress(receiver))
const dataAccrueYield = (assets: bigint) => encodeCallHex('accrueYield(uint256)', padUint256(assets))
const dataRedeem = (shares: bigint, receiver: Hex, owner: Hex) =>
  encodeCallHex('redeem(uint256,address,address)', padUint256(shares), padAddress(receiver), padAddress(owner))
const dataWithdraw = (wad: bigint) => encodeCallHex('withdraw(uint256)', padUint256(wad))
const dataProposeTrade = (
  counterparty: Hex,
  tokenGive: Hex,
  amtGive: bigint,
  tokenGet: Hex,
  amtGet: bigint,
) =>
  encodeCallHex(
    'proposeTrade(address,address,uint256,address,uint256)',
    padAddress(counterparty),
    padAddress(tokenGive),
    padUint256(amtGive),
    padAddress(tokenGet),
    padUint256(amtGet),
  )
const dataAffirm = (tradeId: bigint) => encodeCallHex('affirm(uint256)', padUint256(tradeId))

/* ------------------------------------------------------------------ */
/* Scenario deal scripts                                                */
/* ------------------------------------------------------------------ */

const ETH = 10n ** 18n

function priv(n: number): Hex {
  const b = new Uint8Array(32)
  b[31] = n
  return bytesToHex0x(b) as Hex
}
function addrOf(privHex: Hex): Hex {
  return U.createAddressFromPrivateKey(hexToBytes(privHex)).toString().toLowerCase() as Hex
}

interface TxSpec {
  privKey: Hex
  to: Hex | null
  valueWei: bigint
  dataHex?: Hex
  type?: 0 | 1 | 2
  accessList?: { address: string; storageKeys: string[] }[]
}

interface BlockSpec {
  timestamp: bigint
  txs: TxSpec[]
  note?: string
}

interface ScenarioRun {
  key: string
  id: string
  roomId: bigint
  deploymentDomain: Hex
  blocks: (contract: Record<string, Hex>) => BlockSpec[]
}

const m1 = priv(1)
const m2 = priv(2)
const A1 = addrOf(m1)
const A2 = addrOf(m2)
const DEPLOYER = GENESIS_DEPLOYER_PRIVKEY as Hex

/** balanceOf[m2] slot in WNative (mapping at slot 0) for the 2930 access list. */
function wnativeBalanceSlot(owner: Hex): string {
  return bytesToHex0x(keccak256(concatBytes(padAddress(owner), padUint256(0n))))
}

const scenarios: ScenarioRun[] = [
  {
    key: '0',
    id: 'generic',
    roomId: 101n,
    deploymentDomain: `0x${'11'.repeat(32)}` as Hex,
    blocks: (c) => [
      {
        timestamp: 1001n,
        note: 'plain native value transfer, EIP-1559 tx',
        txs: [{ privKey: m1, to: A2, valueWei: ETH / 2n, type: 2 }],
      },
      {
        timestamp: 1002n,
        note: 'WNative wrap + DealToken transfer from genesis deployer (nonce continues after CREATEs)',
        txs: [
          { privKey: m1, to: c.WNative!, valueWei: ETH, dataHex: dataDeposit() },
          { privKey: DEPLOYER, to: c.DealToken!, valueWei: 0n, dataHex: dataTransfer(A1, 50n * ETH) },
        ],
      },
      {
        timestamp: 1003n,
        note: 'ERC20 transfer + native send to receive() fallback via EIP-2930 tx with access list',
        txs: [
          { privKey: m1, to: c.WNative!, valueWei: 0n, dataHex: dataTransfer(A2, ETH / 4n) },
          {
            privKey: m2,
            to: c.WNative!,
            valueWei: (3n * ETH) / 4n,
            type: 1,
            accessList: [{ address: c.WNative!, storageKeys: [wnativeBalanceSlot(A2)] }],
          },
        ],
      },
      {
        timestamp: 1004n,
        note: 'contract-to-EOA native transfer + REVERTING tx (nonce bump only)',
        txs: [
          { privKey: m1, to: c.WNative!, valueWei: 0n, dataHex: dataWithdraw(ETH / 4n) },
          { privKey: m2, to: c.WNative!, valueWei: 0n, dataHex: dataWithdraw(10n * ETH) },
        ],
      },
      { timestamp: 1005n, note: 'empty force-seal block', txs: [] },
    ],
  },
  {
    key: '1',
    id: 'erc4626',
    roomId: 102n,
    deploymentDomain: `0x${'12'.repeat(32)}` as Hex,
    blocks: (c) => [
      { timestamp: 2001n, txs: [{ privKey: m1, to: c.WNative!, valueWei: 2n * ETH, dataHex: dataDeposit() }] },
      {
        timestamp: 2002n,
        txs: [
          { privKey: m1, to: c.WNative!, valueWei: 0n, dataHex: dataApprove(c.VaultDemo!, ETH) },
          { privKey: m1, to: c.VaultDemo!, valueWei: 0n, dataHex: dataVaultDeposit(ETH, A1) },
        ],
      },
      {
        timestamp: 2003n,
        note: 'demo yield injection (3 txs - full 30M block by gasLimit budget)',
        txs: [
          { privKey: m2, to: c.WNative!, valueWei: ETH, dataHex: dataDeposit() },
          { privKey: m2, to: c.WNative!, valueWei: 0n, dataHex: dataApprove(c.VaultDemo!, ETH) },
          { privKey: m2, to: c.VaultDemo!, valueWei: 0n, dataHex: dataAccrueYield(ETH) },
        ],
      },
      {
        timestamp: 2004n,
        txs: [{ privKey: m1, to: c.VaultDemo!, valueWei: 0n, dataHex: dataRedeem(ETH / 2n, A1, A1) }],
      },
      { timestamp: 2005n, note: 'empty force-seal block', txs: [] },
    ],
  },
  {
    key: '2',
    id: 'dvp',
    roomId: 103n,
    deploymentDomain: `0x${'13'.repeat(32)}` as Hex,
    blocks: (c) => [
      {
        timestamp: 3001n,
        txs: [
          { privKey: DEPLOYER, to: c.DealToken!, valueWei: 0n, dataHex: dataTransfer(A2, 100n * ETH) },
          { privKey: m1, to: c.WNative!, valueWei: ETH, dataHex: dataDeposit() },
        ],
      },
      {
        timestamp: 3002n,
        txs: [
          { privKey: m1, to: c.WNative!, valueWei: 0n, dataHex: dataApprove(c.DvPSettlement!, ETH) },
          { privKey: m2, to: c.DealToken!, valueWei: 0n, dataHex: dataApprove(c.DvPSettlement!, 100n * ETH) },
        ],
      },
      {
        timestamp: 3003n,
        txs: [
          {
            privKey: m1,
            to: c.DvPSettlement!,
            valueWei: 0n,
            dataHex: dataProposeTrade(A2, c.WNative!, ETH, c.DealToken!, 100n * ETH),
          },
        ],
      },
      { timestamp: 3004n, txs: [{ privKey: m2, to: c.DvPSettlement!, valueWei: 0n, dataHex: dataAffirm(1n) }] },
      { timestamp: 3005n, note: 'empty force-seal block', txs: [] },
    ],
  },
]

/* ------------------------------------------------------------------ */
/* Main                                                                 */
/* ------------------------------------------------------------------ */

async function runScenario(run: ScenarioRun): Promise<void> {
  const resolved = resolveScenarioFromDisk(
    {
      scenariosPath: join(umbrellaRoot, 'web3-protocol', 'contracts', 'scenarios.json'),
      contractsOut: join(umbrellaRoot, 'web3-protocol', 'contracts', 'out'),
      contractsRoot: join(umbrellaRoot, 'web3-protocol', 'contracts'),
      forgeBin: 'forge',
    },
    run.key,
  )

  const plan: GenesisPlan = {
    roomId: run.roomId,
    protocolVersion: 4,
    deploymentDomain: run.deploymentDomain,
    members: [
      { address: A1, depositWei: 10n * ETH },
      { address: A2, depositWei: 5n * ETH },
    ],
    deployments: resolved.deployments,
    attributionHints: resolved.attributionHints,
  }
  const { engine, manifest, genesisRoot } = await buildGenesis(plan)

  const contractsByName: Record<string, Hex> = {}
  for (const contract of manifest.contracts) contractsByName[contract.name] = contract.address as Hex

  // per-sender nonce tracking (deployer continues after genesis CREATEs)
  const nonces = new Map<string, bigint>()
  nonces.set(addrOf(DEPLOYER), BigInt(resolved.deployments.length))
  const nextNonce = (privKey: Hex): bigint => {
    const a = addrOf(privKey)
    const n = nonces.get(a) ?? 0n
    nonces.set(a, n + 1n)
    return n
  }

  let preState = await captureState(engine)
  await verifyCapture(engine, preState, genesisRoot, `${run.id} genesis`)
  let prevRoot = genesisRoot

  const blocks: unknown[] = []
  for (const spec of run.blocks(contractsByName)) {
    for (const tx of spec.txs) {
      const raw = signL2Tx({
        privKey: tx.privKey,
        nonce: nextNonce(tx.privKey),
        to: tx.to,
        valueWei: tx.valueWei,
        dataHex: tx.dataHex,
        roomId: run.roomId,
        common: engine.common,
        type: tx.type ?? 0,
        accessList: tx.accessList as never,
      })
      await engine.submitTx(raw)
    }
    const payload = await engine.buildNextBlock(spec.timestamp)

    const header = (engine as any).parentBlock.header
    const env = {
      number: Number(header.number),
      timestamp: Number(header.timestamp),
      gasLimit: Number(header.gasLimit),
      gasUsed: Number(header.gasUsed),
      coinbase: header.coinbase.toString().toLowerCase(),
      baseFee: '0x' + header.baseFeePerGas.toString(16),
      prevRandao: bytesToHex0x(header.mixHash),
      difficulty: '0x' + header.difficulty.toString(16),
      excessBlobGas: '0x' + (header.excessBlobGas ?? 0n).toString(16),
      blobGasUsed: '0x' + (header.blobGasUsed ?? 0n).toString(16),
      parentBeaconBlockRoot: bytesToHex0x(header.parentBeaconBlockRoot ?? new Uint8Array(32)),
    }

    const postState = await captureState(engine)
    await verifyCapture(engine, postState, payload.stateRoot, `${run.id} block ${payload.blockNumber}`)

    const rawCommitment = rawTxCommitment(payload.rawTxs)
    const reduced = bytesToBigint(rawCommitment) % FIELD
    if (reduced !== payload.txCommitment) {
      throw new Error(
        `${run.id} block ${payload.blockNumber}: raw keccak commitment mod FIELD != engine txCommitment`,
      )
    }

    blocks.push({
      blockNumber: Number(payload.blockNumber),
      note: spec.note,
      env,
      preState,
      rawTxs: payload.rawTxs,
      prevStateRoot: prevRoot,
      expectedPostRoot: payload.stateRoot,
      expectedGasUsed: Number(header.gasUsed),
      expectedTxCommitment: bytesToHex0x(rawCommitment),
      txCommitmentField: payload.txCommitment.toString(10),
      postState,
    })

    preState = postState
    prevRoot = payload.stateRoot
  }

  const fixture = {
    scenario: resolved.scenario.id,
    scenarioKey: run.key,
    roomId: run.roomId.toString(10),
    chainId: Number(engine.common.chainId()),
    hardfork: 'cancun',
    genesisRoot,
    members: [
      { address: A1, depositWei: (10n * ETH).toString(10) },
      { address: A2, depositWei: (5n * ETH).toString(10) },
    ],
    contracts: manifest.contracts.map((c) => ({ name: c.name, address: c.address })),
    note:
      'expectedTxCommitment is the RAW keccak256(RLP([keccak256(rawTx)...])) (32 bytes). ' +
      'The protocol header field txCommitmentField = BigInt(expectedTxCommitment) mod BN254 FIELD.',
    blocks,
  }

  await mkdir(OUT_DIR, { recursive: true })
  const outPath = join(OUT_DIR, `${resolved.scenario.id}.json`)
  await writeFile(outPath, JSON.stringify(fixture, null, 2) + '\n')
  console.log(
    `[stf-fixtures] wrote ${outPath} (${blocks.length} blocks, genesisRoot ${genesisRoot.slice(0, 10)}…)`,
  )
}

async function main(): Promise<void> {
  // Probe build to obtain the MerkleStateManager class, then instrument
  // putStorage so all later geneses record storage slot preimages. The probe
  // is thrown away, but assertValidGenesisPlan rejects an empty member list,
  // so it needs one dummy member to get far enough to expose the class.
  const probe = await buildGenesis({
    roomId: 999_999n,
    members: [{ address: A1, depositWei: ETH }],
    deployments: [],
    attributionHints: [],
  })
  patchPutStorage((probe.engine.stateManager as any).constructor)

  for (const run of scenarios) {
    await runScenario(run)
  }
  console.log('[stf-fixtures] all scenarios done')
}

await main()
