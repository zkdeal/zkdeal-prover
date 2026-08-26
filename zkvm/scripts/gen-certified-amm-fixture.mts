/** Generate the certified v4 AMM execution fixture used by the Rust STF test.
 *
 * This deploys the actual Foundry-built RoomERC20/ConstantProductAMM bytecode
 * into @ethereumjs/vm, runs two non-empty blocks (3 successful state-changing
 * transactions each), and records complete slot-keyed pre/post state.
 */

import { readFile, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildGenesis,
  encodeCallHex,
  padAddress,
  padUint256,
  signL2Tx,
  type Hex,
} from '../../../app-node/packages/l2-engine/src/index.js'
import {
  bytesToHex0x,
  claimMerkleRootV4,
  computeExitProgramIdV4,
  computePresetHashV4,
  hashAssetTotalsV4,
  hashExitTotalsV4,
  hashFeeTotalsV4,
  hexToBytes,
  keccak256,
  roomChainIdV4,
} from '../../../app-node/packages/protocol/src/index.js'
import {
  ETH,
  ammCreation,
  pad32,
  rawTxCommitment,
  tokenCreation,
} from './lib/amm-fixture-encoding.mjs'
import { U } from './lib/ethereumjs-util.mjs'
import {
  compactStateV4,
  exitProgramStorage,
  fixtureState,
  type ExitProgramStorageV4,
} from './lib/amm-fixture-witness.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..', '..')
const blockCount = Number(process.env.AMM_BLOCK_COUNT ?? '2')
if (blockCount !== 1 && blockCount !== 2) {
  throw new Error('AMM_BLOCK_COUNT must be 1 (terminal-close profile) or 2 (certified gate fixture)')
}
const output = process.env.AMM_FIXTURE_OUTPUT
  ? resolve(process.env.AMM_FIXTURE_OUTPUT)
  : join(root, 'zkvm', 'fixtures', 'amm-certified-v4.json')
const presetCatalogPath = process.env.ZKDEAL_PRESET_CATALOG_PATH
  ? resolve(process.env.ZKDEAL_PRESET_CATALOG_PATH)
  : join(root, 'contracts', 'presets', 'v4', 'presets.generated.json')
const roomId = 404n
const deploymentDomain = `0x${'a1'.repeat(32)}` as Hex
const chainId = roomChainIdV4(deploymentDomain, roomId)
const AMM_GAS_LIMIT = 16_777_216
const priv0 = `0x${'00'.repeat(31)}01` as Hex
const priv1 = `0x${'00'.repeat(31)}02` as Hex
const member0 = U.createAddressFromPrivateKey(hexToBytes(priv0)).toString().toLowerCase() as Hex
const member1 = U.createAddressFromPrivateKey(hexToBytes(priv1)).toString().toLowerCase() as Hex

interface FoundryArtifact {
  abi: unknown[]
  bytecode: { object: Hex }
}

async function artifact(source: string, contract: string): Promise<FoundryArtifact> {
  return JSON.parse(
    await readFile(join(root, 'contracts', 'out', `${source}.sol`, `${contract}.json`), 'utf8'),
  ) as FoundryArtifact
}

const tokenArtifact = await artifact('RoomERC20', 'RoomERC20')
const ammArtifact = await artifact('ConstantProductAMM', 'ConstantProductAMM')

// buildGenesis exports deterministic CREATE addresses through the package;
// avoid duplicating CREATE address derivation in this evidence generator.
const engineModule = await import('../../../app-node/packages/l2-engine/src/index.js')
const token0Address = engineModule.predictGenesisAddress(0n)
const token1Address = engineModule.predictGenesisAddress(1n)
const ammAddress = engineModule.predictGenesisAddress(2n)

const genesisInput = {
  roomId,
  deploymentDomain,
  protocolVersion: 4,
  members: [
    // The flagship has two L1-backed ERC-20s and free room gas. Synthetic ETH
    // would make the derived asset-0 exit total diverge from L1 escrow.
    { address: member0, depositWei: 0n },
    { address: member1, depositWei: 0n },
  ],
  deployments: [
    {
      name: 'AssetA',
      bytecodeHex: tokenCreation(tokenArtifact.bytecode.object, 'Asset A', 'ASA', member0),
      abiJson: tokenArtifact.abi,
    },
    {
      name: 'AssetB',
      bytecodeHex: tokenCreation(tokenArtifact.bytecode.object, 'Asset B', 'ASB', member0),
      abiJson: tokenArtifact.abi,
    },
    {
      name: 'ConstantProductAMM',
      bytecodeHex: ammCreation(ammArtifact.bytecode.object, token0Address, token1Address),
      abiJson: ammArtifact.abi,
    },
  ],
  attributionHints: [],
}
const built = await buildGenesis(genesisInput)
const engine = built.engine
if (
  built.manifest.contracts[0]?.address !== token0Address ||
  built.manifest.contracts[1]?.address !== token1Address ||
  built.manifest.contracts[2]?.address !== ammAddress
) {
  throw new Error('deterministic certified AMM deployment addresses drifted')
}

const approve = (spender: Hex, amount: bigint) =>
  encodeCallHex('approve(address,uint256)', padAddress(spender), padUint256(amount))
const transfer = (to: Hex, amount: bigint) =>
  encodeCallHex('transfer(address,uint256)', padAddress(to), padUint256(amount))
const addLiquidity = (amount0: bigint, amount1: bigint, receiver: Hex, deadline: bigint) =>
  encodeCallHex(
    'addLiquidity(uint256,uint256,uint256,address,uint256)',
    padUint256(amount0),
    padUint256(amount1),
    padUint256(1n),
    padAddress(receiver),
    padUint256(deadline),
  )
const swap = (tokenIn: Hex, amount: bigint, receiver: Hex, deadline: bigint) =>
  encodeCallHex(
    'swapExactInput(address,uint256,uint256,address,uint256)',
    padAddress(tokenIn),
    padUint256(amount),
    padUint256(1n),
    padAddress(receiver),
    padUint256(deadline),
  )

async function submit(
  key: Hex,
  nonce: bigint,
  to: Hex,
  dataHex: Hex,
  type: 0 | 1 | 2,
) {
  await engine.submitTx(
    signL2Tx({
      privKey: key,
      nonce,
      to,
      valueWei: 0n,
      dataHex,
      roomId,
      common: engine.common,
      type,
      gasLimit: 2_000_000n,
    }),
  )
}

const blocks: unknown[] = []
const pre1 = fixtureState(await engine.captureWitnessStateJson())
const pre1Root = await engine.getStateRootHex()
await submit(priv0, 0n, token0Address, approve(ammAddress, 500_000n * ETH), 0)
await submit(priv0, 1n, token1Address, approve(ammAddress, 500_000n * ETH), 1)
await submit(priv0, 2n, ammAddress, addLiquidity(100_000n * ETH, 100_000n * ETH, member0, 2_000n), 2)
const block1 = await engine.buildNextBlock(1_000n)
const header1 = (engine as unknown as { parentBlock: { header: { gasUsed: bigint } } }).parentBlock.header
const post1 = fixtureState(await engine.captureWitnessStateJson())
blocks.push({
  blockNumber: 1,
  env: {
    number: 1,
    timestamp: 1_000,
    gasLimit: AMM_GAS_LIMIT,
    coinbase: `0x${'00'.repeat(20)}`,
    baseFee: '0x0',
    prevRandao: `0x${'00'.repeat(32)}`,
    difficulty: '0x0',
    excessBlobGas: '0x0',
  },
  preState: pre1,
  postState: post1,
  rawTxs: block1.rawTxs,
  prevStateRoot: pre1Root,
  expectedPostRoot: block1.stateRoot,
  expectedGasUsed: Number(header1.gasUsed),
  expectedTxCommitment: rawTxCommitment(block1.rawTxs),
})

if (blockCount === 2) {
  const pre2Root = await engine.getStateRootHex()
  await submit(priv0, 3n, token0Address, transfer(member1, 10_000n * ETH), 0)
  await submit(priv1, 0n, token0Address, approve(ammAddress, 10_000n * ETH), 1)
  await submit(priv1, 1n, ammAddress, swap(token0Address, 1_000n * ETH, member1, 3_000n), 2)
  const block2 = await engine.buildNextBlock(2_000n)
  const header2 = (engine as unknown as { parentBlock: { header: { gasUsed: bigint } } }).parentBlock.header
  const post2 = fixtureState(await engine.captureWitnessStateJson())
  blocks.push({
    blockNumber: 2,
    env: {
      number: 2,
      timestamp: 2_000,
      gasLimit: AMM_GAS_LIMIT,
      coinbase: `0x${'00'.repeat(20)}`,
      baseFee: '0x0',
      prevRandao: `0x${'00'.repeat(32)}`,
      difficulty: '0x0',
      excessBlobGas: '0x0',
    },
    preState: post1,
    postState: post2,
    rawTxs: block2.rawTxs,
    prevStateRoot: pre2Root,
    expectedPostRoot: block2.stateRoot,
    expectedGasUsed: Number(header2.gasUsed),
    expectedTxCommitment: rawTxCommitment(block2.rawTxs),
  })
}

if (blockCount === 2) {
  const balanceResult = await engine.call(
    token1Address,
    encodeCallHex('balanceOf(address)', padAddress(member1)),
    member1,
  )
  if (balanceResult.length !== 32 || BigInt(bytesToHex0x(balanceResult)) === 0n) {
    throw new Error('certified AMM swap did not successfully credit AssetB to member 1')
  }
}

const initialContracts = (pre1 as Array<{ address: string; code?: Hex }>).filter((a) => a.code)
const generated = JSON.parse(
  await readFile(presetCatalogPath, 'utf8'),
) as {
  generatedFrom: { proofProgramId: Hex }
  presets: { 'amm-v4': { presetHash: Hex; policy: Record<string, unknown> } }
}
// The vault and card witnesses record the guest they were certified against;
// these two did not, so regenerating them during a trust-root update could not
// detect a witness/image mismatch and a reviewer could not tell which guest
// they belong to. Take the same value from the same catalog, and refuse to
// publish under a program ID that disagrees with the build that asked for it.
const proofProgramId = generated.generatedFrom?.proofProgramId?.toLowerCase() as Hex | undefined
if (!proofProgramId || !/^0x[0-9a-f]{64}$/.test(proofProgramId)) {
  throw new Error(`${presetCatalogPath} carries no generatedFrom.proofProgramId`)
}
const requestedProgramId = process.env.ZKDEAL_PROOF_PROGRAM_ID?.toLowerCase()
if (requestedProgramId && requestedProgramId !== proofProgramId) {
  throw new Error(
    `ZKDEAL_PROOF_PROGRAM_ID ${requestedProgramId} does not match the preset catalog's ${proofProgramId}; regenerate the catalog first`,
  )
}
type GeneratedAmm = {
  presetHash: Hex
  policy: Record<string, unknown> & { exitProgramId: Hex; code: Array<{ address: string; name: string; runtimeCodeHash: Hex }> }
  exitProgram: {
    assets: Array<Record<string, unknown>>
    positions: Array<Record<string, unknown>>
    version: 4
  }
}
const generatedAmm = generated.presets['amm-v4'] as unknown as GeneratedAmm
const policy = structuredClone(generatedAmm.policy)
const exitProgram = structuredClone(generatedAmm.exitProgram)
if (computeExitProgramIdV4(exitProgram).toLowerCase() !== policy.exitProgramId.toLowerCase()) {
  throw new Error('generated AMM exit program does not match policy.exitProgramId')
}
for (const pin of policy.code) {
  const account = initialContracts.find((candidate) => candidate.address === pin.address)
  if (!account?.code) throw new Error(`pinned contract ${pin.address} missing from AMM prestate`)
  const runtimeCodeHash = bytesToHex0x(keccak256(hexToBytes(account.code))) as Hex
  if (runtimeCodeHash !== pin.runtimeCodeHash) {
    throw new Error(
      `generated AMM catalog runtime hash drift for ${pin.name}: ${runtimeCodeHash} != ${pin.runtimeCodeHash}`,
    )
  }
}

async function callUint(to: Hex, signature: string, account?: Hex): Promise<bigint> {
  const calldata = account === undefined
    ? encodeCallHex(signature)
    : encodeCallHex(signature, padAddress(account))
  const result = await engine.call(to, calldata, member0)
  if (result.length !== 32) throw new Error(`${signature} returned ${result.length} bytes`)
  return BigInt(bytesToHex0x(result))
}

const excludedLpAccount = `0x${'00'.repeat(19)}01` as Hex
const lpSupply = await callUint(ammAddress, 'totalSupply()')
const lpShares = [
  await callUint(ammAddress, 'balanceOf(address)', member0),
  await callUint(ammAddress, 'balanceOf(address)', member1),
]
const excludedLpShares = await callUint(ammAddress, 'balanceOf(address)', excludedLpAccount)
if (lpShares[0]! + lpShares[1]! + excludedLpShares !== lpSupply) {
  throw new Error('AMM LP supply is not fully attributed to members plus the pinned burn account')
}

const assetTotals = [
  { assetId: 0, total: 0n },
  { assetId: 1, total: 200_000n * ETH },
  { assetId: 2, total: 200_000n * ETH },
]
const exitAllocations: Array<{
  slot: number
  assetId: number
  recipient: Hex
  amount: bigint
}> = []
const residualAllocations: Array<{
  position: number
  assetId: number
  recipientSlot: number
}> = []

for (const [assetId, token] of [[1, token0Address], [2, token1Address]] as const) {
  const direct = [
    await callUint(token, 'balanceOf(address)', member0),
    await callUint(token, 'balanceOf(address)', member1),
  ]
  const backing = await callUint(token, 'balanceOf(address)', ammAddress)
  const memberBacking = lpShares.map((shares) => backing * shares / lpSupply)
  const residual = backing - memberBacking[0]! - memberBacking[1]!
  if (residual > 0n) {
    // This is an explicit, member-approved allocation. It includes both
    // integer division dust and the backing represented by MINIMUM_LIQUIDITY.
    residualAllocations.push({ position: 0, assetId, recipientSlot: 0 })
    memberBacking[0] = memberBacking[0]! + residual
  }
  const amounts = [direct[0]! + memberBacking[0]!, direct[1]! + memberBacking[1]!]
  if (amounts[0]! + amounts[1]! !== assetTotals[assetId]!.total) {
    throw new Error(`asset ${assetId} generated exits are not exactly conserved`)
  }
  for (const [slot, amount] of amounts.entries()) {
    if (amount > 0n) {
      exitAllocations.push({
        slot,
        assetId,
        recipient: slot === 0 ? member0 : member1,
        amount,
      })
    }
  }
}

exitAllocations.sort((a, b) => a.slot - b.slot || a.assetId - b.assetId)
const accounting = assetTotals.map((asset) => ({
  assetId: asset.assetId,
  total: asset.total,
  exitTotal: asset.total,
  feeTotal: 0n,
}))
const settlement = {
  deploymentDomain,
  assetTotals: assetTotals.map((asset) => ({ assetId: asset.assetId, total: asset.total.toString() })),
  residualAllocations,
  exitAllocations: exitAllocations.map((allocation) => ({
    ...allocation,
    amount: allocation.amount.toString(),
  })),
  accounting: accounting.map((asset) => ({
    assetId: asset.assetId,
    total: asset.total.toString(),
    exitTotal: asset.exitTotal.toString(),
    feeTotal: asset.feeTotal.toString(),
  })),
  assetTotalsHash: hashAssetTotalsV4(accounting),
  exitTotalsHash: hashExitTotalsV4(accounting),
  feeTotalsHash: hashFeeTotalsV4(accounting),
  exitRoot: claimMerkleRootV4(exitAllocations.map((allocation) => ({
    deploymentDomain,
    roomId,
    ...allocation,
  }))),
}

const witnessGenesis = await buildGenesis(genesisInput)
if (witnessGenesis.genesisRoot.toLowerCase() !== built.genesisRoot.toLowerCase()) {
  throw new Error('deterministic AMM witness genesis changed the state root')
}
const compactState = await compactStateV4(
  witnessGenesis.engine,
  built.engine,
  [member0, member1],
  exitProgramStorage(exitProgram as ExitProgramStorageV4, [member0, member1]),
)
for (const member of [member0, member1]) {
  const leaf = compactState.accounts.find((account) => account.address === member)
  if (!leaf || leaf.exists) {
    throw new Error(`zero-funded active member ${member} must be an explicit absent compact-state leaf`)
  }
}

const fixture = {
  scenario: blockCount === 1 ? 'amm-terminal-close-v4' : 'amm-certified-v4',
  proofProgramId,
  roomId: roomId.toString(),
  chainId: Number(chainId),
  hardfork: 'osaka',
  members: [member0, member1],
  contracts: { token0: token0Address, token1: token1Address, amm: ammAddress },
  presetHash: computePresetHashV4(policy as never),
  preset: policy,
  exitProgram,
  settlement,
  compactState,
  blocks,
}
await writeFile(output, `${JSON.stringify(fixture, null, 2)}\n`)
console.log(`wrote ${output}`)
