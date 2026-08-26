/**
 * Build production RISC Zero v4 cold/composed requests for the certified AMM.
 *
 * This is deliberately not a hash-only composition spike. It executes the
 * actual RoomERC20/ConstantProductAMM creation bytecode (including constructor
 * arguments), freezes the discovered runtime bundle, and links that reusable
 * cold statement to the exact supplied BatchWitnessV4.
 *
 * Stage 1 (this file) emits a human-auditable JSON spec. Stage 2 is the small
 * Rust encoder in stf-wire, which Borsh-encodes and CPU-validates both the cold
 * constructor transcript and the composed two-block batch before producing
 * host request JSON.
 */

import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  buildGenesis,
  createL2Common,
  prepareRoomV4,
  predictGenesisAddress,
  type Hex,
} from '../../../app-node/packages/l2-engine/src/index.js'
import {
  GENESIS_DEPLOYER_PRIVKEY,
  bytesToHex0x,
  concatBytes,
  hashCompiledBundleV4,
  hexToBytes,
  keccak256,
  utf8ToBytes,
} from '../../../app-node/packages/protocol/src/index.js'
import { createProverJobV4 } from '../../../app-node/packages/zkvm/src/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..', '..')
const defaultJob = join(
  root,
  'test-results',
  'v4-gpu-direct',
  'v4-opt-20260721-0931-amm-p21',
  'amm-succinct',
  'amm-succinct.json.job.json',
)
const defaultOutput = join(
  root,
  'experiments',
  'h100-2gpu-20260721-attempt3',
  'requests',
  'amm-cold-composed-v4.spec.json',
)
const expectedJobSha256 = (
  process.env.AMM_EXPECTED_JOB_SHA256
  ?? '5ac97c2e883157cc6e9792208da2dc35738ea8521c8adcf7318b13cecff583f5'
).toLowerCase()
const jobPath = resolve(process.env.AMM_JOB_PATH ?? defaultJob)
const outputPath = resolve(process.env.AMM_COLD_SPEC_OUTPUT ?? defaultOutput)

const engineRequire = createRequire(join(root, 'packages', 'l2-engine', 'package.json'))
const txPath = engineRequire.resolve('@ethereumjs/tx')
const utilPath = engineRequire.resolve('@ethereumjs/util')
const TX: typeof import('@ethereumjs/tx') = await import(pathToFileURL(txPath).href)
const U: typeof import('@ethereumjs/util') = await import(pathToFileURL(utilPath).href)

interface FoundryArtifact {
  abi: unknown[]
  bytecode: { object: Hex }
  metadata?: string
}

interface JobEnvelope {
  fixtureSha256?: string
  job: {
    v: number
    jobId: Hex
    inputDigest: Hex
    backendId: string
    proofMode: string
    programId: Hex
    presetHash: Hex
    witness: BatchWitness
  }
}

interface CompactAccount {
  address: Hex
  exists: boolean
  nonce: string | number
  balance: Hex
  code: Hex
  storage: Array<{ slot: Hex; value: Hex; proof?: Hex[] }>
}

interface BatchWitness {
  v: number
  deploymentDomain: Hex
  roomId: string | number
  presetHash: Hex
  manifestHash: Hex
  proofProgramId: Hex
  preStateRoot: Hex
  preset: Record<string, unknown>
  preRosterSlots: Array<{ slot: number; state: string | number; account: Hex }>
  compactState: { accounts: CompactAccount[] }
  blocks: Array<{ rawTxs: Hex[] }>
  [key: string]: unknown
}

type DumpAccount = {
  nonce: string
  balance: string
  code?: Hex
  storage: Record<string, Hex>
}

async function artifact(source: string, contract: string): Promise<FoundryArtifact> {
  return JSON.parse(
    await readFile(join(root, 'contracts', 'out', `${source}.sol`, `${contract}.json`), 'utf8'),
  ) as FoundryArtifact
}

function word(value: bigint): string {
  return value.toString(16).padStart(64, '0')
}

function addressWord(address: Hex): string {
  return address.slice(2).padStart(64, '0')
}

function stringTail(value: string): string {
  const bytes = new TextEncoder().encode(value)
  const data = Buffer.from(bytes).toString('hex').padEnd(Math.ceil(bytes.length / 32) * 64, '0')
  return `${word(BigInt(bytes.length))}${data}`
}

function tokenCreation(base: Hex, name: string, symbol: string, holder: Hex): Hex {
  const nameTail = stringTail(name)
  const symbolTail = stringTail(symbol)
  const headBytes = 4n * 32n
  const symbolOffset = headBytes + BigInt(nameTail.length / 2)
  const args = `${word(headBytes)}${word(symbolOffset)}${word(200_000n * 10n ** 18n)}${addressWord(holder)}${nameTail}${symbolTail}`
  return `${base}${args}` as Hex
}

function ammCreation(base: Hex, token0: Hex, token1: Hex): Hex {
  return `${base}${addressWord(token0)}${addressWord(token1)}` as Hex
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value)
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number in analyzer material')
    return JSON.stringify(value)
  }
  if (typeof value === 'bigint') return JSON.stringify(value.toString())
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'object') {
    const object = value as Record<string, unknown>
    return `{${Object.keys(object).sort().map((key) => {
      if (object[key] === undefined) throw new Error(`undefined analyzer field ${key}`)
      return `${JSON.stringify(key)}:${canonicalJson(object[key])}`
    }).join(',')}}`
  }
  throw new Error(`unsupported analyzer material: ${typeof value}`)
}

function contentHash(domain: string, value: unknown): Hex {
  return bytesToHex0x(keccak256(concatBytes(
    utf8ToBytes(domain),
    utf8ToBytes(canonicalJson(value)),
  ))) as Hex
}

function normalizeDump(raw: string) {
  const dump = JSON.parse(raw) as Record<string, DumpAccount>
  return Object.entries(dump)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([address, account]) => ({
      address: address.toLowerCase(),
      nonce: account.nonce,
      balance: account.balance,
      code: account.code ?? '0x',
      storage: Object.entries(account.storage)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([slot, value]) => ({ slot, value })),
    }))
}

function assertEqual(actual: string, expected: string, label: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`${label}: ${actual} != ${expected}`)
  }
}

const sourceBytes = await readFile(jobPath)
const sourceSha256 = createHash('sha256').update(sourceBytes).digest('hex')
if (sourceSha256 !== expectedJobSha256) {
  throw new Error(`refusing non-canonical AMM job: sha256 ${sourceSha256} != ${expectedJobSha256}`)
}
const envelope = JSON.parse(sourceBytes.toString('utf8')) as JobEnvelope
const sourceJob = envelope.job
const requestedProgramId = process.env.ZKDEAL_PROGRAM_ID?.toLowerCase() as Hex | undefined
if (!requestedProgramId || !/^0x[0-9a-f]{64}$/.test(requestedProgramId) || /^0x0{64}$/.test(requestedProgramId)) {
  throw new Error(
    'ZKDEAL_PROGRAM_ID=<fresh cold/composed-capable RISC Zero image ID> is required',
  )
}
if (requestedProgramId === sourceJob.programId.toLowerCase()) {
  throw new Error(
    `ZKDEAL_PROGRAM_ID is the frozen pre-composition image ${sourceJob.programId}; rebuild the guest and use its fresh image ID`,
  )
}
// The 08:30 job remains immutable provenance. Clone its exact workload and
// bind it to the newly built composition-capable guest; never publish a
// runnable cold/composed request under the old image ID.
const witness = structuredClone(sourceJob.witness)
witness.proofProgramId = requestedProgramId
const job = { ...sourceJob, programId: requestedProgramId, witness }
if (
  job.v !== 4
  || job.backendId !== 'risc0'
  || job.proofMode !== 'succinct'
  || witness.v !== 4
  || witness.blocks.length !== 2
  || witness.blocks.some((block) => block.rawTxs.length < 3)
) {
  throw new Error('source job is not the certified two-block/six-transaction v4 RISC Zero AMM job')
}
assertEqual(job.programId, witness.proofProgramId, 'job/witness proof program')
assertEqual(job.presetHash, witness.presetHash, 'job/witness preset')

const members = witness.preRosterSlots
  .filter((slot) => slot.state === 'active' || slot.state === 1)
  .sort((a, b) => a.slot - b.slot)
  .map((slot) => slot.account.toLowerCase() as Hex)
if (members.length !== 2) throw new Error(`certified AMM expected two active members, got ${members.length}`)

const tokenArtifact = await artifact('RoomERC20', 'RoomERC20')
const ammArtifact = await artifact('ConstantProductAMM', 'ConstantProductAMM')
const token0Address = predictGenesisAddress(0n)
const token1Address = predictGenesisAddress(1n)
const ammAddress = predictGenesisAddress(2n)
const deployments = [
  {
    name: 'AssetA',
    bytecodeHex: tokenCreation(tokenArtifact.bytecode.object, 'Asset A', 'ASA', members[0]!),
    abiJson: tokenArtifact.abi,
  },
  {
    name: 'AssetB',
    bytecodeHex: tokenCreation(tokenArtifact.bytecode.object, 'Asset B', 'ASB', members[0]!),
    abiJson: tokenArtifact.abi,
  },
  {
    name: 'ConstantProductAMM',
    bytecodeHex: ammCreation(ammArtifact.bytecode.object, token0Address, token1Address),
    abiJson: ammArtifact.abi,
  },
]

const roomId = BigInt(witness.roomId)
const roomPlan = {
  roomId,
  deploymentDomain: witness.deploymentDomain,
  protocolVersion: 4 as const,
  members: members.map((address) => ({ address, depositWei: 0n })),
  deployments,
  attributionHints: [],
}
const additionalStateEnvelope = witness.compactState.accounts.map((account) => ({
  address: account.address.toLowerCase() as Hex,
  storageSlots: account.storage.map((slot) => slot.slot.toLowerCase() as Hex),
}))

const analyzerVersion = 'zkdeal-certified-static-envelope-analyzer-v4.1'
const prepared = await prepareRoomV4({
  plan: roomPlan,
  compilerVersion: 'solc-0.8.36+commit.8a079791;optimizer=200;viaIR=true;evm=osaka',
  baseProofProgramId: witness.proofProgramId,
  additionalStateEnvelope,
  analyzer: {
    version: analyzerVersion,
    analyze(input) {
      const runtime = input.runtimeContracts.map((contract) => ({
        address: contract.address,
        codeHash: contract.codeHash,
        abiHash: contract.abiHash,
      }))
      return {
        artifactFormat: 'zkdeal-certified-static-envelope-v4',
        analyzedBytecodeArtifactRoot: contentHash(
          'zkdeal/certified-bytecode-analysis/v4',
          {
            evmFork: input.evmFork,
            constructorDeploymentTranscriptHash: input.constructorDeploymentTranscriptHash,
            runtime,
            presetHash: witness.presetHash,
            codePolicy: witness.preset.code,
          },
        ),
        allowedCallTargetRoot: contentHash(
          'zkdeal/certified-call-envelope/v4',
          {
            presetHash: witness.presetHash,
            callRules: witness.preset.callRules,
            runtime,
          },
        ),
      }
    },
  },
})
assertEqual(prepared.coldStateRoot, witness.preStateRoot, 'prepared constructor state / hot prestate')

const coldRoomId = 999_999n // createL2Common => stf_types::COLD_TEMPLATE_CHAIN_ID_V4
const coldBasePlan = {
  roomId: coldRoomId,
  protocolVersion: 3 as const,
  members: members.map((address) => ({ address, depositWei: 0n })),
  attributionHints: [],
}
const [coldInitial, coldInitialized] = await Promise.all([
  buildGenesis({ ...coldBasePlan, deployments: [] }),
  buildGenesis({ ...coldBasePlan, deployments }),
])
assertEqual(coldInitialized.genesisRoot, witness.preStateRoot, 'cold Osaka constructor state / hot prestate')

const coldCommon = createL2Common(coldRoomId)
if (coldCommon.chainId() !== 77_999_999n) {
  throw new Error(`cold chain id drift: ${coldCommon.chainId()}`)
}
const deployerKey = hexToBytes(GENESIS_DEPLOYER_PRIVKEY)
// buildGenesis explicitly inserts a nonce=0/balance=0 deployer before CREATE.
// revm correctly treats that EIP-161-empty account as absent when rebuilding
// an input root. Remove it from the reusable prefix: the first signed nonce-0
// constructor transaction materializes the sender, and the initialized state
// is byte-identical to the real room genesis (nonce=3).
await coldInitial.engine.stateManager.deleteAccount(U.createAddressFromPrivateKey(deployerKey))
const coldInitialRoot = await coldInitial.engine.getStateRootHex()
const coldInitialStateDump = await coldInitial.engine.captureWitnessStateJson()
const rawConstructorTxs = deployments.map((deployment, nonce) => bytesToHex0x(
  TX.createLegacyTx(
    {
      nonce: BigInt(nonce),
      gasPrice: 0n,
      gasLimit: 8_000_000n,
      value: 0n,
      data: hexToBytes(deployment.bytecodeHex),
    },
    { common: coldCommon },
  ).sign(deployerKey).serialize(),
) as Hex)

const compactByAddress = new Map(
  witness.compactState.accounts.map((account) => [account.address.toLowerCase(), account]),
)
const runtimeCode = prepared.artifact.compiledBundle.runtimeContracts.map((contract) => ({
  address: contract.address,
  codeHash: contract.codeHash,
}))
const stateAccess = runtimeCode.map((runtime) => {
  const account = compactByAddress.get(runtime.address.toLowerCase())
  if (!account?.exists || !account.code || account.code === '0x') {
    throw new Error(`hot batch prestate is missing prepared runtime ${runtime.address}`)
  }
  assertEqual(
    bytesToHex0x(keccak256(hexToBytes(account.code))),
    runtime.codeHash,
    `runtime code ${runtime.address}`,
  )
  return {
    address: runtime.address,
    storageSlots: account.storage.map((entry) => entry.slot.toLowerCase()).sort(),
  }
})
const stateRefresh = stateAccess.map((access) => ({
  address: access.address,
  refreshNonce: false,
  refreshBalance: true,
  refreshAllStorage: true,
  storageSlots: [],
}))

const spec = {
  metadata: {
    generatedAt: new Date().toISOString(),
    sourceJob: jobPath,
    sourceJobSha256: sourceSha256,
    fixtureSha256: envelope.fixtureSha256 ?? null,
    sourceJobId: sourceJob.jobId,
    sourceInputDigest: sourceJob.inputDigest,
    programId: requestedProgramId,
    backendId: job.backendId,
    proofMode: job.proofMode,
    expectedExecutedGas: 544_468,
    blockCount: witness.blocks.length,
    transactionCount: witness.blocks.reduce((total, block) => total + block.rawTxs.length, 0),
    constructorCount: rawConstructorTxs.length,
    constructorChainId: coldCommon.chainId().toString(),
    compiler: prepared.artifact.compiledBundle.compilerVersion,
    analyzer: analyzerVersion,
    preparedArtifactHash: prepared.artifactHash,
  },
  ordinaryJob: createProverJobV4(witness as never, {
    backendId: 'risc0',
    proofMode: 'succinct',
  }),
  cold: {
    v: 4,
    compiledBundleHash: hashCompiledBundleV4(prepared.artifact.compiledBundle),
    presetHash: witness.presetHash,
    manifestHash: witness.manifestHash,
    proofProgramId: witness.proofProgramId,
    initialStateRoot: coldInitialRoot,
    initializedStateRoot: coldInitialized.genesisRoot,
    analyzedArtifactRoot: prepared.artifact.compiledBundle.analyzedBytecodeArtifactRoot,
    allowedCallTargetRoot: prepared.artifact.compiledBundle.allowedCallTargetRoot,
    initialState: normalizeDump(coldInitialStateDump),
    setupBlocks: [{
      blockNumber: 0,
      rawTxs: rawConstructorTxs,
      env: { timestamp: 1, gasLimit: 30_000_000 },
      expectedPostStateRoot: coldInitialized.genesisRoot,
    }],
    runtimeCode,
    stateAccess,
    stateRefresh,
  },
  batchWitness: witness,
}

await mkdir(dirname(outputPath), { recursive: true })
await writeFile(outputPath, `${JSON.stringify(spec, null, 2)}\n`)
console.log(JSON.stringify({
  outputPath,
  sourceJobSha256: sourceSha256,
  initializedStateRoot: coldInitialized.genesisRoot,
  compiledBundleHash: spec.cold.compiledBundleHash,
  constructors: rawConstructorTxs.length,
  blocks: witness.blocks.length,
  transactions: spec.metadata.transactionCount,
}, null, 2))
