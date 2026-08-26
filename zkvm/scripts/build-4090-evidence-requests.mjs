#!/usr/bin/env node
/**
 * Deterministic, write-once request assembly for the physical CUDA release gate.
 * This script creates inputs and converts already-verified proof outputs; it
 * never writes either zkVM trust-root file.
 */

import { createHash } from 'node:crypto'
import { lstat, mkdir, open, readFile } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

import {
  CAPABILITY_FORMAT,
  JOURNAL_VERSION,
  LOCK_ARTIFACTS,
  LOCK_FORMAT,
  validateLockShape,
} from '../lock-schema.mjs'
import {
  SOURCE_MANIFEST_FORMAT,
  SOURCE_ROOTS,
  canonicalManifest,
  collectSourceManifest,
} from './check-lock-freshness.mjs'

const ZERO32 = `0x${'00'.repeat(32)}`
const REQUIRED_SOURCE_PROJECTS = [
  'app-node',
  'prover-node',
  'web3-protocol',
  'web2-api',
  'cloud-deployer-infra',
]
const REQUIRED_SOURCE_BINDINGS = [
  'app-node/packages/room-node/capabilities/room-node.json',
  'prover-node/agent/package.json',
  'prover-node/agent/liveness-capability.json',
  'prover-node/agent/trace-capability.json',
  'prover-node/agent/test/fixtures/hosted-trace-join.json',
  'prover-node/agent/src/agent.ts',
  'prover-node/agent/src/heartbeat.ts',
  'prover-node/agent/src/local-prover.ts',
  'prover-node/agent/src/structured-log.ts',
  'prover-node/zkvm/source-manifest.candidate.json',
  'web3-protocol/contracts/contract-capabilities.json',
  'web2-api/server/capabilities/room-batch-hosted-integration-v1.json',
  'cloud-deployer-infra/config/schemas/release-soak-manifest.schema.json',
]
const REQUIRED_DEPLOYMENT_ADDRESSES = [
  'roomManager',
  'roomIntakeFacet',
  'roomImportFacet',
  'roomBatchFacet',
  'roomValidationFacet',
  'roomObservationFacet',
  'roomChallengeFacet',
  'roomHostingFacet',
  'roomPool',
  'roomPoolHostingFacet',
]
const REQUIRED_DURABLE_OPERATIONS = {
  roomBatch: {
    endpoint: '/hosting/v1/l1-operations/room-batches',
    selector: '0x62dad01b',
  },
  roomAggregate: {
    endpoint: '/hosting/v1/l1-operations/room-aggregates',
    selector: '0x5e8b37ac',
    type3BlobTransaction: true,
    partialMemberOutcomes: true,
    successfulMemberOnlyCharging: true,
  },
  withdrawalClaim: {
    endpoint: '/hosting/v1/withdrawals/{roomId}/{epoch}/{withdrawalIndex}/claims',
    selector: '0xb051a9f8',
  },
  sponsorReserveAndStart: {
    endpoint: '/hosting/v1/l1-operations/pool-sponsor-mutations',
    selector: '0x827ac259',
    senderAuthority: 'sponsor',
  },
  sponsorRenew: {
    endpoint: '/hosting/v1/l1-operations/pool-sponsor-mutations',
    selector: '0xf180fe5d',
    senderAuthority: 'sponsor',
  },
  finalizedCheckpoint: {
    endpoint: '/hosting/v1/l1-operations/pool-finalized-checkpoints',
    selector: '0xe19bc67e',
    senderAuthority: 'finality-oracle',
  },
  beneficiaryDisposal: {
    endpoint: '/hosting/v1/l1-operations/pool-beneficiary-disposals',
    selector: '0xed97f11a',
    senderAuthority: 'beneficiary',
    refundRecipient: 'stored-payer',
  },
}
const REQUIRED_OWNER_CAPABILITY_OPERATIONS = {
  roomBatch: {
    endpoint: '/hosting/v1/l1-operations/room-batches',
    selector: '0x62dad01b',
  },
  roomAggregate: {
    endpoint: '/hosting/v1/l1-operations/room-aggregates',
    selector: '0x5e8b37ac',
  },
  withdrawalClaim: {
    endpoint: '/hosting/v1/withdrawals/{roomId}/{epoch}/{withdrawalIndex}/claims',
    selector: '0xb051a9f8',
  },
  poolSponsorMutation: {
    endpoint: '/hosting/v1/l1-operations/pool-sponsor-mutations',
    selectors: {
      reserveAndStartForWithDataAvailabilityWithPermit: '0x827ac259',
      renewRoomForWithPermit: '0xf180fe5d',
    },
    senderAuthority: 'sponsor',
  },
  poolFinalizedCheckpoint: {
    endpoint: '/hosting/v1/l1-operations/pool-finalized-checkpoints',
    selector: '0xe19bc67e',
    senderAuthority: 'finality-oracle',
  },
  poolBeneficiaryDisposal: {
    endpoint: '/hosting/v1/l1-operations/pool-beneficiary-disposals',
    selector: '0xed97f11a',
    senderAuthority: 'beneficiary',
  },
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'))
}

async function writeJsonExclusive(path, value) {
  await mkdir(dirname(path), { recursive: true })
  const handle = await open(path, 'wx')
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8')
  } finally {
    await handle.close()
  }
}

async function writeBytesExclusive(path, value) {
  await mkdir(dirname(path), { recursive: true })
  const handle = await open(path, 'wx')
  try {
    await handle.writeFile(value)
    await handle.sync()
  } finally {
    await handle.close()
  }
}

function requireHex32(value, field) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be exactly 32 bytes of hex`)
  }
  return value.toLowerCase()
}

function requireReceipt(value, field) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error(`${field} must be base64`)
  }
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length === 0) throw new Error(`${field} is empty`)
  return value
}

function requireHexBytes(value, bytes, field) {
  if (typeof value !== 'string' || !new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value)) {
    throw new Error(`${field} must be exactly ${bytes} bytes of hex`)
  }
  return value.toLowerCase()
}

function requireNonemptyHex(value, field) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(value)) {
    throw new Error(`${field} must be nonempty whole-byte hex`)
  }
  return value.toLowerCase()
}

function requireSha256(value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${field} must be a lowercase SHA-256 digest`)
  }
  return value
}

function requireImageReference(value, field) {
  if (typeof value !== 'string' || !/^[^\s@]+@sha256:[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${field} must be a pushed repository@sha256 manifest reference`)
  }
  return value
}

function requireObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${field} must be an object`)
  }
  return value
}

function requireCanonicalDecimal(value, field) {
  const text = String(value ?? '')
  if (!/^(?:0|[1-9][0-9]*)$/.test(text)) {
    throw new Error(`${field} must be a canonical unsigned decimal`)
  }
  return text
}

function requireJobId(value, field) {
  if (typeof value !== 'string' || !/^pj-[0-9a-f]{10,64}$/.test(value)) {
    throw new Error(`${field} must be a durable queue job id`)
  }
  return value
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.entries(value)
      .sort(([left], [right]) => stableCompare(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(',')}}`
  }
  return JSON.stringify(value) ?? 'null'
}

function sealHex(value, field) {
  return `0x${Buffer.from(requireReceipt(value, field), 'base64').toString('hex')}`
}

function resolveFrom(documentPath, child) {
  if (typeof child !== 'string' || child.length === 0) {
    throw new Error('evidence plan paths must be non-empty strings')
  }
  return isAbsolute(child) ? child : resolve(dirname(documentPath), child)
}

function safeRelativePath(root, child, field) {
  if (typeof child !== 'string' || child.length === 0 || isAbsolute(child)) {
    throw new Error(`${field} must be a nonempty relative path`)
  }
  const path = resolve(root, child)
  const back = relative(root, path)
  if (back === '..' || back.startsWith(`..${sep}`) || isAbsolute(back)) {
    throw new Error(`${field} escapes its declared root`)
  }
  return { path, portable: back.split(sep).join('/') }
}

export async function buildStagedZkvmImages(
  candidateManifestSha256,
  orchestrator,
  toolchain,
  runtime,
  outputPath,
) {
  const images = {
    orchestrator: requireImageReference(orchestrator, 'staged orchestrator image'),
    toolchain: requireImageReference(toolchain, 'staged toolchain image'),
    runtime: requireImageReference(runtime, 'staged runtime image'),
  }
  if (new Set(Object.values(images)).size !== 3) {
    throw new Error('staged orchestrator, toolchain and runtime image references must be distinct')
  }
  const receipt = {
    schema: 'zkdeal/4090-staged-zkvm-images/v1',
    candidateManifestSha256: requireSha256(
      candidateManifestSha256,
      'candidateManifestSha256',
    ),
    promoted: false,
    images,
  }
  await writeJsonExclusive(outputPath, receipt)
  return receipt
}

async function computeGeneratedTrustRootClosure(zkvmRoot, stagedImagesReceiptPath) {
  const root = resolve(zkvmRoot)
  const candidatePath = join(root, 'source-manifest.candidate.json')
  const sourceManifestPath = join(root, 'source-manifest.json')
  const lockPath = join(root, 'artifacts.lock.json')
  const [candidateBytes, sourceManifestBytes, lockBytes, stagedImagesBytes] = await Promise.all([
    readFile(candidatePath),
    readFile(sourceManifestPath),
    readFile(lockPath),
    readFile(stagedImagesReceiptPath),
  ])
  if (!candidateBytes.equals(sourceManifestBytes)) {
    throw new Error('minted source-manifest.json is not byte-identical to the sealed candidate manifest')
  }
  const candidate = JSON.parse(candidateBytes.toString('utf8'))
  if (candidate.format !== SOURCE_MANIFEST_FORMAT || candidate.algorithm !== 'sha256') {
    throw new Error(`candidate source manifest is not ${SOURCE_MANIFEST_FORMAT}`)
  }
  if (canonical(candidate.sourceRoots) !== canonical(SOURCE_ROOTS)) {
    throw new Error('candidate source manifest root set differs from the current build contract')
  }
  const observedBytes = Buffer.from(canonicalManifest(collectSourceManifest(root, SOURCE_ROOTS)))
  if (!candidateBytes.equals(observedBytes)) {
    throw new Error('candidate source manifest no longer describes the exact zkVM source tree')
  }
  const excludedOutputs = [
    'artifacts.lock.json',
    'source-manifest.json',
    ...LOCK_ARTIFACTS,
  ]
  const candidatePaths = new Set(candidate.files.map((file) => file.path))
  const preimageOverlap = excludedOutputs.filter((path) => candidatePaths.has(path))
  if (preimageOverlap.length > 0) {
    throw new Error(`generated trust-root output entered the build preimage: ${preimageOverlap.join(', ')}`)
  }

  const lock = JSON.parse(lockBytes.toString('utf8'))
  validateLockShape(lock)
  const candidateSha256 = sha256(candidateBytes)
  if (lock.sourceManifestSha256 !== candidateSha256) {
    throw new Error('artifact lock does not bind the exact sealed candidate/source-manifest bytes')
  }
  if (lock.format !== LOCK_FORMAT || lock.journalVersion !== JOURNAL_VERSION
    || lock.risc0?.capabilityFormat !== CAPABILITY_FORMAT) {
    throw new Error('artifact lock is not the current journal/capability trust-root format')
  }

  const stagedImages = JSON.parse(stagedImagesBytes.toString('utf8'))
  if (canonical(Object.keys(stagedImages).sort(stableCompare))
      !== canonical(['candidateManifestSha256', 'images', 'promoted', 'schema'])
    || stagedImages.schema !== 'zkdeal/4090-staged-zkvm-images/v1'
    || stagedImages.promoted !== false
    || stagedImages.candidateManifestSha256 !== candidateSha256) {
    throw new Error('staged image receipt does not bind the unpromoted sealed candidate')
  }
  const stagedImageMap = requireObject(stagedImages.images, 'staged images')
  if (canonical(Object.keys(stagedImageMap).sort(stableCompare))
      !== canonical(['orchestrator', 'runtime', 'toolchain'])) {
    throw new Error('staged image receipt must contain exactly orchestrator, toolchain and runtime')
  }
  const stagedImageReferences = {
    orchestrator: requireImageReference(stagedImageMap.orchestrator, 'staged orchestrator image'),
    toolchain: requireImageReference(stagedImageMap.toolchain, 'staged toolchain image'),
    runtime: requireImageReference(stagedImageMap.runtime, 'staged runtime image'),
  }
  if (new Set(Object.values(stagedImageReferences)).size !== 3) {
    throw new Error('staged orchestrator, toolchain and runtime image references must be distinct')
  }
  if (stagedImageReferences.toolchain !== lock.toolchain.image
    || stagedImageReferences.runtime !== lock.runtime.image) {
    throw new Error('staged toolchain/runtime image references disagree with the artifact lock')
  }

  const artifacts = []
  for (const artifact of LOCK_ARTIFACTS) {
    const resolved = safeRelativePath(root, artifact, `locked artifact ${artifact}`)
    const stats = await lstat(resolved.path)
    if (!stats.isFile() || stats.isSymbolicLink()) {
      throw new Error(`locked artifact must be a regular non-symlink file: ${artifact}`)
    }
    const bytes = await readFile(resolved.path)
    const digest = sha256(bytes)
    const expected = requireSha256(
      lock.artifacts?.[artifact]?.sha256,
      `artifacts[${artifact}].sha256`,
    )
    if (digest !== expected) {
      throw new Error(`locked artifact ${artifact} sha256 ${digest} != lock ${expected}`)
    }
    artifacts.push({ path: resolved.portable, bytes: bytes.length, sha256: digest })
  }
  artifacts.sort((left, right) => stableCompare(left.path, right.path))

  return {
    schema: 'zkdeal/4090-generated-trust-root-closure/v1',
    algorithm: 'sha256',
    buildPreimage: {
      candidateManifest: {
        path: 'source-manifest.candidate.json',
        bytes: candidateBytes.length,
        sha256: candidateSha256,
        filesDigest: requireSha256(candidate.filesDigest, 'candidate filesDigest'),
        files: candidate.files.length,
        sourceRoots: [...candidate.sourceRoots],
      },
      verifiedAgainstFilesystem: true,
      generatedOutputsExcluded: true,
    },
    stagedImages: {
      receiptBytes: stagedImagesBytes.length,
      receiptSha256: sha256(stagedImagesBytes),
      promoted: false,
      ...stagedImageReferences,
    },
    generatedTrustRoot: {
      sourceManifest: {
        path: 'source-manifest.json',
        bytes: sourceManifestBytes.length,
        sha256: candidateSha256,
        byteIdenticalToCandidate: true,
      },
      artifactLock: {
        path: 'artifacts.lock.json',
        bytes: lockBytes.length,
        sha256: sha256(lockBytes),
        format: lock.format,
        journalVersion: lock.journalVersion,
        capabilityFormat: lock.risc0.capabilityFormat,
      },
      programId: requireHex32(lock.risc0.programId, 'lock risc0.programId'),
      toolchainImage: lock.toolchain.image,
      runtimeImage: lock.runtime.image,
      runtimeHostBinarySha256: requireSha256(
        lock.runtime.hostBinarySha256,
        'lock runtime.hostBinarySha256',
      ),
      lockedArtifacts: artifacts,
    },
    orderingContract: {
      requiredIndependentCudaBuilds: 2,
      trustRootWriter: 'zkvm/build.mjs --cuda --check-repro --bootstrap-lock',
      authorizedPostPreimageWritePaths: [
        'artifacts.lock.json',
        'source-manifest.json',
      ],
      authorizedPostPreimageWritePrefixes: ['build/'],
      stagedImagesAreNotReleasePromotion: true,
      finalPromotionRequiresExactStagedDigests: true,
      rebuildAfterCompositeSealForbidden: true,
      postCompositeSealMutationInvalidatesCandidate: true,
    },
  }
}

export async function buildGeneratedTrustRootClosure(
  zkvmRoot,
  stagedImagesReceiptPath,
  outputPath,
) {
  const closure = await computeGeneratedTrustRootClosure(zkvmRoot, stagedImagesReceiptPath)
  await writeJsonExclusive(outputPath, closure)
  return closure
}

export async function verifyGeneratedTrustRootClosure(
  zkvmRoot,
  stagedImagesReceiptPath,
  closurePath,
) {
  const expected = `${JSON.stringify(
    await computeGeneratedTrustRootClosure(zkvmRoot, stagedImagesReceiptPath),
    null,
    2,
  )}\n`
  const observed = await readFile(closurePath, 'utf8')
  if (observed !== expected) {
    throw new Error('generated trust-root closure differs from the current source/lock/artifact boundary')
  }
  return {
    verified: true,
    schema: 'zkdeal/4090-generated-trust-root-closure/v1',
    sha256: sha256(Buffer.from(observed)),
  }
}

export async function buildSourceClosure(
  archivePath,
  outerManifestPath,
  verificationPath,
  candidateManifestPath,
  outputPath,
) {
  const [archiveBytes, outerBytes, verificationBytes, candidateBytes] = await Promise.all([
    readFile(archivePath),
    readFile(outerManifestPath),
    readFile(verificationPath),
    readFile(candidateManifestPath),
  ])
  const outer = JSON.parse(outerBytes.toString('utf8'))
  const verification = JSON.parse(verificationBytes.toString('utf8'))
  const candidate = JSON.parse(candidateBytes.toString('utf8'))
  if (outer.schemaVersion !== 1 || outer.format !== 'zkdeal-source-bundle'
    || outer.historyIncluded !== false || outer.secretsIncluded !== false) {
    throw new Error('source bundle outer manifest is not a no-history, no-secret schema-1 bundle')
  }
  const archiveSha256 = sha256(archiveBytes)
  if (outer.archive !== basename(archivePath) || outer.archiveSha256 !== archiveSha256
    || outer.archiveBytes !== archiveBytes.length || !Number.isSafeInteger(outer.fileCount)
    || outer.fileCount < 1 || !Number.isSafeInteger(outer.totalBytes) || outer.totalBytes < 1) {
    throw new Error('source bundle archive bytes do not match the outer manifest')
  }
  if (!Array.isArray(outer.projects) || new Set(outer.projects).size !== outer.projects.length
    || REQUIRED_SOURCE_PROJECTS.some((project) => !outer.projects.includes(project))) {
    throw new Error(`source bundle must include ${REQUIRED_SOURCE_PROJECTS.join(', ')}`)
  }
  const outerSha256 = sha256(outerBytes)
  if (verification.verified !== true || verification.format !== 'zkdeal-source-bundle'
    || verification.historyIncluded !== false || verification.secretsIncluded !== false
    || verification.archiveSha256 !== archiveSha256
    || verification.outerManifestSha256 !== outerSha256
    || verification.files !== outer.fileCount || verification.bytes !== outer.totalBytes
    || canonical(verification.projects) !== canonical(outer.projects)) {
    throw new Error('source bundle verification report is not bound to the exact archive and manifest')
  }
  requireSha256(verification.embeddedManifestSha256, 'embeddedManifestSha256')
  requireSha256(verification.entriesSha256, 'entriesSha256')
  const bindings = requireObject(
    verification.criticalSourceBindings,
    'criticalSourceBindings',
  )
  for (const path of REQUIRED_SOURCE_BINDINGS) {
    const binding = requireObject(bindings[path], `criticalSourceBindings[${path}]`)
    requireSha256(binding.sha256, `criticalSourceBindings[${path}].sha256`)
    if (!Number.isSafeInteger(binding.bytes) || binding.bytes < 1
      || ![0o644, 0o755].includes(binding.mode)) {
      throw new Error(`criticalSourceBindings[${path}] has invalid size or mode`)
    }
  }
  if (candidate.format !== 'zkdeal/zkvm-source-manifest/v1'
    || candidate.algorithm !== 'sha256' || !Array.isArray(candidate.sourceRoots)
    || !Array.isArray(candidate.files) || candidate.files.length < 1) {
    throw new Error('zkVM candidate manifest is malformed')
  }
  requireSha256(candidate.filesDigest, 'candidate filesDigest')
  const candidateSha256 = sha256(candidateBytes)
  const candidateBinding = bindings['prover-node/zkvm/source-manifest.candidate.json']
  if (candidateBinding.sha256 !== candidateSha256 || candidateBinding.bytes !== candidateBytes.length) {
    throw new Error('umbrella source bundle does not contain the exact zkVM candidate manifest')
  }
  const closure = {
    schema: 'zkdeal/4090-source-closure/v1',
    algorithm: 'sha256',
    noRepositoryHistory: true,
    noSecrets: true,
    archive: {
      name: outer.archive,
      bytes: archiveBytes.length,
      sha256: archiveSha256,
      outerManifestSha256: outerSha256,
      embeddedManifestSha256: verification.embeddedManifestSha256,
      entriesSha256: verification.entriesSha256,
      fileCount: outer.fileCount,
      totalBytes: outer.totalBytes,
    },
    projects: [...outer.projects],
    requiredProjects: [...REQUIRED_SOURCE_PROJECTS],
    criticalSourceBindings: Object.fromEntries(
      REQUIRED_SOURCE_BINDINGS.map((path) => [path, bindings[path]]),
    ),
    zkvmCandidateManifest: {
      sha256: candidateSha256,
      filesDigest: candidate.filesDigest,
      files: candidate.files.length,
    },
  }
  await writeJsonExclusive(outputPath, closure)
  return closure
}

export async function buildHostedBatchLineage(planPath, outputPath) {
  const plan = await readJson(planPath)
  if (plan.schema !== 'zkdeal/4090-hosted-batch-lineage-plan/v1') {
    throw new Error('hosted batch lineage plan has an unsupported schema')
  }
  if (!['owner-finalized', 'aggregate-pending'].includes(plan.publicationMode)) {
    throw new Error('publicationMode must be owner-finalized or aggregate-pending')
  }
  const roomId = requireCanonicalDecimal(plan.roomId, 'roomId')
  if (typeof plan.correlationId !== 'string' || plan.correlationId.length < 8
    || plan.correlationId.length > 200) {
    throw new Error('correlationId must contain 8 through 200 characters')
  }
  if (!Number.isSafeInteger(plan.chainId) || plan.chainId < 1) {
    throw new Error('chainId must be a positive safe integer')
  }
  const roomManager = requireHexBytes(plan.roomManager, 20, 'roomManager')
  const operationsAccount = requireHexBytes(
    plan.expectedOperationsAccount,
    20,
    'expectedOperationsAccount',
  )
  if (!Number.isSafeInteger(plan.minimumConfirmations) || plan.minimumConfirmations < 1) {
    throw new Error('minimumConfirmations must be a positive integer')
  }
  if (!Array.isArray(plan.admissionIds)
    || (plan.publicationMode === 'owner-finalized' && plan.admissionIds.length < 1)) {
    throw new Error('owner-finalized hosted batches must bind at least one admission')
  }
  const admissionIds = plan.admissionIds.map((value, index) =>
    requireCanonicalDecimal(value, `admissionIds[${index}]`))
  for (let index = 1; index < admissionIds.length; index += 1) {
    if (BigInt(admissionIds[index]) !== BigInt(admissionIds[index - 1]) + 1n) {
      throw new Error('admissionIds must be one contiguous increasing interval')
    }
  }

  const jobs = requireObject(plan.jobs, 'jobs')
  async function loadJob(stage, endpoint) {
    const item = requireObject(jobs[stage], `jobs.${stage}`)
    if (item.endpoint !== endpoint) throw new Error(`jobs.${stage}.endpoint must equal ${endpoint}`)
    const requestPath = resolveFrom(planPath, item.request)
    const resultPath = resolveFrom(planPath, item.result)
    const [requestBytes, resultBytes] = await Promise.all([
      readFile(requestPath),
      readFile(resultPath),
    ])
    const resultDigest = requireSha256(item.resultDigest, `jobs.${stage}.resultDigest`)
    if (sha256(resultBytes) !== resultDigest) {
      throw new Error(`${stage} result bytes do not match their durable resultDigest`)
    }
    return {
      endpoint,
      jobId: requireJobId(item.jobId, `jobs.${stage}.jobId`),
      resultDigest,
      request: JSON.parse(requestBytes.toString('utf8')),
      result: JSON.parse(resultBytes.toString('utf8')),
      requestSha256: sha256(requestBytes),
      resultSha256: sha256(resultBytes),
    }
  }
  const prepare = await loadJob('prepare', '/hosting/v1/rooms/prepare-batch')
  const prove = await loadJob('prove', '/v5/rooms/prove')
  const verify = await loadJob('verify', '/v5/rooms/verify')

  const opening = requireObject(prepare.request.opening, 'prepare request opening')
  if (prepare.request.schemaVersion !== 1 || prepare.request.production !== true
    || prepare.request.proofMode !== 'groth16'
    || requireCanonicalDecimal(opening.roomId, 'prepare opening roomId') !== roomId
    || Number(opening.authorizationMode) !== 1) {
    throw new Error('prepare request is not a production live VALIDITY_ONLY room witness')
  }
  const prepared = prepare.result
  const prepareArtifactDigest = requireSha256(
    prepared.prepareArtifactDigest,
    'prepareArtifactDigest',
  )
  if (prepared.schemaVersion !== 1 || prepared.fixture !== false
    || prepared.preparedFrom !== 'live-room-engine-state'
    || prepared.contentAddress !== prepareArtifactDigest) {
    throw new Error('prepare result is not a content-addressed live-room engine artifact')
  }
  const programId = requireHex32(prepared.programId, 'prepare programId')
  const journalHash = requireHex32(prepared.journalHash, 'prepare journalHash')
  requireReceipt(prepared.roomWitnessB64, 'prepare roomWitnessB64')
  const proofRequest = requireObject(prepared.proofRequest, 'prepare proofRequest')
  if (proofRequest.production !== true || proofRequest.proofMode !== 'groth16'
    || proofRequest.inputDigest !== `0x${prepareArtifactDigest}`
    || canonical(prove.request) !== canonical(proofRequest)) {
    throw new Error('prove request is not the exact production request emitted by live preparation')
  }
  const provisional = requireObject(prepared.provisionalSubmission, 'provisionalSubmission')
  const provisionalJournal = requireObject(provisional.journal, 'provisionalSubmission.journal')
  if (provisional.seal !== '0x' || requireCanonicalDecimal(provisionalJournal.roomId, 'submission roomId') !== roomId
    || requireCanonicalDecimal(provisionalJournal.protocolVersion, 'submission protocolVersion') !== '6'
    || !Array.isArray(provisional.approvals) || provisional.approvals.length !== 0
    || !Array.isArray(provisional.approverChanges) || provisional.approverChanges.length !== 0
    || !Array.isArray(provisional.admissions) || provisional.admissions.length !== admissionIds.length) {
    throw new Error('live provisional submission is not the bound VALIDITY_ONLY admission interval')
  }
  const cursorBefore = BigInt(requireCanonicalDecimal(
    provisionalJournal.admissionCursorBefore,
    'submission admissionCursorBefore',
  ))
  const cursorAfter = BigInt(requireCanonicalDecimal(
    provisionalJournal.admissionCursorAfter,
    'submission admissionCursorAfter',
  ))
  if (cursorAfter - cursorBefore !== BigInt(admissionIds.length)
    || admissionIds.some((id, index) => BigInt(id) !== cursorBefore + BigInt(index) + 1n)) {
    throw new Error('admissionIds do not exactly cover the proved journal cursor interval')
  }

  const proved = prove.result
  if (proved.backendId !== 'risc0' || proved.proofMode !== 'groth16'
    || proved.inputDigest !== `0x${prepareArtifactDigest}`
    || proved.programId !== programId || proved.journalHash !== journalHash
    || canonical(proved.journal) !== canonical(prepared.journal)) {
    throw new Error('prove result is not the exact RISC Zero receipt for the prepared live journal')
  }
  requireReceipt(proved.receiptB64, 'prove receiptB64')
  requireReceipt(proved.ethereumSealB64, 'prove ethereumSealB64')
  if (proved.jobId !== proofRequest.jobId) {
    throw new Error('prove result job identity differs from the prepared witness identity')
  }
  const expectedVerifyRequest = {
    journal: proved.journal,
    journalHash: proved.journalHash,
    receiptB64: proved.receiptB64,
  }
  if (canonical(verify.request) !== canonical(expectedVerifyRequest)) {
    throw new Error('verify request is not the exact proved room receipt')
  }
  const verified = verify.result
  if (verified.ok !== true || verified.proofMode !== 'groth16'
    || verified.journalHash !== journalHash
    || canonical(verified.journal) !== canonical(proved.journal)
    || verified.ethereumSealB64 !== proved.ethereumSealB64
    || (verified.imageId !== undefined && proved.imageId !== undefined
      && verified.imageId !== proved.imageId)) {
    throw new Error('verify result does not bind the proved journal and Ethereum seal')
  }

  let publication
  if (plan.publicationMode === 'owner-finalized') {
    const ownerBytes = await readFile(resolveFrom(planPath, plan.ownerOperation))
    const owner = JSON.parse(ownerBytes.toString('utf8'))
    const binding = requireObject(owner.binding, 'owner operation binding')
    const exactBindings = {
      roomId,
      correlationId: plan.correlationId,
      prepareJobId: prepare.jobId,
      prepareResultDigest: prepare.resultDigest,
      prepareArtifactDigest,
      proveJobId: prove.jobId,
      proveResultDigest: prove.resultDigest,
      verifyJobId: verify.jobId,
      verifyResultDigest: verify.resultDigest,
      journalHash,
    }
    for (const [field, value] of Object.entries(exactBindings)) {
      if (String(binding[field] ?? '').toLowerCase() !== String(value).toLowerCase()) {
        throw new Error(`owner operation binding differs at ${field}`)
      }
    }
    if (owner.status !== 'FINALIZED' || owner.finalized !== true
      || Number(owner.chainId) !== plan.chainId || owner.correlationId !== plan.correlationId
      || String(owner.to ?? '').toLowerCase() !== roomManager
      || String(owner.from ?? '').toLowerCase() !== operationsAccount
      || !Number.isSafeInteger(owner.confirmations)
      || owner.confirmations < plan.minimumConfirmations
      || canonical(binding.admissionIds) !== canonical(admissionIds)) {
      throw new Error('owner operation is not the finalized exact room-batch publication')
    }
    requireHex32(owner.txHash, 'owner txHash')
    requireCanonicalDecimal(owner.blockNumber, 'owner blockNumber')
    requireHex32(owner.blockHash, 'owner blockHash')
    requireHex32(binding.calldataHash, 'owner calldataHash')
    const receiptSource = requireObject(owner.receiptSource, 'owner receiptSource')
    if (receiptSource.canonical !== true || !Array.isArray(receiptSource.providerIds)
      || receiptSource.providerIds.length < 1
      || !Number.isFinite(Date.parse(String(receiptSource.observedAt ?? '')))) {
      throw new Error('owner finalized operation lacks canonical provider evidence')
    }
    const confirmationPolicy = requireObject(binding.confirmationPolicy, 'owner confirmationPolicy')
    if (confirmationPolicy.requireFinalized !== true
      || Number(confirmationPolicy.minimumConfirmations) !== plan.minimumConfirmations) {
      throw new Error('owner operation changed the requested finality policy')
    }
    publication = {
      mode: 'owner-finalized',
      operationId: owner.operationId,
      txHash: owner.txHash,
      blockNumber: String(owner.blockNumber),
      blockHash: owner.blockHash,
      confirmations: owner.confirmations,
      calldataHash: binding.calldataHash,
      evidenceSha256: sha256(ownerBytes),
    }
  } else {
    if (plan.ownerOperation !== undefined) {
      throw new Error('aggregate-pending lineage must not claim an owner publication')
    }
    publication = {
      mode: 'aggregate-pending',
      finalized: false,
      reason: 'held for one recursive aggregate publication',
    }
  }

  const lineage = {
    schema: 'zkdeal/4090-hosted-batch-lineage/v1',
    mode: 'hosted-validity-only',
    fixture: false,
    preparedFrom: 'live-room-engine-state',
    roomId,
    correlationId: plan.correlationId,
    chainId: plan.chainId,
    roomManager,
    expectedOperationsAccount: operationsAccount,
    admissionIds,
    prepareArtifactDigest,
    programId,
    journalHash,
    jobs: Object.fromEntries([prepare, prove, verify].map((job) => [
      job.endpoint,
      {
        jobId: job.jobId,
        resultDigest: job.resultDigest,
        requestSha256: job.requestSha256,
        resultSha256: job.resultSha256,
      },
    ])),
    publication,
  }
  await writeJsonExclusive(outputPath, lineage)
  return lineage
}

export async function buildRoomConfigs(templatePath, outputDirectory) {
  const template = await readJson(templatePath)
  requireHex32(template.deploymentDomain, 'deploymentDomain')
  const outputs = []
  for (let roomId = 1; roomId <= 8; roomId += 1) {
    const path = join(outputDirectory, `room-${roomId}-source.json`)
    await writeJsonExclusive(path, { ...template, roomId })
    outputs.push(path)
  }
  return outputs
}

export async function splitPreparedRoom(preparedPath, coldOutputPath, roomOutputPath) {
  const prepared = await readJson(preparedPath)
  if (!prepared.coldRequest?.coldTemplateWitness || !prepared.roomRequest?.roomWitness) {
    throw new Error('prepared result must contain coldRequest and roomRequest witnesses')
  }
  await writeJsonExclusive(coldOutputPath, prepared.coldRequest)
  await writeJsonExclusive(roomOutputPath, prepared.roomRequest)
  return { coldRequest: prepared.coldRequest, roomRequest: prepared.roomRequest }
}

export async function buildDataAvailabilityRequest(
  preparedPath,
  roomProofPath,
  blobStartIndex,
  outputPath,
) {
  if (!Number.isSafeInteger(blobStartIndex) || blobStartIndex < 0 || blobStartIndex > 5) {
    throw new Error('blobStartIndex must be an integer from zero through five')
  }
  const prepared = await readJson(preparedPath)
  const proof = await readJson(roomProofPath)
  const journal = proof?.journal
  if (!journal) throw new Error('room proof journal is required')
  const canonicalData = prepared?.provisionalSubmission?.canonicalBatchData
    ?? prepared?.roomRequest?.roomWitness?.canonical_batch_data
  if (typeof canonicalData !== 'string' || !/^0x[0-9a-fA-F]+$/.test(canonicalData)) {
    throw new Error('prepared canonical batch data must be non-empty hex')
  }
  const request = {
    equivalenceWitness: {
      deploymentDomain: requireHex32(journal.deployment_domain, 'journal.deployment_domain'),
      roomId: journal.room_id,
      journalHash: requireHex32(proof.journalHash, 'room proof journalHash'),
      canonicalData,
      blobStartIndex,
    },
    proofMode: 'groth16',
    production: true,
  }
  await writeJsonExclusive(outputPath, request)
  return request
}

export async function buildAggregateRequest(planPath, outputPath) {
  const plan = await readJson(planPath)
  if (!Array.isArray(plan.members) || plan.members.length !== 8) {
    throw new Error('release aggregate plan must contain exactly eight members')
  }
  const members = []
  const memberReceipts = []
  const roomIds = new Set()
  let deploymentDomain
  let nextBlob = 0
  let blobMembers = 0
  let calldataMembers = 0
  for (const [index, item] of plan.members.entries()) {
    if (!['blob', 'calldata'].includes(item.kind)) {
      throw new Error(`member ${index} kind must be blob or calldata`)
    }
    const roomProof = await readJson(resolveFrom(planPath, item.roomProof))
    const journal = roomProof.journal
    if (!journal) throw new Error(`member ${index} room proof has no journal`)
    const domain = requireHex32(journal.deployment_domain, `member ${index} deployment domain`)
    deploymentDomain ??= domain
    if (domain !== deploymentDomain) throw new Error('aggregate members have different deployment domains')
    const roomId = String(journal.room_id)
    if (roomIds.has(roomId)) throw new Error(`aggregate room ${roomId} is duplicated`)
    roomIds.add(roomId)
    const member = {
      roomId: journal.room_id,
      roomProgramId: requireHex32(roomProof.programId, `member ${index} room programId`),
      journalHash: requireHex32(roomProof.journalHash, `member ${index} journalHash`),
      equivalenceProgramId: ZERO32,
      equivalenceStatement: ZERO32,
    }
    const receipts = {
      roomReceiptB64: requireReceipt(roomProof.receiptB64, `member ${index} roomReceiptB64`),
    }
    if (item.kind === 'blob') {
      blobMembers += 1
      const daProof = await readJson(resolveFrom(planPath, item.dataAvailabilityProof))
      const daWitness = daProof.equivalenceWitness
      const manifest = daProof.dataAvailabilityManifest
      if (!daWitness || !manifest) throw new Error(`member ${index} data-availability proof is incomplete`)
      if (
        String(daWitness.roomId) !== roomId ||
        requireHex32(daWitness.journalHash, `member ${index} DA journalHash`) !== member.journalHash
      ) {
        throw new Error(`member ${index} data-availability proof is bound to another room/journal`)
      }
      if (manifest.blobStartIndex !== nextBlob) {
        throw new Error(`member ${index} blob range starts at ${manifest.blobStartIndex}, expected ${nextBlob}`)
      }
      const blobCount = manifest.blobVersionedHashes?.length
      if (!Number.isSafeInteger(blobCount) || blobCount < 1 || nextBlob + blobCount > 6) {
        throw new Error(`member ${index} has an invalid blob count`)
      }
      const manifestFields = [
        ['commitments', 48],
        ['evaluationPoints', 32],
        ['evaluations', 32],
        ['kzgProofs', 48],
      ]
      for (const [field, bytes] of manifestFields) {
        if (!Array.isArray(manifest[field]) || manifest[field].length !== blobCount) {
          throw new Error(`member ${index} manifest ${field} count does not match its blobs`)
        }
        manifest[field].forEach((value, itemIndex) =>
          requireHexBytes(value, bytes, `member ${index} manifest ${field}[${itemIndex}]`),
        )
      }
      manifest.blobVersionedHashes.forEach((value, itemIndex) =>
        requireHex32(value, `member ${index} blobVersionedHashes[${itemIndex}]`),
      )
      if (!Array.isArray(daProof.blobsB64) || daProof.blobsB64.length !== blobCount) {
        throw new Error(`member ${index} blob payload count does not match its manifest`)
      }
      daProof.blobsB64.forEach((value, itemIndex) => {
        const bytes = Buffer.from(requireReceipt(value, `member ${index} blobsB64[${itemIndex}]`), 'base64')
        if (bytes.length !== 131072) {
          throw new Error(`member ${index} blob ${itemIndex} must be exactly 131072 bytes`)
        }
      })
      if (daProof.proofMode !== 'groth16') {
        throw new Error(`member ${index} requires a nonempty Groth16 equivalence seal`)
      }
      requireNonemptyHex(manifest.equivalenceSeal, `member ${index} equivalenceSeal`)
      nextBlob += blobCount
      member.equivalenceProgramId = requireHex32(
        daProof.programId,
        `member ${index} equivalence programId`,
      )
      member.equivalenceStatement = requireHex32(
        daProof.statement,
        `member ${index} equivalence statement`,
      )
      receipts.equivalenceReceiptB64 = requireReceipt(
        daProof.receiptB64,
        `member ${index} equivalenceReceiptB64`,
      )
    } else if (item.dataAvailabilityProof !== undefined) {
      throw new Error(`calldata member ${index} must not name a data-availability proof`)
    } else {
      calldataMembers += 1
    }
    members.push(member)
    memberReceipts.push(receipts)
  }
  if (plan.requireMaxTransactionBlobs === true && nextBlob !== 6) {
    throw new Error(`release plan requires six referenced blobs, observed ${nextBlob}`)
  }
  if (
    plan.requireMaxTransactionBlobs === true &&
    (blobMembers !== 6 || calldataMembers !== 2)
  ) {
    throw new Error(
      `release plan requires six one-blob members and two calldata members; observed ${blobMembers} blob and ${calldataMembers} calldata members`,
    )
  }
  const request = {
    aggregateWitness: { deploymentDomain, members },
    memberReceipts,
    proofMode: 'groth16',
    production: true,
  }
  await writeJsonExclusive(outputPath, request)
  return request
}

export async function buildBlobTransactionPayload(planPath, outputPath) {
  const plan = await readJson(planPath)
  if (!Array.isArray(plan.members) || plan.members.length !== 8) {
    throw new Error('release blob payload plan must contain exactly eight members')
  }
  const blobs = []
  let nextBlob = 0
  let blobMembers = 0
  let calldataMembers = 0
  for (const [index, item] of plan.members.entries()) {
    if (item.kind === 'calldata') {
      if (item.dataAvailabilityProof !== undefined) {
        throw new Error(`calldata member ${index} must not name a data-availability proof`)
      }
      calldataMembers += 1
      continue
    }
    if (item.kind !== 'blob') throw new Error(`member ${index} kind must be blob or calldata`)
    blobMembers += 1
    const proof = await readJson(resolveFrom(planPath, item.dataAvailabilityProof))
    const manifest = proof.dataAvailabilityManifest
    if (!manifest || manifest.blobStartIndex !== nextBlob) {
      throw new Error(`member ${index} blob range is not contiguous at ${nextBlob}`)
    }
    if (
      !Array.isArray(proof.blobsB64) ||
      !Array.isArray(manifest.blobVersionedHashes) ||
      proof.blobsB64.length !== manifest.blobVersionedHashes.length ||
      proof.blobsB64.length !== 1
    ) {
      throw new Error(`member ${index} must contribute exactly one complete blob`)
    }
    const bytes = Buffer.from(
      requireReceipt(proof.blobsB64[0], `member ${index} blobsB64[0]`),
      'base64',
    )
    if (bytes.length !== 131072) {
      throw new Error(`member ${index} blob must be exactly 131072 bytes`)
    }
    blobs.push(bytes)
    nextBlob += 1
  }
  if (blobMembers !== 6 || calldataMembers !== 2 || nextBlob !== 6) {
    throw new Error('release blob payload requires six blob and two calldata members')
  }
  const payload = Buffer.concat(blobs)
  await writeBytesExclusive(outputPath, payload)
  return { blobCount: 6, bytes: payload.length, sha256: sha256(payload) }
}

export async function buildOwnerDurableCapabilities(capabilitiesPath, outputPath) {
  const sourceBytes = await readFile(capabilitiesPath)
  const document = JSON.parse(sourceBytes.toString('utf8'))
  if (document.schemaVersion !== 1) {
    throw new Error('owner capabilities must use schemaVersion 1')
  }
  const negotiation = requireObject(document.negotiation, 'negotiation')
  if (negotiation.header !== 'Accept-Schema-Version' || negotiation.default !== 1
    || !Array.isArray(negotiation.supported) || !negotiation.supported.includes(1)) {
    throw new Error('owner capabilities do not support the required schema negotiation')
  }
  const managed = requireObject(document.managedL1Operations, 'managedL1Operations')
  if (managed.statusEndpoint !== '/hosting/v1/l1-transactions/{operationId}'
    || managed.durableNonceJournal !== true || managed.exactSignedBytesArchive !== true
    || managed.independentReceiptEvidence !== true || managed.postFinalityAudit !== true) {
    throw new Error('owner capabilities lack the common durable L1 operation boundary')
  }
  const operations = {}
  for (const [name, expected] of Object.entries(REQUIRED_OWNER_CAPABILITY_OPERATIONS)) {
    const operation = requireObject(managed[name], `managedL1Operations.${name}`)
    if (operation.enabled !== true) {
      throw new Error(`managedL1Operations.${name} is not enabled`)
    }
    for (const [field, value] of Object.entries(expected)) {
      if (canonical(operation[field]) !== canonical(value)) {
        throw new Error(`managedL1Operations.${name}.${field} does not match the release contract`)
      }
    }
    operations[name] = { enabled: true, ...expected }
  }
  const closure = {
    schema: 'zkdeal/4090-owner-durable-capabilities/v1',
    sourceCapabilitiesSha256: sha256(sourceBytes),
    schemaVersion: 1,
    negotiation: {
      header: 'Accept-Schema-Version',
      supported: [1],
      default: 1,
    },
    common: {
      statusEndpoint: managed.statusEndpoint,
      durableNonceJournal: true,
      exactSignedBytesArchive: true,
      independentReceiptEvidence: true,
      postFinalityAudit: true,
    },
    operations,
  }
  await writeJsonExclusive(outputPath, closure)
  return closure
}

export async function validateSettlementScenario(scenarioPath) {
  const scenario = await readJson(scenarioPath)
  if (scenario.schema !== 'zkdeal/4090-physical-settlement-scenario/v2') {
    throw new Error('physical settlement scenario has an unsupported schema')
  }
  const source = requireObject(scenario.sourceClosure, 'sourceClosure')
  if (source.verifiedDeterministicBundle !== true || source.zkvmSubmanifestBound !== true
    || source.repositoryHistoryAllowed !== false
    || !Array.isArray(source.requiredProjects)
    || REQUIRED_SOURCE_PROJECTS.some((project) => !source.requiredProjects.includes(project))) {
    throw new Error('physical scenario does not bind the complete no-history source closure')
  }
  const hosted = requireObject(scenario.hostedBatch, 'hostedBatch')
  const expectedEndpoints = [
    '/hosting/v1/rooms/prepare-batch',
    '/v5/rooms/prove',
    '/v5/rooms/verify',
  ]
  if (hosted.preparedFrom !== 'live-room-engine-state' || hosted.batchInput !== 'BatchInputV5'
    || hosted.fixture !== false || hosted.authorizationMode !== 'VALIDITY_ONLY'
    || hosted.publication !== 'RoomManager.submitBatch'
    || hosted.ownerAcceptanceTokenRequired !== true
    || canonical(hosted.queueEndpoints) !== canonical(expectedEndpoints)) {
    throw new Error('physical scenario does not require the current hosted live BatchInputV5 lineage')
  }
  const publishing = requireObject(scenario.durablePublishing, 'durablePublishing')
  const operations = requireObject(publishing.requiredOperations, 'durablePublishing.requiredOperations')
  if (publishing.ownerManagedOnly !== true || publishing.castEncodingOnly !== true
    || publishing.directBroadcastAllowed !== false
    || publishing.statusEndpoint !== '/hosting/v1/l1-transactions/{operationId}'
    || Object.keys(REQUIRED_DURABLE_OPERATIONS).some((name) =>
      canonical(operations[name]) !== canonical(REQUIRED_DURABLE_OPERATIONS[name]))) {
    throw new Error('physical scenario does not fail closed on every required owner durable L1 operation')
  }
  const deployment = requireObject(scenario.deployment, 'deployment')
  if (deployment.fresh !== true || deployment.runtimeCodeHashesRequired !== true
    || !Array.isArray(deployment.requiredAddressFields)
    || canonical([...deployment.requiredAddressFields].sort(stableCompare))
      !== canonical([...REQUIRED_DEPLOYMENT_ADDRESSES].sort(stableCompare))) {
    throw new Error('physical scenario does not require a fresh complete deployment and code hashes')
  }
  const aggregate = requireObject(scenario.aggregate, 'aggregate')
  if (aggregate.memberCount !== 8 || aggregate.distinctRooms !== true
    || aggregate.singleRecursiveProof !== true || aggregate.maxTransactionBlobs !== 6
    || !Array.isArray(aggregate.members) || aggregate.members.length !== 8) {
    throw new Error('physical scenario must contain one eight-room recursive aggregate with six transaction blobs')
  }
  let nextBlob = 0
  let blobMembers = 0
  let calldataMembers = 0
  const roomIds = new Set()
  for (const [index, member] of aggregate.members.entries()) {
    const roomId = requireCanonicalDecimal(member.roomId, `aggregate.members[${index}].roomId`)
    if (roomIds.has(roomId)) throw new Error(`aggregate room ${roomId} is duplicated`)
    roomIds.add(roomId)
    if (member.availability === 'blob') {
      blobMembers += 1
      if (member.blobStartIndex !== nextBlob || member.blobCount !== 1) {
        throw new Error('aggregate blob members must occupy contiguous one-blob offsets')
      }
      nextBlob += 1
    } else if (member.availability === 'calldata' && member.blobCount === 0) {
      calldataMembers += 1
    } else {
      throw new Error(`aggregate member ${index} has an unsupported availability layout`)
    }
  }
  if (blobMembers !== 6 || calldataMembers !== 2 || nextBlob !== 6) {
    throw new Error('aggregate scenario must contain six blob and two calldata rooms')
  }
  const outcome = requireObject(scenario.expectedAggregateOutcome, 'expectedAggregateOutcome')
  if (outcome.appliedMembers !== 7 || outcome.failedMembers !== 1
    || outcome.failedMemberStateChange !== false
    || outcome.failedMemberChargeFinalization !== false
    || outcome.successfulMemberChargeFinalizations !== 7
    || scenario.preAggregateMutation?.roomId !== outcome.failedRoomId) {
    throw new Error('aggregate scenario does not pin isolated 7+1 partial-success charging')
  }
  const retry = requireObject(scenario.retry, 'retry')
  if (retry.roomId !== outcome.failedRoomId || retry.replayMustFail !== true
    || retry.secondChargeMustNotOccur !== true || retry.freshProofRequired !== true) {
    throw new Error('failed aggregate member does not have a fresh, charge-safe retry contract')
  }
  const sponsorship = requireObject(scenario.sponsorship, 'sponsorship')
  if (sponsorship.distinctPayerAndBeneficiary !== true
    || sponsorship.fundedEvent !== 'SponsoredEscrowFunded'
    || sponsorship.refundRecipient !== 'payer'
    || sponsorship.freshRenewalPriceRequired !== true
    || sponsorship.finalizedCheckpointRequired !== true
    || sponsorship.doubleBillingAllowed !== false) {
    throw new Error('physical scenario lacks the sponsored escrow/refund/renewal boundary')
  }
  const withdrawal = requireObject(scenario.withdrawal, 'withdrawal')
  if (withdrawal.liveHostedValidityOnlyWitness !== true || withdrawal.nonzeroRootRequired !== true
    || withdrawal.realProofRequired !== true || withdrawal.claimRequired !== true
    || withdrawal.replayMustFail !== true) {
    throw new Error('physical scenario lacks a real live-hosted withdrawal claim and replay gate')
  }
  const reorg = requireObject(scenario.reorg, 'reorg')
  if (reorg.preFinalityOrphanRequired !== true || reorg.canonicalRecoveryRequired !== true
    || reorg.finalizedReceiptRequired !== true || reorg.duplicateNonceAllowed !== false
    || reorg.duplicateChargeAllowed !== false) {
    throw new Error('physical scenario lacks pre-finality reorg isolation and canonical recovery')
  }
  const failover = requireObject(scenario.failover, 'failover')
  if (failover.coordinatorPromotion !== true || failover.proverRestart !== true
    || failover.headlessRestart !== true || failover.jobIdentityStable !== true
    || failover.sealedOutputDigestStable !== true) {
    throw new Error('physical scenario lacks durable hosted failover evidence')
  }
  const soak = requireObject(scenario.soak, 'soak')
  const requiredFaults = [
    'headless-restart',
    'prover-restart',
    'coordinator-promotion',
    'indexer-rollback',
    'rpc-split',
    'object-store-restart',
    'database-restart',
    'docker-host-restart-resume',
  ]
  if (!Number.isSafeInteger(soak.durationSeconds) || soak.durationSeconds < 43_200
    || soak.restartSafe !== true || soak.ownerRunnerDigestRequired !== true
    || !Array.isArray(soak.requiredFaults)
    || canonical([...soak.requiredFaults].sort(stableCompare))
      !== canonical([...requiredFaults].sort(stableCompare))) {
    throw new Error('physical scenario lacks the restart-safe 12-hour owner-driven soak')
  }
  const gas = requireObject(scenario.gasEvidence, 'gasEvidence')
  if (gas.realGroth16Verifier !== true || gas.realPointEvaluationPrecompile !== '0x0a'
    || gas.type3BlobTransaction !== true || gas.mockMeasurementsAreReleaseEvidence !== false) {
    throw new Error('physical scenario gas evidence is not qualified real-proof EIP-4844 evidence')
  }
  return {
    valid: true,
    schema: scenario.schema,
    requiredProjects: REQUIRED_SOURCE_PROJECTS.length,
    hostedLiveBatch: true,
    durablePublisherCount: Object.keys(REQUIRED_DURABLE_OPERATIONS).length,
    aggregateMembers: 8,
    transactionBlobs: 6,
    partialSuccess: '7+1',
    soakSeconds: soak.durationSeconds,
  }
}

export async function buildEvidenceClosure(planPath, outputPath) {
  const planBytes = await readFile(planPath)
  const plan = JSON.parse(planBytes.toString('utf8'))
  const root = dirname(planPath)
  const sourceBundleArchiveSha256 = requireSha256(
    plan.sourceBundleArchiveSha256,
    'sourceBundleArchiveSha256',
  )
  const umbrellaSourceManifestSha256 = requireSha256(
    plan.umbrellaSourceManifestSha256,
    'umbrellaSourceManifestSha256',
  )
  const zkvmSourceManifestSha256 = requireSha256(
    plan.zkvmSourceManifestSha256,
    'zkvmSourceManifestSha256',
  )
  const sourceClosureSha256 = requireSha256(
    plan.sourceClosureSha256,
    'sourceClosureSha256',
  )
  const generatedTrustRootClosureSha256 = requireSha256(
    plan.generatedTrustRootClosureSha256,
    'generatedTrustRootClosureSha256',
  )
  const generatedTrustRootPath = safeRelativePath(
    root,
    plan.generatedTrustRootClosure,
    'generatedTrustRootClosure',
  )
  const generatedTrustRootBytes = await readFile(generatedTrustRootPath.path)
  if (sha256(generatedTrustRootBytes) !== generatedTrustRootClosureSha256) {
    throw new Error('generated trust-root closure bytes do not match their declared SHA-256')
  }
  const generatedTrustRoot = JSON.parse(generatedTrustRootBytes.toString('utf8'))
  if (generatedTrustRoot.schema !== 'zkdeal/4090-generated-trust-root-closure/v1'
    || generatedTrustRoot.algorithm !== 'sha256'
    || generatedTrustRoot.buildPreimage?.verifiedAgainstFilesystem !== true
    || generatedTrustRoot.buildPreimage?.generatedOutputsExcluded !== true
    || generatedTrustRoot.orderingContract?.requiredIndependentCudaBuilds !== 2
    || generatedTrustRoot.orderingContract?.postCompositeSealMutationInvalidatesCandidate !== true) {
    throw new Error('generated trust-root closure lacks the non-circular two-build ordering contract')
  }
  const ownerDurableCapabilitiesSha256 = requireSha256(
    plan.ownerDurableCapabilitiesSha256,
    'ownerDurableCapabilitiesSha256',
  )
  if (typeof plan.ownerAcceptanceToken !== 'string'
    || !/^sha256:[0-9a-f]{64}$/.test(plan.ownerAcceptanceToken)) {
    throw new Error('ownerAcceptanceToken must be a final sha256 acceptance token')
  }
  const settlementScenarioSha256 = requireSha256(
    plan.settlementScenarioSha256,
    'settlementScenarioSha256',
  )
  const deploymentAddressesSha256 = requireSha256(
    plan.deploymentAddressesSha256,
    'deploymentAddressesSha256',
  )
  const soakVerificationSha256 = requireSha256(
    plan.soakVerificationSha256,
    'soakVerificationSha256',
  )
  const artifactLockSha256 = requireSha256(plan.artifactLockSha256, 'artifactLockSha256')
  const orchestratorImage = requireImageReference(plan.orchestratorImage, 'orchestratorImage')
  const toolchainImage = requireImageReference(plan.toolchainImage, 'toolchainImage')
  const runtimeImage = requireImageReference(plan.runtimeImage, 'runtimeImage')
  const programId = requireHex32(plan.programId, 'programId')
  if (generatedTrustRoot.buildPreimage?.candidateManifest?.sha256 !== zkvmSourceManifestSha256
    || generatedTrustRoot.generatedTrustRoot?.sourceManifest?.sha256 !== zkvmSourceManifestSha256
    || generatedTrustRoot.generatedTrustRoot?.artifactLock?.sha256 !== artifactLockSha256
    || generatedTrustRoot.stagedImages?.orchestrator !== orchestratorImage
    || generatedTrustRoot.stagedImages?.toolchain !== toolchainImage
    || generatedTrustRoot.stagedImages?.runtime !== runtimeImage
    || generatedTrustRoot.generatedTrustRoot?.toolchainImage !== toolchainImage
    || generatedTrustRoot.generatedTrustRoot?.runtimeImage !== runtimeImage
    || generatedTrustRoot.generatedTrustRoot?.programId !== programId) {
    throw new Error('evidence plan disagrees with the generated trust-root closure')
  }
  if (!Array.isArray(plan.files) || plan.files.length === 0) {
    throw new Error('closure plan files must be a nonempty array')
  }
  const seen = new Set()
  const files = []
  for (const item of plan.files) {
    if (typeof item !== 'string' || item.length === 0 || isAbsolute(item)) {
      throw new Error('closure plan file paths must be nonempty relative paths')
    }
    const path = resolve(root, item)
    const back = relative(root, path)
    if (back === '..' || back.startsWith(`..${sep}`) || isAbsolute(back)) {
      throw new Error(`closure plan path escapes its evidence root: ${item}`)
    }
    const portable = back.split(sep).join('/')
    if (seen.has(portable)) throw new Error(`closure plan file is duplicated: ${portable}`)
    seen.add(portable)
    const bytes = await readFile(path)
    files.push({ path: portable, size: bytes.length, sha256: sha256(bytes) })
  }
  if (!seen.has(generatedTrustRootPath.portable)) {
    throw new Error('closure plan files must include the generated trust-root closure')
  }
  files.sort((left, right) => stableCompare(left.path, right.path))
  const closure = {
    schema: 'zkdeal/4090-evidence-closure/v2',
    algorithm: 'sha256',
    source: {
      bundleArchiveSha256: sourceBundleArchiveSha256,
      umbrellaManifestSha256: umbrellaSourceManifestSha256,
      zkvmManifestSha256: zkvmSourceManifestSha256,
      closureSha256: sourceClosureSha256,
      generatedTrustRootClosureSha256,
    },
    physicalAcceptance: {
      ownerAcceptanceToken: plan.ownerAcceptanceToken,
      ownerDurableCapabilitiesSha256,
      settlementScenarioSha256,
      deploymentAddressesSha256,
      soakVerificationSha256,
    },
    artifactLockSha256,
    orchestratorImage,
    toolchainImage,
    runtimeImage,
    programId,
    planSha256: sha256(planBytes),
    files,
  }
  await writeJsonExclusive(outputPath, closure)
  return closure
}

export async function buildRoomFixture(coldProofPath, roomProofPath, outputPath) {
  const cold = await readJson(coldProofPath)
  const room = await readJson(roomProofPath)
  const coldProgram = requireHex32(cold.programId, 'cold proof programId')
  const roomProgram = requireHex32(room.programId, 'room proof programId')
  if (coldProgram !== roomProgram) throw new Error('cold and room proofs use different programs')
  if (cold.proofMode !== 'groth16' || room.proofMode !== 'groth16' || !room.journal) {
    throw new Error('fixture requires complete Groth16 cold and room proofs')
  }
  if (requireHex32(room.journal.proof_program_id, 'journal proof_program_id') !== roomProgram) {
    throw new Error('room journal is bound to another proof program')
  }
  const fixture = {
    proofSystem: 'risc0-groth16',
    programId: roomProgram,
    journalHash: requireHex32(room.journalHash, 'room proof journalHash'),
    seal: sealHex(room.ethereumSealB64, 'room ethereumSealB64'),
    coldSeal: sealHex(cold.ethereumSealB64, 'cold ethereumSealB64'),
    journal: room.journal,
  }
  await writeJsonExclusive(outputPath, fixture)
  return fixture
}

async function main() {
  const [command, ...args] = process.argv.slice(2)
  if (command === 'source-closure' && args.length === 5) {
    await buildSourceClosure(
      resolve(args[0]),
      resolve(args[1]),
      resolve(args[2]),
      resolve(args[3]),
      resolve(args[4]),
    )
  } else if (command === 'hosted-lineage' && args.length === 2) {
    await buildHostedBatchLineage(resolve(args[0]), resolve(args[1]))
  } else if (command === 'owner-capabilities' && args.length === 2) {
    await buildOwnerDurableCapabilities(resolve(args[0]), resolve(args[1]))
  } else if (command === 'staged-images' && args.length === 5) {
    await buildStagedZkvmImages(args[0], args[1], args[2], args[3], resolve(args[4]))
  } else if (command === 'trust-root-output' && args.length === 3) {
    await buildGeneratedTrustRootClosure(resolve(args[0]), resolve(args[1]), resolve(args[2]))
  } else if (command === 'trust-root-check' && args.length === 3) {
    console.log(JSON.stringify(
      await verifyGeneratedTrustRootClosure(resolve(args[0]), resolve(args[1]), resolve(args[2])),
      null,
      2,
    ))
  } else if (command === 'scenario-check' && args.length === 1) {
    console.log(JSON.stringify(await validateSettlementScenario(resolve(args[0])), null, 2))
  } else if (command === 'room-configs' && args.length === 2) {
    await buildRoomConfigs(resolve(args[0]), resolve(args[1]))
  } else if (command === 'split-prepared' && args.length === 3) {
    await splitPreparedRoom(resolve(args[0]), resolve(args[1]), resolve(args[2]))
  } else if (command === 'da-request' && args.length === 4) {
    await buildDataAvailabilityRequest(
      resolve(args[0]),
      resolve(args[1]),
      Number(args[2]),
      resolve(args[3]),
    )
  } else if (command === 'aggregate-request' && args.length === 2) {
    await buildAggregateRequest(resolve(args[0]), resolve(args[1]))
  } else if (command === 'blob-payload' && args.length === 2) {
    await buildBlobTransactionPayload(resolve(args[0]), resolve(args[1]))
  } else if (command === 'room-fixture' && args.length === 3) {
    await buildRoomFixture(resolve(args[0]), resolve(args[1]), resolve(args[2]))
  } else if (command === 'evidence-closure' && args.length === 2) {
    await buildEvidenceClosure(resolve(args[0]), resolve(args[1]))
  } else {
    throw new Error(
      'usage: build-4090-evidence-requests.mjs source-closure ARCHIVE OUTER VERIFY ' +
        'ZKVM_CANDIDATE OUT | hosted-lineage PLAN OUT | ' +
        'owner-capabilities CAPABILITIES OUT | staged-images CANDIDATE_SHA ' +
        'ORCHESTRATOR TOOLCHAIN RUNTIME OUT | ' +
        'trust-root-output ZKVM_ROOT STAGED_IMAGES OUT | ' +
        'trust-root-check ZKVM_ROOT STAGED_IMAGES CLOSURE | scenario-check SCENARIO | ' +
        'room-configs TEMPLATE OUT_DIR | ' +
        'split-prepared PREPARED COLD_OUT ROOM_OUT | da-request PREPARED ROOM_PROOF ' +
        'BLOB_START OUT | aggregate-request PLAN OUT | blob-payload PLAN OUT | ' +
        'room-fixture COLD_PROOF ROOM_PROOF OUT | evidence-closure PLAN OUT',
    )
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  await main()
}
