import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import {
  CAPABILITY_FORMAT,
  COLD_TEMPLATE_WITNESS_SCHEMA_V5,
  HOST_COMMANDS_V5,
  JOURNAL_VERSION,
  LOCK_ARTIFACTS,
  LOCK_FORMAT,
  ROOM_WITNESS_SCHEMA_V5,
  RUNTIME_COMPATIBILITY,
} from '../lock-schema.mjs'

import {
  buildAggregateRequest,
  buildBlobTransactionPayload,
  buildDataAvailabilityRequest,
  buildEvidenceClosure,
  buildGeneratedTrustRootClosure,
  buildHostedBatchLineage,
  buildOwnerDurableCapabilities,
  buildRoomConfigs,
  buildRoomFixture,
  buildSourceClosure,
  buildStagedZkvmImages,
  splitPreparedRoom,
  validateSettlementScenario,
  verifyGeneratedTrustRootClosure,
} from './build-4090-evidence-requests.mjs'
import {
  SOURCE_ROOTS,
  canonicalManifest,
  collectSourceManifest,
} from './check-lock-freshness.mjs'

const h = (byte) => `0x${byte.repeat(64)}`
const receipt = 'AQ=='
const blob = Buffer.alloc(131072).toString('base64')

async function json(path, value) {
  await writeFile(path, `${JSON.stringify(value)}\n`)
}

async function digest(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex')
}

async function generatedTrustRootFixture(root) {
  for (const source of SOURCE_ROOTS) {
    const path = join(root, source)
    if (basename(source).includes('.')) {
      await mkdir(dirname(path), { recursive: true })
      await writeFile(path, `fixture source ${source}\n`)
    } else {
      await mkdir(path, { recursive: true })
    }
  }
  const manifest = collectSourceManifest(root, SOURCE_ROOTS)
  const manifestBytes = canonicalManifest(manifest)
  await writeFile(join(root, 'source-manifest.candidate.json'), manifestBytes)
  await writeFile(join(root, 'source-manifest.json'), manifestBytes)

  const artifacts = {}
  for (const artifact of LOCK_ARTIFACTS) {
    const path = join(root, artifact)
    await mkdir(dirname(path), { recursive: true })
    await writeFile(path, `fixture artifact ${artifact}\n`)
    artifacts[artifact] = { sha256: await digest(path) }
  }
  const imageDigest = '1'.repeat(64)
  const runtimeDigest = '2'.repeat(64)
  const imageId = '3'.repeat(64)
  const lock = {
    format: LOCK_FORMAT,
    journalVersion: JOURNAL_VERSION,
    runtimeCompatibility: RUNTIME_COMPATIBILITY,
    sourceManifestSha256: createHash('sha256').update(manifestBytes).digest('hex'),
    witnessSchemas: {
      room: ROOM_WITNESS_SCHEMA_V5,
      coldTemplate: COLD_TEMPLATE_WITNESS_SCHEMA_V5,
    },
    toolchain: {
      image: `registry.example/zkdeal/toolchain@sha256:${imageDigest}`,
      digest: `sha256:${imageDigest}`,
      rust: '1.88.0',
      riscZero: { crates: '3.0.6', rustToolchain: '1.91.1', groth16: '0.1.0' },
      wasmPack: '0.13.1',
      risc0HomeTreeSha256: '4'.repeat(64),
    },
    runtime: {
      image: `registry.example/zkdeal/runtime@sha256:${runtimeDigest}`,
      digest: `sha256:${runtimeDigest}`,
      cudaRequired: true,
      cpuFallback: false,
      hostBinarySha256: '5'.repeat(64),
    },
    risc0: {
      imageId,
      programId: `0x${imageId}`,
      containerDigest: `sha256:${runtimeDigest}`,
      cudaRequired: true,
      cpuFallback: false,
      ethereumSeal: true,
      commands: [...HOST_COMMANDS_V5],
      capabilityFormat: CAPABILITY_FORMAT,
      compactStateModel: 'full-room-state-v1',
    },
    artifacts,
  }
  await json(join(root, 'artifacts.lock.json'), lock)
  const stagedImagesPath = join(root, 'staged-images.json')
  await buildStagedZkvmImages(
    lock.sourceManifestSha256,
    `registry.example/zkdeal/orchestrator@sha256:${'6'.repeat(64)}`,
    lock.toolchain.image,
    lock.runtime.image,
    stagedImagesPath,
  )
  return { lock, manifest, manifestBytes, stagedImagesPath }
}

test('source closure binds the exact umbrella archive and cross-project critical inputs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-source-'))
  const archive = join(root, 'zkdeal-source.tar.gz')
  const outerPath = `${archive}.manifest.json`
  const verificationPath = join(root, 'verified.json')
  const candidatePath = join(root, 'source-manifest.candidate.json')
  const output = join(root, 'closure.json')
  await writeFile(archive, Buffer.from('deterministic source fixture'))
  await json(candidatePath, {
    format: 'zkdeal/zkvm-source-manifest/v1', algorithm: 'sha256',
    sourceRoots: ['Cargo.toml'], filesDigest: 'a'.repeat(64),
    files: [{ path: 'Cargo.toml', size: 1, sha256: 'b'.repeat(64), executable: false }],
  })
  const projects = [
    'app-node', 'apps-examples', 'web2-api', 'web3-protocol',
    'prover-node', 'kurtosis-testing', 'cloud-deployer-infra',
  ]
  const criticalPaths = [
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
  const archiveSha256 = await digest(archive)
  await json(outerPath, {
    schemaVersion: 1, format: 'zkdeal-source-bundle', historyIncluded: false,
    secretsIncluded: false, archive: 'zkdeal-source.tar.gz',
    archiveBytes: (await stat(archive)).size, archiveSha256, fileCount: 100,
    totalBytes: 12345, projects,
  })
  const candidateSha256 = await digest(candidatePath)
  const criticalSourceBindings = Object.fromEntries(criticalPaths.map((path) => [
    path,
    {
      sha256: path.includes('source-manifest.candidate') ? candidateSha256 : 'c'.repeat(64),
      bytes: path.includes('source-manifest.candidate') ? 0 : 123,
      mode: 0o644,
    },
  ]))
  criticalSourceBindings['prover-node/zkvm/source-manifest.candidate.json'].bytes =
    (await stat(candidatePath)).size
  await json(verificationPath, {
    verified: true, format: 'zkdeal-source-bundle', historyIncluded: false,
    secretsIncluded: false, archiveSha256,
    outerManifestSha256: await digest(outerPath), embeddedManifestSha256: 'd'.repeat(64),
    entriesSha256: 'e'.repeat(64), files: 100, bytes: 12345, projects,
    criticalSourceBindings,
  })
  const closure = await buildSourceClosure(
    archive, outerPath, verificationPath, candidatePath, output,
  )
  assert.equal(closure.archive.sha256, archiveSha256)
  assert.equal(closure.zkvmCandidateManifest.sha256, candidateSha256)
  assert.equal(closure.requiredProjects.length, 5)
})

test('generated trust-root closure binds the immutable preimage and every write-once output', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-trust-root-'))
  const { lock, stagedImagesPath } = await generatedTrustRootFixture(root)
  const output = join(root, 'generated-trust-root-closure.json')
  const closure = await buildGeneratedTrustRootClosure(root, stagedImagesPath, output)
  assert.equal(closure.schema, 'zkdeal/4090-generated-trust-root-closure/v1')
  assert.equal(closure.buildPreimage.verifiedAgainstFilesystem, true)
  assert.equal(closure.buildPreimage.generatedOutputsExcluded, true)
  assert.equal(closure.generatedTrustRoot.programId, lock.risc0.programId)
  assert.equal(closure.generatedTrustRoot.lockedArtifacts.length, LOCK_ARTIFACTS.length)
  assert.equal(closure.stagedImages.toolchain, lock.toolchain.image)
  assert.equal(closure.stagedImages.promoted, false)
  assert.equal(closure.orderingContract.requiredIndependentCudaBuilds, 2)
  assert.equal(
    (await verifyGeneratedTrustRootClosure(root, stagedImagesPath, output)).verified,
    true,
  )
  await assert.rejects(
    buildGeneratedTrustRootClosure(root, stagedImagesPath, output),
    /exist/i,
  )

  const promotedReceipt = join(root, 'staged-images-promoted.json')
  const promoted = JSON.parse(await readFile(stagedImagesPath, 'utf8'))
  promoted.promoted = true
  await json(promotedReceipt, promoted)
  await assert.rejects(
    verifyGeneratedTrustRootClosure(root, promotedReceipt, output),
    /unpromoted sealed candidate/i,
  )

  const changed = join(root, LOCK_ARTIFACTS[0])
  await writeFile(changed, 'post-seal mutation\n')
  await assert.rejects(
    verifyGeneratedTrustRootClosure(root, stagedImagesPath, output),
    /locked artifact|differs from the current/i,
  )
})

test('hosted lineage binds live preparation, durable prove/verify bytes, and finalized owner publication', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-hosted-'))
  const paths = Object.fromEntries(
    ['prepare-request', 'prepare-result', 'prove-request', 'prove-result', 'verify-request', 'verify-result', 'owner']
      .map((name) => [name, join(root, `${name}.json`)]),
  )
  const roomId = '7'
  const programId = h('1')
  const journalHash = h('2')
  const journal = { room_id: 7, batch_index: 1 }
  const proofRequest = {
    roomWitnessB64: 'AQ==', inputDigest: `0x${'3'.repeat(64)}`,
    jobId: 'room-witness-job', proofMode: 'groth16', production: true,
  }
  const provisionalJournal = {
    protocolVersion: 6, roomId: 7, admissionCursorBefore: 10, admissionCursorAfter: 11,
  }
  await json(paths['prepare-request'], {
    schemaVersion: 1, production: true, proofMode: 'groth16',
    opening: { roomId: 7, authorizationMode: 1 },
  })
  await json(paths['prepare-result'], {
    schemaVersion: 1, fixture: false, preparedFrom: 'live-room-engine-state',
    programId, journalHash, journal, prepareArtifactDigest: '3'.repeat(64),
    contentAddress: '3'.repeat(64), roomWitnessB64: 'AQ==', proofRequest,
    provisionalSubmission: {
      journal: provisionalJournal, seal: '0x', approvals: [], approverChanges: [], admissions: [{}],
    },
  })
  await json(paths['prove-request'], proofRequest)
  const proved = {
    backendId: 'risc0', proofMode: 'groth16', inputDigest: proofRequest.inputDigest,
    jobId: proofRequest.jobId, programId, journalHash, journal,
    receiptB64: 'Ag==', ethereumSealB64: 'Aw==', imageId: programId,
  }
  await json(paths['prove-result'], proved)
  await json(paths['verify-request'], { journal, journalHash, receiptB64: proved.receiptB64 })
  await json(paths['verify-result'], {
    ok: true, proofMode: 'groth16', journalHash, journal,
    ethereumSealB64: proved.ethereumSealB64, imageId: programId,
  })
  const correlationId = 'room-7-batch-lineage'
  const jobIds = {
    prepare: `pj-${'1'.repeat(20)}`,
    prove: `pj-${'2'.repeat(20)}`,
    verify: `pj-${'3'.repeat(20)}`,
  }
  const resultDigests = {
    prepare: await digest(paths['prepare-result']),
    prove: await digest(paths['prove-result']),
    verify: await digest(paths['verify-result']),
  }
  const roomManager = `0x${'44'.repeat(20)}`
  const operations = `0x${'55'.repeat(20)}`
  await json(paths.owner, {
    operationId: 'l1op-room-7', status: 'FINALIZED', finalized: true,
    chainId: 31337, correlationId, to: roomManager, from: operations,
    txHash: h('6'), blockNumber: '100', blockHash: h('7'), confirmations: 12,
    receiptSource: { providerIds: ['rpc-a', 'rpc-b'], observedAt: '2026-08-21T00:00:00.000Z', canonical: true },
    binding: {
      roomId, correlationId,
      prepareJobId: jobIds.prepare, prepareResultDigest: resultDigests.prepare,
      prepareArtifactDigest: '3'.repeat(64),
      proveJobId: jobIds.prove, proveResultDigest: resultDigests.prove,
      verifyJobId: jobIds.verify, verifyResultDigest: resultDigests.verify,
      journalHash, calldataHash: h('8'), admissionIds: ['11'],
      confirmationPolicy: { minimumConfirmations: 2, requireFinalized: true },
    },
  })
  const planPath = join(root, 'plan.json')
  await json(planPath, {
    schema: 'zkdeal/4090-hosted-batch-lineage-plan/v1', publicationMode: 'owner-finalized',
    roomId, correlationId,
    chainId: 31337, roomManager, expectedOperationsAccount: operations,
    minimumConfirmations: 2, admissionIds: ['11'],
    jobs: {
      prepare: { endpoint: '/hosting/v1/rooms/prepare-batch', jobId: jobIds.prepare, resultDigest: resultDigests.prepare, request: 'prepare-request.json', result: 'prepare-result.json' },
      prove: { endpoint: '/v5/rooms/prove', jobId: jobIds.prove, resultDigest: resultDigests.prove, request: 'prove-request.json', result: 'prove-result.json' },
      verify: { endpoint: '/v5/rooms/verify', jobId: jobIds.verify, resultDigest: resultDigests.verify, request: 'verify-request.json', result: 'verify-result.json' },
    },
    ownerOperation: 'owner.json',
  })
  const lineage = await buildHostedBatchLineage(planPath, join(root, 'lineage.json'))
  assert.equal(lineage.preparedFrom, 'live-room-engine-state')
  assert.equal(lineage.publication.txHash, h('6'))
  assert.equal(lineage.admissionIds[0], '11')

  const pendingPlan = JSON.parse(await readFile(planPath, 'utf8'))
  pendingPlan.publicationMode = 'aggregate-pending'
  delete pendingPlan.ownerOperation
  const pendingPlanPath = join(root, 'pending-plan.json')
  await json(pendingPlanPath, pendingPlan)
  const pending = await buildHostedBatchLineage(pendingPlanPath, join(root, 'pending-lineage.json'))
  assert.equal(pending.publication.mode, 'aggregate-pending')
})

test('physical settlement scenario pins live hosting, 6+2 aggregate, faults, and 12-hour resume', async () => {
  const scenario = fileURLToPath(new URL('../docker/release-settlement-scenario.json', import.meta.url))
  const result = await validateSettlementScenario(scenario)
  assert.equal(result.valid, true)
  assert.equal(result.partialSuccess, '7+1')
  assert.equal(result.durablePublisherCount, 7)
  assert.equal(result.soakSeconds, 43_200)
})

test('owner capability closure fails closed until every durable L1 publisher is enabled', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-owner-capabilities-'))
  const capabilities = {
    schemaVersion: 1,
    negotiation: { header: 'Accept-Schema-Version', supported: [1], default: 1 },
    managedL1Operations: {
      statusEndpoint: '/hosting/v1/l1-transactions/{operationId}',
      durableNonceJournal: true,
      exactSignedBytesArchive: true,
      independentReceiptEvidence: true,
      postFinalityAudit: true,
      roomBatch: { enabled: true, endpoint: '/hosting/v1/l1-operations/room-batches', selector: '0x62dad01b' },
      roomAggregate: { enabled: true, endpoint: '/hosting/v1/l1-operations/room-aggregates', selector: '0x5e8b37ac' },
      withdrawalClaim: { enabled: true, endpoint: '/hosting/v1/withdrawals/{roomId}/{epoch}/{withdrawalIndex}/claims', selector: '0xb051a9f8' },
      poolSponsorMutation: {
        enabled: true,
        endpoint: '/hosting/v1/l1-operations/pool-sponsor-mutations',
        selectors: {
          reserveAndStartForWithDataAvailabilityWithPermit: '0x827ac259',
          renewRoomForWithPermit: '0xf180fe5d',
        },
        senderAuthority: 'sponsor',
      },
      poolFinalizedCheckpoint: { enabled: true, endpoint: '/hosting/v1/l1-operations/pool-finalized-checkpoints', selector: '0xe19bc67e', senderAuthority: 'finality-oracle' },
      poolBeneficiaryDisposal: { enabled: true, endpoint: '/hosting/v1/l1-operations/pool-beneficiary-disposals', selector: '0xed97f11a', senderAuthority: 'beneficiary' },
    },
  }
  const source = join(root, 'capabilities.json')
  await json(source, capabilities)
  const closure = await buildOwnerDurableCapabilities(source, join(root, 'closure.json'))
  assert.equal(closure.schema, 'zkdeal/4090-owner-durable-capabilities/v1')
  assert.equal(Object.keys(closure.operations).length, 6)
  assert.equal(closure.sourceCapabilitiesSha256, await digest(source))

  capabilities.managedL1Operations.roomAggregate.enabled = false
  const disabled = join(root, 'disabled.json')
  await json(disabled, capabilities)
  await assert.rejects(
    buildOwnerDurableCapabilities(disabled, join(root, 'disabled-closure.json')),
    /roomAggregate is not enabled/,
  )
})

test('physical scenario rejects direct broadcasting or a missing durable selector', async () => {
  const source = fileURLToPath(new URL('../docker/release-settlement-scenario.json', import.meta.url))
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-publishers-'))
  const scenario = JSON.parse(await readFile(source, 'utf8'))
  scenario.durablePublishing.directBroadcastAllowed = true
  const direct = join(root, 'direct.json')
  await json(direct, scenario)
  await assert.rejects(validateSettlementScenario(direct), /owner durable L1 operation/i)

  scenario.durablePublishing.directBroadcastAllowed = false
  delete scenario.durablePublishing.requiredOperations.beneficiaryDisposal
  const missing = join(root, 'missing.json')
  await json(missing, scenario)
  await assert.rejects(validateSettlementScenario(missing), /owner durable L1 operation/i)
})

test('release room inputs are eight distinct write-once documents', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-room-'))
  const template = join(root, 'template.json')
  await json(template, { deploymentDomain: h('1'), roomId: 99 })
  const paths = await buildRoomConfigs(template, join(root, 'rooms'))
  assert.equal(paths.length, 8)
  assert.equal(JSON.parse(await readFile(paths[7], 'utf8')).roomId, 8)
  await assert.rejects(buildRoomConfigs(template, join(root, 'rooms')), /exist/i)
})

test('DA request binds canonical room bytes, journal, room and blob offset', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-da-'))
  const prepared = join(root, 'prepared.json')
  const proof = join(root, 'proof.json')
  const output = join(root, 'da.json')
  await json(prepared, { roomRequest: { roomWitness: { canonical_batch_data: '0x0102' } } })
  await json(proof, {
    journalHash: h('2'),
    journal: { deployment_domain: h('1'), room_id: 7 },
  })
  const request = await buildDataAvailabilityRequest(prepared, proof, 3, output)
  assert.equal(request.equivalenceWitness.canonicalData, '0x0102')
  assert.equal(request.equivalenceWitness.blobStartIndex, 3)
})

test('DA request consumes canonical bytes from a production live prepare result', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-live-da-'))
  const prepared = join(root, 'prepared.json')
  const proof = join(root, 'proof.json')
  await json(prepared, {
    fixture: false,
    preparedFrom: 'live-room-engine-state',
    provisionalSubmission: { canonicalBatchData: '0x0304' },
  })
  await json(proof, {
    journalHash: h('2'),
    journal: { deployment_domain: h('1'), room_id: 8 },
  })
  const request = await buildDataAvailabilityRequest(
    prepared, proof, 5, join(root, 'da.json'),
  )
  assert.equal(request.equivalenceWitness.canonicalData, '0x0304')
})

test('prepared output splits into exact write-once proof requests', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-split-'))
  const prepared = join(root, 'prepared.json')
  const cold = join(root, 'cold.json')
  const room = join(root, 'room.json')
  await json(prepared, {
    coldRequest: { coldTemplateWitness: { templateId: h('1') }, production: true },
    roomRequest: { roomWitness: { journal: { room_id: 1 } }, production: true },
  })
  await splitPreparedRoom(prepared, cold, room)
  assert.equal(JSON.parse(await readFile(cold, 'utf8')).production, true)
  assert.equal(JSON.parse(await readFile(room, 'utf8')).roomWitness.journal.room_id, 1)
  await assert.rejects(splitPreparedRoom(prepared, cold, room), /exist/i)
})

test('aggregate request enforces eight distinct members and a contiguous six-blob layout', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-aggregate-'))
  const members = []
  for (let index = 0; index < 8; index += 1) {
    const roomProof = `room-${index + 1}.json`
    await json(join(root, roomProof), {
      programId: h('2'),
      journalHash: h(String((index + 3) % 10)),
      receiptB64: receipt,
      journal: { deployment_domain: h('1'), room_id: index + 1 },
    })
    const entry = { kind: index < 6 ? 'blob' : 'calldata', roomProof }
    if (index < 6) {
      const dataAvailabilityProof = `da-${index + 1}.json`
      await json(join(root, dataAvailabilityProof), {
        programId: h('9'),
        statement: h(String((index + 1) % 10)),
        receiptB64: receipt,
        proofMode: 'groth16',
        blobsB64: [blob],
        equivalenceWitness: { roomId: index + 1, journalHash: h(String((index + 3) % 10)) },
        dataAvailabilityManifest: {
          blobStartIndex: index,
          blobVersionedHashes: [h('a')],
          commitments: [`0x${'44'.repeat(48)}`],
          evaluationPoints: [h('5')],
          evaluations: [h('6')],
          kzgProofs: [`0x${'77'.repeat(48)}`],
          equivalenceSeal: '0x01',
        },
      })
      entry.dataAvailabilityProof = dataAvailabilityProof
    }
    members.push(entry)
  }
  const plan = join(root, 'plan.json')
  await json(plan, { requireMaxTransactionBlobs: true, members })
  const request = await buildAggregateRequest(plan, join(root, 'aggregate.json'))
  assert.equal(request.aggregateWitness.members.length, 8)
  assert.equal(request.memberReceipts.filter((item) => item.equivalenceReceiptB64).length, 6)
  const blobPayload = join(root, 'aggregate-blobs.bin')
  const payload = await buildBlobTransactionPayload(plan, blobPayload)
  assert.equal(payload.blobCount, 6)
  assert.equal((await stat(blobPayload)).size, 6 * 131072)

  const drift = JSON.parse(await readFile(join(root, 'da-6.json'), 'utf8'))
  drift.dataAvailabilityManifest.blobStartIndex = 4
  await json(join(root, 'da-drift.json'), drift)
  members[5].dataAvailabilityProof = 'da-drift.json'
  await json(join(root, 'drift-plan.json'), { requireMaxTransactionBlobs: true, members })
  await assert.rejects(
    buildAggregateRequest(join(root, 'drift-plan.json'), join(root, 'bad.json')),
    /starts at/,
  )
})

test('evidence closure is deterministic, write-once and bound to immutable release inputs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-closure-'))
  await writeFile(join(root, 'proof.json'), '{"ok":true}\n')
  await writeFile(join(root, 'receipt.json'), '{"gasUsed":123}\n')
  const orchestratorImage = `registry.example/zkdeal/orchestrator@sha256:${'d'.repeat(64)}`
  const toolchainImage = `registry.example/zkdeal/toolchain@sha256:${'e'.repeat(64)}`
  const runtimeImage = `registry.example/zkdeal/prover@sha256:${'a'.repeat(64)}`
  const generatedTrustRoot = join(root, 'generated-trust-root.json')
  await json(generatedTrustRoot, {
    schema: 'zkdeal/4090-generated-trust-root-closure/v1',
    algorithm: 'sha256',
    buildPreimage: {
      candidateManifest: { sha256: '3'.repeat(64) },
      verifiedAgainstFilesystem: true,
      generatedOutputsExcluded: true,
    },
    stagedImages: {
      orchestrator: orchestratorImage,
      toolchain: toolchainImage,
      runtime: runtimeImage,
    },
    generatedTrustRoot: {
      sourceManifest: { sha256: '3'.repeat(64) },
      artifactLock: { sha256: '9'.repeat(64) },
      toolchainImage,
      runtimeImage,
      programId: h('b'),
    },
    orderingContract: {
      requiredIndependentCudaBuilds: 2,
      postCompositeSealMutationInvalidatesCandidate: true,
    },
  })
  const plan = join(root, 'closure-plan.json')
  await json(plan, {
    sourceBundleArchiveSha256: '1'.repeat(64),
    umbrellaSourceManifestSha256: '2'.repeat(64),
    zkvmSourceManifestSha256: '3'.repeat(64),
    sourceClosureSha256: '4'.repeat(64),
    generatedTrustRootClosure: 'generated-trust-root.json',
    generatedTrustRootClosureSha256: await digest(generatedTrustRoot),
    ownerDurableCapabilitiesSha256: 'c'.repeat(64),
    ownerAcceptanceToken: `sha256:${'5'.repeat(64)}`,
    settlementScenarioSha256: '6'.repeat(64),
    deploymentAddressesSha256: '7'.repeat(64),
    soakVerificationSha256: '8'.repeat(64),
    artifactLockSha256: '9'.repeat(64),
    orchestratorImage,
    toolchainImage,
    runtimeImage,
    programId: h('b'),
    files: ['receipt.json', 'proof.json', 'generated-trust-root.json'],
  })
  const output = join(root, 'closure.json')
  const closure = await buildEvidenceClosure(plan, output)
  assert.equal(closure.schema, 'zkdeal/4090-evidence-closure/v2')
  assert.equal(closure.source.bundleArchiveSha256, '1'.repeat(64))
  assert.equal(
    closure.source.generatedTrustRootClosureSha256,
    await digest(generatedTrustRoot),
  )
  assert.equal(closure.physicalAcceptance.ownerDurableCapabilitiesSha256, 'c'.repeat(64))
  assert.deepEqual(
    closure.files.map((item) => item.path),
    ['generated-trust-root.json', 'proof.json', 'receipt.json'],
  )
  assert.equal(closure.files[0].sha256.length, 64)
  await assert.rejects(buildEvidenceClosure(plan, output), /exist/i)
})

test('room fixture requires matching Groth16 programs and emits nonempty hex seals', async () => {
  const root = await mkdtemp(join(tmpdir(), 'zkdeal-4090-fixture-'))
  const cold = join(root, 'cold.json')
  const room = join(root, 'room.json')
  await json(cold, { programId: h('2'), proofMode: 'groth16', ethereumSealB64: 'AQI=' })
  await json(room, {
    programId: h('2'),
    proofMode: 'groth16',
    ethereumSealB64: 'AwQ=',
    journalHash: h('3'),
    journal: { proof_program_id: h('2') },
  })
  const fixture = await buildRoomFixture(cold, room, join(root, 'fixture.json'))
  assert.equal(fixture.coldSeal, '0x0102')
  assert.equal(fixture.seal, '0x0304')
})
