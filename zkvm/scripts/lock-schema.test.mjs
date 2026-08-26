// Unit coverage for the zkVM trust-root schema shared by `zkvm/build.mjs` and
// the hosted-CI checker. Run with:
//   node --test zkvm/scripts/lock-schema.test.mjs
//
// These are the only tests that can run off the GPU runner: deriving a real
// image ID needs the risc0 toolchain and a CUDA device, so the container-facing
// half of build.mjs is exercised only by .github/workflows/gpu-ci.yml.

import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CAPABILITY_FORMAT,
  CLIENT_VERIFIER_DISABLED_COMMANDS_V5,
  CLIENT_VERIFIER_REFUSAL_V5,
  clientVerifierRefusalScript,
  COLD_TEMPLATE_WITNESS_SCHEMA_V5,
  HOST_COMMANDS_V5,
  JOURNAL_VERSION,
  LOCK_ARTIFACTS,
  LOCK_FORMAT,
  ROOM_WITNESS_SCHEMA_V5,
  RUNTIME_COMPATIBILITY,
  TOOLCHAIN_VERSIONS_FORMAT,
  TOOLCHAIN_VERSIONS_PATH,
  assertCapabilitiesV5,
  assertToolchainVersions,
  fixtureProofProgramId,
  immutableImageDigest,
  programIdToImageId,
  validateLockShape,
} from '../lock-schema.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const zkvmRoot = resolve(here, '..')
const repoRoot = resolve(zkvmRoot, '..')
const hostSrc = join(zkvmRoot, 'crates', 'risc0', 'host', 'src')

/**
 * The whole host crate source, concatenated. These assertions pin the *contract*
 * the host serves (command names, refusal sentence, capability payload), not the
 * file it happens to live in — `cmd_capabilities` and friends have already moved
 * out of main.rs once, and pinning a single path turns a refactor into a red test
 * while a genuine contract change stays green.
 */
function hostSource(dir = hostSrc) {
  let out = ''
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out += hostSource(full)
    else if (entry.name.endsWith('.rs')) out += `${readFileSync(full, 'utf8')}\n`
  }
  return out
}
const dockerfile = join(zkvmRoot, 'docker', 'risc0-cuda.Dockerfile')

const IMAGE_ID = 'a'.repeat(64)
const TOOLCHAIN = `registry.example/zkdeal-toolchain@sha256:${'1'.repeat(64)}`
const RUNTIME = `registry.example/zkdeal-runtime@sha256:${'2'.repeat(64)}`

test('release cache scope isolates both reproducibility volume pairs', () => {
  const scope = 'a'.repeat(64)
  const script = `
    const config = await import('./build-config.mjs');
    const execution = await import('./build-exec.mjs');
    const args = execution.containerArgs('true');
    process.stdout.write(JSON.stringify({ repro: config.REPRO_VOLUMES, args }));
  `
  const result = spawnSync(
    process.execPath,
    ['--input-type=module', '-e', script, '--', 'release-cache-test', '--skip-rust'],
    {
      cwd: zkvmRoot,
      env: { ...process.env, ZKDEAL_BUILD_CACHE_SCOPE: scope },
      encoding: 'utf8',
    },
  )
  assert.equal(result.status, 0, result.stderr)
  const observed = JSON.parse(result.stdout)
  assert.deepEqual(observed.repro, {
    targetVolume: `zkdeal-zkvm-target-repro-${scope}`,
    registryVolume: `zkdeal-zkvm-cargo-registry-repro-${scope}`,
  })
  assert.ok(observed.args.includes(`zkdeal-zkvm-target-${scope}:/ztarget`))
  assert.ok(observed.args.includes(`zkdeal-zkvm-cargo-registry-${scope}:/opt/cargo/registry`))
})

/** Exactly what `cmd_capabilities()` emits for a production CUDA build. */
function v5Capability(overrides = {}) {
  return {
    protocolVersion: 6,
    protocolVersions: [6],
    evmFork: 'osaka',
    imageId: IMAGE_ID,
    programId: `0x${IMAGE_ID}`,
    backendId: 'risc0',
    cudaCompiled: true,
    cuda: true,
    productionCompiled: true,
    cpuFallback: false,
    clientVerifierOnly: false,
    provingAvailable: true,
    executionAvailable: true,
    verificationAvailable: true,
    risc0Version: '3.0.6',
    containerDigest: `sha256:${'2'.repeat(64)}`,
    proofModes: ['succinct', 'groth16'],
    ethereumSeal: true,
    coldTemplateProof: true,
    receiptComposition: 'risc0-assumption-v1',
    preparedStateRefresh: 'authenticated-envelope-v1',
    maxBatchBlocks: 4,
    settlementDerivation: 'guest-exit-program-v1',
    genesisAnchor: 'header-rlp-v1',
    inboxApplication: 'guest-inbox-v1',
    compactStateModel: 'full-room-state-v1',
    dataAvailabilityEquivalence: {
      available: true,
      maxBlobs: 6,
      canonicalBytesPerBlob: 126976,
      preparesCompleteContractManifest: true,
      manifestBlobStartIndex: true,
      aggregateBlobLayout: 'contiguous-member-order-exact-transaction-v1',
      maxTransactionBlobs: 6,
      bundleBuilder: 'c-kzg-2.1.8',
      commitmentBytes: 48,
      proofBytes: 48,
      pointEvaluationInputBytes: 192,
      pointEvaluationPrecompile: '0x0a',
    },
    recursiveAggregate: {
      available: true,
      maxRooms: 8,
      distinctRoomsRequired: true,
      blobRangesBoundByMemberStatement: true,
    },
    withdrawalCommitment: { available: true },
    roomCapabilities: [
      'v5.coldState.perContractRuntime',
      'v5.participantRegistry.configurableSlots',
      'v5.participantRegistry.emptyOpen',
      'v5.participants.multiTouch',
      'v5.policy.perContractCallRules',
      'v5.workload.card-duel',
    ],
    ...overrides,
  }
}

/** A lock exactly as `writeLock` mints it. */
function v5Lock(overrides = {}) {
  return {
    format: LOCK_FORMAT,
    note: 'Reviewed v6-only zkVM trust root.',
    journalVersion: JOURNAL_VERSION,
    runtimeCompatibility: RUNTIME_COMPATIBILITY,
    sourceManifestSha256: '6'.repeat(64),
    witnessSchemas: {
      room: ROOM_WITNESS_SCHEMA_V5,
      coldTemplate: COLD_TEMPLATE_WITNESS_SCHEMA_V5,
    },
    toolchain: {
      image: TOOLCHAIN,
      digest: `sha256:${'1'.repeat(64)}`,
      rust: '1.88.0',
      riscZero: { crates: '3.0.6', rustToolchain: '1.91.1', groth16: '0.1.0' },
      wasmPack: '0.13.1',
      risc0HomeTreeSha256: '4'.repeat(64),
    },
    runtime: {
      image: RUNTIME,
      digest: `sha256:${'2'.repeat(64)}`,
      cudaRequired: true,
      cpuFallback: false,
      hostBinarySha256: '5'.repeat(64),
    },
    risc0: {
      imageId: IMAGE_ID,
      programId: `0x${IMAGE_ID}`,
      containerDigest: `sha256:${'2'.repeat(64)}`,
      cudaRequired: true,
      cpuFallback: false,
      ethereumSeal: true,
      commands: [...HOST_COMMANDS_V5],
      capabilityFormat: CAPABILITY_FORMAT,
      compactStateModel: 'full-room-state-v1',
    },
    artifacts: Object.fromEntries(
      LOCK_ARTIFACTS.map((relative) => [relative, { sha256: '0'.repeat(64) }]),
    ),
    ...overrides,
  }
}

test('a freshly minted v6 lock validates', () => {
  validateLockShape(v5Lock())
})

test('the retired v5 lock shape is rejected', () => {
  // A breaking journal/witness change cannot inherit the previously minted
  // protocol-v5 trust root. Only a reproducible GPU build may mint its v6
  // replacement.
  const committed = JSON.parse(readFileSync(join(zkvmRoot, 'artifacts.lock.json'), 'utf8'))
  assert.throws(() => validateLockShape(committed), /lock format/)

  assert.throws(
    () => validateLockShape(v5Lock({ journalVersion: 5 })),
    /must pin journalVersion 6/,
  )
  assert.throws(
    () => validateLockShape(v5Lock({ runtimeCompatibility: 'v5-only' })),
    /must be v6-only/,
  )
})

test('v4 witness schema pins are rejected', () => {
  assert.throws(
    () =>
      validateLockShape(
        v5Lock({
          witnessSchemas: {
            genesis: 'GenesisWitnessV4/header-rlp-v1/full-room-state-v1',
            batch: 'BatchWitnessV4/previous-exit-allocation-v1/guest-exit-program-v1/full-room-state-v1',
          },
        }),
      ),
    /BatchInputV5 room witness schema/,
  )
})

test('the lock command surface must be exactly the v5 dispatch table', () => {
  const lock = v5Lock()
  lock.risc0.commands = [
    'execute-genesis-v4',
    'prove-genesis-v4',
    'verify-genesis-v4',
    'execute-batch-v4',
    'prove-batch-v4',
    'verify-batch-v4',
    'serve-v4',
  ]
  assert.throws(() => validateLockShape(lock), /command surface differs/)

  const missing = v5Lock()
  missing.risc0.commands = HOST_COMMANDS_V5.filter((c) => c !== 'prove-room-v5')
  assert.throws(() => validateLockShape(missing), /command surface differs/)
})

test('every pinned command is a real subcommand of the v5 host', () => {
  const source = hostSource()
  for (const command of HOST_COMMANDS_V5) {
    assert.ok(
      source.includes(`"${command}"`),
      `${command} does not appear as a match arm in crates/risc0/host/src`,
    )
  }
  for (const command of CLIENT_VERIFIER_DISABLED_COMMANDS_V5) {
    assert.ok(
      HOST_COMMANDS_V5.includes(command),
      `${command} is gated in the client build but absent from the pinned command surface`,
    )
  }
})

test('every dispatched subcommand is pinned: dispatch table and lock surface are set-equal', () => {
  // Reverse direction of the test above, which only proves pinned=>dispatched.
  // `prepare-live-room-batch` shipped dispatched, advertised and served while
  // absent from HOST_COMMANDS_V5 because nothing checked dispatched=>pinned.
  // A quoted token counts as a dispatch arm when `|` or `=>` follows it
  // (possibly across lines): that shape captures the outer `run()` match, its
  // inner delegating matches and the client-verifier gate -- all of which name
  // only real subcommands -- and skips JSON keys, error strings and the
  // "help"/unknown-command fallbacks, which never appear in arm position.
  const source = readFileSync(join(hostSrc, 'main.rs'), 'utf8')
  const dispatched = new Set()
  for (const match of source.matchAll(/"([a-z0-9][a-z0-9-]*)"(?=\s*(?:\||=>))/g)) {
    dispatched.add(match[1])
  }
  assert.deepEqual([...dispatched].sort(), [...HOST_COMMANDS_V5].sort())
})

test('the artifact set is the single source of truth and pins every tracked fixture', () => {
  assert.equal(new Set(LOCK_ARTIFACTS).size, LOCK_ARTIFACTS.length)
  // Regression for the committed lock that omitted the terminal-close witness
  // while the parity suite replayed it: it must be pinned.
  assert.ok(LOCK_ARTIFACTS.includes('fixtures/amm-terminal-close-v4.json'))
  assert.ok(LOCK_ARTIFACTS.includes('fixtures/amm-certified-v4.json'))
  assert.ok(LOCK_ARTIFACTS.includes('build/risc0/capabilities-v6.json'))

  const short = v5Lock()
  delete short.artifacts['fixtures/amm-terminal-close-v4.json']
  assert.throws(() => validateLockShape(short), /artifact set differs/)
})

test('image pins must be pushed repository digests, not local image IDs', () => {
  assert.equal(immutableImageDigest(TOOLCHAIN, 'toolchain'), `sha256:${'1'.repeat(64)}`)
  assert.throws(() => immutableImageDigest('zkdeal-toolchain:v5', 'toolchain'), /repository@sha256/)
  assert.throws(() => immutableImageDigest(undefined, 'toolchain'), /is required/)

  // A bare sha256 is a *local* Docker image ID: it is not fetchable off the
  // build machine, so a lock pinned with one cannot be independently rebuilt.
  // The committed lock used exactly this form for both images.
  assert.throws(() => immutableImageDigest(`sha256:${'1'.repeat(64)}`, 'toolchain'), /repository@sha256/)
  const local = v5Lock()
  local.toolchain.image = `sha256:${'1'.repeat(64)}`
  assert.throws(() => validateLockShape(local), /repository@sha256/)

  const drifted = v5Lock()
  drifted.toolchain.digest = `sha256:${'3'.repeat(64)}`
  assert.throws(() => validateLockShape(drifted), /toolchain image\/digest are inconsistent/)
})

test('the lock pins the runtime image binary, not only the unstripped artifact build', () => {
  // build/risc0/zkdeal-r0 is unstripped and byte-different from the binary the
  // runtime image ships, so it cannot stand in for the deployed prover.
  const missing = v5Lock()
  delete missing.runtime.hostBinarySha256
  assert.throws(() => validateLockShape(missing), /runtime image host binary sha256/)
  assert.ok(!LOCK_ARTIFACTS.includes('build/risc0/zkdeal-r0-runtime'))
})

test('toolchain provenance is observed inside the image, not declared by the script', () => {
  const versions = {
    format: TOOLCHAIN_VERSIONS_FORMAT,
    rust: '1.88.0',
    wasmPack: '0.13.1',
    riscZero: { crates: '3.0.6', rustToolchain: '1.91.1', groth16: '0.1.0' },
    risc0HomeTreeSha256: '4'.repeat(64),
  }
  assert.equal(assertToolchainVersions(versions, 'test'), versions)
  assert.throws(
    () => assertToolchainVersions({ ...versions, format: 'zkdeal/risc0-toolchain-versions/v0' }, 'test'),
    /is not zkdeal\/risc0-toolchain-versions\/v1/,
  )
  assert.throws(
    () => assertToolchainVersions({ ...versions, risc0HomeTreeSha256: 'nope' }, 'test'),
    /malformed risc0HomeTreeSha256/,
  )

  // Every one of these fields used to be a string literal in build.mjs that no
  // checker compared against the image being pinned.
  for (const mutate of [
    (lock) => delete lock.toolchain.risc0HomeTreeSha256,
    (lock) => delete lock.toolchain.riscZero.groth16,
    (lock) => (lock.toolchain.rust = '1.88'),
  ]) {
    const lock = v5Lock()
    mutate(lock)
    assert.throws(() => validateLockShape(lock), /toolchain provenance/)
  }
})

test('the toolchain image records the version manifest build.mjs reads back', () => {
  const source = readFileSync(dockerfile, 'utf8')
  assert.ok(
    source.includes(TOOLCHAIN_VERSIONS_PATH),
    `the Dockerfile no longer writes ${TOOLCHAIN_VERSIONS_PATH}; build.mjs would fail every build`,
  )
  assert.ok(source.includes(`"format": "${TOOLCHAIN_VERSIONS_FORMAT}"`))
  assert.ok(
    source.includes('RISC0_HOME_TREE_SHA256'),
    'the rzup component tree is no longer content-pinnable',
  )
  assert.ok(
    source.includes('crates/risc0/methods/guest/Cargo.lock'),
    'the image build no longer guards the guest lock the outer --locked cannot reach',
  )
})

test('certified witness guest bindings are normalized when present', () => {
  assert.equal(
    fixtureProofProgramId({ proofProgramId: `0x${'A'.repeat(64)}` }),
    `0x${'a'.repeat(64)}`,
  )
  assert.equal(fixtureProofProgramId({}), undefined)

  // The checked-in AMM witnesses predate this field, but their generator must
  // bind the next regenerated copy to the active guest.
  const generator = readFileSync(join(here, 'gen-certified-amm-fixture.mts'), 'utf8')
  assert.ok(
    generator.includes('generatedFrom?.proofProgramId'),
    'the AMM generator no longer binds its witness to a guest program ID',
  )
})

test('the trust root cannot be minted from a single unreproduced build', () => {
  const run = (argv) =>
    spawnSync(process.execPath, [join(zkvmRoot, 'build.mjs'), ...argv], {
      encoding: 'utf8',
      cwd: repoRoot,
    })

  const unreproduced = run([
    '--cuda',
    '--toolchain-image',
    TOOLCHAIN,
    '--runtime-image',
    RUNTIME,
    '--update-lock',
  ])
  assert.notEqual(unreproduced.status, 0)
  assert.match(unreproduced.stderr, /require --check-repro/)

  // The argument guards must reject a local image ID before anything is built.
  const localImage = run([
    '--cuda',
    '--toolchain-image',
    `sha256:${'1'.repeat(64)}`,
    '--runtime-image',
    RUNTIME,
    '--check-repro',
    '--update-lock',
  ])
  assert.notEqual(localImage.status, 0)
  assert.match(localImage.stderr, /repository@sha256/)
})

test('the v6 capability payload is accepted and the v4 one is not', () => {
  assertCapabilitiesV5(v5Capability())

  // The v4 checker demanded protocolVersion 4 and a genesisProof field the v5
  // host does not emit; both of those must now be the failing direction.
  assert.throws(() => assertCapabilitiesV5(v5Capability({ protocolVersion: 4 })), /protocolVersion/)
  assert.throws(
    () => assertCapabilitiesV5(v5Capability({ protocolVersions: [5, 6] })),
    /exactly protocol version 6/,
  )
  assert.throws(
    () => assertCapabilitiesV5(v5Capability({ coldTemplateProof: false })),
    /coldTemplateProof/,
  )
  assert.throws(
    () => assertCapabilitiesV5(v5Capability({ receiptComposition: 'none' })),
    /receiptComposition/,
  )
  assert.throws(
    () => assertCapabilitiesV5(v5Capability({ clientVerifierOnly: true })),
    /clientVerifierOnly/,
  )
  assert.throws(() => assertCapabilitiesV5(v5Capability({ cpuFallback: true })), /cpuFallback/)
  assert.throws(
    () => assertCapabilitiesV5(v5Capability({ programId: `0x${'b'.repeat(64)}` })),
    /programId does not match imageId/,
  )
  // The host derives roomCapabilities by running its own request parser, so a
  // build that drops or corrupts the field is a build whose fixture regressed.
  assert.throws(
    () => assertCapabilitiesV5(v5Capability({ roomCapabilities: undefined })),
    /roomCapabilities string array/,
  )
  assert.throws(
    () => assertCapabilitiesV5(v5Capability({ roomCapabilities: [5] })),
    /roomCapabilities string array/,
  )
  // An honestly partial host is still a valid capability document: the caller
  // compares the reported tokens against what the room it wants needs.
  assertCapabilitiesV5(v5Capability({ roomCapabilities: [] }))
})

test('imageid is read from the programId machine field, never from stdout', () => {
  assert.equal(programIdToImageId({ programId: `0x${IMAGE_ID}` }, 'test'), IMAGE_ID)
  // The pre-v5 script expected a bare 64-hex line on stdout; that must now fail.
  assert.throws(() => programIdToImageId({ imageId: IMAGE_ID }, 'test'), /invalid RISC Zero program id/)
  assert.throws(() => programIdToImageId(IMAGE_ID, 'test'), /invalid RISC Zero program id/)
  assert.throws(
    () => programIdToImageId({ programId: `0x${IMAGE_ID.toUpperCase()}` }, 'test'),
    /invalid RISC Zero program id/,
  )
  assert.throws(() => programIdToImageId(undefined, 'test'), /invalid RISC Zero program id/)
})

test('the client-verifier gate asserts a refusal, not merely a non-zero exit', () => {
  const script = clientVerifierRefusalScript('/opt/zkdeal-r0-client')
  assert.ok(script.startsWith('set -e; '))
  for (const command of CLIENT_VERIFIER_DISABLED_COMMANDS_V5) {
    // `if` keeps the expected non-zero exit from tripping `set -e`.
    assert.ok(script.includes(`if out=$(/opt/zkdeal-r0-client ${command} </dev/null 2>&1); then`))
    assert.ok(script.includes(`echo "${command} was not refused"; exit 1; fi`))
    assert.ok(script.includes(`${command} failed for the wrong reason`))
  }
  // The retired assertion named a v4 command the v5 binary does not implement,
  // so it "passed" on `unknown command`. Nothing v4 may appear here.
  assert.ok(!/-v4\b/.test(script))
  assert.equal(
    script.split(CLIENT_VERIFIER_REFUSAL_V5).length - 1,
    CLIENT_VERIFIER_DISABLED_COMMANDS_V5.length,
  )
})

test('the host refuses gated commands with the sentence the gate matches', () => {
  const source = hostSource()
  assert.ok(
    source.includes(`'{cmd}' ${CLIENT_VERIFIER_REFUSAL_V5}`),
    'host refusal message changed; clientVerifierRefusalScript would silently stop matching',
  )
})

test('trust-root freshness is answered by the deterministic source manifest', () => {
  const result = spawnSync(process.execPath, [join(here, 'check-lock-freshness.mjs')], {
    encoding: 'utf8',
    cwd: resolve(zkvmRoot, '..'),
  })
  assert.ok(result.status === 0 || result.status === 1)
  if (result.status === 1) {
    assert.match(result.stderr, /trust-root freshness failed/)
    assert.match(result.stderr, /Rebuild twice on the pinned GPU runner/)
  }
})

test('the v5 host reports protocol version 6 and writes machine output to a file', () => {
  const source = hostSource()
  assert.ok(source.includes('"protocolVersion": 6'), 'host no longer reports protocolVersion 6')
  assert.ok(
    source.includes('ZKDEAL_RESULT_PATH'),
    'host no longer routes machine output through ZKDEAL_RESULT_PATH',
  )
})
