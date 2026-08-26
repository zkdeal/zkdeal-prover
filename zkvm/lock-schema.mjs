/**
 * Shape of the zkVM trust root, shared by every checker.
 *
 * `zkvm/build.mjs` mints `zkvm/artifacts.lock.json` and `scripts/verify-artifact-locks.mjs`
 * re-checks it in hosted CI. Those two used to carry independent copies of the
 * artifact list and of the literals below, which is how the committed lock came
 * to omit `fixtures/amm-terminal-close-v4.json` while one checker passed and the
 * other could not run at all. There is exactly one copy now, and it lives here.
 *
 * Every literal is derived from the v5 host contract in
 * `zkvm/crates/risc0/host/src/main.rs` (`cmd_capabilities`, the `run()` dispatch
 * table) and from the v5 witness types in `zkvm/crates/stf-types/src/lib.rs`.
 */

export const LOCK_FORMAT = 'zkdeal/zkvm-artifacts-lock/v6'
export const CAPABILITY_FORMAT = 'zkdeal/risc0-capabilities/v6'
export const TOOLCHAIN_VERSIONS_FORMAT = 'zkdeal/risc0-toolchain-versions/v1'
export const JOURNAL_VERSION = 6
export const RUNTIME_COMPATIBILITY = 'v6-only'

/**
 * Where the toolchain image records the versions it actually installed. The
 * lock used to carry hand-written version literals that nothing compared
 * against the image being pinned; `writeLock` now copies this file's observed
 * values instead. Written by `docker/risc0-cuda.Dockerfile` in the `toolchain`
 * stage, so an image built before that stage existed fails loudly rather than
 * producing a lock that misstates its own build environment.
 */
export const TOOLCHAIN_VERSIONS_PATH = '/etc/zkdeal/toolchain-versions.json'

/**
 * Witness schema pins. Each string names the Rust input type that the guest
 * deserializes, the content-address job domain the host binds it under, and the
 * state model it carries, so any change to those three is a lock-visible change.
 * Sources: `BatchInputV5` / `ColdTemplateInputV5` (stf-types), `ROOM_JOB_DOMAIN_V5`
 * / `COLD_TEMPLATE_JOB_DOMAIN_V5` (host main.rs).
 */
export const ROOM_WITNESS_SCHEMA_V5 =
  'BatchInputV5/zkdeal:v6:room-prover-job/guest-exit-program-v1/full-room-state-v1'
export const COLD_TEMPLATE_WITNESS_SCHEMA_V5 =
  'ColdTemplateInputV5/zkdeal:v5:cold-template-prover-job/full-room-state-v1'

/**
 * Exactly the subcommands the v5 host dispatches (`run()` in host main.rs).
 * Pinning the full surface means a silently added or removed command is a lock
 * mismatch rather than an undocumented capability change.
 */
export const HOST_COMMANDS_V5 = [
  'imageid',
  'capabilities',
  'health',
  'serve',
  'prepare-room-v5',
  'prepare-room-batch-v5',
  'prepare-cold-template-v5',
  'execute-room-v5',
  'prove-room-v5',
  'verify-room-v5',
  'execute-cold-template-v5',
  'prove-cold-template-v5',
  'verify-cold-template-v5',
  'prove-room-suite-v5',
  'prepare-live-room-batch',
  'prepare-data-availability-v1',
  'execute-data-availability-v1',
  'prove-data-availability-v1',
  'verify-data-availability-v1',
  'execute-aggregate-v1',
  'prove-aggregate-v1',
  'verify-aggregate-v1',
  'wrap-groth16-v5',
  'wrap-identity-p254-v5',
  'wrap-groth16-from-p254-v5',
]

/** Commands the `client-verifier` build must refuse outright. */
export const CLIENT_VERIFIER_DISABLED_COMMANDS_V5 = [
  'health',
  'serve',
  'prove-room-v5',
  'prove-cold-template-v5',
  'prove-room-suite-v5',
  'prove-data-availability-v1',
  'prove-aggregate-v1',
  'wrap-groth16-v5',
  'wrap-identity-p254-v5',
  'wrap-groth16-from-p254-v5',
]

/** The exact sentence `run()` bails with for a gated subcommand. */
export const CLIENT_VERIFIER_REFUSAL_V5 = 'is disabled in the verifier-only client binary'

/**
 * Shell that proves the `client-verifier` build refuses every gated subcommand
 * *because proving is disabled*, not because the name is unknown to it. `if`
 * guards each invocation so `set -e` does not treat the expected non-zero exit
 * as a build failure, and the message check is what separates a real refusal
 * from `unknown command`.
 */
export function clientVerifierRefusalScript(clientPath) {
  const checks = CLIENT_VERIFIER_DISABLED_COMMANDS_V5.map(
    (command) =>
      `if out=$(${clientPath} ${command} </dev/null 2>&1); then echo "${command} was not refused"; exit 1; fi; ` +
      `case "$out" in *"${CLIENT_VERIFIER_REFUSAL_V5}"*) ;; ` +
      `*) echo "${command} failed for the wrong reason: $out"; exit 1;; esac`,
  )
  return `set -e; ${checks.join('; ')}`
}

/**
 * Every file the lock pins, relative to `zkvm/`. The certified AMM execution
 * witnesses keep their `-v4` filenames because the Rust parity suite still
 * replays that witness schema. They are pinned here so no tracked fixture can
 * drift unnoticed.
 *
 * `build/risc0/zkdeal-r0` is the *unstripped* artifact build produced by
 * `zkvm/build.mjs`. It is byte-different by construction from the stripped
 * binary the runtime image ships (`docker/risc0-cuda.Dockerfile` strips it in
 * the `builder` stage), so this entry does not attest the deployed prover. The
 * deployed binary is pinned separately as `runtime.hostBinarySha256`, extracted
 * from the runtime image itself, and the guest image ID is the value that spans
 * both builds.
 */
export const LOCK_ARTIFACTS = [
  'build/risc0/verifier/r0_wasm_verifier.js',
  'build/risc0/verifier/r0_wasm_verifier_bg.wasm',
  'build/risc0/zkdeal-r0',
  'build/risc0/zkdeal-r0-client',
  'build/risc0/capabilities-v6.json',
  'fixtures/amm-certified-v4.json',
  'fixtures/amm-terminal-close-v4.json',
]

/**
 * `repository@sha256:<manifest digest>` and nothing else.
 *
 * A bare `sha256:…` is a *local* Docker image ID — a config digest that differs
 * from the registry manifest digest, is not stable across machines, and is gone
 * after `docker image prune`. Accepting it made the reproducibility argument
 * reduce to "the one GPU node still has the image cached": nobody else can
 * fetch the toolchain image, rebuild the guest under it, and recompute the
 * pinned program ID, which is the entire purpose of this lock. The repository
 * form is what `docker/README.md` has always documented.
 */
const REPOSITORY_DIGEST =
  /^([a-z0-9][a-z0-9._-]*(?::\d+)?(?:\/[a-z0-9][a-z0-9._-]*)+)@(sha256:[0-9a-f]{64})$/

export function immutableImageDigest(image, label) {
  if (!image) throw new Error(`${label} is required`)
  const match = typeof image === 'string' ? image.match(REPOSITORY_DIGEST) : null
  if (!match) {
    throw new Error(
      `${label} must be a pushed registry reference of the form repository@sha256:<64 hex>; ` +
        'local Docker image IDs are not obtainable off the build machine',
    )
  }
  return match[2]
}

/**
 * `imageid` prints operator prose; its machine payload is
 * `{ "programId": "0x<64 lowercase hex>" }` (host main.rs `run()`).
 */
export function programIdToImageId(result, source) {
  const programId = result?.programId
  if (typeof programId !== 'string' || !/^0x[0-9a-f]{64}$/.test(programId)) {
    throw new Error(`invalid RISC Zero program id from ${source}: ${JSON.stringify(programId)}`)
  }
  return programId.slice(2)
}

/**
 * The v5 host's `capabilities` payload. Read from the machine-result file the
 * host writes under ZKDEAL_RESULT_PATH; stdout is operator prose, not JSON.
 */
export function assertCapabilitiesV5(capability) {
  const expected = {
    protocolVersion: 6,
    evmFork: 'osaka',
    backendId: 'risc0',
    cudaCompiled: true,
    productionCompiled: true,
    cpuFallback: false,
    clientVerifierOnly: false,
    provingAvailable: true,
    executionAvailable: true,
    verificationAvailable: true,
    ethereumSeal: true,
    coldTemplateProof: true,
    receiptComposition: 'risc0-assumption-v1',
    preparedStateRefresh: 'authenticated-envelope-v1',
    maxBatchBlocks: 4,
    settlementDerivation: 'guest-exit-program-v1',
    genesisAnchor: 'header-rlp-v1',
    inboxApplication: 'guest-inbox-v1',
    compactStateModel: 'full-room-state-v1',
  }
  for (const [key, value] of Object.entries(expected)) {
    if (capability[key] !== value) {
      throw new Error(
        `v6 capability ${key}=${JSON.stringify(capability[key])}, expected ${JSON.stringify(value)}`,
      )
    }
  }
  if (
    !Array.isArray(capability.protocolVersions) ||
    capability.protocolVersions.join(',') !== '6'
  ) {
    throw new Error('v6 capability must advertise exactly protocol version 6')
  }
  if (!/^[0-9a-f]{64}$/.test(capability.imageId ?? '')) {
    throw new Error('v6 capability imageId is not a 32-byte lowercase hex digest')
  }
  if (capability.programId !== `0x${capability.imageId}`) {
    throw new Error('v6 capability programId does not match imageId')
  }
  if (
    !Array.isArray(capability.proofModes) ||
    capability.proofModes.join(',') !== 'succinct,groth16'
  ) {
    throw new Error('v6 capability must expose succinct and Groth16 proof modes')
  }
  // The host derives this list by running its own request parser, so a build
  // that loses the field is a build whose fixture regressed. Fail loudly here
  // rather than let a card room be refused with an opaque capability gap.
  if (
    !Array.isArray(capability.roomCapabilities) ||
    capability.roomCapabilities.some((token) => typeof token !== 'string')
  ) {
    throw new Error('v6 capability must report a roomCapabilities string array')
  }
  if (
    capability.dataAvailabilityEquivalence?.available !== true ||
    capability.dataAvailabilityEquivalence?.maxBlobs !== 6 ||
    capability.dataAvailabilityEquivalence?.canonicalBytesPerBlob !== 126976 ||
    capability.dataAvailabilityEquivalence?.preparesCompleteContractManifest !== true ||
    capability.dataAvailabilityEquivalence?.manifestBlobStartIndex !== true ||
    capability.dataAvailabilityEquivalence?.aggregateBlobLayout !==
      'contiguous-member-order-exact-transaction-v1' ||
    capability.dataAvailabilityEquivalence?.maxTransactionBlobs !== 6 ||
    capability.dataAvailabilityEquivalence?.bundleBuilder !== 'c-kzg-2.1.8' ||
    capability.dataAvailabilityEquivalence?.commitmentBytes !== 48 ||
    capability.dataAvailabilityEquivalence?.proofBytes !== 48 ||
    capability.dataAvailabilityEquivalence?.pointEvaluationInputBytes !== 192 ||
    capability.dataAvailabilityEquivalence?.pointEvaluationPrecompile !== '0x0a'
  ) {
    throw new Error('v6 capability must expose the bounded EIP-4844 equivalence rail')
  }
  if (
    capability.recursiveAggregate?.available !== true ||
    capability.recursiveAggregate?.maxRooms !== 8 ||
    capability.recursiveAggregate?.distinctRoomsRequired !== true ||
    capability.recursiveAggregate?.blobRangesBoundByMemberStatement !== true
  ) {
    throw new Error('v6 capability must expose the max-eight distinct-room aggregate rail')
  }
  if (capability.withdrawalCommitment?.available !== true) {
    throw new Error('v6 capability must expose withdrawal commitment parity')
  }
}

const SEMVER = /^\d+\.\d+\.\d+$/

/**
 * The `toolchain-versions.json` the toolchain image writes at build time. Every
 * field is a value observed inside the image (a `--version` banner or a content
 * digest of the installed rzup component tree), never a literal declared by the
 * caller, so a lock minted from it cannot misstate its own build environment.
 */
export function assertToolchainVersions(versions, source) {
  if (versions?.format !== TOOLCHAIN_VERSIONS_FORMAT) {
    throw new Error(
      `${source} is not ${TOOLCHAIN_VERSIONS_FORMAT}; rebuild the toolchain image from the reviewed Dockerfile`,
    )
  }
  const checks = [
    ['rust', versions.rust, SEMVER],
    ['wasmPack', versions.wasmPack, SEMVER],
    ['riscZero.crates', versions.riscZero?.crates, SEMVER],
    ['riscZero.rustToolchain', versions.riscZero?.rustToolchain, SEMVER],
    ['riscZero.groth16', versions.riscZero?.groth16, SEMVER],
    ['risc0HomeTreeSha256', versions.risc0HomeTreeSha256, /^[0-9a-f]{64}$/],
  ]
  for (const [key, value, pattern] of checks) {
    if (typeof value !== 'string' || !pattern.test(value)) {
      throw new Error(`${source} has a malformed ${key}: ${JSON.stringify(value)}`)
    }
  }
  return versions
}

/**
 * The guest image ID a certified fixture was generated against, or `undefined`
 * for a fixture written before that binding existed.
 */
export function fixtureProofProgramId(fixture) {
  const value = fixture?.proofProgramId
  return typeof value === 'string' ? value.toLowerCase() : undefined
}

export function validateLockShape(lock) {
  if (lock?.format !== LOCK_FORMAT) throw new Error(`lock format ${lock?.format} != ${LOCK_FORMAT}`)
  if (lock.journalVersion !== JOURNAL_VERSION) {
    throw new Error(`zkVM lock must pin journalVersion ${JOURNAL_VERSION}`)
  }
  if (lock.runtimeCompatibility !== RUNTIME_COMPATIBILITY) {
    throw new Error(`zkVM lock must be ${RUNTIME_COMPATIBILITY}`)
  }
  if (!/^[0-9a-f]{64}$/.test(lock.sourceManifestSha256 ?? '')) {
    throw new Error('zkVM lock must pin the deterministic source-manifest sha256')
  }
  if (lock.witnessSchemas?.room !== ROOM_WITNESS_SCHEMA_V5) {
    throw new Error('zkVM lock has the wrong BatchInputV5 room witness schema pin')
  }
  if (lock.witnessSchemas?.coldTemplate !== COLD_TEMPLATE_WITNESS_SCHEMA_V5) {
    throw new Error('zkVM lock has the wrong ColdTemplateInputV5 witness schema pin')
  }
  if (
    lock.legacyJournalVersion !== undefined ||
    lock.risc0?.receiptFixture !== undefined ||
    lock.witnessSchemas?.genesis !== undefined ||
    lock.witnessSchemas?.batch !== undefined
  ) {
    throw new Error('zkVM lock contains retired v2/v4 journal, genesis, or receipt-fixture metadata')
  }
  if (!lock.risc0?.cudaRequired || lock.risc0?.cpuFallback !== false) {
    throw new Error('zkVM lock does not require CUDA with CPU fallback disabled')
  }
  if (lock.risc0?.ethereumSeal !== true) {
    throw new Error('zkVM lock must require Ethereum-verifiable seals')
  }
  if (lock.risc0?.compactStateModel !== 'full-room-state-v1') {
    throw new Error('zkVM lock has the wrong state witness model')
  }
  if (lock.risc0?.capabilityFormat !== CAPABILITY_FORMAT) {
    throw new Error(`zkVM lock capability format must be ${CAPABILITY_FORMAT}`)
  }
  const commands = Array.isArray(lock.risc0?.commands) ? [...lock.risc0.commands].sort() : []
  if (JSON.stringify(commands) !== JSON.stringify([...HOST_COMMANDS_V5].sort())) {
    throw new Error(`zkVM lock command surface differs: ${JSON.stringify(lock.risc0?.commands)}`)
  }
  const imageId = lock.risc0?.imageId
  if (!/^[0-9a-f]{64}$/.test(imageId ?? '') || lock.risc0?.programId !== `0x${imageId}`) {
    throw new Error('zkVM lock imageId/programId is malformed or inconsistent')
  }
  const toolchainDigest = immutableImageDigest(lock.toolchain?.image, 'lock.toolchain.image')
  const runtimeDigest = immutableImageDigest(lock.runtime?.image, 'lock.runtime.image')
  if (lock.toolchain?.digest !== toolchainDigest) {
    throw new Error('zkVM lock toolchain image/digest are inconsistent')
  }
  if (lock.runtime?.digest !== runtimeDigest || lock.risc0?.containerDigest !== runtimeDigest) {
    throw new Error('zkVM lock runtime image/digest are inconsistent')
  }
  if (lock.runtime?.cudaRequired !== true || lock.runtime?.cpuFallback !== false) {
    throw new Error('zkVM lock runtime must require CUDA and forbid CPU fallback')
  }
  // The stripped binary the runtime image actually runs. `build/risc0/zkdeal-r0`
  // in `artifacts` is the unstripped artifact build and cannot stand in for it.
  if (!/^[0-9a-f]{64}$/.test(lock.runtime?.hostBinarySha256 ?? '')) {
    throw new Error('zkVM lock must pin the runtime image host binary sha256')
  }
  assertToolchainVersions(
    {
      format: TOOLCHAIN_VERSIONS_FORMAT,
      rust: lock.toolchain?.rust,
      wasmPack: lock.toolchain?.wasmPack,
      riscZero: lock.toolchain?.riscZero,
      risc0HomeTreeSha256: lock.toolchain?.risc0HomeTreeSha256,
    },
    'zkVM lock toolchain provenance',
  )
  const actual = Object.keys(lock.artifacts ?? {}).sort()
  const expected = [...LOCK_ARTIFACTS].sort()
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`zkVM lock artifact set differs: ${JSON.stringify(actual)}`)
  }
}
