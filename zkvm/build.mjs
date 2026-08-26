#!/usr/bin/env node
/**
 * zkdeal RISC Zero artifact pipeline for the current protocol trust root.
 *
 * It produces the CUDA host, local browser verifier, deterministic capability
 * declaration, and a lock over those artifacts plus the certified AMM
 * execution fixtures. `BatchInputV5` and `ColdTemplateInputV5` remain internal
 * Rust compatibility type names; the machine protocol version and journal
 * schema are reported by the host capability payload and pinned by the lock.
 *
 * A production build requires `--cuda`; there is no CPU fallback. The host's
 * `health` command must see a real GPU before any lock can be updated.
 *
 * The host prints operator prose on stdout and writes its machine payload to
 * ZKDEAL_RESULT_PATH (`write_machine_result` / `print_human_result` in
 * `crates/risc0/host/src/main.rs`). Every value read below therefore comes from
 * a result file, never from parsed stdout.
 *
 * Three properties the lock claims are enforced here rather than assumed:
 * both images must be pushed `repository@sha256:` manifest digests so a third
 * party can fetch them and re-derive the guest ID; `--check-repro` is mandatory
 * whenever the lock is written and re-derives every compiled artifact, not just
 * the guest ELF; and the toolchain versions recorded in the lock are read out of
 * the image itself rather than declared as literals in this file.
 *
 * The command-line contract and constants live in `build-config.mjs`, the
 * subprocess/container primitives in `build-exec.mjs`, and the lock mint/verify
 * step in `build-lock.mjs`. This file is the pipeline itself.
 */

import { existsSync, readFileSync } from 'node:fs'
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import {
  CAPABILITY_FORMAT,
  JOURNAL_VERSION,
  TOOLCHAIN_VERSIONS_PATH,
  assertCapabilitiesV5,
  assertToolchainVersions,
  clientVerifierRefusalScript,
  fixtureProofProgramId,
  programIdToImageId,
} from './lock-schema.mjs'
import {
  BOOTSTRAP_LOCK,
  BUILD,
  CAPABILITY_ARTIFACT,
  CERTIFIED_FIXTURES,
  CHECK_REPRO,
  CONTAINER_MACHINE_DIR,
  LOCK,
  MACHINE_DIR,
  REPRO_ARTIFACTS,
  REPRO_VOLUMES,
  RUNTIME_DIGEST,
  RUNTIME_IMAGE,
  SKIP_RUST,
  TOOLCHAIN_DIGEST,
  TOOLCHAIN_IMAGE,
  UPDATE_LOCK,
  guestLockGuard,
  here,
  log,
} from './build-config.mjs'
import {
  assertImageSourceManifest,
  assertPushedImage,
  inClientVerifierMachineResult,
  inContainerCapture,
  inContainerMachineResult,
  inRuntimeCapture,
  inRuntimeMachineResult,
  runtimeHostBinarySha256,
  sha256File,
} from './build-exec.mjs'
import { verifyLock, writeLock } from './build-lock.mjs'
import {
  DEFAULT_CANDIDATE_PATH,
  verifySourceManifest,
} from './scripts/check-lock-freshness.mjs'

function deterministicCapabilityV5(capability) {
  return {
    format: CAPABILITY_FORMAT,
    protocolVersion: capability.protocolVersion,
    protocolVersions: capability.protocolVersions,
    evmFork: capability.evmFork,
    backendId: capability.backendId,
    imageId: capability.imageId,
    programId: capability.programId,
    risc0Version: capability.risc0Version,
    cudaCompiled: capability.cudaCompiled,
    productionCompiled: capability.productionCompiled,
    cpuFallback: capability.cpuFallback,
    // These availability flags and the client-verifier marker are all asserted
    // by the standalone lock verifier on the written artifact, so they must
    // survive the deterministic projection, not only the mint-time check on the
    // raw capability.
    clientVerifierOnly: capability.clientVerifierOnly,
    provingAvailable: capability.provingAvailable,
    executionAvailable: capability.executionAvailable,
    verificationAvailable: capability.verificationAvailable,
    proofModes: capability.proofModes,
    ethereumSeal: capability.ethereumSeal,
    coldTemplateProof: capability.coldTemplateProof,
    receiptComposition: capability.receiptComposition,
    preparedStateRefresh: capability.preparedStateRefresh,
    maxBatchBlocks: capability.maxBatchBlocks,
    settlementDerivation: capability.settlementDerivation,
    genesisAnchor: capability.genesisAnchor,
    inboxApplication: capability.inboxApplication,
    compactStateModel: capability.compactStateModel,
    // Room shapes the host binary can prepare. This projection is an
    // allow-list, so an omitted key would make the pinned artifact disagree
    // with the live host about what the same binary supports.
    roomCapabilities: capability.roomCapabilities,
    dataAvailabilityEquivalence: capability.dataAvailabilityEquivalence,
    recursiveAggregate: capability.recursiveAggregate,
    withdrawalCommitment: capability.withdrawalCommitment,
    toolchainImage: TOOLCHAIN_IMAGE,
    toolchainDigest: TOOLCHAIN_DIGEST,
    runtimeImage: RUNTIME_IMAGE,
    runtimeDigest: RUNTIME_DIGEST,
  }
}

async function writeCapabilitiesV5({ targetVolume = 'zkdeal-zkvm-target' } = {}) {
  const capability = await inContainerMachineResult(
    'capabilities',
    './build/risc0/zkdeal-r0 capabilities',
    { targetVolume },
  )
  assertCapabilitiesV5(capability)
  const deterministic = deterministicCapabilityV5(capability)
  await writeFile(
    join(here, CAPABILITY_ARTIFACT),
    `${JSON.stringify(deterministic, null, 2)}\n`,
  )
  return deterministic
}

async function buildRustV5() {
  await mkdir(join(BUILD, 'risc0', 'verifier'), { recursive: true })

  log('1/5 build RISC Zero browser verifier')
  inContainerCapture(
    'set -e; rustup target add wasm32-unknown-unknown >/dev/null 2>&1; ' +
      'wasm-pack build crates/risc0/wasm-verifier --release --target web ' +
      '--out-dir /workspace/zkvm/build/risc0/verifier --out-name r0_wasm_verifier',
  )

  log('2/5 build deterministic current-protocol CUDA host and guest')
  inContainerCapture(
    guestLockGuard(
      'cargo build --locked --release -p zkdeal-r0 --features production; ' +
        'cp /ztarget/release/zkdeal-r0 /workspace/zkvm/build/risc0/zkdeal-r0; ' +
        '/workspace/zkvm/build/risc0/zkdeal-r0 health >/dev/null',
    ),
  )

  log('3/5 build the pinned headless execute/verify-only client')
  inContainerCapture(
    'set -e; cargo build --locked --release -p zkdeal-r0 --features client-verifier; ' +
      'cp /ztarget/release/zkdeal-r0 /workspace/zkvm/build/risc0/zkdeal-r0-client; ' +
      "! ldd /workspace/zkvm/build/risc0/zkdeal-r0-client | grep -q 'libcuda\\.so'",
  )
  // Every gated subcommand must fail *because proving is disabled*, not because
  // the name happens to be unknown to this build. The host reports the refusal
  // on stderr through `safe_failure_reason`, so match that exact sentence.
  assertClientVerifierRefusals()
  const clientCapability = await inClientVerifierMachineResult('client-capabilities', 'capabilities')
  if (
    clientCapability.clientVerifierOnly !== true ||
    clientCapability.provingAvailable !== false ||
    clientCapability.executionAvailable !== true ||
    clientCapability.verificationAvailable !== true ||
    clientCapability.cudaCompiled !== false ||
    clientCapability.productionCompiled !== false ||
    clientCapability.cpuFallback !== false ||
    clientCapability.protocolVersion !== JOURNAL_VERSION
  ) {
    throw new Error('headless verifier binary is not proving-disabled and GPU-independent')
  }

  log('4/5 read the toolchain image\'s own recorded versions')
  const versions = await toolchainVersions()

  log('5/5 write deterministic current capability declaration')
  const capabilities = await writeCapabilitiesV5()
  // The one machine-readable toolchain value the host reports was previously
  // collected and discarded, so a lock could confidently misstate the risc0
  // release it was built with. Cross-check it against the image.
  if (capabilities.risc0Version !== versions.riscZero.crates) {
    throw new Error(
      `host reports risc0 ${capabilities.risc0Version} but the toolchain image installed ${versions.riscZero.crates}`,
    )
  }
  return { capabilities, versions }
}

/**
 * Copy `toolchain-versions.json` out of the image through the bind mount and
 * validate it. Every field there is observed inside the image rather than
 * declared here, so the lock records what actually built the guest.
 */
async function toolchainVersions() {
  await mkdir(MACHINE_DIR, { recursive: true })
  const path = join(MACHINE_DIR, 'toolchain-versions.json')
  await rm(path, { force: true })
  inContainerCapture(
    `set -e; test -f ${TOOLCHAIN_VERSIONS_PATH} || ` +
      `{ echo "${TOOLCHAIN_VERSIONS_PATH} is missing: rebuild the toolchain image from the reviewed Dockerfile" >&2; exit 1; }; ` +
      `cp ${TOOLCHAIN_VERSIONS_PATH} ${CONTAINER_MACHINE_DIR}/toolchain-versions.json`,
  )
  return assertToolchainVersions(
    JSON.parse(readFileSync(path, 'utf8')),
    'the toolchain image version manifest',
  )
}

function assertClientVerifierRefusals() {
  inContainerCapture(clientVerifierRefusalScript('/workspace/zkvm/build/risc0/zkdeal-r0-client'))
}

async function builtImageId({ targetVolume = 'zkdeal-zkvm-target' } = {}) {
  const result = await inContainerMachineResult('imageid', './build/risc0/zkdeal-r0 imageid', {
    targetVolume,
  })
  return programIdToImageId(result, 'the built host')
}

/**
 * Second independent build of every compiled artifact the lock pins, in fresh
 * target/registry caches. Comparing only the guest ELF would leave
 * dependency drift and host/wasm nondeterminism undetected while the lock still
 * pinned those binaries' sha256 as though they were reproducible.
 */
async function checkReproducibleArtifacts(firstImageId) {
  const repro = join(BUILD, 'risc0', 'repro')
  await rm(repro, { recursive: true, force: true })
  await mkdir(join(repro, 'verifier'), { recursive: true })

  log('repro check: rebuilding every locked artifact in independent volumes')
  inContainerCapture(
    'set -e; rustup target add wasm32-unknown-unknown >/dev/null 2>&1; ' +
      'wasm-pack build crates/risc0/wasm-verifier --release --target web ' +
      '--out-dir /workspace/zkvm/build/risc0/repro/verifier --out-name r0_wasm_verifier',
    REPRO_VOLUMES,
  )
  inContainerCapture(
    guestLockGuard(
      'cargo build --locked --release -p zkdeal-r0 --features production; ' +
        'cp /ztarget/release/zkdeal-r0 /workspace/zkvm/build/risc0/repro/zkdeal-r0; ' +
        'cargo build --locked --release -p zkdeal-r0 --features client-verifier; ' +
        'cp /ztarget/release/zkdeal-r0 /workspace/zkvm/build/risc0/repro/zkdeal-r0-client',
    ),
    REPRO_VOLUMES,
  )

  const second = programIdToImageId(
    await inContainerMachineResult(
      'imageid-repro',
      './build/risc0/repro/zkdeal-r0 imageid',
      REPRO_VOLUMES,
    ),
    'the repro rebuild',
  )
  if (second !== firstImageId) {
    throw new Error(`RISC Zero image id is not reproducible: ${firstImageId} != ${second}`)
  }
  for (const relative of REPRO_ARTIFACTS) {
    const first = await sha256File(join(BUILD, 'risc0', relative))
    const repeat = await sha256File(join(repro, relative))
    if (first !== repeat) {
      throw new Error(
        `build/risc0/${relative} is not reproducible: ${first} != ${repeat}; the lock pins it as if it were`,
      )
    }
  }
  log(`reproducible image id and ${REPRO_ARTIFACTS.length} artifact hashes: ${firstImageId}`)
}

async function verifyRuntimeImage(imageId) {
  log('verify the separately pinned minimal CUDA runtime image')
  const runtimeImageId = programIdToImageId(
    await inRuntimeMachineResult('imageid', 'imageid'),
    'the runtime image',
  )
  if (runtimeImageId !== imageId) {
    throw new Error(`runtime image guest id ${runtimeImageId} != artifact guest id ${imageId}`)
  }
  const capability = await inRuntimeMachineResult('capabilities', 'capabilities')
  assertCapabilitiesV5(capability)
  inRuntimeCapture('health')
  return runtimeHostBinarySha256()
}

/**
 * A certified witness that names a different guest than the one just built is a
 * provenance failure, not a formatting detail. Witnesses written before the
 * binding existed carry no program ID and are reported rather than assumed
 * good; regenerating them under `--update-lock` gives them one.
 */
async function checkFixtureProgramIds(imageId) {
  for (const relative of CERTIFIED_FIXTURES) {
    const fixture = JSON.parse(await readFile(join(here, relative), 'utf8'))
    const declared = fixtureProofProgramId(fixture)
    if (!declared) {
      log(`${relative} declares no proofProgramId; it predates the guest binding and is unchecked`)
      continue
    }
    if (declared !== `0x${imageId}`) {
      throw new Error(
        `${relative} was certified against ${declared}, not the built guest 0x${imageId}`,
      )
    }
  }
}

/**
 * The two certified AMM witnesses under `fixtures/` are FROZEN. The program
 * inputs needed to re-derive them were part of the v4 protocol surface:
 * `scripts/generate-v4-presets.mts` (the `contracts/presets/v4` catalog they
 * were certified against) and the v4 statement encodings in `@zkdeal/protocol`
 * that `zkvm/scripts/gen-certified-amm-fixture.mts` still imports.
 *
 * Nothing is silently skipped here. `checkFixtureProgramIds` runs on every
 * build and refuses any guest the checked-in witnesses were not certified
 * against, so a new guest cannot mint a lock that claims these fixtures. That
 * refusal is the intended signal: re-certifying against a new guest is a
 * deliberate engineering task (port the AMM generator to the current preset source),
 * not a step this build can perform.
 */
function reportFrozenCertifiedFixtures() {
  log(
    `certified witnesses are frozen (${CERTIFIED_FIXTURES.join(', ')}); ` +
      'their v4 generators were removed with the v4 protocol surface. ' +
      'The program-ID binding check below is what enforces the guest they belong to.',
  )
}

async function main() {
  await mkdir(BUILD, { recursive: true })
  let capabilities
  let imageId
  let versions
  let runtimeHostBinary
  if (SKIP_RUST) {
    const path = join(here, CAPABILITY_ARTIFACT)
    if (!existsSync(path)) throw new Error('capabilities-v6.json is missing; run a CUDA build')
    capabilities = JSON.parse(await readFile(path, 'utf8'))
    if (capabilities.format !== CAPABILITY_FORMAT) {
      throw new Error('capabilities-v6.json has the wrong format')
    }
    imageId = capabilities.imageId
  } else {
    const sourceCandidate = verifySourceManifest(here, DEFAULT_CANDIDATE_PATH)
    assertPushedImage(TOOLCHAIN_IMAGE, TOOLCHAIN_DIGEST, 'toolchain image')
    assertPushedImage(RUNTIME_IMAGE, RUNTIME_DIGEST, 'runtime image')
    assertImageSourceManifest(RUNTIME_IMAGE, sourceCandidate.sha256)
    ;({ capabilities, versions } = await buildRustV5())
    imageId = await builtImageId()
    if (capabilities.imageId !== imageId) {
      throw new Error('capability imageId differs from the built host imageId')
    }
    if (CHECK_REPRO) await checkReproducibleArtifacts(imageId)
    runtimeHostBinary = await verifyRuntimeImage(imageId)
    // Fixture/preset regeneration is an explicit trust-root operation. Normal
    // CI verifies the checked-in AMM bytes through the existing lock below.
    if (UPDATE_LOCK || BOOTSTRAP_LOCK) {
      reportFrozenCertifiedFixtures()
    } else {
      log('verify checked-in fixtures without regeneration')
    }
    await checkFixtureProgramIds(imageId)
  }

  const existing = existsSync(LOCK) ? JSON.parse(await readFile(LOCK, 'utf8')) : null
  if (!existing && !BOOTSTRAP_LOCK) {
    throw new Error('artifacts.lock.json is missing; reviewed bootstrap requires --bootstrap-lock')
  }
  if (UPDATE_LOCK || BOOTSTRAP_LOCK) {
    await writeLock(imageId, capabilities, versions, runtimeHostBinary)
  } else {
    await verifyLock(existing, imageId, capabilities, versions, runtimeHostBinary)
  }
}

await main()
