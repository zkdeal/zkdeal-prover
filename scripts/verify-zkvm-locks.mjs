#!/usr/bin/env node
/**
 * Verify the checked-in zkVM artifact lock against what is actually in the
 * prover-node tree. Runs in CI as a REQUIRED job.
 *
 * SCOPE / GUARANTEE:
 *   * Always verified (tracked trust roots): certified fixtures and image pins
 *     vs zkvm/artifacts.lock.json.
 *   * Large gitignored build outputs (host binaries, wasm verifier) are
 *     verified only when present; their absence is REPORTED, not silently
 *     passed over.
 *
 * `--require-zkvm-build` additionally requires every locked production zkVM
 * host/verifier artifact to be materialized. GPU CI uses that mode after its
 * reproducibility build, so a clean runner cannot skip real artifact checks.
 *
 * The card and risc0-ethereum locks have their own checker in the
 * web3-protocol folder: web3-protocol/scripts/verify-artifact-locks.mjs.
 *
 * Exit 0 = every required/verifiable artifact matches. Exit 1 = mismatch or
 * missing lock/artifact. Exit 2 = invalid command line.
 */
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CAPABILITY_FORMAT,
  COLD_TEMPLATE_WITNESS_SCHEMA_V5,
  JOURNAL_VERSION,
  LOCK_ARTIFACTS,
  LOCK_FORMAT,
  ROOM_WITNESS_SCHEMA_V5,
  RUNTIME_COMPATIBILITY,
  assertCapabilitiesV5,
  validateLockShape,
} from '../zkvm/lock-schema.mjs'
import { verifySourceManifest } from '../zkvm/scripts/check-lock-freshness.mjs'

const folderRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const requireZkvmBuild = process.argv.includes('--require-zkvm-build')
const unknownArgs = process.argv.slice(2).filter((arg) => arg !== '--require-zkvm-build')

if (unknownArgs.length > 0) {
  console.error(`usage: node scripts/verify-zkvm-locks.mjs [--require-zkvm-build]`)
  console.error(`unknown argument(s): ${unknownArgs.join(', ')}`)
  process.exit(2)
}

const problems = []
const notVerified = []
const verified = []
let verifiedSourceManifest

try {
  verifiedSourceManifest = verifySourceManifest(join(folderRoot, 'zkvm'))
  verified.push(`zkVM deterministic source manifest (${verifiedSourceManifest.sha256})`)
} catch (error) {
  problems.push(
    `zkVM source manifest: ${error instanceof Error ? error.message : String(error)}`,
  )
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

// Production execution validity uses the RISC Zero trust root. The certified
// fixtures are tracked and always verified. Large generated host/verifier
// artifacts are gitignored, so a clean checkout reports them as NOT VERIFIED;
// a CUDA build must materialize them before release promotion.
//
// The lock SHAPE is not re-declared here. This checker used to carry its own
// copy of the format string, journal version, witness schemas and artifact list,
// which is how the committed lock came to omit a fixture while `zkvm/build.mjs`
// passed and this gate could not run at all. There is exactly one copy and it
// lives in `zkvm/lock-schema.mjs`, which mints the lock; this gate re-checks
// the minted file against the tree.
//
// The `-v4` fixture filenames inside LOCK_ARTIFACTS are deliberate: they are v4
// schema witnesses that the Rust parity suite still replays. See the comment on
// LOCK_ARTIFACTS in zkvm/lock-schema.mjs.
const zkvmLockPath = join(folderRoot, 'zkvm', 'artifacts.lock.json')
if (!existsSync(zkvmLockPath)) {
  problems.push('zkvm/artifacts.lock.json is missing')
} else {
  const zkvmLock = JSON.parse(readFileSync(zkvmLockPath, 'utf8'))
  if (
    verifiedSourceManifest &&
    zkvmLock.sourceManifestSha256 !== verifiedSourceManifest.sha256
  ) {
    problems.push('zkVM lock does not bind the verified deterministic source manifest')
  }
  // Two different questions, deliberately reported at two different severities.
  //
  // (1) DECLARATIONS - the protocol contract the lock states. Every value comes
  //     from zkvm/lock-schema.mjs, never a literal retyped here. A mismatch is
  //     a hard failure: it means the lock describes a host this tree does not
  //     build.
  if (zkvmLock.format !== LOCK_FORMAT) {
    problems.push(`zkVM lock format is ${zkvmLock.format}, expected ${LOCK_FORMAT}`)
  }
  if (zkvmLock.journalVersion !== JOURNAL_VERSION || zkvmLock.runtimeCompatibility !== RUNTIME_COMPATIBILITY) {
    problems.push(`zkVM lock must pin journalVersion=${JOURNAL_VERSION} and ${RUNTIME_COMPATIBILITY}`)
  }
  if (
    zkvmLock.witnessSchemas?.room !== ROOM_WITNESS_SCHEMA_V5 ||
    zkvmLock.witnessSchemas?.coldTemplate !== COLD_TEMPLATE_WITNESS_SCHEMA_V5
  ) {
    problems.push('zkVM lock pins the wrong room/cold-template witness schemas')
  }
  if (
    zkvmLock.legacyJournalVersion !== undefined ||
    zkvmLock.risc0?.receiptFixture !== undefined ||
    zkvmLock.witnessSchemas?.genesis !== undefined ||
    zkvmLock.witnessSchemas?.batch !== undefined
  ) {
    problems.push('zkVM lock still carries retired v2/v4 journal, genesis, or receipt-fixture metadata')
  }
  if (
    zkvmLock.risc0?.cudaRequired !== true ||
    zkvmLock.risc0?.cpuFallback !== false ||
    zkvmLock.risc0?.ethereumSeal !== true ||
    zkvmLock.runtime?.cudaRequired !== true ||
    zkvmLock.runtime?.cpuFallback !== false
  ) {
    problems.push('zkVM lock must require CUDA, forbid CPU fallback, and require Ethereum seals')
  }
  if (zkvmLock.risc0?.compactStateModel !== 'full-room-state-v1') {
    problems.push('zkVM lock must pin compactStateModel=full-room-state-v1')
  }
  if (zkvmLock.risc0?.capabilityFormat !== CAPABILITY_FORMAT) {
    problems.push(`zkVM lock capability format must be ${CAPABILITY_FORMAT}`)
  }
  const digestOf = (image) =>
    typeof image === 'string' ? image.match(/(?:^|@)(sha256:[0-9a-f]{64})$/)?.[1] : undefined
  const runtimeDigest = digestOf(zkvmLock.runtime?.image)
  if (!digestOf(zkvmLock.toolchain?.image) || zkvmLock.toolchain?.digest !== digestOf(zkvmLock.toolchain?.image)) {
    problems.push('zkVM lock toolchain image and digest are inconsistent')
  }
  if (!runtimeDigest || zkvmLock.runtime?.digest !== runtimeDigest || zkvmLock.risc0?.containerDigest !== runtimeDigest) {
    problems.push('zkVM lock runtime image, digest and container digest are inconsistent')
  }
  const imageId = zkvmLock.risc0?.imageId
  if (!/^[0-9a-f]{64}$/.test(imageId ?? '') || zkvmLock.risc0?.programId !== `0x${imageId}`) {
    problems.push('zkVM lock imageId/programId is malformed or inconsistent')
  }
  verified.push('zkVM lock declarations (against zkvm/lock-schema.mjs)')

  // (2) MINTING PROVENANCE - validateLockShape is the contract `zkvm/build.mjs`
  //     applies when it WRITES a lock: pushed registry image references, the
  //     stripped runtime host binary digest, the RISC Zero home-tree digest,
  //     the full artifact set. Every one of those is measured on the build
  //     machine and none of them can be produced, or honestly hand-written, off
  //     it. Asserting them here would make a required hosted job permanently
  //     red for a reason a hosted job can never fix, so the deficit is REPORTED
  //     and left to `--require-zkvm-build` - i.e. GPU CI, immediately after the
  //     reproducibility build that can satisfy it.
  try {
    validateLockShape(zkvmLock)
    verified.push('zkVM lock minting provenance (zkvm/lock-schema.mjs)')
  } catch (error) {
    notVerified.push(
      `zkVM lock has not been minted by the current build contract: ` +
        `${error instanceof Error ? error.message : String(error)} ` +
        `(run node zkvm/build.mjs --cuda --update-lock on the pinned runner)`,
    )
  }

  for (const relative of LOCK_ARTIFACTS) {
    const path = join(folderRoot, 'zkvm', relative)
    const expected = zkvmLock.artifacts?.[relative]?.sha256
    const tracked = relative.startsWith('fixtures/')
    if (!existsSync(path)) {
      // A gitignored build product that no build on this machine has produced
      // cannot be verified here whether or not the lock pins it. Saying so is
      // honest; calling it a hash failure is not. `--require-zkvm-build` turns
      // every one of these into a hard failure.
      if (tracked) problems.push(`zkVM ${relative}: tracked fixture is missing`)
      else notVerified.push(`zkVM ${relative} (run node zkvm/build.mjs --cuda)`)
    } else if (!expected) {
      problems.push(`zkVM ${relative}: present in the tree but absent from the lock`)
    } else if (sha256(path) !== expected) {
      problems.push(`zkVM ${relative}: sha256 mismatch`)
    } else {
      verified.push(`zkVM ${relative}`)
    }
  }
  // The capability artifact is one of the locked artifacts, so its path comes
  // from the same list rather than a second literal that could drift from it.
  const capabilityRelative = LOCK_ARTIFACTS.find((name) => /capabilities-v\d+\.json$/.test(name))
  if (!capabilityRelative) {
    problems.push('zkvm/lock-schema.mjs no longer pins a RISC Zero capability artifact')
  } else if (existsSync(join(folderRoot, 'zkvm', capabilityRelative))) {
    const capability = JSON.parse(readFileSync(join(folderRoot, 'zkvm', capabilityRelative), 'utf8'))
    if (capability.format !== CAPABILITY_FORMAT) {
      problems.push(`RISC Zero capability artifact format is ${capability.format}, expected ${CAPABILITY_FORMAT}`)
    }
    if (capability.imageId !== imageId || capability.programId !== `0x${imageId}`) {
      problems.push('RISC Zero capability artifact disagrees with the zkVM lock image ID')
    }
    if (
      capability.toolchainImage !== zkvmLock.toolchain?.image ||
      capability.toolchainDigest !== zkvmLock.toolchain?.digest ||
      capability.runtimeImage !== zkvmLock.runtime?.image ||
      capability.runtimeDigest !== zkvmLock.runtime?.digest
    ) {
      problems.push('RISC Zero capability artifact disagrees with locked build/runtime provenance')
    }
    // The full declared capability surface, asserted by the same helper the
    // build uses, rather than a hand-copied subset of its fields.
    try {
      assertCapabilitiesV5(capability)
      verified.push('RISC Zero capability semantics')
    } catch (error) {
      problems.push(`RISC Zero capability artifact: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
}

for (const v of verified) console.log(`ok       ${v}`)
for (const n of notVerified) console.log(`NOT VERIFIED  ${n}`)

if (requireZkvmBuild) {
  const missingZkvmBuild = notVerified.filter((entry) => entry.startsWith('zkVM '))
  if (missingZkvmBuild.length > 0) {
    problems.push(
      `--require-zkvm-build was set, but ${missingZkvmBuild.length} locked production zkVM artifact(s) were absent`,
    )
  }
}

if (problems.length > 0) {
  console.error('\nartifact lock verification FAILED:')
  for (const p of problems) console.error(`  - ${p}`)
  process.exit(1)
}
console.log(`\nartifact lock verification passed (${verified.length} verified, ${notVerified.length} not verifiable here)`)
