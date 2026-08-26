/**
 * Minting and verifying `zkvm/artifacts.lock.json`.
 *
 * `writeLock` is the only path that produces a trust root, and it mints through
 * the same `validateLockShape` gate the verifying path uses so a lock that
 * `verifyLock` would later reject can never reach the working tree. Every
 * toolchain value recorded here is observed inside the pinned image rather than
 * declared as a literal.
 */

import { existsSync } from 'node:fs'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import {
  COLD_TEMPLATE_WITNESS_SCHEMA_V5,
  HOST_COMMANDS_V5,
  JOURNAL_VERSION,
  LOCK_ARTIFACTS,
  LOCK_FORMAT,
  ROOM_WITNESS_SCHEMA_V5,
  RUNTIME_COMPATIBILITY,
  validateLockShape,
} from './lock-schema.mjs'
import {
  LOCK,
  RUNTIME_DIGEST,
  RUNTIME_IMAGE,
  TOOLCHAIN_DIGEST,
  TOOLCHAIN_IMAGE,
  here,
  log,
} from './build-config.mjs'
import { sha256File } from './build-exec.mjs'
import {
  DEFAULT_CANDIDATE_PATH,
  DEFAULT_MANIFEST_PATH,
  canonicalManifest,
  collectSourceManifest,
  sourceManifestSha256,
  verifySourceManifest,
} from './scripts/check-lock-freshness.mjs'

export async function artifactHashes() {
  const artifacts = {}
  for (const relative of LOCK_ARTIFACTS) {
    const path = join(here, relative)
    if (!existsSync(path)) throw new Error(`required locked artifact is missing: ${relative}`)
    artifacts[relative] = { sha256: await sha256File(path) }
  }
  return artifacts
}

export async function writeLock(imageId, capabilities, versions, runtimeHostBinary) {
  // `writeLock` is called only after build.mjs has completed the mandatory
  // independent reproducibility build. There is intentionally no standalone
  // source-manifest write command that could bless arbitrary workspace bytes.
  const sourceManifest = collectSourceManifest(here)
  const sourceManifestBytes = canonicalManifest(sourceManifest)
  let candidateBytes
  try {
    candidateBytes = await readFile(DEFAULT_CANDIDATE_PATH, 'utf8')
  } catch {
    throw new Error(
      'source-manifest.candidate.json is missing; prepare the Docker build input before both reproducibility builds',
    )
  }
  if (candidateBytes !== sourceManifestBytes) {
    throw new Error(
      'source-manifest.candidate.json does not describe the exact sources used by the reproducibility closure',
    )
  }
  const sourceDigest = sourceManifestSha256(sourceManifest)
  const lock = {
    format: LOCK_FORMAT,
    note:
      'Reviewed current-protocol zkVM trust root. Regenerate with pushed repository@sha256 --toolchain-image and --runtime-image pins plus --cuda --check-repro --update-lock.',
    journalVersion: JOURNAL_VERSION,
    runtimeCompatibility: RUNTIME_COMPATIBILITY,
    sourceManifestSha256: sourceDigest,
    witnessSchemas: {
      room: ROOM_WITNESS_SCHEMA_V5,
      coldTemplate: COLD_TEMPLATE_WITNESS_SCHEMA_V5,
    },
    // Observed inside the pinned toolchain image, never declared here: a lock
    // whose toolchain block is a set of script literals states what the author
    // believed rather than what compiled the guest.
    toolchain: {
      image: TOOLCHAIN_IMAGE,
      digest: TOOLCHAIN_DIGEST,
      rust: versions.rust,
      riscZero: { ...versions.riscZero },
      wasmPack: versions.wasmPack,
      risc0HomeTreeSha256: versions.risc0HomeTreeSha256,
    },
    runtime: {
      image: RUNTIME_IMAGE,
      digest: RUNTIME_DIGEST,
      cudaRequired: true,
      cpuFallback: false,
      hostBinarySha256: runtimeHostBinary,
    },
    risc0: {
      imageId,
      programId: `0x${imageId}`,
      containerDigest: RUNTIME_DIGEST,
      cudaRequired: true,
      cpuFallback: false,
      ethereumSeal: true,
      commands: [...HOST_COMMANDS_V5],
      capabilityFormat: capabilities.format,
      compactStateModel: capabilities.compactStateModel,
    },
    artifacts: await artifactHashes(),
  }
  // Mint through the same gate the verifying path uses, so a trust root that
  // `verifyLock` would later reject can never reach the working tree.
  validateLockShape(lock)
  await writeFile(LOCK, `${JSON.stringify(lock, null, 2)}\n`)
  await writeFile(DEFAULT_MANIFEST_PATH, sourceManifestBytes)
  log(`lock written: ${LOCK}`)
  log(`source manifest written: ${DEFAULT_MANIFEST_PATH} sha256=${sourceDigest}`)
  return lock
}

export async function verifyLock(lock, imageId, capabilities, versions, runtimeHostBinary) {
  validateLockShape(lock)
  if (lock.risc0.imageId !== imageId || lock.risc0.programId !== `0x${imageId}`) {
    throw new Error(`RISC Zero image id drift: lock=${lock.risc0.imageId}, built=${imageId}`)
  }
  if (TOOLCHAIN_IMAGE && lock.toolchain.image !== TOOLCHAIN_IMAGE) {
    throw new Error(`toolchain image drift: lock=${lock.toolchain.image}, requested=${TOOLCHAIN_IMAGE}`)
  }
  if (RUNTIME_IMAGE && lock.runtime.image !== RUNTIME_IMAGE) {
    throw new Error(`runtime image drift: lock=${lock.runtime.image}, requested=${RUNTIME_IMAGE}`)
  }
  if (
    capabilities.toolchainImage !== lock.toolchain.image ||
    capabilities.toolchainDigest !== lock.toolchain.digest ||
    capabilities.runtimeImage !== lock.runtime.image ||
    capabilities.runtimeDigest !== lock.runtime.digest
  ) {
    throw new Error('capability artifact image provenance disagrees with the zkVM lock')
  }
  if (versions) {
    const drift = [
      ['rust', versions.rust, lock.toolchain.rust],
      ['wasmPack', versions.wasmPack, lock.toolchain.wasmPack],
      [
        'risc0HomeTreeSha256',
        versions.risc0HomeTreeSha256,
        lock.toolchain.risc0HomeTreeSha256,
      ],
      ['riscZero.crates', versions.riscZero.crates, lock.toolchain.riscZero?.crates],
      [
        'riscZero.rustToolchain',
        versions.riscZero.rustToolchain,
        lock.toolchain.riscZero?.rustToolchain,
      ],
      ['riscZero.groth16', versions.riscZero.groth16, lock.toolchain.riscZero?.groth16],
    ].filter(([, observed, pinned]) => observed !== pinned)
    if (drift.length > 0) {
      throw new Error(
        `toolchain provenance drift: ${drift
          .map(([key, observed, pinned]) => `${key} image=${observed} lock=${pinned}`)
          .join(', ')}`,
      )
    }
  }
  if (runtimeHostBinary && lock.runtime.hostBinarySha256 !== runtimeHostBinary) {
    throw new Error(
      `runtime image host binary ${runtimeHostBinary} != lock ${lock.runtime.hostBinarySha256}`,
    )
  }
  for (const relative of LOCK_ARTIFACTS) {
    const expected = lock.artifacts[relative]?.sha256
    const actual = await sha256File(join(here, relative))
    if (actual !== expected) throw new Error(`${relative} sha256 ${actual} != lock ${expected}`)
  }
  const verifiedSource = verifySourceManifest(here, DEFAULT_MANIFEST_PATH)
  if (lock.sourceManifestSha256 !== verifiedSource.sha256) {
    throw new Error(
      `source-manifest sha256 ${verifiedSource.sha256} != lock ${lock.sourceManifestSha256}`,
    )
  }
  log('all locked artifacts match artifacts.lock.json')
}
