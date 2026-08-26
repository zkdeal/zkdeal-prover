#!/usr/bin/env node
/**
 * Deterministic filesystem freshness gate for the zkVM trust root.
 *
 * No repository metadata participates. Every release-affecting source is
 * enumerated, SHA-256 hashed, path-normalised and sorted. The checked-in
 * source manifest is minted only by the reproducible artifact build; this
 * verifier compares it with the current filesystem and the exact artifact
 * lock bytes it names.
 */

import { createHash } from 'node:crypto'
import { existsSync, lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const SOURCE_MANIFEST_FORMAT = 'zkdeal/zkvm-source-manifest/v1'

const here = dirname(fileURLToPath(import.meta.url))
export const DEFAULT_ZKVM_ROOT = resolve(here, '..')
export const DEFAULT_MANIFEST_PATH = join(DEFAULT_ZKVM_ROOT, 'source-manifest.json')
export const DEFAULT_CANDIDATE_PATH = join(
  DEFAULT_ZKVM_ROOT,
  'source-manifest.candidate.json',
)

/** Every path whose bytes can alter a released guest, host, verifier or build contract. */
export const SOURCE_ROOTS = [
  'Cargo.toml',
  'Cargo.lock',
  'rust-toolchain.toml',
  'build-config.mjs',
  'build-exec.mjs',
  'build-lock.mjs',
  'build.mjs',
  'lock-schema.mjs',
  'crates/risc0/methods',
  'crates/risc0/host',
  'crates/risc0/wasm-verifier',
  'crates/stf-core',
  'crates/stf-types',
  'crates/stf-wire',
  'docker',
  'scripts',
  'vendor/risc0-groth16-sys',
  'vendor/risc0-sys',
  'vendor/rustcrypto-sources.json',
  'vendor/rustcrypto-crypto-bigint',
  'vendor/rustcrypto-k256',
]

const IGNORED_SEGMENTS = new Set(['target', 'build', '.git', 'node_modules'])

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function portable(path) {
  return path.split(sep).join('/').normalize('NFC')
}

function stableCompare(left, right) {
  return Buffer.compare(Buffer.from(left.normalize('NFC')), Buffer.from(right.normalize('NFC')))
}

function collectPath(root, path, files) {
  if (!existsSync(path)) {
    throw new Error(`source-manifest root is missing: ${portable(relative(root, path))}`)
  }
  const stats = lstatSync(path)
  // Release sources are a closed tree. Rejecting every symlink is stronger
  // than merely checking its current target and prevents a later retarget from
  // moving bytes outside the reviewed zkVM root.
  if (stats.isSymbolicLink()) {
    throw new Error(`source-manifest symlinks are forbidden: ${portable(relative(root, path))}`)
  }
  if (stats.isFile()) {
    const bytes = readFileSync(path)
    files.push({
      path: portable(relative(root, path)),
      size: bytes.length,
      sha256: sha256(bytes),
      // Filesystem execute bits are not stable across Windows bind mounts.
      // A shebang is the portable executable intent; Docker build steps still
      // apply explicit chmod before running copied scripts.
      executable: bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x21,
    })
    return
  }
  if (!stats.isDirectory()) throw new Error(`unsupported source-manifest entry: ${path}`)
  for (const entry of readdirSync(path, { withFileTypes: true }).sort((a, b) => stableCompare(a.name, b.name))) {
    if (IGNORED_SEGMENTS.has(entry.name)) continue
    collectPath(root, join(path, entry.name), files)
  }
}

export function filesDigest(files) {
  const canonical = files
    .map((file) => `${file.sha256} ${file.size} ${file.executable ? 'x' : '-'} ${file.path}\n`)
    .join('')
  return sha256(canonical)
}

export function collectSourceManifest(
  zkvmRoot = DEFAULT_ZKVM_ROOT,
  roots = SOURCE_ROOTS,
) {
  const files = []
  for (const source of roots) collectPath(zkvmRoot, join(zkvmRoot, source), files)
  files.sort((left, right) => stableCompare(left.path, right.path))
  return {
    format: SOURCE_MANIFEST_FORMAT,
    algorithm: 'sha256',
    sourceRoots: [...roots],
    filesDigest: filesDigest(files),
    files,
  }
}

export function canonicalManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`
}

export function sourceManifestSha256(manifest) {
  return sha256(canonicalManifest(manifest))
}

export function verifySourceManifest(
  zkvmRoot = DEFAULT_ZKVM_ROOT,
  manifestPath = join(zkvmRoot, 'source-manifest.json'),
) {
  if (!existsSync(manifestPath)) {
    throw new Error('zkvm/source-manifest.json is missing; the trust root has not been minted for these sources')
  }
  const expected = JSON.parse(readFileSync(manifestPath, 'utf8'))
  if (expected.format !== SOURCE_MANIFEST_FORMAT || expected.algorithm !== 'sha256') {
    throw new Error(`source manifest is not ${SOURCE_MANIFEST_FORMAT}`)
  }
  if (JSON.stringify(expected.sourceRoots) !== JSON.stringify(SOURCE_ROOTS)) {
    throw new Error('source manifest root set differs from the current build contract')
  }
  const observed = collectSourceManifest(zkvmRoot, expected.sourceRoots)
  if (canonicalManifest(observed) !== canonicalManifest(expected)) {
    const expectedByPath = new Map(expected.files.map((file) => [file.path, file]))
    const observedByPath = new Map(observed.files.map((file) => [file.path, file]))
    const drift = [...new Set([...expectedByPath.keys(), ...observedByPath.keys()])]
      .sort(stableCompare)
      .filter((path) => JSON.stringify(expectedByPath.get(path)) !== JSON.stringify(observedByPath.get(path)))
    throw new Error(`source manifest is stale; changed entries: ${drift.slice(0, 20).join(', ')}`)
  }
  return { manifest: expected, sha256: sourceManifestSha256(expected) }
}

/**
 * Verify the non-authoritative build-input manifest without rewriting it.
 *
 * The source owner prepares this file before the deterministic umbrella source
 * bundle is sealed. The physical GPU node may only check the transferred bytes;
 * rewriting the candidate there would mutate the already-sealed source tree.
 */
export function verifyCandidateSourceManifest(
  zkvmRoot = DEFAULT_ZKVM_ROOT,
  candidatePath = join(zkvmRoot, 'source-manifest.candidate.json'),
  roots = SOURCE_ROOTS,
) {
  if (!existsSync(candidatePath)) {
    throw new Error('zkvm/source-manifest.candidate.json is missing; prepare it before sealing the source bundle')
  }
  const expected = JSON.parse(readFileSync(candidatePath, 'utf8'))
  if (expected.format !== SOURCE_MANIFEST_FORMAT || expected.algorithm !== 'sha256') {
    throw new Error(`candidate source manifest is not ${SOURCE_MANIFEST_FORMAT}`)
  }
  if (JSON.stringify(expected.sourceRoots) !== JSON.stringify(roots)) {
    throw new Error('candidate source manifest root set differs from the current build contract')
  }
  const observed = collectSourceManifest(zkvmRoot, roots)
  if (canonicalManifest(observed) !== canonicalManifest(expected)) {
    const expectedByPath = new Map((expected.files ?? []).map((file) => [file.path, file]))
    const observedByPath = new Map(observed.files.map((file) => [file.path, file]))
    const drift = [...new Set([...expectedByPath.keys(), ...observedByPath.keys()])]
      .sort(stableCompare)
      .filter((path) => JSON.stringify(expectedByPath.get(path)) !== JSON.stringify(observedByPath.get(path)))
    throw new Error(`candidate source manifest is stale; changed entries: ${drift.slice(0, 20).join(', ')}`)
  }
  return { manifest: expected, sha256: sourceManifestSha256(expected) }
}

async function main() {
  const args = process.argv.slice(2)
  const print = args.includes('--print')
  const prepareBuildInput = args.includes('--prepare-build-input')
  const checkBuildInput = args.includes('--check-build-input')
  const unknown = args.filter(
    (arg) => !['--print', '--prepare-build-input', '--check-build-input'].includes(arg),
  )
  if (unknown.length > 0) {
    console.error(
      'usage: node zkvm/scripts/check-lock-freshness.mjs [--print|--prepare-build-input|--check-build-input]',
    )
    console.error('source-manifest minting is available only inside the reproducible artifact build')
    process.exit(2)
  }
  if ([print, prepareBuildInput, checkBuildInput].filter(Boolean).length > 1) {
    console.error('--print, --prepare-build-input and --check-build-input are mutually exclusive')
    process.exit(2)
  }
  if (prepareBuildInput) {
    const manifest = collectSourceManifest()
    writeFileSync(DEFAULT_CANDIDATE_PATH, canonicalManifest(manifest))
    console.log(
      `prepared non-authoritative Docker input ${DEFAULT_CANDIDATE_PATH} sha256=${sourceManifestSha256(manifest)}`,
    )
    console.log(
      'Only the mandatory two-build reproducibility closure may copy these bytes to source-manifest.json and bind them in artifacts.lock.json.',
    )
    return
  }
  if (checkBuildInput) {
    const result = verifyCandidateSourceManifest()
    console.log(`verified transferred non-authoritative build input sha256=${result.sha256}`)
    return
  }
  if (print) {
    const manifest = collectSourceManifest()
    const canonical = canonicalManifest(manifest)
    process.stdout.write(canonical)
    return
  }
  try {
    const verified = verifySourceManifest()
    console.log(`zkVM source manifest is current sha256=${verified.sha256}`)
  } catch (error) {
    console.error(`zkVM trust-root freshness failed: ${error instanceof Error ? error.message : String(error)}`)
    console.error('Rebuild twice on the pinned GPU runner, compare outputs, then mint artifacts.lock.json and source-manifest.json together.')
    process.exit(1)
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) await main()
