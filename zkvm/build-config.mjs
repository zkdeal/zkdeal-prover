/**
 * Command-line contract, paths and constants of the protocol-v6 RISC Zero artifact
 * pipeline.
 *
 * Everything here is evaluated at import time, so the argument guards below
 * reject an unsupported invocation before `build.mjs` starts a container. Both
 * image pins are parsed through `immutableImageDigest`, which refuses a local
 * `sha256:` image ID, and minting the lock is coupled to `--check-repro`.
 */

import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { immutableImageDigest } from './lock-schema.mjs'

export const here = dirname(fileURLToPath(import.meta.url))
export const repoRoot = resolve(here, '..')
export const BUILD = join(here, 'build')
export const LOCK = join(here, 'artifacts.lock.json')
export const CAPABILITY_ARTIFACT = 'build/risc0/capabilities-v6.json'
// Machine-result drop box kept outside the source-manifest root set.
export const MACHINE_DIR = join(BUILD, 'risc0', 'machine')
export const CONTAINER_MACHINE_DIR = '/workspace/zkvm/build/risc0/machine'
const buildCacheScope = process.env.ZKDEAL_BUILD_CACHE_SCOPE
if (
  buildCacheScope !== undefined &&
  !/^[a-z0-9][a-z0-9_.-]{0,127}$/.test(buildCacheScope)
) {
  throw new Error(
    'ZKDEAL_BUILD_CACHE_SCOPE must be a lowercase Docker-volume-safe release identifier',
  )
}
const scopedVolume = (base) =>
  buildCacheScope === undefined ? base : `${base}-${buildCacheScope}`
// Second, independent build tree for --check-repro. A fresh Cargo registry
// cache exercises crates.io resolution again; patched crypto forks are local
// source-manifest entries and need no repository client/cache.
export const REPRO_VOLUMES = {
  targetVolume: scopedVolume('zkdeal-zkvm-target-repro'),
  registryVolume: scopedVolume('zkdeal-zkvm-cargo-registry-repro'),
}
// Compiled outputs the lock pins as if they were reproducible. `--check-repro`
// rebuilds and re-hashes all of them, not just the guest ELF; the capability
// declaration is derived rather than compiled, so it is not in this list.
export const REPRO_ARTIFACTS = [
  'verifier/r0_wasm_verifier.js',
  'verifier/r0_wasm_verifier_bg.wasm',
  'zkdeal-r0',
  'zkdeal-r0-client',
]
// Certified execution witnesses that can record the guest they were generated
// against, so a present witness/image binding is checked instead of assumed.
export const CERTIFIED_FIXTURES = [
  'fixtures/amm-certified-v4.json',
  'fixtures/amm-terminal-close-v4.json',
]
// The guest is a separate cargo workspace, so the outer `--locked` does not
// reach the nested guest resolution that produces the image ID. Fail the build
// if that nested cargo rewrites the guest lock.
export const GUEST_LOCK = 'crates/risc0/methods/guest/Cargo.lock'
export const guestLockGuard = (script) =>
  `set -e; __guest_lock_before=$(sha256sum ${GUEST_LOCK}); ${script}; ` +
  `sha256sum -c <<<"$__guest_lock_before" >/dev/null || ` +
  `{ echo "${GUEST_LOCK} was rewritten by the nested guest build" >&2; exit 1; }`

const args = process.argv.slice(2)
const has = (flag) => args.includes(flag)
const argValue = (flag, fallback) => {
  const index = args.indexOf(flag)
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback
}

export const SKIP_RUST = has('--skip-rust')
export const CHECK_REPRO = has('--check-repro')
export const UPDATE_LOCK = has('--update-lock')
export const BOOTSTRAP_LOCK = has('--bootstrap-lock')
export const CUDA = has('--cuda')
export const TOOLCHAIN_IMAGE = argValue('--toolchain-image')
export const RUNTIME_IMAGE = argValue('--runtime-image')

export const TOOLCHAIN_DIGEST = TOOLCHAIN_IMAGE
  ? immutableImageDigest(TOOLCHAIN_IMAGE, '--toolchain-image')
  : undefined
export const RUNTIME_DIGEST = RUNTIME_IMAGE
  ? immutableImageDigest(RUNTIME_IMAGE, '--runtime-image')
  : undefined

if (has('--receipt')) {
  throw new Error('--receipt is retired: v6 proves room batches and cold templates only')
}
if (has('--image')) {
  throw new Error('--image is ambiguous and retired; pass --toolchain-image and --runtime-image')
}
if (!SKIP_RUST && !CUDA) {
  throw new Error('production v6 artifact builds require --cuda; CPU fallback is forbidden')
}
if (!SKIP_RUST && (!TOOLCHAIN_IMAGE || !RUNTIME_IMAGE)) {
  throw new Error('CUDA builds require immutable --toolchain-image and --runtime-image pins')
}
if (SKIP_RUST && (UPDATE_LOCK || BOOTSTRAP_LOCK)) {
  throw new Error('--skip-rust cannot update or bootstrap the cryptographic trust root')
}
if ((UPDATE_LOCK || BOOTSTRAP_LOCK) && !CHECK_REPRO) {
  // Minting the trust root is the one operation whose reproducibility must not
  // be optional: a nondeterministic build would otherwise be baptised as the
  // pinned program and surface only as an unexplained hash mismatch later.
  throw new Error('--update-lock/--bootstrap-lock require --check-repro; see zkvm/docker/README.md')
}

export const log = (message) => console.log(`[build-zkvm] ${message}`)
