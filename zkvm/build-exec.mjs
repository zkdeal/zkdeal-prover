/**
 * Everything the current artifact pipeline shells out to.
 *
 * Subprocess capture, the pinned toolchain/runtime container invocations, the
 * ZKDEAL_RESULT_PATH machine-result round trip the host uses instead of
 * printing machine payloads on stdout, and the sha256 of the files those runs
 * produce. No value read here ever comes from parsed stdout.
 */

import { createHash, randomUUID } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { mkdir, readFile, rm } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import {
  CONTAINER_MACHINE_DIR,
  MACHINE_DIR,
  RUNTIME_IMAGE,
  TOOLCHAIN_IMAGE,
  log,
  repoRoot,
} from './build-config.mjs'

// When this orchestrator itself runs in Docker, nested Docker bind mounts must
// name the path as seen by the daemon (the Windows host), not `/workspace` as
// seen inside the orchestrator container. The release runner passes that exact
// path explicitly. Spawn uses an argv array, so the value is never interpreted
// by a shell.
const dockerWorkspaceSource = process.env.ZKDEAL_DOCKER_WORKSPACE_SOURCE || repoRoot
if (/[\0\r\n]/.test(dockerWorkspaceSource)) {
  throw new Error('ZKDEAL_DOCKER_WORKSPACE_SOURCE contains a forbidden control character')
}
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

export async function sha256File(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex')
}

export function runCapture(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
    ...options,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(
      `${command} exited ${result.status}: ${String(result.stderr ?? '').slice(-2_000)}`,
    )
  }
  return result.stdout
}

export function runPnpmCapture(commandArgs, options = {}) {
  if (process.platform !== 'win32') return runCapture('pnpm', commandArgs, options)

  // Current Node releases intentionally refuse to spawn .cmd files directly
  // without a shell.  Avoid shell interpolation entirely by invoking the
  // Corepack pnpm entry point with the same node.exe that is running this
  // reviewed build script.
  const corepackPnpm = join(dirname(process.execPath), 'node_modules', 'corepack', 'dist', 'pnpm.js')
  if (!existsSync(corepackPnpm)) {
    throw new Error(`Corepack pnpm entry point is missing: ${corepackPnpm}`)
  }
  return runCapture(process.execPath, [corepackPnpm, ...commandArgs], options)
}

export function containerArgs(
  script,
  {
    targetVolume = scopedVolume('zkdeal-zkvm-target'),
    registryVolume = scopedVolume('zkdeal-zkvm-cargo-registry'),
  } = {},
) {
  return [
    'run',
    '--rm',
    '--gpus',
    'all',
    // The NVIDIA CUDA base image installs an entrypoint that prints a
    // human-readable banner to stdout.  Every command invoked here is a
    // machine-readable artifact build/query, so bypass that presentation
    // wrapper and invoke bash directly.  GPU devices and driver libraries are
    // still injected by the NVIDIA container runtime via `--gpus all`.
    '--entrypoint',
    'bash',
    // RISC Zero's guest ELF currently retains build-path-sensitive Rust panic
    // metadata.  Use the exact path pinned by the reviewed Dockerfile so the
    // independently mounted artifact build and the minimal runtime image
    // derive the same program ID.
    '-v',
    `${dockerWorkspaceSource}:/workspace`,
    '-v',
    `${registryVolume}:/opt/cargo/registry`,
    '-v',
    `${targetVolume}:/ztarget`,
    '-e',
    'CARGO_TARGET_DIR=/ztarget',
    '-e',
    'ZKDEAL_PRODUCTION=1',
    '-w',
    '/workspace/zkvm',
    TOOLCHAIN_IMAGE,
    '-c',
    script,
  ]
}

export function inContainerCapture(script, options = {}) {
  return runCapture('docker', containerArgs(script, options))
}

/**
 * Run one host subcommand inside the toolchain container and return the JSON the
 * host wrote to ZKDEAL_RESULT_PATH. The result file is removed first so a stale
 * payload from an earlier step can never be mistaken for this run's output.
 */
export async function inContainerMachineResult(name, command, options = {}) {
  await mkdir(MACHINE_DIR, { recursive: true })
  const path = join(MACHINE_DIR, `${name}.json`)
  await rm(path, { force: true })
  inContainerCapture(
    `set -e; ZKDEAL_RESULT_PATH=${CONTAINER_MACHINE_DIR}/${name}.json ${command}`,
    options,
  )
  return readMachineResult(path, name)
}

export function readMachineResult(path, name) {
  if (!existsSync(path)) {
    throw new Error(`the host wrote no machine result for '${name}'; ZKDEAL_RESULT_PATH was ignored`)
  }
  return JSON.parse(readFileSync(path, 'utf8'))
}

export async function inClientVerifierMachineResult(name, command) {
  await mkdir(MACHINE_DIR, { recursive: true })
  const path = join(MACHINE_DIR, `${name}.json`)
  await rm(path, { force: true })
  runCapture('docker', [
    'run',
    '--rm',
    '--entrypoint',
    '/workspace/zkvm/build/risc0/zkdeal-r0-client',
    '-v',
    `${repoRoot}:/workspace`,
    '-e',
    `ZKDEAL_RESULT_PATH=${CONTAINER_MACHINE_DIR}/${name}.json`,
    '-w',
    '/workspace/zkvm',
    TOOLCHAIN_IMAGE,
    command,
  ])
  return readMachineResult(path, name)
}

// The host reports `containerDigest` from the ZKDEAL_CONTAINER_DIGEST it is
// handed, so a value injected here and then asserted back would establish
// nothing about which image is running — it is a telemetry label, not
// attestation. Container identity is established instead by launching the
// pinned `repository@sha256:` reference, which Docker resolves by manifest
// digest, and cross-checked by `assertPushedImage` below.
export function inRuntimeCapture(command) {
  return runCapture('docker', ['run', '--rm', '--gpus', 'all', RUNTIME_IMAGE, command])
}

/**
 * The minimal runtime image deliberately mounts nothing from the repository, so
 * the machine result is written inside the container (under the uid-10001 home
 * the image creates) and copied out afterwards rather than through a bind mount
 * whose ownership would depend on the host.
 */
export async function inRuntimeMachineResult(name, command) {
  await mkdir(MACHINE_DIR, { recursive: true })
  const path = join(MACHINE_DIR, `runtime-${name}.json`)
  await rm(path, { force: true })
  const container = `zkdeal-zkvm-runtime-${name}-${randomUUID().slice(0, 8)}`
  try {
    runCapture('docker', [
      'run',
      '--name',
      container,
      '--gpus',
      'all',
      '-e',
      'ZKDEAL_RESULT_PATH=/home/zkdeal/machine-result.json',
      RUNTIME_IMAGE,
      command,
    ])
    runCapture('docker', ['cp', `${container}:/home/zkdeal/machine-result.json`, path])
  } finally {
    spawnSync('docker', ['rm', '-f', container], { encoding: 'utf8' })
  }
  return readMachineResult(path, name)
}

/**
 * The stripped binary the runtime image actually executes, extracted from the
 * image itself. `build/risc0/zkdeal-r0` in the artifact set is the unstripped
 * artifact build and is byte-different by construction, so it cannot stand in
 * for the deployed prover.
 */
export async function runtimeHostBinarySha256() {
  await mkdir(MACHINE_DIR, { recursive: true })
  const path = join(MACHINE_DIR, 'runtime-zkdeal-r0')
  await rm(path, { force: true })
  const container = `zkdeal-zkvm-runtime-export-${randomUUID().slice(0, 8)}`
  try {
    runCapture('docker', ['create', '--name', container, RUNTIME_IMAGE])
    runCapture('docker', ['cp', `${container}:/usr/local/bin/zkdeal-r0`, path])
  } finally {
    spawnSync('docker', ['rm', '-f', container], { encoding: 'utf8' })
  }
  return sha256File(path)
}

/**
 * Prove the pinned reference really is a pushed registry manifest that resolves
 * to the digest recorded in the lock, so a third party can fetch the same image
 * and recompute the guest program ID. A local-only image fails here.
 */
export function assertPushedImage(image, digest, label) {
  const inspect = () =>
    JSON.parse(
      runCapture('docker', ['image', 'inspect', '--format', '{{json .RepoDigests}}', image]).trim() ||
        'null',
    ) ?? []
  let repoDigests
  try {
    repoDigests = inspect()
  } catch {
    log(`pulling ${label} ${image}`)
    runCapture('docker', ['pull', image])
    repoDigests = inspect()
  }
  if (!repoDigests.some((reference) => String(reference).endsWith(`@${digest}`))) {
    throw new Error(
      `${label} ${image} has no pushed repository digest ${digest}: ${JSON.stringify(repoDigests)}`,
    )
  }
}

/** Require the runtime image to bind the exact candidate manifest verified in this tree. */
export function assertImageSourceManifest(image, expectedSha256) {
  const labels =
    JSON.parse(
      runCapture('docker', [
        'image',
        'inspect',
        '--format',
        '{{json .Config.Labels}}',
        image,
      ]).trim() || 'null',
    ) ?? {}
  const observed = labels['org.opencontainers.image.source-manifest.sha256']
  if (observed !== expectedSha256) {
    throw new Error(
      `runtime image source-manifest ${observed ?? 'missing'} != verified candidate ${expectedSha256}`,
    )
  }
}
