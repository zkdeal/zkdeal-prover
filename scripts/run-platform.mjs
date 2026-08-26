#!/usr/bin/env node
/**
 * Dispatch a scripts/<name>.{ps1,sh} pair to the right interpreter for the host
 * OS, so package.json entries are not Windows-only. Extra argv is forwarded
 * verbatim; the child's exit code is propagated (never swallowed).
 *
 *   node scripts/run-platform.mjs run-kurtosis-test [args…]
 */
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const [name, ...rest] = process.argv.slice(2)
const forwarded = rest[0] === '--' ? rest.slice(1) : rest

if (!name) {
  console.error('usage: node scripts/run-platform.mjs <script-base-name> [args…]')
  process.exit(2)
}

const isWindows = process.platform === 'win32'
const script = join(here, `${name}.${isWindows ? 'ps1' : 'sh'}`)

if (!existsSync(script)) {
  console.error(`scripts/${name}.${isWindows ? 'ps1' : 'sh'} not found (platform ${process.platform})`)
  process.exit(2)
}

const { command, args } = isWindows
  ? {
      command: 'powershell',
      args: ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, ...forwarded],
    }
  : { command: 'bash', args: [script, ...forwarded] }

const res = spawnSync(command, args, { stdio: 'inherit' })
if (res.error) {
  console.error(`failed to launch ${command}: ${res.error.message}`)
  process.exit(1)
}
process.exit(res.status ?? 1)
