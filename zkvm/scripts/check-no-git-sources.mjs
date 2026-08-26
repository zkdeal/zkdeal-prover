#!/usr/bin/env node
/** Static release-path gate: dependency/build execution must need no repository client. */

import { readFileSync, readdirSync } from 'node:fs'
import { basename, dirname, extname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const zkvmRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const proverRoot = process.env.ZKDEAL_NO_GIT_SCAN_ROOT
  ? resolve(process.env.ZKDEAL_NO_GIT_SCAN_ROOT)
  : resolve(zkvmRoot, '..')
const problems = []
const excludedDirectories = new Set([
  '.cache',
  '.pnpm-store',
  'build',
  'dist',
  'node_modules',
  'out',
  'target',
  'vendor',
])

function walk(path, accept, out = []) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue
    const child = join(path, entry.name)
    if (entry.isDirectory()) walk(child, accept, out)
    else if (entry.isFile() && accept(child)) out.push(child)
  }
  return out
}

for (const path of walk(
  proverRoot,
  (path) => ['Cargo.toml', 'Cargo.lock'].includes(basename(path)),
)) {
  const source = readFileSync(path, 'utf8')
  if (/\bsource\s*=\s*["']git\+|\bgit\s*=\s*["']/i.test(source)) {
    problems.push(`${relative(proverRoot, path)} contains a repository dependency source`)
  }
}

const commandFiles = walk(proverRoot, (path) => {
  const name = basename(path)
  return (
    name === 'package.json' ||
    name === 'Dockerfile' ||
    name.startsWith('Dockerfile.') ||
    ['.js', '.mjs', '.sh'].includes(extname(name))
  )
})

const forbiddenCommands = [
  /spawn(?:Sync)?\s*\(\s*["']git["']/i,
  /execFile(?:Sync)?\s*\(\s*["']git["']/i,
  /(?:^|["'`;>&|]\s*)git\s+(?:clone|checkout|fetch|log|rev-parse|show|status|submodule|lfs|describe|diff)\b/im,
  /apt(?:-get)?\s+install(?:[^\n]|\\\r?\n)*\bgit(?:-lfs)?\b/i,
]
for (const path of commandFiles) {
  const source = readFileSync(path, 'utf8')
  for (const pattern of forbiddenCommands) {
    if (pattern.test(source)) {
      problems.push(`${relative(proverRoot, path)} contains a forbidden repository command`)
      break
    }
  }
}

if (problems.length > 0) {
  console.error('no-repository-client gate failed:')
  for (const problem of problems) console.error(`  - ${problem}`)
  process.exit(1)
}
console.log(
  `no-repository-client gate passed for ${commandFiles.length} first-party command/build files and all Cargo manifests`,
)
