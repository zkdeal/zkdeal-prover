/**
 * Dry-run the whole sweep plan without touching a GPU.
 *
 * Run this before every sweep. It classifies every active opcode in the dumped
 * manifest, builds each template, simulates it, and reports what would be
 * measured, what would be skipped, and why. A sweep that starts without this
 * passing is a sweep that discovers its own template bugs several GPU-hours in.
 *
 * Usage, from `prover-node/`:
 *   node --experimental-strip-types scripts/opcode-cost/check.mts <manifest.json>
 */

import { readFileSync } from 'node:fs'
import { assemble, maxRepetitions, planForTarget, precompilePlan, planFor, toHex } from './bytecode.mts'
import { classifyManifest, PRECOMPILE_TARGETS, type ManifestEntry } from './targets.mts'
import { validatePlan } from './validate.mts'

const manifestPath = process.argv[2]
if (!manifestPath) {
  console.error('usage: check.mts <osaka-manifest.json>')
  process.exit(2)
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
  schema: string
  opcodes: ManifestEntry[]
  precompiles: string[]
}

if (manifest.schema !== 'zkdeal/osaka-opcode-manifest/v1') {
  console.error(`unexpected manifest schema: ${manifest.schema}`)
  process.exit(2)
}

const targets = classifyManifest(manifest.opcodes)

const byClass = new Map<string, number>()
for (const target of targets) byClass.set(target.klass, (byClass.get(target.klass) ?? 0) + 1)

console.log(`manifest: ${manifest.opcodes.length} bytes, ${targets.length} active opcodes`)
console.log('classes:')
for (const [klass, count] of [...byClass].sort()) console.log(`  ${klass.padEnd(14)} ${count}`)

const issues: string[] = []
const measurable: string[] = []
const skipped: string[] = []

for (const target of targets) {
  if (target.klass === 'unreachable' || target.klass === 'terminating') {
    skipped.push(`${target.name}: ${target.reason ?? 'no reason recorded'}`)
    continue
  }
  let plan
  try {
    plan = planForTarget(target.byte, target.name, target.klass)
  } catch (error) {
    issues.push(`${target.name}: template threw ${(error as Error).message}`)
    continue
  }
  if (plan.unmeasurable) {
    skipped.push(`${target.name}: ${plan.unmeasurable}`)
    continue
  }
  const found = validatePlan(plan)
  if (found.length > 0) {
    for (const issue of found) issues.push(`${issue.name}: ${issue.problem}`)
    continue
  }
  measurable.push(`${target.name} (max ${maxRepetitions(plan)} reps)`)
}

for (const precompile of PRECOMPILE_TARGETS) {
  const plan = precompilePlan(precompile.address, precompile.name, precompile.inputBytes)
  const found = validatePlan(plan)
  if (found.length > 0) {
    for (const issue of found) issues.push(`${issue.name}: ${issue.problem}`)
  } else {
    measurable.push(`${precompile.name} (precompile, max ${maxRepetitions(plan)} reps)`)
  }
}

console.log(`\nmeasurable: ${measurable.length}`)
console.log(`skipped with a stated reason: ${skipped.length}`)
for (const line of skipped) console.log(`  - ${line}`)

if (issues.length > 0) {
  console.log(`\nTEMPLATE ISSUES: ${issues.length}`)
  for (const line of issues) console.log(`  ! ${line}`)
  process.exit(1)
}

// Show one assembled sample so a reviewer can eyeball the bytes.
const sample = planFor(0x01, 'ADD', 'binary')
console.log(`\nsample ADD at 4 repetitions: ${toHex(assemble(sample, 4))}`)
console.log('\nno template issues')
