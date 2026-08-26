/**
 * The sweep driver.
 *
 * Two passes, and the first one is free. `/v5/rooms/execute` runs the batch
 * natively on the host CPU and returns the complete `proofWork` block without
 * taking the prover's single GPU permit, so the entire plan - every row, every
 * point - can be validated before a single GPU second is spent. A template that
 * underflows, reverts, runs out of gas or accidentally fuses is caught here,
 * where a mistake costs milliseconds instead of hours.
 *
 * Only rows that pass the dry run are eligible for the prove pass.
 *
 * Usage, from `prover-node/`:
 *   node --experimental-strip-types scripts/opcode-cost/sweep.mts \
 *     --manifest <osaka-manifest.json> --out <dir> [--prove] [--only NAME,NAME]
 */

import { mkdirSync, writeFileSync, appendFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { readFileSync } from 'node:fs'
import {
  assemble, callTemplate, maxUnits, templateFor, toHex, type UnitPlan,
} from './bytecode.mts'
import {
  classifyManifest, PRECOMPILE_TARGETS, precompileAddresses, type ManifestEntry,
} from './targets.mts'
import { VECTOR_ROWS } from './precompile-vectors.mts'

const args = process.argv.slice(2)
function flag(name: string): string | undefined {
  const index = args.indexOf(name)
  return index >= 0 ? args[index + 1] : undefined
}
const MANIFEST = flag('--manifest') ?? '/data/osaka-manifest.json'
const OUT = flag('--out') ?? '/data/sweep'
const PROVE = args.includes('--prove')
const ONLY = flag('--only')?.split(',').map((name) => name.trim())
const BASE = process.env.PROVER_URL ?? 'http://127.0.0.1:8099'
// When the sweep borrows a prover that is already part of a running stack -
// which is the only safe way to do this, since a second CUDA process just
// exhausts the card - that prover enforces its own shared secret.
const PROVER_TOKEN = process.env.ZKDEAL_PROVER_TOKEN ?? ''
// Node's global fetch is backed by undici, whose header timeout is 300s and is
// not adjustable without the undici package. A single proof that runs longer
// than that surfaces as a bare "fetch failed" - which is exactly what the
// expensive precompile rows produced. Capping the units per row keeps every
// proof inside that window; the slope is unaffected, only the lever arm
// shortens, and the fit quality is reported per row either way.
const MAX_UNITS_OVERRIDE = Number(process.env.SWEEP_MAX_UNITS ?? 0)
/** Generous, but bounded: a stalled prover must not hang the sweep forever. */
const REQUEST_TIMEOUT_MS = Number(process.env.SWEEP_REQUEST_TIMEOUT_MS ?? 1_800_000)

mkdirSync(OUT, { recursive: true })

async function post(path: string, body: unknown): Promise<any> {
  // Deliberately node:http and not fetch.
  //
  // Node's global fetch is backed by undici, whose 300-second header timeout is
  // not adjustable without the undici package. A bn254 or BLS pairing proof
  // runs far longer than that - pairing is orders of magnitude more cycles per
  // gas than anything else measured here - and the timeout surfaces as a bare
  // "fetch failed" with no indication that the request was still being served.
  // node:http lets the deadline be stated explicitly.
  const url = new URL(`${BASE}${path}`)
  const payload = Buffer.from(JSON.stringify(body))
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'content-length': String(payload.byteLength),
  }
  if (PROVER_TOKEN) headers.authorization = `Bearer ${PROVER_TOKEN}`
  return await new Promise((resolve, reject) => {
    const request = httpRequest(
      {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: 'POST',
        headers,
      },
      (response) => {
        const chunks: Buffer[] = []
        response.on('data', (chunk: Buffer) => chunks.push(chunk))
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8')
          if (!(response.statusCode && response.statusCode >= 200 && response.statusCode < 300)) {
            reject(new Error(`${path} HTTP ${response.statusCode}: ${text.slice(0, 300)}`))
            return
          }
          try {
            resolve(text ? JSON.parse(text) : null)
          } catch (error) {
            reject(new Error(`${path} returned unparseable JSON: ${(error as Error).message}`))
          }
        })
      },
    )
    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy(new Error(`${path} exceeded ${REQUEST_TIMEOUT_MS} ms`))
    })
    request.on('error', reject)
    request.end(payload)
  })
}

/**
 * One base request for the whole sweep; only `runtimeCode` varies.
 *
 * Every precompile address is seated as a resident account. The compact witness
 * is a hard allow-list: a STATICCALL to an undeclared address fails with
 * `Database(UndeclaredAccount)` before the precompile is ever reached. This was
 * confirmed empirically rather than assumed.
 */
const PRECOMPILES = precompileAddresses()
const CALL_GAS_LIMIT = 5_000_000
/** Gas forwarded to each precompile call; see FORWARDED_GAS in bytecode.mts. */
const FORWARDED_GAS = 1_000_000
/** Two blocks, one call each, so the batch's executed-gas ceiling is twice. */
const GAS_CEILING = 2 * CALL_GAS_LIMIT
const BASE_REQUEST = {
  deploymentDomain: `0x${'11'.repeat(32)}`,
  roomId: 1,
  l1ChainId: 31337,
  l1InclusionDeadline: 1_000_000,
  authorizationMode: 'unanimous-approvers',
  activeSigners: 1,
  participantCapacity: 128,
  registeredParticipants: 1,
  touchedParticipants: 1,
  touchedContracts: 1,
  residentAccounts: 2 + PRECOMPILES.length,
  residentMirrorVariables: 1,
  importedVariables: 0,
  workload: 'storage',
  stateCommitment: 'mpt',
  senderAccounts: PRECOMPILES,
  // The fixture defaults to 120000 gas per call, which caps a two-block batch
  // at 240000 and truncates every long row - the first dry run pinned every
  // non-zero point at exactly that number. The fixture permits up to 5000000,
  // which buys a lever arm about twenty times longer and therefore a far
  // better-conditioned slope.
  blockCalls: [
    [{ calldata: `0x12345678${'22'.repeat(32)}`, signerIndex: 0, gasLimit: CALL_GAS_LIMIT }],
    [{ calldata: `0x12345678${'33'.repeat(32)}`, signerIndex: 0, gasLimit: CALL_GAS_LIMIT }],
  ],
} as const

export interface Point {
  units: number
  executedGas: number
  opcodeSteps: number
  fusedMotifHits: number
  maxMemoryBytes: number
  encodedWitnessBytes: number
  precompileCalls: number
  cycles?: number
  totalCycles?: number
  segments?: number
  totalPipelineMs?: number
  compositeProofMs?: number
}

/**
 * Choose the largest unit count that fits BOTH the constant runtime length and
 * the batch's gas budget.
 *
 * Sizing on code length alone truncated every row: execution simply ran out of
 * gas and halted, which shows up as a flat gas curve rather than an error. The
 * per-unit gas cost is not known in advance for an arbitrary opcode, so it is
 * measured on a short probe and the cap derived from it. Two CPU calls per row.
 */
async function sizeRow(plan: UnitPlan): Promise<{ cap: number; probeGasPerUnit: number }> {
  const codeCap = maxUnits(plan)
  if (codeCap < 2) return { cap: 0, probeGasPerUnit: 0 }
  // Probe at one and two units and take the difference. A larger probe can
  // itself exceed the gas ceiling for an expensive operation - BN254 pairing
  // costs over 100k gas per call - and a clipped probe yields a nonsense
  // per-unit figure and therefore a nonsense cap. Differencing two adjacent
  // small counts also cancels any one-off cold surcharge on the first unit.
  const one = await measureGasOnly(toHex(assemble(plan, 1)))
  const two = await measureGasOnly(toHex(assemble(plan, 2)))
  const zero = one - (two - one)
  const perUnit = two - one
  if (!(perUnit > 0)) return { cap: Math.min(codeCap, 64), probeGasPerUnit: perUnit }
  // Leave headroom so the largest point cannot clip the ceiling.
  const gasCap = Math.floor((GAS_CEILING * 0.85 - zero) / perUnit)
  let cap = Math.max(4, Math.min(codeCap, gasCap))
  if (MAX_UNITS_OVERRIDE > 0) cap = Math.min(cap, MAX_UNITS_OVERRIDE)
  return { cap, probeGasPerUnit: perUnit }
}

async function measureGasOnly(runtimeCode: string): Promise<number> {
  const prepared = await post('/v5/rooms/prepare', { ...BASE_REQUEST, runtimeCode })
  const executed = await post('/v5/rooms/execute', prepared.roomRequest)
  return Number(executed.proofWork?.executedGas ?? 0)
}

/** Four points spanning the row, including the zero-unit baseline. */
function pointsFor(cap: number): number[] {
  if (cap < 12) return [0, Math.floor(cap / 2), cap]
  return [0, Math.floor(cap / 3), Math.floor((2 * cap) / 3), cap]
}

async function measure(runtimeCode: string, units: number): Promise<Point> {
  const prepared = await post('/v5/rooms/prepare', { ...BASE_REQUEST, runtimeCode })
  const executed = await post('/v5/rooms/execute', prepared.roomRequest)
  const work = executed.proofWork ?? {}
  const point: Point = {
    units,
    executedGas: Number(work.executedGas ?? 0),
    opcodeSteps: Number(work.opcodeSteps ?? 0),
    fusedMotifHits: Number(work.fusedMotifHits ?? 0),
    maxMemoryBytes: Number(work.maxMemoryBytes ?? 0),
    encodedWitnessBytes: Number(work.encodedWitnessBytes ?? 0),
    precompileCalls: Number(work.precompileCalls ?? 0),
  }
  if (PROVE) {
    const proof = await post('/v5/rooms/prove', { ...prepared.roomRequest, proofMode: 'succinct' })
    point.cycles = Number(proof.cycles ?? 0)
    point.totalCycles = Number(proof.totalCycles ?? 0)
    point.segments = Number(proof.segments ?? 0)
    point.totalPipelineMs = Number(proof.profile?.totalPipelineMs ?? 0)
    point.compositeProofMs = Number(proof.profile?.compositeProofMs ?? 0)
  }
  return point
}

/** Ordinary least squares of y on units, with a free intercept. */
function fit(points: readonly Point[], pick: (point: Point) => number) {
  const n = points.length
  const meanX = points.reduce((sum, point) => sum + point.units, 0) / n
  const meanY = points.reduce((sum, point) => sum + pick(point), 0) / n
  let numerator = 0
  let denominator = 0
  for (const point of points) {
    numerator += (point.units - meanX) * (pick(point) - meanY)
    denominator += (point.units - meanX) ** 2
  }
  const slope = denominator === 0 ? 0 : numerator / denominator
  const intercept = meanY - slope * meanX
  let worst = 0
  for (const point of points) {
    worst = Math.max(worst, Math.abs(pick(point) - (intercept + slope * point.units)))
  }
  const span = Math.abs(slope) * Math.max(...points.map((point) => point.units))
  return { slope, intercept, maxResidual: worst, nonlinearity: span === 0 ? 0 : worst / span }
}

/**
 * Verdicts a row can receive. A row that fails any of these is reported with
 * its status rather than being quietly averaged into the table.
 */
function verdict(
  points: readonly Point[],
  expectFused: number,
  expectPrecompile: (units: number) => number,
  isPrecompile: boolean,
): string {
  const first = points[0]!
  for (const point of points) {
    if (point.fusedMotifHits !== expectFused * point.units) return 'CONTAMINATED'
    if (point.precompileCalls !== expectPrecompile(point.units)) return 'PRECOMPILE_COUNT_MISMATCH'
    if (point.encodedWitnessBytes !== first.encodedWitnessBytes) return 'NOT_ISOLATED'
    if (point.maxMemoryBytes !== first.maxMemoryBytes) return 'MEMORY_LEAKED'
  }
  const gas = fit(points, (point) => point.executedGas)
  const steps = fit(points, (point) => point.opcodeSteps)
  if (gas.slope <= 0) return 'BELOW_RESOLUTION'
  // Executed gas rising while the opcode count does not means the frame halted
  // exceptionally and burned its budget: the instruction is present in revm's
  // manifest but not actually executable in this chain configuration. That is a
  // real finding about the build, not a measurement.
  if (steps.slope < 0.5 && gas.slope > 1000) return 'HALTS_IN_CONTEXT'
  if (gas.nonlinearity > 0.005) return 'NONLINEAR'
  // A precompile that rejects its input consumes ALL forwarded gas, and does so
  // perfectly linearly - so linearity alone cannot distinguish "measured the
  // precompile" from "measured a failure burning the gas budget". Two calls per
  // unit at FORWARDED_GAS each is the signature. The pairing, KZG and BLS rows
  // hit this with zeroed inputs: they need real curve points and a valid
  // commitment, not arbitrary bytes.
  if (isPrecompile && gas.slope >= 2 * FORWARDED_GAS * 0.95) return 'PRECOMPILE_CALL_FAILED'
  return 'OK'
}

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8')) as { opcodes: ManifestEntry[] }
const targets = classifyManifest(manifest.opcodes)

interface Row {
  name: string
  byte: number
  klass: string
  kind: 'opcode' | 'precompile'
  plan?: UnitPlan
  cap: number
}

const rows: Row[] = []
for (const target of targets) {
  if (['unreachable', 'forbidden', 'terminating', 'jump'].includes(target.klass)) continue
  const plan = templateFor(target.byte, target.name, target.klass)
  if (plan.unmeasurable) continue
  rows.push({ name: target.name, byte: target.byte, klass: target.klass, kind: 'opcode', plan, cap: maxUnits(plan) })
}
for (const precompile of PRECOMPILE_TARGETS) {
  // Rows with a dedicated vector are swept from that vector instead; a zeroed
  // buffer would short-circuit them (infinity points) or be rejected outright.
  if (VECTOR_ROWS.some((row) => row.address === precompile.address)) continue
  const plan = callTemplate(0xfa, precompile.name, precompile.address, precompile.argsSize)
  rows.push({ name: precompile.name, byte: precompile.address, klass: 'precompile', kind: 'precompile', plan, cap: maxUnits(plan) })
}
for (const vector of VECTOR_ROWS) {
  const plan = callTemplate(0xfa, vector.name, vector.address, 0, vector.input)
  rows.push({ name: vector.name, byte: vector.address, klass: 'precompile', kind: 'precompile', plan, cap: maxUnits(plan) })
}

const selected = ONLY ? rows.filter((row) => ONLY.includes(row.name)) : rows
console.log(`sweep: ${selected.length} rows, mode=${PROVE ? 'prove' : 'dry-run'}, out=${OUT}`)

const jsonl = `${OUT}/${PROVE ? 'proofs' : 'dry-run'}.jsonl`
writeFileSync(jsonl, '')
const summary: any[] = []
let ok = 0
let bad = 0

for (const row of selected) {
  const plan = row.plan!
  try {
    const sized = await sizeRow(plan)
    row.cap = sized.cap
    const units = pointsFor(row.cap)
    const points: Point[] = []
    for (const count of units) {
      points.push(await measure(toHex(assemble(plan, count)), count))
    }
    const expectPrecompile = row.kind === 'precompile' ? (n: number) => 2 * (n + 1) : () => 0
    const status = verdict(points, 0, expectPrecompile, row.kind === 'precompile')
    const gas = fit(points, (point) => point.executedGas)
    const steps = fit(points, (point) => point.opcodeSteps)
    const record: any = {
      name: row.name, byte: row.byte, klass: row.klass, kind: row.kind,
      unitBytes: plan.unit.length, cap: row.cap, status,
      gasPerUnit: gas.slope, gasIntercept: gas.intercept, gasNonlinearity: gas.nonlinearity,
      stepsPerUnit: steps.slope, points,
    }
    if (PROVE) {
      // FIT `cycles`, NOT `totalCycles`.
      //
      // `totalCycles` is padded up to a segment boundary, so every value is a
      // multiple of 2^SEGMENT_PO2 and so is every difference between two of
      // them. On a two-point fit that quantises the gradient to the segment
      // size: harmless on a row costing tens of millions of cycles, and worth
      // ~17% on a 393k-cycle row like BN254_ADD. It is also what once produced
      // negative cycles-per-instruction for the wide PUSH variants.
      //
      // `cycles` is the exact user cycle count and is deterministic for a given
      // guest and input, which is the property a gradient needs.
      const cycles = fit(points, (point) => point.cycles ?? 0)
      record.cyclesPerUnit = cycles.slope
      record.cyclesIntercept = cycles.intercept
      record.cyclesNonlinearity = cycles.nonlinearity
      record.cyclesPerGas = gas.slope === 0 ? null : cycles.slope / gas.slope
      // Kept alongside so the quantisation penalty stays visible in the
      // evidence rather than being something a reader has to take on trust.
      const quantised = fit(points, (point) => point.totalCycles ?? 0)
      record.totalCyclesPerUnit = quantised.slope
      record.totalCyclesPerGas = gas.slope === 0 ? null : quantised.slope / gas.slope
    }
    appendFileSync(jsonl, `${JSON.stringify(record)}\n`)
    summary.push(record)
    if (status === 'OK') ok += 1
    else bad += 1
    console.log(
      `${status === 'OK' ? 'ok  ' : 'BAD '} ${row.name.padEnd(20)} gas/unit=${gas.slope.toFixed(2).padStart(9)} ` +
        `steps/unit=${steps.slope.toFixed(1).padStart(6)} cap=${String(row.cap).padStart(5)} ${status === 'OK' ? '' : status}`,
    )
  } catch (error) {
    bad += 1
    const record = { name: row.name, byte: row.byte, kind: row.kind, status: 'ERROR', error: (error as Error).message }
    appendFileSync(jsonl, `${JSON.stringify(record)}\n`)
    summary.push(record)
    console.log(`ERR  ${row.name.padEnd(20)} ${(error as Error).message.slice(0, 120)}`)
  }
}

writeFileSync(`${OUT}/summary.json`, JSON.stringify({ ok, bad, rows: summary }, null, 2))
console.log(`\n${ok} ok, ${bad} not ok -> ${OUT}/summary.json`)
