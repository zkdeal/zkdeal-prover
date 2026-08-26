/**
 * Re-derive every gradient from recorded points, without re-proving anything.
 *
 * The sweep originally fitted `totalCycles`. That field is padded up to a
 * segment boundary, so both it and every difference between two of its values
 * are multiples of 2^SEGMENT_PO2. On a two-point fit the gradient is therefore
 * quantised to the segment size - which is noise on a row costing tens of
 * millions of cycles and a sixth of the answer on a row costing 400k.
 *
 * Every proof record already carries the exact `cycles` alongside it, so the
 * correction costs nothing: no GPU, no re-run, same underlying measurements.
 *
 *   node refit.mjs <proofs.jsonl | summary.json> [...]
 *
 * Prints the corrected table and the size of the correction, and writes
 * `<input>.refit.json` next to each input.
 */

import { readFileSync, writeFileSync } from 'node:fs'

/** Least-squares slope and intercept, matching the sweep's own `fit`. */
function fit(points, pick) {
  const n = points.length
  if (n < 2) return { slope: 0, intercept: n === 1 ? pick(points[0]) : 0 }
  const meanX = points.reduce((sum, p) => sum + p.units, 0) / n
  const meanY = points.reduce((sum, p) => sum + pick(p), 0) / n
  let num = 0
  let den = 0
  for (const point of points) {
    num += (point.units - meanX) * (pick(point) - meanY)
    den += (point.units - meanX) ** 2
  }
  const slope = den === 0 ? 0 : num / den
  return { slope, intercept: meanY - slope * meanX }
}

function rowsOf(path) {
  const text = readFileSync(path, 'utf8')
  if (path.endsWith('.jsonl')) {
    return text.split('\n').filter(Boolean).map((line) => JSON.parse(line))
  }
  const parsed = JSON.parse(text)
  return Array.isArray(parsed) ? parsed : (parsed.rows ?? [])
}

for (const path of process.argv.slice(2)) {
  const rows = rowsOf(path)
  const corrected = []
  console.log(`=== ${path}`)
  console.log(
    `${'row'.padEnd(22)} ${'exact c/g'.padStart(11)} ${'quantised'.padStart(11)} ${'delta'.padStart(9)}`,
  )

  for (const row of rows) {
    if (row.status !== 'OK' || !Array.isArray(row.points) || row.points.length < 2) {
      corrected.push(row)
      continue
    }
    // A row proved without cycle data cannot be refitted; leaving it untouched
    // is correct, but say so rather than silently emitting the old number.
    if (!row.points.some((point) => typeof point.cycles === 'number' && point.cycles > 0)) {
      console.log(`${String(row.name).padEnd(22)} ${'no cycle data'.padStart(11)}`)
      corrected.push(row)
      continue
    }

    const gas = fit(row.points, (point) => point.executedGas)
    const exact = fit(row.points, (point) => point.cycles ?? 0)
    const quantised = fit(row.points, (point) => point.totalCycles ?? 0)

    const exactPerGas = gas.slope === 0 ? null : exact.slope / gas.slope
    const quantPerGas = gas.slope === 0 ? null : quantised.slope / gas.slope
    const delta =
      exactPerGas && quantPerGas ? ((quantPerGas - exactPerGas) / exactPerGas) * 100 : null

    corrected.push({
      ...row,
      cyclesPerUnit: exact.slope,
      cyclesIntercept: exact.intercept,
      cyclesPerGas: exactPerGas,
      totalCyclesPerUnit: quantised.slope,
      totalCyclesPerGas: quantPerGas,
      refit: 'exact user cycles',
    })

    console.log(
      `${String(row.name).padEnd(22)} ${(exactPerGas ?? 0).toFixed(2).padStart(11)} ` +
        `${(quantPerGas ?? 0).toFixed(2).padStart(11)} ` +
        `${delta === null ? '' : `${delta >= 0 ? '+' : ''}${delta.toFixed(1)}%`.padStart(9)}`,
    )
  }

  const out = `${path.replace(/\.(jsonl|json)$/, '')}.refit.json`
  writeFileSync(out, JSON.stringify(corrected, null, 2))
  console.log(`-> ${out}\n`)
}
