# Opcode and precompile proving-cost evidence, RTX 5090, 2026-08-23 to 2026-08-26

Backing data for `../../EVM-GAS-VS-PROVING-COST.md`. One GPU, one guest build,
`SEGMENT_PO2` held fixed, succinct proof mode.

## Files

| File | Contents |
| --- | --- |
| `osaka-manifest.json` | The instruction inventory, dumped from the pinned interpreter rather than typed: 154 active opcodes, 18 precompiles |
| `prove-production/summary.json` | All 156 attempted rows on the shipped guest, **with raw per-point measurements** |
| `prove-production/summary.refit.json` | The same rows refitted on exact `cycles` |
| `prove-baseline/summary.json` | The comparison build with the 50-motif fusion dispatcher compiled out |
| `vec-batch1/` | ECRECOVER, MODEXP, bn254 add/mul, BLS12 G1ADD/G2ADD, map-to-G1, P256VERIFY - real vectors |
| `vec-batch2/` | BLS12 G1MSM/G2MSM at k=1 and k=2, map-to-G2 - real vectors |
| `vec-heavy2/` | bn254 pairing at k=1/2/4, KZG point evaluation, BLS12 pairing k=1 |
| `vec-final/` | BLAKE2F at 1, 12, 256 and 4096 rounds |
| `vec-dry-final/summary.json` | The free dry-run pass that validated all 14 corrected rows before any GPU time |

## Why the raw points are kept

Each `points` array retains `units`, `executedGas`, `opcodeSteps`,
`precompileCalls`, `cycles`, `totalCycles`, `segments` and timings. That is what
makes `scripts/opcode-cost/refit.mjs` possible: when the sweep was found to be
fitting `totalCycles` - which is padded to a segment boundary, so both it and
every difference between two of its values are multiples of `2^SEGMENT_PO2` -
every affected row was corrected from these files rather than by re-proving.
Refitting moves a row by between -15% and +45%.

Reducing these to the published columns would have made that correction cost
another night of GPU time. They stay in full.

## `proofs.jsonl` versus `summary.json`

`proofs.jsonl` is appended as each row completes, so it survives a run that dies
partway; `summary.json` is written once at the end. Where both exist they carry
the same rows. `proofs.refit.json` is the refitted form.

## Reading the precompile rows

A unit is **two** precompile calls, so `cyclesPerUnit` and `gasPerUnit` are the
marginal cost of a pair. `cyclesPerGas` is unaffected by that convention and is
the column the document publishes.

Rows carry `status`. Only `OK` rows were published; `PRECOMPILE_COUNT_MISMATCH`,
`CONTAMINATED`, `NONLINEAR` and `BELOW_RESOLUTION` rows are retained so that a
reader can see what was excluded and why.

## What is not here

The `remeasure/` run of 2026-08-25 is omitted: all 14 of its rows are
`ERROR`, with `socket hang up` and `ECONNREFUSED` - the stack was torn down
underneath it. It measured nothing and is not evidence of anything.

Earlier dry-run directories (`dry1` through `dry8`, `vec1`, `vec3`, `smoke`,
`vec-prove`, `vec-prove2`, `vec-heavy`) are development iterations superseded by
the runs above.
