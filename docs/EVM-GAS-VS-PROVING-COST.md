# EVM gas versus zk proving cost on the zkdeal prover

Status: SUGGESTION. These are our own measurements on one GPU and one guest
build. Nothing here is a standard, a specification, or a proposal to change
Ethereum's gas schedule. It exists so that a third party hosting a zkdeal
verifier, or an application developer writing a room, can reprice against
numbers rather than against intuition - and can re-derive those numbers on
their own hardware with the harness in this repository.

**The single most important thing in this document is not a number. It is that
published per-opcode results from other RISC Zero deployments do not transfer
to this one.** Which primitives a zkVM accelerates changes the ranking
completely, and our accelerator set is deliberately minimal.

## Decision

Ethereum's gas schedule was calibrated against CPU execution. Inside a zkVM the
cost structure is different, and it differs again between two zkVMs, and again
between two builds of the same zkVM. We therefore publish a measured
cycles-per-gas figure per instruction for this prover, and a repricing
multiplier derived from it, as an input to someone else's pricing decision
rather than as a schedule of our own.

## What this prover actually accelerates

This is the fact that governs every result below.

| Primitive | Treatment in the guest | Source |
| --- | --- | --- |
| Keccak-256 - the opcode, trie hashing, transaction hashes | RISC Zero keccak coprocessor, recursively verified | `zkvm/crates/risc0/methods/guest/src/native_keccak.rs`, guest `Cargo.toml` `native-keccak` |
| secp256k1 - sender recovery and ECRECOVER | Patched k256 over the RISC Zero bigint accelerator | guest `Cargo.toml` `[patch.crates-io]`, `zkvm/vendor/rustcrypto-k256` |
| SHA-256, RIPEMD-160, MODEXP, bn254, BLAKE2F, KZG, BLS12-381, P-256 | **Unaccelerated.** Stock crates.io, compiled to RISC-V | guest `Cargo.lock` |

The `[patch.crates-io]` block in the guest manifest contains exactly two
entries: `k256` and `crypto-bigint`. `sha2` is **not** swapped for an
accelerated fork.

The consequence is direct. Nethermind's January 2026 per-opcode study reports
that on stock RISC0, SHA-256 was roughly **10x cheaper per unit gas than on
SP1**, while KECCAK256 was roughly **12x more expensive**. The SHA-256 half of
that result is a property of an accelerated `sha2`, and **this build does not
have one**. Anyone pricing our prover from those published figures would
under-price SHA-256 substantially. That is the concrete reason this document
exists.

## Evidence boundary

| Item | Value |
| --- | --- |
| What is measured | Marginal cost per executed instruction, by regression over a two-block certified v5 room batch |
| Metric | RISC Zero `cycles` (exact user cycles) and executed gas from the same revm the guest runs. NOT `totalCycles`, which is quantised to segment boundaries and produced negative per-instruction fits |
| Wall clock | Derived from a separate global calibration, never regressed against instruction count - see "Why milliseconds are not fitted directly" |
| Instruction inventory | Dumped from the pinned interpreter, not transcribed: 154 active opcodes, 18 precompiles |
| Hardware | One RTX 5090 |
| Excluded | L1 broadcast and settlement gas, host queueing, Groth16 wrapping (the sweep proves in succinct mode), and anything about other zkVMs |

## Method

For each instruction we emit runtimes containing 0, N/3, 2N/3 and N repetitions
of a stack-neutral unit, prove each, and fit `cost = alpha * units + beta`.
`alpha` is the marginal cost; `beta` absorbs everything that is not the
instruction - cold-template validation, MPT root recomputation, signature
recovery, proof setup, compression. **No absolute is ever quoted; only the
gradient.** This is the marginal-regression approach used by the Nethermind
study, and it is the only way to isolate an instruction from a fixed batch cost
far larger than it.

Four properties hold by construction and are asserted against the prover's own
counters on every sample, not assumed:

* **Constant code length.** Every variant is padded to exactly 24576 bytes.
  Code length is itself a cost - JUMPDEST analysis, the code hash, a dynamic
  control-flow scan, all linear in length, and the code hash re-enters the state
  root each block. Verified by `encodedWitnessBytes` being byte-identical across
  a row.
* **Stack neutrality.** A reservoir pushed once in the prologue is never
  consumed; each unit duplicates the operands it needs and pops its results.
* **No accidental instruction fusion.** The guest replaces 50 ranked adjacent
  ALU pairs with single dispatches. Every unit follows its target with POP or
  DUP, neither of which is any motif's second byte. Verified by
  `fusedMotifHits == 0`.
* **Predictable gas.** A reverted or halted transaction still produces a valid
  proof of a truncated execution, so a broken template yields a clean gradient
  of the wrong thing. Executed gas is asserted against the static prediction.

Gas constants are never transcribed into the harness. `executedGas` comes from
the same pinned revm the guest executes, so the gas gradient is fitted from the
same samples as the cycle gradient.

### Why milliseconds are not fitted directly

Exact user cycle counts are a deterministic function of the witness: same
guest, same input, same count. `totalCycles` is not usable for this - it is
padded to segment boundaries, so quantisation noise of a quarter-segment swamps
per-instruction differences of a few hundred cycles. Wall clock is not, and worse, it is a **step function** of
cycles, because segments are `ceil(totalCycles / 2^SEGMENT_PO2)` and
`SEGMENT_PO2` is fixed for the process. Regressing milliseconds against
instruction count would fit a staircase with a line. Cycles are therefore the
primary metric, and seconds are derived from a separate calibration of
wall clock against segments and cycles. Repeated proofs are a **determinism
check**, not a variance estimate: a mismatch invalidates the premise rather
than needing an average.

### The dispatch floor

`JUMPDEST` is the cheapest repeatable instruction: interpreter dispatch plus
the policy inspector's per-opcode callback plus a no-op body. Every row is
reported both raw and floor-subtracted. The inspector cannot be subtracted
directly - nothing executes without it - so the floor is published as one
lumped quantity rather than split.

## Results

Measured 2026-08-24 on one RTX 5090, `SEGMENT_PO2` fixed, succinct proof mode,
147 instructions fitted cleanly out of 156 attempted. Cycles are exact user
cycles, corrected for the padding artifact described below. MEASURED unless
noted.

Calibration from 588 proved points: `compositeProofMs = 5231 + 9.676e-4 *
cycles`, i.e. **1,033,530 proving cycles per second** on this card.

| Instruction | Accel | cycles | gas | cycles/gas | EF | L2 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `JUMPDEST` | no | 167 | 2 | 83.6 | 607x | 202x |
| `SWAP1` | no | 429 | 6 | 71.5 | 519x | 173x |
| `POP` | no | 380 | 10 | 38.0 | 276x | 92x |
| `ADD` | no | 993 | 22 | 45.1 | 327x | 109x |
| `MUL` | no | 1413 | 26 | 54.3 | 394x | 131x |
| `DIV` | no | 1315 | 26 | 50.6 | 367x | 122x |
| `EXP` | no | 9217 | 136 | 67.8 | 492x | 164x |
| `KECCAK256` | **yes** | 4427 | 88 | 50.3 | 365x | 122x |
| `MLOAD` | no | 836 | 16 | 52.2 | 379x | 126x |
| `MSTORE` | no | 854 | 18 | 47.4 | 344x | 115x |
| `SLOAD` (warm) | no | 1916 | 210 | 9.1 | 66x | 22x |
| `SSTORE` (warm) | no | 3810 | 212 | 18.0 | 131x | 44x |
| `LOG0` | no | 1448 | 1274 | 1.1 | 8x | 3x |
| `LOG4` | no | 3148 | 4298 | 0.7 | 5x | 2x |
| `SHA256` | no | 30443 | 408 | **74.6** | 541x | 180x |
| `RIPEMD160` | no | 22711 | 1920 | 11.8 | 86x | 29x |
| `IDENTITY` | no | 12425 | 282 | 44.1 | 320x | 107x |

**The other precompiles are deliberately not in this table.** Their first
measurement was taken against zeroed input, which several of them reject or
short-circuit, and the numbers it produced were wrong by between 13x and 240x.
The corrected figures are in "Precompiles, measured against inputs that make
them work" below, and the three rows kept here are the three whose cost is
driven by input *length* rather than input *value*, which zero bytes represent
faithfully.

The two rightmost columns are the repricing multiple `m = (t/g) * R_target`
required for a block of that instruction to prove inside the stated throughput.
The EF column uses their L1 target of 60M gas in 8 seconds; the L2 column uses
zkdeal's own 30M block gas limit at a 12-second cadence.

### The accelerator result

**SHA-256 costs 1.48x more proving per unit gas than Keccak-256 here** (74.6
against 50.3 cycles/gas).

Acceleration is visible in ECRECOVER, but it does not make it cheap. Against a
real signature it costs **185.2 cycles/gas** - roughly 2.4x *worse* than the
one-gas dispatch floor, and nine times better than the unaccelerated P-256
verification that does the same job on a different curve (1,634.8). Both numbers
matter: the patched `k256` is worth about an order of magnitude, and an order of
magnitude is not enough to bring a signature check into line with the schedule.

An earlier revision of this document reported ECRECOVER at 2.0 cycles/gas and
called it the cheapest instruction in the table. That figure was measured
against a zeroed input, which fails the range check before any curve arithmetic
happens. See the precompile section below.

That ordering is a direct consequence of which two primitives this build
accelerates, and it is the reverse of what published RISC0 figures would
predict. Nethermind measured SHA-256 as roughly 10x *cheaper* per unit gas on
RISC0 than on SP1, on a build with an accelerated `sha2`. Pricing this prover
from those numbers would under-price SHA-256 by a wide margin.

### Among opcodes, the cheap ones are the worst value

The dispatch floor - `JUMPDEST`, one gas - costs 167 cycles, giving the worst
cycles-per-gas ratio of any *opcode* at 83.6. Interpreter dispatch plus the
policy inspector's per-opcode callback dominates anything a one-gas instruction
does. `SWAP` and `POP` follow for the same reason.

The opcodes with the *best* ratios are the ones the gas schedule already prices
highly: `LOG4` at 0.7, `LOG0` at 1.1, `SLOAD` at 9.1. Within the opcode set, the
mispricing really is concentrated in trivial instructions.

**That conclusion does not extend to the precompiles, and an earlier revision of
this document wrongly said it did.** Once measured against inputs that make them
work, the cryptographic precompiles run from 2.2x the dispatch floor
(`ECRECOVER`, accelerated) to 34x it (KZG point evaluation), and they hold every
one of the top places in the whole study.

The one precompile that stays below the floor is `BLAKE2F` at a single round -
67.1 - and it is the exception that confirms the rule: its gas is literally its
round count, so it is the only row in the set whose schedule already tracks the
work done. At 4,096 rounds it is at 672.1, with the same slope as everything
else here.

So the mispricing is concentrated at both ends: trivial opcodes, and
cryptography the guest has no accelerator for.

### Precompiles, measured against inputs that make them work

Measured 2026-08-25 and 2026-08-26. Every row below uses a real input; the
previous figures used zeroed buffers and are withdrawn.

**Why the first numbers were wrong.** The measurement template ends
`STATICCALL, POP` - it discards the success flag, which is correct for
measurement, because branching on the result would put a comparison inside the
repeated unit and contaminate the gradient. The consequence is that a precompile
which *rejects* its input is indistinguishable from one that accepts it. Both
return, both charge gas, and the gas column matched the published schedule
exactly the whole time. Nothing looked wrong.

But a zeroed buffer is not a neutral input to elliptic-curve code. It decodes to
the point at infinity, which every curve precompile short-circuits; a zero
MODEXP exponent returns immediately; and an all-zero signature fails ECRECOVER's
range check before any curve arithmetic runs. The recorded cost was the cost of
the early exit.

**How the inputs were established.** Every vector is now checked against a real
EVM before a GPU second is spent on it - `scripts/opcode-cost/verify-vectors.sh`
starts a disposable anvil, calls each precompile, and requires the schedule's
output length (an empty return is a rejection) and a non-infinity result, except
where zero is the honest answer for a pairing check. The curve points are sliced
out of pairing vectors already in this repository, so they are subgroup-checked
by construction. The two ECDSA vectors are generated from raw curve arithmetic
and verified against the verification equation, and for ECRECOVER against an
independently computed recovery, rather than copied from any published test set.
All 23 vectors pass, and the two independently derived answers match exactly.

| Precompile | cycles/unit | gas/unit | cycles/gas | EF | L2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `BLAKE2F_r1` | 16,235 | 242 | 67.1 | 487x | 162x |
| `BLAKE2F_r12` | 31,418 | 264 | 119.0 | 864x | 288x |
| `ECRECOVER` | 1,155,371 | 6,240 | 185.2 | 1,344x | 448x |
| `MODEXP_32` | 1,712,223 | 8,400 | 203.8 | 1,479x | 493x |
| `BLAKE2F_r256` | 368,140 | 752 | 489.5 | 3,552x | 1,184x |
| `BN254_ADD` | 271,200 | 540 | 502.2 | 3,644x | 1,215x |
| `BN254_PAIRING_k1` | 86,685,937 | 158,240 | 547.8 | 3,975x | 1,325x |
| `BN254_PAIRING_k2` | 126,456,786 | 226,240 | 558.9 | 4,056x | 1,352x |
| `BN254_PAIRING_k4` | 205,903,905 | 362,240 | 568.4 | 4,125x | 1,375x |
| `BLS12_G1ADD` | 636,954 | 990 | 643.4 | 4,669x | 1,556x |
| `BLAKE2F_r4096` | 5,667,333 | 8,432 | 672.1 | 4,877x | 1,626x |
| `BN254_MUL` | 8,512,051 | 12,240 | 695.4 | 5,047x | 1,682x |
| `BLS12_G2ADD` | 1,022,538 | 1,440 | 710.1 | 5,153x | 1,718x |
| `BLS12_MAP_FP2_TO_G2` | 39,552,598 | 47,840 | 826.8 | 6,000x | 2,000x |
| `BLS12_G1MSM_k2` | 43,493,821 | 45,792 | 949.8 | 6,892x | 2,297x |
| `BLS12_PAIRING_k2` | 211,123,802 | 206,040 | 1,024.7 | 7,436x | 2,479x |
| `BLS12_PAIRING_k1` | 153,513,044 | 140,840 | 1,090.0 | 7,910x | 2,637x |
| `BLS12_MAP_FP_TO_G1` | 12,869,029 | 11,240 | 1,144.9 | 8,308x | 2,769x |
| `BLS12_G1MSM_k1` | 28,572,400 | 24,240 | 1,178.7 | 8,554x | 2,851x |
| `BLS12_G2MSM_k2` | 109,803,169 | 90,240 | 1,216.8 | 8,830x | 2,943x |
| `P256VERIFY` | 22,952,300 | 14,040 | 1,634.8 | 11,863x | 3,954x |
| `BLS12_G2MSM_k1` | 76,587,889 | 45,240 | 1,692.9 | 12,285x | 4,095x |
| `POINT_EVALUATION` | 287,195,711 | 100,240 | 2,865.1 | 20,791x | 6,930x |

A unit is two calls, so `cycles/unit` is the marginal cost of a pair; the
`cycles/gas` column is unaffected by that convention. `BLAKE2F_rN` sweeps the
round count against a constant 213-byte input, which separates work from size by
construction, so its four rows are one operation at four workloads rather than
four operations.

**The size of the correction.** These are not refinements of the old numbers.

| Precompile | published (zeroed) | real input | wrong by |
| --- | ---: | ---: | ---: |
| `ECRECOVER` | 2.0 | 185.2 | 93x |
| `BN254_MUL` | 2.9 | 695.4 | 240x |
| `MODEXP` | 11.3 | 203.8 | 18x |
| `BLS12_G1ADD` | 27.9 | 643.4 | 23x |
| `BN254_ADD` | 37.7 | 502.2 | 13x |

The three length-driven precompiles - `SHA256`, `RIPEMD160`, `IDENTITY` - were
re-checked and are unaffected, which is the expected result and a useful control:
it says the correction is about input *validity*, not about the harness at
large.

**Where the schedule discounts in the right direction, and where it does not.**
Every BLS12-381 row that has a `k` gets *cheaper per gas as `k` grows*: G1 MSM
1,178.7 to 949.8, G2 MSM 1,692.9 to 1,216.8, pairing 1,090.0 to 1,024.7. Adding
a second point roughly doubles the gas but adds well under double the proving
work, because EIP-2537's per-`k` charge sits on top of a large fixed term
(37,700 for pairing) that amortises.

bn254 pairing does the opposite: 547.8, 558.9, 568.4 at k=1, 2 and 4 - slightly
*worse* per gas each time. Its fixed term is proportionally smaller, so there is
less to amortise and the marginal pair costs a little more than the schedule
charges for it.

Neither is a large effect, but the direction is worth having: on this prover the
BLS12-381 discount table tracks real marginal cost, and bn254's does not quite.

**What this changes.** KZG point evaluation at 2,865 cycles/gas is the worst
mispricing in the study by a wide margin: a flat 50,000-gas charge for 287
million cycles across two calls. Behind it, a single-point BLS12-381 G2 MSM at
1,692.9, P-256 verification at 1,634.8, and the BLS12-381 map-to-curve and
pairing rows all sit between 550 and 1,693. Every one of these is unaccelerated
in this guest, and the ranking is almost exactly the list of primitives from the
accelerator table above, in the order of how much arithmetic they do.

The practical reading for a verifier host is that cryptographic precompiles, not
opcodes, dominate the risk. A room whose workload is ordinary EVM execution
prices at roughly 45 cycles/gas; a room that verifies a KZG proof pays sixty
times that per unit gas, and the gas schedule signals none of it.

### Absolute throughput, stated plainly

At a median 45.9 cycles per gas for common ALU work and 1.03M proving cycles per
second, this prover sustains roughly **22,500 gas per second**. Every one of the
147 measured instructions needs a multiplier above 1 at the EF target. Across
opcodes that range is 5.3x to 832x, and against zkdeal's own L2 parameters 1.8x
to 277x.

The corrected precompile rows extend the top of that range by more than an order
of magnitude, to **20,791x** at the EF target for KZG point evaluation. The
earlier figure of 832x was the widest gap in a table whose precompile rows were
measured against inputs those precompiles rejected.

The honest reading is not "reprice these few opcodes." It is that a single-GPU
prover of this design is three orders of magnitude away from L1 block-proving
throughput, and that gas as currently priced does not bound proving time at any
rate close to it. Repricing individual instructions changes the shape of that
gap; it does not close it.

### Fused motifs did not pay for themselves

The production guest replaces 50 ranked adjacent ALU pairs with single
dispatches. Measured against a guest with that dispatcher compiled out, across
the same 147 instructions:

* The median difference is **zero cycles**.
* The largest saving on any row is 70 cycles (0.0%).
* Several ALU instructions are consistently *more* expensive with the
  dispatcher present: `SLT` -126, `SHR` -124, `SHL` -120, `MUL` -116 cycles.

Read carefully: these templates deliberately never fuse - each unit is followed
by `POP` or `DUP`, and `fusedMotifHits == 0` is asserted on every sample. So
this measures the **dispatcher tax on code that does not fuse**, which is about
120 cycles per affected instruction, and not the benefit on code that does. It
is consistent in sign and magnitude with the -3.17% aggregate reported in
`book/docs/performance/TOP-50-EVM-GADGETS.md`, and it says the dispatcher needs
real fusion density to break even.

### The padding artifact, and why the PUSH family is the calibration

Every variant is padded to a constant 24576 bytes, which holds code *length*
constant but not code *analysis cost*: JUMPDEST analysis skips PUSH immediates
wholesale while scanning padding byte by byte. Adding a unit displaces padding,
so a naive fit understates cost.

`PUSH1` through `PUSH32` all perform identical work - push one word, pop it -
and differ only in unit length, which makes them a free in-situ calibration.
Regressing the family gives **15.18 user cycles per displaced padding byte**,
after which all 32 variants agree at 369.9 cycles with a 4.4% maximum residual.
Every row above carries that correction.

Before the correction, `PUSH23` through `PUSH32` fitted to *negative* cycles per
instruction. A negative result is what exposed the artifact; a table without
that internal cross-check would have shipped the bias silently.

### Rows that are not measurements

Every row in the table is one of:

| Status | Meaning |
| --- | --- |
| OK | Fitted cleanly; gradient published |
| PRECOMPILE_CALL_FAILED | The precompile rejected its input and burned the forwarded gas; not a measurement |
| HALTS_IN_CONTEXT | Present in the interpreter's manifest but not executable in this chain configuration |
| NONLINEAR | Curvature above tolerance; secants published instead of a slope |
| BELOW_RESOLUTION | Gradient indistinguishable from the noise floor |

## Honest limitations

* **One GPU, one guest build, one segment size.** Nothing here transfers to
  other hardware without re-running the harness, and the harness is in this
  repository precisely so that it can be re-run.
* **The ranking is a property of our accelerator set, not of RISC Zero.** A
  build that patches `sha2` would produce a materially different table. This is
  the same reason the Nethermind numbers do not apply to us.
* **One proof failed its own verification, once.** `BLS12_PAIRING_k2` first
  returned `verify segment: verification indicates proof is invalid` - RISC
  Zero's `VerificationError::InvalidProof`, not a request rejection. It was
  re-run on an idle card and succeeded, taking 32 minutes and peaking at 16.5 GB
  of VRAM for a 639-million-cycle proof, the largest in this study; the row in
  the table is that successful run and its fit is clean and linear. The first
  attempt was sharing the prover with a soak. A prover that emits a receipt
  failing its own verification is not a normal failure mode even when it does
  not reproduce, so it is recorded here rather than dropped as a flake. It is
  one observation and should not be read as more than that.
* **The precompile rows are three-point fits with a short lever arm.** Units
  {0, 1, 2} rather than the {0, N/3, 2N/3, N} used for opcodes, because a single
  proof at a high unit count on a pairing row runs into hundreds of millions of
  cycles. The gradient is therefore less well conditioned than an opcode row.
  Refitting each row on the segment-quantised `totalCycles` instead of exact
  cycles moves it by between -15% and +45%, which is a fair estimate of the
  remaining uncertainty; treat the precompile figures as accurate to roughly a
  factor of 1.5, not to three digits. The ordering is not in doubt.
* **The precompile inputs are now real, and were not before.** Every vector is
  verified against a live EVM by `scripts/opcode-cost/verify-vectors.sh` before
  it is used. Nothing in the current table is measured against an input its
  precompile rejects. The measurement template still discards the STATICCALL
  success flag by design, so this property is enforced by that script and not by
  the sweep itself - if you add a vector, run it.
* **CREATE, CREATE2, SELFDESTRUCT and CALLCODE cannot be measured on the shipped
  image.** The guest rejects a policy permitting creation or self-destruct
  before execution begins, and latches CALLCODE as a violation during it. This
  is not a configuration that can be relaxed host-side; it would require a
  separate, explicitly non-production guest with a different image id.
* **Storage rows are warm.** Repeating against one slot measures the warm cost;
  the cold surcharge is a one-off that belongs in the intercept.
* **This says nothing about whether a repricing is safe to adopt.** Changing gas
  costs affects contracts that use `GAS`, `GASLEFT` and fixed-gas calls. That
  compatibility question is real and is not addressed here.

## Reproducing this

The harness lives in `scripts/opcode-cost/` alongside this document. The
instruction inventory is derived from the interpreter rather than typed, so a
new opcode cannot silently vanish from the table:

```bash
docker compose run --rm test cargo run -p stf-core --bin dump-opcode-manifest > manifest.json
scripts/opcode-cost/verify-vectors.sh
node --experimental-strip-types scripts/opcode-cost/sweep.mts --manifest manifest.json --out ./out
node --experimental-strip-types scripts/opcode-cost/sweep.mts --manifest manifest.json --out ./out --prove
```

The first sweep is a dry run against `/v5/rooms/execute`, which runs natively on
the CPU and takes no GPU permit. It validates every template - stack balance,
gas prediction, fusion count, memory isolation - before any GPU time is spent.
Running it first is not optional in practice: it caught six template defects
during development, every one of which produced a plausible gradient of the
wrong quantity rather than an error.

`verify-vectors.sh` is the same idea applied to input validity, and it is what
the dry run cannot do: it starts a disposable anvil and calls each precompile
directly, so a vector that the precompile rejects fails there rather than
becoming a plausible-looking measurement of an early exit. It takes about a
minute and needs no GPU.

To correct an existing run without re-proving it, `refit.mjs` re-derives every
gradient from the recorded points:

```bash
node scripts/opcode-cost/refit.mjs ./out/proofs.jsonl
```

Each proof record carries its exact `cycles`, so a fit taken on the wrong field
can be repaired from the evidence rather than by spending the GPU time again.

## Evidence

Every number in this document is traceable to a file under `docs/evidence/`.

| File | Contents |
| --- | --- |
| `opcode-cost-2026-08-26/prove-production/summary.json` | All 156 attempted rows **with raw per-point measurements** - the shipped guest |
| `opcode-cost-2026-08-26/prove-production/summary.refit.json` | The same rows refitted on exact cycles |
| `opcode-cost-2026-08-26/prove-baseline/summary.json` | The comparison build with the fusion dispatcher compiled out |
| `opcode-cost-2026-08-26/vec-batch1/`, `vec-batch2/` | The corrected precompile rows, with and without refit |
| `opcode-cost-2026-08-26/vec-heavy2/`, `vec-final/` | Pairing, KZG and BLAKE2F |
| `opcode-cost-2026-08-26/osaka-manifest.json` | The pinned instruction inventory the sweep was driven from |
| `opcode-proving-cost-2026-08-24.json` | The condensed 147-row table, superseded for precompiles only |

The `summary.json` files retain each proof's `units`, `executedGas`,
`opcodeSteps`, `precompileCalls`, `cycles` and `totalCycles`. That is what makes
`refit.mjs` possible, and it is why they are kept in full rather than reduced to
the published columns.

## Related documents

| Document | What it adds |
| --- | --- |
| [RUNNING-A-PROVER.md](RUNNING-A-PROVER.md) | Operating the published prover image |
| [REPRODUCING-THE-TRUST-ROOT.md](REPRODUCING-THE-TRUST-ROOT.md) | Deriving the pinned guest and image digests from published bytes |
| [../../kurtosis-testing/docs/GPU-SEGMENT-SIZING.md](../../kurtosis-testing/docs/GPU-SEGMENT-SIZING.md) | Why `SEGMENT_PO2` is what it is, and why it must be held fixed across a sweep |
