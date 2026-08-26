# RISC Zero 3.0.6 cold-prefix composition spike

> **ARCHIVED — completed experiment, kept as evidence.** The mechanism shipped:
> the v4 composed-batch branch of `zkvm/crates/risc0/methods/guest/src/main.rs`
> calls `env::verify`, and `zkvm/crates/risc0/host/src/main.rs` attaches the
> cached receipt with `add_assumption`. The v5 branches
> make no `env::verify` call at all — v5 registers the cold template as a
> separate proof instead of folding it as an in-guest assumption. Nothing
> references this folder and no CI job compiles it (it is its own workspace
> root), so treat it as a record of a measurement, not as live guidance.
>
> The directory is named `risc0-composition-v3` after RISC Zero 3.x; every
> package and constant inside it is named after the zkdeal **v4** protocol it
> was written for.

This isolated spike answers one question: can zkdeal prove an immutable cold
room prefix once, cache it, and later prove only a unique hot suffix while
returning one unconditional receipt?

The exact v3.0.6 path is:

1. Prove the cold guest as a composite receipt.
2. Compress and cache that receipt as **succinct**.
3. In the suffix guest, call `env::verify(cold_image_id, cold_journal)`.
4. On the host, supply the cached receipt with
   `ExecutorEnv::builder().add_assumption(cold_receipt)`.
5. Prove the suffix as composite.
6. Compress the suffix receipt to succinct. RISC Zero lifts the suffix segments
   and runs a recursion `resolve` step against the cached cold succinct receipt.
7. Optionally compress the resolved succinct receipt to Groth16 and prepend the
   Groth16 verifier-parameter selector to form the Ethereum verifier-router seal.

Run it from this directory with a RISC Zero 3.0.6 toolchain:

```text
cargo run --release -p zkdeal-risc0-composition-spike --features cuda -- \
  --output-kind succinct \
  --output-dir ./target/composition-spike-output
```

That is also the default output directory; it sits under the gitignored
`target/` so a run does not leave ~450 KB of untracked receipt binaries in the
tree. The binary refuses to run with `RISC0_PROVER` set to anything other than
`local`, or with `RISC0_SERVER_PATH` set, because those redirect proving to an
out-of-process or remote prover while the emitted JSON still credits the local
GPU.

Run the same command again to exercise the cached-cold path. Use
`--output-kind groth16` only where the matching `risc0-groth16` rzup component
is installed. A CUDA build uses RISC Zero's in-process CUDA shrink wrapper;
the non-CUDA crate path uses its Docker wrapper, but this spike deliberately
refuses to run without the `cuda` feature and a GPU visible through
`nvidia-smi`.

For a GPU host build that consumes guest binaries already produced by the exact
toolchain, set `ZKDEAL_COMPOSITION_PREBUILT_DIR` to a directory containing
`zkdeal-cold-template-v4.bin` and `zkdeal-hot-suffix-v4.bin`. The build script
recomputes and checks both RISC Zero image IDs before embedding them; it does not
accept arbitrary replacement binaries.

The source-build path cannot make the same guarantee: the image IDs come from
whatever rzup RISC Zero guest toolchain is installed locally, and that toolchain
version is not pinned anywhere in this folder. The build script sets
`RISC0_BUILD_LOCKED=1` so the committed guest lockfiles bind, and emits a
`cargo:warning` when a built image ID diverges from the pinned constants in
`methods/build.rs`.

## What reuse does and does not buy

- Reused: immutable constructor/setup execution and its segment proof/lift are
  not rerun after the succinct cold receipt is cached.
- Still paid for every final room proof: suffix execution proof, lifting/joining
  its segments, one recursive resolution of the cold assumption, and (for an
  Ethereum seal) the Groth16 wrapper.
- RISC Zero 3.0.6's compressor rejects Groth16 assumption receipts. Cache the
  cold prefix as succinct, then make only the resolved final receipt Groth16.
- The spike journals the cold image ID and cold-journal digest. Any consumer of
  this mechanism must require those exact commitments; letting a prover choose
  an arbitrary cold image ID would be unsound policy. The only consumer this
  ever had is the v4 composed-batch branch — v5 does not compose receipts
  in-guest, so there is no shipping integration left to do here.

The cold guest hashes a template rather than executing EVM constructors. It is
intentionally a composition/API spike; an integration would have replaced that
body with zkdeal's prepared-room/genesis statement and the suffix body with the
authenticated state refresh plus room-local EVM transition.

The first pinned RTX 4090 profile, including the CUDA Groth16 failure that was
diagnosed and fixed two days later, is recorded in
[PROFILE-RTX4090-20260721.md](PROFILE-RTX4090-20260721.md).

Official pinned references:

- RISC Zero v3.0.6 `ExecutorEnvBuilder::add_assumption` source:
  https://github.com/risc0/risc0/blob/v3.0.6/risc0/zkvm/src/host/client/env.rs
- RISC Zero v3.0.6 guest `env::verify` source:
  https://github.com/risc0/risc0/blob/v3.0.6/risc0/zkvm/src/guest/env/verify.rs
- RISC Zero v3.0.6 official lift/resolve test:
  https://github.com/risc0/risc0/blob/v3.0.6/risc0/zkvm/src/host/api/tests.rs
- RISC Zero v3.0.6 compressor implementation (lift, join, resolve, Groth16):
  https://github.com/risc0/risc0/blob/v3.0.6/risc0/zkvm/src/host/server/prove/mod.rs
