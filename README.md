# prover-node

This folder is the machine that turns a room batch witness into a proof the
L1 will accept. The Rust workspace under `zkvm/` re-executes room-local EVM
batches inside the RISC Zero zkVM (`stf-core` and its wire/types crates are
the state-transition function; `crates/risc0/methods` is the guest) and wraps
the result into a Groth16 receipt. The `zkdeal-r0` host binary serves that
pipeline over HTTP on port 8080, which is the interface every other component
- the coordinator's proving queue, the bench runner, the acceptance stack -
speaks to.

Production proving is CUDA-only by design: the shipped image is built from
`zkvm/docker/risc0-cuda.Dockerfile`, whose `toolchain` and `runtime` stages
are both digest-pinned CUDA images, and CPU fallback is disabled rather than
silently tolerated. Reproducibility is enforced, not assumed:
`zkvm/artifacts.lock.json` is the trust root pinning guest programs, image
digests, certified fixtures and toolchain versions; `zkvm/lock-schema.mjs` is
the single source of the lock's shape and literals; and
`scripts/verify-zkvm-locks.mjs` re-checks the lock in CI as a required job -
absent generated build outputs are reported, never silently passed over.

## Motivational example

A prover container can be “healthy” and still be the wrong artifact: a mutable
tag, PTX just-in-time compilation for another GPU, a development build, or a
silent CPU path all change what was actually tested. The useful smoke test
therefore starts from an immutable digest and checks the binary as well as the
HTTP surface.

This run pulls the published `sm100` image on an NVIDIA B200, finds native
`sm_100` cubins with PTX JIT disabled, and then checks that the live service is
production CUDA with no CPU fallback.

[![A terminal verifies the digest-pinned sm100 prover image on B200 and reports production CUDA with CPU fallback disabled.](https://zkdeal.org/blog/terminal/vii-docker-prover-smoke-poster.png?v=71e3944c65e3)](https://zkdeal.org/blog/run-the-supplied-zkdeal-docker-stack/#terminal-recording)

**Watch or inspect the run:** [interactive Asciinema recording](https://zkdeal.org/blog/run-the-supplied-zkdeal-docker-stack/#terminal-recording) · [copyable transcript](https://zkdeal.org/blog/terminal/vii-docker-prover-smoke.txt) · [Asciicast v3](https://zkdeal.org/blog/terminal/vii-docker-prover-smoke.cast) · [VHS tape](https://zkdeal.org/blog/terminal/vii-docker-prover-smoke.tape) · [WebM](https://zkdeal.org/blog/terminal/vii-docker-prover-smoke.webm) · [MP4](https://zkdeal.org/blog/terminal/vii-docker-prover-smoke.mp4)

With the digest-pinned service running on loopback, the final checks stay
small:

```sh
curl -fsS http://127.0.0.1:8080/healthz | \
  jq '{status,protocolVersion,evmFork,cpuFallback,prover}'
curl -fsS http://127.0.0.1:8080/v5/capabilities | \
  jq '{cudaCompiled,productionCompiled,proofModes,ethereumSeal}'
```

Expected result includes:

```text
{"status":"ready","protocolVersion":6,"evmFork":"osaka","cpuFallback":false,"prover":"risc0-local-cuda"}
{"cudaCompiled":true,"productionCompiled":true,"proofModes":["succinct","groth16"],"ethereumSeal":true}
```

[Run the complete image-verification tutorial](https://zkdeal.org/blog/run-the-supplied-zkdeal-docker-stack/) or continue with the [operator guide](docs/RUNNING-A-PROVER.md).

## Quickstart

Docker Desktop must be running. No host toolchain is needed - Rust, CUDA and
Node run inside pinned images. The `smoke` service requires an NVIDIA GPU
with container GPU support; everything else is GPU-free.

```bash
cd prover-node
docker compose run --rm toolchain-build   # digest-pinned CUDA toolchain image
docker compose run --rm build             # guest + host build, runtime image
docker compose run --rm test              # cargo workspace tests (stf-core, stf-wire, stf-types, host check)
docker compose run --rm locks-test        # verify-zkvm-locks.mjs against the tracked trust root
docker compose run --rm smoke             # GPU: boot the prover, prove a certified fixture
```

`CUDA_ARCH` defaults to this stand's card (auto-probed by the image build) and
the prover's `SEGMENT_PO2` is sized from the GPU's VRAM - too large a segment
OOMs the Groth16 wrap and yields no proof, too small misses L1 checkpoint
deadlines. The VRAM→segment table, the reasoning, and the manual override
(`SEGMENT_PO2` on the container, `ZKDEAL_SEGMENT_PO2` for the Kurtosis build)
live in
[../kurtosis-testing/docs/GPU-SEGMENT-SIZING.md](../kurtosis-testing/docs/GPU-SEGMENT-SIZING.md).

Running the **published binaries-only image** (`zkdeal/prover-cuda` on Docker
Hub) as an operator - including Azure confidential-GPU deployment, portal
registration and version verification - is covered in
[docs/RUNNING-A-PROVER.md](docs/RUNNING-A-PROVER.md).

## L1 finality boundary

A valid proof establishes the stated room transition; it does not establish
that the L1 transaction carrying that proof survived a reorg. The settlement
operator retains proof calldata until the accepting block is hash-verified at
or below Ethereum's `finalized` checkpoint. Prover-node heartbeats likewise
remain provisional until canonical and are re-sent when their receipt
disappears, with the pool timeout sized to cover two heartbeat intervals,
reorg margin, and inclusion latency.

## How it connects

Install is independent: no `link:` dependencies, and `pnpm install` here
needs no sibling checkout. The couplings that do exist:

- **Dev-only fixture regeneration** reaches into siblings by relative path:
  `scripts/gen-stf-fixtures.ts` loads `@zkdeal/l2-engine` from
  `../app-node/packages/l2-engine` and reads
  `../web3-protocol/contracts/{scenarios.json,out}`; the `zkvm/scripts/*.mts`
  fixture generators import `../../../app-node/packages/{l2-engine,protocol,zkvm}/src`
  directly. The production build and serve paths use none of this.
- **Consumed by `web2-api`**: the coordinator serves `zkvm/build` under
  `/artifacts/zkvm/` and reads program digests from
  `zkvm/artifacts.lock.json` (env defaults `ZKVM_ARTIFACTS_ROOT`,
  `ZKVM_LOCK_PATH`).
- **Consumed by `kurtosis-testing`**: `scripts/build-docker-images.*` builds
  the prover image from `zkvm/docker/risc0-cuda.Dockerfile` with this folder
  as context, and the acceptance evidence records the image digests.

## Layout

| Path | Contents |
| --- | --- |
| `zkvm/` | Cargo workspace: `crates/risc0/` (host = `zkdeal-r0`, guest `methods`, `wasm-verifier`), `crates/{stf-core,stf-types,stf-wire,stf-wasm}`, `crates/ligetron-guest`; `build.mjs` family (`--cuda`, `--check-repro`, `--update-lock`); `artifacts.lock.json` + `lock-schema.mjs`; `docker/` (CUDA Dockerfile, pinned Groth16 fetch); `fixtures/`; vendored `vendor/` and `ligetron/`. |
| `agent/` | Queue-pull sidecar (`src/{agent,heartbeat,local-prover,structured-log}.ts`): leases jobs from the shared durable prove queue only while the local prover is healthy, requires the owner-derived tenant/room/job/correlation tuple, forwards to the loopback prover, heartbeats the lease every 30 s, and emits bounded secret-free start/complete/error JSON for cross-component joins. Production on-chain health uses the hosted coordinator's scoped durable liveness operation; a direct signer is loopback development only. Trace identifiers are never metric labels. GPU-free tests via `ZKDEAL_AGENT_STUB`. |
| `docs/` | Operator documentation: `RUNNING-A-PROVER.md` (public image, Azure GPU TEE, portal registration, version verification); `EVM-GAS-VS-PROVING-COST.md` (measured marginal proving cost per EVM instruction and precompile, as a repricing suggestion for verifier hosts and room authors - published RISC0 numbers do not transfer to this build, because it accelerates only keccak and secp256k1). |
| `scripts/` | `verify-zkvm-locks.mjs` (required lock gate; `--require-zkvm-build` for GPU CI), `build-zkvm.{sh,ps1}`, `gen-stf-fixtures.ts` (dev-only), `run-platform.mjs` (OS dispatch). |
