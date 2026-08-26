# RTX 5090 release addendum

This is a delta, not a runbook. The complete ceremony - candidate sealing,
static gates, staged image inputs, the mandatory two-build trust-root closure,
proof evidence, and publication - is `RTX4090_RELEASE_RUNBOOK.md` and it stays
authoritative. Only the points below differ on the Linux RTX 5090 node.

## Target architecture

- Pass `--build-arg CUDA_ARCH=120` (Blackwell, compute capability 12.0) to
  every `risc0-cuda.Dockerfile` build; the Dockerfile expands it to
  `-arch=sm_120` in `NVCC_APPEND_FLAGS`. Build invocations are in
  `README.md`.
- A new architecture is a toolchain change: both the toolchain and runtime
  images are rebuilt, the artifact lock is re-minted by the double-build
  closure, and the full GPU evidence gate re-runs. The RISC Zero guest is
  RISC-V, so the guest program ID is expected to be unchanged across
  architectures - verify it against `zkvm/artifacts.lock.json` rather than
  assuming it.

## Host differences (Ubuntu 22.04, native Docker)

- Driver floor is **r570+** for `sm_120` (the release node runs 570.195.03
  against the pinned `nvidia/cuda:12.9.1` base). Install the NVIDIA Container
  Toolkit; the prover probes `nvidia-smi` inside the container and refuses to
  serve without it, so a driver/toolkit problem surfaces as a health failure,
  not a proof failure.
- The orchestrator's nested Docker client uses the native
  `/var/run/docker.sock`; `ZKDEAL_DOCKER_WORKSPACE_SOURCE` is the Linux
  absolute path of the extracted candidate, not a Windows path.

## Local-registry digest flow

`build.mjs` accepts only pushed `repository@sha256:` **manifest** digests for
the toolchain and runtime pins. The rental node must not publish pre-release
source-bound images, so satisfy the pin requirement with a loopback registry:

```sh
docker run -d --name zkdeal-local-registry -p 127.0.0.1:5000:5000 registry:2
docker tag  zkdeal-risc0-toolchain:staging 127.0.0.1:5000/zkdeal/risc0-toolchain:staging
docker push 127.0.0.1:5000/zkdeal/risc0-toolchain:staging   # prints the manifest digest
```

Use the digest printed by `docker push` (or `docker image inspect --format
'{{index .RepoDigests 0}}'`) as the `--toolchain-image` / `--runtime-image`
pin. The public Docker Hub digests exist only after the publication step; that
is when the `sm120` digest row in `docs/RUNNING-A-PROVER.md` is filled.

## sm90 PTX fallback if `sm_120` nvcc compilation fails

If the pinned CUDA 12.9.1 nvcc (or a vendored kernel build) rejects `sm_120`,
embed forward-compatible PTX instead of Blackwell SASS: in
`risc0-cuda.Dockerfile`, replace `-arch=sm_${CUDA_ARCH}` in
`NVCC_APPEND_FLAGS` with

```text
-gencode arch=compute_90,code=compute_90
```

keeping `--frandom-seed=zkdeal-risc0 --objdir-as-tempdir` unchanged. The
r570+ driver JIT-compiles the `compute_90` PTX for `sm_120` at first kernel
load. Three cautions:

1. `zkvm/docker/` is inside the source-manifest roots
   (`check-lock-freshness.mjs` `SOURCE_ROOTS`), so this edit changes the
   candidate manifest. Make it **before** `--prepare-build-input` and the
   umbrella seal; an edit after sealing invalidates the candidate.
2. First-load JIT adds a one-time warm-up delay to the first proof; do not
   read it as a regression in the calibration numbers.
3. Record the fallback in the ceremony ticket: the fatbin is not a native
   `sm_120` build, and a later true `sm_120` rebuild is a new toolchain
   change with a new lock.

## Disk budget on the rental node

Assume roughly **82 GB of usable free disk** and plan the ceremony around the
do-not-prune invariant (no `docker system prune`, failed containers and build
caches stay until the release owner closes the investigation). The large
consumers, in arrival order: the CUDA devel toolchain image, the four
candidate-scoped target/cargo volumes (the repro pair roughly doubles target
usage by design), the loopback registry's copy of every pushed layer, the
~2.2 GB Groth16 parameter set inside each runtime image, and the Kurtosis
enclave image set plus any `enclave dump`. Before starting the mint, record
`df -h` and `docker system df` in the evidence directory and confirm the
headroom; after each evidence unit is sealed and its SHA-256 recorded, move
the archive off-node promptly instead of accumulating it on the 82 GB budget.
