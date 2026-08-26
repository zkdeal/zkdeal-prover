# zkdeal CUDA prover

Before the source owner seals the deterministic umbrella bundle, prepare the
non-authoritative build input from the reviewed tree:

```sh
docker run --rm -v "$PWD:/workspace" -w /workspace node:22-bookworm \
  node zkvm/scripts/check-lock-freshness.mjs --prepare-build-input
docker run --rm -v "$PWD:/workspace:ro" -w /workspace node:22-bookworm \
  node zkvm/scripts/check-lock-freshness.mjs --check-build-input
docker build --platform linux/amd64 \
  -f zkvm/docker/risc0-cuda.Dockerfile \
  --build-arg CUDA_ARCH=89 \
  --build-arg SOURCE_MANIFEST_SHA256=<digest-printed-by-the-previous-command> \
  -t zkdeal-risc0-cuda:current .
```

`source-manifest.candidate.json` is a non-authoritative Docker input. The image
recomputes every listed SHA-256 after copying the sources and exposes the
manifest digest in its OCI labels. Only `build.mjs --check-repro` with the
explicit lock-writer flag may promote those exact bytes to
`source-manifest.json`, after two independent artifact builds match; the
preparation command cannot update either trust root. The no-history physical
source bundle excludes both generated trust-root files, so its fresh extraction
uses first-write `--bootstrap-lock`. `--update-lock` is reserved for a reviewed
workspace that intentionally carries an existing generated lock.
The physical GPU node runs only `--check-build-input`; it must never regenerate
this file after the umbrella archive has been hashed and transferred.

`risc0-cuda.Dockerfile.dockerignore` deliberately limits this build context
to `zkvm/` and excludes local Cargo/build outputs; do not remove it or Docker
will upload multi-gigabyte developer targets before the build starts.

For the multi-artifact `zkvm/build.mjs --cuda` flow, build, **push**, and pin
the source-independent `toolchain` stage and the separately built minimal
`runtime` stage:

```sh
docker build --platform linux/amd64 --target toolchain \
  -f zkvm/docker/risc0-cuda.Dockerfile \
  --build-arg CUDA_ARCH=89 \
  -t registry/zkdeal-risc0-toolchain:current .
docker build --platform linux/amd64 --target runtime \
  -f zkvm/docker/risc0-cuda.Dockerfile \
  --build-arg CUDA_ARCH=89 \
  --build-arg SOURCE_MANIFEST_SHA256=<candidate-manifest-digest> \
  -t registry/zkdeal-risc0-runtime:current .
docker push registry/zkdeal-risc0-toolchain:current
docker push registry/zkdeal-risc0-runtime:current
node zkvm/build.mjs --cuda --check-repro --bootstrap-lock \
  --toolchain-image registry/zkdeal-risc0-toolchain@sha256:<toolchain-manifest-digest> \
  --runtime-image registry/zkdeal-risc0-runtime@sha256:<runtime-manifest-digest>
```

Both pins must be pushed `repository@sha256:` **manifest** digests, printed by
`docker push` or `docker image inspect --format '{{index .RepoDigests 0}}'`.
A bare `sha256:…` is a local image ID: it is a config digest that differs from
the manifest digest, is not stable across machines, and disappears on
`docker image prune`, so nobody off the build machine could fetch the image and
recompute the pinned guest program ID. `build.mjs` rejects that form and
verifies that each pinned reference really resolves to a pushed repository
digest before building.

`--check-repro` is mandatory whenever the lock is written (`--update-lock` or
`--bootstrap-lock`) and cannot be waived: it rebuilds every locked artifact in
independent target and cargo-registry volumes and requires the guest
image ID and all four compiled artifact hashes to match. Minting a trust root
from a single unreproduced build is the one thing this pipeline exists to
prevent, and it roughly doubles the build time by design.

To hard-pin the rzup component archives by content — they are otherwise fetched
under a version string only — read `risc0HomeTreeSha256` from
`/etc/zkdeal/toolchain-versions.json` in a reviewed toolchain image and pass it
back on the next build:

```sh
docker build --platform linux/amd64 --target toolchain \
  --build-arg RISC0_HOME_TREE_SHA256=<digest> ...
```

`CUDA_ARCH=89` is the reviewed target for the inspected RTX 4090 node. A
different GPU architecture is a toolchain change: rebuild both images,
regenerate the artifact lock, and re-run the complete GPU evidence gate.

The RTX 5090 node (Blackwell, compute capability 12.0) takes
`--build-arg CUDA_ARCH=120` in the same three build commands:

```sh
docker build --platform linux/amd64 --target toolchain \
  -f zkvm/docker/risc0-cuda.Dockerfile \
  --build-arg CUDA_ARCH=120 \
  -t registry/zkdeal-risc0-toolchain:current .
docker build --platform linux/amd64 --target runtime \
  -f zkvm/docker/risc0-cuda.Dockerfile \
  --build-arg CUDA_ARCH=120 \
  --build-arg SOURCE_MANIFEST_SHA256=<candidate-manifest-digest> \
  -t registry/zkdeal-risc0-runtime:current .
```

Everything else - candidate-manifest preparation, the pushed-digest pinning
rules, and the mandatory `--check-repro` double build - is
architecture-independent. The 5090-specific deltas (driver floor, the sm90 PTX
fallback if `sm_120` compilation fails, disk budget on the rental node) are
collected in `RTX5090_RELEASE_ADDENDUM.md`; the ceremony procedure itself
remains `RTX4090_RELEASE_RUNBOOK.md`.

The complete physical closure, write-once resume contract, eight-room/six-blob
request assembly, real-proof transaction evidence, and capability/ABI handoff
are specified in `RTX4090_RELEASE_RUNBOOK.md`. The trust root is minted only by
that reviewed RTX 4090 double-build ceremony; ordinary development or
documentation work must leave the lock, source manifest, proof fixtures, and
qualified gas evidence unchanged.

## Running the prover

```sh
docker run --rm --gpus all -p 8080:8080 \
  -e ZKDEAL_PROVER_TOKEN=<shared secret> \
  registry/zkdeal-risc0-runtime@sha256:<runtime-manifest-digest>
```

The image entrypoint is `zkdeal-r0` and its default command is
`serve --host 0.0.0.0 --port 8080`. The router exposes:

- `GET /healthz` - CUDA readiness, unauthenticated
- `GET /metrics` - request counters and driver gauges, unauthenticated
- `GET /v5/capabilities` - the same payload as the `capabilities` subcommand
- `POST /v5/rooms/prepare`, `/execute`, `/prove`, `/verify`
- `POST /hosting/v1/rooms/prepare-batch`
- `POST /v5/cold-templates/execute`, `/prove`, `/verify`
- `POST /v5/data-availability/prepare`, `/execute`, `/prove`, `/verify`
- `POST /v5/aggregates/execute`, `/prove`, `/verify`
- `POST /v5/receipts/wrap`, `/identity-p254`, `/groth16`

Every `POST` route (the `/v5/*` job routes and `/hosting/v1/rooms/prepare-batch`)
requires `Authorization: Bearer $ZKDEAL_PROVER_TOKEN` when that variable is set
at startup; leaving it unset leaves the routes open, which is only defensible on
a loopback bind. Each route runs one job on the single GPU slot, so an
unauthenticated caller can starve every room this prover serves.

Request bodies are exactly the JSON documents the corresponding CLI subcommands
accept (`prepare-room-v5`, `execute-room-v5`, `prove-room-v5`, … in
`zkvm/crates/risc0/host/src/main.rs`), and a single-process GPU semaphore
serializes them to prevent accidental VRAM overcommit.

`ZKDEAL_CONTAINER_DIGEST` is an operator-supplied telemetry label that the host
echoes back in `capabilities` and `health`; nothing in the image derives or
attests it, so a prover running an unrelated image can declare any value.
Container identity is established by launching the pinned
`repository@sha256:` reference, and proof validity is established by the RISC
Zero guest program ID, which the host cannot fake. `zkvm/build.mjs`
deliberately does not inject the variable and does not assert it back.
