# Reproducing the zkdeal trust root

This is the third-party reviewer's guide. It answers one question end to end:
**given only published bytes, can an unrelated party re-derive every value the
deployment trusts, and check that the running prover and the deployed verifier
really are those values?**

Nothing here needs a zkdeal credential, a zkdeal endpoint, or the private
registry account. It needs Docker, Node 22, Python 3, a checkout of the
published sources, and - for the one step that recompiles the guest - an NVIDIA
GPU with the container toolkit.

Every command block names the directory it is run from. Paths are relative to
that directory.

## 0. The chain you are checking

```text
published sources
  -> zkvm/source-manifest.json          (deterministic file inventory + digest)
  -> pinned toolchain image @sha256     (compiler, risc0 components, CUDA arch)
  -> pinned runtime image @sha256       (the shipped prover; carries the digest as an OCI label)
  -> RISC Zero guest program ID         (imageId; re-derived by a double build)
  -> zkvm/artifacts.lock.json           (binds all of the above plus every compiled artifact hash)
  -> on-chain registration              (ColdTemplateRegistry template + room proofProgramId)

verifier side, independently:
  web3-protocol/contracts/risc0-ethereum.lock.json
  -> vendored RiscZeroGroth16Verifier sources (upstream Git blobs)
  -> forge build                                (deployed bytecode)
```

Two links in that chain are cryptographic and self-checking (the guest program
ID and the Groth16 seal). The rest are hash pins, and this document is how you
verify each one yourself rather than taking the lock's word for it.

**Current state (pre-v6 ceremony).** The v6 protocol trust root has not been
minted yet. Until the ceremony in
[`../zkvm/docker/V6_TRUST_ROOT_CEREMONY.md`](../zkvm/docker/V6_TRUST_ROOT_CEREMONY.md)
runs, `zkvm/source-manifest.json` does not exist, `zkvm/artifacts.lock.json` is
still the v5 lock, and the two prover-node gates below are **red by design**.
Section 8 lists exactly what that looks like so you can tell a pending ceremony
apart from a real failure.

## 1. Prerequisites

| Need | Why | Which step |
| --- | --- | --- |
| Docker (Linux/amd64 images) | every build and check runs in a pinned container | all |
| Node 22 | runs the manifest and lock checkers directly | 2, 6, 7 |
| Python 3 (stdlib only) | the dependency-free second manifest implementation | 2 |
| NVIDIA GPU + container toolkit | production builds are CUDA-only; there is no CPU fallback | 3 |
| The two pinned image references | published with the release; `repository@sha256:<64 hex>` | 1, 3 |

Steps 1, 2, 5, 6 and 7 need no GPU. Step 3 is the only one that does.

## 2. Step 1 - pull the pinned images and check their source label

Run from anywhere.

```sh
docker pull <registry>/zkdeal-risc0-toolchain@sha256:<toolchain-digest>
docker pull <registry>/zkdeal-risc0-runtime@sha256:<runtime-digest>
```

Both pins must be pushed **manifest** digests (`repository@sha256:<64 hex>`),
not bare local image IDs. A bare `sha256:...` is a config digest: it differs
from the manifest digest, is not stable across machines, and disappears on
`docker image prune`, so nobody off the build machine could fetch the same
bytes. `zkvm/build-config.mjs` refuses that form outright, and
`assertPushedImage` in `zkvm/build-exec.mjs` re-checks that each reference
really resolves to a pushed repository digest before building.

The runtime image declares which sources it was built from:

```sh
docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.source-manifest.sha256"}}' \
  <registry>/zkdeal-risc0-runtime@sha256:<runtime-digest>
```

That label must equal the manifest digest you compute in step 2. It is set from
the `SOURCE_MANIFEST_SHA256` build argument, and the builder stage independently
`sha256sum --check`s the copied `source-manifest.candidate.json` against the
same value, so a label that disagrees with the copied bytes cannot be built.

The image also carries the manifest file itself. Extract it and diff it against
the published one:

```sh
cid=$(docker create <registry>/zkdeal-risc0-runtime@sha256:<runtime-digest>)
docker cp "$cid:/etc/zkdeal/source-manifest.json" ./image-source-manifest.json
docker cp "$cid:/zkdeal-BUSL-1.1-LICENSE" ./image-LICENSE
docker rm -f "$cid"
```

`org.opencontainers.image.source` and `org.opencontainers.image.licenses`
(`BUSL-1.1`) are on the same image.

The toolchain image records what it actually installed, observed inside the
image rather than declared in a script:

```sh
docker run --rm --entrypoint cat \
  <registry>/zkdeal-risc0-toolchain@sha256:<toolchain-digest> \
  /etc/zkdeal/toolchain-versions.json
```

That JSON (`zkdeal/risc0-toolchain-versions/v1`) carries `rust`, `wasmPack`,
`riscZero.{crates,rustToolchain,groth16,rzupSha256}` and
`risc0HomeTreeSha256`. `zkvm/build.mjs` copies these values into the lock; it
does not retype them.

## 3. Step 2 - verify the source manifest against the published sources

Run from `prover-node/`.

The manifest is a deterministic inventory of every path whose bytes can change
a released guest, host, verifier or build contract: 21 source roots, each file
recorded as `{path, size, sha256, executable}`, sorted by NFC-normalised path
bytes, with `filesDigest` a sha256 over the canonical one-line-per-file
rendering and the manifest digest a sha256 over the canonical JSON. No
repository metadata participates - no commit, no timestamps, no mode bits
(execute intent is the `#!` shebang, because filesystem execute bits are not
stable across Windows bind mounts). Symlinks are rejected outright rather than
followed.

There are deliberately **two** manifests:

| File | Role |
| --- | --- |
| `zkvm/source-manifest.json` | authoritative. Written only by the reproducible double build, and bound by `artifacts.lock.json:sourceManifestSha256`. |
| `zkvm/source-manifest.candidate.json` | non-authoritative Docker build input, prepared before the ceremony. Copied into the image and re-verified inside it. |

Check the candidate against the tree:

```sh
node zkvm/scripts/check-lock-freshness.mjs --check-build-input
```

Success prints `verified transferred non-authoritative build input
sha256=<digest>`. That digest is what the OCI label in step 1 must equal.

Check the authoritative manifest (this is also what `pnpm check:sources` runs):

```sh
node zkvm/scripts/check-lock-freshness.mjs
```

Success prints `zkVM source manifest is current sha256=<digest>`.

To see the inventory itself, or to hash it yourself:

```sh
node zkvm/scripts/check-lock-freshness.mjs --print > /tmp/zkdeal-source-manifest.json
sha256sum /tmp/zkdeal-source-manifest.json
```

`--print`, `--prepare-build-input` and `--check-build-input` are mutually
exclusive, and any other argument exits 2 with a usage line. There is
deliberately **no** flag that writes `source-manifest.json`: minting it is
available only inside the reproducible artifact build.

### The dependency-free second implementation

`zkvm/scripts/verify-source-manifest.py` is a standalone Python 3 stdlib
re-implementation of the same algorithm, carrying its own copy of the source
root list. It is the one the Docker builder stage runs, and it is what you use
if you would rather not execute the project's own JavaScript:

```sh
python3 zkvm/scripts/verify-source-manifest.py zkvm zkvm/source-manifest.candidate.json
```

It takes exactly two arguments (`<zkvm-root> <manifest.json>`) and prints
`verified <n> source files against <path>`. Point it at
`zkvm/source-manifest.json` to check the authoritative manifest the same way.

The duplication is the point: if the two implementations ever disagree about
the inventory, the digest is not deterministic and the trust root is not
reproducible. Inside the image the same script runs against the copied sources
(`RUN python3 /workspace/zkvm/scripts/verify-source-manifest.py /workspace/zkvm
/workspace/zkvm/source-manifest.candidate.json` in
`zkvm/docker/risc0-cuda.Dockerfile`), so the bytes that compiled the guest were
checked against the manifest a third time, in the build itself.

## 4. Step 3 - re-derive the guest program ID (verify mode, GPU)

Run from `prover-node/`. Requires an NVIDIA GPU.

```sh
node zkvm/build.mjs --cuda --check-repro \
  --toolchain-image <registry>/zkdeal-risc0-toolchain@sha256:<toolchain-digest> \
  --runtime-image <registry>/zkdeal-risc0-runtime@sha256:<runtime-digest>
```

**Do not pass `--update-lock` or `--bootstrap-lock`.** Those are the minting
flags; they rewrite `artifacts.lock.json` and `source-manifest.json`. Without
them `build.mjs` takes the `verifyLock` path: it builds, re-derives, and then
compares everything against the checked-in lock, changing nothing. That is
verify mode, and it is what a reviewer runs.

What that single command establishes:

1. `verifySourceManifest` on the candidate manifest - the sources on disk are
   the sources the manifest names (same check as step 2, inside the build).
2. `assertPushedImage` on both pins - each really resolves to a pushed
   repository digest.
3. `assertImageSourceManifest` - the runtime image's
   `org.opencontainers.image.source-manifest.sha256` label equals the verified
   candidate digest (step 1, enforced).
4. A full build inside the pinned toolchain container: the wasm browser
   verifier, the production CUDA host + guest, and the proving-disabled
   `client-verifier` binary (which must not link `libcuda.so`, and must refuse
   every gated subcommand with the host's own refusal sentence).
5. `--check-repro`: a **second independent build** in fresh target and cargo
   registry volumes, requiring the guest image ID *and* all four compiled
   artifact hashes (`verifier/r0_wasm_verifier.js`,
   `verifier/r0_wasm_verifier_bg.wasm`, `zkdeal-r0`, `zkdeal-r0-client`) to
   match bit for bit. This roughly doubles the build time by design.
6. `verifyRuntimeImage`: the separately built runtime image is asked for its
   own `imageid` and `capabilities` and must report the same guest as the
   artifact build, and must pass `health` on a real GPU.
7. `checkFixtureProgramIds`: the certified AMM witnesses under `zkvm/fixtures/`
   must name the built guest (or be reported as predating the binding).
8. `verifyLock`: image ID, both image pins, capability provenance, toolchain
   versions read out of the image, the runtime image's stripped host binary
   sha256, every locked artifact hash, and `sourceManifestSha256` against the
   authoritative manifest.

The guest is a separate cargo workspace, so the outer `--locked` does not reach
the nested resolution that produces the image ID. Every build step is therefore
wrapped in `guestLockGuard`, which fails if
`crates/risc0/methods/guest/Cargo.lock` was rewritten. The Dockerfile applies
the same guard.

### Argument guards you will hit if you get it wrong

These are evaluated at import time in `zkvm/build-config.mjs`, before any
container starts. Verified messages:

| Invocation | Refusal |
| --- | --- |
| no `--cuda` | `production v6 artifact builds require --cuda; CPU fallback is forbidden` |
| `--cuda` without both image flags | `CUDA builds require immutable --toolchain-image and --runtime-image pins` |
| a tag instead of a digest | `--toolchain-image must be a pushed registry reference of the form repository@sha256:<64 hex>; local Docker image IDs are not obtainable off the build machine` |
| `--update-lock` without `--check-repro` | `--update-lock/--bootstrap-lock require --check-repro; see zkvm/docker/README.md` |
| `--skip-rust --update-lock` | `--skip-rust cannot update or bootstrap the cryptographic trust root` |
| `--receipt` | `--receipt is retired: v6 proves room batches and cold templates only` |
| `--image` | `--image is ambiguous and retired; pass --toolchain-image and --runtime-image` |

`--skip-rust` on its own verifies the lock against an already-materialised
`build/risc0/capabilities-v6.json` without containers. It re-derives nothing,
so it is a consistency check, not a reproduction.

### CUDA architecture

`CUDA_ARCH` selects the compiled CUDA kernels (89 = RTX 40xx Ada, 120 = RTX
50xx Blackwell, 86 = Ampere, 90 = Hopper). It changes the **host** binary, not
the guest: the RISC Zero guest is RISC-V, so the program ID is identical across
architecture tags. A different `CUDA_ARCH` is a toolchain change - rebuild both
images and re-run the whole gate; it is not a way to reuse a lock.

## 5. Step 4 - the RISC Zero component pins

Run from `prover-node/`.

The RISC Zero Groth16 proving parameters (about 2.2 GB) are the one large
upstream input. `zkvm/docker/fetch-pinned-risc0-groth16.sh` fetches them by
content, not by version string:

```sh
fetch-pinned-risc0-groth16 <url> <expected-sha256> <expected-size-bytes> <output-path>
```

It downloads immutable byte ranges concurrently (`RISC0_FETCH_PARALLELISM`,
default 8; `RISC0_FETCH_CHUNK_SIZE`, default 8388608), checks every part's
length, concatenates, re-checks the total size, and finally
`sha256sum --check --strict`s the whole archive before moving it into place. The
Dockerfile supplies the three pinned values as build arguments
(`RISC0_GROTH16_SHA256`, `RISC0_GROTH16_SIZE`, `RISC0_GROTH16_VERSION`), next to
`RISC0_VERSION`, `RISC0_RUST_TOOLCHAIN`, `RZUP_SHA256`, `RUSTUP_VERSION`,
`RUSTUP_SHA256` and `WASM_PACK_VERSION`. `rzup` itself is content-pinned before
it is allowed to install anything.

### The RISC0_HOME_TREE_SHA256 re-pin loop

rzup fetches components under a version string only, so re-publishing an
archive under the same version would change the guest ELF - and therefore the
program ID the whole trust root rests on - with no signal that anything moved.
The toolchain stage therefore hashes the installed component tree
(`find /root/.risc0 -type f | sort | xargs sha256sum | sha256sum`) and records
it as `risc0HomeTreeSha256`.

Recording is unconditional; **enforcing is opt-in**, so the value can be adopted
from a reviewed build rather than guessed. The loop, documented in
`zkvm/docker/README.md`:

1. Build the toolchain stage once without the pin.
2. Read `risc0HomeTreeSha256` from `/etc/zkdeal/toolchain-versions.json` in that
   image (step 1 above shows the command).
3. Rebuild passing `--build-arg RISC0_HOME_TREE_SHA256=<digest>`. The stage now
   hard-fails if the installed tree differs.

The value also lands in `artifacts.lock.json` under
`toolchain.risc0HomeTreeSha256`, and `verifyLock` treats a difference between
the image and the lock as toolchain provenance drift.

## 6. Step 5 - verifier-side reproduction

Run from `web3-protocol/`.

The on-chain half of the trust root is the official RISC Zero Ethereum Groth16
verifier, vendored byte-for-byte rather than pulled at deploy time.
`contracts/risc0-ethereum.lock.json` pins:

- repository `https://github.com/risc0/risc0-ethereum`, tag `v3.0.1`, commit
  `365e7b2db4f620fa256580c27558d2623362b9ae`;
- `verifierVersion` `3.0.0` and seal selector `0x73c457ba`;
- a **per-file Git blob hash** (`git:<sha1 of "blob <len>\0" + contents>`) for
  each of the 7 vendored `risc0-ethereum` sources and the 1 OpenZeppelin
  `SafeCast.sol` it depends on, at OpenZeppelin commit
  `acd4ff74de833399287ed6b31b4debf6b2b35527`.

Git blob hashes, not sha256, so you can check them straight against upstream
with `git hash-object` without cloning anything into this tree.

```sh
node scripts/verify-artifact-locks.mjs        # or: pnpm check:artifacts
```

The same script also verifies the card-circuit demo trust root (vkeys and
generated verifiers always; the large gitignored zkeys/wasm only when present,
and their absence is printed as `NOT VERIFIED`, never silently passed over).
Note the card artifacts are an explicitly demo-only, uncontributed ceremony and
are not part of the rollup's proof path.

`pnpm check:artifacts` additionally runs `scripts/check-proof-graph.mjs`, the
freshness checker for the published proof dependency graph
(`proof-dependency-graph.json` and its prose companion). That graph is what
tells you which proof routes can actually advance the rated deployment and
which are structurally unreachable, so read it before deciding what this
reproduction has to cover.

Then compile the verifier and the protocol in the pinned Foundry container -
the digest is in `contracts/foundry-image.txt` and mirrored by `.env`,
`contracts/Dockerfile` and both CI workflows:

```sh
docker compose run --rm contracts-build      # forge build --deny warnings --sizes
docker compose run --rm contracts-test       # build + lint + fmt --check + forge test
```

Compare the resulting `RiscZeroGroth16Verifier` runtime bytecode and codehash
against the deployed address in the deployment manifest.

## 7. Step 6 - check a running prover against the lock

Run from `prover-node/`.

```sh
node scripts/verify-zkvm-locks.mjs                       # pnpm check:artifacts
node scripts/verify-zkvm-locks.mjs --require-zkvm-build  # pnpm check:artifacts:gpu
```

The plain form is what a hosted runner can honestly assert: lock declarations
against `zkvm/lock-schema.mjs` (the single source of the lock's shape and
literals - format `zkdeal/zkvm-artifacts-lock/v6`, `journalVersion` 6,
`runtimeCompatibility` `v6-only`, capability format
`zkdeal/risc0-capabilities/v6`, `compactStateModel` `full-room-state-v1`, CUDA
required, CPU fallback forbidden, Ethereum seals required), the source manifest
binding, the tracked fixtures, and the capability artifact's agreement with the
locked image and provenance. Absent gitignored build outputs are reported as
`NOT VERIFIED`. `--require-zkvm-build` turns each of those reports into a
failure, which is what GPU CI runs immediately after its reproducibility build.

Against a live prover (no credential needed for these two routes):

```sh
curl -s http://127.0.0.1:8080/healthz         | jq '{status, imageId, programId, gpuName, driverVersion, risc0Version}'
curl -s http://127.0.0.1:8080/v5/capabilities | jq '{programId, cudaCompiled, productionCompiled, proofModes}'
```

`programId` must equal `risc0.programId` in `zkvm/artifacts.lock.json`. It
derives from the compiled-in guest ELF and is the one value a host cannot fake,
because proof verification depends on it. Everything else a prover reports
about itself - including `containerDigest`, which merely echoes the operator's
`ZKDEAL_CONTAINER_DIGEST` - is a telemetry label. Container identity comes from
launching the pinned `repository@sha256:` reference; see
[`RUNNING-A-PROVER.md`](RUNNING-A-PROVER.md) section 6.

## 8. What CI re-checks

Neither workflow can mint a trust root; both re-check one.

**`.github/workflows/ci.yml`** (hosted, no GPU):

- `typescript` job, step *Record the exact release-affecting source bytes*: runs
  `check-lock-freshness.mjs --print` and prints its sha256, so the source digest
  of every run is in the log.
- `typescript` job, step *Verify all tracked cryptographic artifact locks*:
  `pnpm -C web3-protocol check:artifacts` and `pnpm -C prover-node
  check:artifacts` - both lock checkers above, as a required job.
- `contracts` job: `forge build --deny warnings --sizes` (the EIP-170/EIP-3860
  gate), `forge lint --severity high --deny warnings`, `forge test -vvv`, a
  Prague-profile BLS gas run, and `forge fmt --check`, all in the digest-pinned
  Foundry container.
- `rust` job: `cargo test -p stf-core --locked` (the native state-transition
  function the guest and the JS engine must agree with), `cargo test -p
  stf-wire -p stf-types --locked`, and a `cargo check` of the host surface with
  `RISC0_SKIP_BUILD=1` (it deliberately does *not* build a guest).
- `eest-osaka` job: the official Osaka EEST v5.4.0 corpus through both engines.
- `optional-capabilities` job: prints, and then machine-checks, the exact list
  of properties a hosted runner did **not** establish - including real RISC Zero
  proving. A green hosted CI is not evidence of any of them.

**`.github/workflows/gpu-ci.yml`** (self-hosted RTX 4090):

- Pins the source bytes before anything runs (`--print` into
  `gpu-ci-evidence/source-manifest-before.json`) and records the digest.
- Fails closed unless both image references are digests, refuses to run if
  another container already holds the GPU, and asserts the runtime image
  **fails** `health` with no GPU assigned (fail-closed startup).
- Runs `node zkvm/build.mjs --toolchain-image ... --runtime-image ... --cuda
  --check-repro` - verify mode, exactly step 3 - then `pnpm
  check:artifacts:gpu`.
- Re-enumerates the source manifest after the build and after the integration
  gates, and fails if either digest moved: a gate that edits release-affecting
  bytes is a failed gate.
- Writes a `zkdeal/gpu-ci-provenance/v6` record (source digest, both image
  references and local IDs, the Foundry digest, the artifact-lock sha256, runner
  and GPU identity) and uploads it with the raw evidence.

### Expected red, pre-ceremony

Until the v6 ceremony runs, from `prover-node/`:

```text
$ node zkvm/scripts/check-lock-freshness.mjs
zkVM trust-root freshness failed: zkvm/source-manifest.json is missing; the trust root has not been minted for these sources

$ node scripts/verify-zkvm-locks.mjs
  - zkVM source manifest: zkvm/source-manifest.json is missing; ...
  - zkVM lock format is zkdeal/zkvm-artifacts-lock/v5, expected zkdeal/zkvm-artifacts-lock/v6
  - zkVM lock must pin journalVersion=6 and v6-only
  - zkVM lock pins the wrong room/cold-template witness schemas
  - zkVM lock capability format must be zkdeal/risc0-capabilities/v6
```

That is the v5 lock being correctly rejected by the v6 schema, not a broken
check. Anything else - a hash mismatch, a missing tracked fixture, a
`sourceManifestSha256` that does not bind - is a real failure and should be
reported.

## 9. Honest limitations

- **Only the guest program ID is cryptographically self-checking.** The image
  digests, the source manifest and the artifact hashes are pins: they prove the
  bytes did not move, not that the bytes are correct. Correctness of the state
  transition is what the sources are published for.
- **A reproduction needs the same CUDA architecture** as the published image to
  compare host binary hashes. The guest program ID is architecture-independent;
  the host binary is not.
- **The certified AMM witnesses under `zkvm/fixtures/` are frozen.** Their v4
  generators were removed with the v4 protocol surface. They are not
  regenerated by a build; `checkFixtureProgramIds` refuses any guest they were
  not certified against, and that refusal is the intended signal.
- **The card-circuit artifacts are demo-only** (uncontributed phase-2 keys) and
  are not on the rollup's proof path.
- **`containerDigest` is not attestation.** Hardware-rooted attestation is the
  Azure confidential-GPU flow in `RUNNING-A-PROVER.md` section 3, and it
  protects the running prover's confidentiality, not proof validity.

## 10. Related documents

| Document | What it adds |
| --- | --- |
| [`../zkvm/docker/README.md`](../zkvm/docker/README.md) | the build commands themselves, the pushed-digest rules, the RISC0_HOME re-pin loop, and the prover's HTTP surface |
| [`../zkvm/docker/V6_TRUST_ROOT_CEREMONY.md`](../zkvm/docker/V6_TRUST_ROOT_CEREMONY.md) | the ordered minting ceremony for the v6 trust root |
| [`../zkvm/docker/RTX4090_RELEASE_RUNBOOK.md`](../zkvm/docker/RTX4090_RELEASE_RUNBOOK.md) | the full physical closure: sealed no-history source bundle, write-once evidence, resume contract |
| [`../zkvm/docker/RTX5090_RELEASE_ADDENDUM.md`](../zkvm/docker/RTX5090_RELEASE_ADDENDUM.md) | Blackwell (`CUDA_ARCH=120`) deltas |
| [`RUNNING-A-PROVER.md`](RUNNING-A-PROVER.md) | operating the published image, and checking which prover is running |
