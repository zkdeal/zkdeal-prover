# v6 trust-root ceremony (RTX 4090, single clean run)

> **This file lives inside `zkvm/docker/`, which is a `SOURCE_ROOT`.** Its bytes
> are part of the deterministic source manifest and therefore of the guest's
> build closure. It must land - committed, final - **before** the ceremony
> starts, and `source-manifest.candidate.json` must be re-prepared afterwards.
> Editing this document during or after the ceremony reopens `check:sources`
> and invalidates the minted trust root. If you need to record what happened,
> write it outside `zkvm/` (see step 9's evidence list).

This is the ordered runbook for minting the **v6** trust root: a new guest
program ID, a new `zkvm/artifacts.lock.json`, the first tracked
`zkvm/source-manifest.json`, and a fresh real-proof fixture for the Solidity
suite. It is deliberately narrower than
[`RTX4090_RELEASE_RUNBOOK.md`](RTX4090_RELEASE_RUNBOOK.md), which specifies the
full physical closure (sealed no-history source bundle, write-once evidence
units, resume contract, eight-room hosted assembly). Use this document when the
box receives the reviewed tree as a **git commit** rather than a sealed archive,
and when the goal is the trust root plus the fixture, not the complete release
evidence set. Everything in the release runbook that is not contradicted here
still applies.

The ceremony is **kurtosis-free**: the fixture is minted against a standalone
runtime container on loopback, not an enclave.

## 0. Preconditions

Nothing below may run until all of these hold.

| Precondition | How to check |
| --- | --- |
| Every zkVM-tree change is final and committed - guest, host, stf crates, `docker/`, `scripts/`, the build `.mjs` family, this file | `git status --porcelain prover-node/zkvm` prints nothing |
| The whole working tree is clean | `git status --porcelain` prints nothing |
| All non-GPU gates are green | app-node, prover-node and web3-protocol docker gates; see step 8 for the two that are red by design until this ceremony finishes |
| The 4090 box has no other GPU container running | `docker ps` shows no container with a GPU device request |
| Registry credentials are available on the box for `docker push` | out of band; never in command history |

Two failure modes this ordering exists to prevent:

- **A dirty guest closure.** `crates/stf-core` and `crates/risc0/**` are inside
  the guest's compile closure. A ceremony run over unreviewed bytes blesses
  them as the pinned program.
- **A stale candidate.** `source-manifest.candidate.json` is a snapshot of the
  source roots. Any byte that moves after it is prepared makes it stale, and
  the build refuses to mint.

Note that `source-manifest.candidate.json` is itself **not** a source root, so
preparing it does not change the digest it describes. That is deliberate: the
manifest would otherwise be self-referential.

## 1. Prepare the candidate manifest (source owner's machine)

Run from `prover-node/`. **Not on the GPU box** - the box only ever verifies a
transferred candidate; regenerating it there is a source mutation.

```sh
docker run --rm -v "$PWD:/workspace" -w /workspace node:22-bookworm \
  node zkvm/scripts/check-lock-freshness.mjs --prepare-build-input
```

It prints:

```text
prepared non-authoritative Docker input .../zkvm/source-manifest.candidate.json sha256=<M>
Only the mandatory two-build reproducibility closure may copy these bytes to source-manifest.json and bind them in artifacts.lock.json.
```

Record `<M>`. It is referenced as `$CandidateSha` for the rest of this
document.

Immediately verify it without rewriting it, then commit:

```sh
docker run --rm -v "$PWD:/workspace:ro" -w /workspace node:22-bookworm \
  node zkvm/scripts/check-lock-freshness.mjs --check-build-input
```

Expected: `verified transferred non-authoritative build input sha256=<M>`.

Commit `prover-node/zkvm/source-manifest.candidate.json` on its own. That
commit is the ceremony input; its SHA is the value the box checks out.

## 2. Sync the commit to the box

The 4090 box is `192.168.0.11` (Windows, Docker Desktop, key-authenticated
account; see the release runbook's node preflight). Check out **exactly** the
commit from step 1 - not a branch tip that may have moved.

On the box, from the repository root:

```powershell
git status --porcelain          # must print nothing
git rev-parse HEAD              # must equal the step-1 commit
```

Then, from `prover-node/`, re-verify the transferred bytes:

```powershell
docker run --rm -v "${PWD}:/workspace:ro" -w /workspace node:22-bookworm `
  node zkvm/scripts/check-lock-freshness.mjs --check-build-input
```

**Stop if the printed digest is not `$CandidateSha`.** A different digest means
the box is not building the sources that were reviewed.

Set the ceremony variables (PowerShell, on the box):

```powershell
$CandidateSha = '<M>'
$Registry     = '<your registry>'
$env:ZKDEAL_BUILD_CACHE_SCOPE = $CandidateSha   # scopes all four build volumes
```

`ZKDEAL_BUILD_CACHE_SCOPE` must match `^[a-z0-9][a-z0-9_.-]{0,127}$`; a
lowercase hex digest satisfies it. It suffixes
`zkdeal-zkvm-target`, `zkdeal-zkvm-cargo-registry`,
`zkdeal-zkvm-target-repro` and `zkdeal-zkvm-cargo-registry-repro`, so a
ceremony cannot silently reuse a previous run's caches. Confirm all four scoped
volumes are absent before the first attempt.

## 3. Build and push the toolchain image (CUDA_ARCH=89, with the RISC0_HOME re-pin loop)

Run from `prover-node/`. The build context is this folder;
`risc0-cuda.Dockerfile.dockerignore` limits it to `zkvm/` minus targets and
build outputs, so do not remove that file.

**First pass - no pin, to learn the digest:**

```powershell
docker build --platform linux/amd64 --target toolchain `
  -f zkvm/docker/risc0-cuda.Dockerfile `
  --build-arg CUDA_ARCH=89 `
  -t "${Registry}/zkdeal-risc0-toolchain:${CandidateSha}-probe" .

docker run --rm --entrypoint cat `
  "${Registry}/zkdeal-risc0-toolchain:${CandidateSha}-probe" `
  /etc/zkdeal/toolchain-versions.json
```

Read `risc0HomeTreeSha256` out of that JSON and record it as
`$Risc0HomeTreeSha256`. Recording the value is unconditional in the image;
enforcing it is opt-in, which is exactly why this two-pass loop exists - the pin
is adopted from a reviewed build, never guessed.

**Second pass - enforced, and this is the image that ships:**

```powershell
docker build --platform linux/amd64 --target toolchain `
  -f zkvm/docker/risc0-cuda.Dockerfile `
  --build-arg CUDA_ARCH=89 `
  --build-arg "RISC0_HOME_TREE_SHA256=${Risc0HomeTreeSha256}" `
  -t "${Registry}/zkdeal-risc0-toolchain:${CandidateSha}" .

docker push "${Registry}/zkdeal-risc0-toolchain:${CandidateSha}"
docker image inspect --format '{{index .RepoDigests 0}}' `
  "${Registry}/zkdeal-risc0-toolchain:${CandidateSha}"
```

Record the printed `repository@sha256:<64 hex>` as `$ToolchainRef`. Delete the
`-probe` tag; it must never be advertised or reused.

If the enforced pass fails with `rzup component tree <a> does not match the
pinned <b>`, the upstream rzup components moved between the two builds. That is
a real toolchain change: stop, investigate, and restart the ceremony from step
1 once the pin is stable.

## 4. Build and push the runtime image

Run from `prover-node/`.

```powershell
docker build --platform linux/amd64 --target runtime `
  -f zkvm/docker/risc0-cuda.Dockerfile `
  --build-arg CUDA_ARCH=89 `
  --build-arg "RISC0_HOME_TREE_SHA256=${Risc0HomeTreeSha256}" `
  --build-arg "SOURCE_MANIFEST_SHA256=${CandidateSha}" `
  -t "${Registry}/zkdeal-risc0-runtime:${CandidateSha}" .

docker push "${Registry}/zkdeal-risc0-runtime:${CandidateSha}"
docker image inspect --format '{{index .RepoDigests 0}}' `
  "${Registry}/zkdeal-risc0-runtime:${CandidateSha}"
```

Record the printed digest reference as `$RuntimeRef`, then check the label the
whole reproduction story rests on:

```powershell
docker image inspect `
  --format '{{index .Config.Labels "org.opencontainers.image.source-manifest.sha256"}}' `
  $RuntimeRef
```

It must equal `$CandidateSha`. (The builder stage already `sha256sum --check`s
the copied candidate against the same build argument, and re-runs
`verify-source-manifest.py` against the copied sources, so a mismatch here
means the reference is wrong, not the label.)

Both refs must be pushed **manifest** digests. `build.mjs` rejects a bare local
`sha256:` image ID and re-verifies each reference resolves to a pushed
repository digest before it builds anything.

## 5. Mint: the mandatory two-build closure

Run from `prover-node/`. This is the only command that writes a trust root.

```powershell
node zkvm/build.mjs --cuda --check-repro --update-lock `
  --toolchain-image $ToolchainRef `
  --runtime-image $RuntimeRef
```

`--update-lock` (not `--bootstrap-lock`) is correct here: this tree carries an
existing generated lock (the v5 one) that is being replaced.
`--bootstrap-lock` is for a fresh extraction of the no-history physical bundle,
which has no lock at all. `--check-repro` is not optional with either flag; the
build refuses the combination without it.

What the run does, in order:

1. verifies the candidate manifest against the tree;
2. asserts both image pins are pushed digests, and that the runtime image's
   source-manifest label equals the verified candidate digest;
3. builds the wasm browser verifier, the production CUDA host + guest, and the
   proving-disabled `client-verifier` binary (no `libcuda.so`, every gated
   subcommand refused with the host's own refusal sentence);
4. reads `/etc/zkdeal/toolchain-versions.json` out of the toolchain image and
   cross-checks the host's reported risc0 version against it;
5. writes `build/risc0/capabilities-v6.json` from the host's own capability
   payload through the deterministic projection;
6. re-derives the image ID, then **rebuilds everything a second time** in the
   `-repro` volume pair and requires the guest image ID plus all four compiled
   artifact hashes to match;
7. verifies the separately pinned runtime image reports the same guest, passes
   `health` on the GPU, and yields its stripped host binary sha256;
8. checks the frozen certified AMM witnesses against the built guest;
9. mints `artifacts.lock.json` through the same `validateLockShape` gate the
   verifier uses, and writes `source-manifest.json` from the exact candidate
   bytes.

Expect roughly double a normal build's wall clock. That is the double build,
by design.

### Expected outputs

| Path | State after the run |
| --- | --- |
| `prover-node/zkvm/artifacts.lock.json` | rewritten: format `zkdeal/zkvm-artifacts-lock/v6`, `journalVersion` 6, `runtimeCompatibility` `v6-only`, new `risc0.imageId`/`programId`, `sourceManifestSha256` = `$CandidateSha`, both image pins, `toolchain.risc0HomeTreeSha256` = `$Risc0HomeTreeSha256`, `runtime.hostBinarySha256`, 7 artifact hashes, 25 host commands |
| `prover-node/zkvm/source-manifest.json` | **NEW tracked file** - byte-identical to `source-manifest.candidate.json` |
| `prover-node/zkvm/source-manifest.candidate.json` | unchanged (already committed in step 1) |
| `prover-node/zkvm/build/risc0/capabilities-v6.json` | regenerated; gitignored build output, but pinned by the lock |
| `prover-node/zkvm/build/risc0/{zkdeal-r0,zkdeal-r0-client,verifier/*}` | rebuilt; gitignored, pinned by the lock |

The final log lines are `lock written: ...` and
`source manifest written: ... sha256=<M>`; that `<M>` must equal
`$CandidateSha`.

If `build.mjs` reports `source-manifest.candidate.json does not describe the
exact sources used by the reproducibility closure`, something edited the zkVM
tree between step 1 and now. Do not re-prepare on the box. Restart from step 1.

## 6. Static gates on the box

Run from `prover-node/`. All three must be green; they were red by design
before the mint.

```powershell
pnpm check:sources          # node zkvm/scripts/check-lock-freshness.mjs
pnpm check:artifacts        # node scripts/verify-zkvm-locks.mjs
pnpm check:artifacts:gpu    # ... --require-zkvm-build
```

Expected first line of `check:sources`:
`zkVM source manifest is current sha256=<M>`.

`check:artifacts` must now print no `NOT VERIFIED` line beginning with `zkVM`,
which is precisely what `check:artifacts:gpu` promotes to a failure. Also worth
running here, since they are cheap and cover the release path:

```powershell
node zkvm/scripts/check-no-git-sources.mjs
node --test zkvm/scripts/*.test.mjs
```

## 7. Mint the real-proof fixture (kurtosis-free)

The Solidity suite's one real CUDA proof comes from the same prepare/prove
boundary the acceptance runner uses, but here it is served by a **standalone
container on loopback**. No enclave, no queue, no coordinator.

### 7a. Start the pinned runtime image

Run from anywhere on the box.

```powershell
docker run -d --name zkdeal-v6-mint --gpus all `
  -p 127.0.0.1:8080:8080 `
  $RuntimeRef
```

Two deliberate choices:

- **No `ZKDEAL_PROVER_TOKEN`.** Every `POST /v5/*` route requires
  `Authorization: Bearer $ZKDEAL_PROVER_TOKEN` *when that variable is set at
  startup*; leaving it unset leaves the routes open. The minter
  (`packages/bench/src/prover-client.ts`) sends only `content-type`, so it can
  only talk to a tokenless prover.
- **`127.0.0.1:8080:8080`, not `8080:8080`.** An unauthenticated prover bound
  to all interfaces is a starvation target - each route takes the single GPU
  slot. The loopback bind is what makes the tokenless run defensible.

Wait for readiness (the health preflight must pass before the listener binds,
so a `/healthz` 200 means a working GPU):

```powershell
curl.exe -s http://127.0.0.1:8080/healthz
curl.exe -s http://127.0.0.1:8080/v5/capabilities
```

Confirm `programId` equals `risc0.programId` in the freshly minted
`zkvm/artifacts.lock.json` before spending GPU time.

### 7b. Run the minter

Run from `kurtosis-testing/`. Install first, in the canonical folder order
(`app-node` is the `link:` hub the bench packages resolve into):

```powershell
pnpm -C ..\app-node install --frozen-lockfile
pnpm install --frozen-lockfile

$env:PROVER_URL     = 'http://127.0.0.1:8080'
$env:PROVENANCE_OUT = '..\web3-protocol\contracts\test\fixtures\room-v5-real-proof.provenance.json'
pnpm --filter @zkdeal/bench mint:fixture
```

The script takes an optional output path as `argv[2]`. **Do not pass one.** Its
default resolves to
`web3-protocol/contracts/test/fixtures/room-v5-real-proof.json`, and that exact
filename is referenced by `RoomManagerRealProof.t.sol:18`,
`RiscZeroOfficialVerifier.t.sol:13` and the script's own default. Renaming it
silently un-covers both suites.

`PROVENANCE_OUT` is optional but should be set: it writes a
`zkdeal/b200-real-proof-fixture-provenance/v1` record with the program ID, GPU
name/UUID, elapsed times, image ID and profile for both the cold-template and
the room proof. It is evidence only; no test reads it.

The minter talks to one already-running production prover. It will not start a
fallback prover and will not accept a development receipt: it requires
`proofMode == 'groth16'` and a non-empty Ethereum seal on both proofs, requires
both proofs to come from the same guest program, and requires the prepared
`genesisDataHash` / `canonicalColdTemplateData` the v6 registry statement binds.
On success it prints
`Decision: fresh zkdeal CUDA proof fixture minted at <path>`.

Both output paths are **outside `zkvm/`**, so the fixture does not disturb the
source manifest that was just minted.

Stop and remove the container when done:

```powershell
docker rm -f zkdeal-v6-mint
```

## 8. Post-mint contracts gate

Run from `web3-protocol/`.

```powershell
docker compose run --rm contracts-test
```

Expected changes versus the pre-ceremony baseline:

- `RoomManagerRealProofTest.test_realCudaProofAdvancesTheLongLivedRoom`
  **stops skipping**. Its skip is a fixture-content check: it requires
  `.journal.authorization_mode`, `.journal.inbox_records_hash` and
  `.genesisDataHash` to exist and `.journal.protocol_version` to equal
  `RoomTypes.PROTOCOL_VERSION`. A v6 fixture satisfies all four, so the skip
  count drops by one and the test must now pass on its merits.
- `RiscZeroOfficialVerifierTest` (2 tests) never skipped: it verifies whatever
  fixture is present against the official upstream Groth16 verifier, including
  the negative cases (a flipped journal hash and a flipped program ID must both
  fail). After the re-mint it is verifying the **new** seal against the **new**
  program ID, so a stale or wrong fixture now fails rather than skips.

If `RoomManagerRealProof` still skips, the fixture is not v6: re-read the
minter's output path and the prover's `programId` before re-running the GPU.

Also re-run the web3-protocol lock gate, which is unaffected by the ceremony
but cheap:

```powershell
pnpm check:artifacts
```

## 9. The single ceremony commit

One commit, on the box or after syncing the outputs back, containing exactly:

| Path | Why |
| --- | --- |
| `prover-node/zkvm/artifacts.lock.json` | the minted v6 trust root |
| `prover-node/zkvm/source-manifest.json` | new tracked authoritative manifest |
| `web3-protocol/contracts/test/fixtures/room-v5-real-proof.json` | the fresh v6 real-proof fixture |
| `web3-protocol/contracts/test/fixtures/room-v5-real-proof.provenance.json` | GPU/program provenance for that fixture |
| `prover-node/docs/RUNNING-A-PROVER.md` | the digest table in section 1: replace the pre-v6 block with the published v6 digests |

`prover-node/zkvm/source-manifest.candidate.json` is **not** in this list - it
was committed in step 1 and must be byte-identical to `source-manifest.json`.

Nothing else. In particular: **no edit to any file under `prover-node/zkvm/`
other than the two generated trust-root files.** `docs/` is outside the source
roots, so the `RUNNING-A-PROVER.md` digest-table update is safe; anything inside
`zkvm/` - including this ceremony document - would make `check:sources` stale
the moment it is committed, and the trust root would have to be minted again.

After the commit, re-run the three gates from step 6 on a clean checkout of it.
Green there is the ceremony's acceptance criterion.

## 10. What happens next (not part of this ceremony)

- Publish the two image digests and refresh the reproduction guide's pins:
  [`../../docs/REPRODUCING-THE-TRUST-ROOT.md`](../../docs/REPRODUCING-THE-TRUST-ROOT.md).
- The manual publication steps - repository visibility, digest publication
  including the still-pending `sm120` entry, dependency graph, L2BEAT
  submission artifacts - are collected in
  `review-l2beat-stages/PUBLICATION-CHECKLIST.md`.
- The full physical-closure evidence set (hosted rooms, blob bundles, soak,
  withdrawal claim, gas evidence) remains
  [`RTX4090_RELEASE_RUNBOOK.md`](RTX4090_RELEASE_RUNBOOK.md).

## Stop conditions

Abort the ceremony and restart from step 1 if any of these occur:

- the box's `git status` is not clean, or `HEAD` is not the step-1 commit;
- `--check-build-input` on the box prints a digest other than `$CandidateSha`;
- the runtime image's source-manifest label does not equal `$CandidateSha`;
- the enforced toolchain build reports an rzup component-tree mismatch;
- `--check-repro` reports any non-reproducible artifact or a differing image ID;
- `build.mjs` reports the candidate does not describe the sources used;
- any of the three step-6 gates is not green;
- the minter reports a non-Groth16 proof mode, an empty seal, mismatched cold
  and room program IDs, or a missing genesis binding.

Preserve failed attempts. Never delete or overwrite an artifact to make a retry
look continuous - the release runbook's write-once evidence rule applies here
too.
