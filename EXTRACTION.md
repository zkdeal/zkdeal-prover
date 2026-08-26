# Extracting `prover-node/` into its own repository

## 1. Carve out the history

```bash
git filter-repo --subdirectory-filter prover-node
# or: git subtree split -P prover-node -b prover-node-only
```

The folder already carries its own `package.json`, `pnpm-lock.yaml`,
`pnpm-workspace.yaml` (two packages: the folder root and `agent/`),
`tsconfig.base.json`, `.gitattributes` and `.gitignore`. There is no
`AUDIT-EXCEPTIONS.md` (the npm dependencies here are dev-only; the audit
gate has nothing production-scoped to triage).

## 2. Sibling references to resolve

There are **no `link:` dependencies** and no production-path sibling reads.
Every coupling is dev-time fixture regeneration:

| File | Reaches into |
| --- | --- |
| `scripts/gen-stf-fixtures.ts` | `createRequire` on `../app-node/packages/l2-engine/package.json`; reads `../web3-protocol/contracts/scenarios.json` and `.../out` |
| `zkvm/scripts/gen-certified-amm-fixture.mts`, `gen-certified-amm-cold-composed.mts`, `zkvm/scripts/lib/amm-fixture-*.mts` | direct source imports from `../../../app-node/packages/{l2-engine,protocol,zkvm}/src` |

Standalone options, in order of effort: (a) document that fixture
regeneration requires an umbrella-shaped checkout of `app-node` and
`web3-protocol` beside this repo at a pinned commit; (b) repoint the imports
at published `@zkdeal/*` packages once those exist. The committed certified
fixtures under `zkvm/fixtures/` are lock-pinned inputs, so the repo builds,
tests and serves without regeneration.

Incoming couplings to keep working:

- `web2-api` reads `zkvm/build` and `zkvm/artifacts.lock.json` via the
  env-overridable `ZKVM_ARTIFACTS_ROOT` and `ZKVM_LOCK_PATH` (defaults hop
  through its `UMBRELLA_ROOT`).
- `kurtosis-testing/scripts/build-docker-images.*` builds the prover image
  with `-f prover-node/zkvm/docker/risc0-cuda.Dockerfile` and this folder as
  the build context. After extraction, that script needs either a
  side-by-side checkout or a published image reference.

## 3. Files that must ride along

- `.gitattributes` - **load-bearing**. `zkvm/artifacts.lock.json` pins sha256
  over raw LF bytes; a CRLF checkout fails `verify-zkvm-locks.mjs`. It also
  carries the `zkvm/ligetron/sdk-rust/** linguist-vendored` line. Land it in
  the first commit.
- `zkvm/artifacts.lock.json` + `zkvm/lock-schema.mjs` - the trust root and
  its single-source schema. The schema derives its literals from the host
  contract in `zkvm/crates/risc0/host/src/main.rs`; they move together.
- `zkvm/rust-toolchain.toml`, `zkvm/Cargo.lock`, the digest pins inside
  `zkvm/docker/risc0-cuda.Dockerfile`, and `zkvm/docker/fetch-pinned-risc0-groth16.sh`.
- Vendored trees `zkvm/vendor/` and `zkvm/ligetron/`.
- `pnpm-lock.yaml` and the `pnpm.overrides` block in `package.json`.

## 4. CI the standalone repo needs

| Job | Command | Runner |
| --- | --- | --- |
| locks (required) | `docker compose run --rm locks-test` | hosted, GPU-free; the trust-root gate on every PR |
| cargo tests | `docker compose run --rm test` | hosted; `stf-core`, `stf-wire`, `stf-types`, host `cargo check` (guest build skipped by design) |
| toolchain + build | `docker compose run --rm toolchain-build && docker compose run --rm build` | GPU runner for the CUDA reproducibility build; pair with `verify-zkvm-locks.mjs --require-zkvm-build` |
| smoke | `docker compose run --rm smoke` | GPU runner; boots the prover and proves a certified fixture |

One infrastructure requirement stands out: the lock records **image
digests**, so a standalone repo needs a registry to push the pinned
toolchain/runtime images to (the umbrella has used
`ghcr.io/olegjakushkin/zkdeal-risc0-{toolchain,runtime}`); locally built,
never-pushed digests cannot serve as a shared trust root.
