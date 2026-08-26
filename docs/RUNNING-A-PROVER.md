# Running a zkdeal CUDA prover node

This is the operator guide for the public prover image
[`zkdeal/prover-cuda`](https://hub.docker.com/r/zkdeal/prover-cuda): what is
inside it, how to run it (including inside an Azure confidential-GPU VM), how
it joins the zkdeal Web2 portal and the on-chain room pool, how it relates to
the published prover source, and how anyone can check which prover version is
actually running.

## 1. What the image is, and where the source is

**The image is the operational product surface; the source is the audit
surface.** Both are public, and they answer different questions. The image is
what you run: one stripped binary plus the proving parameters, pinned by
manifest digest, ready for a GPU. The source is what you check it against: the
guest state-transition function, the `zkdeal-r0` host, the build contract and
the reproducibility ceremony that ties the two together.

The prover source is published under the **Business Source License 1.1**
(`prover-node/zkdeal-BUSL-1.1-LICENSE`, also carried at
`prover-node/zkvm/zkdeal-BUSL-1.1-LICENSE` and shipped inside the image at
`/zkdeal-BUSL-1.1-LICENSE`). In short: copying, modification, redistribution
and non-production use are granted now; there is no Additional Use Grant, so
production use needs a commercial license until the Change Date (16 August
2030), after which the terms become MIT. Publication is a transparency and
audit commitment, not a production-use grant.

Reading the source is one thing; establishing that the image you pulled was
built from it is another. The end-to-end procedure - pinned
`repository@sha256` images, the OCI source-manifest label, the deterministic
source manifest and its dependency-free second implementation, the
double-build re-derivation of the guest program ID, and the verifier-side
locks - is
[REPRODUCING-THE-TRUST-ROOT.md](REPRODUCING-THE-TRUST-ROOT.md).

### What is inside the image

The image ships **no source code**; publishing the repository did not change
its contents. Its useful contents are exactly:

| Path | What |
| --- | --- |
| `/usr/local/bin/zkdeal-r0` | The prover host binary (stripped). The RISC Zero **guest ELF and its image ID are compiled into this binary** - they are not separate files. |
| `/home/zkdeal/.risc0/extensions/v0.1.0-risc0-groth16` | RISC Zero's Groth16 proving parameters (~2.2 GB, upstream content, sha256-verified at build). |
| `/etc/zkdeal/source-manifest.json` | The deterministic inventory of the sources this image was built from. Its sha256 is also the image's `org.opencontainers.image.source-manifest.sha256` label; a reviewer checks one against the other. |
| `/zkdeal-BUSL-1.1-LICENSE` | The license, carried on every shipped first-party image as the BUSL requires. |
| CA certificates, `nvidia/cuda:12.9.1-runtime` base | TLS trust + CUDA runtime libraries. |

It is built with `--target runtime` from
[`zkvm/docker/risc0-cuda.Dockerfile`](../zkvm/docker/risc0-cuda.Dockerfile):
the `builder` stage compiles in a throwaway layer and only the single stripped
binary is copied forward, so no Rust sources, cargo caches or toolchains reach
the published layers. What *does* remain in the binary is Rust panic-location
metadata (file **names** like `crates/risc0/host/src/http.rs`, not file
contents). Removing those strings would require `--remap-path-prefix`, which
changes the guest ELF and therefore the proving image ID - a trust-root
migration we deliberately do not make for cosmetic scrubbing.

The container starts as non-root (`zkdeal`, uid 10001), runs
`zkdeal-r0 serve --host 0.0.0.0 --port 8080`, and its Docker `HEALTHCHECK` is
`zkdeal-r0 health`. The health preflight must pass **before** the HTTP
listener binds: a container without a working CUDA GPU never becomes
routable.

### Architecture tags

CUDA kernels are compiled per GPU architecture. Pick the tag matching your
card; the **guest program ID is identical across all of them** (the guest is
RISC-V, not CUDA), so proofs from any tag verify against the same on-chain
pin.

| Tag | `CUDA_ARCH` | Cards | Status |
| --- | --- | --- | --- |
| `zkdeal/prover-cuda:sm86` | 86 | RTX 30xx (Ampere) | hardware-validated |
| `zkdeal/prover-cuda:sm89` | 89 | RTX 40xx (Ada) - the default-node floor | hardware-validated; `latest` points here |
| `zkdeal/prover-cuda:sm90` | 90 | H100 (Hopper), incl. Azure confidential GPU VMs | **build-verified only** - we have not run it on H100 hardware yet |
| `zkdeal/prover-cuda:sm120` | 120 | RTX 50xx (Blackwell), incl. RTX 5090; needs an r570+ driver | hardware validation in progress - the 5090 release run |

Tags are convenience labels only. Production pins the **manifest digest** and
verifies the image's `org.opencontainers.image.source-manifest.sha256` label
against the deterministic source manifest (§6 for checking a running prover;
[REPRODUCING-THE-TRUST-ROOT.md](REPRODUCING-THE-TRUST-ROOT.md) for the label
and manifest themselves). Recorded image digests:

| Tag | Manifest digest |
| --- | --- |
| `sm89` (= `latest`) | `sha256:810ef5dffb2c9aaf6df152c2d0a8b41b2abdcc9f6021d4334d6fb2a69b977e11` |
| `sm86` | `sha256:76f0acfb81e8d8170a39e215c168153a0854a4927b547d26677e158913c838a5` |
| `sm90` | `sha256:ba3b1ebb47df07c7b47fdfb441f66e00659b889156e3b556b41e566e9a08f454` |
| `sm120` | pending publication - filled by the 5090 release run |

> **Superseded (pre-v6).** The digests above are the last published **v5**
> protocol binaries and are kept for the historical record. The v6 protocol
> requires a fresh trust-root ceremony (new guest program ID, new lock, new
> source manifest); its image digests will be added here when that ceremony
> publishes them. These v5 images do not prove v6 statements and do not verify
> against a v6 deployment.

## 2. Quickstart

Requirements: an NVIDIA GPU with ≥8 GB VRAM, a driver new enough for CUDA
12.9, and the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
- the prover probes the GPU with `nvidia-smi` *inside* the container and
refuses to serve without it.

```bash
docker run --gpus all -p 8080:8080 \
  -e ZKDEAL_PROVER_TOKEN='<a long random secret>' \
  -e SEGMENT_PO2=20 \
  zkdeal/prover-cuda:sm89
```

**Always set `ZKDEAL_PROVER_TOKEN`.** Without it every `/v5/*` proving route
is unauthenticated - the prover prints a `Blocker:` warning and serves
anyway, which is acceptable only on an isolated devnet. Only `GET /healthz`
and `GET /v5/capabilities` (and the counters-only `GET /metrics`) are meant
to be open.

`SEGMENT_PO2` sizes proving segments to VRAM: `20` for ≥12 GB, `19` for 8 GB
cards, `18` below that. Too large OOMs the Groth16 wrap; too small wastes
throughput. The measured table and reasoning live in
[GPU-SEGMENT-SIZING.md](../../kurtosis-testing/docs/GPU-SEGMENT-SIZING.md)
(reference points: RTX 4090 24 GB at PO2 20 ≈ 63 s per room proof; RTX 3080
Laptop 8 GB at PO2 19 peaks ~6.1 GB and OOMs at 20).

## 3. Running inside an Azure GPU TEE (confidential computing)

The prover runs unmodified inside an Azure **NCC ads H100 v5** confidential
VM - an AMD SEV-SNP confidential VM paired with an NVIDIA H100 in
confidential-computing mode. In that deployment the CPU+GPU TEE protects the
*runtime*: VM memory and the GPU's protected memory are encrypted and
isolated from the host/cloud operator, so the prover binary, the Groth16
parameters and in-flight room witnesses are shielded even from whoever runs
the physical machine.

Deployment sketch:

1. Provision an `Standard_NCCads_H100_v5` confidential VM (Ubuntu 24.04 CVM
   image), enabling the confidential GPU option so the H100 boots in CC mode.
2. Install the NVIDIA driver with CC support and the NVIDIA Container
   Toolkit; verify `nvidia-smi conf-compute -f` reports CC enabled.
3. `docker run` the `sm90` tag exactly as in §2 (pin by digest, §5).
4. Attest before trusting: Azure Guest Attestation proves the CVM's
   SEV-SNP report, and NVIDIA's [nvTrust](https://github.com/NVIDIA/nvtrust)
   verifies the H100's CC attestation. Gate the release of your
   `ZKDEAL_PROVER_TOKEN` / queue node token on both reports if you automate
   provisioning.

Honest caveats:

- The `sm90` tag is **build-verified but not yet validated on H100
  hardware** by us. Treat the first deployment as a pilot and confirm
  `/healthz` + a `/v5/cold-templates/prove` round-trip before joining a pool.
- The TEE protects confidentiality/integrity of the *running* prover. It is
  **not** what makes proofs trustworthy - that is the zk layer itself (§6).

## 4. Registering in the Web2 portal (joining the prove queue + room pool)

zkdeal provers **pull** work; nothing connects inbound to your box, so no
ingress/port-forwarding is needed beyond the prover and agent talking to each
other locally.

The moving parts:

- **Your prover** (`zkdeal/prover-cuda`) serves HTTP on localhost.
- **The agent sidecar** (`prover-node/agent`, ~300 lines, in-repo) leases
  jobs from the coordinator's **prove queue** (`/queue/v1/*`), forwards them
  to your prover with your bearer token, heartbeats the lease every 30 s, and
  reports complete/fail.
- **The room pool contract** (`RoomPoolManager` on L1) tracks node identity,
  capacity and liveness on-chain.

Steps:

1. **Get credentials out of band** from the zkdeal operator (the portal has
   deliberately no self-service signup): the queue URL and a
   `ZKDEAL_QUEUE_NODE_TOKEN` (≥16 chars), plus your registered `NODE_ID`.
2. **On-chain registration is admin-gated**: the pool admin calls
   `registerNode(nodeId, serviceAccount, boundAccount, metadataHash,
   heartbeatTimeoutBlocks)` - an operator cannot self-register. The
   `serviceAccount` is a liveness-only address bound to your node. The hosted
   coordinator owns its durable nonce/signing boundary; the agent receives
   only a node-bound `l1-liveness` service credential and the expected address.
3. **Run the agent** next to your prover:

| Env | Meaning |
| --- | --- |
| `QUEUE_URL` | The coordinator's prove-queue base URL (required) |
| `ZKDEAL_QUEUE_NODE_TOKEN` | Node lease credential (required) |
| `NODE_ID` | Your registered node id (else a random `agent-<uuid8>`) |
| `PROVER_URL` | Local prover, default `http://127.0.0.1:8080` |
| `ZKDEAL_PROVER_TOKEN` | Forwarded to your prover as the bearer |
| `ROOM_POOL` + `L1_CHAIN_ID` | Identifies the pool and chain for on-chain heartbeats |
| `NODE_LIVENESS_COORDINATOR_URL` | Hosted coordinator base URL; schema is negotiated from `/hosting/v1/capabilities` |
| `NODE_LIVENESS_COORDINATOR_AUTH_TOKEN` | Node-bound bearer credential with only the `l1-liveness` role |
| `NODE_LIVENESS_ACCOUNT` | Exact expected liveness address; every durable-operation response is checked against it |
| `NODE_LIVENESS_CONFIRMATIONS` | Required canonical confirmation depth (default 2) |
| `NODE_LIVENESS_REQUEST_TIMEOUT_MS` | Per-request coordinator deadline (default 5000 ms) |

Production agents never receive a raw L1 key and never submit directly to an
L1 RPC. Direct viem submission requires `NODE_LIVENESS_DEV_MODE=true`, a raw
development key, and a loopback-only `L1_RPC_URL`.

4. **Liveness semantics**: the agent leases only while your prover's
   `/healthz` passes, and it goes **quiet on-chain when unhealthy** - a node
   whose GPU died must look dead, not healthy. After
   `heartbeatTimeoutBlocks` without a heartbeat anyone can `markNodeStale`.
5. **What the portal shows**: the room-pool console reads `nodeState`
   (Ready/Offline/…), slot capacity, published price epochs and quotes. Your
   queue-side stats (`jobsDone`, last lease/result) are public at the
   queue's `GET /queue/v1/status`.

## 5. How protection works, and its limits

Three independent layers:

1. **Distribution and licensing**: the public image contains one stripped
   binary + upstream proving parameters, and is the operational product
   surface. The source is published under BUSL-1.1 (section 1), so the
   commercial boundary is a license term rather than secrecy. Neither the
   license nor the image shape protects the *protocol* - the protocol's
   security never depends on secrecy, which is why the source can be
   published at all.
2. **Runtime protection (optional, TEE)**: in an Azure confidential GPU VM
   the running prover and witnesses are shielded from the infrastructure
   operator (§3).
3. **Access protection**: bearer token on every proving route; queue node
   token for leasing; a node-bound `l1-liveness` coordinator credential for
   durable heartbeats. Rotate any of them independently.

What none of this needs to protect: **proof validity**. A room batch proof
verifies on L1 against the pinned guest program ID. A malicious or modified
prover cannot mint a valid proof for a wrong state transition - the worst it
can do is fail to produce proofs, which the heartbeat/stale machinery makes
visible.

## 6. Checking prover state and version

Ordered strongest-first:

1. **Launch by digest.** Run `zkdeal/prover-cuda@sha256:<manifest digest>`,
   not a mutable tag. Docker resolves the manifest digest cryptographically;
   this - not any self-report - is what establishes which image is running.
2. **Ask the prover what guest it embeds**:

   ```bash
   curl -s http://127.0.0.1:8080/healthz | jq '{status, imageId, programId, gpuName, driverVersion, risc0Version}'
   curl -s http://127.0.0.1:8080/v5/capabilities | jq '{programId, cudaCompiled, productionCompiled, proofModes, maxBatchBlocks}'
   ```

   `programId`/`imageId` derive from the compiled-in guest ELF - the one
   value the host cannot fake, because proof verification depends on it. It
   must equal `risc0.programId` in the repo's trust root,
   [`zkvm/artifacts.lock.json`](../zkvm/artifacts.lock.json), and it is the
   same across all architecture tags. The `cudaCompiled`/`productionCompiled`
   flags come from compile-time features, never from configuration.
3. **Live counters**: `GET /metrics` (Prometheus text) exposes uptime,
   request counters per route/outcome and GPU utilization/VRAM/power gauges
   (sampled at most every 2 s) - enough to see that a node is actually
   proving without exposing any request bytes.
4. **Binary identity**: the lock's `runtime.hostBinarySha256` is the sha256
   of the stripped `zkdeal-r0` extracted from the pinned image; you can
   `docker cp` the binary out and compare.
5. **Know what is NOT attestation**: the `containerDigest` field in
   `/healthz` merely echoes the `ZKDEAL_CONTAINER_DIGEST` env the operator
   set - it is a telemetry label. Nothing in the image derives or attests
   it. Container identity comes from step 1; hardware-rooted attestation
   comes from the TEE flow in §3.

## 7. Operational reference

- Ports: `8080` HTTP. GPU work is serialized through a single in-process
  permit; a busy prover queues, it does not parallelize one GPU.
- `SEGMENT_PO2` ∈ {18, 19, 20, 21} (21 is deliberately manual-only).
- Logs go to stderr in `Decision:`/`Progress:`/`Blocker:` form.
- The image's env defaults: `RISC0_PROVER=local`, `SEGMENT_PO2=20`,
  `ZKDEAL_PRODUCTION=1`, `RUST_LOG=info`.
- Building from the published source: see
  [`zkvm/docker/README.md`](../zkvm/docker/README.md) - including the
  reproducibility ceremony (`build.mjs --cuda --check-repro`) that keeps the
  published binary independently rebuildable at identical hashes.
  [REPRODUCING-THE-TRUST-ROOT.md](REPRODUCING-THE-TRUST-ROOT.md) is the same
  ground from a reviewer's side: verify rather than build.
