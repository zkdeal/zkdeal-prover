# RTX 4090 release closure

This is the physical release procedure for the current hosted app-node,
coordinator, zkVM, and L1 hosting surfaces. It is intentionally dormant: do not
run it until the source owner and infrastructure owner have sealed and
transferred one final umbrella candidate. Local or non-GPU runs must not update
`zkvm/artifacts.lock.json`,
`zkvm/source-manifest.json`, proof fixtures, or qualified gas evidence.

The compatibility suffixes in CLI names such as `prove-room-v5` identify the
existing request types. The authoritative protocol/journal version is the one
reported by the pinned capability payload and artifact lock.

## Release invariants

- No repository-history client or history-derived identifier participates.
- The transfer identity is the deterministic umbrella source archive. Its
  manifest includes the complete current `app-node`, `prover-node`,
  `web3-protocol`, `web2-api`, and `cloud-deployer-infra` trees; the zkVM source
  manifest is a separately bound submanifest, not a substitute for that
  cross-project closure.
- The release has two non-circular byte boundaries. The candidate manifest and
  umbrella archive seal the build preimage first. `zkvm/artifacts.lock.json`,
  `zkvm/source-manifest.json`, and `zkvm/build/**` are outside that preimage and
  are bound afterward by a separate write-once generated-trust-root closure.
  The final evidence closure binds both boundaries.
- Every build, test, validator, proof, and transaction-evidence command runs in
  Docker. Host PowerShell only orchestrates Docker, reads files, and moves the
  sealed bundle/evidence files.
- Image identity is always a pushed `repository@sha256:<64 hex>` manifest
  reference. A local image ID or mutable tag is never evidence.
- The sealed zkVM candidate-manifest digest scopes four new Docker volumes: the primary
  target/registry pair and a different repro target/registry pair. They must be
  absent before the first ceremony attempt and are retained across an
  interrupted retry.
- Exactly one GPU compute container runs at a time. Exited failure containers,
  build caches, and `.partial` evidence remain until the release owner closes
  the investigation. Do not prune the node during the ceremony.
- Proof and receipt outputs are write-once. A completed unit is skipped on
  resume only after its SHA-256 and the corresponding pinned-runtime verify
  command both pass.
- Mock verifiers, a mocked point-evaluation call, and contract-path overhead
  figures are never release gas evidence.

## Immutable inputs

Record these values in the ceremony ticket before any GPU work:

| Input | Required binding |
| --- | --- |
| Sealed umbrella source bundle | Archive SHA-256, outer-manifest SHA-256, embedded-manifest SHA-256, entries SHA-256, and a successful `source_bundle.py verify` report |
| Cross-project source closure | Exact bindings for app-node room-node capability, prover candidate manifest, contract capability, owner hosted-integration evidence, and soak schema |
| `zkvm/source-manifest.candidate.json` | Prepared before the umbrella archive is sealed, included in that archive, and verified read-only on the GPU node |
| Generated trust-root closure | Write-once index created only after the two matching CUDA builds; binds candidate=minted source manifest, artifact lock, program ID, staged image digests, and every locked artifact |
| Release orchestrator | pushed manifest digest built from `release-orchestrator.Dockerfile` |
| CUDA toolchain | pushed manifest digest, CUDA architecture `sm_89`, reviewed RISC Zero component-tree SHA-256 |
| CUDA runtime | pushed manifest digest whose OCI source-manifest label equals the candidate digest |
| L1 contracts | deployment address manifest produced by `Deploy.s.sol`, including both hosting facets |
| L1 interfaces | checked capability manifest and the two checked ABI SHA-256 values |
| Settlement chain | EIP-4844-capable Anvil/devnet with the real verifier and precompile `0x0a` |
| Runtime L1 publishers | capability-advertised owner durable operations for room batch, aggregate/type-3 blob settlement, withdrawal claim, and sponsored pool mutation; each owns nonce, remote signer, watcher, idempotency, and canonical finality evidence |
| Hosted owner boundary | final non-self-referential hosted-integration acceptance token, validated `owner-durable-capabilities.json`, and digest-pinned owner acceptance runner; interim status, a stale token, or any disabled required publisher is not evidence |
| Stateful soak | digest-pinned 12-hour owner runner, immutable soak manifest, durable journal/state mounts, and scheduled restart/failover/reorg faults |

The Docker definitions already pin their parent manifests. Use the final
candidate digest as the immutable tag component while building; use only the
pushed digest returned by the registry afterward.

```powershell
$CandidateRoot = 'C:\zkdeal-release\<umbrella-archive-sha256>'
$Source = "${CandidateRoot}\prover-node"
$Cloud = "${CandidateRoot}\cloud-deployer-infra"
$Incoming = 'C:\incoming\zkdeal'
$Evidence = 'C:\zkdeal-release-evidence\<umbrella-archive-sha256>'
$SourceBundleSha = '<umbrella-archive-64-lowercase-hex>'
$CandidateSha = '<zkvm-candidate-manifest-64-lowercase-hex>'
$Registry = '<registry>/<namespace>'
$Risc0HomeTreeSha256 = '<reviewed-64-lowercase-hex>'
$NodeImage = 'node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32'
$PythonImage = 'python@sha256:540c7d91f98ff6880174c40e99067bf5941eb54d818a7a5e094d188b196a934d'
```

The source owner runs `--prepare-build-input` before creating the umbrella
archive. The transferred source directory is never edited except for the documented
closure outputs under `zkvm/build`, `zkvm/artifacts.lock.json`, and
`zkvm/source-manifest.json`. The bundle policy excludes the lock and minted
manifest, so the fresh extracted candidate contains neither; the physical
ceremony creates them once after the two matching builds. The candidate
manifest and source closure remain immutable. If a source-root byte changes,
discard the candidate and start with a new owner-sealed bundle and digest.

## Node preflight

The private node is `192.168.0.11`; use the approved key-authenticated account.
Do not place credentials in the ticket or command history. Before the release
owner authorizes the run, inspection is read-only:

1. Confirm Windows has completed boot and Docker Desktop reports a stable
   server.
2. Record Docker client/server versions, running/exited containers, named
   volumes, free disk, and GPU name/UUID/driver.
3. Confirm there is no active GPU compute container or unrelated CUDA task.
4. Confirm the sealed bundle SHA-256 matches the source owner's value.
5. Confirm all four candidate-scoped volumes are absent on the first attempt:
   `zkdeal-zkvm-target-$CandidateSha`,
   `zkdeal-zkvm-cargo-registry-$CandidateSha`,
   `zkdeal-zkvm-target-repro-$CandidateSha`, and
   `zkdeal-zkvm-cargo-registry-repro-$CandidateSha`.

Use one short pinned CUDA container to capture `nvidia-smi -q` into the evidence
directory, then stop it before starting a build. The base reference is:

```text
nvidia/cuda:12.9.1-runtime-ubuntu22.04@sha256:6553b9635f35d992cf0473f55d1e998935a2dd1e2e604d3cbfb2bf295a8faa79
```

## Candidate preparation and static gates

Run the following only after all candidate files, including this runbook and
the already-prepared `source-manifest.candidate.json`, are sealed. Verification
is read-only against source and writes only new evidence files. It cannot update
either trust-root file.

```powershell
docker run --rm `
  -v "${Incoming}:/incoming:ro" -v "${Evidence}:/evidence" `
  $PythonImage python /incoming/source_bundle.py verify `
    --archive /incoming/zkdeal-source.tar.gz `
    --manifest /incoming/zkdeal-source.tar.gz.manifest.json `
    --output /evidence/source/source-bundle-verification.json

docker run --rm `
  -v "${Incoming}:/incoming:ro" -v "${CandidateRoot}:/candidate:ro" `
  -v "${Evidence}:/evidence" -w /candidate/prover-node $NodeImage `
  node zkvm/scripts/build-4090-evidence-requests.mjs source-closure `
    /incoming/zkdeal-source.tar.gz `
    /incoming/zkdeal-source.tar.gz.manifest.json `
    /evidence/source/source-bundle-verification.json `
    /candidate/prover-node/zkvm/source-manifest.candidate.json `
    /evidence/source/source-closure.json

docker run --rm `
  -v "${Source}:/workspace:ro" -w /workspace $NodeImage `
  node zkvm/scripts/check-lock-freshness.mjs --check-build-input

docker run --rm `
  -v "${Source}:/workspace:ro" -w /workspace $NodeImage `
  node zkvm/scripts/build-4090-evidence-requests.mjs scenario-check `
    zkvm/docker/release-settlement-scenario.json

docker run --rm `
  -v "${Source}:/workspace:ro" -w /workspace $NodeImage `
  sh -lc 'node zkvm/scripts/check-no-git-sources.mjs && node --test zkvm/scripts/*.test.mjs'
```

Stop unless the archive SHA-256 in `source-closure.json` is
`$SourceBundleSha`, the zkVM candidate-manifest SHA-256 is `$CandidateSha`, all
five required project roots and critical bindings are present, and the
verification report has `historyIncluded:false` and `secretsIncluded:false`.
Preserve the umbrella archive, outer manifest, verification report, source
closure, and zkVM candidate digest as separate fields. Any attempt to run
`--prepare-build-input` on the GPU node is a source mutation and invalidates the
candidate.

## Stage and push the three immutable image inputs

Build and push the small orchestrator, the source-independent CUDA toolchain,
and the source-bound runtime. Tags are only staging handles; replace them with
the pushed manifest references before the closure command. This is staging,
not release promotion: do not sign, alias, or advertise these images as the
release yet.

```powershell
Set-Location -LiteralPath $Source

docker build --platform linux/amd64 `
  -f zkvm/docker/release-orchestrator.Dockerfile `
  -t "${Registry}/zkdeal-release-orchestrator:${CandidateSha}" .
docker push "${Registry}/zkdeal-release-orchestrator:${CandidateSha}"

docker build --platform linux/amd64 --target toolchain `
  -f zkvm/docker/risc0-cuda.Dockerfile `
  --build-arg CUDA_ARCH=89 `
  --build-arg "RISC0_HOME_TREE_SHA256=${Risc0HomeTreeSha256}" `
  -t "${Registry}/zkdeal-risc0-toolchain:${CandidateSha}" .
docker push "${Registry}/zkdeal-risc0-toolchain:${CandidateSha}"

docker build --platform linux/amd64 --target runtime `
  -f zkvm/docker/risc0-cuda.Dockerfile `
  --build-arg CUDA_ARCH=89 `
  --build-arg "RISC0_HOME_TREE_SHA256=${Risc0HomeTreeSha256}" `
  --build-arg "SOURCE_MANIFEST_SHA256=${CandidateSha}" `
  -t "${Registry}/zkdeal-risc0-runtime:${CandidateSha}" .
docker push "${Registry}/zkdeal-risc0-runtime:${CandidateSha}"
```

Record the three pushed references as `$OrchestratorRef`, `$ToolchainRef`, and
`$RuntimeRef`. Inspect the runtime labels inside Docker and require
`org.opencontainers.image.source-manifest.sha256=$CandidateSha`. Record the
runtime image's program ID and capabilities, but do not treat its caller-set
`containerDigest` field as attestation. These exact pushed digests are inputs to
the double-build closure. They may be promoted later, but they must never be
rebuilt under the same candidate.

Create the exact unpromoted staging receipt through the write-once assembler:

```powershell
docker run --rm `
  -v "${Source}:/workspace:ro" -v "${Evidence}:/evidence" `
  -w /workspace $NodeImage `
  node zkvm/scripts/build-4090-evidence-requests.mjs staged-images `
    $CandidateSha $OrchestratorRef $ToolchainRef $RuntimeRef `
    /evidence/trust/staged-zkvm-images.json
```

The receipt contains exactly the candidate-manifest digest, `promoted:false`,
and the three distinct pushed references. A mutable tag, extra field, rewritten
receipt, or pre-promoted image fails the generated trust-root closure.

## Mandatory two-build trust-root closure

This is the only authorized minting command. The orchestrator runs in Docker,
and its nested Docker client uses the Windows daemon path supplied in
`ZKDEAL_DOCKER_WORKSPACE_SOURCE`. `build.mjs` performs the primary and repro
builds in different candidate-scoped target/registry volumes, compares the
guest image ID plus all four compiled artifact hashes, verifies the separately
pinned runtime, and only then writes the artifact lock and source manifest.

```powershell
docker run --rm `
  --name "zkdeal-trust-closure-${CandidateSha}" `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${Source}:/workspace" `
  -e "ZKDEAL_DOCKER_WORKSPACE_SOURCE=${Source}" `
  -e "ZKDEAL_BUILD_CACHE_SCOPE=${CandidateSha}" `
  -w /workspace `
  $OrchestratorRef `
  node zkvm/build.mjs --cuda --check-repro --bootstrap-lock `
    --toolchain-image $ToolchainRef `
    --runtime-image $RuntimeRef
```

Acceptance requires two matching builds of:

- the guest program/image ID;
- `build/risc0/zkdeal-r0`;
- `build/risc0/zkdeal-r0-client`;
- `build/risc0/verifier/r0_wasm_verifier.js`;
- `build/risc0/verifier/r0_wasm_verifier_bg.wasm`.

After success, immediately create the write-once generated-output index and
then recompute it read-only from the filesystem:

```powershell
docker run --rm `
  -v "${Source}:/workspace:ro" -v "${Evidence}:/evidence" `
  -w /workspace $OrchestratorRef `
  node zkvm/scripts/build-4090-evidence-requests.mjs trust-root-output `
    /workspace/zkvm /evidence/trust/staged-zkvm-images.json `
    /evidence/trust/generated-trust-root-closure.json

docker run --rm `
  -v "${Source}:/workspace:ro" -v "${Evidence}:/evidence:ro" `
  -w /workspace $OrchestratorRef `
  node zkvm/scripts/build-4090-evidence-requests.mjs trust-root-check `
    /workspace/zkvm /evidence/trust/staged-zkvm-images.json `
    /evidence/trust/generated-trust-root-closure.json

docker run --rm `
  -v "${Source}:/workspace:ro" -w /workspace $NodeImage `
  node zkvm/scripts/check-lock-freshness.mjs --check-build-input
```

`trust-root-output` rejects an old-format lock, source drift, a minted manifest
that is not byte-identical to the candidate, a lock/image/program mismatch,
an altered/promoted staging receipt, symlinked artifacts, or any locked-artifact hash drift. Its output path uses
exclusive creation. Preserve a failed attempt; never delete or overwrite it to
make a retry appear continuous.

At this point the build preimage is still the original immutable candidate and
source archive. The new lock, minted manifest, and compiled artifacts form a
separately hashed output set. No circular archive rewrite occurs. Docker-verify
the runtime `imageid`, runtime `capabilities`, and all artifact hashes. If the
closure is interrupted before the generated-output index is written, leave
both volume pairs intact and rerun the identical command after Docker/GPU
stability is restored. A different source/image/input requires a new
`$CandidateSha` and new volume pairs; never reuse the old scope.

## Write-once evidence and resume contract

Every evidence unit has this identity:

```text
SHA-256(runtime manifest reference || program ID || command || exact request bytes)
```

Store each unit under `evidence/units/<unit-id>/`. A proof container writes its
machine result inside `/home/zkdeal/result.json`; after it exits, copy that file
to a unique `attempt-<n>.partial.json`. Run the matching verify command with the
same pinned runtime. Only a successful verify result permits an exclusive move
to the final filename. Never invoke a proof command with a final output path
that already exists.

On resume:

- final proof + final verify result: re-hash and re-verify, then skip;
- partial proof or exited container: preserve it, inspect logs/telemetry, and
  start a new attempt with the same immutable request;
- running proof after orchestration disconnect: reattach to that one container;
- host reboot/container loss: restart the same unit from its request; do not
  infer success from a partial JSON file;
- source/image/request drift: open a new release candidate, not a resume.

Each proof result must retain cycles, total cycles, segments, receipt/seal
sizes, stage timings, GPU UUID/name/utilization/VRAM/power samples, runtime
manifest reference, program ID, request SHA-256, and result SHA-256.

## Assemble eight live hosted rooms and six blob bundles

`release-room-request-template.json`, `room-configs`, `prepare-room-v5`, and
`split-prepared` remain deterministic fixture/dry-run tools. They are forbidden
as physical release evidence. The physical inputs come from an atomic live
app-node engine artifact, a canonical owner proving context no more than eight
L1 blocks old, and the authenticated hosted prepare route. Hosted release rooms
are explicitly `VALIDITY_ONLY`; the headless product does not manufacture
unanimous approvals.

Before collecting room evidence, require the final owner hosted-integration
acceptance token, current room-node/prover capabilities, one fresh deployment,
and a real CUDA-proved cold template registered for the eight rooms. Create six
rooms with `BLOB_REQUIRED` and two with `CALLDATA_REQUIRED`; retain their exact
creation receipts, fixed DA policy, deployment domain, program ID, and fresh
address/codehash manifest.

For each room `1..8`, the digest-pinned owner acceptance runner must:

1. capture one atomic `LiveBlockArtifact` from the production l2-engine and the
   exact admitted transactions/outcomes it contains;
2. fetch `/hosting/v1/rooms/:roomId/proving-context` and require two-provider
   canonical evidence, `VALIDITY_ONLY`, matching deployment/policy/liability
   commitments, and lag no greater than eight L1 blocks;
3. build the production live request consumed by
   `/hosting/v1/rooms/prepare-batch`; require `fixture:false`,
   `preparedFrom:"live-room-engine-state"`, a content-addressed `BatchInputV5`,
   empty approvals, and exact admission/cursor binding;
4. submit the emitted proof request to `/v5/rooms/prove` on the pinned CUDA
   runtime and submit its exact receipt to `/v5/rooms/verify`; retain raw job
   request/result bytes, job IDs, result digests, correlation ID, program ID,
   journal hash, receipt, Ethereum seal, cycles, timings, and GPU telemetry;
5. create a write-once `hosted-lineage-plan.json` with
   `publicationMode:"aggregate-pending"` and run assembler `hosted-lineage`.
   It rejects fixture preparation, request/result digest drift, a non-RISC-Zero
   or non-Groth16 result, mismatched journals/seals, and an owner publication
   falsely claimed before aggregate settlement;
6. for rooms `1..6`, run assembler `da-request` against the live prepare result
   and room proof with `blobStartIndex` `0..5`, then run
   `prove-data-availability-v1` and `verify-data-availability-v1` on the same
   pinned CUDA runtime.

The `hosted-lineage` plan format is:

```json
{
  "schema": "zkdeal/4090-hosted-batch-lineage-plan/v1",
  "publicationMode": "aggregate-pending",
  "roomId": "1",
  "correlationId": "<same-lineage-correlation-id>",
  "chainId": 1,
  "roomManager": "0x<20-byte-fresh-address>",
  "expectedOperationsAccount": "0x<20-byte-scoped-account>",
  "minimumConfirmations": 2,
  "admissionIds": [],
  "jobs": {
    "prepare": {"endpoint":"/hosting/v1/rooms/prepare-batch","jobId":"pj-<id>","resultDigest":"<sha256>","request":"prepare-request.json","result":"prepare-result.json"},
    "prove": {"endpoint":"/v5/rooms/prove","jobId":"pj-<id>","resultDigest":"<sha256>","request":"prove-request.json","result":"prove-result.json"},
    "verify": {"endpoint":"/v5/rooms/verify","jobId":"pj-<id>","resultDigest":"<sha256>","request":"verify-request.json","result":"verify-result.json"}
  }
}
```

```powershell
docker run --rm `
  -v "${Source}:/workspace:ro" -v "${Evidence}:/evidence" `
  -w /workspace $OrchestratorRef `
  node zkvm/scripts/build-4090-evidence-requests.mjs hosted-lineage `
    /evidence/rooms/room-1/hosted-lineage-plan.json `
    /evidence/rooms/room-1/hosted-lineage.json
```

Use `publicationMode:"owner-finalized"` only when the plan also names the exact
FINALIZED managed-L1 operation and at least one contiguous ACKED admission. The
assembler then requires canonical provider/block evidence and the owner's exact
prepare/prove/verify/journal/calldata/admission binding. Room 8 is converted to
this mode only after the aggregate proof is complete, when its batch is
published independently to create the intentionally stale aggregate member.

Each data-availability proof must contain a complete publishable bundle:
canonical bytes/hash/length, one 131,072-byte blob, its versioned hash, a
48-byte commitment, evaluation point/value, 48-byte KZG proof, Groth16
equivalence seal, and the exact offset. Reject a bundle if c-kzg recomputation
from the blob does not reproduce every value.

Place the six DA proofs and eight room proofs beside a write-once copy of
`release-aggregate-plan.json`. Then assemble the recursive request and exact
six-blob type-3 payload:

```powershell
docker run --rm `
  -v "${Source}:/workspace:ro" -v "${Evidence}:/evidence" `
  -w /workspace $OrchestratorRef `
  node zkvm/scripts/build-4090-evidence-requests.mjs aggregate-request `
    /evidence/aggregate/release-aggregate-plan.json `
    /evidence/aggregate/aggregate-request.json

docker run --rm `
  -v "${Source}:/workspace:ro" -v "${Evidence}:/evidence" `
  -w /workspace $OrchestratorRef `
  node zkvm/scripts/build-4090-evidence-requests.mjs blob-payload `
    /evidence/aggregate/release-aggregate-plan.json `
    /evidence/aggregate/aggregate-blobs.bin
```

The assembler accepts exactly eight distinct same-domain members, six one-blob
members at contiguous offsets `0..5`, two calldata members, complete KZG
bundles, and six matching equivalence receipts. The binary payload must be
exactly `786432` bytes. Run `prove-aggregate-v1`; its result carries the exact
`aggregateWitness`, one recursive receipt/seal, member count eight, and the
locked program ID. Run `verify-aggregate-v1` directly on that result.

## Stale-member settlement, success-only charging, and retry

Use `release-settlement-scenario.json` as the machine-readable acceptance plan.
Its `durablePublishing` section pins every required route and selector, forbids
direct broadcast, and restricts `cast` to independent encoding checks. The
scenario validator must fail until all advertised owner operations are green;
the plan is not evidence that currently missing routes exist.
Seed one fee-bearing deposit for every room and make batch 1 consume it. Prove
the eight-member aggregate while all rooms are at batch 0. Before publishing
the aggregate, submit room 8's already-proved calldata batch 1 independently.
This makes the unchanged aggregate member genuinely stale without invalidating
the recursive proof.

Publish the original aggregate as one EIP-4844 type-3 transaction containing
the six blobs in member order. Require:

- seven successful `AggregateMemberOutcome` events and one failed outcome for
  room 8;
- seven `BatchAccepted` and seven `DataAvailabilityAccepted` events;
- exactly seven `ProtocolFeeMadeClaimable` events inside the aggregate
  transaction;
- seven state advances and no room-8 state mutation from the aggregate;
- no room-8 fee-snapshot, claimable-balance, escrow, or payer-refund change and
  no second charge caused by the failed member;
- the aggregate transaction itself succeeds and the failure selector is
  retained for the room-8 outcome.

Then queue one new fee-bearing deposit for room 8, prepare/prove continuation
batch 2 from its independently accepted batch 1, and submit it once. Require one
successful batch/DA/fee-finalization event and one state advance. Replaying the
same continuation must fail without another state or charge change. A separate
closed-member isolation transaction may be retained as adversarial evidence,
but a closed room is final and therefore is not the retry case.

The current Docker Foundry regression
`test_recursive_aggregate_applies_seven_and_leaves_one_stale_member_retryable`
pins the same 7+1 state and fee-finalization semantics with the mock verifier;
it is regression evidence, not qualified proof/gas evidence.

## Sponsored hosting, renewal, reorg, and failover

The same fresh deployment must exercise the managed hosting rail with a payer
that is not the room beneficiary. Retain `SponsoredEscrowFunded`, allocation,
price, maximum-charge, payer, beneficiary, and escrow-balance evidence. Drive
one finalized-checkpoint renewal with a fresh price/max-charge quote, then a
failure/refund path. Require the refund to return to the payer, the beneficiary
to receive no payer refund, the checkpoint batch to advance monotonically, and
no repeated checkpoint/restamp/replay to create another allocation or charge.
If capacity moves nodes, retain both deterministic profile transitions and
prove there is no overlapping billing window.

The current owner renewal route records a durable intent; it is not itself a
shared L1 transaction publisher. Physical sponsorship/renewal evidence is
blocked until the owner advertises and passes all of these allowlisted durable
pool operations:

- sponsor reserve-and-start with fixed DA policy, selector `0x827ac259`;
- sponsor renewal from a strictly newer finalized checkpoint, selector
  `0xf180fe5d`;
- finality-oracle checkpoint recording, selector `0xe19bc67e`;
- beneficiary-authorized disposal, selector `0xed97f11a`.

The sender split is protocol-enforced. Reserve and renewal require the scoped
sponsor account and its `SPONSOR_ROLE`; checkpoint publication requires the
finality-oracle account; `disposeRoom` requires `msg.sender` to equal the
allocation beneficiary even though every unused-token refund must return to the
stored payer. Therefore a sponsor signer cannot dispose a genuinely sponsored
allocation. The owner must bind each principal to its exact sender/selector,
derive calldata from immutable capacity/sponsorship/checkpoint projections,
and retain payer, beneficiary, allocation/checkpoint, fresh quote, maximum
charge, calldata hash, permit nonce/value/deadline, and canonical final receipt.
A direct room-node/prover wallet, ad-hoc keystore send, or caller-supplied raw
calldata is forbidden.

Before one managed L1 operation reaches finality, induce a real devnet reorg
that orphans its included block. The owner watcher must reject the orphaned
receipt, reconcile the indexer projection, and recover the same logical
operation under its persisted idempotency/correlation identity. Retain both
branches, provider observations, WAL/nonce state, canonical replacement
receipt, and finalization evidence. Require zero duplicate nonces, charges,
admission ACKs, state advances, refunds, or withdrawal releases. A post-finality
"reorg" simulated only by editing a fixture is not evidence.

During active live preparation/proving/publication, exercise headless restart,
prover restart, and coordinator promotion. Queue authority remains remote
PostgreSQL; large request/result bytes remain content-addressed in MinIO. The
resumed run must keep the same job IDs, result digests, correlation lineage,
owner operation ID, and sealed proof bytes. Production must not start a
standalone/file queue, let the prover agent send L1 transactions directly, or
give it an operations/payout key. Heartbeats use only the scoped owner durable
`node-heartbeats` operation; the coordinator owns nonce, remote signer, and
canonical watcher state.

## Restart-safe 12-hour owner soak

After the focused physical transactions pass, run the stateful 12-hour soak in
`cloud-deployer-infra/runbooks/release-soak.md`. Its immutable manifest must
bind the umbrella source manifest, source archive, `source-closure.json`, fresh
deployment-address manifest, `release-settlement-scenario.json`, final hosted
owner acceptance token, exact pushed images, contract/circuit/zkVM roots, and
the SHA-256 of `generated-trust-root-closure.json`. The schema requires the live
non-fixture `BatchInputV5` path, a real
CUDA Groth16 proof, eight members/six blobs/7+1 outcomes, successful-member-only
charging, sponsorship, withdrawal claim, pre-finality reorg, fresh deployment,
and restart/resume.

The digest-pinned owner runner must continuously execute the full lifecycle and
schedule all eight faults: headless restart, prover restart, coordinator
promotion, indexer rollback, RPC split, object-store restart, database restart,
and Docker-host restart/resume. State and JSONL journal live on durable mounts.
After a host restart, invoke `soak.py run --resume` with the exact same manifest;
the verifier rejects changed sealed outputs, missing recovery assertions,
duplicate nonce/charge, unresolved safety/claim state, or duration below 43,200
seconds. The current repository supplies the validator/resume contract, not a
digest-pinned physical runner or completed soak; those remain mandatory
external prerequisites and must not be claimed from a dry run.

## Real EIP-4844 receipts and gas

The transaction publisher is an owner-managed durable-operation prerequisite.
It must consume the checked ABI and content-addressed prepare/prove/verify/DA
artifacts, validate their shared correlation lineage, derive the aggregate
calldata and `aggregate-blobs.bin`, reserve the nonce, obtain a scoped remote
signature, archive the exact signed network bytes, and watch canonical
finality. It must not accept caller-supplied calldata, seals, KZG fields, or
blob sidecars. The aggregate operation is allowed to broadcast only when the
owner capability advertises the exact `submitAggregate` selector `0x5e8b37ac`
and the focused artifact/type-3 integration gate is green.

`cast` may be used only to inspect the checked ABI or independently encode bytes
for comparison with the owner's archived calldata. For example, inside the
pinned Foundry image:

```text
cast calldata '<canonical-submitAggregate-signature>' '<decoded-owner-input>'
```

`cast send`, `cast publish`, keystore/password arguments, direct RPC broadcast,
and any direct room-node/prover signer are forbidden release paths. Save the
owner operation request/result, archived exact signed transaction, transaction
hash, receipt, block, and a debug trace proving the real Groth16 verifier and
point-evaluation precompile `0x0a` were executed. For each release number report
separately:

- execution `gasUsed` and `effectiveGasPrice`;
- `blobGasUsed`, blob gas price, and total blob fee;
- total transaction fee;
- number/order of blob versioned hashes;
- verifier/precompile call outcome;
- chain ID, block hash/number, contract code hashes, runtime/program ID, and
  input/proof SHA-256 values.

Qualified receipts are required for room creation, room close with a real
proof, calldata single settlement, blob single settlement, six-blob/eight-room
aggregate settlement, and withdrawal claim. The existing mock-overhead test
must retain its `mock-verifier execution overhead` label and exclusions.

## Withdrawal proof and claim

The release withdrawal case requires an owner-reviewed live hosted
`VALIDITY_ONLY` room witness with funded controlled escrow, a real withdrawal
allocation produced by the live engine, a nonzero guest `withdrawalRoot`, and
its positional leaf/proof. The hosted product does not support unanimous mode,
and neither a manufactured approval set nor the generic zero-root storage
template can stand in for this evidence. Preparation must pass through the same
non-fixture `BatchInputV5`/queue/prove/verify lineage described above.

After proving and accepting that batch:

1. compare guest `withdrawal_leaf_v5`/`withdrawal_root_v5` output with L1
   `withdrawalLeaf` and `withdrawalRoot`;
2. require `verifyWithdrawalProof` to return true for the exact leaf/proof;
3. request the owner durable withdrawal operation through
   `/hosting/v1/withdrawals/{roomId}/{epoch}/{withdrawalIndex}/claims`, require
   its allowlisted `claimWithdrawal` selector `0xb051a9f8`, and save its
   finalized canonical receipt/gas and `WithdrawalClaimed` event;
4. require `isWithdrawalClaimed` to become true and liability/vault balances to
   move by the exact amount;
5. replay the same claim and retain the failing receipt/trace showing no second
   release.

The live nonzero withdrawal witness and the owner-managed publisher are
physical prerequisites; do not claim this gate from the zero-root template,
fixture prepare, or the mock-verifier Foundry suite.

## Contract capability and ABI handoff

Infrastructure consumes these current, history-independent files:

- `app-node/packages/room-node/capabilities/room-node.json`;
- `prover-node/agent/liveness-capability.json`;
- `web2-api/server/capabilities/room-batch-hosted-integration-v1.json` plus the
  final owner capability response carrying the same non-self-referential
  acceptance token and its validated write-once
  `owner-durable-capabilities.json` closure;
- `web3-protocol/contracts/contract-capabilities.json`;
- `web3-protocol/contracts/deployments/contract-capabilities.generated.json`;
- `web3-protocol/contracts/deployments/room-manager.abi.json`;
- `web3-protocol/contracts/deployments/room-pool.abi.json`;
- `web3-protocol/contracts/deployments/addresses.json` from the physical
  deployment;
- `prover-node/zkvm/build/risc0/capabilities-v6.json` from the completed CUDA
  closure;
- `prover-node/zkvm/artifacts.lock.json` and
  `prover-node/zkvm/source-manifest.json` from that same closure;
- `cloud-deployer-infra/config/schemas/release-soak-manifest.schema.json` and
  the completed soak manifest/verifier result.

Run the interface generator and check in Docker. The address-aware check must
use the fresh deployment output, not the old local development address file.

```powershell
docker run --rm `
  -v '<repo>\web3-protocol\contracts:/workspace' -w /workspace `
  $NodeImage node script/generate-contract-interfaces.mjs --check

docker run --rm `
  -v '<repo>\web3-protocol\contracts:/workspace' -w /workspace `
  $NodeImage node script/generate-contract-interfaces.mjs --check `
    --addresses deployments/addresses.json

docker run --rm `
  -v "${Source}:/workspace:ro" -v "${Evidence}:/evidence" -w /workspace `
  $NodeImage node zkvm/scripts/build-4090-evidence-requests.mjs `
    owner-capabilities /evidence/owner/capabilities-response.json `
    /evidence/owner/owner-durable-capabilities.json
```

The owner acceptance runner must save the exact raw response from
`GET /hosting/v1/capabilities` as `capabilities-response.json`. The assembler
requires the common durable nonce, exact-byte archive, independent receipt, and
post-finality audit boundary, plus enabled exact-selector entries for room
batch, aggregate, withdrawal claim, sponsor reserve/renew, finalized
checkpoint, and beneficiary disposal. It fails closed while any new owner
operation remains absent or `enabled:false`; a hand-authored capability fixture
is not physical evidence.

The address manifest must contain valid nonzero deployment addresses for the
manager router, all seven core manager facets, `roomHostingFacet`, the room
pool, and `roomPoolHostingFacet`. Infrastructure also verifies router selector
ownership, the pool `HostingFacetConfigured(facet,codeHash)` event/runtime
codehash, ABI SHA-256 values, data-availability/aggregate/withdrawal event
mappings, liveness/operations/payout authority separation, sponsorship payer
refund ownership, and finalized-checkpoint renewal semantics.

The checked-in development address file is not physical evidence if it lacks
any required facet. Deploy fresh, write the complete manifest, hash it, verify
every runtime codehash and selector table, and bind that hash into both the soak
manifest and evidence closure.

## Evidence closure

Create `evidence-closure-plan.json` only after all trust-root, proof,
transaction, event, gas, capability, ABI, address, codehash, GPU, and failure
receipts are final. It contains:

```json
{
  "sourceBundleArchiveSha256": "<umbrella archive 64 lowercase hex>",
  "umbrellaSourceManifestSha256": "<embedded umbrella manifest 64 lowercase hex>",
  "zkvmSourceManifestSha256": "<minted zkVM source manifest 64 lowercase hex>",
  "sourceClosureSha256": "<source-closure.json 64 lowercase hex>",
  "generatedTrustRootClosure": "trust/generated-trust-root-closure.json",
  "generatedTrustRootClosureSha256": "<generated trust-root closure 64 lowercase hex>",
  "ownerAcceptanceToken": "sha256:<final owner acceptance 64 lowercase hex>",
  "ownerDurableCapabilitiesSha256": "<owner-durable-capabilities.json 64 lowercase hex>",
  "settlementScenarioSha256": "<release-settlement-scenario.json 64 lowercase hex>",
  "deploymentAddressesSha256": "<fresh addresses.json 64 lowercase hex>",
  "soakVerificationSha256": "<completed 12-hour soak verifier result 64 lowercase hex>",
  "artifactLockSha256": "<64 lowercase hex>",
  "orchestratorImage": "<repository>@sha256:<64 lowercase hex>",
  "toolchainImage": "<repository>@sha256:<64 lowercase hex>",
  "runtimeImage": "<repository>@sha256:<64 lowercase hex>",
  "programId": "0x<64 hex>",
  "files": ["trust/staged-zkvm-images.json", "trust/generated-trust-root-closure.json", "relative/path/to/every/final/evidence/file"]
}
```

Mint the write-once closure index in Docker:

```powershell
docker run --rm `
  -v "${Source}:/workspace:ro" -v "${Evidence}:/evidence" `
  -w /workspace $OrchestratorRef `
  node zkvm/scripts/build-4090-evidence-requests.mjs evidence-closure `
    /evidence/evidence-closure-plan.json /evidence/evidence-closure.json
```

The v2 index has no timestamp or history identity. It is the final composite
source-and-artifact seal: it binds the umbrella archive, embedded umbrella
manifest, zkVM submanifest, source closure, generated-trust-root closure,
artifact lock, pushed runtime, program ID, and sorted SHA-256 and size of every
final evidence file. The assembler rejects any disagreement between the
generated closure and the supplied zkVM manifest, artifact lock, runtime, or
program ID, and separately requires the exact orchestrator and toolchain refs.
The file list must include the staging receipt, generated closure, scenario, all eight hosted
lineages, owner acceptance token/capability capture, fresh addresses/codehashes,
soak manifest/state/journal/verifier result, proof/transaction/gas outputs, and
all failure/recovery receipts. Copy the complete evidence directory to
write-once storage and independently re-hash it before signing the release
decision.

Run `trust-root-check` again against the now read-only source tree immediately
before signing or promoting images and once more after copying the evidence
closure to object-locked storage. Only then may the exact staged
`$OrchestratorRef`, `$ToolchainRef`, and `$RuntimeRef` digests be promoted or
signed. Promotion changes metadata only; rebuilding an image or rewriting the
lock, minted manifest, generated closure, or any locked artifact starts a new
candidate.

## Stop conditions

Do not issue a release claim if any of these remains true:

- the two CUDA builds or any of the four artifact hashes differ;
- the umbrella archive/outer/embedded/entries/source-closure hashes disagree,
  any required project/critical binding is absent, or the transferred zkVM
  candidate manifest was regenerated after sealing;
- the runtime label, lock, source manifest, capability program ID, or image
  digest disagree;
- `generated-trust-root-closure.json` is absent, differs on read-only recheck,
  is missing from the final evidence file list, or any source/lock/artifact/image
  byte changed after the composite seal;
- a staged image was rebuilt or promoted under a digest other than the exact
  toolchain/runtime/orchestrator input recorded before the two-build closure;
- any first-party executable path can invoke a repository-history client;
- any physical L1 mutation bypasses an enabled owner durable-operation
  capability, or uses `cast send`, a direct RPC sender, an ad-hoc keystore, or
  caller-supplied raw calldata/blob sidecars;
- the six blob ranges are not exactly contiguous `0..5`, or transaction blobs
  differ from the c-kzg bundle;
- any room proof was prepared from the fixture builder rather than a canonical
  live engine artifact and owner proving context, or prepare/prove/verify job
  bytes and result digests lack one correlation lineage;
- aggregate evidence lacks one real recursive receipt, 7+1 independent member
  outcomes, failed-member isolation, successful-member-only fee finalization,
  and the successful continuation retry;
- gas evidence uses a mock verifier/precompile or omits blob gas/fees;
- withdrawal evidence has a zero/fabricated root or lacks the real claim and
  replay receipt;
- sponsorship lacks a distinct payer/beneficiary and payer-owned refund, or a
  renewal/checkpoint replay causes overlapping billing or another charge;
- reorg/failover evidence lacks canonical recovery under stable durable IDs,
  or production used a standalone/file queue or direct agent L1 sender;
- the fresh deployment address manifest or either hosting facet/codehash is
  missing;
- the final hosted owner acceptance token/runner digest is absent, or the
  12-hour soak is short, non-resumable, missing a scheduled fault/recovery, or
  reports any duplicate nonce/charge or unresolved safety/claim state;
- any final evidence file was replaced rather than created write-once.
