//! Prover capability and readiness reports.
//!
//! Both reports are derived from the compiled feature set and the live driver,
//! never from configuration, so a degraded image cannot claim to be production.

use anyhow::Result;

use crate::gpu::{cuda_version, driver_version, enforce_production_gpu, gpu_name, gpu_uuid};
use crate::receipt::image_id_hex;
use crate::v5_fixture::room_capabilities;

const RISC0_VERSION: &str = "3.0.6";

pub(crate) fn cmd_capabilities() -> serde_json::Value {
    let image_id = image_id_hex();
    serde_json::json!({
        "protocolVersion": 6,
        "protocolVersions": [6],
        "evmFork": "osaka",
        "imageId": image_id.clone(),
        "programId": format!("0x{image_id}"),
        "backendId": "risc0",
        "cudaCompiled": cfg!(feature = "cuda"),
        "cuda": cfg!(feature = "cuda"),
        "productionCompiled": cfg!(feature = "production"),
        "cpuFallback": !cfg!(feature = "production") && !cfg!(feature = "client-verifier"),
        "clientVerifierOnly": cfg!(feature = "client-verifier"),
        "provingAvailable": !cfg!(feature = "client-verifier"),
        "executionAvailable": true,
        "verificationAvailable": true,
        "gpuUuid": gpu_uuid(),
        "gpuName": gpu_name(),
        "driverVersion": driver_version(),
        "cudaVersion": cuda_version(),
        "risc0Version": RISC0_VERSION,
        "containerDigest": std::env::var("ZKDEAL_CONTAINER_DIGEST").ok(),
        "proofModes": ["succinct", "groth16"],
        "ethereumSeal": true,
        "coldTemplateProof": true,
        "liveRoomBatchPrepare": {
            "available": true,
            "schemaVersion": 1,
            "route": "/hosting/v1/rooms/prepare-batch",
            "cliCommand": "prepare-live-room-batch",
            "fixture": false,
            "requiresAuthentication": true,
            "production": true,
            "authorizationModes": ["VALIDITY_ONLY"],
            "derivesCurrentJournal": true,
            "nativeStfValidation": true,
            "prepareArtifactDigestEncoding": "lowercase-sha256-hex-no-prefix",
            "proofRequestInputDigestEncoding": "0x-prefixed-sha256",
            "returns": [
                "roomWitnessB64",
                "prepareArtifactDigest",
                "proverJobIdentity",
                "journalHash",
                "provisionalSubmission"
            ]
        },
        "receiptComposition": "risc0-assumption-v1",
        "dataAvailabilityEquivalence": {
            "available": true,
            "statementDomain": "zkdeal.data-availability.eip4844.v1",
            "challengeDomain": "zkdeal.blob-equivalence.challenge.v1",
            "encoding": "31-byte-big-endian-field-elements-v1",
            "maxBlobs": stf_types::MAX_BLOBS_PER_BATCH_V1,
            "canonicalBytesPerBlob": stf_types::CANONICAL_BYTES_PER_BLOB_V1,
            "opening": "transcript-derived-evaluation-form-barycentric-v1",
            "versionedHash": "sha256-kzg-commitment-0x01",
            "bundleBuilder": "c-kzg-2.1.8",
            "preparesCompleteContractManifest": true,
            "manifestBlobStartIndex": true,
            "aggregateBlobLayout": "contiguous-member-order-exact-transaction-v1",
            "maxTransactionBlobs": stf_types::MAX_BLOBS_PER_BATCH_V1,
            "commitmentBytes": 48,
            "proofBytes": 48,
            "pointEvaluationInputBytes": 192,
            "pointEvaluationPrecompile": "0x0a",
            "routes": {
                "prepare": "/v5/data-availability/prepare",
                "execute": "/v5/data-availability/execute",
                "prove": "/v5/data-availability/prove",
                "verify": "/v5/data-availability/verify",
            },
        },
        "recursiveAggregate": {
            "available": true,
            "statementDomain": "zkdeal.recursive-aggregate.v1",
            "maxRooms": stf_types::MAX_AGGREGATE_ROOMS_V1,
            "distinctRoomsRequired": true,
            "roomReceiptRequired": true,
            "blobEquivalenceReceiptRequiredForBlobMembers": true,
            "blobRangesBoundByMemberStatement": true,
            "composition": "risc0-assumption-v1",
            "routes": {
                "execute": "/v5/aggregates/execute",
                "prove": "/v5/aggregates/prove",
                "verify": "/v5/aggregates/verify",
            },
        },
        "withdrawalCommitment": {
            "available": true,
            "leaf": "abi(deploymentDomain,roomId,outboxEpoch,index,approverEpoch,recipient,asset,amount)",
            "tree": "positional-keccak-v1",
            "proofParityApi": "stf_types::withdrawal_leaf_v5/withdrawal_root_v5",
        },
        "preparedStateRefresh": "authenticated-envelope-v1",
        "maxBatchBlocks": stf_types::MAX_BATCH_BLOCKS_V4,
        "settlementDerivation": "guest-exit-program-v1",
        "genesisAnchor": "header-rlp-v1",
        "inboxApplication": "guest-inbox-v1",
        "compactStateModel": "full-room-state-v1",
        // Room shapes this binary's fixture can actually prepare. Every token
        // is proved by running this binary's own request parser against the
        // canonical request that capability implies, so a degraded image
        // reports a shorter list rather than a claim it cannot honour.
        "roomCapabilities": room_capabilities(),
    })
}

pub(crate) fn cmd_health() -> Result<serde_json::Value> {
    let request = serde_json::json!({ "production": true });
    let gpu = enforce_production_gpu(&request)?;
    Ok(serde_json::json!({
        "status": "ready",
        "imageId": image_id_hex(),
        "programId": format!("0x{}", image_id_hex()),
        "gpuUuid": gpu,
        "gpuName": gpu_name(),
        "driverVersion": driver_version(),
        "cudaVersion": cuda_version(),
        "containerDigest": std::env::var("ZKDEAL_CONTAINER_DIGEST").ok(),
        "protocolVersion": 6,
        "protocolVersions": [6],
        "evmFork": "osaka",
        "cpuFallback": false,
        "risc0Version": RISC0_VERSION,
        "prover": "risc0-local-cuda",
        "settlementDerivation": "guest-exit-program-v1",
        "genesisAnchor": "header-rlp-v1",
        "inboxApplication": "guest-inbox-v1",
        "compactStateModel": "full-room-state-v1",
    }))
}
