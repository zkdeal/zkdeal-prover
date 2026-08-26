//! EIP-4844 equivalence and recursive multi-room receipt commands.
//!
//! Both proof paths use the embedded STF guest. The aggregate path adds every
//! independently verified room/equivalence receipt as an official RISC Zero
//! assumption; the guest resolves those exact image+journal claims and emits
//! the Solidity aggregate statement as its sole 32-byte journal.

use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use c_kzg::{ethereum_kzg_settings, Blob, Bytes32 as KzgBytes32};
use r0_methods::{STF_GUEST_ELF, STF_GUEST_ID};
use risc0_zkvm::{sha::Digest, InnerReceipt, ProverOpts, Receipt};
use stf_types::{
    blob_equivalence_challenge_v1, blob_equivalence_evaluation_v1, blob_versioned_hash_v1,
    canonical_blob_bytes_v1, validate_aggregate_v1, validate_blob_equivalence_v1, AggregateInputV1,
    BlobEquivalenceInputV1, CANONICAL_BYTES_PER_BLOB_V1, MAX_BLOBS_PER_BATCH_V1,
};

use crate::gpu::{enforce_production_gpu, production_requested, GpuTelemetrySampler};
use crate::receipt::{
    build_env, build_env_with_assumptions, compress_groth16_with_verified_identity,
    compress_receipt, encode_ethereum_seal, image_id_hex, persistent_prover,
    require_committed_journal_hash,
};
use crate::B64;

const BLOB_EQUIVALENCE_MAGIC_V1: &[u8; 8] = b"ZKDBEQV1";
const RECURSIVE_AGGREGATE_MAGIC_V1: &[u8; 8] = b"ZKDAGGV1";

fn request_json(raw: &str) -> Result<serde_json::Value> {
    serde_json::from_str(raw).context("stdin is not JSON")
}

fn equivalence_input(request: &serde_json::Value) -> Result<BlobEquivalenceInputV1> {
    serde_json::from_value(
        request
            .get("equivalenceWitness")
            .cloned()
            .context("equivalenceWitness is required")?,
    )
    .context("equivalenceWitness decode")
}

fn aggregate_input(request: &serde_json::Value) -> Result<AggregateInputV1> {
    serde_json::from_value(
        request
            .get("aggregateWitness")
            .cloned()
            .context("aggregateWitness is required")?,
    )
    .context("aggregateWitness decode")
}

#[derive(Debug)]
struct PreparedDataAvailabilityV1 {
    input: BlobEquivalenceInputV1,
    statement: alloy_primitives::B256,
    blobs: Vec<Vec<u8>>,
    kzg_proofs: Vec<alloy_primitives::Bytes>,
}

impl PreparedDataAvailabilityV1 {
    fn manifest(&self, equivalence_seal: &str) -> serde_json::Value {
        serde_json::json!({
            "canonicalDataHash": format!(
                "0x{}",
                hex::encode(alloy_primitives::keccak256(self.input.canonical_data.as_ref()))
            ),
            "canonicalDataLength": self.input.canonical_data.len(),
            "blobStartIndex": self.input.blob_start_index,
            "blobVersionedHashes": self.input.blob_versioned_hashes,
            "commitments": self.input.commitments,
            "evaluationPoints": self.input.evaluation_points,
            "evaluations": self.input.evaluations,
            "kzgProofs": self.kzg_proofs,
            "equivalenceSeal": equivalence_seal,
            "fallbackDeadlineBlock": 0,
            "fallbackSignature": "0x",
        })
    }
}

fn require_empty_or_equal<T: PartialEq>(
    field: &str,
    supplied: &[T],
    derived: &[T],
) -> Result<()> {
    if !supplied.is_empty() && supplied != derived {
        bail!("equivalenceWitness.{field} does not match the canonical blob bundle");
    }
    Ok(())
}

/// Build the complete KZG publication bundle from canonical bytes. Caller
/// fields may be omitted; if present they are assertions and never trusted or
/// silently overwritten.
fn prepare_data_availability_bundle_v1(
    request: &serde_json::Value,
) -> Result<PreparedDataAvailabilityV1> {
    // c-kzg's Blob is a 128 KiB value and its native proof routine uses
    // sizeable stack frames. HTTP runtimes and Rust test workers commonly
    // provide only 2 MiB, so use an explicit bounded worker stack instead of
    // making correctness depend on the caller thread's stack configuration.
    let owned = request.clone();
    std::thread::Builder::new()
        .name("zkdeal-kzg-bundle".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || prepare_data_availability_bundle_inner_v1(&owned))
        .context("spawn KZG bundle worker")?
        .join()
        .map_err(|_| anyhow!("KZG bundle worker panicked"))?
}

fn prepare_data_availability_bundle_inner_v1(
    request: &serde_json::Value,
) -> Result<PreparedDataAvailabilityV1> {
    let supplied = equivalence_input(request)?;
    if supplied.canonical_data.is_empty() {
        bail!("equivalenceWitness.canonicalData must not be empty");
    }
    let blob_count = supplied
        .canonical_data
        .len()
        .div_ceil(CANONICAL_BYTES_PER_BLOB_V1);
    if blob_count == 0 || blob_count > MAX_BLOBS_PER_BATCH_V1 {
        bail!("canonical data requires {blob_count} blobs; supported range is 1..={MAX_BLOBS_PER_BATCH_V1}");
    }

    let blob_bytes = (0..blob_count)
        .map(|index| canonical_blob_bytes_v1(supplied.canonical_data.as_ref(), index))
        .collect::<Vec<_>>();
    let blobs = blob_bytes
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            Blob::from_bytes(bytes)
                .map_err(|error| anyhow!("canonical blob {index} decode: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let settings = ethereum_kzg_settings(0);
    let kzg_commitments = blobs
        .iter()
        .enumerate()
        .map(|(index, blob)| {
            settings
                .blob_to_kzg_commitment(blob)
                .map_err(|error| anyhow!("canonical blob {index} commitment: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let commitments = kzg_commitments
        .iter()
        .map(|commitment| {
            alloy_primitives::Bytes::copy_from_slice(commitment.to_bytes().as_ref())
        })
        .collect::<Vec<_>>();
    let versioned_hashes = commitments
        .iter()
        .map(|commitment| blob_versioned_hash_v1(commitment.as_ref()))
        .collect::<Vec<_>>();
    require_empty_or_equal("commitments", &supplied.commitments, &commitments)?;
    require_empty_or_equal(
        "blobVersionedHashes",
        &supplied.blob_versioned_hashes,
        &versioned_hashes,
    )?;

    let mut input = BlobEquivalenceInputV1 {
        commitments,
        blob_versioned_hashes: versioned_hashes,
        evaluation_points: vec![alloy_primitives::B256::ZERO; blob_count],
        evaluations: vec![alloy_primitives::B256::ZERO; blob_count],
        ..supplied.clone()
    };
    for index in 0..blob_count {
        input.evaluation_points[index] = blob_equivalence_challenge_v1(&input, index)
            .with_context(|| format!("derive canonical blob {index} evaluation point"))?;
    }
    require_empty_or_equal(
        "evaluationPoints",
        &supplied.evaluation_points,
        &input.evaluation_points,
    )?;

    let mut kzg_proofs = Vec::with_capacity(blob_count);
    for index in 0..blob_count {
        let z = KzgBytes32::new(input.evaluation_points[index].0);
        let (proof, c_kzg_y) = settings
            .compute_kzg_proof(&blobs[index], &z)
            .map_err(|error| anyhow!("canonical blob {index} KZG opening: {error}"))?;
        let derived_y = blob_equivalence_evaluation_v1(&input, index)
            .map_err(|error| anyhow!("canonical blob {index} evaluation: {error}"))?;
        if derived_y.as_slice() != c_kzg_y.as_ref() {
            bail!("canonical blob {index} evaluation disagrees with c-kzg");
        }
        if !settings
            .verify_kzg_proof(
                &kzg_commitments[index].to_bytes(),
                &z,
                &c_kzg_y,
                &proof.to_bytes(),
            )
            .map_err(|error| anyhow!("canonical blob {index} KZG verification: {error}"))?
        {
            bail!("canonical blob {index} generated an invalid KZG proof");
        }
        input.evaluations[index] = derived_y;
        kzg_proofs.push(alloy_primitives::Bytes::copy_from_slice(
            proof.to_bytes().as_ref(),
        ));
    }
    require_empty_or_equal("evaluations", &supplied.evaluations, &input.evaluations)?;

    let statement = validate_blob_equivalence_v1(&input)
        .map_err(|error| anyhow!("blob-equivalence witness invalid: {error}"))?;
    let prepared = PreparedDataAvailabilityV1 {
        input,
        statement,
        blobs: blob_bytes,
        kzg_proofs,
    };
    if let Some(asserted) = request.get("dataAvailabilityManifest") {
        let expected = prepared.manifest("0x");
        for field in [
            "canonicalDataHash",
            "canonicalDataLength",
            "blobStartIndex",
            "blobVersionedHashes",
            "commitments",
            "evaluationPoints",
            "evaluations",
            "kzgProofs",
        ] {
            if let Some(value) = asserted.get(field) {
                if value != &expected[field] {
                    bail!("dataAvailabilityManifest.{field} does not match the canonical blob bundle");
                }
            }
        }
    }
    Ok(prepared)
}

fn framed<T: serde::Serialize>(magic: &[u8; 8], value: &T) -> Result<Vec<u8>> {
    let encoded = bincode::serialize(value).context("serialize hosting witness")?;
    let mut bytes = Vec::with_capacity(magic.len() + encoded.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn proof_mode(request: &serde_json::Value) -> Result<&str> {
    let mode = request
        .get("proofMode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("groth16");
    if !matches!(mode, "succinct" | "groth16") {
        bail!("unsupported proofMode '{mode}' (succinct|groth16)");
    }
    Ok(mode)
}

fn decode_receipt(value: &serde_json::Value, field: &str) -> Result<Receipt> {
    let encoded = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("{field} is required"))?;
    let bytes = B64
        .decode(encoded)
        .with_context(|| format!("{field} is not valid base64"))?;
    let receipt: Receipt = bincode::deserialize(&bytes)
        .with_context(|| format!("{field} receipt decode"))?;
    if matches!(receipt.inner, InnerReceipt::Fake(_)) {
        bail!("{field} is a development receipt");
    }
    Ok(receipt)
}

fn verify_claim(receipt: &Receipt, program_id: alloy_primitives::B256, statement: alloy_primitives::B256) -> Result<()> {
    let image_id = Digest::try_from(program_id.as_slice())
        .context("receipt program id must be a 32-byte RISC Zero digest")?;
    receipt
        .verify(image_id)
        .context("member receipt verification failed")?;
    require_committed_journal_hash(&receipt.journal.bytes, statement.0)
}

fn aggregate_assumptions(
    request: &serde_json::Value,
    input: &AggregateInputV1,
) -> Result<Vec<Receipt>> {
    let receipt_values = request
        .get("memberReceipts")
        .and_then(serde_json::Value::as_array)
        .context("memberReceipts is required")?;
    if receipt_values.len() != input.members.len() {
        bail!("memberReceipts length must equal aggregateWitness.members length");
    }
    let mut assumptions = Vec::with_capacity(input.members.len() * 2);
    for (index, (member, value)) in input.members.iter().zip(receipt_values).enumerate() {
        let room = decode_receipt(value, "roomReceiptB64")
            .with_context(|| format!("member {index} room receipt"))?;
        verify_claim(&room, member.room_program_id, member.journal_hash)
            .with_context(|| format!("member {index} room claim"))?;
        assumptions.push(room);
        if member.equivalence_program_id != alloy_primitives::B256::ZERO {
            let equivalence = decode_receipt(value, "equivalenceReceiptB64")
                .with_context(|| format!("member {index} equivalence receipt"))?;
            verify_claim(
                &equivalence,
                member.equivalence_program_id,
                member.equivalence_statement,
            )
            .with_context(|| format!("member {index} equivalence claim"))?;
            assumptions.push(equivalence);
        } else if value.get("equivalenceReceiptB64").is_some() {
            bail!("member {index} is calldata-backed and must not include an equivalence receipt");
        }
    }
    Ok(assumptions)
}

fn prove_statement(
    request: &serde_json::Value,
    witness: &[u8],
    assumptions: Vec<Receipt>,
    expected_statement: alloy_primitives::B256,
    kind: &str,
) -> Result<serde_json::Value> {
    let pipeline_started = Instant::now();
    let gpu = enforce_production_gpu(request)?;
    let production = production_requested(request);
    let mode = proof_mode(request)?;
    let env = if assumptions.is_empty() {
        build_env(witness)?
    } else {
        build_env_with_assumptions(witness, assumptions)?
    };
    let prover = persistent_prover();
    let telemetry = GpuTelemetrySampler::start(production)?;
    let proving_started = Instant::now();
    let info = prover.prove_with_opts(env, STF_GUEST_ELF, &ProverOpts::composite())?;
    let prove_ms = proving_started.elapsed().as_secs_f64() * 1000.0;
    let stats = info.stats;
    info.receipt
        .verify(STF_GUEST_ID)
        .with_context(|| format!("{kind} composite receipt self-verification failed"))?;
    let recursion_started = Instant::now();
    let succinct = compress_receipt(prover.as_ref(), &ProverOpts::succinct(), &info.receipt)?;
    let recursion_ms = recursion_started.elapsed().as_secs_f64() * 1000.0;
    succinct
        .verify(STF_GUEST_ID)
        .with_context(|| format!("{kind} succinct receipt self-verification failed"))?;
    let (receipt, identity_ms, wrapper_ms) = if mode == "groth16" {
        compress_groth16_with_verified_identity(&succinct)?
    } else {
        (succinct, 0.0, 0.0)
    };
    receipt
        .verify(STF_GUEST_ID)
        .with_context(|| format!("{kind} receipt self-verification failed"))?;
    require_committed_journal_hash(&receipt.journal.bytes, expected_statement.0)?;
    let ethereum_seal = if mode == "groth16" {
        Some(encode_ethereum_seal(&receipt).context("encode Ethereum verifier seal")?)
    } else {
        None
    };
    let receipt_bytes = bincode::serialize(&receipt).context("encode receipt")?;
    let gpu_telemetry = telemetry.finish()?;
    Ok(serde_json::json!({
        "kind": kind,
        "statement": format!("0x{}", hex::encode(expected_statement)),
        "receiptB64": B64.encode(&receipt_bytes),
        "ethereumSealB64": ethereum_seal.as_ref().map(|seal| B64.encode(seal)),
        "ethereumSealHex": ethereum_seal.as_ref().map(|seal| format!("0x{}", hex::encode(seal))),
        "proofMode": mode,
        "programId": format!("0x{}", image_id_hex()),
        "imageId": image_id_hex(),
        "cycles": stats.user_cycles,
        "totalCycles": stats.total_cycles,
        "segments": stats.segments,
        "receiptBytes": receipt_bytes.len(),
        "sealBytes": ethereum_seal.as_ref().map_or(0, |seal| seal.len()),
        "profile": {
            "compositeProofMs": prove_ms,
            "succinctCompressionMs": recursion_ms,
            "identityP254Ms": identity_ms,
            "groth16WrapperMs": wrapper_ms,
            "totalPipelineMs": pipeline_started.elapsed().as_secs_f64() * 1000.0,
        },
        "gpuUuid": gpu,
        "gpuName": gpu_telemetry.gpu_name,
        "utilizationSamplesPercent": gpu_telemetry.utilization_percent,
        "vramSamplesMiB": gpu_telemetry.vram_mib,
        "powerSamplesW": gpu_telemetry.power_w,
        "containerDigest": std::env::var("ZKDEAL_CONTAINER_DIGEST").ok(),
    }))
}

pub(crate) fn cmd_prepare_data_availability_v1(raw: &str) -> Result<serde_json::Value> {
    let request = request_json(raw)?;
    let prepared = prepare_data_availability_bundle_v1(&request)?;
    Ok(serde_json::json!({
        "equivalenceWitness": &prepared.input,
        "statement": format!("0x{}", hex::encode(prepared.statement)),
        "dataAvailabilityManifest": prepared.manifest("0x"),
        "blobsB64": prepared.blobs.iter().map(|blob| B64.encode(blob)).collect::<Vec<_>>(),
        "encoding": "31-byte-big-endian-field-elements-v1",
        "pointEvaluationInputBytes": 192,
        "pointEvaluationPrecompile": "0x0a",
    }))
}

pub(crate) fn cmd_execute_data_availability_v1(raw: &str) -> Result<serde_json::Value> {
    let request = request_json(raw)?;
    let prepared = prepare_data_availability_bundle_v1(&request)?;
    Ok(serde_json::json!({
        "ok": true,
        "statement": format!("0x{}", hex::encode(prepared.statement)),
        "programId": format!("0x{}", image_id_hex()),
        "blobCount": prepared.input.blob_versioned_hashes.len(),
        "canonicalDataLength": prepared.input.canonical_data.len(),
        "dataAvailabilityManifest": prepared.manifest("0x"),
    }))
}

pub(crate) fn cmd_prove_data_availability_v1(raw: &str) -> Result<serde_json::Value> {
    let request = request_json(raw)?;
    let prepared = prepare_data_availability_bundle_v1(&request)?;
    let witness = framed(BLOB_EQUIVALENCE_MAGIC_V1, &prepared.input)?;
    let mut result = prove_statement(
        &request,
        &witness,
        Vec::new(),
        prepared.statement,
        "data-availability-equivalence",
    )?;
    let seal = result
        .get("ethereumSealHex")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("0x")
        .to_owned();
    result["equivalenceWitness"] = serde_json::to_value(&prepared.input)?;
    result["dataAvailabilityManifest"] = prepared.manifest(&seal);
    result["blobsB64"] = serde_json::json!(
        prepared.blobs.iter().map(|blob| B64.encode(blob)).collect::<Vec<_>>()
    );
    Ok(result)
}

pub(crate) fn cmd_verify_data_availability_v1(raw: &str) -> Result<serde_json::Value> {
    let request = request_json(raw)?;
    let prepared = prepare_data_availability_bundle_v1(&request)?;
    let receipt = decode_receipt(&request, "receiptB64")?;
    verify_claim(
        &receipt,
        alloy_primitives::B256::from_slice(Digest::new(STF_GUEST_ID).as_bytes()),
        prepared.statement,
    )?;
    Ok(serde_json::json!({
        "ok": true,
        "statement": format!("0x{}", hex::encode(prepared.statement)),
        "programId": format!("0x{}", image_id_hex()),
        "dataAvailabilityManifest": prepared.manifest("0x"),
    }))
}

pub(crate) fn cmd_execute_aggregate_v1(raw: &str) -> Result<serde_json::Value> {
    let request = request_json(raw)?;
    let input = aggregate_input(&request)?;
    let statement = validate_aggregate_v1(&input)
        .map_err(|error| anyhow!("aggregate witness invalid: {error}"))?;
    let assumptions = aggregate_assumptions(&request, &input)?;
    Ok(serde_json::json!({
        "ok": true,
        "statement": format!("0x{}", hex::encode(statement)),
        "programId": format!("0x{}", image_id_hex()),
        "memberCount": input.members.len(),
        "assumptionCount": assumptions.len(),
    }))
}

pub(crate) fn cmd_prove_aggregate_v1(raw: &str) -> Result<serde_json::Value> {
    let request = request_json(raw)?;
    let input = aggregate_input(&request)?;
    let statement = validate_aggregate_v1(&input)
        .map_err(|error| anyhow!("aggregate witness invalid: {error}"))?;
    let assumptions = aggregate_assumptions(&request, &input)?;
    let witness = framed(RECURSIVE_AGGREGATE_MAGIC_V1, &input)?;
    let mut result =
        prove_statement(&request, &witness, assumptions, statement, "recursive-room-aggregate")?;
    // Keep the exact public statement input alongside the receipt so the
    // independent verify command and L1 publisher never have to reconstruct it
    // from transient member files.
    result["aggregateWitness"] = serde_json::to_value(&input)?;
    result["memberCount"] = serde_json::json!(input.members.len());
    Ok(result)
}

pub(crate) fn cmd_verify_aggregate_v1(raw: &str) -> Result<serde_json::Value> {
    let request = request_json(raw)?;
    let input = aggregate_input(&request)?;
    let statement = validate_aggregate_v1(&input)
        .map_err(|error| anyhow!("aggregate witness invalid: {error}"))?;
    let receipt = decode_receipt(&request, "receiptB64")?;
    verify_claim(
        &receipt,
        alloy_primitives::B256::from_slice(Digest::new(STF_GUEST_ID).as_bytes()),
        statement,
    )?;
    Ok(serde_json::json!({
        "ok": true,
        "statement": format!("0x{}", hex::encode(statement)),
        "programId": format!("0x{}", image_id_hex()),
        "memberCount": input.members.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stf_types::AggregateMemberStatementV1;

    fn minimal_equivalence_request() -> serde_json::Value {
        serde_json::json!({
            "equivalenceWitness": {
                "deploymentDomain": format!("0x{}", "11".repeat(32)),
                "roomId": 7,
                "journalHash": format!("0x{}", "22".repeat(32)),
                "canonicalData": "0x0102030405",
                "blobStartIndex": 2
            }
        })
    }

    #[test]
    fn prepare_builds_a_complete_contract_manifest_and_rejects_bundle_drift() {
        let prepared = cmd_prepare_data_availability_v1(
            &minimal_equivalence_request().to_string(),
        )
        .unwrap();
        let manifest = &prepared["dataAvailabilityManifest"];
        let keys = manifest.as_object().unwrap().keys().cloned().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            [
                "blobVersionedHashes",
                "blobStartIndex",
                "canonicalDataHash",
                "canonicalDataLength",
                "commitments",
                "equivalenceSeal",
                "evaluationPoints",
                "evaluations",
                "fallbackDeadlineBlock",
                "fallbackSignature",
                "kzgProofs",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_eq!(manifest["canonicalDataLength"], 5);
        assert_eq!(manifest["blobStartIndex"], 2);
        assert_eq!(manifest["blobVersionedHashes"].as_array().unwrap().len(), 1);
        assert_eq!(manifest["commitments"][0].as_str().unwrap().len(), 98);
        assert_eq!(manifest["kzgProofs"][0].as_str().unwrap().len(), 98);
        assert_eq!(manifest["evaluationPoints"][0].as_str().unwrap().len(), 66);
        assert_eq!(manifest["evaluations"][0].as_str().unwrap().len(), 66);
        let blob = B64.decode(prepared["blobsB64"][0].as_str().unwrap()).unwrap();
        assert_eq!(blob.len(), 4096 * 32);

        let mut commitment_drift = prepared.clone();
        commitment_drift["equivalenceWitness"]["commitments"][0] =
            serde_json::Value::String(format!("0x{}", "00".repeat(48)));
        assert!(cmd_prepare_data_availability_v1(&commitment_drift.to_string())
            .unwrap_err()
            .to_string()
            .contains("commitments"));

        let mut proof_drift = prepared;
        proof_drift["dataAvailabilityManifest"]["kzgProofs"][0] =
            serde_json::Value::String(format!("0x{}", "00".repeat(48)));
        assert!(cmd_prepare_data_availability_v1(&proof_drift.to_string())
            .unwrap_err()
            .to_string()
            .contains("kzgProofs"));
    }

    #[test]
    fn aggregate_request_rejects_receipt_count_drift_before_proving() {
        let input = AggregateInputV1 {
            deployment_domain: alloy_primitives::B256::repeat_byte(0x11),
            members: vec![AggregateMemberStatementV1 {
                room_id: 1,
                room_program_id: alloy_primitives::B256::repeat_byte(0x22),
                journal_hash: alloy_primitives::B256::repeat_byte(0x33),
                equivalence_program_id: alloy_primitives::B256::ZERO,
                equivalence_statement: alloy_primitives::B256::ZERO,
            }],
        };
        let request = serde_json::json!({
            "aggregateWitness": input,
            "memberReceipts": [],
        });
        assert!(aggregate_assumptions(&request, &input)
            .unwrap_err()
            .to_string()
            .contains("length"));
        assert_eq!(
            stf_types::aggregate_statement_v1(&input),
            validate_aggregate_v1(&input).unwrap()
        );
    }
}
