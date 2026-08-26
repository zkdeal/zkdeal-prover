//! v5 room and cold-template commands: execute, prove, verify and prepare.
//!
//! Every command re-executes the statement natively before it proves or
//! accepts anything, and binds the guest journal to that native result.

use std::time::Instant;

use alloy_primitives::keccak256;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use r0_methods::{STF_GUEST_ELF, STF_GUEST_ID};
use risc0_zkvm::{sha::Digest, ProverOpts, Receipt};
use stf_types::{
    cold_template_statement_v6, hash_batch_journal_v5, BatchJournalV5, ColdTemplateInputV5,
};

use crate::witness::cold_template_input_bytes_v5;

use crate::gpu::{enforce_production_gpu, production_requested, GpuTelemetrySampler};
use crate::receipt::{
    build_env, compress_groth16_with_verified_identity, compress_receipt, encode_ethereum_seal,
    image_id_hex, persistent_prover, require_committed_journal_hash,
};
use crate::report::proof_work_json_v5;
use crate::witness::{cold_template_witness_from_stdin, room_witness_from_stdin};
use crate::{v5_fixture, B64};

pub(crate) fn cmd_execute_room_v5(raw: &str) -> Result<serde_json::Value> {
    let (input, _request, _witness, address) = room_witness_from_stdin(raw)?;
    let started = Instant::now();
    let outcome = stf_core::execute_batch_v5_with_report(&input)
        .map_err(|error| anyhow!("native v5 room execution failed: {error}"))?;
    let journal = outcome.journal;
    let journal_hash = hash_batch_journal_v5(&journal);
    Ok(serde_json::json!({
        "journal": journal,
        "journalHash": format!("0x{}", hex::encode(journal_hash)),
        "jobId": address.job_id,
        "inputDigest": address.input_digest,
        "backendId": "risc0",
        "programId": format!("0x{}", image_id_hex()),
        "proofMode": address.proof_mode,
        "executeMs": started.elapsed().as_secs_f64() * 1000.0,
        "proofWork": proof_work_json_v5(&outcome.proof_work, None, None),
    }))
}

pub(crate) fn cmd_prove_room_v5(raw: &str) -> Result<serde_json::Value> {
    let pipeline_started = Instant::now();
    let (input, request, witness, address) = room_witness_from_stdin(raw)?;
    let gpu = enforce_production_gpu(&request)?;
    let production = production_requested(&request);
    let execution_started = Instant::now();
    let native_outcome = stf_core::execute_batch_v5_with_report(&input)
        .map_err(|error| anyhow!("native v5 room execution failed: {error}"))?;
    let journal = native_outcome.journal;
    let execute_ms = execution_started.elapsed().as_secs_f64() * 1000.0;
    let journal_hash = hash_batch_journal_v5(&journal).0;
    let environment_started = Instant::now();
    let env = build_env(&witness)?;
    let environment_ms = environment_started.elapsed().as_secs_f64() * 1000.0;
    if !matches!(address.proof_mode.as_str(), "succinct" | "groth16") {
        bail!(
            "unsupported proofMode '{}' (succinct|groth16)",
            address.proof_mode
        );
    }
    let prover_started = Instant::now();
    let prover = persistent_prover();
    let prover_initialization_ms = prover_started.elapsed().as_secs_f64() * 1000.0;
    let telemetry_sampler = GpuTelemetrySampler::start(production)?;
    let proving_started = Instant::now();
    let info = prover.prove_with_opts(env, STF_GUEST_ELF, &ProverOpts::composite())?;
    let prove_ms = proving_started.elapsed().as_secs_f64() * 1000.0;
    let stats = info.stats;
    info.receipt
        .verify(STF_GUEST_ID)
        .context("v5 room composite proof self-verification failed")?;
    let recursion_started = Instant::now();
    let succinct_receipt =
        compress_receipt(prover.as_ref(), &ProverOpts::succinct(), &info.receipt)?;
    let recursion_ms = recursion_started.elapsed().as_secs_f64() * 1000.0;
    succinct_receipt
        .verify(STF_GUEST_ID)
        .context("v5 room succinct proof self-verification failed")?;
    let (receipt, identity_ms, wrapper_ms) = if address.proof_mode == "groth16" {
        compress_groth16_with_verified_identity(&succinct_receipt)?
    } else {
        (succinct_receipt, 0.0, 0.0)
    };
    let compress_ms = recursion_ms + identity_ms + wrapper_ms;
    let gpu_telemetry = telemetry_sampler.finish()?;
    let verification_started = Instant::now();
    receipt
        .verify(STF_GUEST_ID)
        .context("v5 room proof self-verification failed")?;
    require_committed_journal_hash(&receipt.journal.bytes, journal_hash)?;
    let self_verification_ms = verification_started.elapsed().as_secs_f64() * 1000.0;
    let ethereum_seal = if address.proof_mode == "groth16" {
        Some(encode_ethereum_seal(&receipt).context("encode Ethereum verifier seal")?)
    } else {
        None
    };
    let serialization_started = Instant::now();
    let receipt_bytes = bincode::serialize(&receipt)?;
    let serialization_ms = serialization_started.elapsed().as_secs_f64() * 1000.0;
    Ok(serde_json::json!({
        "receiptB64": B64.encode(&receipt_bytes),
        "ethereumSealB64": ethereum_seal.as_ref().map(|seal| B64.encode(seal)),
        "journal": journal,
        "journalHash": format!("0x{}", hex::encode(journal_hash)),
        "journalB64": B64.encode(&receipt.journal.bytes),
        "jobId": address.job_id,
        "inputDigest": address.input_digest,
        "backendId": "risc0",
        "programId": format!("0x{}", image_id_hex()),
        "proofMode": address.proof_mode,
        "profile": {
            "nativeStatementExecutionMs": execute_ms,
            "environmentBuildMs": environment_ms,
            "proverInitializationMs": prover_initialization_ms,
            "compositeProofMs": prove_ms,
            "succinctCompressionMs": recursion_ms,
            "identityP254Ms": identity_ms,
            "groth16WrapperMs": wrapper_ms,
            "recursiveCompressionMs": compress_ms,
            "selfVerificationMs": self_verification_ms,
            "receiptSerializationMs": serialization_ms,
            "totalPipelineMs": pipeline_started.elapsed().as_secs_f64() * 1000.0,
        },
        "cycles": stats.user_cycles,
        "totalCycles": stats.total_cycles,
        "segments": stats.segments,
        "proofWork": proof_work_json_v5(
            &native_outcome.proof_work,
            Some(stats.user_cycles),
            Some(stats.segments),
        ),
        "receiptBytes": receipt_bytes.len(),
        "sealBytes": ethereum_seal.as_ref().map_or(0, |seal| seal.len()),
        "imageId": image_id_hex(),
        "gpuUuid": gpu,
        "gpuName": gpu_telemetry.gpu_name,
        "utilizationSamplesPercent": gpu_telemetry.utilization_percent,
        "vramSamplesMiB": gpu_telemetry.vram_mib,
        "powerSamplesW": gpu_telemetry.power_w,
        "containerDigest": std::env::var("ZKDEAL_CONTAINER_DIGEST").ok(),
    }))
}

pub(crate) fn cmd_verify_room_v5(raw: &str) -> Result<serde_json::Value> {
    let request: serde_json::Value = serde_json::from_str(raw).context("stdin is not JSON")?;
    let journal: BatchJournalV5 = serde_json::from_value(
        request
            .get("journal")
            .cloned()
            .context("v5 journal is required")?,
    )
    .context("v5 journal decode")?;
    if journal.proof_program_id.as_slice() != Digest::new(STF_GUEST_ID).as_bytes() {
        bail!("v5 journal proofProgramId does not match the embedded image");
    }
    let computed_hash = hash_batch_journal_v5(&journal).0;
    let supplied_hash: [u8; 32] = hex::decode(
        request
            .get("journalHash")
            .and_then(serde_json::Value::as_str)
            .context("journalHash is required")?
            .trim_start_matches("0x"),
    )
    .context("journalHash is not hex")?
    .try_into()
    .map_err(|_| anyhow!("journalHash must be 32 bytes"))?;
    if supplied_hash != computed_hash {
        bail!("journalHash does not hash the supplied v5 journal");
    }
    let receipt_bytes = B64.decode(
        request
            .get("receiptB64")
            .and_then(serde_json::Value::as_str)
            .context("receiptB64 is required")?,
    )?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).context("receipt decode")?;
    let started = Instant::now();
    receipt
        .verify(STF_GUEST_ID)
        .context("v5 room receipt verification failed")?;
    require_committed_journal_hash(&receipt.journal.bytes, computed_hash)?;
    let proof_mode = if receipt.inner.groth16().is_ok() {
        "groth16"
    } else {
        "succinct"
    };
    let ethereum_seal = if proof_mode == "groth16" {
        Some(encode_ethereum_seal(&receipt).context("derive Ethereum verifier seal")?)
    } else {
        None
    };
    Ok(serde_json::json!({
        "ok": true,
        "journal": journal,
        "journalHash": format!("0x{}", hex::encode(computed_hash)),
        "proofMode": proof_mode,
        "ethereumSealB64": ethereum_seal.as_ref().map(|seal| B64.encode(seal)),
        "verifyMs": started.elapsed().as_secs_f64() * 1000.0,
        "imageId": image_id_hex(),
    }))
}

pub(crate) fn cmd_execute_cold_template_v5(raw: &str) -> Result<serde_json::Value> {
    let (input, _request, witness, address) = cold_template_witness_from_stdin(raw)?;
    let started = Instant::now();
    // The framed canonical bytes are the exact guest input, so hashing them
    // here reproduces the genesis identity the proof will bind.
    let genesis_data_hash = keccak256(&witness);
    let statement = stf_core::execute_cold_template_v5(&input, genesis_data_hash)
        .map_err(|error| anyhow!("native v5 cold-template validation failed: {error}"))?;
    Ok(serde_json::json!({
        "templateId": format!("0x{}", hex::encode(input.template_id)),
        "statement": format!("0x{}", hex::encode(statement)),
        "genesisDataHash": format!("0x{}", hex::encode(genesis_data_hash)),
        "jobId": address.job_id,
        "inputDigest": address.input_digest,
        "backendId": "risc0",
        "programId": format!("0x{}", image_id_hex()),
        "executeMs": started.elapsed().as_secs_f64() * 1000.0,
    }))
}

pub(crate) fn cmd_prepare_room_v5(raw: &str) -> Result<serde_json::Value> {
    let image_id = Digest::new(STF_GUEST_ID);
    v5_fixture::prepare(
        raw,
        image_id
            .as_bytes()
            .try_into()
            .expect("RISC Zero image IDs are 32 bytes"),
    )
}

pub(crate) fn cmd_prove_cold_template_v5(raw: &str) -> Result<serde_json::Value> {
    let pipeline_started = Instant::now();
    let (input, request, witness, address) = cold_template_witness_from_stdin(raw)?;
    let gpu = enforce_production_gpu(&request)?;
    let production = production_requested(&request);
    let execution_started = Instant::now();
    let genesis_data_hash = keccak256(&witness);
    let statement = stf_core::execute_cold_template_v5(&input, genesis_data_hash)
        .map_err(|error| anyhow!("native v5 cold-template validation failed: {error}"))?;
    let execute_ms = execution_started.elapsed().as_secs_f64() * 1000.0;
    let environment_started = Instant::now();
    let env = build_env(&witness)?;
    let environment_ms = environment_started.elapsed().as_secs_f64() * 1000.0;
    if !matches!(address.proof_mode.as_str(), "succinct" | "groth16") {
        bail!(
            "unsupported proofMode '{}' (succinct|groth16)",
            address.proof_mode
        );
    }
    let prover_started = Instant::now();
    let prover = persistent_prover();
    let prover_initialization_ms = prover_started.elapsed().as_secs_f64() * 1000.0;
    let telemetry_sampler = GpuTelemetrySampler::start(production)?;
    let proving_started = Instant::now();
    let info = prover.prove_with_opts(env, STF_GUEST_ELF, &ProverOpts::composite())?;
    let prove_ms = proving_started.elapsed().as_secs_f64() * 1000.0;
    let stats = info.stats;
    info.receipt
        .verify(STF_GUEST_ID)
        .context("v5 cold-template composite proof self-verification failed")?;
    let recursion_started = Instant::now();
    let succinct_receipt =
        compress_receipt(prover.as_ref(), &ProverOpts::succinct(), &info.receipt)?;
    let recursion_ms = recursion_started.elapsed().as_secs_f64() * 1000.0;
    succinct_receipt
        .verify(STF_GUEST_ID)
        .context("v5 cold-template succinct proof self-verification failed")?;
    let (receipt, identity_ms, wrapper_ms) = if address.proof_mode == "groth16" {
        compress_groth16_with_verified_identity(&succinct_receipt)?
    } else {
        (succinct_receipt, 0.0, 0.0)
    };
    let compress_ms = recursion_ms + identity_ms + wrapper_ms;
    let gpu_telemetry = telemetry_sampler.finish()?;
    let verification_started = Instant::now();
    receipt
        .verify(STF_GUEST_ID)
        .context("v5 cold-template proof self-verification failed")?;
    require_committed_journal_hash(&receipt.journal.bytes, statement.0)?;
    let self_verification_ms = verification_started.elapsed().as_secs_f64() * 1000.0;
    let ethereum_seal = if address.proof_mode == "groth16" {
        Some(encode_ethereum_seal(&receipt).context("encode Ethereum verifier seal")?)
    } else {
        None
    };
    let receipt_bytes = bincode::serialize(&receipt)?;
    Ok(serde_json::json!({
        "receiptB64": B64.encode(&receipt_bytes),
        "ethereumSealB64": ethereum_seal.as_ref().map(|seal| B64.encode(seal)),
        "templateId": format!("0x{}", hex::encode(input.template_id)),
        "statement": format!("0x{}", hex::encode(statement)),
        "genesisDataHash": format!("0x{}", hex::encode(genesis_data_hash)),
        "canonicalColdTemplateDataB64": B64.encode(&witness),
        "jobId": address.job_id,
        "inputDigest": address.input_digest,
        "backendId": "risc0",
        "programId": format!("0x{}", image_id_hex()),
        "proofMode": address.proof_mode,
        "profile": {
            "nativeStatementExecutionMs": execute_ms,
            "environmentBuildMs": environment_ms,
            "proverInitializationMs": prover_initialization_ms,
            "compositeProofMs": prove_ms,
            "succinctCompressionMs": recursion_ms,
            "identityP254Ms": identity_ms,
            "groth16WrapperMs": wrapper_ms,
            "recursiveCompressionMs": compress_ms,
            "selfVerificationMs": self_verification_ms,
            "totalPipelineMs": pipeline_started.elapsed().as_secs_f64() * 1000.0,
        },
        "cycles": stats.user_cycles,
        "totalCycles": stats.total_cycles,
        "segments": stats.segments,
        "receiptBytes": receipt_bytes.len(),
        "sealBytes": ethereum_seal.as_ref().map_or(0, |seal| seal.len()),
        "gpuUuid": gpu,
        "gpuName": gpu_telemetry.gpu_name,
        "utilizationSamplesPercent": gpu_telemetry.utilization_percent,
        "vramSamplesMiB": gpu_telemetry.vram_mib,
        "powerSamplesW": gpu_telemetry.power_w,
    }))
}

pub(crate) fn cmd_verify_cold_template_v5(raw: &str) -> Result<serde_json::Value> {
    let request: serde_json::Value = serde_json::from_str(raw).context("stdin is not JSON")?;
    let input: ColdTemplateInputV5 = serde_json::from_value(
        request
            .get("coldTemplateWitness")
            .cloned()
            .context("coldTemplateWitness is required")?,
    )
    .context("v5 cold-template witness decode")?;
    if input.proof_program_id.as_slice() != Digest::new(STF_GUEST_ID).as_bytes() {
        bail!("cold-template proofProgramId does not match the embedded image");
    }
    // Re-frame the witness canonically before hashing: the statement binds
    // the exact guest input bytes, never a caller-supplied hash.
    let framed = cold_template_input_bytes_v5(&input)?;
    let genesis_data_hash = keccak256(&framed);
    let statement = cold_template_statement_v6(&input, genesis_data_hash);
    let receipt_bytes = B64.decode(
        request
            .get("receiptB64")
            .and_then(serde_json::Value::as_str)
            .context("receiptB64 is required")?,
    )?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).context("receipt decode")?;
    let started = Instant::now();
    receipt
        .verify(STF_GUEST_ID)
        .context("v5 cold-template receipt verification failed")?;
    require_committed_journal_hash(&receipt.journal.bytes, statement.0)?;
    Ok(serde_json::json!({
        "ok": true,
        "templateId": format!("0x{}", hex::encode(input.template_id)),
        "statement": format!("0x{}", hex::encode(statement)),
        "genesisDataHash": format!("0x{}", hex::encode(genesis_data_hash)),
        "verifyMs": started.elapsed().as_secs_f64() * 1000.0,
        "imageId": image_id_hex(),
    }))
}
