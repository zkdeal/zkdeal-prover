//! Receipt wrapping commands: Poseidon identity-p254 and the BN254 Groth16
//! wrapper an Ethereum verifier accepts.
//!
//! Each command re-verifies its input receipt, refuses to change the committed
//! room statement, and self-verifies the wrapped receipt before returning it.

use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use r0_methods::STF_GUEST_ID;
use risc0_groth16::prove::shrink_wrap;
use risc0_zkvm::{
    get_prover_server, sha::Digestible, Groth16Receipt, Groth16ReceiptVerifierParameters,
    InnerReceipt, ProverOpts, Receipt,
};

use crate::gpu::{enforce_production_gpu, GpuTelemetrySampler};
use crate::receipt::{
    compress_groth16_with_verified_identity, encode_ethereum_seal, image_id_hex,
    require_committed_journal_hash, verify_identity_p254_receipt, without_third_party_stdout,
};
use crate::B64;

pub(crate) fn cmd_wrap_groth16_v5(raw: &str) -> Result<serde_json::Value> {
    let pipeline_started = Instant::now();
    let request: serde_json::Value = serde_json::from_str(raw).context("stdin is not JSON")?;
    let gpu = enforce_production_gpu(&request)?;
    let receipt_bytes = B64.decode(
        request
            .get("receiptB64")
            .and_then(serde_json::Value::as_str)
            .context("receiptB64 is required")?,
    )?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).context("receipt decode")?;
    receipt
        .verify(STF_GUEST_ID)
        .context("input receipt verification failed")?;
    if receipt.inner.groth16().is_ok() {
        bail!("input receipt is already Groth16");
    }
    if receipt.journal.bytes.len() != 32 {
        bail!("input receipt must commit one exact 32-byte room statement");
    }
    if let Some(expected) = request
        .get("statementHash")
        .and_then(serde_json::Value::as_str)
    {
        let expected: [u8; 32] = hex::decode(expected.trim_start_matches("0x"))
            .context("statementHash is not hex")?
            .try_into()
            .map_err(|_| anyhow!("statementHash must be 32 bytes"))?;
        require_committed_journal_hash(&receipt.journal.bytes, expected)?;
    }
    let telemetry_sampler = GpuTelemetrySampler::start(true)?;
    let (wrapped, identity_ms, wrapper_ms) = compress_groth16_with_verified_identity(&receipt)?;
    let gpu_telemetry = telemetry_sampler.finish()?;
    let verification_started = Instant::now();
    wrapped
        .verify(STF_GUEST_ID)
        .context("wrapped Groth16 receipt verification failed")?;
    if wrapped.journal.bytes != receipt.journal.bytes {
        bail!("wrapped receipt changed the committed room statement");
    }
    let self_verification_ms = verification_started.elapsed().as_secs_f64() * 1000.0;
    let ethereum_seal = encode_ethereum_seal(&wrapped).context("encode Ethereum verifier seal")?;
    let wrapped_bytes = bincode::serialize(&wrapped).context("encode wrapped receipt")?;
    Ok(serde_json::json!({
        "receiptB64": B64.encode(&wrapped_bytes),
        "ethereumSealB64": B64.encode(&ethereum_seal),
        "journalB64": B64.encode(&wrapped.journal.bytes),
        "backendId": "risc0",
        "programId": format!("0x{}", image_id_hex()),
        "proofMode": "groth16",
        "profile": {
            "identityP254Ms": identity_ms,
            "groth16WrapperMs": wrapper_ms,
            "recursiveCompressionMs": identity_ms + wrapper_ms,
            "selfVerificationMs": self_verification_ms,
            "totalPipelineMs": pipeline_started.elapsed().as_secs_f64() * 1000.0,
        },
        "receiptBytes": wrapped_bytes.len(),
        "sealBytes": ethereum_seal.len(),
        "gpuUuid": gpu,
        "gpuName": gpu_telemetry.gpu_name,
        "utilizationSamplesPercent": gpu_telemetry.utilization_percent,
        "vramSamplesMiB": gpu_telemetry.vram_mib,
        "powerSamplesW": gpu_telemetry.power_w,
    }))
}

pub(crate) fn cmd_wrap_identity_p254_v5(raw: &str) -> Result<serde_json::Value> {
    let pipeline_started = Instant::now();
    let request: serde_json::Value = serde_json::from_str(raw).context("stdin is not JSON")?;
    let gpu = enforce_production_gpu(&request)?;
    let receipt_bytes = B64.decode(
        request
            .get("receiptB64")
            .and_then(serde_json::Value::as_str)
            .context("receiptB64 is required")?,
    )?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).context("receipt decode")?;
    receipt
        .verify(STF_GUEST_ID)
        .context("input receipt verification failed")?;
    let succinct = match &receipt.inner {
        InnerReceipt::Succinct(succinct) => succinct,
        InnerReceipt::Composite(_) => bail!("input receipt must already be succinct"),
        InnerReceipt::Groth16(_) => bail!("input receipt is already Groth16"),
        InnerReceipt::Fake(_) => bail!("development receipts are not accepted"),
        _ => bail!("unsupported receipt representation"),
    };
    if receipt.journal.bytes.len() != 32 {
        bail!("input receipt must commit one exact 32-byte room statement");
    }
    if let Some(expected) = request
        .get("statementHash")
        .and_then(serde_json::Value::as_str)
    {
        let expected: [u8; 32] = hex::decode(expected.trim_start_matches("0x"))
            .context("statementHash is not hex")?
            .try_into()
            .map_err(|_| anyhow!("statementHash must be 32 bytes"))?;
        require_committed_journal_hash(&receipt.journal.bytes, expected)?;
    }

    let telemetry_sampler = GpuTelemetrySampler::start(true)?;
    let identity_started = Instant::now();
    let identity = get_prover_server(&ProverOpts::succinct())?
        .identity_p254(succinct)
        .context("Poseidon identity proof failed")?;
    let identity_ms = identity_started.elapsed().as_secs_f64() * 1000.0;
    let gpu_telemetry = telemetry_sampler.finish()?;
    let wrapped = Receipt::new(
        InnerReceipt::Succinct(identity),
        receipt.journal.bytes.clone(),
    );
    let verification_started = Instant::now();
    verify_identity_p254_receipt(&wrapped)?;
    if wrapped.journal.bytes != receipt.journal.bytes {
        bail!("Poseidon identity receipt changed the committed room statement");
    }
    let self_verification_ms = verification_started.elapsed().as_secs_f64() * 1000.0;
    let wrapped_bytes = bincode::serialize(&wrapped).context("encode Poseidon identity receipt")?;
    Ok(serde_json::json!({
        "receiptB64": B64.encode(&wrapped_bytes),
        "journalB64": B64.encode(&wrapped.journal.bytes),
        "backendId": "risc0",
        "programId": format!("0x{}", image_id_hex()),
        "proofMode": "identity-p254",
        "profile": {
            "identityP254Ms": identity_ms,
            "selfVerificationMs": self_verification_ms,
            "totalPipelineMs": pipeline_started.elapsed().as_secs_f64() * 1000.0,
        },
        "receiptBytes": wrapped_bytes.len(),
        "gpuUuid": gpu,
        "gpuName": gpu_telemetry.gpu_name,
        "utilizationSamplesPercent": gpu_telemetry.utilization_percent,
        "vramSamplesMiB": gpu_telemetry.vram_mib,
        "powerSamplesW": gpu_telemetry.power_w,
    }))
}

pub(crate) fn cmd_wrap_groth16_from_p254_v5(raw: &str) -> Result<serde_json::Value> {
    let pipeline_started = Instant::now();
    let request: serde_json::Value = serde_json::from_str(raw).context("stdin is not JSON")?;
    let gpu = enforce_production_gpu(&request)?;
    let receipt_bytes = B64.decode(
        request
            .get("receiptB64")
            .and_then(serde_json::Value::as_str)
            .context("receiptB64 is required")?,
    )?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).context("receipt decode")?;
    verify_identity_p254_receipt(&receipt)?;
    let identity = match &receipt.inner {
        InnerReceipt::Succinct(succinct) => succinct,
        InnerReceipt::Composite(_) => bail!("input receipt is not a Poseidon identity receipt"),
        InnerReceipt::Groth16(_) => bail!("input receipt is already Groth16"),
        InnerReceipt::Fake(_) => bail!("development receipts are not accepted"),
        _ => bail!("unsupported receipt representation"),
    };
    if receipt.journal.bytes.len() != 32 {
        bail!("input receipt must commit one exact 32-byte room statement");
    }
    if let Some(expected) = request
        .get("statementHash")
        .and_then(serde_json::Value::as_str)
    {
        let expected: [u8; 32] = hex::decode(expected.trim_start_matches("0x"))
            .context("statementHash is not hex")?
            .try_into()
            .map_err(|_| anyhow!("statementHash must be 32 bytes"))?;
        require_committed_journal_hash(&receipt.journal.bytes, expected)?;
    }

    let telemetry_sampler = GpuTelemetrySampler::start(true)?;
    let wrapper_started = Instant::now();
    let seal = without_third_party_stdout(|| {
        shrink_wrap(&identity.get_seal_bytes()).context("Groth16 wrapper proof failed")
    })?
    .to_vec();
    let wrapper_ms = wrapper_started.elapsed().as_secs_f64() * 1000.0;
    let gpu_telemetry = telemetry_sampler.finish()?;
    let wrapped = Receipt::new(
        InnerReceipt::Groth16(Groth16Receipt::new(
            seal,
            identity.claim.clone(),
            Groth16ReceiptVerifierParameters::default().digest(),
        )),
        receipt.journal.bytes.clone(),
    );
    let verification_started = Instant::now();
    wrapped
        .verify(STF_GUEST_ID)
        .context("wrapped Groth16 receipt verification failed")?;
    if wrapped.journal.bytes != receipt.journal.bytes {
        bail!("wrapped receipt changed the committed room statement");
    }
    let self_verification_ms = verification_started.elapsed().as_secs_f64() * 1000.0;
    let ethereum_seal = encode_ethereum_seal(&wrapped).context("encode Ethereum verifier seal")?;
    let wrapped_bytes = bincode::serialize(&wrapped).context("encode wrapped receipt")?;
    Ok(serde_json::json!({
        "receiptB64": B64.encode(&wrapped_bytes),
        "ethereumSealB64": B64.encode(&ethereum_seal),
        "journalB64": B64.encode(&wrapped.journal.bytes),
        "backendId": "risc0",
        "programId": format!("0x{}", image_id_hex()),
        "proofMode": "groth16",
        "profile": {
            "groth16WrapperMs": wrapper_ms,
            "selfVerificationMs": self_verification_ms,
            "totalPipelineMs": pipeline_started.elapsed().as_secs_f64() * 1000.0,
        },
        "receiptBytes": wrapped_bytes.len(),
        "sealBytes": ethereum_seal.len(),
        "gpuUuid": gpu,
        "gpuName": gpu_telemetry.gpu_name,
        "utilizationSamplesPercent": gpu_telemetry.utilization_percent,
        "vramSamplesMiB": gpu_telemetry.vram_mib,
        "powerSamplesW": gpu_telemetry.power_w,
    }))
}
