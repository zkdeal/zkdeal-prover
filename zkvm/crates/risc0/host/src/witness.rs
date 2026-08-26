//! Long-lived-room witness framing, canonical encoding and content addressing.
//!
//! A witness is only accepted in the exact canonical encoding the job id is
//! derived from, so a request can never address one payload and prove another.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use r0_methods::STF_GUEST_ID;
use risc0_zkvm::sha::Digest;
use sha2::{Digest as ShaDigest, Sha256};
use stf_types::{BatchInputV5, ColdTemplateInputV5};

use crate::B64;

const ROOM_JOB_DOMAIN_V6: &[u8] = b"zkdeal:v6:room-prover-job";
const COLD_TEMPLATE_JOB_DOMAIN_V5: &[u8] = b"zkdeal:v5:cold-template-prover-job";
const ROOM_BATCH_MAGIC_V6: &[u8; 8] = b"ZKDV6BAT";
const COLD_TEMPLATE_MAGIC_V5: &[u8; 8] = b"ZKDV5CLD";

#[derive(Clone, Debug)]
pub(crate) struct ContentAddressV5 {
    pub(crate) input_digest: String,
    pub(crate) job_id: String,
    pub(crate) proof_mode: String,
}

pub(crate) fn embedded_program_id_v5() -> [u8; 32] {
    let embedded: [u8; 32] = Digest::new(STF_GUEST_ID)
        .as_bytes()
        .try_into()
        .expect("RISC Zero image IDs are 32 bytes");
    // `RISC0_SKIP_BUILD=1` intentionally emits an all-zero placeholder while
    // compiling host-only unit tests. Keep that placeholder from weakening a
    // production binary: the substitute exists only in `cfg(test)` and lets
    // content-address tests exercise the same non-zero identity boundary.
    #[cfg(test)]
    if embedded == [0u8; 32] {
        return [0x42; 32];
    }
    embedded
}

fn validate_content_address_v5(
    request: &serde_json::Value,
    witness_bytes: &[u8],
    program_id: [u8; 32],
    preset_hash: [u8; 32],
    job_domain: &[u8],
) -> Result<ContentAddressV5> {
    let embedded_program_id = embedded_program_id_v5();
    if program_id != embedded_program_id {
        bail!(
            "witness proofProgramId {} does not match embedded RISC Zero image {}",
            hex::encode(program_id),
            hex::encode(embedded_program_id)
        );
    }
    let proof_mode = request
        .get("proofMode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("groth16")
        .to_owned();
    if !matches!(proof_mode.as_str(), "succinct" | "groth16") {
        bail!("unsupported proofMode '{proof_mode}' (succinct|groth16)");
    }
    let digest = Sha256::digest(witness_bytes);
    let input_digest = format!("0x{}", hex::encode(digest));
    let mut job_hasher = Sha256::new();
    job_hasher.update(job_domain);
    job_hasher.update(digest);
    job_hasher.update(program_id);
    job_hasher.update(preset_hash);
    job_hasher.update(b"risc0");
    job_hasher.update(proof_mode.as_bytes());
    let job_id = format!("0x{}", hex::encode(job_hasher.finalize()));
    if let Some(got) = request
        .get("inputDigest")
        .and_then(serde_json::Value::as_str)
    {
        if !got.eq_ignore_ascii_case(&input_digest) {
            bail!("inputDigest mismatch: request {got}, witness {input_digest}");
        }
    }
    if let Some(got) = request.get("jobId").and_then(serde_json::Value::as_str) {
        if !got.eq_ignore_ascii_case(&job_id) {
            bail!("jobId mismatch: request {got}, computed {job_id}");
        }
    }
    Ok(ContentAddressV5 {
        input_digest,
        job_id,
        proof_mode,
    })
}

fn room_input_bytes_v5(input: &BatchInputV5) -> Result<Vec<u8>> {
    let mut canonical = input.clone();
    canonical.encoded_witness_bytes = 0;
    let encoded = bincode::serialize(&canonical).context("serialize v6 room witness")?;
    let mut framed = Vec::with_capacity(ROOM_BATCH_MAGIC_V6.len() + encoded.len());
    framed.extend_from_slice(ROOM_BATCH_MAGIC_V6);
    framed.extend_from_slice(&encoded);
    Ok(framed)
}

pub(crate) fn room_witness_from_stdin(
    raw: &str,
) -> Result<(BatchInputV5, serde_json::Value, Vec<u8>, ContentAddressV5)> {
    let request: serde_json::Value = serde_json::from_str(raw).context("stdin is not JSON")?;
    let supplied = if let Some(encoded) = request
        .get("roomWitnessB64")
        .and_then(serde_json::Value::as_str)
    {
        B64.decode(encoded)
            .context("roomWitnessB64 is not valid base64")?
    } else {
        let input: BatchInputV5 = serde_json::from_value(
            request
                .get("roomWitness")
                .cloned()
                .context("roomWitness or roomWitnessB64 is required")?,
        )
        .context("v6 room witness JSON decode")?;
        room_input_bytes_v5(&input)?
    };
    let encoded = supplied
        .strip_prefix(ROOM_BATCH_MAGIC_V6)
        .context("roomWitnessB64 has the wrong protocol magic")?;
    let mut input: BatchInputV5 =
        bincode::deserialize(encoded).context("v6 room witness decode")?;
    let canonical = room_input_bytes_v5(&input)?;
    if canonical != supplied {
        bail!("v6 room witness is not in canonical encoding");
    }
    input.encoded_witness_bytes =
        u32::try_from(supplied.len()).context("v6 room witness exceeds u32")?;
    let address = validate_content_address_v5(
        &request,
        &supplied,
        input.journal.proof_program_id.0,
        input.journal.policy_hash.0,
        ROOM_JOB_DOMAIN_V6,
    )?;
    Ok((input, request, supplied, address))
}

pub(crate) fn cold_template_input_bytes_v5(input: &ColdTemplateInputV5) -> Result<Vec<u8>> {
    let encoded = bincode::serialize(input).context("serialize v5 cold-template witness")?;
    let mut framed = Vec::with_capacity(COLD_TEMPLATE_MAGIC_V5.len() + encoded.len());
    framed.extend_from_slice(COLD_TEMPLATE_MAGIC_V5);
    framed.extend_from_slice(&encoded);
    Ok(framed)
}

pub(crate) fn cold_template_witness_from_stdin(
    raw: &str,
) -> Result<(
    ColdTemplateInputV5,
    serde_json::Value,
    Vec<u8>,
    ContentAddressV5,
)> {
    let request: serde_json::Value = serde_json::from_str(raw).context("stdin is not JSON")?;
    let supplied = if let Some(encoded) = request
        .get("coldTemplateWitnessB64")
        .and_then(serde_json::Value::as_str)
    {
        B64.decode(encoded)
            .context("coldTemplateWitnessB64 is not valid base64")?
    } else {
        let input: ColdTemplateInputV5 = serde_json::from_value(
            request
                .get("coldTemplateWitness")
                .cloned()
                .context("coldTemplateWitness or coldTemplateWitnessB64 is required")?,
        )
        .context("v5 cold-template witness JSON decode")?;
        cold_template_input_bytes_v5(&input)?
    };
    let encoded = supplied
        .strip_prefix(COLD_TEMPLATE_MAGIC_V5)
        .context("cold-template witness has the wrong protocol magic")?;
    let input: ColdTemplateInputV5 =
        bincode::deserialize(encoded).context("v5 cold-template witness decode")?;
    if cold_template_input_bytes_v5(&input)? != supplied {
        bail!("v5 cold-template witness is not in canonical encoding");
    }
    let address = validate_content_address_v5(
        &request,
        &supplied,
        input.proof_program_id.0,
        input.policy_hash.0,
        COLD_TEMPLATE_JOB_DOMAIN_V5,
    )?;
    Ok((input, request, supplied, address))
}
