//! Encode and CPU-validate the production certified-AMM cold/composed inputs.
//!
//! The TypeScript stage executes the actual constructors and emits an
//! auditable JSON spec. This stage converts that spec to the canonical Borsh
//! inputs accepted by `zkdeal-r0 prove-cold-v4` and
//! `prove-composed-batch-v4`. Both statements execute natively before any
//! request files are written, so malformed constructor transcripts or a cold
//! proof that does not link to the real hot prestate fail locally.
//!
//! The spec readers live in [`spec`] and the content-addressing primitives in
//! [`digest`]; this file only orchestrates them.

use std::{
    env,
    error::Error,
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};

use serde_json::{json, Value};
use stf_core::{execute_batch_v4, execute_cold_room_v4, execute_composed_batch_v4};
use stf_types::{hash_batch_journal_v4, hash_cold_room_journal_v4};
use stf_wire::{
    batch_input_to_borsh_v4, batch_journal_to_ts_value_v4, cold_input_to_borsh_v4,
    composed_batch_input_to_borsh_v4, parse_batch_witness_json_v4, ColdRoomJournalWireV4,
    ComposedBatchInputWireV4,
};

// A `src/bin/*.rs` target resolves plain `mod` paths against `src/bin/`, where
// every file is itself an auto-discovered binary; `#[path]` points them at this
// target's own directory instead.
#[path = "gen-amm-cold-composed-v4/digest.rs"]
mod digest;
#[path = "gen-amm-cold-composed-v4/spec.rs"]
mod spec;

use digest::{base64, content_address, hex, risc0_frame_input, sha256};
use spec::{decode_hex, field, parse_cold_wire, string, u64_value};

type DynResult<T> = Result<T, Box<dyn Error>>;

const BATCH_JOB_DOMAIN_V4: &[u8] = b"zkdeal:v4:prover-job";
const COLD_JOB_DOMAIN_V4: &[u8] = b"zkdeal:v4:cold-prover-job";
const COMPOSED_JOB_DOMAIN_V4: &[u8] = b"zkdeal:v4:composed-prover-job";
const PROOF_MODE: &str = "succinct";

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(ErrorKind::InvalidData, message.into()).into()
}

fn write_json(path: &Path, value: &Value) -> DynResult<()> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn main() -> DynResult<()> {
    if sha256(b"abc")
        != decode_hex(
            "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 self-test",
        )?
        .as_slice()
    {
        return Err(invalid("internal SHA-256 self-test failed"));
    }
    let mut args = env::args_os().skip(1);
    let spec_path = PathBuf::from(args.next().ok_or_else(|| {
        invalid("usage: gen-amm-cold-composed-v4 <spec.json> <output-directory>")
    })?);
    let output_dir = PathBuf::from(args.next().ok_or_else(|| {
        invalid("usage: gen-amm-cold-composed-v4 <spec.json> <output-directory>")
    })?);
    if args.next().is_some() {
        return Err(invalid("unexpected extra command-line argument"));
    }

    let root: Value = serde_json::from_slice(&fs::read(&spec_path)?)?;
    let expected_executed_gas = field(&root, "metadata")
        .and_then(|metadata| field(metadata, "expectedExecutedGas"))
        .and_then(|value| u64_value(value, "metadata.expectedExecutedGas"))?;
    let cold_value = field(&root, "cold")?;
    let cold_wire = parse_cold_wire(cold_value)?;
    let batch_value = field(&root, "batchWitness")?;
    let batch_wire =
        parse_batch_witness_json_v4(&serde_json::to_string(batch_value)?).map_err(invalid)?;
    let ordinary_job = field(&root, "ordinaryJob")?;
    let ordinary_witness = field(ordinary_job, "witness")?;
    if ordinary_witness != batch_value {
        return Err(invalid(
            "ordinary job witness differs from the cold/composed hot batch witness",
        ));
    }

    if cold_wire.proof_program_id != batch_wire.proof_program_id
        || cold_wire.preset_hash != batch_wire.preset_hash
        || cold_wire.manifest_hash != batch_wire.manifest_hash
    {
        return Err(invalid(
            "cold and hot statements disagree on program/preset/manifest",
        ));
    }
    if cold_wire.initialized_state_root != batch_wire.prev_state_root {
        return Err(invalid(
            "certified AMM cold initialized root is not the exact hot batch pre-root",
        ));
    }

    let ordinary_input = batch_wire.to_input().map_err(invalid)?;
    let ordinary_journal = execute_batch_v4(&ordinary_input)
        .map_err(|error| invalid(format!("ordinary AMM execution: {error}")))?;
    let ordinary_journal_hash = hash_batch_journal_v4(&ordinary_journal);

    let cold_input = cold_wire.to_input().map_err(invalid)?;
    let cold_journal = execute_cold_room_v4(&cold_input)
        .map_err(|error| invalid(format!("cold constructor execution: {error}")))?;
    let cold_journal_wire = ColdRoomJournalWireV4::from(&cold_journal);
    let composed_wire = ComposedBatchInputWireV4 {
        v: cold_wire.v,
        cold_journal: cold_journal_wire.clone(),
        runtime_code: cold_wire.runtime_code.clone(),
        state_access: cold_wire.state_access.clone(),
        state_refresh: cold_wire.state_refresh.clone(),
        batch: batch_wire.clone(),
    };
    let composed_input = composed_wire.to_input().map_err(invalid)?;
    let batch_journal = execute_composed_batch_v4(&composed_input)
        .map_err(|error| invalid(format!("composed AMM execution: {error}")))?;
    let cold_journal_hash = hash_cold_room_journal_v4(&cold_journal);
    let composed_journal_hash = hash_batch_journal_v4(&batch_journal);

    let cold_bytes = cold_input_to_borsh_v4(&cold_wire);
    let composed_bytes = composed_batch_input_to_borsh_v4(&composed_wire);
    let ordinary_borsh = batch_input_to_borsh_v4(&batch_wire);
    let ordinary_witness_json = serde_json::to_vec(ordinary_witness)?;
    let (ordinary_digest, ordinary_job_id) = content_address(
        BATCH_JOB_DOMAIN_V4,
        &ordinary_witness_json,
        &batch_wire.proof_program_id,
        &batch_wire.preset_hash,
    );
    if string(
        field(ordinary_job, "inputDigest")?,
        "ordinaryJob.inputDigest",
    )? != ordinary_digest
        || string(field(ordinary_job, "jobId")?, "ordinaryJob.jobId")? != ordinary_job_id
        || string(field(ordinary_job, "programId")?, "ordinaryJob.programId")?
            != hex(&batch_wire.proof_program_id)
        || string(field(ordinary_job, "presetHash")?, "ordinaryJob.presetHash")?
            != hex(&batch_wire.preset_hash)
        || string(field(ordinary_job, "backendId")?, "ordinaryJob.backendId")? != "risc0"
        || string(field(ordinary_job, "proofMode")?, "ordinaryJob.proofMode")? != PROOF_MODE
        || u64_value(field(ordinary_job, "v")?, "ordinaryJob.v")? != 4
    {
        return Err(invalid(
            "ordinary job content address/program/preset/backend is not canonical",
        ));
    }
    let ordinary_bento_input = risc0_frame_input(&ordinary_borsh)?;
    let (cold_digest, cold_job_id) = content_address(
        COLD_JOB_DOMAIN_V4,
        &cold_bytes,
        &cold_wire.proof_program_id,
        &cold_wire.preset_hash,
    );
    let (composed_digest, composed_job_id) = content_address(
        COMPOSED_JOB_DOMAIN_V4,
        &composed_bytes,
        &composed_wire.batch.proof_program_id,
        &composed_wire.batch.preset_hash,
    );

    fs::create_dir_all(&output_dir)?;
    let mut ordinary_request = ordinary_job.clone();
    let ordinary_request_object = ordinary_request
        .as_object_mut()
        .ok_or_else(|| invalid("ordinaryJob must be an object"))?;
    ordinary_request_object.insert("production".into(), Value::Bool(true));
    ordinary_request_object.insert(
        "expectedJournal".into(),
        batch_journal_to_ts_value_v4(&ordinary_journal),
    );
    write_json(
        &output_dir.join("ordinary-batch-request.json"),
        &ordinary_request,
    )?;
    fs::write(
        output_dir.join("ordinary-batch-witness.borsh"),
        &ordinary_borsh,
    )?;
    fs::write(
        output_dir.join("ordinary-batch-bento-input.bin"),
        &ordinary_bento_input,
    )?;
    fs::write(output_dir.join("cold-witness.borsh"), &cold_bytes)?;
    fs::write(output_dir.join("composed-witness.borsh"), &composed_bytes)?;
    write_json(
        &output_dir.join("cold-request.json"),
        &json!({
            "production": true,
            "proofMode": PROOF_MODE,
            "jobId": cold_job_id,
            "inputDigest": cold_digest,
            "programId": hex(&cold_wire.proof_program_id),
            "presetHash": hex(&cold_wire.preset_hash),
            "coldWitnessBorshB64": base64(&cold_bytes),
        }),
    )?;
    write_json(
        &output_dir.join("composed-request.template.json"),
        &json!({
            "production": true,
            "proofMode": PROOF_MODE,
            "jobId": composed_job_id,
            "inputDigest": composed_digest,
            "programId": hex(&composed_wire.batch.proof_program_id),
            "presetHash": hex(&composed_wire.batch.preset_hash),
            "composedWitnessBorshB64": base64(&composed_bytes),
            "coldReceiptB64": "__REPLACE_WITH_COLD_RESULT_RECEIPT_B64__",
        }),
    )?;
    write_json(
        &output_dir.join("validation.json"),
        &json!({
            "schema": "zkdeal-amm-cold-composed-validation-v4",
            "sourceSpec": spec_path,
            "cpuValidated": true,
            "constructorTransactions": cold_wire.setup_blocks.iter().map(|block| block.raw_txs.len()).sum::<usize>(),
            "hotBlocks": composed_wire.batch.blocks.len(),
            "hotTransactions": composed_wire.batch.blocks.iter().map(|block| block.raw_txs.len()).sum::<usize>(),
            "expectedExecutedGas": expected_executed_gas,
            "programId": hex(&cold_wire.proof_program_id),
            "presetHash": hex(&cold_wire.preset_hash),
            "manifestHash": hex(&cold_wire.manifest_hash),
            "initialStateRoot": hex(&cold_wire.initial_state_root),
            "initializedAndBatchPreStateRoot": hex(&cold_wire.initialized_state_root),
            "coldTemplateId": hex(&cold_journal_wire.template_id),
            "coldJournalHash": hex(cold_journal_hash.as_slice()),
            "expectedComposedJournalHash": hex(composed_journal_hash.as_slice()),
            "ordinaryInputDigest": ordinary_digest,
            "ordinaryJobId": ordinary_job_id,
            "expectedOrdinaryJournalHash": hex(ordinary_journal_hash.as_slice()),
            "ordinaryWitnessBorshBytes": ordinary_borsh.len(),
            "ordinaryBentoInputBytes": ordinary_bento_input.len(),
            "ordinaryBentoInputSha256": hex(&sha256(&ordinary_bento_input)),
            "coldInputDigest": cold_digest,
            "coldJobId": cold_job_id,
            "composedInputDigest": composed_digest,
            "composedJobId": composed_job_id,
            "coldWitnessBytes": cold_bytes.len(),
            "composedWitnessBytes": composed_bytes.len(),
            "coldJournal": cold_journal,
            "batchJournal": batch_journal_to_ts_value_v4(&batch_journal),
            "ordinaryBatchJournal": batch_journal_to_ts_value_v4(&ordinary_journal),
        }),
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "outputDirectory": output_dir,
            "cpuValidated": true,
            "coldJobId": cold_job_id,
            "composedJobId": composed_job_id,
            "coldWitnessBytes": cold_bytes.len(),
            "composedWitnessBytes": composed_bytes.len(),
            "coldTemplateId": hex(&cold_journal_wire.template_id),
            "coldJournalHash": hex(cold_journal_hash.as_slice()),
            "expectedComposedJournalHash": hex(composed_journal_hash.as_slice()),
            "expectedOrdinaryJournalHash": hex(ordinary_journal_hash.as_slice()),
            "ordinaryJobId": ordinary_job_id,
            "ordinaryInputDigest": ordinary_digest,
            "ordinaryBentoInputBytes": ordinary_bento_input.len(),
            "ordinaryBentoInputSha256": hex(&sha256(&ordinary_bento_input)),
            "postStateRoot": hex(&batch_journal.post_state_root.0),
        }))?
    );
    Ok(())
}
