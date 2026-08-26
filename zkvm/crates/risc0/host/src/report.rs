//! Human decision output, sanitised failure reasons and machine result files.
//!
//! stdout and stderr carry printable human decisions only; every machine
//! payload leaves through an explicit `ZKDEAL_RESULT_PATH` artifact.

use std::io::Read;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

pub(crate) fn proof_work_json_v5(
    work: &stf_core::BatchProofWork,
    guest_cycles: Option<u64>,
    proof_segments: Option<usize>,
) -> serde_json::Value {
    serde_json::json!({
        "blockCount": work.block_count,
        "transactionCount": work.evm.transaction_count,
        "executedGas": work.evm.executed_gas,
        "guestCycles": guest_cycles,
        "proofSegments": proof_segments,
        "opcodeSteps": work.evm.opcode_steps,
        "fusedMotifHits": work.evm.fused_motif_hits,
        "fusedMotifOpcodes": work.evm.fused_motif_opcodes,
        "keccakOpcodes": work.evm.keccak_opcodes,
        "keccakCalls": serde_json::Value::Null,
        "keccakBytes": serde_json::Value::Null,
        "callOpcodes": work.evm.call_opcodes,
        "precompileCalls": work.evm.precompile_calls,
        "maxMemoryBytes": work.evm.max_memory_bytes,
        "accountReads": work.evm.db.account_reads,
        "codeReads": work.evm.db.code_reads,
        "storageReads": work.evm.db.storage_reads,
        "blockHashReads": work.evm.db.block_hash_reads,
        "accountWrites": work.evm.db.account_writes,
        "storageWrites": work.evm.db.storage_writes,
        "residentAccounts": work.evm.state_accounts,
        "residentStorageSlots": work.evm.state_storage_slots,
        "residentCodeBytes": work.evm.state_code_bytes,
        "touchedAccounts": serde_json::Value::Null,
        "touchedStorageSlots": serde_json::Value::Null,
        "trieNodes": serde_json::Value::Null,
        "encodedWitnessBytes": work.encoded_witness_bytes,
        "recursionDepth": serde_json::Value::Null,
        "unmeasured": [
            "keccakCalls",
            "keccakBytes",
            "touchedAccounts",
            "touchedStorageSlots",
            "trieNodes",
            "recursionDepth"
        ],
    })
}

pub(crate) fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading stdin")?;
    Ok(buf)
}

fn shortened_identifier(value: &str) -> String {
    if value.starts_with("0x") && value.len() > 14 {
        format!("{}...{}", &value[..8], &value[value.len() - 4..])
    } else {
        value.to_owned()
    }
}

fn shorten_embedded_identifiers(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if cursor + 2 <= bytes.len() && bytes[cursor] == b'0' && bytes[cursor + 1] == b'x' {
            let mut end = cursor + 2;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            let hex_len = end - cursor - 2;
            if hex_len >= 16 {
                output.push_str(&value[cursor..cursor + 8]);
                output.push_str("...");
                output.push_str(&value[end - 4..end]);
                cursor = end;
                continue;
            }
        }
        let character = value[cursor..]
            .chars()
            .next()
            .expect("cursor is on a character boundary");
        output.push(character);
        cursor += character.len_utf8();
    }
    output
}

pub(crate) fn safe_failure_reason(error: &anyhow::Error) -> String {
    let raw = shorten_embedded_identifiers(&format!("{error:#}"));
    let mut words = Vec::new();
    for word in raw.split_whitespace().take(24) {
        let clean = word
            .trim_matches(|character: char| matches!(character, ',' | ';' | ')' | '(' | '[' | ']'));
        if clean.starts_with("http://") || clean.starts_with("https://") {
            words.push("the configured endpoint".to_owned());
        } else if clean.starts_with("0x")
            && clean[2..]
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            words.push(shortened_identifier(clean));
        } else {
            words.push(word.to_owned());
        }
    }
    if words.is_empty() {
        "The request could not be validated.".to_owned()
    } else {
        words.join(" ")
    }
}

pub(crate) fn write_machine_result(
    command: &str,
    value: &serde_json::Value,
) -> Result<Option<PathBuf>> {
    let Some(path) = std::env::var_os("ZKDEAL_RESULT_PATH") else {
        if command.contains("prove") || command.contains("wrap") {
            bail!(
                "proof output path is required; set ZKDEAL_RESULT_PATH so the receipt is not lost"
            );
        }
        return Ok(None);
    };
    let path = PathBuf::from(path);
    if path.as_os_str().is_empty() {
        bail!("ZKDEAL_RESULT_PATH is empty");
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create result directory")?;
    }
    let encoded = serde_json::to_vec_pretty(value).context("encode machine result")?;
    std::fs::write(&path, encoded).context("write machine result")?;
    Ok(Some(path))
}

pub(crate) fn print_human_result(
    command: &str,
    value: &serde_json::Value,
    saved: Option<&PathBuf>,
) {
    let decision = if command.contains("prove") || command.contains("wrap") {
        "Proof is locally verified and ready for the configured L1 verifier"
    } else if command.starts_with("prepare-") {
        "Deterministic two-block room evidence is ready for CUDA proving"
    } else if command.contains("verify") {
        "Proof and committed statement are valid"
    } else if command == "health" {
        "CUDA prover is ready"
    } else if command == "capabilities" {
        "Prover capabilities inspected"
    } else if command == "imageid" {
        "Proof program identified"
    } else {
        "Witness is valid for deterministic execution"
    };
    let elapsed = value
        .pointer("/profile/totalPipelineMs")
        .or_else(|| value.get("executeMs"))
        .or_else(|| value.get("verifyMs"))
        .and_then(serde_json::Value::as_f64)
        .map(|milliseconds| format!("{milliseconds:.1} ms"))
        .unwrap_or_else(|| "not timed".to_owned());
    let segments = value
        .get("segments")
        .and_then(serde_json::Value::as_u64)
        .map(|count| format!("{count} proof segments"))
        .unwrap_or_else(|| "no proof segmentation reported".to_owned());
    println!("Decision: {decision}");
    println!("Evidence: {elapsed}; {segments}.");
    println!(
        "Blocker: {}",
        if command.contains("prove") || command.contains("wrap") {
            "Ethereum broadcast and inclusion are outside this local proof result."
        } else {
            "None at the completed local validation boundary."
        }
    );
    println!(
        "Next action: {}",
        if command.contains("prove") || command.contains("wrap") {
            "Submit the saved seal only through the pinned room verifier."
        } else if command.starts_with("prepare-") {
            "Prove the cold template once, then prove the room transition."
        } else {
            "Continue with the next authenticated room transition."
        }
    );
    println!(
        "Evidence saved: {}",
        saved
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not requested".to_owned())
    );
    println!("Resource budget: one local CUDA proof slot; CPU fallback disabled.");
}

#[cfg(test)]
mod human_output_tests {
    use super::*;

    use anyhow::anyhow;

    #[test]
    fn embedded_addresses_and_hashes_are_shortened() {
        let failure = anyhow!(
            "storage 0x15339a8aA09A7aA1Ea4258277DFdbd6A1586C805[0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff] is invalid"
        );
        let safe = safe_failure_reason(&failure);
        assert!(safe.contains("0x15339a...C805"));
        assert!(safe.contains("0xffffff...ffff"));
        assert!(!safe.contains("0x15339a8aA09A7aA1Ea4258277DFdbd6A1586C805"));
        assert!(
            !safe.contains("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        );
    }
}
