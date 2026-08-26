//! stf-wasm — the REAL Rust STF (revm + alloy-trie, byte-parity with the
//! ethereumjs engine) compiled to WebAssembly.
//!
//! Both zkVM backends' `execute()` runs through this module so the journal a
//! browser computes is bit-identical to what the risc0/ligetron guests commit
//! (same stf-core, same wire codecs). Built with
//! `wasm-pack build --target web`; the web glue is loaded in Node by passing
//! the wasm bytes to `init` directly (no second nodejs build needed — see
//! packages/zkvm/src/backends/stf-exec.ts).
//!
//! Exports:
//! - `execute(witness_json)` → JSON `{ journal, gasUsed, postStateJson }`
//!   (executeMs is measured by the JS caller — wasm32-unknown has no clock).
//! - `witness_to_wire_hex(witness_json)` → hex of the canonical borsh guest
//!   input (used to build prove requests without duplicating the codec in TS).
//! - `journal_borsh_hex(witness_json)` → hex of the 113-byte borsh journal the
//!   guests commit (ligetron public arg 2 / receipt cross-checks).

use stf_core::{execute_batch_v4 as execute_batch_core_v4, execute_block_full};
use stf_wire::{
    batch_input_to_borsh_v4, batch_journal_to_borsh_v4, batch_journal_to_ts_value_v4,
    input_to_borsh, journal_to_borsh, journal_to_ts_value, parse_batch_witness_json_v4,
    parse_witness_json, post_state_to_dump_json,
};
use wasm_bindgen::prelude::*;

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Execute one block via the real STF. Returns
/// `{"journal": <TS StfJournal>, "gasUsed": "<dec>", "postStateJson": "<slot-keyed dump>"}`.
#[wasm_bindgen]
pub fn execute(witness_json: &str) -> Result<String, JsError> {
    let wire = parse_witness_json(witness_json).map_err(|e| JsError::new(&e))?;
    let input = wire.to_input();
    let outcome = execute_block_full(&input).map_err(|e| JsError::new(&e.to_string()))?;
    let out = serde_json::json!({
        "journal": journal_to_ts_value(&outcome.journal),
        "gasUsed": outcome.gas_used.to_string(),
        "postStateJson": post_state_to_dump_json(&outcome.post_state),
    });
    Ok(out.to_string())
}

/// Canonical borsh guest-input bytes for this witness, hex encoded.
#[wasm_bindgen]
pub fn witness_to_wire_hex(witness_json: &str) -> Result<String, JsError> {
    let wire = parse_witness_json(witness_json).map_err(|e| JsError::new(&e))?;
    Ok(hex_encode(&input_to_borsh(&wire)))
}

/// Execute + return the 113-byte borsh journal (guest commitment), hex encoded.
#[wasm_bindgen]
pub fn journal_borsh_hex(witness_json: &str) -> Result<String, JsError> {
    let wire = parse_witness_json(witness_json).map_err(|e| JsError::new(&e))?;
    let input = wire.to_input();
    let outcome = execute_block_full(&input).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex_encode(&journal_to_borsh(&outcome.journal)))
}

/// Execute one v4 batch (1-4 contiguous blocks) with a single opening state.
#[wasm_bindgen]
pub fn execute_batch_v4(witness_json: &str) -> Result<String, JsError> {
    let wire = parse_batch_witness_json_v4(witness_json).map_err(|e| JsError::new(&e))?;
    let input = wire.to_input().map_err(|e| JsError::new(&e))?;
    let journal = execute_batch_core_v4(&input).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "journal": batch_journal_to_ts_value_v4(&journal) }).to_string())
}

/// Canonical Borsh guest input for a v4 batch, hex encoded.
#[wasm_bindgen]
pub fn batch_witness_to_wire_hex_v4(witness_json: &str) -> Result<String, JsError> {
    let wire = parse_batch_witness_json_v4(witness_json).map_err(|e| JsError::new(&e))?;
    Ok(hex_encode(&batch_input_to_borsh_v4(&wire)))
}

/// Execute and return the exact v4 batch journal bytes committed by the guest.
#[wasm_bindgen]
pub fn batch_journal_borsh_hex_v4(witness_json: &str) -> Result<String, JsError> {
    let wire = parse_batch_witness_json_v4(witness_json).map_err(|e| JsError::new(&e))?;
    let input = wire.to_input().map_err(|e| JsError::new(&e))?;
    let journal = execute_batch_core_v4(&input).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex_encode(&batch_journal_to_borsh_v4(&journal)))
}
