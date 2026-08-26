//! wasm-bindgen wrapper around the risc0 receipt verifier (verify-only
//! build; S2-validated: succinct verify ≈ 47 ms in Node 22).
//!
//! Built with `wasm-pack build --target web`; loaded in Node by handing the
//! wasm bytes to `init` (see packages/zkvm/src/backends/stf-exec.ts loader).

use risc0_zkvm::{sha::Digest, Receipt};
use wasm_bindgen::prelude::*;

/// Verify a (succinct) receipt against an image id (hex, 0x optional).
/// Returns the journal bytes (113-byte borsh StfJournal) on success.
///
/// The name records the intended input, not a constraint: `Receipt::verify`
/// accepts any inner kind the receipt carries. Callers that need the kind must
/// inspect it with [`receipt_kind`]. Dev-mode receipts are rejected — the crate
/// compiles `risc0-zkvm` with `disable-dev-mode`.
#[wasm_bindgen]
pub fn verify_succinct(receipt_bytes: &[u8], image_id_hex: &str) -> Result<Vec<u8>, JsError> {
    let receipt: Receipt = bincode::deserialize(receipt_bytes)
        .map_err(|e| JsError::new(&format!("receipt decode: {e}")))?;
    let id_bytes: [u8; 32] = hex::decode(image_id_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("image id hex: {e}")))?
        .try_into()
        .map_err(|_| JsError::new("image id must be 32 bytes"))?;
    let image_id = Digest::from(id_bytes);
    receipt
        .verify(image_id)
        .map_err(|e| JsError::new(&format!("verify failed: {e}")))?;
    Ok(receipt.journal.bytes)
}

/// Kind of the inner receipt ("succinct", "composite", ...) for diagnostics.
#[wasm_bindgen]
pub fn receipt_kind(receipt_bytes: &[u8]) -> Result<String, JsError> {
    let receipt: Receipt = bincode::deserialize(receipt_bytes)
        .map_err(|e| JsError::new(&format!("receipt decode: {e}")))?;
    let kind = if receipt.inner.succinct().is_ok() {
        "succinct"
    } else if receipt.inner.composite().is_ok() {
        "composite"
    } else {
        "other"
    };
    Ok(kind.to_string())
}
