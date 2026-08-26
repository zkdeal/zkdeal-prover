//! Magic-prefixed framing for the four v4 guest-input families. Each witness
//! kind carries a distinct four-byte tag so a proof request can never be
//! decoded as a different statement, and every decoder enforces the global
//! witness byte cap before touching the borsh body.

use borsh::BorshDeserialize;

use crate::batch_input_v4::{BatchInputWireV4, GenesisInputWireV4};
use crate::cold_input_v4::{ColdRoomInputWireV4, ComposedBatchInputWireV4};

const BATCH_INPUT_MAGIC_V4: &[u8; 4] = b"ZK4B";
const GENESIS_INPUT_MAGIC_V4: &[u8; 4] = b"ZK4G";
const COLD_INPUT_MAGIC_V4: &[u8; 4] = b"ZK4K";
const COMPOSED_BATCH_INPUT_MAGIC_V4: &[u8; 4] = b"ZK4C";

pub fn batch_input_to_borsh_v4(w: &BatchInputWireV4) -> Vec<u8> {
    let body = borsh::to_vec(w).expect("batch input borsh encode cannot fail");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(BATCH_INPUT_MAGIC_V4);
    out.extend_from_slice(&body);
    out
}

pub fn batch_input_from_borsh_v4(bytes: &[u8]) -> Result<BatchInputWireV4, String> {
    if bytes.len() > stf_types::MAX_BATCH_WITNESS_BYTES_V4 {
        return Err(format!(
            "v4 batch witness is {} bytes; cap is {}",
            bytes.len(),
            stf_types::MAX_BATCH_WITNESS_BYTES_V4
        ));
    }
    let body = bytes
        .strip_prefix(BATCH_INPUT_MAGIC_V4)
        .ok_or("v4 batch input magic missing")?;
    BatchInputWireV4::try_from_slice(body).map_err(|e| format!("v4 batch input borsh: {e}"))
}

pub fn genesis_input_to_borsh_v4(w: &GenesisInputWireV4) -> Vec<u8> {
    let body = borsh::to_vec(w).expect("genesis input borsh encode cannot fail");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(GENESIS_INPUT_MAGIC_V4);
    out.extend_from_slice(&body);
    out
}

pub fn genesis_input_from_borsh_v4(bytes: &[u8]) -> Result<GenesisInputWireV4, String> {
    if bytes.len() > stf_types::MAX_BATCH_WITNESS_BYTES_V4 {
        return Err(format!(
            "v4 genesis witness is {} bytes; cap is {}",
            bytes.len(),
            stf_types::MAX_BATCH_WITNESS_BYTES_V4
        ));
    }
    let body = bytes
        .strip_prefix(GENESIS_INPUT_MAGIC_V4)
        .ok_or("v4 genesis input magic missing")?;
    GenesisInputWireV4::try_from_slice(body).map_err(|e| format!("v4 genesis input borsh: {e}"))
}

pub fn cold_input_to_borsh_v4(w: &ColdRoomInputWireV4) -> Vec<u8> {
    let body = borsh::to_vec(w).expect("cold input borsh encode cannot fail");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(COLD_INPUT_MAGIC_V4);
    out.extend_from_slice(&body);
    out
}

pub fn cold_input_from_borsh_v4(bytes: &[u8]) -> Result<ColdRoomInputWireV4, String> {
    if bytes.len() > stf_types::MAX_BATCH_WITNESS_BYTES_V4 {
        return Err(format!(
            "v4 cold witness is {} bytes; cap is {}",
            bytes.len(),
            stf_types::MAX_BATCH_WITNESS_BYTES_V4
        ));
    }
    let body = bytes
        .strip_prefix(COLD_INPUT_MAGIC_V4)
        .ok_or_else(|| "cold input magic mismatch".to_owned())?;
    ColdRoomInputWireV4::try_from_slice(body).map_err(|e| format!("cold input borsh: {e}"))
}

pub fn composed_batch_input_to_borsh_v4(w: &ComposedBatchInputWireV4) -> Vec<u8> {
    let body = borsh::to_vec(w).expect("composed batch input borsh encode cannot fail");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(COMPOSED_BATCH_INPUT_MAGIC_V4);
    out.extend_from_slice(&body);
    out
}

pub fn composed_batch_input_from_borsh_v4(
    bytes: &[u8],
) -> Result<ComposedBatchInputWireV4, String> {
    if bytes.len() > stf_types::MAX_BATCH_WITNESS_BYTES_V4 {
        return Err(format!(
            "v4 composed witness is {} bytes; cap is {}",
            bytes.len(),
            stf_types::MAX_BATCH_WITNESS_BYTES_V4
        ));
    }
    let body = bytes
        .strip_prefix(COMPOSED_BATCH_INPUT_MAGIC_V4)
        .ok_or_else(|| "composed batch input magic mismatch".to_owned())?;
    ComposedBatchInputWireV4::try_from_slice(body)
        .map_err(|e| format!("composed batch input borsh: {e}"))
}
