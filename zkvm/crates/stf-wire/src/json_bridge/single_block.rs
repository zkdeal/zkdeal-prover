//! Single-block TS bridge: the `StfWitness` reader, the `StfJournal` writer
//! and the l2-engine-compatible post-state dump that closes the loop between
//! consecutive blocks.

use serde_json::{Map, Value};

use super::scalars::{get, hex0x, parse_b32, parse_hex_bytes, parse_u256_flex, parse_u64_flex};
use crate::block_v1::{AccountWire, EnvWire, HistoricalBlockHashWire, StfInputWire};
use stf_types::StfJournal;

/// Parse the TS `StfWitness` JSON into the borsh wire input.
///
/// Tolerant on number encodings (decimal strings from the TS host,
/// 0x-hex from fixtures). Account order is normalized to ascending
/// address; storage to ascending slot; zero storage values dropped —
/// so the wire bytes are canonical for a given logical witness.
pub fn parse_witness_json(witness_json: &str) -> Result<StfInputWire, String> {
    let root: Value =
        serde_json::from_str(witness_json).map_err(|e| format!("witness JSON: {e}"))?;
    let obj = root.as_object().ok_or("witness: not an object")?;

    let room_id = parse_u64_flex(get(obj, "roomId")?, "roomId")?;
    let block_number = parse_u64_flex(get(obj, "blockNumber")?, "blockNumber")?;
    let prev_state_root = parse_b32(
        get(obj, "prevStateRoot")?
            .as_str()
            .ok_or("prevStateRoot: not a string")?,
        "prevStateRoot",
    )?;

    let dump_json = get(obj, "stateDumpJson")?
        .as_str()
        .ok_or("stateDumpJson: not a string")?;
    let dump: Value = serde_json::from_str(dump_json).map_err(|e| format!("stateDumpJson: {e}"))?;
    let dump_obj = dump.as_object().ok_or("stateDumpJson: not an object")?;

    let mut state: Vec<AccountWire> = Vec::with_capacity(dump_obj.len());
    for (addr_hex, entry) in dump_obj {
        let e = entry
            .as_object()
            .ok_or_else(|| format!("account {addr_hex}: not an object"))?;
        let addr_bytes = parse_hex_bytes(addr_hex, "account address")?;
        if addr_bytes.len() != 20 {
            return Err(format!("account address {addr_hex}: not 20 bytes"));
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(&addr_bytes);

        let nonce = parse_u64_flex(get(e, "nonce")?, "nonce")?;
        let balance = parse_u256_flex(get(e, "balance")?, "balance")?.to_be_bytes::<32>();
        let code = match e.get("code") {
            Some(Value::String(s)) => parse_hex_bytes(s, "code")?,
            Some(Value::Null) | None => Vec::new(),
            _ => return Err(format!("account {addr_hex}: code not a string")),
        };

        let mut storage: Vec<([u8; 32], [u8; 32])> = Vec::new();
        if let Some(st) = e.get("storage") {
            let st = st
                .as_object()
                .ok_or_else(|| format!("account {addr_hex}: storage not an object"))?;
            for (slot_hex, val) in st {
                let slot = parse_b32(slot_hex, "storage slot")?;
                let val_str = val
                    .as_str()
                    .ok_or_else(|| format!("storage value for {slot_hex}: not a string"))?;
                let value = parse_b32(val_str, "storage value")?;
                if value != [0u8; 32] {
                    storage.push((slot, value));
                }
            }
        }
        storage.sort_by(|a, b| a.0.cmp(&b.0));
        state.push(AccountWire {
            address,
            nonce,
            balance,
            code,
            storage,
        });
    }
    state.sort_by(|a, b| a.address.cmp(&b.address));

    let raw_txs_v = get(obj, "rawTxs")?
        .as_array()
        .ok_or("rawTxs: not an array")?;
    let mut raw_txs = Vec::with_capacity(raw_txs_v.len());
    for (i, t) in raw_txs_v.iter().enumerate() {
        let s = t
            .as_str()
            .ok_or_else(|| format!("rawTxs[{i}]: not a string"))?;
        raw_txs.push(parse_hex_bytes(s, "rawTx")?);
    }

    let env_v = get(obj, "env")?.as_object().ok_or("env: not an object")?;
    let env = EnvWire {
        timestamp: parse_u64_flex(get(env_v, "timestamp")?, "env.timestamp")?,
        gas_limit: parse_u64_flex(get(env_v, "gasLimit")?, "env.gasLimit")?,
    };
    let mut block_hashes = Vec::new();
    if let Some(entries) = obj.get("blockHashes") {
        let entries = entries.as_array().ok_or("blockHashes: not an array")?;
        block_hashes.reserve(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let entry = entry
                .as_object()
                .ok_or_else(|| format!("blockHashes[{index}]: not an object"))?;
            block_hashes.push(HistoricalBlockHashWire {
                number: parse_u64_flex(
                    get(entry, "number")?,
                    &format!("blockHashes[{index}].number"),
                )?,
                hash: parse_b32(
                    get(entry, "hash")?
                        .as_str()
                        .ok_or_else(|| format!("blockHashes[{index}].hash: not a string"))?,
                    &format!("blockHashes[{index}].hash"),
                )?,
            });
        }
    }

    Ok(StfInputWire {
        room_id,
        block_number,
        prev_state_root,
        state,
        raw_txs,
        env,
        block_hashes,
    })
}

/// Journal in the exact TS `StfJournal` JSON shape (decimal ids, lowercase hex).
pub fn journal_to_ts_value(j: &StfJournal) -> Value {
    serde_json::json!({
        "v": j.v,
        "roomId": j.room_id.to_string(),
        "blockNumber": j.block_number.to_string(),
        "prevStateRoot": hex0x(j.prev_state_root.as_slice()),
        "postStateRoot": hex0x(j.post_state_root.as_slice()),
        "txCommitment": hex0x(j.tx_commitment.as_slice()),
        "envHash": hex0x(j.env_hash.as_slice()),
    })
}

/// Post-state as an l2-engine-compatible SLOT-keyed state dump JSON
/// (`Record<address, { nonce, balance, code?, storage }>`; decimal
/// nonce/balance, minimal-length hex storage values). This is fed back
/// into [`parse_witness_json`] as the next block's `stateDumpJson`, which
/// keeps the witness chain running on the wasm STF alone.
pub fn post_state_to_dump_json(post: &stf_core::StateMap) -> String {
    let mut out = Map::new();
    for (address, rec) in &post.accounts {
        let mut acct = Map::new();
        acct.insert("nonce".into(), Value::String(rec.nonce.to_string()));
        acct.insert("balance".into(), Value::String(rec.balance.to_string()));
        if !rec.code.is_empty() {
            acct.insert("code".into(), Value::String(hex0x(&rec.code)));
        }
        let mut storage = Map::new();
        for (slot, value) in &rec.storage {
            if value.is_zero() {
                continue;
            }
            let vbytes = value.to_be_bytes::<32>();
            let first = vbytes.iter().position(|b| *b != 0).unwrap_or(31);
            storage.insert(
                hex0x(&slot.to_be_bytes::<32>()),
                Value::String(hex0x(&vbytes[first..])),
            );
        }
        acct.insert("storage".into(), Value::Object(storage));
        out.insert(hex0x(address.as_slice()), Value::Object(acct));
    }
    Value::Object(out).to_string()
}
