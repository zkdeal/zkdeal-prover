//! Readers for the TypeScript-produced cold/composed spec JSON: tolerant
//! scalar accessors plus the cold-witness section of the document.

use alloy_primitives::U256;
use serde_json::Value;
use stf_wire::{
    AccountWire, BatchBlockWireV4, ColdRoomInputWireV4, ColdRuntimeCodeWireV4,
    ColdStateAccessWireV4, ColdStateRefreshWireV4, EnvWire,
};

use crate::{invalid, DynResult};

pub(crate) fn field<'a>(value: &'a Value, name: &str) -> DynResult<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| invalid(format!("missing field {name}")))
}

pub(crate) fn array<'a>(value: &'a Value, label: &str) -> DynResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| invalid(format!("{label} must be an array")))
}

pub(crate) fn string<'a>(value: &'a Value, label: &str) -> DynResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| invalid(format!("{label} must be a string")))
}

pub(crate) fn bool_value(value: &Value, label: &str) -> DynResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| invalid(format!("{label} must be a boolean")))
}

pub(crate) fn u64_value(value: &Value, label: &str) -> DynResult<u64> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    let raw = string(value, label)?;
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|error| invalid(format!("{label}: {error}")))
    } else {
        raw.parse::<u64>()
            .map_err(|error| invalid(format!("{label}: {error}")))
    }
}

pub(crate) fn decode_hex(value: &str, label: &str) -> DynResult<Vec<u8>> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("{label} must start with 0x")))?;
    if raw.len() % 2 != 0 {
        return Err(invalid(format!("{label} must contain whole bytes")));
    }
    (0..raw.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&raw[offset..offset + 2], 16)
                .map_err(|error| invalid(format!("{label}: {error}")))
        })
        .collect()
}

pub(crate) fn fixed<const N: usize>(value: &Value, label: &str) -> DynResult<[u8; N]> {
    let bytes = decode_hex(string(value, label)?, label)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        invalid(format!("{label} is {} bytes, expected {N}", bytes.len()))
    })
}

pub(crate) fn word(value: &Value, label: &str) -> DynResult<[u8; 32]> {
    let raw = if let Some(value) = value.as_u64() {
        value.to_string()
    } else {
        string(value, label)?.to_owned()
    };
    let parsed = if let Some(hex) = raw.strip_prefix("0x") {
        if hex.is_empty() {
            U256::ZERO
        } else {
            U256::from_str_radix(hex, 16).map_err(|error| invalid(format!("{label}: {error}")))?
        }
    } else {
        U256::from_str_radix(&raw, 10).map_err(|error| invalid(format!("{label}: {error}")))?
    };
    Ok(parsed.to_be_bytes::<32>())
}

pub(crate) fn bytes_field(value: &Value, label: &str) -> DynResult<Vec<u8>> {
    decode_hex(string(value, label)?, label)
}

fn parse_initial_state(cold: &Value) -> DynResult<Vec<AccountWire>> {
    array(field(cold, "initialState")?, "cold.initialState")?
        .iter()
        .enumerate()
        .map(|(index, account)| {
            let prefix = format!("cold.initialState[{index}]");
            let storage = array(field(account, "storage")?, &format!("{prefix}.storage"))?
                .iter()
                .enumerate()
                .map(|(slot_index, entry)| {
                    Ok((
                        word(
                            field(entry, "slot")?,
                            &format!("{prefix}.storage[{slot_index}].slot"),
                        )?,
                        word(
                            field(entry, "value")?,
                            &format!("{prefix}.storage[{slot_index}].value"),
                        )?,
                    ))
                })
                .collect::<DynResult<Vec<_>>>()?;
            Ok(AccountWire {
                address: fixed(field(account, "address")?, &format!("{prefix}.address"))?,
                nonce: u64_value(field(account, "nonce")?, &format!("{prefix}.nonce"))?,
                balance: word(field(account, "balance")?, &format!("{prefix}.balance"))?,
                code: bytes_field(field(account, "code")?, &format!("{prefix}.code"))?,
                storage,
            })
        })
        .collect()
}

fn parse_setup_blocks(cold: &Value) -> DynResult<Vec<BatchBlockWireV4>> {
    array(field(cold, "setupBlocks")?, "cold.setupBlocks")?
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let prefix = format!("cold.setupBlocks[{index}]");
            let env = field(block, "env")?;
            Ok(BatchBlockWireV4 {
                block_number: u64_value(
                    field(block, "blockNumber")?,
                    &format!("{prefix}.blockNumber"),
                )?,
                raw_txs: array(field(block, "rawTxs")?, &format!("{prefix}.rawTxs"))?
                    .iter()
                    .enumerate()
                    .map(|(tx_index, raw)| {
                        bytes_field(raw, &format!("{prefix}.rawTxs[{tx_index}]"))
                    })
                    .collect::<DynResult<Vec<_>>>()?,
                env: EnvWire {
                    timestamp: u64_value(
                        field(env, "timestamp")?,
                        &format!("{prefix}.env.timestamp"),
                    )?,
                    gas_limit: u64_value(
                        field(env, "gasLimit")?,
                        &format!("{prefix}.env.gasLimit"),
                    )?,
                },
                expected_post_state_root: fixed(
                    field(block, "expectedPostStateRoot")?,
                    &format!("{prefix}.expectedPostStateRoot"),
                )?,
            })
        })
        .collect()
}

fn parse_runtime(cold: &Value) -> DynResult<Vec<ColdRuntimeCodeWireV4>> {
    array(field(cold, "runtimeCode")?, "cold.runtimeCode")?
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            Ok(ColdRuntimeCodeWireV4 {
                address: fixed(
                    field(entry, "address")?,
                    &format!("cold.runtimeCode[{index}].address"),
                )?,
                code_hash: fixed(
                    field(entry, "codeHash")?,
                    &format!("cold.runtimeCode[{index}].codeHash"),
                )?,
            })
        })
        .collect()
}

fn parse_access(cold: &Value) -> DynResult<Vec<ColdStateAccessWireV4>> {
    array(field(cold, "stateAccess")?, "cold.stateAccess")?
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            Ok(ColdStateAccessWireV4 {
                address: fixed(
                    field(entry, "address")?,
                    &format!("cold.stateAccess[{index}].address"),
                )?,
                storage_slots: array(
                    field(entry, "storageSlots")?,
                    &format!("cold.stateAccess[{index}].storageSlots"),
                )?
                .iter()
                .enumerate()
                .map(|(slot, value)| {
                    word(
                        value,
                        &format!("cold.stateAccess[{index}].storageSlots[{slot}]"),
                    )
                })
                .collect::<DynResult<Vec<_>>>()?,
            })
        })
        .collect()
}

fn parse_refresh(cold: &Value) -> DynResult<Vec<ColdStateRefreshWireV4>> {
    array(field(cold, "stateRefresh")?, "cold.stateRefresh")?
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            Ok(ColdStateRefreshWireV4 {
                address: fixed(
                    field(entry, "address")?,
                    &format!("cold.stateRefresh[{index}].address"),
                )?,
                refresh_nonce: bool_value(
                    field(entry, "refreshNonce")?,
                    &format!("cold.stateRefresh[{index}].refreshNonce"),
                )?,
                refresh_balance: bool_value(
                    field(entry, "refreshBalance")?,
                    &format!("cold.stateRefresh[{index}].refreshBalance"),
                )?,
                refresh_all_storage: bool_value(
                    field(entry, "refreshAllStorage")?,
                    &format!("cold.stateRefresh[{index}].refreshAllStorage"),
                )?,
                storage_slots: array(
                    field(entry, "storageSlots")?,
                    &format!("cold.stateRefresh[{index}].storageSlots"),
                )?
                .iter()
                .enumerate()
                .map(|(slot, value)| {
                    word(
                        value,
                        &format!("cold.stateRefresh[{index}].storageSlots[{slot}]"),
                    )
                })
                .collect::<DynResult<Vec<_>>>()?,
            })
        })
        .collect()
}

pub(crate) fn parse_cold_wire(cold: &Value) -> DynResult<ColdRoomInputWireV4> {
    Ok(ColdRoomInputWireV4 {
        v: u64_value(field(cold, "v")?, "cold.v")?
            .try_into()
            .map_err(|_| invalid("cold.v exceeds u8"))?,
        compiled_bundle_hash: fixed(
            field(cold, "compiledBundleHash")?,
            "cold.compiledBundleHash",
        )?,
        preset_hash: fixed(field(cold, "presetHash")?, "cold.presetHash")?,
        manifest_hash: fixed(field(cold, "manifestHash")?, "cold.manifestHash")?,
        proof_program_id: fixed(field(cold, "proofProgramId")?, "cold.proofProgramId")?,
        initial_state_root: fixed(field(cold, "initialStateRoot")?, "cold.initialStateRoot")?,
        initialized_state_root: fixed(
            field(cold, "initializedStateRoot")?,
            "cold.initializedStateRoot",
        )?,
        analyzed_artifact_root: fixed(
            field(cold, "analyzedArtifactRoot")?,
            "cold.analyzedArtifactRoot",
        )?,
        allowed_call_target_root: fixed(
            field(cold, "allowedCallTargetRoot")?,
            "cold.allowedCallTargetRoot",
        )?,
        initial_state: parse_initial_state(cold)?,
        setup_blocks: parse_setup_blocks(cold)?,
        runtime_code: parse_runtime(cold)?,
        state_access: parse_access(cold)?,
        state_refresh: parse_refresh(cold)?,
    })
}
