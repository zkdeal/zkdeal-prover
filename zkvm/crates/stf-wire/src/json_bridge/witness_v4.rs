//! TS `BatchWitnessV4` / `GenesisWitnessV4` readers. Genesis reuses the batch
//! reader through a synthetic object so opening and normal batches cannot
//! drift to different witness codecs.

use serde_json::Value;

use super::scalars::{get, parse_b32, parse_hex_bytes, parse_u256_flex, parse_u64_flex};
use super::witness_fields_v4::{
    parse_asset_totals, parse_exit_allocations, parse_inbox_entries, parse_membership_deltas,
    parse_residual_allocations, parse_roster_slots,
};
use crate::batch_input_v4::{
    BatchBlockWireV4, BatchInputWireV4, CompactAccountWireV4, CompactStateWireV4,
    CompactStorageWireV4, GenesisInputWireV4, MemberSlotWireV4,
};
use crate::block_v1::EnvWire;

/// Parse the TS `BatchWitnessV4` shape. V4 deliberately has no
/// `stateDumpJson` compatibility path: callers must supply the complete
/// room-local `full-room-state-v1` prestate and explicit access envelope.
/// Canonical-MPT proof fields are reserved and rejected in this version.
pub fn parse_batch_witness_json_v4(witness_json: &str) -> Result<BatchInputWireV4, String> {
    if witness_json.len() > stf_types::MAX_BATCH_WITNESS_BYTES_V4 {
        return Err(format!(
            "v4 batch witness is {} bytes; cap is {}",
            witness_json.len(),
            stf_types::MAX_BATCH_WITNESS_BYTES_V4
        ));
    }
    let root: Value =
        serde_json::from_str(witness_json).map_err(|e| format!("batch witness JSON: {e}"))?;
    let obj = root.as_object().ok_or("batch witness: not an object")?;
    let version = parse_u64_flex(get(obj, "v")?, "v")?;
    if version != u64::from(stf_types::BATCH_JOURNAL_VERSION_V4) {
        return Err(format!("batch input version {version} != 4"));
    }
    let blocks = get(obj, "blocks")?
        .as_array()
        .ok_or("blocks: not an array")?;
    if blocks.is_empty() || blocks.len() > stf_types::MAX_BATCH_BLOCKS_V4 {
        return Err(format!(
            "blocks length {} outside 1..={} ",
            blocks.len(),
            stf_types::MAX_BATCH_BLOCKS_V4
        ));
    }

    let room_id = parse_u64_flex(get(obj, "roomId")?, "roomId")?;
    let prev_state_root = parse_b32(
        get(obj, "preStateRoot")?
            .as_str()
            .ok_or("preStateRoot: not a string")?,
        "preStateRoot",
    )?;

    let preset_value = get(obj, "preset")?;
    if !preset_value.is_object() {
        return Err("preset: not an object".into());
    }
    let canonical_preset_json =
        serde_json::to_vec(preset_value).map_err(|e| format!("preset canonical JSON: {e}"))?;
    let exit_program_value = get(obj, "exitProgram")?;
    if !exit_program_value.is_object() {
        return Err("exitProgram: not an object".into());
    }
    let canonical_exit_program_json = serde_json::to_vec(exit_program_value)
        .map_err(|e| format!("exit program canonical JSON: {e}"))?;

    let roster_json = get(obj, "preRosterSlots")?
        .as_array()
        .ok_or("preRosterSlots: not an array")?;
    let mut pre_roster_slots = Vec::with_capacity(roster_json.len());
    for (slot_index, slot_json) in roster_json.iter().enumerate() {
        let label = format!("preRosterSlots[{slot_index}]");
        let slot = slot_json
            .as_object()
            .ok_or_else(|| format!("{label}: not an object"))?;
        let slot_number = parse_u64_flex(get(slot, "slot")?, &format!("{label}.slot"))?;
        let state = parse_u64_flex(get(slot, "state")?, &format!("{label}.state"))?;
        if slot_number > u8::MAX as u64 || state > u8::MAX as u64 {
            return Err(format!("{label}: slot/state exceeds u8"));
        }
        let account_bytes = parse_hex_bytes(
            get(slot, "account")?
                .as_str()
                .ok_or_else(|| format!("{label}.account: not a string"))?,
            &format!("{label}.account"),
        )?;
        if account_bytes.len() != 20 {
            return Err(format!("{label}.account: not 20 bytes"));
        }
        let mut account = [0u8; 20];
        account.copy_from_slice(&account_bytes);
        let retired_at_batch = match get(slot, "retiredAtBatch")? {
            Value::Null => None,
            value => Some(parse_u64_flex(value, &format!("{label}.retiredAtBatch"))?),
        };
        pre_roster_slots.push(MemberSlotWireV4 {
            slot: slot_number as u8,
            state: state as u8,
            account,
            joined_at_batch: parse_u64_flex(
                get(slot, "joinedAtBatch")?,
                &format!("{label}.joinedAtBatch"),
            )?,
            retired_at_batch,
        });
    }

    let compact = get(obj, "compactState")?
        .as_object()
        .ok_or("compactState: not an object")?;
    let canonical_state_root = parse_b32(
        get(compact, "canonicalStateRoot")?
            .as_str()
            .ok_or("compactState.canonicalStateRoot: not a string")?,
        "compactState.canonicalStateRoot",
    )?;
    let accounts_json = get(compact, "accounts")?
        .as_array()
        .ok_or("compactState.accounts: not an array")?;
    let mut accounts = Vec::with_capacity(accounts_json.len());
    for (account_index, account_json) in accounts_json.iter().enumerate() {
        let label = format!("compactState.accounts[{account_index}]");
        let account = account_json
            .as_object()
            .ok_or_else(|| format!("{label}: not an object"))?;
        let address_bytes = parse_hex_bytes(
            get(account, "address")?
                .as_str()
                .ok_or_else(|| format!("{label}.address: not a string"))?,
            &format!("{label}.address"),
        )?;
        if address_bytes.len() != 20 {
            return Err(format!("{label}.address: not 20 bytes"));
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_bytes);

        let parse_proof = |value: &Value, proof_label: &str| -> Result<Vec<Vec<u8>>, String> {
            value
                .as_array()
                .ok_or_else(|| format!("{proof_label}: not an array"))?
                .iter()
                .enumerate()
                .map(|(i, node)| {
                    parse_hex_bytes(
                        node.as_str()
                            .ok_or_else(|| format!("{proof_label}[{i}]: not a string"))?,
                        &format!("{proof_label}[{i}]"),
                    )
                })
                .collect()
        };

        let storage_json = get(account, "storage")?
            .as_array()
            .ok_or_else(|| format!("{label}.storage: not an array"))?;
        let mut storage = Vec::with_capacity(storage_json.len());
        for (slot_index, slot_json) in storage_json.iter().enumerate() {
            let slot_label = format!("{label}.storage[{slot_index}]");
            let slot_obj = slot_json
                .as_object()
                .ok_or_else(|| format!("{slot_label}: not an object"))?;
            let slot = parse_u256_flex(get(slot_obj, "slot")?, &format!("{slot_label}.slot"))?
                .to_be_bytes::<32>();
            let value = parse_u256_flex(get(slot_obj, "value")?, &format!("{slot_label}.value"))?
                .to_be_bytes::<32>();
            storage.push(CompactStorageWireV4 {
                slot,
                value,
                proof: parse_proof(get(slot_obj, "proof")?, &format!("{slot_label}.proof"))?,
            });
        }

        let code = parse_hex_bytes(
            get(account, "code")?
                .as_str()
                .ok_or_else(|| format!("{label}.code: not a string"))?,
            &format!("{label}.code"),
        )?;
        accounts.push(CompactAccountWireV4 {
            address,
            exists: get(account, "exists")?
                .as_bool()
                .ok_or_else(|| format!("{label}.exists: not a boolean"))?,
            nonce: parse_u64_flex(get(account, "nonce")?, &format!("{label}.nonce"))?,
            balance: parse_u256_flex(get(account, "balance")?, &format!("{label}.balance"))?
                .to_be_bytes::<32>(),
            code,
            canonical_storage_root: parse_b32(
                get(account, "canonicalStorageRoot")?
                    .as_str()
                    .ok_or_else(|| format!("{label}.canonicalStorageRoot: not a string"))?,
                &format!("{label}.canonicalStorageRoot"),
            )?,
            account_proof: parse_proof(
                get(account, "accountProof")?,
                &format!("{label}.accountProof"),
            )?,
            storage,
        });
    }

    let mut parsed_blocks = Vec::with_capacity(blocks.len());
    for (i, block) in blocks.iter().enumerate() {
        let b = block
            .as_object()
            .ok_or_else(|| format!("blocks[{i}]: not an object"))?;
        let block_number =
            parse_u64_flex(get(b, "blockNumber")?, &format!("blocks[{i}].blockNumber"))?;
        let raw_json = get(b, "rawTxs")?
            .as_array()
            .ok_or_else(|| format!("blocks[{i}].rawTxs: not an array"))?;
        let mut raw_txs = Vec::with_capacity(raw_json.len());
        for (tx_index, raw) in raw_json.iter().enumerate() {
            raw_txs.push(parse_hex_bytes(
                raw.as_str()
                    .ok_or_else(|| format!("blocks[{i}].rawTxs[{tx_index}]: not a string"))?,
                &format!("blocks[{i}].rawTxs[{tx_index}]"),
            )?);
        }
        let env_json = get(b, "env")?
            .as_object()
            .ok_or_else(|| format!("blocks[{i}].env: not an object"))?;
        parsed_blocks.push(BatchBlockWireV4 {
            block_number,
            raw_txs,
            env: EnvWire {
                timestamp: parse_u64_flex(
                    get(env_json, "timestamp")?,
                    &format!("blocks[{i}].env.timestamp"),
                )?,
                gas_limit: parse_u64_flex(
                    get(env_json, "gasLimit")?,
                    &format!("blocks[{i}].env.gasLimit"),
                )?,
            },
            expected_post_state_root: parse_b32(
                get(b, "expectedPostStateRoot")?
                    .as_str()
                    .ok_or_else(|| format!("blocks[{i}].expectedPostStateRoot: not a string"))?,
                &format!("blocks[{i}].expectedPostStateRoot"),
            )?,
        });
    }

    let parse_hash = |key: &str| -> Result<[u8; 32], String> {
        parse_b32(
            get(obj, key)?
                .as_str()
                .ok_or_else(|| format!("{key}: not a string"))?,
            key,
        )
    };
    let active = parse_u64_flex(get(obj, "preActiveMask")?, "preActiveMask")?;
    let pre_used = parse_u64_flex(get(obj, "preUsedMask")?, "preUsedMask")?;
    let post_active = parse_u64_flex(get(obj, "postActiveMask")?, "postActiveMask")?;
    let used = parse_u64_flex(get(obj, "usedMask")?, "usedMask")?;
    if active > u8::MAX as u64
        || pre_used > u8::MAX as u64
        || post_active > u8::MAX as u64
        || used > u8::MAX as u64
    {
        return Err("member mask exceeds u8".into());
    }

    Ok(BatchInputWireV4 {
        v: stf_types::BATCH_JOURNAL_VERSION_V4,
        deployment_id: parse_hash("deploymentDomain")?,
        room_id,
        preset_hash: parse_hash("presetHash")?,
        manifest_hash: parse_hash("manifestHash")?,
        proof_program_id: parse_hash("proofProgramId")?,
        batch_index: parse_u64_flex(get(obj, "batchIndex")?, "batchIndex")?,
        l2_start_height: parse_u64_flex(get(obj, "startL2Block")?, "startL2Block")?,
        previous_block_timestamp: parse_u64_flex(
            get(obj, "previousBlockTimestamp")?,
            "previousBlockTimestamp",
        )?,
        prev_state_root,
        pre_roster_root: parse_hash("preRosterRoot")?,
        post_roster_root: parse_hash("postRosterRoot")?,
        active_mask: active as u8,
        pre_used_mask: pre_used as u8,
        post_active_mask: post_active as u8,
        used_mask: used as u8,
        inbox_start: parse_u64_flex(get(obj, "inboxCursorBefore")?, "inboxCursorBefore")?,
        inbox_end: parse_u64_flex(get(obj, "inboxCursorAfter")?, "inboxCursorAfter")?,
        inbox_inputs_hash: parse_hash("inboxInputsHash")?,
        expected_block_data_hash: parse_hash("batchDataHash")?,
        asset_totals_hash: parse_hash("assetTotalsHash")?,
        exit_totals_hash: parse_hash("exitTotalsHash")?,
        fee_totals_hash: parse_hash("feeTotalsHash")?,
        membership_deltas_hash: parse_hash("membershipDeltasHash")?,
        previous_exit_root: parse_hash("previousExitRoot")?,
        exit_root: parse_hash("exitRoot")?,
        close: get(obj, "close")?.as_bool().ok_or("close: not a boolean")?,
        l1_inclusion_deadline: parse_u64_flex(
            get(obj, "l1InclusionDeadline")?,
            "l1InclusionDeadline",
        )?,
        canonical_preset_json,
        canonical_exit_program_json,
        pre_roster_slots,
        post_roster_slots: parse_roster_slots(get(obj, "postRosterSlots")?, "postRosterSlots")?,
        membership_deltas: parse_membership_deltas(get(obj, "membershipDeltas")?)?,
        inbox_entries: parse_inbox_entries(get(obj, "inboxEntries")?)?,
        asset_totals: parse_asset_totals(get(obj, "assetTotals")?)?,
        residual_allocations: parse_residual_allocations(get(obj, "residualAllocations")?)?,
        previous_exit_allocations: parse_exit_allocations(
            get(obj, "previousExitAllocations")?,
            "previousExitAllocations",
        )?,
        compact_state: CompactStateWireV4 {
            canonical_state_root,
            accounts,
        },
        blocks: parsed_blocks,
    })
}

/// Parse a `GenesisWitnessV4`. Shared preset/roster/compact-state fields
/// flow through the batch parser so opening and normal batches cannot
/// drift to different witness codecs.
pub fn parse_genesis_witness_json_v4(witness_json: &str) -> Result<GenesisInputWireV4, String> {
    if witness_json.len() > stf_types::MAX_BATCH_WITNESS_BYTES_V4 {
        return Err("v4 genesis witness exceeds the global witness cap".into());
    }
    let root: Value =
        serde_json::from_str(witness_json).map_err(|e| format!("genesis witness JSON: {e}"))?;
    let obj = root.as_object().ok_or("genesis witness: not an object")?;
    let hash = |key: &str| -> Result<[u8; 32], String> {
        parse_b32(
            get(obj, key)?
                .as_str()
                .ok_or_else(|| format!("{key}: not a string"))?,
            key,
        )
    };
    let room_id = parse_u64_flex(get(obj, "roomId")?, "roomId")?;
    let active = parse_u64_flex(get(obj, "activeMask")?, "activeMask")?;
    let used = parse_u64_flex(get(obj, "usedMask")?, "usedMask")?;
    if active > 0x7f || used > 0x7f {
        return Err("genesis member masks exceed seven slots".into());
    }
    if obj.contains_key("l1StateImports") {
        return Err(
            "l1StateImports is not part of v4 genesis; room-local state is fresh preset state"
                .into(),
        );
    }

    let mut synthetic = obj.clone();
    synthetic.insert("batchIndex".into(), Value::String("0".into()));
    synthetic.insert("startL2Block".into(), Value::String("0".into()));
    synthetic.insert("preStateRoot".into(), get(obj, "genesisStateRoot")?.clone());
    synthetic.insert(
        "preRosterRoot".into(),
        get(obj, "genesisRosterRoot")?.clone(),
    );
    synthetic.insert(
        "postRosterRoot".into(),
        get(obj, "genesisRosterRoot")?.clone(),
    );
    synthetic.insert("preActiveMask".into(), Value::from(active));
    synthetic.insert("preUsedMask".into(), Value::from(used));
    synthetic.insert("postActiveMask".into(), Value::from(active));
    synthetic.insert("inboxCursorBefore".into(), get(obj, "inboxCursor")?.clone());
    synthetic.insert("inboxCursorAfter".into(), get(obj, "inboxCursor")?.clone());
    synthetic.insert(
        "inboxInputsHash".into(),
        Value::String(format!("0x{}", "00".repeat(32))),
    );
    synthetic.insert(
        "batchDataHash".into(),
        Value::String(format!("0x{}", "00".repeat(32))),
    );
    synthetic.insert(
        "membershipDeltasHash".into(),
        Value::String(format!("0x{}", "00".repeat(32))),
    );
    synthetic.insert(
        "previousExitRoot".into(),
        get(obj, "genesisExitRoot")?.clone(),
    );
    synthetic.insert("exitRoot".into(), get(obj, "genesisExitRoot")?.clone());
    synthetic.insert("close".into(), Value::Bool(false));
    synthetic.insert("preRosterSlots".into(), get(obj, "rosterSlots")?.clone());
    synthetic.insert("postRosterSlots".into(), get(obj, "rosterSlots")?.clone());
    synthetic.insert("membershipDeltas".into(), Value::Array(Vec::new()));
    synthetic.insert("inboxEntries".into(), Value::Array(Vec::new()));
    synthetic.insert("previousExitAllocations".into(), Value::Array(Vec::new()));
    synthetic.insert(
        "blocks".into(),
        serde_json::json!([{
            "blockNumber": "0",
            "rawTxs": [],
            "expectedPostStateRoot": get(obj, "genesisStateRoot")?.clone(),
            "env": { "timestamp": "0", "gasLimit": "1" }
        }]),
    );
    let common = parse_batch_witness_json_v4(&Value::Object(synthetic).to_string())?;
    Ok(GenesisInputWireV4 {
        v: common.v,
        deployment_id: common.deployment_id,
        room_id,
        config_hash: hash("configHash")?,
        preset_hash: common.preset_hash,
        manifest_hash: common.manifest_hash,
        proof_program_id: common.proof_program_id,
        l1_block_number: parse_u64_flex(get(obj, "l1BlockNumber")?, "l1BlockNumber")?,
        l1_block_hash: hash("l1BlockHash")?,
        l1_state_root: hash("l1StateRoot")?,
        l1_header_rlp: parse_hex_bytes(
            get(obj, "l1HeaderRlp")?
                .as_str()
                .ok_or("l1HeaderRlp: not a string")?,
            "l1HeaderRlp",
        )?,
        genesis_state_root: hash("genesisStateRoot")?,
        genesis_roster_root: hash("genesisRosterRoot")?,
        genesis_exit_root: hash("genesisExitRoot")?,
        active_mask: active as u8,
        used_mask: used as u8,
        inbox_cursor: parse_u64_flex(get(obj, "inboxCursor")?, "inboxCursor")?,
        asset_totals_hash: common.asset_totals_hash,
        exit_totals_hash: common.exit_totals_hash,
        fee_totals_hash: common.fee_totals_hash,
        l1_inclusion_deadline: common.l1_inclusion_deadline,
        canonical_preset_json: common.canonical_preset_json,
        canonical_exit_program_json: common.canonical_exit_program_json,
        roster_slots: common.pre_roster_slots,
        asset_totals: common.asset_totals,
        residual_allocations: common.residual_allocations,
        compact_state: common.compact_state,
    })
}
