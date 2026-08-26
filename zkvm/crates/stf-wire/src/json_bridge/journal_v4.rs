//! The public v4 journal JSON shapes shared with TypeScript and Solidity:
//! readers that recompute the statement from the object, and writers that emit
//! the exact TS field names.

use alloy_primitives::B256;
use serde_json::Value;
use stf_types::{BatchJournalV4, GenesisJournalV4};

use super::scalars::{get, hex0x, parse_b32, parse_u64_flex};

/// Parse the public TypeScript/Solidity `BatchJournalV4` shape back into
/// the native journal. Verification uses this to recompute the statement
/// hash rather than trusting a caller-supplied `journalHash` next to an
/// arbitrary JSON object.
pub fn parse_batch_journal_json_v4(journal_json: &str) -> Result<BatchJournalV4, String> {
    let root: Value =
        serde_json::from_str(journal_json).map_err(|e| format!("journal JSON: {e}"))?;
    let obj = root.as_object().ok_or("batch journal: not an object")?;
    let hash = |key: &str| -> Result<B256, String> {
        Ok(B256::from(parse_b32(
            get(obj, key)?
                .as_str()
                .ok_or_else(|| format!("{key}: not a string"))?,
            key,
        )?))
    };
    let version = parse_u64_flex(get(obj, "protocolVersion")?, "protocolVersion")?;
    if version != 4 {
        return Err(format!("batch journal protocolVersion {version} != 4"));
    }
    let active = parse_u64_flex(get(obj, "preActiveMask")?, "preActiveMask")?;
    let post_active = parse_u64_flex(get(obj, "postActiveMask")?, "postActiveMask")?;
    let used = parse_u64_flex(get(obj, "usedMask")?, "usedMask")?;
    if active > u64::from(u8::MAX) || post_active > u64::from(u8::MAX) || used > u64::from(u8::MAX)
    {
        return Err("batch journal roster mask exceeds u8".into());
    }
    let blocks_value = get(obj, "blocks")?
        .as_array()
        .ok_or("batch journal blocks: not an array")?;
    let mut blocks = Vec::with_capacity(blocks_value.len());
    for (index, block) in blocks_value.iter().enumerate() {
        let block = block
            .as_object()
            .ok_or_else(|| format!("batch journal blocks[{index}]: not an object"))?;
        let block_hash = |key: &str| -> Result<B256, String> {
            Ok(B256::from(parse_b32(
                get(block, key)?
                    .as_str()
                    .ok_or_else(|| format!("blocks[{index}].{key}: not a string"))?,
                &format!("blocks[{index}].{key}"),
            )?))
        };
        blocks.push(stf_types::BatchBlockJournalV4 {
            block_number: parse_u64_flex(
                get(block, "blockNumber")?,
                &format!("blocks[{index}].blockNumber"),
            )?,
            post_state_root: block_hash("postStateRoot")?,
            tx_commitment: block_hash("txCommitment")?,
            env_hash: block_hash("envHash")?,
        });
    }
    Ok(BatchJournalV4 {
        v: version as u8,
        deployment_id: hash("deploymentDomain")?,
        room_id: parse_u64_flex(get(obj, "roomId")?, "roomId")?,
        preset_hash: hash("presetHash")?,
        manifest_hash: hash("manifestHash")?,
        proof_program_id: hash("proofProgramId")?,
        batch_index: parse_u64_flex(get(obj, "batchIndex")?, "batchIndex")?,
        l2_start_height: parse_u64_flex(get(obj, "startL2Block")?, "startL2Block")?,
        l2_end_height: parse_u64_flex(get(obj, "endL2Block")?, "endL2Block")?,
        previous_block_timestamp: parse_u64_flex(
            get(obj, "previousBlockTimestamp")?,
            "previousBlockTimestamp",
        )?,
        final_block_timestamp: parse_u64_flex(
            get(obj, "finalBlockTimestamp")?,
            "finalBlockTimestamp",
        )?,
        prev_state_root: hash("preStateRoot")?,
        post_state_root: hash("postStateRoot")?,
        block_roots_hash: hash("blockRootsHash")?,
        blocks,
        pre_roster_root: hash("preRosterRoot")?,
        post_roster_root: hash("postRosterRoot")?,
        active_mask: active as u8,
        post_active_mask: post_active as u8,
        used_mask: used as u8,
        inbox_start: parse_u64_flex(get(obj, "inboxCursorBefore")?, "inboxCursorBefore")?,
        inbox_end: parse_u64_flex(get(obj, "inboxCursorAfter")?, "inboxCursorAfter")?,
        inbox_inputs_hash: hash("inboxInputsHash")?,
        block_data_hash: hash("batchDataHash")?,
        asset_totals_hash: hash("assetTotalsHash")?,
        exit_totals_hash: hash("exitTotalsHash")?,
        fee_totals_hash: hash("feeTotalsHash")?,
        membership_deltas_hash: hash("membershipDeltasHash")?,
        previous_exit_root: hash("previousExitRoot")?,
        exit_root: hash("exitRoot")?,
        close: get(obj, "close")?.as_bool().ok_or("close: not a bool")?,
        l1_inclusion_deadline: parse_u64_flex(
            get(obj, "l1InclusionDeadline")?,
            "l1InclusionDeadline",
        )?,
        exit_allocations: Vec::new(),
        asset_accounting: Vec::new(),
    })
}

pub fn parse_genesis_journal_json_v4(journal_json: &str) -> Result<GenesisJournalV4, String> {
    let root: Value =
        serde_json::from_str(journal_json).map_err(|e| format!("journal JSON: {e}"))?;
    let obj = root.as_object().ok_or("genesis journal: not an object")?;
    let hash = |key: &str| -> Result<B256, String> {
        Ok(B256::from(parse_b32(
            get(obj, key)?
                .as_str()
                .ok_or_else(|| format!("{key}: not a string"))?,
            key,
        )?))
    };
    let version = parse_u64_flex(get(obj, "protocolVersion")?, "protocolVersion")?;
    let active = parse_u64_flex(get(obj, "activeMask")?, "activeMask")?;
    let used = parse_u64_flex(get(obj, "usedMask")?, "usedMask")?;
    if version != 4 || active > u64::from(u8::MAX) || used > u64::from(u8::MAX) {
        return Err("invalid genesis journal version or roster mask".into());
    }
    Ok(GenesisJournalV4 {
        v: version as u8,
        deployment_id: hash("deploymentDomain")?,
        room_id: parse_u64_flex(get(obj, "roomId")?, "roomId")?,
        config_hash: hash("configHash")?,
        preset_hash: hash("presetHash")?,
        manifest_hash: hash("manifestHash")?,
        proof_program_id: hash("proofProgramId")?,
        l1_block_number: parse_u64_flex(get(obj, "l1BlockNumber")?, "l1BlockNumber")?,
        l1_block_hash: hash("l1BlockHash")?,
        l1_state_root: hash("l1StateRoot")?,
        genesis_state_root: hash("genesisStateRoot")?,
        genesis_roster_root: hash("genesisRosterRoot")?,
        genesis_exit_root: hash("genesisExitRoot")?,
        active_mask: active as u8,
        used_mask: used as u8,
        inbox_cursor: parse_u64_flex(get(obj, "inboxCursor")?, "inboxCursor")?,
        asset_totals_hash: hash("assetTotalsHash")?,
        exit_totals_hash: hash("exitTotalsHash")?,
        fee_totals_hash: hash("feeTotalsHash")?,
        l1_inclusion_deadline: parse_u64_flex(
            get(obj, "l1InclusionDeadline")?,
            "l1InclusionDeadline",
        )?,
        exit_allocations: Vec::new(),
        asset_accounting: Vec::new(),
    })
}

pub fn batch_journal_to_ts_value_v4(j: &BatchJournalV4) -> Value {
    serde_json::json!({
        "protocolVersion": j.v,
        "deploymentDomain": hex0x(j.deployment_id.as_slice()),
        "roomId": j.room_id.to_string(),
        "presetHash": hex0x(j.preset_hash.as_slice()),
        "manifestHash": hex0x(j.manifest_hash.as_slice()),
        "proofProgramId": hex0x(j.proof_program_id.as_slice()),
        "batchIndex": j.batch_index.to_string(),
        "startL2Block": j.l2_start_height.to_string(),
        "endL2Block": j.l2_end_height.to_string(),
        "previousBlockTimestamp": j.previous_block_timestamp.to_string(),
        "finalBlockTimestamp": j.final_block_timestamp.to_string(),
        "preStateRoot": hex0x(j.prev_state_root.as_slice()),
        "postStateRoot": hex0x(j.post_state_root.as_slice()),
        "blockRootsHash": hex0x(j.block_roots_hash.as_slice()),
        "blocks": j.blocks.iter().map(|b| serde_json::json!({
            "blockNumber": b.block_number.to_string(),
            "postStateRoot": hex0x(b.post_state_root.as_slice()),
            "txCommitment": hex0x(b.tx_commitment.as_slice()),
            "envHash": hex0x(b.env_hash.as_slice()),
        })).collect::<Vec<_>>(),
        "preRosterRoot": hex0x(j.pre_roster_root.as_slice()),
        "postRosterRoot": hex0x(j.post_roster_root.as_slice()),
        "preActiveMask": j.active_mask,
        "postActiveMask": j.post_active_mask,
        "usedMask": j.used_mask,
        "inboxCursorBefore": j.inbox_start.to_string(),
        "inboxCursorAfter": j.inbox_end.to_string(),
        "inboxInputsHash": hex0x(j.inbox_inputs_hash.as_slice()),
        "batchDataHash": hex0x(j.block_data_hash.as_slice()),
        "assetTotalsHash": hex0x(j.asset_totals_hash.as_slice()),
        "exitTotalsHash": hex0x(j.exit_totals_hash.as_slice()),
        "feeTotalsHash": hex0x(j.fee_totals_hash.as_slice()),
        "membershipDeltasHash": hex0x(j.membership_deltas_hash.as_slice()),
        "previousExitRoot": hex0x(j.previous_exit_root.as_slice()),
        "exitRoot": hex0x(j.exit_root.as_slice()),
        "close": j.close,
        "l1InclusionDeadline": j.l1_inclusion_deadline.to_string(),
        "exitAllocations": j.exit_allocations.iter().map(|allocation| serde_json::json!({
            "slot": allocation.slot,
            "assetId": allocation.asset_id,
            "recipient": hex0x(allocation.recipient.as_slice()),
            "amount": allocation.amount.to_string(),
        })).collect::<Vec<_>>(),
        "assetAccounting": j.asset_accounting.iter().map(|accounting| serde_json::json!({
            "assetId": accounting.asset_id,
            "total": accounting.total.to_string(),
            "exitTotal": accounting.exit_total.to_string(),
            "feeTotal": accounting.fee_total.to_string(),
        })).collect::<Vec<_>>(),
    })
}

pub fn genesis_journal_to_ts_value_v4(j: &GenesisJournalV4) -> Value {
    serde_json::json!({
        "protocolVersion": j.v,
        "deploymentDomain": hex0x(j.deployment_id.as_slice()),
        "roomId": j.room_id.to_string(),
        "configHash": hex0x(j.config_hash.as_slice()),
        "presetHash": hex0x(j.preset_hash.as_slice()),
        "manifestHash": hex0x(j.manifest_hash.as_slice()),
        "proofProgramId": hex0x(j.proof_program_id.as_slice()),
        "l1BlockNumber": j.l1_block_number.to_string(),
        "l1BlockHash": hex0x(j.l1_block_hash.as_slice()),
        "l1StateRoot": hex0x(j.l1_state_root.as_slice()),
        "genesisStateRoot": hex0x(j.genesis_state_root.as_slice()),
        "genesisRosterRoot": hex0x(j.genesis_roster_root.as_slice()),
        "genesisExitRoot": hex0x(j.genesis_exit_root.as_slice()),
        "activeMask": j.active_mask,
        "usedMask": j.used_mask,
        "inboxCursor": j.inbox_cursor.to_string(),
        "assetTotalsHash": hex0x(j.asset_totals_hash.as_slice()),
        "exitTotalsHash": hex0x(j.exit_totals_hash.as_slice()),
        "feeTotalsHash": hex0x(j.fee_totals_hash.as_slice()),
        "l1InclusionDeadline": j.l1_inclusion_deadline.to_string(),
        "exitAllocations": j.exit_allocations.iter().map(|allocation| serde_json::json!({
            "slot": allocation.slot,
            "assetId": allocation.asset_id,
            "recipient": hex0x(allocation.recipient.as_slice()),
            "amount": allocation.amount.to_string(),
        })).collect::<Vec<_>>(),
        "assetAccounting": j.asset_accounting.iter().map(|accounting| serde_json::json!({
            "assetId": accounting.asset_id,
            "total": accounting.total.to_string(),
            "exitTotal": accounting.exit_total.to_string(),
            "feeTotal": accounting.fee_total.to_string(),
        })).collect::<Vec<_>>(),
    })
}
