//! v4 room genesis: the L1 anchor check and the opening public statement.

use alloy_primitives::{keccak256, B256};
use stf_types::{BatchInputV4, GenesisInputV4, GenesisJournalV4, BATCH_JOURNAL_VERSION_V4};

use crate::compact::verify_compact_state_v4;
use crate::policy::ExecutionPolicyV4;
use crate::settlement::{derive_settlement_v4, ExitProgramV4};
use crate::StfError;

fn decode_header_string<'a>(raw: &'a [u8], label: &str) -> Result<&'a [u8], StfError> {
    let mut cursor = raw;
    let value = alloy_rlp::Header::decode_bytes(&mut cursor, false)
        .map_err(|error| StfError::GenesisAnchor(format!("{label}: invalid RLP: {error}")))?;
    if !cursor.is_empty() {
        return Err(StfError::GenesisAnchor(format!(
            "{label}: trailing RLP bytes"
        )));
    }
    Ok(value)
}

fn verify_genesis_l1_anchor_v4(input: &GenesisInputV4) -> Result<(), StfError> {
    if input.l1_block_hash == B256::ZERO || input.l1_state_root == B256::ZERO {
        return Err(StfError::GenesisAnchor(
            "block hash and state root must be non-zero".into(),
        ));
    }
    if input.l1_header_rlp.is_empty() || input.l1_header_rlp.len() > 2_048 {
        return Err(StfError::GenesisAnchor(
            "header RLP length is outside 1..=2048".into(),
        ));
    }
    if keccak256(&input.l1_header_rlp) != input.l1_block_hash {
        return Err(StfError::GenesisAnchor(
            "header RLP does not hash to l1BlockHash".into(),
        ));
    }
    let mut cursor = input.l1_header_rlp.as_ref();
    let view = alloy_rlp::Header::decode_raw(&mut cursor)
        .map_err(|error| StfError::GenesisAnchor(format!("invalid header RLP: {error}")))?;
    if !cursor.is_empty() {
        return Err(StfError::GenesisAnchor(
            "header RLP has trailing bytes".into(),
        ));
    }
    let alloy_rlp::PayloadView::List(fields) = view else {
        return Err(StfError::GenesisAnchor(
            "Ethereum header must be an RLP list".into(),
        ));
    };
    if fields.len() < 15 {
        return Err(StfError::GenesisAnchor(
            "Ethereum header has fewer than 15 fields".into(),
        ));
    }
    let state_root = decode_header_string(fields[3], "header.stateRoot")?;
    if state_root.len() != 32 || state_root != input.l1_state_root.as_slice() {
        return Err(StfError::GenesisAnchor(
            "header stateRoot does not match l1StateRoot".into(),
        ));
    }
    let number = decode_header_string(fields[8], "header.number")?;
    if number.len() > 8 || (number.len() > 1 && number[0] == 0) {
        return Err(StfError::GenesisAnchor(
            "header number is not canonical uint64".into(),
        ));
    }
    let mut number_word = [0u8; 8];
    number_word[8 - number.len()..].copy_from_slice(number);
    if u64::from_be_bytes(number_word) != input.l1_block_number {
        return Err(StfError::GenesisAnchor(
            "header number does not match l1BlockNumber".into(),
        ));
    }
    if input.l1_block_number > input.l1_inclusion_deadline {
        return Err(StfError::GenesisAnchor(
            "L1 anchor is after inclusion deadline".into(),
        ));
    }
    Ok(())
}

/// Authenticate and policy-check the opening state without pretending that
/// room genesis is an EVM block. The resulting journal is the exact public
/// statement approved by initial members and verified by `openRoom`.
pub fn execute_genesis_v4(input: &GenesisInputV4) -> Result<GenesisJournalV4, StfError> {
    if input.genesis_state_root == B256::ZERO {
        return Err(StfError::InvalidBatch(
            "genesis state root must be non-zero".into(),
        ));
    }
    if input.compact_state.canonical_state_root != B256::ZERO {
        return Err(StfError::CompactWitness(
            "room-local genesis state must not masquerade as an L1 multiproof".into(),
        ));
    }
    if input.inbox_cursor != 0 {
        return Err(StfError::InvalidBatch(
            "genesis inbox cursor must be zero".into(),
        ));
    }
    verify_genesis_l1_anchor_v4(input)?;
    if input.active_mask & !0x7f != 0 || input.used_mask & !0x7f != 0 {
        return Err(StfError::InvalidBatch(
            "genesis member masks exceed seven slots".into(),
        ));
    }
    if input.active_mask & !input.used_mask != 0 {
        return Err(StfError::InvalidBatch(
            "genesis active slots must be a subset of used slots".into(),
        ));
    }
    let state = verify_compact_state_v4(&input.compact_state)?;
    let computed_root = state.state_root();
    if computed_root != input.genesis_state_root {
        return Err(StfError::CompactWitness(format!(
            "compact genesis root {computed_root} does not match journal root {}",
            input.genesis_state_root
        )));
    }

    // Reuse the exact preset/code/roster policy parser used for every batch.
    // Empty blocks are intentional here: genesis authenticates state and
    // policy but does not consume an L2 height.
    let policy_input = BatchInputV4 {
        encoded_witness_bytes: input.encoded_witness_bytes,
        deployment_id: input.deployment_id,
        room_id: input.room_id,
        preset_hash: input.preset_hash,
        manifest_hash: input.manifest_hash,
        proof_program_id: input.proof_program_id,
        pre_roster_root: input.genesis_roster_root,
        post_roster_root: input.genesis_roster_root,
        active_mask: input.active_mask,
        pre_used_mask: input.used_mask,
        post_active_mask: input.active_mask,
        used_mask: input.used_mask,
        canonical_preset_json: input.canonical_preset_json.clone(),
        canonical_exit_program_json: input.canonical_exit_program_json.clone(),
        pre_roster_slots: input.roster_slots.clone(),
        post_roster_slots: input.roster_slots.clone(),
        compact_state: input.compact_state.clone(),
        ..Default::default()
    };
    let policy =
        ExecutionPolicyV4::from_input(&policy_input, &state).map_err(StfError::CertifiedPolicy)?;
    let exit_program = ExitProgramV4::parse(&input.canonical_exit_program_json, &policy)
        .map_err(StfError::Settlement)?;
    let settlement = derive_settlement_v4(
        &exit_program,
        &state,
        &input.roster_slots,
        &input.asset_totals,
        &input.residual_allocations,
        input.deployment_id,
        input.room_id,
    )
    .map_err(StfError::Settlement)?;
    if settlement.asset_totals_hash != input.asset_totals_hash
        || settlement.exit_totals_hash != input.exit_totals_hash
        || settlement.fee_totals_hash != input.fee_totals_hash
        || settlement.exit_root != input.genesis_exit_root
    {
        return Err(StfError::Settlement(
            "derived genesis accounting/root does not match expected public statement".into(),
        ));
    }

    Ok(GenesisJournalV4 {
        v: BATCH_JOURNAL_VERSION_V4,
        deployment_id: input.deployment_id,
        room_id: input.room_id,
        config_hash: input.config_hash,
        preset_hash: input.preset_hash,
        manifest_hash: input.manifest_hash,
        proof_program_id: input.proof_program_id,
        l1_block_number: input.l1_block_number,
        l1_block_hash: input.l1_block_hash,
        l1_state_root: input.l1_state_root,
        genesis_state_root: computed_root,
        genesis_roster_root: input.genesis_roster_root,
        genesis_exit_root: input.genesis_exit_root,
        active_mask: input.active_mask,
        used_mask: input.used_mask,
        inbox_cursor: input.inbox_cursor,
        asset_totals_hash: settlement.asset_totals_hash,
        exit_totals_hash: settlement.exit_totals_hash,
        fee_totals_hash: settlement.fee_totals_hash,
        l1_inclusion_deadline: input.l1_inclusion_deadline,
        exit_allocations: settlement.exit_allocations,
        asset_accounting: settlement.accounting,
    })
}
