//! V4 batch journal wire family: the borsh shape the guest commits and the
//! codec the host and verifier use to read it back.

use alloy_primitives::{Address, B256, U256};
use borsh::{BorshDeserialize, BorshSerialize};
use stf_types::{AssetAccountingV4, BatchBlockJournalV4, BatchJournalV4, ExitAllocationV4};

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct BatchBlockJournalWireV4 {
    block_number: u64,
    post_state_root: [u8; 32],
    tx_commitment: [u8; 32],
    env_hash: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct ExitAllocationJournalWireV4 {
    slot: u8,
    asset_id: u8,
    recipient: [u8; 20],
    amount: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct AssetAccountingJournalWireV4 {
    asset_id: u8,
    total: [u8; 32],
    exit_total: [u8; 32],
    fee_total: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct BatchJournalWireV4 {
    v: u8,
    deployment_id: [u8; 32],
    room_id: u64,
    preset_hash: [u8; 32],
    manifest_hash: [u8; 32],
    proof_program_id: [u8; 32],
    batch_index: u64,
    l2_start_height: u64,
    l2_end_height: u64,
    previous_block_timestamp: u64,
    final_block_timestamp: u64,
    prev_state_root: [u8; 32],
    post_state_root: [u8; 32],
    block_roots_hash: [u8; 32],
    blocks: Vec<BatchBlockJournalWireV4>,
    pre_roster_root: [u8; 32],
    post_roster_root: [u8; 32],
    active_mask: u8,
    post_active_mask: u8,
    used_mask: u8,
    inbox_start: u64,
    inbox_end: u64,
    inbox_inputs_hash: [u8; 32],
    block_data_hash: [u8; 32],
    asset_totals_hash: [u8; 32],
    exit_totals_hash: [u8; 32],
    fee_totals_hash: [u8; 32],
    membership_deltas_hash: [u8; 32],
    previous_exit_root: [u8; 32],
    exit_root: [u8; 32],
    close: bool,
    l1_inclusion_deadline: u64,
    exit_allocations: Vec<ExitAllocationJournalWireV4>,
    asset_accounting: Vec<AssetAccountingJournalWireV4>,
}

pub fn batch_journal_to_borsh_v4(j: &BatchJournalV4) -> Vec<u8> {
    borsh::to_vec(&BatchJournalWireV4 {
        v: j.v,
        deployment_id: j.deployment_id.0,
        room_id: j.room_id,
        preset_hash: j.preset_hash.0,
        manifest_hash: j.manifest_hash.0,
        proof_program_id: j.proof_program_id.0,
        batch_index: j.batch_index,
        l2_start_height: j.l2_start_height,
        l2_end_height: j.l2_end_height,
        previous_block_timestamp: j.previous_block_timestamp,
        final_block_timestamp: j.final_block_timestamp,
        prev_state_root: j.prev_state_root.0,
        post_state_root: j.post_state_root.0,
        block_roots_hash: j.block_roots_hash.0,
        blocks: j
            .blocks
            .iter()
            .map(|b| BatchBlockJournalWireV4 {
                block_number: b.block_number,
                post_state_root: b.post_state_root.0,
                tx_commitment: b.tx_commitment.0,
                env_hash: b.env_hash.0,
            })
            .collect(),
        pre_roster_root: j.pre_roster_root.0,
        post_roster_root: j.post_roster_root.0,
        active_mask: j.active_mask,
        post_active_mask: j.post_active_mask,
        used_mask: j.used_mask,
        inbox_start: j.inbox_start,
        inbox_end: j.inbox_end,
        inbox_inputs_hash: j.inbox_inputs_hash.0,
        block_data_hash: j.block_data_hash.0,
        asset_totals_hash: j.asset_totals_hash.0,
        exit_totals_hash: j.exit_totals_hash.0,
        fee_totals_hash: j.fee_totals_hash.0,
        membership_deltas_hash: j.membership_deltas_hash.0,
        previous_exit_root: j.previous_exit_root.0,
        exit_root: j.exit_root.0,
        close: j.close,
        l1_inclusion_deadline: j.l1_inclusion_deadline,
        exit_allocations: j
            .exit_allocations
            .iter()
            .map(|allocation| {
                let mut recipient = [0u8; 20];
                recipient.copy_from_slice(allocation.recipient.as_slice());
                ExitAllocationJournalWireV4 {
                    slot: allocation.slot,
                    asset_id: allocation.asset_id,
                    recipient,
                    amount: allocation.amount.to_be_bytes::<32>(),
                }
            })
            .collect(),
        asset_accounting: j
            .asset_accounting
            .iter()
            .map(|accounting| AssetAccountingJournalWireV4 {
                asset_id: accounting.asset_id,
                total: accounting.total.to_be_bytes::<32>(),
                exit_total: accounting.exit_total.to_be_bytes::<32>(),
                fee_total: accounting.fee_total.to_be_bytes::<32>(),
            })
            .collect(),
    })
    .expect("v4 batch journal borsh encode cannot fail")
}

pub fn batch_journal_from_borsh_v4(bytes: &[u8]) -> Result<BatchJournalV4, String> {
    let w = BatchJournalWireV4::try_from_slice(bytes)
        .map_err(|e| format!("v4 batch journal borsh: {e}"))?;
    if w.v != stf_types::BATCH_JOURNAL_VERSION_V4 {
        return Err(format!("batch journal version {} != 4", w.v));
    }
    Ok(BatchJournalV4 {
        v: w.v,
        deployment_id: B256::from(w.deployment_id),
        room_id: w.room_id,
        preset_hash: B256::from(w.preset_hash),
        manifest_hash: B256::from(w.manifest_hash),
        proof_program_id: B256::from(w.proof_program_id),
        batch_index: w.batch_index,
        l2_start_height: w.l2_start_height,
        l2_end_height: w.l2_end_height,
        previous_block_timestamp: w.previous_block_timestamp,
        final_block_timestamp: w.final_block_timestamp,
        prev_state_root: B256::from(w.prev_state_root),
        post_state_root: B256::from(w.post_state_root),
        block_roots_hash: B256::from(w.block_roots_hash),
        blocks: w
            .blocks
            .into_iter()
            .map(|b| BatchBlockJournalV4 {
                block_number: b.block_number,
                post_state_root: B256::from(b.post_state_root),
                tx_commitment: B256::from(b.tx_commitment),
                env_hash: B256::from(b.env_hash),
            })
            .collect(),
        pre_roster_root: B256::from(w.pre_roster_root),
        post_roster_root: B256::from(w.post_roster_root),
        active_mask: w.active_mask,
        post_active_mask: w.post_active_mask,
        used_mask: w.used_mask,
        inbox_start: w.inbox_start,
        inbox_end: w.inbox_end,
        inbox_inputs_hash: B256::from(w.inbox_inputs_hash),
        block_data_hash: B256::from(w.block_data_hash),
        asset_totals_hash: B256::from(w.asset_totals_hash),
        exit_totals_hash: B256::from(w.exit_totals_hash),
        fee_totals_hash: B256::from(w.fee_totals_hash),
        membership_deltas_hash: B256::from(w.membership_deltas_hash),
        previous_exit_root: B256::from(w.previous_exit_root),
        exit_root: B256::from(w.exit_root),
        close: w.close,
        l1_inclusion_deadline: w.l1_inclusion_deadline,
        exit_allocations: w
            .exit_allocations
            .into_iter()
            .map(|allocation| ExitAllocationV4 {
                slot: allocation.slot,
                asset_id: allocation.asset_id,
                recipient: Address::from(allocation.recipient),
                amount: U256::from_be_bytes(allocation.amount),
            })
            .collect(),
        asset_accounting: w
            .asset_accounting
            .into_iter()
            .map(|accounting| AssetAccountingV4 {
                asset_id: accounting.asset_id,
                total: U256::from_be_bytes(accounting.total),
                exit_total: U256::from_be_bytes(accounting.exit_total),
                fee_total: U256::from_be_bytes(accounting.fee_total),
            })
            .collect(),
    })
}
