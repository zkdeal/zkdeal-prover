//! V4 batch and genesis witness wire family: the borsh structs the host emits
//! and their expansion into the native `stf-types` inputs.

use alloy_primitives::{Address, Bytes, B256, U256};
use borsh::{BorshDeserialize, BorshSerialize};
use stf_types::{
    AssetTotalWitnessV4, BatchBlockV4, BatchInputV4, BlockEnvV1, CompactAccountWitnessV4,
    CompactStateWitnessV4, CompactStorageWitnessV4, ExitAllocationV4, GenesisInputV4,
    InboxAssetAmountV4, InboxEntryWitnessV4, MemberSlotWitnessV4, MembershipDeltaWitnessV4,
    ResidualAllocationV4,
};

use crate::block_v1::EnvWire;
use crate::l2_chain_id_v4;

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BatchBlockWireV4 {
    pub block_number: u64,
    pub raw_txs: Vec<Vec<u8>>,
    pub env: EnvWire,
    pub expected_post_state_root: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CompactStorageWireV4 {
    pub slot: [u8; 32],
    pub value: [u8; 32],
    pub proof: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CompactAccountWireV4 {
    pub address: [u8; 20],
    pub exists: bool,
    pub nonce: u64,
    pub balance: [u8; 32],
    pub code: Vec<u8>,
    pub canonical_storage_root: [u8; 32],
    pub account_proof: Vec<Vec<u8>>,
    pub storage: Vec<CompactStorageWireV4>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CompactStateWireV4 {
    pub canonical_state_root: [u8; 32],
    pub accounts: Vec<CompactAccountWireV4>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MemberSlotWireV4 {
    pub slot: u8,
    pub state: u8,
    pub account: [u8; 20],
    pub joined_at_batch: u64,
    pub retired_at_batch: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AssetTotalWireV4 {
    pub asset_id: u8,
    pub total: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ResidualAllocationWireV4 {
    pub position: u8,
    pub asset_id: u8,
    pub recipient_slot: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExitAllocationWireV4 {
    pub slot: u8,
    pub asset_id: u8,
    pub recipient: [u8; 20],
    pub amount: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct InboxAssetAmountWireV4 {
    pub asset_id: u8,
    pub amount: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct InboxEntryWireV4 {
    pub index: u64,
    pub kind: u8,
    pub account: [u8; 20],
    pub beneficiary_slot: u8,
    pub status: u8,
    pub deposits: Vec<InboxAssetAmountWireV4>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MembershipDeltaWireV4 {
    pub action: u8,
    pub slot: u8,
    pub member: [u8; 20],
    pub join_request_index: u64,
    pub acceptance_expiry: u64,
}

/// V4 batched guest input. The opening state occurs exactly once and every
/// subsequent pre-state is derived inside the guest.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BatchInputWireV4 {
    pub v: u8,
    pub deployment_id: [u8; 32],
    pub room_id: u64,
    pub preset_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub proof_program_id: [u8; 32],
    pub batch_index: u64,
    pub l2_start_height: u64,
    pub previous_block_timestamp: u64,
    pub prev_state_root: [u8; 32],
    pub pre_roster_root: [u8; 32],
    pub post_roster_root: [u8; 32],
    pub active_mask: u8,
    pub pre_used_mask: u8,
    pub post_active_mask: u8,
    pub used_mask: u8,
    pub inbox_start: u64,
    pub inbox_end: u64,
    pub inbox_inputs_hash: [u8; 32],
    pub expected_block_data_hash: [u8; 32],
    pub asset_totals_hash: [u8; 32],
    pub exit_totals_hash: [u8; 32],
    pub fee_totals_hash: [u8; 32],
    pub membership_deltas_hash: [u8; 32],
    pub previous_exit_root: [u8; 32],
    pub exit_root: [u8; 32],
    pub close: bool,
    pub l1_inclusion_deadline: u64,
    pub canonical_preset_json: Vec<u8>,
    pub canonical_exit_program_json: Vec<u8>,
    pub pre_roster_slots: Vec<MemberSlotWireV4>,
    pub post_roster_slots: Vec<MemberSlotWireV4>,
    pub membership_deltas: Vec<MembershipDeltaWireV4>,
    pub inbox_entries: Vec<InboxEntryWireV4>,
    pub asset_totals: Vec<AssetTotalWireV4>,
    pub residual_allocations: Vec<ResidualAllocationWireV4>,
    pub previous_exit_allocations: Vec<ExitAllocationWireV4>,
    pub compact_state: CompactStateWireV4,
    pub blocks: Vec<BatchBlockWireV4>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GenesisInputWireV4 {
    pub v: u8,
    pub deployment_id: [u8; 32],
    pub room_id: u64,
    pub config_hash: [u8; 32],
    pub preset_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub proof_program_id: [u8; 32],
    pub l1_block_number: u64,
    pub l1_block_hash: [u8; 32],
    pub l1_state_root: [u8; 32],
    pub l1_header_rlp: Vec<u8>,
    pub genesis_state_root: [u8; 32],
    pub genesis_roster_root: [u8; 32],
    pub genesis_exit_root: [u8; 32],
    pub active_mask: u8,
    pub used_mask: u8,
    pub inbox_cursor: u64,
    pub asset_totals_hash: [u8; 32],
    pub exit_totals_hash: [u8; 32],
    pub fee_totals_hash: [u8; 32],
    pub l1_inclusion_deadline: u64,
    pub canonical_preset_json: Vec<u8>,
    pub canonical_exit_program_json: Vec<u8>,
    pub roster_slots: Vec<MemberSlotWireV4>,
    pub asset_totals: Vec<AssetTotalWireV4>,
    pub residual_allocations: Vec<ResidualAllocationWireV4>,
    pub compact_state: CompactStateWireV4,
}

fn compact_state_from_wire(source: &CompactStateWireV4) -> CompactStateWitnessV4 {
    CompactStateWitnessV4 {
        canonical_state_root: B256::from(source.canonical_state_root),
        accounts: source
            .accounts
            .iter()
            .map(|account| CompactAccountWitnessV4 {
                address: Address::from(account.address),
                exists: account.exists,
                nonce: account.nonce,
                balance: U256::from_be_bytes(account.balance),
                code: Bytes::from(account.code.clone()),
                canonical_storage_root: B256::from(account.canonical_storage_root),
                account_proof: account
                    .account_proof
                    .iter()
                    .cloned()
                    .map(Bytes::from)
                    .collect(),
                storage: account
                    .storage
                    .iter()
                    .map(|slot| CompactStorageWitnessV4 {
                        slot: U256::from_be_bytes(slot.slot),
                        value: U256::from_be_bytes(slot.value),
                        proof: slot.proof.iter().cloned().map(Bytes::from).collect(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

impl BatchInputWireV4 {
    pub fn to_input(&self) -> Result<BatchInputV4, String> {
        if self.v != stf_types::BATCH_JOURNAL_VERSION_V4 {
            return Err(format!("batch input version {} != 4", self.v));
        }
        let chain_id = l2_chain_id_v4(B256::from(self.deployment_id), self.room_id);
        let encoded_witness_bytes = u32::try_from(
            4usize
                .checked_add(
                    borsh::to_vec(self)
                        .map_err(|error| format!("batch input borsh: {error}"))?
                        .len(),
                )
                .ok_or("batch witness length overflow")?,
        )
        .map_err(|_| "batch witness length exceeds u32")?;
        Ok(BatchInputV4 {
            encoded_witness_bytes,
            deployment_id: B256::from(self.deployment_id),
            room_id: self.room_id,
            preset_hash: B256::from(self.preset_hash),
            manifest_hash: B256::from(self.manifest_hash),
            proof_program_id: B256::from(self.proof_program_id),
            batch_index: self.batch_index,
            l2_start_height: self.l2_start_height,
            previous_block_timestamp: self.previous_block_timestamp,
            prev_state_root: B256::from(self.prev_state_root),
            pre_roster_root: B256::from(self.pre_roster_root),
            post_roster_root: B256::from(self.post_roster_root),
            active_mask: self.active_mask,
            pre_used_mask: self.pre_used_mask,
            post_active_mask: self.post_active_mask,
            used_mask: self.used_mask,
            inbox_start: self.inbox_start,
            inbox_end: self.inbox_end,
            inbox_inputs_hash: B256::from(self.inbox_inputs_hash),
            expected_block_data_hash: B256::from(self.expected_block_data_hash),
            asset_totals_hash: B256::from(self.asset_totals_hash),
            exit_totals_hash: B256::from(self.exit_totals_hash),
            fee_totals_hash: B256::from(self.fee_totals_hash),
            membership_deltas_hash: B256::from(self.membership_deltas_hash),
            previous_exit_root: B256::from(self.previous_exit_root),
            exit_root: B256::from(self.exit_root),
            close: self.close,
            l1_inclusion_deadline: self.l1_inclusion_deadline,
            canonical_preset_json: Bytes::from(self.canonical_preset_json.clone()),
            canonical_exit_program_json: Bytes::from(self.canonical_exit_program_json.clone()),
            pre_roster_slots: self
                .pre_roster_slots
                .iter()
                .map(|slot| MemberSlotWitnessV4 {
                    slot: slot.slot,
                    state: slot.state,
                    account: Address::from(slot.account),
                    joined_at_batch: slot.joined_at_batch,
                    retired_at_batch: slot.retired_at_batch,
                })
                .collect(),
            post_roster_slots: self
                .post_roster_slots
                .iter()
                .map(|slot| MemberSlotWitnessV4 {
                    slot: slot.slot,
                    state: slot.state,
                    account: Address::from(slot.account),
                    joined_at_batch: slot.joined_at_batch,
                    retired_at_batch: slot.retired_at_batch,
                })
                .collect(),
            membership_deltas: self
                .membership_deltas
                .iter()
                .map(|delta| MembershipDeltaWitnessV4 {
                    action: delta.action,
                    slot: delta.slot,
                    member: Address::from(delta.member),
                    join_request_index: delta.join_request_index,
                    acceptance_expiry: delta.acceptance_expiry,
                })
                .collect(),
            inbox_entries: self
                .inbox_entries
                .iter()
                .map(|entry| InboxEntryWitnessV4 {
                    index: entry.index,
                    kind: entry.kind,
                    account: Address::from(entry.account),
                    beneficiary_slot: entry.beneficiary_slot,
                    status: entry.status,
                    deposits: entry
                        .deposits
                        .iter()
                        .map(|deposit| InboxAssetAmountV4 {
                            asset_id: deposit.asset_id,
                            amount: U256::from_be_bytes(deposit.amount),
                        })
                        .collect(),
                })
                .collect(),
            asset_totals: self
                .asset_totals
                .iter()
                .map(|total| AssetTotalWitnessV4 {
                    asset_id: total.asset_id,
                    total: U256::from_be_bytes(total.total),
                })
                .collect(),
            residual_allocations: self
                .residual_allocations
                .iter()
                .map(|allocation| ResidualAllocationV4 {
                    position: allocation.position,
                    asset_id: allocation.asset_id,
                    recipient_slot: allocation.recipient_slot,
                })
                .collect(),
            previous_exit_allocations: self
                .previous_exit_allocations
                .iter()
                .map(|allocation| ExitAllocationV4 {
                    slot: allocation.slot,
                    asset_id: allocation.asset_id,
                    recipient: Address::from(allocation.recipient),
                    amount: U256::from_be_bytes(allocation.amount),
                })
                .collect(),
            compact_state: compact_state_from_wire(&self.compact_state),
            blocks: self
                .blocks
                .iter()
                .map(|block| BatchBlockV4 {
                    block_number: block.block_number,
                    raw_txs: block.raw_txs.iter().cloned().map(Bytes::from).collect(),
                    env: BlockEnvV1 {
                        number: block.block_number,
                        timestamp: block.env.timestamp,
                        gas_limit: block.env.gas_limit,
                        coinbase: Address::ZERO,
                        base_fee: U256::ZERO,
                        prev_randao: B256::ZERO,
                        difficulty: U256::ZERO,
                        excess_blob_gas: 0,
                        chain_id,
                    },
                    expected_post_state_root: B256::from(block.expected_post_state_root),
                })
                .collect(),
        })
    }
}

impl GenesisInputWireV4 {
    pub fn to_input(&self) -> Result<GenesisInputV4, String> {
        if self.v != stf_types::BATCH_JOURNAL_VERSION_V4 {
            return Err(format!("genesis input version {} != 4", self.v));
        }
        let encoded_witness_bytes = u32::try_from(
            4usize
                .checked_add(
                    borsh::to_vec(self)
                        .map_err(|error| format!("genesis input borsh: {error}"))?
                        .len(),
                )
                .ok_or("genesis witness length overflow")?,
        )
        .map_err(|_| "genesis witness length exceeds u32")?;
        Ok(GenesisInputV4 {
            encoded_witness_bytes,
            deployment_id: B256::from(self.deployment_id),
            room_id: self.room_id,
            config_hash: B256::from(self.config_hash),
            preset_hash: B256::from(self.preset_hash),
            manifest_hash: B256::from(self.manifest_hash),
            proof_program_id: B256::from(self.proof_program_id),
            l1_block_number: self.l1_block_number,
            l1_block_hash: B256::from(self.l1_block_hash),
            l1_state_root: B256::from(self.l1_state_root),
            l1_header_rlp: Bytes::from(self.l1_header_rlp.clone()),
            genesis_state_root: B256::from(self.genesis_state_root),
            genesis_roster_root: B256::from(self.genesis_roster_root),
            genesis_exit_root: B256::from(self.genesis_exit_root),
            active_mask: self.active_mask,
            used_mask: self.used_mask,
            inbox_cursor: self.inbox_cursor,
            asset_totals_hash: B256::from(self.asset_totals_hash),
            exit_totals_hash: B256::from(self.exit_totals_hash),
            fee_totals_hash: B256::from(self.fee_totals_hash),
            l1_inclusion_deadline: self.l1_inclusion_deadline,
            canonical_preset_json: Bytes::from(self.canonical_preset_json.clone()),
            canonical_exit_program_json: Bytes::from(self.canonical_exit_program_json.clone()),
            roster_slots: self
                .roster_slots
                .iter()
                .map(|slot| MemberSlotWitnessV4 {
                    slot: slot.slot,
                    state: slot.state,
                    account: Address::from(slot.account),
                    joined_at_batch: slot.joined_at_batch,
                    retired_at_batch: slot.retired_at_batch,
                })
                .collect(),
            asset_totals: self
                .asset_totals
                .iter()
                .map(|total| AssetTotalWitnessV4 {
                    asset_id: total.asset_id,
                    total: U256::from_be_bytes(total.total),
                })
                .collect(),
            residual_allocations: self
                .residual_allocations
                .iter()
                .map(|allocation| ResidualAllocationV4 {
                    position: allocation.position,
                    asset_id: allocation.asset_id,
                    recipient_slot: allocation.recipient_slot,
                })
                .collect(),
            compact_state: compact_state_from_wire(&self.compact_state),
        })
    }
}
