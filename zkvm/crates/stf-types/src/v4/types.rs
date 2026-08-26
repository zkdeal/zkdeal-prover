//! Protocol-v4 witness and journal types.

use alloc::vec::Vec;
use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};

use crate::block::{AccountState, BlockEnvV1};

/// One real EVM block within a v4 proof. The state is supplied once at the
/// beginning of the batch and carried forward inside the guest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchBlockV4 {
    pub block_number: u64,
    pub raw_txs: Vec<Bytes>,
    pub env: BlockEnvV1,
    /// Client-replayed root included in canonical L1 batch calldata. The guest
    /// must reproduce it exactly.
    pub expected_post_state_root: B256,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactStorageWitnessV4 {
    pub slot: U256,
    pub value: U256,
    /// Reserved for a future authenticated partial-state witness version.
    /// `full-room-state-v1` requires this to be empty.
    pub proof: Vec<Bytes>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactAccountWitnessV4 {
    pub address: Address,
    /// False declares an absent address inside the complete room-local access
    /// envelope (for transfers/CREATE into a previously absent account).
    pub exists: bool,
    pub nonce: u64,
    pub balance: U256,
    pub code: Bytes,
    /// Storage root recomputed from every room-local storage leaf carried for
    /// this account.
    pub canonical_storage_root: B256,
    /// Reserved for a future authenticated partial-state witness version.
    /// `full-room-state-v1` requires this to be empty.
    pub account_proof: Vec<Bytes>,
    pub storage: Vec<CompactStorageWitnessV4>,
}

/// Complete room-local state under the `full-room-state-v1` model. Production
/// v4 requires `canonical_state_root == 0`; `accounts` reconstructs the entire
/// room root and omitting a live account or storage leaf is fail-closed. The
/// proof fields are reserved for a future, separately versioned authenticated
/// witness model and must be empty in v4.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactStateWitnessV4 {
    pub canonical_state_root: B256,
    pub accounts: Vec<CompactAccountWitnessV4>,
}

/// Full seven-slot pre-batch roster preimage. The guest recomputes
/// `pre_roster_root` and derives the active-member caller set from it; a host
/// cannot simply label an arbitrary transaction signer as active.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSlotWitnessV4 {
    pub slot: u8,
    /// 0 = unused, 1 = active, 2 = retired.
    pub state: u8,
    pub account: Address,
    pub joined_at_batch: u64,
    pub retired_at_batch: Option<u64>,
}

/// Exact L1-funded amount for one room asset. The L1 manager recomputes these
/// values from escrow and consumed inbox entries; the guest hashes the same
/// concrete values and refuses any exit program that does not conserve them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetTotalWitnessV4 {
    pub asset_id: u8,
    pub total: U256,
}

/// Canonical public claim produced by the guest's pinned exit program.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitAllocationV4 {
    pub slot: u8,
    pub asset_id: u8,
    pub recipient: Address,
    pub amount: U256,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetAccountingV4 {
    pub asset_id: u8,
    pub total: U256,
    pub exit_total: U256,
    pub fee_total: U256,
}

/// Explicit unanimous allocation of the otherwise indivisible remainder from
/// a particular pro-rata position. There is no implicit "last member" or
/// "dust" recipient. The choice changes the derived exit root and is therefore
/// covered by every pre-active member's exact batch approval.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResidualAllocationV4 {
    pub position: u8,
    pub asset_id: u8,
    pub recipient_slot: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxAssetAmountV4 {
    pub asset_id: u8,
    pub amount: U256,
}

/// Exact numbered L1 inbox preimage. `kind=1` is a top-up and must carry one
/// amount plus a beneficiary slot. `kind=2` is a join request and is matched to
/// an activation delta by `index` and `account`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxEntryWitnessV4 {
    pub index: u64,
    pub kind: u8,
    pub account: Address,
    /// 0..6 for a top-up; 255 for a join request (the activation delta chooses
    /// a never-used slot).
    pub beneficiary_slot: u8,
    /// 1 = Pending, 2 = Consumed, 3 = Skipped, 4 = Refunded. Guest inputs may
    /// contain only Pending/Refunded; the guest derives Consumed/Skipped and
    /// hashes that terminal resolution into the journal.
    pub status: u8,
    pub deposits: Vec<InboxAssetAmountV4>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipDeltaWitnessV4 {
    /// 1 = activate, 2 = retire.
    pub action: u8,
    pub slot: u8,
    pub member: Address,
    pub join_request_index: u64,
    pub acceptance_expiry: u64,
}

/// Public-identity and accounting inputs bound by a v4 execution proof.
///
/// Hash/root fields are expected assertions, never settlement authority. The
/// guest derives them from the concrete L1 totals/inbox, roster transition,
/// authenticated post-state, and code-hash-pinned exit program and rejects a
/// mismatch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchInputV4 {
    /// Exact magic-prefixed Borsh witness length, recomputed by stf-wire from
    /// the bytes received by the guest (never accepted from JSON).
    pub encoded_witness_bytes: u32,
    pub deployment_id: B256,
    pub room_id: u64,
    pub preset_hash: B256,
    pub manifest_hash: B256,
    pub proof_program_id: B256,
    pub batch_index: u64,
    pub l2_start_height: u64,
    /// Final timestamp accepted by the preceding L1-verified batch.
    pub previous_block_timestamp: u64,
    pub prev_state_root: B256,
    pub pre_roster_root: B256,
    pub post_roster_root: B256,
    pub active_mask: u8,
    pub pre_used_mask: u8,
    pub post_active_mask: u8,
    pub used_mask: u8,
    pub inbox_start: u64,
    pub inbox_end: u64,
    pub inbox_inputs_hash: B256,
    pub expected_block_data_hash: B256,
    pub asset_totals_hash: B256,
    pub exit_totals_hash: B256,
    pub fee_totals_hash: B256,
    pub membership_deltas_hash: B256,
    /// Exit root accepted by the preceding L1-verified room transition.
    pub previous_exit_root: B256,
    pub exit_root: B256,
    /// Authenticated terminal system marker. When true it takes effect
    /// immediately after the last raw transaction of the last block. No
    /// transaction or block exists after this boundary in the proven batch.
    pub close: bool,
    pub l1_inclusion_deadline: u64,
    /// Exact canonical JSON preimage of `preset_hash`. It is parsed and
    /// enforced inside the guest; certified execution cannot downgrade to a
    /// generic policy while retaining a certified preset hash.
    pub canonical_preset_json: Bytes,
    /// Canonical JSON preimage of the preset's `exitProgramId`.
    pub canonical_exit_program_json: Bytes,
    pub pre_roster_slots: Vec<MemberSlotWitnessV4>,
    pub post_roster_slots: Vec<MemberSlotWitnessV4>,
    pub membership_deltas: Vec<MembershipDeltaWitnessV4>,
    pub inbox_entries: Vec<InboxEntryWitnessV4>,
    pub asset_totals: Vec<AssetTotalWitnessV4>,
    pub residual_allocations: Vec<ResidualAllocationV4>,
    /// Canonical allocation preimage of `previous_exit_root`. The guest
    /// authenticates this list before enforcing retired-slot continuity.
    pub previous_exit_allocations: Vec<ExitAllocationV4>,
    /// Complete room-local `full-room-state-v1` prestate plus its explicit
    /// access envelope. Omitting live room state is fail-closed; proof arrays
    /// and `canonical_state_root` must be empty/zero in this witness version.
    pub compact_state: CompactStateWitnessV4,
    pub blocks: Vec<BatchBlockV4>,
}

/// Per-block result committed inside a v4 batch journal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchBlockJournalV4 {
    pub block_number: u64,
    pub post_state_root: B256,
    pub tx_commitment: B256,
    pub env_hash: B256,
}

/// Canonical public output of the batched guest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchJournalV4 {
    pub v: u8,
    pub deployment_id: B256,
    pub room_id: u64,
    pub preset_hash: B256,
    pub manifest_hash: B256,
    pub proof_program_id: B256,
    pub batch_index: u64,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub previous_block_timestamp: u64,
    pub final_block_timestamp: u64,
    pub prev_state_root: B256,
    pub post_state_root: B256,
    pub block_roots_hash: B256,
    /// One entry per block, preserving every intermediate root.
    pub blocks: Vec<BatchBlockJournalV4>,
    pub pre_roster_root: B256,
    pub post_roster_root: B256,
    pub active_mask: u8,
    pub post_active_mask: u8,
    pub used_mask: u8,
    pub inbox_start: u64,
    pub inbox_end: u64,
    pub inbox_inputs_hash: B256,
    pub block_data_hash: B256,
    pub asset_totals_hash: B256,
    pub exit_totals_hash: B256,
    pub fee_totals_hash: B256,
    pub membership_deltas_hash: B256,
    pub previous_exit_root: B256,
    pub exit_root: B256,
    /// Proof-bound terminal marker copied from the validated batch input.
    pub close: bool,
    pub l1_inclusion_deadline: u64,
    /// Host convenience fields. Their canonical hashes/root above are part of
    /// the L1 statement; these preimages let callers submit the exact claims
    /// without rerunning an independent, potentially divergent allocator.
    pub exit_allocations: Vec<ExitAllocationV4>,
    pub asset_accounting: Vec<AssetAccountingV4>,
}

/// Opening proof input. Unlike a normal batch, genesis authenticates a recent
/// canonical Ethereum header, validates the pinned preset/code/roster
/// envelope, and executes no speculative EVM block. The room-local state is
/// fresh preset state, not an arbitrary import from the L1 state trie.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisInputV4 {
    pub encoded_witness_bytes: u32,
    pub deployment_id: B256,
    pub room_id: u64,
    pub config_hash: B256,
    pub preset_hash: B256,
    pub manifest_hash: B256,
    pub proof_program_id: B256,
    /// Recent canonical L1 header used to bind the opening statement to L1.
    pub l1_block_number: u64,
    pub l1_block_hash: B256,
    pub l1_state_root: B256,
    pub l1_header_rlp: Bytes,
    pub genesis_state_root: B256,
    pub genesis_roster_root: B256,
    pub genesis_exit_root: B256,
    pub active_mask: u8,
    pub used_mask: u8,
    pub inbox_cursor: u64,
    pub asset_totals_hash: B256,
    pub exit_totals_hash: B256,
    pub fee_totals_hash: B256,
    pub l1_inclusion_deadline: u64,
    pub canonical_preset_json: Bytes,
    pub canonical_exit_program_json: Bytes,
    pub roster_slots: Vec<MemberSlotWitnessV4>,
    pub asset_totals: Vec<AssetTotalWitnessV4>,
    pub residual_allocations: Vec<ResidualAllocationV4>,
    /// Complete fresh room-local genesis state. Its root is derived by the
    /// guest and compared with `genesis_state_root`; it deliberately carries
    /// no claim that room-local preset contracts already exist on L1.
    pub compact_state: CompactStateWitnessV4,
}

/// Exact statement consumed by `RoomManagerV4.openRoom`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisJournalV4 {
    pub v: u8,
    pub deployment_id: B256,
    pub room_id: u64,
    pub config_hash: B256,
    pub preset_hash: B256,
    pub manifest_hash: B256,
    pub proof_program_id: B256,
    pub l1_block_number: u64,
    pub l1_block_hash: B256,
    pub l1_state_root: B256,
    pub genesis_state_root: B256,
    pub genesis_roster_root: B256,
    pub genesis_exit_root: B256,
    pub active_mask: u8,
    pub used_mask: u8,
    pub inbox_cursor: u64,
    pub asset_totals_hash: B256,
    pub exit_totals_hash: B256,
    pub fee_totals_hash: B256,
    pub l1_inclusion_deadline: u64,
    pub exit_allocations: Vec<ExitAllocationV4>,
    pub asset_accounting: Vec<AssetAccountingV4>,
}

/// Runtime bytecode that a cold preparation proof discovered after executing
/// the supplied constructors and deterministic initializer calls.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdRuntimeCodeV4 {
    pub address: Address,
    pub code_hash: B256,
}

/// Contract account/storage shape committed by the reusable cold template.
/// It is a template namespace, not the complete room account set: future
/// member EOAs may be added when a concrete room is bound.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStateAccessV4 {
    pub address: Address,
    pub storage_slots: Vec<U256>,
}

/// Values permitted to change while a cold template is bound to a concrete
/// room. Runtime code is never refreshable. Exact slots make this policy
/// fail-closed; analyzers may deliberately list a broader set when required.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStateRefreshV4 {
    pub address: Address,
    pub refresh_nonce: bool,
    pub refresh_balance: bool,
    /// Permit room binding to supply mapping keys that were unknowable before
    /// participants were selected. Static/certified templates should prefer
    /// exact `storage_slots` whenever possible.
    pub refresh_all_storage: bool,
    pub storage_slots: Vec<U256>,
}

/// Reusable, room-independent constructor/setup statement.
///
/// `initial_state` and `setup_blocks` are private witness data. The guest
/// recomputes both roots, executes every raw transaction under Osaka, and
/// checks the resulting runtime bytecode before emitting [`ColdRoomJournalV4`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdRoomInputV4 {
    pub encoded_witness_bytes: u32,
    pub compiled_bundle_hash: B256,
    pub preset_hash: B256,
    pub manifest_hash: B256,
    pub proof_program_id: B256,
    pub initial_state_root: B256,
    pub initialized_state_root: B256,
    pub analyzed_artifact_root: B256,
    pub allowed_call_target_root: B256,
    pub initial_state: Vec<(Address, AccountState)>,
    pub setup_blocks: Vec<BatchBlockV4>,
    pub runtime_code: Vec<ColdRuntimeCodeV4>,
    pub state_access: Vec<ColdStateAccessV4>,
    pub state_refresh: Vec<ColdStateRefreshV4>,
}

/// Public output of reusable cold preparation. It intentionally omits
/// deployment, room id, participants, deposits, and live state values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdRoomJournalV4 {
    pub v: u8,
    pub template_id: B256,
    pub compiled_bundle_hash: B256,
    pub preset_hash: B256,
    pub manifest_hash: B256,
    pub proof_program_id: B256,
    pub constructor_chain_id: u64,
    pub initial_state_root: B256,
    pub initialized_state_root: B256,
    pub setup_data_hash: B256,
    pub runtime_code_root: B256,
    pub state_access_root: B256,
    pub state_refresh_root: B256,
    /// Commitment to every initialized template value except those explicitly
    /// masked by `state_refresh`. A warm room recomputes this over refreshed
    /// state, proving that only declared dynamic values changed.
    pub static_state_commitment: B256,
    pub analyzed_artifact_root: B256,
    pub allowed_call_target_root: B256,
}

/// Private input for a hot batch that consumes a cached cold receipt. The
/// outer guest verifies the cold receipt as a RISC Zero assumption, validates
/// the refresh policy against `batch.compact_state`, and then executes the
/// ordinary v4 batch. The public output remains the normal batch journal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposedBatchInputV4 {
    pub cold_journal: ColdRoomJournalV4,
    pub runtime_code: Vec<ColdRuntimeCodeV4>,
    pub state_access: Vec<ColdStateAccessV4>,
    pub state_refresh: Vec<ColdStateRefreshV4>,
    pub batch: BatchInputV4,
}
