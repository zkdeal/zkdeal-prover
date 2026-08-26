//! Long-lived-room witness and policy types on the v5 engine/API surface.
//! The current `BatchJournalV5` encoding is batch protocol v6.

use alloc::vec::Vec;
use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Deserializer, Serialize};

use crate::block::{BlockEnvV1, HistoricalBlockHash};
use crate::v4::types::CompactStateWitnessV4;

/// Accept a `u64` field as a JSON number, a decimal string or a `0x`-prefixed
/// hex string, matching the way a direct JSON producer (e.g. the TypeScript
/// node emitting `bigint` values) serialises inbox, deposit and forced ids.
///
/// Non-human-readable formats (the guest's bincode witness) branch to
/// `deserialize_u64` so the wire encoding stays a fixed 8-byte integer; only
/// the human-readable JSON path is widened. This mirrors the way
/// `alloy-primitives` decodes its `U256`/`B256` fields, which already round-trip
/// through the same host-bincode/guest-bincode path.
fn deserialize_u64_or_decimal_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    use core::fmt;
    use serde::de::{self, Visitor};

    struct U64OrStringVisitor;

    impl Visitor<'_> for U64OrStringVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a u64 as a JSON number, a decimal string, or a 0x-hex string")
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<u64, E> {
            Ok(value)
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<u64, E> {
            u64::try_from(value)
                .map_err(|_| de::Error::custom("integer is negative or exceeds u64"))
        }

        fn visit_u128<E: de::Error>(self, value: u128) -> Result<u64, E> {
            u64::try_from(value).map_err(|_| de::Error::custom("integer exceeds u64"))
        }

        fn visit_i128<E: de::Error>(self, value: i128) -> Result<u64, E> {
            u64::try_from(value)
                .map_err(|_| de::Error::custom("integer is negative or exceeds u64"))
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<u64, E> {
            let trimmed = value.trim();
            let parsed = if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16)
            } else {
                trimmed.parse::<u64>()
            };
            parsed.map_err(|_| de::Error::custom("string is not a valid u64 integer"))
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_any(U64OrStringVisitor)
    } else {
        deserializer.deserialize_u64(U64OrStringVisitor)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchBlockV5 {
    pub block_number: u64,
    pub raw_txs: Vec<Bytes>,
    pub env: BlockEnvV1,
    pub block_hashes: Vec<HistoricalBlockHash>,
    pub expected_post_state_root: B256,
}

/// One active checkpoint approver in the complete positional v5 preimage.
///
/// Inactive leaves are canonical zeroes and are omitted from this vector.
/// `index` therefore remains reusable after the L1 manager has observed the
/// required withdrawal epoch, without imposing a lifetime member limit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMemberV5 {
    pub index: u64,
    pub member: Address,
    pub joined_epoch: u64,
}

/// Exact queued approver operation consumed by a v5 proof.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterChangeV5 {
    /// 0 = add, 1 = remove, matching `RoomTypes.ApproverAction`.
    pub action: u8,
    pub request_id: u64,
    pub index: u64,
    pub joined_epoch: u64,
    pub deadline: u64,
    pub member: Address,
    pub withdrawal_commitment: B256,
}

/// One operator-signed local admission promise. The EVM transaction signature
/// remains the execution authority; this signature establishes only the
/// include-or-account-for service promise.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReceiptV5 {
    pub admission_id: u64,
    pub transaction_hash: B256,
    #[serde(deserialize_with = "deserialize_u64_or_decimal_string")]
    pub deposit_inbox_id: u64,
    /// Content-addressed identity of the L1 deposit named by
    /// `deposit_inbox_id`. Zero is canonical when no deposit is attached.
    pub deposit_content_hash: B256,
    pub deadline_block: u64,
    pub maximum_batch_index: u64,
    pub bond_epoch: u64,
    pub admission_fee: U256,
    pub signature: Bytes,
}

/// 0 = succeeded, 1 = reverted, 2 = deterministically rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionOutcomeV5 {
    pub admission_id: u64,
    pub transaction_hash: B256,
    pub status: u8,
    pub l2_block_number: u64,
    pub transaction_index: u32,
    pub reason_hash: B256,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRecordV5 {
    pub receipt: AdmissionReceiptV5,
    pub outcome: AdmissionOutcomeV5,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedTransactionV5 {
    #[serde(deserialize_with = "deserialize_u64_or_decimal_string")]
    pub forced_id: u64,
    pub raw_transaction: Bytes,
    pub outcome: AdmissionOutcomeV5,
}

/// Per-asset L1 custody classification committed by every v5 batch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetLiabilityV5 {
    pub asset: Address,
    pub pending: U256,
    pub controlled: U256,
    pub claimable: U256,
    pub paid: U256,
}

/// Exact pending L1 deposit consumed by a batch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositV5 {
    #[serde(deserialize_with = "deserialize_u64_or_decimal_string")]
    pub inbox_id: u64,
    pub depositor: Address,
    pub beneficiary: Address,
    pub asset: Address,
    pub amount: U256,
    /// L1 block in which the deposit entered the room inbox.
    #[serde(deserialize_with = "deserialize_u64_or_decimal_string")]
    pub queued_at_block: u64,
    /// Pre-submission storage flags committed by `inbox_records_hash`.
    pub consumed: bool,
    pub refunded: bool,
}

/// A proof-created withdrawal. Its positional leaf is claimable on L1 as
/// soon as this batch is accepted, even when the room remains open.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalV5 {
    pub index: u64,
    #[serde(rename = "approver_epoch")]
    pub roster_epoch: u64,
    pub recipient: Address,
    pub asset: Address,
    pub amount: U256,
}

/// One authenticated storage slot from an EIP-1186 response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1StorageSlotV5 {
    pub key: U256,
    pub value: U256,
    pub proof: Vec<Bytes>,
}

/// Certified direct mapping from one authenticated L1 slot into a room-local
/// mirror slot. More expressive adapters must introduce a new adapter
/// version and proof program rather than supplying arbitrary room writes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1MirrorBindingV5 {
    pub source_key: U256,
    pub room_contract: Address,
    pub room_slot: U256,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedImportBindingV5 {
    pub adapter_id: B256,
    pub adapter_version: B256,
    pub source: Address,
    pub source_key: U256,
    pub room_contract: Address,
    pub room_slot: U256,
}

/// Private proof material for the one L1 import optionally consumed by a
/// batch. The public journal exposes only the L1 anchor and `import_root`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1ImportWitnessV5 {
    pub source_block: u64,
    pub expiry_block: u64,
    pub header_hash: B256,
    pub state_root: B256,
    pub source: Address,
    pub source_nonce: u64,
    pub source_balance: U256,
    pub source_storage_root: B256,
    pub source_code_hash: B256,
    pub account_proof: Vec<Bytes>,
    pub storage_keys_root: B256,
    pub adapter_id: B256,
    pub adapter_version: B256,
    pub storage: Vec<L1StorageSlotV5>,
    pub mirror_bindings: Vec<L1MirrorBindingV5>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCommitmentV5 {
    pub address: Address,
    pub runtime_code_hash: B256,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRuleV5 {
    /// Zero means any authenticated active member; otherwise an exact
    /// code-pinned caller.
    pub caller: Address,
    pub target: Address,
    pub selectors: Vec<[u8; 4]>,
    /// 0 = CALL, 1 = STATICCALL, 2 = DELEGATECALL.
    pub kinds: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageNamespaceV5 {
    pub contract: Address,
    pub slot_prefix: U256,
    pub prefix_bits: u16,
    pub writable: bool,
}

/// Application-level Merkle participant state kept separate from the
/// checkpoint-approver root. The four slots are committed by policy and read
/// directly before and after execution.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantRegistryBindingV5 {
    pub contract: Address,
    pub root_slot: U256,
    pub epoch_slot: U256,
    pub count_slot: U256,
    pub capacity_slot: U256,
}

/// One asset the room-local exit queue may pay out. `kind` 0 is the native
/// room asset (zero `asset`, `token` and `balance_slot`); `kind` 1 reads the
/// recipient balance from `token`'s `balance_slot` mapping.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitAssetBindingV5 {
    pub asset: Address,
    /// 0 = native, 1 = ERC-20.
    pub kind: u8,
    pub token: Address,
    pub balance_slot: U256,
}

/// Room-local exit-queue authority for validity-only withdrawals. The queue
/// contract is code-pinned by policy; the proved post-state of its `count_slot`
/// and record slots is what mints withdrawal leaves.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitBindingV5 {
    pub queue_contract: Address,
    pub count_slot: U256,
    /// Record `i` occupies slots `records_base_slot + 3*i` (recipient),
    /// `+ 3*i + 1` (asset) and `+ 3*i + 2` (amount).
    pub records_base_slot: U256,
    /// Sorted unique by `asset`.
    pub assets: Vec<ExitAssetBindingV5>,
    /// Receives close-time sweep dust and unattributable residuals.
    pub fallback_recipient: Address,
}

/// Structured certified policy. Its canonical binary commitment is derived
/// by [`crate::execution_policy_hash_v5`]; JSON formatting is not consensus data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPolicyV5 {
    /// 0 = Ethereum MPT, 1 = proof-efficient sparse room tree.
    pub state_commitment: u8,
    pub max_blocks_per_batch: u64,
    pub max_transactions_per_block: u64,
    pub max_gas_per_block: u64,
    pub max_memory_bytes: u64,
    pub allow_contract_creation: bool,
    pub allow_self_destruct: bool,
    pub code: Vec<CodeCommitmentV5>,
    pub calls: Vec<CallRuleV5>,
    pub storage: Vec<StorageNamespaceV5>,
    pub imports: Vec<CertifiedImportBindingV5>,
    pub participant_registry: Option<ParticipantRegistryBindingV5>,
    /// Optional room-local exit-queue authority. Absent on stored legacy
    /// policies, whose canonical hash stays byte-identical.
    #[serde(default)]
    pub exit: Option<ExitBindingV5>,
}

/// The complete private input for one long-lived room transition.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchInputV5 {
    pub encoded_witness_bytes: u32,
    pub l1_chain_id: u64,
    pub journal: BatchJournalV5,
    pub policy: ExecutionPolicyV5,
    #[serde(rename = "approver_capacity")]
    pub roster_capacity: u64,
    #[serde(rename = "pre_approvers")]
    pub pre_roster: Vec<RosterMemberV5>,
    #[serde(rename = "post_approvers")]
    pub post_roster: Vec<RosterMemberV5>,
    #[serde(rename = "approver_changes")]
    pub roster_changes: Vec<RosterChangeV5>,
    pub admissions: Vec<AdmissionRecordV5>,
    pub forced_transactions: Vec<ForcedTransactionV5>,
    /// Exact public bytes placed in Ethereum calldata for validity-only rooms.
    pub canonical_batch_data: Bytes,
    pub pre_liabilities: Vec<AssetLiabilityV5>,
    pub post_liabilities: Vec<AssetLiabilityV5>,
    pub deposits: Vec<DepositV5>,
    pub withdrawals: Vec<WithdrawalV5>,
    pub withdrawal_capacity: u64,
    pub l1_import: Option<L1ImportWitnessV5>,
    pub compact_state: CompactStateWitnessV4,
    pub blocks: Vec<BatchBlockV5>,
}

/// Solidity-compatible `RoomTypes.BatchJournal`. The RISC Zero receipt
/// commits exactly [`crate::hash_batch_journal_v5`] and the L1 manager recomputes
/// the same hash from calldata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchJournalV5 {
    pub protocol_version: u8,
    pub deployment_domain: B256,
    pub room_id: u64,
    /// 0 = unanimous approvers, 1 = validity-only.
    pub authorization_mode: u8,
    pub cold_template_id: B256,
    pub proof_program_id: B256,
    pub proof_system_version: B256,
    pub policy_hash: B256,
    pub batch_index: u64,
    pub start_l2_block: u64,
    pub end_l2_block: u64,
    pub pre_state_root: B256,
    pub post_state_root: B256,
    pub batch_data_hash: B256,
    pub canonical_data_hash: B256,
    pub pre_participant_root: B256,
    pub post_participant_root: B256,
    pub pre_participant_epoch: u64,
    pub post_participant_epoch: u64,
    pub pre_participant_count: u64,
    pub post_participant_count: u64,
    pub participant_capacity: u64,
    #[serde(rename = "pre_approver_root")]
    pub pre_roster_root: B256,
    #[serde(rename = "post_approver_root")]
    pub post_roster_root: B256,
    #[serde(rename = "pre_approver_epoch")]
    pub pre_roster_epoch: u64,
    #[serde(rename = "post_approver_epoch")]
    pub post_roster_epoch: u64,
    pub pre_active_count: u64,
    pub post_active_count: u64,
    #[serde(rename = "approver_change_cursor_before")]
    pub roster_change_cursor_before: u64,
    #[serde(rename = "approver_change_cursor_after")]
    pub roster_change_cursor_after: u64,
    pub inbox_cursor_before: u64,
    pub inbox_cursor_after: u64,
    /// Exact commitment to every L1 inbox record crossed by this batch,
    /// including terminal refunded records that contribute no liability.
    pub inbox_records_hash: B256,
    pub admission_cursor_before: u64,
    pub admission_cursor_after: u64,
    pub admission_records_hash: B256,
    pub forced_cursor_before: u64,
    pub forced_cursor_after: u64,
    pub forced_outcomes_hash: B256,
    pub import_cursor_before: u64,
    pub import_cursor_after: u64,
    pub imported_l1_block: u64,
    pub imported_l1_header_hash: B256,
    pub imported_l1_state_root: B256,
    pub import_root: B256,
    pub outbox_epoch: u64,
    pub withdrawal_root: B256,
    pub pre_liabilities_hash: B256,
    pub post_liabilities_hash: B256,
    #[serde(rename = "approver_changes_hash")]
    pub roster_changes_hash: B256,
    pub l1_inclusion_deadline: u64,
    pub close: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdTemplateInputV5 {
    pub template_id: B256,
    pub initial_state_root: B256,
    pub policy_hash: B256,
    pub proof_program_id: B256,
    pub proof_system_version: B256,
    pub policy: ExecutionPolicyV5,
    pub compact_state: CompactStateWitnessV4,
}
