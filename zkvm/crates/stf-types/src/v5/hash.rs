//! Commitments on the v5 engine/API surface: the protocol-v6 journal hash
//! consumed by `RoomManager`, positional roster/withdrawal trees, and policy
//! and import roots.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, B256, U256};

use crate::abi::{
    abi_address_word_v5, abi_bool_word_v5, abi_u256_word_v5, abi_u64_word_v5, keccak_words_v5,
};
use crate::limits::{MAX_POSITIONAL_CAPACITY_V5, MAX_WITHDRAWAL_CAPACITY_V5};
use crate::v5::types::{
    AdmissionRecordV5, AssetLiabilityV5, BatchJournalV5, ColdTemplateInputV5, DepositV5,
    ExecutionPolicyV5, ForcedTransactionV5, L1ImportWitnessV5, L1StorageSlotV5, RosterChangeV5,
    RosterMemberV5, WithdrawalV5,
};

/// Exact `keccak256(abi.encode(journal))` consumed by `RoomManager`.
pub fn hash_batch_journal_v5(journal: &BatchJournalV5) -> B256 {
    keccak_words_v5([
        abi_u64_word_v5(u64::from(journal.protocol_version)),
        journal.deployment_domain.0,
        abi_u64_word_v5(journal.room_id),
        abi_u64_word_v5(u64::from(journal.authorization_mode)),
        journal.cold_template_id.0,
        journal.proof_program_id.0,
        journal.proof_system_version.0,
        journal.policy_hash.0,
        abi_u64_word_v5(journal.batch_index),
        abi_u64_word_v5(journal.start_l2_block),
        abi_u64_word_v5(journal.end_l2_block),
        journal.pre_state_root.0,
        journal.post_state_root.0,
        journal.batch_data_hash.0,
        journal.canonical_data_hash.0,
        journal.pre_participant_root.0,
        journal.post_participant_root.0,
        abi_u64_word_v5(journal.pre_participant_epoch),
        abi_u64_word_v5(journal.post_participant_epoch),
        abi_u64_word_v5(journal.pre_participant_count),
        abi_u64_word_v5(journal.post_participant_count),
        abi_u64_word_v5(journal.participant_capacity),
        journal.pre_roster_root.0,
        journal.post_roster_root.0,
        abi_u64_word_v5(journal.pre_roster_epoch),
        abi_u64_word_v5(journal.post_roster_epoch),
        abi_u64_word_v5(journal.pre_active_count),
        abi_u64_word_v5(journal.post_active_count),
        abi_u64_word_v5(journal.roster_change_cursor_before),
        abi_u64_word_v5(journal.roster_change_cursor_after),
        abi_u64_word_v5(journal.inbox_cursor_before),
        abi_u64_word_v5(journal.inbox_cursor_after),
        journal.inbox_records_hash.0,
        abi_u64_word_v5(journal.admission_cursor_before),
        abi_u64_word_v5(journal.admission_cursor_after),
        journal.admission_records_hash.0,
        abi_u64_word_v5(journal.forced_cursor_before),
        abi_u64_word_v5(journal.forced_cursor_after),
        journal.forced_outcomes_hash.0,
        abi_u64_word_v5(journal.import_cursor_before),
        abi_u64_word_v5(journal.import_cursor_after),
        abi_u64_word_v5(journal.imported_l1_block),
        journal.imported_l1_header_hash.0,
        journal.imported_l1_state_root.0,
        journal.import_root.0,
        abi_u64_word_v5(journal.outbox_epoch),
        journal.withdrawal_root.0,
        journal.pre_liabilities_hash.0,
        journal.post_liabilities_hash.0,
        journal.roster_changes_hash.0,
        abi_u64_word_v5(journal.l1_inclusion_deadline),
        abi_bool_word_v5(journal.close),
    ])
}

pub fn cold_template_id_v5(
    initial_state_root: B256,
    policy_hash: B256,
    proof_system_version: B256,
) -> B256 {
    let mut encoded = Vec::with_capacity(32 * 4);
    encoded.extend_from_slice(keccak256(b"zkdeal/cold-template-id/v5").as_slice());
    encoded.extend_from_slice(initial_state_root.as_slice());
    encoded.extend_from_slice(policy_hash.as_slice());
    encoded.extend_from_slice(proof_system_version.as_slice());
    keccak256(encoded)
}

/// Exact statement checked by `ColdTemplateRegistry.register`: the v6 domain
/// binds the canonical genesis-package hash alongside the template identity.
pub fn cold_template_statement_v6(input: &ColdTemplateInputV5, genesis_data_hash: B256) -> B256 {
    let label = b"zkdeal/cold-template/v6";
    let mut encoded = Vec::with_capacity(32 * 9);
    encoded.extend_from_slice(&abi_u64_word_v5(32 * 7));
    encoded.extend_from_slice(input.template_id.as_slice());
    encoded.extend_from_slice(input.initial_state_root.as_slice());
    encoded.extend_from_slice(input.policy_hash.as_slice());
    encoded.extend_from_slice(input.proof_program_id.as_slice());
    encoded.extend_from_slice(input.proof_system_version.as_slice());
    encoded.extend_from_slice(genesis_data_hash.as_slice());
    encoded.extend_from_slice(&abi_u64_word_v5(label.len() as u64));
    encoded.extend_from_slice(label);
    encoded.resize(32 * 9, 0);
    keccak256(encoded)
}

/// Positional roster tree used by L1 membership proofs.
pub fn roster_root_v5(members: &[RosterMemberV5], capacity: u64) -> Option<B256> {
    if capacity == 0 || !capacity.is_power_of_two() || capacity > MAX_POSITIONAL_CAPACITY_V5 {
        return None;
    }
    let capacity = usize::try_from(capacity).ok()?;
    let mut leaves = vec![B256::ZERO; capacity];
    let mut previous = None;
    for member in members {
        let index = usize::try_from(member.index).ok()?;
        if index >= capacity
            || member.member == Address::ZERO
            || member.joined_epoch == 0
            || previous.is_some_and(|prior| prior >= member.index)
        {
            return None;
        }
        previous = Some(member.index);
        leaves[index] = keccak_words_v5([
            abi_u64_word_v5(member.index),
            abi_address_word_v5(member.member),
            abi_u64_word_v5(member.joined_epoch),
        ]);
    }
    while leaves.len() > 1 {
        leaves = leaves
            .chunks_exact(2)
            .map(|pair| {
                let mut bytes = [0u8; 64];
                bytes[..32].copy_from_slice(pair[0].as_slice());
                bytes[32..].copy_from_slice(pair[1].as_slice());
                keccak256(bytes)
            })
            .collect();
    }
    leaves.pop()
}

pub fn roster_change_hash_v5(change: &RosterChangeV5) -> B256 {
    keccak_words_v5([
        abi_u64_word_v5(change.request_id),
        abi_u64_word_v5(u64::from(change.action)),
        abi_u64_word_v5(change.index),
        abi_u64_word_v5(change.joined_epoch),
        abi_u64_word_v5(change.deadline),
        abi_address_word_v5(change.member),
        change.withdrawal_commitment.0,
    ])
}

pub fn roster_changes_hash_v5(changes: &[RosterChangeV5]) -> B256 {
    let mut words = Vec::with_capacity(changes.len() + 2);
    words.push(abi_u64_word_v5(32));
    words.push(abi_u64_word_v5(changes.len() as u64));
    words.extend(changes.iter().map(|change| roster_change_hash_v5(change).0));
    keccak_words_v5(words)
}

pub fn admission_record_hash_v5(record: &AdmissionRecordV5) -> B256 {
    keccak_words_v5([
        abi_u64_word_v5(record.receipt.admission_id),
        record.receipt.transaction_hash.0,
        abi_u64_word_v5(record.receipt.deposit_inbox_id),
        record.receipt.deposit_content_hash.0,
        abi_u64_word_v5(record.receipt.deadline_block),
        abi_u64_word_v5(record.receipt.maximum_batch_index),
        abi_u64_word_v5(record.receipt.bond_epoch),
        abi_u256_word_v5(record.receipt.admission_fee),
        keccak256(record.receipt.signature.as_ref()).0,
        abi_u64_word_v5(record.outcome.admission_id),
        record.outcome.transaction_hash.0,
        abi_u64_word_v5(u64::from(record.outcome.status)),
        abi_u64_word_v5(record.outcome.l2_block_number),
        abi_u64_word_v5(u64::from(record.outcome.transaction_index)),
        record.outcome.reason_hash.0,
    ])
}

/// Exact `keccak256(abi.encode(depositor, beneficiary, asset, amount))`
/// identity used by the v6 admission receipt.
pub fn deposit_content_hash_v5(deposit: &DepositV5) -> B256 {
    keccak_words_v5([
        abi_address_word_v5(deposit.depositor),
        abi_address_word_v5(deposit.beneficiary),
        abi_address_word_v5(deposit.asset),
        abi_u256_word_v5(deposit.amount),
    ])
}

/// Exact pre-submission L1 inbox leaf committed by `BatchJournal` v6.
pub fn inbox_record_hash_v5(deposit: &DepositV5) -> B256 {
    keccak_words_v5([
        abi_u64_word_v5(deposit.inbox_id),
        deposit_content_hash_v5(deposit).0,
        abi_u64_word_v5(deposit.queued_at_block),
        abi_bool_word_v5(deposit.consumed),
        abi_bool_word_v5(deposit.refunded),
    ])
}

/// Exact `keccak256(abi.encode(bytes32[] leaves))` range commitment. The
/// empty range therefore hashes the canonical ABI offset and zero length.
pub fn inbox_records_hash_v5(deposits: &[DepositV5]) -> B256 {
    let mut words = Vec::with_capacity(deposits.len() + 2);
    words.push(abi_u64_word_v5(32));
    words.push(abi_u64_word_v5(deposits.len() as u64));
    words.extend(
        deposits
            .iter()
            .map(|deposit| inbox_record_hash_v5(deposit).0),
    );
    keccak_words_v5(words)
}

pub fn admission_records_hash_v5(records: &[AdmissionRecordV5]) -> B256 {
    let mut words = Vec::with_capacity(records.len() + 2);
    words.push(abi_u64_word_v5(32));
    words.push(abi_u64_word_v5(records.len() as u64));
    words.extend(
        records
            .iter()
            .map(|record| admission_record_hash_v5(record).0),
    );
    keccak_words_v5(words)
}

pub fn forced_outcome_hash_v5(forced: &ForcedTransactionV5) -> B256 {
    keccak_words_v5([
        abi_u64_word_v5(forced.forced_id),
        keccak256(forced.raw_transaction.as_ref()).0,
        abi_u64_word_v5(u64::from(forced.outcome.status)),
        abi_u64_word_v5(forced.outcome.l2_block_number),
        abi_u64_word_v5(u64::from(forced.outcome.transaction_index)),
        forced.outcome.reason_hash.0,
    ])
}

pub fn forced_outcomes_hash_v5(forced: &[ForcedTransactionV5]) -> B256 {
    let mut words = Vec::with_capacity(forced.len() + 2);
    words.push(abi_u64_word_v5(32));
    words.push(abi_u64_word_v5(forced.len() as u64));
    words.extend(forced.iter().map(|item| forced_outcome_hash_v5(item).0));
    keccak_words_v5(words)
}

/// The raw transaction is not a valid room transaction at all: unsupported
/// envelope, malformed RLP, wrong or absent chain id, non-zero fee fields,
/// unusable nonce, or unrecoverable signature.
pub const FORCED_REJECTION_UNDECODABLE_V5: u8 = 1;
/// The transaction decodes, but its root call is outside the certified
/// execution policy, so no block of this room could ever contain it.
pub const FORCED_REJECTION_POLICY_V5: u8 = 2;
/// The transaction decodes and is policy-admissible, but the sender account
/// at the terminal state of the batch cannot execute it (nonce mismatch or
/// insufficient balance for the transferred value).
pub const FORCED_REJECTION_SENDER_V5: u8 = 3;

/// Canonical commitment for a proved deterministic rejection of an L1 forced
/// transaction. The guest derives this value from the reason it proved; it is
/// never accepted as witness input, so `reason_hash` cannot be an arbitrary
/// label attached to an unexamined transaction.
pub fn forced_rejection_reason_hash_v5(transaction_hash: B256, reason: u8) -> B256 {
    keccak_words_v5([
        keccak256(b"zkdeal/forced-rejection/v5").0,
        transaction_hash.0,
        abi_u64_word_v5(u64::from(reason)),
    ])
}

pub fn liabilities_hash_v5(values: &[AssetLiabilityV5]) -> B256 {
    let mut words = Vec::with_capacity(values.len() * 5 + 2);
    words.push(abi_u64_word_v5(32));
    words.push(abi_u64_word_v5(values.len() as u64));
    for value in values {
        words.extend([
            abi_address_word_v5(value.asset),
            abi_u256_word_v5(value.pending),
            abi_u256_word_v5(value.controlled),
            abi_u256_word_v5(value.claimable),
            abi_u256_word_v5(value.paid),
        ]);
    }
    keccak_words_v5(words)
}

pub fn withdrawal_leaf_v5(
    deployment_domain: B256,
    room_id: u64,
    outbox_epoch: u64,
    withdrawal: &WithdrawalV5,
) -> B256 {
    keccak_words_v5([
        deployment_domain.0,
        abi_u64_word_v5(room_id),
        abi_u64_word_v5(outbox_epoch),
        abi_u64_word_v5(withdrawal.index),
        abi_u64_word_v5(withdrawal.roster_epoch),
        abi_address_word_v5(withdrawal.recipient),
        abi_address_word_v5(withdrawal.asset),
        abi_u256_word_v5(withdrawal.amount),
    ])
}

pub fn withdrawal_root_v5(
    deployment_domain: B256,
    room_id: u64,
    outbox_epoch: u64,
    withdrawals: &[WithdrawalV5],
    capacity: u64,
) -> Option<B256> {
    if withdrawals.is_empty() {
        return Some(B256::ZERO);
    }
    if capacity == 0 || !capacity.is_power_of_two() || capacity > MAX_WITHDRAWAL_CAPACITY_V5 {
        return None;
    }
    let capacity = usize::try_from(capacity).ok()?;
    let mut leaves = vec![B256::ZERO; capacity];
    let mut previous = None;
    for withdrawal in withdrawals {
        let index = usize::try_from(withdrawal.index).ok()?;
        if index >= capacity
            || withdrawal.recipient == Address::ZERO
            || withdrawal.amount.is_zero()
            || previous.is_some_and(|prior| prior >= withdrawal.index)
        {
            return None;
        }
        previous = Some(withdrawal.index);
        leaves[index] = withdrawal_leaf_v5(deployment_domain, room_id, outbox_epoch, withdrawal);
    }
    while leaves.len() > 1 {
        leaves = leaves
            .chunks_exact(2)
            .map(|pair| {
                let mut bytes = [0u8; 64];
                bytes[..32].copy_from_slice(pair[0].as_slice());
                bytes[32..].copy_from_slice(pair[1].as_slice());
                keccak256(bytes)
            })
            .collect();
    }
    leaves.pop()
}

/// Hash the authenticated key set exactly once. Keys must be sorted before
/// this function is called.
pub fn storage_keys_root_v5(keys: &[U256]) -> B256 {
    let mut encoded = Vec::with_capacity(32 + keys.len() * 32);
    encoded.extend_from_slice(b"zkdeal/l1-storage-keys/v5");
    for key in keys {
        encoded.extend_from_slice(&key.to_be_bytes::<32>());
    }
    keccak256(encoded)
}

pub fn import_payload_commitment_v5(storage: &[L1StorageSlotV5]) -> B256 {
    let mut encoded = Vec::with_capacity(32 + storage.len() * 64);
    encoded.extend_from_slice(b"zkdeal/l1-storage-values/v5");
    for slot in storage {
        encoded.extend_from_slice(&slot.key.to_be_bytes::<32>());
        encoded.extend_from_slice(&slot.value.to_be_bytes::<32>());
    }
    keccak256(encoded)
}

pub fn import_policy_leaf_v5(chain_id: u64, import: &L1ImportWitnessV5) -> B256 {
    keccak_words_v5([
        abi_u64_word_v5(chain_id),
        abi_address_word_v5(import.source),
        import.source_code_hash.0,
        import.storage_keys_root.0,
        import.adapter_id.0,
        import.adapter_version.0,
    ])
}

pub fn import_root_v5(room_id: u64, chain_id: u64, import: &L1ImportWitnessV5) -> B256 {
    keccak_words_v5([
        abi_u64_word_v5(room_id),
        abi_u64_word_v5(import.source_block),
        import.header_hash.0,
        import.state_root.0,
        import_policy_leaf_v5(chain_id, import).0,
        import_payload_commitment_v5(&import.storage).0,
        abi_u64_word_v5(import.expiry_block),
    ])
}

/// Canonical commitment to the certified execution and import-mapping policy.
pub fn execution_policy_hash_v5(policy: &ExecutionPolicyV5) -> B256 {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"zkdeal/execution-policy/v5");
    encoded.push(policy.state_commitment);
    encoded.extend_from_slice(&policy.max_blocks_per_batch.to_be_bytes());
    encoded.extend_from_slice(&policy.max_transactions_per_block.to_be_bytes());
    encoded.extend_from_slice(&policy.max_gas_per_block.to_be_bytes());
    encoded.extend_from_slice(&policy.max_memory_bytes.to_be_bytes());
    encoded.push(u8::from(policy.allow_contract_creation));
    encoded.push(u8::from(policy.allow_self_destruct));
    encoded.extend_from_slice(&(policy.code.len() as u64).to_be_bytes());
    for code in &policy.code {
        encoded.extend_from_slice(code.address.as_slice());
        encoded.extend_from_slice(code.runtime_code_hash.as_slice());
    }
    encoded.extend_from_slice(&(policy.calls.len() as u64).to_be_bytes());
    for call in &policy.calls {
        encoded.extend_from_slice(call.caller.as_slice());
        encoded.extend_from_slice(call.target.as_slice());
        encoded.extend_from_slice(&(call.selectors.len() as u64).to_be_bytes());
        for selector in &call.selectors {
            encoded.extend_from_slice(selector);
        }
        encoded.extend_from_slice(&(call.kinds.len() as u64).to_be_bytes());
        encoded.extend_from_slice(&call.kinds);
    }
    encoded.extend_from_slice(&(policy.storage.len() as u64).to_be_bytes());
    for namespace in &policy.storage {
        encoded.extend_from_slice(namespace.contract.as_slice());
        encoded.extend_from_slice(&namespace.slot_prefix.to_be_bytes::<32>());
        encoded.extend_from_slice(&namespace.prefix_bits.to_be_bytes());
        encoded.push(u8::from(namespace.writable));
    }
    encoded.extend_from_slice(&(policy.imports.len() as u64).to_be_bytes());
    for binding in &policy.imports {
        encoded.extend_from_slice(binding.adapter_id.as_slice());
        encoded.extend_from_slice(binding.adapter_version.as_slice());
        encoded.extend_from_slice(binding.source.as_slice());
        encoded.extend_from_slice(&binding.source_key.to_be_bytes::<32>());
        encoded.extend_from_slice(binding.room_contract.as_slice());
        encoded.extend_from_slice(&binding.room_slot.to_be_bytes::<32>());
    }
    match &policy.participant_registry {
        Some(binding) => {
            encoded.push(1);
            encoded.extend_from_slice(binding.contract.as_slice());
            encoded.extend_from_slice(&binding.root_slot.to_be_bytes::<32>());
            encoded.extend_from_slice(&binding.epoch_slot.to_be_bytes::<32>());
            encoded.extend_from_slice(&binding.count_slot.to_be_bytes::<32>());
            encoded.extend_from_slice(&binding.capacity_slot.to_be_bytes::<32>());
        }
        None => encoded.push(0),
    }
    // Optional tail: a policy without an exit binding appends nothing, so
    // every stored legacy policy hash stays byte-identical, and the fields
    // below are all fixed-width or length-prefixed, so the encoding stays
    // injective against the legacy form.
    if let Some(exit) = &policy.exit {
        encoded.push(1);
        encoded.extend_from_slice(exit.queue_contract.as_slice());
        encoded.extend_from_slice(&exit.count_slot.to_be_bytes::<32>());
        encoded.extend_from_slice(&exit.records_base_slot.to_be_bytes::<32>());
        encoded.extend_from_slice(&(exit.assets.len() as u64).to_be_bytes());
        for asset in &exit.assets {
            encoded.extend_from_slice(asset.asset.as_slice());
            encoded.push(asset.kind);
            encoded.extend_from_slice(asset.token.as_slice());
            encoded.extend_from_slice(&asset.balance_slot.to_be_bytes::<32>());
        }
        encoded.extend_from_slice(exit.fallback_recipient.as_slice());
    }
    keccak256(encoded)
}
