//! Authenticated L1 state import and the room's participant-registry view.

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use std::collections::BTreeMap;
use stf_types::{import_root_v5, storage_keys_root_v5, BatchInputV5, MAX_COMPACT_PROOF_NODES_V4};

use crate::{StateMap, StfError};

pub(crate) fn verify_and_apply_import_v5(
    input: &BatchInputV5,
    state: &mut StateMap,
) -> Result<(), StfError> {
    let journal = &input.journal;
    let Some(import) = input.l1_import.as_ref() else {
        if journal.import_cursor_after != journal.import_cursor_before
            || journal.imported_l1_block != 0
            || journal.imported_l1_header_hash != B256::ZERO
            || journal.imported_l1_state_root != B256::ZERO
            || journal.import_root != B256::ZERO
        {
            return Err(StfError::LongLivedRoom(
                "empty import witness has non-empty public fields".into(),
            ));
        }
        return Ok(());
    };
    if journal.import_cursor_after != journal.import_cursor_before.saturating_add(1)
        || import.source_block != journal.imported_l1_block
        || import.header_hash != journal.imported_l1_header_hash
        || import.state_root != journal.imported_l1_state_root
        || import_root_v5(journal.room_id, input.l1_chain_id, import) != journal.import_root
        || import.expiry_block < journal.l1_inclusion_deadline
        || import.source == Address::ZERO
        || import.source_code_hash == B256::ZERO
    {
        return Err(StfError::LongLivedRoom(
            "L1 import metadata does not match the journal".into(),
        ));
    }
    if import.account_proof.len() > MAX_COMPACT_PROOF_NODES_V4
        || import.account_proof.iter().any(|node| node.len() > 1024)
    {
        return Err(StfError::LongLivedRoom(
            "L1 account proof exceeds the resource envelope".into(),
        ));
    }
    let account = TrieAccount {
        nonce: import.source_nonce,
        balance: import.source_balance,
        storage_root: import.source_storage_root,
        code_hash: import.source_code_hash,
    };
    verify_proof(
        import.state_root,
        Nibbles::unpack(keccak256(import.source).0),
        Some(alloy_rlp::encode(account)),
        &import.account_proof,
    )
    .map_err(|error| StfError::LongLivedRoom(format!("L1 account proof: {error}")))?;

    let mut previous_key = None;
    let mut values = BTreeMap::new();
    let mut proof_nodes = import.account_proof.len();
    for slot in &import.storage {
        if previous_key.is_some_and(|key| key >= slot.key) {
            return Err(StfError::LongLivedRoom(
                "L1 storage keys must be strictly sorted".into(),
            ));
        }
        previous_key = Some(slot.key);
        proof_nodes = proof_nodes
            .checked_add(slot.proof.len())
            .ok_or_else(|| StfError::LongLivedRoom("L1 proof-node count overflow".into()))?;
        if proof_nodes > MAX_COMPACT_PROOF_NODES_V4
            || slot.proof.iter().any(|node| node.len() > 1024)
        {
            return Err(StfError::LongLivedRoom(
                "L1 storage proof exceeds the resource envelope".into(),
            ));
        }
        let expected = (!slot.value.is_zero()).then(|| alloy_rlp::encode(slot.value));
        verify_proof(
            import.source_storage_root,
            Nibbles::unpack(keccak256(slot.key.to_be_bytes::<32>()).0),
            expected,
            &slot.proof,
        )
        .map_err(|error| StfError::LongLivedRoom(format!("L1 storage proof: {error}")))?;
        values.insert(slot.key, slot.value);
    }
    if storage_keys_root_v5(&values.keys().copied().collect::<Vec<_>>()) != import.storage_keys_root
    {
        return Err(StfError::LongLivedRoom(
            "authenticated L1 key set does not match storageKeysRoot".into(),
        ));
    }

    let certified = input
        .policy
        .imports
        .iter()
        .filter(|binding| {
            binding.adapter_id == import.adapter_id
                && binding.adapter_version == import.adapter_version
                && binding.source == import.source
        })
        .collect::<Vec<_>>();
    if certified.len() != import.mirror_bindings.len() {
        return Err(StfError::LongLivedRoom(
            "import mirror map is not the complete certified adapter map".into(),
        ));
    }
    for (binding, expected) in import.mirror_bindings.iter().zip(certified) {
        if binding.source_key != expected.source_key
            || binding.room_contract != expected.room_contract
            || binding.room_slot != expected.room_slot
        {
            return Err(StfError::LongLivedRoom(
                "import mirror write differs from the certified adapter".into(),
            ));
        }
        let value = values.get(&binding.source_key).copied().ok_or_else(|| {
            StfError::LongLivedRoom("import mirror source key is not authenticated".into())
        })?;
        if !state
            .access_storage
            .as_ref()
            .and_then(|allowed| allowed.get(&binding.room_contract))
            .is_some_and(|slots| slots.contains(&binding.room_slot))
        {
            return Err(StfError::LongLivedRoom(
                "import mirror destination is outside the state witness".into(),
            ));
        }
        let account = state
            .accounts
            .get_mut(&binding.room_contract)
            .ok_or_else(|| StfError::LongLivedRoom("import mirror contract is absent".into()))?;
        if value.is_zero() {
            account.storage.remove(&binding.room_slot);
        } else {
            account.storage.insert(binding.room_slot, value);
        }
    }
    Ok(())
}

pub(crate) fn participant_state_v5(
    input: &BatchInputV5,
    state: &StateMap,
) -> Result<(B256, u64, u64, u64), StfError> {
    let binding = input.policy.participant_registry.as_ref().ok_or_else(|| {
        StfError::LongLivedRoom("participant registry binding is required".into())
    })?;
    let account = state
        .accounts
        .get(&binding.contract)
        .ok_or_else(|| StfError::LongLivedRoom("participant registry contract is absent".into()))?;
    let word = |slot: U256| account.storage.get(&slot).copied().unwrap_or_default();
    let root = B256::from(word(binding.root_slot).to_be_bytes::<32>());
    let epoch_value = word(binding.epoch_slot);
    let count_value = word(binding.count_slot);
    let capacity_value = word(binding.capacity_slot);
    if epoch_value > U256::from(u64::MAX)
        || count_value > U256::from(u64::MAX)
        || capacity_value > U256::from(u64::MAX)
    {
        return Err(StfError::LongLivedRoom(
            "participant registry metadata exceeds uint64".into(),
        ));
    }
    let epoch = epoch_value.to::<u64>();
    let count = count_value.to::<u64>();
    let capacity = capacity_value.to::<u64>();
    if root == B256::ZERO
        || epoch == 0
        || capacity < 128
        || capacity > 32_768
        || !capacity.is_power_of_two()
        || count > capacity
    {
        return Err(StfError::LongLivedRoom(
            "participant registry root, epoch, count or capacity is invalid".into(),
        ));
    }
    Ok((root, epoch, count, capacity))
}
