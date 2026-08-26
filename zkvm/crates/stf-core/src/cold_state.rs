//! Shape rules and the static-state commitment shared by every cold v4
//! statement.
//!
//! The commitment is recomputed over both the initialized cold state and a
//! room's refreshed prestate, so a cold proof stays reusable while undeclared
//! static changes fail closed.

use alloy_primitives::{keccak256, Address, B256, U256};
use std::collections::BTreeMap;
use stf_types::{
    hash_cold_state_access_v4, hash_cold_state_refresh_v4, ColdRuntimeCodeV4, ColdStateAccessV4,
    ColdStateRefreshV4, MAX_COMPACT_ACCOUNTS_V4, MAX_COMPACT_STORAGE_SLOTS_V4,
};

use crate::{StateMap, StfError};

fn cold_word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn cold_word_address(value: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(value.as_slice());
    word
}

fn cold_hash_words(words: impl IntoIterator<Item = [u8; 32]>) -> B256 {
    let words = words.into_iter().collect::<Vec<_>>();
    let mut encoded = Vec::with_capacity(words.len() * 32);
    for word in words {
        encoded.extend_from_slice(&word);
    }
    keccak256(encoded)
}

pub(crate) fn validate_cold_shapes_v4(
    runtime_code: &[ColdRuntimeCodeV4],
    state_access: &[ColdStateAccessV4],
    state_refresh: &[ColdStateRefreshV4],
) -> Result<(), StfError> {
    let fail = |message: &str| StfError::ColdPreparation(message.into());
    if runtime_code.len() > MAX_COMPACT_ACCOUNTS_V4
        || state_access.len() > MAX_COMPACT_ACCOUNTS_V4
        || state_refresh.len() > MAX_COMPACT_ACCOUNTS_V4
    {
        return Err(fail("runtime/access/refresh account cap exceeded"));
    }
    for pair in runtime_code.windows(2) {
        if pair[0].address >= pair[1].address {
            return Err(fail(
                "runtime code must be strictly address-sorted and unique",
            ));
        }
    }
    if runtime_code
        .iter()
        .any(|entry| entry.code_hash == B256::ZERO)
    {
        return Err(fail("runtime code hash cannot be zero"));
    }

    let mut access_by_address = BTreeMap::new();
    let mut access_slots = 0usize;
    for access in state_access {
        if access_by_address
            .insert(access.address, &access.storage_slots)
            .is_some()
        {
            return Err(fail("state access accounts must be unique"));
        }
        if access
            .storage_slots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(fail(
                "state access slots must be strictly sorted and unique",
            ));
        }
        access_slots = access_slots
            .checked_add(access.storage_slots.len())
            .ok_or_else(|| fail("state access slot count overflow"))?;
    }
    if state_access
        .windows(2)
        .any(|pair| pair[0].address >= pair[1].address)
    {
        return Err(fail(
            "state access accounts must be strictly address-sorted",
        ));
    }
    if access_slots > MAX_COMPACT_STORAGE_SLOTS_V4 {
        return Err(fail("state access slot cap exceeded"));
    }
    for code in runtime_code {
        if !access_by_address.contains_key(&code.address) {
            return Err(fail(
                "every runtime contract must have a state access entry",
            ));
        }
    }

    let mut previous_refresh = None;
    for refresh in state_refresh {
        if previous_refresh.is_some_and(|previous| previous >= refresh.address) {
            return Err(fail(
                "state refresh accounts must be strictly address-sorted and unique",
            ));
        }
        previous_refresh = Some(refresh.address);
        let Some(allowed_slots) = access_by_address.get(&refresh.address) else {
            return Err(fail(
                "state refresh account is outside the template access set",
            ));
        };
        if refresh
            .storage_slots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(fail(
                "state refresh slots must be strictly sorted and unique",
            ));
        }
        if !refresh.refresh_all_storage
            && refresh
                .storage_slots
                .iter()
                .any(|slot| allowed_slots.binary_search(slot).is_err())
        {
            return Err(fail(
                "state refresh slot is outside the template access set",
            ));
        }
    }
    Ok(())
}

pub(crate) fn verify_cold_runtime_code_v4(
    state: &StateMap,
    runtime_code: &[ColdRuntimeCodeV4],
) -> Result<(), StfError> {
    let expected = runtime_code
        .iter()
        .map(|entry| (entry.address, entry.code_hash))
        .collect::<BTreeMap<_, _>>();
    for entry in runtime_code {
        let Some(account) = state.accounts.get(&entry.address) else {
            return Err(StfError::ColdPreparation(format!(
                "prepared runtime account {} is absent",
                entry.address
            )));
        };
        if account.code.is_empty() || account.code_hash() != entry.code_hash {
            return Err(StfError::ColdPreparation(format!(
                "prepared runtime code hash mismatch at {}",
                entry.address
            )));
        }
    }
    // A cold proof must not conceal an extra deployed contract outside the
    // committed bundle. Future member EOAs are code-empty and remain allowed.
    for (address, account) in &state.accounts {
        if !account.code.is_empty() && !expected.contains_key(address) {
            return Err(StfError::ColdPreparation(format!(
                "uncommitted runtime code at {address}"
            )));
        }
    }
    Ok(())
}

/// Commit every template value that is not explicitly refreshable. This is
/// recomputed over both the initialized cold state and a room's refreshed
/// prestate, so constructor execution never has to be repeated on the hot
/// path while undeclared static changes still fail closed.
pub fn cold_static_state_commitment_v4(
    state: &StateMap,
    state_access: &[ColdStateAccessV4],
    state_refresh: &[ColdStateRefreshV4],
) -> Result<B256, StfError> {
    validate_cold_shapes_v4(&[], state_access, state_refresh)?;
    let refresh = state_refresh
        .iter()
        .map(|entry| (entry.address, entry))
        .collect::<BTreeMap<_, _>>();
    let access_root = hash_cold_state_access_v4(state_access);
    let refresh_root = hash_cold_state_refresh_v4(state_refresh);
    let account_type = keccak256(b"ColdStaticAccountV4(address account,uint64 nonce,uint256 balance,bytes32 codeHash,bytes32 staticStorageHash)");
    let storage_type = keccak256(b"ColdStaticStorageV4(uint256 slot,uint256 value)");
    let mut account_hashes = Vec::with_capacity(state_access.len());
    for access in state_access {
        let account = state.accounts.get(&access.address).ok_or_else(|| {
            StfError::ColdPreparation(format!(
                "template access account {} is absent",
                access.address
            ))
        })?;
        let rule = refresh.get(&access.address).copied();
        if !rule.is_some_and(|entry| entry.refresh_all_storage)
            && account
                .storage
                .keys()
                .any(|slot| access.storage_slots.binary_search(slot).is_err())
        {
            return Err(StfError::ColdPreparation(format!(
                "account {} contains storage outside its cold access set",
                access.address
            )));
        }
        let mut storage_encoded = Vec::new();
        storage_encoded.extend_from_slice(keccak256(b"ColdStaticStorageV4[]").as_slice());
        let static_slots = if rule.is_some_and(|entry| entry.refresh_all_storage) {
            Vec::new()
        } else {
            access
                .storage_slots
                .iter()
                .filter(|slot| {
                    !rule.is_some_and(|entry| entry.storage_slots.binary_search(slot).is_ok())
                })
                .copied()
                .collect::<Vec<_>>()
        };
        storage_encoded.extend_from_slice(&cold_word_u64(static_slots.len() as u64));
        for slot in static_slots {
            let value = account.storage.get(&slot).copied().unwrap_or_default();
            storage_encoded.extend_from_slice(
                cold_hash_words([
                    storage_type.0,
                    slot.to_be_bytes::<32>(),
                    value.to_be_bytes::<32>(),
                ])
                .as_slice(),
            );
        }
        let storage_hash = keccak256(storage_encoded);
        let nonce = if rule.is_some_and(|entry| entry.refresh_nonce) {
            0
        } else {
            account.nonce
        };
        let balance = if rule.is_some_and(|entry| entry.refresh_balance) {
            U256::ZERO
        } else {
            account.balance
        };
        account_hashes.push(cold_hash_words([
            account_type.0,
            cold_word_address(access.address),
            cold_word_u64(nonce),
            balance.to_be_bytes::<32>(),
            account.code_hash().0,
            storage_hash.0,
        ]));
    }
    let mut encoded = Vec::with_capacity((4 + account_hashes.len()) * 32);
    encoded.extend_from_slice(keccak256(b"ColdStaticStateV4(bytes32 stateAccessRoot,bytes32 stateRefreshRoot,bytes32 accountHashes)").as_slice());
    encoded.extend_from_slice(access_root.as_slice());
    encoded.extend_from_slice(refresh_root.as_slice());
    encoded.extend_from_slice(&cold_word_u64(account_hashes.len() as u64));
    for hash in account_hashes {
        encoded.extend_from_slice(hash.as_slice());
    }
    Ok(keccak256(encoded))
}
