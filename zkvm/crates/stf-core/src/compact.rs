//! Authentication of the compact v4 state witness.
//!
//! The witness is either a room-local complete state (`canonicalStateRoot`
//! zero) or an L1 multiproof; in the latter case every account and storage
//! slot is proved against the canonical root before it can be observed.

use alloy_primitives::{keccak256, B256};
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount, EMPTY_ROOT_HASH};
use std::collections::{BTreeMap, BTreeSet};
use stf_types::{
    CompactStateWitnessV4, MAX_COMPACT_ACCOUNTS_V4, MAX_COMPACT_CODE_BYTES_V4,
    MAX_COMPACT_PROOF_NODES_V4, MAX_COMPACT_STORAGE_SLOTS_V4,
};

use crate::{AccountRecord, StateMap, StfError};

pub(crate) fn verify_compact_state_v4(
    witness: &CompactStateWitnessV4,
) -> Result<StateMap, StfError> {
    if witness.accounts.len() > MAX_COMPACT_ACCOUNTS_V4 {
        return Err(StfError::CompactWitness(format!(
            "{} accounts exceeds cap {MAX_COMPACT_ACCOUNTS_V4}",
            witness.accounts.len()
        )));
    }
    let canonical = witness.canonical_state_root != B256::ZERO;
    let mut records = BTreeMap::new();
    let mut allowed_accounts = BTreeSet::new();
    let mut allowed_storage = BTreeMap::new();
    let mut storage_count = 0usize;
    let mut proof_count = 0usize;
    let mut code_bytes = 0usize;
    let mut previous_address = None;

    for account in &witness.accounts {
        if previous_address.is_some_and(|previous| previous >= account.address) {
            return Err(StfError::CompactWitness(
                "accounts must be strictly address-sorted and unique".into(),
            ));
        }
        previous_address = Some(account.address);
        code_bytes = code_bytes
            .checked_add(account.code.len())
            .ok_or_else(|| StfError::CompactWitness("code byte count overflow".into()))?;
        storage_count = storage_count
            .checked_add(account.storage.len())
            .ok_or_else(|| StfError::CompactWitness("storage count overflow".into()))?;
        proof_count = proof_count
            .checked_add(account.account_proof.len())
            .and_then(|n| {
                account
                    .storage
                    .iter()
                    .try_fold(n, |sum, slot| sum.checked_add(slot.proof.len()))
            })
            .ok_or_else(|| StfError::CompactWitness("proof count overflow".into()))?;
        if storage_count > MAX_COMPACT_STORAGE_SLOTS_V4
            || proof_count > MAX_COMPACT_PROOF_NODES_V4
            || code_bytes > MAX_COMPACT_CODE_BYTES_V4
        {
            return Err(StfError::CompactWitness(
                "account/storage/proof/code resource envelope exceeded".into(),
            ));
        }
        if account
            .account_proof
            .iter()
            .chain(account.storage.iter().flat_map(|slot| slot.proof.iter()))
            .any(|node| node.len() > 1024)
        {
            return Err(StfError::CompactWitness(
                "MPT proof node exceeds 1024 bytes".into(),
            ));
        }
        if !canonical
            && (!account.account_proof.is_empty()
                || account.storage.iter().any(|slot| !slot.proof.is_empty()))
        {
            return Err(StfError::CompactWitness(
                "later room-root witness must not smuggle unauthenticated canonical proofs".into(),
            ));
        }

        let account_value = if account.exists {
            // An EIP-161-empty account has no canonical room-trie leaf. If it
            // were admitted as `exists=true`, the same pre-state root could be
            // replayed with arbitrary hidden storage (or observably different
            // EXTCODEHASH existence semantics) and later materialise that state
            // after a nonce/balance change. Require the unique absent encoding.
            if account.nonce == 0 && account.balance.is_zero() && account.code.is_empty() {
                return Err(StfError::CompactWitness(
                    "EIP-161-empty account must be represented as absent and cannot carry storage"
                        .into(),
                ));
            }
            let trie_account = TrieAccount {
                nonce: account.nonce,
                balance: account.balance,
                storage_root: account.canonical_storage_root,
                code_hash: if account.code.is_empty() {
                    revm::primitives::KECCAK_EMPTY
                } else {
                    keccak256(&account.code)
                },
            };
            Some(alloy_rlp::encode(trie_account))
        } else {
            if account.nonce != 0
                || !account.balance.is_zero()
                || !account.code.is_empty()
                || !account.storage.is_empty()
                || account.canonical_storage_root != EMPTY_ROOT_HASH
            {
                return Err(StfError::CompactWitness(
                    "excluded account carries non-empty state".into(),
                ));
            }
            None
        };
        if canonical {
            let key = Nibbles::unpack(keccak256(account.address).0);
            verify_proof(
                witness.canonical_state_root,
                key,
                account_value,
                &account.account_proof,
            )
            .map_err(|e| StfError::CompactWitness(format!("account proof: {e}")))?;
        }

        let mut slots = BTreeSet::new();
        let mut storage = BTreeMap::new();
        let mut previous_slot = None;
        for slot in &account.storage {
            if previous_slot.is_some_and(|previous| previous >= slot.slot) {
                return Err(StfError::CompactWitness(
                    "storage slots must be strictly sorted and unique".into(),
                ));
            }
            previous_slot = Some(slot.slot);
            if canonical {
                let expected = if slot.value.is_zero() {
                    None
                } else {
                    Some(alloy_rlp::encode(slot.value))
                };
                verify_proof(
                    account.canonical_storage_root,
                    Nibbles::unpack(keccak256(slot.slot.to_be_bytes::<32>()).0),
                    expected,
                    &slot.proof,
                )
                .map_err(|e| StfError::CompactWitness(format!("storage proof: {e}")))?;
            }
            slots.insert(slot.slot);
            if !slot.value.is_zero() {
                storage.insert(slot.slot, slot.value);
            }
        }
        allowed_accounts.insert(account.address);
        allowed_storage.insert(account.address, slots);
        if account.exists {
            records.insert(
                account.address,
                AccountRecord {
                    nonce: account.nonce,
                    balance: account.balance,
                    code: account.code.clone(),
                    storage,
                },
            );
        }
    }

    Ok(StateMap::from_compact(
        records,
        allowed_accounts,
        allowed_storage,
    ))
}
