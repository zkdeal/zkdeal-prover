//! The fixture's opening room state, its compact witness, and the certified
//! L1 import the room mirrors.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use stf_types::{
    storage_keys_root_v5, AccountState, CertifiedImportBindingV5, CompactAccountWitnessV4,
    CompactStateWitnessV4, CompactStorageWitnessV4, L1ImportWitnessV5, L1MirrorBindingV5,
    L1StorageSlotV5,
};

use super::bytecode::fixture_address;
use super::contracts::{FixtureContract, RegistrySlots};

pub(super) fn storage_value(
    state: &[(Address, AccountState)],
    contract: Address,
    slot: U256,
) -> Result<U256> {
    let account = state
        .iter()
        .find(|(address, _)| *address == contract)
        .map(|(_, account)| account)
        .with_context(|| format!("participant registry contract {contract} is missing"))?;
    // Canonical Ethereum state does not store zero-valued words. In
    // particular, an empty participant registry's count disappears when a
    // post-state is converted back into an input state between the two room
    // blocks. Reading an absent slot as anything other than zero makes a valid
    // empty registry impossible to carry across that boundary.
    Ok(account
        .storage
        .iter()
        .find(|(key, _)| *key == slot)
        .map(|(_, value)| *value)
        .unwrap_or(U256::ZERO))
}

/// The four registry words as the opening state holds them.
pub(super) fn registry_view(
    state: &[(Address, AccountState)],
    contract: Address,
    slots: RegistrySlots,
) -> Result<(B256, u64, u64, u64)> {
    let root = B256::from(storage_value(state, contract, slots.root)?.to_be_bytes::<32>());
    let epoch = storage_value(state, contract, slots.epoch)?;
    let count = storage_value(state, contract, slots.count)?;
    let capacity = storage_value(state, contract, slots.capacity)?;
    for (label, value) in [("epoch", epoch), ("count", count), ("capacity", capacity)] {
        if value > U256::from(u64::MAX) {
            anyhow::bail!("participant registry {label} exceeds uint64");
        }
    }
    Ok((
        root,
        epoch.to::<u64>(),
        count.to::<u64>(),
        capacity.to::<u64>(),
    ))
}

/// The generated storage a clone-shaped legacy room seeds on its registry
/// contract: mirror variables, import destinations, the registry words, and
/// finally the caller's `initialStorage` overrides.
pub(super) struct LegacySeed<'a> {
    pub(super) registry_contract: Address,
    pub(super) registry: RegistrySlots,
    pub(super) resident_storage_slots: u64,
    pub(super) imported_variables: u64,
    pub(super) workload: &'a str,
    pub(super) registered_participants: u64,
    pub(super) participant_capacity: u64,
    pub(super) participant_root: B256,
    pub(super) initial_storage: &'a [(U256, U256)],
}

fn legacy_registry_storage(seed: &LegacySeed<'_>) -> Vec<(U256, U256)> {
    let mut storage = Vec::new();
    for slot in 0..seed.resident_storage_slots {
        let application_value = match (seed.workload, slot) {
            ("shop-demo", 1) => Some(U256::from(8)),
            ("shop-demo", 2) => Some(U256::from(5)),
            ("shop-demo", 3 | 4) => Some(U256::ZERO),
            ("auction-demo", 1) => Some(U256::from(4)),
            ("auction-demo", 2 | 3 | 4) => Some(U256::ZERO),
            _ => None,
        };
        storage.push((
            U256::from(slot),
            application_value.unwrap_or_else(|| {
                if slot == 0 {
                    U256::ZERO
                } else {
                    U256::from(slot + 1)
                }
            }),
        ));
    }
    for slot in 0..seed.imported_variables {
        storage.push((U256::from(seed.resident_storage_slots + slot), U256::ZERO));
    }
    storage.extend([
        (
            seed.registry.root,
            U256::from_be_bytes(seed.participant_root.0),
        ),
        (seed.registry.epoch, U256::from(1)),
        (
            seed.registry.count,
            U256::from(seed.registered_participants),
        ),
        (
            seed.registry.capacity,
            U256::from(seed.participant_capacity),
        ),
    ]);
    for (slot, value) in seed.initial_storage {
        if let Some(existing) = storage.iter_mut().find(|(key, _)| key == slot) {
            existing.1 = *value;
        } else {
            storage.push((*slot, *value));
        }
    }
    storage.sort_by_key(|(slot, _)| *slot);
    storage
}

/// The room's opening accounts: the signer EOAs, every pinned contract with its
/// own runtime code and its own storage, then anonymous resident filler.
pub(super) fn opening_state(
    contracts: &[FixtureContract],
    signers: &[Address],
    resident_accounts: u64,
    legacy: Option<&LegacySeed<'_>>,
) -> Vec<(Address, AccountState)> {
    let mut state = signers
        .iter()
        .map(|address| {
            (
                *address,
                AccountState {
                    nonce: 0,
                    balance: U256::from(10u64).pow(U256::from(20u64)),
                    code: Bytes::new(),
                    storage: vec![],
                },
            )
        })
        .collect::<Vec<_>>();
    for contract in contracts {
        let storage = match legacy {
            Some(seed) if contract.address == seed.registry_contract => {
                legacy_registry_storage(seed)
            }
            // A clone-shaped room's secondary contracts have always carried one
            // zero word so the compact witness names them; a descriptor-driven
            // room states its own storage instead.
            Some(_) => vec![(U256::ZERO, U256::ZERO)],
            None => contract.storage.clone(),
        };
        state.push((
            contract.address,
            AccountState {
                nonce: 1,
                balance: U256::ZERO,
                code: contract.runtime_code.clone(),
                storage,
            },
        ));
    }
    let existing = state.len() as u64;
    for index in 0..resident_accounts.saturating_sub(existing) {
        state.push((
            fixture_address(b"resident-account", index),
            AccountState {
                nonce: 1,
                balance: U256::from(index + 1),
                code: Bytes::new(),
                storage: vec![],
            },
        ));
    }
    state.sort_by_key(|(address, _)| *address);
    state
}

pub(super) fn compact_state(state: &[(Address, AccountState)]) -> CompactStateWitnessV4 {
    let mut accounts = vec![CompactAccountWitnessV4 {
        address: Address::ZERO,
        exists: false,
        canonical_storage_root: alloy_trie::EMPTY_ROOT_HASH,
        ..Default::default()
    }];
    accounts.extend(state.iter().map(|(address, account)| {
        CompactAccountWitnessV4 {
            address: *address,
            exists: true,
            nonce: account.nonce,
            balance: account.balance,
            code: account.code.clone(),
            canonical_storage_root: alloy_trie::EMPTY_ROOT_HASH,
            account_proof: vec![],
            storage: account
                .storage
                .iter()
                .map(|(slot, value)| CompactStorageWitnessV4 {
                    slot: *slot,
                    value: *value,
                    proof: vec![],
                })
                .collect(),
        }
    }));
    accounts.sort_by_key(|account| account.address);
    CompactStateWitnessV4 {
        canonical_state_root: B256::ZERO,
        accounts,
    }
}

pub(super) fn make_import(
    room_id: u64,
    l1_chain_id: u64,
    deadline: u64,
    room_contract: Address,
    first_room_slot: u64,
    count: u64,
) -> Result<(L1ImportWitnessV5, Vec<CertifiedImportBindingV5>)> {
    let source = fixture_address(b"l1-source", 0);
    let source_code_hash = B256::repeat_byte(0x88);
    let adapter_id = keccak256(b"zkdeal/capacity/import-adapter");
    let adapter_version = keccak256(b"zkdeal/capacity/import-adapter/v1");
    let mut leaves = (0..count)
        .map(|index| {
            let key = U256::from(index + 1);
            let value = U256::from(10_000 + index);
            let path = Nibbles::unpack(keccak256(key.to_be_bytes::<32>()).0);
            (key, value, path)
        })
        .collect::<Vec<_>>();
    let retained = leaves.iter().map(|(_, _, path)| *path).collect::<Vec<_>>();
    leaves.sort_by_key(|(_, _, path)| *path);
    let mut storage_builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(retained));
    for (_, value, path) in &leaves {
        storage_builder.add_leaf(*path, &alloy_rlp::encode(*value));
    }
    let source_storage_root = storage_builder.root();
    let proof_nodes = storage_builder.take_proof_nodes();
    let mut proofs = BTreeMap::new();
    for (key, _, path) in &leaves {
        proofs.insert(
            *key,
            proof_nodes
                .matching_nodes_sorted(path)
                .into_iter()
                .map(|(_, node)| node)
                .collect::<Vec<_>>(),
        );
    }
    leaves.sort_by_key(|(key, _, _)| *key);

    let account = TrieAccount {
        nonce: 3,
        balance: U256::from(100),
        storage_root: source_storage_root,
        code_hash: source_code_hash,
    };
    let account_path = Nibbles::unpack(keccak256(source).0);
    let mut account_builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([account_path]));
    account_builder.add_leaf(account_path, &alloy_rlp::encode(account));
    let state_root = account_builder.root();
    let account_proof = account_builder
        .take_proof_nodes()
        .matching_nodes_sorted(&account_path)
        .into_iter()
        .map(|(_, node)| node)
        .collect();

    let storage = leaves
        .iter()
        .map(|(key, value, _)| L1StorageSlotV5 {
            key: *key,
            value: *value,
            proof: proofs.remove(key).expect("proof prepared for every key"),
        })
        .collect::<Vec<_>>();
    let mirror_bindings = leaves
        .iter()
        .enumerate()
        .map(|(index, (key, _, _))| L1MirrorBindingV5 {
            source_key: *key,
            room_contract,
            room_slot: U256::from(first_room_slot + index as u64),
        })
        .collect::<Vec<_>>();
    let certified = mirror_bindings
        .iter()
        .map(|binding| CertifiedImportBindingV5 {
            adapter_id,
            adapter_version,
            source,
            source_key: binding.source_key,
            room_contract: binding.room_contract,
            room_slot: binding.room_slot,
        })
        .collect::<Vec<_>>();
    let keys = storage.iter().map(|slot| slot.key).collect::<Vec<_>>();
    let import = L1ImportWitnessV5 {
        source_block: 123,
        expiry_block: deadline.saturating_add(100),
        header_hash: keccak256(b"zkdeal/capacity/l1-header"),
        state_root,
        source,
        source_nonce: 3,
        source_balance: U256::from(100),
        source_storage_root,
        source_code_hash,
        account_proof,
        storage_keys_root: storage_keys_root_v5(&keys),
        adapter_id,
        adapter_version,
        storage,
        mirror_bindings,
    };
    let _ = (room_id, l1_chain_id);
    Ok((import, certified))
}
