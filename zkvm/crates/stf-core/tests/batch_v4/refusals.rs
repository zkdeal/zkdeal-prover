//! Refusals: everything a v4 batch witness must not be able to claim.
use std::collections::BTreeMap;

use alloy_primitives::{Address, Bytes, B256, U256};
use stf_core::{execute_batch_v4, AccountRecord, StateMap, StfError};
use stf_types::{
    batch_block_data_hash_v4, CompactAccountWitnessV4, CompactStorageWitnessV4,
    MAX_COMPACT_ACCOUNTS_V4,
};

use crate::batches::{
    certified_amm_address, certified_amm_two_block_batch, real_two_block_batch,
    replace_first_certified_tx,
};

#[test]
fn certified_policy_rejects_unlisted_root_target_and_selector() {
    let mut unlisted_target = certified_amm_two_block_batch();
    replace_first_certified_tx(
        &mut unlisted_target,
        Address::repeat_byte(0x77),
        Bytes::from_static(&[0x09, 0x5e, 0xa7, 0xb3]),
    );
    assert!(matches!(
        execute_batch_v4(&unlisted_target),
        Err(StfError::CertifiedPolicy(message))
            if message.contains("root transaction")
                && message.contains("outside the certified envelope")
    ));

    let mut unlisted_selector = certified_amm_two_block_batch();
    let amm = certified_amm_address(&unlisted_selector);
    replace_first_certified_tx(
        &mut unlisted_selector,
        amm,
        Bytes::from_static(&[0xff, 0xff, 0xff, 0xff]),
    );
    assert!(matches!(
        execute_batch_v4(&unlisted_selector),
        Err(StfError::CertifiedPolicy(message))
            if message.contains("root transaction")
                && message.contains("outside the certified envelope")
    ));
}

#[test]
fn certified_policy_rejects_an_unauthorized_nested_call() {
    let mut input = certified_amm_two_block_batch();
    let mut preset: serde_json::Value =
        serde_json::from_slice(&input.canonical_preset_json).unwrap();
    // Retain member entry points but deliberately remove every contract-to-
    // contract permission. The first AMM transferFrom must therefore be
    // observed and refused by the nested-call inspector.
    preset["callRules"]
        .as_array_mut()
        .unwrap()
        .retain(|rule| rule["caller"] == Address::ZERO.to_string());
    input.canonical_preset_json = Bytes::from(serde_json::to_vec(&preset).unwrap());
    input.preset_hash = alloy_primitives::keccak256(&input.canonical_preset_json);

    assert!(matches!(
        execute_batch_v4(&input),
        Err(StfError::CertifiedPolicy(message))
            if !message.contains("root transaction")
                && message.contains("outside the certified envelope")
    ));
}

#[test]
fn refuses_unapproved_or_implicit_amm_residual_allocation() {
    let mut missing = certified_amm_two_block_batch();
    missing.residual_allocations.clear();
    assert!(matches!(
        execute_batch_v4(&missing),
        Err(StfError::Settlement(message)) if message.contains("unallocated residual")
    ));

    let mut redirected = certified_amm_two_block_batch();
    redirected.residual_allocations[0].recipient_slot = 1;
    assert!(matches!(
        execute_batch_v4(&redirected),
        Err(StfError::Settlement(message))
            if message.contains("derived batch accounting/root")
    ));
}

#[test]
fn refuses_host_supplied_block_data_hash_or_non_contiguous_height() {
    let mut input = real_two_block_batch();
    input.expected_block_data_hash = B256::ZERO;
    assert!(matches!(
        execute_batch_v4(&input),
        Err(StfError::InvalidBatch(_))
    ));

    let mut input = real_two_block_batch();
    input.blocks[1].block_number = 3;
    input.blocks[1].env.number = 3;
    input.expected_block_data_hash = batch_block_data_hash_v4(&input.blocks, input.prev_state_root);
    assert!(matches!(
        execute_batch_v4(&input),
        Err(StfError::InvalidBatch(_))
    ));
}

#[test]
fn rejects_non_deterministic_environment_fields_omitted_from_calldata_encoding() {
    let mut gas_limit = certified_amm_two_block_batch();
    gas_limit.blocks[0].env.gas_limit += 1;
    // gasLimit is intentionally omitted from canonical batch bytes because
    // the guest pins it to the preset resource envelope.
    assert_eq!(
        batch_block_data_hash_v4(&gas_limit.blocks, gas_limit.prev_state_root),
        gas_limit.expected_block_data_hash
    );
    assert!(matches!(
        execute_batch_v4(&gas_limit),
        Err(StfError::InvalidBatch(message)) if message.contains("deterministic")
    ));

    let mut randomness = certified_amm_two_block_batch();
    randomness.blocks[0].env.prev_randao = B256::repeat_byte(1);
    assert_eq!(
        batch_block_data_hash_v4(&randomness.blocks, randomness.prev_state_root),
        randomness.expected_block_data_hash
    );
    assert!(matches!(
        execute_batch_v4(&randomness),
        Err(StfError::InvalidBatch(message)) if message.contains("deterministic")
    ));
}

#[test]
fn rejects_compact_witness_caps_proof_smuggling_and_bad_mpt_proofs() {
    let mut too_many = real_two_block_batch();
    too_many.compact_state.accounts = (0..=MAX_COMPACT_ACCOUNTS_V4)
        .map(|i| {
            let mut raw = [0u8; 20];
            raw[12..].copy_from_slice(&(i as u64).to_be_bytes());
            CompactAccountWitnessV4 {
                address: Address::from(raw),
                exists: false,
                canonical_storage_root: alloy_trie::EMPTY_ROOT_HASH,
                ..Default::default()
            }
        })
        .collect();
    assert!(matches!(
        execute_batch_v4(&too_many),
        Err(StfError::CompactWitness(_))
    ));

    let mut smuggled = real_two_block_batch();
    smuggled.compact_state.accounts[0].account_proof = vec![Bytes::from_static(&[0x80])];
    assert!(matches!(
        execute_batch_v4(&smuggled),
        Err(StfError::CompactWitness(_))
    ));

    let mut forged = real_two_block_batch();
    forged.compact_state.canonical_state_root = B256::repeat_byte(0x99);
    for account in &mut forged.compact_state.accounts {
        account.account_proof = vec![Bytes::from_static(&[0x80])];
        for slot in &mut account.storage {
            slot.proof = vec![Bytes::from_static(&[0x80])];
        }
    }
    assert!(matches!(
        execute_batch_v4(&forged),
        Err(StfError::CompactWitness(_))
    ));
}

#[test]
fn rejects_eip_161_empty_accounts_and_never_hides_their_storage_from_the_root() {
    let address = Address::repeat_byte(0x7e);
    let mut first = StateMap::default();
    first.accounts.insert(
        address,
        AccountRecord {
            storage: BTreeMap::from([(U256::from(1), U256::from(11))]),
            ..Default::default()
        },
    );
    let mut second = StateMap::default();
    second.accounts.insert(
        address,
        AccountRecord {
            storage: BTreeMap::from([(U256::from(1), U256::from(22))]),
            ..Default::default()
        },
    );
    assert_ne!(
        first.state_root(),
        second.state_root(),
        "defensive root construction must commit storage even on an invalid EIP-161-empty record",
    );

    let mut hidden = real_two_block_batch();
    {
        let account = hidden
            .compact_state
            .accounts
            .iter_mut()
            .find(|account| !account.exists)
            .expect("fixture declares at least one absent account");
        account.exists = true;
        account.storage.push(CompactStorageWitnessV4 {
            slot: U256::from(1),
            value: U256::from(11),
            proof: Vec::new(),
        });
    }

    assert!(matches!(
        execute_batch_v4(&hidden),
        Err(StfError::CompactWitness(message))
            if message.contains("EIP-161-empty account")
                && message.contains("cannot carry storage")
    ));

    // Even an exists=true empty account with no storage is non-canonical: it
    // would make EXTCODEHASH distinguish two witnesses for the same trie root.
    hidden
        .compact_state
        .accounts
        .iter_mut()
        .find(|account| account.exists && account.nonce == 0 && account.code.is_empty())
        .expect("mutated empty account remains present")
        .storage
        .clear();
    assert!(matches!(
        execute_batch_v4(&hidden),
        Err(StfError::CompactWitness(message)) if message.contains("must be represented as absent")
    ));
}

#[test]
fn rejects_a_transaction_that_touches_an_undeclared_storage_leaf() {
    let mut input = real_two_block_batch();
    let mut removed_zero_leaf = false;
    for account in &mut input.compact_state.accounts {
        if let Some(index) = account.storage.iter().position(|slot| slot.value.is_zero()) {
            account.storage.remove(index);
            removed_zero_leaf = true;
            break;
        }
    }
    assert!(
        removed_zero_leaf,
        "fixture must exercise a newly written storage leaf"
    );
    assert!(matches!(
        execute_batch_v4(&input),
        Err(StfError::TxExecution(message))
            if message.contains("outside the v4 access envelope")
                || message.contains("UndeclaredStorage")
    ));
}
