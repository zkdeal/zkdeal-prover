//! Positive evidence: real multi-block v4 batches execute, journal their
//! intermediate roots, and honour the close/timestamp rules.

use alloy_primitives::{Address, Bytes, U256};
use stf_core::{execute_batch_v4, tx_commitment_raw, StfError};
use stf_types::{
    batch_block_data_hash_v4, hash_inbox_entries_v4, hash_membership_deltas_v4,
    member_roster_root_v4, CompactAccountWitnessV4, InboxAssetAmountV4, InboxEntryWitnessV4,
    MemberSlotWitnessV4, MembershipDeltaWitnessV4,
};

use crate::batches::{
    certified_amm_two_block_batch, empty_membership_batch, real_two_block_batch,
    set_native_settlement, state_from_compact,
};
use crate::preset::sign_member_zero_value_1559;

#[test]
fn proves_join_then_retire_and_keeps_the_retired_balance_frozen_in_exits() {
    let mut activation = real_two_block_batch();
    let candidate: Address = "0x6813eb9362372eef6200f3b1dbc3f819671cba69"
        .parse()
        .unwrap();
    let deposit = U256::from(1_234_567u64);

    // The candidate is explicitly declared absent in the complete room-state
    // envelope. The numbered L1 join input is the only operation that creates
    // and funds it before the first EVM block.
    activation
        .compact_state
        .accounts
        .push(CompactAccountWitnessV4 {
            address: candidate,
            exists: false,
            nonce: 0,
            balance: U256::ZERO,
            code: Bytes::new(),
            canonical_storage_root: alloy_trie::EMPTY_ROOT_HASH,
            account_proof: Vec::new(),
            storage: Vec::new(),
        });
    activation
        .compact_state
        .accounts
        .sort_by_key(|account| account.address);
    let mut activation_state = state_from_compact(&activation);
    assert_eq!(activation_state.state_root(), activation.prev_state_root);
    activation_state
        .accounts
        .entry(candidate)
        .or_default()
        .balance = deposit;

    activation.batch_index = 9;
    activation.post_roster_slots[2] = MemberSlotWitnessV4 {
        slot: 2,
        state: 1,
        account: candidate,
        joined_at_batch: activation.batch_index,
        retired_at_batch: None,
    };
    activation.post_roster_root = member_roster_root_v4(&activation.post_roster_slots).unwrap();
    activation.post_active_mask = 0b111;
    activation.used_mask = 0b111;
    activation.membership_deltas = vec![MembershipDeltaWitnessV4 {
        action: 1,
        slot: 2,
        member: candidate,
        join_request_index: 1,
        acceptance_expiry: 10_000,
    }];
    activation.membership_deltas_hash = hash_membership_deltas_v4(&activation.membership_deltas);
    activation.inbox_start = 0;
    activation.inbox_end = 1;
    activation.inbox_entries = vec![InboxEntryWitnessV4 {
        index: 1,
        kind: 2,
        account: candidate,
        beneficiary_slot: 255,
        status: 1,
        deposits: vec![InboxAssetAmountV4 {
            asset_id: 0,
            amount: deposit,
        }],
    }];
    let mut resolved_join = activation.inbox_entries.clone();
    resolved_join[0].status = 2;
    activation.inbox_inputs_hash = hash_inbox_entries_v4(&resolved_join);
    let activation_root = activation_state.state_root();
    empty_membership_batch(&mut activation, 1, activation_root);
    set_native_settlement(&mut activation, &activation_state);

    let joined = execute_batch_v4(&activation).expect("guest proves the join boundary");
    assert_eq!(joined.post_roster_root, activation.post_roster_root);
    assert_eq!(joined.post_active_mask, 0b111);
    assert!(joined
        .exit_allocations
        .iter()
        .any(|exit| exit.slot == 2 && exit.recipient == candidate && exit.amount == deposit));

    // The next proven boundary retires the member without consuming another
    // inbox item. No EVM transaction can change the balance in this boundary,
    // and the retired lifetime slot remains in the exact exit derivation.
    let mut retirement = activation.clone();
    retirement.encoded_witness_bytes = 1;
    retirement.batch_index = 10;
    retirement.prev_state_root = joined.post_state_root;
    retirement.previous_exit_root = joined.exit_root;
    retirement.previous_exit_allocations = joined.exit_allocations.clone();
    let candidate_witness = retirement
        .compact_state
        .accounts
        .iter_mut()
        .find(|account| account.address == candidate)
        .unwrap();
    candidate_witness.exists = true;
    candidate_witness.balance = deposit;
    retirement.pre_roster_slots = activation.post_roster_slots.clone();
    retirement.pre_roster_root = activation.post_roster_root;
    retirement.active_mask = 0b111;
    retirement.pre_used_mask = 0b111;
    retirement.post_roster_slots = retirement.pre_roster_slots.clone();
    retirement.post_roster_slots[2].state = 2;
    retirement.post_roster_slots[2].retired_at_batch = Some(retirement.batch_index);
    retirement.post_roster_root = member_roster_root_v4(&retirement.post_roster_slots).unwrap();
    retirement.post_active_mask = 0b011;
    retirement.used_mask = 0b111;
    retirement.membership_deltas = vec![MembershipDeltaWitnessV4 {
        action: 2,
        slot: 2,
        member: candidate,
        join_request_index: 0,
        acceptance_expiry: 0,
    }];
    retirement.membership_deltas_hash = hash_membership_deltas_v4(&retirement.membership_deltas);
    retirement.inbox_start = 1;
    retirement.inbox_end = 1;
    retirement.inbox_entries.clear();
    retirement.inbox_inputs_hash = hash_inbox_entries_v4(&[]);
    empty_membership_batch(&mut retirement, 3, joined.post_state_root);
    let retirement_state = state_from_compact(&retirement);
    assert_eq!(retirement_state.state_root(), joined.post_state_root);
    set_native_settlement(&mut retirement, &retirement_state);

    let retired = execute_batch_v4(&retirement).expect("guest proves the retirement boundary");
    assert_eq!(retired.previous_exit_root, joined.exit_root);
    assert_eq!(retired.post_active_mask, 0b011);
    assert_eq!(retired.used_mask, 0b111);
    assert!(retired
        .exit_allocations
        .iter()
        .any(|exit| exit.slot == 2 && exit.recipient == candidate && exit.amount == deposit));

    // A later, otherwise-valid value transfer cannot credit even one wei to
    // an already-retired slot. The post-state/root and conservation values
    // are internally consistent; only the L1-authenticated frozen allocation
    // makes this transition invalid.
    let mut drift = retirement.clone();
    drift.batch_index = 11;
    drift.prev_state_root = retired.post_state_root;
    drift.previous_exit_root = retired.exit_root;
    drift.previous_exit_allocations = retired.exit_allocations.clone();
    drift.pre_roster_slots = retirement.post_roster_slots.clone();
    drift.post_roster_slots = drift.pre_roster_slots.clone();
    drift.pre_roster_root = retired.post_roster_root;
    drift.post_roster_root = retired.post_roster_root;
    drift.active_mask = 0b011;
    drift.pre_used_mask = 0b111;
    drift.post_active_mask = 0b011;
    drift.used_mask = 0b111;
    drift.membership_deltas.clear();
    drift.membership_deltas_hash = hash_membership_deltas_v4(&[]);
    let mut drift_state = state_from_compact(&drift);
    let sender = drift.pre_roster_slots[0].account;
    let sender_state = drift_state.accounts.get_mut(&sender).unwrap();
    let sender_nonce = sender_state.nonce;
    sender_state.nonce += 1;
    sender_state.balance -= U256::from(1u8);
    drift_state.accounts.get_mut(&candidate).unwrap().balance += U256::from(1u8);
    let post_root = drift_state.state_root();
    empty_membership_batch(&mut drift, 5, post_root);
    drift.blocks[0].raw_txs = vec![sign_member_zero_value_1559(
        drift.blocks[0].env.chain_id,
        sender_nonce,
        candidate,
        U256::from(1u8),
        Bytes::new(),
    )];
    drift.expected_block_data_hash = batch_block_data_hash_v4(&drift.blocks, drift.prev_state_root);
    set_native_settlement(&mut drift, &drift_state);
    assert!(matches!(
        execute_batch_v4(&drift),
        Err(StfError::Settlement(message))
            if message.contains("retired slot 2 asset 0 exit changed")
    ));
}

#[test]
fn executes_two_real_non_empty_blocks_and_journals_intermediate_roots() {
    let input = real_two_block_batch();
    let journal = execute_batch_v4(&input).expect("real 3+4 transaction batch executes");
    assert_eq!(journal.v, 4);
    assert_eq!(journal.blocks.len(), 2);
    assert_eq!(journal.l2_start_height, 1);
    assert_eq!(journal.l2_end_height, 2);
    assert_ne!(journal.blocks[0].post_state_root, input.prev_state_root);
    assert_eq!(journal.blocks[1].post_state_root, journal.post_state_root);
    assert_eq!(journal.block_data_hash, input.expected_block_data_hash);
    assert_eq!(
        journal.previous_block_timestamp,
        input.previous_block_timestamp
    );
    assert_eq!(
        journal.final_block_timestamp,
        input.blocks.last().unwrap().env.timestamp
    );
}

#[test]
fn one_block_flush_is_valid_only_when_it_closes_at_the_final_transaction_boundary() {
    let mut terminal = real_two_block_batch();
    let initial_state = state_from_compact(&terminal);
    let initial_root = initial_state.state_root();
    assert_eq!(initial_root, terminal.prev_state_root);
    empty_membership_batch(&mut terminal, 1, initial_root);
    terminal.blocks.truncate(1);
    terminal.expected_block_data_hash =
        batch_block_data_hash_v4(&terminal.blocks, terminal.prev_state_root);
    set_native_settlement(&mut terminal, &initial_state);

    let non_terminal = terminal.clone();
    assert!(matches!(
        execute_batch_v4(&non_terminal),
        Err(StfError::InvalidBatch(message))
            if message.contains("one-block batch") && message.contains("terminal close")
    ));

    terminal.close = true;
    let journal = execute_batch_v4(&terminal).expect("authenticated one-block close executes");
    assert!(journal.close);
    assert_eq!(journal.blocks.len(), 1);
    assert_eq!(journal.post_state_root, initial_root);
    assert_eq!(
        journal.blocks[0].tx_commitment,
        tx_commitment_raw(&Vec::<Bytes>::new())
    );
}

#[test]
fn rejects_a_first_block_timestamp_rollback_from_the_prior_verified_batch() {
    let mut input = real_two_block_batch();
    input.previous_block_timestamp = input.blocks[0].env.timestamp + 1;
    assert!(matches!(
        execute_batch_v4(&input),
        Err(StfError::InvalidBatch(message)) if message.contains("previous verified timestamp")
    ));
}

#[test]
fn executes_generated_certified_amm_with_three_state_changes_per_block() {
    let input = certified_amm_two_block_batch();
    let journal = execute_batch_v4(&input)
        .expect("generated code-hash-pinned AMM batch executes under its certified policy");
    assert_eq!(journal.blocks.len(), 2);
    assert_eq!(input.blocks[0].raw_txs.len(), 3);
    assert_eq!(input.blocks[1].raw_txs.len(), 3);
    assert_eq!(
        journal.blocks[0].post_state_root,
        input.blocks[0].expected_post_state_root
    );
    assert_eq!(
        journal.post_state_root,
        input.blocks[1].expected_post_state_root
    );
    assert_eq!(journal.preset_hash, input.preset_hash);
    assert_eq!(journal.asset_totals_hash, input.asset_totals_hash);
    assert_eq!(journal.exit_totals_hash, input.exit_totals_hash);
    assert_eq!(journal.fee_totals_hash, input.fee_totals_hash);
    assert_eq!(journal.exit_root, input.exit_root);
    assert_eq!(journal.asset_accounting.len(), 3);
    assert_eq!(journal.exit_allocations.len(), 4);
    assert!(
        journal.asset_accounting[0].total.is_zero(),
        "AMM fixture has no synthetic ETH"
    );
}
