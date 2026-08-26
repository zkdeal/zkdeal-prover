//! Positive evidence: a v5 room batch executes, derives its public
//! statement, and reports proof work from that exact transition.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use stf_core::{
    execute_batch_v5, execute_batch_v5_with_report, execute_block_full_v5_commitment,
    execute_cold_template_v5,
};
use stf_types::{
    admission_records_hash_v5, cold_template_id_v5, cold_template_statement_v6,
    hash_batch_journal_v5, roster_changes_hash_v5, roster_root_v5, AdmissionOutcomeV5,
    AdmissionReceiptV5, AdmissionRecordV5, ColdTemplateInputV5, RosterChangeV5, RosterMemberV5,
};

use crate::support::{account_state, ROOM_ID};
use crate::witness::{sparse_batch, valid_batch, valid_batch_with_import, validity_only_batch};

#[test]
fn executes_two_real_blocks_and_derives_the_v5_statement() {
    let input = valid_batch();
    let journal = execute_batch_v5(&input).expect("valid v5 room batch");
    assert_eq!(journal, input.journal);
    assert_ne!(hash_batch_journal_v5(&journal), B256::ZERO);
}

#[test]
fn validity_only_room_uses_signed_transactions_without_a_customer_roster_vote() {
    let mut input = validity_only_batch();
    let first_hash = keccak256(input.blocks[0].raw_txs[0].as_ref());
    let second_hash = keccak256(input.blocks[1].raw_txs[0].as_ref());
    input.admissions = vec![
        AdmissionRecordV5 {
            receipt: AdmissionReceiptV5 {
                admission_id: 1,
                transaction_hash: first_hash,
                deposit_inbox_id: 0,
                deposit_content_hash: B256::ZERO,
                deadline_block: 1_000,
                maximum_batch_index: 1,
                bond_epoch: 1,
                admission_fee: U256::ZERO,
                signature: Bytes::from(vec![0x11; 65]),
            },
            outcome: AdmissionOutcomeV5 {
                admission_id: 1,
                transaction_hash: first_hash,
                status: 0,
                l2_block_number: 1,
                transaction_index: 0,
                reason_hash: B256::ZERO,
            },
        },
        AdmissionRecordV5 {
            receipt: AdmissionReceiptV5 {
                admission_id: 2,
                transaction_hash: second_hash,
                deposit_inbox_id: 0,
                deposit_content_hash: B256::ZERO,
                deadline_block: 1_000,
                maximum_batch_index: 1,
                bond_epoch: 1,
                admission_fee: U256::ZERO,
                signature: Bytes::from(vec![0x22; 65]),
            },
            outcome: AdmissionOutcomeV5 {
                admission_id: 2,
                transaction_hash: second_hash,
                status: 0,
                l2_block_number: 2,
                transaction_index: 0,
                reason_hash: B256::ZERO,
            },
        },
    ];
    input.journal.admission_cursor_after = 2;
    input.journal.admission_records_hash = admission_records_hash_v5(&input.admissions);

    execute_batch_v5(&input).expect("validity-only transactions are their own execution authority");

    let mut relabelled = input;
    relabelled.admissions[1].outcome.l2_block_number = 1;
    relabelled.journal.admission_records_hash = admission_records_hash_v5(&relabelled.admissions);
    assert!(execute_batch_v5(&relabelled).is_err());
}

#[test]
fn reports_proof_work_from_the_exact_two_block_transition() {
    let input = valid_batch();
    let outcome =
        execute_batch_v5_with_report(&input).expect("valid v5 room batch with proof-work report");
    assert_eq!(outcome.journal, input.journal);
    assert_eq!(outcome.proof_work.block_count, 2);
    assert_eq!(outcome.proof_work.encoded_witness_bytes, 1);
    assert_eq!(outcome.proof_work.evm.transaction_count, 2);
    assert!(outcome.proof_work.evm.executed_gas >= 42_000);
    assert!(outcome.proof_work.evm.opcode_steps > 0);
    assert!(outcome.proof_work.evm.db.account_reads > 0);
    assert!(outcome.proof_work.evm.db.storage_writes > 0);
    assert_eq!(outcome.proof_work.evm.state_accounts, 2);
    assert_eq!(outcome.proof_work.evm.state_storage_slots, 5);
}

#[test]
fn refuses_relabelled_transactions_or_terminal_state() {
    let mut changed = valid_batch();
    changed.journal.batch_data_hash = B256::repeat_byte(0xee);
    assert!(execute_batch_v5(&changed).is_err());

    let mut changed = valid_batch();
    changed.journal.post_state_root = B256::repeat_byte(0xdd);
    assert!(execute_batch_v5(&changed).is_err());
}

#[test]
fn refuses_uncommitted_policy_or_roster() {
    let mut changed = valid_batch();
    changed.policy.max_memory_bytes += 1;
    assert!(execute_batch_v5(&changed).is_err());

    let mut changed = valid_batch();
    changed.post_roster[0].joined_epoch = 2;
    assert!(execute_batch_v5(&changed).is_err());
}

#[test]
fn pure_roster_addition_needs_entrant_consent_but_no_withdrawal_tree() {
    let mut input = valid_batch();
    let entrant = Address::repeat_byte(0x66);
    let change = RosterChangeV5 {
        action: 0,
        request_id: 1,
        index: 1,
        joined_epoch: 2,
        deadline: 2_000,
        member: entrant,
        withdrawal_commitment: B256::ZERO,
    };
    input.post_roster.push(RosterMemberV5 {
        index: 1,
        member: entrant,
        joined_epoch: 2,
    });
    input.roster_changes = vec![change];
    input.journal.post_roster_root = roster_root_v5(&input.post_roster, 2).unwrap();
    input.journal.post_roster_epoch = 2;
    input.journal.post_active_count = 2;
    input.journal.roster_change_cursor_after = 1;
    input.journal.roster_changes_hash = roster_changes_hash_v5(&input.roster_changes);

    assert_eq!(input.journal.withdrawal_root, B256::ZERO);
    execute_batch_v5(&input).expect("a pure add transition has no withdrawal allocation");

    let mut relabelled = input;
    relabelled.roster_changes[0].joined_epoch = 3;
    assert!(execute_batch_v5(&relabelled).is_err());
}

#[test]
fn cold_template_proof_registers_the_exact_initial_state_and_policy() {
    let batch = valid_batch();
    let proof_system_version = B256::repeat_byte(0x55);
    let input = ColdTemplateInputV5 {
        template_id: cold_template_id_v5(
            batch.journal.pre_state_root,
            batch.journal.policy_hash,
            proof_system_version,
        ),
        initial_state_root: batch.journal.pre_state_root,
        policy_hash: batch.journal.policy_hash,
        proof_program_id: batch.journal.proof_program_id,
        proof_system_version,
        policy: batch.policy,
        compact_state: batch.compact_state,
    };
    let genesis_data_hash = B256::repeat_byte(0x77);
    assert_eq!(
        execute_cold_template_v5(&input, genesis_data_hash).unwrap(),
        cold_template_statement_v6(&input, genesis_data_hash)
    );
    // The v6 statement binds the canonical genesis package; a zero hash can
    // never name one.
    assert!(execute_cold_template_v5(&input, B256::ZERO).is_err());

    let mut changed = input;
    changed.initial_state_root = B256::repeat_byte(0xfe);
    assert!(execute_cold_template_v5(&changed, genesis_data_hash).is_err());
}

#[test]
fn authenticates_eip1186_storage_before_writing_the_certified_mirror() {
    let input = valid_batch_with_import();
    execute_batch_v5(&input).expect("authenticated import and two-block room batch");

    let mut stale = input.clone();
    stale
        .l1_import
        .as_mut()
        .unwrap()
        .storage
        .first_mut()
        .unwrap()
        .value = U256::from(10);
    assert!(execute_batch_v5(&stale).is_err());

    let mut redirected = input;
    redirected
        .l1_import
        .as_mut()
        .unwrap()
        .mirror_bindings
        .first_mut()
        .unwrap()
        .room_slot = U256::from(1);
    assert!(execute_batch_v5(&redirected).is_err());
}

#[test]
fn sparse_room_commitment_preserves_the_evm_transition() {
    let sparse = sparse_batch();
    execute_batch_v5(&sparse).expect("sparse room commitment");
    assert_ne!(
        sparse.journal.pre_state_root,
        valid_batch().journal.pre_state_root
    );

    let contract = Address::repeat_byte(0x44);
    let opening = account_state(contract);
    let mpt = valid_batch();
    let mpt_first = execute_block_full_v5_commitment(
        &stf_types::StfInput {
            room_id: ROOM_ID,
            block_number: 1,
            prev_state_root: mpt.journal.pre_state_root,
            state: opening.clone(),
            raw_txs: mpt.blocks[0].raw_txs.clone(),
            env: mpt.blocks[0].env.clone(),
            block_hashes: vec![],
        },
        0,
    )
    .unwrap();
    let sparse_first = execute_block_full_v5_commitment(
        &stf_types::StfInput {
            room_id: ROOM_ID,
            block_number: 1,
            prev_state_root: sparse.journal.pre_state_root,
            state: opening,
            raw_txs: sparse.blocks[0].raw_txs.clone(),
            env: sparse.blocks[0].env.clone(),
            block_hashes: vec![],
        },
        1,
    )
    .unwrap();
    assert_eq!(
        mpt_first.post_state.accounts,
        sparse_first.post_state.accounts
    );
}
