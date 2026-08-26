//! Guards: the witness claims a v5 batch must never be able to make.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use stf_core::execute_batch_v5;
use stf_types::{
    admission_records_hash_v5, batch_block_data_hash_v5, deposit_content_hash_v5,
    forced_rejection_reason_hash_v5, inbox_records_hash_v5, room_chain_id_v5,
    roster_changes_hash_v5, roster_root_v5, withdrawal_leaf_v5, withdrawal_root_v5,
    AdmissionOutcomeV5, AdmissionReceiptV5, AdmissionRecordV5, AssetLiabilityV5, DepositV5,
    HistoricalBlockHash, RosterChangeV5, RosterMemberV5, WithdrawalV5, FORCED_REJECTION_POLICY_V5,
    FORCED_REJECTION_SENDER_V5, FORCED_REJECTION_UNDECODABLE_V5, MAX_POSITIONAL_CAPACITY_V5,
    MAX_WITHDRAWAL_CAPACITY_V5,
};

use crate::support::{sender, sign_call, GAS_LIMIT, ROOM_ID};
use crate::witness::{
    declare_absent_account, exit_batch_with, exit_erc20_asset, exit_holder, forced_entry,
    liabilities, rebind_policy, set_forced, set_liabilities, set_withdrawals, valid_batch,
    valid_batch_with_deposits, valid_batch_with_import, validity_only_batch,
    validity_only_batch_without_exit, ExitBatchOptionsV5,
};

#[test]
fn mode1_without_exit_binding_is_rejected() {
    // A validity-only room whose policy carries no exit binding has no
    // authority that can ever move `controlled` escrow into `claimable`, so
    // the guest refuses every batch of such a room outright, even one that
    // mints no withdrawal at all.
    let input = validity_only_batch_without_exit();
    assert!(input.withdrawals.is_empty());
    let error = execute_batch_v5(&input).expect_err("mode-1 without an exit binding is unprovable");
    assert!(
        format!("{error}").contains("without an exit binding"),
        "unexpected error: {error}"
    );

    // With an exit binding in the policy the guard moves, not disappears: a
    // withdrawal with no matching record in the proved post-state is still
    // refused: the queue record is the authority, never the ledger delta.
    let mut unbacked = exit_batch_with(ExitBatchOptionsV5::default());
    set_liabilities(&mut unbacked, liabilities(100, 0), liabilities(0, 100));
    set_withdrawals(
        &mut unbacked,
        vec![WithdrawalV5 {
            index: 0,
            roster_epoch: 1,
            recipient: Address::repeat_byte(0xbe),
            asset: Address::ZERO,
            amount: U256::from(100),
        }],
        1,
    );
    assert!(execute_batch_v5(&unbacked).is_err());
}

#[test]
fn refuses_a_block_timestamp_that_rewinds_inside_the_batch() {
    let mut rolled_back = valid_batch();
    rolled_back.blocks[1].env.timestamp = rolled_back.blocks[0].env.timestamp - 1;
    rolled_back.journal.batch_data_hash =
        batch_block_data_hash_v5(&rolled_back.blocks, rolled_back.journal.pre_state_root);
    assert!(execute_batch_v5(&rolled_back).is_err());

    // A repeated timestamp is still a legal L2 clock, so the rejection above
    // is the ordering rule and not the re-derived batch-data commitment.
    let mut repeated = valid_batch();
    repeated.blocks[1].env.timestamp = repeated.blocks[0].env.timestamp;
    repeated.journal.batch_data_hash =
        batch_block_data_hash_v5(&repeated.blocks, repeated.journal.pre_state_root);
    execute_batch_v5(&repeated).expect("a non-decreasing L2 clock is valid");
}

#[test]
fn a_closing_batch_cannot_strand_controlled_escrow() {
    let mut stranded = valid_batch();
    stranded.journal.close = true;
    assert!(execute_batch_v5(&stranded).is_err());

    let mut settled = stranded;
    set_liabilities(&mut settled, liabilities(0, 100), liabilities(0, 100));
    execute_batch_v5(&settled).expect("closing with no controlled escrow is valid");
}

#[test]
fn positional_tree_capacity_is_bounded_by_the_l1_membership_proof_depth() {
    let roster = vec![RosterMemberV5 {
        index: 0,
        member: sender(),
        joined_epoch: 1,
    }];
    assert!(roster_root_v5(&roster, MAX_POSITIONAL_CAPACITY_V5).is_some());
    assert!(roster_root_v5(&roster, MAX_POSITIONAL_CAPACITY_V5 * 2).is_none());
    // The capacity is raw witness data read before any policy hash is checked;
    // an unbounded value would otherwise drive a `capacity`-sized allocation.
    assert!(roster_root_v5(&roster, 1 << 40).is_none());

    // The withdrawal outbox has its own, wider bound: 32768 leaves matches
    // `RoomManagerBase.MAX_WITHDRAWALS_PER_EPOCH` and claim-proof depth 15.
    let withdrawals = vec![WithdrawalV5 {
        index: 0,
        roster_epoch: 1,
        recipient: Address::repeat_byte(0xbe),
        asset: Address::ZERO,
        amount: U256::from(1),
    }];
    assert!(withdrawal_root_v5(
        B256::repeat_byte(0x11),
        ROOM_ID,
        1,
        &withdrawals,
        MAX_POSITIONAL_CAPACITY_V5 * 2
    )
    .is_some());
    assert!(withdrawal_root_v5(
        B256::repeat_byte(0x11),
        ROOM_ID,
        1,
        &withdrawals,
        MAX_WITHDRAWAL_CAPACITY_V5
    )
    .is_some());
    assert!(withdrawal_root_v5(
        B256::repeat_byte(0x11),
        ROOM_ID,
        1,
        &withdrawals,
        MAX_WITHDRAWAL_CAPACITY_V5 * 2
    )
    .is_none());

    let mut oversized = valid_batch();
    oversized.roster_capacity = MAX_POSITIONAL_CAPACITY_V5 * 2;
    assert!(execute_batch_v5(&oversized).is_err());
}

#[test]
fn a_rejected_forced_transaction_must_prove_its_deterministic_reason() {
    let chain_id = room_chain_id_v5(B256::repeat_byte(0x11), ROOM_ID);

    // An EIP-4844 envelope can never be a room transaction, whatever the room
    // state is, so the guest derives the rejection itself.
    let undecodable = Bytes::from(vec![0x03, 0x01, 0x02]);
    let mut input = validity_only_batch();
    set_forced(
        &mut input,
        vec![forced_entry(
            undecodable.clone(),
            2,
            forced_rejection_reason_hash_v5(
                keccak256(undecodable.as_ref()),
                FORCED_REJECTION_UNDECODABLE_V5,
            ),
        )],
    );
    execute_batch_v5(&input).expect("a provably undecodable forced transaction may be rejected");

    // The reason hash is derived, never accepted as witness data.
    let mut relabelled = input.clone();
    set_forced(
        &mut relabelled,
        vec![forced_entry(
            undecodable.clone(),
            2,
            B256::repeat_byte(0xab),
        )],
    );
    assert!(execute_batch_v5(&relabelled).is_err());

    let mut mislabelled = input;
    set_forced(
        &mut mislabelled,
        vec![forced_entry(
            undecodable.clone(),
            2,
            forced_rejection_reason_hash_v5(
                keccak256(undecodable.as_ref()),
                FORCED_REJECTION_SENDER_V5,
            ),
        )],
    );
    assert!(execute_batch_v5(&mislabelled).is_err());

    // A root call outside the certified envelope is deterministic too.
    let off_policy = sign_call(chain_id, 2, Address::repeat_byte(0x99), 1);
    let mut policy_rejected = validity_only_batch();
    set_forced(
        &mut policy_rejected,
        vec![forced_entry(
            off_policy.clone(),
            2,
            forced_rejection_reason_hash_v5(
                keccak256(off_policy.as_ref()),
                FORCED_REJECTION_POLICY_V5,
            ),
        )],
    );
    execute_batch_v5(&policy_rejected)
        .expect("a call outside the certified envelope may be rejected");

    // This one the batch could have carried: it decodes, it is inside the
    // certified envelope, and the sender can still execute it at the terminal
    // state. Marking it rejected is censorship, not a deterministic outcome.
    let executable = sign_call(chain_id, 2, Address::repeat_byte(0x44), 11);
    let mut censored = validity_only_batch();
    set_forced(
        &mut censored,
        vec![forced_entry(
            executable.clone(),
            2,
            forced_rejection_reason_hash_v5(
                keccak256(executable.as_ref()),
                FORCED_REJECTION_UNDECODABLE_V5,
            ),
        )],
    );
    assert!(execute_batch_v5(&censored).is_err());
}

#[test]
fn an_admission_cannot_be_rejected_and_executed_by_the_same_batch() {
    let mut input = validity_only_batch();
    let executed_hash = keccak256(input.blocks[0].raw_txs[0].as_ref());
    input.admissions = vec![AdmissionRecordV5 {
        receipt: AdmissionReceiptV5 {
            admission_id: 1,
            transaction_hash: executed_hash,
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
            transaction_hash: executed_hash,
            status: 2,
            l2_block_number: 0,
            transaction_index: 0,
            reason_hash: B256::repeat_byte(0xcd),
        },
    }];
    input.journal.admission_cursor_after = 1;
    input.journal.admission_records_hash = admission_records_hash_v5(&input.admissions);
    assert!(execute_batch_v5(&input).is_err());
}

#[test]
fn deposits_and_withdrawals_must_conserve_the_liability_ledger() {
    let mut input = valid_batch();
    set_liabilities(&mut input, liabilities(100, 0), liabilities(100, 0));
    execute_batch_v5(&input).expect("an unchanged ledger conserves trivially");

    // A post-ledger that credits `controlled` without a consumed deposit is a
    // free mint of room-controlled escrow.
    let mut minted = input;
    set_liabilities(&mut minted, liabilities(100, 0), liabilities(101, 0));
    assert!(execute_batch_v5(&minted).is_err());
}

#[test]
fn crossed_inbox_records_are_content_addressed_and_refunds_are_skipped() {
    let active = DepositV5 {
        inbox_id: 1,
        depositor: Address::repeat_byte(0xa1),
        beneficiary: Address::repeat_byte(0xb1),
        asset: Address::ZERO,
        amount: U256::from(10),
        queued_at_block: 100,
        consumed: false,
        refunded: false,
    };
    let refunded = DepositV5 {
        inbox_id: 2,
        depositor: Address::repeat_byte(0xa2),
        beneficiary: Address::repeat_byte(0xb2),
        asset: Address::ZERO,
        amount: U256::from(7),
        queued_at_block: 101,
        consumed: false,
        refunded: true,
    };
    let mut input =
        valid_batch_with_deposits(vec![(active, U256::ZERO), (refunded, U256::ZERO)]);
    let mut pre = liabilities(100, 0);
    pre[0].pending = U256::from(10);
    let post = liabilities(110, 0);
    set_liabilities(&mut input, pre, post);
    execute_batch_v5(&input).expect("only the live deposit moves pending escrow into control");

    let mut relabelled = input.clone();
    relabelled.deposits[0].depositor = Address::repeat_byte(0xee);
    assert!(
        execute_batch_v5(&relabelled).is_err(),
        "the journal commits the exact deposit content"
    );

    let mut already_consumed = input;
    already_consumed.deposits[0].consumed = true;
    already_consumed.journal.inbox_records_hash = inbox_records_hash_v5(&already_consumed.deposits);
    assert!(
        execute_batch_v5(&already_consumed).is_err(),
        "a composer cannot prove the same live deposit twice"
    );
}

#[test]
fn funded_admission_is_bound_to_the_referenced_deposit_content() {
    let deposit = DepositV5 {
        inbox_id: 1,
        depositor: Address::repeat_byte(0xa1),
        beneficiary: Address::repeat_byte(0xb1),
        asset: Address::ZERO,
        amount: U256::from(100),
        queued_at_block: 100,
        consumed: false,
        refunded: false,
    };
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        deposits: vec![(deposit.clone(), U256::from(3))],
        ..Default::default()
    });
    let transaction_hash = keccak256(input.blocks[0].raw_txs[0].as_ref());
    input.admissions = vec![AdmissionRecordV5 {
        receipt: AdmissionReceiptV5 {
            admission_id: 1,
            transaction_hash,
            deposit_inbox_id: deposit.inbox_id,
            deposit_content_hash: deposit_content_hash_v5(&deposit),
            deadline_block: 1_000,
            maximum_batch_index: 1,
            bond_epoch: 1,
            admission_fee: U256::from(3),
            signature: Bytes::from(vec![0x11; 65]),
        },
        outcome: AdmissionOutcomeV5 {
            admission_id: 1,
            transaction_hash,
            status: 0,
            l2_block_number: 1,
            transaction_index: 0,
            reason_hash: B256::ZERO,
        },
    }];
    input.journal.admission_cursor_after = 1;
    input.journal.admission_records_hash = admission_records_hash_v5(&input.admissions);
    let mut pre = liabilities(100, 0);
    pre[0].pending = U256::from(100);
    set_liabilities(&mut input, pre, liabilities(200, 0));
    execute_batch_v5(&input).expect("receipt, inbox record and liability transition agree");

    let mut swapped = input;
    swapped.admissions[0].receipt.deposit_content_hash = B256::repeat_byte(0xee);
    swapped.journal.admission_records_hash = admission_records_hash_v5(&swapped.admissions);
    assert!(
        execute_batch_v5(&swapped).is_err(),
        "an inbox id cannot be silently rebound to different deposit content"
    );
}

#[test]
fn the_first_batch_must_open_at_its_registered_cold_template() {
    let input = valid_batch();
    assert_eq!(input.journal.batch_index, 1);
    execute_batch_v5(&input).expect("the fixture opens at its own template state");

    let mut relabelled = valid_batch();
    relabelled.journal.cold_template_id = B256::repeat_byte(0x22);
    assert!(execute_batch_v5(&relabelled).is_err());

    // Later batches have moved past the template's initial root, so the guest
    // cannot derive the identity and L1 remains the only binding.
    let mut later = valid_batch();
    later.journal.batch_index = 2;
    later.journal.cold_template_id = B256::repeat_byte(0x22);
    execute_batch_v5(&later).expect("template binding is derivable only for batch 1");
}

#[test]
fn import_mirrors_must_target_a_writable_namespace() {
    let mut input = valid_batch_with_import();
    execute_batch_v5(&input).expect("the certified mirror destination is writable");

    // The mirror write lands before the pre-execution snapshot, so
    // `validate_post_state` can never see it: a read-only destination would
    // silently contradict the namespace flag instead of being refused.
    input.policy.storage[0].writable = false;
    rebind_policy(&mut input);
    let error = execute_batch_v5(&input).expect_err("a read-only mirror destination is refused");
    assert!(
        format!("{error}").contains("writable v5 namespace"),
        "unexpected error: {error}"
    );
}

#[test]
fn approver_removal_pays_exactly_the_committed_withdrawal_leaf() {
    let withdrawal = WithdrawalV5 {
        index: 0,
        roster_epoch: 2,
        recipient: sender(),
        asset: Address::ZERO,
        amount: U256::from(100),
    };
    let mut input = valid_batch();
    input.roster_changes = vec![RosterChangeV5 {
        action: 1,
        request_id: 1,
        index: 0,
        joined_epoch: 1,
        deadline: 2_000,
        member: sender(),
        withdrawal_commitment: withdrawal_leaf_v5(
            input.journal.deployment_domain,
            input.journal.room_id,
            input.journal.outbox_epoch,
            &withdrawal,
        ),
    }];
    input.post_roster.clear();
    input.journal.post_roster_root = roster_root_v5(&input.post_roster, 2).unwrap();
    input.journal.post_roster_epoch = 2;
    input.journal.post_active_count = 0;
    input.journal.roster_change_cursor_after = 1;
    input.journal.roster_changes_hash = roster_changes_hash_v5(&input.roster_changes);
    input.withdrawals = vec![withdrawal];
    input.withdrawal_capacity = 2;
    input.journal.withdrawal_root = withdrawal_root_v5(
        input.journal.deployment_domain,
        input.journal.room_id,
        input.journal.outbox_epoch,
        &input.withdrawals,
        input.withdrawal_capacity,
    )
    .unwrap();
    set_liabilities(&mut input, liabilities(100, 0), liabilities(0, 100));
    execute_batch_v5(&input).expect("a removal paid by its committed allocation is valid");

    // The commitment the departing approver signed is the whole authority for
    // the payout: the allocation cannot be re-priced or re-pointed afterwards.
    for tampered in [
        WithdrawalV5 {
            amount: U256::from(90),
            ..input.withdrawals[0].clone()
        },
        WithdrawalV5 {
            recipient: Address::repeat_byte(0xbe),
            ..input.withdrawals[0].clone()
        },
    ] {
        let mut forged = input.clone();
        let claimable = forged.pre_liabilities[0].controlled - tampered.amount;
        forged.withdrawals = vec![tampered];
        forged.journal.withdrawal_root = withdrawal_root_v5(
            forged.journal.deployment_domain,
            forged.journal.room_id,
            forged.journal.outbox_epoch,
            &forged.withdrawals,
            forged.withdrawal_capacity,
        )
        .unwrap();
        set_liabilities(
            &mut forged,
            liabilities(100, 0),
            liabilities(
                claimable.to::<u64>(),
                (U256::from(100) - claimable).to::<u64>(),
            ),
        );
        assert!(execute_batch_v5(&forged).is_err());
    }
}

#[test]
fn block_hash_history_is_bound_to_the_approved_batch_data() {
    let mut input = valid_batch();
    input.blocks[1].block_hashes = vec![HistoricalBlockHash {
        number: 1,
        hash: B256::repeat_byte(0xf1),
    }];
    // The history is part of the canonical block encoding, so a host that adds
    // one without the approvers seeing it fails the batch-data commitment.
    assert!(execute_batch_v5(&input).is_err());

    input.journal.batch_data_hash =
        batch_block_data_hash_v5(&input.blocks, input.journal.pre_state_root);
    execute_batch_v5(&input).expect("an approved in-window history is valid");

    let mut out_of_window = input;
    out_of_window.blocks[1].block_hashes[0].number = 9;
    out_of_window.journal.batch_data_hash =
        batch_block_data_hash_v5(&out_of_window.blocks, out_of_window.journal.pre_state_root);
    assert!(execute_batch_v5(&out_of_window).is_err());
}

#[test]
fn consumed_deposit_value_must_reach_its_beneficiary() {
    let beneficiary = Address::repeat_byte(0xb1);
    let deposit = DepositV5 {
        inbox_id: 1,
        depositor: Address::repeat_byte(0xa1),
        beneficiary,
        asset: Address::ZERO,
        amount: U256::from(100),
        queued_at_block: 100,
        consumed: false,
        refunded: false,
    };
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        deposits: vec![(deposit.clone(), U256::ZERO)],
        ..Default::default()
    });
    let mut pre = liabilities(100, 0);
    pre[0].pending = U256::from(100);
    set_liabilities(&mut input, pre.clone(), liabilities(200, 0));
    execute_batch_v5(&input).expect("the consumed deposit's value reaches its beneficiary");

    // Same proved blocks with the deposit re-pointed at a third party: the
    // batch state credits 0xb1 while the guest's derived credit goes to 0xdd,
    // so the first block no longer opens at the proved root.
    let mut diverted = input.clone();
    diverted.deposits[0].beneficiary = Address::repeat_byte(0xdd);
    diverted.journal.inbox_records_hash = inbox_records_hash_v5(&diverted.deposits);
    declare_absent_account(&mut diverted.compact_state, Address::repeat_byte(0xdd));
    assert!(execute_batch_v5(&diverted).is_err());

    // A batch whose blocks never reflected the credit strands the depositor:
    // consuming the deposit while crediting nobody is unprovable even though
    // the aggregate liability ledger conserves.
    let mut stranded = exit_batch_with(ExitBatchOptionsV5::default());
    stranded.deposits = vec![deposit];
    stranded.journal.inbox_cursor_after = 1;
    stranded.journal.inbox_records_hash = inbox_records_hash_v5(&stranded.deposits);
    declare_absent_account(&mut stranded.compact_state, beneficiary);
    set_liabilities(&mut stranded, pre, liabilities(200, 0));
    assert!(execute_batch_v5(&stranded).is_err());
}

#[test]
fn consumed_erc20_deposit_is_credited_on_the_bound_token_balance_slot() {
    let balance_slot = U256::from(0x50);
    let deposit = DepositV5 {
        inbox_id: 1,
        depositor: Address::repeat_byte(0xa1),
        beneficiary: exit_holder(),
        asset: exit_erc20_asset(),
        amount: U256::from(70),
        queued_at_block: 100,
        consumed: false,
        refunded: false,
    };
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        erc20_balance_slot: Some(balance_slot),
        deposits: vec![(deposit, U256::ZERO)],
        ..Default::default()
    });
    let erc20 = |pending: u64, controlled: u64| AssetLiabilityV5 {
        asset: exit_erc20_asset(),
        pending: U256::from(pending),
        controlled: U256::from(controlled),
        claimable: U256::ZERO,
        paid: U256::ZERO,
    };
    let mut pre = liabilities(100, 0);
    pre.push(erc20(70, 0));
    let mut post = liabilities(100, 0);
    post.push(erc20(0, 70));
    set_liabilities(&mut input, pre, post);
    execute_batch_v5(&input).expect("the ERC-20 credit lands on the declared balance slot");
}

#[test]
fn the_policy_resource_envelope_bounds_the_proved_batch() {
    let mut too_many_blocks = valid_batch();
    too_many_blocks.policy.max_blocks_per_batch = 1;
    rebind_policy(&mut too_many_blocks);
    assert!(execute_batch_v5(&too_many_blocks).is_err());

    // The certified block gas limit is the policy value, so a room cannot be
    // proved against an environment it never certified.
    let mut wider_gas = valid_batch();
    wider_gas.policy.max_gas_per_block = GAS_LIMIT * 2;
    rebind_policy(&mut wider_gas);
    assert!(execute_batch_v5(&wider_gas).is_err());
}
