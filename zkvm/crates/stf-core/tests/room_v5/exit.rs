//! Proof-derived validity-only exits: post-state queue records mint the
//! withdrawal tree, closing batches sweep residual controlled escrow, and
//! every deviation from the derived allocation is refused.

use alloy_primitives::{keccak256, Address, B256, U256};
use stf_core::execute_batch_v5;
use stf_types::{
    forced_rejection_reason_hash_v5, room_chain_id_v5, AdmissionOutcomeV5, AssetLiabilityV5,
    ForcedTransactionV5, WithdrawalV5, FORCED_REJECTION_SENDER_V5,
};

use crate::support::{
    count_overwrite_runtime_code, sender, sign_exit_call, EXIT_QUEUE_RECORDS_BASE_SLOT, ROOM_ID,
};
use crate::witness::{
    exit_batch_with, exit_erc20_asset, exit_fallback, exit_holder, exit_queue, forced_entry,
    liabilities, set_forced, set_liabilities, set_withdrawals, validity_only_exit_batch,
    ExitBatchOptionsV5,
};

fn chain_id() -> u64 {
    room_chain_id_v5(B256::repeat_byte(0x11), ROOM_ID)
}

#[test]
fn stored_policy_json_without_the_exit_key_still_parses() {
    // Stored legacy policy JSON predates the optional exit binding; it must
    // keep decoding (to None) and keep its canonical hash.
    let policy = validity_only_exit_batch().policy;
    let mut value = serde_json::to_value(&policy).expect("policy serializes");
    value
        .as_object_mut()
        .expect("policy JSON is an object")
        .remove("exit");
    let parsed: stf_types::ExecutionPolicyV5 =
        serde_json::from_value(value).expect("legacy policy JSON parses");
    assert!(parsed.exit.is_none());
}

fn withdrawal(index: u64, recipient: Address, asset: Address, amount: u64) -> WithdrawalV5 {
    WithdrawalV5 {
        index,
        roster_epoch: 1,
        recipient,
        asset,
        amount: U256::from(amount),
    }
}

/// Native + ERC-20 rows for the two-asset sweep fixtures, in sorted order.
fn two_asset_ledger(native_controlled: u64, erc20: AssetLiabilityV5) -> Vec<AssetLiabilityV5> {
    vec![
        AssetLiabilityV5 {
            asset: Address::ZERO,
            pending: U256::ZERO,
            controlled: U256::from(native_controlled),
            claimable: U256::ZERO,
            paid: U256::ZERO,
        },
        erc20,
    ]
}

#[test]
fn validity_exit_records_mint_withdrawals_matching_post_state() {
    let input = validity_only_exit_batch();
    let journal = execute_batch_v5(&input).expect("a recorded exit mints its withdrawal leaf");
    assert_eq!(journal, input.journal);
    assert_ne!(journal.withdrawal_root, B256::ZERO);
}

#[test]
fn exit_withdrawals_must_equal_the_recorded_delta_exactly() {
    let input = validity_only_exit_batch();
    execute_batch_v5(&input).expect("the base single-record exit is valid");
    let recipient = Address::repeat_byte(0xbe);

    // Re-priced amount (ledger kept conserved so only the derivation refuses).
    let mut repriced = input.clone();
    set_liabilities(&mut repriced, liabilities(100, 0), liabilities(61, 39));
    set_withdrawals(
        &mut repriced,
        vec![withdrawal(0, recipient, Address::ZERO, 39)],
        1,
    );
    assert!(execute_batch_v5(&repriced).is_err());

    // Re-pointed recipient.
    let mut repointed = input.clone();
    set_withdrawals(
        &mut repointed,
        vec![withdrawal(0, Address::repeat_byte(0xcf), Address::ZERO, 40)],
        1,
    );
    assert!(execute_batch_v5(&repointed).is_err());

    // Extra unbacked leaf.
    let mut padded = input.clone();
    set_liabilities(&mut padded, liabilities(100, 0), liabilities(59, 41));
    set_withdrawals(
        &mut padded,
        vec![
            withdrawal(0, recipient, Address::ZERO, 40),
            withdrawal(1, Address::repeat_byte(0xcf), Address::ZERO, 1),
        ],
        2,
    );
    assert!(execute_batch_v5(&padded).is_err());

    // Wrong tree capacity for the same leaves.
    let mut widened = input.clone();
    let same_leaves = widened.withdrawals.clone();
    set_withdrawals(&mut widened, same_leaves, 2);
    assert!(execute_batch_v5(&widened).is_err());

    // Wrong roster epoch on the leaf.
    let mut relabelled = input;
    set_withdrawals(
        &mut relabelled,
        vec![WithdrawalV5 {
            roster_epoch: 2,
            ..withdrawal(0, recipient, Address::ZERO, 40)
        }],
        1,
    );
    assert!(execute_batch_v5(&relabelled).is_err());

    // Swapped payload order across two records: the record-creation order is
    // consensus, so exchanging the two leaves' contents is refused even
    // though the totals conserve.
    let two = exit_batch_with(ExitBatchOptionsV5 {
        exit_calls: vec![
            sign_exit_call(chain_id(), 1, exit_queue(), recipient, Address::ZERO, 40),
            sign_exit_call(
                chain_id(),
                2,
                exit_queue(),
                Address::repeat_byte(0xcf),
                Address::ZERO,
                25,
            ),
        ],
        ..Default::default()
    });
    let mut ordered = two;
    set_liabilities(&mut ordered, liabilities(100, 0), liabilities(35, 65));
    set_withdrawals(
        &mut ordered,
        vec![
            withdrawal(0, recipient, Address::ZERO, 40),
            withdrawal(1, Address::repeat_byte(0xcf), Address::ZERO, 25),
        ],
        2,
    );
    execute_batch_v5(&ordered).expect("two records mint two leaves in creation order");

    let mut swapped = ordered;
    set_withdrawals(
        &mut swapped,
        vec![
            withdrawal(0, Address::repeat_byte(0xcf), Address::ZERO, 25),
            withdrawal(1, recipient, Address::ZERO, 40),
        ],
        2,
    );
    assert!(execute_batch_v5(&swapped).is_err());
}

#[test]
fn exit_record_with_undeclared_asset_or_zero_amount_is_refused() {
    // The withdrawals stay empty and the ledger unchanged, so the rejection
    // can only come from the record derivation itself.
    let undeclared = exit_batch_with(ExitBatchOptionsV5 {
        exit_calls: vec![sign_exit_call(
            chain_id(),
            1,
            exit_queue(),
            Address::repeat_byte(0xbe),
            exit_erc20_asset(),
            40,
        )],
        ..Default::default()
    });
    let error = execute_batch_v5(&undeclared).expect_err("undeclared asset is refused");
    assert!(
        format!("{error}").contains("undeclared asset"),
        "unexpected error: {error}"
    );

    let zero_amount = exit_batch_with(ExitBatchOptionsV5 {
        exit_calls: vec![sign_exit_call(
            chain_id(),
            1,
            exit_queue(),
            Address::repeat_byte(0xbe),
            Address::ZERO,
            0,
        )],
        ..Default::default()
    });
    assert!(execute_batch_v5(&zero_amount).is_err());
}

#[test]
fn exit_count_regression_is_refused() {
    // A hostile queue overwrites its own cursor: opening count 5 becomes 3.
    let input = exit_batch_with(ExitBatchOptionsV5 {
        queue_code: count_overwrite_runtime_code(),
        opening_count: 5,
        exit_calls: vec![sign_exit_call(
            chain_id(),
            1,
            exit_queue(),
            Address::with_last_byte(3),
            Address::ZERO,
            0,
        )],
        ..Default::default()
    });
    let error = execute_batch_v5(&input).expect_err("a regressing exit cursor is refused");
    assert!(
        format!("{error}").contains("regressed"),
        "unexpected error: {error}"
    );
}

#[test]
fn exit_batch_with_more_than_256_withdrawal_leaves_is_provable() {
    // 300 records pre-seeded in queue storage; one certified call jumps the
    // count cursor from 0 to 300, so the batch mints 300 leaves at once. The
    // resulting capacity-512 tree exceeds the 256-leaf roster bound by
    // design: the withdrawal outbox is bounded by claim-proof depth 15
    // (32768 leaves) instead, so every bounded close sweep fits one epoch.
    let record_word = |index: u64| U256::from(0x1000 + index);
    let mut opening_queue_storage = Vec::new();
    for index in 0..300u64 {
        let base = EXIT_QUEUE_RECORDS_BASE_SLOT + U256::from(3 * index);
        opening_queue_storage.push((base, record_word(index)));
        // The asset word stays zero (native) and needs no seeded value.
        opening_queue_storage.push((base + U256::from(2u64), U256::from(1u64)));
    }
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        queue_code: count_overwrite_runtime_code(),
        exit_calls: vec![sign_exit_call(
            chain_id(),
            1,
            exit_queue(),
            Address::from_word(B256::from(U256::from(300u64))),
            Address::ZERO,
            0,
        )],
        opening_queue_storage,
        declared_queue_records: 300,
        ..Default::default()
    });
    set_liabilities(&mut input, liabilities(300, 0), liabilities(0, 300));
    set_withdrawals(
        &mut input,
        (0..300u64)
            .map(|index| WithdrawalV5 {
                index,
                roster_epoch: 1,
                recipient: Address::from_word(B256::from(record_word(index))),
                asset: Address::ZERO,
                amount: U256::from(1u64),
            })
            .collect(),
        512,
    );
    let journal = execute_batch_v5(&input).expect("300 leaves fit one withdrawal epoch");
    assert_eq!(input.withdrawal_capacity, 512);
    assert_ne!(journal.withdrawal_root, B256::ZERO);
}

#[test]
fn closing_batch_sweeps_residual_controlled_pro_rata() {
    // Terminal balances: holder 100, sender 300. Residual 100 splits 25/75
    // with no dust; accounts ascend, so the holder leaf comes first.
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        close: true,
        ..Default::default()
    });
    set_liabilities(&mut input, liabilities(100, 0), liabilities(0, 100));
    set_withdrawals(
        &mut input,
        vec![
            withdrawal(0, exit_holder(), Address::ZERO, 25),
            withdrawal(1, sender(), Address::ZERO, 75),
        ],
        2,
    );
    let journal = execute_batch_v5(&input).expect("the close sweep drains controlled escrow");
    assert!(journal.close);

    // The same batch without the sweep leaves strands escrow and is refused.
    let mut stranded = exit_batch_with(ExitBatchOptionsV5 {
        close: true,
        ..Default::default()
    });
    set_liabilities(&mut stranded, liabilities(100, 0), liabilities(0, 100));
    assert!(execute_batch_v5(&stranded).is_err());
}

#[test]
fn closing_sweep_pays_fallback_recipient_when_no_balance_attributes() {
    // The ERC-20 exit asset has no holder balances at the terminal state, so
    // the whole residual is one fallback-recipient leaf.
    let balance_slot = U256::from(0x50);
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        erc20_balance_slot: Some(balance_slot),
        close: true,
        ..Default::default()
    });
    let pre = two_asset_ledger(
        0,
        AssetLiabilityV5 {
            asset: exit_erc20_asset(),
            pending: U256::ZERO,
            controlled: U256::from(100u64),
            claimable: U256::ZERO,
            paid: U256::ZERO,
        },
    );
    let post = two_asset_ledger(
        0,
        AssetLiabilityV5 {
            asset: exit_erc20_asset(),
            pending: U256::ZERO,
            controlled: U256::ZERO,
            claimable: U256::from(100u64),
            paid: U256::ZERO,
        },
    );
    set_liabilities(&mut input, pre, post);
    set_withdrawals(
        &mut input,
        vec![withdrawal(0, exit_fallback(), exit_erc20_asset(), 100)],
        1,
    );
    execute_batch_v5(&input).expect("an unattributable residual pays the fallback recipient");
}

#[test]
fn closing_sweep_dust_goes_to_fallback_recipient() {
    // Residual 101 over balances 100/300: floors 25 + 75, one unit of dust.
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        close: true,
        ..Default::default()
    });
    set_liabilities(&mut input, liabilities(101, 0), liabilities(0, 101));
    set_withdrawals(
        &mut input,
        vec![
            withdrawal(0, exit_holder(), Address::ZERO, 25),
            withdrawal(1, sender(), Address::ZERO, 75),
            withdrawal(2, exit_fallback(), Address::ZERO, 1),
        ],
        4,
    );
    execute_batch_v5(&input).expect("rounding dust lands on the fallback recipient");
}

#[test]
fn mid_life_partial_exit_keeps_the_room_open_and_conserves_the_ledger() {
    let input = validity_only_exit_batch();
    let journal = execute_batch_v5(&input).expect("a mid-life exit is valid without closing");
    assert!(!journal.close);
    assert_eq!(input.post_liabilities[0].controlled, U256::from(60u64));
    assert_eq!(input.post_liabilities[0].claimable, U256::from(40u64));
    // The remaining controlled escrow stays usable: nothing forces the close.
    assert_ne!(input.post_liabilities[0].controlled, U256::ZERO);
}

#[test]
fn multi_checkpoint_exit_lands_against_the_second_epoch_root() {
    let recipient = Address::repeat_byte(0xbe);
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        exit_calls: vec![sign_exit_call(
            chain_id(),
            3,
            exit_queue(),
            recipient,
            Address::ZERO,
            40,
        )],
        second_epoch: true,
        ..Default::default()
    });
    assert_eq!(input.journal.batch_index, 2);
    assert_eq!(input.journal.outbox_epoch, 2);
    set_liabilities(&mut input, liabilities(100, 0), liabilities(60, 40));
    set_withdrawals(
        &mut input,
        vec![withdrawal(0, recipient, Address::ZERO, 40)],
        1,
    );
    let journal = execute_batch_v5(&input).expect("an exit in a later checkpoint is valid");
    assert_eq!(journal.outbox_epoch, 2);
    assert_ne!(journal.withdrawal_root, B256::ZERO);
}

#[test]
fn forced_exit_transaction_mints_the_withdrawal() {
    // The forced queue is the censorship transport: the same signed exit call
    // is both an executed block transaction and the crossed forced entry.
    let mut input = validity_only_exit_batch();
    let raw = input.blocks[1].raw_txs[0].clone();
    let forced = ForcedTransactionV5 {
        forced_id: 1,
        outcome: AdmissionOutcomeV5 {
            admission_id: 1,
            transaction_hash: keccak256(raw.as_ref()),
            status: 0,
            l2_block_number: input.blocks[1].block_number,
            transaction_index: 0,
            reason_hash: B256::ZERO,
        },
        raw_transaction: raw,
    };
    set_forced(&mut input, vec![forced]);
    let journal = execute_batch_v5(&input).expect("a forced exit call mints its withdrawal");
    assert_ne!(journal.withdrawal_root, B256::ZERO);
}

#[test]
fn executable_forced_exit_cannot_be_marked_rejected() {
    // A fresh exit call the sender can still execute at the terminal state
    // (nonce 2, zero value) is censorship if labelled rejected.
    let mut input = validity_only_exit_batch();
    let executable = sign_exit_call(
        chain_id(),
        2,
        exit_queue(),
        Address::repeat_byte(0xbe),
        Address::ZERO,
        1,
    );
    set_forced(
        &mut input,
        vec![forced_entry(
            executable.clone(),
            2,
            forced_rejection_reason_hash_v5(
                keccak256(executable.as_ref()),
                FORCED_REJECTION_SENDER_V5,
            ),
        )],
    );
    assert!(execute_batch_v5(&input).is_err());
}

#[test]
fn terminal_one_block_close_batch_with_exit_binding_is_valid() {
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        single_block: true,
        close: true,
        ..Default::default()
    });
    assert_eq!(input.blocks.len(), 1);
    set_liabilities(&mut input, liabilities(100, 0), liabilities(0, 100));
    set_withdrawals(
        &mut input,
        vec![
            withdrawal(0, exit_holder(), Address::ZERO, 25),
            withdrawal(1, sender(), Address::ZERO, 75),
        ],
        2,
    );
    let journal = execute_batch_v5(&input).expect("a one-block terminal close sweeps and settles");
    assert!(journal.close);
}
