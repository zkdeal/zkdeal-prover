//! Second and later checkpoints: `batchIndex` and the block history it needs.
//!
//! A room that can only ever take one checkpoint is not a long-lived room, and
//! the failure mode is not a proof failure -- a mis-chained batch proves
//! perfectly well and is then rejected by `RoomManagerValidationFacet
//! ._validateJournal`, on chain, after the money has been spent. So these
//! tests assert the five journal fields that facet compares against the room's
//! stored values (`batchIndex == room.batchIndex + 1`, `startL2Block ==
//! room.l2BlockHeight + 1`, `preStateRoot == room.stateRoot`,
//! `preParticipant*` and `outboxEpoch == room.outboxEpoch + 1`) chain onto the
//! previous batch's journal exactly.

use alloy_primitives::{Address, Bytes, B256, U256};
use serde_json::{json, Value};
use stf_types::{room_chain_id_v5, AccountState, CompactStateWitnessV4};

use super::bytecode::storage_runtime;
use super::config::parse_fixture_config;
use super::contracts::{exit_queue_address, legacy_contracts};
use super::request_tests::request;
use super::signing::sign_calldata_as;

const DOMAIN: B256 = B256::repeat_byte(0x11);
const IMAGE_ID: [u8; 32] = [0x7u8; 32];

fn legacy_registry() -> Address {
    legacy_contracts(1, None, &storage_runtime()).1
}

/// `storage_runtime` stores `calldataload(4)` at slot zero, so each of these is
/// one real room call that moves the room's state.
fn storage_call(nonce: u64, value: u64) -> Value {
    let mut input = vec![0x12, 0x34, 0x56, 0x78];
    input.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
    let raw = sign_calldata_as(
        room_chain_id_v5(DOMAIN, 1),
        0,
        nonce,
        legacy_registry(),
        Bytes::from(input),
        120_000,
    );
    json!(format!("0x{}", alloy_primitives::hex::encode(&raw)))
}

/// One block per nonce: block `n` carries the transaction with nonce `n - 1`.
fn blocks(count: u64) -> Value {
    Value::Array(
        (0..count)
            .map(|index| json!([storage_call(index, 9 + index)]))
            .collect(),
    )
}

/// A client-signed `validity-only` room, the mode a card room runs in, asking
/// for checkpoint `batch_index` with the whole history it implies.
fn room_at(batch_index: u64, raw_transactions: Value) -> String {
    request(vec![
        ("authorizationMode", json!("validity-only")),
        ("activeSigners", json!(0)),
        ("batchIndex", json!(batch_index)),
        ("rawTransactions", raw_transactions),
    ])
}

fn journal(prepared: &Value) -> &Value {
    &prepared["roomRequest"]["roomWitness"]["journal"]
}

#[test]
fn a_second_batch_chains_onto_the_first() {
    let first = super::prepare(&room_at(1, blocks(2)), IMAGE_ID).expect("the opening batch");
    let second = super::prepare(&room_at(2, blocks(4)), IMAGE_ID)
        .expect("the same room, two blocks further on");
    let (one, two) = (journal(&first), journal(&second));

    // `journal.batchIndex != room.batchIndex + 1` reverts on L1.
    assert_eq!(one["batch_index"], json!(1));
    assert_eq!(two["batch_index"], json!(2));
    // `journal.startL2Block != room.l2BlockHeight + 1` reverts on L1.
    assert_eq!((&one["start_l2_block"], &one["end_l2_block"]), (&json!(1), &json!(2)));
    assert_eq!((&two["start_l2_block"], &two["end_l2_block"]), (&json!(3), &json!(4)));
    // `journal.preStateRoot != room.stateRoot` reverts on L1.
    assert_eq!(two["pre_state_root"], one["post_state_root"]);
    assert_ne!(two["post_state_root"], two["pre_state_root"]);
    // `journal.preParticipant*` are all compared against the room's stored
    // registry, so all three have to be the first batch's closing values.
    assert_eq!(two["pre_participant_root"], one["post_participant_root"]);
    assert_eq!(two["pre_participant_epoch"], one["post_participant_epoch"]);
    assert_eq!(two["pre_participant_count"], one["post_participant_count"]);
    assert_eq!(two["participant_capacity"], one["participant_capacity"]);
    // `journal.outboxEpoch != room.outboxEpoch + 1` reverts on L1.
    assert_eq!(one["outbox_epoch"], json!(1));
    assert_eq!(two["outbox_epoch"], json!(2));
    // The roster and every cursor `_validateJournal` compares are carried, not
    // reset: the continuation opens where the first batch closed.
    for field in [
        "pre_roster_root",
        "pre_roster_epoch",
        "pre_active_count",
        "roster_change_cursor_before",
        "inbox_cursor_before",
        "admission_cursor_before",
        "forced_cursor_before",
        "pre_liabilities_hash",
    ] {
        let closing = field.replace("pre_", "post_").replace("_before", "_after");
        assert_eq!(two[field], one[&closing], "{field} does not continue {closing}");
    }
    assert_eq!(two["import_cursor_before"], one["import_cursor_after"]);

    // The room's identity is the same room's identity. A continuation that
    // re-registered a template or moved the policy would be a different room.
    for field in ["cold_template_id", "policy_hash", "proof_program_id", "room_id"] {
        assert_eq!(two[field], one[field], "{field} changed between checkpoints");
    }
    assert_eq!(
        second["contractConfig"]["initialStateRoot"],
        first["contractConfig"]["initialStateRoot"]
    );

    // The blocks the batch actually proves are blocks three and four.
    let proved = second["roomRequest"]["roomWitness"]["blocks"]
        .as_array()
        .expect("a batch is a list of blocks");
    assert_eq!(proved.len(), 2);
    assert_eq!(proved[0]["block_number"], json!(3));
    assert_eq!(proved[1]["block_number"], json!(4));
    assert_eq!(second["measurement"]["transactions"], json!(2));
}

#[test]
fn a_continuation_retains_an_unchanged_zero_storage_declaration() {
    let second = super::prepare(&room_at(2, blocks(4)), IMAGE_ID)
        .expect("a continuation may read the inert exit queue count");
    let compact: CompactStateWitnessV4 =
        serde_json::from_value(second["roomRequest"]["roomWitness"]["compact_state"].clone())
            .expect("prepared compact-state witness");
    let queue = compact
        .accounts
        .iter()
        .find(|account| account.address == exit_queue_address())
        .expect("the cold exit-queue account remains present");
    assert!(queue.exists);
    assert!(queue
        .storage
        .iter()
        .any(|slot| slot.slot == U256::ZERO && slot.value == U256::ZERO));
}

#[test]
fn a_continuation_does_not_resurrect_a_removed_declared_account() {
    let removed = Address::repeat_byte(0xa5);
    let declarations = vec![(
        removed,
        AccountState {
            nonce: 1,
            balance: U256::ZERO,
            code: Bytes::from_static(&[0x00]),
            storage: vec![(U256::ZERO, U256::ZERO)],
        },
    )];
    let compact = super::state::compact_state_with_declared_storage(&[], &declarations);
    assert!(!compact
        .accounts
        .iter()
        .any(|account| account.address == removed));
}

#[test]
fn a_third_batch_chains_onto_the_second() {
    // Two replayed blocks is one fold step; four is the general case, and the
    // one that would expose a replay that restarts from the opening state.
    let second = super::prepare(&room_at(2, blocks(4)), IMAGE_ID).expect("checkpoint two");
    let third = super::prepare(&room_at(3, blocks(6)), IMAGE_ID).expect("checkpoint three");
    let (two, three) = (journal(&second), journal(&third));
    assert_eq!(three["batch_index"], json!(3));
    assert_eq!(three["start_l2_block"], json!(5));
    assert_eq!(three["end_l2_block"], json!(6));
    assert_eq!(three["outbox_epoch"], json!(3));
    assert_eq!(three["pre_state_root"], two["post_state_root"]);
}

#[test]
fn a_room_that_names_batch_one_prepares_exactly_what_it_prepared_before() {
    // `batchIndex` defaults to one, and stating it changes nothing: the same
    // request must still produce the same document, cold template included,
    // or every already-registered room's template id moves.
    let implied = super::prepare(&request(vec![]), IMAGE_ID).expect("the historic default");
    let stated = super::prepare(&request(vec![("batchIndex", json!(1))]), IMAGE_ID)
        .expect("the same room, saying so");
    assert_eq!(implied, stated);
    let opening = journal(&implied);
    assert_eq!(opening["batch_index"], json!(1));
    assert_eq!(opening["start_l2_block"], json!(1));
    assert_eq!(opening["end_l2_block"], json!(2));
    assert_eq!(opening["outbox_epoch"], json!(1));
    assert_eq!(
        opening["pre_state_root"],
        implied["contractConfig"]["initialStateRoot"],
        "batch one opens at the registered cold template's initial state"
    );
}

#[test]
fn a_continuation_must_carry_every_block_the_room_already_proved() {
    // The two blocks of batch two alone. Without the history there is no state
    // to open at, and the batch would either fail as a `PreRootMismatch` deep
    // inside `execute_batch_v5` or -- worse -- prove a batch numbered 3..4 on
    // top of the opening state and be rejected on L1.
    let error = parse_fixture_config(&room_at(2, blocks(2)))
        .expect_err("batch two needs blocks one through four");
    let error = format!("{error:#}");
    assert!(error.contains("batchIndex 2"), "{error}");
    assert!(error.contains("all 4 rawTransactions blocks"), "{error}");
    assert!(error.contains("carries 2"), "{error}");
}

#[test]
fn a_continuation_without_client_transactions_is_refused() {
    let error = parse_fixture_config(&request(vec![("batchIndex", json!(2))]))
        .expect_err("a host-scripted workload only ever builds two blocks");
    let error = format!("{error:#}");
    assert!(error.contains("is a continuation"), "{error}");
    assert!(error.contains("rawTransactions"), "{error}");
}

#[test]
fn a_batch_index_outside_the_replay_bound_is_refused() {
    let zero = parse_fixture_config(&room_at(0, blocks(2)))
        .expect_err("there is no batch zero");
    assert!(format!("{zero:#}").contains("counts from one"), "{zero:#}");

    let far = parse_fixture_config(&room_at(65, blocks(4)))
        .expect_err("65 batches is past the replay bound");
    assert!(format!("{far:#}").contains("replay bound"), "{far:#}");
}

#[test]
fn a_block_history_that_is_not_whole_batches_is_refused() {
    let odd = parse_fixture_config(&room_at(1, blocks(3)))
        .expect_err("a batch is two blocks, so a history is an even number of them");
    let odd = format!("{odd:#}");
    assert!(odd.contains("even number of room blocks"), "{odd}");
    assert!(odd.contains("carries 3"), "{odd}");
}

#[test]
fn a_misordered_history_fails_by_name_and_not_inside_execute_batch_v5() {
    // Blocks one and two swapped: the room's second nonce would have to land
    // before its first. The replay is where that is caught, and the message
    // says which L2 block and which batch, rather than surfacing as an opaque
    // native execution failure with no block number attached.
    let history = json!([
        [storage_call(1, 10)],
        [storage_call(0, 9)],
        [storage_call(2, 11)],
        [storage_call(3, 12)]
    ]);
    let error = super::prepare(&room_at(2, history), IMAGE_ID)
        .expect_err("that transaction order never produced this room");
    let error = format!("{error:#}");
    assert!(error.contains("replay L2 block 1"), "{error}");
    assert!(error.contains("batch 2 continues from"), "{error}");
    assert!(
        error.contains("transaction history is not the one this room actually ran"),
        "{error}"
    );
}

#[test]
fn a_continuation_carries_no_second_copy_of_the_l1_import() {
    // The import is verified and applied by the batch that carries it. A
    // continuation opens on an already-mirrored room, so carrying it again
    // would advance `importCursor` a second time for one queued import and be
    // rejected by `_validateJournal`.
    let imported = |batch_index: u64, count: u64| {
        request(vec![
            ("authorizationMode", json!("validity-only")),
            ("activeSigners", json!(0)),
            ("batchIndex", json!(batch_index)),
            ("rawTransactions", blocks(count)),
            ("importedVariables", json!(2)),
            ("residentMirrorVariables", json!(4)),
        ])
    };
    let first = super::prepare(&imported(1, 2), IMAGE_ID).expect("the importing batch");
    let second = super::prepare(&imported(2, 4), IMAGE_ID).expect("the continuation");
    let (one, two) = (journal(&first), journal(&second));
    assert_eq!(one["import_cursor_before"], json!(0));
    assert_eq!(one["import_cursor_after"], json!(1));
    assert_eq!(two["import_cursor_before"], json!(1));
    assert_eq!(two["import_cursor_after"], json!(1));
    assert_eq!(two["import_root"], json!(B256::ZERO));
    assert!(
        second["roomRequest"]["roomWitness"]["l1_import"].is_null(),
        "a continuation carries no import witness"
    );
    // The mirrored values are still in the room: the continuation opens on the
    // state the importing batch left, not on the pre-import opening state.
    assert_eq!(two["pre_state_root"], one["post_state_root"]);
}
