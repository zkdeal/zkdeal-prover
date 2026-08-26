//! `rawTransactions`: rooms whose batch was signed somewhere else.
//!
//! These drive `prepare` end to end rather than only the parser, because the
//! point of a client-signed room is that a batch the host never signed still
//! executes natively, still passes the certified policy, and still reports who
//! signed it. A parse test alone would show none of that.

use alloy_primitives::{Address, Bytes, B256, U256};
use serde_json::{json, Value};
use stf_types::room_chain_id_v5;

use super::bytecode::storage_runtime;
use super::config::parse_fixture_config;
use super::contracts::legacy_contracts;
use super::request_tests::{descriptor_room, request};
use super::signing::{sign_calldata_as, signer_address};

const DUEL: &str = "0x0000000000000000000000000000000000000d01";
const DOMAIN: B256 = B256::repeat_byte(0x11);
const IMAGE_ID: [u8; 32] = [0x7u8; 32];

/// The clone-shaped room a default request implies, and the contract its
/// transactions call.
fn legacy_registry() -> Address {
    legacy_contracts(1, None, &storage_runtime()).1
}

/// `storage_runtime` stores `calldataload(4)` at slot zero and ignores the
/// selector, so any four-byte prefix plus one word is a real room call.
fn storage_call_with(selector: [u8; 4], signer_index: u64, nonce: u64, value: u64) -> Value {
    let mut input = selector.to_vec();
    input.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
    let raw = sign_calldata_as(
        room_chain_id_v5(DOMAIN, 1),
        signer_index,
        nonce,
        legacy_registry(),
        Bytes::from(input),
        120_000,
    );
    json!(format!("0x{}", alloy_primitives::hex::encode(&raw)))
}

/// The historic fixture selector every clone-shaped room already certifies.
fn storage_call(signer_index: u64, nonce: u64, value: u64) -> Value {
    storage_call_with([0x12, 0x34, 0x56, 0x78], signer_index, nonce, value)
}

/// A client-signed room in the mode a card room actually runs in.
///
/// `validity-only` matters here and is not incidental: `execute_batch_v5`
/// builds its active-member set from the batch's own recovered senders only in
/// that mode (`room_v5/mod.rs`, `authorization_mode == 1`). An
/// approver-authorized room takes its active members from the roster instead,
/// so a browser key that is not a roster member is refused by the certified
/// policy however well-formed its transaction is --
/// `an_approver_room_still_admits_only_roster_callers` pins that.
fn client_room(extra: Vec<(&str, Value)>) -> String {
    let mut entries = vec![
        ("authorizationMode", json!("validity-only")),
        ("activeSigners", json!(0)),
        (
            "rawTransactions",
            json!([[storage_call(0, 0, 9)], [storage_call(0, 1, 10)]]),
        ),
    ];
    entries.extend(extra);
    request(entries)
}

#[test]
fn a_client_signed_batch_is_proven_and_reports_who_signed_it() {
    let prepared = super::prepare(&client_room(vec![]), IMAGE_ID)
        .expect("a batch the room's own key signed elsewhere still executes natively");
    assert_eq!(
        prepared["contractConfig"]["minimumImportConfirmations"],
        json!(64),
        "production room fixtures must carry the reviewed L1 import-depth policy"
    );
    assert_eq!(
        prepared["contractConfig"]["minimumDepositConfirmations"],
        json!(64),
        "production room fixtures must carry the reviewed L1 deposit-depth policy"
    );
    assert_eq!(prepared["measurement"]["transactions"], json!(2));
    assert_eq!(prepared["measurement"]["blocks"], json!(2));
    assert_eq!(
        prepared["contractConfig"]["duelistOwners"],
        json!([signer_address(0)]),
        "the recovered sender is reported, not an empty list"
    );
    // The batch really moved the room: block two overwrites block one's word.
    let journal = &prepared["roomRequest"]["roomWitness"]["journal"];
    assert!(journal["post_state_root"].is_string(), "{journal}");
    assert_ne!(journal["post_state_root"], journal["pre_state_root"]);
}

#[test]
fn a_second_signer_must_be_named_before_the_room_will_seat_it() {
    let unseated = super::prepare(
        &client_room(vec![(
            "rawTransactions",
            json!([[storage_call(3, 0, 9)], [storage_call(3, 1, 10)]]),
        )]),
        IMAGE_ID,
    )
    .expect_err("a key the opening state never funded cannot move the room");
    let unseated = format!("{unseated:#}");
    assert!(unseated.contains("this room does not seat"), "{unseated}");
    assert!(unseated.contains("senderAccounts"), "{unseated}");

    let prepared = super::prepare(
        &client_room(vec![
            (
                "rawTransactions",
                json!([[storage_call(3, 0, 9)], [storage_call(3, 1, 10)]]),
            ),
            ("senderAccounts", json!([signer_address(3)])),
            ("residentAccounts", json!(3)),
        ]),
        IMAGE_ID,
    )
    .expect("a named sender is funded into the opening state and moves the room");
    assert_eq!(
        prepared["contractConfig"]["duelistOwners"],
        json!([signer_address(3)])
    );
    assert_eq!(
        prepared["contractConfig"]["roomSigners"]
            .as_array()
            .expect("roomSigners is a list")
            .len(),
        2,
        "the fixture signer and the named sender are both seated"
    );
}

#[test]
fn an_approver_room_still_admits_only_roster_callers() {
    // Seating a key is necessary but not sufficient. Outside `validity-only`,
    // `execute_batch_v5` derives its active-member set from the approver
    // roster, so a stranger's transaction is refused by the certified policy
    // even though the opening state funds the account.
    let error = super::prepare(
        &request(vec![
            (
                "rawTransactions",
                json!([[storage_call(3, 0, 9)], [storage_call(3, 1, 10)]]),
            ),
            ("senderAccounts", json!([signer_address(3)])),
            ("residentAccounts", json!(3)),
        ]),
        IMAGE_ID,
    )
    .expect_err("an approver room does not admit an off-roster caller");
    let error = format!("{error:#}");
    assert!(error.contains("outside the certified envelope"), "{error}");
    assert!(
        error.contains(&format!("{}", signer_address(3))),
        "the refusal names the caller: {error}"
    );
}

#[test]
fn a_client_transaction_signed_for_another_chain_never_reaches_execution() {
    let stray = sign_calldata_as(
        room_chain_id_v5(DOMAIN, 1) + 1,
        0,
        0,
        legacy_registry(),
        Bytes::from(vec![0x12, 0x34, 0x56, 0x78]),
        120_000,
    );
    let error = super::prepare(
        &client_room(vec![(
            "rawTransactions",
            json!([
                [format!("0x{}", alloy_primitives::hex::encode(&stray))],
                [storage_call(0, 1, 10)]
            ]),
        )]),
        IMAGE_ID,
    )
    .expect_err("a room never proves another chain's transaction");
    let error = format!("{error:#}");
    assert!(error.contains("signed for chain"), "{error}");
    assert!(error.contains("rawTransactions[0][0]"), "{error}");
}

#[test]
fn a_client_selector_outside_the_allow_list_is_refused() {
    let error = super::prepare(
        &client_room(vec![("allowedSelectors", json!(["0xdeadbeef"]))]),
        IMAGE_ID,
    )
    .expect_err("the certified policy would refuse the call anyway");
    let error = format!("{error:#}");
    assert!(error.contains("outside allowedSelectors"), "{error}");
    assert!(error.contains("0x12345678"), "{error}");
}

#[test]
fn client_selectors_seed_the_allow_list_when_the_caller_states_none() {
    // Not the historic `0x12345678`: if the client's selectors did not seed the
    // certified allow-list, the room would pin the placeholder and its own
    // `execute_batch_v5` validation would refuse the batch it just built.
    let prepared = super::prepare(
        &client_room(vec![(
            "rawTransactions",
            json!([
                [storage_call_with([0xab, 0xcd, 0xef, 0x01], 0, 0, 9)],
                [storage_call_with([0xab, 0xcd, 0xef, 0x02], 0, 1, 10)]
            ]),
        )]),
        IMAGE_ID,
    )
    .expect("a client-signed room certifies the selectors it actually calls");
    let policy = &prepared["roomRequest"]["roomWitness"]["policy"];
    let selectors = policy["calls"][0]["selectors"]
        .as_array()
        .expect("the flat rule carries selectors");
    assert_eq!(
        selectors,
        &vec![
            json!([0xab, 0xcd, 0xef, 0x01]),
            json!([0xab, 0xcd, 0xef, 0x02])
        ],
        "{policy}"
    );
}

#[test]
fn overlapping_transaction_sources_are_refused_rather_than_ranked() {
    let both = parse_fixture_config(&client_room(vec![(
        "blockCalls",
        json!([["0x12345678"], ["0x12345678"]]),
    )]))
    .expect_err("one of the two would be dropped and still reported as proven");
    assert!(format!("{both}").contains("built from one of them"), "{both}");

    let duel = parse_fixture_config(&descriptor_room(vec![
        ("workload", json!("card-duel")),
        ("cardDuel", json!({ "entryStake": "1000" })),
        ("blockCalls", json!([["0x12345678"], ["0x12345678"]])),
    ]))
    .expect_err("a duel entry point cannot run on one key at 120,000 gas");
    assert!(format!("{duel}").contains("cannot express `blockCalls`"), "{duel}");
}

#[test]
fn a_client_signed_room_may_still_pin_its_own_call_rules() {
    let config = parse_fixture_config(&descriptor_room(vec![
        ("rawTransactions", json!([[storage_call(0, 0, 9)], [storage_call(0, 1, 10)]])),
        (
            "callRules",
            json!([{ "target": DUEL, "selectors": ["0x12345678"], "kinds": [0] }]),
        ),
        ("touchedParticipants", json!(2)),
        ("registeredParticipants", json!(0)),
    ]))
    .expect("client-signed transactions and per-contract call rules coexist");
    assert!(config.raw_transactions.is_some());
    assert_eq!(config.call_rules.expect("rules are kept").len(), 1);
    // A client-signed room decides for itself how many leaves a batch moves.
    assert_eq!(config.touched_participants, 2);
}
