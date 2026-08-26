//! Request-parsing tests for the fixture shapes a card room introduced.
//!
//! These run locally (`cargo test -p zkdeal-r0`) and cover the boundary the
//! prover host is graded on: what a request is allowed to say, and what it is
//! refused for. The prepared-document regression itself is covered by the
//! golden template ids the caller pins.

use alloy_primitives::{keccak256, Address, U256};
use serde_json::{json, Value};

use super::config::{default_registry_slots, parse_fixture_config, DEFAULT_PARTICIPANT_ROOT_SLOT};
use super::contracts::{legacy_contracts, resolve_contracts, ROLE_DUEL};
use super::policy::{fixture_policy, PolicyInputs};
use super::signing::signer_address;
use super::state::{opening_state, registry_view};

const DUEL: &str = "0x0000000000000000000000000000000000000d01";
const TOKEN: &str = "0x0000000000000000000000000000000000000d05";

/// The minimal request every fixture shape starts from. `client_tests` builds
/// its client-signed rooms on the same base.
pub(super) fn request(extra: Vec<(&str, Value)>) -> String {
    let mut document = json!({
        "deploymentDomain": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "roomId": 1,
        "l1ChainId": 1,
        "l1InclusionDeadline": 100,
    });
    let object = document.as_object_mut().expect("request base is an object");
    for (key, value) in extra {
        object.insert(key.to_owned(), value);
    }
    document.to_string()
}

fn two_contracts() -> Value {
    json!([
        { "role": ROLE_DUEL, "address": DUEL, "runtimeCode": "0x600160005500" },
        { "role": "stakeToken", "address": TOKEN, "runtimeCode": "0x6002600055" },
    ])
}

fn registry_at_zero() -> Value {
    json!({ "contract": DUEL, "rootSlot": 0, "epochSlot": 1, "countSlot": 2, "capacitySlot": 3 })
}

pub(super) fn descriptor_room(extra: Vec<(&str, Value)>) -> String {
    let mut entries = vec![
        ("contracts", two_contracts()),
        ("participantRegistry", registry_at_zero()),
        ("residentAccounts", json!(4)),
    ];
    entries.extend(extra);
    request(entries)
}

#[test]
fn a_request_without_descriptors_keeps_the_historic_registry_layout() {
    let config = parse_fixture_config(&request(vec![])).expect("default request parses");
    assert!(config.contracts.is_none());
    assert!(config.call_rules.is_none());
    assert_eq!(config.registry.slots, default_registry_slots());
    assert_eq!(
        config.registry.slots.root,
        U256::from(DEFAULT_PARTICIPANT_ROOT_SLOT)
    );
    assert_eq!(config.signer_accounts, 1);
}

#[test]
fn descriptor_registry_preserves_an_explicit_zero_count_word() {
    let config = parse_fixture_config(&request(vec![
        (
            "contracts",
            json!([{
                "role": "generic",
                "address": DUEL,
                "runtimeCode": "0x600160005500",
                "initialStorage": [
                    { "slot": 0, "value": 1 },
                    { "slot": 1, "value": 1 },
                    { "slot": 2, "value": 0 },
                    { "slot": 3, "value": 128 }
                ]
            }]),
        ),
        ("participantRegistry", registry_at_zero()),
        ("registeredParticipants", json!(0)),
        ("residentAccounts", json!(2)),
    ]))
    .expect("descriptor request parses");
    let resolved = resolve_contracts(&config).expect("contracts resolve");
    let state = opening_state(
        &resolved.contracts,
        &[signer_address(0)],
        config.resident_accounts,
        None,
    );
    let (_, epoch, count, capacity) =
        registry_view(&state, resolved.registry, config.registry.slots)
            .expect("explicit zero count remains represented");
    assert_eq!((epoch, count, capacity), (1, 0, 128));
}

#[test]
fn prepare_accepts_an_explicit_zero_registry_count_word() {
    let raw = request(vec![
        ("authorizationMode", json!("validity-only")),
        ("activeSigners", json!(0)),
        (
            "contracts",
            json!([{
                "role": "generic",
                "address": DUEL,
                "runtimeCode": "0x600160005500",
                "initialStorage": [
                    { "slot": 0, "value": 1 },
                    { "slot": 1, "value": 1 },
                    { "slot": 2, "value": 0 },
                    { "slot": 3, "value": 128 }
                ]
            }]),
        ),
        ("participantRegistry", registry_at_zero()),
        ("registeredParticipants", json!(0)),
        ("residentAccounts", json!(2)),
        ("allowedSelectors", json!(["0x12345678"])),
        ("blockCalls", json!([["0x12345678"], ["0x12345678"]])),
    ]);
    super::prepare(&raw, [7; 32]).expect("zero registry count remains present during preparation");
}

#[test]
fn block_calls_keep_legacy_defaults_and_accept_explicit_signers_and_gas() {
    let config = parse_fixture_config(&request(vec![
        (
            "blockCalls",
            json!([
                [
                    "0x1234567801",
                    { "calldata": "0x1234567802", "signerIndex": 2, "gasLimit": 400000 }
                ],
                [
                    { "calldata": "0x1234567803", "signerIndex": 1, "gasLimit": 21000 }
                ]
            ]),
        ),
        ("residentAccounts", json!(4)),
    ]))
    .expect("mixed legacy and multi-signer calls parse");
    let blocks = config
        .custom_call_blocks
        .expect("block calls remain available to the block builder");
    assert_eq!(blocks[0][0].signer_index, 0);
    assert_eq!(blocks[0][0].gas_limit, 120_000);
    assert_eq!(blocks[0][1].signer_index, 2);
    assert_eq!(blocks[0][1].gas_limit, 400_000);
    assert_eq!(blocks[1][0].signer_index, 1);
    assert_eq!(blocks[1][0].gas_limit, 21_000);
    assert_eq!(config.signer_accounts, 3);
}

#[test]
fn block_call_signer_and_gas_bounds_fail_closed() {
    for (field, value, expected) in [
        ("signerIndex", json!(16), "between zero and fifteen"),
        ("gasLimit", json!(0), "between one and 5000000"),
        ("gasLimit", json!(5_000_001), "between one and 5000000"),
    ] {
        let mut call = json!({ "calldata": "0x12345678" });
        call.as_object_mut()
            .expect("call object")
            .insert(field.to_owned(), value);
        let error = parse_fixture_config(&request(vec![(
            "blockCalls",
            json!([[call], ["0x12345678"]]),
        )]))
        .expect_err("invalid multi-signer metadata is refused");
        assert!(format!("{error}").contains(expected), "{error}");
    }
}

#[test]
fn a_registry_slot_inside_the_generated_mirror_range_is_refused() {
    let error = parse_fixture_config(&request(vec![
        ("residentMirrorVariables", json!(6)),
        (
            "participantRegistry",
            json!({ "rootSlot": 0, "epochSlot": 1, "countSlot": 2, "capacitySlot": 3 }),
        ),
    ]))
    .expect_err("slots 0..3 collide with mirror variables 0..6");
    assert!(
        format!("{error}").contains("collides with the generated mirror-variable range"),
        "{error}"
    );
}

#[test]
fn the_registry_must_name_four_distinct_slots() {
    let error = parse_fixture_config(&descriptor_room(vec![(
        "participantRegistry",
        json!({ "contract": DUEL, "rootSlot": 0, "epochSlot": 0, "countSlot": 2, "capacitySlot": 3 }),
    )]))
    .expect_err("a repeated slot is not a registry");
    assert!(
        format!("{error}").contains("four distinct slots"),
        "{error}"
    );
}

#[test]
fn a_room_may_open_with_an_empty_participant_registry() {
    let config = parse_fixture_config(&descriptor_room(vec![("registeredParticipants", json!(0))]))
        .expect("an empty registry is a legal opening state");
    assert_eq!(config.registered_participants, 0);
}

#[test]
fn the_participant_merkle_sweep_still_needs_pre_registered_leaves() {
    let error = parse_fixture_config(&request(vec![
        ("workload", json!("participant-merkle")),
        ("registeredParticipants", json!(0)),
    ]))
    .expect_err("the generated runtime replaces leaves that must already exist");
    assert!(
        format!("{error}").contains("at least one pre-registered leaf"),
        "{error}"
    );
}

#[test]
fn multiple_touched_leaves_need_a_room_that_owns_its_transactions() {
    let error = parse_fixture_config(&request(vec![
        ("registeredParticipants", json!(4)),
        ("touchedParticipants", json!(2)),
    ]))
    .expect_err("a synthesized storage room touches exactly one leaf");
    assert!(
        format!("{error}").contains("only configurable for participant-merkle"),
        "{error}"
    );
    let config = parse_fixture_config(&descriptor_room(vec![
        ("registeredParticipants", json!(0)),
        ("touchedParticipants", json!(2)),
    ]))
    .expect("a descriptor room decides how many leaves a batch moves");
    assert_eq!(config.touched_participants, 2);
}

#[test]
fn descriptors_carry_their_own_runtime_and_storage() {
    let config = parse_fixture_config(&descriptor_room(vec![(
        "contracts",
        json!([
            { "role": ROLE_DUEL, "address": DUEL, "runtimeCode": "0x600160005500",
              "initialStorage": [{ "slot": 3, "value": 128 }] },
            { "role": "stakeToken", "address": TOKEN, "runtimeCode": "0x6002600055",
              "writable": false, "prefixBits": 256, "slotPrefix": "0" },
        ]),
    )]))
    .expect("descriptor room parses");
    let contracts = config.contracts.expect("descriptors are kept");
    assert_eq!(contracts.len(), 2);
    assert_ne!(contracts[0].runtime_code, contracts[1].runtime_code);
    assert_eq!(contracts[0].storage, vec![(U256::from(3), U256::from(128))]);
    assert!(!contracts[1].writable);
    assert_eq!(contracts[1].prefix_bits, 256);
    // Sorted ascending, as `policy/from_v5.rs` requires of code commitments.
    assert!(contracts[0].address < contracts[1].address);
    assert_eq!(config.touched_contracts, 2);
}

#[test]
fn descriptor_storage_outside_the_declared_namespace_is_refused() {
    let error = parse_fixture_config(&descriptor_room(vec![(
        "contracts",
        json!([
            { "role": ROLE_DUEL, "address": DUEL, "runtimeCode": "0x600160005500" },
            { "role": "stakeToken", "address": TOKEN, "runtimeCode": "0x6002600055",
              "prefixBits": 256, "slotPrefix": "0",
              "initialStorage": [{ "slot": 9, "value": 1 }] },
        ]),
    )]))
    .expect_err("slot 9 is outside a slot-zero-only namespace");
    assert!(
        format!("{error}").contains("outside the declared namespace"),
        "{error}"
    );
}

#[test]
fn touched_contracts_must_agree_with_the_descriptor_list() {
    let error = parse_fixture_config(&descriptor_room(vec![("touchedContracts", json!(5))]))
        .expect_err("a descriptor room states its own contract count");
    assert!(
        format!("{error}").contains("descriptor names 2 accounts"),
        "{error}"
    );
}

#[test]
fn call_rules_carry_caller_specific_staticcall_permissions() {
    let config = parse_fixture_config(&descriptor_room(vec![(
        "callRules",
        json!([
            { "caller": "active-member", "target": DUEL, "selectors": ["0xe22b07a8"], "kinds": [0] },
            { "caller": DUEL, "target": TOKEN, "selectors": ["0x23b872dd"], "kinds": [1] },
        ]),
    )]))
    .expect("per-contract call rules parse");
    let rules = config.call_rules.expect("rules are kept");
    assert_eq!(rules[0].caller, Address::ZERO, "active-member sentinel");
    assert_ne!(rules[1].caller, Address::ZERO);
    assert_eq!(rules[1].kinds, vec![1], "STATICCALL");
}

#[test]
fn duplicate_and_malformed_call_rules_are_refused() {
    let duplicate = parse_fixture_config(&descriptor_room(vec![(
        "callRules",
        json!([
            { "target": DUEL, "selectors": ["0xe22b07a8"] },
            { "target": DUEL, "selectors": ["0x23b872dd"] },
        ]),
    )]))
    .expect_err("the guest requires unique caller/target pairs");
    assert!(
        format!("{duplicate}").contains("duplicate caller/target"),
        "{duplicate}"
    );
    let kind = parse_fixture_config(&descriptor_room(vec![(
        "callRules",
        json!([{ "target": DUEL, "selectors": ["0xe22b07a8"], "kinds": [3] }]),
    )]))
    .expect_err("there are only three call kinds");
    assert!(format!("{kind}").contains("DELEGATECALL"), "{kind}");
}

#[test]
fn a_card_duel_request_must_bring_contracts_a_duel_object_and_call_rules() {
    let without_contracts = parse_fixture_config(&request(vec![("workload", json!("card-duel"))]))
        .expect_err("a duel room's code is never synthesized");
    assert!(
        format!("{without_contracts}").contains("requires a `contracts` descriptor"),
        "{without_contracts}"
    );
    let without_duel =
        parse_fixture_config(&descriptor_room(vec![("workload", json!("card-duel"))]))
            .expect_err("entryStake is not guessable");
    assert!(
        format!("{without_duel}").contains("`cardDuel` object"),
        "{without_duel}"
    );
    let without_rules = parse_fixture_config(&descriptor_room(vec![
        ("workload", json!("card-duel")),
        ("cardDuel", json!({ "entryStake": "1000" })),
    ]))
    .expect_err("the flat active-member rule set cannot reach the stake token");
    assert!(
        format!("{without_rules}").contains("requires `callRules`"),
        "{without_rules}"
    );
}

#[test]
fn a_card_duel_request_seats_two_distinct_signers() {
    let config = parse_fixture_config(&descriptor_room(vec![
        ("workload", json!("card-duel")),
        (
            "cardDuel",
            json!({ "entryStake": "1000", "fundedAmount": "4000" }),
        ),
        (
            "callRules",
            json!([{ "target": DUEL, "selectors": ["0xe22b07a8"] }]),
        ),
        ("registeredParticipants", json!(0)),
        ("touchedParticipants", json!(2)),
        ("residentAccounts", json!(6)),
    ]))
    .expect("a duel room parses");
    assert_eq!(config.signer_accounts, 2, "two seats, two keys");
    let card = config.card.expect("duel request is kept");
    assert_eq!(card.duelists.len(), 2);
    assert_ne!(card.duelists[0].signer_index, card.duelists[1].signer_index);
}

#[test]
fn a_duel_may_not_seat_one_key_twice() {
    let error = parse_fixture_config(&descriptor_room(vec![
        ("workload", json!("card-duel")),
        (
            "cardDuel",
            json!({
                "entryStake": "1000",
                "duelists": [{ "index": 0, "signerIndex": 0 }, { "index": 1, "signerIndex": 0 }],
            }),
        ),
        (
            "callRules",
            json!([{ "target": DUEL, "selectors": ["0xe22b07a8"] }]),
        ),
        ("touchedParticipants", json!(2)),
        ("registeredParticipants", json!(0)),
    ]))
    .expect_err("joinDuel rejects a second seat owned by the first");
    assert!(format!("{error}").contains("distinct signers"), "{error}");
}

#[test]
fn a_policy_pins_one_runtime_hash_per_address() {
    let config = parse_fixture_config(&descriptor_room(vec![])).expect("descriptor room parses");
    let contracts = config.contracts.expect("descriptors are kept");
    let policy = fixture_policy(
        &contracts,
        PolicyInputs {
            state_commitment: 0,
            registry_contract: contracts[0].address,
            registry_slots: config.registry.slots,
            call_rules: None,
            call_selectors: &[[0x12, 0x34, 0x56, 0x78]],
            max_transactions_per_block: 32,
            certified_imports: Vec::new(),
        },
    );
    assert_eq!(policy.code.len(), 2);
    assert_ne!(
        policy.code[0].runtime_code_hash,
        policy.code[1].runtime_code_hash
    );
    assert_eq!(
        policy.code[0].runtime_code_hash,
        keccak256(&contracts[0].runtime_code)
    );
    assert!(policy.code[0].address < policy.code[1].address);
    let registry = policy
        .participant_registry
        .expect("a v5 policy always binds a registry");
    assert_eq!(registry.root_slot, U256::ZERO);
    assert_eq!(registry.capacity_slot, U256::from(3));
}

#[test]
fn the_named_primary_contract_hosts_the_registry_whatever_it_sorts_to() {
    // `contractAddress` sorts last among six synthetic addresses in the legacy
    // shape; reading the sorted head would silently bind the registry, the L1
    // mirror destination and the whole-contract namespace to a synthetic one.
    let primary = Address::repeat_byte(0xff);
    let (contracts, registry) = legacy_contracts(
        6,
        Some(primary),
        &alloy_primitives::Bytes::from_static(&[0x00]),
    );
    assert_eq!(registry, primary);
    assert_eq!(contracts.len(), 6);
    let hosted = contracts
        .iter()
        .find(|contract| contract.address == primary)
        .expect("the primary contract is present");
    assert_eq!(hosted.prefix_bits, 0, "the registry host owns every slot");
    assert!(contracts
        .windows(2)
        .all(|pair| pair[0].address < pair[1].address));
}
