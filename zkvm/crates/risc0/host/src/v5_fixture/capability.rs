//! The room-capability tokens this binary reports.
//!
//! The list is DERIVED, never declared: each token is emitted only if this
//! binary's own request parser accepts the canonical request shape that
//! capability implies, and produces the parsed result the capability promises.
//! A partially-implemented host therefore reports a partial list and the caller
//! refuses with a precise message, instead of preparing a room the prover
//! cannot actually express.

use serde_json::{json, Value};

use super::config::{parse_fixture_config, FixtureConfig, CARD_DUEL_WORKLOAD};

pub(super) const TOKEN_CARD_DUEL_WORKLOAD: &str = "v5.workload.card-duel";
pub(super) const TOKEN_PER_CONTRACT_RUNTIME: &str = "v5.coldState.perContractRuntime";
pub(super) const TOKEN_CONFIGURABLE_SLOTS: &str = "v5.participantRegistry.configurableSlots";
pub(super) const TOKEN_EMPTY_OPEN: &str = "v5.participantRegistry.emptyOpen";
pub(super) const TOKEN_MULTI_TOUCH: &str = "v5.participants.multiTouch";
pub(super) const TOKEN_PER_CONTRACT_CALL_RULES: &str = "v5.policy.perContractCallRules";
pub(super) const TOKEN_MULTI_SIGNER_BLOCK_CALLS: &str = "v5.blockCalls.multiSigner";

const DUEL: &str = "0x0000000000000000000000000000000000000d01";
const ADAPTER: &str = "0x0000000000000000000000000000000000000a02";
const DECK: &str = "0x0000000000000000000000000000000000000d03";
const HAND: &str = "0x0000000000000000000000000000000000000d04";
const TOKEN: &str = "0x0000000000000000000000000000000000000d05";

fn base() -> Value {
    json!({
        "deploymentDomain": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "roomId": 1,
        "l1ChainId": 1,
        "l1InclusionDeadline": 100,
    })
}

fn with(entries: Vec<(&str, Value)>) -> String {
    let mut document = base();
    let object = document.as_object_mut().expect("probe base is an object");
    for (key, value) in entries {
        object.insert(key.to_owned(), value);
    }
    document.to_string()
}

fn contract(role: &str, address: &str, code: &str) -> Value {
    json!({ "role": role, "address": address, "runtimeCode": code })
}

fn registry_at_zero() -> Value {
    json!({
        "contract": DUEL,
        "rootSlot": 0,
        "epochSlot": 1,
        "countSlot": 2,
        "capacitySlot": 3,
    })
}

fn duel_contracts() -> Value {
    json!([
        contract("duel", DUEL, "0x600160005500"),
        contract("adapter", ADAPTER, "0x6002600055"),
        contract("deckVerifier", DECK, "0x6003600055"),
        contract("handVerifier", HAND, "0x6004600055"),
        contract("stakeToken", TOKEN, "0x6005600055"),
    ])
}

fn duel_call_rules() -> Value {
    json!([
        { "caller": "active-member", "target": DUEL, "selectors": ["0xe22b07a8"], "kinds": [0] },
        { "caller": DUEL, "target": TOKEN, "selectors": ["0x23b872dd"], "kinds": [0] },
        { "caller": DUEL, "target": ADAPTER, "selectors": ["0x0f28c97d"], "kinds": [1] },
        { "caller": ADAPTER, "target": DECK, "selectors": ["0x11479fea"], "kinds": [1] },
        { "caller": ADAPTER, "target": HAND, "selectors": ["0x22589aba"], "kinds": [1] },
    ])
}

fn probe(entries: Vec<(&str, Value)>) -> Option<FixtureConfig> {
    parse_fixture_config(&with(entries)).ok()
}

/// A two-contract room whose accounts hold DIFFERENT runtime code, each with
/// its own opening storage.
fn per_contract_runtime() -> bool {
    let Some(config) = probe(vec![
        (
            "contracts",
            json!([
                contract("duel", DUEL, "0x600160005500"),
                json!({
                    "role": "stakeToken",
                    "address": TOKEN,
                    "runtimeCode": "0x6002600055",
                    "initialStorage": [{ "slot": 0, "value": 7 }],
                }),
            ]),
        ),
        ("participantRegistry", registry_at_zero()),
        ("residentAccounts", json!(4)),
    ]) else {
        return false;
    };
    let Some(contracts) = config.contracts.as_ref() else {
        return false;
    };
    contracts.len() == 2
        && contracts[0].runtime_code != contracts[1].runtime_code
        && contracts.iter().any(|entry| !entry.storage.is_empty())
}

/// The registry may live at slots 0..3, where `MerkleParticipants` puts it.
fn configurable_slots() -> bool {
    let Some(config) = probe(vec![
        ("contracts", duel_contracts()),
        ("participantRegistry", registry_at_zero()),
        ("residentAccounts", json!(8)),
    ]) else {
        return false;
    };
    let slots = config.registry.slots;
    config.registry.contract.is_some()
        && slots.root.is_zero()
        && slots.epoch == alloy_primitives::U256::from(1)
        && slots.count == alloy_primitives::U256::from(2)
        && slots.capacity == alloy_primitives::U256::from(3)
}

/// A room may open with an empty participant registry.
fn empty_open() -> bool {
    probe(vec![
        ("contracts", duel_contracts()),
        ("participantRegistry", registry_at_zero()),
        ("residentAccounts", json!(8)),
        ("registeredParticipants", json!(0)),
    ])
    .is_some_and(|config| config.registered_participants == 0)
}

/// More than one participant leaf may move in a batch outside the
/// participant-merkle sweep.
fn multi_touch() -> bool {
    probe(vec![
        ("contracts", duel_contracts()),
        ("participantRegistry", registry_at_zero()),
        ("residentAccounts", json!(8)),
        ("registeredParticipants", json!(0)),
        ("touchedParticipants", json!(2)),
    ])
    .is_some_and(|config| config.touched_participants == 2)
}

/// Caller-specific rules, including contract-to-contract STATICCALL.
fn per_contract_call_rules() -> bool {
    let Some(config) = probe(vec![
        ("contracts", duel_contracts()),
        ("participantRegistry", registry_at_zero()),
        ("residentAccounts", json!(8)),
        ("callRules", duel_call_rules()),
    ]) else {
        return false;
    };
    let Some(rules) = config.call_rules.as_ref() else {
        return false;
    };
    rules
        .iter()
        .any(|rule| rule.caller != alloy_primitives::Address::ZERO && rule.kinds.contains(&1))
}

/// Host-signed block calls may select independent fixture keys and gas limits.
fn multi_signer_block_calls() -> bool {
    probe(vec![
        (
            "blockCalls",
            json!([
                [
                    { "calldata": "0x12345678", "signerIndex": 0, "gasLimit": 200000 },
                    { "calldata": "0x12345678", "signerIndex": 2, "gasLimit": 300000 }
                ],
                [
                    { "calldata": "0x12345678", "signerIndex": 1, "gasLimit": 400000 }
                ]
            ]),
        ),
        ("signerAccounts", json!(3)),
        ("residentAccounts", json!(4)),
    ])
    .is_some_and(|config| {
        config.signer_accounts == 3
            && config.custom_call_blocks.as_ref().is_some_and(|blocks| {
                blocks[0][1].signer_index == 2 && blocks[0][1].gas_limit == 300_000
            })
    })
}

/// The whole card room: five roles, registry at slot zero, an empty registry,
/// two touched leaves, caller-specific rules and a duel request.
fn card_duel_workload() -> bool {
    probe(vec![
        ("workload", json!(CARD_DUEL_WORKLOAD)),
        ("contracts", duel_contracts()),
        ("participantRegistry", registry_at_zero()),
        ("callRules", duel_call_rules()),
        ("cardDuel", json!({ "entryStake": "1000" })),
        ("authorizationMode", json!("validity-only")),
        ("activeSigners", json!(0)),
        ("registeredParticipants", json!(0)),
        ("touchedParticipants", json!(2)),
        ("residentAccounts", json!(9)),
    ])
    .is_some_and(|config| config.workload == CARD_DUEL_WORKLOAD && config.card.is_some())
}

/// Tokens this binary can honestly claim, in a stable order.
pub fn room_capabilities() -> Vec<&'static str> {
    let mut tokens = Vec::new();
    if per_contract_runtime() {
        tokens.push(TOKEN_PER_CONTRACT_RUNTIME);
    }
    if configurable_slots() {
        tokens.push(TOKEN_CONFIGURABLE_SLOTS);
    }
    if empty_open() {
        tokens.push(TOKEN_EMPTY_OPEN);
    }
    if multi_touch() {
        tokens.push(TOKEN_MULTI_TOUCH);
    }
    if per_contract_call_rules() {
        tokens.push(TOKEN_PER_CONTRACT_CALL_RULES);
    }
    if multi_signer_block_calls() {
        tokens.push(TOKEN_MULTI_SIGNER_BLOCK_CALLS);
    }
    // The workload token is last on purpose: a duel room needs every capability
    // above it, so it is the last thing that can become true.
    if card_duel_workload() {
        tokens.push(TOKEN_CARD_DUEL_WORKLOAD);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_probe_passes() {
        assert_eq!(
            room_capabilities(),
            vec![
                TOKEN_PER_CONTRACT_RUNTIME,
                TOKEN_CONFIGURABLE_SLOTS,
                TOKEN_EMPTY_OPEN,
                TOKEN_MULTI_TOUCH,
                TOKEN_PER_CONTRACT_CALL_RULES,
                TOKEN_MULTI_SIGNER_BLOCK_CALLS,
                TOKEN_CARD_DUEL_WORKLOAD,
            ]
        );
    }
}
