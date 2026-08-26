//! Cross-language golden vectors for the guest's forced-rejection derivation.
//!
//! `derive_forced_rejection_reason_v5` is the public mirror of the in-guest
//! `forced_rejection_reason_v5`: given a raw L1 forced transaction, the certified
//! policy, the batch's authenticated caller set and the terminal room state, it
//! returns the deterministic rejection reason (1 undecodable, 2 policy, 3 sender)
//! or `None` when the batch could have carried the transaction. The TypeScript
//! node composes the same status-2 records, so these vectors pin the exact
//! (raw, reason, reasonHash) triples both stacks must agree on.
//!
//! Regenerate the checked-in JSON with:
//!   cargo test -p stf-core --test room_v5 emit_vectors -- --ignored

use std::collections::BTreeSet;
use std::path::PathBuf;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use k256::ecdsa::SigningKey;
use serde::Serialize;
use sha2::{Digest, Sha256};

use stf_core::{derive_forced_rejection_reason_v5, StateMap};
use stf_types::{
    execution_policy_hash_v5, forced_rejection_reason_hash_v5, room_chain_id_v5, AccountState,
    ExecutionPolicyV5, ExitAssetBindingV5,
};

use crate::support::{exit_queue_runtime_code, sender, ROOM_ID};
use crate::witness::{exit_queue, validity_only_batch};

const DEPLOYMENT: B256 = B256::repeat_byte(0x11);
/// Terminal nonce and balance of caller A: chosen so a nonce-4 tx mismatches and
/// a value-above-1000 tx is unaffordable, isolating the sender gate.
const TERMINAL_NONCE_A: u64 = 5;
const TERMINAL_BALANCE_A: u64 = 1_000;

/// keccak of the pinned reasons + raw bytes. The TypeScript mirror pins the same
/// value. Regenerate by running `emit_vectors` and copying the printed digest.
const DIGEST: &str = "0x5eed8ea7f2adb76ef68e70c2401340bdf4469ef66157f8bff0185120414ad5d4";

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/room_v5/vectors/forced-rejection-v5.json")
}

fn key_a() -> SigningKey {
    SigningKey::from_bytes(&B256::with_last_byte(1).0.into()).unwrap()
}

fn key_b() -> SigningKey {
    SigningKey::from_bytes(&B256::with_last_byte(2).0.into()).unwrap()
}

fn address_of(key: &SigningKey) -> Address {
    let point = key.verifying_key().to_encoded_point(false);
    Address::from_raw_public_key(&point.as_bytes()[1..])
}

fn caller_a() -> Address {
    // Identical to `support::sender()`; asserted below so the two never drift.
    address_of(&key_a())
}

fn caller_b() -> Address {
    address_of(&key_b())
}

fn contract() -> Address {
    Address::repeat_byte(0x44)
}

fn chain_id() -> u64 {
    room_chain_id_v5(DEPLOYMENT, ROOM_ID)
}

fn sign_with(key: &SigningKey, hash: B256) -> Signature {
    let (sig, recovery) = key.sign_prehash_recoverable(hash.as_slice()).unwrap();
    let bytes = sig.to_bytes();
    Signature::new(
        U256::from_be_slice(&bytes[..32]),
        U256::from_be_slice(&bytes[32..]),
        recovery.is_y_odd(),
    )
}

/// An admissible contract call: the certified selector followed by one word.
fn admissible_input() -> Vec<u8> {
    let mut input = vec![0x12, 0x34, 0x56, 0x78];
    input.extend_from_slice(&[0u8; 32]);
    input
}

/// Build a 1559 transaction body. `_key` is accepted only so call sites read as
/// `encode_1559(&a, eip1559(&a, ...))`, keeping the signer next to the body it
/// signs; the signature itself is applied by `encode_1559`.
#[allow(clippy::too_many_arguments)]
fn eip1559(
    _key: &SigningKey,
    chain: u64,
    nonce: u64,
    to: TxKind,
    value: U256,
    max_fee: u128,
    max_priority: u128,
    input: Vec<u8>,
) -> TxEip1559 {
    TxEip1559 {
        chain_id: chain,
        nonce,
        gas_limit: 120_000,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: max_priority,
        to,
        value,
        access_list: Default::default(),
        input: Bytes::from(input),
    }
}

fn encode_1559(key: &SigningKey, tx: TxEip1559) -> Bytes {
    let signature = sign_with(key, tx.signature_hash());
    Bytes::from(TxEnvelope::Eip1559(tx.into_signed(signature)).encoded_2718())
}

fn encode_legacy(key: &SigningKey, tx: TxLegacy) -> Bytes {
    let signature = sign_with(key, tx.signature_hash());
    Bytes::from(TxEnvelope::Legacy(tx.into_signed(signature)).encoded_2718())
}

/// The secp256k1 group order, used to flip a canonical low-S signature to the
/// malleable high-S form without changing the recovered signer.
fn secp256k1_order() -> U256 {
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        .parse()
        .unwrap()
}

fn encode_1559_high_s(key: &SigningKey, tx: TxEip1559) -> Bytes {
    let hash = tx.signature_hash();
    let (sig, recovery) = key.sign_prehash_recoverable(hash.as_slice()).unwrap();
    let bytes = sig.to_bytes();
    let r = U256::from_be_slice(&bytes[..32]);
    let s = U256::from_be_slice(&bytes[32..]);
    // (r, n - s, !parity) recovers the same public key as (r, s, parity).
    let flipped = Signature::new(r, secp256k1_order() - s, !recovery.is_y_odd());
    Bytes::from(TxEnvelope::Eip1559(tx.into_signed(flipped)).encoded_2718())
}

struct Case {
    name: &'static str,
    raw: Bytes,
    members: Vec<Address>,
}

fn case(name: &'static str, raw: Bytes, members: Vec<Address>) -> Case {
    Case { name, raw, members }
}

fn cases() -> Vec<Case> {
    let a = key_a();
    let b = key_b();
    let chain = chain_id();
    let members_a = vec![caller_a()];
    let members_b = vec![caller_b()];
    let contract = TxKind::Call(contract());

    vec![
        // ---- reason 1: the raw transaction is not a room transaction at all ----
        case(
            "blob_envelope_prefix",
            Bytes::from(vec![0x03, 0x01, 0x02]),
            members_a.clone(),
        ),
        case(
            "eip7702_envelope_prefix",
            Bytes::from(vec![0x04, 0x01, 0x02]),
            members_a.clone(),
        ),
        case(
            "unknown_type_byte_0x05",
            Bytes::from(vec![0x05, 0x01, 0x02]),
            members_a.clone(),
        ),
        case(
            "malformed_legacy_rlp",
            Bytes::from(vec![0xc0]),
            members_a.clone(),
        ),
        case(
            "pre_eip155_legacy_v27",
            encode_legacy(
                &a,
                TxLegacy {
                    chain_id: None,
                    nonce: TERMINAL_NONCE_A,
                    gas_price: 0,
                    gas_limit: 120_000,
                    to: contract,
                    value: U256::ZERO,
                    input: Bytes::from(admissible_input()),
                },
            ),
            members_a.clone(),
        ),
        case(
            "wrong_chain_id_1559",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain + 1,
                    TERMINAL_NONCE_A,
                    contract,
                    U256::ZERO,
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        case(
            "fee_bearing_1559_max_fee",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    contract,
                    U256::ZERO,
                    1,
                    0,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        case(
            "nonzero_priority_fee_1559",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    contract,
                    U256::ZERO,
                    0,
                    1,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        case(
            "legacy_gas_price_nonzero",
            encode_legacy(
                &a,
                TxLegacy {
                    chain_id: Some(chain),
                    nonce: TERMINAL_NONCE_A,
                    gas_price: 1,
                    gas_limit: 120_000,
                    to: contract,
                    value: U256::ZERO,
                    input: Bytes::from(admissible_input()),
                },
            ),
            members_a.clone(),
        ),
        case(
            "nonce_equals_u64_max",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    u64::MAX,
                    contract,
                    U256::ZERO,
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        case(
            "trailing_bytes_after_valid_envelope",
            {
                let mut raw = encode_1559(
                    &a,
                    eip1559(
                        &a,
                        chain,
                        TERMINAL_NONCE_A,
                        contract,
                        U256::ZERO,
                        0,
                        0,
                        admissible_input(),
                    ),
                )
                .to_vec();
                raw.push(0x00);
                Bytes::from(raw)
            },
            members_a.clone(),
        ),
        case(
            "high_s_signature",
            encode_1559_high_s(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    contract,
                    U256::ZERO,
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        // ---- reason 2: decodes, but the root call is outside the policy ----
        case(
            "contract_creation",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    TxKind::Create,
                    U256::ZERO,
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        case(
            "target_outside_call_rules",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    TxKind::Call(Address::repeat_byte(0x99)),
                    U256::ZERO,
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        case(
            "allowed_target_calldata_below_four_bytes",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    contract,
                    U256::ZERO,
                    0,
                    0,
                    vec![0x12, 0x34, 0x56],
                ),
            ),
            members_a.clone(),
        ),
        case(
            "unknown_selector",
            encode_1559(
                &a,
                eip1559(&a, chain, TERMINAL_NONCE_A, contract, U256::ZERO, 0, 0, {
                    let mut input = vec![0xde, 0xad, 0xbe, 0xef];
                    input.extend_from_slice(&[0u8; 32]);
                    input
                }),
            ),
            members_a.clone(),
        ),
        case(
            "sentinel_rule_caller_not_active_member",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    contract,
                    U256::ZERO,
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_b.clone(),
        ),
        // ---- reason 3: admissible, but the terminal sender cannot execute it ----
        case(
            "sender_nonce_mismatch",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A - 1,
                    contract,
                    U256::ZERO,
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        case(
            "sender_balance_below_value",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    contract,
                    U256::from(TERMINAL_BALANCE_A + 1),
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_a.clone(),
        ),
        case(
            "absent_sender_nonce_one",
            encode_1559(
                &b,
                eip1559(&b, chain, 1, contract, U256::ZERO, 0, 0, admissible_input()),
            ),
            members_b.clone(),
        ),
        // ---- null: the batch could have carried it ----
        case(
            "includable_member_exact_nonce",
            encode_1559(
                &a,
                eip1559(
                    &a,
                    chain,
                    TERMINAL_NONCE_A,
                    contract,
                    U256::ZERO,
                    0,
                    0,
                    admissible_input(),
                ),
            ),
            members_a,
        ),
        case(
            "includable_absent_sender_nonce_zero",
            encode_1559(
                &b,
                eip1559(&b, chain, 0, contract, U256::ZERO, 0, 0, admissible_input()),
            ),
            members_b,
        ),
    ]
}

fn terminal_accounts() -> Vec<(Address, AccountState)> {
    vec![
        (
            caller_a(),
            AccountState {
                nonce: TERMINAL_NONCE_A,
                balance: U256::from(TERMINAL_BALANCE_A),
                code: Bytes::new(),
                storage: vec![],
            },
        ),
        (
            contract(),
            AccountState {
                nonce: 1,
                balance: U256::ZERO,
                code: Bytes::from(vec![0x60, 0x04, 0x35, 0x5f, 0x55, 0x00]),
                storage: vec![],
            },
        ),
        (
            exit_queue(),
            AccountState {
                nonce: 1,
                balance: U256::ZERO,
                code: exit_queue_runtime_code(),
                storage: vec![],
            },
        ),
    ]
}

fn fixture_policy() -> ExecutionPolicyV5 {
    validity_only_batch().policy
}

struct Derived {
    reason: Option<u8>,
    reason_hash: B256,
}

fn derive_all() -> (ExecutionPolicyV5, B256, Vec<Case>, Vec<Derived>) {
    let policy = fixture_policy();
    let policy_hash = execution_policy_hash_v5(&policy);
    let terminal = StateMap::from_input(&terminal_accounts());
    let cases = cases();
    let derived = cases
        .iter()
        .map(|case| {
            let members: BTreeSet<Address> = case.members.iter().copied().collect();
            let reason = derive_forced_rejection_reason_v5(
                case.raw.as_ref(),
                DEPLOYMENT,
                ROOM_ID,
                &policy,
                policy_hash,
                members,
                &terminal,
            )
            .expect("the fixture policy builds against the terminal state");
            let reason_hash = match reason {
                Some(reason) => {
                    forced_rejection_reason_hash_v5(keccak256(case.raw.as_ref()), reason)
                }
                None => B256::ZERO,
            };
            Derived {
                reason,
                reason_hash,
            }
        })
        .collect::<Vec<_>>();
    (policy, policy_hash, cases, derived)
}

fn digest(cases: &[Case], derived: &[Derived]) -> B256 {
    let mut hasher = Sha256::new();
    for (case, out) in cases.iter().zip(derived) {
        hasher.update(case.raw.as_ref());
        hasher.update([out.reason.unwrap_or(0)]);
        hasher.update(out.reason_hash.as_slice());
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    B256::from(bytes)
}

#[derive(Serialize)]
struct TerminalAccountJson {
    address: Address,
    nonce: u64,
    balance: U256,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseJson {
    name: String,
    raw: Bytes,
    active_members: Vec<Address>,
    reason: Option<u8>,
    reason_hash: B256,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VectorsJson {
    schema_version: u32,
    source: String,
    note: String,
    deployment_domain: B256,
    room_id: u64,
    chain_id: String,
    policy: ExecutionPolicyV5,
    policy_hash: B256,
    caller_a: Address,
    caller_b: Address,
    terminal: Vec<TerminalAccountJson>,
    digest: B256,
    cases: Vec<CaseJson>,
}

fn document() -> VectorsJson {
    let (policy, policy_hash, cases, derived) = derive_all();
    let digest = digest(&cases, &derived);
    let cases_json = cases
        .iter()
        .zip(&derived)
        .map(|(case, out)| CaseJson {
            name: case.name.to_string(),
            raw: case.raw.clone(),
            active_members: case.members.clone(),
            reason: out.reason,
            reason_hash: out.reason_hash,
        })
        .collect::<Vec<_>>();
    VectorsJson {
        schema_version: 1,
        source: "stf-core/tests/room_v5/forced_vectors.rs (emit_vectors)".to_string(),
        note: "digest = sha256( for each case in order: raw ++ [reasonByte] ++ reasonHash ), \
               reasonByte = 0 for null"
            .to_string(),
        deployment_domain: DEPLOYMENT,
        room_id: ROOM_ID,
        chain_id: chain_id().to_string(),
        policy,
        policy_hash,
        caller_a: caller_a(),
        caller_b: caller_b(),
        terminal: vec![TerminalAccountJson {
            address: caller_a(),
            nonce: TERMINAL_NONCE_A,
            balance: U256::from(TERMINAL_BALANCE_A),
        }],
        digest,
        cases: cases_json,
    }
}

#[test]
#[ignore]
fn emit_vectors() {
    let document = document();
    let json = serde_json::to_string_pretty(&document).expect("vectors serialize");
    let path = vectors_path();
    std::fs::create_dir_all(path.parent().expect("vectors dir has a parent"))
        .expect("create vectors dir");
    std::fs::write(&path, format!("{json}\n")).expect("write forced-rejection vectors");
    println!("forced-rejection digest = {}", document.digest);
}

#[test]
fn vectors_match_the_derived_reasons() {
    assert_eq!(
        caller_a(),
        sender(),
        "caller A must equal the fixture signer"
    );

    let (_, _, cases, derived) = derive_all();

    // Human-readable spot checks for the unambiguous gates.
    let reason_of = |name: &str| -> Option<u8> {
        let index = cases.iter().position(|case| case.name == name).unwrap();
        derived[index].reason
    };
    assert_eq!(reason_of("blob_envelope_prefix"), Some(1));
    assert_eq!(reason_of("unknown_type_byte_0x05"), Some(1));
    assert_eq!(reason_of("pre_eip155_legacy_v27"), Some(1));
    assert_eq!(reason_of("wrong_chain_id_1559"), Some(1));
    assert_eq!(reason_of("fee_bearing_1559_max_fee"), Some(1));
    assert_eq!(reason_of("nonce_equals_u64_max"), Some(1));
    // Trailing garbage after a valid envelope is undecodable on BOTH stacks:
    // the guest now rejects the unconsumed tail rather than aliasing the tx.
    assert_eq!(
        reason_of("trailing_bytes_after_valid_envelope"),
        Some(1)
    );
    assert_eq!(reason_of("contract_creation"), Some(2));
    assert_eq!(reason_of("target_outside_call_rules"), Some(2));
    assert_eq!(
        reason_of("allowed_target_calldata_below_four_bytes"),
        Some(2)
    );
    assert_eq!(reason_of("unknown_selector"), Some(2));
    assert_eq!(reason_of("sentinel_rule_caller_not_active_member"), Some(2));
    assert_eq!(reason_of("sender_nonce_mismatch"), Some(3));
    assert_eq!(reason_of("sender_balance_below_value"), Some(3));
    assert_eq!(reason_of("absent_sender_nonce_one"), Some(3));
    assert_eq!(reason_of("includable_member_exact_nonce"), None);
    assert_eq!(reason_of("includable_absent_sender_nonce_zero"), None);

    // The full set (including the alloy-framing pins) is fixed by the digest.
    assert_eq!(
        digest(&cases, &derived).to_string(),
        DIGEST,
        "forced-rejection vector digest drifted"
    );

    // Byte-equality with the checked-in consumer copy.
    let json = serde_json::to_string_pretty(&document()).expect("vectors serialize");
    let on_disk = std::fs::read_to_string(vectors_path()).expect(
        "run `cargo test -p stf-core --test room_v5 emit_vectors -- --ignored` to generate the \
         checked-in copy",
    );
    assert_eq!(
        on_disk,
        format!("{json}\n"),
        "checked-in forced-rejection vectors differ from the emitter output"
    );
}

#[test]
fn oversized_exit_asset_list_is_refused_by_the_certified_policy() {
    // The ExitBindingV5.assets vector is bounded (MAX_EXIT_ASSETS_V5). A policy
    // over that bound is refused when the certified policy is built, before any
    // raw transaction is inspected.
    let mut policy = fixture_policy();
    let binding = policy
        .exit
        .as_mut()
        .expect("fixture policy has an exit binding");
    binding.assets = (0..300u64)
        .map(|index| ExitAssetBindingV5 {
            asset: Address::from_word(B256::from(U256::from(index + 1))),
            kind: 1,
            token: contract(),
            balance_slot: U256::from(0x50),
        })
        .collect();
    let policy_hash = execution_policy_hash_v5(&policy);
    let terminal = StateMap::from_input(&terminal_accounts());
    let error = derive_forced_rejection_reason_v5(
        &[0x03, 0x01, 0x02],
        DEPLOYMENT,
        ROOM_ID,
        &policy,
        policy_hash,
        [caller_a()].into_iter().collect(),
        &terminal,
    )
    .expect_err("an over-cap exit asset list is refused");
    assert!(
        format!("{error}").contains("MAX_EXIT_ASSETS_V5"),
        "unexpected error: {error}"
    );
}
