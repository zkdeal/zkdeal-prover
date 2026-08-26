//! Negative tests for the L2 execution profile the STF now ENFORCES rather
//! than forwards to revm.
//!
//! Each case is a witness that a receipt must NOT be producible for:
//! fee-bearing transactions, foreign/absent chain ids, cumulative gas over
//! the block limit, malformed authenticated `BLOCKHASH` history, and
//! transaction nonces forbidden by the active Ethereum fork.
//!
//! The positive counterpart is `parity.rs`: every fixture block produced by
//! the real engine still executes, which is what makes these refusals a
//! profile statement and not an incompatibility.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEip2930, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use stf_core::{execute_block, execute_block_full, StfError};
use stf_types::{block_env_hash, AccountState, BlockEnvV1, StfInput};

const ROOM_ID: u64 = 42;
const CHAIN_ID: u64 = 77_000_042;

/// Deterministic test signer: secp256k1 private key 0x01…01 (well-known).
fn signing_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes(&B256::with_last_byte(1).0.into()).unwrap()
}

fn sender() -> Address {
    let sk = signing_key();
    let uncompressed = sk.verifying_key().to_encoded_point(false);
    Address::from_raw_public_key(&uncompressed.as_bytes()[1..])
}

fn sign_hash(hash: B256) -> Signature {
    let (sig, recid) = signing_key()
        .sign_prehash_recoverable(hash.as_slice())
        .unwrap();
    let b = sig.to_bytes();
    Signature::new(
        U256::from_be_slice(&b[0..32]),
        U256::from_be_slice(&b[32..64]),
        recid.is_y_odd(),
    )
}

fn sign_legacy(tx: TxLegacy) -> Bytes {
    let sig = sign_hash(tx.signature_hash());
    Bytes::from(TxEnvelope::Legacy(tx.into_signed(sig)).encoded_2718())
}

fn sign_1559(tx: TxEip1559) -> Bytes {
    let sig = sign_hash(tx.signature_hash());
    Bytes::from(TxEnvelope::Eip1559(tx.into_signed(sig)).encoded_2718())
}

fn sign_2930(tx: TxEip2930) -> Bytes {
    let sig = sign_hash(tx.signature_hash());
    Bytes::from(TxEnvelope::Eip2930(tx.into_signed(sig)).encoded_2718())
}

fn env(gas_limit: u64) -> BlockEnvV1 {
    BlockEnvV1 {
        number: 1,
        timestamp: 1_000,
        gas_limit,
        coinbase: Address::ZERO,
        base_fee: U256::ZERO,
        prev_randao: B256::ZERO,
        difficulty: U256::ZERO,
        excess_blob_gas: 0,
        chain_id: CHAIN_ID,
    }
}

/// One funded EOA; `prev_state_root` is computed so the STF accepts the state.
fn input(raw_txs: Vec<Bytes>, gas_limit: u64) -> StfInput {
    let state = vec![(
        sender(),
        AccountState {
            nonce: 0,
            balance: U256::from(10u64).pow(U256::from(20u64)),
            code: Bytes::new(),
            storage: vec![],
        },
    )];
    let prev_state_root = stf_core::StateMap::from_input(&state).state_root();
    StfInput {
        room_id: ROOM_ID,
        block_number: 1,
        prev_state_root,
        state,
        raw_txs,
        env: env(gas_limit),
        block_hashes: Vec::new(),
    }
}

fn base_1559(gas_limit: u64, nonce: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(Address::repeat_byte(0x11)),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::new(),
    }
}

#[test]
fn baseline_free_gas_tx_executes() {
    let raw = sign_1559(base_1559(100_000, 0));
    let out = execute_block(&input(vec![raw], 30_000_000)).expect("free-gas tx must execute");
    assert_eq!(out.v, stf_types::JOURNAL_VERSION);
    assert_eq!(out.env_hash, block_env_hash(&env(30_000_000)));
}

#[test]
fn legacy_2930_and_1559_are_the_only_supported_envelopes() {
    let legacy = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce: 0,
        gas_price: 0,
        gas_limit: 100_000,
        to: TxKind::Call(Address::repeat_byte(0x11)),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    execute_block(&input(vec![sign_legacy(legacy)], 30_000_000))
        .expect("zero-fee EIP-155 legacy transaction executes");

    let eip2930 = TxEip2930 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_price: 0,
        gas_limit: 100_000,
        to: TxKind::Call(Address::repeat_byte(0x11)),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::new(),
    };
    execute_block(&input(vec![sign_2930(eip2930)], 30_000_000))
        .expect("zero-fee EIP-2930 transaction executes");

    let eip1559 = sign_1559(base_1559(100_000, 0));
    execute_block(&input(vec![eip1559], 30_000_000))
        .expect("zero-fee EIP-1559 transaction executes");
}

#[test]
fn rejects_blob_and_eip7702_type_bytes_before_payload_decode() {
    for tx_type in [0x03, 0x04] {
        let err = execute_block(&input(vec![Bytes::from(vec![tx_type])], 30_000_000)).unwrap_err();
        assert_eq!(err, StfError::UnsupportedTx(tx_type));
    }
}

#[test]
fn executes_osaka_clz_opcode() {
    let callee = Address::repeat_byte(0x33);
    let state = vec![
        (
            sender(),
            AccountState {
                nonce: 0,
                balance: U256::from(10u64).pow(U256::from(20u64)),
                code: Bytes::new(),
                storage: vec![],
            },
        ),
        (
            callee,
            AccountState {
                nonce: 1,
                balance: U256::ZERO,
                // PUSH1 1; CLZ (EIP-7939); PUSH0; SSTORE; STOP.
                code: Bytes::from(vec![0x60, 0x01, 0x1e, 0x5f, 0x55, 0x00]),
                storage: vec![],
            },
        ),
    ];
    let prev_state_root = stf_core::StateMap::from_input(&state).state_root();
    let mut tx = base_1559(100_000, 0);
    tx.to = TxKind::Call(callee);
    let out = execute_block_full(&StfInput {
        room_id: ROOM_ID,
        block_number: 1,
        prev_state_root,
        state,
        raw_txs: vec![sign_1559(tx)],
        env: env(30_000_000),
        block_hashes: Vec::new(),
    })
    .expect("Osaka CLZ must be enabled");
    assert_eq!(
        out.post_state.accounts[&callee].storage[&U256::ZERO],
        U256::from(255)
    );
}

#[test]
fn rejects_non_zero_max_fee() {
    let mut tx = base_1559(100_000, 0);
    tx.max_fee_per_gas = 1;
    let err = execute_block(&input(vec![sign_1559(tx)], 30_000_000)).unwrap_err();
    assert!(matches!(err, StfError::FeePolicy(_)), "got {err}");
}

#[test]
fn rejects_non_zero_priority_fee() {
    let mut tx = base_1559(100_000, 0);
    tx.max_priority_fee_per_gas = 1;
    let err = execute_block(&input(vec![sign_1559(tx)], 30_000_000)).unwrap_err();
    assert!(matches!(err, StfError::FeePolicy(_)), "got {err}");
}

#[test]
fn rejects_non_zero_legacy_gas_price() {
    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce: 0,
        gas_price: 1,
        gas_limit: 100_000,
        to: TxKind::Call(Address::repeat_byte(0x11)),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let err = execute_block(&input(vec![sign_legacy(tx)], 30_000_000)).unwrap_err();
    assert!(matches!(err, StfError::FeePolicy(_)), "got {err}");
}

#[test]
fn rejects_foreign_chain_id() {
    let mut tx = base_1559(100_000, 0);
    tx.chain_id = CHAIN_ID + 1;
    let err = execute_block(&input(vec![sign_1559(tx)], 30_000_000)).unwrap_err();
    assert!(
        matches!(
            err,
            StfError::ChainId {
                expected: CHAIN_ID,
                got: Some(_)
            }
        ),
        "got {err}"
    );
}

#[test]
fn rejects_pre_eip155_legacy_tx() {
    let tx = TxLegacy {
        chain_id: None,
        nonce: 0,
        gas_price: 0,
        gas_limit: 100_000,
        to: TxKind::Call(Address::repeat_byte(0x11)),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let err = execute_block(&input(vec![sign_legacy(tx)], 30_000_000)).unwrap_err();
    assert!(
        matches!(err, StfError::ChainId { got: None, .. }),
        "got {err}"
    );
}

#[test]
fn rejects_transaction_nonce_at_uint64_maximum() {
    let raw = sign_1559(base_1559(100_000, u64::MAX));
    let err = execute_block(&input(vec![raw], 30_000_000)).unwrap_err();
    assert!(
        matches!(err, StfError::TxDecode(ref message) if message.contains("uint64 maximum")),
        "got {err}"
    );
}

#[test]
fn rejects_block_exceeding_cumulative_gas_limit() {
    // Two individually valid transfers whose cumulative gas exceeds a tiny
    // block limit: individually fine, together outside the L2 profile.
    // Each tx: 21 000 gas used, per-tx limit under the block limit (so revm
    // admits both); together 42 000 > the 30 000 block budget.
    let raws = vec![
        sign_1559(base_1559(25_000, 0)),
        sign_1559(base_1559(25_000, 1)),
    ];
    let err = execute_block(&input(raws, 30_000)).unwrap_err();
    assert!(matches!(err, StfError::BlockGasLimit { .. }), "got {err}");
}

#[test]
fn executes_blockhash_from_authenticated_history() {
    let callee = Address::repeat_byte(0x22);
    let expected_hash = B256::repeat_byte(0x42);
    let state = vec![
        (
            sender(),
            AccountState {
                nonce: 0,
                balance: U256::from(10u64).pow(U256::from(20u64)),
                code: Bytes::new(),
                storage: vec![],
            },
        ),
        (
            callee,
            AccountState {
                nonce: 1,
                balance: U256::ZERO,
                // PUSH0 BLOCKHASH PUSH0 SSTORE STOP
                code: Bytes::from(vec![0x5f, 0x40, 0x5f, 0x55, 0x00]),
                storage: vec![],
            },
        ),
    ];
    let prev_state_root = stf_core::StateMap::from_input(&state).state_root();
    let mut tx = base_1559(100_000, 0);
    tx.to = TxKind::Call(callee);
    let inp = StfInput {
        room_id: ROOM_ID,
        block_number: 1,
        prev_state_root,
        state,
        raw_txs: vec![sign_1559(tx)],
        env: env(30_000_000),
        block_hashes: vec![stf_types::HistoricalBlockHash {
            number: 0,
            hash: expected_hash,
        }],
    };
    let out = execute_block_full(&inp).expect("authenticated BLOCKHASH must execute");
    assert_eq!(
        out.post_state.accounts[&callee].storage[&U256::ZERO],
        U256::from_be_bytes(expected_hash.0)
    );
    assert_eq!(out.proof_work.db.block_hash_reads, 1);
}

#[test]
fn rejects_malformed_blockhash_history() {
    let mut inp = input(Vec::new(), 30_000_000);
    inp.block_hashes = vec![
        stf_types::HistoricalBlockHash {
            number: 0,
            hash: B256::repeat_byte(1),
        },
        stf_types::HistoricalBlockHash {
            number: 0,
            hash: B256::repeat_byte(2),
        },
    ];
    assert!(matches!(
        execute_block(&inp),
        Err(StfError::BlockHashHistory(_))
    ));
}

#[test]
fn env_hash_changes_with_timestamp_and_gas_limit() {
    let a = env(30_000_000);
    let mut b = a.clone();
    b.timestamp += 1;
    let mut c = a.clone();
    c.gas_limit -= 1;
    assert_ne!(block_env_hash(&a), block_env_hash(&b));
    assert_ne!(block_env_hash(&a), block_env_hash(&c));
}

#[test]
fn empty_block_executes_and_commits_the_environment() {
    // Zero-transaction blocks are ordinary in a 500 ms-block room; they must
    // produce a normal journal (post root == pre root, empty-list commitment)
    // and never a degenerate/edge-case input for the guests.
    let inp = input(vec![], 30_000_000);
    let j = execute_block(&inp).expect("empty block must execute");
    assert_eq!(j.post_state_root, inp.prev_state_root);
    assert_eq!(j.env_hash, block_env_hash(&inp.env));
    assert_eq!(
        stf_wire::journal_to_borsh(&j).len(),
        stf_wire::JOURNAL_WIRE_LEN
    );
    // The borsh guest input for an empty block must round-trip too.
    let wire = stf_wire::StfInputWire {
        room_id: inp.room_id,
        block_number: inp.block_number,
        prev_state_root: inp.prev_state_root.0,
        state: vec![],
        raw_txs: vec![],
        env: stf_wire::EnvWire {
            timestamp: inp.env.timestamp,
            gas_limit: inp.env.gas_limit,
        },
        block_hashes: vec![],
    };
    let bytes = stf_wire::input_to_borsh(&wire);
    assert_eq!(stf_wire::input_from_borsh(&bytes).unwrap(), wire);
}
