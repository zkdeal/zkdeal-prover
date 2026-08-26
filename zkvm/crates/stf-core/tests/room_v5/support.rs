//! Shared v5 room scaffolding: the signing key every room transaction uses,
//! the deterministic block environment, and the opening room-local state.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use alloy_trie::EMPTY_ROOT_HASH;
use stf_types::{
    AccountState, BlockEnvV1, CompactAccountWitnessV4, CompactStateWitnessV4,
    CompactStorageWitnessV4,
};

pub(crate) const ROOM_ID: u64 = 7;
pub(crate) const GAS_LIMIT: u64 = 1_000_000;

/// Exit-queue storage layout shared by the fixture policy and the tests.
pub(crate) const EXIT_QUEUE_COUNT_SLOT: U256 = U256::ZERO;
pub(crate) const EXIT_QUEUE_RECORDS_BASE_SLOT: U256 = U256::from_limbs([0x100, 0, 0, 0]);
pub(crate) const EXIT_CALL_SELECTOR: [u8; 4] = [0xe4, 0x17, 0x00, 0x01];

/// Hand-assembled exit-queue runtime: every call appends one record.
///
/// ```text
/// i = SLOAD(count)                     ; count slot 0
/// s = 0x100 + 3*i
/// SSTORE(s,     calldataload(4))       ; recipient
/// SSTORE(s + 1, calldataload(0x24))    ; asset
/// SSTORE(s + 2, calldataload(0x44))    ; amount
/// SSTORE(count, i + 1)
/// ```
pub(crate) fn exit_queue_runtime_code() -> Bytes {
    Bytes::from(vec![
        0x5f, // PUSH0
        0x54, // SLOAD                      [i]
        0x80, // DUP1                       [i, i]
        0x60, 0x03, // PUSH1 3              [i, i, 3]
        0x02, // MUL                        [i, 3i]
        0x61, 0x01, 0x00, // PUSH2 0x0100   [i, 3i, 0x100]
        0x01, // ADD                        [i, s]
        0x60, 0x04, // PUSH1 4              [i, s, 4]
        0x35, // CALLDATALOAD               [i, s, recipient]
        0x81, // DUP2                       [i, s, recipient, s]
        0x55, // SSTORE                     [i, s]
        0x60, 0x24, // PUSH1 0x24           [i, s, 0x24]
        0x35, // CALLDATALOAD               [i, s, asset]
        0x81, // DUP2                       [i, s, asset, s]
        0x60, 0x01, // PUSH1 1              [i, s, asset, s, 1]
        0x01, // ADD                        [i, s, asset, s + 1]
        0x55, // SSTORE                     [i, s]
        0x60, 0x44, // PUSH1 0x44           [i, s, 0x44]
        0x35, // CALLDATALOAD               [i, s, amount]
        0x81, // DUP2                       [i, s, amount, s]
        0x60, 0x02, // PUSH1 2              [i, s, amount, s, 2]
        0x01, // ADD                        [i, s, amount, s + 2]
        0x55, // SSTORE                     [i, s]
        0x50, // POP                        [i]
        0x60, 0x01, // PUSH1 1              [i, 1]
        0x01, // ADD                        [i + 1]
        0x5f, // PUSH0                      [i + 1, 0]
        0x55, // SSTORE                     []
        0x00, // STOP
    ])
}

/// A hostile "queue" that overwrites the count slot with `calldataload(4)`,
/// used to prove the guest refuses a regressing exit cursor.
pub(crate) fn count_overwrite_runtime_code() -> Bytes {
    Bytes::from(vec![0x60, 0x04, 0x35, 0x5f, 0x55, 0x00])
}

pub(crate) fn signing_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes(&B256::with_last_byte(1).0.into()).unwrap()
}

pub(crate) fn sender() -> Address {
    let point = signing_key().verifying_key().to_encoded_point(false);
    Address::from_raw_public_key(&point.as_bytes()[1..])
}

pub(crate) fn sign_hash(hash: B256) -> Signature {
    let (sig, recovery) = signing_key()
        .sign_prehash_recoverable(hash.as_slice())
        .unwrap();
    let bytes = sig.to_bytes();
    Signature::new(
        U256::from_be_slice(&bytes[..32]),
        U256::from_be_slice(&bytes[32..]),
        recovery.is_y_odd(),
    )
}

pub(crate) fn sign_call(chain_id: u64, nonce: u64, target: Address, value: u64) -> Bytes {
    let mut input = vec![0x12, 0x34, 0x56, 0x78];
    input.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 120_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(target),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::from(input),
    };
    let signature = sign_hash(tx.signature_hash());
    Bytes::from(TxEnvelope::Eip1559(tx.into_signed(signature)).encoded_2718())
}

/// Sign one exit-queue call carrying the `(recipient, asset, amount)` record
/// words after the certified selector.
pub(crate) fn sign_exit_call(
    chain_id: u64,
    nonce: u64,
    target: Address,
    recipient: Address,
    asset: Address,
    amount: u64,
) -> Bytes {
    let mut input = EXIT_CALL_SELECTOR.to_vec();
    let mut recipient_word = [0u8; 32];
    recipient_word[12..].copy_from_slice(recipient.as_slice());
    input.extend_from_slice(&recipient_word);
    let mut asset_word = [0u8; 32];
    asset_word[12..].copy_from_slice(asset.as_slice());
    input.extend_from_slice(&asset_word);
    input.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 200_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(target),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::from(input),
    };
    let signature = sign_hash(tx.signature_hash());
    Bytes::from(TxEnvelope::Eip1559(tx.into_signed(signature)).encoded_2718())
}

pub(crate) fn env(number: u64, chain_id: u64) -> BlockEnvV1 {
    BlockEnvV1 {
        number,
        timestamp: 1_900_000_000 + number,
        gas_limit: GAS_LIMIT,
        coinbase: Address::ZERO,
        base_fee: U256::ZERO,
        prev_randao: B256::ZERO,
        difficulty: U256::ZERO,
        excess_blob_gas: 0,
        chain_id,
    }
}

pub(crate) fn account_state(contract: Address) -> Vec<(Address, AccountState)> {
    let mut state = vec![
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
            contract,
            AccountState {
                nonce: 1,
                balance: U256::ZERO,
                // calldata[4..36] -> storage[0]
                code: Bytes::from(vec![0x60, 0x04, 0x35, 0x5f, 0x55, 0x00]),
                storage: vec![
                    (
                        U256::from(10),
                        U256::from_be_bytes(B256::repeat_byte(0x77).0),
                    ),
                    (U256::from(11), U256::from(1)),
                    (U256::from(12), U256::from(1)),
                    (U256::from(13), U256::from(128)),
                ],
            },
        ),
    ];
    state.sort_by_key(|(address, _)| *address);
    state
}

pub(crate) fn compact_state(
    state: &[(Address, AccountState)],
    contract: Address,
) -> CompactStateWitnessV4 {
    let mut accounts = vec![CompactAccountWitnessV4 {
        address: Address::ZERO,
        exists: false,
        canonical_storage_root: EMPTY_ROOT_HASH,
        ..Default::default()
    }];
    accounts.extend(state.iter().map(|(address, account)| {
        let is_contract = *address == contract;
        CompactAccountWitnessV4 {
            address: *address,
            exists: true,
            nonce: account.nonce,
            balance: account.balance,
            code: account.code.clone(),
            canonical_storage_root: EMPTY_ROOT_HASH,
            account_proof: vec![],
            storage: if is_contract {
                let mut storage = vec![CompactStorageWitnessV4 {
                    slot: U256::ZERO,
                    value: U256::ZERO,
                    proof: vec![],
                }];
                storage.extend(account.storage.iter().map(|(slot, value)| {
                    CompactStorageWitnessV4 {
                        slot: *slot,
                        value: *value,
                        proof: vec![],
                    }
                }));
                storage
            } else {
                vec![]
            },
        }
    }));
    accounts.sort_by_key(|account| account.address);
    CompactStateWitnessV4 {
        canonical_state_root: B256::ZERO,
        accounts,
    }
}
