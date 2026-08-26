//! Fixture keys, signed transactions, the block environment and the approver
//! roster.
//!
//! Every key is derived from a fixed seed so a prepared room is reproducible.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use k256::ecdsa::SigningKey;
use stf_types::{BlockEnvV1, RosterMemberV5};

use super::config::GAS_LIMIT;

fn roster_signing_key(index: u64) -> SigningKey {
    let bytes = U256::from(index + 1).to_be_bytes::<32>();
    SigningKey::from_bytes(&bytes.into()).expect("fixed fixture key")
}

fn roster_address(index: u64) -> Address {
    let point = roster_signing_key(index)
        .verifying_key()
        .to_encoded_point(false);
    Address::from_raw_public_key(&point.as_bytes()[1..])
}

/// The fixture EOA a request selects by index. A duel needs two of them:
/// `CardDuelBase.joinDuel` reverts when the second seat's owner equals the
/// first's, so one shared key cannot represent two players.
pub(super) fn signer_address(index: u64) -> Address {
    roster_address(index)
}

fn sign_hash(hash: B256, signer_index: u64) -> Signature {
    let (signature, recovery) = roster_signing_key(signer_index)
        .sign_prehash_recoverable(hash.as_slice())
        .expect("fixed fixture signature");
    let bytes = signature.to_bytes();
    Signature::new(
        U256::from_be_slice(&bytes[..32]),
        U256::from_be_slice(&bytes[32..]),
        recovery.is_y_odd(),
    )
}

pub(super) fn sign_call(chain_id: u64, nonce: u64, target: Address, value: u64) -> Bytes {
    let mut input = vec![0x12, 0x34, 0x56, 0x78];
    input.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
    sign_calldata(chain_id, nonce, target, Bytes::from(input))
}

pub(super) fn sign_calldata(chain_id: u64, nonce: u64, target: Address, input: Bytes) -> Bytes {
    sign_calldata_as(chain_id, 0, nonce, target, input, 120_000)
}

/// A signed EIP-1559 call from fixture key `signer_index`. The gas limit is a
/// parameter because the generic 120,000 that suits a single SSTORE cannot pay
/// for a seven-deep keccak Merkle path plus an ERC-20 escrow transfer.
pub(super) fn sign_calldata_as(
    chain_id: u64,
    signer_index: u64,
    nonce: u64,
    target: Address,
    input: Bytes,
    gas_limit: u64,
) -> Bytes {
    sign_transaction(
        TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(target),
            value: U256::ZERO,
            access_list: Default::default(),
            input,
        },
        signer_index,
    )
}

/// Sign an arbitrary EIP-1559 transaction with fixture key `signer_index` and
/// return its EIP-2718 envelope -- the same wire shape a client-signed
/// `rawTransactions` entry carries.
pub(super) fn sign_transaction(tx: TxEip1559, signer_index: u64) -> Bytes {
    let signature = sign_hash(tx.signature_hash(), signer_index);
    Bytes::from(TxEnvelope::Eip1559(tx.into_signed(signature)).encoded_2718())
}

pub(super) fn sign_participant_update_call(
    chain_id: u64,
    nonce: u64,
    target: Address,
    index: u64,
    old_leaf: B256,
    new_leaf: B256,
    proof: &[B256],
) -> Bytes {
    let mut input = vec![0x12, 0x34, 0x56, 0x78];
    input.extend_from_slice(&U256::from(index).to_be_bytes::<32>());
    input.extend_from_slice(old_leaf.as_slice());
    input.extend_from_slice(new_leaf.as_slice());
    for sibling in proof {
        input.extend_from_slice(sibling.as_slice());
    }
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 500_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(target),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::from(input),
    };
    let signature = sign_hash(tx.signature_hash(), 0);
    Bytes::from(TxEnvelope::Eip1559(tx.into_signed(signature)).encoded_2718())
}

pub(super) fn env(number: u64, chain_id: u64) -> BlockEnvV1 {
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

pub(super) fn roster(active_signers: u64) -> Vec<RosterMemberV5> {
    (0..active_signers)
        .map(|index| RosterMemberV5 {
            index,
            member: roster_address(index),
            joined_epoch: 1,
        })
        .collect()
}
