//! Single-block (journal v2) wire family: the borsh guest input, its expansion
//! into an [`StfInput`], and the fixed-length journal codec.

use alloy_primitives::{Address, Bytes, B256, U256};
use borsh::{BorshDeserialize, BorshSerialize};
use stf_types::{AccountState, BlockEnvV1, StfInput, StfJournal};

use crate::l2_chain_id;

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountWire {
    pub address: [u8; 20],
    pub nonce: u64,
    /// Big-endian 32-byte balance.
    pub balance: [u8; 32],
    pub code: Vec<u8>,
    /// (slot BE32, value BE32) pairs, non-zero values only, slot-sorted.
    pub storage: Vec<([u8; 32], [u8; 32])>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EnvWire {
    pub timestamp: u64,
    pub gas_limit: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HistoricalBlockHashWire {
    pub number: u64,
    pub hash: [u8; 32],
}

/// Complete guest input for one block. `borsh::to_vec` of this struct is what
/// the risc0 host writes into the ExecutorEnv and what the ligetron prover
/// passes as public hex arg 1.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StfInputWire {
    pub room_id: u64,
    pub block_number: u64,
    pub prev_state_root: [u8; 32],
    pub state: Vec<AccountWire>,
    pub raw_txs: Vec<Vec<u8>>,
    pub env: EnvWire,
    pub block_hashes: Vec<HistoricalBlockHashWire>,
}

impl StfInputWire {
    /// Expand into the full [`StfInput`] (fixed L2 env fields, derived chain id).
    pub fn to_input(&self) -> StfInput {
        StfInput {
            room_id: self.room_id,
            block_number: self.block_number,
            prev_state_root: B256::from(self.prev_state_root),
            state: self
                .state
                .iter()
                .map(|a| {
                    (
                        Address::from(a.address),
                        AccountState {
                            nonce: a.nonce,
                            balance: U256::from_be_bytes(a.balance),
                            code: Bytes::from(a.code.clone()),
                            storage: a
                                .storage
                                .iter()
                                .map(|(k, v)| (U256::from_be_bytes(*k), U256::from_be_bytes(*v)))
                                .collect(),
                        },
                    )
                })
                .collect(),
            raw_txs: self
                .raw_txs
                .iter()
                .map(|t| Bytes::from(t.clone()))
                .collect(),
            env: BlockEnvV1 {
                number: self.block_number,
                timestamp: self.env.timestamp,
                gas_limit: self.env.gas_limit,
                coinbase: Address::ZERO,
                base_fee: U256::ZERO,
                prev_randao: B256::ZERO,
                difficulty: U256::ZERO,
                excess_blob_gas: 0,
                chain_id: l2_chain_id(self.room_id),
            },
            block_hashes: self
                .block_hashes
                .iter()
                .map(|entry| stf_types::HistoricalBlockHash {
                    number: entry.number,
                    hash: B256::from(entry.hash),
                })
                .collect(),
        }
    }
}

/* ------------------------------------------------------------------ */
/* Borsh journal (guest output — 113 bytes)                            */
/* ------------------------------------------------------------------ */

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct JournalWire {
    pub v: u8,
    pub room_id: u64,
    pub block_number: u64,
    pub prev_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub tx_commitment: [u8; 32],
    /// journal v2: commitment to the executed block environment.
    pub env_hash: [u8; 32],
}

pub const JOURNAL_WIRE_LEN: usize = 1 + 8 + 8 + 32 + 32 + 32 + 32;

/// Canonical borsh bytes of a guest input.
pub fn input_to_borsh(w: &StfInputWire) -> Vec<u8> {
    borsh::to_vec(w).expect("input borsh encode cannot fail")
}

/// Decode borsh guest-input bytes (guest side).
pub fn input_from_borsh(bytes: &[u8]) -> Result<StfInputWire, String> {
    StfInputWire::try_from_slice(bytes).map_err(|e| format!("input borsh: {e}"))
}

pub fn journal_to_borsh(j: &StfJournal) -> Vec<u8> {
    borsh::to_vec(&JournalWire {
        v: j.v,
        room_id: j.room_id,
        block_number: j.block_number,
        prev_state_root: j.prev_state_root.0,
        post_state_root: j.post_state_root.0,
        tx_commitment: j.tx_commitment.0,
        env_hash: j.env_hash.0,
    })
    .expect("journal borsh encode cannot fail")
}

pub fn journal_from_borsh(bytes: &[u8]) -> Result<StfJournal, String> {
    if bytes.len() != JOURNAL_WIRE_LEN {
        return Err(format!(
            "journal wire length {} != {JOURNAL_WIRE_LEN}",
            bytes.len()
        ));
    }
    let w = JournalWire::try_from_slice(bytes).map_err(|e| format!("journal borsh: {e}"))?;
    Ok(StfJournal {
        v: w.v,
        room_id: w.room_id,
        block_number: w.block_number,
        prev_state_root: B256::from(w.prev_state_root),
        post_state_root: B256::from(w.post_state_root),
        tx_commitment: B256::from(w.tx_commitment),
        env_hash: B256::from(w.env_hash),
    })
}
