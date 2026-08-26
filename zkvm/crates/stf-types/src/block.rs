//! Single-block execution input/output and the block environment shared by
//! every protocol version.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};

/// One account of the (tiny) full pre-state handed to the STF.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    /// Runtime bytecode (empty for EOAs / precompile placeholder accounts).
    #[serde(default)]
    pub code: Bytes,
    /// (slot, value) pairs; values must be non-zero (zero == absent).
    #[serde(default)]
    pub storage: Vec<(U256, U256)>,
}

/// Block environment V1 — mirrors exactly what the ethereumjs engine seals:
/// coinbase 0x0, baseFee 0, prevRandao 0, difficulty 0, gasLimit 30M,
/// excessBlobGas 0 (Cancun header field; blob txs are rejected in-room).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockEnvV1 {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub coinbase: Address,
    pub base_fee: U256,
    pub prev_randao: B256,
    pub difficulty: U256,
    pub excess_blob_gas: u64,
    pub chain_id: u64,
}

/// Canonical commitment to the COMPLETE block environment.
///
/// keccak256 over a fixed-width, fixed-order encoding (156 bytes):
///   u64 number | u64 timestamp | u64 gas_limit | 20B coinbase | 32B base_fee
///   | 32B prev_randao | 32B difficulty | u64 excess_blob_gas | u64 chain_id
///
/// Without this in the journal, a receipt proves only that SOME environment
/// maps (prev_root, txs) to post_root — two witnesses differing in
/// `TIMESTAMP`/`GASLIMIT` would make the identical public statement whenever
/// they happen to reach the same roots. Committing it makes the receipt name
/// the environment it executed, so timestamp/gas-limit-dependent contract
/// logic is attested rather than assumed. Mirrored byte-for-byte by
/// `blockEnvHash` in packages/zkvm/src/journal.ts.
pub fn block_env_hash(env: &BlockEnvV1) -> B256 {
    let mut buf = [0u8; 156];
    buf[0..8].copy_from_slice(&env.number.to_be_bytes());
    buf[8..16].copy_from_slice(&env.timestamp.to_be_bytes());
    buf[16..24].copy_from_slice(&env.gas_limit.to_be_bytes());
    buf[24..44].copy_from_slice(env.coinbase.as_slice());
    buf[44..76].copy_from_slice(&env.base_fee.to_be_bytes::<32>());
    buf[76..108].copy_from_slice(env.prev_randao.as_slice());
    buf[108..140].copy_from_slice(&env.difficulty.to_be_bytes::<32>());
    buf[140..148].copy_from_slice(&env.excess_blob_gas.to_be_bytes());
    buf[148..156].copy_from_slice(&env.chain_id.to_be_bytes());
    keccak256(buf)
}

/// Full input for one L2 block state transition.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StfInput {
    pub room_id: u64,
    pub block_number: u64,
    /// Expected MPT root of `state` (must match or execution refuses).
    pub prev_state_root: B256,
    /// Complete pre-state: every account that exists in the trie.
    pub state: Vec<(Address, AccountState)>,
    /// Raw signed txs exactly as committed by the sequencer (RLP / EIP-2718).
    pub raw_txs: Vec<Bytes>,
    pub env: BlockEnvV1,
    /// Authenticated L2 block hashes available to the EVM `BLOCKHASH`
    /// instruction. Entries must be strictly ordered, unique, and fall in the
    /// 256-block window immediately preceding `env.number`.
    #[serde(default)]
    pub block_hashes: Vec<HistoricalBlockHash>,
}

/// One block-number/hash pair from the room's proof-bound rolling history.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalBlockHash {
    pub number: u64,
    pub hash: B256,
}

/// Public journal the guest commits: binds room, block, roots and the raw
/// (unreduced) tx commitment keccak256(RLP([keccak256(rawTx)...])).
/// The protocol's field-level header value is `tx_commitment mod BN254_FIELD`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StfJournal {
    /// Journal layout version ([`crate::JOURNAL_VERSION`]).
    pub v: u8,
    pub room_id: u64,
    pub block_number: u64,
    pub prev_state_root: B256,
    pub post_state_root: B256,
    pub tx_commitment: B256,
    /// [`block_env_hash`] of the environment this block was executed under.
    pub env_hash: B256,
}
