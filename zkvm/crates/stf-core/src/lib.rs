//! zkdeal Rust STF (Spike S1): re-execute one L2 block with revm and
//! reproduce the EXACT ethereumjs MerkleStateManager state root via
//! alloy-trie, plus the raw tx commitment keccak256(RLP([keccak256(rawTx)..])).
//!
//! Execution config mirrors packages/l2-engine (see docs there):
//!   - SpecId::OSAKA, chainId = 77_000_000 + roomId % 1e6
//!   - free-gas policy: baseFee 0, gasPrice/maxFee 0 txs, coinbase 0x0
//!   - standard runTx semantics (nonce, balance >= value, EIP-3607 all ON)
//!   - reverted txs are still included (nonce bump only)
//!   - EIP-4788 beacon-root system call is a NO-OP (no code at the 4788
//!     address on this L2), so blocks only mutate state through txs.
//!
//! The crate is organised by statement: `block` drives revm for exactly one
//! block, and every proved statement — genesis, cold preparation, a v4 batch,
//! a long-lived v5 batch — is a witness-validation layer above it.

mod batch_v4;
mod block;
mod cold_room;
mod cold_state;
mod compact;
mod db;
mod error;
mod genesis;
mod opcode_gadgets;
mod opcode_manifest;
mod policy;
mod report;
mod room_v5;
mod settlement;
mod txenv;

pub use batch_v4::{
    execute_batch_v4, execute_batch_v4_interpreter_fallback, execute_batch_v4_with_report,
    execute_composed_batch_v4,
};
pub use block::{
    execute_block, execute_block_full, execute_block_full_v5_commitment,
    execute_block_full_with_prepared_runtime, execute_block_full_without_opcode_gadgets,
    tx_commitment_raw,
};
pub use cold_room::{execute_cold_room_v4, validate_composed_cold_link_v4};
pub use cold_state::cold_static_state_commitment_v4;
pub use db::{AccountRecord, DbAccessMetrics, PreparedCodeCacheReport, StateMap, StfDbError};
pub use error::StfError;
pub use genesis::execute_genesis_v4;
pub use opcode_gadgets::{top_50_motif_rank, OpcodeMotif, TOP_50_SOLIDITY_MOTIFS};
pub use opcode_manifest::{
    osaka_opcode_manifest, osaka_precompile_addresses, OpcodeManifestEntry, OpcodeStatus,
};
pub use policy::OsakaSemanticInspector;
pub use report::{
    BatchOutcome, BatchOutcomeV5, BatchProofWork, BlockOutcome, EvmProofWork, TransactionOutcome,
};
pub use room_v5::{
    derive_forced_rejection_reason_v5, execute_batch_v5, execute_batch_v5_with_report,
    execute_cold_template_v5,
};
pub use txenv::tx_env_from_raw;
