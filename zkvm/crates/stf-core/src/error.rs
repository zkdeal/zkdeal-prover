//! The single error taxonomy every STF entry point reports through.

use alloy_primitives::B256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StfError {
    /// Rebuilt pre-state root does not match `input.prev_state_root`.
    PreRootMismatch {
        expected: B256,
        computed: B256,
    },
    /// Raw tx failed to decode (RLP / EIP-2718) or signature recovery failed.
    TxDecode(String),
    /// Tx type not accepted in-room (blob / 7702).
    UnsupportedTx(u8),
    /// revm rejected the tx (invalid nonce/balance/gas...). The sequencer
    /// only seals valid txs, so this means non-parity or a bad input.
    TxExecution(String),
    /// The rolling block-hash witness is malformed or outside the EVM window.
    BlockHashHistory(String),
    /// Tx carries a non-zero fee field; the free-gas L2 admits none.
    FeePolicy(String),
    /// Tx chain id is absent (pre-EIP-155) or not this room's L2 chain.
    ChainId {
        expected: u64,
        got: Option<u64>,
    },
    /// Cumulative gas across the block exceeded the block gas limit.
    BlockGasLimit {
        used: u64,
        limit: u64,
    },
    /// V4 batches contain one to four contiguous blocks.
    InvalidBatch(String),
    CompactWitness(String),
    CertifiedPolicy(String),
    Settlement(String),
    GenesisAnchor(String),
    ColdPreparation(String),
    LongLivedRoom(String),
}

impl core::fmt::Display for StfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StfError::PreRootMismatch { expected, computed } => {
                write!(
                    f,
                    "pre-state root mismatch: expected {expected}, computed {computed}"
                )
            }
            StfError::TxDecode(e) => write!(f, "tx decode failed: {e}"),
            StfError::UnsupportedTx(t) => write!(f, "unsupported tx type {t}"),
            StfError::TxExecution(e) => write!(f, "tx execution failed: {e}"),
            StfError::BlockHashHistory(e) => write!(f, "invalid block-hash history: {e}"),
            StfError::FeePolicy(e) => write!(f, "free-gas policy violated: {e}"),
            StfError::ChainId { expected, got } => match got {
                Some(g) => write!(f, "tx chain id {g} != room chain id {expected}"),
                None => write!(
                    f,
                    "tx has no chain id (pre-EIP-155); room chain id {expected}"
                ),
            },
            StfError::BlockGasLimit { used, limit } => {
                write!(f, "cumulative gas {used} exceeds block gas limit {limit}")
            }
            StfError::InvalidBatch(e) => write!(f, "invalid v4 batch: {e}"),
            StfError::CompactWitness(e) => write!(f, "invalid compact state witness: {e}"),
            StfError::CertifiedPolicy(e) => write!(f, "certified execution policy: {e}"),
            StfError::Settlement(e) => write!(f, "v4 settlement derivation: {e}"),
            StfError::GenesisAnchor(e) => write!(f, "v4 genesis L1 anchor: {e}"),
            StfError::ColdPreparation(e) => write!(f, "v4 cold preparation: {e}"),
            StfError::LongLivedRoom(e) => write!(f, "v5 long-lived room: {e}"),
        }
    }
}
impl std::error::Error for StfError {}
