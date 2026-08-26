//! Host-visible outcome types. None of these are consensus-critical: the
//! journals they carry are, the proof-work counters beside them are telemetry.

use alloy_primitives::B256;
use stf_types::{BatchJournalV4, BatchJournalV5, StfJournal};

use crate::{DbAccessMetrics, StateMap};

/// Host-visible result of a room batch. This is deliberately separate from
/// `BatchJournalV4`, whose hash is consensus-critical.
#[derive(Clone, Debug)]
pub struct BatchOutcome {
    pub journal: BatchJournalV4,
    pub proof_work: BatchProofWork,
}

/// Host-visible result of a v5 room batch. Proof-work is telemetry and is not
/// part of the Solidity-compatible journal commitment.
#[derive(Clone, Debug)]
pub struct BatchOutcomeV5 {
    pub journal: BatchJournalV5,
    pub proof_work: BatchProofWork,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchProofWork {
    pub block_count: u64,
    pub encoded_witness_bytes: u64,
    pub evm: EvmProofWork,
}

/// Everything the host / debug tooling may want beyond the journal.
#[derive(Clone, Debug)]
pub struct BlockOutcome {
    pub journal: StfJournal,
    /// Cumulative gas used across all txs (extra parity signal vs the
    /// engine's sealed header.gasUsed; not part of the journal).
    pub gas_used: u64,
    pub proof_work: EvmProofWork,
    pub post_state: StateMap,
    pub transactions: Vec<TransactionOutcome>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionOutcome {
    pub transaction_hash: B256,
    /// 0 = succeeded, 1 = reverted or halted.
    pub status: u8,
}

/// Proof-sensitive execution shape. Unlike EVM gas, these counters describe
/// work that feeds witness construction and the zkVM trace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvmProofWork {
    pub executed_gas: u64,
    pub transaction_count: u64,
    pub opcode_steps: u64,
    /// Ranked two-op motifs executed through one prepared dispatcher pass.
    pub fused_motif_hits: u64,
    /// Logical EVM operations covered by those motifs (two per hit).
    pub fused_motif_opcodes: u64,
    pub keccak_opcodes: u64,
    pub call_opcodes: u64,
    pub precompile_calls: u64,
    pub max_memory_bytes: u64,
    pub db: DbAccessMetrics,
    pub state_accounts: u64,
    pub state_storage_slots: u64,
    pub state_code_bytes: u64,
}

impl EvmProofWork {
    pub(crate) fn accumulate(&mut self, next: &Self) {
        self.executed_gas = self.executed_gas.saturating_add(next.executed_gas);
        self.transaction_count = self
            .transaction_count
            .saturating_add(next.transaction_count);
        self.opcode_steps = self.opcode_steps.saturating_add(next.opcode_steps);
        self.fused_motif_hits = self.fused_motif_hits.saturating_add(next.fused_motif_hits);
        self.fused_motif_opcodes = self
            .fused_motif_opcodes
            .saturating_add(next.fused_motif_opcodes);
        self.keccak_opcodes = self.keccak_opcodes.saturating_add(next.keccak_opcodes);
        self.call_opcodes = self.call_opcodes.saturating_add(next.call_opcodes);
        self.precompile_calls = self.precompile_calls.saturating_add(next.precompile_calls);
        self.max_memory_bytes = self.max_memory_bytes.max(next.max_memory_bytes);
        self.db.account_reads = self.db.account_reads.saturating_add(next.db.account_reads);
        self.db.code_reads = self.db.code_reads.saturating_add(next.db.code_reads);
        self.db.storage_reads = self.db.storage_reads.saturating_add(next.db.storage_reads);
        self.db.block_hash_reads = self
            .db
            .block_hash_reads
            .saturating_add(next.db.block_hash_reads);
        self.db.account_writes = self
            .db
            .account_writes
            .saturating_add(next.db.account_writes);
        self.db.storage_writes = self
            .db
            .storage_writes
            .saturating_add(next.db.storage_writes);
        self.state_accounts = self.state_accounts.max(next.state_accounts);
        self.state_storage_slots = self.state_storage_slots.max(next.state_storage_slots);
        self.state_code_bytes = self.state_code_bytes.max(next.state_code_bytes);
    }
}
