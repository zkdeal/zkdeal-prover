//! Journal layout versions and the witness/resource bounds enforced by the
//! guest before any unauthenticated input drives an allocation.

/// Journal layout version. 2 adds `env_hash` (see [`crate::StfJournal`]).
pub const JOURNAL_VERSION: u8 = 2;

/// Breaking zkdeal batch journal version. V4 is intentionally unrelated to
/// the legacy per-block v2 journal: it is the public statement consumed by
/// `RoomManagerV4` on every accepted batch.
pub const BATCH_JOURNAL_VERSION_V4: u8 = 4;
/// Protocol v6 keeps the long-lived-room engine implemented by the `v5`
/// modules while extending its public journal and admission receipt ABI.
pub const BATCH_JOURNAL_VERSION_V6: u8 = 6;

/// A normal v4 proof covers 2-4 blocks. One block is accepted only as the
/// final flush of a room; the host/contract decide whether that flush is
/// permitted for a particular submission.
pub const MAX_BATCH_BLOCKS_V4: usize = 4;
pub const MAX_COMPACT_ACCOUNTS_V4: usize = 128;
pub const MAX_COMPACT_STORAGE_SLOTS_V4: usize = 2_048;
pub const MAX_COMPACT_PROOF_NODES_V4: usize = 4_096;
pub const MAX_COMPACT_CODE_BYTES_V4: usize = 2 * 1024 * 1024;
pub const MAX_BATCH_WITNESS_BYTES_V4: usize = 8 * 1024 * 1024;
/// Upper bound on the positional v5 approver-roster tree capacity. It mirrors
/// `RoomManagerBase.MAX_ACTIVE_APPROVERS = 256` and the matching
/// `MAX_APPROVER_PROOF_DEPTH = 8`: a wider tree produces membership proofs L1
/// can never verify, and the capacity is raw witness data reached before any
/// policy hash is checked, so an unbounded value would otherwise drive an
/// eager `capacity`-sized allocation on the prover.
pub const MAX_POSITIONAL_CAPACITY_V5: u64 = 256;
/// Upper bound on the positional v5 withdrawal-outbox tree capacity. It
/// mirrors `RoomManagerBase.MAX_WITHDRAWALS_PER_EPOCH = 32768` and the
/// matching claim-proof depth 15, so a close sweep bounded by
/// `MAX_COMPACT_ACCOUNTS_V4` accounts times the per-room asset list always
/// fits one epoch without chunking.
pub const MAX_WITHDRAWAL_CAPACITY_V5: u64 = 32_768;
/// Upper bound on the number of distinct assets one room-local exit binding
/// may pay out. Every asset is a code-pinned in-room representation, so a
/// realistic certified room declares a handful; 256 is far above that while
/// keeping the close-sweep leaf count (at most this many assets times the
/// `MAX_COMPACT_ACCOUNTS_V4` code-free accounts) inside
/// `MAX_WITHDRAWAL_CAPACITY_V5`. The list is part of the hashed policy, so this
/// is a validation sanity bound rather than a pre-hash allocation guard.
pub const MAX_EXIT_ASSETS_V5: usize = 256;
/// Cold preparation is off the interactive path, but remains bounded so a
/// malicious template cannot turn preparation into an unbounded prover job.
pub const MAX_COLD_BLOCKS_V4: usize = 32;
pub const MAX_COLD_TRANSACTIONS_V4: usize = 256;
pub const MAX_COLD_GAS_PER_BLOCK_V4: u64 = 30_000_000;
/// Constructor and deterministic initializer transactions execute in a
/// template namespace.  This is deliberately not a room chain id: the cold
/// receipt is reusable and must not contain a deployment or room identifier.
pub const COLD_TEMPLATE_CHAIN_ID_V4: u64 = 77_999_999;
