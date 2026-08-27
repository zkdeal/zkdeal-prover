//! Where a batch opens: batch one at the registered cold template, batch `n`
//! at the state the room's own earlier blocks left behind.
//!
//! `prepare` holds no room state. A room asking for its second or later
//! checkpoint sends every block it already proved, and those blocks are
//! replayed here to rederive the opening. That is the whole of the
//! continuation: nothing is remembered between calls, so the same request
//! always prepares the same batch, and a room can be rebuilt from its
//! persisted transactions alone.
//!
//! Five journal fields are decided here and every one of them is pinned on L1
//! by `RoomManagerValidationFacet._validateJournal` against the room's stored
//! values -- `startL2Block == l2BlockHeight + 1`, `preStateRoot ==
//! room.stateRoot`, `preParticipantRoot/Epoch/Count == room.participant*` and
//! `importCursorBefore == room.importCursor`. Deriving them from the replay
//! rather than restating them from the request is what makes a prepared
//! continuation chain instead of merely execute.

use alloy_primitives::{Address, B256};
use anyhow::{anyhow, bail, Result};
use stf_core::execute_block_full_v5_commitment;
use stf_types::{AccountState, CompactStateWitnessV4, L1ImportWitnessV5};

use super::config::FixtureConfig;
use super::contracts::RegistrySlots;
use super::signing::env;
use super::state::{compact_state, compact_state_with_declared_storage, registry_view};

/// The room as its already-proved blocks leave it: the state batch `n` opens
/// at, that state's root, and the height of the last replayed block.
pub(super) struct Replay {
    pub(super) state: Vec<(Address, AccountState)>,
    pub(super) root: B256,
    pub(super) height: u64,
}

/// Re-execute every block the room proved before the requested batch.
///
/// The replay starts from the same post-import execution state batch one's
/// first block starts from, so block numbering, block environments and the L1
/// mirror are identical to the run that originally produced these blocks. An
/// empty history is the opening batch and leaves the inputs untouched, which is
/// what keeps batch one byte-identical to what it has always been.
pub(super) fn replay_history(
    config: &FixtureConfig,
    chain_id: u64,
    history: &[Vec<alloy_primitives::Bytes>],
    execution_state: Vec<(Address, AccountState)>,
    execution_pre_root: B256,
) -> Result<Replay> {
    let (room_id, batch_index) = (config.room_id, config.batch_index);
    let mut replay = Replay {
        state: execution_state,
        root: execution_pre_root,
        height: 0,
    };
    for raw in history {
        replay.height += 1;
        let height = replay.height;
        let outcome = execute_block_full_v5_commitment(
            &stf_types::StfInput {
                room_id,
                block_number: height,
                prev_state_root: replay.root,
                state: replay.state,
                raw_txs: raw.clone(),
                env: env(height, chain_id),
                block_hashes: vec![],
            },
            config.state_commitment,
        )
        .map_err(|error| {
            anyhow!(
                "replay L2 block {height}, which batch {batch_index} continues from: {error}. A \
                 continuation replays the room's earlier blocks exactly as they were first \
                 proved, so a block that no longer executes means the request's transaction \
                 history is not the one this room actually ran"
            )
        })?;
        replay.root = outcome.journal.post_state_root;
        replay.state = outcome.post_state.to_input_state();
    }
    Ok(replay)
}

/// Everything the journal has to say about the state a batch opens at.
pub(super) struct BatchOpening {
    pub(super) pre_state_root: B256,
    pub(super) compact_state: CompactStateWitnessV4,
    pub(super) participant_root: B256,
    pub(super) participant_epoch: u64,
    pub(super) participant_count: u64,
    /// The certified L1 import, carried by the batch that actually applies it.
    /// A continuation inherits an already-mirrored room, so it carries none.
    pub(super) l1_import: Option<L1ImportWitnessV5>,
    pub(super) import_cursor_before: u64,
}

/// What batch one opens at, read out of the state that is actually proved.
pub(super) struct ColdOpening<'a> {
    pub(super) state: &'a [(Address, AccountState)],
    pub(super) root: B256,
    pub(super) participant_root: B256,
    pub(super) participant_epoch: u64,
    pub(super) participant_count: u64,
}

/// Resolve the opening of batch `batch_index`.
///
/// Batch one opens at the cold template's registered initial state -- before
/// the L1 import, which `execute_batch_v5` verifies and applies itself, and
/// which is why the import witness travels with that batch and no other. Every
/// later batch opens at the replay's terminal state with the import cursor
/// already advanced past it.
pub(super) fn batch_opening(
    config: &FixtureConfig,
    cold: ColdOpening<'_>,
    replay: &Replay,
    registry_contract: Address,
    registry_slots: RegistrySlots,
    l1_import: Option<L1ImportWitnessV5>,
) -> Result<BatchOpening> {
    let batch_index = config.batch_index;
    if batch_index == 1 {
        return Ok(BatchOpening {
            pre_state_root: cold.root,
            compact_state: compact_state(cold.state),
            participant_root: cold.participant_root,
            participant_epoch: cold.participant_epoch,
            participant_count: cold.participant_count,
            l1_import,
            import_cursor_before: 0,
        });
    }
    let (root, epoch, count, capacity) =
        registry_view(&replay.state, registry_contract, registry_slots)?;
    if capacity != config.participant_capacity {
        bail!(
            "batch {batch_index} opens on a room whose participant capacity slot holds \
             {capacity}, but the request asks for {}; the capacity is pinned on L1 and cannot \
             change between checkpoints",
            config.participant_capacity
        );
    }
    if root == B256::ZERO || epoch == 0 {
        bail!(
            "batch {batch_index} opens on a participant registry with a zero root or epoch, which \
             the guest refuses; the replayed history does not leave this room in a state a batch \
             can continue from"
        );
    }
    Ok(BatchOpening {
        pre_state_root: replay.root,
        // Replay state is canonical and therefore omits zero storage. Restore
        // the cold template's general storage declaration envelope in the
        // witness so a continuation may still read an unchanged zero slot.
        compact_state: compact_state_with_declared_storage(&replay.state, cold.state),
        participant_root: root,
        participant_epoch: epoch,
        participant_count: count,
        // The import was applied by the batch that carried it; its cursor stays
        // where that batch left it, which is what `_validateJournal` compares
        // against `room.importCursor`.
        l1_import: None,
        import_cursor_before: u64::from(l1_import.is_some()),
    })
}
