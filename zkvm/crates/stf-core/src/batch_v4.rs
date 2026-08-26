//! v4 batch execution: one authenticated opening state, one to four blocks,
//! and the derived settlement statement.

use alloy_primitives::{Address, B256};
use std::collections::BTreeMap;
use stf_types::{
    batch_block_data_hash_v4, batch_block_roots_hash_v4, BatchBlockJournalV4, BatchInputV4,
    BatchJournalV4, ComposedBatchInputV4, StfInput, BATCH_JOURNAL_VERSION_V4, MAX_BATCH_BLOCKS_V4,
};

use crate::block::execute_block_on_state;
use crate::cold_room::validate_composed_cold_link_v4;
use crate::compact::verify_compact_state_v4;
use crate::policy::ExecutionPolicyV4;
use crate::settlement::{
    apply_inbox_v4, authenticate_previous_exit_allocations_v4, derive_settlement_v4,
    enforce_retired_exit_continuity_v4, validate_membership_transition_v4, ExitProgramV4,
};
use crate::{BatchOutcome, BatchProofWork, EvmProofWork, StfError};

/// Execute a normal batch after validating its room-local prestate against a
/// reusable cold proof. Receipt verification itself happens in the RISC Zero
/// guest via `env::verify`; this function checks the statement linkage.
pub fn execute_composed_batch_v4(input: &ComposedBatchInputV4) -> Result<BatchJournalV4, StfError> {
    execute_batch_v4_with_runtime_cache(&input.batch, true, Some(input))
        .map(|outcome| outcome.journal)
}

/// Execute a v4 batch with one authenticated opening state. The post-state of
/// each real EVM block becomes the in-memory pre-state of the next; the guest
/// never accepts a host-supplied intermediate state.
pub fn execute_batch_v4(input: &BatchInputV4) -> Result<BatchJournalV4, StfError> {
    execute_batch_v4_with_report(input).map(|outcome| outcome.journal)
}

/// Execute a batch and retain proof-sensitive work counters for benchmarking.
///
/// The counters are telemetry only: they do not alter the public journal and
/// therefore cannot be used as settlement authority.
pub fn execute_batch_v4_with_report(input: &BatchInputV4) -> Result<BatchOutcome, StfError> {
    execute_batch_v4_with_runtime_cache(input, true, None)
}

/// Reference interpreter path used for semantic-parity tests and profiling.
/// Production batches use [`execute_batch_v4`].
#[doc(hidden)]
pub fn execute_batch_v4_interpreter_fallback(
    input: &BatchInputV4,
) -> Result<BatchJournalV4, StfError> {
    execute_batch_v4_with_runtime_cache(input, false, None).map(|outcome| outcome.journal)
}

fn execute_batch_v4_with_runtime_cache(
    input: &BatchInputV4,
    use_prepared_runtime_cache: bool,
    cold_link: Option<&ComposedBatchInputV4>,
) -> Result<BatchOutcome, StfError> {
    let count = input.blocks.len();
    if !(1..=MAX_BATCH_BLOCKS_V4).contains(&count) {
        return Err(StfError::InvalidBatch(format!(
            "block count {count} outside 1..={MAX_BATCH_BLOCKS_V4}"
        )));
    }
    // `close` is the authenticated terminal system marker. It occurs
    // immediately after the final raw transaction of the final block, so a
    // room can close during a nominal block interval by sealing that partial
    // block and proving it as the one-block final flush. Normal progress must
    // still amortise proof cost across at least two blocks. Enforce this in
    // the guest as well as on L1 so an invalid one-block job never reaches the
    // prover and alternate verifier backends inherit the same rule.
    if count == 1 && !input.close {
        return Err(StfError::InvalidBatch(
            "one-block batch is permitted only as a terminal close".into(),
        ));
    }
    if input.active_mask & !0x7f != 0
        || input.pre_used_mask & !0x7f != 0
        || input.post_active_mask & !0x7f != 0
        || input.used_mask & !0x7f != 0
    {
        return Err(StfError::InvalidBatch(
            "member masks exceed seven slots".into(),
        ));
    }
    if input.active_mask & !input.pre_used_mask != 0
        || input.post_active_mask & !input.used_mask != 0
    {
        return Err(StfError::InvalidBatch(
            "active slots must be a subset of lifetime-used slots".into(),
        ));
    }
    if input.inbox_end < input.inbox_start {
        return Err(StfError::InvalidBatch(
            "inbox cursor moved backwards".into(),
        ));
    }
    if input.compact_state.canonical_state_root != B256::ZERO {
        return Err(StfError::CompactWitness(
            "v4 batches require complete room-local state with canonicalStateRoot zero".into(),
        ));
    }
    let membership_deltas_hash = validate_membership_transition_v4(
        input.batch_index,
        &input.pre_roster_slots,
        &input.post_roster_slots,
        &input.membership_deltas,
        input.pre_roster_root,
        input.post_roster_root,
        input.active_mask,
        input.pre_used_mask,
        input.post_active_mask,
        input.used_mask,
    )
    .map_err(StfError::Settlement)?;
    if membership_deltas_hash != input.membership_deltas_hash {
        return Err(StfError::Settlement(
            "derived membershipDeltasHash does not match expected public statement".into(),
        ));
    }
    let computed_data_hash = batch_block_data_hash_v4(&input.blocks, input.prev_state_root);
    if computed_data_hash != input.expected_block_data_hash {
        return Err(StfError::InvalidBatch(format!(
            "block data hash mismatch: expected {}, computed {}",
            input.expected_block_data_hash, computed_data_hash
        )));
    }

    let mut state = verify_compact_state_v4(&input.compact_state)?;
    let compact_root = state.state_root();
    if compact_root != input.prev_state_root {
        return Err(StfError::CompactWitness(format!(
            "compact root {} does not match batch prev root {}",
            compact_root, input.prev_state_root
        )));
    }
    if let Some(cold_link) = cold_link {
        validate_composed_cold_link_v4(cold_link, &state)?;
    }
    let policy = ExecutionPolicyV4::from_input(input, &state).map_err(StfError::CertifiedPolicy)?;
    let exit_program = ExitProgramV4::parse(&input.canonical_exit_program_json, &policy)
        .map_err(StfError::Settlement)?;
    authenticate_previous_exit_allocations_v4(
        &exit_program,
        &input.pre_roster_slots,
        input.pre_used_mask,
        &input.previous_exit_allocations,
        input.previous_exit_root,
        input.deployment_id,
        input.room_id,
    )
    .map_err(StfError::Settlement)?;
    let inbox_inputs_hash = apply_inbox_v4(
        &exit_program,
        &mut state,
        &input.inbox_entries,
        &input.membership_deltas,
        &input.pre_roster_slots,
        &input.post_roster_slots,
        input.inbox_start,
        input.inbox_end,
    )
    .map_err(StfError::Settlement)?;
    if inbox_inputs_hash != input.inbox_inputs_hash {
        return Err(StfError::Settlement(
            "derived inboxInputsHash does not match expected public statement".into(),
        ));
    }
    // Install only after deterministic inbox mutations have completed. The
    // cache depends solely on runtime bytes and their artifact-bound hashes;
    // balance/storage refreshes are intentionally irrelevant. Code changes in
    // DatabaseCommit invalidate the affected address and fall back safely.
    if use_prepared_runtime_cache {
        state
            .install_prepared_runtime_code(&policy.code_hashes)
            .map_err(StfError::CertifiedPolicy)?;
    } else {
        state.clear_prepared_runtime_code();
    }
    // Post-policy validation compares only the set of accounts and their
    // storage values. Snapshot precisely that data instead of cloning account
    // balances, runtime bytecode, access guards and prepared REVM bytecode.
    let initial_storage = state
        .accounts
        .iter()
        .map(|(address, account)| (*address, account.storage.clone()))
        .collect::<BTreeMap<_, _>>();
    // Inbox application is the deterministic system-input prefix of the first
    // block transition. Canonical batch calldata still names the previously
    // verified room root as its parent; the separately bound inbox hash makes
    // the pre-transaction mutation unambiguous.
    // An empty inbox segment cannot mutate state. Reuse the root already
    // authenticated immediately above instead of rebuilding the complete MPT
    // a second time; non-empty segments still derive a fresh post-inbox root.
    let mut current_root = if input.inbox_entries.is_empty() {
        compact_root
    } else {
        state.state_root()
    };
    let mut journals = Vec::with_capacity(count);
    let mut proof_work = EvmProofWork::default();
    let mut previous_timestamp = input.previous_block_timestamp;

    for (offset, block) in input.blocks.iter().enumerate() {
        let expected_number = input
            .l2_start_height
            .checked_add(offset as u64)
            .ok_or_else(|| StfError::InvalidBatch("L2 height overflow".into()))?;
        if block.block_number != expected_number || block.env.number != expected_number {
            return Err(StfError::InvalidBatch(format!(
                "block {offset} height/env must both be {expected_number}"
            )));
        }
        if block.env.timestamp < previous_timestamp {
            return Err(StfError::InvalidBatch(format!(
                "block {offset} timestamp {} precedes previous verified timestamp {previous_timestamp}",
                block.env.timestamp
            )));
        }
        previous_timestamp = block.env.timestamp;
        let expected_chain_id = stf_types::room_chain_id_v4(input.deployment_id, input.room_id);
        if block.env.chain_id != expected_chain_id {
            return Err(StfError::InvalidBatch(format!(
                "block {offset} chain id {} does not match room chain id {}",
                block.env.chain_id, expected_chain_id
            )));
        }
        if block.env.gas_limit != policy.max_gas_per_block
            || block.env.coinbase != Address::ZERO
            || !block.env.base_fee.is_zero()
            || block.env.prev_randao != B256::ZERO
            || !block.env.difficulty.is_zero()
            || block.env.excess_blob_gas != 0
        {
            return Err(StfError::InvalidBatch(format!(
                "block {offset} environment is not the deterministic v4 room profile"
            )));
        }
        let single = StfInput {
            room_id: input.room_id,
            block_number: block.block_number,
            prev_state_root: current_root,
            state: Vec::new(),
            raw_txs: block.raw_txs.clone(),
            env: block.env.clone(),
            block_hashes: Vec::new(),
        };
        // `current_root` was computed from this exact in-memory state above
        // (or returned with it by the preceding block). Rebuilding the full
        // account/storage MPT here would authenticate nothing new and is very
        // expensive inside the zkVM, so the batched path carries that trusted
        // root/state pair forward explicitly.
        let outcome = execute_block_on_state(
            &single,
            state,
            Some(&policy),
            false,
            0,
            use_prepared_runtime_cache,
            None,
        )?;
        if outcome.gas_used > policy.max_gas_per_block {
            return Err(StfError::CertifiedPolicy(format!(
                "block {offset} uses {} gas, exceeding preset cap {}",
                outcome.gas_used, policy.max_gas_per_block
            )));
        }
        if outcome.journal.post_state_root != block.expected_post_state_root {
            return Err(StfError::InvalidBatch(format!(
                "block {offset} post root {} does not match canonical batch root {}",
                outcome.journal.post_state_root, block.expected_post_state_root
            )));
        }
        current_root = outcome.journal.post_state_root;
        proof_work.accumulate(&outcome.proof_work);
        state = outcome.post_state;
        journals.push(BatchBlockJournalV4 {
            block_number: block.block_number,
            post_state_root: current_root,
            tx_commitment: outcome.journal.tx_commitment,
            env_hash: outcome.journal.env_hash,
        });
    }

    let l2_end_height = input
        .l2_start_height
        .checked_add(count as u64)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| StfError::InvalidBatch("L2 end height overflow".into()))?;

    policy
        .validate_post_state(&initial_storage, &state)
        .map_err(StfError::CertifiedPolicy)?;

    let settlement = derive_settlement_v4(
        &exit_program,
        &state,
        &input.post_roster_slots,
        &input.asset_totals,
        &input.residual_allocations,
        input.deployment_id,
        input.room_id,
    )
    .map_err(StfError::Settlement)?;
    enforce_retired_exit_continuity_v4(
        &input.previous_exit_allocations,
        &settlement.exit_allocations,
        input.pre_used_mask,
        input.active_mask,
    )
    .map_err(StfError::Settlement)?;
    if settlement.asset_totals_hash != input.asset_totals_hash
        || settlement.exit_totals_hash != input.exit_totals_hash
        || settlement.fee_totals_hash != input.fee_totals_hash
        || settlement.exit_root != input.exit_root
    {
        return Err(StfError::Settlement(
            "derived batch accounting/root does not match expected public statement".into(),
        ));
    }

    let block_roots_hash = batch_block_roots_hash_v4(&journals);
    let journal = BatchJournalV4 {
        v: BATCH_JOURNAL_VERSION_V4,
        deployment_id: input.deployment_id,
        room_id: input.room_id,
        preset_hash: input.preset_hash,
        manifest_hash: input.manifest_hash,
        proof_program_id: input.proof_program_id,
        batch_index: input.batch_index,
        l2_start_height: input.l2_start_height,
        l2_end_height,
        previous_block_timestamp: input.previous_block_timestamp,
        final_block_timestamp: previous_timestamp,
        prev_state_root: input.prev_state_root,
        post_state_root: current_root,
        block_roots_hash,
        blocks: journals,
        pre_roster_root: input.pre_roster_root,
        post_roster_root: input.post_roster_root,
        active_mask: input.active_mask,
        post_active_mask: input.post_active_mask,
        used_mask: input.used_mask,
        inbox_start: input.inbox_start,
        inbox_end: input.inbox_end,
        inbox_inputs_hash,
        block_data_hash: computed_data_hash,
        asset_totals_hash: settlement.asset_totals_hash,
        exit_totals_hash: settlement.exit_totals_hash,
        fee_totals_hash: settlement.fee_totals_hash,
        membership_deltas_hash,
        previous_exit_root: input.previous_exit_root,
        exit_root: settlement.exit_root,
        close: input.close,
        l1_inclusion_deadline: input.l1_inclusion_deadline,
        exit_allocations: settlement.exit_allocations,
        asset_accounting: settlement.accounting,
    };
    Ok(BatchOutcome {
        journal,
        proof_work: BatchProofWork {
            block_count: count as u64,
            encoded_witness_bytes: input.encoded_witness_bytes as u64,
            evm: proof_work,
        },
    })
}
