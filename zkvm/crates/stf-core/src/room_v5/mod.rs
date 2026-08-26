//! Long-lived v5 rooms: the cold-template registration statement and one
//! proof-backed batch transition.
//!
//! The witness checks are split by subject — approver roster, escrow
//! liabilities, L1 imports, operator admissions — and composed here in the
//! order the journal is derived.

mod admission;
mod exit;
mod import;
mod liabilities;
mod roster;

use alloy_primitives::{Address, B256};
use revm::context::TxEnv;
use std::collections::{BTreeMap, BTreeSet};
use stf_types::{
    batch_block_data_hash_v5, cold_template_id_v5, cold_template_statement_v6, room_chain_id_v5,
    BatchInputV5, BatchJournalV5, ColdTemplateInputV5, StfInput, BATCH_JOURNAL_VERSION_V6,
    MAX_BATCH_WITNESS_BYTES_V4,
};

use crate::block::{execute_block_on_state, room_state_root_v5};
use crate::compact::verify_compact_state_v4;
use crate::policy::ExecutionPolicyV4;
use crate::txenv::tx_env_from_raw;
use crate::{BatchOutcomeV5, BatchProofWork, EvmProofWork, StateMap, StfError};

use admission::validate_admissions_v5;
use import::{participant_state_v5, verify_and_apply_import_v5};
use liabilities::{apply_deposit_credits_v5, validate_liabilities_v5};
use roster::validate_roster_transition_v5;

/// Validate and derive the one-time L1 cold-template registration statement.
///
/// `genesis_data_hash` is the keccak of the exact framed canonical witness
/// bytes the guest decoded, so the registered statement binds the complete
/// genesis package by construction.
pub fn execute_cold_template_v5(
    input: &ColdTemplateInputV5,
    genesis_data_hash: B256,
) -> Result<B256, StfError> {
    if input.initial_state_root == B256::ZERO
        || input.policy_hash == B256::ZERO
        || input.proof_program_id == B256::ZERO
        || input.proof_system_version == B256::ZERO
        || genesis_data_hash == B256::ZERO
        || cold_template_id_v5(
            input.initial_state_root,
            input.policy_hash,
            input.proof_system_version,
        ) != input.template_id
    {
        return Err(StfError::LongLivedRoom(
            "cold-template identity is zero or not canonically derived".into(),
        ));
    }
    if input.compact_state.canonical_state_root != B256::ZERO {
        return Err(StfError::LongLivedRoom(
            "cold template requires a complete initial room state".into(),
        ));
    }
    let state = verify_compact_state_v4(&input.compact_state)?;
    let initial_root = room_state_root_v5(&state, input.policy.state_commitment)?;
    if initial_root != input.initial_state_root {
        return Err(StfError::PreRootMismatch {
            expected: input.initial_state_root,
            computed: initial_root,
        });
    }
    let mut synthetic_roster = BTreeSet::new();
    synthetic_roster.insert(Address::repeat_byte(0x01));
    ExecutionPolicyV4::from_v5(
        &input.policy,
        input.policy_hash,
        synthetic_roster,
        &state,
        false,
    )
    .map_err(StfError::CertifiedPolicy)?;
    Ok(cold_template_statement_v6(input, genesis_data_hash))
}

/// Derive the deterministic reason an L1 forced transaction could never have
/// been part of a batch of this room, or `None` when the batch could have
/// carried it.
///
/// This is the public mirror of the guest's in-batch forced-rejection
/// derivation (`admission::forced_rejection_reason_v5`). Node composers call it
/// with the batch's authenticated caller set as `active_members` and the last
/// block's post-state as `terminal` to compose the same status-2 records the
/// guest re-derives and refuses to accept otherwise. The certified policy is
/// rebuilt from its binary commitment against `terminal`; `from_v5` pins code
/// against the passed state, and code accounts are identical at the opening and
/// terminal state (`validate_post_state` pins them), so `terminal` is faithful.
pub fn derive_forced_rejection_reason_v5(
    raw: &[u8],
    deployment_domain: B256,
    room_id: u64,
    policy: &stf_types::ExecutionPolicyV5,
    policy_hash: B256,
    active_members: BTreeSet<Address>,
    terminal: &StateMap,
) -> Result<Option<u8>, StfError> {
    let policy = ExecutionPolicyV4::from_v5(policy, policy_hash, active_members, terminal, false)
        .map_err(StfError::CertifiedPolicy)?;
    Ok(admission::forced_rejection_reason_v5(
        raw,
        room_chain_id_v5(deployment_domain, room_id),
        &policy,
        terminal,
    ))
}

/// Execute one proof-backed transition of a long-lived v5 room.
pub fn execute_batch_v5(input: &BatchInputV5) -> Result<BatchJournalV5, StfError> {
    execute_batch_v5_with_report(input).map(|outcome| outcome.journal)
}

/// Execute a v5 transition and retain non-consensus proof-work telemetry.
///
/// The report is derived from the exact transition that produced `journal`;
/// it is never accepted as witness input and does not change the journal hash.
pub fn execute_batch_v5_with_report(input: &BatchInputV5) -> Result<BatchOutcomeV5, StfError> {
    let journal = &input.journal;
    if journal.protocol_version != BATCH_JOURNAL_VERSION_V6
        || journal.deployment_domain == B256::ZERO
        || journal.room_id == 0
        || journal.authorization_mode > 1
        || journal.cold_template_id == B256::ZERO
        || journal.proof_program_id == B256::ZERO
        || journal.proof_system_version == B256::ZERO
        || journal.policy_hash == B256::ZERO
        || journal.batch_index == 0
        || journal.l1_inclusion_deadline == 0
    {
        return Err(StfError::LongLivedRoom(
            "required v6 public identity field is zero or invalid".into(),
        ));
    }
    // The first batch of a room opens at exactly the registered template's
    // initial state (`RoomManagerIntakeFacet` sets `room.stateRoot =
    // template.initialStateRoot` and `_validateJournal` pins `preStateRoot`),
    // so the template identity is derivable here rather than merely echoed.
    // Later batches move past that root and stay bound on L1 only.
    if journal.batch_index == 1
        && cold_template_id_v5(
            journal.pre_state_root,
            journal.policy_hash,
            journal.proof_system_version,
        ) != journal.cold_template_id
    {
        return Err(StfError::LongLivedRoom(
            "first batch does not open at its cold template's registered state".into(),
        ));
    }
    let count = input.blocks.len();
    if count == 0
        || count as u64 > input.policy.max_blocks_per_batch
        || (count == 1 && !journal.close)
        || input.encoded_witness_bytes as usize > MAX_BATCH_WITNESS_BYTES_V4
    {
        return Err(StfError::LongLivedRoom(
            "batch block count or witness size is outside the policy".into(),
        ));
    }
    if journal.end_l2_block
        != journal
            .start_l2_block
            .checked_add(count as u64 - 1)
            .ok_or_else(|| StfError::LongLivedRoom("L2 block range overflow".into()))?
    {
        return Err(StfError::LongLivedRoom(
            "journal L2 range does not match the block count".into(),
        ));
    }
    let mut authenticated_callers = validate_roster_transition_v5(input)?;
    validate_liabilities_v5(input)?;

    if input.compact_state.canonical_state_root != B256::ZERO {
        return Err(StfError::LongLivedRoom(
            "v5 hot batches require a complete room-local prestate".into(),
        ));
    }
    let mut state = verify_compact_state_v4(&input.compact_state)?;
    let opening_root = room_state_root_v5(&state, input.policy.state_commitment)?;
    if opening_root != journal.pre_state_root {
        return Err(StfError::PreRootMismatch {
            expected: journal.pre_state_root,
            computed: opening_root,
        });
    }
    let opening_participants = participant_state_v5(input, &state)?;
    if opening_participants
        != (
            journal.pre_participant_root,
            journal.pre_participant_epoch,
            journal.pre_participant_count,
            journal.participant_capacity,
        )
    {
        return Err(StfError::LongLivedRoom(
            "opening participant registry differs from the journal".into(),
        ));
    }
    verify_and_apply_import_v5(input, &mut state)?;
    // The opening exit-queue cursor is proof state, never witness data: it is
    // read out of the authenticated pre-state (imports cannot target the
    // queue contract) before any block executes.
    let pre_exit_count = match &input.policy.exit {
        Some(binding) if journal.authorization_mode == 1 => {
            exit::exit_record_count_v5(binding, &state)?
        }
        _ => 0,
    };
    // Consumed-deposit value arrives as a system effect of crossing the L1
    // inbox: the beneficiary's credit is part of the proved opening of the
    // first block, so no app transaction can redirect or omit it.
    apply_deposit_credits_v5(input, &mut state)?;
    // Signer recovery is the dominant per-transaction cost inside the guest.
    // A validity-only room needs every caller before the policy can be built,
    // so decode each transaction once here and hand the decoded environments
    // to the executor instead of recovering every signature a second time.
    let mut decoded_blocks: Vec<Option<Vec<TxEnv>>> = Vec::new();
    if journal.authorization_mode == 1 {
        for block in &input.blocks {
            let mut decoded = Vec::with_capacity(block.raw_txs.len());
            for raw in &block.raw_txs {
                let tx_env = tx_env_from_raw(raw.as_ref(), block.env.chain_id)
                    .map_err(|error| StfError::TxDecode(error.to_string()))?;
                authenticated_callers.insert(tx_env.caller);
                decoded.push(tx_env);
            }
            decoded_blocks.push(Some(decoded));
        }
        if authenticated_callers.is_empty() {
            return Err(StfError::LongLivedRoom(
                "validity-only batch has no signed transaction caller".into(),
            ));
        }
    }
    let policy = ExecutionPolicyV4::from_v5(
        &input.policy,
        journal.policy_hash,
        authenticated_callers,
        &state,
        !input.roster_changes.is_empty(),
    )
    .map_err(StfError::CertifiedPolicy)?;
    state
        .install_prepared_runtime_code(&policy.code_hashes)
        .map_err(StfError::CertifiedPolicy)?;
    let initial_storage = state
        .accounts
        .iter()
        .map(|(address, account)| (*address, account.storage.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut current_root = room_state_root_v5(&state, input.policy.state_commitment)?;
    let expected_chain_id = room_chain_id_v5(journal.deployment_domain, journal.room_id);
    let mut proof_work = EvmProofWork::default();
    let mut executed = Vec::with_capacity(input.blocks.len());
    // The shipped room applications gate on `block.timestamp`, so the batch
    // composer must not be able to rewind the L2 clock. The v5 journal carries
    // no timestamp field yet, so only the intra-batch ordering is provable
    // here; binding block 0 to the previously accepted batch needs a journal
    // field and its L1 mirror.
    let mut previous_timestamp: Option<u64> = None;

    for (offset, block) in input.blocks.iter().enumerate() {
        let expected_number = journal
            .start_l2_block
            .checked_add(offset as u64)
            .ok_or_else(|| StfError::LongLivedRoom("L2 block height overflow".into()))?;
        if previous_timestamp.is_some_and(|previous| block.env.timestamp < previous) {
            return Err(StfError::LongLivedRoom(
                "block timestamp precedes the previous block in the same batch".into(),
            ));
        }
        previous_timestamp = Some(block.env.timestamp);
        if block.block_number != expected_number
            || block.env.number != expected_number
            || block.env.chain_id != expected_chain_id
            || block.env.gas_limit != input.policy.max_gas_per_block
            || block.raw_txs.len() as u64 > input.policy.max_transactions_per_block
            || block.env.coinbase != Address::ZERO
            || !block.env.base_fee.is_zero()
            || block.env.prev_randao != B256::ZERO
            || !block.env.difficulty.is_zero()
            || block.env.excess_blob_gas != 0
        {
            return Err(StfError::LongLivedRoom(
                "block does not match the certified room environment".into(),
            ));
        }
        let single = StfInput {
            room_id: journal.room_id,
            block_number: block.block_number,
            prev_state_root: current_root,
            state: Vec::new(),
            raw_txs: block.raw_txs.clone(),
            env: block.env.clone(),
            block_hashes: block.block_hashes.clone(),
        };
        let outcome = execute_block_on_state(
            &single,
            state,
            Some(&policy),
            false,
            input.policy.state_commitment,
            true,
            decoded_blocks.get_mut(offset).and_then(Option::take),
        )?;
        if outcome.journal.post_state_root != block.expected_post_state_root {
            return Err(StfError::LongLivedRoom(
                "proved intermediate root differs from the approved batch".into(),
            ));
        }
        current_root = outcome.journal.post_state_root;
        proof_work.accumulate(&outcome.proof_work);
        executed.push((block.block_number, outcome.transactions));
        state = outcome.post_state;
    }
    policy
        .validate_post_state(&initial_storage, &state)
        .map_err(StfError::CertifiedPolicy)?;
    if current_root != journal.post_state_root
        || batch_block_data_hash_v5(&input.blocks, journal.pre_state_root)
            != journal.batch_data_hash
    {
        return Err(StfError::LongLivedRoom(
            "terminal state or approved batch-data commitment differs".into(),
        ));
    }
    let closing_participants = participant_state_v5(input, &state)?;
    if closing_participants
        != (
            journal.post_participant_root,
            journal.post_participant_epoch,
            journal.post_participant_count,
            journal.participant_capacity,
        )
    {
        return Err(StfError::LongLivedRoom(
            "terminal participant registry differs from the journal".into(),
        ));
    }
    validate_admissions_v5(input, &executed, &policy, &state)?;
    exit::validate_exit_v5(input, pre_exit_count, &state)?;
    Ok(BatchOutcomeV5 {
        journal: journal.clone(),
        proof_work: BatchProofWork {
            block_count: count as u64,
            encoded_witness_bytes: input.encoded_witness_bytes as u64,
            evm: proof_work,
        },
    })
}
