//! Cold v4 room preparation: the reusable constructor proof and the link that
//! binds it to a hot batch's room-local prestate.

use alloy_primitives::{Address, TxKind, B256};
use stf_types::{
    batch_block_data_hash_v4, cold_template_id_v4, hash_cold_runtime_code_v4,
    hash_cold_state_access_v4, hash_cold_state_refresh_v4, ColdRoomInputV4, ColdRoomJournalV4,
    ComposedBatchInputV4, StfInput, BATCH_JOURNAL_VERSION_V4, COLD_TEMPLATE_CHAIN_ID_V4,
    MAX_BATCH_WITNESS_BYTES_V4, MAX_COLD_BLOCKS_V4, MAX_COLD_GAS_PER_BLOCK_V4,
    MAX_COLD_TRANSACTIONS_V4, MAX_COMPACT_ACCOUNTS_V4, MAX_COMPACT_CODE_BYTES_V4,
    MAX_COMPACT_STORAGE_SLOTS_V4,
};

use crate::block::execute_block_on_state;
use crate::cold_state::{
    cold_static_state_commitment_v4, validate_cold_shapes_v4, verify_cold_runtime_code_v4,
};
use crate::txenv::tx_env_from_raw;
use crate::{StateMap, StfError};

/// Execute arbitrary user-supplied constructors and deterministic setup calls
/// exactly once. The resulting proof is reusable because no deployment,
/// room, participant, or live input appears in this statement.
pub fn execute_cold_room_v4(input: &ColdRoomInputV4) -> Result<ColdRoomJournalV4, StfError> {
    if input.encoded_witness_bytes <= 4
        || input.encoded_witness_bytes as usize > MAX_BATCH_WITNESS_BYTES_V4
    {
        return Err(StfError::ColdPreparation(format!(
            "encoded cold witness size must be 5..={MAX_BATCH_WITNESS_BYTES_V4} bytes"
        )));
    }
    if input.compiled_bundle_hash == B256::ZERO
        || input.preset_hash == B256::ZERO
        || input.manifest_hash == B256::ZERO
        || input.proof_program_id == B256::ZERO
    {
        return Err(StfError::ColdPreparation(
            "bundle/preset/manifest/program commitments must be non-zero".into(),
        ));
    }
    if input.runtime_code.is_empty() {
        return Err(StfError::ColdPreparation(
            "runtime code commitment list is empty".into(),
        ));
    }
    if !(1..=MAX_COLD_BLOCKS_V4).contains(&input.setup_blocks.len()) {
        return Err(StfError::ColdPreparation(format!(
            "setup block count must be 1..={MAX_COLD_BLOCKS_V4}"
        )));
    }
    let transaction_count = input
        .setup_blocks
        .iter()
        .try_fold(0usize, |total, block| {
            total.checked_add(block.raw_txs.len())
        })
        .ok_or_else(|| StfError::ColdPreparation("setup transaction count overflow".into()))?;
    if transaction_count == 0 || transaction_count > MAX_COLD_TRANSACTIONS_V4 {
        return Err(StfError::ColdPreparation(format!(
            "setup transaction count must be 1..={MAX_COLD_TRANSACTIONS_V4}"
        )));
    }
    if input.initial_state.len() > MAX_COMPACT_ACCOUNTS_V4
        || input
            .initial_state
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(StfError::ColdPreparation(
            "initial state must be capped, strictly address-sorted and unique".into(),
        ));
    }
    let mut storage_count = 0usize;
    let mut code_bytes = 0usize;
    for (_, account) in &input.initial_state {
        if account
            .storage
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
            || account.storage.iter().any(|(_, value)| value.is_zero())
        {
            return Err(StfError::ColdPreparation(
                "initial storage must be strictly slot-sorted, unique and non-zero".into(),
            ));
        }
        storage_count = storage_count
            .checked_add(account.storage.len())
            .ok_or_else(|| StfError::ColdPreparation("initial storage count overflow".into()))?;
        code_bytes = code_bytes
            .checked_add(account.code.len())
            .ok_or_else(|| StfError::ColdPreparation("initial code size overflow".into()))?;
    }
    if storage_count > MAX_COMPACT_STORAGE_SLOTS_V4 || code_bytes > MAX_COMPACT_CODE_BYTES_V4 {
        return Err(StfError::ColdPreparation(
            "initial state resource envelope exceeded".into(),
        ));
    }
    validate_cold_shapes_v4(
        &input.runtime_code,
        &input.state_access,
        &input.state_refresh,
    )?;

    let mut state = StateMap::from_input(&input.initial_state);
    let initial_root = state.state_root();
    if initial_root != input.initial_state_root {
        return Err(StfError::PreRootMismatch {
            expected: input.initial_state_root,
            computed: initial_root,
        });
    }
    let mut current_root = initial_root;
    let mut previous_timestamp = 0u64;
    let mut saw_creation = false;
    for (offset, block) in input.setup_blocks.iter().enumerate() {
        let expected_number = offset as u64;
        if block.block_number != expected_number || block.env.number != expected_number {
            return Err(StfError::ColdPreparation(format!(
                "setup block {offset} number/env must both equal {expected_number}"
            )));
        }
        if block.env.timestamp < previous_timestamp
            || block.env.chain_id != COLD_TEMPLATE_CHAIN_ID_V4
            || block.env.coinbase != Address::ZERO
            || !block.env.base_fee.is_zero()
            || block.env.prev_randao != B256::ZERO
            || !block.env.difficulty.is_zero()
            || block.env.excess_blob_gas != 0
            || !(1..=MAX_COLD_GAS_PER_BLOCK_V4).contains(&block.env.gas_limit)
        {
            return Err(StfError::ColdPreparation(format!(
                "setup block {offset} environment is outside the cold Osaka profile"
            )));
        }
        previous_timestamp = block.env.timestamp;
        for raw in &block.raw_txs {
            let decoded = tx_env_from_raw(raw, COLD_TEMPLATE_CHAIN_ID_V4)?;
            saw_creation |= matches!(decoded.kind, TxKind::Create);
        }
        let single = StfInput {
            room_id: 0,
            block_number: block.block_number,
            prev_state_root: current_root,
            state: Vec::new(),
            raw_txs: block.raw_txs.clone(),
            env: block.env.clone(),
            block_hashes: Vec::new(),
        };
        let outcome = execute_block_on_state(&single, state, None, false, 0, true, None)?;
        if outcome.journal.post_state_root != block.expected_post_state_root {
            return Err(StfError::ColdPreparation(format!(
                "setup block {offset} post root does not match the supplied constructor transcript"
            )));
        }
        current_root = outcome.journal.post_state_root;
        state = outcome.post_state;
    }
    if !saw_creation {
        return Err(StfError::ColdPreparation(
            "cold setup must contain at least one contract-creation transaction".into(),
        ));
    }
    if current_root != input.initialized_state_root {
        return Err(StfError::ColdPreparation(format!(
            "initialized state root {current_root} does not match expected {}",
            input.initialized_state_root
        )));
    }
    let mut initialized_storage_count = 0usize;
    let mut initialized_code_bytes = 0usize;
    for account in state.accounts.values() {
        initialized_storage_count = initialized_storage_count
            .checked_add(account.storage.len())
            .ok_or_else(|| {
                StfError::ColdPreparation("initialized storage count overflow".into())
            })?;
        initialized_code_bytes = initialized_code_bytes
            .checked_add(account.code.len())
            .ok_or_else(|| StfError::ColdPreparation("initialized code size overflow".into()))?;
    }
    if state.accounts.len() > MAX_COMPACT_ACCOUNTS_V4
        || initialized_storage_count > MAX_COMPACT_STORAGE_SLOTS_V4
        || initialized_code_bytes > MAX_COMPACT_CODE_BYTES_V4
    {
        return Err(StfError::ColdPreparation(
            "initialized state resource envelope exceeded".into(),
        ));
    }
    verify_cold_runtime_code_v4(&state, &input.runtime_code)?;
    let static_state_commitment =
        cold_static_state_commitment_v4(&state, &input.state_access, &input.state_refresh)?;
    let mut journal = ColdRoomJournalV4 {
        v: BATCH_JOURNAL_VERSION_V4,
        template_id: B256::ZERO,
        compiled_bundle_hash: input.compiled_bundle_hash,
        preset_hash: input.preset_hash,
        manifest_hash: input.manifest_hash,
        proof_program_id: input.proof_program_id,
        constructor_chain_id: COLD_TEMPLATE_CHAIN_ID_V4,
        initial_state_root: initial_root,
        initialized_state_root: current_root,
        setup_data_hash: batch_block_data_hash_v4(&input.setup_blocks, initial_root),
        runtime_code_root: hash_cold_runtime_code_v4(&input.runtime_code),
        state_access_root: hash_cold_state_access_v4(&input.state_access),
        state_refresh_root: hash_cold_state_refresh_v4(&input.state_refresh),
        static_state_commitment,
        analyzed_artifact_root: input.analyzed_artifact_root,
        allowed_call_target_root: input.allowed_call_target_root,
    };
    journal.template_id = cold_template_id_v4(&journal);
    Ok(journal)
}

#[doc(hidden)]
pub fn validate_composed_cold_link_v4(
    input: &ComposedBatchInputV4,
    refreshed_state: &StateMap,
) -> Result<(), StfError> {
    let cold = &input.cold_journal;
    if cold.v != BATCH_JOURNAL_VERSION_V4
        || cold.constructor_chain_id != COLD_TEMPLATE_CHAIN_ID_V4
        || cold.template_id != cold_template_id_v4(cold)
    {
        return Err(StfError::ColdPreparation(
            "invalid cold journal version, chain namespace, or template id".into(),
        ));
    }
    if cold.proof_program_id != input.batch.proof_program_id
        || cold.preset_hash != input.batch.preset_hash
        || cold.manifest_hash != input.batch.manifest_hash
    {
        return Err(StfError::ColdPreparation(
            "cold proof does not match the hot batch program/preset/manifest".into(),
        ));
    }
    validate_cold_shapes_v4(
        &input.runtime_code,
        &input.state_access,
        &input.state_refresh,
    )?;
    if hash_cold_runtime_code_v4(&input.runtime_code) != cold.runtime_code_root
        || hash_cold_state_access_v4(&input.state_access) != cold.state_access_root
        || hash_cold_state_refresh_v4(&input.state_refresh) != cold.state_refresh_root
    {
        return Err(StfError::ColdPreparation(
            "cold proof-link preimage does not match the proven roots".into(),
        ));
    }
    verify_cold_runtime_code_v4(refreshed_state, &input.runtime_code)?;
    let refreshed_static = cold_static_state_commitment_v4(
        refreshed_state,
        &input.state_access,
        &input.state_refresh,
    )?;
    if refreshed_static != cold.static_state_commitment {
        return Err(StfError::ColdPreparation(
            "room start changed state outside the proven refresh policy".into(),
        ));
    }
    Ok(())
}
