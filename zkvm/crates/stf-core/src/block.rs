//! Single-block Osaka execution: the one place revm is driven.
//!
//! Every batched path (v4, composed v4, cold v4, v5) funnels through
//! [`execute_block_on_state`], so the transaction admission policy, the
//! certified inspector and the state-commitment mode cannot drift between
//! them.

use alloy_primitives::{keccak256, Address, B256, U256};
use revm::{
    context::{BlockEnv, TxEnv},
    context_interface::{block::BlobExcessGasAndPrice, ContextTr},
    handler::evm::EvmTr,
    primitives::{eip4844::BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE, hardfork::SpecId},
    Context, InspectCommitEvm, MainBuilder, MainContext,
};
use std::collections::BTreeMap;
use stf_types::{block_env_hash, StfInput, StfJournal, JOURNAL_VERSION};

use crate::opcode_gadgets::install_top_50_opcode_gadgets;
use crate::policy::{CertifiedPolicyInspectorV4, ExecutionPolicyV4};
use crate::txenv::tx_env_from_raw;
use crate::{
    BlockOutcome, DbAccessMetrics, EvmProofWork, PreparedCodeCacheReport, StateMap, StfError,
    TransactionOutcome,
};

/// keccak256(RLP([keccak256(rawTx_0), ...])) — RAW 32 bytes (the protocol's
/// field-level header value is this reduced mod the BN254 scalar field).
pub fn tx_commitment_raw(raw_txs: &[impl AsRef<[u8]>]) -> B256 {
    let hashes: Vec<B256> = raw_txs.iter().map(|raw| keccak256(raw.as_ref())).collect();
    keccak256(alloy_rlp::encode(&hashes))
}

/// Execute one block and return the journal (see [`execute_block_full`]).
pub fn execute_block(input: &StfInput) -> Result<StfJournal, StfError> {
    execute_block_full(input).map(|o| o.journal)
}

/// Execute one block: verify pre-state root, run every raw tx through revm
/// (Osaka, free-gas L2 config), recompute the post MPT root.
pub fn execute_block_full(input: &StfInput) -> Result<BlockOutcome, StfError> {
    let mut state = StateMap::from_input(&input.state);
    install_input_block_hashes(&mut state, input)?;
    execute_block_on_state(input, state, None, true, 0, true, None)
}

/// Reference execution with prepared opcode gadgets disabled.
///
/// Production execution enables the gadget table. This hook exists for exact
/// result/gas differential tests and alternating performance measurements.
pub fn execute_block_full_without_opcode_gadgets(
    input: &StfInput,
) -> Result<BlockOutcome, StfError> {
    let mut state = StateMap::from_input(&input.state);
    install_input_block_hashes(&mut state, input)?;
    execute_block_on_state(input, state, None, true, 0, false, None)
}

/// Benchmark/reference hook for the two v5 state commitments. It executes the
/// identical Osaka transition and changes only the root calculation.
pub fn execute_block_full_v5_commitment(
    input: &StfInput,
    state_commitment: u8,
) -> Result<BlockOutcome, StfError> {
    let mut state = StateMap::from_input(&input.state);
    install_input_block_hashes(&mut state, input)?;
    execute_block_on_state(input, state, None, true, state_commitment, true, None)
}

/// Execute one block with an explicit prepared-artifact code-hash set. This is
/// mainly a profiling/parity hook; v4 batch execution installs the same cache
/// automatically from its validated policy and carries it across blocks.
pub fn execute_block_full_with_prepared_runtime(
    input: &StfInput,
    frozen_code_hashes: &BTreeMap<Address, B256>,
) -> Result<(BlockOutcome, PreparedCodeCacheReport), StfError> {
    let mut state = StateMap::from_input(&input.state);
    install_input_block_hashes(&mut state, input)?;
    let report = state
        .install_prepared_runtime_code(frozen_code_hashes)
        .map_err(StfError::CertifiedPolicy)?;
    execute_block_on_state(input, state, None, true, 0, true, None).map(|outcome| (outcome, report))
}

pub(crate) fn room_state_root_v5(state: &StateMap, mode: u8) -> Result<B256, StfError> {
    match mode {
        0 => Ok(state.state_root()),
        1 => Ok(state.sparse_state_root_v5()),
        _ => Err(StfError::LongLivedRoom(
            "unknown v5 state commitment mode".into(),
        )),
    }
}

/// `decoded_txs`, when present, is the already-decoded environment of every
/// raw transaction in `input`, in the same order. Callers that recovered the
/// signers for another reason pass them here so the guest never pays for the
/// same ECDSA recovery twice.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_block_on_state(
    input: &StfInput,
    state: StateMap,
    policy: Option<&ExecutionPolicyV4>,
    verify_pre_state_root: bool,
    state_commitment: u8,
    use_opcode_gadgets: bool,
    decoded_txs: Option<Vec<TxEnv>>,
) -> Result<BlockOutcome, StfError> {
    let use_opcode_gadgets = use_opcode_gadgets && !cfg!(feature = "disable-opcode-gadgets");
    if decoded_txs
        .as_ref()
        .is_some_and(|decoded| decoded.len() != input.raw_txs.len())
    {
        return Err(StfError::TxDecode(
            "pre-decoded transaction list does not match the block".into(),
        ));
    }
    let mut state = state;
    install_input_block_hashes(&mut state, input)?;
    if verify_pre_state_root {
        let computed = room_state_root_v5(&state, state_commitment)?;
        if computed != input.prev_state_root {
            return Err(StfError::PreRootMismatch {
                expected: input.prev_state_root,
                computed,
            });
        }
    }
    // Metrics belong to this block. The state itself is carried across a
    // multi-block batch, so reset counters before handing it to REVM to avoid
    // counting earlier block accesses more than once.
    state.access_metrics = DbAccessMetrics::default();

    let block_env = BlockEnv {
        number: U256::from(input.env.number),
        beneficiary: input.env.coinbase,
        timestamp: U256::from(input.env.timestamp),
        gas_limit: input.env.gas_limit,
        basefee: input.env.base_fee.to::<u64>(),
        difficulty: input.env.difficulty,
        prevrandao: Some(input.env.prev_randao),
        blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new(
            input.env.excess_blob_gas,
            BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
        )),
        // EIP-7843 (Amsterdam) slot number — irrelevant pre-Amsterdam.
        slot_num: 0,
    };

    let chain_id = input.env.chain_id;
    let ctx = Context::mainnet()
        .with_db(state)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.set_spec_and_mainnet_gas_params(SpecId::OSAKA);
        })
        .modify_block_chained(|b| *b = block_env);
    let legacy_policy;
    let inspector_policy = if let Some(policy) = policy {
        policy
    } else {
        legacy_policy = ExecutionPolicyV4::legacy_unrestricted();
        &legacy_policy
    };
    let mut evm = ctx.build_mainnet_with_inspector(CertifiedPolicyInspectorV4::new(
        inspector_policy,
        use_opcode_gadgets,
    ));
    if use_opcode_gadgets {
        install_top_50_opcode_gadgets(&mut evm.instruction);
    }

    let mut gas_used = 0u64;
    let mut transactions = Vec::with_capacity(input.raw_txs.len());
    let mut prepared = decoded_txs.map(Vec::into_iter);
    for raw in &input.raw_txs {
        let tx_env = match prepared.as_mut() {
            Some(decoded) => decoded.next().ok_or_else(|| {
                StfError::TxDecode("pre-decoded transaction list is exhausted".into())
            })?,
            None => tx_env_from_raw(raw.as_ref(), chain_id)?,
        };
        evm.inspector.reset();
        evm.inspector
            .validate_transaction_entry(tx_env.caller, &tx_env.kind, tx_env.data.as_ref())
            .map_err(StfError::CertifiedPolicy)?;
        let result = evm
            .inspect_tx_commit(tx_env)
            .map_err(|e| StfError::TxExecution(format!("{e:?}")))?;
        transactions.push(TransactionOutcome {
            transaction_hash: keccak256(raw.as_ref()),
            status: u8::from(!result.is_success()),
        });
        if let Some(error) = evm.inspector.violation.clone() {
            return Err(StfError::CertifiedPolicy(error));
        }
        if let Some(error) = evm.ctx_mut().db_mut().access_violation.clone() {
            return Err(StfError::TxExecution(error.to_string()));
        }
        // Revert / Halt are valid room state transitions (nonce bump only);
        // the ethereumjs sequencer includes them too.
        gas_used = gas_used
            .checked_add(result.gas_used())
            .ok_or(StfError::BlockGasLimit {
                used: u64::MAX,
                limit: input.env.gas_limit,
            })?;
        // The engine enforces the cumulative block budget while building; a
        // guest that did not would accept blocks outside the L2 profile.
        if gas_used > input.env.gas_limit {
            return Err(StfError::BlockGasLimit {
                used: gas_used,
                limit: input.env.gas_limit,
            });
        }
    }

    // The EVM owns the StateMap. Execution is finished, so move that database
    // out of the consumed context instead of cloning every account, storage
    // map and prepared bytecode cache at each L2 block boundary.
    let inspector_work = evm.inspector.proof_work();
    let post_state = evm.ctx.journaled_state.database;
    let post_state_root = room_state_root_v5(&post_state, state_commitment)?;
    let state_accounts = post_state.accounts.len() as u64;
    let state_storage_slots = post_state
        .accounts
        .values()
        .map(|account| account.storage.len() as u64)
        .sum();
    let state_code_bytes = post_state
        .accounts
        .values()
        .map(|account| account.code.len() as u64)
        .sum();
    let proof_work = EvmProofWork {
        executed_gas: gas_used,
        transaction_count: input.raw_txs.len() as u64,
        opcode_steps: inspector_work.opcode_steps,
        fused_motif_hits: inspector_work.fused_motif_hits,
        fused_motif_opcodes: inspector_work.fused_motif_opcodes,
        keccak_opcodes: inspector_work.keccak_opcodes,
        call_opcodes: inspector_work.call_opcodes,
        precompile_calls: inspector_work.precompile_calls,
        max_memory_bytes: inspector_work.max_memory_bytes,
        db: post_state.access_metrics,
        state_accounts,
        state_storage_slots,
        state_code_bytes,
    };

    Ok(BlockOutcome {
        journal: StfJournal {
            v: JOURNAL_VERSION,
            room_id: input.room_id,
            block_number: input.block_number,
            prev_state_root: input.prev_state_root,
            post_state_root,
            tx_commitment: tx_commitment_raw(&input.raw_txs),
            // Bind the environment that produced these roots (see
            // stf_types::block_env_hash).
            env_hash: block_env_hash(&input.env),
        },
        gas_used,
        proof_work,
        post_state,
        transactions,
    })
}

fn install_input_block_hashes(state: &mut StateMap, input: &StfInput) -> Result<(), StfError> {
    let history = input
        .block_hashes
        .iter()
        .map(|entry| (entry.number, entry.hash))
        .collect::<Vec<_>>();
    state
        .install_block_hashes(input.env.number, &history)
        .map_err(StfError::BlockHashHistory)
}
