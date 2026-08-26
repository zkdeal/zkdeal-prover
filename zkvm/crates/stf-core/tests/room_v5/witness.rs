//! The v5 batch witnesses under test and the mutators the guard tests drive
//! them with.

use std::collections::BTreeMap;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount, EMPTY_ROOT_HASH};
use stf_core::{execute_block_full, execute_block_full_v5_commitment, StateMap};
use stf_types::{
    batch_block_data_hash_v5, canonical_batch_data_v5, cold_template_id_v5,
    execution_policy_hash_v5, forced_outcomes_hash_v5, import_root_v5, inbox_records_hash_v5,
    liabilities_hash_v5, room_chain_id_v5, roster_changes_hash_v5, roster_root_v5,
    storage_keys_root_v5, withdrawal_root_v5, AccountState, AdmissionOutcomeV5, AssetLiabilityV5,
    BatchBlockV5, BatchInputV5, BatchJournalV5, CallRuleV5, CertifiedImportBindingV5,
    CodeCommitmentV5, CompactAccountWitnessV4, CompactStateWitnessV4, CompactStorageWitnessV4,
    DepositV5, ExecutionPolicyV5, ExitAssetBindingV5, ExitBindingV5, ForcedTransactionV5,
    L1ImportWitnessV5, L1MirrorBindingV5, L1StorageSlotV5, ParticipantRegistryBindingV5,
    RosterMemberV5, StorageNamespaceV5, WithdrawalV5,
};

use crate::support::{
    account_state, compact_state, env, exit_queue_runtime_code, sender, sign_call, sign_exit_call,
    EXIT_CALL_SELECTOR, EXIT_QUEUE_COUNT_SLOT, EXIT_QUEUE_RECORDS_BASE_SLOT, GAS_LIMIT, ROOM_ID,
};

pub(crate) fn valid_batch() -> BatchInputV5 {
    valid_batch_with_deposits(Vec::new())
}

/// `valid_batch` whose batch additionally crosses `(deposit, admission fee)`
/// pairs: the blocks execute from the opening state with each net credit
/// applied, exactly the way the guest derives the consumption-time credit.
pub(crate) fn valid_batch_with_deposits(deposits: Vec<(DepositV5, U256)>) -> BatchInputV5 {
    let deployment = B256::repeat_byte(0x11);
    let contract = Address::repeat_byte(0x44);
    let chain_id = room_chain_id_v5(deployment, ROOM_ID);
    let opening = account_state(contract);
    let pre_root = StateMap::from_input(&opening).state_root();
    let mut credited = opening.clone();
    credit_deposits(&mut credited, &deposits, None);
    let credited_root = StateMap::from_input(&credited).state_root();
    let raw0 = sign_call(chain_id, 0, contract, 9);
    let first = execute_block_full(&stf_types::StfInput {
        room_id: ROOM_ID,
        block_number: 1,
        prev_state_root: credited_root,
        state: credited,
        raw_txs: vec![raw0.clone()],
        env: env(1, chain_id),
        block_hashes: vec![],
    })
    .unwrap();
    let raw1 = sign_call(chain_id, 1, contract, 10);
    let second_state = first.post_state.to_input_state();
    let second = execute_block_full(&stf_types::StfInput {
        room_id: ROOM_ID,
        block_number: 2,
        prev_state_root: first.journal.post_state_root,
        state: second_state,
        raw_txs: vec![raw1.clone()],
        env: env(2, chain_id),
        block_hashes: vec![],
    })
    .unwrap();

    let roster = vec![RosterMemberV5 {
        index: 0,
        member: sender(),
        joined_epoch: 1,
    }];
    let roster_root = roster_root_v5(&roster, 2).unwrap();
    let liabilities = vec![AssetLiabilityV5 {
        asset: Address::ZERO,
        pending: U256::ZERO,
        controlled: U256::from(100),
        claimable: U256::ZERO,
        paid: U256::ZERO,
    }];
    let policy = ExecutionPolicyV5 {
        state_commitment: 0,
        max_blocks_per_batch: 4,
        max_transactions_per_block: 32,
        max_gas_per_block: GAS_LIMIT,
        max_memory_bytes: 16 * 1024 * 1024,
        allow_contract_creation: false,
        allow_self_destruct: false,
        code: vec![CodeCommitmentV5 {
            address: contract,
            runtime_code_hash: keccak256([0x60, 0x04, 0x35, 0x5f, 0x55, 0x00]),
        }],
        calls: vec![CallRuleV5 {
            caller: Address::ZERO,
            target: contract,
            selectors: vec![[0x12, 0x34, 0x56, 0x78]],
            kinds: vec![0],
        }],
        storage: vec![StorageNamespaceV5 {
            contract,
            slot_prefix: U256::ZERO,
            prefix_bits: 0,
            writable: true,
        }],
        imports: vec![],
        participant_registry: Some(ParticipantRegistryBindingV5 {
            contract,
            root_slot: U256::from(10),
            epoch_slot: U256::from(11),
            count_slot: U256::from(12),
            capacity_slot: U256::from(13),
        }),
        exit: None,
    };
    let blocks = vec![
        BatchBlockV5 {
            block_number: 1,
            raw_txs: vec![raw0],
            env: env(1, chain_id),
            block_hashes: vec![],
            expected_post_state_root: first.journal.post_state_root,
        },
        BatchBlockV5 {
            block_number: 2,
            raw_txs: vec![raw1],
            env: env(2, chain_id),
            block_hashes: vec![],
            expected_post_state_root: second.journal.post_state_root,
        },
    ];
    let crossed = deposits
        .iter()
        .map(|(deposit, _)| deposit.clone())
        .collect::<Vec<_>>();
    let journal = BatchJournalV5 {
        protocol_version: 6,
        deployment_domain: deployment,
        room_id: ROOM_ID,
        authorization_mode: 0,
        cold_template_id: cold_template_id_v5(
            pre_root,
            execution_policy_hash_v5(&policy),
            B256::repeat_byte(0x55),
        ),
        proof_program_id: B256::repeat_byte(0x33),
        proof_system_version: B256::repeat_byte(0x55),
        policy_hash: execution_policy_hash_v5(&policy),
        batch_index: 1,
        start_l2_block: 1,
        end_l2_block: 2,
        pre_state_root: pre_root,
        post_state_root: second.journal.post_state_root,
        batch_data_hash: batch_block_data_hash_v5(&blocks, pre_root),
        canonical_data_hash: B256::ZERO,
        pre_participant_root: B256::repeat_byte(0x77),
        post_participant_root: B256::repeat_byte(0x77),
        pre_participant_epoch: 1,
        post_participant_epoch: 1,
        pre_participant_count: 1,
        post_participant_count: 1,
        participant_capacity: 128,
        pre_roster_root: roster_root,
        post_roster_root: roster_root,
        pre_roster_epoch: 1,
        post_roster_epoch: 1,
        pre_active_count: 1,
        post_active_count: 1,
        roster_change_cursor_before: 0,
        roster_change_cursor_after: 0,
        inbox_cursor_before: 0,
        inbox_cursor_after: crossed.len() as u64,
        inbox_records_hash: inbox_records_hash_v5(&crossed),
        admission_cursor_before: 0,
        admission_cursor_after: 0,
        admission_records_hash: stf_types::admission_records_hash_v5(&[]),
        forced_cursor_before: 0,
        forced_cursor_after: 0,
        forced_outcomes_hash: stf_types::forced_outcomes_hash_v5(&[]),
        import_cursor_before: 0,
        import_cursor_after: 0,
        imported_l1_block: 0,
        imported_l1_header_hash: B256::ZERO,
        imported_l1_state_root: B256::ZERO,
        import_root: B256::ZERO,
        outbox_epoch: 1,
        withdrawal_root: B256::ZERO,
        pre_liabilities_hash: liabilities_hash_v5(&liabilities),
        post_liabilities_hash: liabilities_hash_v5(&liabilities),
        roster_changes_hash: roster_changes_hash_v5(&[]),
        l1_inclusion_deadline: 1_000,
        close: false,
    };
    let mut input = BatchInputV5 {
        encoded_witness_bytes: 1,
        l1_chain_id: 31_337,
        journal,
        policy,
        roster_capacity: 2,
        pre_roster: roster.clone(),
        post_roster: roster,
        roster_changes: vec![],
        admissions: vec![],
        forced_transactions: vec![],
        canonical_batch_data: Bytes::new(),
        pre_liabilities: liabilities.clone(),
        post_liabilities: liabilities,
        deposits: crossed,
        withdrawals: vec![],
        withdrawal_capacity: 0,
        l1_import: None,
        compact_state: compact_state(&opening, contract),
        blocks,
    };
    for (deposit, _) in &deposits {
        if !deposit.refunded && deposit.asset == Address::ZERO {
            declare_absent_account(&mut input.compact_state, deposit.beneficiary);
        }
    }
    input
}

/// A consistent two-block validity-only batch: no checkpoint approvers,
/// public canonical calldata, transactions are their own authority, and the
/// policy carries the exit binding every provable validity-only room needs.
pub(crate) fn validity_only_batch() -> BatchInputV5 {
    exit_batch_with(ExitBatchOptionsV5::default())
}

/// The unprovable variant: a validity-only conversion of `valid_batch` whose
/// policy has no exit binding, kept only so the guard suite can prove the
/// guest refuses it outright.
pub(crate) fn validity_only_batch_without_exit() -> BatchInputV5 {
    let mut input = valid_batch();
    input.journal.authorization_mode = 1;
    input.pre_roster.clear();
    input.post_roster.clear();
    input.journal.pre_roster_root = B256::ZERO;
    input.journal.post_roster_root = B256::ZERO;
    input.journal.pre_active_count = 0;
    input.journal.post_active_count = 0;
    input.canonical_batch_data = Bytes::from(canonical_batch_data_v5(
        &input.blocks,
        input.journal.pre_state_root,
    ));
    input.journal.canonical_data_hash = keccak256(input.canonical_batch_data.as_ref());
    input
}

/// Mirror of the guest's consumption-time system credit for fixtures: each
/// non-refunded deposit's net value lands on the beneficiary before the
/// batch's blocks execute.
pub(crate) fn credit_deposits(
    state: &mut Vec<(Address, AccountState)>,
    deposits: &[(DepositV5, U256)],
    erc20_balance_slot: Option<U256>,
) {
    for (deposit, fee) in deposits {
        if deposit.refunded {
            continue;
        }
        let net = deposit.amount - fee;
        if net.is_zero() {
            continue;
        }
        if deposit.asset == Address::ZERO {
            if let Some((_, account)) = state
                .iter_mut()
                .find(|(address, _)| *address == deposit.beneficiary)
            {
                account.balance += net;
            } else {
                state.push((
                    deposit.beneficiary,
                    AccountState {
                        nonce: 0,
                        balance: net,
                        code: Bytes::new(),
                        storage: vec![],
                    },
                ));
            }
        } else {
            let balance_slot =
                erc20_balance_slot.expect("fixture ERC-20 deposits need a declared balance slot");
            let slot = erc20_balance_mapping_slot(deposit.beneficiary, balance_slot);
            let (_, token) = state
                .iter_mut()
                .find(|(address, _)| *address == Address::repeat_byte(0x44))
                .expect("fixture token contract is present");
            if let Some(entry) = token.storage.iter_mut().find(|(key, _)| *key == slot) {
                entry.1 += net;
            } else {
                token.storage.push((slot, net));
            }
        }
    }
    state.sort_by_key(|(address, _)| *address);
}

/// Declare `address` in the compact witness envelope as an absent account, so
/// the guest may create it (a deposit beneficiary receiving its credit).
pub(crate) fn declare_absent_account(witness: &mut CompactStateWitnessV4, address: Address) {
    if witness.accounts.iter().any(|account| account.address == address) {
        return;
    }
    witness.accounts.push(CompactAccountWitnessV4 {
        address,
        exists: false,
        canonical_storage_root: EMPTY_ROOT_HASH,
        ..Default::default()
    });
    witness.accounts.sort_by_key(|account| account.address);
}

/// Re-derive the policy commitment and the cold-template identity after a
/// fixture edits the policy or the opening root. The first batch of a room is
/// required to open at the state its registered template pinned.
pub(crate) fn rebind_policy(input: &mut BatchInputV5) {
    input.journal.policy_hash = execution_policy_hash_v5(&input.policy);
    input.journal.cold_template_id = cold_template_id_v5(
        input.journal.pre_state_root,
        input.journal.policy_hash,
        input.journal.proof_system_version,
    );
}

pub(crate) fn liabilities(controlled: u64, claimable: u64) -> Vec<AssetLiabilityV5> {
    vec![AssetLiabilityV5 {
        asset: Address::ZERO,
        pending: U256::ZERO,
        controlled: U256::from(controlled),
        claimable: U256::from(claimable),
        paid: U256::ZERO,
    }]
}

pub(crate) fn set_liabilities(
    input: &mut BatchInputV5,
    pre: Vec<AssetLiabilityV5>,
    post: Vec<AssetLiabilityV5>,
) {
    input.journal.pre_liabilities_hash = liabilities_hash_v5(&pre);
    input.journal.post_liabilities_hash = liabilities_hash_v5(&post);
    input.pre_liabilities = pre;
    input.post_liabilities = post;
}

pub(crate) fn set_forced(input: &mut BatchInputV5, forced: Vec<ForcedTransactionV5>) {
    input.journal.forced_cursor_before = 0;
    input.journal.forced_cursor_after = forced.len() as u64;
    input.journal.forced_outcomes_hash = forced_outcomes_hash_v5(&forced);
    input.forced_transactions = forced;
}

pub(crate) fn valid_batch_with_import() -> BatchInputV5 {
    let mut batch = valid_batch();
    let source = Address::repeat_byte(0x77);
    let source_key = U256::from(5);
    let source_value = U256::from(9);
    let storage_path = Nibbles::unpack(keccak256(source_key.to_be_bytes::<32>()).0);
    let mut storage_builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([storage_path]));
    storage_builder.add_leaf(storage_path, &alloy_rlp::encode(source_value));
    let source_storage_root = storage_builder.root();
    let storage_proof = storage_builder
        .take_proof_nodes()
        .matching_nodes_sorted(&storage_path)
        .into_iter()
        .map(|(_, node)| node)
        .collect();

    let source_code_hash = B256::repeat_byte(0x88);
    let account = TrieAccount {
        nonce: 3,
        balance: U256::from(100),
        storage_root: source_storage_root,
        code_hash: source_code_hash,
    };
    let account_path = Nibbles::unpack(keccak256(source).0);
    let mut account_builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([account_path]));
    account_builder.add_leaf(account_path, &alloy_rlp::encode(account));
    let state_root = account_builder.root();
    let account_proof = account_builder
        .take_proof_nodes()
        .matching_nodes_sorted(&account_path)
        .into_iter()
        .map(|(_, node)| node)
        .collect();

    let room_contract = Address::repeat_byte(0x44);
    let adapter_id = B256::repeat_byte(0xa1);
    let adapter_version = B256::repeat_byte(0xa2);
    batch.policy.imports.push(CertifiedImportBindingV5 {
        adapter_id,
        adapter_version,
        source,
        source_key,
        room_contract,
        room_slot: U256::ZERO,
    });
    rebind_policy(&mut batch);
    let import = L1ImportWitnessV5 {
        source_block: 123,
        expiry_block: 2_000,
        header_hash: B256::repeat_byte(0x90),
        state_root,
        source,
        source_nonce: 3,
        source_balance: U256::from(100),
        source_storage_root,
        source_code_hash,
        account_proof,
        storage_keys_root: storage_keys_root_v5(&[source_key]),
        adapter_id,
        adapter_version,
        storage: vec![L1StorageSlotV5 {
            key: source_key,
            value: source_value,
            proof: storage_proof,
        }],
        mirror_bindings: vec![L1MirrorBindingV5 {
            source_key,
            room_contract,
            room_slot: U256::ZERO,
        }],
    };
    batch.journal.import_cursor_after = 1;
    batch.journal.imported_l1_block = import.source_block;
    batch.journal.imported_l1_header_hash = import.header_hash;
    batch.journal.imported_l1_state_root = import.state_root;
    batch.journal.import_root = import_root_v5(batch.journal.room_id, batch.l1_chain_id, &import);
    batch.l1_import = Some(import);
    batch
}

pub(crate) fn sparse_batch() -> BatchInputV5 {
    let mut batch = valid_batch();
    let contract = Address::repeat_byte(0x44);
    let opening = account_state(contract);
    batch.policy.state_commitment = 1;
    let pre_root = StateMap::from_input(&opening).sparse_state_root_v5();
    let first = execute_block_full_v5_commitment(
        &stf_types::StfInput {
            room_id: ROOM_ID,
            block_number: 1,
            prev_state_root: pre_root,
            state: opening.clone(),
            raw_txs: batch.blocks[0].raw_txs.clone(),
            env: batch.blocks[0].env.clone(),
            block_hashes: vec![],
        },
        1,
    )
    .unwrap();
    let second = execute_block_full_v5_commitment(
        &stf_types::StfInput {
            room_id: ROOM_ID,
            block_number: 2,
            prev_state_root: first.journal.post_state_root,
            state: first.post_state.to_input_state(),
            raw_txs: batch.blocks[1].raw_txs.clone(),
            env: batch.blocks[1].env.clone(),
            block_hashes: vec![],
        },
        1,
    )
    .unwrap();
    batch.journal.pre_state_root = pre_root;
    rebind_policy(&mut batch);
    batch.blocks[0].expected_post_state_root = first.journal.post_state_root;
    batch.blocks[1].expected_post_state_root = second.journal.post_state_root;
    batch.journal.post_state_root = second.journal.post_state_root;
    batch.journal.batch_data_hash = batch_block_data_hash_v5(&batch.blocks, pre_root);
    batch
}

pub(crate) fn forced_entry(raw: Bytes, status: u8, reason_hash: B256) -> ForcedTransactionV5 {
    ForcedTransactionV5 {
        forced_id: 1,
        outcome: AdmissionOutcomeV5 {
            admission_id: 1,
            transaction_hash: keccak256(raw.as_ref()),
            status,
            l2_block_number: 0,
            transaction_index: 0,
            reason_hash,
        },
        raw_transaction: raw,
    }
}

// --- Exit-queue fixtures -------------------------------------------------

pub(crate) fn exit_queue() -> Address {
    Address::repeat_byte(0x45)
}

/// A second funded EOA so the close sweep has more than one pro-rata claimant.
pub(crate) fn exit_holder() -> Address {
    Address::repeat_byte(0x33)
}

pub(crate) fn exit_fallback() -> Address {
    Address::repeat_byte(0xfb)
}

/// L1 asset identity of the fixture's optional ERC-20 exit asset.
pub(crate) fn exit_erc20_asset() -> Address {
    Address::repeat_byte(0x77)
}

pub(crate) fn erc20_balance_mapping_slot(account: Address, slot: U256) -> U256 {
    let mut encoded = [0u8; 64];
    encoded[12..32].copy_from_slice(account.as_slice());
    encoded[32..].copy_from_slice(&slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(encoded).0)
}

pub(crate) struct ExitBatchOptionsV5 {
    pub(crate) queue_code: Bytes,
    /// Opening value of the queue's count slot (nonzero models prior records).
    pub(crate) opening_count: u64,
    /// Declares an ERC-20 exit asset backed by the app contract's balance
    /// mapping at this slot (holder/sender mapping slots become part of the
    /// declared envelope).
    pub(crate) erc20_balance_slot: Option<U256>,
    /// Raw transactions of the batch's second block; empty means one more
    /// plain app call. Sign with nonce 1.. (or 3.. after `second_epoch`).
    pub(crate) exit_calls: Vec<Bytes>,
    pub(crate) single_block: bool,
    pub(crate) close: bool,
    /// Replay one app-only batch first and build this batch as index 2.
    pub(crate) second_epoch: bool,
    /// Crossed L1 deposits as `(deposit, admission fee withheld)` pairs: the
    /// blocks execute from the opening state with each net credit applied,
    /// mirroring the guest's consumption-time system credit.
    pub(crate) deposits: Vec<(DepositV5, U256)>,
    /// Extra opening storage words seeded on the queue contract.
    pub(crate) opening_queue_storage: Vec<(U256, U256)>,
    /// How many exit records the declared witness envelope covers.
    pub(crate) declared_queue_records: u64,
}

impl Default for ExitBatchOptionsV5 {
    fn default() -> Self {
        Self {
            queue_code: exit_queue_runtime_code(),
            opening_count: 0,
            erc20_balance_slot: None,
            exit_calls: Vec::new(),
            single_block: false,
            close: false,
            second_epoch: false,
            deposits: Vec::new(),
            opening_queue_storage: Vec::new(),
            declared_queue_records: 8,
        }
    }
}

fn exit_account_state(
    queue_code: &Bytes,
    opening_count: u64,
    extra_queue_storage: &[(U256, U256)],
) -> Vec<(Address, AccountState)> {
    let contract = Address::repeat_byte(0x44);
    let mut state = account_state(contract);
    for (address, account) in &mut state {
        // Small round balances keep the pro-rata floors of the sweep tests
        // readable: sender 300 + holder 100 = 400 total.
        if *address == sender() {
            account.balance = U256::from(300u64);
        }
    }
    state.push((
        exit_holder(),
        AccountState {
            nonce: 0,
            balance: U256::from(100u64),
            code: Bytes::new(),
            storage: vec![],
        },
    ));
    let mut queue_storage = if opening_count == 0 {
        vec![]
    } else {
        vec![(EXIT_QUEUE_COUNT_SLOT, U256::from(opening_count))]
    };
    queue_storage.extend_from_slice(extra_queue_storage);
    state.push((
        exit_queue(),
        AccountState {
            nonce: 1,
            balance: U256::ZERO,
            code: queue_code.clone(),
            storage: queue_storage,
        },
    ));
    state.sort_by_key(|(address, _)| *address);
    state
}

/// Compact witness over an arbitrary account set with explicitly declared
/// (possibly zero-valued) storage slots: everything the batch will read or
/// write must be inside this envelope.
fn exit_compact_state(
    state: &[(Address, AccountState)],
    declared: &BTreeMap<Address, Vec<U256>>,
) -> CompactStateWitnessV4 {
    let mut accounts = vec![CompactAccountWitnessV4 {
        address: Address::ZERO,
        exists: false,
        canonical_storage_root: EMPTY_ROOT_HASH,
        ..Default::default()
    }];
    accounts.extend(state.iter().map(|(address, account)| {
        let mut slots = account
            .storage
            .iter()
            .map(|(slot, value)| (*slot, *value))
            .collect::<BTreeMap<_, _>>();
        for slot in declared.get(address).into_iter().flatten() {
            slots.entry(*slot).or_insert(U256::ZERO);
        }
        CompactAccountWitnessV4 {
            address: *address,
            exists: true,
            nonce: account.nonce,
            balance: account.balance,
            code: account.code.clone(),
            canonical_storage_root: EMPTY_ROOT_HASH,
            account_proof: vec![],
            storage: slots
                .into_iter()
                .map(|(slot, value)| CompactStorageWitnessV4 {
                    slot,
                    value,
                    proof: vec![],
                })
                .collect(),
        }
    }));
    accounts.sort_by_key(|account| account.address);
    CompactStateWitnessV4 {
        canonical_state_root: B256::ZERO,
        accounts,
    }
}

struct ExecutedExitBlocks {
    blocks: Vec<BatchBlockV5>,
    post_root: B256,
    terminal: Vec<(Address, AccountState)>,
}

fn run_exit_blocks(
    chain_id: u64,
    opening: Vec<(Address, AccountState)>,
    start_number: u64,
    txs_per_block: Vec<Vec<Bytes>>,
) -> ExecutedExitBlocks {
    let pre_root = StateMap::from_input(&opening).state_root();
    let mut state = opening;
    let mut root = pre_root;
    let mut blocks = Vec::new();
    for (offset, raw_txs) in txs_per_block.into_iter().enumerate() {
        let number = start_number + offset as u64;
        let outcome = execute_block_full(&stf_types::StfInput {
            room_id: ROOM_ID,
            block_number: number,
            prev_state_root: root,
            state: state.clone(),
            raw_txs: raw_txs.clone(),
            env: env(number, chain_id),
            block_hashes: vec![],
        })
        .expect("exit fixture block executes");
        blocks.push(BatchBlockV5 {
            block_number: number,
            raw_txs,
            env: env(number, chain_id),
            block_hashes: vec![],
            expected_post_state_root: outcome.journal.post_state_root,
        });
        root = outcome.journal.post_state_root;
        state = outcome.post_state.to_input_state();
    }
    ExecutedExitBlocks {
        blocks,
        post_root: root,
        terminal: state,
    }
}

fn exit_policy(queue_code: &Bytes, erc20_balance_slot: Option<U256>) -> ExecutionPolicyV5 {
    let contract = Address::repeat_byte(0x44);
    let queue = exit_queue();
    let mut assets = vec![ExitAssetBindingV5 {
        asset: Address::ZERO,
        kind: 0,
        token: Address::ZERO,
        balance_slot: U256::ZERO,
    }];
    if let Some(balance_slot) = erc20_balance_slot {
        assets.push(ExitAssetBindingV5 {
            asset: exit_erc20_asset(),
            kind: 1,
            token: contract,
            balance_slot,
        });
    }
    ExecutionPolicyV5 {
        state_commitment: 0,
        max_blocks_per_batch: 4,
        max_transactions_per_block: 32,
        max_gas_per_block: GAS_LIMIT,
        max_memory_bytes: 16 * 1024 * 1024,
        allow_contract_creation: false,
        allow_self_destruct: false,
        code: vec![
            CodeCommitmentV5 {
                address: contract,
                runtime_code_hash: keccak256([0x60, 0x04, 0x35, 0x5f, 0x55, 0x00]),
            },
            CodeCommitmentV5 {
                address: queue,
                runtime_code_hash: keccak256(queue_code.as_ref()),
            },
        ],
        calls: vec![
            CallRuleV5 {
                caller: Address::ZERO,
                target: contract,
                selectors: vec![[0x12, 0x34, 0x56, 0x78]],
                kinds: vec![0],
            },
            CallRuleV5 {
                caller: Address::ZERO,
                target: queue,
                selectors: vec![EXIT_CALL_SELECTOR],
                kinds: vec![0],
            },
        ],
        storage: vec![
            StorageNamespaceV5 {
                contract,
                slot_prefix: U256::ZERO,
                prefix_bits: 0,
                writable: true,
            },
            StorageNamespaceV5 {
                contract: queue,
                slot_prefix: U256::ZERO,
                prefix_bits: 0,
                writable: true,
            },
        ],
        imports: vec![],
        participant_registry: Some(ParticipantRegistryBindingV5 {
            contract,
            root_slot: U256::from(10),
            epoch_slot: U256::from(11),
            count_slot: U256::from(12),
            capacity_slot: U256::from(13),
        }),
        exit: Some(ExitBindingV5 {
            queue_contract: queue,
            count_slot: EXIT_QUEUE_COUNT_SLOT,
            records_base_slot: EXIT_QUEUE_RECORDS_BASE_SLOT,
            assets,
            fallback_recipient: exit_fallback(),
        }),
    }
}

/// Build a consistent validity-only batch whose policy carries the exit
/// binding, with no withdrawals minted yet: tests layer expectations on top
/// via `set_liabilities` and `set_withdrawals`.
pub(crate) fn exit_batch_with(options: ExitBatchOptionsV5) -> BatchInputV5 {
    let deployment = B256::repeat_byte(0x11);
    let contract = Address::repeat_byte(0x44);
    let chain_id = room_chain_id_v5(deployment, ROOM_ID);
    let opening = exit_account_state(
        &options.queue_code,
        options.opening_count,
        &options.opening_queue_storage,
    );

    let (batch_opening, batch_index, start_l2_block) = if options.second_epoch {
        let history = run_exit_blocks(
            chain_id,
            opening,
            1,
            vec![
                vec![sign_call(chain_id, 0, contract, 9)],
                vec![sign_call(chain_id, 1, contract, 10)],
            ],
        );
        (history.terminal, 2u64, 3u64)
    } else {
        (opening, 1u64, 1u64)
    };

    let first_block_txs = if options.second_epoch {
        vec![sign_call(chain_id, 2, contract, 11)]
    } else {
        vec![sign_call(chain_id, 0, contract, 9)]
    };
    let mut txs_per_block = vec![first_block_txs];
    if !options.single_block {
        txs_per_block.push(if options.exit_calls.is_empty() {
            if options.second_epoch {
                vec![sign_call(chain_id, 3, contract, 12)]
            } else {
                vec![sign_call(chain_id, 1, contract, 10)]
            }
        } else {
            options.exit_calls.clone()
        });
    }
    let pre_root = StateMap::from_input(&batch_opening).state_root();
    let mut credited_opening = batch_opening.clone();
    credit_deposits(
        &mut credited_opening,
        &options.deposits,
        options.erc20_balance_slot,
    );
    let executed = run_exit_blocks(chain_id, credited_opening, start_l2_block, txs_per_block);

    let mut declared = BTreeMap::new();
    let mut contract_slots = vec![U256::ZERO];
    if let Some(balance_slot) = options.erc20_balance_slot {
        contract_slots.push(erc20_balance_mapping_slot(sender(), balance_slot));
        contract_slots.push(erc20_balance_mapping_slot(exit_holder(), balance_slot));
    }
    declared.insert(contract, contract_slots);
    let mut queue_slots = vec![EXIT_QUEUE_COUNT_SLOT];
    for record in 0..options.declared_queue_records {
        for word in 0..3u64 {
            queue_slots.push(EXIT_QUEUE_RECORDS_BASE_SLOT + U256::from(3 * record + word));
        }
    }
    declared.insert(exit_queue(), queue_slots);

    let policy = exit_policy(&options.queue_code, options.erc20_balance_slot);
    let policy_hash = execution_policy_hash_v5(&policy);
    let proof_system_version = B256::repeat_byte(0x55);
    let liabilities = liabilities(100, 0);
    let crossed = options
        .deposits
        .iter()
        .map(|(deposit, _)| deposit.clone())
        .collect::<Vec<_>>();
    let canonical = canonical_batch_data_v5(&executed.blocks, pre_root);
    let journal = BatchJournalV5 {
        protocol_version: 6,
        deployment_domain: deployment,
        room_id: ROOM_ID,
        authorization_mode: 1,
        cold_template_id: cold_template_id_v5(pre_root, policy_hash, proof_system_version),
        proof_program_id: B256::repeat_byte(0x33),
        proof_system_version,
        policy_hash,
        batch_index,
        start_l2_block,
        end_l2_block: start_l2_block + executed.blocks.len() as u64 - 1,
        pre_state_root: pre_root,
        post_state_root: executed.post_root,
        batch_data_hash: batch_block_data_hash_v5(&executed.blocks, pre_root),
        canonical_data_hash: keccak256(&canonical),
        pre_participant_root: B256::repeat_byte(0x77),
        post_participant_root: B256::repeat_byte(0x77),
        pre_participant_epoch: 1,
        post_participant_epoch: 1,
        pre_participant_count: 1,
        post_participant_count: 1,
        participant_capacity: 128,
        pre_roster_root: B256::ZERO,
        post_roster_root: B256::ZERO,
        pre_roster_epoch: 1,
        post_roster_epoch: 1,
        pre_active_count: 0,
        post_active_count: 0,
        roster_change_cursor_before: 0,
        roster_change_cursor_after: 0,
        inbox_cursor_before: 0,
        inbox_cursor_after: crossed.len() as u64,
        inbox_records_hash: inbox_records_hash_v5(&crossed),
        admission_cursor_before: 0,
        admission_cursor_after: 0,
        admission_records_hash: stf_types::admission_records_hash_v5(&[]),
        forced_cursor_before: 0,
        forced_cursor_after: 0,
        forced_outcomes_hash: stf_types::forced_outcomes_hash_v5(&[]),
        import_cursor_before: 0,
        import_cursor_after: 0,
        imported_l1_block: 0,
        imported_l1_header_hash: B256::ZERO,
        imported_l1_state_root: B256::ZERO,
        import_root: B256::ZERO,
        outbox_epoch: batch_index,
        withdrawal_root: B256::ZERO,
        pre_liabilities_hash: liabilities_hash_v5(&liabilities),
        post_liabilities_hash: liabilities_hash_v5(&liabilities),
        roster_changes_hash: roster_changes_hash_v5(&[]),
        l1_inclusion_deadline: 1_000,
        close: options.close,
    };
    let mut input = BatchInputV5 {
        encoded_witness_bytes: 1,
        l1_chain_id: 31_337,
        journal,
        policy,
        roster_capacity: 2,
        pre_roster: vec![],
        post_roster: vec![],
        roster_changes: vec![],
        admissions: vec![],
        forced_transactions: vec![],
        canonical_batch_data: Bytes::from(canonical),
        pre_liabilities: liabilities.clone(),
        post_liabilities: liabilities,
        deposits: crossed,
        withdrawals: vec![],
        withdrawal_capacity: 0,
        l1_import: None,
        compact_state: exit_compact_state(&batch_opening, &declared),
        blocks: executed.blocks,
    };
    for (deposit, _) in &options.deposits {
        if !deposit.refunded && deposit.asset == Address::ZERO {
            declare_absent_account(&mut input.compact_state, deposit.beneficiary);
        }
    }
    input
}

/// Bind an exact withdrawal expectation into the witness and the journal.
pub(crate) fn set_withdrawals(
    input: &mut BatchInputV5,
    withdrawals: Vec<WithdrawalV5>,
    capacity: u64,
) {
    input.withdrawal_capacity = capacity;
    input.journal.withdrawal_root = withdrawal_root_v5(
        input.journal.deployment_domain,
        input.journal.room_id,
        input.journal.outbox_epoch,
        &withdrawals,
        capacity,
    )
    .unwrap_or(B256::ZERO);
    input.withdrawals = withdrawals;
}

/// One in-room exit record (recipient 0xbe, native, 40) already reflected in
/// the withdrawal tree and the liability transition.
pub(crate) fn validity_only_exit_batch() -> BatchInputV5 {
    let chain_id = room_chain_id_v5(B256::repeat_byte(0x11), ROOM_ID);
    let recipient = Address::repeat_byte(0xbe);
    let mut input = exit_batch_with(ExitBatchOptionsV5 {
        exit_calls: vec![sign_exit_call(
            chain_id,
            1,
            exit_queue(),
            recipient,
            Address::ZERO,
            40,
        )],
        ..Default::default()
    });
    set_liabilities(&mut input, liabilities(100, 0), liabilities(60, 40));
    set_withdrawals(
        &mut input,
        vec![WithdrawalV5 {
            index: 0,
            roster_epoch: 1,
            recipient,
            asset: Address::ZERO,
            amount: U256::from(40),
        }],
        1,
    );
    input
}
