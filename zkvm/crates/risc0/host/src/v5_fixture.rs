//! Deterministic v5 room fixture.
//!
//! `prepare` turns one JSON request into the exact pair of witnesses the
//! prover proves — a cold template and the first room batch — and validates
//! both natively before returning them. The pieces live in `config` (caps,
//! request parsing and range checks), `contracts` (the per-address
//! descriptors), `policy` (the certified execution policy), `bytecode`
//! (synthesized runtime code), `card` (the hidden-card duel workload), `blocks`
//! (transaction construction), `merkle` (the participant tree), `signing`
//! (keys, transactions and the roster) and `state` (opening state, compact
//! witness and the L1 import).

mod blocks;
mod bytecode;
mod card;
mod config;
mod continuation;
mod contracts;
mod json;
mod merkle;
mod policy;
mod raw;
mod selectors;
mod signing;
mod state;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use stf_core::{execute_block_full_v5_commitment, StateMap, TOP_50_SOLIDITY_MOTIFS};
use stf_types::{
    batch_block_data_hash_v5, canonical_batch_data_v5, cold_template_id_v5,
    execution_policy_hash_v5, liabilities_hash_v5, room_chain_id_v5, roster_changes_hash_v5,
    roster_root_v5, AssetLiabilityV5, BatchBlockV5, BatchInputV5, BatchJournalV5,
    ColdTemplateInputV5,
};

pub use self::capability::room_capabilities;

use self::blocks::build_blocks;
use self::config::{
    parse_fixture_config, CARD_DUEL_WORKLOAD, MAX_ACTIVE_SIGNERS, MAX_IMPORTED_VARIABLES,
    MAX_RESIDENT_ACCOUNTS, MAX_RESIDENT_STORAGE_SLOTS, MAX_TOUCHED_CONTRACTS,
    PRODUCTION_MINIMUM_DEPOSIT_CONFIRMATIONS, PRODUCTION_MINIMUM_IMPORT_CONFIRMATIONS,
};
use self::continuation::{batch_opening, replay_history, ColdOpening};
use self::contracts::{exit_queue_descriptor, resolve_contracts, RoomContracts};
use self::merkle::participant_tree;
use self::policy::{
    check_call_rules, check_registry_namespace, fixture_policy, rule_selectors, selector_allowed,
    PolicyInputs,
};
use self::raw::{
    check_senders_are_seated, client_selectors, inspect_client_transactions, ClientTransaction,
};
use self::selectors::resolve_call_selectors;
use self::signing::{env, roster, signer_address};
use self::state::{compact_state, make_import, opening_state, registry_view, LegacySeed};

mod capability;
#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod continuation_tests;
#[cfg(test)]
mod request_tests;

pub fn prepare(raw: &str, image_id: [u8; 32]) -> Result<Value> {
    let config = parse_fixture_config(raw)?;
    let workload = config.workload.clone();
    let RoomContracts {
        mut contracts,
        registry: registry_contract,
        descriptor_room,
    } = resolve_contracts(&config)?;
    let exit_queue = exit_queue_descriptor();
    if contracts
        .iter()
        .any(|contract| contract.address == exit_queue.address)
    {
        bail!("a room contract collides with the synthetic exit-queue address");
    }
    contracts.push(exit_queue);
    contracts.sort_by_key(|contract| contract.address);
    let registry_slots = config.registry.slots;
    check_registry_namespace(&contracts, registry_contract, registry_slots)
        .map_err(|error| anyhow!("{error}"))?;
    if let Some(rules) = &config.call_rules {
        check_call_rules(&contracts, rules).map_err(|error| anyhow!("{error}"))?;
    }

    let mut participant_levels = participant_tree(
        config.participant_capacity,
        config.registered_participants,
    );
    let generated_participant_root = participant_levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .context("participant tree root is missing")?;
    // The room chain id binds every signature the batch carries, so it has to
    // be known before the client-signed envelopes can be checked, and the
    // senders they recover to have to be known before the opening state seats
    // its accounts.
    let chain_id = room_chain_id_v5(config.deployment_domain, config.room_id);
    let client: Vec<ClientTransaction> = match &config.raw_transactions {
        Some(blocks) => inspect_client_transactions(blocks, chain_id)?,
        None => Vec::new(),
    };
    let mut signers = (0..config.signer_accounts)
        .map(signer_address)
        .collect::<Vec<_>>();
    for extra in &config.sender_accounts {
        if !signers.contains(extra) {
            signers.push(*extra);
        }
    }
    check_senders_are_seated(&client, &signers)?;
    let legacy_seed = (!descriptor_room).then(|| LegacySeed {
        registry_contract,
        registry: registry_slots,
        resident_storage_slots: config.resident_storage_slots,
        imported_variables: config.imported_variables,
        workload: workload.as_str(),
        registered_participants: config.registered_participants,
        participant_capacity: config.participant_capacity,
        participant_root: generated_participant_root,
        initial_storage: &config.initial_storage,
    });
    let state = opening_state(
        &contracts,
        &signers,
        config.resident_accounts,
        legacy_seed.as_ref(),
    );
    // The journal's opening registry is read out of the state that is actually
    // proved, never out of the request. A caller-supplied `initialStorage`
    // override of the root, epoch or count would otherwise silently disagree
    // with the journal and be rejected by the guest after a full prepare.
    let (initial_participant_root, opening_epoch, opening_count, opening_capacity) =
        registry_view(&state, registry_contract, registry_slots)?;
    if opening_capacity != config.participant_capacity {
        bail!(
            "the opening participant capacity slot holds {opening_capacity}, but the request asks \
             for {}",
            config.participant_capacity
        );
    }
    let state_map = StateMap::from_input(&state);
    let initial_state_root = match config.state_commitment {
        0 => state_map.state_root(),
        1 => state_map.sparse_state_root_v5(),
        _ => unreachable!(),
    };
    let mut execution_state = state.clone();
    let mut l1_import = None;
    let mut certified_imports = Vec::new();
    if config.imported_variables > 0 {
        let (import, certified) = make_import(
            config.room_id,
            config.l1_chain_id,
            config.l1_inclusion_deadline,
            registry_contract,
            config.resident_storage_slots,
            config.imported_variables,
        )?;
        let account = execution_state
            .iter_mut()
            .find(|(address, _)| *address == registry_contract)
            .expect("primary room contract is present");
        for (binding, slot) in import.mirror_bindings.iter().zip(&import.storage) {
            let destination = account
                .1
                .storage
                .iter_mut()
                .find(|(key, _)| *key == binding.room_slot)
                .expect("every imported destination is represented in the witness");
            destination.1 = slot.value;
        }
        l1_import = Some(import);
        certified_imports = certified;
    }
    execution_state.sort_by_key(|(address, _)| *address);
    let execution_pre_root = match config.state_commitment {
        0 => StateMap::from_input(&execution_state).state_root(),
        1 => StateMap::from_input(&execution_state).sparse_state_root_v5(),
        _ => unreachable!(),
    };

    let room_blocks = build_blocks(
        &config,
        chain_id,
        &contracts,
        registry_contract,
        &client,
        &mut participant_levels,
    )?;
    // Every Merkle path the blocks carry was derived from the host's own tree.
    // If the opening root does not equal that tree's root the first proof is
    // rejected on chain-state grounds nobody can debug from the failure.
    if room_blocks.uses_participant_proofs
        && initial_participant_root != generated_participant_root
    {
        bail!(
            "the opening participant root differs from the tree the fixture built its proofs \
             against; a room whose transactions carry Merkle paths cannot override the root slot"
        );
    }
    let transaction_count = room_blocks.transaction_count();
    let raw0 = room_blocks.first;
    let raw1 = room_blocks.second;

    // Everything the room already proved is replayed before the requested
    // batch is built, so batch n's opening state is derived from the same cold
    // template batch one opened at rather than remembered between calls.
    let replay = replay_history(
        &config,
        chain_id,
        &room_blocks.history,
        execution_state,
        execution_pre_root,
    )?;
    let opening = batch_opening(
        &config,
        ColdOpening {
            state: &state,
            root: initial_state_root,
            participant_root: initial_participant_root,
            participant_epoch: opening_epoch,
            participant_count: opening_count,
        },
        &replay,
        registry_contract,
        registry_slots,
        l1_import,
    )?;
    let start_l2_block = replay.height + 1;
    let end_l2_block = start_l2_block + 1;
    let first = execute_block_full_v5_commitment(
        &stf_types::StfInput {
            room_id: config.room_id,
            block_number: start_l2_block,
            prev_state_root: replay.root,
            state: replay.state,
            raw_txs: raw0.clone(),
            env: env(start_l2_block, chain_id),
            block_hashes: vec![],
        },
        config.state_commitment,
    )
    .map_err(|error| anyhow!("prepare first v5 block: {error}"))?;
    let second = execute_block_full_v5_commitment(
        &stf_types::StfInput {
            room_id: config.room_id,
            block_number: end_l2_block,
            prev_state_root: first.journal.post_state_root,
            state: first.post_state.to_input_state(),
            raw_txs: raw1.clone(),
            env: env(end_l2_block, chain_id),
            block_hashes: vec![],
        },
        config.state_commitment,
    )
    .map_err(|error| anyhow!("prepare second v5 block: {error}"))?;

    let call_selectors = match &config.call_rules {
        Some(rules) => {
            for (target, selector) in &room_blocks.calls {
                if !selector_allowed(rules, *target, *selector) {
                    bail!(
                        "call 0x{} against {target} is outside the certified callRules",
                        alloy_primitives::hex::encode(selector)
                    );
                }
            }
            rule_selectors(rules)
        }
        None => resolve_call_selectors(
            &config.custom_call_blocks,
            &client_selectors(&client),
            config.allowed_selectors.clone(),
        )?,
    };
    let policy = fixture_policy(
        &contracts,
        PolicyInputs {
            state_commitment: config.state_commitment,
            registry_contract,
            registry_slots,
            call_rules: config.call_rules.as_deref(),
            call_selectors: &call_selectors,
            max_transactions_per_block: config.max_transactions_per_block,
            certified_imports,
        },
    );
    let policy_hash = execution_policy_hash_v5(&policy);
    let proof_program_id = B256::from(image_id);
    let proof_system_version = keccak256(b"risc0-groth16-v1");
    let template_id = cold_template_id_v5(initial_state_root, policy_hash, proof_system_version);
    let cold = ColdTemplateInputV5 {
        template_id,
        initial_state_root,
        policy_hash,
        proof_program_id,
        proof_system_version,
        policy: policy.clone(),
        compact_state: compact_state(&state),
    };

    let roster = roster(config.active_signers);
    let roster_capacity = config.active_signers.max(2).next_power_of_two();
    let roster_root = if config.authorization_mode == 0 {
        roster_root_v5(&roster, roster_capacity).context("derive initial roster root")?
    } else {
        B256::ZERO
    };
    let liabilities = vec![AssetLiabilityV5 {
        asset: Address::ZERO,
        pending: U256::ZERO,
        controlled: U256::ZERO,
        claimable: U256::ZERO,
        paid: U256::ZERO,
    }];
    let blocks = vec![
        BatchBlockV5 {
            block_number: start_l2_block,
            raw_txs: raw0,
            env: env(start_l2_block, chain_id),
            block_hashes: vec![],
            expected_post_state_root: first.journal.post_state_root,
        },
        BatchBlockV5 {
            block_number: end_l2_block,
            raw_txs: raw1,
            env: env(end_l2_block, chain_id),
            block_hashes: vec![],
            expected_post_state_root: second.journal.post_state_root,
        },
    ];
    let closing = second.post_state.to_input_state();
    let (post_participant_root, post_participant_epoch, post_participant_count, _) =
        registry_view(&closing, registry_contract, registry_slots)?;
    let journal = BatchJournalV5 {
        protocol_version: 6,
        deployment_domain: config.deployment_domain,
        room_id: config.room_id,
        authorization_mode: config.authorization_mode,
        cold_template_id: template_id,
        proof_program_id,
        proof_system_version,
        policy_hash,
        batch_index: config.batch_index,
        start_l2_block,
        end_l2_block,
        pre_state_root: opening.pre_state_root,
        post_state_root: second.journal.post_state_root,
        batch_data_hash: batch_block_data_hash_v5(&blocks, opening.pre_state_root),
        canonical_data_hash: if config.authorization_mode == 1 {
            keccak256(canonical_batch_data_v5(&blocks, opening.pre_state_root))
        } else {
            B256::ZERO
        },
        pre_participant_root: opening.participant_root,
        post_participant_root,
        pre_participant_epoch: opening.participant_epoch,
        post_participant_epoch,
        pre_participant_count: opening.participant_count,
        post_participant_count,
        participant_capacity: config.participant_capacity,
        pre_roster_root: roster_root,
        post_roster_root: roster_root,
        pre_roster_epoch: 1,
        post_roster_epoch: 1,
        pre_active_count: config.active_signers,
        post_active_count: config.active_signers,
        roster_change_cursor_before: 0,
        roster_change_cursor_after: 0,
        inbox_cursor_before: 0,
        inbox_cursor_after: 0,
        inbox_records_hash: stf_types::inbox_records_hash_v5(&[]),
        admission_cursor_before: 0,
        admission_cursor_after: 0,
        admission_records_hash: stf_types::admission_records_hash_v5(&[]),
        forced_cursor_before: 0,
        forced_cursor_after: 0,
        forced_outcomes_hash: stf_types::forced_outcomes_hash_v5(&[]),
        import_cursor_before: opening.import_cursor_before,
        import_cursor_after: opening.import_cursor_before
            + u64::from(opening.l1_import.is_some()),
        imported_l1_block: opening
            .l1_import
            .as_ref()
            .map_or(0, |import| import.source_block),
        imported_l1_header_hash: opening
            .l1_import
            .as_ref()
            .map_or(B256::ZERO, |import| import.header_hash),
        imported_l1_state_root: opening
            .l1_import
            .as_ref()
            .map_or(B256::ZERO, |import| import.state_root),
        import_root: opening.l1_import.as_ref().map_or(B256::ZERO, |import| {
            stf_types::import_root_v5(config.room_id, config.l1_chain_id, import)
        }),
        // `_validateJournal` requires `outboxEpoch == room.outboxEpoch + 1`,
        // and a room's outbox epoch starts at zero, so it tracks the batch
        // index exactly.
        outbox_epoch: config.batch_index,
        withdrawal_root: B256::ZERO,
        pre_liabilities_hash: liabilities_hash_v5(&liabilities),
        post_liabilities_hash: liabilities_hash_v5(&liabilities),
        roster_changes_hash: roster_changes_hash_v5(&[]),
        l1_inclusion_deadline: config.l1_inclusion_deadline,
        close: false,
    };
    let room = BatchInputV5 {
        encoded_witness_bytes: 0,
        l1_chain_id: config.l1_chain_id,
        journal,
        policy,
        roster_capacity,
        pre_roster: roster.clone(),
        post_roster: roster,
        roster_changes: vec![],
        admissions: vec![],
        forced_transactions: vec![],
        canonical_batch_data: if config.authorization_mode == 1 {
            Bytes::from(canonical_batch_data_v5(&blocks, opening.pre_state_root))
        } else {
            Bytes::new()
        },
        pre_liabilities: liabilities.clone(),
        post_liabilities: liabilities,
        deposits: vec![],
        withdrawals: vec![],
        withdrawal_capacity: 0,
        l1_import: opening.l1_import,
        compact_state: opening.compact_state,
        blocks,
    };
    // The genesis identity is the keccak of the framed canonical cold witness
    // bytes (the exact guest input), so the fixture derives it the same way
    // the proof will.
    let canonical_cold_template_data = crate::witness::cold_template_input_bytes_v5(&cold)?;
    let genesis_data_hash = keccak256(&canonical_cold_template_data);
    stf_core::execute_cold_template_v5(&cold, genesis_data_hash)
        .map_err(|error| anyhow!("validate prepared cold template: {error}"))?;
    stf_core::execute_batch_v5(&room)
        .map_err(|error| anyhow!("validate prepared room batch: {error}"))?;

    Ok(json!({
        "coldRequest": {
            "coldTemplateWitness": cold,
            "proofMode": "groth16",
            "production": true
        },
        "roomRequest": {
            "roomWitness": room,
            "proofMode": "groth16",
            "production": true
        },
        "contractConfig": {
            "templateId": template_id,
            "initialStateRoot": initial_state_root,
            "policyHash": policy_hash,
            "proofProgramId": proof_program_id,
            "proofSystemVersion": proof_system_version,
            "genesisDataHash": genesis_data_hash,
            "canonicalColdTemplateData": format!(
                "0x{}",
                hex::encode(&canonical_cold_template_data)
            ),
            "initialApproverRoot": roster_root,
            "initialActiveCount": config.active_signers,
            "initialParticipantRoot": initial_participant_root,
            "initialParticipantCount": opening_count,
            "participantRegistryContract": registry_contract,
            "minimumImportConfirmations": PRODUCTION_MINIMUM_IMPORT_CONFIRMATIONS,
            "minimumDepositConfirmations": PRODUCTION_MINIMUM_DEPOSIT_CONFIRMATIONS,
            "roomSigners": signers,
            "duelistOwners": room_blocks.owners,
            "asset": Address::ZERO
        },
        "measurement": {
            "stateCommitment": if config.state_commitment == 0 { "MPT" } else { "SPARSE_ROOM_TREE" },
            // The batch index and the L2 block range are not restated here:
            // they are journal fields, and a second copy is a second thing to
            // disagree. `roomRequest.roomWitness.journal` carries them.
            "blocks": 2,
            "transactions": transaction_count,
            "authorizationMode": if config.authorization_mode == 0 { "UNANIMOUS_APPROVERS" } else { "VALIDITY_ONLY" },
            "activeSigners": config.active_signers,
            "registeredParticipants": opening_count,
            "participantCapacity": config.participant_capacity,
            "participantTreeDepth": config.participant_depth,
            "touchedParticipants": if workload == "participant-merkle" || workload == CARD_DUEL_WORKLOAD { config.touched_participants } else { 0 },
            "residentAccounts": config.resident_accounts,
            "touchedAccounts": config.touched_contracts + 1,
            "residentL1MirrorVariables": config.resident_storage_slots + config.imported_variables,
            "freshlyImportedVariables": config.imported_variables,
            "workload": workload,
            "preparedMotifHits": if workload == "opcode-gadgets" {
                config.touched_contracts * 2 * config.gadget_repeats * TOP_50_SOLIDITY_MOTIFS.len() as u64
            } else {
                0
            },
            "protocolCaps": {
                "activeSigners": MAX_ACTIVE_SIGNERS,
                "residentAccounts": MAX_RESIDENT_ACCOUNTS,
                "touchedContracts": MAX_TOUCHED_CONTRACTS,
                "residentL1MirrorVariables": MAX_RESIDENT_STORAGE_SLOTS,
                "freshlyImportedVariables": MAX_IMPORTED_VARIABLES
            }
        }
    }))
}
