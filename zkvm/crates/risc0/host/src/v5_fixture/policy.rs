//! The certified execution policy a parsed fixture request implies.
//!
//! Code commitments, call rules and storage namespaces are all derived from
//! the per-contract descriptors, so a room whose accounts hold different code
//! is described exactly rather than by one shared hash.

use alloy_primitives::{keccak256, Address, U256};
use stf_types::{
    CallRuleV5, CertifiedImportBindingV5, CodeCommitmentV5, ExecutionPolicyV5,
    ExitAssetBindingV5, ExitBindingV5, ParticipantRegistryBindingV5, StorageNamespaceV5,
};

use super::config::GAS_LIMIT;
use super::contracts::{
    exit_fallback_recipient, exit_queue_address, FixtureCallRule, FixtureContract, RegistrySlots,
};

/// Everything policy construction needs that is not a contract descriptor.
pub(super) struct PolicyInputs<'a> {
    pub(super) state_commitment: u8,
    pub(super) registry_contract: Address,
    pub(super) registry_slots: RegistrySlots,
    pub(super) call_rules: Option<&'a [FixtureCallRule]>,
    pub(super) call_selectors: &'a [[u8; 4]],
    pub(super) max_transactions_per_block: u64,
    pub(super) certified_imports: Vec<CertifiedImportBindingV5>,
}

pub(super) fn fixture_policy(
    contracts: &[FixtureContract],
    inputs: PolicyInputs<'_>,
) -> ExecutionPolicyV5 {
    let PolicyInputs {
        state_commitment,
        registry_contract,
        registry_slots,
        call_rules,
        call_selectors,
        max_transactions_per_block,
        certified_imports,
    } = inputs;
    let mut code = contracts
        .iter()
        .map(|contract| CodeCommitmentV5 {
            address: contract.address,
            runtime_code_hash: keccak256(&contract.runtime_code),
        })
        .collect::<Vec<_>>();
    // `policy/from_v5.rs` rejects code commitments that are not strictly
    // ascending, so the sort is part of the contract, not a tidy-up.
    code.sort_by_key(|commitment| commitment.address);
    let calls = match call_rules {
        Some(rules) => rules
            .iter()
            .map(|rule| CallRuleV5 {
                caller: rule.caller,
                target: rule.target,
                selectors: rule.selectors.clone(),
                kinds: rule.kinds.clone(),
            })
            .collect(),
        None => contracts
            .iter()
            .map(|contract| CallRuleV5 {
                caller: Address::ZERO,
                target: contract.address,
                selectors: call_selectors.to_vec(),
                kinds: vec![0],
            })
            .collect(),
    };
    ExecutionPolicyV5 {
        state_commitment,
        max_blocks_per_batch: 4,
        max_transactions_per_block,
        max_gas_per_block: GAS_LIMIT,
        max_memory_bytes: 16 * 1024 * 1024,
        allow_contract_creation: false,
        allow_self_destruct: false,
        code,
        calls,
        storage: contracts
            .iter()
            .map(|contract| StorageNamespaceV5 {
                contract: contract.address,
                slot_prefix: contract.slot_prefix,
                prefix_bits: contract.prefix_bits,
                writable: contract.writable,
            })
            .collect(),
        imports: certified_imports,
        participant_registry: Some(ParticipantRegistryBindingV5 {
            contract: registry_contract,
            root_slot: registry_slots.root,
            epoch_slot: registry_slots.epoch,
            count_slot: registry_slots.count,
            capacity_slot: registry_slots.capacity,
        }),
        // The benchmark workloads never mint a withdrawal, but a
        // validity-only room is unprovable without an exit binding, so every
        // fixture room certifies the synthetic inert queue.
        exit: Some(ExitBindingV5 {
            queue_contract: exit_queue_address(),
            count_slot: U256::ZERO,
            records_base_slot: U256::from(0x100),
            assets: vec![ExitAssetBindingV5 {
                asset: Address::ZERO,
                kind: 0,
                token: Address::ZERO,
                balance_slot: U256::ZERO,
            }],
            fallback_recipient: exit_fallback_recipient(),
        }),
    }
}

/// The guest requires every registry slot to sit inside a writable namespace of
/// the registry contract. Catching that here turns a policy mistake into a
/// prepare-time error instead of a rejection after a multi-minute proof.
pub(super) fn check_registry_namespace(
    contracts: &[FixtureContract],
    registry_contract: Address,
    slots: RegistrySlots,
) -> Result<(), String> {
    for slot in slots.all() {
        let covered = contracts.iter().any(|contract| {
            contract.address == registry_contract
                && contract.writable
                && super::contracts::slot_in_namespace(
                    slot,
                    contract.slot_prefix,
                    contract.prefix_bits,
                )
        });
        if !covered {
            return Err(format!(
                "participant registry slot {slot:#x} is not inside a writable namespace of {registry_contract}"
            ));
        }
    }
    Ok(())
}

/// Every call rule must name a code-pinned target, and a non-sentinel caller
/// must itself be code-pinned. Mirrors `policy/from_v5.rs`.
pub(super) fn check_call_rules(
    contracts: &[FixtureContract],
    rules: &[FixtureCallRule],
) -> Result<(), String> {
    let pinned = |address: Address| contracts.iter().any(|entry| entry.address == address);
    for rule in rules {
        if !pinned(rule.target) {
            return Err(format!(
                "call rule target {} is not one of the room's pinned contracts",
                rule.target
            ));
        }
        if rule.caller != Address::ZERO && !pinned(rule.caller) {
            return Err(format!(
                "call rule caller {} is neither the active-member sentinel nor a pinned contract",
                rule.caller
            ));
        }
    }
    Ok(())
}

/// Whether `selector` is permitted against `target` by the supplied rules.
pub(super) fn selector_allowed(
    rules: &[FixtureCallRule],
    target: Address,
    selector: [u8; 4],
) -> bool {
    rules.iter().any(|rule| {
        rule.caller == Address::ZERO
            && rule.target == target
            && rule.kinds.contains(&0)
            && rule.selectors.contains(&selector)
    })
}

/// The union of every rule's selectors, used as the fixture's reported
/// allow-list when per-contract rules replace the flat one.
pub(super) fn rule_selectors(rules: &[FixtureCallRule]) -> Vec<[u8; 4]> {
    let mut selectors = rules
        .iter()
        .flat_map(|rule| rule.selectors.iter().copied())
        .collect::<Vec<_>>();
    selectors.sort();
    selectors.dedup();
    selectors
}
