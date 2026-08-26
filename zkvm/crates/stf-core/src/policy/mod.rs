//! Certified-preset validation enforced by the v4 STF.
//!
//! The guest receives the canonical preset JSON preimage, recomputes the
//! registry `presetHash`, authenticates the seven-slot roster, verifies every
//! pinned runtime code hash, and observes the complete CALL/CREATE/
//! SELFDESTRUCT trace. This prevents a valid generic execution proof from
//! being relabelled as a certified AMM/vault/card proof.
//!
//! This module holds the schema — the preset JSON shape, the resolved rule
//! types and the policy record itself. The two constructors, the enforcement
//! predicates and the REVM inspectors live in the sibling modules.

mod enforce;
mod from_input;
mod from_v5;
mod inspector;

pub(crate) use inspector::CertifiedPolicyInspectorV4;
pub use inspector::OsakaSemanticInspector;

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, B256, U256};
use serde::Deserialize;
use stf_types::{member_roster_root_v4, MemberSlotWitnessV4};

const ACTIVE_MEMBER_SENTINEL: Address = Address::ZERO;
const ROSTER_SLOTS: usize = 7;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PresetJsonV4 {
    version: u8,
    execution_level: String,
    fork: String,
    #[serde(default)]
    code: Vec<CodeJsonV4>,
    #[serde(default)]
    call_rules: Vec<CallRuleJsonV4>,
    #[serde(default)]
    storage_namespaces: Vec<StorageNamespaceJsonV4>,
    #[serde(default)]
    application_domain_bindings: Vec<ApplicationDomainBindingJsonV4>,
    #[serde(default)]
    active_member_argument_rules: Vec<ActiveMemberArgumentRuleJsonV4>,
    #[serde(default)]
    membership_state_guards: Vec<MembershipStateGuardJsonV4>,
    resources: ResourceEnvelopeJsonV4,
    allow_contract_creation: bool,
    allow_self_destruct: bool,
    exit_program_id: String,
    #[serde(default)]
    asset_ids: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationDomainBindingJsonV4 {
    contract: String,
    storage_slot: String,
    domain_tag: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActiveMemberArgumentRuleJsonV4 {
    target: String,
    selector: String,
    argument_word_indices: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipStateGuardJsonV4 {
    contract: String,
    storage_slot: String,
    bit_offset: u16,
    bit_width: u16,
    allowed_values: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodeJsonV4 {
    address: String,
    runtime_code_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallRuleJsonV4 {
    caller: String,
    target: String,
    selectors: Vec<String>,
    kinds: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageNamespaceJsonV4 {
    contract: String,
    slot_prefix: String,
    prefix_bits: u16,
    writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceEnvelopeJsonV4 {
    max_blocks_per_batch: usize,
    max_transactions_per_block: usize,
    max_gas_per_block: String,
    max_witness_bytes: usize,
    max_memory_pages: usize,
    max_touched_accounts: usize,
    max_touched_storage_slots: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllowedCallKind {
    Call,
    StaticCall,
    DelegateCall,
}

#[derive(Clone, Debug)]
struct CallRule {
    caller: Address,
    target: Address,
    selectors: BTreeSet<[u8; 4]>,
    kinds: BTreeSet<u8>,
}

#[derive(Clone, Debug)]
struct StorageNamespace {
    contract: Address,
    slot_prefix: U256,
    prefix_bits: u16,
    writable: bool,
}

#[derive(Clone, Debug)]
struct ActiveMemberArgumentRule {
    target: Address,
    selector: [u8; 4],
    argument_word_indices: Vec<u8>,
}

#[derive(Clone, Debug)]
struct MembershipStateGuard {
    contract: Address,
    storage_slot: U256,
    bit_offset: u16,
    bit_width: u16,
    allowed_values: BTreeSet<U256>,
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutionPolicyV4 {
    pub(crate) certified: bool,
    pub(crate) active_members: BTreeSet<Address>,
    pub(crate) code_hashes: BTreeMap<Address, B256>,
    call_rules: Vec<CallRule>,
    storage_namespaces: Vec<StorageNamespace>,
    active_member_argument_rules: Vec<ActiveMemberArgumentRule>,
    membership_state_guards: Vec<MembershipStateGuard>,
    membership_changed: bool,
    allow_contract_creation: bool,
    allow_self_destruct: bool,
    pub(crate) max_gas_per_block: u64,
    pub(crate) max_memory_bytes: usize,
    pub(crate) exit_program_id: B256,
    pub(crate) preset_asset_ids: Vec<u8>,
}

pub(crate) fn verify_roster(
    slots: &[MemberSlotWitnessV4],
    expected_root: B256,
    active_mask: u8,
    used_mask: u8,
) -> Result<BTreeSet<Address>, String> {
    if slots.len() != ROSTER_SLOTS {
        return Err(format!("pre-roster requires exactly {ROSTER_SLOTS} slots"));
    }
    let mut active = BTreeSet::new();
    let mut computed_active = 0u8;
    let mut computed_used = 0u8;
    let mut leaves = Vec::with_capacity(ROSTER_SLOTS);
    for (index, slot) in slots.iter().enumerate() {
        if usize::from(slot.slot) != index {
            return Err(format!("pre-roster slot {index} missing or out of order"));
        }
        match slot.state {
            0 => {
                if slot.account != Address::ZERO
                    || slot.joined_at_batch != 0
                    || slot.retired_at_batch.is_some()
                {
                    return Err(format!("unused roster slot {index} is not zeroed"));
                }
            }
            1 => {
                if slot.account == Address::ZERO || slot.retired_at_batch.is_some() {
                    return Err(format!("active roster slot {index} is malformed"));
                }
                if !active.insert(slot.account) {
                    return Err("duplicate active roster account".into());
                }
                computed_active |= 1 << index;
                computed_used |= 1 << index;
            }
            2 => {
                let retired = slot
                    .retired_at_batch
                    .ok_or_else(|| format!("retired roster slot {index} has no retire batch"))?;
                if slot.account == Address::ZERO || retired < slot.joined_at_batch {
                    return Err(format!("retired roster slot {index} is malformed"));
                }
                computed_used |= 1 << index;
            }
            other => return Err(format!("roster slot {index} has invalid state {other}")),
        }
        leaves.push(slot.clone());
    }
    let computed_root = member_roster_root_v4(&leaves).expect("seven roster slots are non-empty");
    if computed_root != expected_root {
        return Err(format!(
            "pre-roster root mismatch: expected {expected_root}, computed {}",
            computed_root
        ));
    }
    if computed_active != active_mask || computed_used != used_mask {
        return Err("pre-roster masks do not match the batch journal masks".into());
    }
    Ok(active)
}

fn slot_has_prefix(slot: U256, prefix: U256, bits: u16) -> bool {
    if bits == 0 {
        return true;
    }
    let shift = 256usize - usize::from(bits);
    (slot >> shift) == (prefix >> shift)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateMap;
    use alloy_primitives::{keccak256, Bytes};
    use stf_types::{application_domain_v4, member_roster_root_v4, BatchInputV4};

    fn policy_input(domain_value: B256) -> (BatchInputV4, StateMap) {
        let deployment_id = B256::repeat_byte(0x11);
        let room_id = 42;
        let contract = Address::repeat_byte(0x44);
        let code = Bytes::from_static(&[0x00]);
        let code_hash = keccak256(&code);
        let preset = serde_json::json!({
            "adapters": [],
            "allowContractCreation": false,
            "allowSelfDestruct": false,
            "applicationDomainBindings": [{
                "contract": contract.to_string(),
                "domainTag": "zkdeal/card-application/v4",
                "storageSlot": format!("0x{:064x}", 2),
            }],
            "assetIds": [0],
            "callRules": [],
            "code": [{
                "address": contract.to_string(),
                "name": "BoundApplication",
                "runtimeCodeHash": code_hash.to_string(),
            }],
            "displayName": "Bound application test",
            "executionLevel": "certified",
            "exitProgramId": B256::repeat_byte(0x55).to_string(),
            "fork": "osaka",
            "presetId": "bound-app-v4",
            "resources": {
                "maxBlocksPerBatch": 4,
                "maxGasPerBlock": "30000000",
                "maxMemoryPages": 16,
                "maxTouchedAccounts": 8,
                "maxTouchedStorageSlots": 8,
                "maxTransactionsPerBlock": 8,
                "maxWitnessBytes": 1048576,
            },
            "storageNamespaces": [],
            "version": 4,
        });
        let canonical = Bytes::from(serde_json::to_vec(&preset).unwrap());
        let mut slots = vec![MemberSlotWitnessV4 {
            slot: 0,
            state: 1,
            account: Address::repeat_byte(0x33),
            joined_at_batch: 0,
            retired_at_batch: None,
        }];
        for slot in 1..7 {
            slots.push(MemberSlotWitnessV4 {
                slot,
                ..Default::default()
            });
        }
        let roster_root = member_roster_root_v4(&slots).unwrap();
        let input = BatchInputV4 {
            encoded_witness_bytes: 1,
            deployment_id,
            room_id,
            preset_hash: keccak256(&canonical),
            pre_roster_root: roster_root,
            post_roster_root: roster_root,
            active_mask: 1,
            pre_used_mask: 1,
            post_active_mask: 1,
            used_mask: 1,
            canonical_preset_json: canonical,
            pre_roster_slots: slots.clone(),
            post_roster_slots: slots,
            ..Default::default()
        };
        let mut state = StateMap::default();
        state.accounts.insert(
            contract,
            crate::AccountRecord {
                code,
                storage: BTreeMap::from([(
                    U256::from(2),
                    U256::from_be_slice(domain_value.as_slice()),
                )]),
                ..Default::default()
            },
        );
        (input, state)
    }

    #[test]
    fn certified_application_domain_is_derived_inside_the_guest_policy() {
        let deployment = B256::repeat_byte(0x11);
        let expected = application_domain_v4(b"zkdeal/card-application/v4", deployment, 42);
        let (input, state) = policy_input(expected);
        ExecutionPolicyV4::from_input(&input, &state).unwrap();

        let (wrong_input, wrong_state) = policy_input(B256::repeat_byte(0xaa));
        let error = ExecutionPolicyV4::from_input(&wrong_input, &wrong_state).unwrap_err();
        assert!(error.contains("derived room application domain"));

        let other_room = BatchInputV4 {
            room_id: 43,
            ..input
        };
        let error = ExecutionPolicyV4::from_input(&other_room, &state).unwrap_err();
        assert!(error.contains("derived room application domain"));
    }
}
