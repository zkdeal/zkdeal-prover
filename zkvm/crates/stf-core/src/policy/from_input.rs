//! The v4 constructor: parse and authenticate the canonical preset JSON.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{keccak256, Address, B256, U256};
use stf_types::{
    BatchInputV4, MAX_BATCH_BLOCKS_V4, MAX_BATCH_WITNESS_BYTES_V4, MAX_COMPACT_ACCOUNTS_V4,
    MAX_COMPACT_STORAGE_SLOTS_V4,
};

use super::{
    slot_has_prefix, verify_roster, ActiveMemberArgumentRule, AllowedCallKind, CallRule,
    ExecutionPolicyV4, MembershipStateGuard, PresetJsonV4, StorageNamespace,
    ACTIVE_MEMBER_SENTINEL,
};
use crate::StateMap;

fn parse_address(value: &str, label: &str) -> Result<Address, String> {
    value
        .parse::<Address>()
        .map_err(|error| format!("{label}: invalid address: {error}"))
}

fn parse_b256(value: &str, label: &str) -> Result<B256, String> {
    value
        .parse::<B256>()
        .map_err(|error| format!("{label}: invalid bytes32: {error}"))
}

fn parse_selector(value: &str, label: &str) -> Result<[u8; 4], String> {
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{label}: selector needs 0x prefix"))?;
    if value.len() != 8 {
        return Err(format!("{label}: selector is not bytes4"));
    }
    let mut selector = [0u8; 4];
    for (index, byte) in selector.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{label}: selector is not hex"))?;
    }
    Ok(selector)
}

impl ExecutionPolicyV4 {
    pub(crate) fn from_input(input: &BatchInputV4, state: &StateMap) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_slice(&input.canonical_preset_json)
            .map_err(|error| format!("preset JSON: {error}"))?;
        let canonical = serde_json::to_vec(&value)
            .map_err(|error| format!("canonical preset JSON: {error}"))?;
        if canonical.as_slice() != input.canonical_preset_json.as_ref() {
            return Err("preset JSON is not canonical".into());
        }
        if keccak256(&canonical) != input.preset_hash {
            return Err("canonical preset JSON does not hash to presetHash".into());
        }
        let preset: PresetJsonV4 =
            serde_json::from_value(value).map_err(|error| format!("preset schema: {error}"))?;
        if preset.version != 4 || preset.fork != "osaka" {
            return Err("preset must be v4 with Osaka semantics".into());
        }
        let certified = match preset.execution_level.as_str() {
            "generic" => false,
            "certified" => true,
            other => return Err(format!("unknown preset executionLevel {other}")),
        };
        let exit_program_id = parse_b256(&preset.exit_program_id, "exitProgramId")?;
        let mut previous_asset = None;
        for asset_id in &preset.asset_ids {
            if *asset_id >= 16 || previous_asset.is_some_and(|previous| *asset_id <= previous) {
                return Err("preset assetIds must be sorted unique values below 16".into());
            }
            previous_asset = Some(*asset_id);
        }
        if preset.resources.max_blocks_per_batch == 0
            || preset.resources.max_blocks_per_batch > MAX_BATCH_BLOCKS_V4
            || input.blocks.len() > preset.resources.max_blocks_per_batch
        {
            return Err("preset maxBlocksPerBatch is invalid or exceeded".into());
        }
        let max_gas_per_block = preset
            .resources
            .max_gas_per_block
            .parse::<u64>()
            .map_err(|_| "preset maxGasPerBlock is not a u64 decimal")?;
        if max_gas_per_block == 0
            || preset.resources.max_transactions_per_block == 0
            || preset.resources.max_witness_bytes == 0
            || preset.resources.max_witness_bytes > MAX_BATCH_WITNESS_BYTES_V4
            || input.encoded_witness_bytes == 0
            || input.encoded_witness_bytes as usize > preset.resources.max_witness_bytes
            || preset.resources.max_memory_pages == 0
            || preset.resources.max_memory_pages > 4_096
            || preset.resources.max_touched_accounts == 0
            || preset.resources.max_touched_accounts > MAX_COMPACT_ACCOUNTS_V4
            || preset.resources.max_touched_storage_slots == 0
            || preset.resources.max_touched_storage_slots > MAX_COMPACT_STORAGE_SLOTS_V4
        {
            return Err("preset resource envelope is invalid or exceeds guest caps".into());
        }
        if input.canonical_preset_json.len() > 256 * 1024
            || input.canonical_exit_program_json.len() > 64 * 1024
        {
            return Err("preset/exit-program component byte cap exceeded".into());
        }
        let max_memory_bytes = preset
            .resources
            .max_memory_pages
            .checked_mul(65_536)
            .ok_or("preset maxMemoryPages byte overflow")?;
        if input.compact_state.accounts.len() > preset.resources.max_touched_accounts {
            return Err("preset touched-account cap exceeded".into());
        }
        let touched_slots: usize = input
            .compact_state
            .accounts
            .iter()
            .map(|account| account.storage.len())
            .sum();
        if touched_slots > preset.resources.max_touched_storage_slots {
            return Err("preset touched-storage cap exceeded".into());
        }
        for (index, block) in input.blocks.iter().enumerate() {
            if block.raw_txs.len() > preset.resources.max_transactions_per_block {
                return Err(format!("block {index} exceeds preset transaction cap"));
            }
        }

        let active_members = verify_roster(
            &input.pre_roster_slots,
            input.pre_roster_root,
            input.active_mask,
            input.pre_used_mask,
        )?;

        let mut code_hashes = BTreeMap::new();
        for (index, code) in preset.code.iter().enumerate() {
            let address = parse_address(&code.address, &format!("code[{index}].address"))?;
            let code_hash = parse_b256(
                &code.runtime_code_hash,
                &format!("code[{index}].runtimeCodeHash"),
            )?;
            if code_hashes.insert(address, code_hash).is_some() {
                return Err("duplicate preset code address".into());
            }
        }
        if certified && code_hashes.is_empty() {
            return Err("certified preset has no code commitments".into());
        }
        if certified && (preset.allow_contract_creation || preset.allow_self_destruct) {
            return Err("certified preset cannot allow creation or selfdestruct".into());
        }
        for (address, expected_hash) in &code_hashes {
            let account = state
                .accounts
                .get(address)
                .ok_or_else(|| format!("pinned code account {address} is absent"))?;
            if account.code_hash() != *expected_hash {
                return Err(format!("runtime code hash mismatch at {address}"));
            }
        }
        if certified {
            for (address, account) in &state.accounts {
                if !account.code.is_empty() && !code_hashes.contains_key(address) {
                    return Err(format!("uncommitted executable code at {address}"));
                }
            }
        }

        let mut domain_binding_keys = BTreeSet::new();
        for (index, binding) in preset.application_domain_bindings.iter().enumerate() {
            let contract = parse_address(
                &binding.contract,
                &format!("applicationDomainBindings[{index}].contract"),
            )?;
            if !code_hashes.contains_key(&contract) {
                return Err(format!(
                    "applicationDomainBindings[{index}] contract is not code-pinned"
                ));
            }
            let storage_slot = U256::from_be_slice(
                parse_b256(
                    &binding.storage_slot,
                    &format!("applicationDomainBindings[{index}].storageSlot"),
                )?
                .as_slice(),
            );
            if !domain_binding_keys.insert((contract, storage_slot)) {
                return Err("duplicate application-domain binding".into());
            }
            let tag = binding.domain_tag.as_bytes();
            if tag.is_empty() || tag.len() > 64 || tag.iter().any(|byte| byte.is_ascii_control()) {
                return Err(format!(
                    "applicationDomainBindings[{index}] domainTag must be 1..64 printable UTF-8 bytes"
                ));
            }
            let expected =
                stf_types::application_domain_v4(tag, input.deployment_id, input.room_id);
            let account = state
                .accounts
                .get(&contract)
                .ok_or_else(|| format!("applicationDomainBindings[{index}] contract is absent"))?;
            let actual = account
                .storage
                .get(&storage_slot)
                .copied()
                .unwrap_or_default();
            if actual != U256::from_be_slice(expected.as_slice()) {
                return Err(format!(
                    "applicationDomainBindings[{index}] storage does not match the derived room application domain"
                ));
            }
        }

        let mut call_rules = Vec::new();
        let mut call_rule_keys = BTreeSet::new();
        for (index, rule) in preset.call_rules.iter().enumerate() {
            let caller = parse_address(&rule.caller, &format!("callRules[{index}].caller"))?;
            let target = parse_address(&rule.target, &format!("callRules[{index}].target"))?;
            if certified && caller != ACTIVE_MEMBER_SENTINEL && !code_hashes.contains_key(&caller) {
                return Err(format!("callRules[{index}] caller is not code-pinned"));
            }
            if certified && !code_hashes.contains_key(&target) {
                return Err(format!("callRules[{index}] target is not code-pinned"));
            }
            if !call_rule_keys.insert((caller, target)) {
                return Err("duplicate call rule".into());
            }
            let mut selectors = BTreeSet::new();
            for (selector_index, selector) in rule.selectors.iter().enumerate() {
                if !selectors.insert(parse_selector(
                    selector,
                    &format!("callRules[{index}].selectors[{selector_index}]"),
                )?) {
                    return Err("duplicate call selector".into());
                }
            }
            if selectors.is_empty() {
                return Err("call rule has no selectors".into());
            }
            let mut kinds = BTreeSet::new();
            for kind in &rule.kinds {
                let kind = match kind.as_str() {
                    "call" => AllowedCallKind::Call,
                    "staticcall" => AllowedCallKind::StaticCall,
                    "delegatecall" => AllowedCallKind::DelegateCall,
                    other => return Err(format!("unsupported certified call kind {other}")),
                };
                kinds.insert(kind as u8);
            }
            if kinds.is_empty() {
                return Err("call rule has no call kinds".into());
            }
            call_rules.push(CallRule {
                caller,
                target,
                selectors,
                kinds,
            });
        }

        let mut active_member_argument_rules = Vec::new();
        let mut active_argument_keys = BTreeSet::new();
        for (index, rule) in preset.active_member_argument_rules.iter().enumerate() {
            let target = parse_address(
                &rule.target,
                &format!("activeMemberArgumentRules[{index}].target"),
            )?;
            if !code_hashes.contains_key(&target) {
                return Err(format!(
                    "activeMemberArgumentRules[{index}] target is not code-pinned"
                ));
            }
            let selector = parse_selector(
                &rule.selector,
                &format!("activeMemberArgumentRules[{index}].selector"),
            )?;
            if !active_argument_keys.insert((target, selector)) {
                return Err("duplicate active-member argument rule".into());
            }
            if rule.argument_word_indices.is_empty()
                || rule
                    .argument_word_indices
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(format!(
                    "activeMemberArgumentRules[{index}] argumentWordIndices must be sorted, unique, and non-empty"
                ));
            }
            if !call_rules.iter().any(|call_rule| {
                call_rule.caller == ACTIVE_MEMBER_SENTINEL
                    && call_rule.target == target
                    && call_rule.selectors.contains(&selector)
            }) {
                return Err(format!(
                    "activeMemberArgumentRules[{index}] selector is not an active-member entry point"
                ));
            }
            active_member_argument_rules.push(ActiveMemberArgumentRule {
                target,
                selector,
                argument_word_indices: rule.argument_word_indices.clone(),
            });
        }

        let mut membership_state_guards = Vec::new();
        let mut membership_guard_keys = BTreeSet::new();
        for (index, guard) in preset.membership_state_guards.iter().enumerate() {
            let contract = parse_address(
                &guard.contract,
                &format!("membershipStateGuards[{index}].contract"),
            )?;
            if !code_hashes.contains_key(&contract) {
                return Err(format!(
                    "membershipStateGuards[{index}] contract is not code-pinned"
                ));
            }
            let storage_slot = U256::from_be_slice(
                parse_b256(
                    &guard.storage_slot,
                    &format!("membershipStateGuards[{index}].storageSlot"),
                )?
                .as_slice(),
            );
            if guard.bit_width == 0
                || guard.bit_offset >= 256
                || guard.bit_width > 256 - guard.bit_offset
            {
                return Err(format!(
                    "membershipStateGuards[{index}] bit range is invalid"
                ));
            }
            if !membership_guard_keys.insert((
                contract,
                storage_slot,
                guard.bit_offset,
                guard.bit_width,
            )) {
                return Err("duplicate membership state guard".into());
            }
            let max_value = if guard.bit_width == 256 {
                U256::MAX
            } else {
                (U256::from(1u8) << usize::from(guard.bit_width)) - U256::from(1u8)
            };
            let mut allowed_values = BTreeSet::new();
            for value in &guard.allowed_values {
                let value = U256::from(*value);
                if value > max_value || !allowed_values.insert(value) {
                    return Err(format!(
                        "membershipStateGuards[{index}] allowedValues are duplicate or outside the field"
                    ));
                }
            }
            if allowed_values.is_empty() {
                return Err(format!(
                    "membershipStateGuards[{index}] allowedValues must be non-empty"
                ));
            }
            membership_state_guards.push(MembershipStateGuard {
                contract,
                storage_slot,
                bit_offset: guard.bit_offset,
                bit_width: guard.bit_width,
                allowed_values,
            });
        }

        let mut storage_namespaces = Vec::new();
        for (index, namespace) in preset.storage_namespaces.iter().enumerate() {
            if namespace.prefix_bits > 256 {
                return Err(format!("storageNamespaces[{index}] prefixBits exceeds 256"));
            }
            let contract = parse_address(
                &namespace.contract,
                &format!("storageNamespaces[{index}].contract"),
            )?;
            if certified && !code_hashes.contains_key(&contract) {
                return Err(format!(
                    "storageNamespaces[{index}] contract is not code-pinned"
                ));
            }
            let prefix = parse_b256(
                &namespace.slot_prefix,
                &format!("storageNamespaces[{index}].slotPrefix"),
            )?;
            storage_namespaces.push(StorageNamespace {
                contract,
                slot_prefix: U256::from_be_bytes(prefix.0),
                prefix_bits: namespace.prefix_bits,
                writable: namespace.writable,
            });
        }
        if certified {
            for account in &input.compact_state.accounts {
                if account.storage.is_empty() {
                    continue;
                }
                if !code_hashes.contains_key(&account.address) {
                    return Err(format!(
                        "storage declared for non-code-pinned account {}",
                        account.address
                    ));
                }
                for slot in &account.storage {
                    if !storage_namespaces.iter().any(|namespace| {
                        namespace.contract == account.address
                            && slot_has_prefix(
                                slot.slot,
                                namespace.slot_prefix,
                                namespace.prefix_bits,
                            )
                    }) {
                        return Err(format!(
                            "storage {}[{:#x}] is outside the certified namespace",
                            account.address, slot.slot
                        ));
                    }
                }
            }
        }

        let policy = Self {
            certified,
            active_members,
            code_hashes,
            call_rules,
            storage_namespaces,
            active_member_argument_rules,
            membership_state_guards,
            membership_changed: !input.membership_deltas.is_empty(),
            allow_contract_creation: preset.allow_contract_creation,
            allow_self_destruct: preset.allow_self_destruct,
            max_gas_per_block,
            max_memory_bytes,
            exit_program_id,
            preset_asset_ids: preset.asset_ids,
        };
        policy.validate_membership_state_guards(state)?;
        Ok(policy)
    }
}
