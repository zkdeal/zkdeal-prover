//! The v5 constructor: build the inspector policy from the binary policy
//! commitment and an arbitrary-size authenticated approver roster.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, B256};
use stf_types::{execution_policy_hash_v5, ExecutionPolicyV5, MAX_EXIT_ASSETS_V5};

use super::{
    slot_has_prefix, AllowedCallKind, CallRule, ExecutionPolicyV4, StorageNamespace,
    ACTIVE_MEMBER_SENTINEL,
};
use crate::StateMap;

impl ExecutionPolicyV4 {
    pub(crate) fn legacy_unrestricted() -> Self {
        Self {
            certified: false,
            active_members: BTreeSet::new(),
            code_hashes: BTreeMap::new(),
            call_rules: Vec::new(),
            storage_namespaces: Vec::new(),
            active_member_argument_rules: Vec::new(),
            membership_state_guards: Vec::new(),
            membership_changed: false,
            allow_contract_creation: true,
            allow_self_destruct: true,
            max_gas_per_block: u64::MAX,
            max_memory_bytes: usize::MAX,
            exit_program_id: B256::ZERO,
            preset_asset_ids: Vec::new(),
        }
    }

    /// Build the inspector policy from the v5 binary policy commitment and
    /// arbitrary-size authenticated roster. The inspector is shared with v4
    /// because CALL/CREATE/SELFDESTRUCT and storage-write semantics are EVM
    /// properties, not roster-layout properties.
    pub(crate) fn from_v5(
        policy: &ExecutionPolicyV5,
        expected_hash: B256,
        active_members: BTreeSet<Address>,
        state: &StateMap,
        membership_changed: bool,
    ) -> Result<Self, String> {
        if execution_policy_hash_v5(policy) != expected_hash {
            return Err("structured v5 policy does not hash to policyHash".into());
        }
        if policy.state_commitment > 1
            || policy.max_blocks_per_batch == 0
            || policy.max_blocks_per_batch > 64
            || policy.max_transactions_per_block == 0
            || policy.max_transactions_per_block > 4_096
            || policy.max_gas_per_block == 0
            || policy.max_memory_bytes == 0
            || active_members.is_empty()
        {
            return Err(
                "v5 state commitment, resource envelope or active roster is invalid".into(),
            );
        }
        if policy.allow_contract_creation || policy.allow_self_destruct {
            return Err(
                "certified v5 rooms cannot permit creation or selfdestruct; use generic execution"
                    .into(),
            );
        }

        let mut code_hashes = BTreeMap::new();
        let mut previous_code = None;
        for code in &policy.code {
            if code.address == Address::ZERO
                || code.runtime_code_hash == B256::ZERO
                || previous_code.is_some_and(|previous| previous >= code.address)
                || code_hashes
                    .insert(code.address, code.runtime_code_hash)
                    .is_some()
            {
                return Err("v5 code commitments must be non-zero, sorted, and unique".into());
            }
            previous_code = Some(code.address);
            let account = state
                .accounts
                .get(&code.address)
                .ok_or_else(|| format!("v5 pinned code account {} is absent", code.address))?;
            if account.code_hash() != code.runtime_code_hash {
                return Err(format!("v5 runtime code hash mismatch at {}", code.address));
            }
        }
        if code_hashes.is_empty() {
            return Err("certified v5 policy has no code commitments".into());
        }
        for (address, account) in &state.accounts {
            if !account.code.is_empty() && !code_hashes.contains_key(address) {
                return Err(format!("uncommitted executable code at {address}"));
            }
        }

        let mut call_rules = Vec::new();
        let mut call_keys = BTreeSet::new();
        for rule in &policy.calls {
            if rule.target == Address::ZERO
                || !code_hashes.contains_key(&rule.target)
                || (rule.caller != ACTIVE_MEMBER_SENTINEL
                    && !code_hashes.contains_key(&rule.caller))
                || !call_keys.insert((rule.caller, rule.target))
            {
                return Err("v5 call rules require unique code-pinned caller/target pairs".into());
            }
            let selectors = rule.selectors.iter().copied().collect::<BTreeSet<_>>();
            if selectors.is_empty() || selectors.len() != rule.selectors.len() {
                return Err("v5 call selectors must be non-empty and unique".into());
            }
            let mut kinds = BTreeSet::new();
            for kind in &rule.kinds {
                if *kind > AllowedCallKind::DelegateCall as u8 || !kinds.insert(*kind) {
                    return Err("v5 call kinds must be unique CALL/STATICCALL/DELEGATECALL".into());
                }
            }
            if kinds.is_empty() {
                return Err("v5 call rule has no allowed call kind".into());
            }
            call_rules.push(CallRule {
                caller: rule.caller,
                target: rule.target,
                selectors,
                kinds,
            });
        }
        if call_rules.is_empty() {
            return Err("certified v5 policy has no call rules".into());
        }

        let mut storage_namespaces = Vec::new();
        let mut storage_keys = BTreeSet::new();
        for namespace in &policy.storage {
            if namespace.prefix_bits > 256
                || !code_hashes.contains_key(&namespace.contract)
                || !storage_keys.insert((
                    namespace.contract,
                    namespace.slot_prefix,
                    namespace.prefix_bits,
                ))
            {
                return Err(
                    "v5 storage namespaces must be unique and refer to code-pinned contracts"
                        .into(),
                );
            }
            storage_namespaces.push(StorageNamespace {
                contract: namespace.contract,
                slot_prefix: namespace.slot_prefix,
                prefix_bits: namespace.prefix_bits,
                writable: namespace.writable,
            });
        }
        for (address, account) in &state.accounts {
            for slot in account.storage.keys() {
                if !storage_namespaces.iter().any(|namespace| {
                    namespace.contract == *address
                        && slot_has_prefix(*slot, namespace.slot_prefix, namespace.prefix_bits)
                }) {
                    return Err(format!(
                        "storage {address}[{slot:#x}] is outside the certified v5 namespace"
                    ));
                }
            }
        }
        // An L1 import mirror is a storage write like any other. It is applied
        // before the pre-execution snapshot, so `validate_post_state`'s
        // read-only rule can never observe it: a binding pointed at a
        // `writable: false` namespace would silently contradict that flag.
        for binding in &policy.imports {
            if !storage_namespaces.iter().any(|namespace| {
                namespace.contract == binding.room_contract
                    && namespace.writable
                    && slot_has_prefix(
                        binding.room_slot,
                        namespace.slot_prefix,
                        namespace.prefix_bits,
                    )
            }) {
                return Err(
                    "L1 import mirror destinations must be in a writable v5 namespace".into(),
                );
            }
        }
        let participant = policy
            .participant_registry
            .as_ref()
            .ok_or_else(|| "v5 participant registry binding is required".to_string())?;
        if participant.contract == Address::ZERO
            || !code_hashes.contains_key(&participant.contract)
            || [
                participant.root_slot,
                participant.epoch_slot,
                participant.count_slot,
                participant.capacity_slot,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len()
                != 4
        {
            return Err(
                "participant registry must name one code-pinned contract and four unique slots"
                    .into(),
            );
        }
        for slot in [
            participant.root_slot,
            participant.epoch_slot,
            participant.count_slot,
            participant.capacity_slot,
        ] {
            if !storage_namespaces.iter().any(|namespace| {
                namespace.contract == participant.contract
                    && namespace.writable
                    && slot_has_prefix(slot, namespace.slot_prefix, namespace.prefix_bits)
            }) {
                return Err("participant registry slots must be in a writable namespace".into());
            }
            if policy.imports.iter().any(|binding| {
                binding.room_contract == participant.contract && binding.room_slot == slot
            }) {
                return Err("L1 imports cannot overwrite participant registry metadata".into());
            }
        }
        // The exit queue is the withdrawal authority for validity-only rooms,
        // so its identity has to be as pinned as the registry's: exact code,
        // writable room-owned storage, and no L1 import that could overwrite
        // the proved record region.
        if let Some(exit) = &policy.exit {
            if exit.queue_contract == Address::ZERO
                || !code_hashes.contains_key(&exit.queue_contract)
                || exit.queue_contract == participant.contract
                || exit.fallback_recipient == Address::ZERO
            {
                return Err(
                    "exit binding requires a code-pinned queue distinct from the participant \
                     registry and a non-zero fallback recipient"
                        .into(),
                );
            }
            for slot in [exit.count_slot, exit.records_base_slot] {
                if !storage_namespaces.iter().any(|namespace| {
                    namespace.contract == exit.queue_contract
                        && namespace.writable
                        && slot_has_prefix(slot, namespace.slot_prefix, namespace.prefix_bits)
                }) {
                    return Err("exit queue slots must be in a writable namespace".into());
                }
            }
            if policy
                .imports
                .iter()
                .any(|binding| binding.room_contract == exit.queue_contract)
            {
                return Err("L1 imports cannot write into the exit queue contract".into());
            }
            if exit.assets.len() > MAX_EXIT_ASSETS_V5 {
                return Err("exit binding declares more assets than MAX_EXIT_ASSETS_V5".into());
            }
            let mut previous_asset = None;
            for asset in &exit.assets {
                if previous_asset.is_some_and(|previous| previous >= asset.asset) {
                    return Err("exit assets must be sorted and unique".into());
                }
                previous_asset = Some(asset.asset);
                match asset.kind {
                    0 => {
                        if asset.asset != Address::ZERO
                            || asset.token != Address::ZERO
                            || !asset.balance_slot.is_zero()
                        {
                            return Err(
                                "native exit asset must use the zero asset, token and balance slot"
                                    .into(),
                            );
                        }
                    }
                    1 => {
                        if asset.asset == Address::ZERO
                            || asset.token == Address::ZERO
                            || !code_hashes.contains_key(&asset.token)
                        {
                            return Err(
                                "ERC-20 exit asset requires a non-zero asset and a code-pinned \
                                 token"
                                    .into(),
                            );
                        }
                    }
                    _ => return Err("exit asset kind must be native or ERC-20".into()),
                }
            }
        }

        Ok(Self {
            certified: true,
            active_members,
            code_hashes,
            call_rules,
            storage_namespaces,
            active_member_argument_rules: Vec::new(),
            membership_state_guards: Vec::new(),
            membership_changed,
            allow_contract_creation: false,
            allow_self_destruct: false,
            max_gas_per_block: policy.max_gas_per_block,
            max_memory_bytes: usize::try_from(policy.max_memory_bytes)
                .map_err(|_| "v5 maxMemoryBytes exceeds host usize")?,
            exit_program_id: B256::ZERO,
            preset_asset_ids: Vec::new(),
        })
    }
}
