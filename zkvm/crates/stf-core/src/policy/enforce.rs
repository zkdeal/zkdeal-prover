//! Enforcement predicates: what a certified policy permits during execution
//! and what the terminal state is allowed to look like.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, U256};

use super::{slot_has_prefix, AllowedCallKind, ExecutionPolicyV4, ACTIVE_MEMBER_SENTINEL};
use crate::StateMap;

impl ExecutionPolicyV4 {
    pub(super) fn is_precompile(address: Address) -> bool {
        revm::precompile::Precompiles::new(revm::precompile::PrecompileSpecId::OSAKA)
            .contains(&address)
    }

    pub(super) fn allows_call(
        &self,
        caller: Address,
        target: Address,
        kind: AllowedCallKind,
        selector: Option<[u8; 4]>,
    ) -> bool {
        if !self.certified {
            return true;
        }
        // Osaka precompiles are part of the pinned execution semantics. They
        // may be reached only internally from a code-pinned contract, never
        // as an unregistered member entry point.
        if Self::is_precompile(target) && self.code_hashes.contains_key(&caller) {
            return kind != AllowedCallKind::DelegateCall;
        }
        let caller_rule = if self.active_members.contains(&caller) {
            ACTIVE_MEMBER_SENTINEL
        } else {
            caller
        };
        let Some(selector) = selector else {
            return false;
        };
        self.call_rules.iter().any(|rule| {
            rule.caller == caller_rule
                && rule.target == target
                && rule.kinds.contains(&(kind as u8))
                && rule.selectors.contains(&selector)
        })
    }

    pub(super) fn validate_active_member_arguments(
        &self,
        target: Address,
        selector: Option<[u8; 4]>,
        input: &[u8],
    ) -> Result<(), String> {
        let Some(selector) = selector else {
            return Ok(());
        };
        let Some(rule) = self
            .active_member_argument_rules
            .iter()
            .find(|rule| rule.target == target && rule.selector == selector)
        else {
            return Ok(());
        };
        for word_index in &rule.argument_word_indices {
            let start = 4usize
                .checked_add(
                    usize::from(*word_index)
                        .checked_mul(32)
                        .ok_or("ABI index overflow")?,
                )
                .ok_or("ABI index overflow")?;
            let end = start.checked_add(32).ok_or("ABI index overflow")?;
            let word = input
                .get(start..end)
                .ok_or_else(|| format!("active-member ABI argument {word_index} is missing"))?;
            if word[..12].iter().any(|byte| *byte != 0) {
                return Err(format!(
                    "active-member ABI argument {word_index} is not a canonical address"
                ));
            }
            let member = Address::from_slice(&word[12..]);
            if !self.active_members.contains(&member) {
                return Err(format!(
                    "active-member ABI argument {word_index} ({member}) is not in the authenticated roster"
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate_membership_state_guards(&self, state: &StateMap) -> Result<(), String> {
        if !self.membership_changed {
            return Ok(());
        }
        for guard in &self.membership_state_guards {
            let account = state
                .accounts
                .get(&guard.contract)
                .ok_or_else(|| format!("membership guard contract {} is absent", guard.contract))?;
            let packed = account
                .storage
                .get(&guard.storage_slot)
                .copied()
                .unwrap_or_default();
            let mask = if guard.bit_width == 256 {
                U256::MAX
            } else {
                (U256::from(1u8) << usize::from(guard.bit_width)) - U256::from(1u8)
            };
            let value = (packed >> usize::from(guard.bit_offset)) & mask;
            if !guard.allowed_values.contains(&value) {
                return Err(format!(
                    "membership change is forbidden by {}[{:#x}] state value {value}",
                    guard.contract, guard.storage_slot
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_post_state(
        &self,
        pre_storage: &BTreeMap<Address, BTreeMap<U256, U256>>,
        post: &StateMap,
    ) -> Result<(), String> {
        if !self.certified {
            return Ok(());
        }
        for (address, expected_hash) in &self.code_hashes {
            let account = post
                .accounts
                .get(address)
                .ok_or_else(|| format!("pinned code account {address} disappeared"))?;
            if account.code_hash() != *expected_hash {
                return Err(format!("pinned code changed at {address}"));
            }
        }
        let addresses: BTreeSet<Address> = pre_storage
            .keys()
            .chain(post.accounts.keys())
            .copied()
            .collect();
        for address in addresses {
            let before = pre_storage.get(&address);
            let after = post.accounts.get(&address);
            let slots: BTreeSet<U256> = before
                .into_iter()
                .flat_map(|storage| storage.keys())
                .chain(after.into_iter().flat_map(|account| account.storage.keys()))
                .copied()
                .collect();
            for slot in slots {
                let old = before
                    .and_then(|storage| storage.get(&slot))
                    .copied()
                    .unwrap_or_default();
                let new = after
                    .and_then(|account| account.storage.get(&slot))
                    .copied()
                    .unwrap_or_default();
                if old != new
                    && !self.storage_namespaces.iter().any(|namespace| {
                        namespace.contract == address
                            && namespace.writable
                            && slot_has_prefix(slot, namespace.slot_prefix, namespace.prefix_bits)
                    })
                {
                    return Err(format!(
                        "write to read-only/out-of-envelope storage {address}[{slot:#x}]"
                    ));
                }
            }
        }
        self.validate_membership_state_guards(post)?;
        Ok(())
    }
}
