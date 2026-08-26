//! revm integration: authenticated reads through `Database` and the
//! ethereumjs-equivalent `DatabaseCommit` semantics.

use super::{StateMap, StfDbError};
use alloy_primitives::{map::AddressMap, Address, Bytes, B256, U256};
use revm::{
    primitives::KECCAK_EMPTY,
    state::{Account, AccountInfo, Bytecode},
    Database, DatabaseCommit,
};

impl Database for StateMap {
    type Error = StfDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.access_metrics.account_reads = self.access_metrics.account_reads.saturating_add(1);
        if self
            .access_accounts
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&address))
        {
            return Err(StfDbError::UndeclaredAccount { address });
        }
        Ok(self.accounts.get(&address).map(|a| {
            let prepared = self.validated_prepared_code(&address, a);
            let code_hash = prepared
                .map(|(hash, _)| hash)
                .unwrap_or_else(|| a.code_hash());
            let code = if let Some((_, code)) = prepared {
                code.clone()
            } else {
                Bytecode::new_raw(a.code.clone())
            };
            AccountInfo::new(a.balance, a.nonce, code_hash, code)
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.access_metrics.code_reads = self.access_metrics.code_reads.saturating_add(1);
        if let Some(code) = self.prepared_code.get(&code_hash) {
            return Ok(code.clone());
        }
        for a in self.accounts.values() {
            if !a.code.is_empty() && a.code_hash() == code_hash {
                return Ok(Bytecode::new_raw(a.code.clone()));
            }
        }
        Ok(Bytecode::default())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.access_metrics.storage_reads = self.access_metrics.storage_reads.saturating_add(1);
        if self.access_storage.as_ref().is_some_and(|allowed| {
            !allowed
                .get(&address)
                .is_some_and(|slots| slots.contains(&index))
        }) {
            return Err(StfDbError::UndeclaredStorage {
                address,
                slot: index,
            });
        }
        Ok(self
            .accounts
            .get(&address)
            .and_then(|a| a.storage.get(&index).copied())
            .unwrap_or_default())
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.access_metrics.block_hash_reads =
            self.access_metrics.block_hash_reads.saturating_add(1);
        Ok(self.block_hashes.get(&number).copied().unwrap_or_default())
    }
}

/// Scan opcodes while skipping PUSH immediates. This is telemetry/dispatch
/// classification only: revm remains the semantic interpreter in both cases.
pub(super) fn has_dynamic_interpreter_control_flow(code: &[u8]) -> bool {
    let mut pc = 0usize;
    while pc < code.len() {
        let opcode = code[pc];
        if matches!(
            opcode,
            0x56 | 0x57 | 0xf0 | 0xf1 | 0xf2 | 0xf4 | 0xf5 | 0xfa
        ) {
            return true;
        }
        pc += 1;
        if (0x60..=0x7f).contains(&opcode) {
            pc = pc.saturating_add(usize::from(opcode - 0x5f));
        }
    }
    false
}

impl DatabaseCommit for StateMap {
    fn commit(&mut self, changes: AddressMap<Account>) {
        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }
            self.access_metrics.account_writes =
                self.access_metrics.account_writes.saturating_add(1);
            self.access_metrics.storage_writes = self
                .access_metrics
                .storage_writes
                .saturating_add(account.storage.len() as u64);
            if self
                .access_accounts
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&address))
            {
                self.access_violation
                    .get_or_insert(StfDbError::UndeclaredAccount { address });
            }
            if let Some(allowed) = &self.access_storage {
                for key in account.storage.keys() {
                    if !allowed
                        .get(&address)
                        .is_some_and(|slots| slots.contains(key))
                    {
                        self.access_violation
                            .get_or_insert(StfDbError::UndeclaredStorage {
                                address,
                                slot: *key,
                            });
                    }
                }
            }
            if account.is_selfdestructed() {
                self.accounts.remove(&address);
                self.prepared_code_addresses.remove(&address);
                continue;
            }
            let delete_after_merge = {
                let record = self.accounts.entry(address).or_default();
                if account.is_created() {
                    record.storage.clear();
                }
                record.nonce = account.info.nonce;
                record.balance = account.info.balance;
                match &account.info.code {
                    Some(code) if !code.is_empty() => {
                        record.code = code.original_bytes();
                    }
                    _ => {
                        if account.info.code_hash == KECCAK_EMPTY {
                            record.code = Bytes::new();
                        }
                    }
                }
                for (key, slot) in account.storage {
                    let value = slot.present_value();
                    if value.is_zero() {
                        record.storage.remove(&key);
                    } else {
                        record.storage.insert(key, value);
                    }
                }
                // REVM's `Account::is_empty` ignores storage. Applying that
                // predicate before the merge deleted storage-only CREATE
                // collision targets, which is observably wrong under EIP-7610.
                record.is_empty()
            };
            if delete_after_merge {
                self.accounts.remove(&address);
                self.prepared_code_addresses.remove(&address);
                continue;
            }
            // Storage/balance/nonce mutations intentionally keep analyzed code
            // hot. If runtime bytes changed, however, this address immediately
            // falls back to revm's ordinary load/analyze path; a certified
            // policy will additionally reject the changed code post-state.
            if self
                .prepared_code_addresses
                .get(&address)
                .is_some_and(|expected| {
                    self.accounts
                        .get(&address)
                        .is_some_and(|record| record.code_hash() != *expected)
                })
            {
                self.prepared_code_addresses.remove(&address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use revm::state::EvmStorageSlot;
    use std::collections::BTreeMap;

    use crate::AccountRecord;

    fn touched_account(code: Bytes, storage: Option<(U256, U256)>) -> Account {
        let code_hash = keccak256(&code);
        let info = AccountInfo::new(U256::ZERO, 1, code_hash, Bytecode::new_raw(code));
        let mut account = Account::default();
        account.info = info.clone();
        account.original_info = Box::new(info);
        account.mark_touch();
        if let Some((slot, value)) = storage {
            account
                .storage
                .insert(slot, EvmStorageSlot::new_changed(U256::ZERO, value, 0));
        }
        account
    }

    #[test]
    fn storage_commits_keep_code_hot_but_code_commits_invalidate_the_address() {
        let address = Address::repeat_byte(0x44);
        // PUSH1 7; PUSH1 0; SSTORE; STOP (contains no dynamic control flow).
        let original = Bytes::from_static(&[0x60, 0x07, 0x60, 0x00, 0x55, 0x00]);
        let mut state = StateMap::default();
        state.accounts.insert(
            address,
            AccountRecord {
                nonce: 1,
                code: original.clone(),
                ..Default::default()
            },
        );
        let frozen = BTreeMap::from([(address, keccak256(&original))]);
        let report = state.install_prepared_runtime_code(&frozen).unwrap();
        assert_eq!(report.cached_contracts, 1);

        let mut storage_change = AddressMap::default();
        storage_change.insert(
            address,
            touched_account(original.clone(), Some((U256::ZERO, U256::from(9)))),
        );
        state.commit(storage_change);
        assert!(state.prepared_code_addresses.contains_key(&address));
        assert_eq!(state.prepared_runtime_code_len(), 1);

        let replacement = Bytes::from_static(&[0x60, 0x08, 0x60, 0x00, 0x55, 0x00]);
        let mut code_change = AddressMap::default();
        code_change.insert(address, touched_account(replacement.clone(), None));
        state.commit(code_change);
        assert!(!state.prepared_code_addresses.contains_key(&address));
        let loaded = Database::basic(&mut state, address).unwrap().unwrap();
        assert_eq!(loaded.code.unwrap().original_bytes(), replacement);

        let uncached = StateMap {
            accounts: state.accounts.clone(),
            block_hashes: state.block_hashes.clone(),
            access_accounts: state.access_accounts.clone(),
            access_storage: state.access_storage.clone(),
            access_violation: state.access_violation.clone(),
            prepared_code: BTreeMap::new(),
            prepared_code_addresses: BTreeMap::new(),
            access_metrics: state.access_metrics,
        };
        assert_eq!(state.state_root(), uncached.state_root());
    }

    #[test]
    fn push_immediates_are_not_misclassified_as_dynamic_opcodes() {
        assert!(!has_dynamic_interpreter_control_flow(&[0x60, 0xf1, 0x00]));
        assert!(has_dynamic_interpreter_control_flow(&[0xf1, 0x00]));
        assert!(has_dynamic_interpreter_control_flow(&[0x60, 0x00, 0x56]));
    }

    #[test]
    fn touched_storage_only_collision_target_is_not_deleted() {
        let address = Address::repeat_byte(0x76);
        let slot = U256::from(7);
        let value = U256::from(11);
        let mut state = StateMap::default();
        state.accounts.insert(
            address,
            AccountRecord {
                nonce: 0,
                balance: U256::ZERO,
                code: Bytes::new(),
                storage: BTreeMap::from([(slot, value)]),
            },
        );

        let mut collision = Account::default();
        collision.mark_touch();
        let mut changes = AddressMap::default();
        changes.insert(address, collision);
        state.commit(changes);

        assert_eq!(
            state
                .accounts
                .get(&address)
                .and_then(|account| account.storage.get(&slot)),
            Some(&value),
            "EIP-7610 CREATE collision must preserve pre-existing storage"
        );
    }
}
