//! In-memory account state + revm Database/DatabaseCommit implementation.
//!
//! Commit semantics deliberately mirror ethereumjs `runTx` + `journal.cleanup()`
//! at Osaka (EIP-158/161 state clear is unconditionally active):
//!   - untouched accounts are ignored,
//!   - selfdestructed accounts are removed,
//!   - touched-and-empty accounts (nonce 0, balance 0, no code or storage)
//!     are REMOVED
//!     from the trie — this is what deletes the 0x00..00 coinbase that gets
//!     "paid" 0 fees every block on the free-gas L2,
//!   - newly created contracts wipe any prior storage,
//!   - zero-valued slots are deleted (an MPT never stores zero values).
//!
//! The revm `Database`/`DatabaseCommit` implementations and the two state
//! commitments live in the sibling modules; this one owns the records
//! themselves and the witness/prepared-code installation that precedes
//! execution.

mod evm;
mod roots;

use evm::has_dynamic_interpreter_control_flow;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::EMPTY_ROOT_HASH;
use revm::{primitives::KECCAK_EMPTY, state::Bytecode};
use std::collections::{BTreeMap, BTreeSet};
use stf_types::AccountState;

/// One account as tracked between transactions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountRecord {
    pub nonce: u64,
    pub balance: U256,
    /// Runtime bytecode (empty for EOAs).
    pub code: Bytes,
    /// Only non-zero slots.
    pub storage: BTreeMap<U256, U256>,
}

impl AccountRecord {
    /// Canonical room-trie emptiness. A storage-bearing record must always be
    /// committed even if its account-info fields satisfy EIP-161 emptiness.
    /// V4 witness validation rejects that non-canonical state at the boundary,
    /// but keeping the storage check here prevents any future caller from
    /// silently hiding storage behind an omitted account leaf.
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance.is_zero() && self.code.is_empty() && self.storage.is_empty()
    }

    pub fn code_hash(&self) -> B256 {
        if self.code.is_empty() {
            KECCAK_EMPTY
        } else {
            keccak256(&self.code)
        }
    }

    pub fn storage_root(&self) -> B256 {
        if self.storage.is_empty() {
            EMPTY_ROOT_HASH
        } else {
            alloy_trie::root::storage_root_unhashed(
                self.storage
                    .iter()
                    .filter(|(_, v)| !v.is_zero())
                    .map(|(k, v)| (B256::from(*k), *v)),
            )
        }
    }
}

/// Complete (tiny) L2 state: address -> account. BTreeMap for determinism.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateMap {
    pub accounts: BTreeMap<Address, AccountRecord>,
    /// Proof-authenticated rolling block history used by `BLOCKHASH`.
    pub block_hashes: BTreeMap<u64, B256>,
    /// `None` is the legacy full-state API. V4 always installs a declared
    /// account/storage envelope and fails closed on an undeclared read.
    pub access_accounts: Option<BTreeSet<Address>>,
    pub access_storage: Option<BTreeMap<Address, BTreeSet<U256>>>,
    /// `DatabaseCommit` cannot return an error, so a write outside the exact
    /// v4 envelope is latched here and checked immediately after each tx.
    pub access_violation: Option<StfDbError>,
    /// revm's hash-checked, legacy-analyzed representation for runtimes frozen
    /// by the prepared room artifact/policy. `Bytecode` is Arc-backed, so this
    /// map remains cheap to clone as state advances across a 2-4 block batch.
    /// It is execution metadata only and never contributes to the state root.
    #[doc(hidden)]
    pub prepared_code: BTreeMap<B256, Bytecode>,
    /// Address binding from the frozen artifact. A later code mutation makes
    /// that address ineligible immediately even if another account still uses
    /// the old cached hash.
    #[doc(hidden)]
    pub prepared_code_addresses: BTreeMap<Address, B256>,
    /// Execution-shape telemetry. It never contributes to a state root.
    #[doc(hidden)]
    pub access_metrics: DbAccessMetrics,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DbAccessMetrics {
    pub account_reads: u64,
    pub code_reads: u64,
    pub storage_reads: u64,
    pub block_hash_reads: u64,
    pub account_writes: u64,
    pub storage_writes: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreparedCodeCacheReport {
    pub requested_contracts: usize,
    pub cached_contracts: usize,
    /// Cached metadata is safe, but dynamic JUMP/CALL/CREATE control flow is
    /// still executed instruction-by-instruction by revm's interpreter.
    pub dynamic_interpreter_contracts: usize,
    /// Non-legacy formats remain on revm's ordinary per-load path.
    pub fallback_contracts: usize,
}

impl StateMap {
    pub fn from_input(state: &[(Address, AccountState)]) -> Self {
        let mut accounts = BTreeMap::new();
        for (address, acct) in state {
            accounts.insert(
                *address,
                AccountRecord {
                    nonce: acct.nonce,
                    balance: acct.balance,
                    code: acct.code.clone(),
                    storage: acct
                        .storage
                        .iter()
                        .filter(|(_, v)| !v.is_zero())
                        .map(|(k, v)| (*k, *v))
                        .collect(),
                },
            );
        }
        Self {
            accounts,
            block_hashes: BTreeMap::new(),
            access_accounts: None,
            access_storage: None,
            access_violation: None,
            prepared_code: BTreeMap::new(),
            prepared_code_addresses: BTreeMap::new(),
            access_metrics: DbAccessMetrics::default(),
        }
    }

    pub fn from_compact(
        accounts: BTreeMap<Address, AccountRecord>,
        access_accounts: BTreeSet<Address>,
        access_storage: BTreeMap<Address, BTreeSet<U256>>,
    ) -> Self {
        Self {
            accounts,
            block_hashes: BTreeMap::new(),
            access_accounts: Some(access_accounts),
            access_storage: Some(access_storage),
            access_violation: None,
            prepared_code: BTreeMap::new(),
            prepared_code_addresses: BTreeMap::new(),
            access_metrics: DbAccessMetrics::default(),
        }
    }

    /// Install the exact rolling history admitted for one block. Returning
    /// zero for an unavailable block is normal EVM behavior; accepting a
    /// future, duplicate, unordered, or overlong witness is not.
    pub fn install_block_hashes(
        &mut self,
        current_number: u64,
        history: &[(u64, B256)],
    ) -> Result<(), String> {
        if history.len() > 256 {
            return Err("block-hash history exceeds 256 entries".into());
        }
        let oldest = current_number.saturating_sub(256);
        let mut previous = None;
        let mut hashes = BTreeMap::new();
        for (number, hash) in history {
            if *number < oldest || *number >= current_number {
                return Err(format!(
                    "block-hash entry {number} is outside [{oldest}, {current_number})"
                ));
            }
            if previous.is_some_and(|prior| prior >= *number) {
                return Err("block-hash history must be strictly ordered and unique".into());
            }
            previous = Some(*number);
            hashes.insert(*number, *hash);
        }
        self.block_hashes = hashes;
        Ok(())
    }

    /// Instantiate revm's analyzed runtime representation once from the
    /// artifact's frozen address->code-hash set. The runtime bytes remain the
    /// consensus authority: every hash is recomputed from authenticated state,
    /// and ABI metadata is deliberately absent from this path.
    pub fn install_prepared_runtime_code(
        &mut self,
        frozen_code_hashes: &BTreeMap<Address, B256>,
    ) -> Result<PreparedCodeCacheReport, String> {
        let mut report = PreparedCodeCacheReport {
            requested_contracts: frozen_code_hashes.len(),
            ..Default::default()
        };
        let mut cache = BTreeMap::new();
        for (address, expected_hash) in frozen_code_hashes {
            let account = self
                .accounts
                .get(address)
                .ok_or_else(|| format!("prepared runtime account {address} is absent"))?;
            let actual_hash = account.code_hash();
            if actual_hash != *expected_hash {
                return Err(format!(
                    "prepared runtime code hash mismatch at {address}: expected {expected_hash}, got {actual_hash}"
                ));
            }
            if account.code.is_empty() {
                report.fallback_contracts += 1;
                continue;
            }
            let Ok(analyzed) = Bytecode::new_raw_checked(account.code.clone()) else {
                // Preserve the existing interpreter/database behavior for a
                // format revm cannot pre-analyze here; execution will surface
                // the same decode failure if this account is actually called.
                report.fallback_contracts += 1;
                continue;
            };
            if !analyzed.is_legacy() {
                report.fallback_contracts += 1;
                continue;
            }
            if has_dynamic_interpreter_control_flow(&account.code) {
                report.dynamic_interpreter_contracts += 1;
            }
            cache.insert(actual_hash, analyzed);
            report.cached_contracts += 1;
        }
        self.prepared_code = cache;
        self.prepared_code_addresses = frozen_code_hashes.clone();
        Ok(report)
    }

    /// Diagnostic/reference mode used by parity tests and profiles.
    pub fn clear_prepared_runtime_code(&mut self) {
        self.prepared_code.clear();
        self.prepared_code_addresses.clear();
    }

    pub fn prepared_runtime_code_len(&self) -> usize {
        self.prepared_code.len()
    }

    fn validated_prepared_code(
        &self,
        address: &Address,
        account: &AccountRecord,
    ) -> Option<(B256, &Bytecode)> {
        let code_hash = *self.prepared_code_addresses.get(address)?;
        let bytecode = self.prepared_code.get(&code_hash)?;
        // Runtime bytes remain authoritative even if a caller bypasses
        // DatabaseCommit and mutates the public state map directly.
        (bytecode.original_byte_slice() == account.code.as_ref()).then_some((code_hash, bytecode))
    }

    /// Canonical account vector for feeding this post-state into the next
    /// block of a batched guest execution. Empty accounts and zero slots are
    /// omitted exactly as they are from the state trie.
    pub fn to_input_state(&self) -> Vec<(Address, AccountState)> {
        self.accounts
            .iter()
            .filter(|(_, account)| !account.is_empty())
            .map(|(address, account)| {
                (
                    *address,
                    AccountState {
                        nonce: account.nonce,
                        balance: account.balance,
                        code: account.code.clone(),
                        storage: account.storage.iter().map(|(k, v)| (*k, *v)).collect(),
                    },
                )
            })
            .collect()
    }
}

/// Database-level failures. The state handed to the STF is complete in memory,
/// so the only reachable failures are accesses outside the authenticated
/// witness envelope. `BLOCKHASH` is deliberately *not* one of them: it is
/// served from the per-block history installed by `install_input_block_hashes`
/// and reads outside that window return zero, matching the EVM. The v5 batch
/// path carries that history per block (`BatchBlockV5::block_hashes`); the
/// retired v4 batch path passes none, so a v4 room contract reading BLOCKHASH
/// inside the 256-block window sees zero where the ethereumjs engine serves a
/// real hash and the batch fails with a root mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StfDbError {
    /// An account outside the declared access envelope was read.
    UndeclaredAccount { address: Address },
    /// A storage slot outside the declared access envelope was read.
    UndeclaredStorage { address: Address, slot: U256 },
}

impl core::fmt::Display for StfDbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StfDbError::UndeclaredAccount { address } => {
                write!(f, "account {address} is outside the v4 access envelope")
            }
            StfDbError::UndeclaredStorage { address, slot } => write!(
                f,
                "storage {address}[{slot:#x}] is outside the v4 access envelope"
            ),
        }
    }
}

impl std::error::Error for StfDbError {}

impl revm::database_interface::DBErrorMarker for StfDbError {}
