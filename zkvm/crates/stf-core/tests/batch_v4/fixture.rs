//! The JSON fixture schema shared by every v4 batch test, and the
//! materialisation of one fixture into a compact state witness.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::Deserialize;
use stf_core::AccountRecord;
use stf_types::{
    AccountState, BlockEnvV1, CompactAccountWitnessV4, CompactStateWitnessV4,
    CompactStorageWitnessV4, ResidualAllocationV4,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Fixture {
    pub(crate) room_id: String,
    pub(crate) chain_id: u64,
    #[serde(default)]
    pub(crate) members: Vec<FixtureMember>,
    #[serde(default)]
    pub(crate) preset_hash: Option<B256>,
    #[serde(default)]
    pub(crate) preset: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) exit_program: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) settlement: Option<FixtureSettlement>,
    #[serde(default)]
    pub(crate) compact_state: Option<FixtureCompactState>,
    pub(crate) blocks: Vec<Block>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureCompactState {
    pub(crate) canonical_state_root: B256,
    pub(crate) accounts: Vec<FixtureCompactAccount>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureCompactAccount {
    pub(crate) address: Address,
    pub(crate) exists: bool,
    pub(crate) nonce: String,
    pub(crate) balance: B256,
    pub(crate) code: Bytes,
    pub(crate) canonical_storage_root: B256,
    pub(crate) account_proof: Vec<Bytes>,
    pub(crate) storage: Vec<FixtureCompactStorage>,
}

#[derive(Deserialize)]
pub(crate) struct FixtureCompactStorage {
    pub(crate) slot: B256,
    pub(crate) value: B256,
    pub(crate) proof: Vec<Bytes>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum FixtureMember {
    Address(Address),
    Funded { address: Address },
}

impl FixtureMember {
    pub(crate) fn address(&self) -> Address {
        match self {
            Self::Address(address) | Self::Funded { address } => *address,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureSettlement {
    pub(crate) deployment_domain: B256,
    pub(crate) asset_totals: Vec<FixtureAssetTotal>,
    pub(crate) residual_allocations: Vec<ResidualAllocationV4>,
    pub(crate) exit_allocations: Vec<FixtureExitAllocation>,
    pub(crate) accounting: Vec<FixtureAccounting>,
    pub(crate) asset_totals_hash: B256,
    pub(crate) exit_totals_hash: B256,
    pub(crate) fee_totals_hash: B256,
    pub(crate) exit_root: B256,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureAssetTotal {
    pub(crate) asset_id: u8,
    pub(crate) total: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureExitAllocation {
    pub(crate) slot: u8,
    pub(crate) asset_id: u8,
    pub(crate) recipient: Address,
    pub(crate) amount: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureAccounting {
    pub(crate) asset_id: u8,
    pub(crate) total: String,
    pub(crate) exit_total: String,
    pub(crate) fee_total: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Block {
    #[serde(default)]
    pub(crate) block_number: u64,
    pub(crate) env: Env,
    pub(crate) pre_state: Vec<Account>,
    pub(crate) post_state: Vec<Account>,
    pub(crate) raw_txs: Vec<Bytes>,
    pub(crate) prev_state_root: B256,
    pub(crate) expected_post_root: B256,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Env {
    pub(crate) timestamp: u64,
    pub(crate) gas_limit: u64,
    pub(crate) coinbase: Address,
    pub(crate) base_fee: String,
    pub(crate) prev_randao: B256,
    pub(crate) difficulty: String,
    pub(crate) excess_blob_gas: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Account {
    pub(crate) address: Address,
    pub(crate) nonce: String,
    pub(crate) balance: String,
    #[serde(default)]
    pub(crate) code: Option<Bytes>,
    #[serde(default)]
    pub(crate) storage: BTreeMap<B256, B256>,
}

pub(crate) fn hex_u64(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

pub(crate) fn hex_u256(s: &str) -> U256 {
    U256::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

pub(crate) fn decimal_u256(s: &str) -> U256 {
    U256::from_str_radix(s, 10).unwrap()
}

pub(crate) fn account(a: &Account) -> (Address, AccountState) {
    (
        a.address,
        AccountState {
            nonce: hex_u64(&a.nonce),
            balance: hex_u256(&a.balance),
            code: a.code.clone().unwrap_or_default(),
            storage: a
                .storage
                .iter()
                .map(|(k, v)| (U256::from_be_bytes(k.0), U256::from_be_bytes(v.0)))
                .collect(),
        },
    )
}

pub(crate) fn mapping_slot(address: Address, slot: U256) -> U256 {
    let mut encoded = [0u8; 64];
    encoded[12..32].copy_from_slice(address.as_slice());
    encoded[32..].copy_from_slice(&slot.to_be_bytes::<32>());
    U256::from_be_bytes(alloy_primitives::keccak256(encoded).0)
}

pub(crate) fn compact_state(fixture: &Fixture) -> CompactStateWitnessV4 {
    if let Some(compact) = &fixture.compact_state {
        return CompactStateWitnessV4 {
            canonical_state_root: compact.canonical_state_root,
            accounts: compact
                .accounts
                .iter()
                .map(|account| CompactAccountWitnessV4 {
                    address: account.address,
                    exists: account.exists,
                    nonce: account
                        .nonce
                        .parse()
                        .expect("compact-state nonce is decimal"),
                    balance: U256::from_be_bytes(account.balance.0),
                    code: account.code.clone(),
                    canonical_storage_root: account.canonical_storage_root,
                    account_proof: account.account_proof.clone(),
                    storage: account
                        .storage
                        .iter()
                        .map(|slot| CompactStorageWitnessV4 {
                            slot: U256::from_be_bytes(slot.slot.0),
                            value: U256::from_be_bytes(slot.value.0),
                            proof: slot.proof.clone(),
                        })
                        .collect(),
                })
                .collect(),
        };
    }

    let initial: BTreeMap<Address, AccountState> =
        fixture.blocks[0].pre_state.iter().map(account).collect();
    let mut envelope: BTreeMap<Address, BTreeSet<U256>> = BTreeMap::new();
    // revm loads the beneficiary even though this room fixes it to zero and
    // all transactions use zero priority fees. The access envelope must
    // declare that absent account explicitly.
    envelope.entry(Address::ZERO).or_default();
    for block in fixture.blocks.iter().take(4) {
        for source in block.pre_state.iter().chain(&block.post_state) {
            let slots = envelope.entry(source.address).or_default();
            slots.extend(
                source
                    .storage
                    .keys()
                    .map(|slot| U256::from_be_bytes(slot.0)),
            );
        }
    }
    // Exit derivation reads declared balance/reserve slots even when their
    // canonical value is zero. Such leaves are absent from an MPT dump, so
    // the complete room-state access envelope must add them explicitly.
    if let Some(program) = &fixture.exit_program {
        let mut asset_storage = BTreeMap::<u8, (Address, U256)>::new();
        for asset in program["assets"].as_array().unwrap() {
            if asset["kind"] == "erc20" {
                let asset_id = asset["assetId"].as_u64().unwrap() as u8;
                let token: Address = asset["token"].as_str().unwrap().parse().unwrap();
                let balance_slot =
                    U256::from_str_radix(asset["balanceSlot"].as_str().unwrap(), 10).unwrap();
                let supply_slot =
                    U256::from_str_radix(asset["totalSupplySlot"].as_str().unwrap(), 10).unwrap();
                let slots = envelope.entry(token).or_default();
                slots.insert(supply_slot);
                slots.extend(
                    fixture
                        .members
                        .iter()
                        .map(|member| mapping_slot(member.address(), balance_slot)),
                );
                asset_storage.insert(asset_id, (token, balance_slot));
            }
        }
        for position in program["positions"].as_array().unwrap() {
            let contract: Address = position["contract"].as_str().unwrap().parse().unwrap();
            let share_slot =
                U256::from_str_radix(position["shareBalanceSlot"].as_str().unwrap(), 10).unwrap();
            let supply_slot =
                U256::from_str_radix(position["totalSupplySlot"].as_str().unwrap(), 10).unwrap();
            {
                let slots = envelope.entry(contract).or_default();
                slots.insert(supply_slot);
                slots.extend(
                    fixture
                        .members
                        .iter()
                        .map(|member| mapping_slot(member.address(), share_slot)),
                );
                for excluded in position["excludedShareAccounts"].as_array().unwrap() {
                    slots.insert(mapping_slot(
                        excluded.as_str().unwrap().parse().unwrap(),
                        share_slot,
                    ));
                }
            }
            for backing in position["backings"].as_array().unwrap() {
                let asset_id = backing["assetId"].as_u64().unwrap() as u8;
                let (token, balance_slot) = asset_storage[&asset_id];
                envelope
                    .entry(token)
                    .or_default()
                    .insert(mapping_slot(contract, balance_slot));
                if let Some(reserve_slot) = backing["reserveSlot"].as_str() {
                    envelope
                        .entry(contract)
                        .or_default()
                        .insert(U256::from_str_radix(reserve_slot, 10).unwrap());
                }
            }
        }
    }

    let accounts = envelope
        .into_iter()
        .map(|(address, slots)| {
            let initial_account = initial.get(&address);
            let storage = slots
                .into_iter()
                .map(|slot| CompactStorageWitnessV4 {
                    slot,
                    value: initial_account
                        .and_then(|account| {
                            account
                                .storage
                                .iter()
                                .find_map(|(key, value)| (*key == slot).then_some(*value))
                        })
                        .unwrap_or_default(),
                    proof: Vec::new(),
                })
                .collect::<Vec<_>>();
            let (exists, nonce, balance, code, canonical_storage_root) =
                if let Some(account) = initial_account {
                    let record = AccountRecord {
                        nonce: account.nonce,
                        balance: account.balance,
                        code: account.code.clone(),
                        storage: account.storage.iter().copied().collect(),
                    };
                    (
                        true,
                        account.nonce,
                        account.balance,
                        account.code.clone(),
                        record.storage_root(),
                    )
                } else {
                    (
                        false,
                        0,
                        U256::ZERO,
                        Bytes::new(),
                        alloy_trie::EMPTY_ROOT_HASH,
                    )
                };
            CompactAccountWitnessV4 {
                address,
                exists,
                nonce,
                balance,
                code,
                canonical_storage_root,
                account_proof: Vec::new(),
                storage,
            }
        })
        .collect();
    CompactStateWitnessV4 {
        canonical_state_root: B256::ZERO,
        accounts,
    }
}

pub(crate) fn env(source: &Env, number: u64, chain_id: u64) -> BlockEnvV1 {
    BlockEnvV1 {
        number,
        timestamp: source.timestamp,
        gas_limit: source.gas_limit,
        coinbase: source.coinbase,
        base_fee: hex_u256(&source.base_fee),
        prev_randao: source.prev_randao,
        difficulty: hex_u256(&source.difficulty),
        excess_blob_gas: hex_u64(&source.excess_blob_gas),
        chain_id,
    }
}
