//! The canonical exit-program preimage: its JSON schema, the parser that
//! authenticates it against the preset commitment, and the deposit credit it
//! applies to room-local state.

use std::collections::BTreeSet;

use alloy_primitives::{keccak256, Address, U256};
use serde::Deserialize;

use super::{
    add_u256, mapping_slot, read_storage, write_storage, ExitAssetKindV4, ExitAssetV4,
    ExitProgramV4, PositionBackingV4, ProRataPositionV4, MAX_ASSETS,
};
use crate::policy::ExecutionPolicyV4;
use crate::{AccountRecord, StateMap};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExitProgramJsonV4 {
    version: u8,
    assets: Vec<ExitAssetJsonV4>,
    #[serde(default)]
    positions: Vec<ProRataPositionJsonV4>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExitAssetJsonV4 {
    asset_id: u8,
    kind: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    balance_slot: Option<String>,
    #[serde(default)]
    total_supply_slot: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProRataPositionJsonV4 {
    kind: String,
    contract: String,
    share_balance_slot: String,
    total_supply_slot: String,
    #[serde(default)]
    excluded_share_accounts: Vec<String>,
    backings: Vec<PositionBackingJsonV4>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PositionBackingJsonV4 {
    asset_id: u8,
    #[serde(default)]
    reserve_slot: Option<String>,
}

fn parse_address(value: &str, label: &str) -> Result<Address, String> {
    value
        .parse::<Address>()
        .map_err(|error| format!("{label}: invalid address: {error}"))
}

fn parse_decimal_u256(value: &str, label: &str) -> Result<U256, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{label}: expected canonical decimal uint256"));
    }
    U256::from_str_radix(value, 10).map_err(|_| format!("{label}: uint256 overflow"))
}

impl ExitProgramV4 {
    pub(crate) fn parse(canonical_json: &[u8], policy: &ExecutionPolicyV4) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_slice(canonical_json)
            .map_err(|error| format!("exit program JSON: {error}"))?;
        let canonical = serde_json::to_vec(&value)
            .map_err(|error| format!("canonical exit program JSON: {error}"))?;
        if canonical.as_slice() != canonical_json {
            return Err("exit program JSON is not canonical".into());
        }
        if keccak256(&canonical) != policy.exit_program_id {
            return Err("canonical exit program JSON does not hash to preset.exitProgramId".into());
        }
        let parsed: ExitProgramJsonV4 = serde_json::from_value(value)
            .map_err(|error| format!("exit program schema: {error}"))?;
        if parsed.version != 4 {
            return Err("exit program version must be 4".into());
        }
        if parsed.assets.is_empty() || parsed.assets.len() > MAX_ASSETS {
            return Err("exit program needs 1..16 assets".into());
        }

        let mut assets = Vec::with_capacity(parsed.assets.len());
        let mut previous_asset = None;
        for (index, asset) in parsed.assets.into_iter().enumerate() {
            if previous_asset.is_some_and(|previous| asset.asset_id <= previous) {
                return Err("exit program assets must be sorted by unique assetId".into());
            }
            previous_asset = Some(asset.asset_id);
            let kind = match asset.kind.as_str() {
                "native" => {
                    if asset.asset_id != 0
                        || asset.token.is_some()
                        || asset.balance_slot.is_some()
                        || asset.total_supply_slot.is_some()
                    {
                        return Err("native exit asset must be id 0 and have no token/slots".into());
                    }
                    ExitAssetKindV4::Native
                }
                "erc20" => {
                    let token = parse_address(
                        asset
                            .token
                            .as_deref()
                            .ok_or("erc20 exit asset has no token")?,
                        &format!("assets[{index}].token"),
                    )?;
                    let balance_slot = parse_decimal_u256(
                        asset
                            .balance_slot
                            .as_deref()
                            .ok_or("erc20 exit asset has no balanceSlot")?,
                        &format!("assets[{index}].balanceSlot"),
                    )?;
                    let total_supply_slot = parse_decimal_u256(
                        asset
                            .total_supply_slot
                            .as_deref()
                            .ok_or("erc20 exit asset has no totalSupplySlot")?,
                        &format!("assets[{index}].totalSupplySlot"),
                    )?;
                    if policy.certified && !policy.code_hashes.contains_key(&token) {
                        return Err(format!("exit asset token {token} is not code-hash pinned"));
                    }
                    ExitAssetKindV4::Erc20 {
                        token,
                        balance_slot,
                        total_supply_slot,
                    }
                }
                other => {
                    return Err(format!(
                        "assets[{index}]: unsupported exit asset kind {other}"
                    ))
                }
            };
            assets.push(ExitAssetV4 {
                asset_id: asset.asset_id,
                kind,
            });
        }

        for preset_asset in &policy.preset_asset_ids {
            if !assets.iter().any(|asset| asset.asset_id == *preset_asset) {
                return Err(format!(
                    "preset asset {preset_asset} is absent from exit program"
                ));
            }
        }

        let known_assets = assets
            .iter()
            .map(|asset| asset.asset_id)
            .collect::<BTreeSet<_>>();
        let mut positions = Vec::with_capacity(parsed.positions.len());
        let mut seen_contracts = BTreeSet::new();
        for (position_index, position) in parsed.positions.into_iter().enumerate() {
            if position.kind != "pro-rata" {
                return Err(format!(
                    "positions[{position_index}]: unsupported kind {}",
                    position.kind
                ));
            }
            let contract = parse_address(
                &position.contract,
                &format!("positions[{position_index}].contract"),
            )?;
            if !seen_contracts.insert(contract) {
                return Err("exit positions must use unique contract addresses".into());
            }
            if policy.certified && !policy.code_hashes.contains_key(&contract) {
                return Err(format!("exit position {contract} is not code-hash pinned"));
            }
            let share_balance_slot = parse_decimal_u256(
                &position.share_balance_slot,
                &format!("positions[{position_index}].shareBalanceSlot"),
            )?;
            let total_supply_slot = parse_decimal_u256(
                &position.total_supply_slot,
                &format!("positions[{position_index}].totalSupplySlot"),
            )?;
            if position.backings.is_empty() {
                return Err(format!("positions[{position_index}] has no backing assets"));
            }
            let mut excluded_share_accounts = Vec::new();
            let mut previous_excluded = None;
            for (excluded_index, account) in position.excluded_share_accounts.iter().enumerate() {
                let account = parse_address(
                    account,
                    &format!("positions[{position_index}].excludedShareAccounts[{excluded_index}]"),
                )?;
                if account == Address::ZERO
                    || previous_excluded.is_some_and(|previous| account <= previous)
                {
                    return Err(format!("positions[{position_index}] excluded accounts must be sorted, unique and nonzero"));
                }
                previous_excluded = Some(account);
                excluded_share_accounts.push(account);
            }
            let mut backings = Vec::new();
            let mut previous_backing = None;
            for (backing_index, backing) in position.backings.into_iter().enumerate() {
                if !known_assets.contains(&backing.asset_id)
                    || previous_backing.is_some_and(|previous| backing.asset_id <= previous)
                {
                    return Err(format!(
                        "positions[{position_index}] backings must be sorted unique known assets"
                    ));
                }
                previous_backing = Some(backing.asset_id);
                let asset = assets
                    .iter()
                    .find(|asset| asset.asset_id == backing.asset_id)
                    .unwrap();
                if !matches!(asset.kind, ExitAssetKindV4::Erc20 { .. }) {
                    return Err(format!(
                        "positions[{position_index}].backings[{backing_index}] must be ERC-20"
                    ));
                }
                let reserve_slot = backing
                    .reserve_slot
                    .as_deref()
                    .map(|value| {
                        parse_decimal_u256(
                            value,
                            &format!(
                                "positions[{position_index}].backings[{backing_index}].reserveSlot"
                            ),
                        )
                    })
                    .transpose()?;
                backings.push(PositionBackingV4 {
                    asset_id: backing.asset_id,
                    reserve_slot,
                });
            }
            positions.push(ProRataPositionV4 {
                contract,
                share_balance_slot,
                total_supply_slot,
                excluded_share_accounts,
                backings,
            });
        }

        Ok(Self { assets, positions })
    }

    pub(super) fn asset(&self, asset_id: u8) -> Result<&ExitAssetV4, String> {
        self.assets
            .iter()
            .find(|asset| asset.asset_id == asset_id)
            .ok_or_else(|| format!("asset {asset_id} is not declared by the exit program"))
    }

    pub(super) fn credit(
        &self,
        state: &mut StateMap,
        asset_id: u8,
        recipient: Address,
        amount: U256,
    ) -> Result<(), String> {
        if amount.is_zero() {
            return Err("inbox deposit amount must be positive".into());
        }
        match &self.asset(asset_id)?.kind {
            ExitAssetKindV4::Native => {
                if state
                    .access_accounts
                    .as_ref()
                    .is_some_and(|allowed| !allowed.contains(&recipient))
                {
                    return Err(format!("inbox recipient {recipient} is outside the complete compact-state envelope"));
                }
                let account = state
                    .accounts
                    .entry(recipient)
                    .or_insert_with(AccountRecord::default);
                account.balance = add_u256(account.balance, amount, "native inbox credit")?;
            }
            ExitAssetKindV4::Erc20 {
                token,
                balance_slot,
                total_supply_slot,
            } => {
                let recipient_slot = mapping_slot(recipient, *balance_slot);
                let current = read_storage(state, *token, recipient_slot, "ERC-20 inbox balance")?;
                write_storage(
                    state,
                    *token,
                    recipient_slot,
                    add_u256(current, amount, "ERC-20 inbox balance")?,
                    "ERC-20 inbox balance",
                )?;
                let supply = read_storage(state, *token, *total_supply_slot, "ERC-20 totalSupply")?;
                write_storage(
                    state,
                    *token,
                    *total_supply_slot,
                    add_u256(supply, amount, "ERC-20 totalSupply")?,
                    "ERC-20 totalSupply",
                )?;
            }
        }
        Ok(())
    }
}
