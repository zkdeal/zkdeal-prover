//! Terminal settlement: per-asset accounting, pro-rata position unwinding and
//! the exit-claim leaves L1 will honour.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{B256, U256};
use stf_types::{
    claim_merkle_root_v4, hash_asset_totals_v4, hash_exit_totals_v4, hash_fee_totals_v4,
    AssetAccountingV4, AssetTotalWitnessV4, ExitAllocationV4, MemberSlotWitnessV4,
    ResidualAllocationV4,
};

use super::{
    add_u256, mapping_slot, mul_div_floor, read_storage, DerivedSettlementV4, ExitAssetKindV4,
    ExitProgramV4, MAX_ASSETS, MAX_MEMBERS, MEMBER_UNUSED,
};
use crate::StateMap;

pub(crate) fn derive_settlement_v4(
    program: &ExitProgramV4,
    state: &StateMap,
    roster: &[MemberSlotWitnessV4],
    totals: &[AssetTotalWitnessV4],
    residual_allocations: &[ResidualAllocationV4],
    deployment_id: B256,
    room_id: u64,
) -> Result<DerivedSettlementV4, String> {
    if totals.len() != program.assets.len() {
        return Err("asset totals must exactly cover the exit-program asset set".into());
    }
    let mut total_map = BTreeMap::new();
    for (index, total) in totals.iter().enumerate() {
        if total.asset_id != program.assets[index].asset_id
            || total_map.insert(total.asset_id, total.total).is_some()
        {
            return Err("asset totals must be sorted and exactly match exit-program assets".into());
        }
    }
    let used = roster
        .iter()
        .filter(|slot| slot.state != MEMBER_UNUSED)
        .collect::<Vec<_>>();
    if used.is_empty() {
        return Err("settlement requires at least one lifetime-used member".into());
    }
    let mut amounts = BTreeMap::<(u8, u8), U256>::new();
    for slot in &used {
        for asset in &program.assets {
            let balance = match &asset.kind {
                ExitAssetKindV4::Native => state
                    .accounts
                    .get(&slot.account)
                    .map(|account| account.balance)
                    .unwrap_or_default(),
                ExitAssetKindV4::Erc20 {
                    token,
                    balance_slot,
                    ..
                } => read_storage(
                    state,
                    *token,
                    mapping_slot(slot.account, *balance_slot),
                    "member ERC-20 exit balance",
                )?,
            };
            amounts.insert((slot.slot, asset.asset_id), balance);
        }
    }

    let mut residual_choices = BTreeMap::new();
    let mut previous_key = None;
    for residual in residual_allocations {
        let key = (residual.position, residual.asset_id);
        if residual.position as usize >= program.positions.len()
            || residual.recipient_slot as usize >= MAX_MEMBERS
            || previous_key.is_some_and(|previous| key <= previous)
            || residual_choices
                .insert(key, residual.recipient_slot)
                .is_some()
        {
            return Err("residual allocations must be sorted, unique and in range".into());
        }
        previous_key = Some(key);
    }

    let mut consumed_residuals = BTreeSet::new();
    for (position_index, position) in program.positions.iter().enumerate() {
        let total_supply = read_storage(
            state,
            position.contract,
            position.total_supply_slot,
            "position totalSupply",
        )?;
        let mut member_shares = Vec::with_capacity(used.len());
        let mut attributed_supply = U256::ZERO;
        for slot in &used {
            let shares = read_storage(
                state,
                position.contract,
                mapping_slot(slot.account, position.share_balance_slot),
                "member position shares",
            )?;
            attributed_supply = add_u256(attributed_supply, shares, "position share attribution")?;
            member_shares.push((slot.slot, shares));
        }
        for account in &position.excluded_share_accounts {
            let shares = read_storage(
                state,
                position.contract,
                mapping_slot(*account, position.share_balance_slot),
                "excluded position shares",
            )?;
            attributed_supply = add_u256(attributed_supply, shares, "position excluded shares")?;
        }
        if attributed_supply != total_supply {
            return Err(format!("position {position_index} has shares outside used members and explicitly excluded accounts"));
        }

        for backing in &position.backings {
            let asset = program.asset(backing.asset_id)?;
            let ExitAssetKindV4::Erc20 {
                token,
                balance_slot,
                ..
            } = asset.kind
            else {
                return Err("pro-rata backing must be ERC-20".into());
            };
            let backing_balance = read_storage(
                state,
                token,
                mapping_slot(position.contract, balance_slot),
                "position token backing",
            )?;
            if let Some(reserve_slot) = backing.reserve_slot {
                let reserve =
                    read_storage(state, position.contract, reserve_slot, "position reserve")?;
                if reserve != backing_balance {
                    return Err(format!("position {position_index} asset {} reserve is not synchronized to token balance", backing.asset_id));
                }
            }
            if total_supply.is_zero() && !backing_balance.is_zero() {
                return Err(format!(
                    "position {position_index} has backing with zero share supply"
                ));
            }
            let mut distributed = U256::ZERO;
            if !total_supply.is_zero() {
                for (slot, shares) in &member_shares {
                    let claim = mul_div_floor(
                        backing_balance,
                        *shares,
                        total_supply,
                        "position pro-rata claim",
                    )?;
                    let entry = amounts.entry((*slot, backing.asset_id)).or_default();
                    *entry = add_u256(*entry, claim, "position exit allocation")?;
                    distributed = add_u256(distributed, claim, "position distributed total")?;
                }
            }
            let residual = backing_balance
                .checked_sub(distributed)
                .ok_or("position distribution exceeds backing")?;
            let residual_key = (position_index as u8, backing.asset_id);
            match (
                residual.is_zero(),
                residual_choices.get(&residual_key).copied(),
            ) {
                (true, None) => {}
                (true, Some(_)) => {
                    return Err(format!(
                        "position {position_index} asset {} declares a zero residual",
                        backing.asset_id
                    ));
                }
                (false, None) => {
                    return Err(format!(
                        "position {position_index} asset {} has an unallocated residual",
                        backing.asset_id
                    ));
                }
                (false, Some(slot)) => {
                    let recipient = roster
                        .get(slot as usize)
                        .filter(|member| member.state != MEMBER_UNUSED)
                        .ok_or_else(|| {
                            format!("position {position_index} residual recipient slot is unused")
                        })?;
                    let entry = amounts
                        .entry((recipient.slot, backing.asset_id))
                        .or_default();
                    *entry = add_u256(*entry, residual, "position residual allocation")?;
                    consumed_residuals.insert(residual_key);
                }
            }
        }
    }
    if consumed_residuals.len() != residual_choices.len() {
        return Err("a residual allocation does not identify a nonzero derived residual".into());
    }

    let mut exit_allocations = Vec::new();
    let mut accounting = Vec::with_capacity(program.assets.len());
    for asset in &program.assets {
        if let ExitAssetKindV4::Erc20 {
            token,
            total_supply_slot,
            ..
        } = asset.kind
        {
            let supply = read_storage(state, token, total_supply_slot, "exit asset totalSupply")?;
            let funded = total_map[&asset.asset_id];
            if supply != funded {
                return Err(format!(
                    "asset {} room token supply {supply} does not match L1-funded total {funded}",
                    asset.asset_id
                ));
            }
        }
        let mut exit_total = U256::ZERO;
        for slot in &used {
            let amount = amounts
                .get(&(slot.slot, asset.asset_id))
                .copied()
                .unwrap_or_default();
            if !amount.is_zero() {
                exit_allocations.push(ExitAllocationV4 {
                    slot: slot.slot,
                    asset_id: asset.asset_id,
                    recipient: slot.account,
                    amount,
                });
                exit_total = add_u256(exit_total, amount, "asset exit total")?;
            }
        }
        let total = total_map[&asset.asset_id];
        if exit_total != total {
            return Err(format!(
                "asset {} is not exactly conserved: exits {exit_total}, funded {total}",
                asset.asset_id
            ));
        }
        accounting.push(AssetAccountingV4 {
            asset_id: asset.asset_id,
            total,
            exit_total,
            fee_total: U256::ZERO,
        });
    }
    // The loops above are slot-major only within each asset, so enforce the
    // protocol's canonical (slot,asset) order before hashing the Merkle leaves.
    exit_allocations.sort_by_key(|allocation| (allocation.slot, allocation.asset_id));
    let asset_totals_hash = hash_asset_totals_v4(&accounting);
    let exit_totals_hash = hash_exit_totals_v4(&accounting);
    let fee_totals_hash = hash_fee_totals_v4(&accounting);
    let exit_root = claim_merkle_root_v4(deployment_id, room_id, &exit_allocations);
    Ok(DerivedSettlementV4 {
        exit_allocations,
        accounting,
        asset_totals_hash,
        exit_totals_hash,
        fee_totals_hash,
        exit_root,
    })
}

/// Authenticate the exact canonical allocation preimage accepted by the
/// preceding L1 transition. These checks intentionally mirror
/// `RoomCodecV4.computeExitRoot`: nonzero leaves, strictly increasing
/// `(slot,asset)` keys, used slots, declared assets and roster recipients.
pub(crate) fn authenticate_previous_exit_allocations_v4(
    program: &ExitProgramV4,
    roster: &[MemberSlotWitnessV4],
    used_mask: u8,
    allocations: &[ExitAllocationV4],
    expected_root: B256,
    deployment_id: B256,
    room_id: u64,
) -> Result<(), String> {
    if allocations.len() > MAX_MEMBERS * program.assets.len() {
        return Err("previous exit allocation list exceeds room dimensions".into());
    }
    let mut previous_key = None;
    for allocation in allocations {
        // Asset ids are sorted and unique but never required to be contiguous
        // from zero, so declared membership is `program.asset(...)`, not a
        // comparison against the list length. The `MAX_ASSETS` bound is what
        // the `(slot, asset)` sort key below assumes.
        if allocation.slot as usize >= MAX_MEMBERS
            || allocation.asset_id as usize >= MAX_ASSETS
            || program.asset(allocation.asset_id).is_err()
            || allocation.amount.is_zero()
        {
            return Err("previous exit allocations contain an out-of-range or zero leaf".into());
        }
        let bit = 1u8 << allocation.slot;
        let member = roster
            .get(allocation.slot as usize)
            .filter(|member| member.slot == allocation.slot && member.state != MEMBER_UNUSED)
            .ok_or("previous exit allocation references an unused roster slot")?;
        if used_mask & bit == 0 || allocation.recipient != member.account {
            return Err("previous exit allocation recipient/slot does not match pre-roster".into());
        }
        let key = u16::from(allocation.slot) * MAX_ASSETS as u16 + u16::from(allocation.asset_id);
        if previous_key.is_some_and(|previous| key <= previous) {
            return Err("previous exit allocations must be sorted and unique".into());
        }
        previous_key = Some(key);
    }
    let computed = claim_merkle_root_v4(deployment_id, room_id, allocations);
    if computed != expected_root {
        return Err(format!(
            "previous exit allocation root {computed} does not match previousExitRoot {expected_root}"
        ));
    }
    Ok(())
}

/// Slots retired before this batch are immutable L1 claims. Newly retired
/// slots are deliberately excluded: their current post-state allocation is
/// what becomes frozen by this batch.
pub(crate) fn enforce_retired_exit_continuity_v4(
    previous: &[ExitAllocationV4],
    current: &[ExitAllocationV4],
    pre_used_mask: u8,
    pre_active_mask: u8,
) -> Result<(), String> {
    let already_retired = pre_used_mask & !pre_active_mask & 0x7f;
    if already_retired == 0 {
        return Ok(());
    }
    let previous_amounts = previous
        .iter()
        .map(|allocation| ((allocation.slot, allocation.asset_id), allocation.amount))
        .collect::<BTreeMap<_, _>>();
    let current_amounts = current
        .iter()
        .map(|allocation| ((allocation.slot, allocation.asset_id), allocation.amount))
        .collect::<BTreeMap<_, _>>();
    let keys = previous_amounts
        .keys()
        .chain(current_amounts.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    for (slot, asset_id) in keys {
        if already_retired & (1u8 << slot) == 0 {
            continue;
        }
        let before = previous_amounts
            .get(&(slot, asset_id))
            .copied()
            .unwrap_or_default();
        let after = current_amounts
            .get(&(slot, asset_id))
            .copied()
            .unwrap_or_default();
        if before != after {
            return Err(format!(
                "retired slot {slot} asset {asset_id} exit changed from {before} to {after}"
            ));
        }
    }
    Ok(())
}
