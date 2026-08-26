//! Repeated-record readers for the v4 witness JSON: roster slots, asset
//! totals, allocations, membership deltas and inbox entries. Each one maps a
//! single JSON array onto its borsh wire vector.

use serde_json::Value;

use super::scalars::{get, parse_address20, parse_u256_flex, parse_u64_flex};
use crate::batch_input_v4::{
    AssetTotalWireV4, ExitAllocationWireV4, InboxAssetAmountWireV4, InboxEntryWireV4,
    MemberSlotWireV4, MembershipDeltaWireV4, ResidualAllocationWireV4,
};

pub(super) fn parse_roster_slots(
    value: &Value,
    label: &str,
) -> Result<Vec<MemberSlotWireV4>, String> {
    let slots = value
        .as_array()
        .ok_or_else(|| format!("{label}: not an array"))?;
    slots
        .iter()
        .enumerate()
        .map(|(index, slot)| {
            let item_label = format!("{label}[{index}]");
            let slot = slot
                .as_object()
                .ok_or_else(|| format!("{item_label}: not an object"))?;
            let slot_number = parse_u64_flex(get(slot, "slot")?, &format!("{item_label}.slot"))?;
            let state = parse_u64_flex(get(slot, "state")?, &format!("{item_label}.state"))?;
            if slot_number > u8::MAX as u64 || state > u8::MAX as u64 {
                return Err(format!("{item_label}: slot/state exceeds u8"));
            }
            Ok(MemberSlotWireV4 {
                slot: slot_number as u8,
                state: state as u8,
                account: parse_address20(get(slot, "account")?, &format!("{item_label}.account"))?,
                joined_at_batch: parse_u64_flex(
                    get(slot, "joinedAtBatch")?,
                    &format!("{item_label}.joinedAtBatch"),
                )?,
                retired_at_batch: match get(slot, "retiredAtBatch")? {
                    Value::Null => None,
                    value => Some(parse_u64_flex(
                        value,
                        &format!("{item_label}.retiredAtBatch"),
                    )?),
                },
            })
        })
        .collect()
}

pub(super) fn parse_asset_totals(value: &Value) -> Result<Vec<AssetTotalWireV4>, String> {
    value
        .as_array()
        .ok_or("assetTotals: not an array")?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let label = format!("assetTotals[{index}]");
            let value = value
                .as_object()
                .ok_or_else(|| format!("{label}: not an object"))?;
            let asset_id = parse_u64_flex(get(value, "assetId")?, &format!("{label}.assetId"))?;
            if asset_id > u8::MAX as u64 {
                return Err(format!("{label}.assetId exceeds u8"));
            }
            Ok(AssetTotalWireV4 {
                asset_id: asset_id as u8,
                total: parse_u256_flex(get(value, "total")?, &format!("{label}.total"))?
                    .to_be_bytes::<32>(),
            })
        })
        .collect()
}

pub(super) fn parse_residual_allocations(
    value: &Value,
) -> Result<Vec<ResidualAllocationWireV4>, String> {
    value
        .as_array()
        .ok_or("residualAllocations: not an array")?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let label = format!("residualAllocations[{index}]");
            let value = value
                .as_object()
                .ok_or_else(|| format!("{label}: not an object"))?;
            let position = parse_u64_flex(get(value, "position")?, &format!("{label}.position"))?;
            let asset_id = parse_u64_flex(get(value, "assetId")?, &format!("{label}.assetId"))?;
            let recipient_slot = parse_u64_flex(
                get(value, "recipientSlot")?,
                &format!("{label}.recipientSlot"),
            )?;
            if position > u8::MAX as u64
                || asset_id > u8::MAX as u64
                || recipient_slot > u8::MAX as u64
            {
                return Err(format!("{label}: value exceeds u8"));
            }
            Ok(ResidualAllocationWireV4 {
                position: position as u8,
                asset_id: asset_id as u8,
                recipient_slot: recipient_slot as u8,
            })
        })
        .collect()
}

pub(super) fn parse_exit_allocations(
    value: &Value,
    field: &str,
) -> Result<Vec<ExitAllocationWireV4>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{field}: not an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let label = format!("{field}[{index}]");
            let value = value
                .as_object()
                .ok_or_else(|| format!("{label}: not an object"))?;
            let slot = parse_u64_flex(get(value, "slot")?, &format!("{label}.slot"))?;
            let asset_id = parse_u64_flex(get(value, "assetId")?, &format!("{label}.assetId"))?;
            if slot > u8::MAX as u64 || asset_id > u8::MAX as u64 {
                return Err(format!("{label}: slot/assetId exceeds u8"));
            }
            Ok(ExitAllocationWireV4 {
                slot: slot as u8,
                asset_id: asset_id as u8,
                recipient: parse_address20(
                    get(value, "recipient")?,
                    &format!("{label}.recipient"),
                )?,
                amount: parse_u256_flex(get(value, "amount")?, &format!("{label}.amount"))?
                    .to_be_bytes::<32>(),
            })
        })
        .collect()
}

pub(super) fn parse_membership_deltas(value: &Value) -> Result<Vec<MembershipDeltaWireV4>, String> {
    value
        .as_array()
        .ok_or("membershipDeltas: not an array")?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let label = format!("membershipDeltas[{index}]");
            let value = value
                .as_object()
                .ok_or_else(|| format!("{label}: not an object"))?;
            let action = parse_u64_flex(get(value, "action")?, &format!("{label}.action"))?;
            let slot = parse_u64_flex(get(value, "slot")?, &format!("{label}.slot"))?;
            if action > u8::MAX as u64 || slot > u8::MAX as u64 {
                return Err(format!("{label}: action/slot exceeds u8"));
            }
            Ok(MembershipDeltaWireV4 {
                action: action as u8,
                slot: slot as u8,
                member: parse_address20(get(value, "member")?, &format!("{label}.member"))?,
                join_request_index: parse_u64_flex(
                    get(value, "joinRequestIndex")?,
                    &format!("{label}.joinRequestIndex"),
                )?,
                acceptance_expiry: parse_u64_flex(
                    get(value, "acceptanceExpiry")?,
                    &format!("{label}.acceptanceExpiry"),
                )?,
            })
        })
        .collect()
}

pub(super) fn parse_inbox_entries(value: &Value) -> Result<Vec<InboxEntryWireV4>, String> {
    value
        .as_array()
        .ok_or("inboxEntries: not an array")?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let label = format!("inboxEntries[{index}]");
            let value = value
                .as_object()
                .ok_or_else(|| format!("{label}: not an object"))?;
            let kind = parse_u64_flex(get(value, "kind")?, &format!("{label}.kind"))?;
            let beneficiary_slot = parse_u64_flex(
                get(value, "beneficiarySlot")?,
                &format!("{label}.beneficiarySlot"),
            )?;
            if kind > u8::MAX as u64 || beneficiary_slot > u8::MAX as u64 {
                return Err(format!("{label}: kind/beneficiarySlot exceeds u8"));
            }
            let deposits = get(value, "deposits")?
                .as_array()
                .ok_or_else(|| format!("{label}.deposits: not an array"))?
                .iter()
                .enumerate()
                .map(|(deposit_index, deposit)| {
                    let deposit_label = format!("{label}.deposits[{deposit_index}]");
                    let deposit = deposit
                        .as_object()
                        .ok_or_else(|| format!("{deposit_label}: not an object"))?;
                    let asset_id = parse_u64_flex(
                        get(deposit, "assetId")?,
                        &format!("{deposit_label}.assetId"),
                    )?;
                    if asset_id > u8::MAX as u64 {
                        return Err(format!("{deposit_label}.assetId exceeds u8"));
                    }
                    Ok(InboxAssetAmountWireV4 {
                        asset_id: asset_id as u8,
                        amount: parse_u256_flex(
                            get(deposit, "amount")?,
                            &format!("{deposit_label}.amount"),
                        )?
                        .to_be_bytes::<32>(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(InboxEntryWireV4 {
                index: parse_u64_flex(get(value, "index")?, &format!("{label}.index"))?,
                kind: kind as u8,
                account: parse_address20(get(value, "account")?, &format!("{label}.account"))?,
                beneficiary_slot: beneficiary_slot as u8,
                status: {
                    let status = parse_u64_flex(get(value, "status")?, &format!("{label}.status"))?;
                    if status > u8::MAX as u64 {
                        return Err(format!("{label}.status exceeds u8"));
                    }
                    status as u8
                },
                deposits,
            })
        })
        .collect()
}
