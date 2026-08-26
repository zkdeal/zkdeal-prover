//! Seven-slot roster shape rules and the proved membership transition.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, B256};
use stf_types::{
    hash_membership_deltas_v4, member_roster_root_v4, MemberSlotWitnessV4, MembershipDeltaWitnessV4,
};

use super::{
    MAX_MEMBERS, MEMBER_ACTIVATE, MEMBER_ACTIVE, MEMBER_RETIRE, MEMBER_RETIRED, MEMBER_UNUSED,
};

fn validate_roster_shape(
    slots: &[MemberSlotWitnessV4],
    expected_root: B256,
    active_mask: u8,
    used_mask: u8,
    label: &str,
) -> Result<(), String> {
    if slots.len() != MAX_MEMBERS {
        return Err(format!("{label} needs seven slots"));
    }
    let mut computed_active = 0u8;
    let mut computed_used = 0u8;
    let mut occupants = BTreeSet::new();
    for (index, slot) in slots.iter().enumerate() {
        if slot.slot as usize != index {
            return Err(format!("{label} slot {index} is missing or out of order"));
        }
        match slot.state {
            MEMBER_UNUSED => {
                if slot.account != Address::ZERO
                    || slot.joined_at_batch != 0
                    || slot.retired_at_batch.is_some()
                {
                    return Err(format!("{label} unused slot {index} is not zeroed"));
                }
            }
            MEMBER_ACTIVE => {
                if slot.account == Address::ZERO || slot.retired_at_batch.is_some() {
                    return Err(format!("{label} active slot {index} is malformed"));
                }
                computed_active |= 1 << index;
                computed_used |= 1 << index;
                if !occupants.insert(slot.account) {
                    return Err(format!("{label} has a duplicate lifetime occupant"));
                }
            }
            MEMBER_RETIRED => {
                if slot.account == Address::ZERO
                    || slot.retired_at_batch.is_none()
                    || slot.retired_at_batch.unwrap() < slot.joined_at_batch
                {
                    return Err(format!("{label} retired slot {index} is malformed"));
                }
                computed_used |= 1 << index;
                if !occupants.insert(slot.account) {
                    return Err(format!("{label} has a duplicate lifetime occupant"));
                }
            }
            _ => return Err(format!("{label} slot {index} has invalid state")),
        }
    }
    if computed_active != active_mask || computed_used != used_mask {
        return Err(format!("{label} masks do not match roster"));
    }
    if member_roster_root_v4(slots) != Some(expected_root) {
        return Err(format!("{label} root does not match roster"));
    }
    Ok(())
}

pub(crate) fn validate_membership_transition_v4(
    batch_index: u64,
    before: &[MemberSlotWitnessV4],
    after: &[MemberSlotWitnessV4],
    deltas: &[MembershipDeltaWitnessV4],
    pre_root: B256,
    post_root: B256,
    pre_active_mask: u8,
    pre_used_mask: u8,
    post_active_mask: u8,
    post_used_mask: u8,
) -> Result<B256, String> {
    if batch_index == 0 {
        return Err("membership transition batch index must be positive".into());
    }
    validate_roster_shape(
        before,
        pre_root,
        pre_active_mask,
        pre_used_mask,
        "pre-roster",
    )?;
    validate_roster_shape(
        after,
        post_root,
        post_active_mask,
        post_used_mask,
        "post-roster",
    )?;
    if deltas.len() > MAX_MEMBERS {
        return Err("too many membership deltas".into());
    }
    let mut by_slot = BTreeMap::new();
    let mut previous_delta_slot = None;
    for delta in deltas {
        if delta.slot as usize >= MAX_MEMBERS
            || previous_delta_slot.is_some_and(|previous| delta.slot <= previous)
            || by_slot.insert(delta.slot, delta).is_some()
        {
            return Err("membership deltas must be sorted by unique valid slot".into());
        }
        previous_delta_slot = Some(delta.slot);
    }
    for slot in 0..MAX_MEMBERS {
        let previous = &before[slot];
        let next = &after[slot];
        match by_slot.get(&(slot as u8)).copied() {
            None if previous != next => {
                return Err(format!("slot {slot} changed without a membership delta"));
            }
            None => {}
            Some(delta) if delta.action == MEMBER_ACTIVATE => {
                if previous.state != MEMBER_UNUSED
                    || next.state != MEMBER_ACTIVE
                    || next.account != delta.member
                    || next.joined_at_batch != batch_index
                    || next.retired_at_batch.is_some()
                    || delta.member == Address::ZERO
                    || delta.join_request_index == 0
                    || delta.acceptance_expiry == 0
                {
                    return Err(format!("slot {slot} has malformed activation"));
                }
            }
            Some(delta) if delta.action == MEMBER_RETIRE => {
                if previous.state != MEMBER_ACTIVE
                    || next.state != MEMBER_RETIRED
                    || next.account != previous.account
                    || delta.member != previous.account
                    || next.joined_at_batch != previous.joined_at_batch
                    || next.retired_at_batch != Some(batch_index)
                    || delta.join_request_index != 0
                    || delta.acceptance_expiry != 0
                {
                    return Err(format!("slot {slot} has malformed retirement"));
                }
            }
            Some(_) => return Err(format!("slot {slot} has invalid membership action")),
        }
    }
    Ok(hash_membership_deltas_v4(deltas))
}
