//! The deterministic inbox segment applied before the first block of a batch.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, B256};
use stf_types::{
    hash_inbox_entries_v4, InboxEntryWitnessV4, MemberSlotWitnessV4, MembershipDeltaWitnessV4,
};

use super::{
    ExitProgramV4, INBOX_CONSUMED, INBOX_DEPOSIT, INBOX_JOIN, INBOX_PENDING, INBOX_REFUNDED,
    INBOX_SKIPPED, JOIN_SLOT_SENTINEL, MAX_ASSETS, MAX_MEMBERS, MEMBER_ACTIVATE, MEMBER_ACTIVE,
};
use crate::StateMap;

pub(crate) fn apply_inbox_v4(
    program: &ExitProgramV4,
    state: &mut StateMap,
    entries: &[InboxEntryWitnessV4],
    deltas: &[MembershipDeltaWitnessV4],
    pre_roster: &[MemberSlotWitnessV4],
    post_roster: &[MemberSlotWitnessV4],
    cursor_before: u64,
    cursor_after: u64,
) -> Result<B256, String> {
    if cursor_after < cursor_before {
        return Err("inbox cursor moved backwards".into());
    }
    let expected_len = cursor_after
        .checked_sub(cursor_before)
        .ok_or("inbox cursor underflow")? as usize;
    if entries.len() != expected_len {
        return Err(format!(
            "inbox preimage length {} does not cover cursor {}..{}",
            entries.len(),
            cursor_before,
            cursor_after
        ));
    }
    let activations = deltas
        .iter()
        .filter(|delta| delta.action == MEMBER_ACTIVATE)
        .map(|delta| (delta.join_request_index, delta))
        .collect::<BTreeMap<_, _>>();
    if activations.len()
        != deltas
            .iter()
            .filter(|delta| delta.action == MEMBER_ACTIVATE)
            .count()
    {
        return Err("activation deltas reuse a join request index".into());
    }
    let mut consumed_joins = BTreeSet::new();
    let mut resolved_entries = entries.to_vec();
    for (offset, entry) in entries.iter().enumerate() {
        let expected_index = cursor_before
            .checked_add(offset as u64 + 1)
            .ok_or("inbox index overflow")?;
        if entry.index != expected_index {
            return Err(format!(
                "inbox entry {offset} has index {}, expected {expected_index}",
                entry.index
            ));
        }
        if entry.deposits.is_empty() || entry.deposits.len() > MAX_ASSETS {
            return Err(format!(
                "inbox entry {} has invalid deposit count",
                entry.index
            ));
        }
        if entry.status != INBOX_PENDING && entry.status != INBOX_REFUNDED {
            return Err(format!(
                "inbox entry {} input status is not Pending/Refunded",
                entry.index
            ));
        }
        let mut previous_asset = None;
        for deposit in &entry.deposits {
            if deposit.amount.is_zero()
                || previous_asset.is_some_and(|previous| deposit.asset_id <= previous)
            {
                return Err(format!(
                    "inbox entry {} deposits must be positive and sorted unique",
                    entry.index
                ));
            }
            previous_asset = Some(deposit.asset_id);
            program.asset(deposit.asset_id)?;
        }
        let recipient = match entry.kind {
            INBOX_DEPOSIT => {
                if entry.deposits.len() != 1 || entry.beneficiary_slot as usize >= MAX_MEMBERS {
                    return Err(format!("top-up inbox entry {} is malformed", entry.index));
                }
                if entry.status == INBOX_REFUNDED {
                    continue;
                }
                let slot = &pre_roster[entry.beneficiary_slot as usize];
                if slot.state != MEMBER_ACTIVE || slot.account != entry.account {
                    // A deposit is authorized by the depositor's signature
                    // only while that identity is in the pre-active roster.
                    // If the cursor crosses it after retirement, leave its
                    // escrow unconsumed and refundable instead of allowing
                    // the remaining roster to alter the frozen exit.
                    resolved_entries[offset].status = INBOX_SKIPPED;
                    continue;
                }
                resolved_entries[offset].status = INBOX_CONSUMED;
                slot.account
            }
            INBOX_JOIN => {
                if entry.beneficiary_slot != JOIN_SLOT_SENTINEL || entry.account == Address::ZERO {
                    return Err(format!("join inbox entry {} is malformed", entry.index));
                }
                if entry.status == INBOX_REFUNDED {
                    if activations.contains_key(&entry.index) {
                        return Err(format!(
                            "refunded join inbox entry {} cannot activate",
                            entry.index
                        ));
                    }
                    continue;
                }
                let Some(delta) = activations.get(&entry.index).copied() else {
                    // Permissionless join requests cannot pin the ordered
                    // inbox. Advancing past one without an activation leaves
                    // its escrow unconsumed and refundable on L1.
                    resolved_entries[offset].status = INBOX_SKIPPED;
                    continue;
                };
                resolved_entries[offset].status = INBOX_CONSUMED;
                if delta.member != entry.account {
                    return Err(format!(
                        "join inbox entry {} does not match activation acceptance",
                        entry.index
                    ));
                }
                let slot = &post_roster[delta.slot as usize];
                if slot.state != MEMBER_ACTIVE || slot.account != entry.account {
                    return Err(format!(
                        "join inbox entry {} does not match post-roster",
                        entry.index
                    ));
                }
                consumed_joins.insert(entry.index);
                slot.account
            }
            _ => return Err(format!("inbox entry {} has unsupported kind", entry.index)),
        };
        for deposit in &entry.deposits {
            program.credit(state, deposit.asset_id, recipient, deposit.amount)?;
        }
    }
    if consumed_joins.len() != activations.len() {
        return Err(
            "an activation delta does not consume an inbox join request in this segment".into(),
        );
    }
    Ok(hash_inbox_entries_v4(&resolved_entries))
}
