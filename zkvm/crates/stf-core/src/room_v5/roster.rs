//! The v5 positional approver roster and its queued add/remove transitions.

use alloy_primitives::{Address, B256};
use std::collections::{BTreeMap, BTreeSet};
use stf_types::{
    roster_changes_hash_v5, roster_root_v5, withdrawal_leaf_v5, BatchInputV5, RosterMemberV5,
};

use crate::StfError;

fn active_roster_map_v5(
    members: &[RosterMemberV5],
    capacity: u64,
    expected_root: B256,
) -> Result<BTreeMap<u64, RosterMemberV5>, StfError> {
    let computed = roster_root_v5(members, capacity)
        .ok_or_else(|| StfError::LongLivedRoom("invalid positional roster preimage".into()))?;
    if computed != expected_root {
        return Err(StfError::LongLivedRoom(
            "positional roster preimage does not match journal root".into(),
        ));
    }
    let mut by_index = BTreeMap::new();
    let mut addresses = BTreeSet::new();
    for member in members {
        if !addresses.insert(member.member)
            || by_index.insert(member.index, member.clone()).is_some()
        {
            return Err(StfError::LongLivedRoom(
                "active roster contains a duplicate index or account".into(),
            ));
        }
    }
    Ok(by_index)
}

pub(crate) fn validate_roster_transition_v5(
    input: &BatchInputV5,
) -> Result<BTreeSet<Address>, StfError> {
    let journal = &input.journal;
    if journal.authorization_mode == 1 {
        if journal.pre_roster_root != B256::ZERO
            || journal.post_roster_root != B256::ZERO
            || journal.pre_active_count != 0
            || journal.post_active_count != 0
            || journal.pre_roster_epoch != journal.post_roster_epoch
            || journal.roster_change_cursor_before != journal.roster_change_cursor_after
            || !input.pre_roster.is_empty()
            || !input.post_roster.is_empty()
            || !input.roster_changes.is_empty()
            || journal.roster_changes_hash != roster_changes_hash_v5(&[])
        {
            return Err(StfError::LongLivedRoom(
                "validity-only rooms cannot carry checkpoint approvers".into(),
            ));
        }
        return Ok(BTreeSet::new());
    }
    if journal.authorization_mode != 0 {
        return Err(StfError::LongLivedRoom(
            "unknown room authorization mode".into(),
        ));
    }
    let mut expected = active_roster_map_v5(
        &input.pre_roster,
        input.roster_capacity,
        journal.pre_roster_root,
    )?;
    let post = active_roster_map_v5(
        &input.post_roster,
        input.roster_capacity,
        journal.post_roster_root,
    )?;
    if expected.len() as u64 != journal.pre_active_count
        || post.len() as u64 != journal.post_active_count
    {
        return Err(StfError::LongLivedRoom(
            "roster active count does not match its complete preimage".into(),
        ));
    }
    let change_count = journal
        .roster_change_cursor_after
        .checked_sub(journal.roster_change_cursor_before)
        .ok_or_else(|| StfError::LongLivedRoom("roster cursor moved backwards".into()))?;
    if change_count != input.roster_changes.len() as u64
        || roster_changes_hash_v5(&input.roster_changes) != journal.roster_changes_hash
    {
        return Err(StfError::LongLivedRoom(
            "roster operations do not match cursor range or journal hash".into(),
        ));
    }
    let expected_post_epoch = journal
        .pre_roster_epoch
        .checked_add(u64::from(!input.roster_changes.is_empty()))
        .ok_or_else(|| StfError::LongLivedRoom("roster epoch overflow".into()))?;
    if journal.post_roster_epoch != expected_post_epoch {
        return Err(StfError::LongLivedRoom(
            "roster epoch does not match the proved transition".into(),
        ));
    }
    for (offset, change) in input.roster_changes.iter().enumerate() {
        let request_id = journal
            .roster_change_cursor_before
            .checked_add(offset as u64 + 1)
            .ok_or_else(|| StfError::LongLivedRoom("roster request id overflow".into()))?;
        if change.request_id != request_id || change.deadline < journal.l1_inclusion_deadline {
            return Err(StfError::LongLivedRoom(
                "roster operation request id or deadline is invalid".into(),
            ));
        }
        match change.action {
            0 => {
                if change.member == Address::ZERO
                    || change.joined_epoch != journal.post_roster_epoch
                    || change.withdrawal_commitment != B256::ZERO
                    || expected
                        .values()
                        .any(|member| member.member == change.member)
                    || expected
                        .insert(
                            change.index,
                            RosterMemberV5 {
                                index: change.index,
                                member: change.member,
                                joined_epoch: change.joined_epoch,
                            },
                        )
                        .is_some()
                {
                    return Err(StfError::LongLivedRoom(
                        "invalid add-member transition".into(),
                    ));
                }
            }
            1 => {
                let removed = expected.remove(&change.index).ok_or_else(|| {
                    StfError::LongLivedRoom("remove operation names an inactive index".into())
                })?;
                if removed.member != change.member
                    || removed.joined_epoch != change.joined_epoch
                    || change.withdrawal_commitment == B256::ZERO
                {
                    return Err(StfError::LongLivedRoom(
                        "remove operation does not match the active member".into(),
                    ));
                }
                let withdrawal = input
                    .withdrawals
                    .iter()
                    .find(|withdrawal| withdrawal.index == change.index)
                    .ok_or_else(|| {
                        StfError::LongLivedRoom(
                            "removed member has no withdrawal allocation".into(),
                        )
                    })?;
                if withdrawal.recipient != change.member
                    || withdrawal.roster_epoch != journal.post_roster_epoch
                    || withdrawal_leaf_v5(
                        journal.deployment_domain,
                        journal.room_id,
                        journal.outbox_epoch,
                        withdrawal,
                    ) != change.withdrawal_commitment
                {
                    return Err(StfError::LongLivedRoom(
                        "removed member allocation commitment is invalid".into(),
                    ));
                }
            }
            _ => return Err(StfError::LongLivedRoom("unknown roster action".into())),
        }
    }
    if expected != post {
        return Err(StfError::LongLivedRoom(
            "post-roster preimage is not the result of queued operations".into(),
        ));
    }
    Ok(input
        .pre_roster
        .iter()
        .map(|member| member.member)
        .collect())
}
