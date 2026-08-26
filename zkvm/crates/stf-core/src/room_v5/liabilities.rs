//! Per-asset escrow accounting for one v5 batch: consumed deposits, minted
//! withdrawals, and the conservation rule between the two liability vectors.

use alloy_primitives::{Address, U256};
use std::collections::BTreeMap;
use stf_types::{inbox_records_hash_v5, liabilities_hash_v5, withdrawal_root_v5, BatchInputV5};

use super::exit::{mapping_slot_v5, read_storage_v5};
use crate::{StateMap, StfError};

fn checked_add_v5(left: U256, right: U256, label: &str) -> Result<U256, StfError> {
    left.checked_add(right)
        .ok_or_else(|| StfError::LongLivedRoom(format!("{label} overflow")))
}

/// Credit each consumed (non-refunded) deposit's net value to its beneficiary
/// as a deterministic system effect, before any app block executes.
///
/// `validate_liabilities_v5` proves only per-asset aggregate conservation:
/// nothing there binds the consumed value to the named beneficiary, so a batch
/// composer could otherwise move `pending` escrow into room control while
/// crediting nobody, or a third party, stranding the depositor. The credit is
/// app-independent: a native deposit raises the beneficiary's balance, an
/// ERC-20 deposit raises the beneficiary's policy-declared balance slot of the
/// bound in-room token. The admission fee of every receipt referencing the
/// deposit is withheld and stays unattributed inside `controlled` escrow — it
/// is the operator's compensation, reachable through the application or the
/// close sweep. An asset with no in-room representation fails closed.
///
/// METHODOLOGY REVIEW (red-team item 12, app/rollup boundary): this system
/// credit defines the protocol's deposit-arrival semantics and is enforced
/// nowhere else (guest-only guarantee). An application that additionally mints
/// its own representation of the same deposit would double-count it; certified
/// room applications must treat this credited balance as the canonical
/// arrival event.
pub(crate) fn apply_deposit_credits_v5(
    input: &BatchInputV5,
    state: &mut StateMap,
) -> Result<(), StfError> {
    for deposit in &input.deposits {
        if deposit.refunded {
            continue;
        }
        let mut fees = U256::ZERO;
        for record in &input.admissions {
            if record.receipt.deposit_inbox_id == deposit.inbox_id {
                fees = checked_add_v5(fees, record.receipt.admission_fee, "admission fee total")?;
            }
        }
        let net = deposit.amount.checked_sub(fees).ok_or_else(|| {
            StfError::LongLivedRoom(
                "admission fees exceed the consumed deposit they reference".into(),
            )
        })?;
        if net.is_zero() {
            continue;
        }
        if deposit.asset == Address::ZERO {
            if state
                .access_accounts
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&deposit.beneficiary))
            {
                return Err(StfError::LongLivedRoom(
                    "deposit beneficiary is outside the complete compact-state envelope".into(),
                ));
            }
            let account = state.accounts.entry(deposit.beneficiary).or_default();
            account.balance = checked_add_v5(account.balance, net, "beneficiary balance")?;
        } else {
            let bound = input
                .policy
                .exit
                .as_ref()
                .and_then(|exit| {
                    exit.assets
                        .iter()
                        .find(|bound| bound.asset == deposit.asset && bound.kind == 1)
                })
                .ok_or_else(|| {
                    StfError::LongLivedRoom(
                        "deposit asset has no certified in-room token binding".into(),
                    )
                })?;
            let slot = mapping_slot_v5(deposit.beneficiary, bound.balance_slot);
            let current = read_storage_v5(state, bound.token, slot, "deposit credit")?;
            let credited = checked_add_v5(current, net, "beneficiary token balance")?;
            let account = state.accounts.get_mut(&bound.token).ok_or_else(|| {
                StfError::LongLivedRoom("deposit credit token account is absent".into())
            })?;
            account.storage.insert(slot, credited);
        }
    }
    Ok(())
}

pub(crate) fn validate_liabilities_v5(input: &BatchInputV5) -> Result<(), StfError> {
    let journal = &input.journal;
    // A withdrawal is authenticated only by `validate_roster_transition_v5`
    // binding it to a signed `withdrawal_commitment` (unanimous rooms) or by
    // `validate_exit_v5` re-deriving it from the policy-bound exit queue's
    // proved post-state (validity-only rooms). A validity-only room whose
    // policy carries no exit binding has no authority that can ever move
    // `controlled` escrow into `claimable`, so no batch of such a room is
    // provable at all: refusing only batches that mint a withdrawal would let
    // the room accept deposits it can never let anyone withdraw.
    if journal.authorization_mode == 1 && input.policy.exit.is_none() {
        return Err(StfError::LongLivedRoom(
            "validity-only rooms are unprovable without an exit binding".into(),
        ));
    }
    if liabilities_hash_v5(&input.pre_liabilities) != journal.pre_liabilities_hash
        || liabilities_hash_v5(&input.post_liabilities) != journal.post_liabilities_hash
        || input.pre_liabilities.len() != input.post_liabilities.len()
    {
        return Err(StfError::LongLivedRoom(
            "liability preimages do not match the journal".into(),
        ));
    }
    let mut deposits = BTreeMap::<Address, U256>::new();
    if inbox_records_hash_v5(&input.deposits) != journal.inbox_records_hash {
        return Err(StfError::LongLivedRoom(
            "L1 inbox records do not match the journal commitment".into(),
        ));
    }
    for (offset, deposit) in input.deposits.iter().enumerate() {
        let expected_id = journal
            .inbox_cursor_before
            .checked_add(offset as u64 + 1)
            .ok_or_else(|| StfError::LongLivedRoom("inbox id overflow".into()))?;
        if deposit.inbox_id != expected_id
            || deposit.depositor == Address::ZERO
            || deposit.amount.is_zero()
            || deposit.beneficiary == Address::ZERO
            || deposit.queued_at_block == 0
            || deposit.consumed
        {
            return Err(StfError::LongLivedRoom(
                "deposit preimage is malformed or non-contiguous".into(),
            ));
        }
        // A refund is terminal but remains part of the crossed cursor range.
        // L1 steps over it without moving any value into room control.
        if deposit.refunded {
            continue;
        }
        let previous = deposits.get(&deposit.asset).copied().unwrap_or_default();
        deposits.insert(
            deposit.asset,
            checked_add_v5(previous, deposit.amount, "deposit total")?,
        );
    }
    if journal.inbox_cursor_after
        != journal
            .inbox_cursor_before
            .checked_add(input.deposits.len() as u64)
            .ok_or_else(|| StfError::LongLivedRoom("inbox cursor overflow".into()))?
    {
        return Err(StfError::LongLivedRoom(
            "inbox cursor does not match consumed deposits".into(),
        ));
    }

    let mut withdrawals = BTreeMap::<Address, U256>::new();
    for withdrawal in &input.withdrawals {
        let previous = withdrawals
            .get(&withdrawal.asset)
            .copied()
            .unwrap_or_default();
        withdrawals.insert(
            withdrawal.asset,
            checked_add_v5(previous, withdrawal.amount, "withdrawal total")?,
        );
    }
    let expected_root = withdrawal_root_v5(
        journal.deployment_domain,
        journal.room_id,
        journal.outbox_epoch,
        &input.withdrawals,
        input.withdrawal_capacity,
    )
    .ok_or_else(|| StfError::LongLivedRoom("invalid withdrawal tree preimage".into()))?;
    if expected_root != journal.withdrawal_root {
        return Err(StfError::LongLivedRoom(
            "withdrawal tree does not match the journal".into(),
        ));
    }

    let mut previous_asset = None;
    for (pre, post) in input
        .pre_liabilities
        .iter()
        .zip(input.post_liabilities.iter())
    {
        if pre.asset != post.asset
            || previous_asset.is_some_and(|asset| asset >= pre.asset)
            || pre.paid != post.paid
        {
            return Err(StfError::LongLivedRoom(
                "liabilities must use the same sorted assets and paid total".into(),
            ));
        }
        previous_asset = Some(pre.asset);
        let deposit = deposits.remove(&pre.asset).unwrap_or_default();
        let withdrawal = withdrawals.remove(&pre.asset).unwrap_or_default();
        let expected_pending = pre
            .pending
            .checked_sub(deposit)
            .ok_or_else(|| StfError::LongLivedRoom("deposit exceeds pending liability".into()))?;
        let expected_claimable = checked_add_v5(pre.claimable, withdrawal, "claimable total")?;
        let available_controlled = checked_add_v5(pre.controlled, deposit, "controlled total")?;
        let expected_controlled =
            available_controlled
                .checked_sub(withdrawal)
                .ok_or_else(|| {
                    StfError::LongLivedRoom("withdrawal exceeds controlled liability".into())
                })?;
        if post.pending != expected_pending
            || post.claimable != expected_claimable
            || post.controlled != expected_controlled
        {
            return Err(StfError::LongLivedRoom(
                "post-liabilities do not conserve consumed deposits and withdrawals".into(),
            ));
        }
        // A closing batch is the last statement L1 will ever accept for this
        // room, so no later withdrawal root can be produced. Escrow still
        // classified as `controlled` would be unreachable forever; `pending`
        // remains refundable through the L1 deposit-expiry path and is
        // therefore left to the operator.
        if journal.close && !post.controlled.is_zero() {
            return Err(StfError::LongLivedRoom(
                "closing batch leaves controlled escrow that could never be withdrawn".into(),
            ));
        }
    }
    if !deposits.is_empty() || !withdrawals.is_empty() {
        return Err(StfError::LongLivedRoom(
            "deposit or withdrawal names an unsupported asset".into(),
        ));
    }
    Ok(())
}
