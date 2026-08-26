//! Operator admission receipts and L1 forced transactions.
//!
//! A "deterministically rejected" forced transaction is a proved claim: the
//! guest re-derives the reason from the raw transaction, the certified policy
//! and the terminal state, and refuses any rejection it cannot reproduce.

use alloy_primitives::{keccak256, B256, U256};
use stf_types::{
    admission_records_hash_v5, canonical_batch_data_v5, deposit_content_hash_v5,
    forced_outcomes_hash_v5, forced_rejection_reason_hash_v5, room_chain_id_v5, BatchInputV5,
    FORCED_REJECTION_POLICY_V5, FORCED_REJECTION_SENDER_V5, FORCED_REJECTION_UNDECODABLE_V5,
};

use crate::policy::{CertifiedPolicyInspectorV4, ExecutionPolicyV4};
use crate::txenv::tx_env_from_raw;
use crate::{StateMap, StfError, TransactionOutcome};

fn validate_processed_outcome_v5(
    blocks: &[(u64, Vec<TransactionOutcome>)],
    transaction_hash: B256,
    status: u8,
    l2_block_number: u64,
    transaction_index: u32,
    reason_hash: B256,
) -> Result<(), StfError> {
    if status == 2 {
        if l2_block_number != 0 || transaction_index != 0 || reason_hash == B256::ZERO {
            return Err(StfError::LongLivedRoom(
                "rejected admission has invalid location or reason".into(),
            ));
        }
        return Ok(());
    }
    if status > 1 || reason_hash != B256::ZERO {
        return Err(StfError::LongLivedRoom(
            "processed admission status or reason is invalid".into(),
        ));
    }
    let transactions = blocks
        .iter()
        .find(|(number, _)| *number == l2_block_number)
        .map(|(_, transactions)| transactions)
        .ok_or_else(|| StfError::LongLivedRoom("admission names an absent L2 block".into()))?;
    let outcome = transactions
        .get(transaction_index as usize)
        .ok_or_else(|| StfError::LongLivedRoom("admission names an absent transaction".into()))?;
    if outcome.transaction_hash != transaction_hash || outcome.status != status {
        return Err(StfError::LongLivedRoom(
            "admission outcome differs from proved EVM execution".into(),
        ));
    }
    Ok(())
}

/// Derive the deterministic reason an L1 forced transaction could never be
/// part of this batch, or `None` when the batch could have carried it.
///
/// The order is fixed so the derived reason is a function of the transaction
/// and the proved transition alone. `terminal` is the post-state of the last
/// block: a transaction the sender can still execute there is one the batch
/// composer chose not to include, which is censorship rather than a
/// deterministic rejection.
pub(crate) fn forced_rejection_reason_v5(
    raw: &[u8],
    chain_id: u64,
    policy: &ExecutionPolicyV4,
    terminal: &StateMap,
) -> Option<u8> {
    let Ok(tx) = tx_env_from_raw(raw, chain_id) else {
        return Some(FORCED_REJECTION_UNDECODABLE_V5);
    };
    if CertifiedPolicyInspectorV4::new(policy, false)
        .validate_transaction_entry(tx.caller, &tx.kind, tx.data.as_ref())
        .is_err()
    {
        return Some(FORCED_REJECTION_POLICY_V5);
    }
    let (nonce, balance) = terminal
        .accounts
        .get(&tx.caller)
        .map(|account| (account.nonce, account.balance))
        .unwrap_or((0, U256::ZERO));
    if nonce != tx.nonce || balance < tx.value {
        return Some(FORCED_REJECTION_SENDER_V5);
    }
    None
}

pub(crate) fn validate_admissions_v5(
    input: &BatchInputV5,
    executed: &[(u64, Vec<TransactionOutcome>)],
    policy: &ExecutionPolicyV4,
    terminal: &StateMap,
) -> Result<(), StfError> {
    let journal = &input.journal;
    let admission_count = journal
        .admission_cursor_after
        .checked_sub(journal.admission_cursor_before)
        .ok_or_else(|| StfError::LongLivedRoom("admission cursor moved backwards".into()))?;
    if admission_count != input.admissions.len() as u64
        || admission_records_hash_v5(&input.admissions) != journal.admission_records_hash
    {
        return Err(StfError::LongLivedRoom(
            "admission records do not match cursor range or journal hash".into(),
        ));
    }
    let forced_count = journal
        .forced_cursor_after
        .checked_sub(journal.forced_cursor_before)
        .ok_or_else(|| StfError::LongLivedRoom("forced cursor moved backwards".into()))?;
    if forced_count != input.forced_transactions.len() as u64
        || forced_outcomes_hash_v5(&input.forced_transactions) != journal.forced_outcomes_hash
    {
        return Err(StfError::LongLivedRoom(
            "forced outcomes do not match cursor range or journal hash".into(),
        ));
    }
    if journal.authorization_mode == 0 {
        if !input.admissions.is_empty()
            || !input.forced_transactions.is_empty()
            || !input.canonical_batch_data.is_empty()
            || journal.canonical_data_hash != B256::ZERO
        {
            return Err(StfError::LongLivedRoom(
                "unanimous rooms cannot carry operator admission data".into(),
            ));
        }
        return Ok(());
    }
    if journal.authorization_mode != 1 {
        return Err(StfError::LongLivedRoom(
            "unknown room authorization mode".into(),
        ));
    }
    let canonical = canonical_batch_data_v5(&input.blocks, journal.pre_state_root);
    if canonical.as_slice() != input.canonical_batch_data.as_ref()
        || keccak256(input.canonical_batch_data.as_ref()) != journal.canonical_data_hash
    {
        return Err(StfError::LongLivedRoom(
            "public canonical batch data differs from proved blocks".into(),
        ));
    }
    for (offset, record) in input.admissions.iter().enumerate() {
        let expected = journal
            .admission_cursor_before
            .checked_add(offset as u64 + 1)
            .ok_or_else(|| StfError::LongLivedRoom("admission id overflow".into()))?;
        if record.receipt.admission_id != expected
            || record.outcome.admission_id != expected
            || record.receipt.transaction_hash != record.outcome.transaction_hash
            || record.receipt.maximum_batch_index < journal.batch_index
            || record.receipt.deadline_block < journal.l1_inclusion_deadline
            || record.receipt.signature.len() != 65
        {
            return Err(StfError::LongLivedRoom(
                "admission receipt identity, deadline or signature shape is invalid".into(),
            ));
        }
        if record.receipt.deposit_inbox_id == 0 {
            if !record.receipt.admission_fee.is_zero()
                || record.receipt.deposit_content_hash != B256::ZERO
            {
                return Err(StfError::LongLivedRoom(
                    "unfunded admission carries a fee or deposit content hash".into(),
                ));
            }
        } else {
            if record.receipt.deposit_content_hash == B256::ZERO {
                return Err(StfError::LongLivedRoom(
                    "funded admission omits its deposit content hash".into(),
                ));
            }
            // When the referenced entry is crossed by this batch, re-derive
            // the exact content address and commercial fee bound in-guest.
            // References outside this cursor range are checked authoritatively
            // against room storage by RoomManager during submission.
            if let Some(deposit) = input
                .deposits
                .iter()
                .find(|deposit| deposit.inbox_id == record.receipt.deposit_inbox_id)
            {
                if deposit.refunded
                    || deposit.consumed
                    || deposit_content_hash_v5(deposit) != record.receipt.deposit_content_hash
                    || deposit.amount < record.receipt.admission_fee
                {
                    return Err(StfError::LongLivedRoom(
                        "admission deposit content or fee does not match the L1 inbox record"
                            .into(),
                    ));
                }
            }
        }
        // The record carries no raw transaction, so the guest cannot derive a
        // rejection reason for it. The one contradiction it can refuse is a
        // record claiming an admission was rejected while this very batch
        // executed that transaction.
        if record.outcome.status == 2
            && executed.iter().any(|(_, transactions)| {
                transactions
                    .iter()
                    .any(|outcome| outcome.transaction_hash == record.outcome.transaction_hash)
            })
        {
            return Err(StfError::LongLivedRoom(
                "admission is marked rejected but the batch executed that transaction".into(),
            ));
        }
        validate_processed_outcome_v5(
            executed,
            record.outcome.transaction_hash,
            record.outcome.status,
            record.outcome.l2_block_number,
            record.outcome.transaction_index,
            record.outcome.reason_hash,
        )?;
    }
    for (offset, forced) in input.forced_transactions.iter().enumerate() {
        let expected = journal
            .forced_cursor_before
            .checked_add(offset as u64 + 1)
            .ok_or_else(|| StfError::LongLivedRoom("forced id overflow".into()))?;
        let transaction_hash = keccak256(forced.raw_transaction.as_ref());
        if forced.forced_id != expected
            || forced.outcome.admission_id != expected
            || forced.outcome.transaction_hash != transaction_hash
        {
            return Err(StfError::LongLivedRoom(
                "forced transaction identity or hash is invalid".into(),
            ));
        }
        // A forced transaction is the room's censorship escape hatch, so
        // "deterministically rejected" has to be proved rather than declared.
        // The guest re-derives both the reason and its commitment; an operator
        // cannot attach an arbitrary reason hash to a transaction the batch
        // could have carried.
        if forced.outcome.status == 2 {
            let reason = forced_rejection_reason_v5(
                forced.raw_transaction.as_ref(),
                room_chain_id_v5(journal.deployment_domain, journal.room_id),
                policy,
                terminal,
            )
            .ok_or_else(|| {
                StfError::LongLivedRoom(
                    "forced transaction is executable and cannot be deterministically rejected"
                        .into(),
                )
            })?;
            if forced.outcome.reason_hash
                != forced_rejection_reason_hash_v5(transaction_hash, reason)
            {
                return Err(StfError::LongLivedRoom(
                    "forced rejection reason hash is not the proved reason".into(),
                ));
            }
        }
        validate_processed_outcome_v5(
            executed,
            transaction_hash,
            forced.outcome.status,
            forced.outcome.l2_block_number,
            forced.outcome.transaction_index,
            forced.outcome.reason_hash,
        )?;
    }
    Ok(())
}
