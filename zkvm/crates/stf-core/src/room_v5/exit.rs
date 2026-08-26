//! Proof-derived validity-only exits.
//!
//! The policy-bound room-local exit queue is the only authority that can move
//! `controlled` escrow into `claimable`: withdrawal leaves are re-derived from
//! the proved post-state records here, and a closing batch additionally sweeps
//! every residual controlled balance pro rata over the terminal code-free
//! accounts, with dust and unattributable residue paid to the binding's
//! fallback recipient. Nothing in this module treats witness-supplied
//! withdrawals as authority; they are compared against the derivation.

use alloy_primitives::{keccak256, Address, U256};
use std::collections::BTreeMap;
use stf_types::{BatchInputV5, ExitBindingV5, WithdrawalV5, MAX_WITHDRAWAL_CAPACITY_V5};

use crate::{StateMap, StfError};

/// The positional withdrawal-tree capacity for `leaf_count` derived exit
/// leaves: the next power of two, or zero for an empty allocation.
///
/// A close sweep is bounded by `MAX_COMPACT_ACCOUNTS_V4` code-free accounts
/// times the per-room asset list, and record-minted leaves by the compact
/// storage envelope, so a valid batch never reaches this cap. Refusing an
/// over-cap allocation explicitly keeps the failure a named exit-allocation
/// error rather than the misleading "invalid withdrawal tree preimage" the
/// `None` from `withdrawal_root_v5` would otherwise surface.
pub(crate) fn withdrawal_tree_capacity_v5(leaf_count: usize) -> Result<u64, StfError> {
    if leaf_count == 0 {
        return Ok(0);
    }
    if leaf_count as u64 > MAX_WITHDRAWAL_CAPACITY_V5 {
        return Err(StfError::LongLivedRoom(
            "exit allocation exceeds MAX_WITHDRAWAL_CAPACITY_V5".into(),
        ));
    }
    Ok((leaf_count as u64).next_power_of_two())
}

/// One exit obligation derived from proved room state, before it is given a
/// positional index in the withdrawal tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExitRecordV5 {
    pub(crate) recipient: Address,
    pub(crate) asset: Address,
    pub(crate) amount: U256,
}

pub(crate) fn mapping_slot_v5(account: Address, slot: U256) -> U256 {
    let mut encoded = [0u8; 64];
    encoded[12..32].copy_from_slice(account.as_slice());
    encoded[32..].copy_from_slice(&slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(encoded).0)
}

pub(crate) fn read_storage_v5(
    state: &StateMap,
    address: Address,
    slot: U256,
    label: &str,
) -> Result<U256, StfError> {
    if state.access_storage.as_ref().is_some_and(|allowed| {
        !allowed
            .get(&address)
            .is_some_and(|slots| slots.contains(&slot))
    }) {
        return Err(StfError::LongLivedRoom(format!(
            "{label}: storage {address}[{slot:#x}] is outside the complete compact-state envelope"
        )));
    }
    Ok(state
        .accounts
        .get(&address)
        .and_then(|account| account.storage.get(&slot))
        .copied()
        .unwrap_or_default())
}

fn address_from_word_v5(value: U256, label: &str) -> Result<Address, StfError> {
    let bytes = value.to_be_bytes::<32>();
    if bytes[..12].iter().any(|byte| *byte != 0) {
        return Err(StfError::LongLivedRoom(format!(
            "{label} is wider than an address"
        )));
    }
    Ok(Address::from_slice(&bytes[12..]))
}

fn checked_add_exit_v5(left: U256, right: U256, label: &str) -> Result<U256, StfError> {
    left.checked_add(right)
        .ok_or_else(|| StfError::LongLivedRoom(format!("{label} overflow")))
}

/// Read the proved exit-record cursor out of the queue contract's storage.
pub(crate) fn exit_record_count_v5(
    binding: &ExitBindingV5,
    state: &StateMap,
) -> Result<u64, StfError> {
    let count = read_storage_v5(
        state,
        binding.queue_contract,
        binding.count_slot,
        "exit record count",
    )?;
    u64::try_from(count)
        .map_err(|_| StfError::LongLivedRoom("exit record count exceeds u64".into()))
}

/// Read records `from..to` out of the terminal queue storage. Every record
/// must name a non-zero recipient, a positive amount and a declared asset.
pub(crate) fn read_exit_records_v5(
    binding: &ExitBindingV5,
    terminal_state: &StateMap,
    from: u64,
    to: u64,
) -> Result<Vec<ExitRecordV5>, StfError> {
    let mut records = Vec::new();
    for index in from..to {
        let offset = U256::from(index)
            .checked_mul(U256::from(3u64))
            .and_then(|words| binding.records_base_slot.checked_add(words))
            .ok_or_else(|| StfError::LongLivedRoom("exit record slot overflow".into()))?;
        let recipient_slot = offset;
        let asset_slot = checked_add_exit_v5(offset, U256::from(1u64), "exit record slot")?;
        let amount_slot = checked_add_exit_v5(offset, U256::from(2u64), "exit record slot")?;
        let recipient = address_from_word_v5(
            read_storage_v5(
                terminal_state,
                binding.queue_contract,
                recipient_slot,
                "exit record recipient",
            )?,
            "exit record recipient",
        )?;
        let asset = address_from_word_v5(
            read_storage_v5(
                terminal_state,
                binding.queue_contract,
                asset_slot,
                "exit record asset",
            )?,
            "exit record asset",
        )?;
        let amount = read_storage_v5(
            terminal_state,
            binding.queue_contract,
            amount_slot,
            "exit record amount",
        )?;
        if recipient == Address::ZERO
            || amount.is_zero()
            || !binding.assets.iter().any(|bound| bound.asset == asset)
        {
            return Err(StfError::LongLivedRoom(
                "exit record has a zero recipient, zero amount, or undeclared asset".into(),
            ));
        }
        records.push(ExitRecordV5 {
            recipient,
            asset,
            amount,
        });
    }
    Ok(records)
}

/// Allocate each bound asset's residual controlled escrow pro rata over the
/// code-free non-zero-address accounts of the terminal state. Rounding dust
/// and residue with no balance to attribute it against are paid to the
/// binding's fallback recipient as the last leaf of that asset.
pub(crate) fn derive_close_sweep_v5(
    binding: &ExitBindingV5,
    terminal_state: &StateMap,
    residuals: &BTreeMap<Address, U256>,
) -> Result<Vec<ExitRecordV5>, StfError> {
    let mut leaves = Vec::new();
    for bound in &binding.assets {
        let residual = residuals.get(&bound.asset).copied().unwrap_or_default();
        if residual.is_zero() {
            continue;
        }
        // The terminal state map is a BTreeMap, so this enumeration is
        // address-ascending, which is the consensus ordering of the leaves.
        let mut balances = Vec::new();
        let mut total = U256::ZERO;
        for (address, account) in &terminal_state.accounts {
            if *address == Address::ZERO || !account.code.is_empty() {
                continue;
            }
            let balance = match bound.kind {
                0 => account.balance,
                1 => read_storage_v5(
                    terminal_state,
                    bound.token,
                    mapping_slot_v5(*address, bound.balance_slot),
                    "exit sweep ERC-20 balance",
                )?,
                _ => {
                    return Err(StfError::LongLivedRoom(
                        "exit asset kind is not native or ERC-20".into(),
                    ));
                }
            };
            if balance.is_zero() {
                continue;
            }
            total = checked_add_exit_v5(total, balance, "exit sweep balance total")?;
            balances.push((*address, balance));
        }
        if total.is_zero() {
            leaves.push(ExitRecordV5 {
                recipient: binding.fallback_recipient,
                asset: bound.asset,
                amount: residual,
            });
            continue;
        }
        let mut distributed = U256::ZERO;
        for (address, balance) in balances {
            let share = residual
                .checked_mul(balance)
                .ok_or_else(|| StfError::LongLivedRoom("exit sweep share overflow".into()))?
                / total;
            if share.is_zero() {
                continue;
            }
            distributed = checked_add_exit_v5(distributed, share, "exit sweep distributed total")?;
            leaves.push(ExitRecordV5 {
                recipient: address,
                asset: bound.asset,
                amount: share,
            });
        }
        let dust = residual.checked_sub(distributed).ok_or_else(|| {
            StfError::LongLivedRoom("exit sweep distributed more than the residual".into())
        })?;
        if !dust.is_zero() {
            leaves.push(ExitRecordV5 {
                recipient: binding.fallback_recipient,
                asset: bound.asset,
                amount: dust,
            });
        }
    }
    Ok(leaves)
}

/// Compare the witness withdrawals against the proof-derived allocation:
/// record leaves in record-creation order first, then (for a closing batch)
/// sweep leaves grouped by binding-asset order with accounts ascending and
/// the fallback-recipient leaf last per asset. The legacy guard in
/// `liabilities.rs` covers unanimous rooms and rooms without a binding.
pub(crate) fn validate_exit_v5(
    input: &BatchInputV5,
    pre_exit_count: u64,
    terminal_state: &StateMap,
) -> Result<(), StfError> {
    let journal = &input.journal;
    let Some(binding) = input.policy.exit.as_ref() else {
        return Ok(());
    };
    if journal.authorization_mode != 1 {
        return Ok(());
    }
    let post_count = exit_record_count_v5(binding, terminal_state)?;
    if post_count < pre_exit_count {
        return Err(StfError::LongLivedRoom(
            "exit record count regressed inside the batch".into(),
        ));
    }
    let mut expected = read_exit_records_v5(binding, terminal_state, pre_exit_count, post_count)?;
    if journal.close {
        // Residuals use the exact arithmetic `validate_liabilities_v5`
        // enforces: per asset, controlled escrow after this batch's records
        // is `pre.controlled + consumed deposits - record withdrawals`.
        let mut consumed = BTreeMap::<Address, U256>::new();
        for deposit in &input.deposits {
            if deposit.refunded {
                continue;
            }
            let previous = consumed.get(&deposit.asset).copied().unwrap_or_default();
            consumed.insert(
                deposit.asset,
                checked_add_exit_v5(previous, deposit.amount, "exit deposit total")?,
            );
        }
        let mut recorded = BTreeMap::<Address, U256>::new();
        for record in &expected {
            let previous = recorded.get(&record.asset).copied().unwrap_or_default();
            recorded.insert(
                record.asset,
                checked_add_exit_v5(previous, record.amount, "exit record total")?,
            );
        }
        let mut residuals = BTreeMap::new();
        for pre in &input.pre_liabilities {
            let available = checked_add_exit_v5(
                pre.controlled,
                consumed.get(&pre.asset).copied().unwrap_or_default(),
                "exit controlled total",
            )?;
            let residual = available
                .checked_sub(recorded.get(&pre.asset).copied().unwrap_or_default())
                .ok_or_else(|| {
                    StfError::LongLivedRoom("exit records exceed controlled escrow".into())
                })?;
            if !residual.is_zero() {
                residuals.insert(pre.asset, residual);
            }
        }
        expected.extend(derive_close_sweep_v5(binding, terminal_state, &residuals)?);
    }
    let expected = expected
        .into_iter()
        .enumerate()
        .map(|(index, record)| WithdrawalV5 {
            index: index as u64,
            roster_epoch: journal.post_roster_epoch,
            recipient: record.recipient,
            asset: record.asset,
            amount: record.amount,
        })
        .collect::<Vec<_>>();
    let expected_capacity = withdrawal_tree_capacity_v5(expected.len())?;
    if input.withdrawals != expected || input.withdrawal_capacity != expected_capacity {
        return Err(StfError::LongLivedRoom(
            "withdrawals do not equal the proof-derived exit allocation".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdrawal_capacity_rounds_up_and_is_bounded_by_the_outbox_depth() {
        assert_eq!(withdrawal_tree_capacity_v5(0).unwrap(), 0);
        assert_eq!(withdrawal_tree_capacity_v5(1).unwrap(), 1);
        assert_eq!(withdrawal_tree_capacity_v5(2).unwrap(), 2);
        assert_eq!(withdrawal_tree_capacity_v5(300).unwrap(), 512);
        // The largest allocation that still fits one epoch is exactly the cap,
        // which is itself a power of two.
        assert_eq!(
            withdrawal_tree_capacity_v5(MAX_WITHDRAWAL_CAPACITY_V5 as usize).unwrap(),
            MAX_WITHDRAWAL_CAPACITY_V5
        );
        // One leaf past the cap is refused with the named exit-allocation error
        // rather than falling through to `withdrawal_root_v5` returning `None`.
        let error = withdrawal_tree_capacity_v5(MAX_WITHDRAWAL_CAPACITY_V5 as usize + 1)
            .expect_err("an over-cap allocation is refused");
        assert!(
            format!("{error}").contains("MAX_WITHDRAWAL_CAPACITY_V5"),
            "unexpected error: {error}"
        );
    }
}
