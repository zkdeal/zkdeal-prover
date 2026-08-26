//! Guest-derived v4 funding, roster and settlement logic.
//!
//! Nothing in this module treats a host-supplied root/hash as authority. The
//! host provides concrete L1-bound totals/inbox preimages and the canonical
//! preimage of the preset's exit-program commitment. The guest applies inputs,
//! reads the authenticated post-state, derives claim leaves, and only then may
//! compare the resulting public commitments with expected submission values.
//!
//! This module holds the shared vocabulary — the resolved exit-program types,
//! the protocol constants and the state-access helpers. The exit-program
//! parser, the roster transition, the inbox segment and the settlement
//! derivation live in the sibling modules.

mod exit;
mod inbox;
mod program;
mod roster;

pub(crate) use exit::{
    authenticate_previous_exit_allocations_v4, derive_settlement_v4,
    enforce_retired_exit_continuity_v4,
};
pub(crate) use inbox::apply_inbox_v4;
pub(crate) use roster::validate_membership_transition_v4;

use alloy_primitives::{keccak256, Address, B256, U256};
use stf_types::{AssetAccountingV4, ExitAllocationV4};

use crate::StateMap;

const MAX_ASSETS: usize = 16;
const MAX_MEMBERS: usize = 7;
const INBOX_DEPOSIT: u8 = 1;
const INBOX_JOIN: u8 = 2;
const INBOX_PENDING: u8 = 1;
const INBOX_CONSUMED: u8 = 2;
const INBOX_SKIPPED: u8 = 3;
const INBOX_REFUNDED: u8 = 4;
const MEMBER_UNUSED: u8 = 0;
const MEMBER_ACTIVE: u8 = 1;
const MEMBER_RETIRED: u8 = 2;
const MEMBER_ACTIVATE: u8 = 1;
const MEMBER_RETIRE: u8 = 2;
const JOIN_SLOT_SENTINEL: u8 = u8::MAX;

#[derive(Clone, Debug)]
enum ExitAssetKindV4 {
    Native,
    Erc20 {
        token: Address,
        balance_slot: U256,
        total_supply_slot: U256,
    },
}

#[derive(Clone, Debug)]
struct ExitAssetV4 {
    asset_id: u8,
    kind: ExitAssetKindV4,
}

#[derive(Clone, Debug)]
struct PositionBackingV4 {
    asset_id: u8,
    reserve_slot: Option<U256>,
}

#[derive(Clone, Debug)]
struct ProRataPositionV4 {
    contract: Address,
    share_balance_slot: U256,
    total_supply_slot: U256,
    excluded_share_accounts: Vec<Address>,
    backings: Vec<PositionBackingV4>,
}

#[derive(Clone, Debug)]
pub(crate) struct ExitProgramV4 {
    assets: Vec<ExitAssetV4>,
    positions: Vec<ProRataPositionV4>,
}

#[derive(Clone, Debug)]
pub(crate) struct DerivedSettlementV4 {
    pub(crate) exit_allocations: Vec<ExitAllocationV4>,
    pub(crate) accounting: Vec<AssetAccountingV4>,
    pub(crate) asset_totals_hash: B256,
    pub(crate) exit_totals_hash: B256,
    pub(crate) fee_totals_hash: B256,
    pub(crate) exit_root: B256,
}

fn mapping_slot(account: Address, slot: U256) -> U256 {
    let mut encoded = [0u8; 64];
    encoded[12..32].copy_from_slice(account.as_slice());
    encoded[32..].copy_from_slice(&slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(encoded).0)
}

fn read_storage(
    state: &StateMap,
    address: Address,
    slot: U256,
    label: &str,
) -> Result<U256, String> {
    if state.access_storage.as_ref().is_some_and(|allowed| {
        !allowed
            .get(&address)
            .is_some_and(|slots| slots.contains(&slot))
    }) {
        return Err(format!(
            "{label}: storage {address}[{slot:#x}] is outside the complete compact-state envelope"
        ));
    }
    Ok(state
        .accounts
        .get(&address)
        .and_then(|account| account.storage.get(&slot))
        .copied()
        .unwrap_or_default())
}

fn write_storage(
    state: &mut StateMap,
    address: Address,
    slot: U256,
    value: U256,
    label: &str,
) -> Result<(), String> {
    if state.access_storage.as_ref().is_some_and(|allowed| {
        !allowed
            .get(&address)
            .is_some_and(|slots| slots.contains(&slot))
    }) {
        return Err(format!(
            "{label}: storage {address}[{slot:#x}] is outside the complete compact-state envelope"
        ));
    }
    let account = state
        .accounts
        .get_mut(&address)
        .ok_or_else(|| format!("{label}: token account {address} is absent"))?;
    if value.is_zero() {
        account.storage.remove(&slot);
    } else {
        account.storage.insert(slot, value);
    }
    Ok(())
}

fn add_u256(left: U256, right: U256, label: &str) -> Result<U256, String> {
    left.checked_add(right)
        .ok_or_else(|| format!("{label}: uint256 addition overflow"))
}

fn mul_div_floor(
    value: U256,
    numerator: U256,
    denominator: U256,
    label: &str,
) -> Result<U256, String> {
    if denominator.is_zero() {
        return Err(format!("{label}: division by zero"));
    }
    value
        .checked_mul(numerator)
        .ok_or_else(|| format!("{label}: uint256 multiplication overflow"))
        .map(|product| product / denominator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stf_types::{
        claim_merkle_root_v4, hash_inbox_entries_v4, InboxAssetAmountV4, InboxEntryWitnessV4,
        MemberSlotWitnessV4,
    };

    fn native_program() -> ExitProgramV4 {
        ExitProgramV4 {
            assets: vec![ExitAssetV4 {
                asset_id: 0,
                kind: ExitAssetKindV4::Native,
            }],
            positions: Vec::new(),
        }
    }

    fn roster(account: Address, state: u8) -> Vec<MemberSlotWitnessV4> {
        let mut slots = vec![MemberSlotWitnessV4 {
            slot: 0,
            state,
            account,
            joined_at_batch: 0,
            retired_at_batch: (state == MEMBER_RETIRED).then_some(1),
        }];
        for slot in 1..MAX_MEMBERS as u8 {
            slots.push(MemberSlotWitnessV4 {
                slot,
                ..Default::default()
            });
        }
        slots
    }

    fn deposit(account: Address) -> InboxEntryWitnessV4 {
        InboxEntryWitnessV4 {
            index: 1,
            kind: INBOX_DEPOSIT,
            account,
            beneficiary_slot: 0,
            status: INBOX_PENDING,
            deposits: vec![InboxAssetAmountV4 {
                asset_id: 0,
                amount: U256::from(7),
            }],
        }
    }

    #[test]
    fn deposit_is_consumed_only_while_depositor_is_pre_active() {
        let account = Address::repeat_byte(0x11);
        let active = roster(account, MEMBER_ACTIVE);
        let mut state = StateMap::default();
        let hash = apply_inbox_v4(
            &native_program(),
            &mut state,
            &[deposit(account)],
            &[],
            &active,
            &active,
            0,
            1,
        )
        .unwrap();
        let mut terminal = deposit(account);
        terminal.status = INBOX_CONSUMED;
        assert_eq!(hash, hash_inbox_entries_v4(&[terminal]));
        assert_eq!(state.accounts[&account].balance, U256::from(7));
    }

    #[test]
    fn deposit_crossed_after_retirement_is_skipped_and_uncredited() {
        let account = Address::repeat_byte(0x11);
        let retired = roster(account, MEMBER_RETIRED);
        let mut state = StateMap::default();
        let hash = apply_inbox_v4(
            &native_program(),
            &mut state,
            &[deposit(account)],
            &[],
            &retired,
            &retired,
            0,
            1,
        )
        .unwrap();
        let mut terminal = deposit(account);
        terminal.status = INBOX_SKIPPED;
        assert_eq!(hash, hash_inbox_entries_v4(&[terminal]));
        assert!(!state.accounts.contains_key(&account));
    }

    #[test]
    fn previous_exit_preimage_is_canonical_and_root_authenticated() {
        let account = Address::repeat_byte(0x11);
        let roster = roster(account, MEMBER_ACTIVE);
        let allocation = ExitAllocationV4 {
            slot: 0,
            asset_id: 0,
            recipient: account,
            amount: U256::from(9),
        };
        let deployment = B256::repeat_byte(0x44);
        let root = claim_merkle_root_v4(deployment, 7, std::slice::from_ref(&allocation));
        authenticate_previous_exit_allocations_v4(
            &native_program(),
            &roster,
            1,
            std::slice::from_ref(&allocation),
            root,
            deployment,
            7,
        )
        .unwrap();

        let duplicate = vec![allocation.clone(), allocation.clone()];
        assert!(authenticate_previous_exit_allocations_v4(
            &native_program(),
            &roster,
            1,
            &duplicate,
            claim_merkle_root_v4(deployment, 7, &duplicate),
            deployment,
            7,
        )
        .unwrap_err()
        .contains("sorted and unique"));

        let wrong_recipient = vec![ExitAllocationV4 {
            recipient: Address::repeat_byte(0x22),
            ..allocation
        }];
        assert!(authenticate_previous_exit_allocations_v4(
            &native_program(),
            &roster,
            1,
            &wrong_recipient,
            claim_merkle_root_v4(deployment, 7, &wrong_recipient),
            deployment,
            7,
        )
        .unwrap_err()
        .contains("recipient/slot"));
    }

    #[test]
    fn previous_exit_leaves_may_use_non_contiguous_asset_ids() {
        let account = Address::repeat_byte(0x11);
        let roster = roster(account, MEMBER_ACTIVE);
        // Asset ids are only required sorted and unique, so a room declaring
        // {0, 7} must be able to authenticate the exit root it produced itself.
        let program = ExitProgramV4 {
            assets: vec![
                ExitAssetV4 {
                    asset_id: 0,
                    kind: ExitAssetKindV4::Native,
                },
                ExitAssetV4 {
                    asset_id: 7,
                    kind: ExitAssetKindV4::Native,
                },
            ],
            positions: Vec::new(),
        };
        let deployment = B256::repeat_byte(0x44);
        let allocation = ExitAllocationV4 {
            slot: 0,
            asset_id: 7,
            recipient: account,
            amount: U256::from(9),
        };
        authenticate_previous_exit_allocations_v4(
            &program,
            &roster,
            1,
            std::slice::from_ref(&allocation),
            claim_merkle_root_v4(deployment, 7, std::slice::from_ref(&allocation)),
            deployment,
            7,
        )
        .unwrap();

        let undeclared = vec![ExitAllocationV4 {
            asset_id: 9,
            ..allocation
        }];
        assert!(authenticate_previous_exit_allocations_v4(
            &program,
            &roster,
            1,
            &undeclared,
            claim_merkle_root_v4(deployment, 7, &undeclared),
            deployment,
            7,
        )
        .unwrap_err()
        .contains("out-of-range or zero leaf"));
    }

    #[test]
    fn residual_dust_cannot_be_redirected_away_from_an_already_retired_slot() {
        let retired = Address::repeat_byte(0x11);
        let active = Address::repeat_byte(0x22);
        // Models a one-unit pro-rata residual assigned to slot 0 by the prior
        // accepted batch and redirected to slot 1 without changing total exits.
        let previous = vec![
            ExitAllocationV4 {
                slot: 0,
                asset_id: 0,
                recipient: retired,
                amount: U256::from(6),
            },
            ExitAllocationV4 {
                slot: 1,
                asset_id: 0,
                recipient: active,
                amount: U256::from(4),
            },
        ];
        let redirected = vec![
            ExitAllocationV4 {
                slot: 0,
                asset_id: 0,
                recipient: retired,
                amount: U256::from(5),
            },
            ExitAllocationV4 {
                slot: 1,
                asset_id: 0,
                recipient: active,
                amount: U256::from(5),
            },
        ];
        assert!(
            enforce_retired_exit_continuity_v4(&previous, &redirected, 0b11, 0b10)
                .unwrap_err()
                .contains("retired slot 0 asset 0 exit changed")
        );
    }
}
