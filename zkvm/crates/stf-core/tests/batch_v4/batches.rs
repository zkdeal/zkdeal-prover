//! Batch witnesses built from the checked-in fixtures: the generic
//! two-block room batch and the certified AMM batch, plus the mutators the
//! refusal tests drive them with.

use std::fs;
use std::path::Path;

use alloy_primitives::{Address, Bytes, B256, U256};
use stf_types::{
    batch_block_data_hash_v4, claim_merkle_root_v4, hash_asset_totals_v4, hash_exit_totals_v4,
    hash_fee_totals_v4, hash_inbox_entries_v4, hash_membership_deltas_v4, member_roster_root_v4,
    AccountState, AssetAccountingV4, AssetTotalWitnessV4, BatchBlockV4, BatchInputV4,
    ExitAllocationV4,
};

use crate::fixture::{compact_state, decimal_u256, env, hex_u256, Fixture, FixtureMember};
use crate::preset::{
    direct_native_exit_program_json, generic_preset_json, roster, sign_member_zero_1559,
};

pub(crate) fn replace_first_certified_tx(
    input: &mut BatchInputV4,
    target: Address,
    calldata: Bytes,
) {
    let chain_id = input.blocks[0].env.chain_id;
    input.blocks[0].raw_txs[0] = sign_member_zero_1559(chain_id, 0, target, calldata);
    input.expected_block_data_hash = batch_block_data_hash_v4(&input.blocks, input.prev_state_root);
}

pub(crate) fn certified_amm_address(input: &BatchInputV4) -> Address {
    let preset: serde_json::Value = serde_json::from_slice(&input.canonical_preset_json).unwrap();
    preset["code"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "ConstantProductAMM")
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

pub(crate) fn real_two_block_batch() -> BatchInputV4 {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("generic.json");
    let fixture: Fixture = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let room_id = fixture.room_id.parse().unwrap();
    let first = &fixture.blocks[0];

    let mut first_txs = fixture.blocks[0].raw_txs.clone();
    first_txs.extend(fixture.blocks[1].raw_txs.clone());
    let mut second_txs = fixture.blocks[2].raw_txs.clone();
    second_txs.extend(fixture.blocks[3].raw_txs.clone());
    assert_eq!(first_txs.len(), 3);
    assert_eq!(second_txs.len(), 4);

    let blocks = vec![
        BatchBlockV4 {
            block_number: 1,
            raw_txs: first_txs,
            env: env(&fixture.blocks[0].env, 1, fixture.chain_id),
            expected_post_state_root: fixture.blocks[1].expected_post_root,
        },
        BatchBlockV4 {
            block_number: 2,
            raw_txs: second_txs,
            env: env(&fixture.blocks[3].env, 2, fixture.chain_id),
            expected_post_state_root: fixture.blocks[3].expected_post_root,
        },
    ];
    let block_hash = batch_block_data_hash_v4(&blocks, first.prev_state_root);
    let canonical_exit_program_json = direct_native_exit_program_json();
    let canonical_preset_json =
        generic_preset_json(alloy_primitives::keccak256(&canonical_exit_program_json));
    let pre_roster_slots = roster();
    let post_roster_slots = pre_roster_slots.clone();
    let final_state = &fixture.blocks.last().unwrap().post_state;
    let mut exit_allocations = pre_roster_slots
        .iter()
        .filter(|slot| slot.state != 0)
        .filter_map(|slot| {
            let amount = final_state
                .iter()
                .find(|account| account.address == slot.account)
                .map(|account| hex_u256(&account.balance))
                .unwrap_or_default();
            (!amount.is_zero()).then_some(ExitAllocationV4 {
                slot: slot.slot,
                asset_id: 0,
                recipient: slot.account,
                amount,
            })
        })
        .collect::<Vec<_>>();
    exit_allocations.sort_by_key(|allocation| (allocation.slot, allocation.asset_id));
    let total = exit_allocations
        .iter()
        .fold(U256::ZERO, |sum, allocation| sum + allocation.amount);
    let accounting = vec![AssetAccountingV4 {
        asset_id: 0,
        total,
        exit_total: total,
        fee_total: U256::ZERO,
    }];
    let deployment_id = B256::repeat_byte(0x11);
    BatchInputV4 {
        encoded_witness_bytes: 1,
        deployment_id,
        room_id,
        preset_hash: alloy_primitives::keccak256(&canonical_preset_json),
        manifest_hash: B256::repeat_byte(0x22),
        proof_program_id: B256::repeat_byte(0x33),
        batch_index: 9,
        l2_start_height: 1,
        previous_block_timestamp: 0,
        prev_state_root: first.prev_state_root,
        pre_roster_root: member_roster_root_v4(&pre_roster_slots).unwrap(),
        post_roster_root: member_roster_root_v4(&post_roster_slots).unwrap(),
        active_mask: 0b11,
        pre_used_mask: 0b11,
        post_active_mask: 0b11,
        used_mask: 0b11,
        inbox_start: 0,
        inbox_end: 0,
        inbox_inputs_hash: hash_inbox_entries_v4(&[]),
        expected_block_data_hash: block_hash,
        asset_totals_hash: hash_asset_totals_v4(&accounting),
        exit_totals_hash: hash_exit_totals_v4(&accounting),
        fee_totals_hash: hash_fee_totals_v4(&accounting),
        membership_deltas_hash: hash_membership_deltas_v4(&[]),
        previous_exit_root: claim_merkle_root_v4(deployment_id, room_id, &exit_allocations),
        exit_root: claim_merkle_root_v4(deployment_id, room_id, &exit_allocations),
        close: false,
        l1_inclusion_deadline: 999,
        canonical_preset_json,
        canonical_exit_program_json,
        pre_roster_slots,
        post_roster_slots,
        membership_deltas: Vec::new(),
        inbox_entries: Vec::new(),
        asset_totals: vec![AssetTotalWitnessV4 { asset_id: 0, total }],
        residual_allocations: Vec::new(),
        previous_exit_allocations: exit_allocations,
        compact_state: compact_state(&fixture),
        blocks,
    }
}

pub(crate) fn certified_amm_two_block_batch() -> BatchInputV4 {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("amm-certified-v4.json");
    let fixture: Fixture = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(fixture.blocks.len(), 2);
    assert!(fixture.blocks.iter().all(|block| block.raw_txs.len() >= 3));

    let canonical_preset_json = Bytes::from(
        serde_json::to_vec(
            fixture
                .preset
                .as_ref()
                .expect("fixture has generated preset"),
        )
        .unwrap(),
    );
    let canonical_exit_program_json = Bytes::from(
        serde_json::to_vec(
            fixture
                .exit_program
                .as_ref()
                .expect("fixture has generated exit program"),
        )
        .unwrap(),
    );
    let preset_hash = fixture
        .preset_hash
        .expect("fixture has generated preset hash");
    assert_eq!(
        alloy_primitives::keccak256(&canonical_preset_json),
        preset_hash
    );
    let settlement = fixture
        .settlement
        .as_ref()
        .expect("fixture has settlement expectations");
    assert_eq!(settlement.deployment_domain, B256::repeat_byte(0xa1));
    let accounting = settlement
        .accounting
        .iter()
        .map(|asset| AssetAccountingV4 {
            asset_id: asset.asset_id,
            total: decimal_u256(&asset.total),
            exit_total: decimal_u256(&asset.exit_total),
            fee_total: decimal_u256(&asset.fee_total),
        })
        .collect::<Vec<_>>();
    let expected_allocations = settlement
        .exit_allocations
        .iter()
        .map(|allocation| ExitAllocationV4 {
            slot: allocation.slot,
            asset_id: allocation.asset_id,
            recipient: allocation.recipient,
            amount: decimal_u256(&allocation.amount),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        hash_asset_totals_v4(&accounting),
        settlement.asset_totals_hash
    );
    assert_eq!(
        hash_exit_totals_v4(&accounting),
        settlement.exit_totals_hash
    );
    assert_eq!(hash_fee_totals_v4(&accounting), settlement.fee_totals_hash);
    assert_eq!(
        claim_merkle_root_v4(
            settlement.deployment_domain,
            fixture.room_id.parse().unwrap(),
            &expected_allocations
        ),
        settlement.exit_root
    );
    let first = &fixture.blocks[0];
    let blocks = fixture
        .blocks
        .iter()
        .map(|block| BatchBlockV4 {
            block_number: block.block_number,
            raw_txs: block.raw_txs.clone(),
            env: env(&block.env, block.block_number, fixture.chain_id),
            expected_post_state_root: block.expected_post_root,
        })
        .collect::<Vec<_>>();
    let block_hash = batch_block_data_hash_v4(&blocks, first.prev_state_root);
    let pre_roster_slots = roster();
    let compact_state = compact_state(&fixture);
    for member in fixture.members.iter().map(FixtureMember::address) {
        let leaf = compact_state
            .accounts
            .iter()
            .find(|account| account.address == member)
            .expect("every active member is explicitly declared in the AMM witness");
        assert!(
            !leaf.exists,
            "zero-funded active member must be an absent leaf"
        );
    }
    let coinbase = compact_state
        .accounts
        .iter()
        .find(|account| account.address == Address::ZERO)
        .expect("fixed zero coinbase is explicitly declared in the AMM witness");
    assert!(!coinbase.exists, "zero coinbase must be an absent leaf");
    BatchInputV4 {
        encoded_witness_bytes: 1,
        deployment_id: B256::repeat_byte(0xa1),
        room_id: fixture.room_id.parse().unwrap(),
        preset_hash,
        manifest_hash: B256::repeat_byte(0xa2),
        proof_program_id: B256::repeat_byte(0xa3),
        batch_index: 1,
        l2_start_height: 1,
        previous_block_timestamp: 0,
        prev_state_root: first.prev_state_root,
        pre_roster_root: member_roster_root_v4(&pre_roster_slots).unwrap(),
        post_roster_root: member_roster_root_v4(&pre_roster_slots).unwrap(),
        active_mask: 0b11,
        pre_used_mask: 0b11,
        post_active_mask: 0b11,
        used_mask: 0b11,
        inbox_start: 0,
        inbox_end: 0,
        inbox_inputs_hash: hash_inbox_entries_v4(&[]),
        expected_block_data_hash: block_hash,
        asset_totals_hash: settlement.asset_totals_hash,
        exit_totals_hash: settlement.exit_totals_hash,
        fee_totals_hash: settlement.fee_totals_hash,
        membership_deltas_hash: hash_membership_deltas_v4(&[]),
        previous_exit_root: settlement.exit_root,
        exit_root: settlement.exit_root,
        close: false,
        l1_inclusion_deadline: 1_000,
        canonical_preset_json,
        canonical_exit_program_json,
        pre_roster_slots: pre_roster_slots.clone(),
        post_roster_slots: pre_roster_slots,
        membership_deltas: Vec::new(),
        inbox_entries: Vec::new(),
        asset_totals: settlement
            .asset_totals
            .iter()
            .map(|asset| AssetTotalWitnessV4 {
                asset_id: asset.asset_id,
                total: decimal_u256(&asset.total),
            })
            .collect(),
        residual_allocations: settlement.residual_allocations.clone(),
        previous_exit_allocations: expected_allocations,
        compact_state,
        blocks,
    }
}

pub(crate) fn state_from_compact(input: &BatchInputV4) -> stf_core::StateMap {
    let state = input
        .compact_state
        .accounts
        .iter()
        .filter(|account| account.exists)
        .map(|account| {
            (
                account.address,
                AccountState {
                    nonce: account.nonce,
                    balance: account.balance,
                    code: account.code.clone(),
                    storage: account
                        .storage
                        .iter()
                        .filter(|slot| !slot.value.is_zero())
                        .map(|slot| (slot.slot, slot.value))
                        .collect(),
                },
            )
        })
        .collect::<Vec<_>>();
    stf_core::StateMap::from_input(&state)
}

pub(crate) fn set_native_settlement(input: &mut BatchInputV4, state: &stf_core::StateMap) {
    let mut exits = input
        .post_roster_slots
        .iter()
        .filter(|member| member.state != 0)
        .filter_map(|member| {
            let amount = state
                .accounts
                .get(&member.account)
                .map(|account| account.balance)
                .unwrap_or_default();
            (!amount.is_zero()).then_some(ExitAllocationV4 {
                slot: member.slot,
                asset_id: 0,
                recipient: member.account,
                amount,
            })
        })
        .collect::<Vec<_>>();
    exits.sort_by_key(|allocation| (allocation.slot, allocation.asset_id));
    let total = exits
        .iter()
        .fold(U256::ZERO, |sum, allocation| sum + allocation.amount);
    let accounting = vec![AssetAccountingV4 {
        asset_id: 0,
        total,
        exit_total: total,
        fee_total: U256::ZERO,
    }];
    input.asset_totals = vec![AssetTotalWitnessV4 { asset_id: 0, total }];
    input.asset_totals_hash = hash_asset_totals_v4(&accounting);
    input.exit_totals_hash = hash_exit_totals_v4(&accounting);
    input.fee_totals_hash = hash_fee_totals_v4(&accounting);
    input.exit_root = claim_merkle_root_v4(input.deployment_id, input.room_id, &exits);
}

pub(crate) fn empty_membership_batch(input: &mut BatchInputV4, block_number: u64, post_root: B256) {
    let mut first = input.blocks[0].clone();
    first.block_number = block_number;
    first.env.number = block_number;
    first.raw_txs.clear();
    first.expected_post_state_root = post_root;
    let mut second = first.clone();
    second.block_number = block_number + 1;
    second.env.number = block_number + 1;
    input.blocks = vec![first, second];
    input.l2_start_height = block_number;
    input.expected_block_data_hash = batch_block_data_hash_v4(&input.blocks, input.prev_state_root);
}
