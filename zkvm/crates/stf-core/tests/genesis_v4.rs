use alloy_primitives::{keccak256, Address, Bytes, B256};
use alloy_trie::EMPTY_ROOT_HASH;
use stf_core::{execute_genesis_v4, StfError};
use stf_types::{
    claim_merkle_root_v4, hash_asset_totals_v4, hash_exit_totals_v4, hash_fee_totals_v4,
    member_roster_root_v4, AssetAccountingV4, AssetTotalWitnessV4, CompactAccountWitnessV4,
    CompactStateWitnessV4, GenesisInputV4, MemberSlotWitnessV4,
};

fn direct_native_exit_program() -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "assets": [{ "assetId": 0, "kind": "native" }],
            "positions": [],
            "version": 4
        }))
        .unwrap(),
    )
}

fn generic_preset(exit_program_id: B256) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "allowContractCreation": true,
            "allowSelfDestruct": false,
            "adapters": [],
            "assetIds": [0],
            "callRules": [],
            "code": [],
            "displayName": "Generic room-local EVM",
            "executionLevel": "generic",
            "exitProgramId": exit_program_id.to_string(),
            "fork": "osaka",
            "presetId": "generic-v4",
            "resources": {
                "maxBlocksPerBatch": 4,
                "maxGasPerBlock": "30000000",
                "maxMemoryPages": 4096,
                "maxTouchedAccounts": 128,
                "maxTouchedStorageSlots": 2048,
                "maxTransactionsPerBlock": 32,
                "maxWitnessBytes": 8388608
            },
            "storageNamespaces": [],
            "version": 4
        }))
        .unwrap(),
    )
}

fn canonical_header(state_root: B256, number: u64) -> Bytes {
    let bloom = [0u8; 256];
    let nonce = [0u8; 8];
    let fields = vec![
        alloy_rlp::encode(B256::repeat_byte(0x01)), // parentHash
        alloy_rlp::encode(B256::repeat_byte(0x02)), // ommersHash
        alloy_rlp::encode(Address::ZERO),           // beneficiary
        alloy_rlp::encode(state_root),              // stateRoot
        alloy_rlp::encode(B256::repeat_byte(0x03)), // transactionsRoot
        alloy_rlp::encode(B256::repeat_byte(0x04)), // receiptsRoot
        alloy_rlp::encode(bloom.as_slice()),        // logsBloom
        alloy_rlp::encode(0u64),                    // difficulty
        alloy_rlp::encode(number),                  // number
        alloy_rlp::encode(30_000_000u64),           // gasLimit
        alloy_rlp::encode(0u64),                    // gasUsed
        alloy_rlp::encode(1_900_000_000u64),        // timestamp
        alloy_rlp::encode(&[] as &[u8]),            // extraData
        alloy_rlp::encode(B256::repeat_byte(0x05)), // mixHash
        alloy_rlp::encode(nonce.as_slice()),        // nonce
    ];
    let payload = fields.into_iter().flatten().collect::<Vec<_>>();
    let mut out = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(&payload);
    Bytes::from(out)
}

fn genesis() -> GenesisInputV4 {
    let mut roster = vec![MemberSlotWitnessV4 {
        slot: 0,
        state: 1,
        account: "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap(),
        joined_at_batch: 0,
        retired_at_batch: None,
    }];
    for slot in 1..7 {
        roster.push(MemberSlotWitnessV4 {
            slot,
            ..Default::default()
        });
    }
    let exit_program = direct_native_exit_program();
    let preset = generic_preset(keccak256(&exit_program));
    let accounting = vec![AssetAccountingV4 {
        asset_id: 0,
        total: alloy_primitives::U256::ZERO,
        exit_total: alloy_primitives::U256::ZERO,
        fee_total: alloy_primitives::U256::ZERO,
    }];
    let l1_block_number = 123;
    let l1_header_rlp = canonical_header(EMPTY_ROOT_HASH, l1_block_number);
    GenesisInputV4 {
        encoded_witness_bytes: 1,
        deployment_id: B256::repeat_byte(0x11),
        room_id: 42,
        config_hash: B256::repeat_byte(0x22),
        preset_hash: keccak256(&preset),
        manifest_hash: B256::repeat_byte(0x33),
        proof_program_id: B256::repeat_byte(0x44),
        l1_block_number,
        l1_block_hash: keccak256(&l1_header_rlp),
        l1_state_root: EMPTY_ROOT_HASH,
        l1_header_rlp,
        genesis_state_root: EMPTY_ROOT_HASH,
        genesis_roster_root: member_roster_root_v4(&roster).unwrap(),
        genesis_exit_root: claim_merkle_root_v4(B256::repeat_byte(0x11), 42, &[]),
        active_mask: 1,
        used_mask: 1,
        inbox_cursor: 0,
        asset_totals_hash: hash_asset_totals_v4(&accounting),
        exit_totals_hash: hash_exit_totals_v4(&accounting),
        fee_totals_hash: hash_fee_totals_v4(&accounting),
        l1_inclusion_deadline: 999,
        canonical_preset_json: preset,
        canonical_exit_program_json: exit_program,
        roster_slots: roster,
        asset_totals: vec![AssetTotalWitnessV4 {
            asset_id: 0,
            total: alloy_primitives::U256::ZERO,
        }],
        residual_allocations: Vec::new(),
        compact_state: CompactStateWitnessV4 {
            canonical_state_root: B256::ZERO,
            accounts: vec![CompactAccountWitnessV4 {
                address: Address::repeat_byte(0xaa),
                exists: false,
                canonical_storage_root: EMPTY_ROOT_HASH,
                ..Default::default()
            }],
        },
    }
}

#[test]
fn authenticates_a_zero_block_genesis_statement() {
    let input = genesis();
    let journal =
        execute_genesis_v4(&input).expect("canonical empty-trie exclusion proof is valid");
    assert_eq!(journal.v, 4);
    assert_eq!(journal.genesis_state_root, EMPTY_ROOT_HASH);
    assert_eq!(journal.genesis_roster_root, input.genesis_roster_root);
}

#[test]
fn refuses_room_state_that_masquerades_as_an_l1_import() {
    let mut conflated = genesis();
    conflated.compact_state.canonical_state_root = conflated.l1_state_root;
    assert!(matches!(
        execute_genesis_v4(&conflated),
        Err(StfError::CompactWitness(message)) if message.contains("room-local")
    ));
}

#[test]
fn refuses_a_forged_l1_header_anchor() {
    let mut wrong_hash = genesis();
    wrong_hash.l1_block_hash = B256::repeat_byte(0xfe);
    assert!(matches!(
        execute_genesis_v4(&wrong_hash),
        Err(StfError::GenesisAnchor(message)) if message.contains("does not hash")
    ));

    let mut wrong_number = genesis();
    wrong_number.l1_block_number += 1;
    assert!(matches!(
        execute_genesis_v4(&wrong_number),
        Err(StfError::GenesisAnchor(message)) if message.contains("number")
    ));

    let mut wrong_root = genesis();
    wrong_root.l1_state_root = B256::repeat_byte(0xfd);
    assert!(matches!(
        execute_genesis_v4(&wrong_root),
        Err(StfError::GenesisAnchor(message)) if message.contains("stateRoot")
    ));
}
