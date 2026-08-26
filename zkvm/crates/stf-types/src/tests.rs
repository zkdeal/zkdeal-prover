use alloy_primitives::{Address, Bytes, B256, U256};

use super::*;

#[test]
fn u64_id_fields_accept_numbers_decimal_and_hex_strings() {
    // A direct JSON producer (the TypeScript node emitting bigints) may send the
    // deposit, forced and admission id fields as decimal or hex strings; the
    // widened deserializer accepts all three forms and rejects non-integers.
    let base = serde_json::json!({
        "inbox_id": 1,
        "depositor": Address::repeat_byte(0x11),
        "beneficiary": Address::repeat_byte(0x22),
        "asset": Address::ZERO,
        "amount": "0x64",
        "queued_at_block": 100,
        "consumed": false,
        "refunded": false
    });
    let number: DepositV5 = serde_json::from_value(base.clone()).unwrap();
    assert_eq!(number.inbox_id, 1);
    assert_eq!(number.queued_at_block, 100);

    let mut decimal = base.clone();
    decimal["inbox_id"] = serde_json::json!("1");
    decimal["queued_at_block"] = serde_json::json!("100");
    assert_eq!(serde_json::from_value::<DepositV5>(decimal).unwrap(), number);

    let mut hexed = base.clone();
    hexed["inbox_id"] = serde_json::json!("0x1");
    hexed["queued_at_block"] = serde_json::json!("0x64");
    assert_eq!(serde_json::from_value::<DepositV5>(hexed).unwrap(), number);

    let forced: ForcedTransactionV5 = serde_json::from_value(serde_json::json!({
        "forced_id": "7",
        "raw_transaction": "0x02",
        "outcome": {
            "admission_id": 7,
            "transaction_hash": B256::ZERO,
            "status": 0,
            "l2_block_number": 0,
            "transaction_index": 0,
            "reason_hash": B256::ZERO
        }
    }))
    .unwrap();
    assert_eq!(forced.forced_id, 7);

    let receipt: AdmissionReceiptV5 = serde_json::from_value(serde_json::json!({
        "admission_id": 1,
        "transaction_hash": B256::ZERO,
        "deposit_inbox_id": "9",
        "deposit_content_hash": B256::ZERO,
        "deadline_block": 100,
        "maximum_batch_index": 1,
        "bond_epoch": 1,
        "admission_fee": "0x0",
        "signature": "0x"
    }))
    .unwrap();
    assert_eq!(receipt.deposit_inbox_id, 9);

    let mut bad = base;
    bad["inbox_id"] = serde_json::json!("not-a-number");
    assert!(serde_json::from_value::<DepositV5>(bad).is_err());
}

#[test]
fn owner_policy_and_liability_commitments_match_cross_language_vectors() {
    let policy = ExecutionPolicyV5 {
        state_commitment: 1,
        max_blocks_per_batch: 8,
        max_transactions_per_block: 1_024,
        max_gas_per_block: 30_000_000,
        max_memory_bytes: 268_435_456,
        allow_contract_creation: false,
        allow_self_destruct: false,
        code: vec![],
        calls: vec![],
        storage: vec![],
        imports: vec![],
        participant_registry: None,
        exit: None,
    };
    let liabilities = [AssetLiabilityV5 {
        asset: Address::repeat_byte(0x33),
        pending: U256::from(1),
        controlled: U256::from(2),
        claimable: U256::from(3),
        paid: U256::from(4),
    }];
    // The exit binding is an optional hash tail: a policy without one keeps
    // the pre-exit vector byte-identical.
    assert_eq!(
        execution_policy_hash_v5(&policy),
        "0x19e8cd5b38fc34be9aa28be1460d33c3c1e7083da85c70646f4a6ca95216375a"
            .parse::<B256>()
            .unwrap()
    );
    let mut bound = policy.clone();
    bound.exit = Some(ExitBindingV5 {
        queue_contract: Address::repeat_byte(0x45),
        count_slot: U256::ZERO,
        records_base_slot: U256::from(0x100),
        assets: vec![ExitAssetBindingV5::default()],
        fallback_recipient: Address::repeat_byte(0xfb),
    });
    assert_ne!(
        execution_policy_hash_v5(&bound),
        execution_policy_hash_v5(&policy)
    );
    assert_eq!(
        liabilities_hash_v5(&liabilities),
        "0x90f7330755d3c4e04b3f84c7183918722b36d96a2cb1bf864b80f8d84ebfb1aa"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn v5_public_batch_data_carries_replay_inputs_not_only_an_environment_hash() {
    let coinbase = Address::repeat_byte(0x42);
    let transaction = Bytes::from_static(&[0x02, 0xaa, 0xbb, 0xcc]);
    let block = BatchBlockV5 {
        block_number: 1,
        raw_txs: vec![transaction.clone()],
        env: BlockEnvV1 {
            number: 1,
            timestamp: 1_900_000_001,
            gas_limit: 5_000_000,
            coinbase,
            base_fee: U256::from(7),
            prev_randao: B256::repeat_byte(0x33),
            difficulty: U256::ZERO,
            excess_blob_gas: 9,
            chain_id: 31337,
        },
        block_hashes: vec![],
        expected_post_state_root: B256::repeat_byte(0x55),
    };
    let encoded = canonical_batch_data_v5(&[block], B256::repeat_byte(0x11));
    assert!(encoded
        .windows(coinbase.len())
        .any(|window| window == coinbase.as_slice()));
    assert!(encoded
        .windows(transaction.len())
        .any(|window| window == transaction.as_ref()));
    assert!(encoded.len() > 32, "public data must contain replay inputs");
}

#[test]
fn v5_journal_hash_matches_the_solidity_abi_vector() {
    let journal = BatchJournalV5 {
        protocol_version: 6,
        deployment_domain: B256::repeat_byte(0x11),
        room_id: 7,
        authorization_mode: 1,
        cold_template_id: B256::repeat_byte(0x22),
        proof_program_id: B256::repeat_byte(0x33),
        proof_system_version: B256::repeat_byte(0x44),
        policy_hash: B256::repeat_byte(0x55),
        batch_index: 1,
        start_l2_block: 1,
        end_l2_block: 2,
        pre_state_root: B256::repeat_byte(0x66),
        post_state_root: B256::repeat_byte(0x77),
        batch_data_hash: B256::repeat_byte(0x88),
        canonical_data_hash: B256::repeat_byte(0x89),
        pre_participant_root: B256::repeat_byte(0x8a),
        post_participant_root: B256::repeat_byte(0x8b),
        pre_participant_epoch: 1,
        post_participant_epoch: 2,
        pre_participant_count: 127,
        post_participant_count: 128,
        participant_capacity: 1_024,
        pre_roster_root: B256::repeat_byte(0x99),
        post_roster_root: B256::repeat_byte(0xaa),
        pre_roster_epoch: 1,
        post_roster_epoch: 2,
        pre_active_count: 1,
        post_active_count: 2,
        roster_change_cursor_before: 0,
        roster_change_cursor_after: 1,
        inbox_cursor_before: 2,
        inbox_cursor_after: 3,
        inbox_records_hash: B256::repeat_byte(0x9a),
        admission_cursor_before: 3,
        admission_cursor_after: 4,
        admission_records_hash: B256::repeat_byte(0xa1),
        forced_cursor_before: 5,
        forced_cursor_after: 6,
        forced_outcomes_hash: B256::repeat_byte(0xa2),
        import_cursor_before: 4,
        import_cursor_after: 5,
        imported_l1_block: 123,
        imported_l1_header_hash: B256::repeat_byte(0xbb),
        imported_l1_state_root: B256::repeat_byte(0xcc),
        import_root: B256::repeat_byte(0xdd),
        outbox_epoch: 6,
        withdrawal_root: B256::repeat_byte(0xee),
        pre_liabilities_hash: B256::repeat_byte(0x01),
        post_liabilities_hash: B256::repeat_byte(0x02),
        roster_changes_hash: B256::repeat_byte(0x03),
        l1_inclusion_deadline: 999,
        close: false,
    };
    assert_eq!(
        hash_batch_journal_v5(&journal),
        "0x30c74fdcd7ad68d2f1405ebc908e500d4171b87248e6e2d505d3d875914a6be0"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn v6_deposit_and_inbox_hashes_match_standard_abi_vectors() {
    let deposit = DepositV5 {
        inbox_id: 7,
        depositor: Address::repeat_byte(0x11),
        beneficiary: Address::repeat_byte(0x22),
        asset: Address::repeat_byte(0x33),
        amount: U256::from(12_345),
        queued_at_block: 456,
        consumed: false,
        refunded: false,
    };
    assert_eq!(
        deposit_content_hash_v5(&deposit),
        "0xe48f1d1bd5290da78e53e0550f8f78f3ca7b3e01d2578e0edaf0afb814981c06"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        inbox_record_hash_v5(&deposit),
        "0x854c2f210362c9f425ea24bb683d218ae630bbf643a1972c2e701d05e68a314c"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        inbox_records_hash_v5(&[deposit]),
        "0x961075932acfbf6b0d4296549a6ac6887564456522e8173cd54f131c2a2c2494"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        inbox_records_hash_v5(&[]),
        "0x569e75fc77c1a856f6daaf9e69d8a9566ca34aa47f9133711ce065a571af0cfd"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn v6_cold_template_statement_matches_the_solidity_abi_vector() {
    let input = ColdTemplateInputV5 {
        template_id: B256::repeat_byte(0x11),
        initial_state_root: B256::repeat_byte(0x22),
        policy_hash: B256::repeat_byte(0x33),
        proof_program_id: B256::repeat_byte(0x44),
        proof_system_version: B256::repeat_byte(0x55),
        ..Default::default()
    };
    let genesis_data_hash = B256::repeat_byte(0x66);
    // Independent reference derivation of `abi.encode("zkdeal/cold-template/v6",
    // templateId, initialStateRoot, policyHash, proofProgramId,
    // proofSystemVersion, genesisDataHash)`: seven head words (the string
    // offset 224 plus six bytes32 values), then the string length word and the
    // 32-byte-padded label.
    let label = b"zkdeal/cold-template/v6";
    let mut encoded = Vec::new();
    let mut offset_word = [0u8; 32];
    offset_word[24..].copy_from_slice(&(32u64 * 7).to_be_bytes());
    encoded.extend_from_slice(&offset_word);
    for word in [
        input.template_id,
        input.initial_state_root,
        input.policy_hash,
        input.proof_program_id,
        input.proof_system_version,
        genesis_data_hash,
    ] {
        encoded.extend_from_slice(word.as_slice());
    }
    let mut length_word = [0u8; 32];
    length_word[24..].copy_from_slice(&(label.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&length_word);
    encoded.extend_from_slice(label);
    encoded.resize(32 * 9, 0);
    let reference = alloy_primitives::keccak256(&encoded);
    assert_eq!(
        cold_template_statement_v6(&input, genesis_data_hash),
        reference
    );
    assert_eq!(
        reference,
        "0xc24f56299dc179c03c2f80f571abd411f259c9b4c01139d2e22b2ac0c255e7bc"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn join_acceptance_binds_the_exact_batch_journal() {
    let hash = hash_join_acceptance_struct_v4(
        42,
        9,
        2,
        Address::repeat_byte(0x33),
        B256::repeat_byte(0x77),
        "0x8fc85a84b0de22ca84d94c87e0cef14a2e47a5f3ddfa7f43802e6c6a03426b2f"
            .parse()
            .unwrap(),
        "0x2a2d85126440c9d10dc3604bcbc442e50b0f4c5c85cdf75bcbeb5b445a4dd128"
            .parse()
            .unwrap(),
        1_900_000_000,
    );
    assert_eq!(
        hash,
        "0x53297a622e37b60fd5d7cad8f5df642cce0fcd8a9676fad36d59a087b9875616"
            .parse::<B256>()
            .unwrap()
    );
    assert_ne!(
        hash,
        hash_join_acceptance_struct_v4(
            42,
            9,
            2,
            Address::repeat_byte(0x33),
            B256::repeat_byte(0x77),
            "0x8fc85a84b0de22ca84d94c87e0cef14a2e47a5f3ddfa7f43802e6c6a03426b2f"
                .parse()
                .unwrap(),
            B256::repeat_byte(0xfe),
            1_900_000_000,
        )
    );
}

#[test]
fn v4_room_and_application_domains_match_typescript_and_solidity_vectors() {
    let deployment = B256::repeat_byte(0x11);
    let other_deployment = B256::repeat_byte(0x22);
    assert_eq!(room_chain_id_v4(deployment, 42), 1_134_288_386_081_462);
    assert_ne!(
        room_chain_id_v4(deployment, 42),
        room_chain_id_v4(deployment, 1_000_042)
    );
    assert_eq!(
        room_chain_id_v4(deployment, 1_000_042),
        1_903_597_234_960_603
    );
    assert_eq!(
        room_chain_id_v4(other_deployment, 42),
        1_452_954_241_746_695
    );
    assert!(room_chain_id_v4(deployment, 42) & (1u64 << 50) != 0);
    assert_eq!(
        application_domain_v4(b"zkdeal/application/v4", deployment, 42),
        "0x3bd6360dff3b81a372aa96cedc91f43ee2e16849374a1bedf07d20a3c2559c14"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        card_application_domain_v4(deployment, 42),
        "0x4434b3b3c65faf556abd64c0742a696ff700d75d57bde12f80ed818d1d826662"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn proven_room_instance_domain_matches_typescript_vector() {
    assert_eq!(
        prepared_room_instance_id_v4(
            B256::repeat_byte(0xa1),
            B256::repeat_byte(0xa2),
            B256::repeat_byte(0x99),
            42,
            B256::repeat_byte(0xb1),
        ),
        "0xea53e8f9e3dcd736585a492f6e126824079cfdd4e28ea5bcc188d18d39ca0cf9"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn cold_journal_hash_matches_typescript_vector() {
    let mut journal = ColdRoomJournalV4 {
        v: 4,
        template_id: B256::ZERO,
        compiled_bundle_hash: B256::repeat_byte(0x11),
        preset_hash: B256::repeat_byte(0x22),
        manifest_hash: B256::repeat_byte(0x33),
        proof_program_id: B256::repeat_byte(0x44),
        constructor_chain_id: COLD_TEMPLATE_CHAIN_ID_V4,
        initial_state_root: B256::repeat_byte(0x55),
        initialized_state_root: B256::repeat_byte(0x66),
        setup_data_hash: B256::repeat_byte(0x77),
        runtime_code_root: B256::repeat_byte(0x88),
        state_access_root: B256::repeat_byte(0x99),
        state_refresh_root: B256::repeat_byte(0xaa),
        static_state_commitment: B256::repeat_byte(0xbb),
        analyzed_artifact_root: B256::repeat_byte(0xcc),
        allowed_call_target_root: B256::repeat_byte(0xdd),
    };
    journal.template_id = cold_template_id_v4(&journal);
    assert_eq!(
        journal.template_id,
        "0x15bbc53630dc58c0b5943dddc09bbf051e35c661f32be64736c4e846fd4cb529"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        hash_cold_room_journal_v4(&journal),
        "0x72ca560fc6d41ed955c7f404ec02f5a15427350eb25a116f8922ad325d5d55be"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn batch_journal_hash_matches_typescript_and_solidity_vector() {
    let journal = BatchJournalV4 {
        v: 4,
        deployment_id: B256::repeat_byte(0x11),
        room_id: 42,
        preset_hash: B256::repeat_byte(0x22),
        manifest_hash: B256::repeat_byte(0x33),
        proof_program_id: B256::repeat_byte(0x44),
        batch_index: 5,
        l2_start_height: 6,
        l2_end_height: 7,
        previous_block_timestamp: 4,
        final_block_timestamp: 5,
        prev_state_root: B256::repeat_byte(0x55),
        post_state_root: B256::repeat_byte(0x66),
        block_roots_hash: B256::repeat_byte(0x77),
        blocks: Vec::new(),
        pre_roster_root: B256::repeat_byte(0x88),
        post_roster_root: B256::repeat_byte(0x99),
        active_mask: 3,
        post_active_mask: 5,
        used_mask: 7,
        inbox_start: 8,
        inbox_end: 9,
        inbox_inputs_hash: B256::repeat_byte(0xab),
        block_data_hash: B256::repeat_byte(0xaa),
        asset_totals_hash: B256::repeat_byte(0xbb),
        exit_totals_hash: B256::repeat_byte(0xcc),
        fee_totals_hash: B256::repeat_byte(0xdd),
        membership_deltas_hash: B256::repeat_byte(0xee),
        previous_exit_root: B256::repeat_byte(0xef),
        exit_root: B256::repeat_byte(0xff),
        close: true,
        l1_inclusion_deadline: 10,
        exit_allocations: Vec::new(),
        asset_accounting: Vec::new(),
    };
    assert_eq!(
        hash_batch_journal_v4(&journal),
        "0x5e09f930b7b5df1a7e274a8290aa2264da80d5bbb0725192c603ba57e1222de7"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn block_roots_hash_matches_typescript_and_solidity_vector() {
    let blocks = [
        BatchBlockJournalV4 {
            post_state_root: B256::repeat_byte(0x42),
            ..Default::default()
        },
        BatchBlockJournalV4 {
            post_state_root: B256::repeat_byte(0x43),
            ..Default::default()
        },
    ];
    assert_eq!(
        batch_block_roots_hash_v4(&blocks),
        "0x097e3d35a59cc3f691fb250cee70c3c63895b1a9a1f7a59876379364430c6d8b"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn genesis_journal_hash_matches_typescript_and_solidity_vector() {
    let journal = GenesisJournalV4 {
        v: 4,
        deployment_id: B256::repeat_byte(0x01),
        room_id: 42,
        config_hash: "0x8fc85a84b0de22ca84d94c87e0cef14a2e47a5f3ddfa7f43802e6c6a03426b2f"
            .parse()
            .unwrap(),
        preset_hash: B256::repeat_byte(0x11),
        manifest_hash: B256::repeat_byte(0x12),
        proof_program_id: B256::repeat_byte(0x14),
        l1_block_number: 123,
        l1_block_hash: B256::repeat_byte(0x15),
        l1_state_root: B256::repeat_byte(0x16),
        genesis_state_root: B256::repeat_byte(0x41),
        genesis_roster_root: "0x8f880c367fecc7e5cb060b0c811ca65ebf24ef9c9c15f2fac144ef726a48109a"
            .parse()
            .unwrap(),
        genesis_exit_root: B256::ZERO,
        active_mask: 3,
        used_mask: 3,
        inbox_cursor: 2,
        asset_totals_hash: "0x84996d0a0f7d8a6916bcef08610c0be84fe41a21d5666698daca333b085f5199"
            .parse()
            .unwrap(),
        exit_totals_hash: "0x8e9f49e192aace24f5424d8658af1cd4ef6ca54cbddd17ef19e8676e254c18ee"
            .parse()
            .unwrap(),
        fee_totals_hash: "0xec3b26abf4f1670e34d64d317361ebceda91df167586caba07ed26f828c9fbbd"
            .parse()
            .unwrap(),
        l1_inclusion_deadline: 1_900_000_000,
        exit_allocations: Vec::new(),
        asset_accounting: Vec::new(),
    };
    assert_eq!(
        hash_genesis_journal_v4(&journal),
        "0x42f23726afa5950a439bcef039052ba77f366a0343298bc9d10bc85a260ec337"
            .parse::<B256>()
            .unwrap()
    );
}
