use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use k256::ecdsa::SigningKey;
use stf_core::{
    cold_static_state_commitment_v4, execute_block_full, execute_cold_room_v4,
    validate_composed_cold_link_v4, StateMap,
};
use stf_types::{
    hash_cold_room_journal_v4, prepared_room_instance_id_v4, AccountState, BatchBlockV4,
    BatchInputV4, BlockEnvV1, ColdRoomInputV4, ColdRuntimeCodeV4, ColdStateAccessV4,
    ColdStateRefreshV4, ComposedBatchInputV4, StfInput, COLD_TEMPLATE_CHAIN_ID_V4,
};

fn signer() -> (SigningKey, Address) {
    let key = SigningKey::from_bytes(&B256::with_last_byte(1).0.into()).unwrap();
    let address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        .parse()
        .unwrap();
    (key, address)
}

fn sign_creation(init_code: Bytes) -> Bytes {
    let (key, _) = signer();
    let tx = TxEip1559 {
        chain_id: COLD_TEMPLATE_CHAIN_ID_V4,
        nonce: 0,
        gas_limit: 1_000_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Create,
        value: U256::ZERO,
        access_list: Default::default(),
        input: init_code,
    };
    let (signature, recovery_id) = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap();
    let bytes = signature.to_bytes();
    let signature = Signature::new(
        U256::from_be_slice(&bytes[..32]),
        U256::from_be_slice(&bytes[32..]),
        recovery_id.is_y_odd(),
    );
    Bytes::from(TxEnvelope::Eip1559(tx.into_signed(signature)).encoded_2718())
}

fn env() -> BlockEnvV1 {
    BlockEnvV1 {
        number: 0,
        timestamp: 1,
        gas_limit: 2_000_000,
        coinbase: Address::ZERO,
        base_fee: U256::ZERO,
        prev_randao: B256::ZERO,
        difficulty: U256::ZERO,
        excess_blob_gas: 0,
        chain_id: COLD_TEMPLATE_CHAIN_ID_V4,
    }
}

fn prepared_input() -> (ColdRoomInputV4, StateMap, Address) {
    let (_, sender) = signer();
    let contract = sender.create(0);
    let initial_state = vec![(
        sender,
        AccountState {
            nonce: 0,
            balance: U256::from(10_000_000_000u64),
            code: Bytes::new(),
            storage: Vec::new(),
        },
    )];
    let initial_root = StateMap::from_input(&initial_state).state_root();
    // Constructor writes slot zero to one, then returns one-byte STOP runtime.
    let raw = sign_creation(Bytes::from_static(&[
        0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x01, 0x60, 0x11, 0x60, 0x00, 0x39, 0x60, 0x01, 0x60,
        0x00, 0xf3, 0x00,
    ]));
    let execution = execute_block_full(&StfInput {
        room_id: 0,
        block_number: 0,
        prev_state_root: initial_root,
        state: initial_state.clone(),
        raw_txs: vec![raw.clone()],
        env: env(),
        block_hashes: Vec::new(),
    })
    .unwrap();
    let runtime = execution.post_state.accounts[&contract].code.clone();
    assert_eq!(runtime.as_ref(), &[0x00]);
    let block = BatchBlockV4 {
        block_number: 0,
        raw_txs: vec![raw],
        env: env(),
        expected_post_state_root: execution.journal.post_state_root,
    };
    (
        ColdRoomInputV4 {
            encoded_witness_bytes: 5,
            compiled_bundle_hash: B256::repeat_byte(0x11),
            preset_hash: B256::repeat_byte(0x22),
            manifest_hash: B256::repeat_byte(0x33),
            proof_program_id: B256::repeat_byte(0x44),
            initial_state_root: initial_root,
            initialized_state_root: execution.journal.post_state_root,
            analyzed_artifact_root: B256::repeat_byte(0x55),
            allowed_call_target_root: B256::repeat_byte(0x66),
            initial_state,
            setup_blocks: vec![block],
            runtime_code: vec![ColdRuntimeCodeV4 {
                address: contract,
                code_hash: keccak256(&runtime),
            }],
            state_access: vec![ColdStateAccessV4 {
                address: contract,
                storage_slots: vec![U256::ZERO],
            }],
            state_refresh: vec![ColdStateRefreshV4 {
                address: contract,
                refresh_nonce: false,
                refresh_balance: false,
                refresh_all_storage: false,
                storage_slots: vec![U256::ZERO],
            }],
        },
        execution.post_state,
        contract,
    )
}

#[test]
fn constructors_are_executed_once_and_emit_a_reusable_room_independent_statement() {
    let (input, initialized, _) = prepared_input();
    let journal = execute_cold_room_v4(&input).unwrap();
    assert_ne!(journal.template_id, B256::ZERO);
    assert_eq!(journal.initialized_state_root, initialized.state_root());
    assert_eq!(journal.constructor_chain_id, COLD_TEMPLATE_CHAIN_ID_V4);
    assert_ne!(hash_cold_room_journal_v4(&journal), B256::ZERO);

    let cold_hash = hash_cold_room_journal_v4(&journal);
    let deployment = B256::repeat_byte(0xa1);
    let config = B256::repeat_byte(0xb2);
    assert_ne!(
        prepared_room_instance_id_v4(cold_hash, journal.template_id, deployment, 7, config),
        prepared_room_instance_id_v4(cold_hash, journal.template_id, deployment, 8, config),
        "one cached prefix may spawn rooms, but their replay domains must differ"
    );
}

#[test]
fn warm_refresh_masks_only_declared_values_and_never_runtime_code() {
    let (input, initialized, contract) = prepared_input();
    let journal = execute_cold_room_v4(&input).unwrap();

    let mut allowed_refresh = initialized.clone();
    allowed_refresh
        .accounts
        .get_mut(&contract)
        .unwrap()
        .storage
        .insert(U256::ZERO, U256::from(99));
    assert_eq!(
        cold_static_state_commitment_v4(
            &allowed_refresh,
            &input.state_access,
            &input.state_refresh
        )
        .unwrap(),
        journal.static_state_commitment
    );

    let mut changed_code = allowed_refresh.clone();
    changed_code.accounts.get_mut(&contract).unwrap().code = Bytes::from_static(&[0x01]);
    assert_ne!(
        cold_static_state_commitment_v4(&changed_code, &input.state_access, &input.state_refresh)
            .unwrap(),
        journal.static_state_commitment
    );

    let mut undeclared_slot = initialized;
    undeclared_slot
        .accounts
        .get_mut(&contract)
        .unwrap()
        .storage
        .insert(U256::from(1), U256::from(7));
    assert!(cold_static_state_commitment_v4(
        &undeclared_slot,
        &input.state_access,
        &input.state_refresh
    )
    .is_err());
}

#[test]
fn cold_proof_rejects_a_runtime_hash_not_produced_by_the_constructor() {
    let (mut input, _, _) = prepared_input();
    input.runtime_code[0].code_hash = B256::repeat_byte(0xff);
    assert!(execute_cold_room_v4(&input).is_err());
}

#[test]
fn cold_proof_rejects_invalid_witness_and_setup_gas_envelopes() {
    let (mut input, _, _) = prepared_input();
    input.encoded_witness_bytes = 4;
    assert!(execute_cold_room_v4(&input).is_err());

    let (mut input, _, _) = prepared_input();
    input.setup_blocks[0].env.gas_limit = stf_types::MAX_COLD_GAS_PER_BLOCK_V4 + 1;
    assert!(execute_cold_room_v4(&input).is_err());
}

#[test]
fn hot_link_requires_the_exact_cold_program_preset_and_manifest() {
    let (cold_input, initialized, _) = prepared_input();
    let cold_journal = execute_cold_room_v4(&cold_input).unwrap();
    let mut composed = ComposedBatchInputV4 {
        cold_journal,
        runtime_code: cold_input.runtime_code,
        state_access: cold_input.state_access,
        state_refresh: cold_input.state_refresh,
        batch: BatchInputV4 {
            proof_program_id: cold_input.proof_program_id,
            preset_hash: cold_input.preset_hash,
            manifest_hash: cold_input.manifest_hash,
            ..Default::default()
        },
    };
    validate_composed_cold_link_v4(&composed, &initialized).unwrap();
    composed.batch.preset_hash = B256::repeat_byte(0xfe);
    assert!(validate_composed_cold_link_v4(&composed, &initialized).is_err());
}
