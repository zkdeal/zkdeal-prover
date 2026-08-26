//! Signed room transactions and the canonical preset / exit-program
//! preimages the generic v4 fixtures are proved against.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use stf_types::MemberSlotWitnessV4;

pub(crate) fn sign_member_zero_1559(
    chain_id: u64,
    nonce: u64,
    target: Address,
    input: Bytes,
) -> Bytes {
    sign_member_zero_value_1559(chain_id, nonce, target, U256::ZERO, input)
}

pub(crate) fn sign_member_zero_value_1559(
    chain_id: u64,
    nonce: u64,
    target: Address,
    value: U256,
    input: Bytes,
) -> Bytes {
    // Well-known development key 0x00..01, whose address is roster slot 0.
    let key = k256::ecdsa::SigningKey::from_bytes(&B256::with_last_byte(1).0.into()).unwrap();
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 2_000_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(target),
        value,
        access_list: Default::default(),
        input,
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

pub(crate) fn direct_native_exit_program_json() -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "assets": [{ "assetId": 0, "kind": "native" }],
            "positions": [],
            "version": 4
        }))
        .unwrap(),
    )
}

pub(crate) fn generic_preset_json(exit_program_id: B256) -> Bytes {
    let preset = serde_json::json!({
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
    });
    Bytes::from(serde_json::to_vec(&preset).unwrap())
}

pub(crate) fn roster() -> Vec<MemberSlotWitnessV4> {
    let mut slots = vec![
        MemberSlotWitnessV4 {
            slot: 0,
            state: 1,
            account: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
                .parse()
                .unwrap(),
            joined_at_batch: 0,
            retired_at_batch: None,
        },
        MemberSlotWitnessV4 {
            slot: 1,
            state: 1,
            account: "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"
                .parse()
                .unwrap(),
            joined_at_batch: 0,
            retired_at_batch: None,
        },
    ];
    for slot in 2..7 {
        slots.push(MemberSlotWitnessV4 {
            slot,
            ..Default::default()
        });
    }
    slots
}
