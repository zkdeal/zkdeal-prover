//! Differential execution gate for the ranked straight-line opcode gadgets.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address, Bytes, Signature, TxKind, B256, U256};
use stf_core::{
    execute_block_full, execute_block_full_without_opcode_gadgets, StateMap, TOP_50_SOLIDITY_MOTIFS,
};
use stf_types::{AccountState, BlockEnvV1, StfInput};

const CHAIN_ID: u64 = 77_000_501;
const CALLER: Address = address!("7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
const CONTRACT: Address = address!("000000000000000000000000000000000000c0de");

fn sign_call() -> Bytes {
    let key = k256::ecdsa::SigningKey::from_bytes(&B256::with_last_byte(1).0.into()).unwrap();
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: 3_000_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(CONTRACT),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::new(),
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

fn all_motif_runtime() -> Bytes {
    let mut code = Vec::with_capacity(TOP_50_SOLIDITY_MOTIFS.len() * 8 + 3);
    for (index, motif) in TOP_50_SOLIDITY_MOTIFS.iter().enumerate() {
        // Three fresh non-zero operands make every unary/binary pair valid.
        // Varying the values exercises signed, comparison, shift, and division
        // paths without triggering an exceptional halt.
        code.extend_from_slice(&[
            0x60,
            (index as u8).wrapping_add(2),
            0x60,
            (index as u8).wrapping_add(3),
            0x60,
            (index as u8).wrapping_add(4),
            motif.first,
            motif.second,
        ]);
    }
    // Commit the final result so parity covers more than the final nonce/gas.
    code.extend_from_slice(&[0x5f, 0x55, 0x00]); // PUSH0; SSTORE; STOP
    Bytes::from(code)
}

fn input() -> StfInput {
    let state = vec![
        (
            CALLER,
            AccountState {
                nonce: 0,
                balance: U256::from(10u64.pow(18)),
                code: Bytes::new(),
                storage: Vec::new(),
            },
        ),
        (
            CONTRACT,
            AccountState {
                nonce: 1,
                balance: U256::ZERO,
                code: all_motif_runtime(),
                storage: Vec::new(),
            },
        ),
    ];
    let prev_state_root = StateMap::from_input(&state).state_root();
    StfInput {
        room_id: 501,
        block_number: 1,
        prev_state_root,
        state,
        raw_txs: vec![sign_call()],
        env: BlockEnvV1 {
            number: 1,
            timestamp: 1,
            gas_limit: 3_000_000,
            coinbase: Address::ZERO,
            base_fee: U256::ZERO,
            prev_randao: B256::ZERO,
            difficulty: U256::ZERO,
            excess_blob_gas: 0,
            chain_id: CHAIN_ID,
        },
        block_hashes: Vec::new(),
    }
}

#[test]
fn all_top_50_gadgets_match_plain_osaka_execution() {
    let input = input();
    let plain =
        execute_block_full_without_opcode_gadgets(&input).expect("plain Osaka execution succeeds");
    let prepared = execute_block_full(&input).expect("prepared gadget execution succeeds");

    assert_eq!(prepared.journal, plain.journal);
    assert_eq!(prepared.gas_used, plain.gas_used);
    assert_eq!(
        prepared.post_state.to_input_state(),
        plain.post_state.to_input_state()
    );
    assert_eq!(
        prepared.proof_work.opcode_steps,
        plain.proof_work.opcode_steps
    );
    assert_eq!(prepared.proof_work.fused_motif_hits, 50);
    assert_eq!(prepared.proof_work.fused_motif_opcodes, 100);
    assert_eq!(plain.proof_work.fused_motif_hits, 0);
}
