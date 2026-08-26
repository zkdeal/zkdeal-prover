//! Wire codecs shared by every zkVM backend.
//!
//! Two layers:
//!
//! 1. **Borsh wire types** ([`StfInputWire`], [`journal_to_borsh`] /
//!    [`journal_from_borsh`]) — the exact bytes that cross the guest boundary
//!    for BOTH backends (risc0 `env::read::<Vec<u8>>()`, ligetron hex arg 1).
//!    Fixed layout; the journal is 145 bytes
//!    (`1 + 8 + 8 + 32 + 32 + 32 + 32`) since journal v2 added `env_hash`.
//! 2. **Witness-JSON bridge** (feature `json`, host/wasm side only) — parses
//!    the TS `StfWitness` shape produced by `@zkdeal/zkvm`
//!    (`{ roomId, blockNumber, prevStateRoot, stateDumpJson, rawTxs, env }`,
//!    where `stateDumpJson` is the l2-engine SLOT-keyed `serializeStateDump`
//!    output) into an [`stf_types::StfInput`], and serializes journals /
//!    post-state dumps back into the TS shapes.
//!
//! The block environment is deliberately NOT part of the witness beyond
//! `timestamp` + `gasLimit`: the zkdeal L2 fixes coinbase=0x0, baseFee=0,
//! prevRandao=0, difficulty=0, excessBlobGas=0 and derives
//! legacy chain id for legacy single-block witnesses. V4 batches instead use
//! the deployment-scoped `room_chain_id_v4`, mirrored by the protocol package.
//!
//! The codecs are split by wire message family — `block_v1` (single block),
//! `batch_input_v4`, `cold_input_v4`, `batch_journal_v4` and the
//! magic-prefixed `frame_v4` framing — and re-exported flat from here, which
//! is the only path callers use.

use alloy_primitives::B256;

mod batch_input_v4;
mod batch_journal_v4;
mod block_v1;
mod cold_input_v4;
mod frame_v4;

pub use batch_input_v4::{
    AssetTotalWireV4, BatchBlockWireV4, BatchInputWireV4, CompactAccountWireV4, CompactStateWireV4,
    CompactStorageWireV4, ExitAllocationWireV4, GenesisInputWireV4, InboxAssetAmountWireV4,
    InboxEntryWireV4, MemberSlotWireV4, MembershipDeltaWireV4, ResidualAllocationWireV4,
};
pub use batch_journal_v4::{batch_journal_from_borsh_v4, batch_journal_to_borsh_v4};
pub use block_v1::{
    input_from_borsh, input_to_borsh, journal_from_borsh, journal_to_borsh, AccountWire, EnvWire,
    HistoricalBlockHashWire, JournalWire, StfInputWire, JOURNAL_WIRE_LEN,
};
pub use cold_input_v4::{
    ColdRoomInputWireV4, ColdRoomJournalWireV4, ColdRuntimeCodeWireV4, ColdStateAccessWireV4,
    ColdStateRefreshWireV4, ComposedBatchInputWireV4,
};
pub use frame_v4::{
    batch_input_from_borsh_v4, batch_input_to_borsh_v4, cold_input_from_borsh_v4,
    cold_input_to_borsh_v4, composed_batch_input_from_borsh_v4, composed_batch_input_to_borsh_v4,
    genesis_input_from_borsh_v4, genesis_input_to_borsh_v4,
};

/// Deterministic L2 chain id for a room (protocol constants.ts mirror).
pub fn l2_chain_id(room_id: u64) -> u64 {
    77_000_000 + room_id % 1_000_000
}

pub fn l2_chain_id_v4(deployment_id: B256, room_id: u64) -> u64 {
    stf_types::room_chain_id_v4(deployment_id, room_id)
}

/* ------------------------------------------------------------------ */
/* Witness-JSON bridge (feature `json`)                                */
/* ------------------------------------------------------------------ */

#[cfg(feature = "json")]
mod json_bridge;

#[cfg(feature = "json")]
pub use json_bridge::{
    batch_journal_to_ts_value_v4, genesis_journal_to_ts_value_v4, journal_to_ts_value,
    parse_batch_journal_json_v4, parse_batch_witness_json_v4, parse_genesis_journal_json_v4,
    parse_genesis_witness_json_v4, parse_witness_json, post_state_to_dump_json,
};

#[cfg(test)]
mod tests {
    use super::*;
    use stf_types::{BatchBlockJournalV4, BatchJournalV4, StfJournal};

    #[test]
    fn journal_roundtrip() {
        let j = StfJournal {
            v: stf_types::JOURNAL_VERSION,
            room_id: 42,
            block_number: 7,
            prev_state_root: B256::repeat_byte(0xaa),
            post_state_root: B256::repeat_byte(0xbb),
            tx_commitment: B256::repeat_byte(0xcc),
            env_hash: B256::repeat_byte(0xdd),
        };
        let bytes = journal_to_borsh(&j);
        assert_eq!(bytes.len(), JOURNAL_WIRE_LEN);
        assert_eq!(journal_from_borsh(&bytes).unwrap(), j);
    }

    #[test]
    fn batch_v4_journal_roundtrip_preserves_intermediate_roots() {
        let j = BatchJournalV4 {
            v: stf_types::BATCH_JOURNAL_VERSION_V4,
            deployment_id: B256::repeat_byte(0x01),
            room_id: 42,
            preset_hash: B256::repeat_byte(0x02),
            manifest_hash: B256::repeat_byte(0x12),
            proof_program_id: B256::repeat_byte(0x03),
            batch_index: 8,
            l2_start_height: 10,
            l2_end_height: 11,
            previous_block_timestamp: 1_000,
            final_block_timestamp: 1_002,
            prev_state_root: B256::repeat_byte(0x04),
            post_state_root: B256::repeat_byte(0x06),
            block_roots_hash: B256::repeat_byte(0x14),
            blocks: vec![
                BatchBlockJournalV4 {
                    block_number: 10,
                    post_state_root: B256::repeat_byte(0x05),
                    tx_commitment: B256::repeat_byte(0x15),
                    env_hash: B256::repeat_byte(0x25),
                },
                BatchBlockJournalV4 {
                    block_number: 11,
                    post_state_root: B256::repeat_byte(0x06),
                    tx_commitment: B256::repeat_byte(0x16),
                    env_hash: B256::repeat_byte(0x26),
                },
            ],
            pre_roster_root: B256::repeat_byte(0x07),
            post_roster_root: B256::repeat_byte(0x08),
            active_mask: 0b11,
            post_active_mask: 0b101,
            used_mask: 0b111,
            inbox_start: 4,
            inbox_end: 7,
            inbox_inputs_hash: B256::repeat_byte(0x19),
            block_data_hash: B256::repeat_byte(0x09),
            asset_totals_hash: B256::repeat_byte(0x0a),
            exit_totals_hash: B256::repeat_byte(0x1a),
            fee_totals_hash: B256::repeat_byte(0x2a),
            membership_deltas_hash: B256::repeat_byte(0x3a),
            previous_exit_root: B256::repeat_byte(0x4a),
            exit_root: B256::repeat_byte(0x0b),
            close: false,
            l1_inclusion_deadline: 99,
            exit_allocations: Vec::new(),
            asset_accounting: Vec::new(),
        };
        let bytes = batch_journal_to_borsh_v4(&j);
        assert_eq!(batch_journal_from_borsh_v4(&bytes).unwrap(), j);
    }

    #[test]
    fn cold_and_composed_v4_inputs_have_distinct_magic_and_roundtrip() {
        let cold = ColdRoomInputWireV4 {
            v: stf_types::BATCH_JOURNAL_VERSION_V4,
            compiled_bundle_hash: [0x11; 32],
            preset_hash: [0x22; 32],
            manifest_hash: [0x33; 32],
            proof_program_id: [0x44; 32],
            ..Default::default()
        };
        let cold_bytes = cold_input_to_borsh_v4(&cold);
        assert_eq!(&cold_bytes[..4], b"ZK4K");
        assert_eq!(cold_input_from_borsh_v4(&cold_bytes).unwrap(), cold);
        assert!(batch_input_from_borsh_v4(&cold_bytes).is_err());

        let composed = ComposedBatchInputWireV4 {
            v: stf_types::BATCH_JOURNAL_VERSION_V4,
            cold_journal: ColdRoomJournalWireV4 {
                v: stf_types::BATCH_JOURNAL_VERSION_V4,
                template_id: [0xaa; 32],
                ..Default::default()
            },
            batch: BatchInputWireV4 {
                v: stf_types::BATCH_JOURNAL_VERSION_V4,
                ..Default::default()
            },
            ..Default::default()
        };
        let composed_bytes = composed_batch_input_to_borsh_v4(&composed);
        assert_eq!(&composed_bytes[..4], b"ZK4C");
        assert_eq!(
            composed_batch_input_from_borsh_v4(&composed_bytes).unwrap(),
            composed
        );
        let expanded = composed.to_input().unwrap();
        assert_eq!(
            expanded.batch.encoded_witness_bytes as usize,
            composed_bytes.len()
        );
        let expanded_from_known_len = composed
            .to_input_with_encoded_witness_bytes(composed_bytes.len() as u32)
            .unwrap();
        assert_eq!(expanded_from_known_len, expanded);
    }

    #[cfg(feature = "json")]
    #[test]
    fn witness_json_parses_decimal_and_hex() {
        let dump = r#"{"0x00000000000000000000000000000000000000aa":{"nonce":"1","balance":"1000","storage":{"0x0000000000000000000000000000000000000000000000000000000000000001":"0x02"}}}"#;
        let witness = serde_json::json!({
            "roomId": "101",
            "blockNumber": "3",
            "prevStateRoot": format!("0x{}", "11".repeat(32)),
            "stateDumpJson": dump,
            "rawTxs": ["0xdead"],
            "env": { "timestamp": "1234", "gasLimit": "30000000" },
        })
        .to_string();
        let wire = parse_witness_json(&witness).unwrap();
        assert_eq!(wire.room_id, 101);
        assert_eq!(wire.block_number, 3);
        assert_eq!(wire.state.len(), 1);
        assert_eq!(wire.state[0].nonce, 1);
        assert_eq!(wire.state[0].storage.len(), 1);
        assert_eq!(wire.raw_txs[0], vec![0xde, 0xad]);
        let input = wire.to_input();
        assert_eq!(input.env.chain_id, 77_000_101);
        assert_eq!(input.env.number, 3);
    }
}
