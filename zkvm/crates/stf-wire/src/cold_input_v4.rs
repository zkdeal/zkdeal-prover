//! V4 cold-template and composed-batch wire family: the constructor witness,
//! the cold journal mirror, and the composed statement that links them to a
//! hot batch.

use alloy_primitives::{Address, Bytes, B256, U256};
use borsh::{BorshDeserialize, BorshSerialize};
use stf_types::{
    AccountState, BatchBlockV4, BlockEnvV1, ColdRoomInputV4, ColdRoomJournalV4, ColdRuntimeCodeV4,
    ColdStateAccessV4, ColdStateRefreshV4, ComposedBatchInputV4,
};

use crate::batch_input_v4::{BatchBlockWireV4, BatchInputWireV4};
use crate::block_v1::AccountWire;

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ColdRuntimeCodeWireV4 {
    pub address: [u8; 20],
    pub code_hash: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ColdStateAccessWireV4 {
    pub address: [u8; 20],
    pub storage_slots: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ColdStateRefreshWireV4 {
    pub address: [u8; 20],
    pub refresh_nonce: bool,
    pub refresh_balance: bool,
    pub refresh_all_storage: bool,
    pub storage_slots: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ColdRoomInputWireV4 {
    pub v: u8,
    pub compiled_bundle_hash: [u8; 32],
    pub preset_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub proof_program_id: [u8; 32],
    pub initial_state_root: [u8; 32],
    pub initialized_state_root: [u8; 32],
    pub analyzed_artifact_root: [u8; 32],
    pub allowed_call_target_root: [u8; 32],
    pub initial_state: Vec<AccountWire>,
    pub setup_blocks: Vec<BatchBlockWireV4>,
    pub runtime_code: Vec<ColdRuntimeCodeWireV4>,
    pub state_access: Vec<ColdStateAccessWireV4>,
    pub state_refresh: Vec<ColdStateRefreshWireV4>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ColdRoomJournalWireV4 {
    pub v: u8,
    pub template_id: [u8; 32],
    pub compiled_bundle_hash: [u8; 32],
    pub preset_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub proof_program_id: [u8; 32],
    pub constructor_chain_id: u64,
    pub initial_state_root: [u8; 32],
    pub initialized_state_root: [u8; 32],
    pub setup_data_hash: [u8; 32],
    pub runtime_code_root: [u8; 32],
    pub state_access_root: [u8; 32],
    pub state_refresh_root: [u8; 32],
    pub static_state_commitment: [u8; 32],
    pub analyzed_artifact_root: [u8; 32],
    pub allowed_call_target_root: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ComposedBatchInputWireV4 {
    pub v: u8,
    pub cold_journal: ColdRoomJournalWireV4,
    pub runtime_code: Vec<ColdRuntimeCodeWireV4>,
    pub state_access: Vec<ColdStateAccessWireV4>,
    pub state_refresh: Vec<ColdStateRefreshWireV4>,
    pub batch: BatchInputWireV4,
}

fn cold_runtime_from_wire(values: &[ColdRuntimeCodeWireV4]) -> Vec<ColdRuntimeCodeV4> {
    values
        .iter()
        .map(|entry| ColdRuntimeCodeV4 {
            address: Address::from(entry.address),
            code_hash: B256::from(entry.code_hash),
        })
        .collect()
}

fn cold_access_from_wire(values: &[ColdStateAccessWireV4]) -> Vec<ColdStateAccessV4> {
    values
        .iter()
        .map(|entry| ColdStateAccessV4 {
            address: Address::from(entry.address),
            storage_slots: entry
                .storage_slots
                .iter()
                .copied()
                .map(U256::from_be_bytes)
                .collect(),
        })
        .collect()
}

fn cold_refresh_from_wire(values: &[ColdStateRefreshWireV4]) -> Vec<ColdStateRefreshV4> {
    values
        .iter()
        .map(|entry| ColdStateRefreshV4 {
            address: Address::from(entry.address),
            refresh_nonce: entry.refresh_nonce,
            refresh_balance: entry.refresh_balance,
            refresh_all_storage: entry.refresh_all_storage,
            storage_slots: entry
                .storage_slots
                .iter()
                .copied()
                .map(U256::from_be_bytes)
                .collect(),
        })
        .collect()
}

impl ColdRoomInputWireV4 {
    pub fn to_input(&self) -> Result<ColdRoomInputV4, String> {
        if self.v != stf_types::BATCH_JOURNAL_VERSION_V4 {
            return Err(format!("cold input version {} != 4", self.v));
        }
        let encoded_witness_bytes = u32::try_from(
            4usize
                .checked_add(
                    borsh::to_vec(self)
                        .map_err(|error| format!("cold input borsh: {error}"))?
                        .len(),
                )
                .ok_or("cold witness length overflow")?,
        )
        .map_err(|_| "cold witness length exceeds u32")?;
        Ok(ColdRoomInputV4 {
            encoded_witness_bytes,
            compiled_bundle_hash: B256::from(self.compiled_bundle_hash),
            preset_hash: B256::from(self.preset_hash),
            manifest_hash: B256::from(self.manifest_hash),
            proof_program_id: B256::from(self.proof_program_id),
            initial_state_root: B256::from(self.initial_state_root),
            initialized_state_root: B256::from(self.initialized_state_root),
            analyzed_artifact_root: B256::from(self.analyzed_artifact_root),
            allowed_call_target_root: B256::from(self.allowed_call_target_root),
            initial_state: self
                .initial_state
                .iter()
                .map(|account| {
                    (
                        Address::from(account.address),
                        AccountState {
                            nonce: account.nonce,
                            balance: U256::from_be_bytes(account.balance),
                            code: Bytes::from(account.code.clone()),
                            storage: account
                                .storage
                                .iter()
                                .map(|(slot, value)| {
                                    (U256::from_be_bytes(*slot), U256::from_be_bytes(*value))
                                })
                                .collect(),
                        },
                    )
                })
                .collect(),
            setup_blocks: self
                .setup_blocks
                .iter()
                .map(|block| BatchBlockV4 {
                    block_number: block.block_number,
                    raw_txs: block.raw_txs.iter().cloned().map(Bytes::from).collect(),
                    env: BlockEnvV1 {
                        number: block.block_number,
                        timestamp: block.env.timestamp,
                        gas_limit: block.env.gas_limit,
                        coinbase: Address::ZERO,
                        base_fee: U256::ZERO,
                        prev_randao: B256::ZERO,
                        difficulty: U256::ZERO,
                        excess_blob_gas: 0,
                        chain_id: stf_types::COLD_TEMPLATE_CHAIN_ID_V4,
                    },
                    expected_post_state_root: B256::from(block.expected_post_state_root),
                })
                .collect(),
            runtime_code: cold_runtime_from_wire(&self.runtime_code),
            state_access: cold_access_from_wire(&self.state_access),
            state_refresh: cold_refresh_from_wire(&self.state_refresh),
        })
    }
}

impl ColdRoomJournalWireV4 {
    pub fn to_journal(&self) -> ColdRoomJournalV4 {
        ColdRoomJournalV4 {
            v: self.v,
            template_id: B256::from(self.template_id),
            compiled_bundle_hash: B256::from(self.compiled_bundle_hash),
            preset_hash: B256::from(self.preset_hash),
            manifest_hash: B256::from(self.manifest_hash),
            proof_program_id: B256::from(self.proof_program_id),
            constructor_chain_id: self.constructor_chain_id,
            initial_state_root: B256::from(self.initial_state_root),
            initialized_state_root: B256::from(self.initialized_state_root),
            setup_data_hash: B256::from(self.setup_data_hash),
            runtime_code_root: B256::from(self.runtime_code_root),
            state_access_root: B256::from(self.state_access_root),
            state_refresh_root: B256::from(self.state_refresh_root),
            static_state_commitment: B256::from(self.static_state_commitment),
            analyzed_artifact_root: B256::from(self.analyzed_artifact_root),
            allowed_call_target_root: B256::from(self.allowed_call_target_root),
        }
    }
}

impl From<&ColdRoomJournalV4> for ColdRoomJournalWireV4 {
    fn from(value: &ColdRoomJournalV4) -> Self {
        Self {
            v: value.v,
            template_id: value.template_id.0,
            compiled_bundle_hash: value.compiled_bundle_hash.0,
            preset_hash: value.preset_hash.0,
            manifest_hash: value.manifest_hash.0,
            proof_program_id: value.proof_program_id.0,
            constructor_chain_id: value.constructor_chain_id,
            initial_state_root: value.initial_state_root.0,
            initialized_state_root: value.initialized_state_root.0,
            setup_data_hash: value.setup_data_hash.0,
            runtime_code_root: value.runtime_code_root.0,
            state_access_root: value.state_access_root.0,
            state_refresh_root: value.state_refresh_root.0,
            static_state_commitment: value.static_state_commitment.0,
            analyzed_artifact_root: value.analyzed_artifact_root.0,
            allowed_call_target_root: value.allowed_call_target_root.0,
        }
    }
}

impl ComposedBatchInputWireV4 {
    pub fn to_input(&self) -> Result<ComposedBatchInputV4, String> {
        let encoded_witness_bytes = u32::try_from(
            4usize
                .checked_add(
                    borsh::to_vec(self)
                        .map_err(|error| format!("composed input borsh: {error}"))?
                        .len(),
                )
                .ok_or("composed witness length overflow")?,
        )
        .map_err(|_| "composed witness length exceeds u32")?;
        self.to_input_with_encoded_witness_bytes(encoded_witness_bytes)
    }

    /// Convert a decoded composed witness when its exact canonical byte length
    /// is already known from the proof-bound guest input frame.
    pub fn to_input_with_encoded_witness_bytes(
        &self,
        encoded_witness_bytes: u32,
    ) -> Result<ComposedBatchInputV4, String> {
        if self.v != stf_types::BATCH_JOURNAL_VERSION_V4 {
            return Err(format!("composed batch input version {} != 4", self.v));
        }
        let mut batch = self.batch.to_input()?;
        batch.encoded_witness_bytes = encoded_witness_bytes;
        Ok(ComposedBatchInputV4 {
            cold_journal: self.cold_journal.to_journal(),
            runtime_code: cold_runtime_from_wire(&self.runtime_code),
            state_access: cold_access_from_wire(&self.state_access),
            state_refresh: cold_refresh_from_wire(&self.state_refresh),
            batch,
        })
    }
}
