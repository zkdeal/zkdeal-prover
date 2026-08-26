//! Protocol-v4 cold-preparation commitments: the reusable template identifier,
//! its journal hash, and the room-binding instance domain.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, B256, U256};

use crate::abi::{address_word, b256_word, hash_words, u256_word, uint256_word};
use crate::v4::types::{
    ColdRoomJournalV4, ColdRuntimeCodeV4, ColdStateAccessV4, ColdStateRefreshV4,
};

pub fn hash_cold_runtime_code_v4(values: &[ColdRuntimeCodeV4]) -> B256 {
    let type_hash = keccak256(b"ColdRuntimeCodeV4(address contractAddress,bytes32 codeHash)");
    let mut encoded = Vec::with_capacity((2 + values.len()) * 32);
    encoded.extend_from_slice(keccak256(b"ColdRuntimeCodeV4[]").as_slice());
    encoded.extend_from_slice(&u256_word(values.len() as u64));
    for value in values {
        encoded.extend_from_slice(
            hash_words([
                b256_word(type_hash),
                address_word(value.address),
                b256_word(value.code_hash),
            ])
            .as_slice(),
        );
    }
    keccak256(encoded)
}

fn hash_cold_slot_list_v4(domain: &'static [u8], slots: &[U256]) -> B256 {
    let mut encoded = Vec::with_capacity((2 + slots.len()) * 32);
    encoded.extend_from_slice(keccak256(domain).as_slice());
    encoded.extend_from_slice(&u256_word(slots.len() as u64));
    for slot in slots {
        encoded.extend_from_slice(&uint256_word(*slot));
    }
    keccak256(encoded)
}

pub fn hash_cold_state_access_v4(values: &[ColdStateAccessV4]) -> B256 {
    let type_hash = keccak256(b"ColdStateAccessV4(address account,bytes32 storageSlotsHash)");
    let mut encoded = Vec::with_capacity((2 + values.len()) * 32);
    encoded.extend_from_slice(keccak256(b"ColdStateAccessV4[]").as_slice());
    encoded.extend_from_slice(&u256_word(values.len() as u64));
    for value in values {
        let slots_hash =
            hash_cold_slot_list_v4(b"ColdStateAccessStorageSlotV4[]", &value.storage_slots);
        encoded.extend_from_slice(
            hash_words([
                b256_word(type_hash),
                address_word(value.address),
                b256_word(slots_hash),
            ])
            .as_slice(),
        );
    }
    keccak256(encoded)
}

pub fn hash_cold_state_refresh_v4(values: &[ColdStateRefreshV4]) -> B256 {
    let type_hash = keccak256(
        b"ColdStateRefreshV4(address account,bool refreshNonce,bool refreshBalance,bool refreshAllStorage,bytes32 storageSlotsHash)",
    );
    let mut encoded = Vec::with_capacity((2 + values.len()) * 32);
    encoded.extend_from_slice(keccak256(b"ColdStateRefreshV4[]").as_slice());
    encoded.extend_from_slice(&u256_word(values.len() as u64));
    for value in values {
        let slots_hash =
            hash_cold_slot_list_v4(b"ColdStateRefreshStorageSlotV4[]", &value.storage_slots);
        encoded.extend_from_slice(
            hash_words([
                b256_word(type_hash),
                address_word(value.address),
                u256_word(u64::from(value.refresh_nonce)),
                u256_word(u64::from(value.refresh_balance)),
                u256_word(u64::from(value.refresh_all_storage)),
                b256_word(slots_hash),
            ])
            .as_slice(),
        );
    }
    keccak256(encoded)
}

/// Derive the reusable template identifier from the complete proven cold
/// statement. `template_id` itself is excluded to avoid a self-reference.
pub fn cold_template_id_v4(journal: &ColdRoomJournalV4) -> B256 {
    hash_words([
        b256_word(keccak256(b"ColdTemplateIdV4(bytes32 compiledBundleHash,bytes32 presetHash,bytes32 manifestHash,bytes32 proofProgramId,uint64 constructorChainId,bytes32 initialStateRoot,bytes32 initializedStateRoot,bytes32 setupDataHash,bytes32 runtimeCodeRoot,bytes32 stateAccessRoot,bytes32 stateRefreshRoot,bytes32 staticStateCommitment,bytes32 analyzedArtifactRoot,bytes32 allowedCallTargetRoot)")),
        b256_word(journal.compiled_bundle_hash),
        b256_word(journal.preset_hash),
        b256_word(journal.manifest_hash),
        b256_word(journal.proof_program_id),
        u256_word(journal.constructor_chain_id),
        b256_word(journal.initial_state_root),
        b256_word(journal.initialized_state_root),
        b256_word(journal.setup_data_hash),
        b256_word(journal.runtime_code_root),
        b256_word(journal.state_access_root),
        b256_word(journal.state_refresh_root),
        b256_word(journal.static_state_commitment),
        b256_word(journal.analyzed_artifact_root),
        b256_word(journal.allowed_call_target_root),
    ])
}

/// Solidity-friendly public journal hash committed by the cold guest.
pub fn hash_cold_room_journal_v4(journal: &ColdRoomJournalV4) -> B256 {
    hash_words([
        b256_word(keccak256(b"ColdRoomJournalV4(uint256 protocolVersion,bytes32 templateId,bytes32 compiledBundleHash,bytes32 presetHash,bytes32 manifestHash,bytes32 proofProgramId,uint64 constructorChainId,bytes32 initialStateRoot,bytes32 initializedStateRoot,bytes32 setupDataHash,bytes32 runtimeCodeRoot,bytes32 stateAccessRoot,bytes32 stateRefreshRoot,bytes32 staticStateCommitment,bytes32 analyzedArtifactRoot,bytes32 allowedCallTargetRoot)")),
        u256_word(u64::from(journal.v)),
        b256_word(journal.template_id),
        b256_word(journal.compiled_bundle_hash),
        b256_word(journal.preset_hash),
        b256_word(journal.manifest_hash),
        b256_word(journal.proof_program_id),
        u256_word(journal.constructor_chain_id),
        b256_word(journal.initial_state_root),
        b256_word(journal.initialized_state_root),
        b256_word(journal.setup_data_hash),
        b256_word(journal.runtime_code_root),
        b256_word(journal.state_access_root),
        b256_word(journal.state_refresh_root),
        b256_word(journal.static_state_commitment),
        b256_word(journal.analyzed_artifact_root),
        b256_word(journal.allowed_call_target_root),
    ])
}

/// Bind a reusable template to one deployment/room/config namespace. Every
/// signature/nullifier may include this value without preventing cold-proof
/// reuse by other rooms.
pub fn prepared_room_instance_id_v4(
    cold_journal_hash: B256,
    template_id: B256,
    deployment_id: B256,
    room_id: u64,
    config_hash: B256,
) -> B256 {
    hash_words([
        b256_word(keccak256(b"PreparedRoomInstanceV4(bytes32 coldJournalHash,bytes32 templateId,bytes32 deploymentDomain,uint256 roomId,bytes32 configHash)")),
        b256_word(cold_journal_hash),
        b256_word(template_id),
        b256_word(deployment_id),
        u256_word(room_id),
        b256_word(config_hash),
    ])
}
