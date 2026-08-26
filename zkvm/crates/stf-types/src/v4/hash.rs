//! Protocol-v4 commitments: roster root, journal hashes and the accounting,
//! inbox and claim projections mirrored by RoomCodecV4 and its TypeScript twin.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, B256, U256};

use crate::abi::{address_word, b256_word, hash_words, u256_word, uint256_word};
use crate::v4::types::{
    AssetAccountingV4, BatchBlockJournalV4, BatchJournalV4, ExitAllocationV4, GenesisJournalV4,
    InboxEntryWitnessV4, MemberSlotWitnessV4, MembershipDeltaWitnessV4,
};

/// Protocol-v4 seven-slot roster commitment (OpenZeppelin-compatible sorted
/// pair hashing, odd nodes duplicated). Structural slot validation remains a
/// guest policy check; this helper is the byte-exact commitment primitive.
pub fn member_roster_root_v4(slots: &[MemberSlotWitnessV4]) -> Option<B256> {
    if slots.is_empty() {
        return None;
    }
    let type_hash =
        keccak256(b"MemberSlotV4(uint8 slot,uint8 state,address account,uint64 joinedAtBatch,uint64 retiredAtBatch)");
    let word = |value: u64| {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    };
    let mut leaves = slots
        .iter()
        .map(|slot| {
            let mut encoded = Vec::with_capacity(32 * 6);
            encoded.extend_from_slice(type_hash.as_slice());
            encoded.extend_from_slice(&word(u64::from(slot.slot)));
            encoded.extend_from_slice(&word(u64::from(slot.state)));
            encoded.extend_from_slice(&[0u8; 12]);
            encoded.extend_from_slice(slot.account.as_slice());
            encoded.extend_from_slice(&word(slot.joined_at_batch));
            encoded.extend_from_slice(&word(slot.retired_at_batch.unwrap_or_default()));
            keccak256(encoded)
        })
        .collect::<Vec<_>>();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for pair in leaves.chunks(2) {
            let a = pair[0];
            let b = *pair.get(1).unwrap_or(&a);
            let (left, right) = if a <= b { (a, b) } else { (b, a) };
            let mut encoded = [0u8; 64];
            encoded[..32].copy_from_slice(left.as_slice());
            encoded[32..].copy_from_slice(right.as_slice());
            next.push(keccak256(encoded));
        }
        leaves = next;
    }
    leaves.pop()
}

/// `hashBlockRootsV4` from the v4 protocol package and RoomCodecV4.
pub fn batch_block_roots_hash_v4(blocks: &[BatchBlockJournalV4]) -> B256 {
    let mut encoded = Vec::with_capacity((2 + blocks.len()) * 32);
    encoded.extend_from_slice(keccak256(b"BatchBlockRootsV4[]").as_slice());
    encoded.extend_from_slice(&u256_word(blocks.len() as u64));
    for block in blocks {
        encoded.extend_from_slice(block.post_state_root.as_slice());
    }
    keccak256(encoded)
}

/// Signature-free EIP-712 struct hash accepted from a joining member. The
/// exact batch journal is included so an entrant cannot authorize activation
/// while leaving the incumbent roster free to choose different exits or state.
pub fn hash_join_acceptance_struct_v4(
    room_id: u64,
    request_index: u64,
    slot: u8,
    member: Address,
    deposits_hash: B256,
    config_hash: B256,
    journal_hash: B256,
    expiry: u64,
) -> B256 {
    hash_words([
        b256_word(keccak256(b"JoinAcceptanceV4(uint256 roomId,uint64 requestIndex,uint8 slot,address member,bytes32 depositsHash,bytes32 configHash,bytes32 journalHash,uint64 expiry)")),
        u256_word(room_id),
        u256_word(request_index),
        u256_word(u64::from(slot)),
        address_word(member),
        b256_word(deposits_hash),
        b256_word(config_hash),
        b256_word(journal_hash),
        u256_word(expiry),
    ])
}

fn hash_asset_amount_v4(asset_id: u8, amount: U256) -> B256 {
    hash_words([
        b256_word(keccak256(b"AssetAmountV4(uint8 assetId,uint256 amount)")),
        u256_word(u64::from(asset_id)),
        uint256_word(amount),
    ])
}

fn hash_amount_projection_v4(list_domain: &'static [u8], values: &[(u8, U256)]) -> B256 {
    let mut encoded = Vec::with_capacity((2 + values.len()) * 32);
    encoded.extend_from_slice(keccak256(list_domain).as_slice());
    encoded.extend_from_slice(&u256_word(values.len() as u64));
    for (asset_id, amount) in values {
        encoded.extend_from_slice(hash_asset_amount_v4(*asset_id, *amount).as_slice());
    }
    keccak256(encoded)
}

pub fn hash_asset_totals_v4(values: &[AssetAccountingV4]) -> B256 {
    hash_amount_projection_v4(
        b"AssetTotalsV4[]",
        &values
            .iter()
            .map(|v| (v.asset_id, v.total))
            .collect::<Vec<_>>(),
    )
}

pub fn hash_exit_totals_v4(values: &[AssetAccountingV4]) -> B256 {
    hash_amount_projection_v4(
        b"ExitTotalsV4[]",
        &values
            .iter()
            .map(|v| (v.asset_id, v.exit_total))
            .collect::<Vec<_>>(),
    )
}

pub fn hash_fee_totals_v4(values: &[AssetAccountingV4]) -> B256 {
    hash_amount_projection_v4(
        b"FeeTotalsV4[]",
        &values
            .iter()
            .map(|v| (v.asset_id, v.fee_total))
            .collect::<Vec<_>>(),
    )
}

pub fn hash_membership_deltas_v4(values: &[MembershipDeltaWitnessV4]) -> B256 {
    let item_type = keccak256(
        b"MembershipDeltaV4(uint8 action,uint8 slot,address member,uint64 joinRequestIndex,uint64 acceptanceExpiry)",
    );
    let mut encoded = Vec::with_capacity((2 + values.len()) * 32);
    encoded.extend_from_slice(keccak256(b"MembershipDeltaV4[]").as_slice());
    encoded.extend_from_slice(&u256_word(values.len() as u64));
    for value in values {
        let hash = hash_words([
            b256_word(item_type),
            u256_word(u64::from(value.action)),
            u256_word(u64::from(value.slot)),
            address_word(value.member),
            u256_word(value.join_request_index),
            u256_word(value.acceptance_expiry),
        ]);
        encoded.extend_from_slice(hash.as_slice());
    }
    keccak256(encoded)
}

pub fn hash_inbox_entries_v4(values: &[InboxEntryWitnessV4]) -> B256 {
    let deposit_type = keccak256(
        b"DepositInboxV4(uint64 index,address depositor,uint8 beneficiarySlot,uint8 assetId,uint256 amount,uint8 status)",
    );
    let join_type = keccak256(
        b"JoinRequestInboxV4(uint64 index,address candidate,bytes32 depositsHash,uint8 status)",
    );
    let mut encoded = Vec::with_capacity((2 + values.len()) * 32);
    encoded.extend_from_slice(keccak256(b"InboxSegmentV4[]").as_slice());
    encoded.extend_from_slice(&u256_word(values.len() as u64));
    for value in values {
        let hash = match value.kind {
            1 if value.deposits.len() == 1 => {
                let deposit = &value.deposits[0];
                hash_words([
                    b256_word(deposit_type),
                    u256_word(value.index),
                    address_word(value.account),
                    u256_word(u64::from(value.beneficiary_slot)),
                    u256_word(u64::from(deposit.asset_id)),
                    uint256_word(deposit.amount),
                    u256_word(u64::from(value.status)),
                ])
            }
            2 => {
                let deposits = value
                    .deposits
                    .iter()
                    .map(|entry| (entry.asset_id, entry.amount))
                    .collect::<Vec<_>>();
                let deposits_hash = hash_amount_projection_v4(b"AssetAmountV4[]", &deposits);
                hash_words([
                    b256_word(join_type),
                    u256_word(value.index),
                    address_word(value.account),
                    b256_word(deposits_hash),
                    u256_word(u64::from(value.status)),
                ])
            }
            _ => B256::ZERO,
        };
        encoded.extend_from_slice(hash.as_slice());
    }
    keccak256(encoded)
}

pub fn hash_claim_leaf_v4(
    deployment_id: B256,
    room_id: u64,
    allocation: &ExitAllocationV4,
) -> B256 {
    hash_words([
        b256_word(keccak256(b"ClaimLeafV4(bytes32 deploymentDomain,uint256 roomId,uint8 slot,uint8 assetId,address recipient,uint256 amount)")),
        b256_word(deployment_id),
        u256_word(room_id),
        u256_word(u64::from(allocation.slot)),
        u256_word(u64::from(allocation.asset_id)),
        address_word(allocation.recipient),
        uint256_word(allocation.amount),
    ])
}

pub fn claim_merkle_root_v4(
    deployment_id: B256,
    room_id: u64,
    allocations: &[ExitAllocationV4],
) -> B256 {
    if allocations.is_empty() {
        return keccak256(b"zkdeal/merkle-empty/v4");
    }
    let mut leaves = allocations
        .iter()
        .map(|allocation| hash_claim_leaf_v4(deployment_id, room_id, allocation))
        .collect::<Vec<_>>();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for pair in leaves.chunks(2) {
            let a = pair[0];
            let b = *pair.get(1).unwrap_or(&a);
            let (left, right) = if a <= b { (a, b) } else { (b, a) };
            let mut encoded = [0u8; 64];
            encoded[..32].copy_from_slice(left.as_slice());
            encoded[32..].copy_from_slice(right.as_slice());
            next.push(keccak256(encoded));
        }
        leaves = next;
    }
    leaves[0]
}

/// Solidity `hashBatchJournal` / TypeScript `hashBatchJournalV4`.
pub fn hash_batch_journal_v4(journal: &BatchJournalV4) -> B256 {
    let type_hash = keccak256(b"BatchJournalV4(uint256 protocolVersion,bytes32 deploymentDomain,uint256 roomId,bytes32 presetHash,bytes32 manifestHash,bytes32 proofProgramId,uint64 batchIndex,uint64 startL2Block,uint64 endL2Block,uint64 previousBlockTimestamp,uint64 finalBlockTimestamp,bytes32 preStateRoot,bytes32 postStateRoot,bytes32 blockRootsHash,bytes32 preRosterRoot,bytes32 postRosterRoot,uint8 preActiveMask,uint8 postActiveMask,uint8 usedMask,uint64 inboxCursorBefore,uint64 inboxCursorAfter,bytes32 inboxInputsHash,bytes32 batchDataHash,bytes32 assetTotalsHash,bytes32 exitTotalsHash,bytes32 feeTotalsHash,bytes32 membershipDeltasHash,bytes32 previousExitRoot,bytes32 exitRoot,bool close,uint64 l1InclusionDeadline)");
    let mut encoded = Vec::with_capacity(32 * 32);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(&u256_word(u64::from(journal.v)));
    encoded.extend_from_slice(journal.deployment_id.as_slice());
    encoded.extend_from_slice(&u256_word(journal.room_id));
    encoded.extend_from_slice(journal.preset_hash.as_slice());
    encoded.extend_from_slice(journal.manifest_hash.as_slice());
    encoded.extend_from_slice(journal.proof_program_id.as_slice());
    encoded.extend_from_slice(&u256_word(journal.batch_index));
    encoded.extend_from_slice(&u256_word(journal.l2_start_height));
    encoded.extend_from_slice(&u256_word(journal.l2_end_height));
    encoded.extend_from_slice(&u256_word(journal.previous_block_timestamp));
    encoded.extend_from_slice(&u256_word(journal.final_block_timestamp));
    encoded.extend_from_slice(journal.prev_state_root.as_slice());
    encoded.extend_from_slice(journal.post_state_root.as_slice());
    encoded.extend_from_slice(journal.block_roots_hash.as_slice());
    encoded.extend_from_slice(journal.pre_roster_root.as_slice());
    encoded.extend_from_slice(journal.post_roster_root.as_slice());
    encoded.extend_from_slice(&u256_word(u64::from(journal.active_mask)));
    encoded.extend_from_slice(&u256_word(u64::from(journal.post_active_mask)));
    encoded.extend_from_slice(&u256_word(u64::from(journal.used_mask)));
    encoded.extend_from_slice(&u256_word(journal.inbox_start));
    encoded.extend_from_slice(&u256_word(journal.inbox_end));
    encoded.extend_from_slice(journal.inbox_inputs_hash.as_slice());
    encoded.extend_from_slice(journal.block_data_hash.as_slice());
    encoded.extend_from_slice(journal.asset_totals_hash.as_slice());
    encoded.extend_from_slice(journal.exit_totals_hash.as_slice());
    encoded.extend_from_slice(journal.fee_totals_hash.as_slice());
    encoded.extend_from_slice(journal.membership_deltas_hash.as_slice());
    encoded.extend_from_slice(journal.previous_exit_root.as_slice());
    encoded.extend_from_slice(journal.exit_root.as_slice());
    encoded.extend_from_slice(&u256_word(u64::from(journal.close)));
    encoded.extend_from_slice(&u256_word(journal.l1_inclusion_deadline));
    keccak256(encoded)
}

/// Solidity `RoomCodecV4.hashGenesisJournal` / TypeScript
/// `hashGenesisJournalV4`.
pub fn hash_genesis_journal_v4(journal: &GenesisJournalV4) -> B256 {
    let type_hash = keccak256(b"GenesisJournalV4(uint256 protocolVersion,bytes32 deploymentDomain,uint256 roomId,bytes32 configHash,bytes32 presetHash,bytes32 manifestHash,bytes32 proofProgramId,uint64 l1BlockNumber,bytes32 l1BlockHash,bytes32 l1StateRoot,bytes32 genesisStateRoot,bytes32 genesisRosterRoot,bytes32 genesisExitRoot,uint8 activeMask,uint8 usedMask,uint64 inboxCursor,bytes32 assetTotalsHash,bytes32 exitTotalsHash,bytes32 feeTotalsHash,uint64 l1InclusionDeadline)");
    let mut encoded = Vec::with_capacity(21 * 32);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(&u256_word(u64::from(journal.v)));
    encoded.extend_from_slice(journal.deployment_id.as_slice());
    encoded.extend_from_slice(&u256_word(journal.room_id));
    encoded.extend_from_slice(journal.config_hash.as_slice());
    encoded.extend_from_slice(journal.preset_hash.as_slice());
    encoded.extend_from_slice(journal.manifest_hash.as_slice());
    encoded.extend_from_slice(journal.proof_program_id.as_slice());
    encoded.extend_from_slice(&u256_word(journal.l1_block_number));
    encoded.extend_from_slice(journal.l1_block_hash.as_slice());
    encoded.extend_from_slice(journal.l1_state_root.as_slice());
    encoded.extend_from_slice(journal.genesis_state_root.as_slice());
    encoded.extend_from_slice(journal.genesis_roster_root.as_slice());
    encoded.extend_from_slice(journal.genesis_exit_root.as_slice());
    encoded.extend_from_slice(&u256_word(u64::from(journal.active_mask)));
    encoded.extend_from_slice(&u256_word(u64::from(journal.used_mask)));
    encoded.extend_from_slice(&u256_word(journal.inbox_cursor));
    encoded.extend_from_slice(journal.asset_totals_hash.as_slice());
    encoded.extend_from_slice(journal.exit_totals_hash.as_slice());
    encoded.extend_from_slice(journal.fee_totals_hash.as_slice());
    encoded.extend_from_slice(&u256_word(journal.l1_inclusion_deadline));
    keccak256(encoded)
}
