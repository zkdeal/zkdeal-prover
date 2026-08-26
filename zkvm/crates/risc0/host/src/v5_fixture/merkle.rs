//! The fixture's participant Merkle tree: leaves, levels, membership proofs
//! and in-place updates.

use alloy_primitives::{keccak256, B256};

fn participant_leaf(index: u64, registered_participants: u64) -> B256 {
    if index >= registered_participants {
        return B256::ZERO;
    }
    let mut input = b"zkdeal/v5/registered-participant".to_vec();
    input.extend_from_slice(&index.to_be_bytes());
    keccak256(input)
}

pub(super) fn participant_tree(capacity: u64, registered_participants: u64) -> Vec<Vec<B256>> {
    let mut levels = vec![(0..capacity)
        .map(|index| participant_leaf(index, registered_participants))
        .collect::<Vec<_>>()];
    while levels.last().expect("leaf level exists").len() > 1 {
        let current = levels.last().expect("current level exists");
        let next = current
            .chunks_exact(2)
            .map(|pair| {
                let mut encoded = [0u8; 64];
                encoded[..32].copy_from_slice(pair[0].as_slice());
                encoded[32..].copy_from_slice(pair[1].as_slice());
                keccak256(encoded)
            })
            .collect::<Vec<_>>();
        levels.push(next);
    }
    levels
}

pub(super) fn participant_proof(levels: &[Vec<B256>], mut index: usize) -> Vec<B256> {
    let mut proof = Vec::with_capacity(levels.len().saturating_sub(1));
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        proof.push(level[index ^ 1]);
        index >>= 1;
    }
    proof
}

pub(super) fn update_participant_tree(levels: &mut [Vec<B256>], mut index: usize, new_leaf: B256) {
    levels[0][index] = new_leaf;
    for level in 0..levels.len() - 1 {
        let parent = index >> 1;
        let left = levels[level][parent * 2];
        let right = levels[level][parent * 2 + 1];
        let mut encoded = [0u8; 64];
        encoded[..32].copy_from_slice(left.as_slice());
        encoded[32..].copy_from_slice(right.as_slice());
        levels[level + 1][parent] = keccak256(encoded);
        index = parent;
    }
}
