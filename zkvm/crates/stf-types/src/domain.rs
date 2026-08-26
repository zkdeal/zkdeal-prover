//! Deployment-scoped chain-id and application-domain derivations.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, B256};

/// Domain-separated, deployment-scoped L2 chain id used by v4 execution.
///
/// The first 50 digest bits are used and bit 50 is forced to one. This keeps
/// both the chain id and legacy EIP-155 `v = 2*chainId+35/36` exactly
/// representable by the JavaScript EVM while reserving a private 51-bit
/// namespace, without modulo bias. This is only a compatibility prefilter,
/// not a replay-security domain; the full application domain is that boundary.
pub fn room_chain_id_v4(deployment_id: B256, room_id: u64) -> u64 {
    let type_hash = keccak256(b"RoomChainIdV4(bytes32 deploymentDomain,uint256 roomId)");
    let mut encoded = [0u8; 96];
    encoded[..32].copy_from_slice(type_hash.as_slice());
    encoded[32..64].copy_from_slice(deployment_id.as_slice());
    encoded[88..96].copy_from_slice(&room_id.to_be_bytes());
    let digest = keccak256(encoded);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest.as_slice()[..8]);
    (u64::from_be_bytes(prefix) >> 14) | (1u64 << 50)
}

pub fn room_chain_id_v5(deployment_id: B256, room_id: u64) -> u64 {
    let type_hash = keccak256(b"RoomChainIdV5(bytes32 deploymentDomain,uint256 roomId)");
    let mut encoded = [0u8; 96];
    encoded[..32].copy_from_slice(type_hash.as_slice());
    encoded[32..64].copy_from_slice(deployment_id.as_slice());
    encoded[88..96].copy_from_slice(&room_id.to_be_bytes());
    let digest = keccak256(encoded);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest.as_slice()[..8]);
    (u64::from_be_bytes(prefix) >> 14) | (1u64 << 50)
}

/// Solidity-compatible `keccak256(abi.encode(tag, deploymentDomain, roomId))`.
/// Certified application presets use this full 256-bit value in room-local
/// storage so even a hypothetical uint64 chain-id collision cannot replay an
/// application proof across rooms or deployments.
pub fn application_domain_v4(tag: &[u8], deployment_id: B256, room_id: u64) -> B256 {
    let padded = tag.len().div_ceil(32) * 32;
    let mut encoded = Vec::with_capacity(128 + padded);
    let mut word = [0u8; 32];
    word[31] = 96; // dynamic string tail starts after the three head words
    encoded.extend_from_slice(&word);
    encoded.extend_from_slice(deployment_id.as_slice());
    word = [0u8; 32];
    word[24..].copy_from_slice(&room_id.to_be_bytes());
    encoded.extend_from_slice(&word);
    word = [0u8; 32];
    let length = u64::try_from(tag.len()).expect("application-domain tags fit in u64");
    word[24..].copy_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(&word);
    encoded.extend_from_slice(tag);
    encoded.resize(128 + padded, 0);
    keccak256(encoded)
}

pub fn card_application_domain_v4(deployment_id: B256, room_id: u64) -> B256 {
    application_domain_v4(b"zkdeal/card-application/v4", deployment_id, room_id)
}
