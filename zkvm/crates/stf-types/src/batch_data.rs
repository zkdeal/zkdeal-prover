//! Canonical batch calldata encodings. These are the exact public bytes an
//! L1 verifier and an independent replayer both hash, so the encoding is
//! written against fixed-width integers rather than any serde implementation.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, B256};

use crate::v4::types::BatchBlockV4;
use crate::v5::types::BatchBlockV5;

/// Hash the exact ordered block bytes and environments committed by a v4
/// proof. Fixed-width lengths and big-endian integers make the encoding
/// independent of serde/Borsh implementations used by the host.
fn canonical_batch_bytes_versioned(
    version: u64,
    blocks: &[BatchBlockV4],
    pre_state_root: B256,
) -> Vec<u8> {
    fn list(items: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
        let payload = items.into_iter().flatten().collect::<Vec<_>>();
        let mut out =
            Vec::with_capacity(alloy_rlp::length_of_length(payload.len()) + payload.len());
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(&payload);
        out
    }

    let mut parent = pre_state_root;
    let encoded_blocks = blocks
        .iter()
        .map(|block| {
            let txs = list(
                block
                    .raw_txs
                    .iter()
                    .map(|tx| alloy_rlp::encode(tx.as_ref())),
            );
            let encoded = list([
                alloy_rlp::encode(block.block_number),
                alloy_rlp::encode(block.env.timestamp),
                alloy_rlp::encode(parent),
                alloy_rlp::encode(block.expected_post_state_root),
                txs,
            ]);
            parent = block.expected_post_state_root;
            encoded
        })
        .collect::<Vec<_>>();
    list([alloy_rlp::encode(version), list(encoded_blocks)])
}

pub fn canonical_batch_bytes_v4(blocks: &[BatchBlockV4], pre_state_root: B256) -> Vec<u8> {
    canonical_batch_bytes_versioned(4, blocks, pre_state_root)
}

/// Solidity/TypeScript-compatible `keccak256(encodeCanonicalBatchV4(...))`.
pub fn batch_block_data_hash_v4(blocks: &[BatchBlockV4], pre_state_root: B256) -> B256 {
    keccak256(canonical_batch_bytes_v4(blocks, pre_state_root))
}

/// Canonical transaction, environment and intermediate-root commitment used
/// by v5 approvals. This is intentionally a new domain even though the block
/// wire shape is shared with the mature Osaka executor.
pub fn canonical_batch_data_v5(blocks: &[BatchBlockV5], pre_state_root: B256) -> Vec<u8> {
    fn list(items: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
        let payload = items.into_iter().flatten().collect::<Vec<_>>();
        let mut out =
            Vec::with_capacity(alloy_rlp::length_of_length(payload.len()) + payload.len());
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(&payload);
        out
    }

    let mut parent = pre_state_root;
    let encoded_blocks = blocks
        .iter()
        .map(|block| {
            let txs = list(
                block
                    .raw_txs
                    .iter()
                    .map(|tx| alloy_rlp::encode(tx.as_ref())),
            );
            let history =
                list(block.block_hashes.iter().map(|item| {
                    list([alloy_rlp::encode(item.number), alloy_rlp::encode(item.hash)])
                }));
            let environment = list([
                alloy_rlp::encode(block.env.number),
                alloy_rlp::encode(block.env.timestamp),
                alloy_rlp::encode(block.env.gas_limit),
                alloy_rlp::encode(block.env.coinbase),
                alloy_rlp::encode(block.env.base_fee),
                alloy_rlp::encode(block.env.prev_randao),
                alloy_rlp::encode(block.env.difficulty),
                alloy_rlp::encode(block.env.excess_blob_gas),
                alloy_rlp::encode(block.env.chain_id),
            ]);
            let encoded = list([
                alloy_rlp::encode(block.block_number),
                environment,
                alloy_rlp::encode(parent),
                alloy_rlp::encode(block.expected_post_state_root),
                history,
                txs,
            ]);
            parent = block.expected_post_state_root;
            encoded
        })
        .collect::<Vec<_>>();
    list([alloy_rlp::encode(5u64), list(encoded_blocks)])
}

pub fn batch_block_data_hash_v5(blocks: &[BatchBlockV5], pre_state_root: B256) -> B256 {
    keccak256(canonical_batch_data_v5(blocks, pre_state_root))
}
