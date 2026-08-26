//! Golden vectors for the v5 canonical batch-data encoder.
//!
//! `canonical_batch_data_v5` is the exact public byte string an L1 verifier and
//! an independent replayer both hash, so its encoding is a cross-language
//! contract. These vectors pin the encoder output for the empty, one-block and
//! two-block chained cases; the room-fallback decoder (TypeScript, W1-E) consumes
//! the checked-in copy and asserts byte-for-byte agreement, and both sides pin
//! the same `DIGEST` over the encoded bytes.
//!
//! Regenerate the checked-in JSON with:
//!   cargo test -p stf-types --test canonical_batch_vectors \
//!       emit_canonical_batch_vectors -- --ignored

use std::path::PathBuf;

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stf_types::{canonical_batch_data_v5, BatchBlockV5, BlockEnvV1, HistoricalBlockHash};

/// Digest over the ordered `(len, encoded)` framing of every case's canonical
/// bytes. Reproduce in any language as:
///   sha256( for each case in order: u32_be(encoded.len) ++ encoded )
const DIGEST: &str = "0x6008493a081c685c51b3a871c10e7548b86246a41840930f79bf858d41208864";

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/canonical-batch-v5.json")
}

#[derive(Serialize)]
struct CaseV5 {
    name: String,
    pre_state_root: B256,
    blocks: Vec<BatchBlockV5>,
    encoded: Bytes,
}

#[derive(Serialize)]
struct VectorsV5 {
    schema_version: u32,
    source: String,
    note: String,
    digest: String,
    cases: Vec<CaseV5>,
}

fn env(number: u64) -> BlockEnvV1 {
    BlockEnvV1 {
        number,
        timestamp: 1_900_000_000 + number,
        gas_limit: 30_000_000,
        coinbase: Address::ZERO,
        base_fee: U256::ZERO,
        prev_randao: B256::ZERO,
        difficulty: U256::ZERO,
        excess_blob_gas: 0,
        chain_id: 77_000_007,
    }
}

fn cases() -> Vec<(String, B256, Vec<BatchBlockV5>)> {
    let pre = B256::repeat_byte(0x11);
    let one = vec![BatchBlockV5 {
        block_number: 1,
        raw_txs: vec![Bytes::from_static(&[0x02, 0xaa, 0xbb, 0xcc])],
        env: env(1),
        block_hashes: vec![],
        expected_post_state_root: B256::repeat_byte(0x22),
    }];
    let two = vec![
        BatchBlockV5 {
            block_number: 1,
            raw_txs: vec![Bytes::from_static(&[0x02, 0xaa, 0xbb, 0xcc])],
            env: env(1),
            block_hashes: vec![],
            expected_post_state_root: B256::repeat_byte(0x22),
        },
        BatchBlockV5 {
            block_number: 2,
            raw_txs: vec![
                Bytes::from_static(&[0x01, 0x11]),
                Bytes::from_static(&[0x02, 0x33, 0x44]),
            ],
            env: env(2),
            block_hashes: vec![HistoricalBlockHash {
                number: 1,
                hash: B256::repeat_byte(0x22),
            }],
            expected_post_state_root: B256::repeat_byte(0x33),
        },
    ];
    vec![
        ("empty".to_string(), pre, Vec::new()),
        ("one_block".to_string(), pre, one),
        ("two_block_chained".to_string(), pre, two),
    ]
}

fn build() -> VectorsV5 {
    let mut hasher = Sha256::new();
    let mut out = Vec::new();
    for (name, pre, blocks) in cases() {
        let encoded = canonical_batch_data_v5(&blocks, pre);
        hasher.update((encoded.len() as u32).to_be_bytes());
        hasher.update(&encoded);
        out.push(CaseV5 {
            name,
            pre_state_root: pre,
            blocks,
            encoded: Bytes::from(encoded),
        });
    }
    let digest: [u8; 32] = hasher.finalize().into();
    VectorsV5 {
        schema_version: 1,
        source: "stf-types canonical_batch_data_v5 (canonical_batch_vectors::emit)".to_string(),
        note: "digest = sha256( for each case in order: u32_be(encoded.len) ++ encoded )"
            .to_string(),
        digest: B256::from(digest).to_string(),
        cases: out,
    }
}

#[test]
#[ignore]
fn emit_canonical_batch_vectors() {
    let vectors = build();
    let json = serde_json::to_string_pretty(&vectors).expect("vectors serialize");
    let path = vectors_path();
    std::fs::create_dir_all(path.parent().expect("vectors dir has a parent"))
        .expect("create vectors dir");
    std::fs::write(&path, format!("{json}\n")).expect("write canonical-batch vectors");
}

#[test]
fn canonical_batch_vectors_match_the_checked_in_copy() {
    let vectors = build();
    assert_eq!(vectors.digest, DIGEST, "canonical-batch digest drifted");
    let json = serde_json::to_string_pretty(&vectors).expect("vectors serialize");
    let on_disk = std::fs::read_to_string(vectors_path()).expect(
        "run `cargo test -p stf-types --test canonical_batch_vectors \
         emit_canonical_batch_vectors -- --ignored` to generate the checked-in copy",
    );
    assert_eq!(
        on_disk,
        format!("{json}\n"),
        "checked-in canonical-batch vectors differ from the encoder output"
    );
}
