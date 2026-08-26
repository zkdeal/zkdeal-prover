//! zkdeal STF guest: exactly four magic-prefixed statements, selected by the
//! 8-byte witness prefix and nothing else.
//!
//! - `ZKDV6BAT`: execute one room batch (1-4 contiguous real blocks) with the
//!   REAL stf-core (revm + alloy-trie, ethereumjs parity proven by
//!   zkvm/crates/stf-core tests); commits the 32-byte Solidity
//!   `hashBatchJournalV5` statement.
//! - `ZKDV5CLD`: validate one cold-template genesis package; the statement
//!   binds the exact framed witness bytes by construction.
//! - `ZKDBEQV1`: EIP-4844 blob-equivalence identity statement.
//! - `ZKDAGGV1`: recursive aggregate over member room receipts, each verified
//!   as a RISC Zero assumption.
//!
//! Input: one magic-prefixed bincode witness through RISC Zero's bulk input
//! frame; the retired v4 borsh encodings are not accepted. Output: exactly one
//! 32-byte Solidity-compatible statement hash. The image id of this guest
//! (docker-deterministic build) is the room `programDigest` for the risc0
//! backend.
//!
//! Any malformed input or STF failure panics: a receipt simply cannot be
//! produced for an invalid witness - there is no error channel to attest.

use bincode::Options;
use risc0_zkvm::{guest::env, sha::Digest};
use stf_core::{execute_batch_v5, execute_cold_template_v5};
use stf_types::{
    hash_batch_journal_v5, validate_aggregate_v1, validate_blob_equivalence_v1, AggregateInputV1,
    BatchInputV5, BlobEquivalenceInputV1, ColdTemplateInputV5,
};

mod native_keccak;

const ROOM_BATCH_MAGIC_V6: &[u8; 8] = b"ZKDV6BAT";
const COLD_TEMPLATE_MAGIC_V5: &[u8; 8] = b"ZKDV5CLD";
const BLOB_EQUIVALENCE_MAGIC_V1: &[u8; 8] = b"ZKDBEQV1";
const RECURSIVE_AGGREGATE_MAGIC_V1: &[u8; 8] = b"ZKDAGGV1";

/// The byte format the host serialises with (`bincode::serialize`), minus its
/// trailing-byte tolerance: the host's re-serialise-and-compare canonicality
/// check refuses padding, and the proved decode must not be the one place
/// where it is accepted.
fn strict_bincode() -> impl Options {
    bincode::options()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

fn main() {
    let input_bytes = env::read_frame();
    if let Some(encoded) = input_bytes.strip_prefix(ROOM_BATCH_MAGIC_V6) {
        let mut input: BatchInputV5 = strict_bincode()
            .deserialize(encoded)
            .expect("v6 room batch witness is malformed");
        input.encoded_witness_bytes =
            u32::try_from(input_bytes.len()).expect("v6 room witness length exceeds u32");
        let journal = execute_batch_v5(&input).expect("v6 room batch STF execution failed");
        env::commit_slice(hash_batch_journal_v5(&journal).as_slice());
    } else if let Some(encoded) = input_bytes.strip_prefix(COLD_TEMPLATE_MAGIC_V5) {
        // The genesis package identity is the exact framed input this guest
        // decodes, magic prefix included, so the registered statement binds
        // the canonical cold witness bytes by construction.
        let genesis_data_hash = alloy_primitives::keccak256(&input_bytes);
        let input: ColdTemplateInputV5 = strict_bincode()
            .deserialize(encoded)
            .expect("v5 cold-template witness is malformed");
        let statement = execute_cold_template_v5(&input, genesis_data_hash)
            .expect("v5 cold-template validation failed");
        env::commit_slice(statement.as_slice());
    } else if let Some(encoded) = input_bytes.strip_prefix(BLOB_EQUIVALENCE_MAGIC_V1) {
        let input: BlobEquivalenceInputV1 = strict_bincode()
            .deserialize(encoded)
            .expect("blob-equivalence witness is malformed");
        let statement = validate_blob_equivalence_v1(&input)
            .expect("blob-equivalence identity validation failed");
        env::commit_slice(statement.as_slice());
    } else if let Some(encoded) = input_bytes.strip_prefix(RECURSIVE_AGGREGATE_MAGIC_V1) {
        let input: AggregateInputV1 = strict_bincode()
            .deserialize(encoded)
            .expect("recursive aggregate witness is malformed");
        let statement =
            validate_aggregate_v1(&input).expect("recursive aggregate statement is invalid");
        for member in &input.members {
            let room_image = Digest::try_from(member.room_program_id.as_slice())
                .expect("room program id must be a RISC Zero digest");
            env::verify(room_image, member.journal_hash.as_slice())
                .expect("room receipt assumption verification is infallible");
            if member.equivalence_program_id != alloy_primitives::B256::ZERO {
                let equivalence_image =
                    Digest::try_from(member.equivalence_program_id.as_slice())
                        .expect("equivalence program id must be a RISC Zero digest");
                env::verify(equivalence_image, member.equivalence_statement.as_slice())
                    .expect("equivalence receipt assumption verification is infallible");
            }
        }
        env::commit_slice(statement.as_slice());
    } else {
        panic!("unsupported witness magic");
    }
}
