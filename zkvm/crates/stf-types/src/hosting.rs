//! Data-availability equivalence and recursive-settlement statements.
//!
//! The equivalence witness uses the EIP-4844 evaluation-form identity test:
//! canonical public bytes are packed into 31-byte field elements, evaluated
//! at a transcript-derived point, and compared with the value opened by the
//! transaction blob. L1 verifies that opening against the transaction's
//! versioned blob hash. The recursive aggregate then verifies the room and
//! (when present) equivalence receipts as RISC Zero assumptions and commits
//! the exact statement consumed by `RoomManagerHostingFacet`.

use alloc::{vec, vec::Vec};
use alloy_primitives::{keccak256, Bytes, B256};
use bls12_381::Scalar;
use ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::abi::{abi_u64_word_v5, keccak_words_v5};

pub const MAX_BLOBS_PER_BATCH_V1: usize = 6;
pub const MAX_AGGREGATE_ROOMS_V1: usize = 8;
pub const FIELD_ELEMENTS_PER_BLOB_V1: usize = 4096;
pub const CANONICAL_BYTES_PER_FIELD_ELEMENT_V1: usize = 31;
pub const CANONICAL_BYTES_PER_BLOB_V1: usize =
    FIELD_ELEMENTS_PER_BLOB_V1 * CANONICAL_BYTES_PER_FIELD_ELEMENT_V1;

const VERSIONED_HASH_VERSION_KZG: u8 = 1;
const DATA_AVAILABILITY_STATEMENT_LABEL: &[u8] =
    b"zkdeal.data-availability.eip4844.v1";
const AGGREGATE_STATEMENT_LABEL: &[u8] = b"zkdeal.recursive-aggregate.v1";
const EQUIVALENCE_CHALLENGE_LABEL: &[u8] =
    b"zkdeal.blob-equivalence.challenge.v1";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobEquivalenceInputV1 {
    pub deployment_domain: B256,
    pub room_id: u64,
    /// Exact `keccak256(abi.encode(RoomTypes.BatchJournal))`.
    pub journal_hash: B256,
    /// Canonical length-prefixed public batch bytes from the room journal.
    pub canonical_data: Bytes,
    /// Transaction-wide index of this room's first blob. Single-room proofs
    /// use zero; aggregate receipts bind each room's contiguous range.
    #[serde(default)]
    pub blob_start_index: u8,
    #[serde(default)]
    pub blob_versioned_hashes: Vec<B256>,
    /// Compressed BLS12-381 G1 commitments, exactly 48 bytes each.
    #[serde(default)]
    pub commitments: Vec<Bytes>,
    #[serde(default)]
    pub evaluation_points: Vec<B256>,
    #[serde(default)]
    pub evaluations: Vec<B256>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateMemberStatementV1 {
    pub room_id: u64,
    pub room_program_id: B256,
    pub journal_hash: B256,
    /// Zero for calldata members; otherwise the room-pinned equivalence image.
    pub equivalence_program_id: B256,
    /// Zero for calldata members; otherwise the exact DA statement hash.
    pub equivalence_statement: B256,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateInputV1 {
    pub deployment_domain: B256,
    pub members: Vec<AggregateMemberStatementV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostingStatementError {
    EmptyCanonicalData,
    BadBlobCount,
    NonCanonicalBlobCount,
    BadBlobRange,
    VectorLengthMismatch,
    BadCommitmentLength,
    BadVersionedHash,
    BadChallenge,
    NonCanonicalEvaluation,
    EvaluationMismatch,
    BadAggregateCount,
    ZeroRoom,
    DuplicateRoom,
    ZeroRoomProgram,
    IncompleteEquivalence,
}

impl core::fmt::Display for HostingStatementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Exact `keccak256(abi.encode(bytes32[]))` used by Solidity.
fn abi_b256_array_hash(values: &[B256]) -> B256 {
    let mut words = Vec::with_capacity(values.len() + 2);
    words.push(abi_u64_word_v5(32));
    words.push(abi_u64_word_v5(values.len() as u64));
    words.extend(values.iter().map(|value| value.0));
    keccak_words_v5(words)
}

/// Exact `keccak256(abi.encode(bytes[]))` used by Solidity. Element offsets
/// are relative to the dynamic array body immediately after its length word.
fn abi_bytes_array_hash(values: &[Bytes]) -> B256 {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&abi_u64_word_v5(32));
    encoded.extend_from_slice(&abi_u64_word_v5(values.len() as u64));
    let mut offset = values.len() * 32;
    for value in values {
        encoded.extend_from_slice(&abi_u64_word_v5(offset as u64));
        offset += 32 + value.len().div_ceil(32) * 32;
    }
    for value in values {
        encoded.extend_from_slice(&abi_u64_word_v5(value.len() as u64));
        encoded.extend_from_slice(value.as_ref());
        encoded.resize(encoded.len().div_ceil(32) * 32, 0);
    }
    keccak256(encoded)
}

pub fn data_availability_statement_v1(input: &BlobEquivalenceInputV1) -> B256 {
    keccak_words_v5([
        keccak256(DATA_AVAILABILITY_STATEMENT_LABEL).0,
        input.deployment_domain.0,
        abi_u64_word_v5(input.room_id),
        input.journal_hash.0,
        keccak256(input.canonical_data.as_ref()).0,
        abi_u64_word_v5(input.canonical_data.len() as u64),
        abi_u64_word_v5(input.blob_start_index as u64),
        abi_b256_array_hash(&input.blob_versioned_hashes).0,
        abi_bytes_array_hash(&input.commitments).0,
        abi_b256_array_hash(&input.evaluation_points).0,
        abi_b256_array_hash(&input.evaluations).0,
    ])
}

pub fn aggregate_member_hash_v1(member: &AggregateMemberStatementV1) -> B256 {
    keccak_words_v5([
        abi_u64_word_v5(member.room_id),
        member.room_program_id.0,
        member.journal_hash.0,
        member.equivalence_program_id.0,
        member.equivalence_statement.0,
    ])
}

pub fn aggregate_statement_v1(input: &AggregateInputV1) -> B256 {
    let members = input
        .members
        .iter()
        .map(aggregate_member_hash_v1)
        .collect::<Vec<_>>();
    keccak_words_v5([
        keccak256(AGGREGATE_STATEMENT_LABEL).0,
        input.deployment_domain.0,
        abi_b256_array_hash(&members).0,
    ])
}

fn scalar_from_be(value: B256) -> Option<Scalar> {
    let mut little = value.0;
    little.reverse();
    Option::<Scalar>::from(Scalar::from_bytes(&little))
}

fn scalar_to_be(value: Scalar) -> B256 {
    let mut bytes = value.to_bytes();
    bytes.reverse();
    B256::from(bytes)
}

/// Expected EIP-4844 opening value for the canonical bytes of one blob. The
/// returned big-endian scalar is what the transaction builder opens with KZG
/// and what L1 supplies to the point-evaluation precompile.
pub fn blob_equivalence_evaluation_v1(
    input: &BlobEquivalenceInputV1,
    blob_index: usize,
) -> Result<B256, HostingStatementError> {
    let z = input
        .evaluation_points
        .get(blob_index)
        .copied()
        .and_then(scalar_from_be)
        .ok_or(HostingStatementError::BadChallenge)?;
    let values = blob_field_values(input.canonical_data.as_ref(), blob_index);
    Ok(scalar_to_be(evaluate_blob(&values, z)))
}

pub fn blob_versioned_hash_v1(commitment: &[u8]) -> B256 {
    let mut digest: [u8; 32] = Sha256::digest(commitment).into();
    digest[0] = VERSIONED_HASH_VERSION_KZG;
    B256::from(digest)
}

/// Canonical EIP-4844 blob bytes for one chunk: 4096 big-endian field
/// elements, each carrying at most 31 payload bytes behind a zero prefix.
pub fn canonical_blob_bytes_v1(canonical_data: &[u8], blob_index: usize) -> Vec<u8> {
    let values = blob_field_values(canonical_data, blob_index);
    let mut blob = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB_V1 * 32);
    for value in values {
        blob.extend_from_slice(scalar_to_be(value).as_slice());
    }
    blob
}

/// Fiat-Shamir challenge for one blob opening. Rejection sampling produces a
/// canonical BLS scalar without modulo bias. The point is derived from every
/// public identity needed to prevent a prover-selected collision.
pub fn blob_equivalence_challenge_v1(
    input: &BlobEquivalenceInputV1,
    blob_index: usize,
) -> Option<B256> {
    let commitment = input.commitments.get(blob_index)?;
    let versioned_hash = input.blob_versioned_hashes.get(blob_index)?;
    for counter in 0u32..=u32::MAX {
        let mut hasher = Sha256::new();
        hasher.update(EQUIVALENCE_CHALLENGE_LABEL);
        hasher.update(input.deployment_domain.as_slice());
        hasher.update(input.room_id.to_be_bytes());
        hasher.update(input.journal_hash.as_slice());
        hasher.update(keccak256(input.canonical_data.as_ref()).as_slice());
        hasher.update((input.canonical_data.len() as u64).to_be_bytes());
        hasher.update((input.blob_start_index as u64).to_be_bytes());
        hasher.update((blob_index as u64).to_be_bytes());
        hasher.update(versioned_hash.as_slice());
        hasher.update(commitment.as_ref());
        hasher.update(counter.to_be_bytes());
        let candidate = B256::from(<[u8; 32]>::from(hasher.finalize()));
        if scalar_from_be(candidate).is_some() {
            return Some(candidate);
        }
    }
    None
}

fn blob_field_values(canonical_data: &[u8], blob_index: usize) -> Vec<Scalar> {
    let blob_start = blob_index * CANONICAL_BYTES_PER_BLOB_V1;
    let mut values = vec![Scalar::ZERO; FIELD_ELEMENTS_PER_BLOB_V1];
    for (field_index, value) in values.iter_mut().enumerate() {
        let start = blob_start + field_index * CANONICAL_BYTES_PER_FIELD_ELEMENT_V1;
        if start >= canonical_data.len() {
            break;
        }
        let end = core::cmp::min(
            start + CANONICAL_BYTES_PER_FIELD_ELEMENT_V1,
            canonical_data.len(),
        );
        // One leading zero byte makes every 31-byte payload a canonical BLS
        // scalar while preserving byte order without an auxiliary codec.
        let mut word = [0u8; 32];
        word[32 - (end - start)..].copy_from_slice(&canonical_data[start..end]);
        *value = scalar_from_be(B256::from(word))
            .expect("a 31-byte big-endian payload is below the BLS modulus");
    }
    values
}

/// Evaluate an EIP-4844 evaluation-form blob at `z` using the roots-of-unity
/// barycentric identity from the polynomial-commitments specification.
fn evaluate_blob(values: &[Scalar], z: Scalar) -> Scalar {
    debug_assert_eq!(values.len(), FIELD_ELEMENTS_PER_BLOB_V1);
    let exponent = 1u64 << (Scalar::S - 12);
    let omega = Scalar::ROOT_OF_UNITY.pow_vartime(&[exponent, 0, 0, 0]);
    let mut natural_roots = vec![Scalar::ONE; FIELD_ELEMENTS_PER_BLOB_V1];
    for index in 1..FIELD_ELEMENTS_PER_BLOB_V1 {
        natural_roots[index] = natural_roots[index - 1] * omega;
    }
    let roots = (0..FIELD_ELEMENTS_PER_BLOB_V1)
        .map(|index| {
            let reversed = index.reverse_bits() >> (usize::BITS - 12);
            natural_roots[reversed]
        })
        .collect::<Vec<_>>();
    if let Some(index) = roots.iter().position(|root| *root == z) {
        return values[index];
    }
    // Montgomery batch inversion: one field inversion per blob instead of
    // 4096, plus linear multiplications. This materially reduces guest cycles
    // while preserving the independent c-kzg reference semantics.
    let denominators = roots.iter().map(|root| z - root).collect::<Vec<_>>();
    let mut prefixes = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB_V1);
    let mut product = Scalar::ONE;
    for denominator in &denominators {
        prefixes.push(product);
        product *= denominator;
    }
    let mut product_inverse = Option::<Scalar>::from(product.invert())
        .expect("all non-zero domain denominators have a non-zero product");
    let mut sum = Scalar::ZERO;
    for index in (0..FIELD_ELEMENTS_PER_BLOB_V1).rev() {
        // `roots[index]` is omega^bitreverse(index), matching EIP-4844.
        let denominator_inverse = product_inverse * prefixes[index];
        product_inverse *= denominators[index];
        sum += values[index] * roots[index] * denominator_inverse;
    }
    let n_inverse = Option::<Scalar>::from(
        Scalar::from(FIELD_ELEMENTS_PER_BLOB_V1 as u64).invert(),
    )
    .expect("the non-zero domain size is invertible");
    (z.pow_vartime(&[FIELD_ELEMENTS_PER_BLOB_V1 as u64, 0, 0, 0]) - Scalar::ONE)
        * n_inverse
        * sum
}

/// Validate the complete equivalence witness and return the exact statement
/// L1 verifies. This is run both natively by the host and inside the guest.
pub fn validate_blob_equivalence_v1(
    input: &BlobEquivalenceInputV1,
) -> Result<B256, HostingStatementError> {
    if input.canonical_data.is_empty() {
        return Err(HostingStatementError::EmptyCanonicalData);
    }
    let count = input.blob_versioned_hashes.len();
    if count == 0 || count > MAX_BLOBS_PER_BATCH_V1 {
        return Err(HostingStatementError::BadBlobCount);
    }
    if input.blob_start_index as usize + count > MAX_BLOBS_PER_BATCH_V1 {
        return Err(HostingStatementError::BadBlobRange);
    }
    let canonical_count = input
        .canonical_data
        .len()
        .div_ceil(CANONICAL_BYTES_PER_BLOB_V1);
    if count != canonical_count {
        return Err(HostingStatementError::NonCanonicalBlobCount);
    }
    if input.commitments.len() != count
        || input.evaluation_points.len() != count
        || input.evaluations.len() != count
    {
        return Err(HostingStatementError::VectorLengthMismatch);
    }
    for index in 0..count {
        let commitment = &input.commitments[index];
        if commitment.len() != 48 {
            return Err(HostingStatementError::BadCommitmentLength);
        }
        if blob_versioned_hash_v1(commitment) != input.blob_versioned_hashes[index] {
            return Err(HostingStatementError::BadVersionedHash);
        }
        let expected_challenge = blob_equivalence_challenge_v1(input, index)
            .ok_or(HostingStatementError::BadChallenge)?;
        if input.evaluation_points[index] != expected_challenge {
            return Err(HostingStatementError::BadChallenge);
        }
        scalar_from_be(input.evaluation_points[index])
            .ok_or(HostingStatementError::BadChallenge)?;
        let supplied_y = scalar_from_be(input.evaluations[index])
            .ok_or(HostingStatementError::NonCanonicalEvaluation)?;
        let expected_y = blob_equivalence_evaluation_v1(input, index)?;
        if scalar_to_be(supplied_y) != expected_y {
            return Err(HostingStatementError::EvaluationMismatch);
        }
    }
    Ok(data_availability_statement_v1(input))
}

pub fn validate_aggregate_v1(
    input: &AggregateInputV1,
) -> Result<B256, HostingStatementError> {
    if input.members.is_empty() || input.members.len() > MAX_AGGREGATE_ROOMS_V1 {
        return Err(HostingStatementError::BadAggregateCount);
    }
    for (index, member) in input.members.iter().enumerate() {
        if member.room_id == 0 {
            return Err(HostingStatementError::ZeroRoom);
        }
        if member.room_program_id == B256::ZERO {
            return Err(HostingStatementError::ZeroRoomProgram);
        }
        if input.members[..index]
            .iter()
            .any(|prior| prior.room_id == member.room_id)
        {
            return Err(HostingStatementError::DuplicateRoom);
        }
        if (member.equivalence_program_id == B256::ZERO)
            != (member.equivalence_statement == B256::ZERO)
        {
            return Err(HostingStatementError::IncompleteEquivalence);
        }
    }
    Ok(aggregate_statement_v1(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_vector() -> BlobEquivalenceInputV1 {
        BlobEquivalenceInputV1 {
            deployment_domain: B256::repeat_byte(0x11),
            room_id: 7,
            journal_hash: B256::repeat_byte(0x22),
            canonical_data: Bytes::from_static(b"zkdeal-eip4844-vector"),
            blob_start_index: 2,
            blob_versioned_hashes: vec![B256::repeat_byte(0x33)],
            commitments: vec![Bytes::from(vec![0x44; 48])],
            evaluation_points: vec![B256::repeat_byte(0x55)],
            evaluations: vec![B256::repeat_byte(0x66)],
        }
    }

    #[test]
    fn aggregate_is_bounded_unique_and_ordered() {
        let member = AggregateMemberStatementV1 {
            room_id: 1,
            room_program_id: B256::repeat_byte(0x11),
            journal_hash: B256::repeat_byte(0x22),
            equivalence_program_id: B256::ZERO,
            equivalence_statement: B256::ZERO,
        };
        let input = AggregateInputV1 {
            deployment_domain: B256::repeat_byte(0x33),
            members: vec![member.clone()],
        };
        assert_eq!(validate_aggregate_v1(&input), Ok(aggregate_statement_v1(&input)));
        let mut duplicate = input.clone();
        duplicate.members.push(member);
        assert_eq!(
            validate_aggregate_v1(&duplicate),
            Err(HostingStatementError::DuplicateRoom)
        );

        let mut eight = input.clone();
        eight.members = (1..=8)
            .map(|room_id| AggregateMemberStatementV1 {
                room_id,
                ..input.members[0].clone()
            })
            .collect();
        assert!(validate_aggregate_v1(&eight).is_ok());
        let mut nine = eight.clone();
        nine.members.push(AggregateMemberStatementV1 {
            room_id: 9,
            ..input.members[0].clone()
        });
        assert_eq!(
            validate_aggregate_v1(&nine),
            Err(HostingStatementError::BadAggregateCount)
        );
        let mut reversed = eight.clone();
        reversed.members.reverse();
        assert_ne!(aggregate_statement_v1(&eight), aggregate_statement_v1(&reversed));
    }

    #[test]
    fn all_zero_blob_evaluates_to_zero_and_binds_the_commitment_hash() {
        let commitment = Bytes::from(vec![0x42; 48]);
        let versioned = blob_versioned_hash_v1(commitment.as_ref());
        let mut input = BlobEquivalenceInputV1 {
            deployment_domain: B256::repeat_byte(0x11),
            room_id: 7,
            journal_hash: B256::repeat_byte(0x22),
            canonical_data: Bytes::from(vec![0u8; 1]),
            blob_start_index: 0,
            blob_versioned_hashes: vec![versioned],
            commitments: vec![commitment],
            evaluation_points: vec![B256::ZERO],
            evaluations: vec![B256::ZERO],
        };
        input.evaluation_points[0] = blob_equivalence_challenge_v1(&input, 0).unwrap();
        assert_eq!(
            validate_blob_equivalence_v1(&input),
            Ok(data_availability_statement_v1(&input))
        );
        input.blob_versioned_hashes[0] = B256::repeat_byte(0x99);
        assert_eq!(
            validate_blob_equivalence_v1(&input),
            Err(HostingStatementError::BadVersionedHash)
        );
    }

    #[test]
    fn nonzero_multi_blob_partial_tail_matches_and_verifies_with_c_kzg() {
        use c_kzg::{ethereum_kzg_settings, Blob, Bytes32};

        let mut canonical = vec![0u8; CANONICAL_BYTES_PER_BLOB_V1 + 37];
        for (index, byte) in canonical.iter_mut().enumerate() {
            *byte = ((index * 17 + 3) % 251) as u8;
        }
        let settings = ethereum_kzg_settings(0);
        let blobs = (0..2)
            .map(|index| {
                Blob::from_bytes(&canonical_blob_bytes_v1(&canonical, index)).unwrap()
            })
            .collect::<Vec<_>>();
        let commitments = blobs
            .iter()
            .map(|blob| {
                Bytes::copy_from_slice(
                    settings
                        .blob_to_kzg_commitment(blob)
                        .unwrap()
                        .to_bytes()
                        .as_ref(),
                )
            })
            .collect::<Vec<_>>();
        let mut input = BlobEquivalenceInputV1 {
            deployment_domain: B256::repeat_byte(0x12),
            room_id: 91,
            journal_hash: B256::repeat_byte(0x34),
            canonical_data: Bytes::from(canonical),
            blob_start_index: 3,
            blob_versioned_hashes: commitments
                .iter()
                .map(|commitment| blob_versioned_hash_v1(commitment.as_ref()))
                .collect(),
            commitments,
            evaluation_points: vec![B256::ZERO; 2],
            evaluations: vec![B256::ZERO; 2],
        };
        for index in 0..2 {
            input.evaluation_points[index] =
                blob_equivalence_challenge_v1(&input, index).unwrap();
        }
        for index in 0..2 {
            let z = Bytes32::new(input.evaluation_points[index].0);
            let (proof, c_kzg_y) = settings.compute_kzg_proof(&blobs[index], &z).unwrap();
            let ours = blob_equivalence_evaluation_v1(&input, index).unwrap();
            assert_eq!(ours.as_slice(), c_kzg_y.as_ref());
            input.evaluations[index] = ours;
            let commitment = c_kzg::Bytes48::from_bytes(input.commitments[index].as_ref())
                .unwrap();
            assert!(settings
                .verify_kzg_proof(
                    &commitment,
                    &z,
                    &c_kzg_y,
                    &proof.to_bytes(),
                )
                .unwrap());
        }
        assert_eq!(
            validate_blob_equivalence_v1(&input),
            Ok(data_availability_statement_v1(&input))
        );
        // The second blob is a genuine partial final chunk, not an accidental
        // empty extra blob accepted by a zero-only vector.
        assert_eq!(input.canonical_data.len() - CANONICAL_BYTES_PER_BLOB_V1, 37);
    }

    #[test]
    fn transcript_mutations_and_noncanonical_scalars_are_rejected_or_rebound() {
        let base = statement_vector();
        let base_challenge = blob_equivalence_challenge_v1(&base, 0).unwrap();
        for changed in [
            BlobEquivalenceInputV1 {
                deployment_domain: B256::repeat_byte(0x12),
                ..base.clone()
            },
            BlobEquivalenceInputV1 {
                room_id: 8,
                ..base.clone()
            },
            BlobEquivalenceInputV1 {
                journal_hash: B256::repeat_byte(0x23),
                ..base.clone()
            },
            BlobEquivalenceInputV1 {
                canonical_data: Bytes::from_static(b"zkdeal-eip4844-vector-longer"),
                ..base.clone()
            },
            BlobEquivalenceInputV1 {
                blob_start_index: 3,
                ..base.clone()
            },
            BlobEquivalenceInputV1 {
                blob_versioned_hashes: vec![B256::repeat_byte(0x34)],
                ..base.clone()
            },
            BlobEquivalenceInputV1 {
                commitments: vec![Bytes::from(vec![0x45; 48])],
                ..base.clone()
            },
        ] {
            assert_ne!(
                blob_equivalence_challenge_v1(&changed, 0).unwrap(),
                base_challenge
            );
        }

        let commitment = Bytes::from(vec![0x42; 48]);
        let mut valid = BlobEquivalenceInputV1 {
            deployment_domain: B256::repeat_byte(0x11),
            room_id: 7,
            journal_hash: B256::repeat_byte(0x22),
            canonical_data: Bytes::from(vec![0u8; 1]),
            blob_start_index: 0,
            blob_versioned_hashes: vec![blob_versioned_hash_v1(commitment.as_ref())],
            commitments: vec![commitment],
            evaluation_points: vec![B256::ZERO],
            evaluations: vec![B256::ZERO],
        };
        valid.evaluation_points[0] = blob_equivalence_challenge_v1(&valid, 0).unwrap();
        valid.evaluations[0] = B256::from([
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8,
            0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe,
            0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
        ]);
        assert_eq!(
            validate_blob_equivalence_v1(&valid),
            Err(HostingStatementError::NonCanonicalEvaluation)
        );
    }

    #[test]
    fn solidity_statement_vectors_are_stable() {
        let da = data_availability_statement_v1(&statement_vector());
        let aggregate = AggregateInputV1 {
            deployment_domain: B256::repeat_byte(0x11),
            members: vec![
                AggregateMemberStatementV1 {
                    room_id: 7,
                    room_program_id: B256::repeat_byte(0x22),
                    journal_hash: B256::repeat_byte(0x33),
                    equivalence_program_id: B256::ZERO,
                    equivalence_statement: B256::ZERO,
                },
                AggregateMemberStatementV1 {
                    room_id: 8,
                    room_program_id: B256::repeat_byte(0x44),
                    journal_hash: B256::repeat_byte(0x55),
                    equivalence_program_id: B256::repeat_byte(0x66),
                    equivalence_statement: B256::repeat_byte(0x77),
                },
            ],
        };
        assert_eq!(
            da,
            "0x7c0f23be0c71f2e587feb97ea2f4b8c06fc359a753d58f0a6f41bd79a4289c22"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            aggregate_statement_v1(&aggregate),
            "0xb78f9345f50c979096d1333c12078c006c7c8cb47f05fe7ebab708573fd6de4d"
                .parse::<B256>()
                .unwrap()
        );
    }
}
