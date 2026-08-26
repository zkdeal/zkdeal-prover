//! Deterministic EVM runtime code the fixture deploys, and the fixture's
//! address derivation.
//!
//! Every builder emits fixed bytes so a prepared room is byte-reproducible.

use alloy_primitives::{keccak256, Address, Bytes};
use stf_core::TOP_50_SOLIDITY_MOTIFS;

pub(super) fn fixture_address(label: &[u8], index: u64) -> Address {
    let mut seed = Vec::with_capacity(label.len() + 8);
    seed.extend_from_slice(label);
    seed.extend_from_slice(&index.to_be_bytes());
    Address::from_slice(&keccak256(seed).as_slice()[12..])
}

pub(super) fn storage_runtime() -> Bytes {
    Bytes::from(vec![0x60, 0x04, 0x35, 0x5f, 0x55, 0x00])
}

pub(super) fn opcode_gadget_runtime(repeats: u64) -> Bytes {
    let mut code = Vec::with_capacity(repeats as usize * 600 + 7);
    for repetition in 0..repeats {
        for (index, motif) in TOP_50_SOLIDITY_MOTIFS.iter().enumerate() {
            code.extend_from_slice(&[
                0x60,
                (index as u8).wrapping_add(2),
                0x60,
                (index as u8).wrapping_add(3),
                0x60,
                (repetition as u8).wrapping_add(4),
                motif.first,
                motif.second,
            ]);
            let first_arity = if matches!(motif.first, 0x15 | 0x19) {
                1
            } else {
                2
            };
            let second_arity = if matches!(motif.second, 0x15 | 0x19) {
                1
            } else {
                2
            };
            let remaining = 5 - first_arity - second_arity;
            code.extend(std::iter::repeat_n(0x50, remaining)); // POP
        }
    }
    // Store a transaction-varying calldata word after every motif stack has
    // been cleared. The room therefore proves a real state transition.
    code.extend_from_slice(&[0x60, 0x04, 0x35, 0x5f, 0x55, 0x00]);
    Bytes::from(code)
}

fn push_u16(code: &mut Vec<u8>, value: usize) -> usize {
    let value = u16::try_from(value).expect("participant runtime fits PUSH2");
    code.extend_from_slice(&[0x61, (value >> 8) as u8, value as u8]);
    code.len() - 2
}

fn patch_u16(code: &mut [u8], position: usize, value: usize) {
    let value = u16::try_from(value).expect("participant jump fits PUSH2");
    code[position] = (value >> 8) as u8;
    code[position + 1] = value as u8;
}

fn push_calldata_offset(code: &mut Vec<u8>, offset: usize) {
    if offset <= u8::MAX as usize {
        code.extend_from_slice(&[0x60, offset as u8]);
    } else {
        let _ = push_u16(code, offset);
    }
}

fn append_participant_path(
    code: &mut Vec<u8>,
    leaf_offset: usize,
    proof_offset: usize,
    depth: u64,
) {
    push_calldata_offset(code, leaf_offset);
    code.extend_from_slice(&[0x35, 0x5f, 0x52]); // leaf -> memory[0]
    for level in 0..depth {
        push_calldata_offset(code, proof_offset + level as usize * 32);
        code.extend_from_slice(&[0x35, 0x60, 0x20, 0x52]); // sibling -> memory[32]
        code.extend_from_slice(&[
            0x60,
            0x04,
            0x35, // index
            0x60,
            level as u8,
            0x1c, // index >> level
            0x60,
            0x01,
            0x16, // direction bit
        ]);
        let right_jump = push_u16(code, 0);
        code.push(0x57); // JUMPI
        code.extend_from_slice(&[0x60, 0x40, 0x5f, 0x20, 0x5f, 0x52]); // left hash
        let done_jump = push_u16(code, 0);
        code.push(0x56); // JUMP
        let right = code.len();
        code.push(0x5b); // JUMPDEST
        code.extend_from_slice(&[
            0x5f, 0x51, // current
            0x60, 0x20, 0x51, // sibling
            0x5f, 0x52, // sibling -> memory[0], current remains
            0x60, 0x20, 0x52, // current -> memory[32]
            0x60, 0x40, 0x5f, 0x20, 0x5f, 0x52, // right hash
        ]);
        let done = code.len();
        code.push(0x5b); // JUMPDEST
        patch_u16(code, right_jump, right);
        patch_u16(code, done_jump, done);
    }
}

/// Verify the previous leaf against the current application root, derive the
/// replacement root from the same positional proof, then advance the epoch.
/// Every transaction carries one real path for a distinct participant index.
pub(super) fn participant_merkle_runtime(depth: u64) -> Bytes {
    let mut code = Vec::new();
    let proof_offset = 100;
    append_participant_path(&mut code, 36, proof_offset, depth);
    code.extend_from_slice(&[
        0x5f, 0x51, // derived old root
        0x63, 0x3b, 0x9a, 0xca, 0x00, 0x54, // stored root
        0x14, 0x15, // EQ, ISZERO
    ]);
    let failure_jump = push_u16(&mut code, 0);
    code.push(0x57); // JUMPI
    append_participant_path(&mut code, 68, proof_offset, depth);
    code.extend_from_slice(&[0x5f, 0x51, 0x63, 0x3b, 0x9a, 0xca, 0x00, 0x55]);
    // participantEpoch += 1
    code.extend_from_slice(&[
        0x63, 0x3b, 0x9a, 0xca, 0x01, 0x54, 0x60, 0x01, 0x01, 0x63, 0x3b, 0x9a, 0xca, 0x01, 0x55,
        0x00,
    ]);
    let failure = code.len();
    code.extend_from_slice(&[0x5b, 0x5f, 0x5f, 0xfd]); // JUMPDEST; REVERT(0,0)
    patch_u16(&mut code, failure_jump, failure);
    Bytes::from(code)
}

/// Small deterministic EVM workload matching the persistent-shop proof
/// boundary: register a session in block one, then purchase one tokenized item
/// in block two. The production Solidity contract carries the complete
/// authorization and claim surface; this bytecode keeps the CUDA benchmark
/// focused on the same state transition rather than host-side simulation.
pub(super) fn shop_demo_runtime() -> Bytes {
    let mut code = vec![
        0x60, 0x04, 0x35, // action = calldata word
        0x60, 0x09, 0x14, // action == 9 (register)
        0x60, 0x00, 0x57, // jump to register
        0x60, 0x01, 0x54, // inventory
        0x60, 0x01, 0x90, 0x03, // inventory - 1
        0x60, 0x01, 0x55, // store inventory
        0x60, 0x03, 0x54, 0x60, 0x05, 0x01, // proceeds + price
        0x60, 0x03, 0x55, // store proceeds
        0x60, 0x04, 0x54, 0x60, 0x01, 0x01, // buyer inventory + 1
        0x60, 0x04, 0x55, 0x00, // store and stop
    ];
    let register = u8::try_from(code.len()).expect("shop demo runtime fits PUSH1");
    code[7] = register;
    code.extend_from_slice(&[
        0x5b, // JUMPDEST
        0x60, 0x01, 0x5f, 0x55, 0x00, // session active = 1
    ]);
    Bytes::from(code)
}

/// Small deterministic EVM workload matching the auction proof boundary:
/// accept a commitment in block one, then consume two units and allocate the
/// conserved clearing outputs in block two. Full ranking, ties, partial fills,
/// deadlines and reveal-bond rules are exercised by the Solidity application
/// tests.
pub(super) fn auction_demo_runtime() -> Bytes {
    let mut code = vec![
        0x60, 0x04, 0x35, // action = calldata word
        0x60, 0x09, 0x14, // action == 9 (commit)
        0x60, 0x00, 0x57, // jump to commit
        0x60, 0x01, 0x54, 0x60, 0x02, 0x90, 0x03, // inventory - 2
        0x60, 0x01, 0x55, // store inventory
        0x60, 0x02, 0x54, 0x60, 0x0a, 0x01, // seller proceeds + 10
        0x60, 0x02, 0x55, // store proceeds
        0x60, 0x03, 0x54, 0x60, 0x02, 0x01, // winner inventory + 2
        0x60, 0x03, 0x55, 0x00, // store and stop
    ];
    let commit = u8::try_from(code.len()).expect("auction demo runtime fits PUSH1");
    code[7] = commit;
    code.extend_from_slice(&[
        0x5b, // JUMPDEST
        0x5f, 0x54, 0x60, 0x01, 0x01, 0x5f, 0x55, 0x00, // commitment count += 1
    ]);
    Bytes::from(code)
}
