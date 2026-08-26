//! zkdeal STF ligetron guest (PRODUCTION statement, wasm32-wasip1).
//!
//! Runs the REAL stf-core (revm + alloy-trie — the same STF whose parity
//! with the ethereumjs engine is pinned by zkvm/crates/stf-core tests) under
//! the Ligero wasm prover and binds the resulting journal to a public
//! expected-journal argument.
//!
//! Args (1-indexed after implicit argv[0] = "Ligero"), ALL PUBLIC
//! (`private-indices: []`):
//!   [1] hex : borsh(StfInputWire) — the full block witness (pre-state,
//!             raw txs, env). PUBLIC by design: Ligero private args must be
//!             control-flow-oblivious, and EVM re-execution is inherently
//!             data-dependent (S3 finding). zkdeal rooms have no secret
//!             block data — members already share every block — so the
//!             proof binds "this public witness executes to this journal".
//!   [2] hex : expected 145-byte borsh(StfJournal) v2 (binds the executed
//!             block environment via env_hash).
//!
//! The guest recomputes the journal via stf-core and asserts byte equality
//! with arg 2 (assert_one per byte → unsatisfiable circuit on mismatch).
//! programDigest for the ligetron backend = sha256 of this wasm binary.
//!
//! Constraint-cost note (honest expectations, measured in zkvm build
//! reports): keccak256 costs ≈250k quadratic constraints under Ligero and a
//! block witness triggers dozens of keccaks (account/storage tries) plus
//! full revm interpretation — even small blocks are in the tens of millions
//! of quad constraints, near/over the ~20–50M practical ceiling of an 8 GB
//! GPU. This guest is the real statement; proving capacity, not statement
//! honesty, is the limiting factor.

use ligetron::*;
use stf_core::execute_block;
use stf_wire::{input_from_borsh, journal_to_borsh};

fn main() {
    let args = get_args();

    let input_bytes = args.get_as_bytes(1);
    let expected_journal = args.get_as_bytes(2);

    let wire = match input_from_borsh(input_bytes) {
        Ok(w) => w,
        Err(_) => {
            print_str(b"zkdeal-stf-guest: borsh input decode failed");
            assert_one(0);
            return;
        }
    };
    let input = wire.to_input();

    let journal = match execute_block(&input) {
        Ok(j) => j,
        Err(_) => {
            print_str(b"zkdeal-stf-guest: stf execution failed");
            assert_one(0);
            return;
        }
    };
    let journal_bytes = journal_to_borsh(&journal);

    // Visible in prover stdout for diagnostics (NOT a commitment).
    dump_memory(&journal_bytes);

    // Bind the computed journal to the public expected-journal argument.
    assert_one((journal_bytes.len() == expected_journal.len()) as i32);
    for i in 0..journal_bytes.len() {
        assert_one((journal_bytes[i] == expected_journal[i]) as i32);
    }
}
