//! NON-PRODUCTION SPIKE — see stf.rs. The production Ligetron guest is
//! zkvm/crates/ligetron-guest.
//!
//! Ligetron guest: STF-shaped workload.
//! Args (1-indexed after implicit argv[0] = "Ligero"):
//!   [1] hex : tx blob (private)      -> raw bytes
//!   [2] i64 : rounds (public)
//!   [3] hex : expected 32-byte post-state root (public)
//!
//! Arg 1 is declared private by the configs this crate's reference host emits
//! (`private-indices:[1]` in host_ref_body.rs), yet it determines every loop
//! bound and branch in stf.rs. That is the configuration S3 found does not
//! work — see zkvm/crates/ligetron-guest/src/main.rs:11-13, which records that
//! Ligero private args must be control-flow-oblivious, and the production
//! backends, which ship `private-indices: []`. Kept as the experimental record;
//! do not copy this configuration into a new guest.

mod stf;

use ligetron::*;

/// Upper bound on the public `rounds` argument. Work is O(rounds * txs)
/// keccaks, so an unbounded value is a non-terminating guest and an unbounded
/// prover trace rather than a capacity measurement. Well above any rounds count
/// the S3 experiment used.
const MAX_ROUNDS: i64 = 1_000_000;

fn main() {
    let args = get_args();

    // argv[0] is the implicit "Ligero", so three statement args means len 4.
    // Without this, a short argv reaches the SDK's fail_with_message!, whose
    // body asserts `assert_zero(0)` — a trivially satisfied constraint — and
    // fail-closed behaviour would rest entirely on the runtime rejecting the
    // subsequent proc_exit(1) rather than on a constraint this guest emitted.
    if args.len() < 4 {
        print_str(b"stf-guest(spike): expected 3 arguments (blob, rounds, root)");
        assert_one(0);
        return;
    }

    let input = args.get_as_bytes(1);
    let rounds_arg = args.get_as_int(2);
    let expected = args.get_as_bytes(3);

    // Public args are attacker-supplied; validate the length before the
    // fixed-32-byte comparison below indexes into it.
    if expected.len() != 32 {
        print_str(b"stf-guest(spike): expected-root argument is not 32 bytes");
        assert_one(0);
        return;
    }

    // get_as_int returns i64, so an unchecked `as u64` turns -1 into ~1.8e19
    // rounds. Same guard shape as the length check above.
    if rounds_arg < 0 || rounds_arg > MAX_ROUNDS {
        print_str(b"stf-guest(spike): rounds argument is negative or out of range");
        assert_one(0);
        return;
    }
    let rounds = rounds_arg as u64;

    let root = match stf::run_stf(input, rounds) {
        Some(root) => root,
        None => {
            print_str(b"stf-guest(spike): tx blob is malformed");
            assert_one(0);
            return;
        }
    };

    // publish computed root (visible in prover stdout)
    dump_memory(&root);

    // bind the result to the public expected-root argument
    for i in 0..32 {
        assert_one((root[i] == expected[i]) as i32);
    }
}
