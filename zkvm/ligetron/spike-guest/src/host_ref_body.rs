//! NON-PRODUCTION SPIKE — see stf.rs. Native reference host for the S3
//! capacity experiment: generates the deterministic tx blob, computes the
//! expected post-state root and prints the prover and verifier config lines.
//!
//! The emitted configs carry `private-indices:[1]` over the tx blob, which
//! drives every loop bound and branch in stf.rs. That is the configuration S3
//! found does not work — see zkvm/crates/ligetron-guest/src/main.rs:11-13
//! (Ligero private args must be control-flow-oblivious) and the production
//! backends, which ship `private-indices: []`. Kept as the experimental record;
//! do not copy it into a new guest. Note also that the verifier line replaces
//! the private arg with zero bytes of the same length, which parses as zero
//! transactions and therefore derives a different root.

#[path = "stf.rs"]
mod stf;

/// Caps on the generated workload, matching the guest's own MAX_ROUNDS
/// (src/main.rs) so the reference host cannot emit a config the guest rejects.
const MAX_NUM_TXS: u32 = 100_000;
const MAX_ROUNDS: u64 = 1_000_000;

/// Parse a positional CLI argument, printing usage instead of panicking on a
/// malformed value.
fn arg<T: std::str::FromStr>(a: &[String], idx: usize, name: &str, default: T) -> T {
    match a.get(idx) {
        None => default,
        Some(s) => match s.parse::<T>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("usage: stf_host_ref [num_txs] [rounds]");
                eprintln!("  {} must be a non-negative integer, got '{}'", name, s);
                std::process::exit(2);
            }
        },
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let num_txs: u32 = arg(&a, 1, "num_txs", 64).min(MAX_NUM_TXS);
    let rounds: u64 = arg(&a, 2, "rounds", 1).min(MAX_ROUNDS);

    // deterministic pseudo-random tx blob (few KB of JSON)
    let mut txs = String::from("{\"txs\":[");
    let mut seed: u64 = 0x5eed_1234_abcd_9876;
    for i in 0..num_txs {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let f = (seed >> 33) % 128;
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let t = (seed >> 33) % 128;
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let amt = (seed >> 20) % 100_000;
        if i > 0 { txs.push(','); }
        txs.push_str(&format!("{{\"f\":{},\"t\":{},\"a\":{}}}", f, t, amt));
    }
    txs.push_str("]}");

    let input = txs.as_bytes();
    let root = match stf::run_stf(input, rounds) {
        Some(root) => root,
        None => {
            eprintln!("internal error: generated tx blob did not parse");
            std::process::exit(1);
        }
    };

    let hex_input: String = input.iter().map(|b| format!("{:02x}", b)).collect();
    let hex_root: String = root.iter().map(|b| format!("{:02x}", b)).collect();

    eprintln!("input bytes: {}", input.len());
    eprintln!("txs: {}  rounds: {}  keccaks: {}", num_txs, rounds, 2 + (num_txs as u64) * rounds);
    eprintln!("root: {}", hex_root);

    // line 1: prover config, line 2: verifier config (private arg obscured, same length)
    println!(
        "{{\"program\":\"stf_guest.wasm\",\"shader-path\":\"./shader\",\"packing\":8192,\"private-indices\":[1],\"args\":[{{\"hex\":\"{}\"}},{{\"i64\":{}}},{{\"hex\":\"{}\"}}]}}",
        hex_input, rounds, hex_root
    );
    let obscured = "00".repeat(input.len());
    println!(
        "{{\"program\":\"stf_guest.wasm\",\"shader-path\":\"./shader\",\"packing\":8192,\"private-indices\":[1],\"args\":[{{\"hex\":\"{}\"}},{{\"i64\":{}}},{{\"hex\":\"{}\"}}]}}",
        obscured, rounds, hex_root
    );
}
