//! NON-PRODUCTION SPIKE. Superseded by zkvm/crates/ligetron-guest, which runs
//! the real shared stf-core. Kept only as the S3 capacity experiment; nothing
//! in the product builds, ships or trusts it, and its output
//! (`stf_guest.wasm`) is deliberately absent from zkvm/artifacts.lock.json, so
//! a client configured with it fails the programDigest pin.
//!
//! STF-shaped workload shared by the wasm guest and the native reference host.
//! Approximates a zkdeal L2 state transition: parse a JSON-ish tx blob,
//! apply balance updates over a small map, keccak-chain everything,
//! produce a 32-byte post-state root.

use std::collections::BTreeMap;
use tiny_keccak::{Hasher, Keccak};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Longest run of digits accepted for one numeric field. `u64::MAX` is 20
/// digits wide, so a longer run cannot be a value we can represent; the
/// checked arithmetic below rejects the in-width overflow cases.
const MAX_NUM_DIGITS: usize = 20;

/// Parse a run of ASCII digits starting at `*i`.
///
/// Returns `None` when the run is empty, longer than `MAX_NUM_DIGITS`, or
/// overflows `u64`. The unchecked `v * 10 + d` this replaces was the one place
/// where the release profile (`overflow-checks` off, see Cargo.toml) and a
/// default native build disagreed: wrap versus panic on the same input.
fn parse_num(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    let mut digits = 0usize;
    while *i < b.len() && b[*i].is_ascii_digit() {
        digits += 1;
        if digits > MAX_NUM_DIGITS {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b[*i] - b'0') as u64)?;
        *i += 1;
    }
    if digits == 0 {
        None
    } else {
        Some(v)
    }
}

/// Advance `*i` past the two-byte key marker `"<key>`, returning false when the
/// marker is absent from the remaining input. The `i + 1 < n` bound keeps the
/// scan in range; the boolean is what stops a truncated or reordered object
/// from being turned into a fabricated `(f, 0, 0)` transaction.
fn seek_key(b: &[u8], i: &mut usize, key: u8) -> bool {
    let n = b.len();
    while *i + 1 < n && !(b[*i] == b'"' && b[*i + 1] == key) {
        *i += 1;
    }
    if *i + 1 < n {
        *i += 2;
        true
    } else {
        false
    }
}

/// Minimal JSON scanner for our fixed shape:
/// {"txs":[{"f":1,"t":2,"a":30}, ...]}
/// Avoids serde to keep the guest small; still does real byte-level parsing work.
///
/// Returns `None` if any started tx object is malformed — a missing `"t"`/`"a"`
/// key, a missing numeral, or an out-of-range numeral. The caller must treat
/// that as a proving failure rather than proving a transition over transactions
/// that were never in the blob.
pub fn parse_txs(input: &[u8]) -> Option<Vec<(u32, u32, u64)>> {
    let mut txs = Vec::new();
    let mut i = 0usize;
    let n = input.len();

    while i < n {
        // find '{' of a tx object (skip the outer object brace at pos 0)
        if input[i] == b'"' && i + 2 < n && input[i + 1] == b'f' && input[i + 2] == b'"' {
            i += 3;
            while i < n && !input[i].is_ascii_digit() { i += 1; }
            let f = parse_num(input, &mut i)? as u32;
            if !seek_key(input, &mut i, b't') { return None; }
            while i < n && !input[i].is_ascii_digit() { i += 1; }
            let t = parse_num(input, &mut i)? as u32;
            if !seek_key(input, &mut i, b'a') { return None; }
            while i < n && !input[i].is_ascii_digit() { i += 1; }
            let a = parse_num(input, &mut i)?;
            txs.push((f, t, a));
        } else {
            i += 1;
        }
    }
    Some(txs)
}

pub const NUM_ACCOUNTS: u32 = 128;
pub const INIT_BALANCE: u64 = 1_000_000;

/// Run the state transition. `rounds` re-applies the tx batch to scale work.
/// Returns the 32-byte post-state root, or `None` if the blob is malformed.
pub fn run_stf(input: &[u8], rounds: u64) -> Option<[u8; 32]> {
    let txs = parse_txs(input)?;

    let mut state: BTreeMap<u32, u64> = (0..NUM_ACCOUNTS).map(|i| (i, INIT_BALANCE)).collect();
    let mut chain: [u8; 32] = keccak256(input);

    for r in 0..rounds {
        for (idx, &(f, t, a)) in txs.iter().enumerate() {
            let from = f % NUM_ACCOUNTS;
            let to = t % NUM_ACCOUNTS;

            // tx hash: chain || from || to || amount || round || idx  (like a receipt hash)
            let mut buf = [0u8; 32 + 4 + 4 + 8 + 8 + 8];
            buf[..32].copy_from_slice(&chain);
            buf[32..36].copy_from_slice(&from.to_le_bytes());
            buf[36..40].copy_from_slice(&to.to_le_bytes());
            buf[40..48].copy_from_slice(&a.to_le_bytes());
            buf[48..56].copy_from_slice(&r.to_le_bytes());
            buf[56..64].copy_from_slice(&(idx as u64).to_le_bytes());
            chain = keccak256(&buf);

            // balance transition with checks (branchy map work)
            let amount = a % 10_000;
            let fb = *state.get(&from).unwrap_or(&0);
            if fb >= amount && from != to {
                *state.entry(from).or_insert(0) -= amount;
                *state.entry(to).or_insert(0) += amount;
            } else {
                // failed tx still burns a fee
                let fee = amount / 100 + 1;
                let e = state.entry(from).or_insert(0);
                *e = e.saturating_sub(fee);
            }
        }
    }

    // post-state root: keccak over sequential (key, balance) pairs, chained with tx hash chain
    let mut acc: Vec<u8> = Vec::with_capacity((NUM_ACCOUNTS as usize) * 12 + 32);
    acc.extend_from_slice(&chain);
    for (k, v) in state.iter() {
        acc.extend_from_slice(&k.to_le_bytes());
        acc.extend_from_slice(&v.to_le_bytes());
    }
    Some(keccak256(&acc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// The guest and the reference host must derive byte-identical roots from
    /// the same blob; this pins the value so a change to either the parser or
    /// the transition is a test failure rather than a silent re-measurement.
    #[test]
    fn known_blob_has_a_fixed_root() {
        let blob = br#"{"txs":[{"f":1,"t":2,"a":30},{"f":2,"t":3,"a":40}]}"#;
        assert_eq!(
            hex(&run_stf(blob, 3).expect("well-formed blob must parse")),
            "d910cb0b36e54f60a3a82074ff9b1ddc61c3ecd2ac4628517478e6e0b22a8ac8"
        );
    }

    #[test]
    fn well_formed_blob_parses_every_field() {
        let blob = br#"{"txs":[{"f":1,"t":2,"a":30},{"f":7,"t":9,"a":0}]}"#;
        assert_eq!(parse_txs(blob), Some(vec![(1, 2, 30), (7, 9, 0)]));
    }

    #[test]
    fn empty_blob_yields_no_transactions() {
        assert_eq!(parse_txs(br#"{"txs":[]}"#), Some(Vec::new()));
    }

    /// Blobs that used to produce a fabricated `(f, 0, 0)` transaction, or to
    /// wrap/panic in `parse_num` depending on the profile, must all be rejected.
    #[test]
    fn malformed_blobs_are_rejected() {
        let cases: &[(&str, &[u8])] = &[
            ("truncated after \"f\"", br#"{"txs":[{"f":1"#),
            ("truncated mid-object", br#"{"txs":[{"f":1,"t":2"#),
            ("keys reordered, \"t\" before \"f\"", br#"{"txs":[{"t":2,"f":1,"a":30}]}"#),
            ("missing \"a\" key", br#"{"txs":[{"f":1,"t":2,"x":30}]}"#),
            ("no numeral after \"f\"", br#"{"txs":[{"f":,"t":2,"a":30}]}"#),
            (
                "numeral wider than u64",
                br#"{"txs":[{"f":1,"t":2,"a":99999999999999999999}]}"#,
            ),
            (
                "numeral overflowing u64 at 20 digits",
                br#"{"txs":[{"f":1,"t":2,"a":18446744073709551616}]}"#,
            ),
        ];
        for (name, blob) in cases {
            assert_eq!(parse_txs(blob), None, "{name} should be rejected");
            assert_eq!(run_stf(blob, 1), None, "{name} should not yield a root");
        }
    }

    /// `u64::MAX` itself is exactly at the digit cap and must still parse, so
    /// the cap rejects only what cannot be represented.
    #[test]
    fn largest_representable_amount_parses() {
        let blob = br#"{"txs":[{"f":1,"t":2,"a":18446744073709551615}]}"#;
        assert_eq!(parse_txs(blob), Some(vec![(1, 2, u64::MAX)]));
    }

    #[test]
    fn zero_rounds_still_produces_a_root() {
        let blob = br#"{"txs":[{"f":1,"t":2,"a":30}]}"#;
        assert!(run_stf(blob, 0).is_some());
    }
}
