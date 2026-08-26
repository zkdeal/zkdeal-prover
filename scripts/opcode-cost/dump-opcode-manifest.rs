//! Emit the Osaka opcode and precompile inventory as JSON.
//!
//! The proving-cost sweep has to state which instructions it measured and,
//! just as importantly, which it did not. Hand-typing that list into the
//! harness would let the two drift apart silently: a new opcode would simply
//! be absent from the table with nothing to notice it. This binary dumps the
//! inventory from the same pinned REVM interpreter the guest executes, so the
//! sweep's completeness claim is derived rather than asserted.
//!
//! Read-only. Prints JSON on stdout and nothing else.
//!
//! Run from `prover-node/`:
//!   docker compose run --rm test cargo run -p stf-core --bin dump-opcode-manifest

use stf_core::{osaka_opcode_manifest, osaka_precompile_addresses, OpcodeStatus};

fn main() {
    let manifest = osaka_opcode_manifest();
    let opcodes = manifest
        .iter()
        .map(|entry| {
            serde_json::json!({
                "byte": entry.byte,
                "hex": format!("0x{:02x}", entry.byte),
                "name": entry.name,
                "active": matches!(entry.status, OpcodeStatus::Active),
            })
        })
        .collect::<Vec<_>>();

    let precompiles = osaka_precompile_addresses()
        .iter()
        .map(|address| format!("{address:?}"))
        .collect::<Vec<_>>();

    let active = opcodes
        .iter()
        .filter(|entry| entry["active"].as_bool() == Some(true))
        .count();

    let document = serde_json::json!({
        "schema": "zkdeal/osaka-opcode-manifest/v1",
        "spec": "osaka",
        "activeOpcodes": active,
        "invalidOpcodes": opcodes.len() - active,
        "precompileCount": precompiles.len(),
        "opcodes": opcodes,
        "precompiles": precompiles,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("manifest serialises")
    );
}
