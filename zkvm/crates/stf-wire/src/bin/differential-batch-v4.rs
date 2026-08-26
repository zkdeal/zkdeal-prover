//! Fast Osaka revm side of the 10k differential matrix.
//!
//! Input is newline-delimited canonical `BatchWitnessV4` JSON. One process
//! handles the full corpus so the TypeScript ethereumjs driver does not pay
//! cargo/process startup per trace. Output preserves line order and is JSONL:
//! `{trace,ok,journal}` or `{trace,ok:false,error}`. An invalid/adversarial
//! witness is therefore evidence, not a process-level crash.

use std::io::{self, BufRead, Write};

use stf_core::execute_batch_v4;
use stf_wire::{batch_journal_to_ts_value_v4, parse_batch_witness_json_v4};

fn run_trace(trace: u64, line: &str) -> serde_json::Value {
    let result = parse_batch_witness_json_v4(line)
        .and_then(|wire| wire.to_input())
        .map_err(|error| format!("witness: {error}"))
        .and_then(|input| {
            execute_batch_v4(&input)
                .map_err(|error| format!("stf: {error}"))
                .map(|journal| batch_journal_to_ts_value_v4(&journal))
        });
    match result {
        Ok(journal) => serde_json::json!({ "trace": trace, "ok": true, "journal": journal }),
        Err(error) => serde_json::json!({ "trace": trace, "ok": false, "error": error }),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut trace = 0u64;
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        trace = trace.checked_add(1).ok_or("trace counter overflow")?;
        serde_json::to_writer(&mut stdout, &run_trace(trace, &line))?;
        stdout.write_all(b"\n")?;
        // This binary is a persistent request/response worker. The JS side
        // waits for one response before sending its next trace, so buffering
        // until stdin EOF deadlocks the corpus on request one.
        stdout.flush()?;
    }
    Ok(())
}
