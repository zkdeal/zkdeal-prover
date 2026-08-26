//! Witness-JSON bridge (feature `json`, host/wasm side only).
//!
//! Split by wire message family: shared scalar readers, the single-block TS
//! shapes, the v4 witness readers (with their repeated-record helpers) and the
//! v4 journal shapes.

mod journal_v4;
mod scalars;
mod single_block;
mod witness_fields_v4;
mod witness_v4;

pub use journal_v4::{
    batch_journal_to_ts_value_v4, genesis_journal_to_ts_value_v4, parse_batch_journal_json_v4,
    parse_genesis_journal_json_v4,
};
pub use single_block::{journal_to_ts_value, parse_witness_json, post_state_to_dump_json};
pub use witness_v4::{parse_batch_witness_json_v4, parse_genesis_witness_json_v4};
