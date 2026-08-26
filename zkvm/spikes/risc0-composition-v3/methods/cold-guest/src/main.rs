//! Minimal immutable cold-prefix guest.
//!
//! The production version of this statement would execute constructors and
//! authenticate the prepared room state. This bounded spike deliberately only
//! commits the template bytes so it measures RISC Zero composition mechanics,
//! not another EVM implementation.

use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

fn main() {
    let immutable_template: Vec<u8> = env::read();
    let template_digest = Impl::hash_bytes(&immutable_template);
    env::commit_slice(template_digest.as_bytes());
}
