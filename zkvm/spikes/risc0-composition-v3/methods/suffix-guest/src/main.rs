//! Minimal hot-suffix guest using RISC Zero's receipt-assumption syscall.
//!
//! The cold image ID and journal are included in this guest's public journal.
//! A zkdeal preset/RoomManager integration must compare those values with the
//! registered prepared-room artifact; accepting an arbitrary caller-selected
//! cold image would not be a safe production policy.

use risc0_zkvm::{
    guest::env,
    sha::{Digest, Impl, Sha256},
};

fn main() {
    let cold_image_words: [u32; 8] = env::read();
    let cold_journal: Vec<u8> = env::read();
    let hot_suffix: Vec<u8> = env::read();
    let cold_image_id = Digest::new(cold_image_words);

    // This records an assumption in the suffix claim. The host must provide a
    // receipt with the exact image ID and journal through add_assumption. Final
    // compression resolves that assumption into one unconditional receipt.
    env::verify(cold_image_id, cold_journal.as_slice())
        .expect("env::verify is infallible once a matching assumption is supplied");

    let cold_journal_digest = Impl::hash_bytes(&cold_journal);
    let hot_suffix_digest = Impl::hash_bytes(&hot_suffix);
    env::commit_slice(cold_image_id.as_bytes());
    env::commit_slice(cold_journal_digest.as_bytes());
    env::commit_slice(hot_suffix_digest.as_bytes());
}
