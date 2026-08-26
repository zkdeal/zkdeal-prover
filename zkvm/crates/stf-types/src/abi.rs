//! Solidity ABI word primitives shared by the v4 and v5 commitment modules.
//!
//! The two families are kept separate because they are byte-for-byte pinned by
//! different Solidity/TypeScript codecs; they are collected here only so the
//! commitment modules do not each carry a private copy.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, B256, U256};

pub(crate) fn abi_u64_word_v5(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

pub(crate) fn abi_bool_word_v5(value: bool) -> [u8; 32] {
    abi_u64_word_v5(u64::from(value))
}

pub(crate) fn abi_address_word_v5(value: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(value.as_slice());
    word
}

pub(crate) fn abi_u256_word_v5(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

pub(crate) fn keccak_words_v5(words: impl IntoIterator<Item = [u8; 32]>) -> B256 {
    let words = words.into_iter().collect::<Vec<_>>();
    let mut encoded = Vec::with_capacity(words.len() * 32);
    for word in words {
        encoded.extend_from_slice(&word);
    }
    keccak256(encoded)
}

pub(crate) fn u256_word(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

pub(crate) fn uint256_word(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

pub(crate) fn address_word(value: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(value.as_slice());
    out
}

pub(crate) fn hash_words(words: impl IntoIterator<Item = [u8; 32]>) -> B256 {
    let words = words.into_iter().collect::<Vec<_>>();
    let mut encoded = Vec::with_capacity(words.len() * 32);
    for word in words {
        encoded.extend_from_slice(&word);
    }
    keccak256(encoded)
}

pub(crate) fn b256_word(value: B256) -> [u8; 32] {
    value.0
}
