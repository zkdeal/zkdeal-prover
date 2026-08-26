//! Shared input/output types for the zkdeal Rust state-transition function.
//!
//! These are the types that will cross the zkVM guest boundary later, so they
//! stay `no_std`-compatible (std is a default feature for host convenience).
//! All values are canonical big-endian; hex serialization comes from
//! `alloy-primitives` serde impls.
//!
//! The crate is organized internally by type family (`domain`, `limits`,
//! `block`, `v4`, `v5`, `batch_data`), but every item stays re-exported from
//! the crate root, which is the only path callers use.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod abi;
mod batch_data;
mod block;
mod domain;
mod hosting;
mod limits;
mod v4;
mod v5;

pub use batch_data::*;
pub use block::*;
pub use domain::*;
pub use hosting::*;
pub use limits::*;
pub use v4::*;
pub use v5::*;

#[cfg(test)]
mod tests;
