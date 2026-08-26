//! Exhaustive Osaka opcode inventory.
//!
//! The semantic authority remains the pinned REVM Osaka interpreter and the
//! official execution-spec tests. This module makes the coverage boundary
//! explicit: every byte is either a named Osaka instruction or an invalid
//! instruction that must halt.

use revm::bytecode::opcode::OpCode;
use revm::precompile::{PrecompileSpecId, Precompiles};
use revm::primitives::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpcodeStatus {
    Active,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpcodeManifestEntry {
    pub byte: u8,
    pub name: &'static str,
    pub status: OpcodeStatus,
}

pub fn osaka_opcode_manifest() -> [OpcodeManifestEntry; 256] {
    core::array::from_fn(|index| {
        let byte = index as u8;
        match OpCode::new(byte) {
            Some(opcode) => OpcodeManifestEntry {
                byte,
                name: opcode.as_str(),
                status: OpcodeStatus::Active,
            },
            None => OpcodeManifestEntry {
                byte,
                name: "INVALID",
                status: OpcodeStatus::Invalid,
            },
        }
    })
}

pub fn osaka_precompile_addresses() -> Vec<Address> {
    let mut addresses = Precompiles::new(PrecompileSpecId::OSAKA)
        .addresses()
        .copied()
        .collect::<Vec<_>>();
    addresses.sort();
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_opcode_byte_has_one_explicit_classification() {
        let manifest = osaka_opcode_manifest();
        assert_eq!(manifest.len(), 256);
        for (byte, entry) in manifest.iter().enumerate() {
            assert_eq!(usize::from(entry.byte), byte);
            match (OpCode::new(entry.byte), entry.status) {
                (Some(opcode), OpcodeStatus::Active) => assert_eq!(entry.name, opcode.as_str()),
                (None, OpcodeStatus::Invalid) => assert_eq!(entry.name, "INVALID"),
                other => panic!("opcode 0x{byte:02x} has inconsistent classification: {other:?}"),
            }
        }
    }

    #[test]
    fn osaka_additions_and_block_context_are_active() {
        for byte in [0x1eu8, 0x20, 0x40, 0x49, 0x4a, 0x5c, 0x5d, 0x5e] {
            assert_eq!(
                osaka_opcode_manifest()[usize::from(byte)].status,
                OpcodeStatus::Active,
                "opcode 0x{byte:02x}"
            );
        }
    }

    #[test]
    fn every_osaka_precompile_is_present_and_callable() {
        let precompiles = Precompiles::new(PrecompileSpecId::OSAKA);
        let expected = (1..=0x11)
            .map(revm::precompile::u64_to_address)
            .chain(core::iter::once(revm::precompile::u64_to_address(0x100)))
            .collect::<Vec<_>>();
        assert_eq!(osaka_precompile_addresses(), expected);
        for address in expected {
            let precompile = precompiles
                .get(&address)
                .unwrap_or_else(|| panic!("missing Osaka precompile at {address}"));
            let _semantic_result = precompile.execute(&[], u64::MAX);
        }
    }
}
