//! Primitive JSON accessors shared by every fixture request parser.
//!
//! They exist so the parsers in `config`, `contracts` and `card` report the
//! same message shape for the same mistake, and so a malformed request is
//! rejected before any state is built.

use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{bail, Context, Result};
use serde_json::Value;

pub(super) fn parse_u64(value: &Value, key: &str) -> Result<u64> {
    let value = value
        .get(key)
        .with_context(|| format!("{key} is required"))?;
    parse_u64_value(value, key)
}

pub(super) fn parse_u64_value(value: &Value, label: &str) -> Result<u64> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    value
        .as_str()
        .with_context(|| format!("{label} must be an unsigned integer"))?
        .parse()
        .with_context(|| format!("{label} is outside uint64"))
}

pub(super) fn parse_u64_or(value: &Value, key: &str, default: u64) -> Result<u64> {
    if value.get(key).is_none() {
        return Ok(default);
    }
    parse_u64(value, key)
}

pub(super) fn parse_b256(value: &Value, key: &str) -> Result<B256> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{key} is required"))?
        .parse()
        .with_context(|| format!("{key} must be bytes32"))
}

pub(super) fn parse_address_value(value: &Value, label: &str) -> Result<Address> {
    value
        .as_str()
        .with_context(|| format!("{label} must be an address"))?
        .parse()
        .with_context(|| format!("{label} must be a 20-byte address"))
}

pub(super) fn parse_optional_address(value: &Value, key: &str) -> Result<Option<Address>> {
    value
        .get(key)
        .map(|raw| parse_address_value(raw, key))
        .transpose()
}

pub(super) fn parse_hex_bytes(value: &Value, label: &str) -> Result<Bytes> {
    let raw = value
        .as_str()
        .with_context(|| format!("{label} must be hexadecimal bytes"))?;
    raw.parse()
        .with_context(|| format!("{label} must be even-length 0x-prefixed hexadecimal bytes"))
}

/// A uint256 carried as a JSON number, a decimal string or a `0x` string.
pub(super) fn parse_word(value: &Value, label: &str) -> Result<U256> {
    if let Some(number) = value.as_u64() {
        return Ok(U256::from(number));
    }
    let raw = value
        .as_str()
        .with_context(|| format!("{label} must be a number or string"))?;
    raw.parse()
        .with_context(|| format!("{label} is outside uint256"))
}

pub(super) fn parse_word_or(value: &Value, key: &str, default: U256) -> Result<U256> {
    match value.get(key) {
        None => Ok(default),
        Some(raw) => parse_word(raw, key),
    }
}

pub(super) fn parse_selector(value: &Value, label: &str) -> Result<[u8; 4]> {
    let bytes = parse_hex_bytes(value, label)?;
    if bytes.len() != 4 {
        bail!("{label} must contain exactly four bytes");
    }
    Ok(<[u8; 4]>::try_from(bytes.as_ref()).expect("selector length checked"))
}

/// `[{ "slot": .., "value": .. }]`, sorted by slot with duplicates rejected.
pub(super) fn parse_storage_entries(raw: &Value, label: &str, cap: usize) -> Result<Vec<(U256, U256)>> {
    let entries = raw
        .as_array()
        .with_context(|| format!("{label} must be an array"))?;
    if entries.len() > cap {
        bail!("{label} exceeds the certified storage-slot cap");
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let row = entry
            .as_object()
            .with_context(|| format!("{label}[{index}] must be an object"))?;
        let word = |name: &str| -> Result<U256> {
            let value = row
                .get(name)
                .with_context(|| format!("{label}[{index}].{name} is required"))?;
            parse_word(value, &format!("{label}[{index}].{name}"))
        };
        parsed.push((word("slot")?, word("value")?));
    }
    parsed.sort_by_key(|(slot, _)| *slot);
    if parsed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        bail!("{label} contains a duplicate slot");
    }
    Ok(parsed)
}
