//! Tolerant scalar readers shared by every witness- and journal-JSON parser:
//! decimal-or-hex integers, 0x byte strings, fixed-width words and addresses.

use alloy_primitives::U256;
use serde_json::{Map, Value};

pub(super) fn parse_u64_flex(v: &Value, label: &str) -> Result<u64, String> {
    match v {
        Value::Number(n) => n.as_u64().ok_or_else(|| format!("{label}: not a u64")),
        Value::String(s) => {
            let s = s.trim();
            if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(if h.is_empty() { "0" } else { h }, 16)
                    .map_err(|e| format!("{label}: bad hex u64: {e}"))
            } else {
                s.parse::<u64>()
                    .map_err(|e| format!("{label}: bad u64: {e}"))
            }
        }
        _ => Err(format!("{label}: expected number or string")),
    }
}

pub(super) fn parse_u256_flex(v: &Value, label: &str) -> Result<U256, String> {
    match v {
        Value::Number(n) => {
            let u = n.as_u64().ok_or_else(|| format!("{label}: not a uint"))?;
            Ok(U256::from(u))
        }
        Value::String(s) => {
            let s = s.trim();
            if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                U256::from_str_radix(if h.is_empty() { "0" } else { h }, 16)
                    .map_err(|e| format!("{label}: bad hex u256: {e}"))
            } else {
                U256::from_str_radix(s, 10).map_err(|e| format!("{label}: bad u256: {e}"))
            }
        }
        _ => Err(format!("{label}: expected number or string")),
    }
}

pub(super) fn parse_hex_bytes(s: &str, label: &str) -> Result<Vec<u8>, String> {
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| format!("{label}: missing 0x prefix"))?;
    if h.len() % 2 != 0 {
        return Err(format!("{label}: odd-length hex"));
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    let b = h.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("{label}: bad hex"))?;
        let lo = (b[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("{label}: bad hex"))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

pub(super) fn parse_b32(s: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex_bytes(s, label)?;
    if bytes.len() > 32 {
        return Err(format!("{label}: longer than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

pub(super) fn get<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a Value, String> {
    obj.get(key)
        .ok_or_else(|| format!("witness missing '{key}'"))
}

pub(super) fn parse_address20(value: &Value, label: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex_bytes(
        value
            .as_str()
            .ok_or_else(|| format!("{label}: not a string"))?,
        label,
    )?;
    if bytes.len() != 20 {
        return Err(format!("{label}: not 20 bytes"));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(super) fn hex0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
