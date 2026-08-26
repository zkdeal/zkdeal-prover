//! The selector allow-list a prepared room certifies.
//!
//! Three sources feed it: `allowedSelectors` when the caller states one,
//! `blockCalls` when the host signs the calldata itself, and the selectors
//! recovered from `rawTransactions` when a client signed elsewhere. Whatever
//! the source, every selector the batch actually calls has to appear in the
//! list the policy commits to, or the room refuses its own batch.
//!
//! Rooms that bring per-contract `callRules` bypass all of this: their
//! selectors come from the rules, target by target.

use alloy_primitives::Bytes;
use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::json::{parse_hex_bytes, parse_selector};

/// One host-signed call. String entries use the legacy signer-zero/120k shape;
/// object entries opt into an explicit deterministic signer and gas limit.
#[derive(Clone, Debug)]
pub(super) struct FixtureBlockCall {
    pub(super) calldata: Bytes,
    pub(super) signer_index: u64,
    pub(super) gas_limit: u64,
}

/// The selector allow-list the prepared policy certifies, and the check that
/// every configured call stays inside it.
///
/// `client_selectors` are the selectors recovered from `rawTransactions`. They
/// are treated exactly like `blockCalls` selectors: they seed the allow-list
/// when the caller states none, and they must stay inside it when the caller
/// does. Without that, a client-signed room with no `callRules` would certify
/// the historic `0x12345678` placeholder and then be refused by its own policy.
pub(super) fn resolve_call_selectors(
    custom_call_blocks: &Option<Vec<Vec<FixtureBlockCall>>>,
    client_selectors: &[[u8; 4]],
    allowed_selectors: Option<Vec<[u8; 4]>>,
) -> Result<Vec<[u8; 4]>> {
    let call_selectors = allowed_selectors.unwrap_or_else(|| {
        let mut selectors = custom_call_blocks
            .as_ref()
            .map(|blocks| {
                blocks
                    .iter()
                    .flatten()
                    .map(|call| {
                        <[u8; 4]>::try_from(&call.calldata[..4])
                            .expect("custom calls have selectors")
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        selectors.extend_from_slice(client_selectors);
        if selectors.is_empty() {
            return vec![[0x12, 0x34, 0x56, 0x78]];
        }
        selectors.sort();
        selectors.dedup();
        selectors
    });
    if let Some(blocks) = custom_call_blocks {
        for selector in blocks.iter().flatten().map(|call| {
            <[u8; 4]>::try_from(&call.calldata[..4]).expect("custom calls have selectors")
        }) {
            if !call_selectors.contains(&selector) {
                bail!("blockCalls contains a selector outside allowedSelectors");
            }
        }
    }
    for selector in client_selectors {
        if !call_selectors.contains(selector) {
            bail!(
                "rawTransactions calls selector 0x{}, which is outside allowedSelectors",
                alloy_primitives::hex::encode(selector)
            );
        }
    }
    Ok(call_selectors)
}

pub(super) fn parse_optional_call_blocks(
    config: &Value,
) -> Result<Option<Vec<Vec<FixtureBlockCall>>>> {
    let Some(raw_blocks) = config.get("blockCalls") else {
        return Ok(None);
    };
    let blocks = raw_blocks
        .as_array()
        .context("blockCalls must be an array containing exactly two block arrays")?;
    if blocks.len() != 2 {
        bail!("blockCalls must contain exactly two room blocks");
    }
    let mut parsed = Vec::with_capacity(2);
    for (block_index, raw_block) in blocks.iter().enumerate() {
        let calls = raw_block
            .as_array()
            .with_context(|| format!("blockCalls[{block_index}] must be an array"))?;
        if calls.is_empty() || calls.len() > 32 {
            bail!("each blockCalls entry must contain between one and 32 calls");
        }
        let mut block = Vec::with_capacity(calls.len());
        for (call_index, call) in calls.iter().enumerate() {
            let label = format!("blockCalls[{block_index}][{call_index}]");
            let (calldata, signer_index, gas_limit) = if call.is_string() {
                (parse_hex_bytes(call, &label)?, 0, 120_000)
            } else {
                let object = call
                    .as_object()
                    .with_context(|| format!("{label} must be calldata hex or an object"))?;
                let calldata = parse_hex_bytes(
                    object
                        .get("calldata")
                        .with_context(|| format!("{label}.calldata is required"))?,
                    &format!("{label}.calldata"),
                )?;
                let signer_index = object
                    .get("signerIndex")
                    .map(|value| {
                        super::json::parse_u64_value(value, &format!("{label}.signerIndex"))
                    })
                    .transpose()?
                    .unwrap_or(0);
                let gas_limit = object
                    .get("gasLimit")
                    .map(|value| super::json::parse_u64_value(value, &format!("{label}.gasLimit")))
                    .transpose()?
                    .unwrap_or(120_000);
                (calldata, signer_index, gas_limit)
            };
            if calldata.len() < 4 {
                bail!("every custom call must include a four-byte selector");
            }
            if signer_index >= 16 {
                bail!("{label}.signerIndex must be between zero and fifteen");
            }
            if gas_limit == 0 || gas_limit > 5_000_000 {
                bail!("{label}.gasLimit must be between one and 5000000");
            }
            block.push(FixtureBlockCall {
                calldata,
                signer_index,
                gas_limit,
            });
        }
        parsed.push(block);
    }
    Ok(Some(parsed))
}

pub(super) fn parse_allowed_selectors(config: &Value) -> Result<Option<Vec<[u8; 4]>>> {
    let Some(raw_selectors) = config.get("allowedSelectors") else {
        return Ok(None);
    };
    let selectors = raw_selectors
        .as_array()
        .context("allowedSelectors must be an array")?;
    if selectors.is_empty() || selectors.len() > 64 {
        bail!("allowedSelectors must contain between one and 64 selectors");
    }
    let mut parsed = Vec::with_capacity(selectors.len());
    for (index, selector) in selectors.iter().enumerate() {
        parsed.push(parse_selector(
            selector,
            &format!("allowedSelectors[{index}]"),
        )?);
    }
    parsed.sort();
    parsed.dedup();
    Ok(Some(parsed))
}
