//! Raw signed tx (RLP / EIP-2718) -> revm TxEnv, mirroring the engine's
//! room tx policy: legacy / EIP-2930 / EIP-1559 only, free gas.

use alloy_consensus::{transaction::SignerRecoverable, Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use revm::context::TxEnv;

use crate::StfError;

/// Decode one raw tx into a revm `TxEnv` and enforce the documented L2
/// admission policy.
///
/// `expected_chain_id` is checked here (not only inside revm) so a proof of a
/// block containing another chain's transaction is impossible, and the
/// free-gas rule is enforced rather than forwarded: the ethereumjs sequencer
/// rejects fee-bearing txs, so a guest that accepts them would make a valid
/// statement about a block outside the L2 profile.
pub fn tx_env_from_raw(raw: &[u8], expected_chain_id: u64) -> Result<TxEnv, StfError> {
    // EIP-2718 type bytes are unambiguous. Reject unsupported envelopes before
    // decoding so even truncated/adversarial blob (0x03) and EIP-7702 (0x04)
    // payloads fail with the policy error instead of a generic RLP error.
    if matches!(raw.first(), Some(0x03 | 0x04)) {
        return Err(StfError::UnsupportedTx(raw[0]));
    }
    // Canonical-identity: a forced tx's keccak identity is committed over the
    // exact bytes L1 accepted, so trailing garbage after a valid envelope must
    // be undecodable, not a silently-accepted alias. `decode_2718` advances the
    // slice and ignores trailing bytes, so decode into a cursor and reject any
    // unconsumed tail. Without this, `canonical` and `canonical || garbage`
    // would decode to the same tx yet carry different keccak identities, and a
    // hostile `forceTransaction(canonical || garbage)` would be undischargeable
    // (its identity is over the full bytes; the mirror can only yield reason 1).
    let mut buf: &[u8] = raw;
    let envelope =
        TxEnvelope::decode_2718(&mut buf).map_err(|e| StfError::TxDecode(format!("{e}")))?;
    if !buf.is_empty() {
        return Err(StfError::TxDecode(format!(
            "{} trailing byte(s) after the transaction envelope",
            buf.len()
        )));
    }

    match &envelope {
        TxEnvelope::Legacy(_) | TxEnvelope::Eip2930(_) | TxEnvelope::Eip1559(_) => {}
        other => return Err(StfError::UnsupportedTx(other.tx_type() as u8)),
    }
    if envelope.nonce() == u64::MAX {
        return Err(StfError::TxDecode(
            "transaction nonce cannot equal the uint64 maximum".into(),
        ));
    }

    // Free-gas L2: base fee is 0 and the engine's admission policy rejects any
    // non-zero fee field. max_fee_per_gas is gasPrice for legacy/2930.
    if envelope.max_fee_per_gas() != 0 {
        return Err(StfError::FeePolicy(format!(
            "non-zero gas price / maxFeePerGas: {}",
            envelope.max_fee_per_gas()
        )));
    }
    if envelope.max_priority_fee_per_gas().unwrap_or(0) != 0 {
        return Err(StfError::FeePolicy(format!(
            "non-zero maxPriorityFeePerGas: {}",
            envelope.max_priority_fee_per_gas().unwrap_or(0)
        )));
    }
    match envelope.chain_id() {
        // Pre-EIP-155 legacy txs carry no chain id and are replayable across
        // chains — never admissible in a room.
        None => {
            return Err(StfError::ChainId {
                expected: expected_chain_id,
                got: None,
            })
        }
        Some(id) if id != expected_chain_id => {
            return Err(StfError::ChainId {
                expected: expected_chain_id,
                got: Some(id),
            })
        }
        Some(_) => {}
    }

    let caller = envelope
        .recover_signer()
        .map_err(|e| StfError::TxDecode(format!("signer recovery: {e}")))?;

    Ok(TxEnv {
        tx_type: envelope.tx_type() as u8,
        caller,
        gas_limit: envelope.gas_limit(),
        // For legacy/2930 this is gasPrice; for 1559 it is maxFeePerGas.
        gas_price: envelope.max_fee_per_gas(),
        kind: envelope.kind(),
        value: envelope.value(),
        data: envelope.input().clone(),
        nonce: envelope.nonce(),
        chain_id: envelope.chain_id(),
        access_list: envelope.access_list().cloned().unwrap_or_default(),
        gas_priority_fee: envelope.max_priority_fee_per_gas(),
        ..Default::default()
    })
}
