//! Official Osaka EEST state-test runner for the shipped revm/stf-core path.
//!
//! Input and output are JSONL so the TypeScript gate can execute the same
//! authoritative pre-state, environment, and signed transaction bytes in
//! @ethereumjs/vm and revm without translating them into room-specific data.

use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
};

use alloy_consensus::{transaction::SignerRecoverable, Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{hex, Address, Bytes, B256, U256};
use revm::{
    context::BlockEnv,
    context_interface::{block::BlobExcessGasAndPrice, ContextTr},
    handler::{evm::EvmTr, MainBuilder, MainContext},
    primitives::{eip4844::BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE, hardfork::SpecId},
    Context, InspectCommitEvm,
};
use serde::Deserialize;
use serde_json::{json, Value};
use stf_core::{AccountRecord, OsakaSemanticInspector, StateMap};

const GAS_CAP_EXCEPTION: &str = "TransactionException.GAS_LIMIT_EXCEEDS_MAXIMUM";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EestInput {
    id: String,
    chain_id: String,
    env: EestEnv,
    pre: BTreeMap<Address, EestAccount>,
    txbytes: Bytes,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EestEnv {
    current_coinbase: Address,
    current_gas_limit: String,
    current_number: String,
    current_timestamp: String,
    current_random: B256,
    current_difficulty: String,
    current_base_fee: String,
    current_excess_blob_gas: String,
}

#[derive(Debug, Deserialize)]
struct EestAccount {
    nonce: String,
    balance: String,
    code: Bytes,
    storage: BTreeMap<String, String>,
}

fn hex_u64(value: &str, label: &str) -> Result<u64, String> {
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)
        .map_err(|error| format!("{label}: {error}"))
}

fn hex_u256(value: &str, label: &str) -> Result<U256, String> {
    U256::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)
        .map_err(|error| format!("{label}: {error}"))
}

fn state_from_pre(pre: BTreeMap<Address, EestAccount>) -> Result<StateMap, String> {
    let mut accounts = BTreeMap::new();
    for (address, input) in pre {
        let mut storage = BTreeMap::new();
        for (slot, value) in input.storage {
            let slot = hex_u256(&slot, "storage slot")?;
            let value = hex_u256(&value, "storage value")?;
            if !value.is_zero() {
                storage.insert(slot, value);
            }
        }
        accounts.insert(
            address,
            AccountRecord {
                nonce: hex_u64(&input.nonce, "account nonce")?,
                balance: hex_u256(&input.balance, "account balance")?,
                code: input.code,
                storage,
            },
        );
    }
    Ok(StateMap {
        accounts,
        block_hashes: Default::default(),
        access_accounts: None,
        access_storage: None,
        access_violation: None,
        prepared_code: Default::default(),
        prepared_code_addresses: Default::default(),
        access_metrics: Default::default(),
    })
}

fn decode_tx(raw: &[u8]) -> Result<revm::context::TxEnv, String> {
    if matches!(raw.first(), Some(0x03 | 0x04)) {
        return Err(format!("unsupported EEST envelope 0x{:02x}", raw[0]));
    }
    let envelope = TxEnvelope::decode_2718(&mut &raw[..])
        .map_err(|error| format!("transaction decode: {error}"))?;
    match &envelope {
        TxEnvelope::Legacy(_) | TxEnvelope::Eip2930(_) | TxEnvelope::Eip1559(_) => {}
        other => {
            return Err(format!(
                "unsupported EEST envelope 0x{:02x}",
                other.tx_type() as u8
            ))
        }
    }
    if envelope.nonce() == u64::MAX {
        return Err("transaction nonce is max".into());
    }
    let caller = envelope
        .recover_signer()
        .map_err(|error| format!("transaction signer: {error}"))?;
    Ok(revm::context::TxEnv {
        tx_type: envelope.tx_type() as u8,
        caller,
        gas_limit: envelope.gas_limit(),
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

fn result_value(
    accepted: bool,
    post_state_root: B256,
    exception: Option<&str>,
    gas_used: Option<u64>,
    error: Option<String>,
) -> Value {
    let mut result = json!({
        "accepted": accepted,
        "postStateRoot": format!("{post_state_root}")
    });
    if let Some(exception) = exception {
        result["exception"] = json!(exception);
    }
    if let Some(gas_used) = gas_used {
        result["gasUsed"] = json!(format!("0x{gas_used:x}"));
    }
    if let Some(error) = error {
        result["error"] = json!(error);
    }
    result
}

fn execute(input: EestInput) -> Result<Value, String> {
    let input_id = input.id.clone();
    let chain_id = hex_u64(&input.chain_id, "chain id")?;
    let state = state_from_pre(input.pre)?;
    let block_env = BlockEnv {
        number: U256::from(hex_u64(&input.env.current_number, "block number")?),
        beneficiary: input.env.current_coinbase,
        timestamp: U256::from(hex_u64(&input.env.current_timestamp, "timestamp")?),
        gas_limit: hex_u64(&input.env.current_gas_limit, "block gas limit")?,
        basefee: hex_u64(&input.env.current_base_fee, "base fee")?,
        difficulty: hex_u256(&input.env.current_difficulty, "difficulty")?,
        prevrandao: Some(input.env.current_random),
        blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new(
            hex_u64(&input.env.current_excess_blob_gas, "excess blob gas")?,
            BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
        )),
        slot_num: 0,
    };
    let tx = match decode_tx(&input.txbytes) {
        Ok(tx) => tx,
        Err(error) => {
            let exception = if error.contains("transaction nonce is max") {
                "TransactionException.NONCE_IS_MAX"
            } else if error.contains("Unexpected type flag. Got 0") {
                // Alloy rejects the overflowing legacy fee product while
                // decoding it. The official fixture permits either an
                // insufficient-funds or explicit fee-product-overflow result.
                "TransactionException.GASLIMIT_PRICE_PRODUCT_OVERFLOW"
            } else {
                "revm:HARNESS_ERROR"
            };
            return Ok(json!({
                "id": input_id,
                "result": result_value(
                    false,
                    state.state_root(),
                    Some(exception),
                    None,
                    Some(error),
                )
            }));
        }
    };
    let ctx = Context::mainnet()
        .with_db(state)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.set_spec_and_mainnet_gas_params(SpecId::OSAKA);
        })
        .modify_block_chained(|block| *block = block_env);
    let mut evm = ctx.build_mainnet_with_inspector(OsakaSemanticInspector);
    let execution = evm.inspect_tx_commit(tx);
    let post_state = evm.ctx_mut().db_mut().clone();
    let root = post_state.state_root();
    let result = match execution {
        Ok(execution) => result_value(true, root, None, Some(execution.gas_used()), None),
        Err(error) => {
            let detail = format!("{error:?}");
            let exception = if detail.contains("TxGasLimitGreaterThanCap") {
                GAS_CAP_EXCEPTION
            } else if detail.contains("CallGasCostMoreThanGasLimit") {
                "TransactionException.INTRINSIC_GAS_TOO_LOW"
            } else if detail.contains("GasFloorMoreThanGasLimit") {
                "TransactionException.INTRINSIC_GAS_BELOW_FLOOR_GAS_COST"
            } else if detail.contains("CreateInitCodeSizeLimit") {
                "TransactionException.INITCODE_SIZE_EXCEEDED"
            } else if detail.contains("GasPriceLessThanBasefee") {
                "TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS"
            } else if detail.contains("CallerGasLimitMoreThanBlock") {
                "TransactionException.GAS_ALLOWANCE_EXCEEDED"
            } else if detail.contains("LackOfFundForMaxFee") {
                "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS"
            } else if detail.contains("PriorityFeeGreaterThanMaxFee") {
                "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS"
            } else if detail.contains("RejectCallerWithCode") {
                "TransactionException.SENDER_NOT_EOA"
            } else {
                "revm:UNMAPPED_TRANSACTION_EXCEPTION"
            };
            result_value(false, root, Some(exception), None, Some(detail))
        }
    };
    let mut output = json!({ "id": input_id, "result": result });
    if std::env::var("EEST_STATE_DETAILS").as_deref() == Ok("1") {
        let summary = post_state
            .accounts
            .iter()
            .map(|(address, account)| {
                (
                    format!("{address}"),
                    json!({
                        "exists": true,
                        "nonce": account.nonce.to_string(),
                        "balance": account.balance.to_string(),
                        "code": format!("0x{}", hex::encode(&account.code)),
                        "storage": account.storage.iter().map(|(slot, value)| {
                            (format!("{slot:#x}"), format!("{value:#x}"))
                        }).collect::<BTreeMap<_, _>>()
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        output["result"]["stateSummary"] = json!(summary);
    }
    Ok(output)
}

fn run_line(line: &str) -> Value {
    match serde_json::from_str::<EestInput>(line) {
        Ok(input) => {
            let id = input.id.clone();
            match execute(input) {
                Ok(result) => result,
                Err(error) => json!({ "id": id, "result": {
                    "accepted": false,
                    "postStateRoot": format!("{}", B256::ZERO),
                    "exception": "revm:HARNESS_ERROR",
                    "error": error
                }}),
            }
        }
        Err(error) => json!({ "id": null, "result": {
            "accepted": false,
            "postStateRoot": format!("{}", B256::ZERO),
            "exception": "revm:HARNESS_ERROR",
            "error": format!("input decode: {error}")
        }}),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        serde_json::to_writer(&mut stdout, &run_line(&line))?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
