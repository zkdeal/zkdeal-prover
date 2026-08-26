#![recursion_limit = "256"]

//! zkdeal-r0 persistent CUDA proof service and human CLI.
//!
//! The production image exposes the v5 long-lived room and cold-template
//! statements. The HTTP service is the machine API; public CLI commands save
//! machine artifacts only to an explicit result path.
//!
//! Env: SEGMENT_PO2 caps segment size (memory/latency knob; S2 measured
//! ~4.8 GiB peak at po2 20).
//!
//! stdout and stderr contain printable human decisions only.
//!
//! This file is the command dispatcher only. The work lives in `receipt`
//! (prover session and receipt binding), `gpu` (driver probing and the
//! production gate), `witness` (v5 witness framing), `commands_v5` and
//! `wrap_v5` (the commands themselves), `suite_v5`, `capabilities`, `http`
//! and `report` (human and machine output).

mod capabilities;
mod commands_v5;
mod gpu;
mod hosting;
mod http;
mod live_prepare;
mod receipt;
mod report;
mod suite_v5;
mod v5_fixture;
mod witness;
mod wrap_v5;

use anyhow::{bail, Context, Result};
use r0_methods::STF_GUEST_ID;
use risc0_zkvm::sha::Digest;

use crate::capabilities::{cmd_capabilities, cmd_health};
use crate::commands_v5::{
    cmd_execute_cold_template_v5, cmd_execute_room_v5, cmd_prove_cold_template_v5,
    cmd_prove_room_v5, cmd_verify_cold_template_v5, cmd_verify_room_v5,
};
use crate::http::serve_v5;
use crate::live_prepare::cmd_prepare_live_room_batch;
use crate::hosting::{
    cmd_execute_aggregate_v1, cmd_execute_data_availability_v1,
    cmd_prepare_data_availability_v1, cmd_prove_aggregate_v1,
    cmd_prove_data_availability_v1, cmd_verify_aggregate_v1,
    cmd_verify_data_availability_v1,
};
use crate::receipt::image_id_hex;
use crate::report::{print_human_result, read_stdin, safe_failure_reason, write_machine_result};
use crate::suite_v5::cmd_prove_room_suite_v5;
use crate::wrap_v5::{
    cmd_wrap_groth16_from_p254_v5, cmd_wrap_groth16_v5, cmd_wrap_identity_p254_v5,
};

pub(crate) const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn run() -> Result<()> {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    if cfg!(feature = "client-verifier")
        && matches!(
            cmd.as_str(),
            "prove-room-v5"
                | "prove-cold-template-v5"
                | "wrap-groth16-v5"
                | "wrap-identity-p254-v5"
                | "wrap-groth16-from-p254-v5"
                | "prove-room-suite-v5"
                | "prove-data-availability-v1"
                | "prove-aggregate-v1"
                | "serve"
                | "health"
        )
    {
        bail!("'{cmd}' is disabled in the verifier-only client binary");
    }
    match cmd.as_str() {
        "imageid" => {
            let value = serde_json::json!({
                "programId": format!("0x{}", image_id_hex())
            });
            let saved = write_machine_result(&cmd, &value)?;
            print_human_result(&cmd, &value, saved.as_ref());
            Ok(())
        }
        "capabilities" => {
            let value = cmd_capabilities();
            let saved = write_machine_result(&cmd, &value)?;
            print_human_result(&cmd, &value, saved.as_ref());
            Ok(())
        }
        "health" => {
            let value = cmd_health()?;
            let saved = write_machine_result(&cmd, &value)?;
            print_human_result(&cmd, &value, saved.as_ref());
            Ok(())
        }
        "prove-room-suite-v5" => {
            let raw = read_stdin()?;
            let value = cmd_prove_room_suite_v5(&raw)?;
            let saved = write_machine_result(&cmd, &value)?;
            print_human_result(&cmd, &value, saved.as_ref());
            Ok(())
        }
        "prepare-data-availability-v1"
        | "execute-data-availability-v1"
        | "prove-data-availability-v1"
        | "verify-data-availability-v1"
        | "execute-aggregate-v1"
        | "prove-aggregate-v1"
        | "verify-aggregate-v1" => {
            let raw = read_stdin()?;
            let out = match cmd.as_str() {
                "prepare-data-availability-v1" => cmd_prepare_data_availability_v1(&raw)?,
                "execute-data-availability-v1" => cmd_execute_data_availability_v1(&raw)?,
                "prove-data-availability-v1" => cmd_prove_data_availability_v1(&raw)?,
                "verify-data-availability-v1" => cmd_verify_data_availability_v1(&raw)?,
                "execute-aggregate-v1" => cmd_execute_aggregate_v1(&raw)?,
                "prove-aggregate-v1" => cmd_prove_aggregate_v1(&raw)?,
                "verify-aggregate-v1" => cmd_verify_aggregate_v1(&raw)?,
                _ => unreachable!("hosting command list is exhaustive"),
            };
            let saved = write_machine_result(&cmd, &out)?;
            print_human_result(&cmd, &out, saved.as_ref());
            Ok(())
        }
        "serve" => serve_v5(),
        "prepare-live-room-batch" => {
            let raw = read_stdin()?;
            let out = cmd_prepare_live_room_batch(&raw)?;
            let saved = write_machine_result(&cmd, &out)?;
            print_human_result(&cmd, &out, saved.as_ref());
            Ok(())
        }
        "prepare-room-v5" | "prepare-cold-template-v5" | "prepare-room-batch-v5" => {
            let raw = read_stdin()?;
            if std::env::var_os("ZKDEAL_RESULT_PATH").is_none() {
                bail!(
                    "fixture output path is required; set ZKDEAL_RESULT_PATH so machine evidence is preserved"
                );
            }
            let image_id = Digest::new(STF_GUEST_ID);
            let prepared = v5_fixture::prepare(
                &raw,
                image_id
                    .as_bytes()
                    .try_into()
                    .expect("RISC Zero image IDs are 32 bytes"),
            )?;
            let out = match cmd.as_str() {
                "prepare-cold-template-v5" => prepared
                    .get("coldRequest")
                    .cloned()
                    .context("prepared cold-template request is missing")?,
                "prepare-room-batch-v5" => prepared
                    .get("roomRequest")
                    .cloned()
                    .context("prepared room request is missing")?,
                _ => prepared,
            };
            let saved = write_machine_result(&cmd, &out)?;
            print_human_result(&cmd, &out, saved.as_ref());
            Ok(())
        }
        "execute-room-v5"
        | "prove-room-v5"
        | "verify-room-v5"
        | "execute-cold-template-v5"
        | "prove-cold-template-v5"
        | "verify-cold-template-v5"
        | "wrap-groth16-v5"
        | "wrap-identity-p254-v5"
        | "wrap-groth16-from-p254-v5" => {
            let raw = read_stdin()?;
            let out = match cmd.as_str() {
                "execute-room-v5" => cmd_execute_room_v5(&raw)?,
                "prove-room-v5" => cmd_prove_room_v5(&raw)?,
                "verify-room-v5" => cmd_verify_room_v5(&raw)?,
                "execute-cold-template-v5" => cmd_execute_cold_template_v5(&raw)?,
                "prove-cold-template-v5" => cmd_prove_cold_template_v5(&raw)?,
                "verify-cold-template-v5" => cmd_verify_cold_template_v5(&raw)?,
                "wrap-groth16-v5" => cmd_wrap_groth16_v5(&raw)?,
                "wrap-identity-p254-v5" => cmd_wrap_identity_p254_v5(&raw)?,
                "wrap-groth16-from-p254-v5" => cmd_wrap_groth16_from_p254_v5(&raw)?,
                _ => unreachable!("v5 command list is exhaustive"),
            };
            let saved = write_machine_result(&cmd, &out)?;
            print_human_result(&cmd, &out, saved.as_ref());
            Ok(())
        }
        other => bail!("unknown command '{other}'"),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Decision: Request rejected; no proof or state transition was produced.");
        eprintln!("Evidence: No machine payload or unverified receipt was printed.");
        eprintln!("Blocker: {}", safe_failure_reason(&error));
        eprintln!(
            "Next action: Check the witness, pinned program, CUDA readiness, and result path."
        );
        eprintln!("Evidence saved: None unless a private command-specific path was configured.");
        eprintln!("Resource budget: No successful proof slot was reported.");
        std::process::exit(1);
    }
}
