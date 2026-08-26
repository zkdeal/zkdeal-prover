//! Benchmark suite driver.
//!
//! Each case proves its cold template once and then repeats the room proof,
//! writing every receipt as machine evidence under `ZKDEAL_SUITE_DIR`.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, Context, Result};

use crate::commands_v5::{cmd_prove_cold_template_v5, cmd_prove_room_v5};

fn machine_json(path: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create suite evidence directory")?;
    }
    let bytes = serde_json::to_vec_pretty(value).context("encode suite machine evidence")?;
    std::fs::write(path, bytes).context("write suite machine evidence")
}

fn safe_suite_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(crate) fn cmd_prove_room_suite_v5(raw: &str) -> Result<serde_json::Value> {
    let config: serde_json::Value =
        serde_json::from_str(raw).context("suite configuration is not JSON")?;
    let cases = config
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .context("suite cases are required")?;
    if cases.is_empty() || cases.len() > 32 {
        bail!("suite must contain between one and 32 cases");
    }
    let root = PathBuf::from(
        std::env::var_os("ZKDEAL_SUITE_DIR")
            .context("ZKDEAL_SUITE_DIR is required for machine evidence")?,
    );
    std::fs::create_dir_all(&root).context("create suite evidence root")?;
    let started = Instant::now();
    let alternating = config
        .get("schedule")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|schedule| schedule == "alternating");
    if alternating {
        let mut prepared = Vec::with_capacity(cases.len());
        let mut common_samples = None;
        for case in cases {
            let name = case
                .get("name")
                .and_then(serde_json::Value::as_str)
                .context("suite case name is required")?;
            if !safe_suite_name(name) {
                bail!("suite case name must be short printable ASCII");
            }
            let samples = case
                .get("samples")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1);
            if samples == 0 || samples > 20 {
                bail!("suite case sample count is outside 1 through 20");
            }
            if let Some(expected) = common_samples {
                if samples != expected {
                    bail!("alternating suite cases must use the same sample count");
                }
            } else {
                common_samples = Some(samples);
            }
            let directory = root.join(name);
            let cold_raw = std::fs::read_to_string(directory.join("cold-request.json"))
                .with_context(|| format!("{name} cold request is unavailable"))?;
            let room_raw = std::fs::read_to_string(directory.join("room-request.json"))
                .with_context(|| format!("{name} room request is unavailable"))?;
            let cold = cmd_prove_cold_template_v5(&cold_raw)
                .with_context(|| format!("{name} cold-template proof failed"))?;
            machine_json(&directory.join("cold-proof.json"), &cold)?;
            if case
                .get("warmup")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                let receipt = cmd_prove_room_v5(&room_raw)
                    .with_context(|| format!("{name} warmup proof failed"))?;
                machine_json(&directory.join("warmup.json"), &receipt)?;
            }
            prepared.push((name.to_owned(), directory, room_raw, Vec::new()));
        }
        for index in 1..=common_samples.unwrap_or(1) {
            for (name, directory, room_raw, timings) in &mut prepared {
                let receipt = cmd_prove_room_v5(room_raw)
                    .with_context(|| format!("{name} measured proof {index} failed"))?;
                let total = receipt
                    .pointer("/profile/totalPipelineMs")
                    .and_then(serde_json::Value::as_f64)
                    .context("measured receipt has no complete pipeline timing")?;
                machine_json(&directory.join(format!("measured-{index}.json")), &receipt)?;
                timings.push(total);
            }
        }
        let summary = prepared
            .into_iter()
            .map(|(name, _, _, timings)| {
                serde_json::json!({
                    "name": name,
                    "samples": timings.len(),
                    "completePipelineMs": timings
                })
            })
            .collect::<Vec<_>>();
        return Ok(serde_json::json!({
            "decision": "SUITE_COMPLETED",
            "schedule": "alternating",
            "proofMode": "groth16",
            "cpuFallback": false,
            "cases": summary,
            "profile": {
                "totalPipelineMs": started.elapsed().as_secs_f64() * 1000.0
            }
        }));
    }
    let mut summary = Vec::with_capacity(cases.len());
    for case in cases {
        let name = case
            .get("name")
            .and_then(serde_json::Value::as_str)
            .context("suite case name is required")?;
        if !safe_suite_name(name) {
            bail!("suite case name must be short printable ASCII");
        }
        let samples = case
            .get("samples")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1);
        if samples == 0 || samples > 20 {
            bail!("suite case sample count is outside 1 through 20");
        }
        let warmup = case
            .get("warmup")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let directory = root.join(name);
        let cold_raw = std::fs::read_to_string(directory.join("cold-request.json"))
            .with_context(|| format!("{name} cold request is unavailable"))?;
        let room_raw = std::fs::read_to_string(directory.join("room-request.json"))
            .with_context(|| format!("{name} room request is unavailable"))?;

        let cold = cmd_prove_cold_template_v5(&cold_raw)
            .with_context(|| format!("{name} cold-template proof failed"))?;
        machine_json(&directory.join("cold-proof.json"), &cold)?;
        if warmup {
            let receipt = cmd_prove_room_v5(&room_raw)
                .with_context(|| format!("{name} warmup proof failed"))?;
            machine_json(&directory.join("warmup.json"), &receipt)?;
        }
        let mut timings = Vec::with_capacity(samples as usize);
        for index in 1..=samples {
            let receipt = cmd_prove_room_v5(&room_raw)
                .with_context(|| format!("{name} measured proof {index} failed"))?;
            let total = receipt
                .pointer("/profile/totalPipelineMs")
                .and_then(serde_json::Value::as_f64)
                .context("measured receipt has no complete pipeline timing")?;
            machine_json(&directory.join(format!("measured-{index}.json")), &receipt)?;
            timings.push(total);
        }
        summary.push(serde_json::json!({
            "name": name,
            "samples": samples,
            "completePipelineMs": timings
        }));
    }
    Ok(serde_json::json!({
        "decision": "SUITE_COMPLETED",
        "proofMode": "groth16",
        "cpuFallback": false,
        "cases": summary,
        "profile": {
            "totalPipelineMs": started.elapsed().as_secs_f64() * 1000.0
        }
    }))
}
