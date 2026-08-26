//! NVIDIA probing, per-proof telemetry sampling and the production GPU gate.
//!
//! Production proving may never silently fall back to a CPU, so every field
//! reported here is observed from the local driver rather than configured.

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

/// `/healthz` and `/v5/capabilities` are unauthenticated and every field they
/// report costs an `nvidia-smi` subprocess spawn plus wait. Sampling at most
/// once per window keeps a request burst from parking runtime threads in
/// `waitpid`, while staying short enough that a GPU that disappears still
/// fails the very next health check.
const GPU_PROBE_TTL: Duration = Duration::from_secs(2);
static GPU_PROBE_CACHE: Mutex<BTreeMap<String, (Instant, Option<String>)>> =
    Mutex::new(BTreeMap::new());

fn nvidia_query(field: &str) -> Option<String> {
    if let Ok(cache) = GPU_PROBE_CACHE.lock() {
        if let Some((sampled, value)) = cache.get(field) {
            if sampled.elapsed() < GPU_PROBE_TTL {
                return value.clone();
            }
        }
    }
    let value = nvidia_query_uncached(field);
    if let Ok(mut cache) = GPU_PROBE_CACHE.lock() {
        cache.insert(field.to_owned(), (Instant::now(), value.clone()));
    }
    value
}

fn nvidia_query_uncached(field: &str) -> Option<String> {
    let out = Command::new("nvidia-smi")
        .args([
            &format!("--query-gpu={field}"),
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

pub(crate) fn gpu_uuid() -> Option<String> {
    nvidia_query("uuid")
}

pub(crate) fn driver_version() -> Option<String> {
    nvidia_query("driver_version")
}

pub(crate) fn cuda_version() -> Option<String> {
    std::env::var("CUDA_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub(crate) fn gpu_name() -> Option<String> {
    nvidia_query("name")
}

/// One driver sample for the unauthenticated `/metrics` route:
/// `(utilization %, memory used MiB, power draw W)`. The combined field list
/// is a single `GPU_PROBE_CACHE` entry, so a scrape burst costs at most one
/// `nvidia-smi` spawn per `GPU_PROBE_TTL` window; the TTL already sits above
/// the telemetry emission floor and must not be lowered for scraping.
pub(crate) fn gpu_metrics_sample() -> Option<(f64, f64, f64)> {
    let line = nvidia_query("utilization.gpu,memory.used,power.draw")?;
    let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
    if fields.len() != 3 {
        return None;
    }
    Some((
        fields[0].parse().ok()?,
        fields[1].parse().ok()?,
        fields[2].parse().ok()?,
    ))
}

pub(crate) fn production_requested(request: &serde_json::Value) -> bool {
    request
        .get("production")
        .and_then(|x| x.as_bool())
        .unwrap_or(false)
        || std::env::var("ZKDEAL_PRODUCTION").is_ok_and(|v| v == "1")
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GpuTelemetrySamples {
    pub(crate) gpu_name: Option<String>,
    pub(crate) utilization_percent: Vec<f64>,
    pub(crate) vram_mib: Vec<f64>,
    pub(crate) power_w: Vec<f64>,
}

fn query_gpu_telemetry_sample() -> Option<(String, f64, f64, f64)> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,utilization.gpu,memory.used,power.draw",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .next()?
        .to_owned();
    let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
    if fields.len() != 4 {
        return None;
    }
    Some((
        fields[0].to_owned(),
        fields[1].parse().ok()?,
        fields[2].parse().ok()?,
        fields[3].parse().ok()?,
    ))
}

pub(crate) struct GpuTelemetrySampler {
    required: bool,
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<GpuTelemetrySamples>>,
    thread: Option<JoinHandle<()>>,
}

impl GpuTelemetrySampler {
    pub(crate) fn start(required: bool) -> Result<Self> {
        let initial = query_gpu_telemetry_sample();
        if required && initial.is_none() {
            bail!("production proving refused: GPU telemetry sampling is unavailable");
        }
        let mut samples = GpuTelemetrySamples::default();
        if let Some((name, utilization, vram, power)) = initial {
            samples.gpu_name = Some(name);
            samples.utilization_percent.push(utilization);
            samples.vram_mib.push(vram);
            samples.power_w.push(power);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Mutex::new(samples));
        let thread_stop = Arc::clone(&stop);
        let thread_samples = Arc::clone(&shared);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(250));
                if let Some((name, utilization, vram, power)) = query_gpu_telemetry_sample() {
                    if let Ok(mut samples) = thread_samples.lock() {
                        samples.gpu_name.get_or_insert(name);
                        samples.utilization_percent.push(utilization);
                        samples.vram_mib.push(vram);
                        samples.power_w.push(power);
                    }
                }
            }
        });
        Ok(Self {
            required,
            stop,
            samples: shared,
            thread: Some(thread),
        })
    }

    pub(crate) fn finish(mut self) -> Result<GpuTelemetrySamples> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow!("GPU telemetry sampler panicked"))?;
        }
        let samples = self
            .samples
            .lock()
            .map_err(|_| anyhow!("GPU telemetry sampler mutex poisoned"))?
            .clone();
        let aligned = samples.utilization_percent.len() == samples.vram_mib.len()
            && samples.vram_mib.len() == samples.power_w.len();
        if self.required
            && (!aligned
                || samples.utilization_percent.is_empty()
                || samples.gpu_name.as_deref().is_none_or(str::is_empty))
        {
            bail!("production proof completed without valid aligned GPU telemetry");
        }
        Ok(samples)
    }
}

impl Drop for GpuTelemetrySampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Production proving may never silently use a CPU, IPC service, or Bonsai.
/// Build-time CUDA support and runtime NVIDIA visibility are both required.
pub(crate) fn enforce_production_gpu(request: &serde_json::Value) -> Result<Option<String>> {
    let production = production_requested(request);
    if !production {
        return Ok(gpu_uuid());
    }
    if !cfg!(feature = "production") || !cfg!(feature = "cuda") {
        bail!(
            "production proving refused: zkdeal-r0 was not built with --features production (CUDA)"
        );
    }
    if let Ok(provider) = std::env::var("RISC0_PROVER") {
        if provider != "local" {
            bail!("production proving refused: RISC0_PROVER must be 'local', got '{provider}'");
        }
    }
    let uuid = gpu_uuid().context(
        "production proving refused: nvidia-smi found no CUDA GPU; CPU fallback is disabled",
    )?;
    Ok(Some(uuid))
}
