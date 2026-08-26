use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::{bail, Context, Result};
use risc0_zkvm::{
    default_prover,
    sha::{Impl, Sha256},
    ExecutorEnv, InnerReceipt, ProverOpts, Receipt,
};
use serde_json::json;
use zkdeal_composition_methods::{
    ZKDEAL_COLD_TEMPLATE_V4_ELF, ZKDEAL_COLD_TEMPLATE_V4_ID, ZKDEAL_HOT_SUFFIX_V4_ELF,
    ZKDEAL_HOT_SUFFIX_V4_ID,
};

const IMMUTABLE_TEMPLATE: &[u8] =
    b"zkdeal:v4:composition-spike:immutable-contracts+constructors+state-envelope";
const HOT_SUFFIX: &[u8] = b"zkdeal:v4:composition-spike:room+members+ordered-transactions+close";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputKind {
    Succinct,
    Groth16,
}

impl OutputKind {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "succinct" => Ok(Self::Succinct),
            "groth16" => Ok(Self::Groth16),
            other => bail!("unsupported output kind '{other}' (expected succinct|groth16)"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Succinct => "succinct",
            Self::Groth16 => "groth16",
        }
    }
}

fn main() -> Result<()> {
    let (output_kind, output_dir) = parse_args()?;
    let gpu = require_cuda_gpu()?;
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;

    let prover = default_prover();
    // The cache is keyed on the template digest as well as the image ID: the
    // image ID does not change when IMMUTABLE_TEMPLATE does, so keying on it
    // alone would silently reuse the previous template's journal.
    let cold_template_digest = Impl::hash_bytes(IMMUTABLE_TEMPLATE);
    let cache_path = output_dir.join(cold_cache_file_name(cold_template_digest.as_bytes()));

    let cold_stage_started = Instant::now();
    let cached_cold = load_cached_cold(&cache_path, cold_template_digest.as_bytes());
    // Only a cache hit actually loads and verifies a receipt; on a miss this
    // stage proves, compresses and writes instead, so the figure is null there.
    let cold_load_and_verify_ms = cached_cold.as_ref().map(|_| millis(cold_stage_started));
    let (cold_receipt, cold_cache_hit, cold_prove_ms, cold_compress_ms, cold_stats) =
        if let Some(receipt) = cached_cold {
            (receipt, true, 0.0, 0.0, None)
        } else {
            let env = ExecutorEnv::builder()
                .write(&IMMUTABLE_TEMPLATE.to_vec())?
                .build()?;
            let prove_started = Instant::now();
            let info = prover.prove_with_opts(
                env,
                ZKDEAL_COLD_TEMPLATE_V4_ELF,
                &ProverOpts::composite(),
            )?;
            let prove_ms = millis(prove_started);
            let stats = json!({
                "userCycles": info.stats.user_cycles,
                "totalCycles": info.stats.total_cycles,
                "segments": info.stats.segments,
            });
            let compress_started = Instant::now();
            let receipt = prover.compress(&ProverOpts::succinct(), &info.receipt)?;
            let compress_ms = millis(compress_started);
            receipt
                .verify(ZKDEAL_COLD_TEMPLATE_V4_ID)
                .context("new cold receipt failed verification")?;
            require_succinct(&receipt)?;
            require_cold_journal(&receipt.journal.bytes, cold_template_digest.as_bytes())?;
            atomic_write(&cache_path, &bincode::serialize(&receipt)?)?;
            (receipt, false, prove_ms, compress_ms, Some(stats))
        };
    let cold_stage_total_ms = millis(cold_stage_started);

    let suffix_env = ExecutorEnv::builder()
        .write(&ZKDEAL_COLD_TEMPLATE_V4_ID)?
        .write(&cold_receipt.journal.bytes)?
        .write(&HOT_SUFFIX.to_vec())?
        .add_assumption(cold_receipt.clone())
        .build()?;

    // Prove only the unique suffix as a composite receipt. Supplying the cached
    // receipt makes this result unconditional, but its assumption receipt still
    // has to be folded by recursion during the next compression step.
    let suffix_prove_started = Instant::now();
    let suffix_info = prover.prove_with_opts(
        suffix_env,
        ZKDEAL_HOT_SUFFIX_V4_ELF,
        &ProverOpts::composite(),
    )?;
    let suffix_prove_ms = millis(suffix_prove_started);
    suffix_info
        .receipt
        .verify(ZKDEAL_HOT_SUFFIX_V4_ID)
        .context("composite suffix receipt failed verification")?;

    // This compression performs lift/join for the suffix and one resolve step
    // against the cached cold succinct receipt. It does not rerun the cold guest
    // or regenerate the cold execution proof.
    let resolve_started = Instant::now();
    let resolved_succinct = prover.compress(&ProverOpts::succinct(), &suffix_info.receipt)?;
    let resolve_ms = millis(resolve_started);
    resolved_succinct
        .verify(ZKDEAL_HOT_SUFFIX_V4_ID)
        .context("resolved succinct receipt failed verification")?;
    require_succinct(&resolved_succinct)?;

    let (final_receipt, groth16_ms) = match output_kind {
        OutputKind::Succinct => (resolved_succinct, 0.0),
        OutputKind::Groth16 => {
            let started = Instant::now();
            let receipt = prover.compress(&ProverOpts::groth16(), &resolved_succinct)?;
            (receipt, millis(started))
        }
    };
    final_receipt
        .verify(ZKDEAL_HOT_SUFFIX_V4_ID)
        .context("final receipt failed verification")?;

    let final_receipt_bytes = bincode::serialize(&final_receipt)?;
    let receipt_path = output_dir.join(format!("final-{}.receipt.bin", output_kind.as_str()));
    atomic_write(&receipt_path, &final_receipt_bytes)?;
    let (ethereum_seal_path, ethereum_seal_bytes) = if output_kind == OutputKind::Groth16 {
        let seal = encode_ethereum_seal(&final_receipt)?;
        let path = output_dir.join("final-groth16.ethereum-seal.bin");
        atomic_write(&path, &seal)?;
        (Some(path.display().to_string()), seal.len())
    } else {
        (None, 0)
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "risc0Version": "3.0.6",
            "outputKind": output_kind.as_str(),
            "gpu": gpu,
            "cold": {
                "cacheHit": cold_cache_hit,
                "cachePath": cache_path.display().to_string(),
                "cacheBytes": fs::metadata(&cache_path)?.len(),
                "loadAndVerifyMs": cold_load_and_verify_ms,
                "stageTotalMs": cold_stage_total_ms,
                "proveCompositeMs": cold_prove_ms,
                "compressToSuccinctMs": cold_compress_ms,
                "stats": cold_stats,
                "imageId": hex::encode(risc0_zkvm::sha::Digest::new(ZKDEAL_COLD_TEMPLATE_V4_ID).as_bytes()),
                "journalBytes": cold_receipt.journal.bytes.len(),
            },
            "hotSuffix": {
                "proveCompositeMs": suffix_prove_ms,
                "resolveToSuccinctMs": resolve_ms,
                "groth16WrapMs": groth16_ms,
                "stats": {
                    "userCycles": suffix_info.stats.user_cycles,
                    "totalCycles": suffix_info.stats.total_cycles,
                    "segments": suffix_info.stats.segments,
                },
                "imageId": hex::encode(risc0_zkvm::sha::Digest::new(ZKDEAL_HOT_SUFFIX_V4_ID).as_bytes()),
            },
            "final": {
                "receiptPath": receipt_path.display().to_string(),
                "receiptBytes": final_receipt_bytes.len(),
                "journalBytes": final_receipt.journal.bytes.len(),
                "ethereumSealPath": ethereum_seal_path,
                "ethereumSealBytes": ethereum_seal_bytes,
            },
            "interpretation": {
                "coldExecutionReproved": false,
                "perFinalResolvePaid": true,
                "groth16WrapPaidPerFinal": output_kind == OutputKind::Groth16,
            }
        }))?
    );
    Ok(())
}

#[cfg(feature = "cuda")]
fn require_cuda_gpu() -> Result<String> {
    // `default_prover()` branches on RISC0_PROVER before anything else: `ipc`
    // and `actor` prove in an out-of-process r0vm of unknown build (located via
    // RISC0_SERVER_PATH) and `bonsai` proves off-machine entirely, while the
    // emitted JSON still credits the GPU nvidia-smi reports here. Only
    // in-process local proving is measurable, so refuse the rest.
    let prover = env::var("RISC0_PROVER").unwrap_or_default();
    if !prover.is_empty() && !prover.eq_ignore_ascii_case("local") {
        bail!("RISC0_PROVER={prover} redirects proving away from this process; unset it and rerun");
    }
    if env::var_os("RISC0_SERVER_PATH").is_some() {
        bail!("RISC0_SERVER_PATH is set; it only selects an external r0vm, so unset it and rerun");
    }
    let output = Command::new("nvidia-smi")
        .args(["--query-gpu=uuid,name", "--format=csv,noheader,nounits"])
        .output()
        .context("starting nvidia-smi; CUDA proving requires an NVIDIA GPU")?;
    if !output.status.success() {
        bail!(
            "nvidia-smi failed (status {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let gpu = String::from_utf8(output.stdout)
        .context("nvidia-smi returned non-UTF-8 output")?
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    if gpu.is_empty() {
        bail!("nvidia-smi reported no CUDA GPU; refusing CPU fallback");
    }
    Ok(gpu)
}

#[cfg(not(feature = "cuda"))]
fn require_cuda_gpu() -> Result<String> {
    bail!("composition proof binary was built without the required 'cuda' feature")
}

fn parse_args() -> Result<(OutputKind, PathBuf)> {
    let mut output_kind = OutputKind::Succinct;
    // Default under target/ so the ~450 KB of receipt binaries a run produces
    // land in an already-gitignored directory.
    let mut output_dir = PathBuf::from("target/composition-spike-output");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-kind" => {
                let value = args.next().context("--output-kind requires a value")?;
                output_kind = OutputKind::parse(&value)?;
            }
            "--output-dir" => {
                output_dir = PathBuf::from(args.next().context("--output-dir requires a value")?);
            }
            "--help" | "-h" => {
                println!(
                    "usage: zkdeal-risc0-composition-spike \
                     [--output-kind succinct|groth16] [--output-dir PATH]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument '{other}'"),
        }
    }
    Ok((output_kind, output_dir))
}

fn millis(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn cold_cache_file_name(template_digest: &[u8]) -> String {
    format!(
        "cold-{}-{}.succinct-receipt.bin",
        hex::encode(risc0_zkvm::sha::Digest::new(ZKDEAL_COLD_TEMPLATE_V4_ID).as_bytes()),
        hex::encode(&template_digest[..8])
    )
}

/// Return the cached cold receipt, or `None` when there is nothing usable on
/// disk. Every failure here — missing, unreadable, undecodable, unverifiable,
/// composite or committing a stale template — is recoverable by re-proving from
/// `IMMUTABLE_TEMPLATE`, so a damaged cache must not abort the run.
fn load_cached_cold(cache_path: &Path, expected_journal: &[u8]) -> Option<Receipt> {
    if !cache_path.is_file() {
        return None;
    }
    match read_cached_cold(cache_path, expected_journal) {
        Ok(receipt) => Some(receipt),
        Err(error) => {
            eprintln!(
                "discarding unusable cold cache {}: {error:#}",
                cache_path.display()
            );
            None
        }
    }
}

fn read_cached_cold(cache_path: &Path, expected_journal: &[u8]) -> Result<Receipt> {
    let bytes =
        fs::read(cache_path).with_context(|| format!("reading {}", cache_path.display()))?;
    let receipt: Receipt = bincode::deserialize(&bytes).context("decoding cold receipt")?;
    receipt
        .verify(ZKDEAL_COLD_TEMPLATE_V4_ID)
        .context("cached cold receipt failed verification")?;
    require_succinct(&receipt)?;
    require_cold_journal(&receipt.journal.bytes, expected_journal)?;
    Ok(receipt)
}

fn require_cold_journal(journal: &[u8], expected_journal: &[u8]) -> Result<()> {
    if journal != expected_journal {
        bail!(
            "cold journal does not commit the current IMMUTABLE_TEMPLATE digest \
             (expected {}, found {})",
            hex::encode(expected_journal),
            hex::encode(journal)
        );
    }
    Ok(())
}

fn require_succinct(receipt: &Receipt) -> Result<()> {
    if !matches!(receipt.inner, InnerReceipt::Succinct(_)) {
        bail!(
            "cold assumption must be cached as a succinct receipt; RISC Zero 3.0.6 cannot \
             compress a composite receipt containing a Groth16 assumption"
        );
    }
    Ok(())
}

fn encode_ethereum_seal(receipt: &Receipt) -> Result<Vec<u8>> {
    let groth16 = receipt
        .inner
        .groth16()
        .context("Ethereum seals require a Groth16 receipt")?;
    let mut out = Vec::with_capacity(4 + groth16.seal.len());
    out.extend_from_slice(&groth16.verifier_parameters.as_bytes()[..4]);
    out.extend_from_slice(&groth16.seal);
    Ok(out)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    // Unique per process so two runs sharing --output-dir cannot stage over each
    // other, and still `.tmp`-suffixed so .gitignore keeps covering it.
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = fs::File::create(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", temporary.display()))?;
    // Durable before the rename, so a crash cannot publish a torn artefact.
    file.sync_all()
        .with_context(|| format!("flushing {}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path)
        .with_context(|| format!("renaming {} to {}", temporary.display(), path.display()))?;
    let written = fs::read(path).with_context(|| format!("re-reading {}", path.display()))?;
    if written != bytes {
        bail!("{} does not match the bytes just written", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_kind_is_strict() {
        assert_eq!(OutputKind::parse("succinct").unwrap(), OutputKind::Succinct);
        assert_eq!(OutputKind::parse("groth16").unwrap(), OutputKind::Groth16);
        assert!(OutputKind::parse("composite").is_err());
    }

    #[test]
    fn cold_cache_key_tracks_the_template() {
        let template = Impl::hash_bytes(IMMUTABLE_TEMPLATE).as_bytes().to_vec();
        let edited = Impl::hash_bytes(b"zkdeal:v4:composition-spike:edited-template")
            .as_bytes()
            .to_vec();
        assert_ne!(
            cold_cache_file_name(&template),
            cold_cache_file_name(&edited)
        );
    }

    #[test]
    fn cold_journal_must_commit_the_current_template() {
        let expected = Impl::hash_bytes(IMMUTABLE_TEMPLATE).as_bytes().to_vec();
        let stale = Impl::hash_bytes(b"zkdeal:v4:composition-spike:edited-template")
            .as_bytes()
            .to_vec();
        assert!(require_cold_journal(&expected, &expected).is_ok());
        assert!(require_cold_journal(&stale, &expected).is_err());
    }
}
