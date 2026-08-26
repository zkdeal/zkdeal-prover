//! RISC Zero prover session, receipt compression and journal binding.
//!
//! Every receipt this host emits is self-verified here before it can reach a
//! machine result, and the guest journal is always bound to the statement
//! native execution computed.

use std::collections::BTreeMap;
use std::io::Write;
use std::rc::Rc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use r0_methods::STF_GUEST_ID;
use risc0_circuit_recursion::control_id::BN254_IDENTITY_CONTROL_ID;
use risc0_groth16::prove::shrink_wrap;
use risc0_zkp::core::hash::poseidon_254::Poseidon254HashSuite;
use risc0_zkvm::{
    default_prover, get_prover_server,
    sha::{Digest, Digestible},
    ExecutorEnv, Groth16Receipt, Groth16ReceiptVerifierParameters, InnerReceipt, Prover,
    ProverOpts, Receipt, SuccinctReceiptVerifierParameters, VerifierContext, ALLOWED_CONTROL_ROOT,
};

thread_local! {
    /// The HTTP runtime admits one proof at a time and pins blocking work to
    /// one worker. Keeping the prover object on that worker avoids rebuilding
    /// its local client state for every room batch.
    static PERSISTENT_PROVER: Rc<dyn Prover> = default_prover();
}

pub(crate) fn persistent_prover() -> Rc<dyn Prover> {
    PERSISTENT_PROVER.with(Rc::clone)
}

#[cfg(unix)]
struct ThirdPartyStdoutGuard {
    saved_fd: libc::c_int,
}

#[cfg(unix)]
impl ThirdPartyStdoutGuard {
    fn new() -> Result<Self> {
        std::io::stdout().flush().context("flush prover report")?;
        // SAFETY: every descriptor is checked before use. The service admits
        // one proof at a time, so this process-wide redirect cannot overlap a
        // second proving request.
        unsafe {
            libc::fflush(std::ptr::null_mut());
            let saved_fd = libc::dup(libc::STDOUT_FILENO);
            if saved_fd < 0 {
                return Err(std::io::Error::last_os_error()).context("duplicate stdout");
            }
            let null_fd = libc::open(b"/dev/null\0".as_ptr().cast(), libc::O_WRONLY);
            if null_fd < 0 {
                libc::close(saved_fd);
                return Err(std::io::Error::last_os_error()).context("open output sink");
            }
            if libc::dup2(null_fd, libc::STDOUT_FILENO) < 0 {
                let error = std::io::Error::last_os_error();
                libc::close(null_fd);
                libc::close(saved_fd);
                return Err(error).context("redirect third-party stdout");
            }
            libc::close(null_fd);
            Ok(Self { saved_fd })
        }
    }
}

#[cfg(unix)]
impl Drop for ThirdPartyStdoutGuard {
    fn drop(&mut self) {
        // SAFETY: `saved_fd` is an owned duplicate created in `new`. Flush
        // native C and C++ output while the sink is still installed.
        unsafe {
            libc::fflush(std::ptr::null_mut());
            libc::dup2(self.saved_fd, libc::STDOUT_FILENO);
            libc::close(self.saved_fd);
        }
    }
}

pub(crate) fn without_third_party_stdout<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    #[cfg(unix)]
    let guard = ThirdPartyStdoutGuard::new()?;
    let result = action();
    #[cfg(unix)]
    drop(guard);
    result
}

pub(crate) fn compress_receipt(
    prover: &dyn Prover,
    opts: &ProverOpts,
    receipt: &Receipt,
) -> Result<Receipt> {
    without_third_party_stdout(|| prover.compress(opts, receipt))
}

pub(crate) fn compress_groth16_with_verified_identity(
    receipt: &Receipt,
) -> Result<(Receipt, f64, f64)> {
    receipt
        .verify(STF_GUEST_ID)
        .context("Groth16 input receipt verification failed")?;
    let succinct = match &receipt.inner {
        InnerReceipt::Succinct(succinct) => succinct,
        InnerReceipt::Composite(_) => bail!("Groth16 input must already be succinct"),
        InnerReceipt::Groth16(_) => bail!("Groth16 input is already wrapped"),
        InnerReceipt::Fake(_) => bail!("development receipts are not accepted"),
        _ => bail!("unsupported Groth16 input representation"),
    };

    let identity_started = Instant::now();
    let identity = get_prover_server(&ProverOpts::succinct())?
        .identity_p254(succinct)
        .context("Poseidon identity proof failed")?;
    let identity_ms = identity_started.elapsed().as_secs_f64() * 1000.0;
    let identity_receipt = Receipt::new(
        InnerReceipt::Succinct(identity),
        receipt.journal.bytes.clone(),
    );
    // This verification is also a synchronization boundary between the
    // recursion CUDA work and the independent Groth16 CUDA implementation.
    verify_identity_p254_receipt(&identity_receipt)?;
    let identity = match &identity_receipt.inner {
        InnerReceipt::Succinct(identity) => identity,
        _ => unreachable!("the verified identity receipt is succinct"),
    };

    let wrapper_started = Instant::now();
    let seal = without_third_party_stdout(|| {
        shrink_wrap(&identity.get_seal_bytes()).context("Groth16 wrapper proof failed")
    })?
    .to_vec();
    let wrapper_ms = wrapper_started.elapsed().as_secs_f64() * 1000.0;
    let wrapped = Receipt::new(
        InnerReceipt::Groth16(Groth16Receipt::new(
            seal,
            identity.claim.clone(),
            Groth16ReceiptVerifierParameters::default().digest(),
        )),
        receipt.journal.bytes.clone(),
    );
    wrapped
        .verify(STF_GUEST_ID)
        .context("wrapped Groth16 receipt verification failed")?;
    Ok((wrapped, identity_ms, wrapper_ms))
}

pub(crate) fn image_id_hex() -> String {
    hex::encode(Digest::new(STF_GUEST_ID).as_bytes())
}

/// Exact encoding expected by the official RISC Zero Ethereum verifier
/// router: first four bytes of the Groth16 verifier-parameter digest followed
/// by the raw Groth16 seal. Kept local to avoid pulling a second, mismatched
/// risc0-zkvm version through the broad contracts helper crate.
pub(crate) fn encode_ethereum_seal(receipt: &Receipt) -> Result<Vec<u8>> {
    let groth16 = receipt
        .inner
        .groth16()
        .context("Ethereum seals require a Groth16 receipt")?;
    let selector = &groth16.verifier_parameters.as_bytes()[..4];
    let mut out = Vec::with_capacity(selector.len() + groth16.seal.len());
    out.extend_from_slice(selector);
    out.extend_from_slice(&groth16.seal);
    Ok(out)
}

/// Verify the special Poseidon/BabyBear identity receipt produced immediately
/// before the BN254 Groth16 wrapper. It deliberately uses a different control
/// root and hash suite from an ordinary RISC Zero succinct receipt, so the
/// default verifier context must not be used.
pub(crate) fn verify_identity_p254_receipt(receipt: &Receipt) -> Result<()> {
    let identity = match &receipt.inner {
        InnerReceipt::Succinct(succinct) => succinct,
        _ => bail!("input receipt is not a Poseidon identity receipt"),
    };
    if identity.control_id != BN254_IDENTITY_CONTROL_ID {
        bail!("identity receipt uses an unexpected recursion program");
    }

    let suite = Poseidon254HashSuite::new_suite();
    let verifier_parameters = SuccinctReceiptVerifierParameters {
        control_root: identity
            .control_inclusion_proof
            .root(&identity.control_id, suite.hashfn.as_ref()),
        inner_control_root: Some(ALLOWED_CONTROL_ROOT),
        ..Default::default()
    };
    let verifier_context = VerifierContext::empty()
        .with_suites(BTreeMap::from([("poseidon_254".to_owned(), suite)]))
        .with_succinct_verifier_parameters(verifier_parameters);
    receipt
        .verify_with_context(&verifier_context, STF_GUEST_ID)
        .context("Poseidon identity receipt verification failed")
}

pub(crate) fn build_env(input_bytes: &[u8]) -> Result<ExecutorEnv<'_>> {
    build_env_with_assumptions(input_bytes, Vec::new())
}

pub(crate) fn build_env_with_assumptions(
    input_bytes: &[u8],
    assumptions: Vec<Receipt>,
) -> Result<ExecutorEnv<'_>> {
    let mut builder = ExecutorEnv::builder();
    if let Ok(po2) = std::env::var("SEGMENT_PO2") {
        builder.segment_limit_po2(po2.parse().context("bad SEGMENT_PO2")?);
    }
    builder.write_frame(input_bytes);
    for receipt in assumptions {
        // Official RISC Zero composition API. A proven receipt resolves the
        // guest's `env::verify` call and makes the final receipt unconditional.
        builder.add_assumption(receipt);
    }
    builder.build().map_err(|e| anyhow!("env build: {e}"))
}

pub(crate) fn require_committed_journal_hash(bytes: &[u8], expected: [u8; 32]) -> Result<()> {
    if bytes.len() != 32 {
        bail!(
            "guest journal is {} bytes; expected exactly one 32-byte statement hash",
            bytes.len()
        );
    }
    if bytes != expected {
        bail!(
            "guest committed {}, native execution computed {}",
            hex::encode(bytes),
            hex::encode(expected)
        );
    }
    Ok(())
}
