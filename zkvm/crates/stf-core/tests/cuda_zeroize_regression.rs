const KERNEL: &str = include_str!("../../../vendor/risc0-sys/kernels/zkp/cuda/eltwise.cu");
const FFI: &str = include_str!("../../../vendor/risc0-sys/kernels/zkp/cuda/ffi.cu");
const DECLARATIONS: &str = include_str!("../../../vendor/risc0-sys/kernels/zkp/cuda/kernels.h");
const HOST_MANIFEST: &str = include_str!("../../risc0/host/Cargo.toml");
const WORKSPACE_MANIFEST: &str = include_str!("../../../Cargo.toml");
const GROTH16_MANIFEST: &str = include_str!("../../../vendor/risc0-groth16-sys/Cargo.toml");
const WORKSPACE_LOCK: &str = include_str!("../../../Cargo.lock");
const GROTH16_COEFFICIENTS: &str =
    include_str!("../../../vendor/risc0-groth16-sys/kernels/cuda/groth16_coeffs.cuh");
const GROTH16_FFI: &str = include_str!("../../../vendor/risc0-groth16-sys/kernels/cuda/ffi.cu");
const GROTH16_PROVER: &str =
    include_str!("../../../vendor/risc0-groth16-sys/kernels/cuda/groth16_prover.cuh");

#[test]
fn rounded_cuda_zeroize_launches_are_bounds_checked() {
    assert!(KERNEL.contains("eltwise_zeroize_fp(Fp* elems, const uint32_t count)"));
    assert!(KERNEL.contains("eltwise_zeroize_fpext(FpExt* elems, const uint32_t count)"));
    assert_eq!(KERNEL.matches("if (idx < count)").count(), 6);
    assert!(FFI.contains("launchKernel(eltwise_zeroize_fp, count, 0, elems, count)"));
    assert!(FFI.contains("launchKernel(eltwise_zeroize_fpext, count, 0, elems, count)"));
    assert!(DECLARATIONS.contains("eltwise_zeroize_fp(Fp* elems, const uint32_t count)"));
    assert!(DECLARATIONS.contains("eltwise_zeroize_fpext(FpExt* elems, const uint32_t count)"));
}

#[test]
fn groth16_coefficients_use_the_setup_asset_cuda_abi() {
    assert!(
        WORKSPACE_MANIFEST.contains("risc0-groth16-sys = { path = \"vendor/risc0-groth16-sys\" }"),
        "the workspace must use the reviewed vendored Groth16 implementation"
    );
    assert!(HOST_MANIFEST.contains("risc0-groth16"));
    assert!(GROTH16_MANIFEST.contains("version = \"=0.1.12\""));
    let locked = WORKSPACE_LOCK
        .split("[[package]]")
        .find(|package| package.contains("name = \"sppark\""))
        .expect("sppark must be locked");
    assert!(locked.contains("version = \"0.1.12\""));
    assert!(GROTH16_COEFFICIENTS.contains("sizeof(fr_t) == 32"));
    assert!(GROTH16_COEFFICIENTS.contains("sizeof(coeff_t) == 48"));
    assert!(!GROTH16_COEFFICIENTS.contains("serialized_coeff_t"));
    assert!(!GROTH16_COEFFICIENTS.contains("expand_serialized_coeffs"));
    assert!(GROTH16_COEFFICIENTS.contains("file_size != expected_file_size"));
    assert!(GROTH16_FFI.contains("struct PersistentProverCache"));
    assert!(GROTH16_FFI.contains("new PersistentProverCache"));
    assert!(GROTH16_FFI.contains("const bool setup_changed"));
    assert!(GROTH16_FFI.contains("std::unique_ptr<SRS> srs"));
    assert!(GROTH16_FFI.contains("groth16_prover prover("));
    assert!(!GROTH16_FFI.contains("std::unique_ptr<groth16_prover>"));
}

#[test]
fn groth16_cross_stream_witness_read_waits_for_upload() {
    assert!(GROTH16_PROVER.contains("event_t witness_ready(gpu);"));
    assert!(GROTH16_PROVER.contains("witness_ready.wait(gpu[0]);"));

    let upload = GROTH16_PROVER
        .find("gpu.HtoD(&d_witness[0]")
        .expect("witness upload must exist");
    let event = GROTH16_PROVER
        .find("event_t witness_ready(gpu);")
        .expect("witness upload event must exist");
    let wait = GROTH16_PROVER
        .find("witness_ready.wait(gpu[0]);")
        .expect("cross-stream wait must exist");
    let reader = GROTH16_PROVER
        .find("witness_into_poly<<<gpu.sm_count(), 512, 0, gpu[0]>>>")
        .expect("A-polynomial witness reader must exist");

    assert!(upload < event && event < wait && wait < reader);

    assert!(GROTH16_PROVER.contains("event_t fuzzed_witness_ready(gpu);"));
    assert!(GROTH16_PROVER.contains("fuzzed_witness_ready.wait(gpu[2]);"));
    let fuzz = GROTH16_PROVER
        .find("coeff_wise_add<<<gpu.sm_count(), 1024, 0, gpu>>>")
        .expect("fuzz-add kernel must exist");
    let msm_event = GROTH16_PROVER
        .find("event_t fuzzed_witness_ready(gpu);")
        .expect("fuzzed-witness event must exist");
    let msm_wait = GROTH16_PROVER
        .find("fuzzed_witness_ready.wait(gpu[2]);")
        .expect("MSM stream wait must exist");
    let msm_reader = GROTH16_PROVER
        .find("msm_g1.invoke(results.a")
        .expect("first MSM witness reader must exist");
    assert!(fuzz < msm_event && msm_event < msm_wait && msm_wait < msm_reader);
}
