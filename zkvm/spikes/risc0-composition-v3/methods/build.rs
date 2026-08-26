use std::{env, fs, path::PathBuf};

/// Image IDs of the guest binaries the PROFILE-RTX4090-20260721.md artefact
/// hashes were taken against. The rzup RISC Zero guest toolchain that produced
/// them was not recorded, so a source build on a different one legitimately
/// diverges; see `warn_on_image_id_drift`.
const COLD_ID: [u32; 8] = [
    3243506034, 2376225010, 3973648882, 994476441, 3452484564, 663280316, 1416306653, 4171046651,
];
const SUFFIX_ID: [u32; 8] = [
    2220940870, 3222258921, 261152568, 243929857, 366246180, 1780067661, 4169468384, 3920035011,
];

const COLD_GUEST: &str = "zkdeal-cold-template-v4";
const SUFFIX_GUEST: &str = "zkdeal-hot-suffix-v4";

fn main() {
    println!("cargo:rerun-if-env-changed=ZKDEAL_COMPOSITION_PREBUILT_DIR");
    println!("cargo:rerun-if-env-changed=RISC0_BUILD_LOCKED");
    if let Some(dir) = env::var_os("ZKDEAL_COMPOSITION_PREBUILT_DIR") {
        emit_verified_prebuilt(PathBuf::from(dir));
        return;
    }

    // risc0-build 3.0.6 passes `--locked` to the guest cargo invocation only
    // when this is non-empty, so without it the committed guest lockfiles are
    // decorative and a source build may re-resolve guest dependencies — and
    // with them the guest ELF and its image ID. Honour an explicit override.
    if env::var_os("RISC0_BUILD_LOCKED").is_none() {
        env::set_var("RISC0_BUILD_LOCKED", "1");
    }

    // Keep this spike on the exact API used by the production zkdeal prover.
    // `embed_methods` builds both independent guests and emits their ELF/image
    // ID constants into OUT_DIR/methods.rs.
    warn_on_image_id_drift(&risc0_build::embed_methods());
}

/// The source-build path embeds whatever image IDs the local guest toolchain
/// produces. Nothing downstream consumes the pinned constants on this path, so
/// divergence is a warning rather than a failure — but it does mean the run is
/// no longer comparable with the pinned profile, and that the prebuilt branch
/// would reject these binaries.
fn warn_on_image_id_drift(guests: &[risc0_build::GuestListEntry]) {
    for guest in guests {
        let pinned: &[u32; 8] = match &*guest.name {
            COLD_GUEST => &COLD_ID,
            SUFFIX_GUEST => &SUFFIX_ID,
            _ => continue,
        };
        if guest.image_id.as_words() != &pinned[..] {
            println!(
                "cargo:warning={} image ID {:?} differs from the pinned {:?}; \
                 measurements are not comparable with PROFILE-RTX4090-20260721.md",
                guest.name,
                guest.image_id.as_words(),
                pinned
            );
        }
    }
}

/// CI and the GPU node may consume the exact, already-built guest binaries.
/// Recompute both image IDs before embedding them; this is not a skip-build
/// escape hatch and cannot silently substitute different guest code.
fn emit_verified_prebuilt(dir: PathBuf) {
    let cold = dir.join(format!("{COLD_GUEST}.bin"));
    let suffix = dir.join(format!("{SUFFIX_GUEST}.bin"));
    println!("cargo:rerun-if-changed={}", cold.display());
    println!("cargo:rerun-if-changed={}", suffix.display());

    let cold_bytes = fs::read(&cold).expect("read prebuilt cold guest");
    let suffix_bytes = fs::read(&suffix).expect("read prebuilt suffix guest");
    let actual_cold = risc0_binfmt::compute_image_id(&cold_bytes)
        .expect("compute cold image ID")
        .as_words()
        .to_owned();
    let actual_suffix = risc0_binfmt::compute_image_id(&suffix_bytes)
        .expect("compute suffix image ID")
        .as_words()
        .to_owned();
    assert_eq!(actual_cold, COLD_ID, "prebuilt cold image ID changed");
    assert_eq!(actual_suffix, SUFFIX_ID, "prebuilt suffix image ID changed");

    let generated = format!(
        "pub const ZKDEAL_COLD_TEMPLATE_V4_ELF: &[u8] = include_bytes!({cold:?});\n\
         pub const ZKDEAL_COLD_TEMPLATE_V4_PATH: &str = {cold:?};\n\
         pub const ZKDEAL_COLD_TEMPLATE_V4_ID: [u32; 8] = {COLD_ID:?};\n\
         pub const ZKDEAL_HOT_SUFFIX_V4_ELF: &[u8] = include_bytes!({suffix:?});\n\
         pub const ZKDEAL_HOT_SUFFIX_V4_PATH: &str = {suffix:?};\n\
         pub const ZKDEAL_HOT_SUFFIX_V4_ID: [u32; 8] = {SUFFIX_ID:?};\n",
        cold = cold.display().to_string(),
        suffix = suffix.display().to_string(),
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("methods.rs");
    fs::write(out, generated).expect("write prebuilt methods.rs");
}
