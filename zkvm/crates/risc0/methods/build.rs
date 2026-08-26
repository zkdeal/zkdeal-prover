//! Guest embedding. Two modes:
//!
//! - default (RISC0_USE_DOCKER unset): native guest build with the installed
//!   rzup Rust toolchain. `zkvm/build.mjs` runs this mode inside the immutable
//!   source-independent CUDA toolchain image, avoiding Docker-outside-Docker
//!   path translation on Windows while retaining a pinned build environment.
//! - RISC0_USE_DOCKER=1: optional developer mode using the upstream guest
//!   builder container. Production artifact generation does not use it.
//!
//! The docker context root is the zkvm/ workspace (two levels up), so the
//! guest's path-deps on stf-core / stf-types resolve inside the build
//! container.

use std::collections::HashMap;

use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};

fn main() {
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");
    println!("cargo:rerun-if-env-changed=RISC0_DOCKER_CONTAINER_TAG");
    println!("cargo:rerun-if-env-changed=ZKDEAL_OPCODE_GADGET_BASELINE");

    let mut guest = GuestOptionsBuilder::default();
    if std::env::var("ZKDEAL_OPCODE_GADGET_BASELINE").is_ok_and(|value| value == "1") {
        guest.features(vec!["opcode-gadget-baseline".to_string()]);
    }
    if std::env::var("RISC0_USE_DOCKER").is_ok_and(|v| v == "1") {
        let root = std::env::var("RISC0_DOCKER_ROOT").unwrap_or_else(|_| {
            // crates/risc0/methods → zkvm workspace root
            let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
            format!("{manifest}/../../..")
        });
        let docker = DockerOptionsBuilder::default()
            .root_dir(root)
            .docker_container_tag("r0.1.91.1")
            .build()
            .expect("docker options");
        guest.use_docker(docker);
    }
    let guest = guest.build().expect("guest options");
    embed_methods_with_options(HashMap::from([("stf-guest", guest)]));
}
