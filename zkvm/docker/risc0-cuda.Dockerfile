# syntax=docker/dockerfile:1.7

# Linux/amd64 manifest digests for NVIDIA CUDA 12.9.1 on Ubuntu 22.04.
# Refresh only in a reviewed toolchain update; tags are intentionally retained
# as human-readable labels but the immutable manifest digest is authoritative.
FROM nvidia/cuda:12.9.1-devel-ubuntu22.04@sha256:38804006c937a83f28f63a959abcee688042072319c8614ad57b350958a30bd3 AS toolchain

ARG RUST_VERSION=1.88.0
ARG RUSTUP_VERSION=1.28.2
ARG RUSTUP_SHA256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
ARG RZUP_SHA256=7cdc1dd5d4b8ef38ea6170c45bd29ba65d389f0e96b365da61631d1fc5c6c1ca

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:/root/.risc0/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates clang cmake curl libssl-dev pkg-config python3 xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
      -o /tmp/rustup-init \
    && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum --check --strict \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rm /tmp/rustup-init \
    && rustc --version | grep -F "rustc ${RUST_VERSION}"

# Pin rzup itself by content, then pin both components used by risc0-build.
# rzup component versions are semantic versions without the release-channel
# prefixes used in the corresponding Docker image/toolchain labels.
ARG RISC0_VERSION=3.0.6
ARG RISC0_RUST_TOOLCHAIN=1.91.1
ARG RISC0_GROTH16_VERSION=0.1.0
ARG RISC0_GROTH16_SHA256=4b4f2b2fb8380369ed14f0dc48380a1bbcbc82c7d553f1888b47d0a9f8e72e4d
ARG RISC0_GROTH16_SIZE=2335797480
# RISC Zero 3.x ships the CUDA STARK-to-Groth16 wrapper as a separate
# target-agnostic rzup component. The SDK requests this exact version at
# runtime, so pin it instead of following rzup's mutable default.
# Without it `ProverOpts::groth16()` completes the expensive composite proof
# and then fails before producing an Ethereum-verifiable seal.
COPY zkvm/docker/fetch-pinned-risc0-groth16.sh /usr/local/bin/fetch-pinned-risc0-groth16
RUN curl -fsSL \
      https://risc0-artifacts.s3.us-west-2.amazonaws.com/rzup/prod/Linux-X64/rzup \
      -o /usr/local/bin/rzup \
    && echo "${RZUP_SHA256}  /usr/local/bin/rzup" | sha256sum --check --strict \
    && chmod +x /usr/local/bin/rzup \
    && rzup install cargo-risczero "${RISC0_VERSION}" \
    && rzup install rust "${RISC0_RUST_TOOLCHAIN}"

# The Groth16 parameter archive is multi-gigabyte. Fetch immutable byte ranges
# concurrently, verify the complete object, and materialize the directory rzup
# would have created. The final rzup call records the installed version without
# downloading it a second time.
RUN chmod +x /usr/local/bin/fetch-pinned-risc0-groth16 \
    && fetch-pinned-risc0-groth16 \
         "https://risc0-artifacts.s3.us-west-2.amazonaws.com/rzup/components/risc0-groth16/sha256/${RISC0_GROTH16_SHA256}" \
         "${RISC0_GROTH16_SHA256}" "${RISC0_GROTH16_SIZE}" \
         /tmp/risc0-groth16.tar.xz \
    && mkdir -p "/root/.risc0/extensions/v${RISC0_GROTH16_VERSION}-risc0-groth16" \
    && tar -xJf /tmp/risc0-groth16.tar.xz \
         -C "/root/.risc0/extensions/v${RISC0_GROTH16_VERSION}-risc0-groth16" \
    && rm /tmp/risc0-groth16.tar.xz \
    && rzup install risc0-groth16 "${RISC0_GROTH16_VERSION}"

# Browser receipt verification is part of the current trust root. Build the exact
# crates.io release under its published Cargo.lock instead of relying on an
# unversioned binary inherited from a developer image.
ARG WASM_PACK_VERSION=0.13.1
RUN cargo install --locked --version "${WASM_PACK_VERSION}" wasm-pack \
    && wasm-pack --version | grep -F "wasm-pack ${WASM_PACK_VERSION}"

# Groth16 compression pulls circom-witnesscalc, whose checked-in protobuf
# schema is compiled during the Rust build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# `rzup install` fetches its component archives over the network under a version
# string only, so re-publishing an archive under the same version would change
# the guest ELF -- and therefore the program ID the whole trust root rests on --
# with no signal that anything moved. Record a content digest over the installed
# component tree, which is the artefact those archives actually produce, and
# hard-fail when RISC0_HOME_TREE_SHA256 is supplied and disagrees. Recording it
# is unconditional; enforcing it is opt-in so the value can be adopted from a
# reviewed build rather than guessed.
#
# The same file carries the versions this image actually installed. They used to
# be string literals inside zkvm/build.mjs, so an image built with different
# build args produced a lock that confidently misstated its own build
# environment; build.mjs now copies these observed values instead.
ARG RISC0_HOME_TREE_SHA256=
RUN set -eu \
    && mkdir -p /etc/zkdeal \
    && tree=$(find /root/.risc0 -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1) \
    && if [ -n "${RISC0_HOME_TREE_SHA256:-}" ] && [ "${RISC0_HOME_TREE_SHA256}" != "${tree}" ]; then \
         echo "rzup component tree ${tree} does not match the pinned ${RISC0_HOME_TREE_SHA256}" >&2; \
         exit 1; \
       fi \
    && printf '{\n  "format": "zkdeal/risc0-toolchain-versions/v1",\n  "rust": "%s",\n  "rustcBanner": "%s",\n  "wasmPack": "%s",\n  "wasmPackBanner": "%s",\n  "riscZero": {\n    "crates": "%s",\n    "rustToolchain": "%s",\n    "groth16": "%s",\n    "rzupSha256": "%s"\n  },\n  "risc0HomeTreeSha256": "%s"\n}\n' \
         "$(rustc --version | cut -d' ' -f2)" "$(rustc --version)" \
         "$(wasm-pack --version | cut -d' ' -f2)" "$(wasm-pack --version)" \
         "${RISC0_VERSION}" "${RISC0_RUST_TOOLCHAIN}" "${RISC0_GROTH16_VERSION}" "${RZUP_SHA256}" \
         "${tree}" \
         > /etc/zkdeal/toolchain-versions.json

# Docker build stages do not receive a GPU device, so RISC Zero's default
# `-arch=native` probe cannot discover the target architecture. The image
# builder supplies the inspected stand's architecture (sm_89 by default).
#
# NVIDIA documents both flags below for reproducible CUDA objects:
# `--frandom-seed` fixes the generated internal symbol names and
# `--objdir-as-tempdir` prevents random temporary paths from entering an object.
# Without them two clean sm_100 builds produced different fatbins even though
# the RISC Zero guest image ID was identical, so the host binary could not pass
# the artifact lock's independent-build check.
ARG CUDA_ARCH=89
ENV NVCC_APPEND_FLAGS="-arch=sm_${CUDA_ARCH} --frandom-seed=zkdeal-risc0 --objdir-as-tempdir"

WORKDIR /workspace

# `toolchain` intentionally ends before source is copied. Its immutable image
# can therefore be pinned independently of artifacts.lock.json and fixtures.
FROM toolchain AS builder

ARG SOURCE_MANIFEST_SHA256
COPY zkvm/source-manifest.candidate.json /workspace/zkvm/source-manifest.candidate.json
RUN set -eu \
    && test "${#SOURCE_MANIFEST_SHA256}" -eq 64 \
    && case "${SOURCE_MANIFEST_SHA256}" in *[!0-9a-f]*) exit 1;; esac \
    && echo "${SOURCE_MANIFEST_SHA256}  /workspace/zkvm/source-manifest.candidate.json" \
         | sha256sum --check --strict

COPY zkvm/Cargo.toml zkvm/Cargo.lock zkvm/rust-toolchain.toml /workspace/zkvm/
COPY zkvm/build-config.mjs zkvm/build-exec.mjs zkvm/build-lock.mjs zkvm/build.mjs zkvm/lock-schema.mjs /workspace/zkvm/
COPY zkvm/crates /workspace/zkvm/crates
COPY zkvm/docker /workspace/zkvm/docker
COPY zkvm/scripts /workspace/zkvm/scripts
COPY zkvm/vendor /workspace/zkvm/vendor
RUN python3 /workspace/zkvm/scripts/verify-source-manifest.py \
      /workspace/zkvm /workspace/zkvm/source-manifest.candidate.json

# `production` enables the official risc0-zkvm CUDA feature. The host also
# refuses production jobs at runtime unless a real local NVIDIA GPU is visible.
#
# The guest is a separate cargo workspace (see `exclude` in zkvm/Cargo.toml), so
# this `--locked` constrains only the outer resolution; the guest ELF that
# defines the image ID is produced by a nested cargo invocation inside
# risc0-build that the flag does not reach. Fail the image build if that nested
# resolution rewrites the checked-in guest lock, which is the one observable
# signal that the guest's dependencies drifted.
RUN cd /workspace/zkvm \
    && guest_lock=$(sha256sum crates/risc0/methods/guest/Cargo.lock) \
    && cargo build --locked --release -p zkdeal-r0 --features production \
    && { echo "${guest_lock}" | sha256sum --check --strict --status \
         || { echo 'the nested guest build rewrote crates/risc0/methods/guest/Cargo.lock' >&2; exit 1; }; } \
    && strip /workspace/zkvm/target/release/zkdeal-r0

FROM nvidia/cuda:12.9.1-runtime-ubuntu22.04@sha256:6553b9635f35d992cf0473f55d1e998935a2dd1e2e604d3cbfb2bf295a8faa79 AS runtime

ARG SOURCE_MANIFEST_SHA256
ARG RISC0_GROTH16_VERSION=0.1.0
RUN test "${#SOURCE_MANIFEST_SHA256}" -eq 64 \
    && case "${SOURCE_MANIFEST_SHA256}" in *[!0-9a-f]*) exit 1;; esac
LABEL org.opencontainers.image.title="zkdeal RISC Zero CUDA prover" \
      org.opencontainers.image.source-manifest.sha256="${SOURCE_MANIFEST_SHA256}" \
      org.opencontainers.image.source="https://github.com/zkdeal/zkdeal-prover" \
      org.opencontainers.image.licenses="BUSL-1.1"

ENV RISC0_PROVER=local \
    RISC0_HOME=/home/zkdeal/.risc0 \
    RUST_LOG=info \
    SEGMENT_PO2=20 \
    ZKDEAL_PRODUCTION=1

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 zkdeal

# rzup installs Groth16 proving parameters under root's home in the toolchain
# stage. The production process runs as uid 10001, and rzup resolves components
# relative to RISC0_HOME (or that user's home), so explicitly copy and chown the
# pinned component into the runtime-visible location.
COPY --from=toolchain --chown=10001:10001 \
    /root/.risc0/extensions/v${RISC0_GROTH16_VERSION}-risc0-groth16 \
    /home/zkdeal/.risc0/extensions/v${RISC0_GROTH16_VERSION}-risc0-groth16

COPY --from=builder /workspace/zkvm/target/release/zkdeal-r0 /usr/local/bin/zkdeal-r0
COPY --from=builder /workspace/zkvm/source-manifest.candidate.json /etc/zkdeal/source-manifest.json

# The BUSL requires conspicuous display of the license on each copy of the
# Licensed Work; every shipped first-party image carries it at the image root.
COPY --chmod=0444 zkvm/zkdeal-BUSL-1.1-LICENSE /zkdeal-BUSL-1.1-LICENSE

USER zkdeal
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD ["zkdeal-r0", "health"]

ENTRYPOINT ["zkdeal-r0"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
