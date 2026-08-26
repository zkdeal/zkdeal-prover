# Ligetron (ligero-prover) native build + lavapipe software Vulkan
# Pinned: ligero-prover v1.5.0 (6395bb105f259160b42654ec4e3592432b048126)
#         Dawn cec4482eccee45696a7c0019e750c77f101ced04 (per upstream README)
#         wabt 0ef5bd9a261407d4469a849e7ff41f34c889c45e (was `main`; this is the
#         revision `main` resolved to when the pin was taken, so the pinned build
#         matches what the unpinned one produced)
#         ubuntu 24.04 by index digest (mesa/lavapipe version is part of the
#         runtime contract — see the ICD assertion at the bottom of this file)
# Build/run commands: zkvm/ligetron/docker/README.md
FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ gcc clang ca-certificates cmake ninja-build python3 pkg-config \
    libgmp-dev libtbb-dev libssl-dev libboost-all-dev zlib1g-dev \
    libprotobuf-dev protobuf-compiler \
    libvulkan-dev libvulkan1 vulkan-tools mesa-vulkan-drivers \
    libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev libx11-xcb-dev \
    curl time \
 && rm -rf /var/lib/apt/lists/*

# ---------------- Dawn (WebGPU) ----------------
ARG DAWN_COMMIT=cec4482eccee45696a7c0019e750c77f101ced04
ARG DAWN_ARCHIVE_SHA256=99895e68a8061e8b7a44cebb9788b7a370725ff6b0203440377f9a0b1da7a7ed
RUN test "$(printf %s "${DAWN_COMMIT}" | wc -c)" -eq 40 \
 && curl -fsSL -o /tmp/dawn.tar.gz \
      "https://dawn.googlesource.com/dawn/+archive/${DAWN_COMMIT}.tar.gz" \
 && echo "${DAWN_ARCHIVE_SHA256}  /tmp/dawn.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/dawn \
 && tar xzf /tmp/dawn.tar.gz -C /opt/dawn \
 && rm -f /tmp/dawn.tar.gz
RUN cd /opt/dawn && cmake -S . -B out -G Ninja \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DDAWN_FETCH_DEPENDENCIES=OFF \
      -DDAWN_BUILD_MONOLITHIC_LIBRARY=STATIC \
      -DDAWN_ENABLE_INSTALL=ON \
      -DCMAKE_BUILD_TYPE=Release \
      -DDAWN_BUILD_SAMPLES=OFF \
      -DTINT_BUILD_TESTS=OFF \
      -DDAWN_USE_GLFW=OFF \
      -DDAWN_ENABLE_DESKTOP_GL=OFF \
      -DDAWN_ENABLE_OPENGLES=OFF \
 && cmake --build out -j 6 \
 && cmake --install out

# ---------------- wabt ----------------
# All upstream bytes are fetched as reviewed, checksum-pinned HTTPS archives.
ARG WABT_REF=0ef5bd9a261407d4469a849e7ff41f34c889c45e
ARG WABT_ARCHIVE_SHA256=7522e9ff3fe1d4859b1365f9e25f73986932656f5b0c630093d6b7b57ef073e6
RUN test "$(printf %s "${WABT_REF}" | wc -c)" -eq 40 \
 && curl -fsSL -o /tmp/wabt.tar.gz \
      "https://codeload.github.com/WebAssembly/wabt/tar.gz/${WABT_REF}" \
 && echo "${WABT_ARCHIVE_SHA256}  /tmp/wabt.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/wabt \
 && tar xzf /tmp/wabt.tar.gz -C /opt/wabt --strip-components=1 \
 && rm -f /tmp/wabt.tar.gz \
 && cd /opt/wabt \
 && cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTS=OFF -DBUILD_TOOLS=OFF -DBUILD_LIBWASM=OFF \
 && cmake --build build -j 8 \
 && cmake --install build

# ---------------- ligero-prover ----------------
ARG LIGERO_COMMIT=6395bb105f259160b42654ec4e3592432b048126
ARG LIGERO_ARCHIVE_SHA256=0cf882a09882b14cddce5bbba85a649a0401daefdece48bc1194eea054ec0b56
RUN test "$(printf %s "${LIGERO_COMMIT}" | wc -c)" -eq 40 \
 && curl -fsSL -o /tmp/ligero.tar.gz \
      "https://codeload.github.com/ligeroinc/ligero-prover/tar.gz/${LIGERO_COMMIT}" \
 && echo "${LIGERO_ARCHIVE_SHA256}  /tmp/ligero.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/ligero \
 && tar xzf /tmp/ligero.tar.gz -C /opt/ligero --strip-components=1 \
 && rm -f /tmp/ligero.tar.gz
RUN cd /opt/ligero && cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j 8

# Runtime env: force lavapipe (software Vulkan CPU rasterizer).
# mesa 25.x (ubuntu 24.04 current) ships lvp_icd.json WITHOUT the arch
# suffix; older mesa used lvp_icd.x86_64.json. Point at the unsuffixed name
# (present in the pinned image); callers may override at `docker run -e`.
ENV VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json \
    VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json
# Assert the ICD manifest the two variables above name actually exists and
# loads. Without this the failure mode is silent at build time and fatal at run
# time: the loader finds no ICD, Dawn falls back to the Null backend and
# webgpu_prover segfaults in stage 1 (packages/zkvm/src/backends/
# ligetron-node.ts). The base digest pin above is what makes the path stable;
# this check is what notices when the pin is moved.
RUN test -f "$VK_DRIVER_FILES" \
 && vulkaninfo --summary > /dev/null

# The tag (`ligetron:v1.5.0`) is chosen at `docker build -t` time and all three
# upstream revisions and archive digests are overridable ARGs, so two correctly-named images
# can contain different provers. These labels are the only thing that ties a
# running container back to the sources it was built from; record them with the
# image digest whenever Ligetron evidence is published.
LABEL org.opencontainers.image.title="zkdeal Ligetron prover/verifier (lavapipe software Vulkan)" \
      org.opencontainers.image.source="https://github.com/ligeroinc/ligero-prover" \
      io.zkdeal.ligero.commit="${LIGERO_COMMIT}" \
      io.zkdeal.ligero.archive.sha256="${LIGERO_ARCHIVE_SHA256}" \
      io.zkdeal.dawn.commit="${DAWN_COMMIT}" \
      io.zkdeal.dawn.archive.sha256="${DAWN_ARCHIVE_SHA256}" \
      io.zkdeal.wabt.commit="${WABT_REF}" \
      io.zkdeal.wabt.archive.sha256="${WABT_ARCHIVE_SHA256}"

WORKDIR /opt/ligero/build
CMD ["/bin/bash"]
