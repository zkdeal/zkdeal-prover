# syntax=docker/dockerfile:1.7

# This small image runs build.mjs inside Docker while retaining access to the
# Docker daemon. Both parent images are immutable linux/amd64 manifest pins.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS node_runtime

FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c
COPY --from=node_runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node_runtime /usr/lib/libstdc++.so.6 /usr/lib/libstdc++.so.6
COPY --from=node_runtime /usr/lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1
RUN node --version && docker --version

# The orchestrator image is pushed to the release registry, so it carries the
# MIT license for the first-party source. Build context is the prover-node root
# ($Source in the runbook).
COPY --chmod=0444 LICENSE /LICENSE
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /workspace
