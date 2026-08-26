#!/usr/bin/env bash
# Build the zkVM artifact tree and verify or update artifacts.lock.json.
# ZKVM_TOOLCHAIN_IMAGE and ZKVM_RUNTIME_IMAGE must be immutable sha256 image
# IDs or repository digest references produced from the pinned Dockerfile.
set -euo pipefail
cd "$(dirname "$0")/.."

TOOLCHAIN_IMAGE="${ZKVM_TOOLCHAIN_IMAGE:-}"
RUNTIME_IMAGE="${ZKVM_RUNTIME_IMAGE:-}"
SKIP_RUST=false
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --toolchain-image)
      TOOLCHAIN_IMAGE="${2:?--toolchain-image needs a value}"
      shift 2
      ;;
    --runtime-image)
      RUNTIME_IMAGE="${2:?--runtime-image needs a value}"
      shift 2
      ;;
    --skip-rust)
      SKIP_RUST=true
      ARGS+=("$1")
      shift
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ "$SKIP_RUST" == false ]]; then
  [[ -n "$TOOLCHAIN_IMAGE" && -n "$RUNTIME_IMAGE" ]] || {
    echo 'ZKVM_TOOLCHAIN_IMAGE and ZKVM_RUNTIME_IMAGE are required' >&2
    exit 1
  }
  ARGS+=(--toolchain-image "$TOOLCHAIN_IMAGE" --runtime-image "$RUNTIME_IMAGE" --cuda)
fi

exec node zkvm/build.mjs "${ARGS[@]}"
