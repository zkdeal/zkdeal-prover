#!/bin/sh
# Regenerate osaka-manifest.json from the pinned interpreter.
#
# The inventory has to come from revm itself, or the sweep can silently miss an
# instruction - the first draft of the classification was missing SLOTNUM, and
# only this cross-check caught it. But the dumping program cannot LIVE under
# `zkvm/crates/`: the prover image verifies every file there against
# `zkvm/source-manifest.candidate.json`, so adding one file makes the image
# unbuildable until the manifest ceremony is re-run. Discovered the hard way.
#
# So the program is kept here, outside the manifest roots, and copied into a
# scratch clone of the workspace only for the duration of the build. The tracked
# tree is never modified.
#
# Run from `prover-node/`:
#   sh scripts/opcode-cost/regenerate-manifest.sh
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

echo "staging a scratch copy of the workspace in $SCRATCH"
cp -r "$ROOT/zkvm" "$SCRATCH/zkvm"
mkdir -p "$SCRATCH/zkvm/crates/stf-core/src/bin"
cp "$HERE/dump-opcode-manifest.rs" "$SCRATCH/zkvm/crates/stf-core/src/bin/dump-opcode-manifest.rs"

docker run --rm \
  -v "$SCRATCH/zkvm:/w" -w /w \
  -v zkdeal-opcode-cost-registry:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/w/target \
  rust:1.88-bookworm \
  bash -c "cargo run -q -p stf-core --bin dump-opcode-manifest --locked" \
  > "$HERE/osaka-manifest.json"

echo "wrote $HERE/osaka-manifest.json"
grep -o '"activeOpcodes": [0-9]*' "$HERE/osaka-manifest.json" || true
grep -o '"precompileCount": [0-9]*' "$HERE/osaka-manifest.json" || true

# The tracked tree must be untouched by this.
if [ -e "$ROOT/zkvm/crates/stf-core/src/bin/dump-opcode-manifest.rs" ]; then
  echo "REGENERATE-FAIL: the dumping program leaked into the tracked tree" >&2
  exit 1
fi
echo "tracked tree unchanged"
