#!/bin/bash
# Prove that every sweep vector makes its precompile do the FULL work.
#
# Why this exists
# ---------------
# The measurement template ends `STATICCALL, POP`: it discards the success
# flag. That is correct for measurement - branching on the result would put a
# comparison inside the repeated unit and contaminate the gradient - but it
# means a precompile that REJECTS its input is indistinguishable from one that
# accepts it. Both charge gas, both return, and the sweep reports OK.
#
# That is not hypothetical. It is what produced the first round of precompile
# numbers: zeroed inputs decode to the point at infinity, the curve precompiles
# short-circuit, and the recorded cycles priced an early exit. The gas column
# matched the schedule perfectly the whole time, so nothing looked wrong.
#
# So correctness is established HERE, against a real EVM, before a GPU second is
# spent - and the measurement template stays untouched.
#
# Two properties are checked per vector:
#
#   1. The call returns the schedule's output length. An empty return is a
#      rejection; every precompile in this set returns a fixed-size result.
#   2. The result is not all zeros, except where zero is the honest answer
#      (a pairing check that legitimately fails). A zero G1/G2 point is the
#      point at infinity - the signature of exactly the short-circuit this is
#      here to rule out.
#
# Usage:  ./verify-vectors.sh [--hardfork NAME]
set -uo pipefail

IMG_FOUNDRY="${IMG_FOUNDRY:-ghcr.io/foundry-rs/foundry:v1.7.1}"
IMG_NODE="${IMG_NODE:-node:22-bookworm}"
HARDFORK="${HARDFORK:-osaka}"
[ "${1:-}" = "--hardfork" ] && HARDFORK="$2"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
ANVIL="zkdeal-vector-anvil-$$"
PORT=8599

cleanup() { docker rm -f "$ANVIL" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

say() { printf '[verify-vectors] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. The vector table is the single source of truth; dump it rather than
#    restating any byte of it here.
# ---------------------------------------------------------------------------
cat >"$WORK/dump.mjs" <<'DUMP'
import { VECTOR_ROWS } from '/app/precompile-vectors.mts'
process.stdout.write(JSON.stringify(VECTOR_ROWS.map((r) => ({
  name: r.name, address: r.address, input: r.input,
}))))
DUMP

docker run --rm -v "$HERE:/app:ro" -v "$WORK:/work" "$IMG_NODE" \
  node --experimental-strip-types --no-warnings /work/dump.mjs >"$WORK/vectors.json" \
  || { say "FATAL: could not read the vector table"; exit 1; }

COUNT="$(docker run --rm -v "$WORK:/work" "$IMG_NODE" \
  node -e 'console.log(JSON.parse(require("fs").readFileSync("/work/vectors.json")).length)')"
say "loaded ${COUNT} vectors"

# ---------------------------------------------------------------------------
# 2. A throwaway chain. Nothing else runs on it, so it cannot disturb a soak or
#    an acceptance rig sharing this host.
# ---------------------------------------------------------------------------
say "starting a disposable anvil at hardfork ${HARDFORK}"
docker run -d --name "$ANVIL" -p "127.0.0.1:${PORT}:8545" --entrypoint anvil \
  "$IMG_FOUNDRY" --host 0.0.0.0 --hardfork "$HARDFORK" --silent >/dev/null \
  || { say "FATAL: anvil would not start"; exit 1; }

RPC="http://127.0.0.1:${PORT}"
for _ in $(seq 1 30); do
  docker run --rm --network host --entrypoint cast "$IMG_FOUNDRY" \
    block-number --rpc-url "$RPC" >/dev/null 2>&1 && break
  sleep 1
done

# ---------------------------------------------------------------------------
# 3. Expected output length per precompile, and whether zero is a legitimate
#    answer. Lengths are from the EIPs, not from observation - an implementation
#    that returned the wrong width would be a finding, not a new baseline.
# ---------------------------------------------------------------------------
expected_len() {
  case "$1" in
    1) echo 32 ;;    5) echo 32 ;;    6) echo 64 ;;     7) echo 64 ;;
    8) echo 32 ;;    9) echo 64 ;;    10) echo 64 ;;    11) echo 128 ;;
    12) echo 128 ;;  13) echo 256 ;;  14) echo 256 ;;   15) echo 32 ;;
    16) echo 128 ;;  17) echo 256 ;;  256) echo 32 ;;
    *) echo 0 ;;
  esac
}

# A pairing check answers 0 or 1; both are real work. Everything else returning
# all zeros means the operation short-circuited on a degenerate input.
zero_is_valid() { case "$1" in 8|15) return 0 ;; *) return 1 ;; esac; }

PASS=0; FAIL=0
while IFS=$'\t' read -r name address input; do
  target="0x$(printf '%040x' "$address")"
  out="$(docker run --rm --network host --entrypoint cast "$IMG_FOUNDRY" \
    call "$target" --rpc-url "$RPC" --data "0x${input}" 2>&1)"

  case "$out" in 0x*) ;; *)
    printf '  FAIL  %-22s call errored: %s\n' "$name" "$(echo "$out" | head -1 | cut -c1-90)"
    FAIL=$((FAIL + 1)); continue ;;
  esac

  hex="${out#0x}"
  got=$(( ${#hex} / 2 ))
  want="$(expected_len "$address")"

  if [ "$got" -ne "$want" ]; then
    reason="returned ${got} bytes, the schedule says ${want}"
    [ "$got" -eq 0 ] && reason="EMPTY RETURN - the precompile rejected this input"
    printf '  FAIL  %-22s %s\n' "$name" "$reason"
    FAIL=$((FAIL + 1)); continue
  fi

  if [ -z "${hex//0/}" ] && ! zero_is_valid "$address"; then
    printf '  FAIL  %-22s all-zero result - the operation short-circuited\n' "$name"
    FAIL=$((FAIL + 1)); continue
  fi

  printf '  ok    %-22s %3d bytes  %s\n' "$name" "$got" "$(echo "$hex" | cut -c1-24)..."
  PASS=$((PASS + 1))
done < <(docker run --rm -v "$WORK:/work" "$IMG_NODE" node -e '
  for (const r of JSON.parse(require("fs").readFileSync("/work/vectors.json"))) {
    console.log([r.name, r.address, r.input].join("\t"))
  }')

# ---------------------------------------------------------------------------
# 4. The two vectors whose exact value is known independently: both were
#    produced by curve arithmetic in scratchpad/gen_vectors.py and verified
#    there, so an exact match proves the whole path end to end.
# ---------------------------------------------------------------------------
say "checking the two independently derived answers"
check_exact() {
  local name="$1" target="$2" input="$3" want="$4"
  local got
  got="$(docker run --rm --network host --entrypoint cast "$IMG_FOUNDRY" \
    call "$target" --rpc-url "$RPC" --data "0x${input}" 2>/dev/null)"
  if [ "${got,,}" = "0x${want,,}" ]; then
    printf '  ok    %-22s matches the value derived off-chain\n' "$name"
    PASS=$((PASS + 1))
  else
    printf '  FAIL  %-22s got %s\n                             want 0x%s\n' "$name" "$got" "$want"
    FAIL=$((FAIL + 1))
  fi
}

VECTORS="$(cat "$WORK/vectors.json")"
field() { docker run --rm -v "$WORK:/work" "$IMG_NODE" node -e '
  const rows = JSON.parse(require("fs").readFileSync("/work/vectors.json"))
  process.stdout.write(rows.find((r) => r.name === process.argv[1]).input)' "$1"; }

check_exact ECRECOVER-recovers "0x$(printf '%040x' 1)" "$(field ECRECOVER)" \
  "000000000000000000000000f1985e0f473909e46899f098eaac1b92b2cb989e"
check_exact P256VERIFY-accepts "0x$(printf '%040x' 256)" "$(field P256VERIFY)" \
  "0000000000000000000000000000000000000000000000000000000000000001"

echo
say "${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ] || exit 1
