#!/usr/bin/env bash
set -euo pipefail

url="${1:?artifact URL is required}"
expected_sha256="${2:?artifact SHA-256 is required}"
expected_size="${3:?artifact byte size is required}"
output="${4:?output path is required}"
# Default parallelism is deliberately modest: 32-way range reads have been
# observed to draw S3 connection resets and silent mid-transfer stalls on
# rented hosts, and a stalled part previously hung the whole build.
parallelism="${RISC0_FETCH_PARALLELISM:-8}"
chunk_size="${RISC0_FETCH_CHUNK_SIZE:-8388608}"
chunk_dir=$(mktemp -d)
trap 'rm -rf "${chunk_dir}"' EXIT

part_count=$(( (expected_size + chunk_size - 1) / chunk_size ))

download_part() {
  local part="$1"
  local start=$(( part * chunk_size ))
  local end=$(( start + chunk_size - 1 ))
  local target
  if (( end >= expected_size )); then
    end=$(( expected_size - 1 ))
  fi
  target=$(printf '%s/part-%03d' "${chunk_dir}" "${part}")
  # --speed-* abort a transfer that stalls below 10 KiB/s for 30 s and
  # --max-time bounds any single attempt, so a dead-but-open connection
  # fails fast and the retry budget can actually help.
  curl --fail --location --silent --show-error \
    --retry 8 --retry-all-errors --connect-timeout 15 \
    --speed-time 30 --speed-limit 10240 --max-time 600 \
    --range "${start}-${end}" --output "${target}" "${url}"
  test "$(stat -c '%s' "${target}")" -eq "$(( end - start + 1 ))"
}

export -f download_part
export url expected_size chunk_size chunk_dir
seq 0 $(( part_count - 1 )) | xargs -P "${parallelism}" -n 1 bash -c 'download_part "$1"' _

rm -f "${output}.tmp"
for part in $(seq 0 $(( part_count - 1 ))); do
  part_path=$(printf '%s/part-%03d' "${chunk_dir}" "${part}")
  cat "${part_path}" >> "${output}.tmp"
done
test "$(stat -c '%s' "${output}.tmp")" -eq "${expected_size}"
echo "${expected_sha256}  ${output}.tmp" | sha256sum --check --strict
mv "${output}.tmp" "${output}"
