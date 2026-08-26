# Build the zkVM artifact tree and verify or update artifacts.lock.json.
# Requires immutable toolchain and runtime image references produced from
# zkvm/docker/risc0-cuda.Dockerfile. The toolchain compiles artifacts; the
# minimal runtime image is independently checked against the same guest ID.
param(
    [switch]$CheckRepro,
    [switch]$UpdateLock,
    [switch]$BootstrapLock,
    [switch]$SkipRust,
    [string]$ToolchainImage = $env:ZKVM_TOOLCHAIN_IMAGE,
    [string]$RuntimeImage = $env:ZKVM_RUNTIME_IMAGE
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$args_ = @("$repo\zkvm\build.mjs")

if (-not $SkipRust) {
    if (-not $ToolchainImage -or -not $RuntimeImage) {
        throw "ZKVM_TOOLCHAIN_IMAGE and ZKVM_RUNTIME_IMAGE must be immutable sha256 references"
    }
    $args_ += @(
        "--toolchain-image", $ToolchainImage,
        "--runtime-image", $RuntimeImage,
        "--cuda"
    )
}
if ($CheckRepro) { $args_ += "--check-repro" }
if ($UpdateLock) { $args_ += "--update-lock" }
if ($BootstrapLock) { $args_ += "--bootstrap-lock" }
if ($SkipRust) { $args_ += "--skip-rust" }

node @args_
exit $LASTEXITCODE
