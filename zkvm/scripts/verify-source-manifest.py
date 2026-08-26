#!/usr/bin/env python3
"""Verify a candidate zkVM source manifest against bytes copied into Docker."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unicodedata


FORMAT = "zkdeal/zkvm-source-manifest/v1"
SOURCE_ROOTS = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "build-config.mjs",
    "build-exec.mjs",
    "build-lock.mjs",
    "build.mjs",
    "lock-schema.mjs",
    "crates/risc0/methods",
    "crates/risc0/host",
    "crates/risc0/wasm-verifier",
    "crates/stf-core",
    "crates/stf-types",
    "crates/stf-wire",
    "docker",
    "scripts",
    "vendor/risc0-groth16-sys",
    "vendor/risc0-sys",
    "vendor/rustcrypto-sources.json",
    "vendor/rustcrypto-crypto-bigint",
    "vendor/rustcrypto-k256",
]
IGNORED = {"target", "build", ".git", "node_modules"}


def normalized_relative(root: Path, path: Path) -> str:
    return unicodedata.normalize("NFC", path.relative_to(root).as_posix())


def collect(root: Path, path: Path, files: list[dict[str, object]]) -> None:
    if not path.exists() and not path.is_symlink():
        raise ValueError(f"source-manifest root is missing: {normalized_relative(root, path)}")
    if path.is_symlink():
        raise ValueError(f"source-manifest symlinks are forbidden: {normalized_relative(root, path)}")
    if path.is_file():
        payload = path.read_bytes()
        files.append(
            {
                "path": normalized_relative(root, path),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "executable": payload.startswith(b"#!"),
            }
        )
        return
    if not path.is_dir():
        raise ValueError(f"unsupported source-manifest entry: {path}")
    for child in sorted(
        path.iterdir(),
        key=lambda value: unicodedata.normalize("NFC", value.name).encode("utf-8"),
    ):
        if child.name not in IGNORED:
            collect(root, child, files)


def files_digest(files: list[dict[str, object]]) -> str:
    payload = "".join(
        f"{item['sha256']} {item['size']} {'x' if item['executable'] else '-'} {item['path']}\n"
        for item in files
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify-source-manifest.py <zkvm-root> <manifest.json>")
    root = Path(sys.argv[1]).resolve(strict=True)
    manifest_path = Path(sys.argv[2]).resolve(strict=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != FORMAT or manifest.get("algorithm") != "sha256":
        raise ValueError("candidate has the wrong source-manifest format")
    if manifest.get("sourceRoots") != SOURCE_ROOTS:
        raise ValueError("candidate sourceRoots differ from the Docker build contract")
    files: list[dict[str, object]] = []
    for relative in SOURCE_ROOTS:
        collect(root, root / relative, files)
    files.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    if files != manifest.get("files"):
        raise ValueError("candidate file inventory or SHA-256 values differ from copied sources")
    if files_digest(files) != manifest.get("filesDigest"):
        raise ValueError("candidate filesDigest differs from copied sources")
    print(f"verified {len(files)} source files against {manifest_path}")


if __name__ == "__main__":
    main()
