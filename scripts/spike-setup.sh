#!/usr/bin/env bash
# Phase 0 spike prerequisites.
set -euo pipefail

echo "node-tpm2 Phase 0 spike"
echo

if ! command -v rustc >/dev/null; then
  echo "Install Rust: https://rustup.rs"
  exit 1
fi

if [[ "$(uname -s)" == "Linux" ]]; then
  echo "Linux — harness smoke only (does not close Phase 0)."
  echo "  sudo apt install pkg-config libtss2-dev build-essential"
  echo "  cargo run --features esapi --bin spike -- all"
  echo
elif [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ -n "${WINDIR:-}" ]]; then
  echo "Windows — Phase 0 decision runs here (non-elevated PowerShell)."
  echo "  1. cargo run --bin tbs-probe"
  echo "  2. cargo build --features esapi"
  echo "  3. cargo run --features esapi --bin spike -- quote"
  echo
  echo "Use swtpm in the VM; do not passthrough host fTPM."
else
  echo "Platform: $(uname -s)"
fi

echo "Default build (no esapi): cargo build"
echo "See spike/README.md for the decision matrix."
