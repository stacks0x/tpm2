#!/usr/bin/env bash
# Hardware credential probes for feature/provision-ak (no npm publish required).
#
# Usage (on VM after git pull):
#   ./scripts/vm-credential-test.sh
#
# Optional:
#   TPM2_DUMP_CMD=1 ./scripts/vm-credential-test.sh   # hex-dump PolicySecret command
#
# Safe: read-only TPM ops except transient CreatePrimary/Load/FlushContext.
# Does NOT Clear, EvictControl, PCR_Extend, or NV_Write.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROBE=(cargo run --no-default-features --features probe-bin --bin tbs-probe --)

echo "== node-tpm2 VM credential test =="
echo "repo: $ROOT"
echo "branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo

if [[ ! -e /dev/tpmrm0 ]]; then
  echo "ERROR: /dev/tpmrm0 not found. Install/start swtpm or ensure TPM resource manager is up."
  exit 1
fi

if ! command -v cargo >/dev/null; then
  echo "ERROR: cargo not found (install Rust: https://rustup.rs)"
  exit 1
fi

echo "== unit tests (no hardware) =="
cargo test --no-default-features -q
echo "PASS  unit tests"
echo

export TPM2_HARDWARE_TEST=1

run_probe() {
  local name=$1
  shift
  echo "== $name =="
  if "${PROBE[@]}" "$@"; then
    echo "PASS  $name"
  else
    echo "FAIL  $name (exit $?)"
    return 1
  fi
  echo
}

FAIL=0
run_probe "get-random" get-random || FAIL=1
run_probe "pcr-read" pcr-read || FAIL=1
run_probe "quote" quote || FAIL=1
run_probe "provision-ak" provision-ak || FAIL=1
run_probe "policy-secret" policy-secret || FAIL=1
run_probe "activate-credential" activate-credential || FAIL=1

echo "== summary =="
if [[ "$FAIL" -eq 0 ]]; then
  echo "All probes passed."
  exit 0
else
  echo "One or more probes failed."
  echo "policy-secret / activate-credential may still fail on some swtpm EK policies;"
  echo "compare with: TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2 policysecret -S /tmp/s.ctx -c endorsement"
  exit 1
fi
