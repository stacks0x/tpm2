#!/usr/bin/env bash
# Hardware credential probes for feature/provision-ak (no npm publish required).
#
# Usage (on VM after git pull):
#   ./scripts/vm-credential-test.sh
#
# Writes a log alongside console output:
#   ./scripts/vm-credential-test.sh | tee vm-credential-test.log
#
# Optional:
#   TPM2_DUMP_CMD=1 ./scripts/vm-credential-test.sh
#
# Safe: read-only TPM ops except transient CreatePrimary/Load/FlushContext.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG="${VM_CREDENTIAL_TEST_LOG:-$ROOT/vm-credential-test.log}"
: >"$LOG"

# Status/progress on stderr so it stays visible even when stdout is piped to tee.
log() {
  echo "$@" | tee -a "$LOG" >&2
}

log "== node-tpm2 VM credential test =="
log "repo:   $ROOT"
log "branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
log "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "log:    $LOG"
log

if [[ ! -e /dev/tpmrm0 ]]; then
  log "ERROR: /dev/tpmrm0 not found. Install/start swtpm or ensure TPM resource manager is up."
  exit 1
fi

if ! command -v cargo >/dev/null; then
  log "ERROR: cargo not found (install Rust: https://rustup.rs)"
  exit 1
fi

export CARGO_TERM_COLOR=always
export TPM2_HARDWARE_TEST=1

log "== building tbs-probe (first run may take a few minutes) =="
if ! cargo build --no-default-features --features probe-bin --bin tbs-probe 2>&1 | tee -a "$LOG"; then
  log "FAIL  cargo build"
  exit 1
fi
PROBE=(cargo run --no-default-features --features probe-bin --bin tbs-probe --)
log "PASS  cargo build"
log

log "== unit tests (no hardware) =="
if ! cargo test --no-default-features 2>&1 | tee -a "$LOG"; then
  log "FAIL  unit tests"
  exit 1
fi
log "PASS  unit tests"
log

run_probe() {
  local name=$1
  shift
  log "== $name =="
  # Probe stdout goes to console and log; progress stays on stderr via log().
  if "${PROBE[@]}" "$@" 2>&1 | tee -a "$LOG"; then
    log "PASS  $name"
  else
    log "FAIL  $name (exit ${PIPESTATUS[0]})"
    return 1
  fi
  log
}

FAIL=0
run_probe "get-random" get-random || FAIL=1
run_probe "pcr-read" pcr-read || FAIL=1
run_probe "quote" quote || FAIL=1
run_probe "provision-ak" provision-ak || FAIL=1
run_probe "policy-secret" policy-secret || FAIL=1
run_probe "activate-credential" activate-credential || FAIL=1

log "== summary =="
if [[ "$FAIL" -eq 0 ]]; then
  log "All probes passed."
  exit 0
else
  log "One or more probes failed (see output above and $LOG)."
  log "Baseline: TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2 startauthsession -S policy --session=/tmp/s.ctx"
  log "          TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2 policysecret -S /tmp/s.ctx -c endorsement"
  exit 1
fi
