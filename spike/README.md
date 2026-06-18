# Phase 0 spike — decoupled probes

Phase 0 answers two **independent** Windows questions. Linux is harness smoke only; it does not close Phase 0.

## Environment (Windows)

- Target: Windows 11 guest in virt-manager (swtpm emulated TPM — **not** host passthrough)
- Manufacturer reporting **IBM** is expected (swtpm)
- Every privilege run: **non-elevated PowerShell**. Elevation defeats the test.

## Two probes

| Probe | Feature | Depends on | Answers |
|-------|---------|------------|---------|
| `tbs-probe` | (default) | `windows` crate only | Can a normal user reach TPM through TBS? |
| `spike` | `esapi` | tss-esapi + tpm2-tss | Option A build + full quote/blob sequence |

`cargo build` with default features does **not** pull tss-esapi. `tbs-probe` must build even if tpm2-tss never builds on Windows.

## Run order on Windows VM (non-elevated PowerShell)

```powershell
# 1. Baseline TBS + owner-hierarchy CreatePrimary (direct TBS, no tpm2-tss)
cargo run --bin tbs-probe -- all
# Or individually:
cargo run --bin tbs-probe -- get-random
cargo run --bin tbs-probe -- create-primary

# Debug marshalling (prints command hex):
$env:TBS_PROBE_DEBUG=1; cargo run --bin tbs-probe -- create-primary

# 2. Option A build feasibility (expected FAIL on Windows — closed)
cargo build --features esapi
```

### RC discipline (CreatePrimary)

| TPM_RC | Meaning | Action |
|--------|---------|--------|
| `0x00000000` | PASS | Unprivileged provisioning works |
| Auth-class (`FMT1 \| A`) | Hierarchy wants auth | Real privilege failure |
| Format-class (`FMT1`, not auth) | Malformed command | Fix marshalling — **not** a privilege result |
| Other | Unexpected | Investigate |

Phase 0 closes when `create-primary` returns `0x00000000` non-elevated.

## Decision matrix

| `tbs-probe` | full-sequence privilege | Windows `esapi` build | Decision |
|-------------|-------------------------|----------------------|----------|
| PASS | PASS | PASS | **Option A** (tss-esapi) |
| PASS | PASS | FAIL | **Option B** (direct-TBS codec) |
| PASS | unknown | FAIL | **Option B** — extend tbs-probe |
| FAIL | — | — | **Bigger problem** — rethink privilege model |

## Linux (harness smoke only)

Confirms spike *code* is correct against `/dev/tpmrm0`. Does not answer Windows architecture questions.

```bash
sudo apt install pkg-config libtss2-dev build-essential
cargo run --features esapi --bin spike -- all
```

## What closes Phase 0

Both Windows answers: baseline TBS (PASS/FAIL) and A-vs-B from build + full-sequence result.

## Option B extension (if `esapi` build fails)

Next command after GetRandom: `TPM2_CreatePrimary` in owner hierarchy (`0x40000001`) with standard ECC storage template, null auth. Distinguish RC classes:

- `0x000` — success, unprivileged provisioning works
- Auth-class RC — hierarchy demands privilege
- Format-class RC (`0x080` bit) — fix marshalling, not a privilege signal
