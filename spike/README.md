# Spike probes — direct TBS validation

Historical Phase 0 probes. **Decision: Option B (direct TBS, no tpm2-tss).** Both privilege
gates passed unprivileged on Windows 11 (June 2026).

## Environment (Windows)

- Windows 11 guest with swtpm emulated TPM (**not** host passthrough)
- Manufacturer **IBM** is expected (swtpm)
- Every run: **non-elevated PowerShell**. Elevation defeats the test.

## Probes

| Probe | Feature | Depends on | Purpose |
|-------|---------|------------|---------|
| `tbs-probe` | (default) | `windows` crate only | Unprivileged TBS + CreatePrimary |
| `spike` | `esapi` | tss-esapi + tpm2-tss | Option A harness (Linux smoke) |

`cargo build` with default features does **not** pull tss-esapi.

## Run on Windows VM (non-elevated PowerShell)

```powershell
cargo run --bin tbs-probe -- all
```

CreatePrimary uses owner-hierarchy **password session** auth (null password) and ECC P256
storage template. On success the probe **flushes the transient primary** it created
(`FlushContext` / `GetCapability handles-transient` fallback on `0x80xxxxxx` only).

**Transient handle note:** swtpm returns `0x80FFFFFF` as the loaded transient slot. That is
the real handle (confirmed via `GetCapability handles-transient`), not a parse error.
`FlushContext` uses command code `0x165` (`00 00 01 65`). Windows TBS requires reusing one
`Tbsi_Context_Create` per process — a new context per command yields `TPM_RC_HANDLE` on flush.

```powershell
# Option A feasibility (expected FAIL on Windows — closed)
cargo build --features esapi
```

### RC discipline (CreatePrimary)

| TPM_RC | Meaning | Action |
|--------|---------|--------|
| `0x00000000` | PASS | Unprivileged provisioning works |
| Auth-class (`FMT1 \| A`) | Hierarchy wants auth | Real privilege failure |
| Format-class (`FMT1`, not auth) | Malformed command | Fix marshalling |
| Other | Unexpected | Investigate |

## Linux (esapi harness smoke only)

Does not answer Windows architecture questions.

```bash
sudo apt install pkg-config libtss2-dev build-essential
cargo run --features esapi --bin spike -- all
```

## Outcome

| Check | Result |
|-------|--------|
| Unprivileged `GetRandom` via TBS | **PASS** |
| Unprivileged owner-hierarchy `CreatePrimary` | **PASS** |
| Option A (`tss-esapi` on Windows) | **FAIL** → Option B chosen |

Library work continues on Option B in the main crate and napi bindings.
