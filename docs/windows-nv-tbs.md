# Windows TBS: NV command research (node-tpm2)

Reference for **hand-marshalled NV commands** on Windows raw TBS. Derived from
[tpm2-tss](https://github.com/tpm2-software/tpm2-tss) `Tss2_Sys_NV_*_Prepare` — not
guessed from Part 3 prose alone.

## Why this doc exists

Windows TBS is strict about handle vs parameter placement. Several beta releases
fixed one command at a time without cross-checking the full matrix against TSS.
**Do not publish another NV beta until all rows below pass golden-byte tests and
`nv-smoke` on the Windows test laptop.**

## Command wire layout (session commands, tag `0x8002`)

```
tag(2) | size(4) | code(4) | handles... | authAreaSize(4) | authSessions... | parameters...
```

Password session (null auth): 9 bytes — `TPM_RH_PW`, empty nonce TPM2B, continueSession, empty auth TPM2B.

## NV command matrix (TSS Prepare order)

| Command | Handles | Parameters (after auth) | Notes |
|---------|---------|------------------------|-------|
| `NV_ReadPublic` | `[nvIndex]` | *(none)* | `TPM_ST_NO_SESSIONS` |
| `NV_DefineSpace` | `[TPM_RH_OWNER]` | `auth` TPM2B, `publicInfo` TPM2B | |
| `NV_UndefineSpace` | `[TPM_RH_OWNER, nvIndex]` | *(none)* | **nvIndex is handle 2, not a param** |
| `NV_Read` | `[authHandle, nvIndex]` | **`size` u16, `offset` u16** | TSS order is size→offset |
| `NV_Write` | `[authHandle, nvIndex]` | **`data` TPM2B, `offset` u16** | TSS order is data→offset |

When `authHandle == nvIndex` (index-auth attributes), only one handle is sent; params omit nvIndex.

## Windows-specific behavior

| Operation | Standard user | Admin | Notes |
|-----------|---------------|-------|-------|
| `NV_DefineSpace` / `NV_UndefineSpace` | `REQUIRES_ELEVATION` | OK | TBS `0x80280400` |
| `NV_ReadPublic` owner range | Often fails ~`0xA6` | Often fails | Factory EK indices OK; use define size for bounds |
| `NV_Read` response | — | — | Use `parameters_after_rc` (session tag, param-size prefix quirks) |
| `NV_Write` | — | OK on test hw | Validated beta.2+ |

## Response parsing

| Response | Parser |
|----------|--------|
| `NV_ReadPublic` | `parse_nv_read_public_fields` (Linux param-size prefix vs Windows direct TPM2B) |
| `NV_Read` | `parameters_after_rc` then `read_tpm2b`, fallback `after_rc` |
| `NV_Write` | RC only (no payload) |

## Validation checklist (before npm publish)

**On dev machine (zero TPM contact — no hardware I/O):**

```bash
cargo test --lib nv::tests -- --skip hw_
npm run build
npm run verify:package
```

**On Windows test laptop only (Admin, mutating):**

```powershell
npm install node-tpm2@beta
node node_modules\node-tpm2\examples\nv-smoke.mjs
```

Expected: define → write → read roundtrip → undefine → `nv-smoke: OK`.

## Known beta history (avoid repeating)

| Version | Issue |
|---------|-------|
| beta.0 | `NV_UndefineSpace`: nvIndex in params not handles |
| beta.1 | Same; define elevation mapping |
| beta.2 | Read/write handles fixed; read **response** not parsed; read params were size→offset |
| beta.3 | Incorrectly swapped read params to offset→size — **do not use**; fix reverts to TSS size→offset + response parser |
