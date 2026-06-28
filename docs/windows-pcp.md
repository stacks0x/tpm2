# Windows: Platform Crypto Provider (PCP)

On Windows, node-tpm2 uses the **Microsoft Platform Crypto Provider** for attestation keys — not raw TBS wrapped blobs. Linux continues to use ECDSA TBS-wrapped blobs; AK formats differ by design and verifiers should accept both.

## Operations and privilege

| Operation | Standard user | Elevated admin | SYSTEM |
|-----------|---------------|----------------|--------|
| `Tpm.isAvailable()`, PCR read, `readPublic` | Yes | Yes | Yes |
| `tpm.pcr.extend` | Yes † | No (`REQUIRES_ELEVATION`) | Yes † |
| `provisionAk()` user scope (`PCP1`) | Yes | Yes | Yes |
| `quote()` | Yes | Yes | Yes |
| `provisionAk({ scope: 'machine' })` (`PCP2`) | No | Yes | Yes (production enroll) |
| `activateCredential()` (PCP) | No | Yes | Yes |

**Runtime apps** typically only need `quote()` with a blob/locator from enrollment. Activation is an enrollment-time proof-of-possession step.

**† `pcr.extend`:** Prefer PCR indices **16–23** (not **0–7**, which are boot/Secure Boot measurements). Standard users receive **`REQUIRES_ELEVATION`** (`hresult` `0x80280400`); **Administrator** can extend (validated on real Intel laptop). Linux standard user can extend unless firmware locks the index.

## AK blob formats

| Magic | Scope | Meaning |
|-------|-------|---------|
| `PCP1` | User | Dev / same-user flows; random key name if omitted |
| `PCP2` | Machine | Fleet / cross-user; stable `keyName` required |

Blob layout: magic + key name + PCP creation attestation fields (`public` holds metadata; `private` is empty).

## Threat model: device vs application

**A quote proves an enrolled device, not a specific app or user.**

On Windows, a machine-scoped attestation key (`PCP2`) is a **host-local capability**, not a secret. The exported blob is mainly a **locator**: magic, `keyName`, and scope. At quote time the library opens the persisted PCP key by that name. Any standard-user process that knows the fleet `keyName` can obtain a valid quote from the same AK — that is how cross-user runtime quoting works after one-time elevated provisioning.

This is inherent to device attestation on Windows (and similar on Linux: anyone with read/write on `/dev/tpmrm0` can use a copied AK blob on the same TPM). It is **not** a library bug and should not be “fixed” by treating the blob as a password.

| What a quote establishes | What it does **not** establish |
|--------------------------|--------------------------------|
| The TPM that was enrolled still holds the AK | Which Windows process produced the quote |
| PCR values at quote time match the attestation | Which human user clicked “sign in” |
| `qualifyingData` matches what the verifier sent (if you set it) | That only your product binary ran |

**Your enrollment service** should bind identity at enroll time: verify `akPublicDer`, optionally verify PCP creation attestation fields in the blob, register the device once, then issue runtime challenges via `qualifyingData`. **App and user binding** are separate layers (session auth, mTLS, OS login, etc.).

Use a **vendor-prefixed, stable `keyName`** for machine scope (for example `my-app-device-ak`). Do not rely on secrecy of the blob or key name; rely on TPM possession + server-side enrollment records + challenge nonces.

## Machine key provisioning

```javascript
await Tpm.provisionAk({
  keyName: 'my-app-device-ak',  // your product prefix, not library-specific
  scope: 'machine',
  overwrite: true,              // replaces existing key of same name
});
```

Requirements:

- PCP must advertise **Security Descr Support** (probe: `tbs-probe pcp-capabilities`)
- Machine keys get a DACL granting Built-in Users read/sign so standard users can open and quote
- PCP ignores `NCRYPT_OVERWRITE_KEY_FLAG`; the library deletes an existing key before recreate when `overwrite: true`

## Quote scheme

PCP identity keys are RSA-2048. Quotes use `TPM_ALG_NULL` (key default RSASSA), matching go-attestation. Linux uses explicit ECDSA+SHA256.

## Errors at enrollment time

Machine provisioning from a standard user returns `TpmError` with `code: 'REQUIRES_ELEVATION'` and an NCrypt `hresult`. Runtime quote failures use the same structured error shape (`tpmRc` for TPM, `hresult` for PCP/NCrypt).

## Validating with `tbs-probe` (Rust, developers only)

The npm module and `tbs-probe` share the same Rust core but are **different artifacts**. Validate Rust with the probe; validate the **npm package** with [examples/smoke-test.mjs](../examples/smoke-test.mjs) on a clean machine.

```powershell
# Runtime path (standard PowerShell)
cargo run --no-default-features --features probe-bin --bin tbs-probe -- all

# SYSTEM provision + standard quote — see `tbs-probe help`
```

## Simulating SYSTEM locally

Intune/SCCM/GPO run enrollment as **SYSTEM**, not interactive admin. On a dev VM, use a one-shot scheduled task (no extra tools):

```powershell
# Admin PowerShell — see tbs-probe help for full script
schtasks /Create /TN "my-app-system-provision" /RU SYSTEM ...
schtasks /Run /TN "my-app-system-provision"
```

Then quote from standard PowerShell with the saved AK blob.
