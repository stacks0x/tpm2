# Windows: Platform Crypto Provider (PCP)

On Windows, node-tpm2 uses the **Microsoft Platform Crypto Provider** for attestation keys — not raw TBS wrapped blobs. Linux continues to use ECDSA TBS-wrapped blobs; AK formats differ by design and verifiers should accept both.

## Operations and privilege

| Operation | Standard user | Elevated admin | SYSTEM |
|-----------|---------------|----------------|--------|
| `Tpm.isAvailable()`, PCR read, `readPublic` | Yes | Yes | Yes |
| `provisionAk()` user scope (`PCP1`) | Yes | Yes | Yes |
| `quote()` | Yes | Yes | Yes |
| `provisionAk({ scope: 'machine' })` (`PCP2`) | No | Yes | Yes (production enroll) |
| `activateCredential()` (PCP) | No | Yes | Yes |

**Runtime apps** typically only need `quote()` with a blob/locator from enrollment. Activation is an enrollment-time proof-of-possession step.

## AK blob formats

| Magic | Scope | Meaning |
|-------|-------|---------|
| `PCP1` | User | Dev / same-user flows; random key name if omitted |
| `PCP2` | Machine | Fleet / cross-user; stable `keyName` required |

Blob layout: magic + key name + PCP creation attestation fields (`public` holds metadata; `private` is empty).

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
