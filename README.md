# node-tpm2

**TPM 2.0 attestation for Node.js** — prebuilt native bindings, no `tpm2-tools`, no `tpm2-tss`, no Rust toolchain at install time.

Use the TPM your OS already exposes: **TBS + Platform Crypto Provider** on Windows, **`/dev/tpmrm0`** on Linux. One small API for PCR reads, attestation key provisioning, quotes, and credential activation.

```javascript
import { Tpm } from 'node-tpm2';

const tpm = await Tpm.open();

const { akPublicDer, akBlob } = await tpm.attest.provisionAk();
const quote = await tpm.attest.quote({
  akBlob,
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('your-challenge-nonce'),
});

// quote.message + quote.signature → send to your verifier
```

## Why node-tpm2

| | node-tpm2 | Shelling out to tpm2-tools |
|---|-----------|----------------------------|
| Install | `npm install` + prebuilt `.node` | OS packages, PATH, version drift |
| API | Async JavaScript, structured errors | Parse CLI output |
| Windows fleet | Machine-scoped PCP keys, cross-user quote | PCP/NCrypt scripting pain |
| AK persistence | Wrapped blob (`akBlob`) — no persistent TPM handles in your app | Handle bookkeeping |

**Use it when you need:**

- **Device attestation** — prove boot/software state via PCR quotes bound to a challenge nonce
- **Fleet enrollment** — provision a machine-scoped attestation key at install time (Intune, SCCM, GPO); quote at runtime as the logged-in user
- **Remote verification** — export AK public key (SPKI DER) and quote blobs to your backend; verify with standard TPM quote rules
- **EK-backed onboarding** — read the EK certificate, activate credentials during enrollment

## How it works

```
┌─────────────────────────────────────────────────────────┐
│  Your Node app (Tpm.open / flat helpers)                │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│  node-tpm2 (napi-rs) — command build, sessions, blobs   │
└──────────────┬─────────────────────────┬────────────────┘
               │                         │
     Linux     │                         │  Windows
               ▼                         ▼
        /dev/tpmrm0              TBS + NCrypt PCP
        ECDSA P-256 AK           RSA-2048 persisted AK
        TPM2B wrapped blob       PCP1 (user) / PCP2 (machine)
```

- **No persistent TPM handles in your process.** You keep an `akBlob` (portable wrapped key material). Each operation loads transiently, signs, and flushes.
- **Platform-native AK formats.** Linux uses ECDSA P-256 TPM2B blobs; Windows uses Microsoft PCP (`PCP1` user / `PCP2` machine). Verifiers should accept both.
- **Structured errors.** Failures throw `TpmError` with stable `code`, optional `suggestion`, `tpmRc` (TPM return code), and `hresult` (Windows NCrypt).

## Install

```bash
npm install node-tpm2
```

Node **20+**. npm installs a prebuilt native binary for your OS/arch via optional platform packages.

## API at a glance

**Handle style** (grouped operations):

```javascript
const tpm = await Tpm.open();

await tpm.info();                          // manufacturer, firmware, virtual-TPM hint
await tpm.pcr.read([0, 1, 7]);             // SHA-256 PCR digests
await tpm.attest.ekCertificate();          // EK cert from NV, or null

const ak = await tpm.attest.provisionAk();   // returns AkHandle
await ak.quote({ pcrSelection: [7], qualifyingData: nonce });
await ak.export();                           // persist akBlob
await ak.activateCredential({ credentialBlob, secret });

await using tpm = await Tpm.open();        // Symbol.asyncDispose when done
```

**Flat style** (same operations, functional entry points):

```javascript
await Tpm.isAvailable();
await Tpm.provisionAk({ keyName: 'my-app-ak' });
await Tpm.quote({ akBlob, pcrSelection: [0], qualifyingData: nonce });
await Tpm.pcrRead([0, 1, 7]);
await Tpm.readEkCertificate();
await Tpm.activateCredential({ akBlob, credentialBlob, secret });
```

Errors:

```javascript
try {
  await Tpm.provisionAk({ scope: 'machine', keyName: 'fleet-ak' });
} catch (err) {
  if (err.code === 'REQUIRES_ELEVATION') {
    // Windows: machine keys need Admin/SYSTEM at provision time only
  }
}
```

Full reference: [docs/getting-started.md](./docs/getting-started.md) · Windows fleet: [docs/windows-pcp.md](./docs/windows-pcp.md)

## Privileges (honest summary)

There is **no separate TPM daemon to install**, but the OS still controls access:

| | Linux | Windows |
|---|-------|---------|
| **Typical runtime** (quote, PCR read) | User in `tss` group (or equivalent access to `/dev/tpmrm0`) | Standard user — no elevation |
| **User-scoped AK** (`provisionAk()`) | Same as runtime | Standard user |
| **Machine-scoped AK** (`scope: 'machine'`) | N/A | **Admin or SYSTEM at enrollment** — then standard users quote with the saved blob |
| **Credential activation** | TPM policy dependent | Elevated / SYSTEM |

**Fleet pattern:** installer runs once elevated (or as SYSTEM) → saves `akBlob` → app quotes unprivileged forever after. See [docs/windows-pcp.md](./docs/windows-pcp.md).

## Validate your install

```bash
npm ls node-tpm2
node node_modules/node-tpm2/examples/smoke-test.mjs runtime
```

Windows fleet smoke (elevated provision, then standard-user quote):

```bash
node node_modules/node-tpm2/examples/smoke-test.mjs provision-machine --key-name my-app-device-ak --out ak.blob.json
node node_modules/node-tpm2/examples/smoke-test.mjs quote --in ak.blob.json
```

Use paths under `node_modules/node-tpm2/` after `npm install` (not `examples/` at the project root).

## Platform support

| Platform | Status | Attestation key |
|----------|--------|-----------------|
| Linux (glibc/musl, x64/arm64) | Supported | ECDSA P-256 TPM2B |
| Windows (x64/arm64) | Supported | RSA-2048 PCP |
| macOS | Not supported (`isAvailable()` → false) | — |

## Development

```bash
git clone https://github.com/stacks0x/tpm2.git && cd tpm2
npm install && npm run build
node examples/smoke-test.mjs runtime
```

Rust probe for low-level validation (repo only, **not** published to npm):

```powershell
cargo run --no-default-features --features probe-bin --bin tbs-probe -- all
```

## License

Apache-2.0
