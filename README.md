# node-tpm2

Native TPM 2.0 for Node.js. Prebuilt binaries — no `tpm2-tools`, no `tpm2-tss`, no Rust at install time.

Talks to the TPM through OS-native paths: **TBS + Platform Crypto Provider** on Windows, **`/dev/tpmrm0`** on Linux. Returns buffers and typed records, not CLI text.

```javascript
import { Tpm } from 'node-tpm2';

if (!(await Tpm.isAvailable())) throw new Error('No TPM');

await using tpm = await Tpm.open();

const ak = await tpm.attest.provisionAk();
const { message, signature } = await ak.quote({
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('challenge-nonce'),
});
```

**Pre-release** (`0.0.x-beta`). [Roadmap](./docs/roadmap.md) for remaining namespaces.

---

## Install

```bash
npm install node-tpm2
```

Node **20+**. One prebuilt `.node` per platform via optional dependencies.

---

## Examples

### Check the TPM

```javascript
import { Tpm } from 'node-tpm2';

if (!(await Tpm.isAvailable())) {
  console.log('No TPM or no access');
  process.exit(1);
}

const info = await Tpm.info();
console.log(info.manufacturer, info.firmwareVersion, info.isVirtual ? '(virtual)' : '');
```

### Device attestation (dev / same-user)

Provision a user-scoped attestation key, quote PCRs bound to a server challenge, send `message` + `signature` + `akPublicDer` to your verifier.

```javascript
import { Tpm } from 'node-tpm2';
import { writeFileSync } from 'node:fs';

const challenge = Buffer.from('server-issued-nonce-or-session-id');

const { akPublicDer, akBlob } = await Tpm.provisionAk();
writeFileSync('ak.blob.json', JSON.stringify({
  public: akBlob.public.toString('base64'),
  private: akBlob.private.toString('base64'),
}));

const { message, signature } = await Tpm.quote({
  akBlob,
  pcrSelection: [0, 1, 7],
  qualifyingData: challenge,
});

// → POST { akPublicDer, message, signature, pcrSelection } to your backend
```

### Handle style (grouped API)

```javascript
import { Tpm } from 'node-tpm2';

await using tpm = await Tpm.open();

const pcrs = await tpm.pcr.read([0, 1, 7]);
const ekCert = await tpm.attest.ekCertificate();   // Buffer | null

const ak = await tpm.attest.provisionAk();
const quote = await ak.quote({
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('challenge'),
});

const saved = ak.export();   // persist { public, private } for next session
```

### Windows fleet enrollment

**Threat model:** A machine AK proves **this enrolled device**, not which app or user quoted. The blob is a locator (`keyName`), not a secret — see [Threat model in windows-pcp.md](./docs/windows-pcp.md#threat-model-device-vs-application).

**Once** at install time (Admin or SYSTEM): create a machine-scoped key with a stable name and persist the blob.

```javascript
import { Tpm } from 'node-tpm2';
import { writeFileSync } from 'node:fs';

// Run elevated or as SYSTEM — see docs/windows-pcp.md
const { akPublicDer, akBlob } = await Tpm.provisionAk({
  keyName: 'my-app-device-ak',
  scope: 'machine',
  overwrite: true,
});

writeFileSync('C:\\ProgramData\\my-app\\ak.blob.json', JSON.stringify({
  public: akBlob.public.toString('base64'),
  private: akBlob.private.toString('base64'),
}));
// Register akPublicDer + creation data with your enrollment service
```

**Every runtime session** (standard user): load the blob and quote — no elevation.

```javascript
import { Tpm } from 'node-tpm2';
import { readFileSync } from 'node:fs';

const raw = JSON.parse(readFileSync('C:\\ProgramData\\my-app\\ak.blob.json', 'utf8'));
const akBlob = {
  public: Buffer.from(raw.public, 'base64'),
  private: Buffer.from(raw.private, 'base64'),
};

const quote = await Tpm.quote({
  akBlob,
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('runtime-challenge'),
});
```

### Read PCRs and TPM objects

```javascript
import { Tpm } from 'node-tpm2';

await using tpm = await Tpm.open();

const digests = await tpm.pcr.read([0, 1, 7]);           // { 0: 'abc…', … }
const ek = await tpm.readPublic('0x81010001');           // endorsement key
const { publicKeyDer, name } = ek;
```

### Credential activation (enrollment proof-of-possession)

```javascript
import { Tpm } from 'node-tpm2';

// credentialBlob + secret from your verifier's MakeCredential step
const recovered = await Tpm.activateCredential({
  akBlob,
  credentialBlob,
  secret,
});
// recovered → proves AK is on the TPM that owns the EK
```

### Errors

```javascript
import { Tpm, TpmError } from 'node-tpm2';

try {
  await Tpm.provisionAk({ scope: 'machine', keyName: 'fleet-ak' });
} catch (err) {
  if (err instanceof TpmError && err.code === 'REQUIRES_ELEVATION') {
    // Windows: run enrollment elevated or as SYSTEM, not at runtime
  }
}
```

More detail: [getting-started.md](./docs/getting-started.md) · [api-reference.md](./docs/api-reference.md) · [windows-pcp.md](./docs/windows-pcp.md) · [Error reference](#error-reference)

---

## Privilege matrix

**Legend:** ✓ standard user (with normal TPM access) · ✗ needs elevation · — not applicable · \* policy/firmware may block

| API | Linux standard user | Windows standard user | Windows Admin / SYSTEM |
|-----|:-------------------:|:---------------------:|:----------------------:|
| **Root** | | | |
| `Tpm.isAvailable()` | ✓ | ✓ | ✓ |
| `Tpm.open()` | ✓ | ✓ | ✓ |
| `tpm.info()` | ✓ | ✓ | ✓ |
| `tpm.readPublic(handle)` | ✓ | ✓ | ✓ |
| **random** | | | |
| `tpm.random.bytes(n)` | ✓ | ✓ | ✓ |
| **pcr** | | | |
| `tpm.pcr.read(...)` | ✓ | ✓ | ✓ |
| `tpm.pcr.extend(i, digest)` | ✓ † | ✗ | ✓ † |
| **nv** | | | |
| `tpm.nv.read(...)` | ✓ ‡ | ✓ ‡ | ✓ |
| `tpm.nv.write(...)` | ✓ ‡ | ✓ ‡ | ✓ |
| `tpm.attest.ekCertificate()` | ✓ | ✓ | ✓ |
| **keys** | | | |
| `tpm.keys.create(...)` | ✓ | ✓ | ✓ |
| `tpm.keys.load(blob)` | ✓ | ✓ | ✓ |
| `key.sign(digest)` | ✓ | ✓ | ✓ |
| `key.decrypt(cipher)` | ✓ | ✓ | ✓ |
| **seal** | | | |
| `tpm.seal.seal(...)` | ✓ | ✓ | ✓ |
| `tpm.unseal(blob)` | ✓ | ✓ | ✓ |
| **attest** | | | |
| `tpm.attest.provisionAk()` user | ✓ | ✓ | ✓ |
| `tpm.attest.provisionAk({ scope: 'machine' })` | — | ✗ | ✓ |
| `ak.quote(...)` / `Tpm.quote(...)` | ✓ | ✓ | ✓ |
| `ak.activateCredential(...)` | ✓ | ✗ | ✓ |

**Linux standard user** requires read/write on `/dev/tpmrm0` (commonly the `tss` group). That is a one-time deploy permission, not root for every call.

**Windows fleet pattern:** provision machine AK elevated or as SYSTEM once → persist `akBlob` → standard users quote forever after. See [docs/windows-pcp.md](./docs/windows-pcp.md).

**Planned rows** are design targets from the [roadmap](./docs/roadmap.md); unprivileged use matches the Phase 0 spike (`GetRandom`, `CreatePrimary` succeeded on Windows 11 without admin). Firmware or group policy can still deny specific PCR/NV operations on Linux — those surface as `TPM_RC`, not silent failure.

**‡ `nv.read/write`:** Success depends on index attributes and auth. Well-known EK cert indices (`0x01c00002`, `0x01c0000A`) are read-only. User-defined indices require prior `NV_DefineSpace` (not in public API).

**† `pcr.extend`:** Linux standard user (prefer indices **16–23** for experiments; avoid **0–7** boot/Secure Boot PCRs). **Windows standard user → `REQUIRES_ELEVATION`** (`TPM_E_COMMAND_BLOCKED` from TBS). Windows Administrator can extend on real hardware (validated). Standard-user failure is not `COMMAND_BLOCKED` — re-run elevated.

---

## API reference (shipped)

Import: `import { Tpm, TpmError } from 'node-tpm2'`

All flat methods also exist on `Tpm.*` (e.g. `Tpm.pcrRead` ≡ `tpm.pcr.read`).

### Availability

```javascript
await Tpm.isAvailable();              // boolean, never throws
await Tpm.info();                     // { manufacturer, firmwareVersion, isVirtual, spec }
```

### Handle

```javascript
await using tpm = await Tpm.open();
await tpm.readPublic('0x81000001');   // → { publicKeyDer, name }
```

### PCR

```javascript
await tpm.pcr.read([0, 1, 7], 'sha256');   // → { 0: 'hex…', 1: 'hex…', … }
await tpm.pcr.extend(7, digest);           // digest: 32-byte Buffer (SHA-256 bank)
await Tpm.pcrExtend(7, digest);            // flat
```

### Random

```javascript
await tpm.random.bytes(32);   // Buffer from TPM2_GetRandom
await Tpm.randomBytes(32);    // flat
```

### Keys (device-bound signing)

```javascript
const key = await tpm.keys.create({ type: 'ecc', sign: true });
const digest = crypto.createHash('sha256').update('payload').digest();
const signature = await key.sign(digest);
const saved = key.export();

const reloaded = await tpm.keys.load(saved);
await reloaded.sign(digest);
```

Flat: `Tpm.createKey()`, `Tpm.signKeyBlob({ keyBlob, digest })`. RSA `decrypt` is not yet implemented.

### Attestation

```javascript
const ak = await tpm.attest.provisionAk({
  keyName: 'my-app-device-ak',    // Windows: required for machine scope
  scope: 'machine',               // Windows: 'user' | 'machine'
  overwrite: true,
});

const akBlob = ak.export();         // { public, private }
await ak.quote({ pcrSelection: [0, 1, 7], qualifyingData: Buffer.from('nonce') });
await tpm.attest.ekCertificate();   // Buffer | null
await ak.activateCredential({ credentialBlob, secret });
```

### Flat equivalents

```javascript
await Tpm.pcrRead([0, 1, 7]);
await Tpm.readPublic('0x81010001');
await Tpm.readEkCertificate();
await Tpm.provisionAk({ scope: 'user' });
await Tpm.quote({ akBlob, pcrSelection: [7], qualifyingData: nonce });
await Tpm.activateCredential({ akBlob, credentialBlob, secret });
```

### Types

```typescript
type AkBlob = { public: Buffer; private: Buffer };

type ProvisionAkOptions = {
  keyName?: string;
  scope?: 'user' | 'machine';
  overwrite?: boolean;
};

type QuoteOptions = {
  akBlob: AkBlob;
  pcrSelection: number[];
  qualifyingData: Buffer;
  bank?: 'sha256';
};
```

---

## Error reference

Failures throw `TpmError` (subclass of `Error`). Inspect **`code`** for programmatic handling; use **`message`** for logs; **`tpmRc`** / **`hresult`** carry raw platform codes when present.

```javascript
import { Tpm, TpmError } from 'node-tpm2';

try {
  await Tpm.provisionAk({ scope: 'machine', keyName: 'fleet-ak' });
} catch (err) {
  if (err instanceof TpmError) {
    err.code;        // stable string — branch on this
    err.message;     // human detail (includes context + hex codes)
    err.suggestion;  // optional remediation
    err.tpmRc;       // TPM 2.0 response code (number), when applicable
    err.hresult;     // Windows NCrypt / Win32 HRESULT (number), when applicable
  }
}
```

**Wire format** (native → JS): `__tpm2__code|message|suggestion|tpmRc|hresult` — empty trailing fields mean undefined.

**Stability:** error **codes** are semver-stable after `latest`. New codes may be added in minors; renames require a major.

### Stable error codes

| Code | When | `tpmRc` | `hresult` | Typical `suggestion` |
|------|------|:-------:|:---------:|----------------------|
| `TPM_UNAVAILABLE` | No TPM, no native binary, macOS, or backend not built | — | — | Install platform package / check TPM |
| `ACCESS_DENIED` | OS denied device or key access | — | sometimes | Linux: `tss` group; container: pass device |
| `REQUIRES_ELEVATION` | Windows operation needs Admin/SYSTEM | — | ✓ | Re-run enrollment elevated or as SYSTEM; **`pcr.extend` from standard user** |
| `COMMAND_BLOCKED` | Windows TBS blocked raw ordinal (e.g. ActivateCredential) | ✓ | — | Use NCrypt PCP — elevation does not help |
| `NOT_SUPPORTED` | Feature or PCP capability missing on this platform | — | sometimes | — |
| `INVALID_ARGUMENT` | Bad JS/Rust option (e.g. empty machine `keyName`) | — | sometimes | Fix caller input |
| `KEY_NOT_FOUND` | NCrypt key / blob locator not found | — | ✓ | Check persisted blob / key name |
| `ALREADY_EXISTS` | NCrypt key name already exists | — | ✓ | Use `overwrite: true` |
| `MARSHALLING_ERROR` | Codec bug, malformed TPM command, or unclassified NCrypt failure | sometimes | sometimes | Report bug or check firmware |
| `TRANSPORT_ERROR` | TBS / `/dev/tpmrm0` I/O failure | — | — | Retry; check driver / device node |
| `AUTH_FAILED` | TPM auth-class response (policy / password / hierarchy) | ✓ | — | Check object auth or policy |
| `TPM_RC` | Other TPM non-success response | ✓ | — | See `tpmRc` nibble / TPM spec |

### TPM response code → `TpmError.code`

When the TPM returns a non-zero response code, the library classifies it:

| TPM RC class | Condition | Maps to | Example `tpmRc` |
|--------------|-----------|---------|-----------------|
| Success | `rc === 0` | (no error) | `0` |
| Auth | `(rc & 0x0300) === 0x0300` | `AUTH_FAILED` | `0x38E` (`TPM_RC_AUTH_FAIL`) |
| Format | `(rc & 0xFF00) === 0x0100` or FMT1 bit set | `MARSHALLING_ERROR` | `0x125` (`TPM_RC_ASYMMETRIC`) |
| Windows TBS blocked | `rc === 0x80280400` | `COMMAND_BLOCKED` * | `0x80280400` |

\* **`PCR_Extend`:** mapped to **`REQUIRES_ELEVATION`** (same `hresult` `0x80280400`) — Administrator can extend on Windows client; standard user should re-run elevated.
| Other | everything else | `TPM_RC` | vendor-specific |

Auth-class and format-class detection follows TPM 2.0 response-code layout (see `src/tbs/rc.rs`). **`tpmRc` on the error is the full 32-bit value** from the TPM response header — use it for logs and TPM spec lookup.

### Windows NCrypt HRESULT → `TpmError.code`

PCP / NCrypt failures on Windows map through `classify_ncrypt` (`src/tbs/ncrypt.rs`):

| HRESULT | Name | Typical code | Notes |
|---------|------|--------------|-------|
| `0x80090011` | `NTE_NOT_FOUND` | `KEY_NOT_FOUND` | Missing persisted key |
| `0x80090016` | `NTE_BAD_KEYSET` | `KEY_NOT_FOUND` | Key set not found |
| `0x8009000B` | `NTE_EXISTS` | `ALREADY_EXISTS` | Key name collision |
| `0x80090027` | `NTE_INVALID_PARAMETER` | `INVALID_ARGUMENT` | Bad NCrypt parameter |
| `0x80090030` | `NTE_DEVICE_NOT_READY` | `REQUIRES_ELEVATION` | Often privilege / readiness |
| `0x80090010` | `NTE_PERM` | `REQUIRES_ELEVATION` | Permission |
| `0x80090029` | `NTE_BAD_FLAGS` | `REQUIRES_ELEVATION` | Bad flags |
| `0x8009000F` | `NTE_INTERNAL_ERROR` | `REQUIRES_ELEVATION` | Machine provision from standard user (observed) |
| `0x80280084` | PCP activation / `TPM_RC_VALUE` | `REQUIRES_ELEVATION` | Standard user activation; elevated → `MARSHALLING_ERROR` |
| `0x5` / `0x80070005` | Access denied | `REQUIRES_ELEVATION` or `ACCESS_DENIED` | Machine provision → elevation |
| (other) | — | `MARSHALLING_ERROR` | Unmapped NCrypt failure |

**Transport** errors from `/dev/tpmrm0` or TBS that mention permission denied are promoted to `ACCESS_DENIED`; other I/O errors stay `TRANSPORT_ERROR`.

---

## API reference

Subsystem namespaces on `TpmHandle`. See [docs/api-reference.md](./docs/api-reference.md) for full detail.

| Namespace | Methods |
|-----------|---------|
| `tpm.random` | `bytes(n)` ✅ |
| `tpm.keys` | `create`, `load`, `KeyHandle.sign`, `KeyHandle.decrypt` ✅ |
| `tpm.pcr` | `extend(index, digest)` |
| `tpm.nv` | `read`, `write` ✅ |
| `tpm.seal` | `seal`, `unseal` ✅ |

---

## Platforms

| Platform | Status | Attestation key |
|----------|--------|-----------------|
| Linux x64/arm64 gnu/musl | Supported | ECDSA P-256 TPM2B |
| Windows x64/arm64 | Supported | RSA-2048 PCP |
| macOS | Unavailable | `isAvailable()` → `false` |

---

## Contributing

```bash
git clone https://github.com/stacks0x/tpm2.git && cd tpm2
npm install && npm run build
cargo test --lib
npm run verify:package
node examples/smoke-test.mjs runtime
```

Docs: [getting-started.md](./docs/getting-started.md) · [windows-pcp.md](./docs/windows-pcp.md) · [roadmap.md](./docs/roadmap.md)

Low-level Rust validation: `cargo run --no-default-features --features probe-bin --bin tbs-probe --` (repo only, not published to npm).

---

## License

Apache-2.0
