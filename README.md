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

More detail: [getting-started.md](./docs/getting-started.md) · [windows-pcp.md](./docs/windows-pcp.md)

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
| `tpm.random.bytes(n)` | ✓ *planned* | ✓ *planned* | ✓ |
| **pcr** | | | |
| `tpm.pcr.read(...)` | ✓ | ✓ | ✓ |
| `tpm.pcr.extend(i, digest)` | ✓ *planned* | ✓ *planned* | ✓ |
| **nv** | | | |
| `tpm.nv.read(...)` | ✓ *planned* | ✓ *planned* | ✓ |
| `tpm.nv.write(...)` | ✓ *planned* | ✓ *planned* | ✓ |
| `tpm.attest.ekCertificate()` | ✓ | ✓ | ✓ |
| **keys** | | | |
| `tpm.keys.create(...)` | ✓ *planned* | ✓ *planned* | ✓ |
| `tpm.keys.load(blob)` | ✓ *planned* | ✓ *planned* | ✓ |
| `key.sign(digest)` | ✓ *planned* | ✓ *planned* | ✓ |
| `key.decrypt(cipher)` | ✓ *planned* | ✓ *planned* | ✓ |
| **seal** | | | |
| `tpm.seal(...)` | ✓ *planned* | ✓ *planned* | ✓ |
| `tpm.unseal(blob)` | ✓ *planned* | ✓ *planned* | ✓ |
| **attest** | | | |
| `tpm.attest.provisionAk()` user | ✓ | ✓ | ✓ |
| `tpm.attest.provisionAk({ scope: 'machine' })` | — | ✗ | ✓ |
| `ak.quote(...)` / `Tpm.quote(...)` | ✓ | ✓ | ✓ |
| `ak.activateCredential(...)` | ✓ | ✗ | ✓ |

**Linux standard user** requires read/write on `/dev/tpmrm0` (commonly the `tss` group). That is a one-time deploy permission, not root for every call.

**Windows fleet pattern:** provision machine AK elevated or as SYSTEM once → persist `akBlob` → standard users quote forever after. See [docs/windows-pcp.md](./docs/windows-pcp.md).

**Planned rows** are design targets from the [roadmap](./docs/roadmap.md); unprivileged use matches the Phase 0 spike (`GetRandom`, `CreatePrimary` succeeded on Windows 11 without admin). Firmware or group policy can still deny specific PCR/NV operations — those surface as `TPM_RC` or `COMMAND_BLOCKED`, not silent failure.

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
```

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

### Errors

```javascript
catch (err) {
  if (err instanceof TpmError) {
    err.code;        // REQUIRES_ELEVATION | TPM_RC | ACCESS_DENIED | …
    err.tpmRc;       // TPM return code
    err.hresult;     // Windows NCrypt
    err.suggestion;
  }
}
```

---

## API reference (planned)

Subsystem namespaces not yet on `TpmHandle`. See [docs/roadmap.md](./docs/roadmap.md) for phases and acceptance criteria.

| Namespace | Methods |
|-----------|---------|
| `tpm.random` | `bytes(n)` |
| `tpm.pcr` | `extend(index, digest)` |
| `tpm.nv` | `read`, `write` |
| `tpm.keys` | `create`, `load`, `KeyHandle.sign`, `KeyHandle.decrypt` |
| `tpm.seal` | `seal`, `unseal` |

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
