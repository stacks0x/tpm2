# Getting started

node-tpm2 exposes TPM 2.0 attestation through a small JavaScript API. Install is a normal npm dependency — prebuilt native binaries, no `tpm2-tools` or Rust toolchain on the target machine.

## Install

```bash
npm install node-tpm2
```

Requires Node 20+. Platform binaries resolve automatically (`node-tpm2-windows-x64-msvc`, `node-tpm2-linux-x64-gnu`, etc.).

## Check the TPM

```javascript
import { Tpm } from 'node-tpm2';

if (!(await Tpm.isAvailable())) {
  throw new Error('No accessible TPM');
}

const info = await Tpm.info();
console.log(info.manufacturer, info.firmwareVersion, info.isVirtual);
```

## Provision and quote

### User-scoped (development and same-user apps)

Works as a **standard user** on Windows and Linux (with `/dev/tpmrm0` access):

```javascript
import { Tpm } from 'node-tpm2';

const { akPublicDer, akBlob } = await Tpm.provisionAk();
// akPublicDer → register with your verifier
// akBlob → persist locally (encrypted at rest in your app)

const quote = await Tpm.quote({
  akBlob,
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('session-nonce-or-challenge'),
  bank: 'sha256',
});
// quote.message, quote.signature → send to verifier
```

### Handle style

```javascript
const tpm = await Tpm.open();
const ak = await tpm.attest.provisionAk();

const quote = await ak.quote({
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('challenge'),
});

const saved = ak.export(); // { public, private } buffers for storage
```

## Windows: machine-scoped AK (fleet)

When a **privileged installer** creates the key and a **standard user** quotes at runtime:

```javascript
// Enrollment — Admin or SYSTEM only (once per device)
const { akBlob } = await Tpm.provisionAk({
  keyName: 'my-app-device-ak',
  scope: 'machine',
  overwrite: true,
});

// Runtime — standard user, no elevation
const quote = await Tpm.quote({
  akBlob,
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('challenge'),
});
```

See [windows-pcp.md](./windows-pcp.md) for PCP details, DACL behavior, and SYSTEM enrollment.

## Linux permissions

Read/write on `/dev/tpmrm0` (commonly membership in the `tss` group):

```bash
sudo usermod -aG tss "$USER"
# log out and back in
```

## Errors

Native failures throw `TpmError`:

| Field | Meaning |
|-------|---------|
| `code` | Stable string (`TPM_UNAVAILABLE`, `REQUIRES_ELEVATION`, `ACCESS_DENIED`, …) |
| `message` | Human-readable detail |
| `suggestion` | Optional remediation hint |
| `tpmRc` | TPM 2.0 return code when applicable |
| `hresult` | Windows NCrypt HRESULT when applicable |

```javascript
import { Tpm, TpmError } from 'node-tpm2';

try {
  await Tpm.provisionAk({ scope: 'machine', keyName: 'x' });
} catch (err) {
  if (err instanceof TpmError && err.code === 'REQUIRES_ELEVATION') {
    // Run enrollment elevated or as SYSTEM
  }
}
```

## What ships in npm

The published package contains the JavaScript API, type definitions, user docs, and the smoke-test example — **not** Rust sources, `tbs-probe`, or spike binaries. Those stay in the git repo for developers.
