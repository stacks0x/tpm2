# Getting started

node-tpm2 talks to the TPM 2.0 through OS-native paths — no tpm2-tools, no tpm2-tss, and no Rust toolchain at install time.

| Platform | Transport | Attestation key (AK) |
|----------|-----------|----------------------|
| Linux | `/dev/tpmrm0` | ECDSA P-256 wrapped TPM2B blob |
| Windows | TBS + NCrypt PCP | RSA-2048 persisted PCP key (`PCP1` / `PCP2` blob) |

## Install

```bash
npm install node-tpm2
```

Requires Node 20+. npm pulls a prebuilt native binary for your OS/arch from optional platform packages (`node-tpm2-windows-x64-msvc`, `node-tpm2-linux-x64-gnu`, etc.).

## Quick check

```javascript
import { Tpm } from 'node-tpm2';

console.log('available', await Tpm.isAvailable());
console.log('info', await Tpm.info());
```

## Provision and quote (development)

Works **without admin** on both Linux and Windows (user-scoped AK on Windows):

```javascript
import { Tpm } from 'node-tpm2';

const { akPublicDer, akBlob } = await Tpm.provisionAk();
console.log('AK SPKI', akPublicDer.length, 'bytes');

const quote = await Tpm.quote({
  akBlob,
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('session-nonce-or-challenge'),
  bank: 'sha256',
});
console.log('quote', quote.message.length, quote.signature.length);
```

## Windows: machine-scoped AK (cross-user)

For apps where a **privileged installer** creates the key and a **standard user** quotes at runtime, use a machine-scoped key with a stable name. See [windows-pcp.md](./windows-pcp.md).

```javascript
// Run elevated or as SYSTEM (enrollment / install time only)
const { akBlob } = await Tpm.provisionAk({
  keyName: 'my-app-device-ak',
  scope: 'machine',
  overwrite: true,
});
// Persist akBlob (and upload creation attestation to your verifier)

// Runtime — standard user, no admin
const quote = await Tpm.quote({
  akBlob,
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('challenge'),
});
```

## Linux permissions

Your user needs read/write on `/dev/tpmrm0` (commonly the `tss` group):

```bash
sudo usermod -aG tss "$USER"
```

## Errors

Native failures surface as `TpmError` with `code`, `message`, optional `suggestion`, and `tpmRc` when the TPM returned an RC.
