# node-tpm2

Native TPM 2.0 for Node. Zero tooling, no admin.

- Windows via TBS, Linux via `/dev/tpmrm0`.
- Direct TBS command marshalling — no tpm2-tss, no tpm2-tools at install or runtime.
- Ships as prebuilt native binaries via napi-rs platform packages.

> **Status: pre-release.** `Tpm.isAvailable()` and `Tpm.info()` work on Windows and Linux.
> `Tpm.open()` and attestation methods are not implemented yet.

## Install

```bash
npm install node-tpm2
```

npm resolves exactly one prebuilt native binary from `optionalDependencies` — no build step,
no tpm2-tools, no Rust. Requires platform packages published for your OS/arch.

## Development

```bash
git clone https://github.com/stacks0x/tpm2.git
cd tpm2
npm install
npm run build
node --input-type=module -e "
  import { Tpm } from './index.js';
  console.log('available', await Tpm.isAvailable());
  console.log('info', await Tpm.info());
"
```

On Linux, your user needs read/write on `/dev/tpmrm0` (typically the `tss` group).

## Windows probe (direct TBS validation)

Non-elevated PowerShell on Windows 11:

```powershell
cargo run --bin tbs-probe -- all
```

See [spike/README.md](./spike/README.md) for probe details and RC discipline.

## License

Apache-2.0
