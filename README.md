# node-tpm2

Native TPM 2.0 for Node. Zero tooling at install time — prebuilt napi-rs binaries, no tpm2-tss, no tpm2-tools.

| Platform | Backend | Attestation key |
|----------|---------|-----------------|
| Linux | `/dev/tpmrm0` | ECDSA P-256 wrapped blob |
| Windows | TBS + NCrypt PCP | RSA-2048 persisted PCP key |
| macOS | — | Not supported (returns unavailable) |

## Install

```bash
npm install node-tpm2
```

Requires Node 20+. Resolves a prebuilt `.node` binary for your OS/arch via optional platform packages.

## Quick start

```javascript
import { Tpm } from 'node-tpm2';

if (!(await Tpm.isAvailable())) throw new Error('no TPM');

const { akBlob } = await Tpm.provisionAk();
const quote = await Tpm.quote({
  akBlob,
  pcrSelection: [0, 1, 7],
  qualifyingData: Buffer.from('challenge-bytes'),
});
```

See [docs/getting-started.md](./docs/getting-started.md) for API details and [docs/windows-pcp.md](./docs/windows-pcp.md) for Windows machine-scoped keys (privileged install → unprivileged quote).

## Validate install (clean machine)

After `npm install`, run the npm smoke test — **not** the Rust probe:

```bash
node node_modules/node-tpm2/examples/smoke-test.mjs runtime
```

Windows fleet path (Admin/SYSTEM provision, then standard user quote):

```bash
node node_modules/node-tpm2/examples/smoke-test.mjs provision-machine --key-name my-app-device-ak --out ak.blob.json
node node_modules/node-tpm2/examples/smoke-test.mjs quote --in ak.blob.json
```

## Development (this repo)

```bash
git clone https://github.com/stacks0x/tpm2.git
cd tpm2
npm install
npm run build
node examples/smoke-test.mjs runtime
```

Rust probe (developers, not the npm artifact):

```powershell
cargo build --no-default-features --features probe-bin --bin tbs-probe
.\target\debug\tbs-probe.exe all
.\target\debug\tbs-probe.exe help
```

Linux: user needs access to `/dev/tpmrm0` (typically the `tss` group).

## License

Apache-2.0
