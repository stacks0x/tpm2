# node-tpm2

Native TPM 2.0 for Node. Zero tooling, no admin.

- Windows via TBS, Linux via `/dev/tpmrm0`.
- Ships as prebuilt native binaries: `npm install node-tpm2` pulls one binary, no build step, no tpm2-tools, no PATH edits.
- Subsystem API: `tpm.pcr`, `tpm.keys`, `tpm.random`, `tpm.nv`, `tpm.attest`.

> **Status: pre-release / spike phase.** Option A (`tss-esapi`) validation is in progress.
> `Tpm.open()` throws `NOT_IMPLEMENTED` until the first working release.

## Spike (Phase 0)

Two decoupled probes — see [spike/README.md](./spike/README.md).

```bash
# Windows (non-elevated): baseline TBS, then Option A feasibility
cargo run --bin tbs-probe
cargo build --features esapi

# Linux: harness smoke only
cargo run --features esapi --bin spike -- all
```

## Development

```bash
npm install
npm run build          # compile .node + native.js loader
node -e "import { Tpm } from './index.js'; console.log(await Tpm.isAvailable())"
```

On Linux, your user needs access to `/dev/tpmrm0` (typically the `tss` group).

## License

Apache-2.0
