# node-tpm2

Native TPM 2.0 for Node. Zero tooling, no admin.

- Windows via TBS, Linux via `/dev/tpmrm0`.
- Ships as prebuilt native binaries: `npm install node-tpm2` pulls one binary, no build step, no tpm2-tools, no PATH edits.
- Subsystem API: `tpm.pcr`, `tpm.keys`, `tpm.random`, `tpm.nv`, `tpm.attest`.

> **Status: pre-release placeholder.** The native backend is not published yet.
> `Tpm.open()` throws `NOT_IMPLEMENTED` until the first working release. Watch this repo.

## License

Apache-2.0
