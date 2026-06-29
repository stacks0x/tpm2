# API roadmap

Plan to complete the public `node-tpm2` API: subsystem namespaces, exportable key
handles, and parity between Linux (TBS) and Windows (TBS for general ops, PCP for
attestation persistence where required).

This library is standalone. Consumers integrate via npm; nothing in this repo references
or depends on downstream products.

---

## Current state (0.0.6)

**Shipped and validated on real Windows 11 hardware (Intel TPM, non-virtual):** attestation (user + machine provision, cross-user quote, SYSTEM provision), `random`, `keys` (sign + RSA decrypt), `pcr.read` / `pcr.extend` (admin on Windows), `nv` (read/write/define/undefine/readPublic), `seal` / `unseal`.

| Namespace | Methods |
|-----------|---------|
| Root | `Tpm.isAvailable()`, `Tpm.open()`, `Tpm.info()`, `tpm.readPublic()` |
| `tpm.random` | `bytes(n)` |
| `tpm.pcr` | `read`, `extend` |
| `tpm.nv` | `read`, `write`, `readPublic`, `define`, `undefine` |
| `tpm.keys` | `create`, `load`; `KeyHandle.sign`, `export`, `decrypt` |
| `tpm.seal` | `seal`, `unseal` |
| `tpm.attest` | `provisionAk`, `quote`, `ekCertificate` |
| `AkHandle` | `export`, `quote`, `activateCredential`, `publicKeyDer` |
| Flat | Parity wrappers for all of the above (`Tpm.pcrRead`, `Tpm.nvDefine`, `Tpm.seal`, …) |

**Platform split:** General ops (keys, seal, NV, PCR, random) use TBS on both OSes. Attestation persistence on Windows uses NCrypt PCP (`PCP1` / `PCP2` blobs); Linux uses TBS-wrapped ECDSA AK blobs.

---

## Target API

```typescript
import { Tpm, TpmError } from 'node-tpm2';

await using tpm = await Tpm.open();

// ── Root ──────────────────────────────────────────────────────────
await Tpm.isAvailable();
await tpm.info();

// ── random ────────────────────────────────────────────────────────
await tpm.random.bytes(32);

// ── pcr ───────────────────────────────────────────────────────────
await tpm.pcr.read([0, 1, 7], 'sha256');
await tpm.pcr.extend(7, digest);              // digest: Buffer, 32 bytes for sha256 bank

// ── nv ────────────────────────────────────────────────────────────
await tpm.nv.read('0x01c00002');              // handle or well-known name
await tpm.nv.write('0x01800001', data, opts); // opts: auth, offset — policy-dependent

// ── keys ──────────────────────────────────────────────────────────
const key = await tpm.keys.create({
  type: 'ecc',           // 'ecc' | 'rsa'
  sign: true,
  decrypt: false,
});
const blob = key.export();
const loaded = await tpm.keys.load(blob);
await loaded.sign(digest);                    // Buffer in → signature Buffer out
await loaded.decrypt(cipher);                 // when key was created with decrypt: true

// ── seal ──────────────────────────────────────────────────────────
const sealed = await tpm.seal({
  data: secret,
  pcrSelection: [7],
  pcrPolicy: 'current' | digest,             // bind to current PCR state or explicit digest
});
const plain = await tpm.unseal(sealed);

// ── attest (opinionated attestation — unchanged intent) ───────────
const ak = await tpm.attest.provisionAk({ scope, keyName, overwrite });
await ak.quote({ pcrSelection, qualifyingData });
await tpm.attest.ekCertificate();
await ak.activateCredential({ credentialBlob, secret });

// ── plumbing ──────────────────────────────────────────────────────
await tpm.readPublic('0x81010001');
```

Flat equivalents remain on `Tpm.*` for every operation (thin wrappers over the same native calls).

---

## Platform strategy

| Concern | Linux | Windows |
|---------|-------|---------|
| Transport | `/dev/tpmrm0` | TBS (`Tbsip_Submit_Command`) |
| General keys (`keys.*`) | TBS wrapped TPM2B blobs | TBS wrapped blobs (same codec as Linux) |
| Attestation AK (`attest.provisionAk`) | TBS wrapped ECDSA AK | NCrypt PCP persisted key (`PCP1` / `PCP2` blob) |
| Quote / activate | Load blob transiently → operate → flush | PCP open by key name + TBS for quote crypto |
| Seal / unseal | TBS policy-bound object | TBS (same commands; no PCP required) |
| NV | TBS NV_Read / NV_Write | TBS NV commands |

**Rule:** PCP is for **attestation key persistence and fleet cross-user quote**, not for every key operation. General `keys.*` and `seal` use the shared TBS command path on both OSes so behavior and blobs stay aligned.

---

## Implementation phases

### Phase 0 — API hygiene ✅ (this branch)

**Goal:** Published types match runtime; namespace skeleton on `TpmHandle`.

- [x] Remove bogus top-level exports from `index.d.ts`
- [x] Add namespace objects on `TpmHandle`: `random`, `nv`, `keys`, `seal`, `pcr.extend`
- [x] Add `KeyHandle` / `KeyBlob` types; unimplemented methods throw `NOT_SUPPORTED`
- [ ] Acceptance: `npm run verify:package`

### Phase 1 — `tpm.random.bytes` ✅ (this branch)

**Goal:** Public `GetRandom`.

- [x] Rust: `random.rs` — marshal `TPM2_GetRandom`, ≤64 bytes per call, loop for larger
- [x] NAPI: `randomBytes`
- [x] JS: `tpm.random.bytes(n)`, `Tpm.randomBytes(n)`
- [ ] Tests: integration on Linux + Windows VM

### Phase 2 — `tpm.keys` ✅

**Goal:** General exportable signing keys via TBS wrapped blobs (both OSes).

- [x] `keys.create` / `keys.load` / `key.sign` — ECC + RSA sign keys
- [x] Unit tests: templates, Sign command golden, option validation, HW roundtrip
- [x] `key.decrypt` — RSA OAEP
- [ ] Windows VM sign smoke

### Phase 3 — `tpm.pcr.extend` ✅ (this branch)

**Goal:** Software measurement hook.

- [x] Rust: `TPM2_PCR_Extend` with SHA-256 bank selection matching `pcr.read`.
- [x] JS: `tpm.pcr.extend(index, digest)`.
- [x] Tests: extend → read → digest changed.
- [x] Caveats: some firmware policies lock PCRs; surface `TPM_RC` / `COMMAND_BLOCKED` cleanly.
- [x] Acceptance: Linux unprivileged on swtpm/dev VM; **Windows Administrator** on real client hardware (PCR 23 validated).

### Phase 4 — `tpm.nv` ✅ (this branch)

**Goal:** General NV index access beyond EK cert helper.

- [x] Rust: `nv.read_public(handle)` — size + attributes via `nv_read_public`.
- [x] `nv.read(handle, offset, size)`.
- [x] `nv.write(handle, offset, data, auth?)` — optional auth for password-protected indices.
- [x] `nv.define` / `nv.undefine` — owner-auth; owner NV range only; refuses EK indices.
- [x] Migrate `readEkCertificate` to call `nv.read` on well-known EK cert index internally.
- [x] JS: `tpm.nv.read`, `tpm.nv.write`, `tpm.nv.readPublic`, `tpm.nv.define`, `tpm.nv.undefine`; document which indices are safe on consumer hardware.
- [ ] Acceptance: EK cert read unchanged; optional integration test against swtpm-defined NV index (hardware: use `examples/nv-smoke.mjs` on test machine).

### Phase 5 — `tpm.seal` / `tpm.unseal` ✅ (this branch)

**Goal:** TPM-bound secrets with optional PCR policy.

- [x] Rust: `seal({ data, pcrSelection? })` — storage primary, `Create` sealed object, export blob.
- [x] `unseal(blob)` — load + `Unseal`.
- [x] PCR policy: `PolicyPCR` session when `pcrSelection` provided.
- [x] JS: `tpm.seal`, `tpm.unseal`; flat aliases.
- [x] Tests: roundtrip without PCR; unit tests for marshalling.
- [ ] Acceptance: Linux + Windows TBS; roundtrip with PCR extend before unseal on hardware.

### Phase 6 — Hardening & 1.0 (ongoing)

- Real hardware matrix (firmware TPM, Hyper-V, physical laptop).
- Fuzz/malformed response handling on codec.
- Stable semver on error codes (`latest` tag).
- Performance: reuse TBS context per `TpmHandle` where safe (today: per-call context on Windows TBS path).

---

## Dependency order

```
Phase 0 (hygiene)
    ↓
Phase 1 (random) ─────────────────────────────┐
    ↓                                         │
Phase 2 (keys) ──→ Phase 5 (seal uses keys)   │
    ↓                                         │
Phase 3 (pcr.extend) ──→ Phase 5 (PCR policy) │
    ↓                                         │
Phase 4 (nv) ─────────────────────────────────┘
    ↓
Phase 6 (1.0)
```

Phases 1 and 3 can run in parallel after Phase 0. Phase 2 blocks Phase 5. Phase 4 is independent.

---

## Testing strategy

| Layer | Tool |
|-------|------|
| Command golden bytes | Rust unit tests |
| Privilege / elevation | `tbs-probe` (repo only) + `examples/smoke-test.mjs` (published) |
| Cross-platform | Linux CI + Windows VM manual gate before each beta |
| NV / seal edge cases | swtpm with scripted NV define in CI (Linux) |

---

## Out of scope (remain non-goals)

- macOS TPM (no hardware).
- Persistent handle / `EvictControl` in the public API.
- Full TPM2 policy language exposed to JS (only fixed recipes: activate-credential, seal-with-PCR).
- PKCS#11, OpenSSL engine, or platform keystore integration.

---

## Versioning

- Implement phases on `dev`; beta publish after each phase or logical group (e.g. **0.0.5-beta.0** = full NV + seal + keys decrypt).
- `1.0.0` when Phases 0–5 acceptance criteria pass on real hardware and API surface in README matches implementation.
