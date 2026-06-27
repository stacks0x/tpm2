# API roadmap

Plan to complete the public `node-tpm2` API: subsystem namespaces, exportable key
handles, and parity between Linux (TBS) and Windows (TBS for general ops, PCP for
attestation persistence where required).

This library is standalone. Consumers integrate via npm; nothing in this repo references
or depends on downstream products.

---

## Current state (0.0.4-beta)

**Shipped**

| Namespace | Methods |
|-----------|---------|
| Root | `Tpm.isAvailable()`, `Tpm.open()`, `Tpm.info()` |
| `tpm.pcr` | `read` |
| `tpm.attest` | `provisionAk`, `quote`, `ekCertificate` |
| `AkHandle` | `export`, `quote`, `activateCredential`, `publicKeyDer` |
| Flat | `Tpm.pcrRead`, `readPublic`, `readEkCertificate`, `quote`, `provisionAk`, `activateCredential` |

**Rust foundation already present (not exposed on `TpmHandle` yet):**

- Command codec: `CreatePrimary`, `Create`, `Load`, `FlushContext`, `Quote`, `GetRandom`, sessions, policy digest
- Linux key path: `keys.rs` (storage primary, AK create/load)
- Windows PCP path: `pcp.rs` (identity AK, machine DACL, quote, activation)
- NV: EK certificate read via fixed index
- Credential: full activate-credential flow (Linux TBS; Windows PCP)

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

### Phase 0 — API hygiene (1–2 days)

**Goal:** Published types match runtime; namespace skeleton on `TpmHandle`.

- Remove bogus top-level exports from `index.d.ts` (only `Tpm`, `TpmError` from `index.js`).
- Add empty namespace objects on `TpmHandle`: `random`, `nv`, `keys`, `seal` — methods throw `NOT_SUPPORTED` until implemented (or hide until ready; prefer explicit `NOT_SUPPORTED` during beta).
- Add `KeyHandle` interface mirroring `AkHandle` (`export`, `sign`, `decrypt`).
- Document target API in README + this roadmap.
- Acceptance: `npm run verify:package`; TypeScript consumers see only real exports.

### Phase 1 — `tpm.random.bytes` (2–3 days)

**Goal:** Public `GetRandom`.

- Rust: `random.rs` — marshal `TPM2_GetRandom`, size limit per spec (≤ 64 bytes per call; loop for larger).
- NAPI: `random_bytes(n: u32)`.
- JS: `tpm.random.bytes(n)`, `Tpm.randomBytes(n)`.
- Tests: unit golden command; integration on Linux + Windows VM.
- Acceptance: unprivileged success on both platforms with normal TPM access.

### Phase 2 — `tpm.keys` (1–2 weeks)

**Goal:** General exportable signing keys, separate from attestation.

- Rust:
  - `keys.create(opts)` — storage primary (deterministic template) + `Create` keyed object; return `KeyBlob` (same shape as `AkBlob` on Linux).
  - `keys.load(blob)` — `Load` under primary; return transient handle wrapper.
  - `key.sign(digest)` — `Sign` with appropriate scheme (ECDSA+SHA256 / RSASSA+SHA256).
  - `key.decrypt(cipher)` — optional, RSA-OAEP or TPM-defined scheme.
  - Windows: **TBS path only** (not PCP); blobs are portable TPM2B like Linux.
- JS: `KeyHandle` with `export()`, `sign()`, optional `decrypt()`.
- Tests: create → export → load → sign → verify signature offline; flush hygiene.
- Acceptance: no persistent TPM handles; blob persists across process restarts on same TPM.

### Phase 3 — `tpm.pcr.extend` (3–5 days)

**Goal:** Software measurement hook.

- Rust: `TPM2_PCR_Extend` with SHA-256 bank selection matching `pcr.read`.
- JS: `tpm.pcr.extend(index, digest)`.
- Tests: extend → read → digest changed.
- Caveats: some firmware policies lock PCRs; surface `TPM_RC` / `COMMAND_BLOCKED` cleanly.
- Acceptance: works unprivileged on swtpm and dev VM where PCRs are extendable.

### Phase 4 — `tpm.nv` (1 week)

**Goal:** General NV index access beyond EK cert helper.

- Rust:
  - `nv.read_public(handle)` — already partially in `nv.rs`; expose metadata (size, attributes).
  - `nv.read(handle, offset, size)`.
  - `nv.write(handle, offset, data, auth?)` — auth optional buffer for password/session auth.
  - `nv.define` / `nv.undefine` — **defer** unless needed (owner-auth, high privilege).
- Migrate `readEkCertificate` to call `nv.read` on well-known EK cert index internally.
- JS: `tpm.nv.read`, `tpm.nv.write`; document which indices are safe on consumer hardware.
- Acceptance: EK cert read unchanged; optional integration test against swtpm-defined NV index.

### Phase 5 — `tpm.seal` / `tpm.unseal` (1–2 weeks)

**Goal:** TPM-bound secrets with optional PCR policy.

- Rust:
  - `seal({ data, pcrSelection?, name? })` — create storage primary or use fixed template, `Create` sealed object, export blob.
  - `unseal(blob)` — load + `Unseal`.
  - PCR policy: `PolicyPCR` session when `pcrSelection` provided.
- JS: `tpm.seal`, `tpm.unseal`; flat aliases.
- Tests: roundtrip without PCR; roundtrip with PCR extend before unseal; negative test wrong PCR.
- Acceptance: Linux + Windows TBS; document that PCR-bound seal requires extend permission on chosen indices.

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

- Implement phases on `dev`; beta publish after each phase or logical group (e.g. beta.4 = random + keys).
- `1.0.0` when Phases 0–5 acceptance criteria pass on real hardware and API surface in README matches implementation.
