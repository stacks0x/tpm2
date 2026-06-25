# Release and clean-machine test checklist

The `tbs-probe` binary proves the **Rust core**. Publishing requires proving the **npm native module** loads and calls the same paths on a machine with **no Rust toolchain**.

## Before you tag

### 1. Build release native artifacts (on each target OS, or CI matrix)

```bash
npm ci
npm run build          # release .node + platform package stubs
```

Confirm a `.node` file exists under `npm/<triple>/` for each platform you ship.

### 2. Dry-run the tarball

```bash
npm publish --dry-run
```

Check:

- `files` includes `index.js`, `api.js`, `native.cjs`, `native.d.ts`, `index.d.ts`, `examples/`, `docs/`
- No `target/`, `*.ctx`, probe artifacts, or spike junk
- Version in root `package.json` matches all `optionalDependencies` platform package versions

### 3. Bump version atomically

Increment root **and** every `npm/*/package.json` (or run `napi prepublish -t npm` after version bump). Pin consumers to exact versions — native drift under semver ranges is painful.

### 4. Publish platform packages, then root

```bash
npm run prepublishOnly   # napi prepublish -t npm --skip-optional-publish
# Publish each node-tpm2-*-platform package, then:
npm publish
```

Or use your CI release workflow if configured.

---

## Clean VM test (npm only, no Rust)

Goal: **`npm install` → `node examples/smoke-test.mjs` works**.

### Option A — published to npm (recommended)

On a fresh Windows VM (Node 20+ only):

```powershell
mkdir tpm2-test && cd tpm2-test
npm init -y
npm install node-tpm2@<exact-version>
node node_modules/node-tpm2/examples/smoke-test.mjs runtime
```

On Linux:

```bash
mkdir tpm2-test && cd tpm2-test
npm init -y
npm install node-tpm2@<exact-version>
node node_modules/node-tpm2/examples/smoke-test.mjs runtime
```

### Option B — local tarball (pre-publish)

On the **build machine** after `npm run build`:

```bash
mkdir -p dist-pack
npm pack --pack-destination dist-pack
for d in npm/*/; do (cd "$d" && npm pack --pack-destination "../../dist-pack"); done
```

Copy `dist-pack/*.tgz` to the clean VM. Install **platform package first**, then root:

```powershell
npm install .\node-tpm2-windows-x64-msvc-0.0.4.tgz
npm install .\node-tpm2-0.0.4.tgz
node node_modules\node-tpm2\examples\smoke-test.mjs runtime
```

If install tries to compile from source or fetch missing platform packages, the release is not ready.

---

## Windows two-step test (matches production)

Same scenario validated by `tbs-probe`, but through **Node**:

**Step 1 — Admin or SYSTEM** (install/enrollment context):

```powershell
node node_modules\node-tpm2\examples\smoke-test.mjs provision-machine --key-name my-app-device-ak --out ak.blob.json
```

Or run Step 1 via SYSTEM scheduled task (see [windows-pcp.md](./windows-pcp.md)), then copy the blob to a path the standard user can read (e.g. `C:\ProgramData\my-app\ak.blob.json`).

**Step 2 — Standard user** (runtime):

```powershell
node node_modules\node-tpm2\examples\smoke-test.mjs quote --in C:\ProgramData\my-app\ak.blob.json
```

Pass = npm module quotes a machine AK a privileged context created.

---

## Linux clean VM

Single step — no privilege split:

```bash
node node_modules/node-tpm2/examples/smoke-test.mjs runtime
```

Ensure `/dev/tpmrm0` is accessible.

---

## What “ready to publish” means

Not “probe passed,” but:

> On a clean machine with only Node/npm, `npm install node-tpm2@X` and `smoke-test.mjs` succeed for runtime (and Windows machine provision + quote if you ship fleet enrollment).

Also run `npm publish --dry-run` and verify tarball contents before the first public tag.
