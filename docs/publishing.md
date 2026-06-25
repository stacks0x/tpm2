# Publishing `node-tpm2` to npm

End users install with `npm install node-tpm2` only. Rust and build tools stay in CI.

## One-time setup

1. **npm account** with publish access to `node-tpm2` and the platform packages
   (`node-tpm2-win32-x64-msvc`, etc.). The main package `node-tpm2@0.0.1` is already
   claimed; platform package names are created on first publish (no separate claim step).

2. **GitHub secret** on `stacks0x/tpm2`:
   - Settings → Secrets and variables → Actions → **New repository secret**
   - Name: `NPM_TOKEN`
   - Value: npm **Automation** token (bypasses 2FA for CI)

3. **Merge** `feature/tbs-napi` → `main` (release workflow runs from tagged commits on main).

## Release (CI)

```bash
# On main, after version bump in package.json + npm/*/package.json:
git tag v0.0.2
git push origin main --tags
```

Or: GitHub → Actions → **Release** → **Run workflow**.

The workflow will:

1. Cross-compile all seven targets (Windows, Linux gnu/musl, darwin stub)
2. Copy `.node` files into `npm/*` via `napi artifacts`
3. Publish each platform package with `--provenance`
4. Run `napi prepublish` and publish `node-tpm2`

## Verify on a clean machine (Phase 1 acceptance)

```powershell
mkdir C:\sanity
cd C:\sanity
npm init -y
npm install node-tpm2@0.0.2
node --input-type=module -e "import { Tpm } from 'node-tpm2'; console.log(await Tpm.isAvailable()); console.log(await Tpm.info());"
```

Expected on a TPM host: `true` and structured `info` — **no Rust, no git clone, no npm run build**.

## Local publish (emergency only)

Requires built artifacts in `npm/*`:

```bash
npm run create-npm-dirs
npm run build -- --target x86_64-pc-windows-msvc   # repeat per target, or use CI artifacts
npm run artifacts
npm run prepublishOnly
for d in npm/*/; do (cd "$d" && npm publish --access public); done
npm publish --access public
```

Prefer CI releases for provenance and reproducibility.
