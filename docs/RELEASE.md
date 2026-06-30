# Releasing node-tpm2

One workflow for **beta** and **stable** releases. npm dist-tag is chosen automatically from the version string in `package.json`:

| Version in `package.json` | npm dist-tag | Git tag example |
|---------------------------|--------------|-----------------|
| `0.0.7-beta.0` | `beta` | `v0.0.7-beta.0` |
| `0.0.7` | `latest` | `v0.0.7` |

**Tag format:** always `v` + version — **`v0.0.7`**, not `v.0.0.7`.

---

## Prerequisites (once)

- **npm:** Automation token in **project `.npmrc`** (gitignored — `cp .npmrc.example .npmrc`). Per-repo isolation; do not put publish tokens in `~/.npmrc`. Do **not** run `npm login`.

---

## npm publish asks for OTP (EOTP) even with Automation token

**Cause:** leftover **`npm login` session** — npm config shows `auth-type=web` and `_auth=(protected)`. Publish uses web auth (OTP); `npm whoami` may still work via token.

**Fix (once):**

```bash
npm logout
npm config delete auth-type
```

Ensure **project** `.npmrc` in repo root (from `.npmrc.example`):

```
//registry.npmjs.org/:_authToken=npm_YOUR_AUTOMATION_TOKEN
```

Remove publish auth from `~/.npmrc` if present (avoid two tokens fighting). Clear session login:

```bash
npm logout
npm config delete auth-type
```

Verify:

```bash
npm config get auth-type    # should be empty or undefined, NOT "web"
npm config get _auth          # should be empty
npm whoami                    # stacks0x
```

Then publish:

```bash
npm run release:publish
npm run release:tag
```

**ENEEDAUTH on platform packages:** `npm whoami` from repo root can succeed while `npm publish` from `npm/linux-*` fails. npm does not apply project `.npmrc` auth in those subdirs. `scripts/publish-release.mjs` passes `--userconfig` on every publish; for manual platform publishes use:

```bash
npm publish --access public --userconfig /path/to/tpm2/.npmrc
```

Do **not** run `npm login` again on this machine.

---

## Beta release (feature validation)

Use when Windows/hardware validation is still required before `latest`.

```bash
# 1. Bump (example)
npm run bump -- 0.0.8-beta.0

# 2. Commit on dev, merge to main when ready
git add -A && git commit -m "Bump version to 0.0.8-beta.0."
git checkout main && git merge dev && git push origin main dev

# 3. Full release (preflight → npm publish → git tag)
npm run release
```

**Windows test laptop (Admin for NV):**

```powershell
npm install node-tpm2@beta
node node_modules\node-tpm2\examples\nv-smoke.mjs
node node_modules\node-tpm2\examples\smoke-test.mjs runtime
```

Do **not** publish another beta for the same fix without re-validating.

---

## Stable release (`latest`)

Ship when beta acceptance passes (or docs-only patch).

```bash
npm run bump -- 0.0.8
# commit + merge to main (same as beta)
npm run release
```

Verify:

```bash
npm view node-tpm2 version dist-tags
```

---

## What each command does

| Command | Action |
|---------|--------|
| `npm run bump -- <version>` | Sync version in `package.json`, `Cargo.toml`, `npm/*`, rebuild `native.cjs` |
| `npm run release:preflight` | `cargo test --lib -- --skip hw_` + `verify:package` (zero TPM contact) |
| `npm run release:publish` | Cross-build all platform `.node` files + publish to npm |
| `npm run release:tag` | `git tag v<version>` + `git push origin v<version>` |
| `npm run release` | All three: preflight → publish → tag |

**Aliases:** `publish:release` = `release:publish` (same script).

---

## Git tags vs npm

| System | Purpose |
|--------|---------|
| **npm** | What users install (`npm install node-tpm2`) |
| **Git tag `vX.Y.Z`** | Which **commit** that version came from (audits, bug reports) |

Always tag after a successful npm publish. Optional [GitHub Release](https://github.com/stacks0x/tpm2/releases) from the same tag (one-line notes are fine).

---

## GitHub Actions

`.github/workflows/release.yml` **builds** on `v*` tag push (matrix artifacts). **npm publish from CI is manual only** (`workflow_dispatch`) so local `npm run release` does not fight CI on duplicate publishes.

To publish from CI instead of locally: bump version on `main`, push tag, run **Release** workflow manually with `NPM_TOKEN` set — advanced; local publish is the default path.

---

## Checklist (copy every release)

```
- [ ] Version bumped (`npm run bump -- …`)
- [ ] Changes committed; `main` is the release commit
- [ ] `npm run release:preflight` passed (or full `npm run release`)
- [ ] npm publish succeeded
- [ ] Git tag pushed (`v` + version, no extra dot)
- [ ] (Beta) Windows smoke / nv-smoke on test laptop
- [ ] (Stable) `npm view node-tpm2 dist-tags` shows expected latest/beta
```

---

## Common mistakes

| Mistake | Fix |
|---------|-----|
| `git push origin v.0.0.7` | Use `v0.0.7` — no dot after `v` |
| Publish without bumping platform packages | Always use `npm run bump` (updates all packages + rebuild) |
| `SECURITY.md` / new `files` entry fails verify | Add path to `scripts/verify-package-tarball.mjs` allowlist |
| Republish same version to npm | Impossible — bump patch (e.g. `0.0.7` → `0.0.8`) |
