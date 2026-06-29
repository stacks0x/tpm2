---
name: npm-release
description: >-
  node-tpm2 npm release workflow — bump version, beta vs latest dist-tags,
  preflight, publish, git tags. Use when the user asks to release, publish,
  bump version, tag a version, or ship beta/latest to npm.
---

# node-tpm2 — npm release

Full reference: [docs/RELEASE.md](../../docs/RELEASE.md)

## Rules for agents

1. **Never publish to npm** unless the user explicitly asks to publish/release in that message.
2. **Never bump version** unless the user asks — propose the next version, don't silently bump.
3. **Never push git tags** unless the user asked for release/tag/push.
4. **Dev machine TPM:** mutating validation stays on Windows test laptop ([tpm-dev-machine-no-mutate](../tpm-dev-machine-no-mutate/SKILL.md) if present locally).

## Version → dist-tag (automatic)

| `package.json` version | npm dist-tag | Git tag |
|------------------------|--------------|---------|
| contains `-` (e.g. `0.0.8-beta.0`) | `beta` | `v0.0.8-beta.0` |
| no hyphen (e.g. `0.0.8`) | `latest` | `v0.0.8` |

Git tag is **`v` + version** — never `v.0.0.8`.

## Standard workflow (user runs on fortress)

```bash
npm run bump -- <version>     # syncs all packages + rebuild native.cjs
# user commits; main = release commit
npm run release               # preflight → publish → tag push
```

Step-by-step:

```bash
npm run release:preflight     # cargo test --skip hw_ + verify:package
npm run release:publish       # cross-build + npm publish all packages
npm run release:tag           # git tag v<version> && git push origin v<version>
```

## When to use beta vs latest

| Type | When |
|------|------|
| **Beta** | New TPM/NV/API behavior; needs Windows test laptop validation |
| **Latest** | Beta accepted, or docs-only / tarball-only fix (e.g. SECURITY.md) |

## After beta publish

User validates on **Windows test laptop** (not dev machine):

```powershell
npm install node-tpm2@beta
node node_modules\node-tpm2\examples\nv-smoke.mjs
```

## Files touched by bump

`package.json`, `Cargo.toml`, `Cargo.lock`, `npm/*/package.json`, `native.cjs` (via `npm run build`).

New files in npm `files` array → add to `scripts/verify-package-tarball.mjs` `MAIN_TARBALL_ALLOWLIST`.

## Do not

- Hand-edit `native.cjs` version strings — use `npm run bump`
- Use `publish:beta` name as meaning "beta only" — use `release:publish`; dist-tag follows version
- Create GitHub Release without a git tag on the published commit
