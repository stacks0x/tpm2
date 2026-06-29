#!/usr/bin/env node
/**
 * Bump node-tpm2 version everywhere (main + platform packages + Cargo + native.cjs).
 *
 * Usage:
 *   node scripts/bump-version.mjs 0.0.7          # stable → npm dist-tag latest
 *   node scripts/bump-version.mjs 0.0.7-beta.0   # prerelease → npm dist-tag beta
 */
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/.test(version)) {
  console.error('Usage: node scripts/bump-version.mjs <version>');
  console.error('  stable:     0.0.7');
  console.error('  prerelease: 0.0.7-beta.0');
  process.exit(1);
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const distTag = version.includes('-') ? 'beta' : 'latest';

const pkgPath = join(root, 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
pkg.version = version;
for (const name of Object.keys(pkg.optionalDependencies ?? {})) {
  pkg.optionalDependencies[name] = version;
}
writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);

const cargoPath = join(root, 'Cargo.toml');
writeFileSync(
  cargoPath,
  readFileSync(cargoPath, 'utf8').replace(/^version = "[^"]+"/m, `version = "${version}"`),
);

for (const dir of readdirSync(join(root, 'npm'))) {
  const platformPkgPath = join(root, 'npm', dir, 'package.json');
  const platformPkg = JSON.parse(readFileSync(platformPkgPath, 'utf8'));
  platformPkg.version = version;
  writeFileSync(platformPkgPath, `${JSON.stringify(platformPkg, null, 2)}\n`);
}

console.log(`\n> npm run build`);
execSync('npm run build', { cwd: root, stdio: 'inherit' });

console.log(`\nBumped to ${version} (npm dist-tag: ${distTag})`);
console.log('Next: commit, merge to main if needed, then npm run release');
