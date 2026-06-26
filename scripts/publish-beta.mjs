#!/usr/bin/env node
/**
 * Build all native targets and publish node-tpm2 + platform packages with dist-tag beta.
 * Requires: npm login (or ~/.npmrc auth token), rust, node 20+.
 * Run from repo root: node scripts/publish-beta.mjs
 */
import { execSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const distTag = version.includes('-') ? 'beta' : 'latest';

function run(cmd, opts = {}) {
  console.log(`\n> ${cmd}`);
  execSync(cmd, { stdio: 'inherit', cwd: root, ...opts });
}

try {
  run('npm whoami');
} catch {
  console.error('\nNot logged in to npm. Run: npm login');
  console.error('Or set //registry.npmjs.org/:_authToken=... in ~/.npmrc');
  process.exit(1);
}

console.log(`\nPublishing node-tpm2@${version} (dist-tag: ${distTag})`);

const targets = [
  'x86_64-pc-windows-msvc',
  'aarch64-pc-windows-msvc',
  'x86_64-unknown-linux-gnu',
  'x86_64-unknown-linux-musl',
  'aarch64-unknown-linux-gnu',
  'aarch64-unknown-linux-musl',
  'aarch64-apple-darwin',
];

for (const target of targets) {
  const musl = target.includes('musl');
  const cmd = musl
    ? `npm run build -- --target ${target} -x`
    : `npm run build -- --target ${target}`;
  try {
    run(cmd);
  } catch (e) {
    console.error(`\nBuild failed for ${target}. Install cross tools if needed.`);
    console.error('Windows on Linux: cargo install cargo-xwin');
    console.error('musl: zig + cargo-zigbuild (see .github/workflows/release.yml)');
    throw e;
  }
}

run('npm run create-npm-dirs');
run('npm run artifacts');
run('npm run patch-windows-npm');
run('npm run prepublishOnly');

for (const dir of readdirSync(join(root, 'npm'))) {
  const pkgDir = join(root, 'npm', dir);
  run(`npm publish --access public --tag ${distTag}`, { cwd: pkgDir });
}

run(`npm publish --access public --tag ${distTag}`);

console.log(`\nDone. Install with: npm install node-tpm2@${version}`);
