#!/usr/bin/env node
/**
 * Build all native targets and publish node-tpm2 + platform packages.
 * Dist-tag is chosen from package.json version:
 *   - prerelease (contains `-`) → `beta`
 *   - stable (e.g. 0.0.5)      → `latest`
 *
 * Auth: use an npm **Automation** token in project .npmrc (see .npmrc.example):
 *   //registry.npmjs.org/:_authToken=npm_...
 * Session login (`npm login`) often triggers browser 2FA on publish and fails in scripts.
 *
 * Run: npm run publish:release
 */
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';
import { homedir } from 'node:os';
import {
  assertMainTarball,
  assertPlatformTarball,
} from './verify-package-tarball.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const projectNpmrc = join(root, '.npmrc');
// npm only auto-loads project .npmrc when cwd is the repo root; platform packages
// live under npm/* and publish with cwd there, so pass --userconfig explicitly.
const npmUserConfig = existsSync(projectNpmrc)
  ? ` --userconfig ${JSON.stringify(projectNpmrc)}`
  : '';
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const distTag = version.includes('-') ? 'beta' : 'latest';

// Prepend ~/zig when present (musl + aarch64-linux-gnu cross-builds need it).
const zigBin = join(homedir(), 'zig');
if (existsSync(join(zigBin, 'zig')) && !process.env.PATH?.split(':').includes(zigBin)) {
  process.env.PATH = `${zigBin}:${process.env.PATH ?? ''}`;
}

const TARGETS = [
  ['x86_64-pc-windows-msvc', 'node-tpm2.win32-x64-msvc.node', 'xwin'],
  ['aarch64-pc-windows-msvc', 'node-tpm2.win32-arm64-msvc.node', 'xwin'],
  ['x86_64-unknown-linux-gnu', 'node-tpm2.linux-x64-gnu.node', null],
  ['x86_64-unknown-linux-musl', 'node-tpm2.linux-x64-musl.node', 'zig'],
  ['aarch64-unknown-linux-gnu', 'node-tpm2.linux-arm64-gnu.node', 'zig'],
  ['aarch64-unknown-linux-musl', 'node-tpm2.linux-arm64-musl.node', 'zig'],
];

function run(cmd, opts = {}) {
  console.log(`\n> ${cmd}`);
  execSync(cmd, { stdio: 'inherit', cwd: root, ...opts });
}

const REQUIRED_EXPORTS = [
  'provisionAk',
  'quote',
  'pcrRead',
  'pcrExtend',
  'getFixedProperties',
  'isAvailable',
  'activateCredential',
  'randomBytes',
  'createKey',
  'signKeyBlob',
  'decryptKeyBlob',
  'keyBlobPublicDer',
  'nvRead',
  'nvWrite',
  'nvReadPublic',
  'nvDefine',
  'nvUndefine',
  'seal',
  'unseal',
];

function assertBinaryExports(nodePath) {
  const data = readFileSync(nodePath);
  const missing = REQUIRED_EXPORTS.filter((name) => !data.includes(name));
  if (missing.length > 0) {
    throw new Error(
      `${nodePath} is missing NAPI exports: ${missing.join(', ')}. ` +
        'Rebuild from current sources; do not publish stale .node artifacts.',
    );
  }
  console.log(`  verified exports in ${nodePath} (${data.length} bytes)`);
}

function stageArtifact(target, nodeFile) {
  const src = join(root, nodeFile);
  assertBinaryExports(src);
  const destDir = join(root, 'artifacts', `bindings-${target}`);
  mkdirSync(destDir, { recursive: true });
  cpSync(src, join(destDir, nodeFile));
  console.log(`  staged ${nodeFile} -> artifacts/bindings-${target}/`);
}

try {
  run(`npm whoami${npmUserConfig}`);
  // whoami from repo root can succeed while publish from npm/* subdirs fails without --userconfig
  run(`npm whoami${npmUserConfig}`, { cwd: join(root, 'npm') });
} catch {
  console.error('\nNot logged in to npm.');
  console.error('Add an Automation token to project .npmrc (cp .npmrc.example .npmrc):');
  console.error('  //registry.npmjs.org/:_authToken=npm_...');
  process.exit(1);
}

console.log(`\nPublishing node-tpm2@${version} (dist-tag: ${distTag})`);

rmSync(join(root, 'artifacts'), { recursive: true, force: true });

for (const [target, nodeFile, cross] of TARGETS) {
  const crossFlag = cross === 'zig' || cross === 'xwin' ? ' -x' : '';
  const cmd =
    `npx napi build --platform --release --target ${target}${crossFlag} ` +
    `--js native.cjs --dts native.d.ts && node scripts/patch-windows-npm-packages.mjs`;
  try {
    run(cmd);
    stageArtifact(target, nodeFile);
  } catch {
    console.error(`\nBuild failed for ${target}.`);
    if (cross === 'xwin') {
      console.error('Windows: rustup target add <triple> && cargo install cargo-xwin');
    }
    if (cross === 'zig') {
      console.error('Cross Linux: install zig (https://ziglang.org) + cargo install cargo-zigbuild');
      console.error('  e.g. export PATH="$HOME/zig:$PATH"');
    }
    process.exit(1);
  }
}

run('npm run create-npm-dirs');
run('npm run artifacts');
run('npm run prepublishOnly');
run('npm run patch-windows-npm');

for (const dir of readdirSync(join(root, 'npm'))) {
  if (dir === 'darwin-arm64') continue;
  const nodeFiles = readdirSync(join(root, 'npm', dir)).filter((f) => f.endsWith('.node'));
  for (const nodeFile of nodeFiles) {
    assertBinaryExports(join(root, 'npm', dir, nodeFile));
  }
  assertPlatformTarball(dir, { requireNode: true });
}

assertMainTarball();

for (const dir of readdirSync(join(root, 'npm'))) {
  const pkgDir = join(root, 'npm', dir);
  if (dir === 'darwin-arm64') {
    console.log('\nSkipping darwin-arm64 (build on macOS CI, publish separately).');
    continue;
  }
  try {
    run(`npm publish --access public --tag ${distTag}${npmUserConfig}`, { cwd: pkgDir });
  } catch {
    console.error(`
Publish failed.

Common causes:
  - npm login session (auth-type=web) — use Automation token in project .npmrc instead
  - missing project .npmrc — cp .npmrc.example .npmrc and paste token
  - ENEEDAUTH from npm/* subdirs — fixed by --userconfig in this script; update and re-run

Fix: Automation token at https://www.npmjs.com/settings/~/tokens
Project .npmrc:
  //registry.npmjs.org/:_authToken=npm_YOUR_TOKEN

Then re-run: npm run publish:release
(Platform packages already published can be skipped manually if needed.)
`);
    process.exit(1);
  }
}

run(`npm publish --access public --tag ${distTag}${npmUserConfig}`);

console.log(`\nDone. Install with: npm install node-tpm2@${version}`);
