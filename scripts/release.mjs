#!/usr/bin/env node
/**
 * Release helpers for node-tpm2.
 *
 *   npm run release:preflight   — tests + tarball verify (no TPM, no publish)
 *   npm run release:publish     — build all targets + npm publish
 *   npm run release:tag         — git tag v<version> from package.json + push
 *   npm run release             — preflight → publish → tag (full local release)
 *
 * See docs/RELEASE.md
 */
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function run(cmd) {
  console.log(`\n> ${cmd}`);
  execSync(cmd, { cwd: root, stdio: 'inherit' });
}

function readVersion() {
  return JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
}

function preflight() {
  run('cargo test --lib -- --skip hw_');
  run('npm run verify:package');
  const version = readVersion();
  const distTag = version.includes('-') ? 'beta' : 'latest';
  console.log(`\nPreflight OK — ready to publish ${version} (dist-tag: ${distTag})`);
}

function publish() {
  run('node scripts/publish-release.mjs');
}

function tag() {
  const version = readVersion();
  const gitTag = `v${version}`;
  try {
    execSync(`git rev-parse -q --verify "refs/tags/${gitTag}"`, { cwd: root, stdio: 'pipe' });
    console.error(`\nTag ${gitTag} already exists locally. Delete or pick a new version.`);
    process.exit(1);
  } catch {
    // tag does not exist — OK
  }
  run(`git tag -a ${gitTag} -m "node-tpm2 ${version}"`);
  run(`git push origin ${gitTag}`);
  console.log(`\nTagged and pushed ${gitTag}`);
  console.log(`Optional GitHub Release: gh release create ${gitTag} --title "${version}" --notes "See CHANGELOG or commit log."`);
}

const cmd = process.argv[2] ?? 'all';

switch (cmd) {
  case 'preflight':
    preflight();
    break;
  case 'publish':
    publish();
    break;
  case 'tag':
    tag();
    break;
  case 'all':
    preflight();
    publish();
    tag();
    break;
  default:
    console.error(`Unknown command: ${cmd}`);
    console.error('Usage: node scripts/release.mjs [preflight|publish|tag|all]');
    process.exit(1);
}
