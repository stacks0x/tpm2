#!/usr/bin/env node
/**
 * Assert npm tarballs match the publish allowlist (no probe/spike/src leakage).
 * Run: npm run verify:package
 */
import { execSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

export const MAIN_TARBALL_ALLOWLIST = new Set([
  'package.json',
  'LICENSE',
  'README.md',
  'index.js',
  'index.d.ts',
  'api.js',
  'native.cjs',
  'native.d.ts',
  'docs/getting-started.md',
  'docs/api-reference.md',
  'docs/windows-pcp.md',
  'docs/roadmap.md',
]);

const SOURCE_FORBIDDEN = [
  /^src\//,
  /^target\//,
  /^Cargo\./,
  /\.rs$/,
  /tbs-probe/i,
  /spike/i,
  /^scripts\//,
  /^docs\/dev\//,
  /^npm\//,
  /^artifacts\//,
  /\.ctx$/,
  /^policy\//,
  /^tests\//,
  /\/tests\//,
  /__tests__\//,
  /\.test\.(m?js|c?js|ts)$/,
  /\.spec\.(m?js|c?js|ts)$/,
];

/** Extra rules for the main JS package (binaries ship via optional platform deps). */
const MAIN_FORBIDDEN = [...SOURCE_FORBIDDEN, /\.node$/];

export function parseNpmPackFiles(cwd) {
  const out = execSync('npm pack --dry-run 2>&1', { cwd, encoding: 'utf8' });
  const files = [];
  let inContents = false;
  for (const line of out.split('\n')) {
    if (line.includes('Tarball Contents')) {
      inContents = true;
      continue;
    }
    if (line.includes('Tarball Details')) break;
    if (!inContents || !line.includes('npm notice')) continue;
    const match = line.match(/npm notice (?:\d+(?:\.\d+)?[kMG]?B )?(.+)$/);
    if (match) files.push(match[1].trim());
  }
  if (files.length === 0) {
    throw new Error(`npm pack --dry-run returned no files (cwd=${cwd})`);
  }
  return files;
}

function assertForbidden(files, label, patterns) {
  for (const file of files) {
    for (const re of patterns) {
      if (re.test(file)) {
        throw new Error(`[${label}] forbidden: ${file}`);
      }
    }
  }
}

export function assertMainTarball() {
  const files = parseNpmPackFiles(root);
  assertForbidden(files, 'main', MAIN_FORBIDDEN);
  for (const file of files) {
    if (file.startsWith('examples/')) {
      if (file !== 'examples/smoke-test.mjs') {
        throw new Error(`[main] unexpected example in tarball: ${file}`);
      }
      continue;
    }
    if (!MAIN_TARBALL_ALLOWLIST.has(file)) {
      throw new Error(`[main] unexpected: ${file}`);
    }
  }
  console.log(`main tarball OK (${files.length} files)`);
}

export function assertPlatformTarball(dirName, { requireNode = false } = {}) {
  const pkgDir = join(root, 'npm', dirName);
  const files = parseNpmPackFiles(pkgDir);
  assertForbidden(files, dirName, SOURCE_FORBIDDEN);
  const nodeCount = files.filter((f) => f.endsWith('.node')).length;
  if (requireNode && nodeCount !== 1) {
    throw new Error(`[${dirName}] must ship exactly one .node (found ${nodeCount})`);
  }
  if (nodeCount > 1) {
    throw new Error(`[${dirName}] expected at most one .node, found ${nodeCount}`);
  }
  for (const file of files) {
    if (file === 'package.json' || file === 'README.md' || file === 'LICENSE') continue;
    if (!file.endsWith('.node')) {
      throw new Error(`[${dirName}] unexpected: ${file}`);
    }
  }
  console.log(`platform ${dirName} OK (${files.length} files${nodeCount ? ', .node present' : ', no .node yet'})`);
}

const isMain = process.argv[1]?.endsWith('verify-package-tarball.mjs');
if (isMain) {
  assertMainTarball();
  for (const dir of readdirSync(join(root, 'npm'))) {
    assertPlatformTarball(dir);
  }
  console.log('\nAll package tarballs verified.');
}
