#!/usr/bin/env node
/**
 * npm spam-filter blocks new unscoped *-win32-* package names.
 * napi-rs generates win32-* npm names from Rust triples; we publish as windows-* instead.
 * Binary filenames stay node-tpm2.win32-*.node — only the npm package name changes.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const RENAMES = {
  'node-tpm2-win32-x64-msvc': 'node-tpm2-windows-x64-msvc',
  'node-tpm2-win32-arm64-msvc': 'node-tpm2-windows-arm64-msvc',
}

const WIN_DIRS = ['win32-x64-msvc', 'win32-arm64-msvc']

for (const dir of WIN_DIRS) {
  const pkgPath = join(root, 'npm', dir, 'package.json')
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
  if (RENAMES[pkg.name]) {
    pkg.name = RENAMES[pkg.name]
    writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`)
  }

  const readmePath = join(root, 'npm', dir, 'README.md')
  let readme = readFileSync(readmePath, 'utf8')
  for (const [from, to] of Object.entries(RENAMES)) {
    readme = readme.replaceAll(from, to)
  }
  writeFileSync(readmePath, readme)
}

const rootPkgPath = join(root, 'package.json')
const rootPkg = JSON.parse(readFileSync(rootPkgPath, 'utf8'))
rootPkg.optionalDependencies = Object.fromEntries(
  Object.entries(rootPkg.optionalDependencies).map(([name, version]) => [
    RENAMES[name] ?? name,
    version,
  ]),
)
writeFileSync(rootPkgPath, `${JSON.stringify(rootPkg, null, 2)}\n`)

const nativePath = join(root, 'native.cjs')
let native = readFileSync(nativePath, 'utf8')
for (const [from, to] of Object.entries(RENAMES)) {
  native = native.replaceAll(`'${from}'`, `'${to}'`)
  native = native.replaceAll(`'${from}/package.json'`, `'${to}/package.json'`)
}
writeFileSync(nativePath, native)

// Warn on optional-binding version skew; throw only when NAPI_RS_ENFORCE_VERSION_CHECK is set.
const pkgVersion = rootPkg.version
const versionCheckNeedle = `if (bindingPackageVersion !== '${pkgVersion}' && process.env.NAPI_RS_ENFORCE_VERSION_CHECK`
const versionCheckReplacement = `if (bindingPackageVersion !== '${pkgVersion}') {
          if (typeof process !== 'undefined' && process.emitWarning) {
            process.emitWarning(
              \`[node-tpm2] optional binding version \${bindingPackageVersion} !== ${pkgVersion}; run npm install or npm run build\`,
              { type: 'node-tpm2', code: 'NATIVE_BINDING_VERSION' },
            )
          }
        }
        if (bindingPackageVersion !== '${pkgVersion}' && process.env.NAPI_RS_ENFORCE_VERSION_CHECK`
if (native.includes(versionCheckNeedle)) {
  native = native.replaceAll(versionCheckNeedle, versionCheckReplacement)
  writeFileSync(nativePath, native)
}

console.log('Patched Windows npm package names: win32-* -> windows-*')
