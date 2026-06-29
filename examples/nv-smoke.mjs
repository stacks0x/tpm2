#!/usr/bin/env node
/**
 * NV define / read / write / undefine cycle (owner NV index).
 *
 * WARNING: Mutates TPM NV storage. Use only on a test machine.
 * Requires owner authorization (often empty password on consumer TPMs).
 * Windows: run elevated (Admin); standard user gets REQUIRES_ELEVATION.
 *
 * Usage:
 *   node nv-smoke.mjs
 *   node nv-smoke.mjs --handle 0x01800042 --size 64
 *
 * Install:
 *   npm install node-tpm2@beta
 *   node node_modules/node-tpm2/examples/nv-smoke.mjs
 */

import { Tpm } from '../index.js';

function flagValue(args, name) {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && args[i + 1]) return args[++i];
    const prefix = `${name}=`;
    if (args[i]?.startsWith(prefix)) return args[i].slice(prefix.length);
  }
  return undefined;
}

async function main() {
  const args = process.argv.slice(2);
  const handle = flagValue(args, '--handle') ?? '0x01800042';
  const size = Number(flagValue(args, '--size') ?? '64');

  if (!(await Tpm.isAvailable())) {
    console.error('FAIL: no TPM');
    process.exit(1);
  }

  await using tpm = await Tpm.open();
  const payload = Buffer.from(`node-tpm2-nv-smoke-${Date.now()}`);

  console.log(`== nv-smoke handle=${handle} size=${size} ==`);

  try {
    await tpm.nv.undefine(handle);
    console.log('  (pre-clean undefine OK)');
  } catch {
    console.log('  (pre-clean undefine skipped — index may not exist)');
  }

  await tpm.nv.define({ handle, size });
  console.log('PASS  nv.define');

  try {
    const meta = await tpm.nv.readPublic(handle);
    console.log('PASS  nv.readPublic', meta);
  } catch (err) {
    // Windows raw TBS often blocks NV_ReadPublic for owner-range indices (~0xA6);
    // read/write still work via owner auth fallback in the native layer.
    console.log(
      '  (nv.readPublic skipped:',
      err.code ?? err.message,
      '— continuing with define size)',
    );
  }

  await tpm.nv.write(handle, payload, 0);
  console.log('PASS  nv.write', payload.length, 'bytes');

  const readBack = await tpm.nv.read(handle, 0, payload.length);
  if (!readBack.equals(payload)) {
    console.error('FAIL: read mismatch');
    console.error('  wrote:', payload.length, payload.toString('hex'));
    console.error('  read: ', readBack.length, readBack.toString('hex'));
    process.exit(1);
  }
  console.log('PASS  nv.read roundtrip');

  await tpm.nv.undefine(handle);
  console.log('PASS  nv.undefine');

  console.log('\nnv-smoke: OK');
}

main().catch((err) => {
  console.error('FAIL:', err.message ?? err);
  if (err.code) console.error('  code:', err.code);
  if (err.tpmRc != null) console.error('  tpmRc:', err.tpmRc);
  if (err.hresult != null) console.error('  hresult:', err.hresult);
  process.exit(1);
});
