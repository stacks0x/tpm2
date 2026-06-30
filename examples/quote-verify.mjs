#!/usr/bin/env node
/**
 * Verify Linux ECDSA quote signature against akPublicDer.
 *
 * From repo (tests local build with fix):
 *   npm run build
 *   node examples/quote-verify.mjs
 *
 * From npm install (after 0.0.7+ published):
 *   node node_modules/node-tpm2/examples/quote-verify.mjs
 *
 * Mutating: provisions a user AK and quotes PCRs. Run only on machines where that is OK.
 */

import { createHash, createPublicKey, verify } from 'node:crypto';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Tpm } from '../index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const qualifyingData = createHash('sha256').update('node-tpm2-repro').digest();

const { akPublicDer, akBlob } = await Tpm.provisionAk();
const { message, signature } = await Tpm.quote({
  akBlob,
  pcrSelection: [0, 7],
  qualifyingData,
  bank: 'sha256',
});

const key = createPublicKey({ key: akPublicDer, format: 'der', type: 'spki' });
const ok = verify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature);

console.log({
  akPublicDerLen: akPublicDer.length,
  messageLen: message.length,
  sigLen: signature.length,
  sigHexPrefix: signature.subarray(0, 8).toString('hex'),
  verify: ok,
});

if (!ok) {
  console.error('FAIL: signature did not verify');
  console.error('  sigLen 64 expected after quote fix; 24 means old 0.0.6 npm build');
  process.exit(1);
}

console.log('quote-verify: OK');
