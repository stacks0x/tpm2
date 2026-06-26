#!/usr/bin/env node
/**
 * Validate the published npm native module (not tbs-probe).
 *
 * Usage:
 *   node smoke-test.mjs runtime
 *   node smoke-test.mjs provision-machine [--key-name NAME] [--out PATH]
 *   node smoke-test.mjs quote [--in PATH]
 *
 * Install on a clean machine:
 *   npm install node-tpm2@<version>
 *   node node_modules/node-tpm2/examples/smoke-test.mjs runtime
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Tpm } from '../index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function usage() {
  console.error(`Usage:
  smoke-test.mjs runtime
  smoke-test.mjs provision-machine [--key-name NAME] [--out PATH]
  smoke-test.mjs quote [--in PATH]

Windows: provision-machine needs elevation or SYSTEM.
Runtime quote works unprivileged (user or machine AK blob).`);
  process.exit(2);
}

function flagValue(args, name) {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && args[i + 1]) return args[++i];
    const prefix = `${name}=`;
    if (args[i]?.startsWith(prefix)) return args[i].slice(prefix.length);
  }
  return undefined;
}

function saveBlob(path, akBlob) {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(
    path,
    JSON.stringify(
      {
        public: akBlob.public.toString('base64'),
        private: akBlob.private.toString('base64'),
      },
      null,
      2,
    ),
  );
}

function loadBlob(path) {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  return {
    public: Buffer.from(raw.public, 'base64'),
    private: Buffer.from(raw.private, 'base64'),
  };
}

function blobScope(akBlob) {
  const head = akBlob.public.subarray(0, 4).toString('ascii');
  if (head === 'PCP2') return 'machine';
  if (head === 'PCP1') return 'user';
  return 'linux-tpm2b';
}

async function assertAvailable() {
  const ok = await Tpm.isAvailable();
  if (!ok) {
    console.error('FAIL: Tpm.isAvailable() returned false');
    process.exit(1);
  }
  console.log('PASS  Tpm.isAvailable()');
}

async function runRuntime() {
  await assertAvailable();
  const info = await Tpm.info();
  console.log('PASS  Tpm.info()', info);

  const { akPublicDer, akBlob } = await Tpm.provisionAk();
  console.log(`PASS  Tpm.provisionAk() scope=${blobScope(akBlob)} SPKI=${akPublicDer.length}B`);

  const qualifying = Buffer.from('node-tpm2-smoke-test-qualifying-data');
  const quote = await Tpm.quote({
    akBlob,
    pcrSelection: [0, 1, 7],
    qualifyingData: qualifying,
    bank: 'sha256',
  });
  if (!quote.message.length || !quote.signature.length) {
    console.error('FAIL: empty quote');
    process.exit(1);
  }
  console.log(
    `PASS  Tpm.quote() message=${quote.message.length}B signature=${quote.signature.length}B`,
  );
  console.log('\nsmoke-test: runtime OK');
}

async function runProvisionMachine(args) {
  await assertAvailable();
  const keyName = flagValue(args, '--key-name') ?? 'my-app-device-ak';
  const out =
    flagValue(args, '--out') ??
    resolve(process.env.PROGRAMDATA ?? 'C:\\ProgramData', 'node-tpm2-spike', 'ak.blob.json');

  if (process.platform !== 'win32') {
    console.error('FAIL: provision-machine is Windows PCP only');
    process.exit(1);
  }

  const { akPublicDer, akBlob } = await Tpm.provisionAk({
    keyName,
    scope: 'machine',
    overwrite: true,
  });
  if (blobScope(akBlob) !== 'machine') {
    console.error(`FAIL: expected PCP2 machine blob, got scope=${blobScope(akBlob)}`);
    process.exit(1);
  }
  saveBlob(out, akBlob);
  console.log(`PASS  Tpm.provisionAk(machine) keyName=${keyName} SPKI=${akPublicDer.length}B`);
  console.log(`  wrote ${out}`);
  console.log('\nNEXT (standard user, from your project directory):');
  console.log(`  node node_modules/node-tpm2/examples/smoke-test.mjs quote --in ${out}`);
}

async function runQuote(args) {
  await assertAvailable();
  const input =
    flagValue(args, '--in') ??
    resolve(process.env.PROGRAMDATA ?? 'C:\\ProgramData', 'node-tpm2-spike', 'ak.blob.json');

  const akBlob = loadBlob(input);
  console.log(`  loaded blob scope=${blobScope(akBlob)} from ${input}`);

  const qualifying = Buffer.from('node-tpm2-smoke-test-qualifying-data');
  const quote = await Tpm.quote({
    akBlob,
    pcrSelection: [0, 1, 7],
    qualifyingData: qualifying,
    bank: 'sha256',
  });
  console.log(
    `PASS  Tpm.quote() message=${quote.message.length}B signature=${quote.signature.length}B`,
  );
  console.log('\nsmoke-test: quote OK');
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case 'runtime':
      await runRuntime();
      break;
    case 'provision-machine':
      await runProvisionMachine(rest);
      break;
    case 'quote':
      await runQuote(rest);
      break;
    default:
      usage();
  }
}

main().catch((err) => {
  console.error('FAIL:', err.message ?? err);
  if (err.code) console.error('  code:', err.code);
  if (err.suggestion) console.error('  suggestion:', err.suggestion);
  if (err.tpmRc != null) console.error('  tpmRc:', err.tpmRc);
  if (err.hresult != null) console.error('  hresult:', err.hresult);
  process.exit(1);
});
