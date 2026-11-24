#!/usr/bin/env node
// Decrypts a CabinetPass vault/backup with the same code the web page uses
// and prints a JSON summary (also used by the app's interop test).
//
//   node decrypt/test/verify-node.cjs <file.cpv> <master password>
//
// With --csv it prints the vault as CSV for another password manager instead
// (not encrypted: redirect it to a file, import it, then delete it):
//
//   node decrypt/test/verify-node.cjs <file.cpv> <master password> --csv [standard|bitwarden]
'use strict';
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const hashwasm = require('../vendor/hash-wasm-argon2.umd.min.js');
const CP = require('../cabinetpass-crypto.js');
const X = require('../export.js');

const argon2id = ({ password, salt, memoryKiB, iterations, parallelism, hashLength }) =>
  hashwasm.argon2id({ password, salt, memorySize: memoryKiB, iterations, parallelism, hashLength, outputType: 'binary' });

async function main() {
  const [file, password, flag, format = 'standard'] = process.argv.slice(2);
  if (!file || password === undefined || (flag !== undefined && flag !== '--csv') || !X.FORMATS[format]) {
    console.error('usage: verify-node.cjs <file.cpv> <master password> [--csv [standard|bitwarden]]');
    process.exit(2);
  }
  const imported = CP.parseImport(new Uint8Array(fs.readFileSync(file)));
  const steps = [];
  const { data } = await CP.openVault(imported, password, { argon2id, onStep: (s) => steps.push(s.step) });
  if (flag === '--csv') {
    process.stdout.write(X.toCsv(data, format));
    return;
  }

  const entries = data.entries.filter((e) => !e.deleted);
  const attachments = [];
  for (const e of entries) {
    for (const a of e.attachments || []) {
      const blob = imported.files.get(a.id);
      if (!blob) {
        attachments.push({ id: a.id, missing: true });
        continue;
      }
      const plain = await CP.decryptAttachment(a, blob);
      attachments.push({ id: a.id, name: a.name, size: plain.length, sha256: createHash('sha256').update(plain).digest('hex') });
    }
  }
  const pw = (e) => (e.fields.find((f) => f.kind === 'password' && f.value) || {}).value || null;
  console.log(JSON.stringify({
    kind: imported.kind,
    steps,
    titles: entries.map((e) => e.title).sort(),
    passwords: Object.fromEntries(entries.map((e) => [e.title, pw(e)])),
    attachments,
  }));
}

main().catch((e) => {
  console.error(`${e.name}: ${e.message}`);
  process.exit(1);
});
