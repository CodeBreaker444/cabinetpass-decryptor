#!/usr/bin/env node
// Test suite for the CabinetPass Vault Viewer. No dependencies: Node 18+.
//
//   npm test            (or)   node decrypt/test/run-tests.cjs
//
// fixtures/sample-backup.cpv was exported by the real CabinetPass app;
// fixtures/sample-expected.json lists what it must decrypt to. Secret values
// are listed as SHA-256 hashes.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const hashwasm = require('../vendor/hash-wasm-argon2.umd.min.js');
const CP = require('../cabinetpass-crypto.js');

const here = (...p) => path.join(__dirname, ...p);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const expected = JSON.parse(fs.readFileSync(here('fixtures', 'sample-expected.json'), 'utf8'));
const sampleBytes = () => new Uint8Array(fs.readFileSync(here('fixtures', 'sample-backup.cpv')));

const argon2id = ({ password, salt, memoryKiB, iterations, parallelism, hashLength }) =>
  hashwasm.argon2id({ password, salt, memorySize: memoryKiB, iterations, parallelism, hashLength, outputType: 'binary' });

// Argon2id at 64 MiB takes ~1 s; decrypt the sample once and share it.
let opened;
async function openSample() {
  if (!opened) {
    const imported = CP.parseImport(sampleBytes());
    const steps = [];
    const { data } = await CP.openVault(imported, expected.password, { argon2id, onStep: (s) => steps.push(s) });
    opened = { imported, data, steps };
  }
  return opened;
}
const active = (data) => data.entries.filter((e) => !e.deleted);

test('vendored hash-wasm matches the pinned npm release', () => {
  const bytes = fs.readFileSync(here('..', 'vendor', 'hash-wasm-argon2.umd.min.js'));
  assert.equal(sha256(bytes), 'dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094');
});

test('Argon2id matches the reference implementation', async () => {
  // Same value from libargon2 (the C reference, via argon2-cffi) and from the
  // Dart `cryptography` package used by the app:
  //   hash_secret_raw(b'password', b'somesalt', time_cost=2, memory_cost=65536,
  //                   parallelism=1, hash_len=32, type=Type.ID)
  const enc = new TextEncoder();
  const out = await argon2id({ password: enc.encode('password'), salt: enc.encode('somesalt'),
    memoryKiB: 65536, iterations: 2, parallelism: 1, hashLength: 32 });
  assert.equal(Buffer.from(out).toString('hex'), '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7');
});

test('sample: envelope and KDF parameters', async () => {
  const { imported, steps } = await openSample();
  assert.equal(imported.kind, expected.kind);
  const { kdf } = imported.envelope;
  assert.deepEqual([kdf.alg, kdf.memoryKiB, kdf.iterations, kdf.parallelism],
    [expected.kdf.alg, expected.kdf.m, expected.kdf.t, expected.kdf.p]);
  assert.equal(kdf.salt.length, 16);
  assert.deepEqual(steps.map((s) => s.step), ['Derive master key', 'Unwrap vault key', 'Decrypt vault', 'Decompress', 'Parse']);
});

test('sample: items, groups and 2FA accounts', async () => {
  const { data } = await openSample();
  assert.deepEqual(active(data).map((e) => e.title).sort(), expected.titles);
  assert.deepEqual(data.entries.filter((e) => e.deleted).map((e) => e.title), expected.deletedTitles);
  assert.deepEqual(data.groups.slice().sort((a, b) => a.sort - b.sort).map((g) => g.name), expected.groups);
  assert.deepEqual(data.totps.map(({ issuer, account, secret }) => ({ issuer, account, secret })), expected.totps);
});

test('sample: every field value, by hash', async () => {
  const { data } = await openSample();
  for (const e of active(data)) {
    const want = expected.fields[e.title];
    const got = Object.fromEntries(e.fields.map((f) => [f.label, { kind: f.kind, sha256: sha256(Buffer.from(f.value, 'utf8')) }]));
    assert.deepEqual(got, want, e.title);
  }
});

test('sample: attachments decrypt to the original bytes', async () => {
  const { data, imported } = await openSample();
  const atts = active(data).flatMap((e) => e.attachments || []);
  assert.equal(atts.length, Object.keys(expected.attachments).length);
  for (const a of atts) {
    const want = expected.attachments[a.name];
    const plain = await CP.decryptAttachment(a, imported.files.get(a.id));
    assert.equal(a.mime, want.mime, a.name);
    assert.equal(plain.length, want.size, a.name);
    assert.equal(sha256(plain), want.sha256, a.name);
  }
});

test('sample: SSH public key fingerprint matches ssh-keygen', async () => {
  const { data } = await openSample();
  const ssh = active(data).find((e) => e.type === 'ssh');
  const pub = ssh.fields.find((f) => f.label === 'Public Key').value.split(/\s+/)[1];
  const fp = `SHA256:${createHash('sha256').update(Buffer.from(pub, 'base64')).digest('base64').replace(/=+$/, '')}`;
  assert.equal(fp, expected.sshFingerprint);
  assert.equal(ssh.fields.find((f) => f.kind === 'sshKey').value.split('\n')[0], '-----BEGIN OPENSSH PRIVATE KEY-----');
});

test('wrong password is rejected', async () => {
  const imported = CP.parseImport(sampleBytes());
  await assert.rejects(CP.openVault(imported, 'wrong password', { argon2id }),
    (e) => e instanceof CP.DecryptError && e.message === 'Incorrect master password.');
});

test('tampering is detected (AES-GCM authentication)', async () => {
  const { imported, data } = await openSample();
  const flip = (bytes, i) => {
    const copy = bytes.slice();
    copy[i] ^= 0x01;
    return copy;
  };

  // Vault payload: flip one ciphertext byte.
  const env = imported.envelope;
  const tampered = { ...imported, envelope: { ...env, payload: flip(env.payload, 20) } };
  await assert.rejects(CP.openVault(tampered, expected.password, { argon2id }), CP.DecryptError);

  // Attachment: flip a byte, or swap two files (each is bound to its ID by the AAD).
  const [a, b] = active(data).flatMap((e) => e.attachments);
  await assert.rejects(CP.decryptAttachment(a, flip(imported.files.get(a.id), 15)), CP.DecryptError);
  await assert.rejects(CP.decryptAttachment({ ...a, key: b.key }, imported.files.get(b.id)), CP.DecryptError);
  await assert.rejects(CP.decryptAttachment(a, imported.files.get(b.id)), CP.DecryptError);
});

test('bare vault.cpv opens without files', async () => {
  const bundle = JSON.parse(Buffer.from(sampleBytes()).toString('utf8'));
  const vaultOnly = Buffer.from(bundle.vault, 'base64');
  const imported = CP.parseImport(new Uint8Array(vaultOnly));
  assert.equal(imported.kind, 'vault');
  assert.equal(imported.files.size, 0);
  const { data } = await CP.openVault(imported, expected.password, { argon2id });
  assert.deepEqual(active(data).map((e) => e.title).sort(), expected.titles);
});

test('rejects files that are not CabinetPass vaults', () => {
  const enc = (o) => new TextEncoder().encode(typeof o === 'string' ? o : JSON.stringify(o));
  assert.throws(() => CP.parseImport(enc('not json')), CP.FormatError);
  assert.throws(() => CP.parseImport(enc({ format: 'something-else' })), CP.FormatError);
  assert.throws(() => CP.parseImport(enc({ format: 'cabinetpass-vault', v: 2 })), /Unsupported vault version 2/);
  assert.throws(() => CP.parseImport(enc({ format: 'cabinetpass-vault', v: 1, kdf: { alg: 'pbkdf2' } })), /Unsupported key derivation/);
});

test('TOTP matches RFC 6238 test vectors', async () => {
  const s1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
  const s256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
  const s512 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA';
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1234567890, '89005924', '91819424', '93441116'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [t, sha1, sha256v, sha512] of vectors) {
    const at = t * 1000;
    assert.equal(await CP.totp(s1, { digits: 8, at }), sha1, `sha1 @${t}`);
    assert.equal(await CP.totp(s256, { digits: 8, at, algorithm: 'sha256' }), sha256v, `sha256 @${t}`);
    assert.equal(await CP.totp(s512, { digits: 8, at, algorithm: 'sha512' }), sha512, `sha512 @${t}`);
  }
});
