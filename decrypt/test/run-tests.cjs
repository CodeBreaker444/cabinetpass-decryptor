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

// ---------- Google Drive (read-only) ----------
const D = require('../drive.js');

test('Drive: sign-in URL asks only for the hidden app folder, with a state value', () => {
  const u = new URL(D.authUrl({ redirect: 'https://cabinetpass.com/decrypt/', state: 'abc123' }));
  assert.equal(u.origin + u.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(u.searchParams.get('scope'), 'https://www.googleapis.com/auth/drive.appdata');
  assert.equal(u.searchParams.get('response_type'), 'token');
  assert.equal(u.searchParams.get('redirect_uri'), 'https://cabinetpass.com/decrypt/');
  assert.equal(u.searchParams.get('state'), 'abc123');
  assert.equal(D.redirectUri({ origin: 'https://cabinetpass.com', pathname: '/decrypt/' }), 'https://cabinetpass.com/decrypt/');
  assert.equal(D.redirectUri({ origin: 'https://cabinetpass.com', pathname: '/decrypt/index.html' }), 'https://cabinetpass.com/decrypt/');
});

test('Drive: redirect parsing checks state and reports errors', () => {
  assert.equal(D.parseRedirect('', 's'), null);
  assert.equal(D.parseRedirect('#section', 's'), null, 'ordinary anchors are ignored');
  const ok = D.parseRedirect('#access_token=tok&token_type=Bearer&expires_in=3599&state=s', 's');
  assert.equal(ok.token, 'tok');
  assert.ok(ok.expiresAt > Date.now());
  assert.throws(() => D.parseRedirect('#access_token=tok&state=evil', 's'), /could not be verified/, 'CSRF: state mismatch');
  assert.throws(() => D.parseRedirect('#access_token=tok&state=s', null), /could not be verified/, 'no pending sign-in');
  assert.throws(() => D.parseRedirect('#error=access_denied&state=s', 's'), /cancelled/);
});

test('Drive: downloads vault.cpv and attachments read-only, and the vault decrypts', async () => {
  // What the app keeps in appDataFolder: the bare vault plus att_<id> blobs.
  const backup = JSON.parse(new TextDecoder().decode(sampleBytes()));
  const vaultBytes = CP.b64ToBytes(backup.vault);
  const attIds = Object.keys(backup.files || {});
  const driveFiles = [
    { id: 'drv-vault', name: 'vault.cpv', modifiedTime: '2026-10-05T10:00:00Z' },
    ...attIds.map((id, i) => ({ id: `drv-att-${i}`, name: `att_${id}` })),
  ];
  const requests = [];
  const fetchFn = async (url, init = {}) => {
    requests.push({ url, method: init.method || 'GET', auth: init.headers && init.headers.Authorization });
    const u = new URL(url);
    const body = (b) => ({ ok: true, status: 200, json: async () => b, arrayBuffer: async () => b });
    if (u.pathname === '/drive/v3/files') {
      assert.equal(u.searchParams.get('spaces'), 'appDataFolder');
      const q = u.searchParams.get('q');
      const match = q.startsWith("name = 'vault.cpv'") ? driveFiles.slice(0, 1) : driveFiles.slice(1);
      return body({ files: match });
    }
    const id = decodeURIComponent(u.pathname.split('/').pop());
    assert.equal(u.searchParams.get('alt'), 'media');
    if (id === 'drv-vault') return body(vaultBytes.buffer.slice(vaultBytes.byteOffset, vaultBytes.byteOffset + vaultBytes.byteLength));
    const i = Number(id.replace('drv-att-', ''));
    const bytes = CP.b64ToBytes(backup.files[attIds[i]]);
    return body(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
  };

  const r = await D.fetchVault('tok', fetchFn);
  assert.equal(r.modifiedTime, '2026-10-05T10:00:00Z');
  assert.equal(r.attachments.size, attIds.length);
  const imported = CP.parseImport(r.bytes);
  assert.equal(imported.kind, 'vault');
  const { data } = await CP.openVault(imported, expected.password, { argon2id });
  assert.equal(active(data).length, active((await openSample()).data).length);

  // An attachment fetched on demand decrypts like the backup's copy.
  const withFile = active(data).find((e) => (e.attachments || []).length);
  if (withFile) {
    const a = withFile.attachments[0];
    const blob = await D.fetchAttachment('tok', r.attachments.get(a.id), fetchFn);
    const plain = await CP.decryptAttachment(a, blob);
    assert.ok(plain.length > 0);
  }
  assert.ok(requests.every((q) => q.method === 'GET'), 'read-only: only GET requests');
  assert.ok(requests.every((q) => q.auth === 'Bearer tok'));
});

test('Drive: clear errors for an expired session and for a missing vault', async () => {
  const expired = async () => ({ ok: false, status: 401 });
  await assert.rejects(D.fetchVault('tok', expired), /session expired/);
  const empty = async () => ({ ok: true, status: 200, json: async () => ({ files: [] }) });
  await assert.rejects(D.fetchVault('tok', empty), /No CabinetPass vault/);
});

// ---------- CSV export ----------
const X = require('../export.js');

// A small RFC 4180 reader, written separately from the writer under test.
function parseCsv(text) {
  const rows = [];
  let row = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\r' && text[i + 1] === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; i++; }
    else cell += c;
  }
  assert.equal(cell, '', 'the file ends with a line break');
  assert.equal(row.length, 0);
  return rows;
}
const asObjects = ([header, ...rows]) => rows.map((r) => Object.fromEntries(header.map((k, i) => [k, r[i]])));

test('CSV export: quoting keeps every character, and 2FA secrets become otpauth URIs', () => {
  assert.equal(X.csvLine(['plain', 'a,b', 'say "hi"', 'two\nlines', ' padded ', '', null]),
    'plain,"a,b","say ""hi""","two\nlines"," padded ",,');
  const tricky = ['=1+1', '@cmd', 'ünïcode ✓', 'a,"b"\r\nc', "it's", '\ttab'];
  assert.deepEqual(parseCsv(`${X.csvLine(tricky)}\r\n`), [tricky], 'values are written as stored, never altered');

  assert.equal(X.otpauthUri('JBSW Y3DP', { issuer: 'My Bank', account: 'a@b.co' }),
    'otpauth://totp/My%20Bank:a%40b.co?secret=JBSWY3DP&issuer=My%20Bank');
  assert.equal(X.otpauthUri('ABC', { issuer: 'X', digits: 8, period: 60, algorithm: 'sha256' }),
    'otpauth://totp/X?secret=ABC&issuer=X&digits=8&period=60&algorithm=SHA256');
  const uri = 'otpauth://totp/Kept:as-is?secret=ABC&digits=7';
  assert.equal(X.otpauthUri(uri, { issuer: 'Other' }), uri);
  assert.equal(X.otpauthUri('', { issuer: 'X' }), '');
  assert.match(X.fileName('standard', new Date('2026-11-22T10:00:00Z')), /^cabinetpass-passwords-2026-11-22\.csv$/);
  assert.throws(() => X.toCsv({}, 'xml'), /Unknown export format/);
});

test('CSV export (Standard): every item and 2FA account, nothing lost', async () => {
  const { data } = await openSample();
  const table = parseCsv(X.toCsv(data, 'standard'));
  assert.deepEqual(table[0], ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth']);
  assert.ok(table.every((r) => r.length === 6));
  const rows = asObjects(table);
  assert.deepEqual(rows.map((r) => r.Title), [...expected.titles, ...expected.totps.map((t) => t.issuer)],
    'active items by title, then 2FA accounts; Recently Deleted is left out');

  const github = rows.find((r) => r.Title === 'GitHub');
  const hashOf = (label) => expected.fields.GitHub[label].sha256;
  assert.equal(sha256(Buffer.from(github.URL)), hashOf('Website'));
  assert.equal(sha256(Buffer.from(github.Username)), hashOf('Username'));
  assert.equal(sha256(Buffer.from(github.Password)), hashOf('Password'));
  const otp = new URL(github.OTPAuth);
  assert.equal(sha256(Buffer.from(otp.searchParams.get('secret'))), hashOf('One-Time Code'));
  assert.equal(otp.searchParams.get('issuer'), 'GitHub');

  // Every stored value is somewhere in its row, whatever the item type.
  for (const e of active(data)) {
    const r = rows.find((x) => x.Title === e.title);
    const cells = Object.values(r);
    for (const f of e.fields.filter((x) => x.value)) {
      assert.ok(cells.includes(f.value) || r.Notes.includes(`${f.label}: ${f.value}`) || r.Notes.includes(`${f.label}:\n${f.value}`) ||
        (f.kind === 'totp' && r.OTPAuth.includes(f.value)), `${e.title}: ${f.label}`);
    }
    if (e.notes) assert.ok(r.Notes.endsWith(e.notes), `${e.title}: notes`);
  }
  const ssh = rows.find((r) => r.Title === 'Build server');
  assert.equal(ssh.Password, '', 'a key passphrase is not passed off as a login password');
  assert.match(ssh.Notes, /Passphrase: .+/);

  const [totp] = expected.totps;
  const account = rows.find((r) => r.Title === totp.issuer);
  assert.equal(account.Username, totp.account);
  assert.equal(new URL(account.OTPAuth).searchParams.get('secret'), totp.secret);

  assert.deepEqual(X.summary(data), { items: expected.titles.length, totps: expected.totps.length,
    files: Object.keys(expected.attachments).length, passkeys: 0 });
});

test('CSV export (Bitwarden): folders, favourites, custom fields and note items', () => {
  const data = {
    groups: [{ id: 'web', name: 'Web Logins' }, { id: 'id', name: 'Identity' }],
    entries: [
      { id: '1', title: 'Shop, "Best"', group: 'web', type: 'login', fav: true, notes: 'line one\nline two',
        fields: [
          { label: 'Email', kind: 'email', value: 'me@example.com' },
          { label: 'Password', kind: 'password', value: 'p,w"1' },
          { label: 'Website', kind: 'url', value: 'https://shop.example' },
          { label: 'Backup site', kind: 'url', value: 'https://alt.example' },
          { label: 'PIN: card', kind: 'hidden', value: '4321' },
          { label: 'Recovery codes', kind: 'multiline', value: 'aaa\nbbb' },
          { label: 'Empty', kind: 'text', value: '' },
        ],
        passkeys: [{ id: 'cred', rp: 'shop.example', key: 'SECRET-PRIVATE-KEY' }],
        attachments: [{ id: 'a1', name: 'receipt.pdf', key: 'SECRET-FILE-KEY' }],
        pwHistory: [{ v: 'old-password', at: '2026-01-01' }] },
      { id: '2', title: 'Passport', group: 'id', type: 'identity', fields: [{ label: 'Number', kind: 'hidden', value: 'X123' }] },
      { id: '3', title: 'Gone', group: 'web', type: 'login', deleted: '2026-01-01', fields: [{ label: 'Password', kind: 'password', value: 'deleted-pw' }] },
    ],
    totps: [{ id: 't', issuer: 'Google', account: 'me@example.com', secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, alg: 'sha1' }],
  };
  const csv = X.toCsv(data, 'bitwarden');
  const table = parseCsv(csv);
  assert.deepEqual(table[0], ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp']);
  assert.ok(table.every((r) => r.length === 11));
  const [passport, shop, google] = asObjects(table);

  assert.deepEqual(shop, {
    folder: 'Web Logins', favorite: '1', type: 'login', name: 'Shop, "Best"',
    notes: 'line one\nline two\n\nRecovery codes:\naaa\nbbb',
    fields: 'Backup site: https://alt.example\nPIN - card: 4321', reprompt: '0',
    login_uri: 'https://shop.example', login_username: 'me@example.com', login_password: 'p,w"1', login_totp: '',
  });
  assert.deepEqual([passport.folder, passport.type, passport.name, passport.fields], ['Identity', 'note', 'Passport', 'Number: X123']);
  assert.deepEqual([google.type, google.name, google.login_username], ['login', 'Google', 'me@example.com']);
  assert.equal(google.login_totp, 'otpauth://totp/Google:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google');

  for (const secret of ['SECRET-PRIVATE-KEY', 'SECRET-FILE-KEY', 'old-password', 'deleted-pw']) {
    assert.ok(!csv.includes(secret) && !X.toCsv(data, 'standard').includes(secret), `${secret} is never exported`);
  }
  assert.deepEqual(X.summary(data), { items: 2, totps: 1, files: 1, passkeys: 1 });
});
