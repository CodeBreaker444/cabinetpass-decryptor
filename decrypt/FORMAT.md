# CabinetPass file format (v1)

This document specifies everything needed to decrypt a CabinetPass vault
without the app. The reference implementation is
[`cabinetpass-crypto.js`](cabinetpass-crypto.js), about 200 lines with no
dependencies besides an Argon2id function. It was written separately from
the app's Dart code, and the app's test suite checks that the two agree.

## Overview

```
master password ──Argon2id(salt, m, t, p)──▶ KEK (32 bytes)
KEK ──AES-256-GCM  AAD "cabinetpass.dek.v1"────▶ DEK (32 bytes, random per vault)
DEK ──AES-256-GCM  AAD "cabinetpass.vault.v1"──▶ gzip(vault JSON)
file key ──AES-256-GCM  AAD "cabinetpass.file.v1:<id>"──▶ [gzip](file bytes)
```

- **KEK** (key-encryption key) is derived from the master password and
  never stored.
- **DEK** (data-encryption key) is random. Changing the master password
  only re-wraps the DEK. The vault payload is not re-encrypted.
- **File keys** are random per attachment and live inside the encrypted
  vault JSON. Anyone without the vault can't read a file, even with the
  file's blob.

### AES-GCM blob layout

Every encrypted blob (wrapped key, payload, attachment) is:

```
nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes)
```

The nonce is random per encryption. The AAD is the UTF-8 encoding of the
strings above. For attachments, `<id>` is the attachment's `id`. This binds
each blob to its role, so a blob can't be swapped for another and still
authenticate.

In WebCrypto: `iv = blob[0:12]`, `data = blob[12:]` (ciphertext‖tag),
`tagLength = 128`.

## Vault envelope (`vault.cpv`)

UTF-8 JSON. This is the file stored on device and as `vault.cpv` in the
Google Drive app-data folder.

```json
{
  "format": "cabinetpass-vault",
  "v": 1,
  "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 4, "salt": "<base64, 16 bytes>" },
  "wrappedKey": "<base64 AES-GCM blob of the 32-byte DEK>",
  "keyUpdated": "2026-10-01T08:16:23.000Z",
  "payload": "<base64 AES-GCM blob of gzip(vault JSON)>",
  "updated": "2026-10-01T08:16:23.000Z"
}
```

| Field | Meaning |
|---|---|
| `kdf.m` | Argon2id memory in KiB (65536 = 64 MiB) |
| `kdf.t` | iterations |
| `kdf.p` | parallelism (lanes) |
| `kdf.salt` | random, 16 bytes |

Argon2 version is 0x13, output length is 32 bytes, and the password is the
UTF-8 bytes of the master password with no normalization. A failed GCM tag
check on `wrappedKey` means the password is wrong.

The KDF parameters are read from the file, so readers must honour them
rather than hard-code the defaults.

## Backup bundle (Settings › Export Encrypted Backup)

```json
{
  "format": "cabinetpass-backup",
  "v": 1,
  "vault": "<base64 of the vault envelope JSON bytes above>",
  "files": { "<attachment id>": "<base64 AES-GCM blob>", "...": "..." }
}
```

The bundle adds no extra encryption: each file is already encrypted. On
Google Drive, attachments are stored separately as `att_<id>`, holding the
raw blob bytes.

## Vault JSON (decrypted payload)

```jsonc
{
  "schema": 1,
  "groups": [
    { "id": "web", "name": "Web Logins", "icon": "globe", "color": "blue",
      "type": "login", "sort": 0, "updated": "…" }
  ],
  "entries": [
    {
      "id": "…", "title": "GitHub", "group": "web", "type": "login",
      "fields": [
        { "id": "…", "label": "Username", "value": "octocat", "kind": "username" },
        { "id": "…", "label": "Password", "value": "…", "kind": "password" }
      ],
      "notes": "",
      "attachments": [
        { "id": "…", "name": "id.jpg", "mime": "image/jpeg", "size": 754211,
          "key": "<base64, 32-byte AES key>", "compression": "gzip", "created": "…" }
      ],
      "pwHistory": [ { "v": "old password", "at": "…" } ],
      "fav": false,
      "created": "…", "updated": "…", "used": null,
      "deleted": null            // ISO date when in Recently Deleted
    }
  ],
  "totps": [
    { "id": "…", "issuer": "Google", "account": "me@example.com",
      "secret": "<base32>", "digits": 6, "period": 30, "alg": "sha1", "updated": "…" }
  ],
  "generated": [ { "v": "…", "at": "…" } ],
  "tombstones": { "<id>": "<deleted at>" },
  "updated": "…"
}
```

- **`type`** is one of `login`, `card`, `bank`, `note`, `identity`, `wifi`,
  `document`, `ssh`, `custom`. Unknown values should be treated as `custom`.
- **Field `kind`** is one of `text`, `username`, `password`, `hidden`,
  `email`, `url`, `phone`, `number`, `date`, `totp`, `multiline`, `sshKey`.
  Unknown values should be treated as `text`.
  - A `totp` field holds a base32 secret or an `otpauth://` URI.
  - An `sshKey` field holds a private key as text: OpenSSH, PEM or PuTTY
    `.ppk`. Trailing whitespace is trimmed, so add a final newline before
    writing it to a file, because OpenSSH requires one.
  - `password`, `hidden`, `totp` and `sshKey` are secrets: the app masks
    them and leaves them out of search.
- **SSH items** (`type: "ssh"`) use the fields `Username`, `Host`, `Port`,
  `Private Key` (`sshKey`), `Passphrase` (`password`) and `Public Key`
  (`multiline`).
- **Attachment `compression`**: if it is `"gzip"`, gunzip the plaintext
  after decryption. If it is absent, the plaintext is the file itself.
  Photos are re-encoded (max 2560 px, JPEG quality 82, metadata stripped)
  before encryption, so `size` is the stored size.
- **`tombstones`** record hard-deleted ids for sync merging. They hold no
  user data.

## Verify it yourself

Open [`index.html`](index.html) in a browser. It works from `file://` and
needs no server. A Content-Security-Policy (`connect-src 'none'`) blocks
every network request from the page.

A sample backup made by the app is in
[`test/fixtures/sample-backup.cpv`](test/fixtures/sample-backup.cpv). Its
password is `correct horse battery staple`.

From the command line (Node 18+, run from the repository root):

```sh
npm test                                                  # full test suite
node decrypt/test/verify-node.cjs backup.cpv 'password'   # summarise any backup
```

`verify-node.cjs` prints item titles, the decryption steps and the
SHA-256 of every decrypted file.

The app's own test suite also checks this code. It creates vaults with the
app's Dart code and checks that this implementation decrypts them byte for
byte.

## Third-party code

`vendor/hash-wasm-argon2.umd.min.js` is
[hash-wasm](https://github.com/Daninet/hash-wasm) 4.12.0 (MIT,
`vendor/hash-wasm-LICENSE.txt`), unmodified from npm. Its SHA-256 is
`dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094`. To
check it:

```sh
curl -sL https://unpkg.com/hash-wasm@4.12.0/dist/argon2.umd.min.js | shasum -a 256
```

AES-GCM, SHA and HMAC come from the browser's WebCrypto. gzip comes from
`DecompressionStream`.
