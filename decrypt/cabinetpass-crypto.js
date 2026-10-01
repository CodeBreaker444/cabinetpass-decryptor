/*!
 * CabinetPass vault decryption — reference implementation.
 *
 * Independent, dependency-light re-implementation of the format written by
 * the CabinetPass app (lib/core/storage/vault_repository.dart,
 * lib/core/crypto/crypto_service.dart). Runs in browsers and Node 18+.
 *
 *   Master password --Argon2id(m, t, p, salt, 32 bytes)--> KEK
 *   KEK  --AES-256-GCM, AAD "cabinetpass.dek.v1"-->      vault key (DEK)
 *   DEK  --AES-256-GCM, AAD "cabinetpass.vault.v1"-->    gzip(JSON vault)
 *   file key (in vault JSON) --AES-256-GCM, AAD "cabinetpass.file.v1:<id>"--> [gzip](file)
 *
 * Every AES-GCM blob is: nonce (12 bytes) || ciphertext || tag (16 bytes).
 *
 * Needs: WebCrypto (crypto.subtle), DecompressionStream, and an Argon2id
 * function — in browsers the vendored hash-wasm (window.hashwasm.argon2id).
 *
 * SPDX-License-Identifier: MIT
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.CabinetPassCrypto = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const AAD = {
    dek: 'cabinetpass.dek.v1',
    vault: 'cabinetpass.vault.v1',
    file: (id) => `cabinetpass.file.v1:${id}`,
  };
  // Browsers and Node 19+ expose WebCrypto as a global; Node 18 only via node:crypto.
  const webcrypto = globalThis.crypto && globalThis.crypto.subtle
    ? globalThis.crypto
    : typeof require === 'function' ? require('node:crypto').webcrypto : undefined;
  if (!webcrypto || !webcrypto.subtle) throw new Error('WebCrypto is not available in this environment.');
  const subtle = webcrypto.subtle;

  const NONCE_BYTES = 12;
  const TAG_BYTES = 16;

  class FormatError extends Error {}
  class DecryptError extends Error {}

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(bytes, max = 16) {
    const h = Array.from(bytes.slice(0, max), (b) => b.toString(16).padStart(2, '0')).join('');
    return bytes.length > max ? `${h}…` : h;
  }

  function parseJson(bytes, what) {
    try {
      return JSON.parse(dec.decode(bytes));
    } catch {
      throw new FormatError(`${what} is not valid JSON.`);
    }
  }

  function parseEnvelope(obj) {
    if (!obj || obj.format !== 'cabinetpass-vault') throw new FormatError('Not a CabinetPass vault file.');
    if (obj.v !== 1) throw new FormatError(`Unsupported vault version ${obj.v}.`);
    const k = obj.kdf || {};
    if (k.alg !== 'argon2id') throw new FormatError(`Unsupported key derivation "${k.alg}".`);
    return {
      version: obj.v,
      kdf: { alg: k.alg, memoryKiB: k.m, iterations: k.t, parallelism: k.p, salt: b64ToBytes(k.salt) },
      wrappedKey: b64ToBytes(obj.wrappedKey),
      payload: b64ToBytes(obj.payload),
      keyUpdated: obj.keyUpdated,
      updated: obj.updated,
    };
  }

  /**
   * Accepts a backup bundle (.cpv with files) or a bare vault.cpv.
   * Returns { kind, envelope, files: Map<id, Uint8Array> }.
   */
  function parseImport(bytes) {
    const obj = parseJson(bytes, 'The file');
    if (obj && obj.format === 'cabinetpass-backup') {
      const vaultBytes = b64ToBytes(obj.vault);
      const files = new Map(Object.entries(obj.files || {}).map(([id, b64]) => [id, b64ToBytes(b64)]));
      return { kind: 'backup', envelope: parseEnvelope(parseJson(vaultBytes, 'The embedded vault')), files };
    }
    return { kind: 'vault', envelope: parseEnvelope(obj), files: new Map() };
  }

  async function aesGcmDecrypt(blob, keyBytes, aad) {
    if (blob.length < NONCE_BYTES + TAG_BYTES) throw new DecryptError('Encrypted data is truncated.');
    const key = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    try {
      const plain = await subtle.decrypt(
        { name: 'AES-GCM', iv: blob.slice(0, NONCE_BYTES), additionalData: enc.encode(aad), tagLength: TAG_BYTES * 8 },
        key,
        blob.slice(NONCE_BYTES), // ciphertext || tag, as WebCrypto expects
      );
      return new Uint8Array(plain);
    } catch {
      throw new DecryptError('Authentication failed.');
    }
  }

  async function gunzip(bytes) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  /**
   * Opens a vault. [argon2id] is ({password, salt, memoryKiB, iterations,
   * parallelism, hashLength}) => Promise<Uint8Array>. [onStep] receives
   * progress entries for display.
   */
  async function openVault(imported, password, { argon2id, onStep = () => {} }) {
    const { envelope } = imported;
    const { kdf } = envelope;
    const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

    let t = now();
    const kek = await argon2id({
      password: enc.encode(password),
      salt: kdf.salt,
      memoryKiB: kdf.memoryKiB,
      iterations: kdf.iterations,
      parallelism: kdf.parallelism,
      hashLength: 32,
    });
    onStep({
      step: 'Derive master key',
      detail: `Argon2id m=${kdf.memoryKiB} KiB t=${kdf.iterations} p=${kdf.parallelism}, salt ${hex(kdf.salt)}`,
      ms: now() - t,
    });

    t = now();
    let dek;
    try {
      dek = await aesGcmDecrypt(envelope.wrappedKey, kek, AAD.dek);
    } catch (e) {
      if (e instanceof DecryptError) throw new DecryptError('Incorrect master password.');
      throw e;
    }
    onStep({ step: 'Unwrap vault key', detail: `AES-256-GCM, AAD "${AAD.dek}", ${dek.length * 8}-bit key`, ms: now() - t });

    t = now();
    const compressed = await aesGcmDecrypt(envelope.payload, dek, AAD.vault);
    onStep({
      step: 'Decrypt vault',
      detail: `AES-256-GCM, AAD "${AAD.vault}", ${envelope.payload.length.toLocaleString()} → ${compressed.length.toLocaleString()} bytes`,
      ms: now() - t,
    });

    t = now();
    const json = await gunzip(compressed);
    onStep({ step: 'Decompress', detail: `gzip, ${compressed.length.toLocaleString()} → ${json.length.toLocaleString()} bytes`, ms: now() - t });

    const data = parseJson(json, 'The decrypted vault');
    const entries = (data.entries || []).filter((e) => !e.deleted);
    onStep({
      step: 'Parse',
      detail: `${entries.length} items, ${(data.groups || []).length} groups, ${(data.totps || []).length} 2FA accounts`,
      ms: 0,
    });
    return { data, dek };
  }

  /** Decrypts one attachment blob using metadata from the vault JSON. */
  async function decryptAttachment(attachment, blob) {
    const plain = await aesGcmDecrypt(blob, b64ToBytes(attachment.key), AAD.file(attachment.id));
    return attachment.compression === 'gzip' ? gunzip(plain) : plain;
  }

  /** RFC 6238 TOTP via WebCrypto (for displaying codes). */
  async function totp(secretBase32, { digits = 6, period = 30, algorithm = 'sha1', at = Date.now() } = {}) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = secretBase32.replace(/[\s=-]/g, '').toUpperCase();
    const bytes = [];
    let buffer = 0;
    let bits = 0;
    for (const ch of clean) {
      const v = alphabet.indexOf(ch);
      if (v < 0) throw new FormatError('Invalid Base32 secret.');
      buffer = (buffer << 5) | v;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((buffer >> bits) & 0xff);
      }
    }
    const counter = Math.floor(at / 1000 / period);
    const msg = new Uint8Array(8);
    new DataView(msg.buffer).setUint32(4, counter >>> 0);
    new DataView(msg.buffer).setUint32(0, Math.floor(counter / 2 ** 32));
    const hash = { sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512' }[algorithm] || 'SHA-1';
    const key = await subtle.importKey('raw', new Uint8Array(bytes), { name: 'HMAC', hash }, false, ['sign']);
    const h = new Uint8Array(await subtle.sign('HMAC', key, msg));
    const o = h[h.length - 1] & 0x0f;
    const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
    return String(bin % 10 ** digits).padStart(digits, '0');
  }

  return { AAD, FormatError, DecryptError, parseImport, openVault, decryptAttachment, totp, b64ToBytes, hex };
});
