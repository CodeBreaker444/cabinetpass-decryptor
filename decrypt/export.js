/*!
 * CabinetPass Vault Viewer — CSV export.
 *
 * Turns a decrypted vault into a CSV file that other password managers can
 * import. Pure functions: nothing here touches the network, the page or the
 * vault itself.
 *
 * The CSV is NOT encrypted. Values are written exactly as stored (nothing is
 * escaped for spreadsheets), because an importer needs the real password.
 *
 * SPDX-License-Identifier: MIT
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.CabinetPassExport = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const FORMATS = {
    // The layout Apple Passwords exports; most password managers read it.
    standard: {
      name: 'Standard',
      file: 'cabinetpass-passwords',
      header: ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'],
    },
    // Bitwarden's own CSV: keeps folders, favourites and custom fields.
    bitwarden: {
      name: 'Bitwarden',
      file: 'cabinetpass-bitwarden',
      header: ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'],
    },
  };

  /** One CSV record (RFC 4180): cells are quoted only when they need it. */
  function csvLine(cells) {
    return cells.map((c) => {
      const s = c == null ? '' : String(c);
      return /[",\r\n]|^\s|\s$/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    }).join(',');
  }

  /** An otpauth:// URI for a 2FA secret. A value that already is one is kept as it is. */
  function otpauthUri(value, { issuer = '', account = '', digits, period, algorithm } = {}) {
    const v = String(value || '').trim();
    if (!v) return '';
    if (/^otpauth:\/\//i.test(v)) return v;
    const enc = encodeURIComponent;
    const label = [issuer, account].filter(Boolean).map(enc).join(':');
    let uri = `otpauth://totp/${label}?secret=${enc(v.replace(/\s+/g, ''))}`;
    if (issuer) uri += `&issuer=${enc(issuer)}`;
    if (digits && Number(digits) !== 6) uri += `&digits=${Number(digits)}`;
    if (period && Number(period) !== 30) uri += `&period=${Number(period)}`;
    const alg = String(algorithm || '').toUpperCase().replace('-', '');
    if (alg && alg !== 'SHA1') uri += `&algorithm=${alg}`;
    return uri;
  }

  /**
   * Every item as one flat record. The first website, user name (or email),
   * password and 2FA field fill the columns every importer knows; all other
   * fields are kept as labelled extras. Recently Deleted is left out.
   */
  function records(data) {
    const groups = new Map((data.groups || []).map((g) => [g.id, g.name]));
    const items = (data.entries || []).filter((e) => !e.deleted).map((e) => {
      const fields = (e.fields || []).filter((f) => f.value);
      const used = new Set();
      const take = (kind) => {
        const f = fields.find((x) => x.kind === kind && !used.has(x));
        if (!f) return '';
        used.add(f);
        return f.value;
      };
      const url = take('url');
      const username = take('username') || take('email');
      // An SSH item's password field is the key's passphrase: it stays beside the key.
      const password = e.type === 'ssh' ? '' : take('password');
      const totp = otpauthUri(take('totp'), { issuer: e.title, account: username });
      return {
        title: e.title || '',
        folder: groups.get(e.group) || '',
        favorite: !!e.fav,
        url, username, password, totp,
        extra: fields.filter((f) => !used.has(f)).map((f) => [f.label || f.kind, f.value]),
        notes: e.notes || '',
      };
    }).sort((a, b) => a.title.localeCompare(b.title));

    const totps = (data.totps || []).filter((t) => t.secret).map((t) => ({
      title: t.issuer || t.account || '2FA account',
      folder: '', favorite: false, url: '', username: t.account || '', password: '',
      totp: otpauthUri(t.secret, { issuer: t.issuer, account: t.account, digits: t.digits, period: t.period, algorithm: t.alg }),
      extra: [], notes: '',
    }));
    return [...items, ...totps];
  }

  const isMultiline = (v) => /[\r\n]/.test(v);
  const labelled = ([label, value]) => (isMultiline(value) ? `${label}:\n${value}` : `${label}: ${value}`);
  const joinNotes = (parts) => parts.filter(Boolean).join('\n\n');

  function standardRow(r) {
    return [r.title, r.url, r.username, r.password, joinNotes([r.extra.map(labelled).join('\n'), r.notes]), r.totp];
  }

  function bitwardenRow(r) {
    // Bitwarden reads `fields` as one "name: value" per line, so values that
    // span lines go to the notes instead.
    const oneLine = r.extra.filter(([, v]) => !isMultiline(v));
    const multi = r.extra.filter(([, v]) => isMultiline(v));
    const login = r.url || r.username || r.password || r.totp;
    return [
      r.folder, r.favorite ? '1' : '', login ? 'login' : 'note', r.title,
      joinNotes([r.notes, ...multi.map(labelled)]),
      oneLine.map(([label, v]) => `${label.replace(/:\s+/g, ' - ').replace(/[\r\n]+/g, ' ')}: ${v}`).join('\n'),
      '0', r.url, r.username, r.password, r.totp,
    ];
  }

  /** What an export holds and what a CSV can't carry, for the confirmation text. */
  function summary(data) {
    const active = (data.entries || []).filter((e) => !e.deleted);
    return {
      items: active.length,
      totps: (data.totps || []).filter((t) => t.secret).length,
      files: active.reduce((n, e) => n + (e.attachments || []).length, 0),
      passkeys: active.reduce((n, e) => n + (e.passkeys || []).length, 0),
    };
  }

  /** The whole vault as CSV text in the given format ('standard' or 'bitwarden'). */
  function toCsv(data, format = 'standard') {
    const f = FORMATS[format];
    if (!f) throw new Error(`Unknown export format: ${format}`);
    const row = format === 'bitwarden' ? bitwardenRow : standardRow;
    return [f.header, ...records(data).map(row)].map(csvLine).join('\r\n') + '\r\n';
  }

  const fileName = (format, date = new Date()) => `${FORMATS[format].file}-${date.toISOString().slice(0, 10)}.csv`;

  return { FORMATS, csvLine, otpauthUri, records, summary, toCsv, fileName };
});
