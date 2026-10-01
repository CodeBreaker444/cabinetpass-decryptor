/*!
 * CabinetPass Vault Viewer — UI. All decryption is in cabinetpass-crypto.js.
 * Vault contents are rendered with textContent only (never innerHTML).
 * SPDX-License-Identifier: MIT
 */
(function () {
  'use strict';
  const CP = window.CabinetPassCrypto;
  const $ = (id) => document.getElementById(id);

  const state = {
    imported: null, // { kind, envelope, files }
    fileName: '',
    data: null,
    filter: { kind: 'all', id: null },
    query: '',
    selected: null,
    urls: new Set(), // blob: URLs to revoke on lock
    timers: new Set(),
    log: [],
  };

  // ---------- DOM helpers ----------
  function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  const ICONS = {
    eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z|c12,12,3',
    eyeOff: 'M3 3l18 18|M10.6 5.1A10.7 10.7 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.2|M6.6 6.6A17.4 17.4 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6|M9.9 9.9a3 3 0 0 0 4.2 4.2',
    copy: 'r9,9,13,13,2|M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
    file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z|M14 2v6h6',
    check: 'm5 12 5 5L20 7',
  };
  function icon(name, size = 17) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', size);
    svg.setAttribute('height', size);
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    for (const part of ICONS[name].split('|')) {
      let el;
      if (part.startsWith('c')) {
        const [cx, cy, r] = part.slice(1).split(',');
        el = document.createElementNS(ns, 'circle');
        el.setAttribute('cx', cx); el.setAttribute('cy', cy); el.setAttribute('r', r);
      } else if (part.startsWith('r')) {
        const [x, y, w, hh, rx] = part.slice(1).split(',');
        el = document.createElementNS(ns, 'rect');
        el.setAttribute('x', x); el.setAttribute('y', y); el.setAttribute('width', w); el.setAttribute('height', hh); el.setAttribute('rx', rx);
      } else {
        el = document.createElementNS(ns, 'path');
        el.setAttribute('d', part);
      }
      svg.append(el);
    }
    return svg;
  }

  function toast(msg) {
    const t = h('div', { class: 'toast', text: msg });
    document.body.append(t);
    setTimeout(() => t.remove(), 1400);
  }

  async function copy(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${label} copied`);
    } catch {
      toast('Copy not allowed here');
    }
  }

  const PALETTE = ['#0b5cf0', '#5856d6', '#af52de', '#ff2d55', '#ff3b30', '#ff9500', '#34c759', '#30b0c7', '#32ade6', '#a2845e'];
  const GROUP_COLORS = { blue: '#007aff', cyan: '#32ade6', teal: '#30b0c7', mint: '#00c7be', green: '#34c759', yellow: '#ffcc00', orange: '#ff9500', red: '#ff3b30', pink: '#ff2d55', purple: '#af52de', indigo: '#5856d6', brown: '#a2845e', gray: '#8e8e93' };
  function colorFor(title) {
    let hash = 7;
    for (const ch of title) hash = (hash * 31 + ch.codePointAt(0)) & 0x7fffffff;
    return PALETTE[hash % PALETTE.length];
  }
  function avatar(title) {
    return h('div', { class: 'avatar', style: `background:${colorFor(title || '?')}`, text: (title || '?').trim().charAt(0).toUpperCase() });
  }
  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${Math.round(n / 1024)} KB`;
    if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
    return `${(n / 1073741824).toFixed(2)} GB`;
  }
  // Field kinds whose values are masked and never searched.
  const SECRET_KINDS = ['password', 'hidden', 'totp', 'sshKey'];

  const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : '—');

  // ---------- Argon2id adapter (hash-wasm) ----------
  const argon2id = ({ password, salt, memoryKiB, iterations, parallelism, hashLength }) =>
    window.hashwasm.argon2id({ password, salt, memorySize: memoryKiB, iterations, parallelism, hashLength, outputType: 'binary' });

  // ---------- Unlock ----------
  const drop = $('drop');
  const fileInput = $('file');
  const pw = $('pw');
  const go = $('go');

  function updateGo() {
    go.disabled = !(state.imported && pw.value);
  }

  async function loadFile(file) {
    $('err').textContent = '';
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      state.imported = CP.parseImport(bytes);
      state.fileName = file.name;
      const env = state.imported.envelope;
      $('fileName').textContent = file.name;
      $('fileInfo').textContent =
        `${state.imported.kind === 'backup' ? 'Backup' : 'Vault'} · ${fmtBytes(bytes.length)} · ` +
        `${state.imported.files.size} encrypted file${state.imported.files.size === 1 ? '' : 's'} · ` +
        `Argon2id m=${env.kdf.memoryKiB} KiB t=${env.kdf.iterations} p=${env.kdf.parallelism} · updated ${fmtDate(env.updated)}`;
      pw.focus();
    } catch (e) {
      state.imported = null;
      $('fileName').textContent = 'Drop a .cpv file here, or click to choose';
      $('fileInfo').textContent = '';
      $('err').textContent = e.message || String(e);
    }
    updateGo();
  }

  drop.addEventListener('click', () => fileInput.click());
  drop.addEventListener('keydown', (e) => (e.key === 'Enter' || e.key === ' ') && fileInput.click());
  fileInput.addEventListener('change', () => fileInput.files[0] && loadFile(fileInput.files[0]));
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, () => drop.classList.remove('over')));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) loadFile(f);
  });
  // Don't let a stray drop navigate away from the page.
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());

  pw.addEventListener('input', updateGo);
  pw.addEventListener('keydown', (e) => e.key === 'Enter' && !go.disabled && decrypt());
  $('reveal').addEventListener('click', () => {
    const show = pw.type === 'password';
    pw.type = show ? 'text' : 'password';
    $('reveal').replaceChildren(icon(show ? 'eyeOff' : 'eye'));
  });
  go.addEventListener('click', decrypt);

  function renderSteps(target, steps, running) {
    target.replaceChildren(
      ...steps.map((s, i) =>
        h('li', {},
          h('span', {}, i < steps.length - (running ? 1 : 0) ? icon('check') : h('span', { text: '…' })),
          h('div', {}, h('div', { class: 't', text: `${i + 1}. ${s.step}` }), h('div', { class: 'd', text: s.detail })),
          h('span', { class: 'ms', text: s.ms ? `${s.ms.toFixed(0)} ms` : '' }),
        )),
    );
  }
  async function decrypt() {
    if (!state.imported || !pw.value) return;
    go.disabled = true;
    $('err').textContent = '';
    $('busy').textContent = 'Deriving key with Argon2id…';
    state.log = [];
    try {
      const { data } = await CP.openVault(state.imported, pw.value, {
        argon2id,
        onStep: (s) => {
          state.log.push(s);
          renderSteps($('steps'), state.log, false);
          $('busy').textContent = s.step === 'Derive master key' ? 'Decrypting…' : '';
        },
      });
      pw.value = '';
      state.data = data;
      showVault();
    } catch (e) {
      $('err').textContent = e instanceof CP.DecryptError || e instanceof CP.FormatError ? e.message : `Error: ${e.message || e}`;
      $('busy').textContent = '';
      updateGo();
    }
  }

  // ---------- Vault viewer ----------
  function activeEntries() {
    return (state.data.entries || []).filter((e) => !e.deleted);
  }
  function groupById(id) {
    return (state.data.groups || []).find((g) => g.id === id);
  }
  const fieldValue = (e, kinds) => (e.fields.find((f) => kinds.includes(f.kind) && f.value) || {}).value || '';
  const subtitle = (e) => fieldValue(e, ['username', 'email']) || fieldValue(e, ['url']) || e.type;

  function showVault() {
    $('unlock').classList.add('hidden');
    $('vault').classList.remove('hidden');
    const items = activeEntries();
    const files = items.reduce((n, e) => n + (e.attachments || []).length, 0);
    $('vaultTitle').textContent = state.fileName;
    $('vaultMeta').textContent = `${items.length} items · ${files} files · ${(state.data.totps || []).length} 2FA accounts · last updated ${fmtDate(state.imported.envelope.updated)}`;
    renderSide();
    renderList();
  }

  function renderSide() {
    const items = activeEntries();
    const btn = (kind, id, label, count, color) =>
      h('button', {
        class: state.filter.kind === kind && state.filter.id === id ? 'sel' : '',
        onclick: () => { state.filter = { kind, id }; state.selected = null; renderSide(); renderList(); renderDetail(); },
      },
      color ? h('span', { class: 'dot', style: `background:${color}` }) : null,
      h('span', { text: label }),
      h('span', { class: 'n', text: String(count) }));

    const search = h('div', { class: 'field search' },
      h('input', { placeholder: 'Search', value: state.query, oninput: (e) => { state.query = e.target.value; renderList(); } }));

    const groups = [...(state.data.groups || [])].sort((a, b) => (a.sort || 0) - (b.sort || 0));
    $('side').replaceChildren(
      search,
      h('h4', { text: 'Library' }),
      btn('all', null, 'All Items', items.length),
      btn('fav', null, 'Favorites', items.filter((e) => e.fav).length),
      btn('files', null, 'Files', items.filter((e) => (e.attachments || []).length).length),
      btn('totp', null, '2FA Accounts', (state.data.totps || []).length),
      h('h4', { text: 'Groups' }),
      ...groups.map((g) => btn('group', g.id, g.name, items.filter((e) => e.group === g.id).length, GROUP_COLORS[g.color] || '#8e8e93')),
    );
  }

  function renderList() {
    const q = state.query.trim().toLowerCase();
    const list = $('list');
    if (state.filter.kind === 'totp') {
      const totps = (state.data.totps || []).filter((t) => !q || `${t.issuer} ${t.account}`.toLowerCase().includes(q));
      list.replaceChildren(...totps.map((t) =>
        h('button', { class: `item${state.selected === t.id ? ' sel' : ''}`, onclick: () => { state.selected = t.id; renderList(); renderDetail(); } },
          avatar(t.issuer), h('div', { style: 'min-width:0' }, h('div', { class: 't', text: t.issuer }), h('div', { class: 's', text: t.account })))));
      if (!totps.length) list.replaceChildren(h('div', { class: 'empty', text: 'No 2FA accounts' }));
      return;
    }
    let items = activeEntries();
    if (state.filter.kind === 'fav') items = items.filter((e) => e.fav);
    if (state.filter.kind === 'files') items = items.filter((e) => (e.attachments || []).length);
    if (state.filter.kind === 'group') items = items.filter((e) => e.group === state.filter.id);
    if (q) {
      items = items.filter((e) =>
        e.title.toLowerCase().includes(q) || (e.notes || '').toLowerCase().includes(q) ||
        e.fields.some((f) => !SECRET_KINDS.includes(f.kind) && f.value.toLowerCase().includes(q)));
    }
    items.sort((a, b) => a.title.localeCompare(b.title));
    if (!items.length) {
      list.replaceChildren(h('div', { class: 'empty', text: q ? 'No results' : 'No items' }));
      return;
    }
    list.replaceChildren(...items.map((e) =>
      h('button', { class: `item${state.selected === e.id ? ' sel' : ''}`, onclick: () => { state.selected = e.id; renderList(); renderDetail(); } },
        avatar(e.title),
        h('div', { style: 'min-width:0' },
          h('div', { class: 't' }, e.title, e.fav ? ' ★' : '', (e.attachments || []).length ? ' 📎' : ''),
          h('div', { class: 's', text: subtitle(e) })))));
  }

  function clearTimers() {
    state.timers.forEach(clearInterval);
    state.timers.clear();
  }

  function secretRow(label, value, { mono = false, small = false, kind = '' } = {}) {
    let shown = false;
    const v = h('div', { class: `v${mono ? ' mono' : ''}${small ? ' small' : ''}`, text: '••••••••••' });
    const eye = h('button', { class: 'icon-btn', title: 'Reveal', 'aria-label': `Reveal ${label}` }, icon('eye'));
    eye.addEventListener('click', () => {
      shown = !shown;
      v.textContent = shown ? value : '••••••••••';
      eye.replaceChildren(icon(shown ? 'eyeOff' : 'eye'));
    });
    return h('div', { class: 'f' },
      h('div', { class: 'grow' }, h('div', { class: 'k', text: label }), v),
      kind !== 'totp' ? eye : null,
      h('button', { class: 'icon-btn', title: 'Copy', 'aria-label': `Copy ${label}`, onclick: () => copy(value, label) }, icon('copy')));
  }

  function totpRow(label, secret, opts = {}) {
    const code = h('div', { class: 'code', text: '––– –––' });
    const left = h('span', { class: 'muted' });
    let current = '';
    const tick = async () => {
      try {
        current = await CP.totp(secret, opts);
        code.textContent = current.length === 6 ? `${current.slice(0, 3)} ${current.slice(3)}` : current;
        const period = opts.period || 30;
        left.textContent = `${period - (Math.floor(Date.now() / 1000) % period)}s`;
      } catch {
        code.textContent = 'invalid secret';
      }
    };
    tick();
    state.timers.add(setInterval(tick, 1000));
    return h('div', { class: 'f' },
      h('div', { class: 'grow' }, h('div', { class: 'k', text: label }), code), left,
      h('button', { class: 'icon-btn', title: 'Copy code', onclick: () => copy(current, 'Code') }, icon('copy')));
  }

  function parseOtpField(value) {
    if (!value.startsWith('otpauth://')) return { secret: value };
    const u = new URL(value);
    return {
      secret: u.searchParams.get('secret') || '',
      digits: Number(u.searchParams.get('digits')) || 6,
      period: Number(u.searchParams.get('period')) || 30,
      algorithm: (u.searchParams.get('algorithm') || 'SHA1').toLowerCase().replace('-', ''),
    };
  }

  function renderDetail() {
    clearTimers();
    const pane = $('detail');
    if (!state.selected) {
      pane.replaceChildren(h('div', { class: 'empty', text: 'Select an item' }));
      return;
    }
    if (state.filter.kind === 'totp') {
      const t = (state.data.totps || []).find((x) => x.id === state.selected);
      if (!t) return;
      pane.replaceChildren(h('div', { class: 'detail' },
        h('div', { class: 'head' }, avatar(t.issuer), h('div', {}, h('h2', { text: t.issuer }), h('div', { class: 'muted', text: t.account }))),
        h('div', { class: 'group' },
          totpRow('Current code', t.secret, { digits: t.digits, period: t.period, algorithm: t.alg }),
          secretRow('Setup key', t.secret, { mono: true }),
          h('div', { class: 'f' }, h('div', { class: 'grow' }, h('div', { class: 'k', text: 'Parameters' }),
            h('div', { class: 'v', text: `${(t.alg || 'sha1').toUpperCase()} · ${t.digits || 6} digits · ${t.period || 30}s` }))))));
      return;
    }
    const e = activeEntries().find((x) => x.id === state.selected);
    if (!e) return;
    const g = groupById(e.group);
    const rows = e.fields.filter((f) => f.value).map((f) => {
      if (f.kind === 'totp') {
        const o = parseOtpField(f.value);
        return totpRow(f.label, o.secret, o);
      }
      if (f.kind === 'sshKey') {
        // OpenSSH rejects private keys without a trailing newline.
        return secretRow(f.label, `${f.value.trimEnd()}\n`, { mono: true, small: true });
      }
      if (SECRET_KINDS.includes(f.kind)) return secretRow(f.label, f.value, { mono: f.kind === 'password' });
      return h('div', { class: 'f' },
        h('div', { class: 'grow' }, h('div', { class: 'k', text: f.label }), h('div', { class: 'v', text: f.value })),
        h('button', { class: 'icon-btn', title: 'Copy', onclick: () => copy(f.value, f.label) }, icon('copy')));
    });

    const sections = [
      h('div', { class: 'head' }, avatar(e.title),
        h('div', {}, h('h2', { text: e.title }), h('div', { class: 'muted', text: `${g ? g.name : 'No group'} · ${e.type}` }))),
    ];
    if (rows.length) sections.push(h('div', { class: 'group' }, ...rows));
    if (e.notes) sections.push(h('div', { class: 'h', text: 'Notes' }), h('div', { class: 'group' }, h('div', { class: 'f' }, h('div', { class: 'v', text: e.notes }))));
    if ((e.attachments || []).length) {
      sections.push(h('div', { class: 'h', text: 'Files' }), h('div', { class: 'group' }, h('div', { class: 'atts' }, ...e.attachments.map(attachmentTile))));
    }
    if ((e.pwHistory || []).length) {
      sections.push(h('div', { class: 'h', text: 'Password history' }),
        h('div', { class: 'group' }, ...[...e.pwHistory].reverse().map((p) => secretRow(`Changed ${fmtDate(p.at)}`, p.v, { mono: true }))));
    }
    sections.push(h('div', { class: 'muted', style: 'text-align:center;margin-top:6px', text: `Created ${fmtDate(e.created)} · Modified ${fmtDate(e.updated)}` }));
    pane.replaceChildren(h('div', { class: 'detail' }, ...sections));
  }

  // ---------- Attachments ----------
  const decrypted = new Map(); // id -> { url, bytes, error }

  async function getAttachment(a) {
    if (decrypted.has(a.id)) return decrypted.get(a.id);
    const blob = state.imported.files.get(a.id);
    let result;
    if (!blob) {
      result = { error: 'Not in this file. Export a backup from the app (Settings › Export Encrypted Backup) to include files.' };
    } else {
      try {
        const bytes = await CP.decryptAttachment(a, blob);
        const url = URL.createObjectURL(new Blob([bytes], { type: a.mime }));
        state.urls.add(url);
        result = { url, bytes };
      } catch (e) {
        result = { error: e.message || String(e) };
      }
    }
    decrypted.set(a.id, result);
    return result;
  }

  function attachmentTile(a) {
    const thumb = h('div', { class: 'thumb' }, icon('file', 30));
    const tile = h('button', { class: 'att', title: a.name, onclick: () => openPreview(a) },
      thumb, h('div', { class: 'nm', text: a.name }), h('div', { class: 'muted', text: fmtBytes(a.size) }));
    if (a.mime && a.mime.startsWith('image/')) {
      getAttachment(a).then((r) => r.url && thumb.replaceChildren(h('img', { src: r.url, alt: '' })));
    }
    return tile;
  }

  async function openPreview(a) {
    const r = await getAttachment(a);
    const body = $('pvBody');
    $('pvName').textContent = `${a.name} · ${fmtBytes(a.size)}`;
    $('pvDownload').disabled = !r.url;
    $('pvDownload').onclick = () => {
      if (!r.url) return;
      const link = h('a', { href: r.url, download: a.name });
      document.body.append(link);
      link.click();
      link.remove();
    };
    if (r.error) body.replaceChildren(h('div', { class: 'empty', text: r.error }));
    else if (a.mime.startsWith('image/')) body.replaceChildren(h('img', { src: r.url, alt: a.name }));
    else if (a.mime === 'application/pdf') body.replaceChildren(h('iframe', { src: r.url, title: a.name }));
    else body.replaceChildren(h('div', { class: 'empty', text: 'Preview not available. Use Download to save the decrypted file.' }));
    $('preview').showModal();
  }
  $('pvClose').addEventListener('click', () => $('preview').close());
  // 'close' is dispatched async; skip if another preview already reopened it.
  $('preview').addEventListener('close', () => !$('preview').open && $('pvBody').replaceChildren());

  // ---------- Log + lock ----------
  $('showLog').addEventListener('click', () => {
    renderSteps($('logSteps'), state.log, false);
    $('log').showModal();
  });
  $('logClose').addEventListener('click', () => $('log').close());

  function lock() {
    clearTimers();
    state.urls.forEach((u) => URL.revokeObjectURL(u));
    // Reload discards every decrypted value held by this page.
    location.reload();
  }
  $('lock').addEventListener('click', lock);
})();
