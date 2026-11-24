/*!
 * CabinetPass Vault Viewer — read-only Google Drive access.
 *
 * Signs in with Google's standard OAuth redirect (no Google scripts are
 * loaded into this page) for the `drive.appdata` scope, then downloads the
 * encrypted files the CabinetPass app keeps in its hidden app folder:
 *
 *   vault.cpv        the encrypted vault (same format as a backup's vault)
 *   att_<id>         one encrypted attachment each
 *
 * Read-only by construction: this module only ever sends GET requests.
 * Nothing is uploaded, renamed or deleted, and the access token lives in
 * memory only. It is never revoked: revoking ends the grant for every client
 * of the CabinetPass project and signs out the apps too.
 *
 * SPDX-License-Identifier: MIT
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.CabinetPassDrive = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // The CabinetPass Google Cloud project's web OAuth client. The hidden app
  // folder is shared by every client of one project, so this page sees the
  // same files as the app.
  const CLIENT_ID = '669255503923-armcah0ton2503jk9b5o5vdsrs7vl4cr.apps.googleusercontent.com';
  const SCOPE = 'https://www.googleapis.com/auth/drive.appdata';
  const API = 'https://www.googleapis.com/drive/v3/files';
  const ABOUT = 'https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)';
  const VAULT_NAME = 'vault.cpv';
  const ATT_PREFIX = 'att_';
  const STATE_KEY = 'cabinetpass.oauth.state';

  class DriveError extends Error {
    /** status: HTTP status; code: Google's OAuth error (e.g. interaction_required). */
    constructor(message, status, code) {
      super(message);
      this.status = status;
      this.code = code;
    }
  }

  /** The address Google sends the user back to: this page, without query or hash. */
  function redirectUri(loc) {
    // …/decrypt/ and …/decrypt/index.html are the same page; Google only
    // accepts the exact URI registered, so always use the folder form.
    return `${loc.origin}${loc.pathname.replace(/index\.html$/, '')}`;
  }

  function randomState(cryptoObj) {
    const b = new Uint8Array(16);
    cryptoObj.getRandomValues(b);
    return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Google's OAuth 2.0 authorization URL (token response, appdata scope only).
   * loginHint (an email) picks that account, so a silent sign-in works when
   * the browser is signed in to several Google accounts.
   */
  function authUrl({ redirect, state, clientId = CLIENT_ID, loginHint }) {
    const p = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirect,
      response_type: 'token',
      scope: SCOPE,
      state,
      include_granted_scopes: 'false',
      prompt: 'select_account',
    });
    if (loginHint) p.set('login_hint', loginHint);
    return `https://accounts.google.com/o/oauth2/v2/auth?${p}`;
  }

  /**
   * Reads Google's redirect (`#access_token=…&state=…` or `#error=…`).
   * Returns null when the hash isn't an OAuth response. Throws DriveError on
   * an error response or a state mismatch (possible CSRF).
   */
  function parseRedirect(hash, expectedState) {
    if (!hash || hash.length < 2) return null;
    const p = new URLSearchParams(hash.replace(/^#/, ''));
    if (!p.has('access_token') && !p.has('error')) return null;
    if (!expectedState || p.get('state') !== expectedState) {
      throw new DriveError('Sign-in could not be verified. Please try again.');
    }
    if (p.has('error')) {
      const e = p.get('error');
      throw new DriveError(e === 'access_denied' ? 'Google sign-in was cancelled.' : `Google sign-in failed (${e}).`, undefined, e);
    }
    const expiresIn = Number(p.get('expires_in')) || 3600;
    return { token: p.get('access_token'), expiresAt: Date.now() + expiresIn * 1000 };
  }

  /** Starts sign-in: remembers a one-time state, then sends the user to Google. */
  function signIn(win = globalThis) {
    const state = randomState(win.crypto);
    win.sessionStorage.setItem(STATE_KEY, state);
    win.location.assign(authUrl({ redirect: redirectUri(win.location), state }));
  }

  /** Completes sign-in on return; strips the token from the address bar. */
  function completeSignIn(win = globalThis) {
    const expected = win.sessionStorage.getItem(STATE_KEY);
    const hash = win.location.hash;
    let result;
    try {
      result = parseRedirect(hash, expected);
    } finally {
      if (hash && /access_token=|error=/.test(hash)) {
        win.sessionStorage.removeItem(STATE_KEY);
        win.history.replaceState(null, '', redirectUri(win.location));
      }
    }
    return result;
  }

  async function get(fetchFn, url, token, as = 'json') {
    const res = await fetchFn(url, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (res.status === 401) throw new DriveError('Your Google session expired. Sign in again.', 401);
    if (!res.ok) throw new DriveError(`Google Drive returned ${res.status}.`, res.status);
    return as === 'bytes' ? new Uint8Array(await res.arrayBuffer()) : res.json();
  }

  async function list(fetchFn, token, query) {
    const out = [];
    let pageToken = '';
    do {
      const p = new URLSearchParams({
        spaces: 'appDataFolder',
        q: query,
        fields: 'nextPageToken,files(id,name,size,modifiedTime)',
        pageSize: '1000',
      });
      if (pageToken) p.set('pageToken', pageToken);
      const r = await get(fetchFn, `${API}?${p}`, token);
      out.push(...(r.files || []));
      pageToken = r.nextPageToken || '';
    } while (pageToken);
    return out;
  }

  /**
   * Downloads the encrypted vault and lists encrypted attachments.
   * Returns { bytes, modifiedTime, attachments: Map<attachmentId, driveFileId> }.
   */
  async function fetchVault(token, fetchFn = globalThis.fetch.bind(globalThis)) {
    const vaults = await list(fetchFn, token, `name = '${VAULT_NAME}' and trashed = false`);
    if (!vaults.length) {
      throw new DriveError('No CabinetPass vault in this Google account. Turn on sync in the app first (Settings › Google Drive).');
    }
    const v = vaults[0];
    const [bytes, atts] = await Promise.all([
      get(fetchFn, `${API}/${encodeURIComponent(v.id)}?alt=media`, token, 'bytes'),
      list(fetchFn, token, `name contains '${ATT_PREFIX}' and trashed = false`),
    ]);
    const attachments = new Map();
    for (const f of atts) {
      if (f.name && f.name.startsWith(ATT_PREFIX)) attachments.set(f.name.slice(ATT_PREFIX.length), f.id);
    }
    return { bytes, modifiedTime: v.modifiedTime, attachments };
  }

  /** Downloads one encrypted attachment by its Drive file id. */
  function fetchAttachment(token, driveId, fetchFn = globalThis.fetch.bind(globalThis)) {
    return get(fetchFn, `${API}/${encodeURIComponent(driveId)}?alt=media`, token, 'bytes');
  }

  /** The signed-in Google account's email (Drive's about works with the appdata scope). */
  async function accountEmail(token, fetchFn = globalThis.fetch.bind(globalThis)) {
    const r = await get(fetchFn, ABOUT, token);
    return (r && r.user && r.user.emailAddress) || null;
  }

  return { CLIENT_ID, SCOPE, VAULT_NAME, ATT_PREFIX, DriveError, redirectUri, authUrl, parseRedirect, signIn, completeSignIn, fetchVault, fetchAttachment, accountEmail };
});
