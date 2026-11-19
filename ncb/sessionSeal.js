'use strict';

/*
THE SEALED PLAYER SESSION

Why this exists, and why it is shaped the way it is.

BridgeMind stores a session handle in `localStorage.ncb_session_token` and sends it as
`Authorization: Bearer <handle>` on every call. That is the whole authentication contract of the
existing frontend, and it is the one thing this migration must not break: the app ships as a static
build with no code in it that knows about NodeSend's session design.

NoCodeBackend, however, does not accept a bearer at all. Its per-user session lives in an `HttpOnly`
`__Secure-better-auth.session_token` cookie on the vendor origin, and its `Authorization` header is
reserved for the DATABASE SECRET — a handle-translation scheme was tested live and FAILED. So the
cookie has to be held by somebody other than the browser, and the browser has to keep carrying a
bearer.

A sealed blob is the intersection of those two facts:

  * the upstream cookie never leaves this process in the clear, so nothing sensitive reaches public
    JavaScript, a log line, or a response body;
  * the handle the browser holds is useless to anyone who does not also hold the sealing key, and it
    cannot be replayed against NCB directly, because NCB has never seen it;
  * it is STATELESS. NodeSend owns no durable storage, so the alternative — a server-side session map
    keyed by a random id — loses every signed-in player on a container restart. That is the failure
    this file exists to avoid, and it is why the answer is a sealed token rather than a session table.
  * it is integrity-protected and time-bounded: an old handle expires on its own, and a tampered one
    fails the authentication tag instead of being trusted.

What this does NOT claim: the sealed handle is a bearer credential. Whoever holds it can use it, for
as long as it is valid. That is inherited from the frontend model it replaces, and the mitigations are
the short lifetime, the origin allow-list at the edge, and the fact that it opens exactly the routes
this gateway exposes — never NCB directly.
*/

const crypto = require('node:crypto');

const PREFIX = 'ncbs1';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const MIN_KEY_CHARS = 32;
// Twelve hours, bounded. A long-lived handle in localStorage is a bigger risk than the extra sign-in;
// a short one logs people out mid-session, which is the complaint this whole gateway is here to end.
const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;
const MIN_TTL_MS = 5 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;

function keyFor(secret, salt) {
  // HKDF, not a bare hash of the secret: the secret may be any human-chosen string, and each handle
  // gets its own salt so two handles minted for the same session are not byte-identical.
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(secret, 'utf8'), salt,
    Buffer.from('ncb-gateway-session-seal-v1'), KEY_LENGTH));
}

function ttlFromEnv(env) {
  const n = Number(env.NCB_SESSION_TTL_MS);
  if (!Number.isSafeInteger(n) || n <= 0) return DEFAULT_TTL_MS;
  return Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, n));
}

/**
 * @param {object} options
 * @param {object} [options.env]
 * @param {Function} [options.now] injectable so expiry is testable without sleeping
 */
function createSessionSeal({ env = process.env, now = Date.now } = {}) {
  const secret = String(env.NCB_SESSION_SEAL_KEY || '').trim();
  const ttlMs = ttlFromEnv(env);
  if (secret.length < MIN_KEY_CHARS) {
    // Fail closed and say why. A default key would silently mint handles that anyone could forge
    // after a deploy that forgot the variable, and every test would pass.
    return {
      configured: false,
      reason: 'ncb_session_seal_key_unconfigured',
      detail: `NCB_SESSION_SEAL_KEY must be set to at least ${MIN_KEY_CHARS} characters.`,
      ttlMs,
      seal: () => { throw new Error('session seal is not configured'); },
      open: () => ({ ok: false, reason: 'unconfigured' })
    };
  }

  return {
    configured: true,
    reason: null,
    ttlMs,

    /** Encrypts the upstream session material into the handle the browser will carry. */
    seal({ cookie, userId, instance, email }) {
      const salt = crypto.randomBytes(SALT_LENGTH);
      const iv = crypto.randomBytes(IV_LENGTH);
      const issuedAt = now();
      const payload = Buffer.from(JSON.stringify({
        v: 1, u: String(userId ?? ''), c: String(cookie ?? ''), i: String(instance ?? ''),
        e: String(email ?? ''), s: issuedAt, x: issuedAt + ttlMs
      }), 'utf8');
      const k = keyFor(secret, salt);
      const cipher = crypto.createCipheriv('aes-256-gcm', k, iv);
      const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
      const tag = cipher.getAuthTag();
      const b64 = (b) => b.toString('base64url');
      return `${PREFIX}.${b64(salt)}.${b64(iv)}.${b64(tag)}.${b64(ciphertext)}`;
    },

    /**
     * Returns {ok:true, session} or {ok:false, reason}. `reason` is one of a closed set, because the
     * difference between `expired` and `tampered` and `malformed` is what lets a route answer 401 for
     * an invalid session and 503 for a misconfiguration instead of calling everything "signed out".
     */
    open(handle) {
      const text = String(handle ?? '');
      if (!text.startsWith(`${PREFIX}.`)) return { ok: false, reason: 'not_a_sealed_handle' };
      const parts = text.split('.');
      if (parts.length !== 5) return { ok: false, reason: 'malformed' };
      let salt, iv, tag, ciphertext;
      try {
        salt = Buffer.from(parts[1], 'base64url');
        iv = Buffer.from(parts[2], 'base64url');
        tag = Buffer.from(parts[3], 'base64url');
        ciphertext = Buffer.from(parts[4], 'base64url');
      } catch { return { ok: false, reason: 'malformed' }; }
      if (salt.length !== SALT_LENGTH || iv.length !== IV_LENGTH || tag.length !== 16 || !ciphertext.length) {
        return { ok: false, reason: 'malformed' };
      }
      let plain;
      try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', keyFor(secret, salt), iv);
        decipher.setAuthTag(tag);
        plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch {
        // Wrong key, edited handle, or a handle minted before a key rotation. All the same answer:
        // this handle is not authentic. The distinction from a genuine expired session is preserved
        // by the timestamp below, which a forged handle cannot produce.
        return { ok: false, reason: 'tampered' };
      }
      let payload;
      try { payload = JSON.parse(plain.toString('utf8')); } catch { return { ok: false, reason: 'malformed' }; }
      if (!payload || payload.v !== 1 || typeof payload.c !== 'string' || payload.c === '') {
        return { ok: false, reason: 'malformed' };
      }
      if (!Number.isFinite(payload.x) || now() > payload.x) return { ok: false, reason: 'expired' };
      return {
        ok: true,
        session: {
          cookie: payload.c, userId: String(payload.u ?? ''), instance: String(payload.i ?? ''),
          email: String(payload.e ?? ''), issuedAt: Number(payload.s), expiresAt: Number(payload.x)
        }
      };
    },

    /**
     * For logs and /health: what a handle IS, never what it CONTAINS. Called with the handle, this
     * function's own output is safe to print — which is the property the rest of this relay already
     * holds its logs to.
     */
    describe(handle) {
      const opened = this.open(handle);
      if (!opened.ok) return { valid: false, reason: opened.reason };
      return {
        valid: true,
        userIdHash: crypto.createHash('sha256').update(opened.session.userId).digest('hex').slice(0, 8),
        remainingMs: Math.max(0, opened.session.expiresAt - now()),
        instanceMatches: opened.session.instance === String(env.NCB_INSTANCE || '55954_bridgemind')
      };
    },

    // Deliberately NO accessor for the cookie beyond `open()`. The one that lived here threw an
    // Error and was unreachable, so it was decoration with a scary name; `open().session.cookie` is
    // the single way to reach it, and the gateway transport is the only caller.
  };
}

module.exports = { createSessionSeal, PREFIX, DEFAULT_TTL_MS, MIN_KEY_CHARS };
