'use strict';

/*
THE CLUB SERVICE ACCOUNT, OVER THE NATIVE NCB TRANSPORT.

`clubs/ncbAccountClient.js` speaks the protocol the AWS proxy used: sign in, take the token from the
response BODY, and send it back as `Authorization: Bearer`. That proxy is dead, and the vendor does
not accept that shape — measured, not assumed:

  * `Authorization` on the native data family is the DATABASE SECRET slot (`403 Invalid secret_key.`),
    so a body token presented there is not "a session the vendor declines", it is a wrong credential
    in a privileged slot;
  * the body token is not a session channel at all (the live translation test failed);
  * the native per-user session is the vendor's own `HttpOnly` cookie, captured from the sign-in
    response and replayed.

So this module changes the TRANSPORT and nothing else. Every guard in the original is kept, because
every guard was written against a failure that has already happened somewhere:

  * the identity comes from `get-session`, never from the sign-in body — a password being accepted
    proves that SOME account is signed in, which is not the same fact as "this is the club account";
  * one sign-in at a time, one renewal after a 401, then a cooldown — no login stampede;
  * the cookie never leaves this process, is never returned to a caller, never logged, and the club
    routes never learn it;
  * an upstream error body is filtered to a field whitelist and redacted, because NCB echoes what it
    was sent;
  * `public-data` is REFUSED rather than dialled, because the native host has no such family (four
    candidate paths all answer an HTML 404) — a silent request to a nonexistent route would surface
    as a storage fault and be debugged as one.

`proxy` remains the default transport: a deployment that has not proven the native path keeps
behaving exactly as it does today, and the existing 243-check gate stays a measurement of the shipped
code rather than of a fixture. Native mode additionally requires BOTH bases to be configured
explicitly — it will not fall back to the vendor's published URLs by accident, because a test that
silently dials production is worse than a test that fails.
*/

const REQUEST_TIMEOUT_MS = 12000;
const RENEWAL_COOLDOWN_MS = 15000;
const SAFE_ERROR_FIELDS = Object.freeze(['error', 'message', 'status', 'code']);
const MAX_ERROR_CHARS = 240;
const COOKIE_PAIR = (line) => String(line ?? '').split(';')[0];

function redact(text, secrets = []) {
  let out = String(text ?? '');
  for (const secret of secrets) {
    const value = String(secret ?? '');
    if (value.length < 3) continue;
    out = out.split(value).join('[redacted]');
  }
  return out.slice(0, MAX_ERROR_CHARS);
}

function describeFailure(body, secrets) {
  if (!body || typeof body !== 'object') return redact(body ?? 'unrecognised response', secrets);
  const picked = SAFE_ERROR_FIELDS
    .filter((key) => body[key] !== undefined && body[key] !== null)
    .map((key) => `${key}=${redact(body[key], secrets)}`);
  return picked.length ? picked.join(' ') : redact('rejected without a described reason', secrets);
}

/**
 * Which transport a deployment gets, and why. Split out because the answer is a safety property an
 * operator can read in one place: native requires intent (explicit bases), and silence keeps today's
 * behaviour.
 *
 * The bases must be https, with one narrow exception that exists only so a gate can dial a local
 * fake: `NCB_ALLOW_INSECURE_UPSTREAM=1` admits loopback http and nothing else. Same shape as the
 * exception in ncb/nativeClient.js, for the same reason — a plain `http://` test URL that also
 * satisfied the production check would mean the credential rules were tested against a transport
 * production can never select.
 */
const LOOPBACK_HTTP = /^http:\/\/(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?\/.+$/;
function usableBase(url, allowInsecureLoopback) {
  return /^https:\/\/.+/.test(url) || (allowInsecureLoopback && LOOPBACK_HTTP.test(url));
}

function readTransport(env = {}) {
  const wanted = String(env.NCB_TRANSPORT || 'proxy').trim().toLowerCase();
  const authBase = String(env.NCB_AUTH_API_URL || '').trim().replace(/\/$/, '');
  const dataBase = String(env.NCB_DATA_API_URL || '').trim().replace(/\/$/, '');
  if (wanted !== 'native') {
    return { transport: 'proxy', authBase: null, dataBase: null, reason: null };
  }
  const allowLoopback = env.NCB_ALLOW_INSECURE_UPSTREAM === '1';
  // Re-append the slash the loopback pattern expects, so a base written without a trailing path
  // still reads as the same URL in both checks.
  const ok = (base) => usableBase(`${base}/`, allowLoopback);
  if (!ok(authBase) || !ok(dataBase)) {
    return {
      transport: 'native', authBase, dataBase,
      reason: 'ncb_native_bases_incomplete',
      detail: 'NCB_TRANSPORT=native requires explicit https:// NCB_AUTH_API_URL and NCB_DATA_API_URL (loopback http only with NCB_ALLOW_INSECURE_UPSTREAM=1).'
    };
  }
  return { transport: 'native', authBase, dataBase, reason: null };
}

/**
 * @param {object} options
 * @param {object} options.account  { email, password, instance, expectedUserId }
 * @param {object} options.transport result of readTransport()
 * @param {Function} [options.fetchImpl]
 * @param {Function} [options.now]
 */
function createNativeAccountClient({ account, transport, fetchImpl = null, now = Date.now } = {}) {
  const secrets = [account.email, account.password];
  // One rule for both transports to this vendor: a bare https origin, or nothing at all.
  const configuredOrigin = String(account.trustedOrigin ?? 'https://app.bridgemind.app').trim();
  const trustedOrigin = /^https:\/\/[A-Za-z0-9.:_-]+$/.test(configuredOrigin) ? configuredOrigin : '';
  let cookie = '';
  let renewal = null;
  let cooldownUntil = 0;
  let signedInUser = null;
  const stats = { signIns: 0, renewals: 0, failures: 0, retries: 0, identityChecks: 0 };
  const doFetch = (...args) => (typeof fetchImpl === 'function' ? fetchImpl : globalThis.fetch).apply(globalThis, args);

  // Auth family: instance by HEADER (`?Instance=` is rejected there). Data family: instance by QUERY
  // (`?db=` is rejected there). Getting this backwards is the single most common way to break an NCB
  // integration, and both measurements are encoded here rather than in a comment.
  function buildUrl(group, path) {
    if (group === 'data') {
      const sep = path.includes('?') ? '&' : '?';
      return `${transport.dataBase}/${path}${sep}Instance=${encodeURIComponent(account.instance)}`;
    }
    if (group === 'public-data') return null;   // refused, see the header note
    return `${transport.authBase}/${path}?db=${encodeURIComponent(account.instance)}`;
  }

  async function rawFetch(url, { method = 'GET', body, captureCookie = false } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    timer.unref?.();
    try {
      const response = await doFetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          // The instance travels by header on the auth family only; the data family takes it by
          // query, and a header there is ignored rather than harmful — but sending both would make
          // a future base change impossible to read off the wire.
          ...(url.startsWith(transport.authBase) ? { 'X-Database-Instance': account.instance } : {}),
          // The same trusted Origin the player gateway sends, for the same reason. This account's
          // ONLY path to a session is `sign-in/email`, and if the vendor asserts an origin at session
          // issuance — the suspicion the live player 403 raised — an account that sends none would
          // fail with `club_account_login_failed`, a message that says nothing about origins and
          // would be debugged as a bad password. Two transports to one vendor must not differ in the
          // one header whose absence is invisible until it is expensive.
          ...(trustedOrigin ? { Origin: trustedOrigin } : {}),
          ...(cookie ? { Cookie: cookie } : {})
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal
      });
      const text = await response.text().catch(() => '');
      let parsed = null;
      try { parsed = JSON.parse(text); } catch { /* an HTML 404 from a nonexistent route */ }
      let cookiePair = null;
      if (captureCookie) {
        const list = typeof response.headers.getSetCookie === 'function'
          ? response.headers.getSetCookie()
          : [response.headers.get('set-cookie')].filter(Boolean);
        cookiePair = list.map(COOKIE_PAIR).filter(Boolean).join('; ');
      }
      return { httpStatus: response.status, body: parsed ?? {}, cookiePair, nonJson: text.trimStart().charAt(0) !== '{' && text.trimStart().charAt(0) !== '[' };
    } catch (error) {
      const name = error?.name === 'AbortError' ? 'timeout' : (error?.name || 'network_error');
      return { httpStatus: 0, body: { error: name }, cookiePair: null, nonJson: false };
    } finally {
      clearTimeout(timer);
    }
  }

  // The identity question, asked of the authority rather than of the sign-in response.
  async function verifySessionIdentity() {
    const check = await rawFetch(buildUrl('auth', 'get-session'), { method: 'GET' });
    if (check.httpStatus < 200 || check.httpStatus >= 300) {
      return { ok: false, reason: 'club_account_identity_unverifiable', detail: 'get-session did not answer' };
    }
    const user = check.body?.data?.user ?? check.body?.user ?? null;
    if (!user || typeof user !== 'object') {
      return { ok: false, reason: 'club_account_identity_unverifiable', detail: 'the session named no user' };
    }
    const sessionId = String(user.id ?? '').trim();
    if (account.expectedUserId) {
      return sessionId === account.expectedUserId
        ? { ok: true, user }
        : { ok: false, reason: 'club_account_identity_mismatch', detail: 'the session user id is not the configured club account' };
    }
    const sessionEmail = String(user.email ?? '').trim().toLowerCase();
    if (sessionEmail === '') {
      return { ok: false, reason: 'club_account_identity_unverifiable', detail: 'the session carries no email and no expected user id is configured' };
    }
    return sessionEmail === String(account.email).toLowerCase()
      ? { ok: true, user }
      : { ok: false, reason: 'club_account_identity_mismatch', detail: 'the authenticated session belongs to a different account' };
  }

  async function performSignIn() {
    const result = await rawFetch(buildUrl('auth', 'sign-in/email'), {
      method: 'POST', body: { email: account.email, password: account.password }, captureCookie: true
    });
    // The cookie is the session. A body token in the same response proves nothing and is not used.
    if (result.httpStatus >= 200 && result.httpStatus < 300 && result.cookiePair) {
      cookie = result.cookiePair;
      signedInUser = null;
      const identity = await verifySessionIdentity();
      if (!identity.ok) {
        cookie = '';
        stats.failures += 1;
        cooldownUntil = now() + RENEWAL_COOLDOWN_MS;
        return { ok: false, reason: identity.reason, detail: identity.detail };
      }
      signedInUser = identity.user;
      stats.signIns += 1;
      stats.identityChecks += 1;
      cooldownUntil = 0;
      return { ok: true, reason: null, detail: '' };
    }
    cookie = '';
    signedInUser = null;
    stats.failures += 1;
    cooldownUntil = now() + RENEWAL_COOLDOWN_MS;
    // Generic reason on purpose: a wrong password must not be quoted onward, and the body could
    // echo what it was sent.
    return {
      ok: false,
      reason: result.cookiePair ? 'club_account_cookie_missing' : 'club_account_login_failed',
      detail: describeFailure(result.body, secrets)
    };
  }

  function ensureSession() {
    if (cookie) return Promise.resolve({ ok: true });
    if (renewal) return renewal;
    if (cooldownUntil > now()) {
      return Promise.resolve({ ok: false, reason: 'club_account_cooling_down', detail: 'The club account sign-in is in a cooldown after a failure.' });
    }
    renewal = performSignIn().finally(() => { renewal = null; });
    return renewal;
  }

  async function request({ group = 'data', path, method = 'GET', query = null, body }) {
    if (group === 'public-data') {
      return { ok: false, reason: 'club_public_family_unavailable', detail: 'the native NCB host serves no public-data family' };
    }
    const first = await ensureSession();
    if (!first.ok) return first;

    const url = `${buildUrl(group, path)}${query ? `&${query}` : ''}`;
    let response = await rawFetch(url, { method, body });

    if (response.httpStatus === 401) {
      cookie = '';
      signedInUser = null;
      const renewed = renewal ?? (await ensureSession());
      if (!renewed.ok) return { ...renewed, reason: renewed.reason ?? 'club_account_login_failed' };
      stats.renewals += 1;
      stats.retries += 1;
      response = await rawFetch(url, { method, body });
      if (response.httpStatus === 401) {
        cookie = '';
        signedInUser = null;
        return { ok: false, reason: 'club_account_rejected', detail: 'The club session was rejected twice; no further retry was attempted.' };
      }
    }

    if (response.httpStatus === 0) return { ok: false, reason: 'club_account_unreachable', detail: describeFailure(response.body, secrets) };
    if (response.nonJson && response.httpStatus >= 400) {
      // An HTML answer from a JSON API is a routing fault, not a data answer, and reporting it as
      // `club_account_request_failed` with the page quoted would be both misleading and noisy.
      return { ok: false, reason: 'club_account_route_missing', detail: `HTTP ${response.httpStatus} non-JSON answer from ${group}` };
    }
    if (response.httpStatus < 200 || response.httpStatus >= 300) {
      return {
        ok: false,
        httpStatus: response.httpStatus,
        reason: response.httpStatus === 403 ? 'club_account_forbidden' : 'club_account_request_failed',
        detail: describeFailure(response.body, secrets)
      };
    }
    return { ok: true, body: response.body, httpStatus: response.httpStatus };
  }

  return {
    transport: 'native',
    unavailable: null,
    configured: true,
    request,
    getSession: () => request({ group: 'auth', path: 'get-session', method: 'GET' }),
    async signOut() {
      if (!cookie) return { ok: true, reason: null, detail: 'no active club session' };
      cookie = '';
      signedInUser = null;
      const result = await rawFetch(buildUrl('auth', 'sign-out'), { method: 'POST', body: {} });
      return { ok: true, reason: null, detail: `sign-out attempted (HTTP ${result.httpStatus || 'unreachable'})` };
    },
    status() {
      return {
        configured: true,
        transport: 'native',
        // Presence flags only: no cookie, no credential, no table contents.
        sessionActive: Boolean(cookie),
        identityVerified: Boolean(cookie) && Boolean(signedInUser),
        cooldownUntil,
        user: signedInUser ? { id: String(signedInUser.id ?? '') } : null,
        stats: { ...stats }
      };
    },
    // Test seam only — the same one the proxy client does not need because its token was a body
    // field. Nothing in the relay calls this; it exists so a gate can prove the cookie never escapes.
    __heldCookie: () => cookie
  };
}

module.exports = { createNativeAccountClient, readTransport, redact, describeFailure, RENEWAL_COOLDOWN_MS };
