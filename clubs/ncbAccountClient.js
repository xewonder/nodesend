'use strict';

/*
 * SERVER-ONLY NCB ACCOUNT CLIENT — the club service account.
 *
 * Every club-data operation runs on ONE dedicated ordinary NCB account — the club service account,
 * identified only by the server-side environment variable that holds its address. Its session
 * token is held in this process's memory and nowhere else. Not the caller's bearer: NCB runtime
 * access is `shared_readwrite`, so a membership read done with the caller's own session answers a
 * question about rows the caller can rewrite. Authorization decided from rewritable rows is a
 * formality, which is why this client exists and why the routes 503 when it cannot be built.
 *
 * THE PROTOCOL IS THE ONE ALREADY IN PRODUCTION USE, not an invention:
 *   POST {NCB_PROXY_BASE}/auth/sign-in/email?Instance={NCB_INSTANCE}   body { email, password }
 *   -> a JSON body carrying `token`; every later call sends `Authorization: Bearer <token>`
 *   GET  {NCB_PROXY_BASE}/auth/get-session?Instance={NCB_INSTANCE}     -> the session's user
 * Sign-in alone proves only that SOME token was issued, so the identity is always taken from
 * `get-session` and compared to the configured account before a single data call is made.
 *
 * WHAT THIS FILE REFUSES TO DO, in order of how much it would cost to get wrong:
 *   * Hand the token to a caller. No function returns it, no response carries it, no log writes
 *     it. `status()` reports presence booleans and a user id, never a secret.
 *   * Read credentials from anywhere but the environment. They are never function arguments, so
 *     a request body cannot supply them.
 *   * Use an MCP secret_key, or fall back to an anonymous/public-data read. There is no code path
 *     here that reaches a table without this account's bearer.
 *   * Guess an identity. `get-session` unreadable, silent, or naming a different account all fail
 *     closed and the token is dropped.
 *   * Retry a renewal into a loop. One sign-in at a time, one retry after a 401, then a cooldown.
 *   * Echo a credential in an error. NCB's error body is not trusted to be free of what it was
 *     sent, so it is filtered to a field whitelist and then string-redacted.
 *   * Run as a browser variable. `assertNotFrontendFacing` refuses a VITE_* club-credential name
 *     at boot: Vite inlines every VITE_* value into the published bundle, so one would be a
 *     published password.
 */

const SIGN_IN_PATH = 'sign-in/email';
const GET_SESSION_PATH = 'get-session';
const SIGN_OUT_PATH = 'sign-out';
const REQUEST_TIMEOUT_MS = 12000;
const RENEWAL_COOLDOWN_MS = 15000;
const MAX_ERROR_CHARS = 240;

// Fields that may legitimately appear in an NCB error envelope. Anything else is dropped, so an
// echoed credential can only reach a log if it arrives under one of these names.
const SAFE_ERROR_FIELDS = Object.freeze(['error', 'message', 'status', 'code']);

// Same proxy defaults as the rest of this relay (bridge.js), so a deployment that configures NCB
// once does not configure it twice under two different names.
const DEFAULT_NCB_PROXY_BASE = 'https://rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url.us-east-2.on.aws';
const DEFAULT_NCB_INSTANCE = '55954_bridgemind';

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
 * Refuses a deployment that would leak the account into a published bundle. Checked against the
 * real environment at boot, not against a template.
 */
function assertNotFrontendFacing(env = {}) {
  const leaked = Object.keys(env).filter((key) => /^VITE_.*CLUB_NCB/i.test(key));
  if (leaked.length) {
    return {
      ok: false,
      reason: 'club_credentials_must_not_be_frontend_env',
      detail: `Remove ${leaked.join(', ')} from the frontend environment.`
    };
  }
  return { ok: true, reason: null, detail: '' };
}

function readClubAccountConfig(env = {}) {
  const guard = assertNotFrontendFacing(env);
  if (!guard.ok) return { ok: false, ...guard };

  const email = String(env.CLUB_NCB_EMAIL ?? '').trim();
  const password = String(env.CLUB_NCB_PASSWORD ?? '');
  if (!email || !password) {
    return { ok: false, reason: 'club_account_unconfigured', detail: 'CLUB_NCB_EMAIL and CLUB_NCB_PASSWORD are both required.' };
  }

  const proxyBase = String(env.NCB_PROXY_BASE ?? DEFAULT_NCB_PROXY_BASE).trim();
  const instance = String(env.NCB_INSTANCE ?? DEFAULT_NCB_INSTANCE).trim();
  // Optional, and preferred when supplied: comparing a user id does not depend on the session
  // payload carrying an email address at all.
  const expectedUserId = String(env.CLUB_NCB_EXPECTED_USER_ID ?? '').trim();

  try {
    // A base that cannot be a URL would otherwise fail inside fetch with the credential nearby.
    new URL(proxyBase);
  } catch {
    return { ok: false, reason: 'club_account_unconfigured', detail: 'NCB_PROXY_BASE is not a valid URL.' };
  }

  return { ok: true, email, password, proxyBase, instance, expectedUserId };
}

/**
 * @param {object} options
 * @param {object} [options.env]
 * @param {Function} [options.fetchImpl] injected so the whole credential/token lifecycle is
 *   testable against a recorded NCB exchange with no network. Left unset, `globalThis.fetch` is
 *   resolved AT CALL TIME rather than captured here: a client built at module load must not freeze
 *   the fetch that existed then, or a harness that swaps the global afterwards keeps dialing the
 *   real network while every other route in the process is mocked.
 * @param {Function} [options.now]
 */
function createNcbAccountClient({ env = process.env, fetchImpl = null, now = Date.now } = {}) {
  const config = readClubAccountConfig(env);
  if (!config.ok) {
    // Fail closed at construction: no client, no attempt, no half-open session.
    const unavailable = { ok: false, reason: config.reason, detail: config.detail };
    return {
      unavailable,
      configured: false,
      async request() { return { ok: false, reason: config.reason, detail: config.detail }; },
      async getSession() { return { ok: false, reason: config.reason, detail: config.detail }; },
      async signOut() { return { ok: true, reason: null, detail: 'not configured; nothing to sign out' }; },
      status() { return { configured: false, reason: config.reason, sessionActive: false, identityVerified: false, cooldownUntil: 0 }; }
    };
  }

  const secrets = [config.email, config.password];
  let token = '';
  let renewal = null;
  let cooldownUntil = 0;
  let signedInUser = null;
  const stats = { signIns: 0, renewals: 0, failures: 0, retries: 0, identityChecks: 0 };

  // The proxy separates its route families BY PATH — /auth/..., /data/..., /public-data/... —
  // with `Instance` as the only query parameter. Nothing here invents a fourth family.
  function buildUrl(group, path) {
    const url = new URL(`/${group || 'auth'}/${path}`, config.proxyBase);
    url.searchParams.set('Instance', config.instance);
    return url.toString();
  }

  async function rawFetch(url, { method = 'POST', body, bearer = null, headers = {} } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    timer.unref?.();
    // Applied with the global as its receiver on purpose: a caller that passes
    // `fetchImpl: globalThis.fetch` hands over an unbound reference, and undici's fetch throws
    // "Illegal invocation" when called detached. That would surface as an unreachable backend —
    // the wrong diagnosis, and a reason to fail closed that was never real.
    const doFetch = (...args) => (typeof fetchImpl === 'function' ? fetchImpl : globalThis.fetch).apply(globalThis, args);
    try {
      const response = await doFetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
          ...headers
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal
      });
      const parsed = await response.json().catch(() => ({}));
      return { httpStatus: response.status, body: parsed };
    } catch (error) {
      // The NAME only. A fetch error can carry the request URL, and this URL family takes its
      // credentials in the body — but the name is all a caller needs and it cannot leak.
      const name = error?.name === 'AbortError' ? 'timeout' : (error?.name || 'network_error');
      return { httpStatus: 0, body: { error: name } };
    } finally {
      clearTimeout(timer);
    }
  }

  async function verifySessionIdentity() {
    const check = await rawFetch(buildUrl(null, GET_SESSION_PATH), { method: 'GET', bearer: token });
    if (check.httpStatus < 200 || check.httpStatus >= 300) {
      return { ok: false, reason: 'club_account_identity_unverifiable', detail: 'get-session did not answer' };
    }
    const user = check.body?.data?.user ?? check.body?.user ?? null;
    if (!user || typeof user !== 'object') {
      return { ok: false, reason: 'club_account_identity_unverifiable', detail: 'the session named no user' };
    }
    const sessionId = String(user.id ?? '').trim();
    if (config.expectedUserId) {
      return sessionId === config.expectedUserId
        ? { ok: true, user }
        : { ok: false, reason: 'club_account_identity_mismatch', detail: 'the session user id is not the configured club account' };
    }
    const sessionEmail = String(user.email ?? '').trim().toLowerCase();
    if (sessionEmail === '') {
      return { ok: false, reason: 'club_account_identity_unverifiable', detail: 'the session carries no email and no expected user id is configured' };
    }
    // The other account's address is deliberately NOT quoted into the detail: a misconfigured
    // deployment would otherwise write a real person's email into the relay log.
    return sessionEmail === config.email.toLowerCase()
      ? { ok: true, user }
      : { ok: false, reason: 'club_account_identity_mismatch', detail: 'the authenticated session belongs to a different account' };
  }

  async function performSignIn() {
    const result = await rawFetch(buildUrl(null, SIGN_IN_PATH), {
      method: 'POST',
      body: { email: config.email, password: config.password }
    });
    const issued = result.body?.token ?? result.body?.data?.token ?? null;
    if (result.httpStatus >= 200 && result.httpStatus < 300 && typeof issued === 'string' && issued.length > 0) {
      token = issued;
      signedInUser = null;
      const identity = await verifySessionIdentity();
      if (!identity.ok) {
        // The password was accepted but this is not provably the club account's session. That is
        // a failure, not a warning: drop the bearer and refuse every later call.
        token = '';
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
    token = '';
    signedInUser = null;
    stats.failures += 1;
    cooldownUntil = now() + RENEWAL_COOLDOWN_MS;
    return {
      ok: false,
      // Generic reason on purpose: the body could echo the submitted credentials, and a wrong
      // password must not be quoted onward.
      reason: 'club_account_login_failed',
      detail: describeFailure(result.body, secrets)
    };
  }

  // Serialized: every concurrent caller awaits the SAME sign-in, so a burst of expired-token 401s
  // produces exactly one new session instead of a login stampede.
  function ensureSession() {
    if (token) return Promise.resolve({ ok: true });
    if (renewal) return renewal;
    if (cooldownUntil > now()) {
      return Promise.resolve({ ok: false, reason: 'club_account_cooling_down', detail: 'The club account sign-in is in a cooldown after a failure.' });
    }
    renewal = performSignIn().finally(() => { renewal = null; });
    return renewal;
  }

  async function authenticatedRequest({ group, path, method = 'GET', query = null, body }) {
    const first = await ensureSession();
    if (!first.ok) return first;

    const url = `${buildUrl(group, path)}${query ? `&${query}` : ''}`;
    let response = await rawFetch(url, { method, body, bearer: token });

    if (response.httpStatus === 401) {
      token = '';
      signedInUser = null;
      const renewed = renewal ?? (await ensureSession());
      if (!renewed.ok) return { ...renewed, reason: renewed.reason ?? 'club_account_login_failed' };
      stats.renewals += 1;
      stats.retries += 1;
      response = await rawFetch(url, { method, body, bearer: token });
      if (response.httpStatus === 401) {
        token = '';
        signedInUser = null;
        return { ok: false, reason: 'club_account_rejected', detail: 'The club session was rejected twice; no further retry was attempted.' };
      }
    }

    if (response.httpStatus === 0) return { ok: false, reason: 'club_account_unreachable', detail: describeFailure(response.body, secrets) };
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
    unavailable: null,
    configured: true,
    request: authenticatedRequest,
    async getSession() { return authenticatedRequest({ path: GET_SESSION_PATH, method: 'GET' }); },
    async signOut() {
      if (!token) return { ok: true, reason: null, detail: 'no active club session' };
      const current = token;
      token = '';
      signedInUser = null;
      const result = await rawFetch(buildUrl(null, SIGN_OUT_PATH), { method: 'POST', body: {}, bearer: current });
      // Best effort: the local token is already gone, which is the state that matters.
      return { ok: true, reason: null, detail: `sign-out attempted (HTTP ${result.httpStatus || 'unreachable'})` };
    },
    status() {
      return {
        configured: true,
        // Presence FLAGS, never values. Nothing here is serialised to a client, and a boot log or
        // an operator probe must not be able to print a secret by accident.
        sessionActive: Boolean(token),
        // Only ever true when get-session confirmed this account's identity for the CURRENT token.
        identityVerified: Boolean(token) && Boolean(signedInUser),
        cooldownUntil,
        user: signedInUser ? { id: String(signedInUser.id ?? '') } : null,
        stats: { ...stats }
      };
    }
  };
}

module.exports = {
  SIGN_IN_PATH,
  GET_SESSION_PATH,
  RENEWAL_COOLDOWN_MS,
  assertNotFrontendFacing,
  readClubAccountConfig,
  createNcbAccountClient,
  redact,
  describeFailure
};
