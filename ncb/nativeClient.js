'use strict';

/*
THE ONLY THING IN NODESEND THAT SPEAKS TO NoCodeBackend FOR A PLAYER.

Two families, two instance channels, one rule that is not negotiable: a player request never carries
`Authorization`.

Measured, and the reason for every branch below:
  * auth  https://app.nocodebackend.com/api/user-auth/<verb>   instance via X-Database-Instance
          (`?Instance=` is REJECTED here; `?db=` also works, the header is what the guide names)
  * data  https://app.nocodebackend.com/api/data/<verb>/<table>[/<id>]   instance via ?Instance=
          (`?db=` is rejected here: "Instance is required.")
  * `Authorization: Bearer <anything>` on the data family answers 403 "Invalid secret_key." — that
    header is the DATABASE SECRET slot. Presenting it for a player would substitute a full-access
    credential for their own session and quietly disable the RLS this whole design exists to keep.
    So this file refuses, in code, not in a comment.
  * the per-user session is the vendor's own HttpOnly cookie, captured from the sign-in response and
    replayed on every later call. The body token NCB returns is NOT accepted as a session channel —
    that translation was tested live and failed — so nothing here ever treats it as one.
  * a 404 from read-by-id says "Record not found or access denied": deletion and denial look alike, so
    callers must not read a 404 as proof of anything on its own.
*/

const AUTH_VERBS = new Set(['sign-in/email', 'sign-up/email', 'get-session', 'sign-out',
  'change-password', 'forget-password', 'reset-password', 'revoke-session', 'email-verification',
  'send-verification-email']);
const DATA_VERBS = new Set(['read', 'create', 'update', 'delete']);
const METHOD_BY_VERB = { read: 'GET', create: 'POST', update: 'PUT', delete: 'DELETE' };
const TABLE_NAME = /^[A-Za-z][A-Za-z0-9_]{1,62}$/;
const ROW_ID = /^[A-Za-z0-9_-]{1,64}$/;
// Query names that must never come from a caller: they are how a secret would sneak in.
const RESERVED_QUERY = /^(Instance|db|key|secret_key|api_key|apikey|access_token|token)$/i;

function classify(response) {
  // `response` here is the NORMALISED shape ({httpStatus, json}) the transport builds, never a fetch
  // Response: those two objects disagree about every field name, and reading the wrong one makes each
  // branch fall through to `unexpected`.
  const { httpStatus, json } = response;
  if (httpStatus === 0) return 'unreachable';
  if (httpStatus >= 500) return 'upstream_error';
  if (httpStatus === 401) return 'invalid_session';
  if (httpStatus === 403) {
    // The vendor's own words distinguish a bad secret from a denied row, and the difference decides
    // whether the caller should re-authenticate or simply accept a not-found.
    const text = String(json?.error ?? json?.message ?? '');
    return /secret_key/i.test(text) ? 'secret_key_rejected' : 'forbidden';
  }
  if (httpStatus === 404) return 'not_found';
  if (httpStatus === 400) {
    const text = String(json?.error ?? json?.message ?? json?.code ?? '');
    return /instance is required/i.test(text) ? 'instance_required' : 'rejected';
  }
  if (httpStatus >= 200 && httpStatus < 300) {
    if (json && typeof json === 'object' && json.status && json.status !== 'success') return 'rejected';
    return 'ok';
  }
  return 'unexpected';
}

/**
 * @param {object} options
 * @param {object} [options.env]
 * @param {Function} [options.fetchImpl] so the tests can dial a loopback fake
 */
function createNcbNativeClient({ env = process.env, fetchImpl = null, timeoutMs = 8000 } = {}) {
  const authBase = String(env.NCB_AUTH_API_URL || 'https://app.nocodebackend.com/api/user-auth').replace(/\/$/, '');
  const dataBase = String(env.NCB_DATA_API_URL || 'https://app.nocodebackend.com/api/data').replace(/\/$/, '');
  const instance = String(env.NCB_INSTANCE || '55954_bridgemind').trim();
  // Only the harness may relax this, and only to loopback: a player gateway that will dial an
  // arbitrary http URL has handed a session to whatever listens there. The shape check stays for
  // production and the exception is narrow enough to be auditable in one line.
  const allowLoopbackHttp = env.NCB_ALLOW_INSECURE_UPSTREAM === '1';
  const usable = (url) => /^https:\/\/.+/.test(url) || (allowLoopbackHttp && /^http:\/\/(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?\/.+/.test(url));
  const configured = usable(authBase) && usable(dataBase) && instance !== '';
  const doFetch = (...args) => (typeof fetchImpl === 'function' ? fetchImpl : globalThis.fetch).apply(globalThis, args);

  /* The Origin the vendor sees on every call from this process.

     The known-working PoC sent `Origin: https://app.bridgemind.app` on all of its requests, including
     the sign-in that returned 200 and a session cookie; NodeSend sent none. Measured here with an
     address no account can own, so no credential was involved: WITHOUT that header the vendor still
     reached credential validation (401 INVALID_EMAIL_OR_PASSWORD), which is why the header is not the
     whole story and is also why sending it is free — it makes our request indistinguishable from the
     one that is known to work, on the one family where the vendor decides whether to issue a session.

     It is a name, not a secret: an Origin value is public information, it is not a credential, and
     nothing here reads it from a browser request — a client cannot choose which origin the relay
     claims upstream. Set NCB_TRUSTED_ORIGIN= to send none. */
  const configuredOrigin = String(env.NCB_TRUSTED_ORIGIN ?? 'https://app.bridgemind.app').trim();
  const trustedOrigin = /^https:\/\/[A-Za-z0-9.:_-]+$/.test(configuredOrigin) ? configuredOrigin : '';

  async function send(url, { method = 'GET', headers = {}, body, captureCookie = false } = {}) {
    // The refusal is here rather than at each call site so a future route cannot forget it.
    for (const name of Object.keys(headers)) {
      if (/^authorization$/i.test(name) || /^(x-)?(database-)?secret[-_]?key$/i.test(name)) {
        const error = new Error('REFUSED: a player request must never carry an Authorization or secret-key header');
        error.code = 'secret_substitution_refused';
        throw error;
      }
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref?.();
    try {
      const response = await doFetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json', ...headers,
          // Applied AFTER the caller's headers, not before: a request that reached this transport must
          // not be able to decide which origin the relay claims to the vendor. A test that needs a
          // different value sets NCB_TRUSTED_ORIGIN, which is the same knob production uses.
          ...(trustedOrigin && !headers?.origin ? { Origin: trustedOrigin } : {})
        },
        ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
        signal: controller.signal
      });
      const text = await response.text().catch(() => '');
      let json = null;
      try { json = JSON.parse(text); } catch { /* non-json upstream body */ }
      // classify() is handed a NORMALISED object, not the Response. A fetch Response has `.status`,
      // not `.httpStatus`, and no parsed `.json` — reading those off it yields undefined, every branch
      // misses, and a perfectly good 200 is reported as an unknown answer. That is how a working
      // sign-in came back as `400 request failed` the first time this was run.
      const result = { httpStatus: response.status, json, text, kind: classify({ httpStatus: response.status, json }) };
      if (captureCookie) {
        const list = typeof response.headers.getSetCookie === 'function'
          ? response.headers.getSetCookie() : [response.headers.get('set-cookie')].filter(Boolean);
        // The pair, not the whole line: attributes stay with the vendor and must never be forwarded
        // to a browser that is talking to NodeSend, not to NCB.
        result.cookiePair = list.map((line) => String(line).split(';')[0]).join('; ');
        result.cookieNames = list.map((line) => String(line).split('=')[0]);
      }
      return result;
    } catch (error) {
      // The NAME only, as everywhere else in this relay: a fetch error can carry the URL, and the URL
      // family here is the one place a session could appear in a query.
      return { httpStatus: 0, json: null, text: '', kind: 'unreachable', errorName: error?.name || 'Error' };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    configured,
    authBase,
    dataBase,
    instance,
    reasons: { authBase, dataBase, instance },

    /**
     * A call described by the path the relay already uses internally — `/data/read/table?x=1`,
     * `/data/update/table/7` — performed against the native data family with the CALLER's cookie.
     *
     * This exists so `bridge.js` can move its session, quota and credential traffic onto the native
     * transport without rewriting every call site's path string. The parsing is not a convenience:
     * it is where the verb, table and row id are validated and where the reserved query names are
     * dropped, so a caller-controlled path cannot smuggle an `Instance` or a `key` into the query.
     *
     * The answer is duck-typed as `{ ok, status, json() }`, which is the shape the relay's existing
     * transports already present. Returning a private shape here would mean editing the quota ledger
     * to accommodate the transport, and the ledger's failure semantics are what keeps quota correct.
     */
    async dataPath(path, { cookie = '', body, headers = {} } = {}) {
      const [fullPath, query = ''] = String(path || '').split('?');
      const parts = fullPath.split('/').filter(Boolean);       // ['data','read','table','7']
      const [, verb, table, ...rest] = parts;
      if (parts[0] !== 'data' || !DATA_VERBS.has(verb)) return { ok: false, status: 0, json: async () => null, kind: 'unknown_verb' };
      const id = rest.join('/');
      // The method comes from the VERB, exactly as `data()` maps it: a caller passing `method` as
      // well would be a second source of truth about the same request, and the two can disagree.
      const result = await this.data(verb, table, { id, query, body, cookie, headers });
      return {
        ok: result.httpStatus >= 200 && result.httpStatus < 300,
        status: result.httpStatus,
        kind: result.kind,
        json: async () => result.json
      };
    },

    /** Auth family: instance by header. `cookie` is replayed only for verbs that need a session. */
    auth(verb, { method = 'POST', body, cookie = '', headers = {} } = {}) {
      if (!AUTH_VERBS.has(verb)) return Promise.resolve({ httpStatus: 0, kind: 'unknown_verb', json: null });
      const url = `${authBase}/${verb}?db=${encodeURIComponent(instance)}`;
      return send(url, {
        method,
        body,
        captureCookie: true,
        headers: { 'X-Database-Instance': instance, ...(cookie ? { Cookie: cookie } : {}), ...headers }
      });
    },

    /**
     * Data family: instance by query. `query` is the caller's own filter string, minus every reserved
     * name — that removal is the whole of the "no parameter smuggling" story on this route.
     * `headers` exists so the refusal below is reachable from a test: an extra header that nobody
     * passes is not a guard, it is a comment.
     */
    data(verb, table, { id = '', query = '', body, cookie = '', headers = {} } = {}) {
      if (!DATA_VERBS.has(verb)) return Promise.resolve({ httpStatus: 0, kind: 'unknown_verb', json: null });
      if (!TABLE_NAME.test(String(table))) return Promise.resolve({ httpStatus: 0, kind: 'bad_table', json: null });
      if (id !== '' && !ROW_ID.test(String(id))) return Promise.resolve({ httpStatus: 0, kind: 'bad_row_id', json: null });
      const kept = String(query || '').split('&').filter((pair) => {
        if (!pair) return false;
        const name = decodeURIComponent(pair.split('=')[0] || '');
        return !RESERVED_QUERY.test(name);
      }).join('&');
      const url = `${dataBase}/${verb}/${encodeURIComponent(table)}${id === '' ? '' : `/${encodeURIComponent(id)}`}?Instance=${encodeURIComponent(instance)}${kept ? `&${kept}` : ''}`;
      return send(url, {
        method: METHOD_BY_VERB[verb],
        body,
        headers: { ...(cookie ? { Cookie: cookie } : {}), ...headers }
      });
    }
  };
}

module.exports = { createNcbNativeClient, AUTH_VERBS, DATA_VERBS, RESERVED_QUERY, classify };
