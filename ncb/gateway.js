'use strict';

/*
THE PLAYER GATEWAY — the only NodeSend surface that turns a browser request into an NCB call.

It exists to replace a dead AWS Lambda, so it deliberately keeps that Lambda's two contracts and
drops everything else about it:

  * path shape. BridgeMind builds `${proxyBase}/auth/<verb>` and `${proxyBase}/data/<verb>/<table>`
    (src/api.js:156-166) and attaches `Authorization: Bearer ${localStorage.ncb_session_token}` to
    every one of them. Pointing that base at `https://nodesend.waveloc.com/ncb` therefore needs NO
    frontend change: the verbs, the path segments, the query strings and the response envelopes all
    stay as the client already parses them. That is the whole reason these routes look the way they do.
  * the envelope. Every answer is `{status:'success'|'error', data, ...}` — the shape `isSignedIn()`
    and the 101 data call sites already branch on.

What it refuses to be:

  * not a general proxy. Only five auth verbs and four data verbs exist, the table name must be on an
    allow-list, the row id must be a safe token, and reserved query names (`key`, `Instance`, `token`,
    …) are stripped from the caller's query before it is forwarded. There is no way to name an upstream
    URL, so this cannot be aimed at somebody else's instance.
  * not a secret carrier. `nativeClient` throws rather than let `Authorization` onto a player request,
    which is what keeps NCB's per-user RLS real: the database secret would see everything and the
    vendor would stop scoping rows by `user_id` at that moment.
  * not an ambient authority. The upstream session cookie is captured from the vendor, sealed with a
    server-side key (sessionSeal.js), and handed back to the browser as `token` — which is what
    `src/api.js` already stores. The browser never receives the vendor cookie, and it cannot send one
    that NodeSend has not sealed.

Two answers that must never be confused, because the last outage proved they are: an UNVERIFIABLE
session (NCB unreachable) is 503, and a session that is genuinely not valid is 401. A 401 is what makes
a client throw away a working login, so an upstream problem answered as 401 logs every player out.
*/

const { Router } = require('express');
const { createNcbNativeClient, AUTH_VERBS } = require('./nativeClient.js');
const { createSessionSeal, PREFIX } = require('./sessionSeal.js');
// The ONE invitation-code rule, shared with the relay's own routes and the claim module. Imported
// rather than restated: three separate validators in one deployment is what made code `777` read as
// `valid:true` on one route and `400 bad_code` on the route the browser calls.
const { normalizeInvitationCode } = require('./invitationCode.js');

const AUTH_ROUTES = [
  { path: '/ncb/auth/sign-in/email', verb: 'sign-in/email', method: 'post', mints: true },
  { path: '/ncb/auth/sign-up/email', verb: 'sign-up/email', method: 'post', mints: true },
  { path: '/ncb/auth/get-session', verb: 'get-session', method: 'get', renews: true },
  { path: '/ncb/auth/sign-out', verb: 'sign-out', method: 'post' },
  { path: '/ncb/auth/change-password', verb: 'change-password', method: 'post' }
];
const DATA_VERBS = { get: 'read', post: 'create', put: 'update', delete: 'delete' };
// The tables the SHIPPED browser touches. Measured, not assumed: every name here is a table some
// `dataFetch(...)` call site in BridgeMind-Greta/src reads or writes (the enumeration and the call
// sites are pinned by verify-ncb-integration.mjs). A table missing from this list is a silent 403 in
// production, which is the failure this whole gateway was built to end — so the list belongs in code
// as well as in the deployment environment, and `NCB_TABLE_ALLOWLIST` narrows it rather than being
// the only place it exists.
const DEFAULT_TABLES = [
  'user_settings', 'llm_preferences', 'recorded_hands', 'community_games', 'user_codes',
  'ai_providers', 'ai_models', 'ai_model_parameters', 'ai_decision_traces', 'ai_usage_events',
  'app_config', 'coach_feedback_flags', 'game_analysis_reports', 'replay_attempts',
  'system_ai_config',
  'tournaments', 'tournament_boards', 'tournament_attempts'
];
// Club tables are reached through the dedicated Clubs service account with its own authorization
// checks (clubs/ncbAccountClient.js). Listing them here would put a second, weaker path in front of
// the authority data, and that path would be scoped by a browser-held handle rather than by R1.
const AUTHORITY_TABLES = ['system_admins', 'clubs', 'club_memberships',
  'club_board_collections', 'club_collection_boards'];
// NodeSend's own server-side ledger and per-user encrypted credential store. The browser never reads
// or writes any of these — no call site exists — and the quota tables are `shared_readwrite` on the
// vendor side, so they carry NO per-user row isolation: allowing them here would let any signed-in
// account read and rewrite other accounts' counters and credential rows. Excluded by name, in code,
// rather than left to a deployment variable that could be set wrongly.
const SERVER_ONLY_TABLES = [
  'ai_quota_usage', 'ai_quota_config', 'ai_quota_user_override', 'ai_quota_reservation',
  'ai_provider_credentials_1770000000',
  // The reservation table is the arbitration itself. If a signed-in account could insert into it, the
  // account could hold every record of a code it never redeemed and starve the pool — the exact
  // failure the reservation is meant to prevent, reachable through the route meant to be broad.
  'invitation_reservations'
];
// ── WRITE POLICY: which verbs a player may exercise on an allowed table ──────
// An allow-list that answers "yes, this table" and then forwards read/create/update/delete alike is a
// URL filter, not an authorization model. Measured against the shipped call sites, most of these
// tables are read by every player and written only by an administrator — so a uniform CRUD grant would
// let any signed-in account repoint the system's AI provider (`system_ai_config`), rewrite the global
// app config, edit the model catalogue, or mark somebody else's invitation code as spent. None of
// that is required by a player's own flow, so none of it is allowed.
//
//   full   — the player's own data: read, create, update, delete
//   create — the player appends a record about their own play; never edits or removes one
//   read   — a player may look; every write is an administrative action taken elsewhere
//
// A table absent from this map is treated as `read`, because the safe default for anything not
// deliberately reviewed is the one that cannot damage another account.
const PLAYER_TABLE_WRITE_POLICY = Object.freeze({
  user_settings: 'full', llm_preferences: 'full', recorded_hands: 'full', community_games: 'full',
  replay_attempts: 'full', game_analysis_reports: 'full',
  tournaments: 'full', tournament_boards: 'full', tournament_attempts: 'full',
  coach_feedback_flags: 'create', ai_usage_events: 'create', ai_decision_traces: 'create',
  app_config: 'read', ai_providers: 'read', ai_models: 'read', ai_model_parameters: 'read',
  system_ai_config: 'read', user_codes: 'read'
});
// `system_ai_credentials` is excluded from the allow-list entirely rather than made read-only: it
// holds the SYSTEM AI provider key material and endpoint. Read cross-account hands an attacker
// ciphertext plus a target to attack offline; write lets any signed-in account point the deployment's
// AI traffic at a key of their choosing. Both are administrative actions and belong on a route that
// authorizes them as such, on the same service-account model Clubs uses — not on a player CRUD path.
const CREDENTIAL_TABLES = ['system_ai_credentials'];
const NEVER_THROUGH_THE_GATEWAY = [...AUTHORITY_TABLES, ...SERVER_ONLY_TABLES, ...CREDENTIAL_TABLES];
const WRITE_VERBS = ['create', 'update', 'delete'];
function writePermission(verb, table) {
  if (!WRITE_VERBS.includes(verb)) return { allowed: true, policy: PLAYER_TABLE_WRITE_POLICY[table] || 'read' };
  const policy = PLAYER_TABLE_WRITE_POLICY[table] || 'read';
  if (policy === 'full') return { allowed: true, policy };
  if (policy === 'create' && verb === 'create') return { allowed: true, policy };
  return { allowed: false, policy };
}
// The one anonymous read the app performs — an invitation code looked up BEFORE any account exists.
const PUBLIC_TABLES = ['user_codes'];
// Exactly the fields BridgeMind's registration flow reads (`code` for its own match test, `id`,
// `used`, `registered_user_id` for the claim read-back). Anything else the table holds — timestamps,
// notes, whoever issued it — stays in the database.
const PUBLIC_FIELDS = ['id', 'code', 'used', 'registered_user_id'];
const MAX_QUERY_CHARS = 512;
const MAX_BODY_BYTES = 256 * 1024;
const AUTH_RATE_MAX = Number(process.env.NCB_GATEWAY_AUTH_RATE_MAX || 20);
const AUTH_RATE_WINDOW_MS = Number(process.env.NCB_GATEWAY_AUTH_RATE_WINDOW_MS || 60000);
/**
 * The body each auth verb may send upstream — a whitelist, not a passthrough.
 *
 * The gateway used to forward whatever JSON the browser posted. That is how a live investigation found
 * an `origin` field riding along to the vendor on a request whose known-working shape never had one:
 * harmless to better-auth, which ignores unknown keys, but exactly the kind of caller-controlled
 * surface that turns into a different meaning the next time the vendor tightens a route. Sign-in takes
 * two fields. Nothing else reaches the vendor, whatever the client sent.
 */
const AUTH_BODY_FIELDS = Object.freeze({
  'sign-in/email': ['email', 'password'],
  'sign-up/email': ['email', 'password', 'name', 'image', 'callbackURL'],
  'change-password': ['currentPassword', 'newPassword', 'sessionIdentifier'],
  'sign-out': [],
  'get-session': []
});
function projectAuthBody(verb, body) {
  const allowed = AUTH_BODY_FIELDS[verb] ?? [];
  const source = (body && typeof body === 'object' && !Array.isArray(body)) ? body : {};
  const out = {};
  let dropped = 0;
  for (const key of allowed) {
    const value = source[key];
    if (value === undefined || value === null) continue;
    if (typeof value === 'string') {
      if (value.length > 512) continue;                     // no credential-shaped runaway field
      out[key] = value;
    } else if (typeof value === 'boolean' || typeof value === 'number') {
      out[key] = value;
    } else dropped += 1;                                    // objects and arrays are never forwarded
  }
  for (const key of Object.keys(source)) if (!allowed.includes(key)) dropped += 1;
  return { body: out, dropped };
}

/**
 * What an upstream auth answer means TO THE CALLER. One table, so the three kinds of refusal cannot
 * drift back into a single 400 — the collapse that made a dead gateway look like a bad password.
 *
 *   401 → 401   the credentials were checked and refused. The player can act on this.
 *   403 → 502   the vendor refused on policy grounds (origin trust, unverified or banned account,
 *               route restriction). Nobody can type their way out of it, so it is not a 4xx for the
 *               browser and not a 200-with-an-error-envelope either.
 *   429 → 429   the vendor is throttling. Relay the back-off or the client retries into a longer window.
 *   400/422 → 400  the request itself was malformed — genuinely the caller's to fix.
 *   anything else unmapped → 502, because an unrecognised upstream answer is this gateway's problem.
 */
function authUpstreamStatus(httpStatus) {
  const status = Number(httpStatus);
  if (status === 401) return { status: 401, error: 'invalid_credentials' };
  if (status === 429) return { status: 429, error: 'upstream_rate_limited', retryAfterSeconds: Math.max(1, Math.ceil(AUTH_RATE_WINDOW_MS / 1000)) };
  if (status === 400 || status === 422) return { status: 400, error: 'request_rejected' };
  if (status === 403) return { status: 502, error: 'upstream_forbidden' };
  return { status: 502, error: 'upstream_rejected' };
}

/**
 * Did the vendor DECIDE, or did we simply stop hearing it?
 *
 * This is the question a released reservation turns on, and getting it wrong spends an invitation on
 * nobody or on the wrong person. A transport failure (`httpStatus 0` — a timeout, an aborted request,
 * a socket closed mid-flight) and any 5xx mean the request reached a server that was still working on
 * it: the account may exist at NCB right now, with nothing on this side able to say either way. A 4xx
 * is different in kind — the vendor read the whole request and refused it, so no account was created
 * and the record it was holding is genuinely free again.
 *
 * Releasing after an ambiguous answer is the bug this predicate exists to prevent: the held record
 * would go to a SECOND registrant while the first one's account quietly exists, which is exactly the
 * "one invitation, two accounts" outcome the reservation was built to make impossible. So the
 * ambiguous branch holds the reservation and recovery finishes it for whichever account authenticates
 * with that address; only the decided branch gives the record back to the pool.
 *
 * The status is the whole authority, because `0` is already what the transport reports when it heard
 * nothing back. Reading the transport KIND instead would be wrong in both directions: a 422 is
 * better-auth's ordinary "user already exists", which the vendor decided and which must free the
 * record, yet it classifies as `unexpected` and would otherwise be held — stranding one invitation per
 * mistyped email until a small pool was empty.
 */
function signUpOutcomeIsAmbiguous(httpStatus) {
  const status = Number(httpStatus) || 0;
  if (status === 0) return true;                       // timeout, abort, reset: nothing was heard
  if (status === 408 || status === 502 || status === 503 || status === 504) return true;
  return status >= 500;                                // any other server fault may have created it
}
// Tighter than sign-in on purpose: this endpoint is anonymous, answers before any credential exists,
// and is an existence oracle over invitation codes. The route it replaces (`/auth/validate-invitation`)
// is limited the same way, so this is the same posture rather than a new one.
const PUBLIC_RATE_MAX = Number(process.env.NCB_GATEWAY_PUBLIC_RATE_MAX || 10);
const MAX_RATE_BUCKETS = 5000;

/**
 * The CORS allow-list, from NCB_GATEWAY_ALLOWED_ORIGINS.
 *
 * Membership is exact and the scheme is constrained, which is the whole point: nothing here ever
 * reflects an origin that was not named, and a wildcard is not expressible. But production is not
 * the only place a browser runs — `npm run dev` in BridgeMind serves Vite on http://localhost:5173
 * (its config sets `host: '0.0.0.0'` and no port, so 5173 is the default), and a client cannot be
 * developed against a gateway that structurally refuses to name its origin.
 *
 * So `http` is admitted ONLY for the loopback hosts, and only when explicitly configured. `*` is
 * dropped by the shape check, an unknown origin is never reflected, and an https requirement still
 * governs everything that is not a development machine.
 */
function parseAllowList(env) {
  const raw = String(env.NCB_GATEWAY_ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  return raw.filter((origin) => /^https:\/\/[A-Za-z0-9.:_-]+$/.test(origin)
    || /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$/.test(origin));
}

function parseTables(env) {
  const raw = String(env.NCB_TABLE_ALLOWLIST || '').split(',').map((s) => s.trim()).filter(Boolean);
  const list = (raw.length ? raw : DEFAULT_TABLES).filter((t) => !NEVER_THROUGH_THE_GATEWAY.includes(t));
  return [...new Set(list)];
}

const GATEWAY_PREFIX = '/ncb';

/**
 * THE CORS DECISION, for the relay's single app-wide `cors()` call in bridge.js.
 *
 * It has to live there rather than in the router, and that is a fact about the `cors` package rather
 * than a preference: cors is mounted first, it answers every OPTIONS itself with a 204 and never
 * calls `next()`, and it sets `Access-Control-Allow-Origin` on the way out. A handler further down can
 * choose a status; it cannot un-set a header that was already written. Measured, not remembered —
 * the relay's current setting emits `*` for every path and swallows preflights for every path.
 *
 * So this is the one hook that can narrow `/ncb` without touching anything else, and it is written to
 * be exactly that:
 *
 *   * a path that is not in the /ncb namespace gets the option object the relay passes today,
 *     unchanged. `/ai`, `/auth`, `/health`, Trickster, quota, multiplayer, Clubs — same wildcard,
 *     same preflight, same exposed headers as the build before this file existed. Requirement: the
 *     gateway must not alter the answers any existing surface gives a browser.
 *   * an allow-listed origin on a gateway path gets its own origin echoed with `credentials: true`,
 *     which is what BridgeMind's `credentials: 'include'` fetches need — a wildcard is rejected by the
 *     browser in credentialed mode, so the old proxy's `*` would simply have failed the app.
 *   * an origin that is not on the list gets `origin: false`, and cors emits NO CORS header at all and
 *     falls through to the router, which answers 403 `origin_not_allowed`. Fail closed, and visibly.
 *   * a gateway request with no `Origin` header (a CLI, another server) keeps the plain behaviour;
 *     these routes are not cookie-authenticated, so a missing header grants nothing.
 *
 * @param {object} options
 * @param {object} [options.env]
 * @param {string[]|null} [options.exposedHeaders] the relay's own list, passed through untouched
 */
function createCorsResolver({ env = process.env, exposedHeaders = null } = {}) {
  const allowedOrigins = parseAllowList(env);
  const base = exposedHeaders ? { exposedHeaders } : {};

  return function ncbCors(req, callback) {
    let path = '';
    try { path = String(req.path || (req.url || '').split('?')[0]); } catch { path = ''; }
    if (path !== GATEWAY_PREFIX && !path.startsWith(`${GATEWAY_PREFIX}/`)) {
      return callback(null, base);
    }
    const origin = String(req.headers?.origin || '');
    if (!origin) return callback(null, base);
    if (!allowedOrigins.includes(origin)) return callback(null, { ...base, origin: false });
    return callback(null, {
      ...base,
      origin,
      credentials: true,
      methods: 'GET, POST, PUT, DELETE, OPTIONS',
      allowedHeaders: 'Content-Type, Authorization',
      maxAge: 600
    });
  };
}

function buildNcbGateway({ env = process.env, fetchImpl = null, log = null, guestRead = null, invitationClaim = null } = {}) {
  const seal = createSessionSeal({ env });
  const ncb = createNcbNativeClient({ env, fetchImpl, timeoutMs: Number(env.NODESEND_NCB_TIMEOUT_MS || 8000) });
  const allowedOrigins = parseAllowList(env);
  const tables = parseTables(env);
  // Registration is closed unless this is explicitly turned on, and the reason is measured rather than
  // assumed: see the refusal in the auth loop below.
  const signUpAllowed = String(env.NCB_GATEWAY_ALLOW_SIGN_UP || '').trim() === '1';
  const router = Router();
  const rateBuckets = new Map();
  const event = (name, data) => { if (typeof log === 'function') log(name, data); };

  // Bounded, in-process, per address — throttling, not access control, and said so in the shape of
  // the code: the same window/limit constants the invitation route already uses.
  function hit(ip) {
    const now = Date.now();
    const key = String(ip || 'unknown');
    const entry = rateBuckets.get(key);
    if (!entry || now - entry.startedAt >= AUTH_RATE_WINDOW_MS) {
      if (rateBuckets.size >= MAX_RATE_BUCKETS) {
        rateBuckets.delete(rateBuckets.keys().next().value);
      }
      rateBuckets.set(key, { startedAt: now, count: 1 });
      return 0;
    }
    entry.count += 1;
    if (entry.count <= AUTH_RATE_MAX) return 0;
    return Math.max(1, Math.ceil((AUTH_RATE_WINDOW_MS - (now - entry.startedAt)) / 1000));
  }

  function bearer(req) {
    const value = String(req.get('authorization') || '');
    return value.startsWith('Bearer ') ? value.slice(7).trim() : '';
  }

  /**
   * Resolves the caller's upstream cookie from their sealed handle, keeping the two failure classes
   * apart. `unavailable` is what lets a route answer 503 instead of logging a player out.
   */
  function resolveHandle(req) {
    const handle = bearer(req);
    if (!handle) return { kind: 'missing' };
    if (!handle.startsWith(`${PREFIX}.`)) return { kind: 'not_sealed' };
    if (!seal.configured) return { kind: 'misconfigured' };
    const opened = seal.open(handle);
    if (!opened.ok) return { kind: opened.reason === 'expired' ? 'expired' : 'invalid' };
    if (opened.session.instance && opened.session.instance !== ncb.instance) {
      // A handle minted for another instance is not this instance's session. Forwarding it would ask
      // NCB about somebody else's database under a name that looks like ours.
      return { kind: 'wrong_instance' };
    }
    return { kind: 'ok', cookie: opened.session.cookie, session: opened.session };
  }

  function reply(res, status, body) {
    if (!res.headersSent) res.status(status).json(body);
  }

  // Origin control lives in ONE place, and it is the app-wide `cors()` call in bridge.js — see
  // `corsOrigin` below. Doing it here instead would have been a lie: the relay's cors() runs first,
  // reflects whatever Origin it is given, and answers the preflight before this router is ever
  // reached, so a "refusal" mounted downstream could set a status but could not un-set a header.
  router.use((req, res, next) => {
    const origin = String(req.get('origin') || '');
    if (origin && !allowedOrigins.includes(origin)) {
      // Unreachable in normal operation (corsOrigin already refused it with 403). Kept because a
      // future mount that forgets corsOrigin must fail closed rather than serve a session route.
      event('ncb_gateway_origin_refused', { path: req.path });
      return reply(res, 403, { status: 'error', data: null, error: 'origin_not_allowed' });
    }
    next();
  });

  // A valid, unused invitation is a SERVER-side precondition on account creation, and this runs
  // before the auth handler so the check cannot be reordered behind an upstream call. The rule it
  // replaces is the one the removal of the Lambda exposed: Login.jsx validates the code in the
  // browser, so a caller that skips the UI never had to present one at all — a client-side check is
  // not an authorization. See ncb/invitationClaim.js for what a claim can and cannot guarantee.
  // Mounted as MIDDLEWARE on the path rather than as a second route, for a reason an operator can
  // check: `routes` in /health is the published count of endpoints this gateway offers, and this is
  // not a new endpoint — it is a precondition on the one below. A `router.post` here would silently
  // make the mount say 15 while advertising 14.
  router.use('/ncb/auth/sign-up/email', async (req, res, next) => {
    if (req.method !== 'POST') return next();               // the verb route answers everything else
    if (!signUpAllowed) return next();                 // the refusal below answers, unchanged
    const requestId = res.get('X-Request-Id') || null;
    // Registration is only allowed when there is a privileged channel that can record the claim AND a
    // database that can arbitrate it. Turning the lever on without either is the "open and broken"
    // state this route exists to end: an account gets created and nothing links it to a code.
    if (!invitationClaim) {
      event('ncb_gateway_registration_unclaimed', { requestId });
      return reply(res, 503, {
        status: 'error', data: null, error: 'invitation_claim_unavailable',
        detail: 'registration cannot be enabled until the server-side invitation claim is wired'
      });
    }
    // The code and the address are read here and then removed from the body: neither is a vendor
    // field, and leaving them in place would make every legitimate registration look like a
    // dropped-field anomaly in the log. `email` is needed because the reservation is bound to the
    // address being registered — not as proof of anything, but as the record of what was held.
    const code = invitationClaim.normalize(req.body?.invitationCode);
    const email = String(req.body?.email ?? '').trim();
    delete req.body.invitationCode;
    if (!code) {
      event('ncb_gateway_registration_without_invitation', { requestId });
      return reply(res, 403, { status: 'error', data: null, error: 'invitation_required' });
    }
    const begun = await invitationClaim.begin({ code, email });
    if (!begun.ok) {
      const status = begun.outcome === 'invitation_exhausted' || begun.outcome === 'already_claimed' ? 409
        : begun.outcome === 'code_not_found' || begun.outcome === 'code_required' ? 403
          : 503;   // store unavailable / read failed / claim unavailable are deployment faults, never the caller's
      event('ncb_gateway_registration_invitation_refused', { outcome: begun.outcome, status, requestId });
      return reply(res, status, { status: 'error', data: null, error: begun.outcome, detail: begun.reason || null });
    }
    req.invitationReservation = begun;
    // The release rule, stated because the alternative strands records: a reservation taken for a
    // request that NEVER CREATED AN ACCOUNT is given back, so a wrong password or an upstream outage
    // cannot empty a ten-record pool one failed attempt at a time. A reservation that outlived an
    // account creation is NEVER released here — that is the case recovery exists for, and dropping it
    // would hand a spent-but-unlinked record to the next caller. Nothing in this hook looks at age.
    //
    // The third case is the one that costs a record either way, and it is decided by evidence rather
    // than by optimism: when the vendor's answer never arrived (`invitationAccountOutcomeUnknown`) we
    // cannot prove no account was created, so the reservation is HELD. Releasing it would put this
    // record back in play for a second registrant while the first one's account may already exist at
    // NCB — the exact double-assignment the reservation exists to prevent. The stranded record is the
    // lesser fault and it is recoverable: the account that authenticates with this address finishes it
    // through the authorized recovery route, and an operator marks it `abandoned` if that never comes.
    res.on('finish', () => {
      const held = req.invitationReservation;
      if (!held || held.settled || req.invitationAccountCreated) return;
      if (req.invitationAccountOutcomeUnknown) {
        held.settled = 'held_for_ambiguous_outcome';
        event('invitation_reservation_held_ambiguous_outcome', { recordId: held.recordId, requestId });
        return;
      }
      Promise.resolve(invitationClaim.release(held))
        .then((done) => { if (done && done.ok !== true) event('invitation_release_unconfirmed', { recordId: held.recordId, reason: done.reason }); })
        .catch(() => event('invitation_release_failed', { recordId: held.recordId }));
    });
    return next();
  });

  for (const route of AUTH_ROUTES) {
    router[route.method](route.path, async (req, res) => {
      const requestId = res.get('X-Request-Id') || null;
      const retryAfter = hit(req.ip);
      if (retryAfter > 0) {
        res.setHeader('Retry-After', String(retryAfter));
        event('ncb_gateway_rate_limited', { verb: route.verb, requestId });
        return reply(res, 429, { status: 'error', data: null, error: 'too_many_attempts' });
      }

      const needed = route.verb !== 'sign-in/email' && route.verb !== 'sign-up/email'
        && route.verb !== 'forget-password' && route.verb !== 'reset-password';
      // WHY REGISTRATION IS CLOSED HERE, and why "the release note says so" was not acceptable.
      //
      // Login.jsx checks the invitation code in the browser and only then calls sign-up, so on this
      // build NOTHING above the vendor stands between a visitor and an account: POST the verb with no
      // code at all and NCB creates the user. Meanwhile the write policy added in this same change set
      // refuses the claim (`update/user_codes` is read-only for players, because that table is shared
      // by every account and a general CRUD path must not let one of them spend another's invitation).
      // So the two halves together produce an account whose invitation is never marked used and a UI
      // that then reports failure — registration that is simultaneously open and broken, which is the
      // worst combination. Closed by default until claiming moves to a server-side route that can
      // verify the code, bind it to the new account and record `registered_user_id`.
      //
      // `NCB_GATEWAY_ALLOW_SIGN_UP=1` reopens it without a redeploy; that is the operator's lever, not
      // a code change, and 403 here answers before any upstream call is made, so no account can be
      // created by a request that reaches this process.
      if (route.verb === 'sign-up/email' && !signUpAllowed) {
        event('ncb_gateway_sign_up_refused', { verb: route.verb, requestId });
        return reply(res, 403, {
          status: 'error', data: null, error: 'sign_up_unavailable',
          detail: 'registration is temporarily closed on this deployment; signing in still works'
        });
      }
      // Only the fields this verb is defined to take reach the vendor; the count of what was dropped is
      // logged as a number, never as the values, which could be a password.
      const projected = projectAuthBody(route.verb, req.body);
      if (projected.dropped > 0) event('ncb_gateway_body_fields_dropped', { verb: route.verb, count: projected.dropped, requestId });
      const upstreamBodyJson = JSON.stringify(projected.body);
      let authCall = { kind: 'unreachable', httpStatus: 0 };
      if (needed) {
        const resolved = resolveHandle(req);
        if (resolved.kind === 'misconfigured') {
          event('ncb_gateway_seal_unconfigured', { verb: route.verb, requestId });
          return reply(res, 503, { status: 'error', data: null, error: 'gateway_unconfigured' });
        }
        if (resolved.kind !== 'ok') {
          // `not_sealed` is the honest answer for a stale NCB body token left in localStorage from
          // the old proxy: it is not a session here, and it is renewed the moment the app signs in
          // again. It is 401 because the credential really is unusable — and only then.
          event('ncb_gateway_unauthenticated', { reason: resolved.kind, verb: route.verb, requestId });
          return reply(res, 401, { status: 'error', data: null, error: 'invalid_session', reason: resolved.kind });
        }
        authCall = await ncb.auth(route.verb, {
          method: route.method === 'get' ? 'GET' : 'POST',
          ...(route.method === 'get' ? {} : { body: upstreamBodyJson }),
          cookie: resolved.cookie
        });
      } else {
        authCall = await ncb.auth(route.verb, { method: 'POST', body: upstreamBodyJson });
      }

      if (authCall.kind === 'unreachable' || authCall.kind === 'upstream_error') {
        // Never 401. This is the branch the outage turned on.
        event('ncb_gateway_upstream_unavailable', { verb: route.verb, kind: authCall.kind, requestId });
        const held = route.verb === 'sign-up/email' && signUpOutcomeIsAmbiguous(authCall.httpStatus);
        if (held) req.invitationAccountOutcomeUnknown = true;
        return reply(res, 503, {
          status: 'error', data: null, error: 'auth_service_unavailable',
          // Said to the client because the alternative is worse than it looks: a browser that treats a
          // timeout as a plain failure retries with ANOTHER code, and each retry quietly takes a
          // record out of the pool. This says the attempt is unfinished against THIS code and that the
          // authorized recovery route is what settles it.
          ...(held ? { invitationHeldForRecovery: true } : {})
        });
      }
      if (authCall.kind === 'secret_key_rejected') {
        event('ncb_gateway_secret_rejected', { verb: route.verb, requestId });
        return reply(res, 502, { status: 'error', data: null, error: 'gateway_misconfigured' });
      }
      if (authCall.kind !== 'ok') {
        /* THE UPSTREAM ANSWER IS A FACT WITH THREE KINDS, and collapsing them was the original bug.

           401 means the credentials were checked and refused: the player can act on that, so it is a
           401 here too. 403 means the vendor REFUSED on policy grounds — an untrusted origin, an
           unverified or banned account, a route restriction — none of which a player can fix by typing
           their password again, and all of which an operator has to see as a server-side fault. 429
           means the vendor is throttling this address, and answering it with anything but 429 invites
           the client to retry straight into a longer window.

           The old code answered every one of those with a 400, which told the UI "bad input" about a
           gateway it knew nothing about. The vendor's own error CODE is carried out — whitelisted to a
           token-shaped string, never a free-text body — because on the next single attempt it is the
           difference between "fix the headers" and "this account is not verified". */
        const upstreamCode = String(authCall.json?.code ?? '').trim();
        const safeCode = /^[A-Z0-9_-]{2,48}$/.test(upstreamCode) ? upstreamCode : null;
        const mapped = authUpstreamStatus(authCall.httpStatus);
        if (mapped.retryAfterSeconds) res.setHeader('Retry-After', String(mapped.retryAfterSeconds));
        event('ncb_gateway_rejected', {
          verb: route.verb, status: authCall.httpStatus, mapped: mapped.status, code: safeCode, requestId
        });
        // A 408 lands here rather than in the outage branch above (the transport classifies it as an
        // unrecognised answer), and it belongs to the ambiguous half: the vendor had the request and
        // ran out of time, which is not the same as having refused it. Every other status that reaches
        // this line is a 4xx decision — bad credentials, duplicate email, a policy refusal — where no
        // account exists and the record genuinely goes back in the pool.
        const held = route.verb === 'sign-up/email' && signUpOutcomeIsAmbiguous(authCall.httpStatus);
        if (held) req.invitationAccountOutcomeUnknown = true;
        return reply(res, mapped.status, {
          status: 'error', data: null, error: mapped.error, code: safeCode,
          upstream_status: authCall.httpStatus, httpStatus: mapped.status,
          ...(held ? { invitationHeldForRecovery: true } : {})
        });
      }

      const upstreamBody = authCall.json ?? {};
      const user = upstreamBody?.user ?? upstreamBody?.data?.user ?? null;
      // From this line on, an account exists at the vendor. Whatever happens next — a refused claim,
      // a missing cookie, a body this route cannot turn into a session — the reservation must survive,
      // because releasing it would put a record behind an account that was already created.
      if (route.verb === 'sign-up/email' && user?.id) req.invitationAccountCreated = true;

      if (route.renews && !user?.id) {
        // The authority answered, and answered "nobody". That is an invalid session — the opposite
        // case from the 503 above, and the distinction is the whole reason a player with a working
        // login is not logged out during an outage. A signed-out upstream session must never be
        // relayed as a 200 whose `data` happens to be null.
        //
        // This rule belongs to get-session ONLY. Sign-out and change-password legitimately answer
        // without a user object, and demanding one there turns a successful sign-out into a 401.
        event('ncb_gateway_upstream_no_session', { verb: route.verb, requestId });
        return reply(res, 401, { status: 'error', data: null, error: 'invalid_session', reason: 'upstream_no_session' });
      }

      if (route.mints && user?.id && authCall.cookiePair) {
        // THE CLAIM, recorded by NodeSend with the identity the vendor just returned — not one the
        // caller named. It happens only on the path that hands out a session: if the upstream gave no
        // cookie there is no account this relay can sign anyone into, so the code stays unused rather
        // than being spent on an account nobody can reach. A failed or unconfirmed claim is reported
        // in the body and never turned into a silent success; the client keeps its retry, and the
        // retry goes through the same authorized route rather than a CRUD write.
        let claimed = null;
        if (route.verb === 'sign-up/email' && req.invitationReservation) {
          const held = req.invitationReservation;
          const outcome = await invitationClaim.finish({
            code: held.code, recordId: held.recordId, reservationId: held.reservationId,
            userId: String(user.id), emailHash: held.emailHash
          });
          // `settled` means the reservation has been driven to a conclusion by this request, either
          // way: the finish hook must not release what is now either spent or awaiting recovery.
          if (held.settled !== 'released') held.settled = outcome.ok ? 'claimed' : 'held_for_recovery';
          claimed = { invitationClaimed: outcome.ok === true, invitationClaim: outcome.outcome };
          if (outcome.outcome === 'claim_conflict') {
            event('ncb_gateway_registration_conflict', { recordId: held.recordId, requestId });
          }
        }
        const token = seal.seal({
          cookie: authCall.cookiePair, userId: String(user.id), instance: ncb.instance,
          email: String(user.email || '')
        });
        // `token` at the top level is what src/api.js reads (api.js:131-137). Its own NCB body token,
        // if there is one, is deliberately NOT forwarded: it is not a session channel (measured), and
        // two plausible-looking tokens in one response is how a future reader re-introduces the bug.
        return reply(res, 200, {
          status: 'success', data: { user, session: upstreamBody?.session ?? upstreamBody?.data?.session ?? null }, token,
          ...(claimed || {})
        });
      }

      if (route.renews && user?.id) {
        const resolved = resolveHandle(req);
        // Re-mint so the expiry slides with real use. A player who keeps working never sees a
        // sign-out; a stolen handle stops being useful on its own, without a server-side map.
        const token = seal.seal({
          cookie: resolved.cookie, userId: String(user.id), instance: ncb.instance,
          email: String(user.email || upstreamBody?.session?.email || '')
        });
        return reply(res, 200, { status: 'success', data: { user, session: upstreamBody?.session ?? upstreamBody?.data?.session ?? null }, token });
      }

      if (route.verb === 'sign-out') {
        return reply(res, 200, { status: 'success', data: null });
      }
      return reply(res, 200, { status: 'success', data: upstreamBody?.data ?? upstreamBody });
    });
  }

  function dataGuard(verbName) {
    return async (req, res) => {
      const table = String(req.params.table || '');
      const id = String(req.params.id || '');
      if (!tables.includes(table)) {
        event('ncb_gateway_table_refused', { table, verb: verbName });
        return reply(res, 403, { status: 'error', data: null, error: 'table_not_allowed' });
      }
      // Refused BEFORE the credential is even parsed: a write an administrator owns should read as a
      // refusal at the table, not as a session problem, and the caller learns the true reason.
      const permission = writePermission(verbName, table);
      if (!permission.allowed) {
        event('ncb_gateway_write_refused', { table, verb: verbName, policy: permission.policy });
        return reply(res, 403, {
          status: 'error', data: null, error: 'write_not_allowed',
          detail: `this table is ${permission.policy}-only through the player gateway`
        });
      }
      if (id !== '' && !/^[A-Za-z0-9_-]{1,64}$/.test(id)) {
        return reply(res, 400, { status: 'error', data: null, error: 'bad_row_id' });
      }
      const query = String(req.url.split('?')[1] || '');
      if (query.length > MAX_QUERY_CHARS) {
        return reply(res, 400, { status: 'error', data: null, error: 'query_too_long' });
      }

      const resolved = resolveHandle(req);
      if (resolved.kind === 'misconfigured') {
        return reply(res, 503, { status: 'error', data: null, error: 'gateway_unconfigured' });
      }
      if (resolved.kind !== 'ok') {
        event('ncb_gateway_data_unauthenticated', { reason: resolved.kind, verb: verbName, table });
        return reply(res, 401, { status: 'error', data: null, error: 'invalid_session', reason: resolved.kind });
      }

      const body = ['create', 'update'].includes(verbName) && req.body !== undefined
        ? JSON.stringify(req.body) : undefined;
      const result = await ncb.data(verbName, table, { id, query, body, cookie: resolved.cookie });

      if (result.kind === 'unreachable' || result.kind === 'upstream_error') {
        // 502: the caller's session is fine and NCB is the thing that failed. Answering 401 here is
        // how a transient upstream fault becomes a mass sign-out.
        event('ncb_gateway_data_upstream_unavailable', { verb: verbName, table, kind: result.kind });
        return reply(res, 502, { status: 'error', data: null, error: 'storage_unavailable' });
      }
      if (result.kind === 'secret_key_rejected') {
        // Unreachable by construction; kept because it is the failure mode this whole file exists to
        // prevent, and it must be loud rather than silent if it ever somehow happens.
        event('ncb_gateway_secret_rejected', { verb: verbName, table });
        return reply(res, 502, { status: 'error', data: null, error: 'gateway_misconfigured' });
      }
      if (result.kind === 'not_found') {
        return reply(res, 404, { status: 'error', data: null, error: 'not_found_or_not_yours' });
      }
      if (result.kind === 'invalid_session') {
        event('ncb_gateway_upstream_session_rejected', { verb: verbName, table });
        return reply(res, 401, { status: 'error', data: null, error: 'invalid_session', reason: 'upstream_rejected' });
      }
      if (result.kind !== 'ok') {
        event('ncb_gateway_data_rejected', { verb: verbName, table, status: result.httpStatus });
        return reply(res, 400, { status: 'error', data: null, error: 'request_rejected' });
      }
      return reply(res, 200, result.json ?? { status: 'success', data: null });
    };
  }

  for (const [method, verbName] of Object.entries(DATA_VERBS)) {
    router[method](`/ncb/data/${verbName}/:table`, dataGuard(verbName));
    if (verbName !== 'create') router[method](`/ncb/data/${verbName}/:table/:id`, dataGuard(verbName));
  }

  // A named read of the caller's own identity, used by the tests and by any future route that must
  // not re-implement handle parsing.
  router.get('/ncb/whoami', (req, res) => {
    const resolved = resolveHandle(req);
    if (resolved.kind !== 'ok') return reply(res, 401, { status: 'error', data: null, error: 'invalid_session', reason: resolved.kind });
    return reply(res, 200, {
      status: 'success',
      data: { userIdHash: require('node:crypto').createHash('sha256').update(resolved.session.userId).digest('hex').slice(0, 8), remainingMs: Math.max(0, resolved.session.expiresAt - Date.now()) }
    });
  });

  /* THE ONE ANONYMOUS READ: an invitation code, looked up before any account exists.

     `publicDataFetch('read/user_codes?code=…')` is what `Login.jsx:172` calls to decide whether a
     registration may proceed, and it runs while the visitor has nothing to authenticate with. The
     native host has no public family (measured: four candidate paths, all an HTML 404), so the only
     honest implementation is a read made on this relay's own service account — the same dedicated
     club account, with the same session-cookie discipline, never the database secret.

     Which is exactly why the route is narrow rather than general:

       * one table, named here, not configured;
       * one row selected by equality on `code` OR `id` — an absent filter is REFUSED, because an
         unfiltered read of an invitation table is a list of live codes handed to whoever asks;
       * the answer is projected to the four fields the registration flow reads, so a column added to
         the table later cannot leak through this route by accident;
       * rate-limited on its own bucket, tighter than sign-in, because it is an unauthenticated
         existence oracle;
       * and if no service account is configured it answers 503 with a named reason, so a registration
         failure reads as an outage rather than as "your code is invalid". */
  const publicBuckets = new Map();
  function publicHit(ip) {
    const now = Date.now();
    const entry = publicBuckets.get(ip);
    if (!entry || now - entry.startedAt >= AUTH_RATE_WINDOW_MS) {
      if (publicBuckets.size >= MAX_RATE_BUCKETS) publicBuckets.delete(publicBuckets.keys().next().value);
      publicBuckets.set(ip, { startedAt: now, count: 1 });
      return 0;
    }
    entry.count += 1;
    if (entry.count <= PUBLIC_RATE_MAX) return 0;
    return Math.max(1, Math.ceil((AUTH_RATE_WINDOW_MS - (now - entry.startedAt)) / 1000));
  }

  router.get('/ncb/public-data/read/:table', async (req, res) => {
    const table = String(req.params.table || '');
    if (!PUBLIC_TABLES.includes(table)) {
      event('ncb_gateway_public_table_refused', { table });
      return reply(res, 403, { status: 'error', data: null, error: 'table_not_allowed' });
    }
    const retryAfter = publicHit(String(req.ip || 'unknown'));
    if (retryAfter > 0) {
      res.setHeader('Retry-After', String(retryAfter));
      event('ncb_gateway_public_rate_limited', { table });
      return reply(res, 429, { status: 'error', data: null, error: 'too_many_attempts' });
    }
    const params = new URLSearchParams(String(req.url.split('?')[1] || ''));
    // `db`-family and secret-bearing names are refused outright. `Instance` is NOT one of them: the
    // client's own transport appends `?Instance=` to every URL it builds (src/api.js:20), the data
    // family strips it rather than rejecting the request, and refusing it here would break
    // registration with a 400 that no browser can explain. It is dropped, and the relay's own
    // instance is the only one the read can reach.
    for (const smuggled of ['key', 'secret_key', 'api_key', 'apikey', 'token', 'access_token', 'db']) {
      if (params.has(smuggled)) return reply(res, 400, { status: 'error', data: null, error: 'query_not_allowed' });
    }
    params.delete('Instance');
    const code = String(params.get('code') || '').trim();
    const id = String(params.get('id') || '').trim();
    if (params.size > (code ? 1 : 0) + (id ? 1 : 0)) {
      // Anything beyond the one equality filter is an attempt to widen the read.
      return reply(res, 400, { status: 'error', data: null, error: 'query_not_allowed' });
    }
    if (!code && !id) {
      // No equality filter means "list them". Never.
      event('ncb_gateway_public_unfiltered_refused', { table });
      return reply(res, 400, { status: 'error', data: null, error: 'filter_required' });
    }
    // ONE validator, shared with the relay's own invitation routes (ncb/invitationCode.js). The rule
    // this replaces demanded 4-64 characters from [A-Za-z0-9-], which rejected the owner's reserved
    // test code `777` with 400 bad_code while POST /auth/validate-invitation accepted the same string
    // as valid — one field with two opinions, and the browser always met the strict one.
    const normalizedCode = normalizeInvitationCode(code);
    if (code && !normalizedCode) return reply(res, 400, { status: 'error', data: null, error: 'bad_code' });
    // A trimmed code is what the rest of this route filters on; `code` itself stays the caller's
    // string, because it is a const in this handler and rewriting it would be the kind of mutation
    // that hides a mismatch between what was asked and what was answered.
    const filterCode = normalizedCode || code;
    if (id && !/^[A-Za-z0-9_-]{1,64}$/.test(id)) return reply(res, 400, { status: 'error', data: null, error: 'bad_row_id' });
    if (typeof guestRead !== 'function') {
      event('ncb_gateway_public_reader_absent', { table });
      return reply(res, 503, { status: 'error', data: null, error: 'invitation_lookup_unavailable' });
    }
    const filter = filterCode ? { code: filterCode } : { id };
    const read = await guestRead({ table, ...filter });
    if (!read || read.ok !== true) {
      event('ncb_gateway_public_read_failed', { table, reason: read?.reason || 'guest_read_failed' });
      return reply(res, 503, { status: 'error', data: null, error: read?.reason || 'invitation_lookup_unavailable' });
    }
    const rows = (Array.isArray(read.rows) ? read.rows : [])
      .map((row) => Object.fromEntries(PUBLIC_FIELDS.filter((f) => row?.[f] !== undefined).map((f) => [f, row[f]])));
    // The vendor's list envelope, because that is the shape `Login.jsx` branches on.
    return reply(res, 200, { status: 'success', data: rows, metadata: { page: 1, limit: rows.length, hasMore: false, hasPrev: false } });
  });

  function health() {
    // Booleans and counts only. No origin list contents, no table names beyond a count, no key.
    return {
      configured: seal.configured && ncb.configured,
      reason: !seal.configured ? seal.reason
        : (!ncb.configured ? 'ncb_api_urls_unconfigured' : null),
      routes: AUTH_ROUTES.length + (Object.keys(DATA_VERBS).length * 2 - 1) + 2,
      authVerbs: AUTH_ROUTES.length,
      dataVerbs: Object.keys(DATA_VERBS).length,
      allowedOriginsConfigured: allowedOrigins.length,
      tablesAllowlisted: tables.length,
      // The anonymous invitation read: whether it exists at all, and — a count, never the name —
      // how many fields a returned row can carry.
      publicReadServed: typeof guestRead === 'function',
      publicReadFields: PUBLIC_FIELDS.length,
      // Whether a visitor can create an account through this process at all. A release-readiness
      // question, so it belongs in the health report rather than in an operator's memory.
      signUpAllowed,
      // Whether enabling registration would actually be safe: with the lever on and no privileged
      // claim channel, this route refuses rather than creating unlinkable accounts.
      invitationClaimWired: Boolean(invitationClaim),
      sessionState: 'stateless_sealed_handle',
      restartSafe: true,
      upstreamCookieExposedToClient: false,
      secretKeyUsableByPlayers: false
    };
  }

  return {
    router,
    configured: seal.configured && ncb.configured,
    reason: seal.configured ? (ncb.configured ? null : 'ncb_api_urls_unconfigured') : seal.reason,
    health,
    // Exposed for the gate only: these are the strings that make the two allow-lists auditable.
    _internals: { allowedOrigins, tables, neverThroughGateway: NEVER_THROUGH_THE_GATEWAY, AUTH_VERBS }
  };
}

module.exports = { buildNcbGateway, createCorsResolver, authUpstreamStatus, signUpOutcomeIsAmbiguous, AUTH_ROUTES, DEFAULT_TABLES, NEVER_THROUGH_THE_GATEWAY };
