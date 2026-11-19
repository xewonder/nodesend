/*
LIVE NCB SMOKE TEST — executed by the owner, because the credentials are the owner's to hold.

This is the half of the verification a mocked upstream cannot settle: a real session against the real
NoCodeBackend instance, and whether per-user row scoping actually holds when NCB itself decides.
Nothing here is simulated: when a variable is absent, the affected step reports NOT TESTED with the
name of what is missing, and the run still finishes.

READS FROM THE ENVIRONMENT (never printed, never logged, never written to disk)
  NCB_TEST_EMAIL_A / NCB_TEST_PASSWORD_A          authorised test account A
  NCB_TEST_EMAIL_B / NCB_TEST_PASSWORD_B          authorised test account B
  NCB_SESSION_SEAL_KEY                             any value of >= 32 characters, test-only
  NCB_GATEWAY_ALLOWED_ORIGINS                     optional; defaults to the localhost dev origin
  CLUB_NCB_EMAIL / CLUB_NCB_PASSWORD + CLUB_NCB_SCHEMA_JSON|_FILE   optional; enables the clubs and
                                                   invitation steps. Without them those routes answer
                                                   their own named 503, which this run reports as
                                                   NOT TESTED rather than calling it a failure.
  LIVE_TEST_INVITATION_CODE                       optional; an EXISTING disposable code, read only
  LIVE_ALLOW_SIGNOUT=1                            opt in to the sign-out step

NEVER DOES
  * writes to no table — every data call is a GET. The only state change available is sign-out, and
    that is opt-in, because ending a live session is a side effect rather than an observation. It is
    never performed against the club service account, whose session this relay caches deliberately.
  * creates no invitation, consumes none, alters none.
  * prints no credential: emails and ids appear as 8-hex SHA-256 prefixes, handles as a ten-character
    prefix and length, and the upstream cookie appears nowhere — which the run asserts about itself.

USAGE — one paste, from the NodeSend directory:

  set NCB_TEST_EMAIL_A=...&& set NCB_TEST_PASSWORD_A=...&& set NCB_TEST_EMAIL_B=...&& set NCB_TEST_PASSWORD_B=...&& set NCB_SESSION_SEAL_KEY=...&& node verify-ncb-live.mjs

Restart persistence needs no second paste: the run spawns a FRESH child process that boots the relay
again and validates the handle the first process obtained — which is exactly what a container restart
does to a design that keeps no session table.
*/

import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(HERE, 'noop.cjs'));

const AUTH_URL = process.env.NCB_AUTH_API_URL || 'https://app.nocodebackend.com/api/user-auth';
const DATA_URL = process.env.NCB_DATA_API_URL || 'https://app.nocodebackend.com/api/data';
const INSTANCE = process.env.NCB_INSTANCE || '55954_bridgemind';
const LAMBDA = process.env.NCB_PROXY_BASE || 'https://rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url.us-east-2.on.aws';
const SEAL_KEY = String(process.env.NCB_SESSION_SEAL_KEY || '');
const ORIGINS = process.env.NCB_GATEWAY_ALLOWED_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173';
const ALLOW_SIGNOUT = process.env.LIVE_ALLOW_SIGNOUT === '1';
const INVITATION_CODE = String(process.env.LIVE_TEST_INVITATION_CODE || '').trim();

const accounts = {
  A: { email: String(process.env.NCB_TEST_EMAIL_A || ''), password: String(process.env.NCB_TEST_PASSWORD_A || '') },
  B: { email: String(process.env.NCB_TEST_EMAIL_B || ''), password: String(process.env.NCB_TEST_PASSWORD_B || '') }
};
const club = { email: String(process.env.CLUB_NCB_EMAIL || ''), password: String(process.env.CLUB_NCB_PASSWORD || '') };

// Nothing that identifies a person appears in the output. A hash prefix still tells two accounts apart.
const tag = (value) => crypto.createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 8);
const hint = (value) => `${String(value || '').slice(0, 10)}…(len ${String(value || '').length})`;

const missing = [];
if (SEAL_KEY.length < 32) missing.push('NCB_SESSION_SEAL_KEY (at least 32 characters)');
if (!accounts.A.email || !accounts.A.password) missing.push('NCB_TEST_EMAIL_A / NCB_TEST_PASSWORD_A');
if (!accounts.B.email || !accounts.B.password) missing.push('NCB_TEST_EMAIL_B / NCB_TEST_PASSWORD_B');
if (missing.length) {
  console.log('LIVE SMOKE TEST CANNOT RUN — absent from this environment:');
  for (const m of missing) console.log(`  - ${m}`);
  console.log('\nNothing was contacted and nothing was written. This is NOT TESTED, not a pass.');
  process.exit(3);
}

// ── audit both legs: browser→relay carries the handle; relay→NCB must carry no secret ──
const outbound = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (url, init = {}) => {
  let host = '', pathname = '';
  try { const u = new URL(String(url)); host = u.host; pathname = u.pathname; } catch { /* not a url */ }
  const names = Object.keys(init?.headers ?? {}).map((k) => k.toLowerCase());
  outbound.push({ host, pathname, authorization: names.includes('authorization'), cookie: names.includes('cookie') });
  return realFetch(url, init);
};

process.env = {
  ...process.env,
  BRIDGE_API_KEY: process.env.BRIDGE_API_KEY || 'live-smoke-relay-key',
  NCB_TRANSPORT: 'native',
  NCB_AUTH_API_URL: AUTH_URL,
  NCB_DATA_API_URL: DATA_URL,
  NCB_PROXY_BASE: LAMBDA,
  NCB_INSTANCE: INSTANCE,
  NCB_SESSION_SEAL_KEY: SEAL_KEY,
  NCB_GATEWAY_ALLOWED_ORIGINS: ORIGINS,
  ...(club.email && club.password ? { CLUB_NCB_EMAIL: club.email, CLUB_NCB_PASSWORD: club.password } : {}),
  NODESEND_PRIVATE_KEY_B64: ''
};
delete process.env.NODESEND_PRIVATE_KEY_PEM;
delete process.env.NCB_ALLOW_INSECURE_UPSTREAM;   // live NCB is https; the loopback escape stays off

const bridge = require(path.join(HERE, 'bridge.js'));
const relay = bridge.app.listen(0, '127.0.0.1');
await new Promise((r) => relay.once('listening', r));
const BASE = `http://127.0.0.1:${relay.address().port}`;
const ORIGIN = (ORIGINS.split(',')[0] || '').trim();

const results = [];
const record = (name, pass, detail = '') => { results.push({ name, pass: pass === true, detail: String(detail ?? '').slice(0, 200) }); return pass === true; };
const notTested = (name, why) => results.push({ name, pass: null, detail: `NOT TESTED — ${why}` });
const call = async (method, route, { token = '', body } = {}) => {
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text, headers: Object.fromEntries(res.headers.entries()) };
};

console.log(`relay ${BASE}  ->  ${AUTH_URL}`);
console.log(`accounts ${tag(accounts.A.email)} / ${tag(accounts.B.email)}   instance ${INSTANCE}\n`);

// ── 1-2. sign in both users, and look at what the client is handed ─────────
const signed = {};
for (const key of ['A', 'B']) {
  const r = await call('POST', '/ncb/auth/sign-in/email', { body: { email: accounts[key].email, password: accounts[key].password } });
  const user = r.json?.data?.user ?? {};
  signed[key] = {
    status: r.status, handle: String(r.json?.token ?? ''), userId: String(user.id ?? ''),
    ok: r.status === 200 && r.json?.status === 'success' && Boolean(user.id)
  };
  record(`1${key}. account ${key} signs in against live NCB through the gateway`,
    signed[key].ok && signed[key].handle.startsWith('ncbs1.'),
    `status ${r.status}, handle ${hint(signed[key].handle)}, user ${tag(signed[key].userId)}`);
  record(`2${key}. no vendor cookie, and no Set-Cookie, reaches the client`,
    !JSON.stringify(r.json).includes('__Secure-better-auth') && !('set-cookie' in r.headers),
    Object.keys(r.headers).join(','));
}
record('1. both accounts received DIFFERENT handles for different identities',
  Boolean(signed.A.handle) && signed.A.handle !== signed.B.handle && signed.A.userId !== signed.B.userId,
  `${tag(signed.A.userId)} vs ${tag(signed.B.userId)}`);

// ── 3. get-session, and renewal ────────────────────────────────────────────
const sessionA = await call('GET', '/ncb/auth/get-session', { token: signed.A.handle });
record('3a. get-session resolves the live identity from the handle',
  sessionA.status === 200 && sessionA.json?.status === 'success' && sessionA.json?.data?.user?.id === signed.A.userId,
  `${sessionA.status} user ${tag(sessionA.json?.data?.user?.id)}`);
record('3b. get-session re-mints the handle (sliding expiry, no server-side session table)',
  typeof sessionA.json?.token === 'string' && sessionA.json.token.startsWith('ncbs1.') && sessionA.json.token !== signed.A.handle,
  `${hint(signed.A.handle)} -> ${hint(sessionA.json?.token)}`);
const renewedWorks = await call('GET', '/ncb/data/read/user_settings?limit=1', { token: sessionA.json?.token });
const oldWorks = await call('GET', '/ncb/data/read/user_settings?limit=1', { token: signed.A.handle });
record('3c. both the renewed and the previous handle work (two tabs, no forced sign-out)',
  renewedWorks.status === 200 && oldWorks.status === 200, `${renewedWorks.status}/${oldWorks.status}`);

// ── 4. authenticated private-table reads ──────────────────────────────────
const reads = {};
for (const key of ['A', 'B']) {
  const r = await call('GET', '/ncb/data/read/user_settings?limit=20&sort=id&order=asc', { token: signed[key].handle });
  const l = await call('GET', '/ncb/data/read/llm_preferences?limit=20', { token: signed[key].handle });
  reads[key] = {
    settings: Array.isArray(r.json?.data) ? r.json.data : null,
    prefs: Array.isArray(l.json?.data) ? l.json.data : null,
    status: r.status, prefStatus: l.status, envelope: r.json?.status === 'success' && 'metadata' in (r.json ?? {})
  };
  record(`4${key}. account ${key} reads the app's own tables through the gateway (policy is asserted in section 5, not assumed here)`,
    r.status === 200 && l.status === 200 && reads[key].envelope,
    `user_settings rows ${reads[key].settings?.length ?? 'n/a'}, llm_preferences rows ${reads[key].prefs?.length ?? 'n/a'}`);
}

// ── 5. WHOSE ROWS ARE THESE: policy first, then the assertion it supports ───
//
// This section used to assert cross-user isolation on `user_settings` and `llm_preferences`. That was
// a guess dressed as a test. Both tables are documented `shared_readwrite` — measured on 2026-11-17
// while the native PoC was being built, which is precisely why that PoC refused to compare them:
//
//   "Two tables, not one, and neither is user_settings: measured shared_readwrite, so a comparison
//    there would measure the ABSENCE of a policy and report it as a result."
//
// The shipped frontend is the second piece of evidence: every read it makes of these tables carries an
// explicit `?user_id=` filter (settingsService.js:191, :211), which nobody writes if the database
// already scopes rows by session. So a 5a/5b/5d "failure" on those tables is the vendor's policy
// working as configured, and treating it as an isolation breach would have led to a code change that
// fixed nothing while making the test agree with reality by assertion.
//
// What is actually in scope for this run, and provable WITHOUT writing anything:
//
//   * identity binding — each handle resolves to its own account, and no field the caller controls
//     changes that;
//   * EQUIVALENCE — for the same session, what the gateway returns is exactly what the vendor returns
//     to that session directly. This is the property that matters: if the two agree, the relay neither
//     widens a table nor narrows one, whatever that table's policy turns out to be. The test can do
//     the direct comparison because it minted the handle with its own sealing key, so it can open it
//     and use the wrapped cookie — in this process, for this comparison, and printed nowhere;
//   * on a table DECLARED private (the scratch table the earlier native test proved isolation on),
//     cross-user access must fail — and only if rows exist. An empty result is never read as a
//     restriction: that is the mistake the original PoC made and reported as NOT PROVEN.
const idsOf = (list) => new Set((list ?? []).map((r) => String(r.id)));
const SCRATCH_TABLE = String(process.env.LIVE_PRIVATE_TABLE || 'tmp_rls_isolation_20261119').replace(/[^A-Za-z0-9_]/g, '');
const TABLE_POLICY = [
  { table: 'user_settings', policy: 'shared', provenance: 'measured 2026-11-17; the frontend filters it by user_id itself' },
  { table: 'llm_preferences', policy: 'shared', provenance: 'same storage family as user_settings' },
  { table: SCRATCH_TABLE, policy: 'private', provenance: 'the table the native RLS test proved cross-user isolation on' }
];

// Open a handle this run minted, to obtain the session it wraps. Value is never printed.
const sealForComparison = bridge.ncbSeal({ env: process.env });
const cookieOf = (handle) => { const o = sealForComparison.open(handle); return o.ok ? o.session.cookie : ''; };
// `rowId` switches to the by-id route shape. It is not cosmetic: `?id=7` on the LIST route is an
// equality filter that answers 200 with nothing in it, while `/7` is the read the vendor answers 404
// for when the row is not yours. Comparing the wrong one reports a denial as a success — which the
// dry run caught on first pass.
const directVendorRead = async (cookie, table, query, rowId = '') => {
  if (!cookie) return { status: 0, rows: null, json: null, url: '(no cookie in the handle)' };
  const where = rowId ? `/${encodeURIComponent(rowId)}` : '';
  const url = `${DATA_URL}/read/${table}${where}?Instance=${encodeURIComponent(INSTANCE)}&${query}`;
  const res = await fetch(url, {
    headers: { Cookie: cookie, Origin: process.env.NCB_TRUSTED_ORIGIN || 'https://app.bridgemind.app' }
  });
  const json = await res.json().catch(() => null);
  return {
    status: res.status, url,
    rows: Array.isArray(json?.data) ? json.data : (json && json.data && !Array.isArray(json.data) ? [json.data] : null),
    json
  };
};

// 5a — identity is bound to the handle, and to nothing the caller controls.
const idA = await call('GET', '/ncb/auth/get-session', { token: signed.A.handle });
const idB = await call('GET', '/ncb/auth/get-session', { token: signed.B.handle });
record('5a. each handle resolves to its OWN account at the vendor, and the two are different',
  idA.json?.data?.user?.id === signed.A.userId && idB.json?.data?.user?.id === signed.B.userId
  && signed.A.userId !== signed.B.userId,
  `A=${tag(signed.A.userId)} B=${tag(signed.B.userId)} via gateway: ${tag(idA.json?.data?.user?.id)}/${tag(idB.json?.data?.user?.id)}`);

// 5b-5d — one pass per table: what the policy is, and whether the relay matches it exactly.
for (const { table, policy, provenance } of TABLE_POLICY) {
  const gA = await call('GET', `/ncb/data/read/${table}?limit=50`, { token: signed.A.handle });
  const gB = await call('GET', `/ncb/data/read/${table}?limit=50`, { token: signed.B.handle });
  if (gA.status === 502 && /storage_unavailable|upstream/.test(String(gA.json?.error))) {
    notTested(`5. ${table} (${policy})`, `the table did not answer (${gA.json?.error}) — not treated as a result either way`);
    continue;
  }
  const dA = await directVendorRead(cookieOf(signed.A.handle), table, 'limit=50');
  const rowsA = idsOf(gA.json?.data ?? []);
  const rowsB = idsOf(gB.json?.data ?? []);
  const directA = idsOf(dA.rows ?? []);
  const overlap = [...rowsA].filter((id) => rowsB.has(id));

  // The decisive one: same session, same table, gateway vs vendor directly. Equal row-id sets means the
  // relay forwards what the session is entitled to — no more (which would be exposure) and no less
  // (which would break the app).
  const sameSet = (x, y) => x.size === y.size && [...x].every((v) => y.has(v));
  record(`5b. gateway read of ${table} equals the vendor's own read for the same session`,
    dA.status === 200 && sameSet(rowsA, directA),
    `${policy}; via-gateway ${rowsA.size} row(s), direct ${directA.size} row(s), vendor status ${dA.status}`);

  if (policy === 'shared') {
    // Nothing is claimed about isolation here. The overlap is REPORTED, and it is only meaningful
    // because 5b already showed the vendor grants exactly the same rows directly.
    record(`5c. ${table} behaves as its declared ${policy} policy (no isolation claimed, none assumed)`,
      gA.status === 200 && gB.status === 200,
      `A ${rowsA.size}, B ${rowsB.size}, seen by both ${overlap.length} — ${provenance}`);
    continue;
  }

  if (gA.status === 403 && gA.json?.error === 'table_not_allowed') {
    // Naming this separately matters: without it the run would fall through to "no rows", report NOT
    // PROVEN, and leave the operator believing the table was empty when in fact the gateway was never
    // asked to serve it.
    notTested(`5d. cross-user isolation on the private table ${table}`,
      'the gateway allow-list does not serve it — add it to NCB_TABLE_ALLOWLIST for the test run only');
    continue;
  }
  if (rowsA.size === 0) {
    notTested(`5d. cross-user isolation on the private table ${table}`,
      'this session owns no row there and this run performs no writes — an empty result proves nothing, which is the error the original PoC made');
    continue;
  }
  const firstA = [...rowsA][0];
  const cross = await call('GET', `/ncb/data/read/${table}/${firstA}`, { token: signed.B.handle });
  const ownAgain = await call('GET', `/ncb/data/read/${table}/${firstA}`, { token: signed.A.handle });
  const crossDirect = await directVendorRead(cookieOf(signed.B.handle), table, 'limit=1', firstA);
  record(`5d. on the PRIVATE table ${table}, B cannot read A's row — and the vendor refuses it directly too`,
    cross.status === 404 && ownAgain.status === 200 && crossDirect.status === 404,
    `B via gateway ${cross.status}, B direct ${crossDirect.status} ${JSON.stringify(crossDirect.json).slice(0, 70)}, A ${ownAgain.status} (row ${tag(firstA)})`);
}

// A spoofed identity in the query must not produce rows the session could not otherwise see. On a
// shared table that filter is honoured by the vendor by design, so the test is equality with the
// direct call, not emptiness.
const spoofTable = 'user_settings';
const spoofed = await call('GET', `/ncb/data/read/${spoofTable}?user_id=${encodeURIComponent(signed.B.userId)}`, { token: signed.A.handle });
const spoofedDirect = await directVendorRead(cookieOf(signed.A.handle), spoofTable, `user_id=${encodeURIComponent(signed.B.userId)}`);
const spoofRows = idsOf(spoofed.json?.data ?? []);
const spoofDirectRows = idsOf(spoofedDirect.rows ?? []);
record('5e. a caller-supplied user_id filter yields exactly what the vendor itself returns for that session — the gateway adds no reach',
  spoofed.status === spoofedDirect.status && [...spoofRows].every((v) => spoofDirectRows.has(v)) && spoofRows.size === spoofDirectRows.size,
  `gateway ${spoofRows.size} row(s), direct ${spoofDirectRows.size} row(s)`);
const serverOnly = await call('GET', '/ncb/data/read/ai_quota_usage?limit=1', { token: signed.A.handle });
record('5f. the shared_readwrite quota tables stay unreachable through the player gateway (that exclusion is a control, not a convenience)',
  serverOnly.status === 403, `${serverOnly.status}`);

// ── 6. the other authenticated surfaces, with the same handle ─────────────
const quota = await call('GET', '/ai/quota', { token: signed.A.handle });
record('6a. GET /ai/quota accepts the sealed handle (no AWS, no service secret)',
  quota.status === 200 && quota.json?.error === undefined, `${quota.status} ${JSON.stringify(quota.json).slice(0, 110)}`);
const clubReady = Boolean(club.email && club.password && (process.env.CLUB_NCB_SCHEMA_JSON || process.env.CLUB_NCB_SCHEMA_FILE));
if (club.email && club.password && !clubReady) {
  notTested('6b. /clubs and /me/club with a sealed handle', 'CLUB_NCB_SCHEMA_JSON / _FILE not present, so the club store is inert by design');
} else if (clubReady) {
  const clubs = await call('GET', '/clubs', { token: signed.A.handle });
  const myClub = await call('GET', '/me/club', { token: signed.A.handle });
  record('6b. GET /clubs and GET /me/club accept the handle and keep the service-account model',
    clubs.status === 200 && myClub.status === 200, `${clubs.status}/${myClub.status}`);
} else {
  notTested('6b. /clubs and /me/club with a sealed handle', 'CLUB_NCB_EMAIL / CLUB_NCB_PASSWORD not present');
}
const trickster = await call('GET', '/trickster/bid/health', { token: signed.A.handle });
record('6c. the Trickster gateway accepts the sealed handle', trickster.status === 200, `${trickster.status}`);

// ── 7. anonymous invitation lookup (read-only, opt-in) ────────────────────
if (!INVITATION_CODE) {
  notTested('7. anonymous invitation-code lookup', 'LIVE_TEST_INVITATION_CODE not supplied');
} else if (!clubReady) {
  notTested('7. anonymous invitation-code lookup', 'no usable club service account, so the route fails closed by design');
} else {
  const look = await call('GET', `/ncb/public-data/read/user_codes?code=${encodeURIComponent(INVITATION_CODE)}`);
  const row = look.json?.data?.[0];
  record('7. an existing disposable code is readable anonymously, projected, and untouched',
    look.status === 200 && Array.isArray(look.json?.data)
    && (row ? Object.keys(row).every((k) => ['id', 'code', 'used', 'registered_user_id'].includes(k)) : true),
    `${look.status} rows ${look.json?.data?.length ?? 0}`);
  const again = await call('GET', `/ncb/public-data/read/user_codes?code=${encodeURIComponent(INVITATION_CODE)}`);
  record('7b. the read is idempotent — nothing was consumed or written',
    JSON.stringify(again.json?.data) === JSON.stringify(look.json?.data), `${again.status}`);
}
const unfiltered = await call('GET', '/ncb/public-data/read/user_codes');
record('7c. an unfiltered invitation read is refused (the route cannot enumerate codes)',
  unfiltered.status === 400, `${unfiltered.status}`);

// ── 8. restart persistence, in a genuinely fresh process ───────────────────
const child = spawn(process.execPath, [path.join(HERE, 'verify-ncb-live-child.mjs')], {
  cwd: HERE, env: { ...process.env, LIVE_CHILD_BASE_HANDLE: signed.A.handle }, encoding: 'utf8'
});
let childOut = '';
child.stdout.on('data', (d) => { childOut += String(d); });
child.stderr.on('data', (d) => { childOut += String(d); });
const childCode = await new Promise((resolve) => child.on('close', resolve));
const childLine = (childOut.match(/CHILD_RESULT:\{.*\}/) || [''])[0];
const childParsed = (() => { try { return JSON.parse(childLine.replace('CHILD_RESULT:', '')); } catch { return null; } })();
record('8. a NEW process with the same sealing key accepts the live handle (restart-safe)',
  childCode === 0 && childParsed?.session === true && childParsed?.data === true && childParsed?.cookieExposed === false,
  childParsed ? JSON.stringify(childParsed) : `exit ${childCode} ${childOut.slice(-120)}`);

// ── 9. sign-out, and rejection of the invalidated session ─────────────────
if (!ALLOW_SIGNOUT) {
  notTested('9. sign-out invalidates the session', 'set LIVE_ALLOW_SIGNOUT=1 to end a live test session (a side effect, so opt-in)');
} else {
  const out = await call('POST', '/ncb/auth/sign-out', { token: signed.B.handle });
  const after = await call('GET', '/ncb/auth/get-session', { token: signed.B.handle });
  const afterRead = await call('GET', '/ncb/data/read/user_settings?limit=1', { token: signed.B.handle });
  record('9a. sign-out answers the success envelope the client needs', out.status === 200 && out.json?.status === 'success', `${out.status}`);
  record('9b. the signed-out handle is then refused as invalid, not as an outage',
    after.status === 401 && afterRead.status === 401, `${after.status}/${afterRead.status}`);
  const aStill = await call('GET', '/ncb/data/read/user_settings?limit=1', { token: signed.A.handle });
  record('9c. and the other account’s session is unaffected', aStill.status === 200, `${aStill.status}`);
}
const garbage = await call('GET', '/ncb/auth/get-session', { token: 'ncbs1.' + 'A'.repeat(22) + '.x.y.z' });
record('9d. a forged handle is refused as invalid, and never opened against the vendor',
  garbage.status === 401 && ['invalid', 'not_sealed'].includes(garbage.json?.reason), JSON.stringify(garbage.json));

// ── 10. an NCB outage must not look like a sign-out ───────────────────────
{
  const dead = bridge.buildNcbGateway({ env: { ...process.env, NCB_AUTH_API_URL: 'https://127.0.0.1:1/api/user-auth', NCB_DATA_API_URL: 'https://127.0.0.1:1/api/data' } });
  const express = require('express');
  const app = express(); app.use(express.json()); app.use(dead.router);
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const b = `http://127.0.0.1:${srv.address().port}`;
  const r1 = await fetch(`${b}/ncb/auth/sign-in/email`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ORIGIN }, body: JSON.stringify({ email: accounts.A.email, password: accounts.A.password }) });
  const r2 = await fetch(`${b}/ncb/data/read/user_settings?limit=1`, { headers: { Origin: ORIGIN, Authorization: `Bearer ${signed.A.handle}` } });
  record('10. with NCB unreachable the gateway answers 503/502 and never the 401 that discards a session',
    r1.status === 503 && [502, 503].includes(r2.status), `sign-in ${r1.status}, data ${r2.status}`);
  await new Promise((r) => srv.close(r));
}

// ── 11. the AWS dependency is gone, measured ──────────────────────────────
// Scoped to the relay→vendor leg. The audit wrapper also sees this script's own calls to the relay,
// and if the relay happens to share a host with the upstream (as it does in a loopback dry run),
// matching on the hostname alone would count a browser request as a vendor one — and the whole point
// of 11a is that it never lies about which leg it measured.
const vendorHost = new URL(AUTH_URL).host;
const toVendor = outbound.filter((o) => o.host === vendorHost && o.pathname.startsWith('/api/'));
const toAws = outbound.filter((o) => /lambda-url|on\.aws/i.test(o.host));
record('11a. no relay→NCB request carried an Authorization header (the secret slot was never used)',
  toVendor.length > 0 && toVendor.every((o) => !o.authorization),
  JSON.stringify(toVendor.filter((o) => o.authorization).map((o) => o.pathname)));
record('11b. no request was made to the AWS Lambda host at all',
  toAws.length === 0, JSON.stringify(toAws.slice(0, 2)));
record('11c. and the relay did reach the vendor, so 11a/11b are not vacuous',
  toVendor.length >= 4 && toVendor.some((o) => o.cookie), `${toVendor.length} vendor request(s)`);

// ── 12. nothing secret in the run's own output ───────────────────────────
const health = await (await fetch(`${BASE}/health`)).json();
const dumped = JSON.stringify(results) + JSON.stringify(health);
record('12a. /health reports native transport with a live seal and no leaked base or key',
  health.ncb?.transport === 'native' && health.ncbGateway?.configured === true
  && !dumped.includes(SEAL_KEY) && !dumped.includes('lambda-url'), JSON.stringify(health.ncb));
record('12b. no account password, vendor cookie or sealing key appears in this report',
  !dumped.includes(accounts.A.password) && !dumped.includes(accounts.B.password)
  && !dumped.includes('__Secure-better-auth') && !(club.password && dumped.includes(club.password)), '');

await new Promise((r) => relay.close(r));
globalThis.fetch = realFetch;

const counts = { pass: 0, fail: 0, skipped: 0 };
for (const r of results) {
  if (r.pass === true) counts.pass += 1; else if (r.pass === false) counts.fail += 1; else counts.skipped += 1;
  const mark = r.pass === true ? 'PASS' : r.pass === false ? 'FAIL' : 'SKIP';
  console.log(`${mark}  ${r.name}${r.detail ? `   [${r.detail}]` : ''}`);
}
console.log(`\nLIVE SMOKE: ${counts.pass} passed, ${counts.fail} failed, ${counts.skipped} not tested`);
console.log(counts.fail === 0
  ? 'VERDICT: every live step that could be run passed.'
  : 'VERDICT: live failures present — do not deploy until they are explained.');
process.exit(counts.fail === 0 ? 0 : 1);
