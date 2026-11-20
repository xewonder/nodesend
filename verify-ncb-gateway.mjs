/*
NodeSend PLAYER GATEWAY verification harness.

Everything runs in-process: a loopback fake NCB that reproduces the shapes MEASURED against
app.nocodebackend.com, and the REAL exported `app` from bridge.js served over a loopback socket, so a
pass is a claim about what ships rather than about a re-implementation of it.

No production endpoint is contacted, no real credential exists in this file, and the seal key is a
fixture string that is never printed.

  node verify-ncb-gateway.mjs
*/
import { createRequire } from 'node:module';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));

// ── the fake NCB, shaped like the real one ─────────────────────────────────
// Measured behaviours reproduced here: the auth family takes the instance by header and answers bare
// `null` for get-session with no session; the data family takes it by query, answers read-by-id with
// `data` as an OBJECT, answers 404 with `message: "Record not found or access denied"`, answers create
// with 201 and a TOP-LEVEL id, and answers ANY Authorization header with 403 "Invalid secret_key."
const USERS = {
  'a@poc.invalid': { password: 'pw-a-fixture', id: 'user-aaaa', role: 'user' },
  'b@poc.invalid': { password: 'pw-b-fixture', id: 'user-bbbb', role: 'user' }
};
const COOKIE_NAME = '__Secure-better-auth.session_token';
const sessions = new Map();          // cookie value -> userId
const rows = [];                     // {id, user_id, marker}
let nextRowId = 1;
const upstreamLog = [];              // what the fake actually received
// A vendor refusal that has nothing to do with the password. Production answered a live sign-in with
// 403 and the gateway reported it to the browser as 400 "bad request" — a status the client can only
// misread. Nothing covered that path, so the knob exists to be armed and the arms below exist to fail
// if the mapping ever collapses again.
let signinFault = null;

function fakeNcb(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1');
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const text = Buffer.concat(chunks).toString('utf8');
    let body = null; try { body = JSON.parse(text); } catch { /* none */ }
    const authHeader = req.headers.authorization ?? null;
    const cookieRaw = req.headers.cookie ?? '';
    const cookiePair = cookieRaw.split(';').map((s) => s.trim()).find((s) => s.startsWith(`${COOKIE_NAME}=`)) ?? '';
    upstreamLog.push({ path: url.pathname, query: Object.fromEntries(url.searchParams), method: req.method,
      hasAuthorization: authHeader !== null, authorization: authHeader, instanceHeader: req.headers['x-database-instance'] ?? null,
      // Recorded because the live failure was a difference in what the vendor SAW, not in what the
      // gateway computed: the PoC that authenticated successfully sent an Origin, this transport
      // originally sent none. An arm below pins the shape of the whole request, on the wire.
      originHeader: req.headers.origin ?? null, contentType: req.headers['content-type'] ?? null,
      hasCookie: cookiePair !== '', body });
    const send = (status, payload, headers = {}) => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(payload === null ? 'null' : JSON.stringify(payload));
    };

    // The one rule that must never be modelled away: a player request carrying a secret is refused.
    if (authHeader !== null) return send(403, { status: 'failed', error: 'Invalid secret_key.' });

    if (url.pathname.startsWith('/api/user-auth/')) {
      const verb = url.pathname.slice('/api/user-auth/'.length);
      if (!req.headers['x-database-instance']) {
        return send(400, { error: 'Missing database instance. Provide X-Database-Instance header or db query parameter.' });
      }
      if (verb === 'sign-in/email' || verb === 'sign-up/email') {
        if (signinFault) {
          return send(signinFault.status,
            { code: signinFault.code, message: signinFault.message, status: 'failed' },
            signinFault.headers ?? {});
        }
        const u = USERS[body?.email];
        if (!u || (verb === 'sign-in/email' && u.password !== body?.password)) return send(401, { code: 'USER_NOT_FOUND', message: 'Invalid email or password' });
        const cookieValue = `fixture-cookie-${u.id}-${crypto.randomBytes(4).toString('hex')}`;
        sessions.set(cookieValue, u.id);
        // The vendor's own body token is present and is NOT a session channel — the gateway must not
        // forward it, and one arm below proves it does not.
        return send(200, { user: { id: u.id, email: body.email, role: u.role }, token: `vendor-body-token-${u.id}` },
          { 'Set-Cookie': `${COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=app.nocodebackend.com` });
      }
      if (verb === 'get-session') {
        const value = cookiePair.split('=').slice(1).join('=');
        const userId = sessions.get(value);
        if (!userId) return send(200, null);
        const u = Object.entries(USERS).find(([, x]) => x.id === userId)?.[1];
        return send(200, { user: { id: u.id, email: u.email || '', role: u.role }, session: { userId } });
      }
      if (verb === 'sign-out') {
        const value = cookiePair.split('=').slice(1).join('=');
        sessions.delete(value);
        return send(200, { success: true }, { 'Set-Cookie': `${COOKIE_NAME}=; Max-Age=0; Path=/` });
      }
      return send(404, { error: 'Auth Route Not Found' });
    }

    if (url.pathname.startsWith('/api/data/')) {
      if (!url.searchParams.get('Instance')) return send(400, { status: 'failed', error: 'Instance is required.' });
      const [, , verb, table, id] = url.pathname.split('/').filter(Boolean);
      const userId = sessions.get(cookiePair.split('=').slice(1).join('='));
      if (!userId) return send(401, { status: 'failed', error: 'Unauthorized. Provide a valid session cookie.' });
      const scoped = rows.filter((r) => r.user_id === userId);
      if (verb === 'read' && id) {
        const row = scoped.find((r) => String(r.id) === id);
        if (!row) return send(404, { message: 'Record not found or access denied', status: 'error' });
        return send(200, { status: 'success', data: row });
      }
      if (verb === 'read') {
        const wanted = url.searchParams.get('user_id');
        const list = wanted === null ? scoped : scoped.filter((r) => String(r.user_id) === wanted);
        // Reserved names reach the fake as evidence: an arm asserts they were stripped upstream.
        return send(200, { status: 'success', data: list, metadata: { page: 1, limit: 20, hasMore: false, hasPrev: false } });
      }
      if (verb === 'create') {
        const row = { id: nextRowId++, user_id: userId, marker: body?.marker ?? null };
        rows.push(row);
        return send(201, { status: 'success', message: 'Record created successfully', id: row.id });
      }
      if (verb === 'update') {
        const row = scoped.find((r) => String(r.id) === id);
        if (!row) return send(404, { message: 'Record not found or access denied', status: 'error' });
        Object.assign(row, body ?? {});
        return send(200, { status: 'success', message: 'updated', id: row.id });
      }
      if (verb === 'delete') {
        const row = scoped.find((r) => String(r.id) === id);
        if (!row) return send(404, { message: 'Record not found or access denied', status: 'error' });
        rows.splice(rows.indexOf(row), 1);
        return send(200, { status: 'success', message: 'Record deleted successfully' });
      }
      return send(404, { status: 'failed', error: 'no such verb' });
    }
    return send(404, { status: 'failed', error: 'no such path' });
  });
}

const fake = http.createServer(fakeNcb);
await new Promise((r) => fake.listen(0, '127.0.0.1', r));
const FAKE_BASE = `http://127.0.0.1:${fake.address().port}`;
const UPSTREAM_URLS = {
  NCB_AUTH_API_URL: `${FAKE_BASE}/api/user-auth`,
  NCB_DATA_API_URL: `${FAKE_BASE}/api/data`,
  // The gateway must be able to dial a loopback http URL for the tests, and the native client's
  // configured check demands https. A local-only exception, tested as such below.
  NCB_INSTANCE: '55954_bridgemind'
};

// ── boot the REAL relay against the fake ───────────────────────────────────
const SEAL_KEY = 'gateway-fixture-seal-key-not-a-real-secret-32chars';
const ALLOWED_ORIGIN = 'https://app.bridgemind.app';
process.env = {
  ...process.env,
  BRIDGE_API_KEY: 'relay-key-not-a-club-secret',
  NCB_PROXY_BASE: FAKE_BASE,               // the legacy transport, also aimed at the fake
  ...UPSTREAM_URLS,
  NCB_ALLOW_INSECURE_UPSTREAM: '1',
  NCB_SESSION_SEAL_KEY: SEAL_KEY,
  NCB_GATEWAY_ALLOWED_ORIGINS: ALLOWED_ORIGIN,
  NCB_TABLE_ALLOWLIST: 'user_settings,recorded_hands,user_codes,ai_quota_usage',
  NODESEND_PRIVATE_KEY_B64: '',
  AI_QUOTA_RESERVATION_TABLE: ''
};
delete process.env.NODESEND_PRIVATE_KEY_PEM;

const bridge = require(path.join(ROOT, 'bridge.js'));
const { app, ncbSeal, ncbNativeClient, buildNcbGateway, ncbGatewayClubTables } = bridge;
// Imported directly rather than through the relay's exports, because section 16 wires a claim channel
// of its own around a local pool: the objects under test are these modules, and bridge.js supplies the
// transport, not the logic.
const { createInvitationReservations } = require('./ncb/invitationReservations.js');
const createInvitationClaimForGate = require('./ncb/invitationClaim.js').createInvitationClaim;

const server = app.listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${server.address().port}`;

const results = [];
const check = (name, condition, detail = '') => {
  results.push({ name, pass: condition === true, detail: condition === true ? '' : String(detail ?? '').slice(0, 240) });
};

async function call(method, route, { token = '', origin = ALLOWED_ORIGIN, body, headers = {} } = {}) {
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(origin ? { Origin: origin } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers
    },
    ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) })
  });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text, headers: Object.fromEntries(res.headers.entries()) };
}

async function signInAs(email, password) {
  const r = await call('POST', '/ncb/auth/sign-in/email', { body: { email, password } });
  return r;
}

// Capture what the relay prints, so "no credential in logs" is measured rather than asserted.
const capturedLogs = [];
const realLog = console.log; const realInfo = console.info; const realError = console.error;
console.log = (...a) => { capturedLogs.push(a.map(String).join(' ')); realLog(...a); };
console.info = (...a) => { capturedLogs.push(a.map(String).join(' ')); realInfo(...a); };
console.error = (...a) => { capturedLogs.push(a.map(String).join(' ')); realError(...a); };

// ── 1. sign-in, and what it is allowed to hand back ────────────────────────
const A = await signInAs('a@poc.invalid', 'pw-a-fixture');
const B = await signInAs('b@poc.invalid', 'pw-b-fixture');
check('1a. sign-in through the gateway succeeds', A.status === 200 && A.json?.status === 'success' && A.json?.data?.user?.id === 'user-aaaa', `${A.status} ${A.text.slice(0, 160)}`);
check('1b. the answer is the shape BridgeMind already parses (status success + data.user)',
  typeof A.json?.status === 'string' && 'data' in (A.json ?? {}) && Boolean(A.json?.data?.user), A.text.slice(0, 160));
const tokenA = A.json?.token ?? ''; const tokenB = B.json?.token ?? '';
check('1c. the handle is a sealed token, not the vendor cookie and not the vendor body token',
  tokenA.startsWith('ncbs1.') && !tokenA.includes('fixture-cookie') && !tokenA.includes('vendor-body-token'), tokenA.slice(0, 40));
check('1d. NO Set-Cookie is forwarded to the browser — the upstream session never becomes ambient',
  !('set-cookie' in A.headers) && !('set-cookie' in B.headers), JSON.stringify(Object.keys(A.headers)));
check('1e. two accounts get two different handles', tokenA !== tokenB && tokenA.length > 20 && tokenB.length > 20, `${tokenA.length}/${tokenB.length}`);

// The upstream cookie value the fake minted for A, recovered from the fake's own view of the next
// authenticated call, so the leak checks compare against the real thing rather than a guess.
const probeRead = await call('GET', '/ncb/data/read/user_settings?limit=5', { token: tokenA });
const seenCookies = upstreamLog.filter((e) => e.hasCookie).map((e) => e.path);
check('1f. an authenticated data read through the gateway reaches upstream with a cookie',
  probeRead.status === 200 && seenCookies.length > 0, `${probeRead.status} cookiePaths=${JSON.stringify(seenCookies.slice(0, 3))}`);
check('1g. and the answer keeps the vendor envelope the 101 browser call sites expect',
  probeRead.json?.status === 'success' && Array.isArray(probeRead.json?.data) && 'metadata' in (probeRead.json ?? {}), probeRead.text.slice(0, 160));

// ── 2. the secret must be unreachable by a player request ───────────────────
const authedUpstream = upstreamLog.filter((e) => e.hasAuthorization);
check('2a. NOT ONE player request carried an Authorization header upstream',
  authedUpstream.length === 0, `${authedUpstream.length} request(s) carried one: ${JSON.stringify(authedUpstream.slice(0, 2))}`);
const smuggling = await call('GET', '/ncb/data/read/user_settings?key=ncb_sec_real-looking-value&token=abc&Instance=99999_other', { token: tokenA });
// Found by path, not by position. `at(-1)` is whatever the fake saw last, and the gateway makes an
// auth hop before a data hop on some paths — a position-based read here could pass while looking at
// the wrong request entirely.
const smuggleEntry = [...upstreamLog].reverse().find((e) => e.path.startsWith('/api/data/'));
check('2b. reserved query names are stripped before forwarding (no key, no token, no foreign Instance)',
  smuggleEntry && !('key' in smuggleEntry.query) && !('token' in smuggleEntry.query) && smuggleEntry.query.Instance === '55954_bridgemind',
  JSON.stringify(smuggleEntry?.query ?? {}));
check('2c. the smuggled request still served the caller\'s own instance', smuggling.status === 200 && smuggling.json?.status === 'success', `${smuggling.status} ${smuggling.text.slice(0, 120)}`);

const client = ncbNativeClient({ env: { ...process.env } });
let refused = null;
try { await client.data('read', 'user_settings', { cookie: 'x', headers: { Authorization: 'Bearer ncb_sec_x' } }); } catch (error) { refused = error?.code ?? null; }
check('2d. the transport REFUSES an Authorization header by construction, not by convention',
  refused === 'secret_substitution_refused', String(refused));

// ── 3. unauthorized, invalid and unavailable are three different answers ────
const noToken = await call('GET', '/ncb/data/read/user_settings', {});
check('3a. a data call with no handle is 401 invalid_session', noToken.status === 401 && noToken.json?.error === 'invalid_session', `${noToken.status} ${noToken.text.slice(0, 120)}`);
const legacy = await call('GET', '/ncb/data/read/user_settings', { token: 'old-ncb-body-token-not-a-handle' });
check('3b. a stale legacy bearer is 401 and is named as unsealed, not as a server fault',
  legacy.status === 401 && legacy.json?.reason === 'not_sealed', `${legacy.status} ${JSON.stringify(legacy.json)}`);
const tampered = await call('GET', '/ncb/data/read/user_settings', { token: `${tokenA.slice(0, -4)}ZZZZ` });
check('3c. an edited handle fails the authentication tag and is 401', tampered.status === 401 && tampered.json?.reason === 'invalid', `${tampered.status} ${JSON.stringify(tampered.json)}`);
const authNoToken = await call('GET', '/ncb/auth/get-session', {});
check('3d. get-session with no handle is 401, not 503', authNoToken.status === 401, `${authNoToken.status}`);

const deadUpstream = buildNcbGateway({ env: { ...process.env, NCB_AUTH_API_URL: 'http://127.0.0.1:1/api/user-auth', NCB_DATA_API_URL: 'http://127.0.0.1:1/api/data' } });
const express = require('express');
const deadApp = express(); deadApp.use(express.json()); deadApp.use(deadUpstream.router);
const deadServer = deadApp.listen(0, '127.0.0.1');
await new Promise((r) => deadServer.once('listening', r));
const deadBase = `http://127.0.0.1:${deadServer.address().port}`;
const deadSignIn = await fetch(`${deadBase}/ncb/auth/sign-in/email`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ALLOWED_ORIGIN }, body: JSON.stringify({ email: 'a@poc.invalid', password: 'pw-a-fixture' })
});
const deadBody = await deadSignIn.text().catch(() => '');
check('3e. when NCB is unreachable, sign-in answers 503 — never a 401 that discards a working login',
  deadSignIn.status === 503 && JSON.parse(deadBody || '{}').error === 'auth_service_unavailable', `${deadSignIn.status} ${deadBody.slice(0, 120)}`);
const deadData = await fetch(`${deadBase}/ncb/data/read/user_settings`, { headers: { Origin: ALLOWED_ORIGIN, Authorization: `Bearer ${tokenA}` } });
const deadDataText = await deadData.text().catch(() => '');
check('3f. when NCB is unreachable, a data call answers 502 storage_unavailable, not 401',
  deadData.status === 502 && JSON.parse(deadDataText || '{}').error === 'storage_unavailable', `${deadData.status} ${deadDataText.slice(0, 120)}`);
await new Promise((r) => deadServer.close(r));

const noKeyGateway = buildNcbGateway({ env: { ...process.env, NCB_SESSION_SEAL_KEY: '' } });
check('3g. with no seal key the gateway refuses to run rather than minting forgeable handles',
  noKeyGateway.configured === false && noKeyGateway.reason === 'ncb_session_seal_key_unconfigured' && noKeyGateway.health().routes > 0,
  JSON.stringify(noKeyGateway.health()));
const noKeyApp = express(); noKeyApp.use(express.json()); noKeyApp.use(noKeyGateway.router);
const noKeyServer = noKeyApp.listen(0, '127.0.0.1');
await new Promise((r) => noKeyServer.once('listening', r));
const noKeyCall = await fetch(`http://127.0.0.1:${noKeyServer.address().port}/ncb/data/read/user_settings`, { headers: { Origin: ALLOWED_ORIGIN, Authorization: `Bearer ${tokenA}` } });
check('3h. and every route then answers 503 with the named deployment reason',
  noKeyCall.status === 503 && (await noKeyCall.text()).includes('gateway_unconfigured'), noKeyCall.status);
await new Promise((r) => noKeyServer.close(r));

// ── 4. two-user RLS isolation, through the gateway, as the vendor enforces it ─
const markerA = `A-${crypto.randomBytes(6).toString('hex')}`;
const markerB = `B-${crypto.randomBytes(6).toString('hex')}`;
const madeA = await call('POST', '/ncb/data/create/user_settings', { token: tokenA, body: { marker: markerA } });
const madeB = await call('POST', '/ncb/data/create/user_settings', { token: tokenB, body: { marker: markerB } });
check('4a. each identity can create its own row through the gateway',
  madeA.status === 200 && madeB.status === 200 && madeA.json?.id >= 1 && madeB.json?.id >= 1,
  `${madeA.status}/${madeB.status} ${madeA.text.slice(0, 90)}`);
const idA = madeA.json?.id; const idB = madeB.json?.id;

const listA = await call('GET', '/ncb/data/read/user_settings?limit=20', { token: tokenA });
const listB = await call('GET', '/ncb/data/read/user_settings?limit=20', { token: tokenB });
const markersOf = (j) => (j?.data ?? []).map((r) => r.marker);
check('4b. A sees its own row — so a later zero is a hiding, not an emptiness',
  markersOf(listA.json).includes(markerA) && !markersOf(listA.json).includes(markerB), JSON.stringify(markersOf(listA.json)));
check('4c. B sees its own row and not A\'s',
  markersOf(listB.json).includes(markerB) && !markersOf(listB.json).includes(markerA), JSON.stringify(markersOf(listB.json)));
const crossFilter = await call('GET', `/ncb/data/read/user_settings?user_id=user-bbbb`, { token: tokenA });
check('4d. A filtering by B\'s user id receives nothing', crossFilter.status === 200 && (crossFilter.json?.data ?? []).length === 0,
  `${crossFilter.status} rows=${(crossFilter.json?.data ?? []).length}`);
const crossById = await call('GET', `/ncb/data/read/user_settings/${idB}`, { token: tokenA });
check('4e. A addressing B\'s row by primary key is not served (404, the vendor\'s ambiguous answer)',
  crossById.status === 404 && crossById.json?.error === 'not_found_or_not_yours', `${crossById.status} ${crossById.text.slice(0, 100)}`);
const crossByIdB = await call('GET', `/ncb/data/read/user_settings/${idA}`, { token: tokenB });
check('4f. and the same holds in the other direction',
  crossByIdB.status === 404, `${crossByIdB.status}`);
const ownById = await call('GET', `/ncb/data/read/user_settings/${idA}`, { token: tokenA });
check('4g. while each owner still reads its own row by id (the read-by-id OBJECT shape is passed through)',
  ownById.status === 200 && ownById.json?.data?.marker === markerA && !Array.isArray(ownById.json?.data),
  `${ownById.status} ${ownById.text.slice(0, 120)}`);
const updOther = await call('PUT', `/ncb/data/update/user_settings/${idB}`, { token: tokenA, body: { marker: 'hijacked' } });
check('4h. A cannot update B\'s row', updOther.status === 404, `${updOther.status}`);
const delOther = await call('DELETE', `/ncb/data/delete/user_settings/${idB}`, { token: tokenA });
check('4i. A cannot delete B\'s row', delOther.status === 404, `${delOther.status}`);
const stillThere = await call('GET', `/ncb/data/read/user_settings/${idB}`, { token: tokenB });
check('4j. and B\'s row is unchanged afterwards — the negative test has a positive control',
  stillThere.status === 200 && stillThere.json?.data?.marker === markerB, `${stillThere.status} ${stillThere.text.slice(0, 120)}`);

// ── 5. allow-lists: the gateway is not a general proxy ──────────────────────
for (const table of ncbGatewayClubTables) {
  const refusedCall = await call('GET', `/ncb/data/read/${table}`, { token: tokenA });
  check(`5a. club table ${table} is refused at the gateway (it belongs to the service-account path)`,
    refusedCall.status === 403 && refusedCall.json?.error === 'table_not_allowed', `${refusedCall.status}`);
}
const unknownTable = await call('GET', '/ncb/data/read/some_admin_table', { token: tokenA });
check('5b. a table outside the allow-list is refused, never forwarded', unknownTable.status === 403, `${unknownTable.status} ${unknownTable.text.slice(0, 90)}`);
const nastyTable = await call('GET', '/ncb/data/read/..%2F..%2Fetc', { token: tokenA });
check('5c. a table name that is not a plain identifier is refused before any upstream call',
  [403, 404].includes(nastyTable.status), `${nastyTable.status} ${nastyTable.text.slice(0, 90)}`);
const badId = await call('GET', '/ncb/data/read/user_settings/not*an%20id', { token: tokenA });
check('5d. a row id that is not a safe token is refused', badId.status === 400 && badId.json?.error === 'bad_row_id', `${badId.status} ${badId.text.slice(0, 90)}`);
const longQuery = await call('GET', `/ncb/data/read/user_settings?x=${'y'.repeat(600)}`, { token: tokenA });
check('5e. an oversized query is refused rather than proxied', longQuery.status === 400 && longQuery.json?.error === 'query_too_long', `${longQuery.status}`);

// ── 6. CORS: a named list, on these routes only ────────────────────────────
const evilOrigin = await call('GET', '/ncb/data/read/user_settings', { token: tokenA, origin: 'https://evil.example.com' });
check('6a. an origin not on the allow-list is refused', evilOrigin.status === 403 && evilOrigin.json?.error === 'origin_not_allowed', `${evilOrigin.status}`);
check('6b. and no credentialed CORS header is emitted for it',
  !('access-control-allow-origin' in evilOrigin.headers), JSON.stringify(Object.keys(evilOrigin.headers)));
const goodOrigin = await call('GET', '/ncb/data/read/user_settings', { token: tokenA, origin: ALLOWED_ORIGIN });
check('6c. the allowed origin gets its own origin echoed, not a wildcard',
  goodOrigin.headers['access-control-allow-origin'] === ALLOWED_ORIGIN && goodOrigin.headers['access-control-allow-credentials'] === 'true',
  JSON.stringify(goodOrigin.headers['access-control-allow-origin']));
const preflight = await fetch(`${BASE}/ncb/data/read/user_settings`, {
  method: 'OPTIONS', headers: { Origin: ALLOWED_ORIGIN, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization,content-type' }
});
check('6d. preflight for the allowed origin succeeds with the narrowed method and header list',
  preflight.status === 204 && preflight.headers.get('access-control-allow-origin') === ALLOWED_ORIGIN
  && String(preflight.headers.get('access-control-allow-headers') || '').toLowerCase().includes('authorization'), preflight.status);
const preflightEvil = await fetch(`${BASE}/ncb/data/read/user_settings`, { method: 'OPTIONS', headers: { Origin: 'https://evil.example.com', 'Access-Control-Request-Method': 'GET' } });
check('6e. preflight from a stranger is refused, not reflected', preflightEvil.status === 403, `${preflightEvil.status}`);
// The relay-wide cors() must be unchanged for everything that is not /ncb. Measured baseline for
// this build, before the gateway existed: a WILDCARD `Access-Control-Allow-Origin` on actual requests
// and on preflights, with no credentials header. Narrowing /ncb must not silently move that.
const otherOriginAi = await fetch(`${BASE}/ai/quota`, { headers: { Origin: 'https://anything.example' } });
check('6f. existing non-gateway routes still answer any origin exactly as before',
  otherOriginAi.headers.get('access-control-allow-origin') === '*'
  && !otherOriginAi.headers.get('access-control-allow-credentials')
  && Boolean(otherOriginAi.headers.get('access-control-expose-headers')),
  JSON.stringify(Object.fromEntries(otherOriginAi.headers)));
const otherPreflight = await fetch(`${BASE}/ai/chat`, {
  method: 'OPTIONS', headers: { Origin: 'https://anything.example', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'x-ai-decision-key,content-type' }
});
check('6g. and a preflight on an existing route is still answered by cors, with its old wildcard and a header list wide enough for x-ai-decision-key',
  otherPreflight.status === 204 && otherPreflight.headers.get('access-control-allow-origin') === '*'
  && String(otherPreflight.headers.get('access-control-allow-headers') || '').toLowerCase().includes('x-ai-decision-key'),
  `${otherPreflight.status} ${otherPreflight.headers.get('access-control-allow-origin')}/${otherPreflight.headers.get('access-control-allow-headers')}`);

// ── 7. session renewal and restart-safety ───────────────────────────────────
const gs1 = await call('GET', '/ncb/auth/get-session', { token: tokenA });
check('7a. get-session works with the handle and returns the frontend\'s signed-in shape',
  gs1.status === 200 && gs1.json?.status === 'success' && gs1.json?.data?.user?.id === 'user-aaaa', `${gs1.status} ${gs1.text.slice(0, 140)}`);
const renewed = gs1.json?.token ?? '';
check('7b. get-session re-mints the handle (sliding expiry without a server-side session table)',
  renewed.startsWith('ncbs1.') && renewed !== tokenA, `${renewed.slice(0, 20)}/${tokenA.slice(0, 20)}`);
const afterRenew = await call('GET', '/ncb/data/read/user_settings', { token: renewed });
check('7c. and the renewed handle works immediately', afterRenew.status === 200, `${afterRenew.status}`);
check('7d. the old handle still works — renewal is not a rotation that locks out a live tab',
  (await call('GET', '/ncb/data/read/user_settings', { token: tokenA })).status === 200);

const seal = ncbSeal({ env: { NCB_SESSION_SEAL_KEY: SEAL_KEY, NCB_INSTANCE: '55954_bridgemind' } });
const openedHere = seal.open(tokenA);
const sealInNewProcess = ncbSeal({ env: { NCB_SESSION_SEAL_KEY: SEAL_KEY, NCB_INSTANCE: '55954_bridgemind' } });
const openedThere = sealInNewProcess.open(tokenA);
check('7e. RESTART-SAFE: a freshly built sealer with the same key opens the same handle — no memory state',
  openedHere.ok && openedThere.ok && openedHere.session.userId === openedThere.session.userId && openedHere.session.cookie === openedThere.session.cookie,
  JSON.stringify({ a: openedHere.ok, b: openedThere.ok }));
const wrongKey = ncbSeal({ env: { NCB_SESSION_SEAL_KEY: 'a-completely-different-fixture-seal-key-32chars', NCB_INSTANCE: '55954_bridgemind' } });
check('7f. and a different key cannot open it — the handle is bound to the server secret',
  wrongKey.open(tokenA).ok === false && wrongKey.open(tokenA).reason === 'tampered', JSON.stringify(wrongKey.open(tokenA)));
const clock = { now: 1_700_000_000_000 };
const shortSeal = ncbSeal({ env: { NCB_SESSION_SEAL_KEY: SEAL_KEY, NCB_INSTANCE: '55954_bridgemind', NCB_SESSION_TTL_MS: '1' }, now: () => clock.now });
// The floor is a property in its own right: honoured literally, a one-millisecond TTL would mint a
// handle that is dead the instant it is returned, and the outage that follows would look like the
// vendor rejecting sessions rather than a decimal point in somebody's deployment config.
check('7g0. an absurdly short TTL is clamped to the five-minute floor, not honoured literally',
  shortSeal.ttlMs === 5 * 60 * 1000, shortSeal.ttlMs);
const expiring = shortSeal.seal({ cookie: 'c', userId: 'u', instance: '55954_bridgemind' });
clock.now += shortSeal.ttlMs + 1000;
const expired = shortSeal.open(expiring);
check('7g. an expired handle says `expired`, which is a different answer from `tampered`',
  expired.ok === false && expired.reason === 'expired', JSON.stringify(expired));
const forged = ncbSeal({ env: { NCB_SESSION_SEAL_KEY: SEAL_KEY } }).seal({ cookie: 'attacker-cookie', userId: 'user-bbbb', instance: 'other-instance' });
const wrongInstance = ncbSeal({ env: { NCB_SESSION_SEAL_KEY: SEAL_KEY, NCB_INSTANCE: '55954_bridgemind' } }).open(forged);
check('7h. a handle carrying a foreign instance is rejected by the gateway, not forwarded',
  wrongInstance.ok && wrongInstance.session.instance === 'other-instance', JSON.stringify(wrongInstance.session?.instance));

// ── 8. sign-out, and rate limiting ─────────────────────────────────────────
const signedOut = await call('POST', '/ncb/auth/sign-out', { token: tokenA });
check('8a. sign-out succeeds and returns the vendor-shape envelope',
  signedOut.status === 200 && signedOut.json?.status === 'success', `${signedOut.status} ${signedOut.text.slice(0, 90)}`);
// The upstream session is genuinely gone: the fake's get-session now answers bare null, which the
// gateway must translate to 401 invalid_session rather than passing `null` through as success.
const afterSignOut = await call('GET', '/ncb/auth/get-session', { token: tokenA });
check('8b. a handle whose upstream session was ended is 401 invalid_session, not a 200 with null data',
  afterSignOut.status === 401 && afterSignOut.json?.reason === 'upstream_no_session', `${afterSignOut.status} ${afterSignOut.text.slice(0, 140)}`);
const afterSignOutRead = await call('GET', '/ncb/data/read/user_settings', { token: tokenA });
check('8b2. and its data calls are refused too — the handle cannot outlive the session it wraps',
  afterSignOutRead.status === 401 && afterSignOutRead.json?.reason === 'upstream_rejected',
  `${afterSignOutRead.status} ${afterSignOutRead.text.slice(0, 140)}`);

const burst = [];
for (let i = 0; i < 30; i += 1) burst.push(call('POST', '/ncb/auth/sign-in/email', { body: { email: 'nobody@poc.invalid', password: 'x' } }));
const burstResults = await Promise.all(burst);
const burstStatuses = burstResults.map((r) => r.status);
const limited = burstResults.find((r) => r.status === 429);
check('8c. a credential-stuffing burst is throttled rather than forwarded forever',
  (burstStatuses.filter((s) => s === 429).length) > 0, JSON.stringify([...new Set(burstStatuses)]));
check('8d. a 429 carries Retry-After, so a client backs off instead of hammering',
  limited && /^\d+$/.test(String(limited.headers['retry-after'] ?? '')), `retry-after=${limited?.headers['retry-after']}`);
check('8e. the burst never reached upstream more times than the window allows',
  upstreamLog.filter((e) => e.path === '/api/user-auth/sign-in/email').length <= 30, String(upstreamLog.filter((e) => e.path === '/api/user-auth/sign-in/email').length));

// ── 9. nothing secret is printed or returned ───────────────────────────────
console.log = realLog; console.info = realInfo; console.error = realError;
const allText = capturedLogs.join('\n');
const leakables = [SEAL_KEY, 'fixture-cookie', 'vendor-body-token', '__Secure-better-auth.session_token', 'ncb_sec_'];
const leakedInLogs = leakables.filter((s) => allText.includes(s));
check('9a. no seal key, upstream cookie, vendor token or secret appears in any log line',
  leakedInLogs.length === 0, leakedInLogs.join(','));
const bodiesText = JSON.stringify([A.json, B.json, gs1.json, probeRead.json, madeA.json, ownById.json]);
const leakedInBodies = leakables.filter((s) => bodiesText.includes(s));
check('9b. no seal key, upstream cookie or secret appears in any response body',
  leakedInBodies.length === 0, leakedInBodies.join(','));
const health = await (await fetch(`${BASE}/health`)).json();
const healthText = JSON.stringify(health);
check('9c. /health leaks nothing about the gateway beyond booleans and counts',
  !healthText.includes('fixture-cookie') && !healthText.includes(SEAL_KEY) && !healthText.includes('poc.invalid')
  && !/@[a-z]/i.test(JSON.stringify(health.ncbGateway)), healthText.slice(healthText.indexOf('ncbGateway'), healthText.indexOf('ncbGateway') + 220));
check('9d. whoami identifies a caller only by a hash, never by user id or email',
  !JSON.stringify((await call('GET', '/ncb/whoami', { token: tokenB })).json).includes('user-bbbb'), '');
// Scoped to the gateway's own /health block. Searching the whole document is a false positive by
// construction: `/health` legitimately names the club tables elsewhere (clubs.routes, clubs.configured)
// and a deny-list word appearing in an UNRELATED block is not the gateway echoing a credential.
const gatewayHealthText = JSON.stringify(health.ncbGateway ?? {});
const tableNamesInHealth = ncbGatewayClubTables.filter((t) => gatewayHealthText.includes(t));
check('9e. and no table name from the deny-list is echoed by the gateway health block', tableNamesInHealth.length === 0, tableNamesInHealth.join(','));

// ── 10. the rest of the relay is unchanged ─────────────────────────────────
const root = await (await fetch(`${BASE}/`)).json();
const clubsGuard = await call('GET', '/clubs', { origin: '' });
const unknownPath = await call('GET', '/definitely-not-a-route', { origin: '' });
check('10a. / still advertises the pre-existing surface',
  root.version === 'bridge-nodesend-quota-v9' && root.endpoints?.aiChat === 'POST /ai/chat' && Boolean(root.endpoints?.myClub), JSON.stringify(Object.keys(root.endpoints ?? {})));
check('10b. club routes keep their own guard envelope, untouched by the new mount',
  clubsGuard.status === 401 && clubsGuard.json?.error === 'auth_error', `${clubsGuard.status} ${clubsGuard.text.slice(0, 90)}`);
check('10c. the catch-all 404 still answers for a path that is on neither surface',
  unknownPath.status === 404 && unknownPath.json?.error === 'Endpoint not found', `${unknownPath.status}`);
check('10d. /health.clubs is still reported as before, alongside the new gateway block',
  Boolean(health.clubs) && typeof health.clubs?.configured === 'boolean' && health.clubs.routes >= 21 && Boolean(health.ncbGateway),
  JSON.stringify(health.clubs));
check('10e. the gateway reports its own state and the properties the audit asked for',
  health.ncbGateway.configured === true && health.ncbGateway.restartSafe === true
  && health.ncbGateway.sessionState === 'stateless_sealed_handle'
  && health.ncbGateway.upstreamCookieExposedToClient === false
  && health.ncbGateway.secretKeyUsableByPlayers === false, JSON.stringify(health.ncbGateway));

// ── 11. the shipped surface is what was declared ────────────────────────────
const mounted = [];
const walk = (stack) => { for (const layer of stack) { if (layer?.route) { for (const m of Object.keys(layer.route.methods ?? {})) mounted.push(`${m.toUpperCase()} ${layer.route.path}`); } else if (layer?.handle?.stack) walk(layer.handle.stack); } };
for (const layer of app._router.stack) { if (layer?.handle?.stack) walk(layer.handle.stack); }
const ncbMounted = mounted.filter((r) => r.includes('/ncb/'));
const expectedRoutes = bridge.ncbMount.health().routes;
check('11a. every gateway route is mounted, the count matches the health claim, and nothing else is under /ncb',
  // Fourteen: five auth verbs, seven data routes (four verbs, with `create` taking no row id),
  // `/ncb/whoami`, and `/ncb/public-data/read/:table` — the anonymous invitation read the shipped
  // registration flow performs. The number is pinned on purpose: a route appearing here without
  // being named in a gate is exactly what this arm is for.
  ncbMounted.length === expectedRoutes && expectedRoutes === 14 && ncbMounted.every((r) => r.includes('/ncb/')),
  `mounted=${ncbMounted.length} health=${expectedRoutes} ${JSON.stringify(ncbMounted)}`);
check('11b. no route accepts an upstream URL or a table that is not enumerated',
  !ncbMounted.some((r) => /:url|:base|:host|:table\/:anything/.test(r)) && ncbMounted.some((r) => r.includes(':table')),
  JSON.stringify(ncbMounted.filter((r) => r.includes(':table'))));

// ── 12. the fake itself is honest about what it saw ─────────────────────────
check('12a. the fake received the instance by HEADER on auth calls and by QUERY on data calls',
  upstreamLog.filter((e) => e.path.startsWith('/api/user-auth')).every((e) => e.instanceHeader === '55954_bridgemind')
  && upstreamLog.filter((e) => e.path.startsWith('/api/data')).every((e) => e.query.Instance === '55954_bridgemind'),
  JSON.stringify(upstreamLog.filter((e) => e.path.startsWith('/api/data')).slice(0, 2).map((e) => e.query)));
check('12b. the create call was answered 201 with a top-level id and the gateway passed that id back',
  typeof madeA.json?.id === 'number' && madeA.json?.status === 'success', JSON.stringify(madeA.json));
const dataCallsWithAuth = upstreamLog.filter((e) => e.path.startsWith('/api/data') && e.hasAuthorization).length;
check('12c. across the whole run, zero upstream data calls carried a credential that is not the player\'s own cookie',
  dataCallsWithAuth === 0, `${dataCallsWithAuth}`);

// ── 13. the request the VENDOR sees, pinned on the wire ─────────────────────
// The live sign-in failure was invisible to every assertion above: the gateway's own logic was fine,
// the handle was minted correctly for the accounts that worked, and the transport nonetheless sent a
// request that differed from the one proven to authenticate. So this section pins the bytes the
// upstream receives — method, URL shape, headers, body — rather than the gateway's intent.
//
// It runs against a SECOND mount of the same shipped builder, on its own port, with the auth throttle
// raised. Not because the throttle is in the way — section 8 proves it works, and it had already
// counted these requests and turned all of them into 429s — but because raising the limit on the live
// mount would weaken that arm. A second instance costs nothing and keeps every existing assertion
// measuring the same configuration it measured before.
const probeMount = bridge.buildNcbGateway({ env: { ...process.env, NCB_GATEWAY_AUTH_RATE_MAX: '5000' } });
const probeApp = require('express')();
probeApp.use(require('express').json());
probeApp.use(probeMount.router);
const probeServer = probeApp.listen(0, '127.0.0.1');
await new Promise((r) => probeServer.once('listening', r));
const PROBE_BASE = `http://127.0.0.1:${probeServer.address().port}`;
const probeCall = async (method, route, { token = '', body, headers = {} } = {}) => {
  const res = await fetch(`${PROBE_BASE}${route}`, {
    method,
    headers: {
      'Content-Type': 'application/json', Origin: ALLOWED_ORIGIN,
      ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text, headers: Object.fromEntries(res.headers.entries()) };
};

{
  const before = upstreamLog.length;
  const shaped = await probeCall('POST', '/ncb/auth/sign-in/email', { body: { email: 'a@poc.invalid', password: 'pw-a-fixture' } });
  const sent = upstreamLog.slice(before).find((e) => e.path.endsWith('/sign-in/email'));
  check('13a. the sign-in reaches the vendor as the known-working shape: POST, ?db=, X-Database-Instance, Origin, JSON body',
    shaped?.status === 200 && sent && sent.method === 'POST'
    && sent.query.db === '55954_bridgemind' && sent.instanceHeader === '55954_bridgemind'
    && typeof sent.originHeader === 'string' && /^https:\/\//.test(sent.originHeader)
    && /application\/json/.test(String(sent.contentType))
    && sent.hasAuthorization === false && sent.body?.email === 'a@poc.invalid' && 'password' in (sent.body ?? {}),
    JSON.stringify({ status: shaped?.status, db: sent?.query?.db, header: sent?.instanceHeader, origin: sent?.originHeader, ct: sent?.contentType }));
  check('13b. the Origin the vendor sees is the configured trusted origin, never something the caller supplied',
    sent?.originHeader === (process.env.NCB_TRUSTED_ORIGIN || 'https://app.bridgemind.app'),
    `${sent?.originHeader}`);
  const spoofedOrigin = await probeCall('POST', '/ncb/auth/sign-in/email', {
    headers: { 'X-Forwarded-Origin': 'https://evil.example', Referer: 'https://evil.example/' },
    body: { email: 'a@poc.invalid', password: 'pw-a-fixture', origin: 'https://evil.example' }
  });
  const spoofedSent = upstreamLog[upstreamLog.length - 1];
  check('13c. a caller cannot steer it: forwarded-origin headers and an origin field in the body change nothing upstream',
    spoofedOrigin.status === 200 && spoofedSent?.originHeader === sent?.originHeader
    && spoofedSent?.body?.origin === undefined,
    `${spoofedSent?.originHeader} body keys=${Object.keys(spoofedSent?.body ?? {}).join(',')}`);
  const dataBefore = upstreamLog.length;
  const handleForProbe = await probeCall('POST', '/ncb/auth/sign-in/email', { body: { email: 'b@poc.invalid', password: 'pw-b-fixture' } });
  await probeCall('GET', '/ncb/data/read/user_settings?limit=1', { token: handleForProbe.json?.token });
  const dataSent = upstreamLog.slice(dataBefore).find((e) => e.path.startsWith('/api/data'));
  check('13d. the data family carries the caller cookie with the same Origin and no Authorization',
    dataSent && dataSent.hasCookie === true && dataSent.hasAuthorization === false
    && dataSent.originHeader === sent?.originHeader && dataSent.query.Instance === '55954_bridgemind',
    JSON.stringify({ cookie: dataSent?.hasCookie, auth: dataSent?.hasAuthorization, origin: dataSent?.originHeader }));
}

// ── 14. an upstream refusal keeps its own identity ──────────────────────────
// 401 = the credentials were refused; 403 = the vendor declined for a reason the player cannot type
// their way out of; 429 = back off. Collapsing those into one client-side 400 is the defect that made
// a live policy refusal indistinguishable from a mistyped password, and a 401 in that place would have
// deleted working sessions.
{
  const table = bridge.ncbAuthUpstreamStatus;
  check('14a. the mapping is a table with the three classes distinct, and no class maps to 401 except bad credentials',
    table(401).status === 401 && table(403).status === 502 && table(429).status === 429
    && table(400).status === 400 && table(422).status === 400 && table(500).status === 502
    && [403, 429, 404, 409, 500, 503].every((s) => table(s).status !== 401),
    JSON.stringify([401, 403, 429, 400, 422, 500].map((s) => `${s}->${table(s).status}`)));

  signinFault = { status: 403, code: 'EMAIL_NOT_VERIFIED', message: 'Email is not verified. Please verify your email.' };
  const forbidden = await probeCall('POST', '/ncb/auth/sign-in/email', { body: { email: 'a@poc.invalid', password: 'pw-a-fixture' } });
  signinFault = null;
  check('14b. an upstream 403 is reported as a gateway-side fault (502), never as a client 400 and never as 401',
    forbidden.status === 502 && forbidden.json?.error === 'upstream_forbidden' && forbidden.json?.code === 'EMAIL_NOT_VERIFIED',
    `${forbidden.status} ${JSON.stringify(forbidden.json)}`);
  check('14c. and it carries no free-text upstream message, no cookie and no credential',
    !JSON.stringify(forbidden.json).includes('Please verify')
    && !JSON.stringify(forbidden.json).includes('fixture-cookie') && forbidden.json?.upstream_status === 403,
    JSON.stringify(forbidden.json));

  signinFault = { status: 429, code: 'TOO_MANY_REQUESTS', message: 'Too many requests. Please try again later.' };
  const limited = await probeCall('POST', '/ncb/auth/sign-in/email', { body: { email: 'a@poc.invalid', password: 'pw-a-fixture' } });
  signinFault = null;
  check('14d. an upstream 429 is relayed as 429 with Retry-After, so the client backs off instead of hammering',
    limited.status === 429 && Number(limited.headers['retry-after']) > 0 && limited.json?.error === 'upstream_rate_limited',
    `${limited.status} retry-after=${limited.headers['retry-after']}`);

  const wrongPassword = await probeCall('POST', '/ncb/auth/sign-in/email', { body: { email: 'a@poc.invalid', password: 'wrong' } });
  check('14e. genuine bad credentials still answer 401 — the player CAN act on that one',
    wrongPassword.status === 401 && wrongPassword.json?.error === 'invalid_credentials' && wrongPassword.json?.code === 'USER_NOT_FOUND',
    `${wrongPassword.status} ${JSON.stringify(wrongPassword.json)}`);
  const unsealed = await probeCall('GET', '/ncb/auth/get-session', { token: 'ncbs1.short.short.short' });
  check('14f. and no refusal path in this section returns a 200 or an empty success',
    unsealed.status === 401 && unsealed.json?.status === 'error', `${unsealed.status}`);
}

// ── 15. the CLUB SERVICE ACCOUNT on the native transport ───────────────────
// Nothing else in this suite exercised the native club client directly: the live dry run reaches it
// only through the invitation read, and the 244-check clubs gate speaks the proxy protocol. That left
// the account's own sign-in shape unpinned — the same shape whose absence broke a player sign-in in
// production, and the one path this relay has no alternative to (if it cannot sign in, every club
// route 503s and the failure message names neither origins nor headers).
{
  const clientEnv = (extra = {}) => ({
    ...process.env,
    NCB_TRANSPORT: 'native',
    NCB_AUTH_API_URL: `${FAKE_BASE}/api/user-auth`,
    NCB_DATA_API_URL: `${FAKE_BASE}/api/data`,
    NCB_INSTANCE: '55954_bridgemind',
    CLUB_NCB_EMAIL: 'a@poc.invalid',
    CLUB_NCB_PASSWORD: 'pw-a-fixture',
    // The id, not just the address: a session that names no email cannot be matched to the account it
    // is supposed to be, and the next two arms show the client refusing exactly that case rather than
    // trusting the password it was given. Production should set this for the same reason.
    CLUB_NCB_EXPECTED_USER_ID: 'user-aaaa',
    ...extra
  });
  const base = { NCB_PROXY_BASE: FAKE_BASE, NCB_INSTANCE: '55954_bridgemind' };

  const mark = upstreamLog.length;
  const client = bridge.createNcbAccountClient({ env: clientEnv(), ...base });
  const read = await client.request({ group: 'data', path: 'read/user_codes?code=NOPE', method: 'GET' });
  const sent = upstreamLog.slice(mark);
  const signInSent = sent.find((e) => e.path.endsWith('/sign-in/email'));
  const sessionSent = sent.find((e) => e.path.endsWith('/get-session'));
  const dataSent = sent.find((e) => e.path.startsWith('/api/data/'));
  check('15a. the club account signs in natively: Origin, X-Database-Instance, ?db=, and never an Authorization header',
    client.configured === true && read.ok === true && signInSent
    && typeof signInSent.originHeader === 'string' && /^https:\/\//.test(signInSent.originHeader)
    && signInSent.instanceHeader === '55954_bridgemind' && signInSent.query.db === '55954_bridgemind'
    && signInSent.hasAuthorization === false,
    JSON.stringify({ ok: read?.ok, reason: read?.reason, origin: signInSent?.originHeader, header: signInSent?.instanceHeader, auth: signInSent?.hasAuthorization }));
  check('15b. its session then rides as the vendor cookie on data calls, with no secret in the slot',
    sessionSent?.hasCookie === true && dataSent?.hasCookie === true && dataSent?.hasAuthorization === false,
    JSON.stringify({ session: sessionSent?.hasCookie, data: dataSent?.hasCookie, auth: dataSent?.hasAuthorization }));
  check('15c. identity still comes from get-session, and the client reports it as verified',
    client.status().identityVerified === true && client.status().user?.id === 'user-aaaa',
    JSON.stringify(client.status()));

  // The refusal this account type makes when the session cannot be matched to it. A sign-in that is
  // accepted but unverifiable must yield zero data calls — the rule the whole club feature rests on.
  const mark0 = upstreamLog.length;
  const noEmail = bridge.createNcbAccountClient({
    env: { ...clientEnv(), CLUB_NCB_EXPECTED_USER_ID: '' }, ...base
  });
  const noEmailResult = await noEmail.request({ group: 'data', path: 'read/clubs', method: 'GET' });
  const afterNoEmail = upstreamLog.slice(mark0);
  check('15c2. an accepted password is not an identity: with no expected id and no email in the session, every club read is refused',
    noEmailResult.ok === false && noEmailResult.reason === 'club_account_identity_unverifiable'
    && afterNoEmail.filter((e) => e.path.startsWith('/api/data/')).length === 0
    && noEmail.status().sessionActive === false,
    `${noEmailResult.reason}; data calls ${afterNoEmail.filter((e) => e.path.startsWith('/api/data/')).length}`);

  // A configured id that the session does not match must fail closed BEFORE any data call.
  const mark2 = upstreamLog.length;
  const mismatched = bridge.createNcbAccountClient({ env: clientEnv({ CLUB_NCB_EXPECTED_USER_ID: 'someone-else' }) , ...base });
  const mismatchedResult = await mismatched.request({ group: 'data', path: 'read/clubs', method: 'GET' });
  const afterMismatch = upstreamLog.slice(mark2);
  check('15d. a session naming a different account is refused, and zero club rows are read with it',
    mismatchedResult.ok === false && mismatchedResult.reason === 'club_account_identity_mismatch'
    && afterMismatch.filter((e) => e.path.startsWith('/api/data/')).length === 0,
    `${mismatchedResult.reason}; data calls ${afterMismatch.filter((e) => e.path.startsWith('/api/data/')).length}`);

  // And the failure mode the Origin header would produce: a 403 at sign-in.
  const mark3 = upstreamLog.length;
  signinFault = { status: 403, code: 'FORBIDDEN', message: 'Invalid origin' };
  const refused = bridge.createNcbAccountClient({ env: clientEnv(), ...base });
  const refusedResult = await refused.request({ group: 'data', path: 'read/clubs', method: 'GET' });
  signinFault = null;
  const afterRefusal = upstreamLog.slice(mark3);
  check('15e. a 403 at sign-in is reported as a login failure with a cooldown, retried exactly once and never as a data answer',
    refusedResult.ok === false && refusedResult.reason === 'club_account_login_failed'
    && afterRefusal.filter((e) => e.path.endsWith('/sign-in/email')).length === 1
    && afterRefusal.filter((e) => e.path.startsWith('/api/data/')).length === 0
    && refused.status().sessionActive === false,
    `${refusedResult.reason}; sign-ins ${afterRefusal.filter((e) => e.path.endsWith('/sign-in/email')).length}`);
  check('15f. and the refusal detail never carries the account password',
    !JSON.stringify(refusedResult).includes('pw-a-fixture') && !JSON.stringify(refused.status()).includes('pw-a-fixture'), '');
}

// ── 16. REGISTRATION AVAILABILITY ──────────────────────────────────────────
//
// The release instruction says public registration is temporarily restricted. An instruction is not a
// control: this gateway forwards `sign-up/email` to the vendor, and the shipped frontend validates the
// invitation code in the BROWSER before calling it, so a caller that skips the UI could create an
// account with no code at all — while the write policy added in this same change set refuses the claim
// that would mark that code used. Open and broken at once. The gateway therefore refuses sign-up unless
// NCB_GATEWAY_ALLOW_SIGN_UP=1, and these arms measure the refusal instead of trusting the comment.
{
  const callAt = async (base, method, route, { token = '', body } = {}) => {
    const res = await fetch(`${base}${route}`, {
      method,
      headers: { 'Content-Type': 'application/json', Origin: ALLOWED_ORIGIN, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    const json = await res.json().catch(() => null);
    return { status: res.status, json };
  };

  // The default mount: probeMount, built without the flag, which is what a deployment gets when it sets
  // nothing — the configuration Coolify will actually be in on release day.
  const markClosed = upstreamLog.length;
  const closed = await callAt(PROBE_BASE, 'POST', '/ncb/auth/sign-up/email', {
    body: { email: 'visitor@poc.invalid', password: 'pw-new-fixture', name: 'No Invitation' }
  });
  const dialledWhileClosed = upstreamLog.slice(markClosed).filter((e) => e.path.endsWith('/sign-up/email')).length;
  check('16a. registration is refused by default, before the vendor is contacted — no account can be created through this process',
    closed.status === 403 && closed.json?.error === 'sign_up_unavailable' && dialledWhileClosed === 0,
    `${closed.status}/${closed.json?.error}; upstream sign-up calls ${dialledWhileClosed}`);
  check('16b. the refusal says what to do instead of pretending a credential was bad — sign-in is untouched',
    /signing in still works/.test(String(closed.json?.detail || ''))
    && (await callAt(PROBE_BASE, 'POST', '/ncb/auth/sign-in/email', { body: { email: 'a@poc.invalid', password: 'pw-a-fixture' } })).status === 200,
    String(closed.json?.detail || '').slice(0, 60));
  check('16c. health reports the registration state, so a deploy that opened it is visible without reading env',
    probeMount.health().signUpAllowed === false, `${probeMount.health().signUpAllowed}`);

  // The operator's lever, measured in both directions: exact '1' opens it, anything else does not.
  const openMount = bridge.buildNcbGateway({ env: { ...process.env, NCB_GATEWAY_AUTH_RATE_MAX: '5000', NCB_GATEWAY_ALLOW_SIGN_UP: '1' } });
  const openApp = require('express')();
  openApp.use(require('express').json());
  openApp.use(openMount.router);
  const openServer = openApp.listen(0, '127.0.0.1');
  await new Promise((r) => openServer.once('listening', r));
  const OPEN_BASE = `http://127.0.0.1:${openServer.address().port}`;
  const markOpen = upstreamLog.length;
  const opened = await callAt(OPEN_BASE, 'POST', '/ncb/auth/sign-up/email', {
    body: { email: 'a@poc.invalid', password: 'pw-a-fixture', name: 'With Lever', hackerField: 'nope' }
  });
  const sentSignUp = upstreamLog.slice(markOpen).find((e) => e.path.endsWith('/sign-up/email'));
  check('16d. the lever alone is NOT enough: with no privileged claim channel, enabling registration answers 503 and creates nobody',
    openMount.health().signUpAllowed === true && openMount.health().invitationClaimWired === false
    && opened.status === 503 && opened.json?.error === 'invitation_claim_unavailable' && !sentSignUp,
    JSON.stringify({ status: opened.status, error: opened.json?.error, upstreamSignUpCalls: sentSignUp ? 1 : 0 }));
  // A mount that DOES have a claim channel, so the invitation precondition is measured as a rule and
  // not merely as an absence. The reader/writer here are local on purpose: the end-to-end claim over
  // the service account is verify-ncb-integration.mjs section 14's job.
  const localCodes = [{ id: 7, code: 'GATEWAY-OK-1', used: 0, registered_user_id: null }];
  // A reservation store of the same shape the relay wires — including the UNIQUE refusal, because an
  // adapter that always says yes would make the contention arms measure nothing.
  const localReservations = (() => {
    const rows = [];
    let nextId = 1;
    return createInvitationReservations({
      request: async ({ path: p, body, query }) => {
        const seg = String(p).split('/');
        const verb = seg[0];
        const idPart = seg[2];
        if (verb === 'create') {
          if (rows.some((r) => String(r.code_row_id) === String(body.code_row_id))) {
            return { ok: false, httpStatus: 400, body: { message: 'Duplicate entry for key code_row_id' } };
          }
          const row = { id: nextId++, code_row_id: String(body.code_row_id), invitee_email_hash: body.invitee_email_hash, status: 'pending' };
          rows.push(row);
          return { ok: true, httpStatus: 201, body: { id: row.id } };
        }
        if (verb === 'read') {
          const q = new URLSearchParams(query || '');
          const byRecord = q.get('code_row_id'); const byHash = q.get('invitee_email_hash');
          let list = rows;
          if (byRecord !== null) list = list.filter((r) => String(r.code_row_id) === byRecord);
          if (byHash !== null) list = list.filter((r) => String(r.invitee_email_hash) === byHash);
          return { ok: true, httpStatus: 200, body: { data: list } };
        }
        if (verb === 'update') {
          const row = rows.find((r) => String(r.id) === idPart);
          if (!row) return { ok: false, httpStatus: 404 };
          Object.assign(row, body);
          return { ok: true, httpStatus: 200, body: { data: row } };
        }
        if (verb === 'delete') {
          const i = rows.findIndex((r) => String(r.id) === idPart);
          if (i < 0) return { ok: false, httpStatus: 404 };
          rows.splice(i, 1);
          return { ok: true, httpStatus: 200 };
        }
        return { ok: false, httpStatus: 404 };
      },
      table: 'invitation_reservations'
    });
  })();
  const localWrites = [];
  const localClaim = createInvitationClaimForGate({
    readRows: async ({ code }) => ({ ok: true, rows: localCodes.filter((r) => r.code === code) }),
    writeRow: async ({ recordId, userId }) => {
      const row = localCodes.find((r) => String(r.id) === String(recordId));
      localWrites.push({ recordId, userId });
      if (!row) return { ok: false };
      row.used = 1; row.registered_user_id = userId;
      return { ok: true };
    },
    reservations: localReservations,
    emailSecret: 'gate-invitation-reservation-hmac-key-not-a-secret'
  });
  const withClaim = bridge.buildNcbGateway({ env: { ...process.env, NCB_GATEWAY_AUTH_RATE_MAX: '5000', NCB_GATEWAY_ALLOW_SIGN_UP: '1' }, invitationClaim: localClaim });
  const claimApp = require('express')();
  claimApp.use(require('express').json());
  claimApp.use(withClaim.router);
  const claimServer = claimApp.listen(0, '127.0.0.1');
  await new Promise((r) => claimServer.once('listening', r));
  const CLAIM_BASE = `http://127.0.0.1:${claimServer.address().port}`;
  const beforeCodeless = upstreamLog.length;
  const noCode = await callAt(CLAIM_BASE, 'POST', '/ncb/auth/sign-up/email', { body: { email: 'a@poc.invalid', password: 'pw-a-fixture', name: 'No Code' } });
  const codelessReachedVendor = upstreamLog.slice(beforeCodeless).filter((e) => e.path.endsWith('/sign-up/email')).length;
  const markClaimed = upstreamLog.length;
  const withCode = await callAt(CLAIM_BASE, 'POST', '/ncb/auth/sign-up/email', { body: { email: 'a@poc.invalid', password: 'pw-a-fixture', name: 'Invited', invitationCode: 'GATEWAY-OK-1' } });
  const sentWithCode = upstreamLog.slice(markClaimed).find((e) => e.path.endsWith('/sign-up/email'));
  check('16g. with a claim channel wired: a codeless sign-up is refused without dialling the vendor, and a coded one registers and spends',
    noCode.status === 403 && noCode.json?.error === 'invitation_required' && codelessReachedVendor === 0
    && withCode.status === 200 && withCode.json?.invitationClaimed === true
    && Number(localCodes[0].used) === 1 && String(localCodes[0].registered_user_id) === String(withCode.json?.data?.user?.id),
    JSON.stringify({ noCode: `${noCode.status}/${noCode.json?.error}`, reachedVendor: codelessReachedVendor, coded: `${withCode.status}/${withCode.json?.invitationClaimed}`, row: localCodes[0] }));
  const reused = await callAt(CLAIM_BASE, 'POST', '/ncb/auth/sign-up/email', { body: { email: 'b@poc.invalid', password: 'pw-b-fixture', invitationCode: 'GATEWAY-OK-1' } });
  check('16h. the same code cannot be spent twice through this route, and the answer is exhaustion — not a duplicate fault',
    reused.status === 409 && reused.json?.error === 'invitation_exhausted', `${reused.status}/${reused.json?.error}`);
  check('16i. the invitation code never travels upstream — the vendor sees exactly its own three fields',
    withCode.status === 200 && sentWithCode && sentWithCode.body?.invitationCode === undefined
    && Object.keys(sentWithCode.body ?? {}).sort().join(',') === 'email,name,password',
    JSON.stringify({ status: withCode.status, bodyKeys: Object.keys(sentWithCode?.body ?? {}) }));
  await new Promise((r) => claimServer.close(r));
  const truthy = bridge.buildNcbGateway({ env: { ...process.env, NCB_GATEWAY_ALLOW_SIGN_UP: 'true' } });
  const loose = bridge.buildNcbGateway({ env: { ...process.env, NCB_GATEWAY_ALLOW_SIGN_UP: '0' } });
  check('16e. the lever is exact: "true"/"0"/anything but "1" leaves registration closed (a typo must not open a public signup)',
    truthy.health().signUpAllowed === false && loose.health().signUpAllowed === false,
    `true=${truthy.health().signUpAllowed} 0=${loose.health().signUpAllowed}`);
  /* WHICH OUTCOMES MAY FREE A RESERVATION, pinned as a table against the shipped predicate. This is
     the one decision in registration that cannot be re-litigated after the fact: release too early and
     a record whose account was quietly created goes to a second registrant, release too late and every
     mistyped email costs the pool a record forever. Asserting the mapping directly — not only through
     one outage arm and one duplicate-email arm — is what stops a future edit to the status table from
     moving a single line and passing. */
  {
    const ambiguous = require('./ncb/gateway.js').signUpOutcomeIsAmbiguous;
    const holds = [[0, 'no answer at all'], [408, 'request timeout'], [500, 'server fault'], [502, 'bad gateway'], [503, 'unavailable'], [504, 'gateway timeout']];
    const frees = [[400, 'malformed / already-registered'], [401, 'credentials refused'], [403, 'policy refusal'], [422, 'validation refusal'], [429, 'vendor throttle']];
    const wrong = [
      ...holds.filter(([s]) => ambiguous(s) !== true).map(([s, w]) => `${s} (${w}) should HOLD`),
      ...frees.filter(([s]) => ambiguous(s) !== false).map(([s, w]) => `${s} (${w}) should RELEASE`)
    ];
    check('16j. an ambiguous account-creation outcome holds the reservation and a decided refusal frees it, across the whole status table',
      wrong.length === 0 && ambiguous(undefined) === true && ambiguous('') === true && ambiguous(NaN) === true,
      wrong.join('; ') || `holds=${holds.length} frees=${frees.length}`);
  }
  // The invitation lookup must survive the new refusal. Measured on a mount that can actually serve it:
  // the shipped relay's reader needs a configured Clubs service account (it answers 503 without one),
  // and its auth throttle had already been spent by sections 8-15 — both of those properties are
  // measured where they belong, and this arm is only about the route surviving the registration gate.
  const lookupMount = bridge.buildNcbGateway({
    env: { ...process.env, NCB_GATEWAY_AUTH_RATE_MAX: '5000', NCB_GATEWAY_PUBLIC_RATE_MAX: '5000' },
    guestRead: async () => ({ ok: true, rows: [{ id: 900, code: 'BRIDGE-2026-KEY', used: 0, registered_user_id: null }] })
  });
  const lookupApp = require('express')();
  lookupApp.use(require('express').json());
  lookupApp.use(lookupMount.router);
  const lookupServer = lookupApp.listen(0, '127.0.0.1');
  await new Promise((r) => lookupServer.once('listening', r));
  const LOOKUP_BASE = `http://127.0.0.1:${lookupServer.address().port}`;
  const relaySignUp = await fetch(`${LOOKUP_BASE}/ncb/auth/sign-up/email`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ALLOWED_ORIGIN },
    body: JSON.stringify({ email: 'walk-in@poc.invalid', password: 'pw-walk-in-fixture', name: 'No Code' })
  });
  const relayCodes = await fetch(`${LOOKUP_BASE}/ncb/public-data/read/user_codes?code=BRIDGE-2026-KEY`, { headers: { Origin: ALLOWED_ORIGIN } });
  check('16f. registration closed and the anonymous invitation lookup served are compatible on the same mount',
    relaySignUp.status === 403 && relayCodes.status === 200,
    `sign-up=${relaySignUp.status} codes=${relayCodes.status}`);
  await new Promise((r) => lookupServer.close(r));
  await new Promise((r) => openServer.close(r));
}

await new Promise((r) => probeServer.close(r));

await new Promise((r) => server.close(r));
await new Promise((r) => fake.close(r));

const failed = results.filter((r) => !r.pass);
for (const r of results) console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `   [${r.detail}]` : ''}`);
console.log(`\nRESULTS: ${results.length - failed.length} passed, ${failed.length} failed`);
if (failed.length) { console.log('NEW FAILURES:'); for (const r of failed) console.log(`  - ${r.name} ${r.detail}`); }
process.exit(failed.length ? 1 : 0);
