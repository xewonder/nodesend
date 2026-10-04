// NodeSend TRICKSTER gateway verification harness.
//
// Everything runs in-process against a loopback mock of the two upstream services,
// with the BridgeMind session authority (NCB /auth/get-session) mocked through
// global.fetch: NO production endpoint is contacted, and no real store is needed.
// The relay itself is the real exported `app`, served over HTTP, so the routes, the
// session guard and the body forwarding are exercised exactly as a browser would
// exercise them.
//
//   node verify-trickster-gateway.mjs
import { createRequire } from 'node:module';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));

const SESSION_SECRET = 'ncb-session-lookup-must-never-appear-in-a-response';
const UPSTREAM_SECRET = 'TRICKSTER-UPSTREAM-KEY-do-not-leak-8f21';
const BID_DECOY = 'https://bid.example.invalid';

// The four Trickster routes never touch the per-user quota store, so this harness needs no
// store mock beyond the session lookup below — and since NodeSend became the quota
// authority, "no store mock" is a claim worth testing rather than assuming: the fetch stub
// records any /data/ route it is asked for, and check 12b fails the run if a Trickster call
// ever spends a user's quota. (This file used to stub the `pg` driver for the retired
// Postgres quota path; that dependency is gone.)
const ncbDataRoutes = [];

process.env.BRIDGE_API_KEY = 'relay-key-not-used-by-trickster';
process.env.NCB_PROXY_BASE = 'https://ncb.test.invalid';
process.env.NCB_INSTANCE = '55954_bridgemind';
process.env.TRICKSTER_BID_URL = BID_DECOY;
process.env.TRICKSTER_PLAY_URL = BID_DECOY;
process.env.TRICKSTER_TIMEOUT_MS = '15000';
process.env.TRICKSTER_API_KEY = UPSTREAM_SECRET;

const SESSIONS = { 'tok-good': { id: 7, role: 'user' }, 'tok-admin': { id: 9, role: 'administrator' } };

// ── mock upstream: records what the relay actually sent ─────────────────────
const served = [];
let upstreamMode = 'ok';
const upstream = http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    const record = { url: req.url, method: req.method, body, headers: req.headers };
    served.push(record);
    const json = (status, payload, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers });
      res.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
    };
    if (req.url === '/hang') return; // never answers: the relay's timeout must fire
    if (upstreamMode === 'html') return json(200, '<!DOCTYPE html><html><body>ok</body></html>', { 'content-type': 'text/html' });
    if (upstreamMode === 'html-error') return json(400, '<!DOCTYPE html><pre>Bad Request</pre>', { 'content-type': 'text/html' });
    if (upstreamMode === 'truncated') return json(200, '{"bid":');
    if (upstreamMode === 'bid-extra') return json(200, { bid: '3C', confidence: 0.9 });
    if (upstreamMode === 'bid-wrong') return json(200, { card: '3C' });
    if (upstreamMode === 'play-extra') return json(200, { suit: 1, rank: 13, pct: 71 });
    if (upstreamMode === 'play-strings') return json(200, { suit: '1', rank: '13' });
    if (upstreamMode === 'leak') return json(500, { error: `BridgeBidder.dll: Stack Trace at System.Parse at /app/src/deal.cs:88 secret=${UPSTREAM_SECRET}` });
    if (upstreamMode === 'reject400') return json(400, { error: 'Vulnerable value Both is invalid.' });
    if (upstreamMode === 'reject405') return json(405, { error: 'Method not allowed.' }, { allow: 'POST' });
    if (upstreamMode === 'reject500') return json(500, { error: 'Internal server error.' });
    if (req.url === '/health') return json(200, { status: 'ok' });
    if (req.url === '/suggest-bid') return json(200, { bid: '3C' });
    if (req.url === '/suggest-card') return json(200, { suit: 1, rank: 13 });
    return json(404, { error: 'not found' });
  });
});
await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
const UPSTREAM_BASE = `http://127.0.0.1:${upstream.address().port}`;
process.env.TRICKSTER_BID_URL = UPSTREAM_BASE;
process.env.TRICKSTER_PLAY_URL = UPSTREAM_BASE;

const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  if (target.startsWith('https://ncb.test.invalid')) {
    // A Trickster call must never reach the quota storage. Recording the NCB traffic here
    // makes "Trickster is quota-free" an observation about this run rather than a reading
    // of the source text — see check 12b below.
    if (new URL(target).pathname.startsWith('/data/')) ncbDataRoutes.push(new URL(target).pathname);
    const token = String(init?.headers?.Authorization || init?.headers?.authorization || '');
    const key = token.replace(/^Bearer\s+/, '');
    const user = SESSIONS[key];
    return new Response(JSON.stringify(user
      ? { status: 'success', data: { user } }
      : { status: 'error', message: 'invalid session' }), {
      status: user ? 200 : 401, headers: { 'content-type': 'application/json' }
    });
  }
  if (target.startsWith('https://hang.test.invalid')) {
    return new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    });
  }
  return realFetch(url, init);
};

const bridge = require(path.join(ROOT, 'bridge.js'));
const { app, tricksterBaseUrl, tricksterUpstreamHeaders, tricksterSafeError, tricksterShapeOk, tricksterTimeoutMs } = bridge;
const server = await new Promise((resolve) => {
  const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
});
const BASE = `http://127.0.0.1:${server.address().port}`;

const results = [];
const check = (name, pass, detail = '') => results.push({ name, pass: !!pass, detail: String(detail).slice(0, 220) });
const call = async (method, route, { token, body, headers = {} } = {}) => {
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: {
      accept: 'application/json',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, json, text, headers: res.headers };
};

const HAR_FIXTURE = {
  deal: 'W:J92.84.K5.QJT853 - - -',
  vulnerable: 'None',
  auction: '',
  bidSystemNS: 'TwoOverOneGameForce',
  bidSystemEW: 'TwoOverOneGameForce'
};
const PLAY_FIXTURE = { trumpSuit: 3, player: { hand: 'KCQC9C' }, legalCards: [{ suit: 1, rank: 13 }] };

// ── 1-3: existence and the session guard ───────────────────────────────────
const ROUTES = [
  ['GET', '/trickster/bid/health'], ['GET', '/trickster/play/health'],
  ['POST', '/trickster/bid/suggest-bid'], ['POST', '/trickster/play/suggest-card']
];
const withSession = [];
for (const [method, route] of ROUTES) {
  served.length = 0; upstreamMode = 'ok';
  const res = await call(method, route, { token: 'tok-good', body: method === 'POST' ? HAR_FIXTURE : undefined });
  withSession.push({ route, status: res.status, proxied: served.length });
}
check('1. all four Trickster routes exist and are proxied with a session',
  withSession.length === 4 && withSession.every((r) => r.status === 200 && r.proxied === 1),
  JSON.stringify(withSession));

const withoutSession = [];
for (const [method, route] of ROUTES) {
  served.length = 0;
  const res = await call(method, route, { body: method === 'POST' ? HAR_FIXTURE : undefined });
  const bad = await call(method, route, { token: 'tok-not-a-session', body: method === 'POST' ? HAR_FIXTURE : undefined });
  const relayKeyOnly = await call(method, route, { headers: { 'x-api-key': 'relay-key-not-used-by-trickster' }, body: method === 'POST' ? HAR_FIXTURE : undefined });
  withoutSession.push({
    route, anonymous: res.status, invalid: bad.status, relayKeyOnly: relayKeyOnly.status,
    proxied: served.length, body: res.json
  });
}
check('2. all four routes require the BridgeMind session (same guard as /ai/chat)',
  withoutSession.every((r) => r.anonymous === 401 && r.invalid === 401 && r.relayKeyOnly === 401),
  JSON.stringify(withoutSession.map(({ route, anonymous, invalid, relayKeyOnly }) => `${route} ${anonymous}/${invalid}/${relayKeyOnly}`)));
check('3. unauthenticated fails closed: no upstream call, no decision, session code',
  withoutSession.every((r) => r.proxied === 0 && r.body?.success === false && r.body?.status === 'auth_error' && !('bid' in (r.body ?? {}))),
  JSON.stringify(withoutSession[0]?.body));

// ── 4-5: the exact HAR fixture, forwarded unchanged ───────────────────────
served.length = 0; upstreamMode = 'ok';
const har = await call('POST', '/trickster/bid/suggest-bid', { token: 'tok-good', body: HAR_FIXTURE });
const forwarded = JSON.parse(served[0]?.body ?? '{}');
check('4. the exact opening-bid fixture is forwarded unchanged',
  served.length === 1 && served[0].url === '/suggest-bid' && served[0].method === 'POST'
  && JSON.stringify(forwarded) === JSON.stringify(HAR_FIXTURE)
  && forwarded.deal === 'W:J92.84.K5.QJT853 - - -'
  && Object.keys(forwarded).join() === Object.keys(HAR_FIXTURE).join()
  && har.status === 200 && JSON.stringify(har.json) === '{"bid":"3C"}',
  `${served[0]?.url} ${served[0]?.body}`);
check('5. an empty auction stays an empty string, never null/absent/[]',
  Object.hasOwn(forwarded, 'auction') && forwarded.auction === ''
  && served[0].body.includes('"auction":""') && !served[0].body.includes('"auction":null'),
  served[0]?.body ?? '');
check('5b. the play route forwards its body unchanged too',
  await (async () => {
    served.length = 0;
    const res = await call('POST', '/trickster/play/suggest-card', { token: 'tok-good', body: PLAY_FIXTURE });
    return served.length === 1 && served[0].url === '/suggest-card'
      && JSON.stringify(JSON.parse(served[0].body)) === JSON.stringify(PLAY_FIXTURE)
      && res.status === 200 && res.json?.suit === 1 && res.json?.rank === 13;
  })(), served[0]?.body ?? '');

// ── 6-7: response shape validation ────────────────────────────────────────
const bidShapes = [];
for (const [mode, expect] of [['ok', 200], ['bid-extra', 502], ['bid-wrong', 502]]) {
  upstreamMode = mode;
  const res = await call('POST', '/trickster/bid/suggest-bid', { token: 'tok-good', body: HAR_FIXTURE });
  bidShapes.push({ mode, status: res.status, body: res.json });
}
check('6. a bid 200 must be exactly {"bid":"..."}; anything wider is refused as a contract change',
  bidShapes[0].status === 200 && JSON.stringify(bidShapes[0].body) === '{"bid":"3C"}'
  && bidShapes[1].status === 502 && bidShapes[1].body?.error === 'trickster_unexpected_shape'
  && bidShapes[2].status === 502 && !('card' in (bidShapes[2].body ?? {})),
  JSON.stringify(bidShapes));
const playShapes = [];
for (const [mode, expect] of [['ok', 200], ['play-extra', 502], ['play-strings', 502]]) {
  upstreamMode = mode;
  const res = await call('POST', '/trickster/play/suggest-card', { token: 'tok-good', body: PLAY_FIXTURE });
  playShapes.push({ mode, status: res.status, body: res.json });
}
check('7. a play 200 must be exactly {"suit":n,"rank":n} with integers',
  playShapes[0].status === 200 && JSON.stringify(playShapes[0].body) === '{"suit":1,"rank":13}'
  && playShapes[1].status === 502 && playShapes[2].status === 502
  && playShapes.every((s) => !('pct' in (s.body ?? {}))), JSON.stringify(playShapes));
check('7b. no requestId or gateway metadata is ever added to a 200 body',
  Object.keys(har.json ?? {}).join() === 'bid' && Object.keys(bidShapes[0].body ?? {}).join() === 'bid',
  JSON.stringify(har.json));

// ── 8: upstream status preserved, safely ──────────────────────────────────
const statuses = [];
for (const [mode, want, wantError] of [
  ['reject400', 400, 'Vulnerable value Both is invalid.'],
  ['reject405', 405, undefined],
  ['reject500', 500, 'Internal server error.'],
  ['leak', 500, 'trickster_upstream_500']
]) {
  upstreamMode = mode;
  const res = await call('POST', '/trickster/bid/suggest-bid', { token: 'tok-good', body: HAR_FIXTURE });
  statuses.push({ mode, status: res.status, body: res.json });
  if (res.json?.error !== wantError) statuses[statuses.length - 1].mismatch = `${res.json?.error} != ${wantError}`;
}
check('8. 400/405/500 semantics are preserved with the upstream status code',
  statuses[0].status === 400 && statuses[0].body?.upstreamStatus === 400
  && statuses[1].status === 405 && statuses[1].body?.upstreamStatus === 405
  && statuses[2].status === 500 && statuses[2].body?.upstreamStatus === 500,
  JSON.stringify(statuses.map(({ mode, status }) => `${mode}=${status}`)));
check('8b. an upstream stack trace, path or secret is never relayed',
  statuses[3].status === 500 && statuses[3].body?.error === 'trickster_upstream_500'
  && !/Stack|Trace|\.cs|\/app\/|at System|BridgeBidder/.test(JSON.stringify(statuses[3].body))
  && !JSON.stringify(statuses[3].body).includes(UPSTREAM_SECRET)
  && tricksterSafeError({ error: 'Traceback: /app/x.py at deal.Parse' }, 500) === 'trickster_upstream_500'
  && tricksterSafeError({ error: 'Field deal is required.' }, 400) === 'Field deal is required.',
  JSON.stringify(statuses[3].body));
check('8c. a wrong verb on a real path answers 405 with Allow: POST, not 404',
  await (async () => {
    const res = await call('GET', '/trickster/bid/suggest-bid', { token: 'tok-good' });
    const play = await call('GET', '/trickster/play/suggest-card', { token: 'tok-good' });
    return res.status === 405 && res.headers.get('allow') === 'POST'
      && play.status === 405 && play.headers.get('allow') === 'POST';
  })());

// ── 9: non-JSON upstream ──────────────────────────────────────────────────
const htmlResults = [];
for (const mode of ['html', 'html-error', 'truncated']) {
  upstreamMode = mode;
  const res = await call('POST', '/trickster/bid/suggest-bid', { token: 'tok-good', body: HAR_FIXTURE });
  htmlResults.push({ mode, status: res.status, body: res.json, text: res.text });
}
check('9. an HTML or malformed upstream answer is refused, and its text never reaches the caller',
  htmlResults.every((r) => r.status === 502 && r.body?.error === 'trickster_invalid_response')
  && !htmlResults.some((r) => /DOCTYPE|<html>|<pre>|Bad Request/.test(r.text)),
  JSON.stringify(htmlResults.map(({ mode, status, body }) => `${mode}=${status}:${body?.error}`)));

// ── 10: timeout and unreachable ───────────────────────────────────────────
process.env.TRICKSTER_BID_URL = 'https://hang.test.invalid';
upstreamMode = 'ok';
const timedOut = await call('POST', '/trickster/bid/suggest-bid', { token: 'tok-good', body: HAR_FIXTURE });
process.env.TRICKSTER_BID_URL = 'http://127.0.0.1:1/unreachable';
const unreachable = await call('POST', '/trickster/bid/suggest-bid', { token: 'tok-good', body: HAR_FIXTURE });
process.env.TRICKSTER_BID_URL = UPSTREAM_BASE;
const recovered = await call('POST', '/trickster/bid/suggest-bid', { token: 'tok-good', body: HAR_FIXTURE });
check('10. timeout answers 504 and an unreachable service 502, both JSON, and neither is retried locally',
  timedOut.status === 504 && timedOut.json?.error === 'trickster_timeout'
  && unreachable.status === 502 && unreachable.json?.error === 'trickster_unreachable'
  && recovered.status === 200 && recovered.json?.bid === '3C'
  && !('fallback' in (timedOut.json ?? {})) && !('bid' in (unreachable.json ?? {})),
  JSON.stringify({ timeout: timedOut.status, unreachable: unreachable.status, recovered: recovered.status }));
check('10b. a misconfigured upstream URL fails closed instead of being called',
  tricksterBaseUrl('bid') === UPSTREAM_BASE
  && (() => {
    const previous = process.env.TRICKSTER_BID_URL;
    process.env.TRICKSTER_BID_URL = 'http://bid.example.com';
    const httpRejected = tricksterBaseUrl('bid') === null;
    process.env.TRICKSTER_BID_URL = 'https://user:pw@bid.example.com';
    const credsRejected = tricksterBaseUrl('bid') === null;
    process.env.TRICKSTER_BID_URL = 'not a url';
    const malformedRejected = tricksterBaseUrl('bid') === null;
    process.env.TRICKSTER_BID_URL = previous;
    return httpRejected && credsRejected && malformedRejected;
  })()
  && (() => { const previous = process.env.TRICKSTER_BID_URL; process.env.TRICKSTER_BID_URL = 'http://127.0.0.1:9'; const loopbackOk = tricksterBaseUrl('bid') === 'http://127.0.0.1:9'; process.env.TRICKSTER_BID_URL = previous; return loopbackOk; })(),
  JSON.stringify({ base: tricksterBaseUrl('bid') }));
check('10c. the timeout is bounded and read per request',
  (() => {
    const previous = process.env.TRICKSTER_TIMEOUT_MS;
    const read = (value) => { process.env.TRICKSTER_TIMEOUT_MS = value; return tricksterTimeoutMs(); };
    const inside = read('30000');
    const atMax = read('60000');
    const aboveMax = read('90000');
    const belowMin = read('10');
    const unset = read('');
    const junk = read('abc');
    process.env.TRICKSTER_TIMEOUT_MS = previous;
    return inside === 30000 && atMax === 60000 && aboveMax === 15000
      && belowMin === 15000 && unset === 15000 && junk === 15000;
  })(),
  `30000->${(() => { const p = process.env.TRICKSTER_TIMEOUT_MS; process.env.TRICKSTER_TIMEOUT_MS = '30000'; const v = tricksterTimeoutMs(); process.env.TRICKSTER_TIMEOUT_MS = p; return v; })()}`);
check('10d. the shape predicates accept the documented answers and refuse the rest',
  tricksterShapeOk('bid:suggest', { bid: 'Pass' }) === true
  && tricksterShapeOk('bid:suggest', { bid: '2NT' }) === true
  && tricksterShapeOk('bid:suggest', { bid: '' }) === false
  && tricksterShapeOk('bid:suggest', { bid: null }) === false
  && tricksterShapeOk('play:suggest', { suit: 0, rank: 14 }) === true
  && tricksterShapeOk('play:suggest', { rank: 14 }) === false
  && tricksterShapeOk('bid:health', { status: 'ok' }) === true
  && tricksterShapeOk('play:health', { status: 'ok', extra: 1 }) === false
  && tricksterShapeOk('bid:suggest', null) === false);

// ── 11: the upstream key is server-only ───────────────────────────────────
served.length = 0; upstreamMode = 'ok';
await call('POST', '/trickster/bid/suggest-bid', { token: 'tok-good', body: HAR_FIXTURE });
const root = await call('GET', '/', {});
const health = await call('GET', '/health', {});
const sourceOfTruth = fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8');
const envExample = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
const everyResponseText = [root.text, health.text, har.text, timedOut.text, unreachable.text,
  recovered.text].map((value) => String(value ?? '')).join('\n');
check('11. TRICKSTER_API_KEY is sent upstream and never returned by any route',
  served[0]?.headers?.['x-api-key'] === UPSTREAM_SECRET
  && !everyResponseText.includes(UPSTREAM_SECRET)
  && !JSON.stringify(root.json).includes(UPSTREAM_SECRET)
  && !JSON.stringify(health.json).includes(UPSTREAM_SECRET)
  && root.json?.trickster?.apiKeyConfigured === true
  && health.json?.trickster?.apiKeyConfigured === true,
  JSON.stringify({ upstream: served[0]?.headers?.['x-api-key'] ?? null, rootKeys: Object.keys(root.json ?? {}), healthKeys: Object.keys(health.json ?? {}) }));
check('11b. the key is read only server-side, is optional, and is never a VITE_ name',
  (() => {
    const clauses = {
      noViteTricksterInSource: !/VITE_TRICKSTER/.test(sourceOfTruth),
      noViteTricksterInEnvExample: !/VITE_TRICKSTER/.test(envExample),
      noViteAnyTrickster: !/VITE_\w*TRICKSTER/i.test(envExample),
      keyDocumentedAsServerSide: /TRICKSTER_API_KEY/.test(envExample),
      keyReadFromProcessEnv: sourceOfTruth.includes('process.env.TRICKSTER_API_KEY'),
      headerSentWhenConfigured: tricksterUpstreamHeaders()['x-api-key'] === UPSTREAM_SECRET,
      headerOmittedWhenUnset: (() => {
        const previous = process.env.TRICKSTER_API_KEY;
        delete process.env.TRICKSTER_API_KEY;
        const headerless = tricksterUpstreamHeaders();
        process.env.TRICKSTER_API_KEY = previous;
        // The header names are exactly what bridge.js writes; only x-api-key may
        // disappear, and the two content headers must survive without it.
        return !('x-api-key' in headerless)
          && headerless.Accept === 'application/json'
          && headerless['Content-Type'] === 'application/json';
      })(),
      noKeyEchoInResponses: !everyResponseText.includes(UPSTREAM_SECRET)
    };
    check.__clauses = clauses;
    return Object.values(clauses).every(Boolean);
  })(),
  JSON.stringify(check.__clauses ?? {}));

// ── 12: nothing that already worked was changed ───────────────────────────
const aiNoSession = await call('POST', '/ai/chat', { body: { messages: [] } });
const quotaConfigNoSession = await call('GET', '/ai/quota/config', {});
const quotaNoKey = await call('GET', '/quota', {});
const publicKey = await call('GET', '/crypto/public-key', {});
const missing = await call('GET', '/nope', {});
// The expectations below are the relay's documented PRE-EXISTING behaviour, read
// from bridge.js rather than guessed: requireApiKey answers 403 (500 only when the
// relay itself has no key configured), and /crypto/public-key answers 500 when no
// RSA key is present — this harness deliberately configures none, so the Trickster
// routes are proven not to depend on it.
check('12. existing AI, quota, session and relay behaviour is unchanged',
  aiNoSession.status === 401 && aiNoSession.json?.status === 'auth_error'
  && quotaConfigNoSession.status === 401
  && quotaNoKey.status === 403 && quotaNoKey.json?.error === 'Forbidden'
  && publicKey.status === 500 && publicKey.json?.error === 'NodeSend encryption is not configured'
  && missing.status === 404 && missing.json?.error === 'Endpoint not found'
  && root.json?.endpoints?.aiChat === 'POST /ai/chat'
  && root.json?.auth?.ai === 'BridgeMind Bearer session'
  // UPDATED 2026-10-04, disclosed: this clause used to pin the quota authority to
  // "bridgemind" and to require the remote-adapter helpers (bridgemindQuotaEndpoint,
  // sanitizeQuotaDecision) to exist. Both are gone by design — NodeSend is the sole quota
  // authority now — so the clause is re-aimed at the new surface rather than deleted: it
  // still proves the Trickster gateway did not disturb the quota reporting, and now proves
  // it reports the architecture the relay actually runs.
  && root.json?.quota?.authority === 'nodesend' && root.json?.quota?.storage === 'ncb'
  && root.json?.quota?.replicas === 'exactly-one-quota-service-replica'
  && health.json?.quotaAuthority === 'nodesend' && health.json?.quotaStorage === 'ncb'
  && health.json?.quotaReplicas === 'exactly-one-quota-service-replica'
  && health.json?.status === 'healthy'
  && root.json?.endpoints?.email === 'POST /send' && root.json?.endpoints?.quota === 'GET|POST /quota'
  && bridge.NODESEND_VERSION === 'bridge-nodesend-quota-v9'
  && typeof bridge.quotaStore?.findReservation === 'function'
  && typeof bridge.reserveQuotaDecision === 'function'
  && bridge.QUOTA_SINGLE_REPLICA_INVARIANT === 'exactly-one-quota-service-replica'
  && typeof bridge.bridgemindQuotaEndpoint === 'undefined'
  && typeof bridge.sanitizeQuotaDecision === 'undefined'
  && typeof bridge.quotaServiceState === 'undefined'
  && Object.keys(bridge.TRICKSTER_RESPONSE_SHAPES).join() === 'bid:health,play:health,bid:suggest,play:suggest'
  && !/requireApiKey[\s\S]{0,80}proxyTrickster/.test(sourceOfTruth)
  && (sourceOfTruth.match(/app\.(get|post)\("\/trickster\//g) || []).length === 6,
  JSON.stringify({ ai: aiNoSession.status, quotaConfig: quotaConfigNoSession.status, quota: quotaNoKey.status, pub: publicKey.status, missing: missing.status }));

// ── 12b: Trickster billing is unchanged ───────────────────────────────────
// Every Trickster call above went through requireBridgeSession, and NodeSend now holds the
// quota counter itself. If the gateway had been wired into the reservation path, one of
// those calls would have reached the store — so this is a measured absence, from the
// traffic of this run, not a reading of the source.
check('12b. a Trickster call never touches the quota store (billing unchanged)',
  ncbDataRoutes.length === 0, ncbDataRoutes.join(','));

// ── report ────────────────────────────────────────────────────────────────
server.close();
upstream.close();
globalThis.fetch = realFetch;
let failed = 0;
for (const r of results) {
  if (!r.pass) failed += 1;
  console.log(`${r.pass ? 'PASS' : 'FAIL'} ${r.name}${r.detail ? '  [' + r.detail + ']' : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
