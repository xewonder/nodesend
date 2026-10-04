// NodeSend session + external BridgeMind quota-decision verification harness.
//
//   node verify-session-quota.mjs
//
// Architecture under test: NodeSend validates the caller's BridgeMind bearer against
// NCB /auth/get-session, then asks a BridgeMind-OWNED quota service for a decision
// and relays it. NodeSend holds no quota data, so the mock of that service is a real
// loopback HTTP server rather than a fetch stub: the adapter's URL building, header
// forwarding, status mapping and body parsing are exercised over an actual socket,
// the way they will run against production BridgeMind.
//
// Nothing here contacts a real endpoint. global.fetch is replaced for the NCB session
// authority and the AI provider, and every other URL that is not loopback is refused
// outright, so an accidental call to a real host fails the run instead of making one.
//
// Section 1 proves the fail-closed state that matters most: with BRIDGEMIND_QUOTA_URL
// unset — which is the situation until BridgeMind publishes this endpoint — no quota
// route guesses, no provider is reached, and every surface says unavailable.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIV_B64 = Buffer.from(privateKey.export({ type: 'pkcs1', format: 'pem' })).toString('base64');
const PROVIDER_SECRET = 'sk-REAL-PROVIDER-KEY-should-never-be-logged-9f3a';
const NCB_BASE = 'https://ncb.test.invalid';
const NCB_LAMBDA_HOST = 'rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url';
// Something a quota service must never put in a decision, used to prove the relay
// drops fields it was never told about instead of relaying them.
const INTERNAL_BAIT = 'ai_quota_usage';
const SERVICE_INTERNAL_TOKEN = 'BRIDGEMIND-SERVICE-SECRET-do-not-relay-4d1c';
const enc = (s) => crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(s)).toString('base64');

const USERS = {
  'tok-a': { id: 101, role: 'user' },
  'tok-b': { id: 202, role: 'user' },
  'tok-d': { id: 203, role: 'user' },
  'tok-admin': { id: 900, role: 'administrator' }
};
const PERIOD = '2026-10';
const RESET_AT = '2026-11-01T00:00:00.000Z';
// Ordered trace of what the relay actually did, so "reserve happens before the
// provider" is a measured sequence rather than an assumption.
const events = [];
// Every route the NCB mock was asked for, so "NCB is used for the session lookup
// only" is settled by the traffic of this run rather than by a text search.
const ncbRoutes = [];
const world = { providerCalls: 0, providerAuthHeaders: [], seenAuthHeaders: [] };

// ── the BridgeMind quota service, as a real HTTP server ───────────────────
const service = {
  mode: 'allow',
  configMode: 'ok',
  requests: [],
  counters: { reserve: 0, status: 0, config: 0 },
  used: 0
};
const summaryFor = (allowed, extra = {}) => ({
  allowed, enabled: true, unlimited: false, period: PERIOD,
  used: service.used, limit: 3, remaining: Math.max(0, 3 - service.used),
  percentage: Math.round((service.used / 3) * 100), resetAt: RESET_AT, ...extra
});

const quotaService = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (chunk) => { raw += chunk; });
  req.on('end', () => {
    let body = null;
    try { body = raw ? JSON.parse(raw) : null; } catch { body = raw === '' ? null : raw; }
    const url = req.url;
    const route = url.replace(/^\//, '');
    service.requests.push({
      method: req.method, url, route, body, raw,
      auth: req.headers.authorization ?? null,
      apiKey: req.headers['x-api-key'] ?? null,
      contentType: req.headers['content-type'] ?? null
    });
    service.counters[route] = (service.counters[route] || 0) + 1;
    events.push(route);
    const send = (status, payload, type = 'application/json') => {
      res.writeHead(status, { 'content-type': type });
      res.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
    };
    // One table of answers shared by /reserve and /status, so a mode means the same
    // thing on both surfaces and no branch can quietly disagree with the other.
    // `status` is the HTTP answer, `body` the payload, `hang` never answers.
    const answers = {
      allow: () => ({ status: 200, body: summaryFor(true) }),
      unlimited: () => ({ status: 200, body: { allowed: true, enabled: false, unlimited: true, used: 0, limit: null, remaining: null, percentage: 0 } }),
      bare: () => ({ status: 200, body: { allowed: true } }),
      exhausted: () => ({ status: 200, body: summaryFor(false, { reason: 'quota_exhausted', used: 3, remaining: 0, percentage: 100 }) }),
      silent429: () => ({ status: 429, body: { allowed: false } }),
      outageCode: () => ({ status: 200, body: { allowed: false, reason: 'quota_service_unavailable' } }),
      http500: () => ({ status: 500, body: { message: `database exploded on ${INTERNAL_BAIT} token=${SERVICE_INTERNAL_TOKEN}` } }),
      html: () => ({ status: 200, body: '<!DOCTYPE html><html><body>quota error</body></html>', type: 'text/html' }),
      noAllowed: () => ({ status: 200, body: {} }),
      allowedString: () => ({ status: 200, body: { allowed: 'true' } }),
      array: () => ({ status: 200, body: [{ allowed: true }] }),
      // The adversarial pair: a denial STATUS whose body claims permission. Neither
      // is a decision, and a relay that trusted the body over the status would hand
      // out a provider call on the strength of an error page.
      spoofedAllow403: () => ({ status: 403, body: { allowed: true, used: 0, limit: 999, remaining: 999 } }),
      spoofedAllow500: () => ({ status: 500, body: { allowed: true, used: 0, limit: 999, remaining: 999 } }),
      // Everything the allowlist must drop: a table name, SQL, a row id, a service
      // secret and a DSN, riding alongside a valid decision.
      internals: () => ({ status: 200, body: {
        allowed: true, enabled: true, unlimited: false, used: 1, limit: 3, remaining: 2,
        percentage: 33, period: PERIOD, resetAt: RESET_AT,
        table: INTERNAL_BAIT, sql: `SELECT * FROM ${INTERNAL_BAIT}`, row_id: 4211,
        service_token: SERVICE_INTERNAL_TOKEN, dsn: 'postgres://svc:pw@db.internal:5432/x', nested: { a: 1 }
      } }),
      hang: () => ({ hang: true })
    };
    // A granted reservation IS a spend, so the counter moves before the summary is
    // built: the answer has to report the call it just granted, as the real service
    // would. Getting this order wrong would make the relay look like it reported a
    // stale count, so it is stated here rather than left to be inferred.
    if (route === 'reserve' && service.mode === 'allow') service.used += 1;
    const answer = (answers[service.mode] || answers.allow)();
    if (route === 'reserve' || route === 'status') {
      if (answer.hang) return; // never answers: the relay's timeout must fire
      return send(answer.status, answer.body, answer.type || 'application/json');
    }
    if (route === 'config') {
      service.configHits = (service.configHits || 0) + 1;
      if (service.configMode === 'forbidden') return send(403, { success: false, error: 'Admin access required' });
      if (service.configMode === 'reject400') return send(400, { success: false, error: `default_call_limit must be between 1 and 100000 on ${INTERNAL_BAIT}` });
      if (service.configMode === 'http500') return send(500, { message: `config write failed on ${INTERNAL_BAIT}` });
      if (service.configMode === 'html') return send(200, '<!DOCTYPE html><html>config</html>', 'text/html');
      if (service.configMode === 'nullObject') return send(200, 'null');
      if (req.method === 'PUT' && service.configMode === 'ok' && body && typeof body === 'object') {
        service.config = { ...(service.config || {}), ...body };
      }
      return send(200, { success: true, quota_enabled: true, default_call_limit: 100, period_type: 'monthly', updated_at: '2026-10-03 10:00:00' });
    }
    events.push(`unexpected-route:${route}`);
    return send(404, { error: 'no such quota route' });
  });
});
await new Promise((resolve) => quotaService.listen(0, '127.0.0.1', resolve));
const QUOTA_SERVICE_BASE = `http://127.0.0.1:${quotaService.address().port}`;

// ── mocked NCB session authority and mocked provider ───────────────────────
const logs = [];
const realLog = console.log.bind(console);
for (const m of ['log', 'info', 'warn', 'error']) {
  console[m] = (...a) => { logs.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')); };
}

const realFetch = globalThis.fetch;
global.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u.startsWith(NCB_BASE) || u.includes(NCB_LAMBDA_HOST)) {
    const route = new URL(u).pathname;
    ncbRoutes.push(route);
    const auth = String(opts.headers?.Authorization || '');
    world.seenAuthHeaders.push(auth);
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });
    if (route === '/auth/get-session') {
      events.push('session');
      const user = USERS[auth.replace('Bearer ', '')];
      return user ? json({ status: 'success', data: { user } }) : json({ status: 'error' }, 401);
    }
    // Any other NCB route means this relay went back to reading tables directly.
    events.push(`ncb-data:${route}`);
    return json({ status: 'error', error: 'NCB data API must not be used by NodeSend' }, 500);
  }
  if (u.includes('dashscope.aliyuncs.com')) {
    world.providerCalls++;
    events.push('provider');
    const providerAuth = String(opts.headers?.Authorization || '');
    world.providerAuthHeaders.push(providerAuth);
    world.seenAuthHeaders.push(providerAuth);
    return new Response(JSON.stringify({
      choices: [{ message: { role: 'assistant', content: 'P7N' } }],
      usage: { prompt_tokens: 11, completion_tokens: 5, total_tokens: 16 }
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  if (u.startsWith('http://127.0.0.1:') || u.startsWith('http://localhost:')) {
    // The relay itself, and the BridgeMind quota service, over real sockets.
    return realFetch(u, opts);
  }
  throw new Error(`harness refused an unexpected outbound request to ${u}`);
};

process.env.NODESEND_PRIVATE_KEY_B64 = PRIV_B64;
process.env.BRIDGE_API_KEY = 'server-only-bridge-key';
process.env.NCB_PROXY_BASE = NCB_BASE;
process.env.NCB_INSTANCE = '55954_bridgemind';
// Low enough that the 'hang' mode proves a timeout, high enough to be a real bound.
process.env.NODESEND_QUOTA_TIMEOUT_MS = '500';
// Deliberately NOT set yet: section 1 measures the unconfigured state.
delete process.env.BRIDGEMIND_QUOTA_URL;
process.env.PORT = '3999';

const mod = await import(pathToFileURL(path.join(ROOT, 'bridge.js')).href);
const { app, NODESEND_VERSION } = mod;
const bodyOf = async (res) => { try { return await res.json(); } catch { return {}; } };
await new Promise((r) => app.listen(3999, '127.0.0.1', r));
const B = 'http://127.0.0.1:3999';
const CHAT = (tok, extra = {}) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: `Bearer ${tok}` } : {}) },
  body: JSON.stringify({
    provider: 'alibaba',
    config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', encryptedApiKey: enc(PROVIDER_SECRET) },
    model: 'qwen3.8-flash',
    messages: [{ role: 'user', content: 'hi' }],
    ...extra
  })
});

const results = [];
const check = (name, pass, detail = '') => { results.push({ name, pass: !!pass, detail: String(detail).slice(0, 240) }); };
const AUTH = (tok) => ({ headers: { Authorization: `Bearer ${tok}` } });
const PUTJSON = (tok, obj) => ({ method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok}` }, body: JSON.stringify(obj) });
let r, j, pc;

// ── 1. unconfigured is fail-closed, not a guess ────────────────────────────
// This is the state production is in until BridgeMind publishes the endpoint.
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
check('no BRIDGEMIND_QUOTA_URL: /ai/chat -> 503, provider untouched', r.status === 503 && j.status === 'quota_service_unavailable' && world.providerCalls === 0, `status=${r.status} providerCalls=${world.providerCalls}`);
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('no BRIDGEMIND_QUOTA_URL: GET /ai/quota -> 503 with nulls', r.status === 503 && j.used === null && j.limit === null && j.remaining === null && j.percentage === null, JSON.stringify({ s: r.status, u: j.used }));
check('an unconfigured quota never invents a period or reset date', !('period' in j) && !('resetAt' in j), Object.keys(j).join(','));
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
check('no BRIDGEMIND_QUOTA_URL: admin GET config -> 503', r.status === 503, `status=${r.status}`);
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 5 }));
check('no BRIDGEMIND_QUOTA_URL: admin PUT config -> 503, no saved:true', r.status === 503, `status=${r.status}`);
const h0 = await bodyOf(await fetch(`${B}/health`));
check('health reports bridgemind authority, unconfigured service', h0.quotaAuthority === 'bridgemind' && h0.quotaServiceConfigured === false && h0.quotaServiceStatus === 'unconfigured' && h0.quotaStorage === undefined, JSON.stringify({ a: h0.quotaAuthority, c: h0.quotaServiceConfigured, s: h0.quotaServiceStatus }));
check('the quota service received no request at all while unconfigured', service.requests.length === 0 && events.filter((e) => e === 'reserve' || e === 'status' || e === 'config').length === 0, events.join(','));

// ── 2. the session is still the identity authority ─────────────────────────
process.env.BRIDGEMIND_QUOTA_URL = QUOTA_SERVICE_BASE;
r = await fetch(`${B}/ai/chat`, CHAT(null));
check('no session -> 401, no quota call, provider untouched', r.status === 401 && service.counters.reserve === 0 && world.providerCalls === 0, `status=${r.status}`);
r = await fetch(`${B}/ai/chat`, CHAT('tok-nope'));
check('invalid session -> 401, no quota call, provider untouched', r.status === 401 && service.counters.reserve === 0 && world.providerCalls === 0, `status=${r.status}`);
r = await fetch(`${B}/ai/chat`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'server-only-bridge-key' }, body: JSON.stringify({ provider: 'alibaba', messages: [{ role: 'user', content: 'hi' }] }) });
check('the relay key cannot unlock an AI endpoint instead of a session', r.status === 401, `status=${r.status}`);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
check('valid session accepted with no x-api-key', r.status === 200, `status=${r.status}`);
check('provider dispatched exactly once', world.providerCalls === 1, `providerCalls=${world.providerCalls}`);
check('the granted call carries the authoritative summary from the service', j.quota && j.quota.used === 1 && j.quota.limit === 3 && j.quota.remaining === 2 && j.quota.percentage === 33 && j.quota.period === PERIOD, JSON.stringify(j.quota));
const order1 = events.slice(events.lastIndexOf('session'));
check('reserve happens AFTER the session lookup and BEFORE the provider', order1.join(',') === 'session,reserve,provider', order1.join(','));
check('exactly one quota reservation per chat', service.counters.reserve === 1, `reserve calls=${service.counters.reserve}`);

// ── 3. what NodeSend actually sends to the quota service ──────────────────
const firstReserve = service.requests.find((q) => q.route === 'reserve');
check('the reservation is POST /reserve on the configured base', firstReserve?.method === 'POST' && firstReserve?.url === '/reserve', JSON.stringify({ m: firstReserve?.method, u: firstReserve?.url }));
check('the reservation forwards the caller bearer and nothing else', firstReserve?.auth === 'Bearer tok-a' && firstReserve?.apiKey === null && firstReserve?.body !== null, `${firstReserve?.auth} x-api-key=${firstReserve?.apiKey}`);
check('the reservation body asserts no identity', JSON.stringify(firstReserve?.body) === '{}', firstReserve?.raw ?? 'no reservation request recorded');
r = await fetch(`${B}/ai/quota`, AUTH('tok-b'));
const statusCall = service.requests.find((q) => q.route === 'status');
check('the status read is GET /status with no body', statusCall?.method === 'GET' && statusCall?.raw === '' && statusCall?.auth === 'Bearer tok-b', JSON.stringify({ m: statusCall?.method, raw: statusCall?.raw }));
check('no request ever names a user_id to the quota service', !service.requests.some((q) => 'user_id' in (q.body || {}) || /user_id=|userId/.test(q.url)), service.requests.map((q) => q.url).join(','));

// ── 4. identity cannot be influenced by the caller ────────────────────────
const beforeIdentity = service.requests.length;
r = await fetch(`${B}/ai/quota?user_id=202&period_key=1999-01`, AUTH('tok-a'));
j = await bodyOf(r);
check('query-string user_id cannot ask about another user', r.status === 200 && j.used === 1 && j.limit === 3, JSON.stringify({ s: r.status, u: j.used, l: j.limit }));
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', { user_id: 999, userId: 999, period_key: '1999-01', email: 'someone@example.com' }));
check('a body user_id is never forwarded to the quota service', r.status === 200 && service.requests.slice(beforeIdentity).every((q) => !/999|1999-01|someone@example/.test(JSON.stringify(q.body) + q.url)), JSON.stringify(service.requests.slice(beforeIdentity).map((q) => q.body)));
check('identity travels only as the bearer token', service.requests.slice(beforeIdentity).every((q) => q.auth === 'Bearer tok-a'), '');
r = await fetch(`${B}/ai/quota`);
check('GET /ai/quota requires a session', r.status === 401, `status=${r.status}`);

// ── 5. exhaustion is a decision, and it stops the provider ────────────────
service.mode = 'exhausted';
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-d'));
j = await bodyOf(r);
check('exhausted -> 429', r.status === 429 && j.status === 'quota_exhausted', `status=${r.status}`);
check('exhausted does NOT call provider', world.providerCalls === pc, `before=${pc} after=${world.providerCalls}`);
check('exhausted relays the service summary, not an invented one', j.quota && j.quota.remaining === 0 && j.quota.limit === 3 && j.quota.percentage === 100 && j.quota.period === PERIOD, JSON.stringify(j.quota));
r = await fetch(`${B}/ai/quota`, AUTH('tok-d'));
j = await bodyOf(r);
check('GET /ai/quota reports exhaustion as a readable answer, not an outage', r.status === 200 && j.allowed === false && j.used === 3 && j.error === undefined, JSON.stringify({ s: r.status, a: j.allowed, e: j.error }));
service.mode = 'silent429';
r = await fetch(`${B}/ai/chat`, CHAT('tok-d'));
check('an HTTP 429 from the service is exhaustion whatever its body says', r.status === 429, `status=${r.status}`);

// ── 6. an unusable service fails closed on every surface ──────────────────
const outages = [
  ['http500', 'an HTTP 500 from the quota service'],
  ['html', 'an HTML body from whatever sits in front of it'],
  ['noAllowed', 'a body with no decision in it'],
  ['allowedString', 'a non-boolean allowed field'],
  ['array', 'a JSON array instead of an object'],
  ['outageCode', 'an explicit quota_service_unavailable reason'],
  ['hang', 'a service that never answers (timeout)'],
  ['spoofedAllow403', 'a 403 whose body claims the call is allowed'],
  ['spoofedAllow500', "a 500 whose body claims the call is allowed"]
];
for (const [mode, label] of outages) {
  service.mode = mode;
  pc = world.providerCalls;
  r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
  j = await bodyOf(r);
  check(`${label} -> /ai/chat 503 and provider untouched`, r.status === 503 && j.status === 'quota_service_unavailable' && world.providerCalls === pc, `status=${r.status} providerCalls=${world.providerCalls - pc}`);
  check(`${label} is never relayed as a 429 or as allowed`, r.status !== 429 && !(j.quota && j.quota.allowed === true), JSON.stringify(j).slice(0, 90));
  service.mode = 'allow';
}
for (const [mode, label] of [['http500', '500'], ['noAllowed', 'no decision'], ['allowedString', 'non-boolean allowed'], ['hang', 'timeout'], ['spoofedAllow403', 'a 403 claiming permission'], ['spoofedAllow500', 'a 500 claiming permission']]) {
  service.mode = mode;
  r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
  j = await bodyOf(r);
  check(`${label} -> GET /ai/quota 503 with nulls, never 0/limit`, r.status === 503 && j.used === null && j.limit === null, `status=${r.status}`);
}
service.mode = 'allow';
r = await fetch(`${B}/health`);
j = await bodyOf(r);
check('health still serves and reports the outage it observed', r.status === 200 && j.quotaAuthority === 'bridgemind' && j.quotaServiceConfigured === true && ['unreachable', 'invalid'].includes(j.quotaServiceStatus), JSON.stringify({ c: j.quotaServiceConfigured, s: j.quotaServiceStatus }));
const hReady = await bodyOf(await fetch(`${B}/ai/quota`, AUTH('tok-a')));
r = await fetch(`${B}/health`);
j = await bodyOf(r);
check('health returns to ready once the service answers properly', hReady.allowed === true && j.quotaServiceStatus === 'ready', JSON.stringify(j.quotaServiceStatus));
check('a successful read did not leak the service body into health', !JSON.stringify(j).includes(INTERNAL_BAIT) && !JSON.stringify(j).includes('127.0.0.1'), JSON.stringify(j.quotaService ?? j.quotaServiceStatus));

// ── 7. the allowlist, not the upstream body, reaches the browser ───────────
service.mode = 'internals';
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
const quotaJson = JSON.stringify(j.quota ?? null);
check('an allowed decision is still honoured when it carries extra fields', r.status === 200 && world.providerCalls > 0, `status=${r.status}`);
check('table names, SQL, row ids and service secrets are dropped', typeof quotaJson === 'string' && !quotaJson.includes(INTERNAL_BAIT) && !quotaJson.includes('SELECT') && !quotaJson.includes('row_id') && !quotaJson.includes(SERVICE_INTERNAL_TOKEN) && !quotaJson.includes('postgres'), quotaJson);
check('only the documented decision fields survive', Object.keys(j.quota ?? {}).sort().join(',') === 'enabled,limit,percentage,period,remaining,resetAt,unlimited,used', Object.keys(j.quota ?? {}).sort().join(','));
service.mode = 'allow';
service.configMode = 'reject400';
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 25 }));
j = await bodyOf(r);
check('a rejected admin write keeps the service status and drops its error text', r.status === 400 && j.status === 'quota_configuration_write_400' && !JSON.stringify(j).includes(INTERNAL_BAIT), JSON.stringify(j).slice(0, 140));
service.configMode = 'ok';

// ── 8. quota disabled is the service's call, relayed as unlimited ──────────
service.mode = 'unlimited';
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
check('unlimited decision -> provider allowed', r.status === 200 && world.providerCalls === pc + 1, `status=${r.status}`);
check('unlimited is relayed as unlimited', j.quota && j.quota.unlimited === true && j.quota.enabled === false && j.quota.limit === null, JSON.stringify(j.quota));
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('GET /ai/quota reports unlimited when the service says so', r.status === 200 && j.unlimited === true && j.enabled === false, JSON.stringify({ e: j.enabled, u: j.unlimited }));
service.mode = 'bare';
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
check('a bare allowed:true grants the call and adds no invented summary', r.status === 200 && !('quota' in j), JSON.stringify(Object.keys(j)));
service.mode = 'allow';

// ── 9. admin config remains admin-only at this relay, then proxies ─────────
r = await fetch(`${B}/ai/quota/config`);
check('config GET without a session -> 401', r.status === 401, `status=${r.status}`);
const configHitsBefore = service.counters.config;
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-a'));
j = await bodyOf(r);
check('config GET as an ordinary user -> 403', r.status === 403 && j.status === 'forbidden', `status=${r.status}`);
check('a 403 makes no call to the quota service at all', service.counters.config === configHitsBefore, `hits=${service.counters.config} vs ${configHitsBefore}`);
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-a', { quota_enabled: 1, default_call_limit: 7 }));
check('config PUT as an ordinary user -> 403 before any outbound call', r.status === 403 && service.counters.config === configHitsBefore, `hits=${service.counters.config}`);
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
j = await bodyOf(r);
check('admin GET config -> proxied answer', r.status === 200 && j.quota_enabled === true && j.default_call_limit === 100 && j.period_type === 'monthly', JSON.stringify(j).slice(0, 140));
const cfg = service.requests.filter((q) => q.route === 'config' && q.method === 'GET').slice(-1)[0];
check('the config read is GET /config with the admin own bearer', cfg?.method === 'GET' && cfg?.auth === 'Bearer tok-admin', JSON.stringify({ m: cfg?.method, a: cfg?.auth }));
const putBody = { quota_enabled: 0, default_call_limit: 25, note: 'whatever the admin set' };
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', putBody));
j = await bodyOf(r);
const cfgPut = service.requests.filter((q) => q.method === 'PUT').slice(-1)[0];
check('admin PUT proxies the body unchanged', r.status === 200 && cfgPut?.url === '/config' && JSON.stringify(cfgPut?.body) === JSON.stringify(putBody), cfgPut?.raw ?? 'no PUT recorded');
check('the proxy response is the service body, with no fields added', Object.keys(j).sort().join(',') === 'default_call_limit,period_type,quota_enabled,success,updated_at', Object.keys(j).sort().join(','));
service.configMode = 'forbidden';
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 30 }));
j = await bodyOf(r);
check('a 403 from the service reaches the admin as 403, not as saved', r.status === 403 && j.saved === undefined && j.status === 'quota_configuration_write_403', `status=${r.status}`);
service.configMode = 'http500';
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
j = await bodyOf(r);
check('a 500 on the config read is relayed as 500 without the service message', r.status === 500 && j.status === 'quota_configuration_read_500' && !JSON.stringify(j).includes(INTERNAL_BAIT), JSON.stringify(j).slice(0, 120));
service.configMode = 'ok';
service.configMode = 'html';
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
j = await bodyOf(r);
check('an HTML config page is refused, and its text never reaches the caller', r.status === 503 && j.status === 'quota_service_unavailable', `status=${r.status}`);
service.configMode = 'nullObject';
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 30 }));
check('a 200 whose body is not an object is never reported as a confirmation', r.status === 502, `status=${r.status}`);
service.configMode = 'ok';
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', 'not-an-object'));
check('a non-object admin body is refused locally, not forwarded', r.status === 400, `status=${r.status}`);

// ── 10. relay invariants preserved by this change ──────────────────────────
r = await fetch(`${B}/send`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
check('/send still 403 without x-api-key', r.status === 403, `status=${r.status}`);
r = await fetch(`${B}/rocketchat`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'server-only-bridge-key' }, body: JSON.stringify({ text: 'x' }) });
check('/rocketchat still accepts x-api-key', r.status !== 403 && r.status !== 401, `status=${r.status}`);
r = await fetch(`${B}/quota`, { headers: { Authorization: 'Bearer tok-a' } });
check('generic /quota unchanged (403 without key)', r.status === 403, `status=${r.status}`);
r = await fetch(`${B}/quota`, { headers: { 'x-api-key': 'server-only-bridge-key' } });
check('generic /quota still fails closed when its own service is unconfigured', r.status === 503, `status=${r.status}`);
r = await fetch(`${B}/ai/chat`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' },
  body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', apiKey: PROVIDER_SECRET }, model: 'qwen3.8-flash', messages: [{ role: 'user', content: 'hi' }] })
});
j = await bodyOf(r);
check('plaintext provider key still refused, and spends no reservation', r.status === 400 && /disabled|required/i.test(String(j.error)), `status=${r.status}`);
const reserveBeforeTest = service.counters.reserve;
pc = world.providerCalls;
r = await fetch(`${B}/ai/test`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' }, body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', encryptedApiKey: enc(PROVIDER_SECRET) }, model: 'qwen3.8-flash' }) });
check('/ai/test dispatches the provider but asks the quota service for nothing', r.status === 200 && world.providerCalls === pc + 1 && service.counters.reserve === reserveBeforeTest, `status=${r.status} reserve=${service.counters.reserve - reserveBeforeTest}`);
r = await fetch(`${B}/ai/models`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' }, body: JSON.stringify({ provider: 'alibaba', config: {} }) });
j = await bodyOf(r);
check('/ai/models 200 with session and no reservation', r.status === 200 && j.models?.length === 2 && service.counters.reserve === reserveBeforeTest, `status=${r.status}`);
r = await fetch(`${B}/crypto/public-key`);
j = await bodyOf(r);
check('public key still served unauthenticated', r.status === 200 && j.publicKey?.includes('BEGIN PUBLIC KEY'), `status=${r.status}`);
const rootInfo = await bodyOf(await fetch(`${B}/`));
check('root advertises the bridgemind quota authority without naming a table', rootInfo.quotaService?.authority === 'bridgemind' && !JSON.stringify(rootInfo).includes(INTERNAL_BAIT), JSON.stringify(rootInfo.quotaService));
check('root does not report a storage layer it no longer has', !('quotaStorage' in rootInfo), Object.keys(rootInfo).join(','));

// ── 11. Trickster behaviour is untouched by the quota move ────────────────
const tricksterNoSession = [];
const tricksterWithSession = [];
const dataCallsBeforeTrickster = events.length;
for (const route of ['/trickster/bid/health', '/trickster/play/health', '/trickster/bid/suggest-bid', '/trickster/play/suggest-card']) {
  tricksterNoSession.push((await fetch(`${B}${route}`, { method: route.includes('suggest') ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json' }, ...(route.includes('suggest') ? { body: '{}' } : {}) })).status);
  tricksterWithSession.push((await fetch(`${B}${route}`, { method: route.includes('suggest') ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' }, ...(route.includes('suggest') ? { body: '{}' } : {}) })).status);
}
check('Trickster routes still answer 401 without a session', tricksterNoSession.every((s) => s === 401), tricksterNoSession.join(','));
check('Trickster routes still proxy with a session (502 upstream unreachable, never 401/403/503-quota)', tricksterWithSession.every((s) => s === 502), tricksterWithSession.join(','));
check('a Trickster call makes no quota request', events.slice(dataCallsBeforeTrickster).filter((e) => e === 'reserve' || e === 'status' || e === 'config').length === 0, '');
r = await fetch(`${B}/trickster/bid/suggest-bid`, AUTH('tok-a'));
check('a wrong verb on a Trickster path still answers 405 with Allow: POST', r.status === 405 && r.headers.get('allow') === 'POST', `status=${r.status} allow=${r.headers.get('allow')}`);

// ── 12. secret hygiene ────────────────────────────────────────────────────
const blob = logs.join('\n');
check('no bearer token in logs', !blob.includes('tok-a') && !blob.includes('tok-admin'), '');
check('no provider secret in logs', !blob.includes(PROVIDER_SECRET), '');
check('no private key material in logs', !blob.includes('PRIVATE KEY'), '');
check('the shared relay key is never sent to the quota service', !service.requests.some((q) => q.apiKey !== null || JSON.stringify(q).includes('server-only-bridge-key')), '');
check('no quota-service host or path is echoed to the browser', !(await (async () => { const t = await (await fetch(`${B}/ai/quota`, AUTH('tok-a'))).text(); return t.includes('127.0.0.1') || t.includes(QUOTA_SERVICE_BASE); })()), '');
check('no log line names a table, an NCB data route or the quota service URL', !/ai_quota|\/data\/|QUOTA_SERVICE|127\.0\.0\.1:\d+\/reserve/.test(blob), blob.split('\n').find((l) => /ai_quota|\/data\//.test(l)) || '');
check('the outage log never carries the service error text', !blob.includes('database exploded') && !blob.includes(SERVICE_INTERNAL_TOKEN), blob.split('\n').find((l) => /exploded/.test(l)) || '');
check('encrypted provider credential still reaches the provider decrypted', world.providerAuthHeaders.includes(`Bearer ${PROVIDER_SECRET}`), `providerAuthCount=${world.providerAuthHeaders.length}`);
check('provider is never authenticated by the user bearer', world.providerAuthHeaders.length > 0 && !world.providerAuthHeaders.some((h) => h.includes('tok-')), world.providerAuthHeaders.map((h) => h.slice(0, 10) + '…').join(','));
const echoText = await Promise.all([
  fetch(`${B}/ai/quota`, AUTH('tok-admin')).then((res) => res.text()),
  fetch(`${B}/ai/quota/config`, AUTH('tok-admin')).then((res) => res.text()),
  fetch(`${B}/ai/quota/config`, AUTH('tok-a')).then((res) => res.text()),
  fetch(`${B}/ai/chat`, CHAT('tok-a')).then((res) => res.text()),
  fetch(`${B}/health`).then((res) => res.text()),
  fetch(`${B}/`).then((res) => res.text()),
  fetch(`${B}/crypto/public-key`).then((res) => res.text())
]);
check('every probe returned a body to inspect', echoText.length === 7 && echoText.every((t) => typeof t === 'string' && t.length > 0), echoText.map((t) => typeof t).join(','));
const SECRET_STRINGS = [...Object.keys(USERS), PROVIDER_SECRET, SERVICE_INTERNAL_TOKEN, 'PRIVATE KEY', 'server-only-bridge-key'];
const leaked = echoText.map((t, i) => SECRET_STRINGS.filter((s) => t.includes(s)).map((s) => `${i}:${s}`)).flat();
check('no response body carries a bearer, a session token or a provider key', leaked.length === 0, leaked.join(','));
const canary = JSON.stringify({ authorization: 'Bearer tok-a', key: PROVIDER_SECRET, internal: SERVICE_INTERNAL_TOKEN });
check('the leak detector fires on a planted leak (positive control)', SECRET_STRINGS.some((s) => canary.includes(s)) && leaked.length === 0, SECRET_STRINGS.filter((s) => canary.includes(s))[0] || 'none');

// ── 13. source gates: the direct-table design must not come back ──────────
// Runtime proof first, before any text search: the NCB mock records every route it
// is asked for, so "only /auth/get-session was ever requested" is an observation
// about this run's traffic, not a claim about the source text.
const ncbDataEvents = events.filter((e) => String(e).startsWith('ncb-data:'));
check('NCB received /auth/get-session only, for the entire run', ncbDataEvents.length === 0, ncbDataEvents.join(','));
check('every quota call went to the configured BridgeMind service', service.requests.length > 0 && service.requests.every((q) => ['reserve', 'status', 'config'].includes(q.route)) && !service.requests.some((q) => /\/data\/|ai_quota/.test(q.url)), `${service.requests.length} calls: ${[...new Set(service.requests.map((q) => q.route + ' ' + q.method))].join(' | ')}`);
check('the NCB host was asked for exactly one route, all run', [...new Set(ncbRoutes)].join(',') === '/auth/get-session', `${ncbRoutes.length} NCB calls: ${[...new Set(ncbRoutes)].join(',')}`);
const bridgeSrc = fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8');
const codeOnly = bridgeSrc.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^[ \t]*\/\/.*$/gm, ' ');
const envExample = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
check('no NCB data route is built anywhere in the relay', !/\/data\/(read|create|update|delete)/.test(codeOnly) && !/\/data\//.test(codeOnly), '');
// Word boundaries, not substrings: `quota_configuration_write_500` is a log code and
// `ai_quota_usage` contains `quota_usage` as a fragment. A substring test would fire
// on those and teach whoever reads it next to distrust the gate, so each retired name
// is tested as the whole identifier it is.
const retiredTableNames = ['ai_quota_config', 'ai_quota_user_override', 'ai_quota_usage', 'quota_config', 'quota_usage', 'quota_user_override'];
const tableHits = retiredTableNames.filter((t) => new RegExp(`\\b${t}\\b`).test(codeOnly));
check('no quota table is named in production source', tableHits.length === 0, tableHits.join(','));
check('no SQL or DDL is issued from the relay', !/\b(CREATE TABLE|ALTER TABLE|DROP TABLE|TRUNCATE|ON CONFLICT|INSERT INTO|UPSERT)\b/i.test(codeOnly) && !/\bSELECT\b[\s\S]{0,60}\bFROM\b/i.test(codeOnly), '');
const sessionCallSites = (codeOnly.match(/ncbRequest\(req,\s*"\/auth\/get-session"/g) || []).length;
const ncbRequestUses = (codeOnly.match(/ncbRequest\s*\(/g) || []).length;
check('NCB is called for /auth/get-session and for nothing else', sessionCallSites === 1 && ncbRequestUses === 2, `session=${sessionCallSites} total ncbRequest( =${ncbRequestUses}`);
check('no direct-table machinery survives', !/ncbDataRead|ncbDataWrite|ncbDataCreate|ncbDataUpdate|ncbRowList|ncbFlag|ncbInt|ncbDateTime|readNcbQuotaState|readNcbQuotaConfig|withUserQuotaLock|quotaUserLocks|getCurrentPeriodKey|getNextResetAt|resolveQuotaLimit|isSensibleQuotaLimit|QUOTA_SCHEMA_SQL/.test(codeOnly), '');
check('no database credential or driver is reachable from the relay', !/DATABASE_URL|QUOTA_DATABASE_URL|\brequire\(\s*["']pg["']\s*\)/.test(codeOnly) && !pkg.dependencies?.pg, Object.keys(pkg.dependencies || {}).join(','));
check('the adapter reads exactly one new env name', (codeOnly.match(/process\.env\.BRIDGEMIND_QUOTA_URL/g) || []).length === 1, `reads=${(codeOnly.match(/process\.env\.BRIDGEMIND_QUOTA_URL/g) || []).length}`);
check('identity is read only from the validated session', /req\.bridgeUser\?\.id/.test(codeOnly) && !/req\.body\??\.user_id|req\.query\??\.user_id|query\.user_id/.test(codeOnly), '');
check('the session and admin guards are still attached to all five AI surfaces', /app\.post\("\/ai\/models",\s*requireBridgeSession/.test(codeOnly)
  && /app\.post\("\/ai\/test",\s*requireBridgeSession/.test(codeOnly)
  && /app\.post\("\/ai\/chat",\s*requireBridgeSession/.test(codeOnly)
  && /app\.get\("\/ai\/quota",\s*requireBridgeSession/.test(codeOnly)
  && /app\.get\("\/ai\/quota\/config",\s*requireBridgeSession,\s*requireBridgeAdmin/.test(codeOnly)
  && /app\.put\("\/ai\/quota\/config",\s*requireBridgeSession,\s*requireBridgeAdmin/.test(codeOnly), '');
check('health names bridgemind and not a storage backend', /quotaAuthority:\s*"bridgemind"/.test(codeOnly) && !/quotaAuthority:\s*"(ncb|postgres)"/.test(codeOnly), '');
check('BRIDGEMIND_QUOTA_URL requires https outside loopback and refuses credentials', /protocol\s*!==\s*"https:"/.test(codeOnly) && /base\.username\s*\|\|\s*base\.password/.test(codeOnly), '');
// UPDATED 2026-10-04, disclosed: this assertion used to REQUIRE the phrase "does not exist
// in BridgeMind yet". That phrase is now false, so the check would have gone red for doing
// the right thing. It is re-aimed, not weakened: it still demands that the file states the
// unconfigured consequence, and additionally forbids the stale "does not exist" claim, so
// the doc cannot drift back to saying the endpoint is missing while also saying it is
// pending deployment.
// Prose is matched with comment markers and line wrapping removed. Matching the raw text
// would have made this gate fail on a line break alone — the phrase below really is
// written across two comment lines — and the same brittleness would let a rewrap hide a
// revived claim: "does not exist in BridgeMind yet" split over two lines would slip past a
// raw absence check. Both directions are therefore tested on the same normalised prose.
const envProse = envExample.replace(/^#\s?/gm, '').replace(/\s+/g, ' ');
check('.env.example documents the decision service as present in code but awaiting deployment, and never claims it does not exist',
  /BRIDGEMIND_QUOTA_URL=/.test(envExample)
    && /exists in the BridgeMind application code/.test(envProse)
    && /must be deployed as a/.test(envProse)
    && /fail closed while it is unset/.test(envProse)
    && /does not exist in BridgeMind yet/.test(envProse) === false, '');
check('.env.example documents the x-ai-decision-key header as a billing label and explicitly not identity',
  /x-ai-decision-key: <logical decision key>/.test(envProse)
    && /BILLING label/.test(envProse)
    && /never authentication, never identity/.test(envProse), '');
check('.env.example keeps the two quota URLs clearly distinct', /NODESEND_QUOTA_URL is NOT the flag/.test(envExample), '');
check('.env.example still carries no database configuration', !/BRIDGEMIND_QUOTA_DATABASE_URL|^DATABASE_URL|NODESEND_QUOTA_DB_/m.test(envExample), '');
check('no browser-visible quota secret exists', !/VITE_[A-Z_]*(QUOTA|NCB|DATABASE|BEARER|SESSION|BRIDGEMIND)/i.test(envExample + bridgeSrc), '');
check('the direct-table harness never came back', !fs.existsSync(path.join(ROOT, 'verify-postgres-quota.mjs')) && !fs.existsSync(path.join(ROOT, 'verify-ncb-quota.mjs')), '');
check('version declares the bridgemind quota authority', NODESEND_VERSION === 'bridge-bridgemind-quota-v8', NODESEND_VERSION);

// ── 14. the adapter's own predicates ─────────────────────────────────────
const { bridgemindQuotaEndpoint, bridgemindQuotaConfigured, sanitizeQuotaDecision, isQuotaCount, quotaServiceState, QUOTA_PUBLIC_FIELDS } = mod;
check('endpoint paths derive from the configured base', bridgemindQuotaEndpoint('reserve') === `${QUOTA_SERVICE_BASE}/reserve` && bridgemindQuotaEndpoint('/status') === `${QUOTA_SERVICE_BASE}/status`, bridgemindQuotaEndpoint('reserve'));
check('a trailing slash on the base does not double up', (() => {
  const previous = process.env.BRIDGEMIND_QUOTA_URL;
  process.env.BRIDGEMIND_QUOTA_URL = `${QUOTA_SERVICE_BASE}/`;
  const one = bridgemindQuotaEndpoint('status') === `${QUOTA_SERVICE_BASE}/status`;
  process.env.BRIDGEMIND_QUOTA_URL = previous;
  return one;
})(), bridgemindQuotaEndpoint('status'));
check('a plain host without a path still resolves the routes', (() => {
  const previous = process.env.BRIDGEMIND_QUOTA_URL;
  process.env.BRIDGEMIND_QUOTA_URL = 'https://api.bridgemind.app';
  const ok = bridgemindQuotaEndpoint('reserve') === 'https://api.bridgemind.app/reserve';
  process.env.BRIDGEMIND_QUOTA_URL = previous;
  return ok;
})(), '');
check('non-https, credential-bearing and malformed bases are refused', (() => {
  const previous = process.env.BRIDGEMIND_QUOTA_URL;
  const refused = ['http://api.bridgemind.app', 'https://user:pw@api.bridgemind.app', 'not a url', ''].every((value) => {
    process.env.BRIDGEMIND_QUOTA_URL = value;
    return bridgemindQuotaEndpoint('reserve') === null;
  });
  const loopbackOk = (() => { process.env.BRIDGEMIND_QUOTA_URL = 'http://127.0.0.1:9'; const v = bridgemindQuotaEndpoint('reserve'); process.env.BRIDGEMIND_QUOTA_URL = previous; return v === 'http://127.0.0.1:9/reserve'; })();
  return refused && loopbackOk && bridgemindQuotaConfigured() === true;
})(), '');
check('sanitizeQuotaDecision requires a boolean allowed', sanitizeQuotaDecision(null).valid === false && sanitizeQuotaDecision({}).valid === false && sanitizeQuotaDecision({ allowed: 'true' }).valid === false && sanitizeQuotaDecision([]).valid === false && sanitizeQuotaDecision({ allowed: true }).valid === true, '');
check('a denial without a reason is exhaustion, and an unknown reason cannot pick 503', sanitizeQuotaDecision({ allowed: false }).reason === 'quota_exhausted' && sanitizeQuotaDecision({ allowed: false, reason: 'token_expired' }).reason === 'quota_exhausted' && sanitizeQuotaDecision({ allowed: false, reason: 'quota_service_unavailable' }).reason === 'quota_service_unavailable', '');
check('negative and impossible counts are dropped, not relayed', (() => {
  const d = sanitizeQuotaDecision({ allowed: true, used: -5, limit: 1.5, remaining: 'many', percentage: 900 });
  return d.summary.used === undefined && d.summary.limit === undefined && d.summary.remaining === undefined && d.summary.percentage === 100;
})(), JSON.stringify(sanitizeQuotaDecision({ allowed: true, used: -5, limit: 1.5, remaining: 'many', percentage: 900 }).summary));
check('oversized strings are dropped rather than relayed', (() => {
  const d = sanitizeQuotaDecision({ allowed: true, period: 'x'.repeat(70), resetAt: 'y'.repeat(70) });
  return d.summary.period === undefined && d.summary.resetAt === undefined;
})(), '');
check('only allowlisted fields can ever survive', (() => {
  const d = sanitizeQuotaDecision({ allowed: true, table: 'x', sql: 'y', row_id: 1, secret: 'z', used: 1 });
  return Object.keys(d.summary).every((k) => QUOTA_PUBLIC_FIELDS.includes(k)) && Object.keys(d.summary).join(',') === 'used';
})(), '');
check('isQuotaCount accepts non-negative safe integers only', isQuotaCount(0) && isQuotaCount(100000) && !isQuotaCount(-1) && !isQuotaCount(1.5) && !isQuotaCount(Number.MAX_SAFE_INTEGER + 1) && !isQuotaCount(NaN), '');
check('quotaServiceState reports configuration without naming the target', (() => { const s = quotaServiceState(); return 'configured' in s && 'status' in s && !JSON.stringify(s).includes('127.0.0.1'); })(), JSON.stringify(quotaServiceState()));

console.log = realLog;
let failed = 0;
for (const x of results) {
  if (!x.pass) failed++;
  console.log(`${x.pass ? 'PASS' : 'FAIL'}  ${x.name}${x.detail ? '   [' + x.detail + ']' : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed`);
console.log('MOCKED: the NCB session authority and the AI provider are in-process fakes; the BridgeMind quota');
console.log('service is a real loopback HTTP server, so the adapter is exercised over a socket.');
console.log('NOT CONFIGURED ANYWHERE REAL: no production endpoint was contacted, and no quota row exists here.');
service.requests.length = 0;
quotaService.close();
process.exit(failed ? 1 : 0);
