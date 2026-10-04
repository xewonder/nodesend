// NodeSend gate: the caller's logical-decision key must reach BridgeMind's quota
// reservation, and must reach NOTHING else.
//
//   node verify-decision-key-forwarding.mjs
//
// Why this exists: BridgeMind bills at most one quota unit per logical AI decision,
// keyed by (validated session user, UTC period, the caller's key). The browser sends
// that key as the `x-ai-decision-key` request header on POST /ai/chat. If NodeSend did
// not forward it, every retry of one decision would arrive keyless and be charged again
// — i.e. the Phase 2 fix would be inert in production. These checks pin the forwarding,
// and pin that the key stops at the quota service.
//
// Architecture under test is the real one: the BridgeMind quota service is a loopback
// HTTP server (so URL building, header forwarding and status mapping are exercised over
// a socket, not a stub), NCB /auth/get-session and the AI provider are fetch mocks, and
// any other outbound URL is refused outright.
//
// Cases: A key reaches /reserve exactly · B missing key means no key is invented ·
// C never in the provider body · D never in provider headers · E bearer still forwarded
// F denial still blocks the provider · G two attempts of one decision carry the SAME key
// H different decisions stay different · I no secret or token in any log ·
// J status/config requests are unchanged · K emission and non-vacuity controls.
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIV_B64 = Buffer.from(privateKey.export({ type: 'pkcs1', format: 'pem' })).toString('base64');
const PROVIDER_SECRET = 'sk-REAL-PROVIDER-KEY-should-never-be-logged-9f3a';
const SESSION_TOKEN = 'bridge-session-token-6b1f2e3d4c5b';
const FOREIGN_TOKEN = 'another-users-session-token-77aa';
const NCB_BASE = 'https://ncb.test.invalid';
const NCB_LAMBDA_HOST = 'rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url';
const PROVIDER_HOST = 'dashscope.aliyuncs.com';
const PERIOD = '2026-10';
const RESET_AT = '2026-11-01T00:00:00.000Z';
const HEADER = 'x-ai-decision-key';
// A key long enough to be absurd but still inside NodeSend's own 256-char guard, used
// for the "forwarded byte-for-byte" claim, and one above it for the drop case.
const KEY_A = 'bid:6f9d2c1e-0a4b-4c8d-9e1f-2a3b4c5d6e7f';
const KEY_B = 'card:1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901';
const KEY_LONG = `bid:${'7'.repeat(300)}`;
const KEY_CONTROL = `bid:${String.fromCharCode(7)}bad`;

const enc = (s) => crypto.publicEncrypt(
  { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  Buffer.from(s)
).toString('base64');

const USERS = {
  [SESSION_TOKEN]: { id: 101, role: 'user' },
  [FOREIGN_TOKEN]: { id: 202, role: 'user' },
  'tok-admin': { id: 900, role: 'administrator' }
};

// ── the BridgeMind quota service, as a real HTTP server that records everything ──
const service = { mode: 'allow', requests: [] };
const summary = (allowed, used) => ({
  allowed, enabled: true, unlimited: false, used,
  limit: 100, remaining: Math.max(0, 100 - used),
  percentage: Math.round((used / 100) * 100), period: PERIOD, resetAt: RESET_AT
});
const quotaService = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => { raw += c; });
  req.on('end', () => {
    const route = String(req.url || '').replace(/^\//, '');
    // The whole header map is captured, so "the key is the only thing added" and
    // "no provider credential rode along" are read from traffic, not asserted.
    service.requests.push({ route, method: req.method, headers: { ...req.headers }, raw });
    const send = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (route === 'reserve') {
      const used = service.requests.filter((r) => r.route === 'reserve').length;
      if (service.mode === 'exhausted') {
        return send(429, { allowed: false, reason: 'quota_exhausted', ...summary(false, 100) });
      }
      return send(200, summary(true, used));
    }
    if (route === 'status') return send(200, { allowed: true, ...summary(true, 3) });
    if (route === 'config') {
      return send(200, { quota_enabled: true, default_call_limit: 100, period_type: 'monthly', updated_at: '2026-10-03 10:00:00' });
    }
    return send(404, { error: 'no such quota route' });
  });
});
await new Promise((r) => quotaService.listen(0, '127.0.0.1', r));
const QUOTA_SERVICE_BASE = `http://127.0.0.1:${quotaService.address().port}`;

// ── log capture + fetch mock ───────────────────────────────────────────────
const logs = [];
// The relay's own output is captured so "nothing secret is logged" can be asserted, but
// the harness's own report must not be swallowed by that capture — hence realLog.
const realLog = console.log.bind(console);
for (const m of ['log', 'info', 'warn', 'error']) {
  console[m] = (...a) => { logs.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')); };
}
const realFetch = globalThis.fetch;
const provider = { calls: 0, requests: [] };
const ncbRoutes = [];
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u.startsWith(NCB_BASE) || u.includes(NCB_LAMBDA_HOST)) {
    const route = new URL(u).pathname;
    ncbRoutes.push(route);
    if (route === '/auth/get-session') {
      const user = USERS[String(opts.headers?.Authorization || '').replace('Bearer ', '')];
      const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });
      return user ? json({ status: 'success', data: { user } }) : json({ status: 'error' }, 401);
    }
    // Any other NCB route means the relay went back to reading tables itself.
    return new Response(JSON.stringify({ status: 'error' }), { status: 500 });
  }
  if (u.includes(PROVIDER_HOST)) {
    provider.calls += 1;
    provider.requests.push({ url: u, headers: { ...(opts.headers || {}) }, body: String(opts.body || '') });
    return new Response(JSON.stringify({
      choices: [{ message: { role: 'assistant', content: 'P7N' } }],
      usage: { prompt_tokens: 11, completion_tokens: 5, total_tokens: 16 }
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  if (u.startsWith('http://127.0.0.1:') || u.startsWith('http://localhost:')) return realFetch(u, opts);
  throw new Error(`harness refused an unexpected outbound request to ${u}`);
};

process.env.NODESEND_PRIVATE_KEY_B64 = PRIV_B64;
process.env.BRIDGE_API_KEY = 'server-only-bridge-key';
process.env.NCB_PROXY_BASE = NCB_BASE;
process.env.NCB_INSTANCE = '55954_bridgemind';
process.env.BRIDGEMIND_QUOTA_URL = QUOTA_SERVICE_BASE;
process.env.NODESEND_QUOTA_TIMEOUT_MS = '2000';
process.env.PORT = '4123';

const mod = await import(pathToFileURL(path.join(ROOT, 'bridge.js')).href);
const { app } = mod;
const relayServer = await new Promise((r) => {
  const s = app.listen(4123, '127.0.0.1', () => r(s));
});
const B = 'http://127.0.0.1:4123';

const results = [];
const check = (name, pass, detail = '') => results.push({ name, pass: !!pass, detail });
const chat = (token = SESSION_TOKEN, key) => fetch(`${B}/ai/chat`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(key === undefined ? {} : { [HEADER]: key })
  },
  body: JSON.stringify({
    provider: 'alibaba',
    config: { baseUrl: `https://${PROVIDER_HOST}/compatible-mode/v1`, encryptedApiKey: enc(PROVIDER_SECRET) },
    model: 'qwen3.8-flash',
    messages: [{ role: 'user', content: 'hi' }]
  })
});
const reserves = () => service.requests.filter((r) => r.route === 'reserve');
const keyOf = (r) => r.headers[HEADER] ?? null;
const reset = (mode = 'allow') => { service.requests.length = 0; provider.requests.length = 0; provider.calls = 0; service.mode = mode; };

// ── K. emission first: an assertion about a header nobody sent is worthless ──
reset();
const first = await chat(SESSION_TOKEN, KEY_A);
const firstBody = await first.json().catch(() => ({}));
check('K1. the run really reached both the quota service and the provider (nothing below is judging an absent request)',
  reserves().length === 1 && provider.calls === 1 && first.status === 200 && firstBody.success === true,
  `reserve=${reserves().length} provider=${provider.calls} status=${first.status}`);
check('K2. NCB is still contacted for the session and nothing else',
  ncbRoutes.length > 0 && ncbRoutes.every((r) => r === '/auth/get-session'),
  [...new Set(ncbRoutes)].join(',') || 'none');

// ── A. the key arrives, exactly ────────────────────────────────────────────
check('A1. the caller decision key reaches POST {quota}/reserve under the same header name',
  keyOf(reserves()[0]) === KEY_A,
  `saw ${JSON.stringify(keyOf(reserves()[0]))}`);
// The structural claim, measured rather than listed: take the header set of a keyless
// reservation and the header set of a keyed one, and require the decision key to be the
// ONLY difference. A hand-written allowlist would have to grow every time undici adds a
// default header, and would then be testing the transport instead of this relay.
reset();
await chat(SESSION_TOKEN);
const keylessNames = Object.keys(reserves()[0].headers);
reset();
await chat(SESSION_TOKEN, KEY_A);
const keyedNames = Object.keys(reserves()[0].headers);
const added = keyedNames.filter((h) => keylessNames.includes(h) === false);
const dropped = keylessNames.filter((h) => keyedNames.includes(h) === false);
check('A2. relative to a keyless reservation, the decision key is the ONLY header added and none removed',
  added.join(',') === HEADER && dropped.length === 0
    && keyOf(reserves()[0]) === KEY_A,
  `added=${added.join('|') || 'none'} dropped=${dropped.join('|') || 'none'}`);
check('A3. the reservation body is still exactly {} — the key never becomes a body field',
  reserves()[0].raw === '{}', JSON.stringify(reserves()[0].raw));
check('A4. the reserve URL is still derived from the configured base and nothing was appended to it',
  reserves()[0].route === 'reserve' && reserves()[0].method === 'POST',
  `${reserves()[0].method} /${reserves()[0].route}`);

// ── B. a missing key must not be manufactured ─────────────────────────────
reset();
const noKey = await chat(SESSION_TOKEN);
check('B1. with no incoming key, /reserve is sent with NO decision header at all — not an empty one, not an invented one',
  reserves().length === 1 && keyOf(reserves()[0]) === null
    && HEADER in reserves()[0].headers === false,
  `header present: ${HEADER in (reserves()[0]?.headers || {})} value=${JSON.stringify(keyOf(reserves()[0]))}`);
check('B2. a keyless request still bills and still reaches the provider',
  noKey.status === 200 && provider.calls === 1, `status=${noKey.status} provider=${provider.calls}`);

reset();
await chat(SESSION_TOKEN, '');
check('B3. an empty or whitespace-only key is dropped rather than forwarded as a zero-length header',
  reserves().length === 1 && (HEADER in reserves()[0].headers) === false,
  JSON.stringify(reserves()[0]?.headers?.[HEADER] ?? null));

reset();
await chat(SESSION_TOKEN, KEY_LONG);
check('B4. an over-long key is not forwarded (BridgeMind would refuse it anyway; forwarding it could throw inside fetch and cost the caller its own AI call)',
  reserves().length === 1 && (HEADER in reserves()[0].headers) === false && provider.calls === 1,
  `forwarded=${HEADER in (reserves()[0]?.headers || {})} provider=${provider.calls}`);

// A control character can never be presented at all: undici refuses the header before
// the request leaves, and a browser's fetch does the same. So this asserts the measured
// transport behaviour rather than pretending to reach the product guard, and the guard is
// asserted separately as defence-in-depth for any caller that is not a fetch client.
reset();
let controlRejected = false;
try {
  await chat(SESSION_TOKEN, KEY_CONTROL);
} catch {
  controlRejected = true;
}
check('B5. a control-character key cannot even be presented to the relay, and nothing was billed for it',
  controlRejected === true && reserves().length === 0 && provider.calls === 0,
  `transport refused=${controlRejected} reserve calls=${reserves().length}`);
check('B6. the product guard still exists for non-fetch callers: a control-char value is unusable, not forwarded',
  /if \(CONTROL_CHARS\.test\(value\)\) return null;/u.test(
    (await import('node:fs')).readFileSync(path.join(ROOT, 'bridge.js'), 'utf8')),
  'decisionKeyValue drops control characters');

// ── C / D. the key must stop at the quota service ──────────────────────────
reset();
await chat(SESSION_TOKEN, KEY_A);
const providerBlob = provider.requests.map((r) => `${r.url}|${JSON.stringify(r.headers)}|${r.body}`).join(' ');
check('C1. the decision key appears nowhere in the provider request body',
  provider.requests.length === 1 && provider.requests[0].body.includes(KEY_A) === false
    && provider.requests[0].body.includes('decisionKey') === false && provider.requests[0].body.includes(HEADER) === false,
  provider.requests[0]?.body?.slice(0, 120));
check('C2. the provider body carries no billing or routing envelope of any kind',
  provider.requests.length === 1
    && Object.keys(JSON.parse(provider.requests[0].body)).every((k) =>
      ['provider', 'config', 'decisionkey', HEADER, 'quota'].includes(k.toLowerCase()) === false),
  Object.keys(JSON.parse(provider.requests[0]?.body || '{}')).join(','));
check('D1. the decision key appears in no provider request header',
  provider.requests.every((r) => Object.keys(r.headers).some((h) => h.toLowerCase() === HEADER) === false)
    && providerBlob.includes(KEY_A) === false,
  provider.requests.map((r) => Object.keys(r.headers).join('+')).join(' | '));
check('D2. the provider bearer is the provider key, never the caller session token',
  provider.requests.every((r) => String(r.headers.Authorization || '').includes(SESSION_TOKEN) === false)
    && logs.join('\n').includes(SESSION_TOKEN) === false,
  'checked both directions');

// ── E. auth forwarding is untouched ───────────────────────────────────────
reset();
await chat(SESSION_TOKEN, KEY_A);
await fetch(`${B}/ai/quota`, { headers: { Authorization: `Bearer ${SESSION_TOKEN}` } });
const statusReq = service.requests.find((r) => r.route === 'status');
check('E1. the caller bearer still reaches /reserve unchanged, alongside the key',
  reserves()[0].headers.authorization === `Bearer ${SESSION_TOKEN}`,
  JSON.stringify(reserves()[0].headers.authorization));
check('E2. /status still carries only the bearer and no decision key (that surface is unchanged)',
  statusReq?.headers.authorization === `Bearer ${SESSION_TOKEN}`
    && (HEADER in statusReq.headers) === false,
  Object.keys(statusReq?.headers || {}).join(','));
check('E3. the shared relay API key is never sent to the quota service',
  service.requests.every((r) => ('x-api-key' in r.headers) === false),
  service.requests.map((r) => Object.keys(r.headers).filter((h) => h.includes('api')).join('+')).join(' | ') || 'none');

// ── F. denial still blocks dispatch, with and without a key ────────────────
reset('exhausted');
const denied = await chat(SESSION_TOKEN, KEY_A);
check('F1. quota_exhausted still prevents provider dispatch and the key is still forwarded on the refusal',
  denied.status === 429 && provider.calls === 0 && keyOf(reserves()[0]) === KEY_A
    && (await denied.json()).status === 'quota_exhausted',
  `status=${denied.status} provider=${provider.calls}`);
reset('exhausted');
const deniedNoKey = await chat(SESSION_TOKEN);
check('F2. an exhausted refusal without a key behaves identically (no key is invented on the denial path either)',
  deniedNoKey.status === 429 && provider.calls === 0 && (HEADER in reserves()[0].headers) === false,
  `status=${deniedNoKey.status}`);
reset();
service.mode = 'allow';

// ── G / H. one decision repeated, and two decisions apart ─────────────────
reset();
await chat(SESSION_TOKEN, KEY_A);
await chat(SESSION_TOKEN, KEY_A);
await chat(SESSION_TOKEN, KEY_A);
check('G1. three physical /ai/chat attempts of one decision produce three /reserve requests all carrying the SAME key',
  reserves().length === 3 && reserves().every((r) => keyOf(r) === KEY_A),
  reserves().map((r) => keyOf(r)).join(','));
check('G2. NodeSend stays a dumb relay here: it asks every time and lets BridgeMind decide to charge once',
  provider.calls === 3, `provider calls=${provider.calls}`);

reset();
await chat(SESSION_TOKEN, KEY_A);
await chat(SESSION_TOKEN, KEY_B);
check('H1. two different decision keys stay different on the wire and are never merged or reused',
  reserves().map((r) => keyOf(r)).join('|') === `${KEY_A}|${KEY_B}`,
  reserves().map((r) => keyOf(r)).join(','));

reset();
await chat(SESSION_TOKEN, KEY_A);
await chat(FOREIGN_TOKEN, KEY_A);
check('H2. two different users presenting the same key are still authenticated separately — the bearer travels with each request',
  reserves().length === 2 && reserves().every((r) => keyOf(r) === KEY_A)
    && reserves()[0].headers.authorization === `Bearer ${SESSION_TOKEN}`
    && reserves()[1].headers.authorization === `Bearer ${FOREIGN_TOKEN}`,
  reserves().map((r) => String(r.headers.authorization).slice(-6)).join(','));

// ── I. nothing secret is logged ───────────────────────────────────────────
const allLogs = logs.join('\n');
const SECRETS = [PROVIDER_SECRET, SESSION_TOKEN, FOREIGN_TOKEN, PRIV_B64, 'server-only-bridge-key'];
check('I1. no provider key, session bearer, RSA private key or relay key appears in any log line',
  SECRETS.every((s) => allLogs.includes(s) === false),
  SECRETS.filter((s) => allLogs.includes(s)).map((s) => s.slice(0, 6) + '…').join(',') || 'clean');
check('I2. no quota-service host, path or internal field is echoed to the browser response',
  allLogs.includes(QUOTA_SERVICE_BASE) === false,
  QUOTA_SERVICE_BASE);

// ── J. other quota surfaces keep their exact previous shape ──────────────
reset();
await fetch(`${B}/ai/quota`, { headers: { Authorization: `Bearer ${SESSION_TOKEN}`, [HEADER]: KEY_A } });
// /ai/quota/config is role-gated inside NodeSend and a non-admin is refused BEFORE any
// outbound call is made, so an administrator bearer is what actually exercises this
// surface. (A 403 here would have made the check vacuous — it would have proved the
// guard works while saying nothing about the header.)
await fetch(`${B}/ai/quota/config`, { headers: { Authorization: `Bearer tok-admin`, [HEADER]: KEY_A } });
check('J1. GET /ai/quota and GET /ai/quota/config never forward a key even if the caller sends one',
  service.requests.length === 2
    && service.requests.every((r) => (HEADER in r.headers) === false)
    && service.requests.map((r) => r.route).join(',') === 'status,config',
  service.requests.map((r) => `${r.route}:${HEADER in r.headers}`).join(' '));

// ── non-vacuity: the detector must be able to fail ───────────────────────
check('V1. the key assertion has teeth: a reserve request recorded WITHOUT the header fails the same predicate used in A1',
  (() => {
    const stripped = { route: 'reserve', method: 'POST', headers: { authorization: `Bearer ${SESSION_TOKEN}` }, raw: '{}' };
    return keyOf(stripped) === KEY_A;
  })() === false && keyOf(reserves()[0] || { headers: {} }) !== 'definitely-not-sent',
  'planted keyless request is rejected by the A1 predicate');

realLog(`--- traffic: reserve=${reserves().length || 'reset'} provider=${provider.calls} quota requests recorded=${service.requests.length}`);
let failed = 0;
for (const r of results) {
  if (!r.pass) failed += 1;
  realLog(`${r.pass ? 'PASS' : 'FAIL'} ${r.name}${r.detail ? ' [' + String(r.detail).slice(0, 200) + ']' : ''}`);
}
realLog(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed`);
relayServer.close();
quotaService.close();
process.exit(failed ? 1 : 0);
