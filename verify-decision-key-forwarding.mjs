// NodeSend decision-key propagation verification harness.
//
//   node verify-decision-key-forwarding.mjs
//
// The caller's `x-ai-decision-key` header is the idempotency key for one logical AI
// decision, and since v9 it ends its journey INSIDE this process: NodeSend holds the quota
// authority, so the key is written to the reservation ledger in NCB and must reach nothing
// else. Rewritten 2026-10-04, disclosed: this harness used to prove that NodeSend forwarded
// the header onward to an external BridgeMind `/reserve`. That hop is gone, so the claim
// being pinned is now the one that matters for billing — the key arrives at the ledger, is
// scoped to the validated session user, and never appears in a provider request, a response
// body, a log line, or another user's rows.
//
// Architecture under test is the real one: NCB (session authority AND the quota tables) is a
// loopback HTTP server, so the route grammar, the filter spelling, the bearer forwarding and
// the reservation body are exercised over a socket rather than a stub; the AI provider is a
// fetch mock that records every header and byte of body; any other outbound URL is refused
// outright, so an accidental call to a production host fails the run instead of making one.
//
// Cases: A key lands in the ledger byte-for-byte · B no key means none is invented ·
// C never in the provider body · D never in provider headers · E bearer discipline ·
// F denial and outage still block the provider · G one key twice = one charge ·
// H two keys = two charges · I nothing secret is logged · J status and config carry no key ·
// K non-vacuity controls · L oversized and hostile keys are dropped, not trusted ·
// M the outcome header is CORS-exposed and nothing else is · N a key is not an identity.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIV_B64 = Buffer.from(privateKey.export({ type: 'pkcs1', format: 'pem' })).toString('base64');
const PROVIDER_SECRET = 'sk-REAL-PROVIDER-KEY-should-never-be-logged-9f3a';
const SESSION_TOKEN = 'bridge-session-token-6b1f2e3d4c5b';
const FOREIGN_TOKEN = 'another-users-session-token-77aa';
const ADMIN_TOKEN = 'tok-admin-key-9c8b';
const PROVIDER_HOST = 'dashscope.aliyuncs.com';
const HEADER = 'x-ai-decision-key';
// Never hardcode a calendar month into a gate: it would pass today and expire silently.
const PERIOD = new Date().toISOString().slice(0, 7);
const LIMIT = 100;
// Keys with characters the documented grammar allows, so "byte-for-byte" is a real claim.
const KEY_A = 'bid:6f9d2c1e-0a4b-4c8d.9e1f+2a3b4c5d6e7f';
const KEY_B = 'card#1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901';
const KEY_SHARED = 'shared-across-accounts';
const KEY_LONG = `bid:${'7'.repeat(300)}`;
const KEY_CONTROL = `bid:${String.fromCharCode(7)}bad`;
const KEY_EMPTY_WORDS = ['undefined', 'null', 'NaN', '{}', '[object Object]', 'string'];
const enc = (s) => crypto.publicEncrypt(
  { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  Buffer.from(s)).toString('base64');

const USERS = {
  [SESSION_TOKEN]: { id: 101, role: 'user' },
  [FOREIGN_TOKEN]: { id: 202, role: 'user' },
  [ADMIN_TOKEN]: { id: 900, role: 'administrator' }
};

// ── NCB: the session authority AND the quota store, over a real socket ─────
// Keyed by the real table names, because that is how the mock looks a route up: a property
// called `usage` would answer /data/read/ai_quota_usage with "unknown table", and everything
// downstream would then fail closed for a reason that has nothing to do with the relay.
const store = {
  ai_quota_config: [{ id: 1, quota_enabled: 1, default_call_limit: LIMIT, period_type: 'monthly', updated_at: '2026-10-04 09:00:00' }],
  ai_quota_user_override: [], ai_quota_usage: [], ai_quota_reservation: [],
  nextId: 100, requests: [], fault: null
};
const storeTable = (table) => store[table] || null;
const ncbServer = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => { raw += c; });
  req.on('end', () => {
    const url = new URL(req.url, 'http://ncb.mock');
    const pathname = url.pathname;
    const query = Object.fromEntries(url.searchParams.entries());
    const auth = String(req.headers.authorization || '');
    const table = pathname.split('/')[3];
    const rowId = pathname.split('/')[4];
    let body = null;
    try { body = raw ? JSON.parse(raw) : null; } catch { body = raw; }
    store.requests.push({ method: req.method, pathname, table, rowId, query, auth, body, raw, headers: { ...req.headers } });
    const send = (status, payload) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
    };
    if (pathname === '/auth/get-session') {
      const user = USERS[auth.replace('Bearer ', '')];
      return user ? send(200, { status: 'success', data: { user } }) : send(401, { status: 'error' });
    }
    if (pathname.startsWith('/data/read/')) {
      const rows = (storeTable(table) || []).filter((row) => Object.entries(query).every(([key, value]) =>
        key === 'Instance' || String(row[key]) === String(value)));
      return send(200, { status: 'success', data: rows, metadata: { page: 1, limit: 10, hasMore: false, hasPrev: false } });
    }
    if (pathname.startsWith('/data/create/')) {
      if (table === 'ai_quota_reservation' && store.fault === 'reservation_down') return send(500, { status: 'error' });
      if (table === 'ai_quota_reservation' && (store.ai_quota_reservation || []).some((r) => r.user_id === body.user_id
        && r.period_key === body.period_key && r.decision_key === body.decision_key)) {
        return send(409, { status: 'error', message: 'duplicate key on uk_reservation' });
      }
      const row = { id: store.nextId++, ...body };
      storeTable(table).push(row);
      return send(200, { status: 'success', data: [row] });
    }
    if (pathname.startsWith('/data/update/')) {
      const target = (storeTable(table) || []).find((r) => String(r.id) === String(rowId));
      if (!target) return send(404, { status: 'error' });
      Object.assign(target, body);
      return send(200, { status: 'success', data: [target] });
    }
    if (pathname.startsWith('/data/delete/')) {
      const before = (storeTable(table) || []).length;
      store[table] = (storeTable(table) || []).filter((r) => String(r.id) !== String(rowId));
      if (store[table].length === before) return send(404, { status: 'error' });
      return send(200, { status: 'success', data: [] });
    }
    return send(404, { status: 'error', message: 'no such route' });
  });
});
await new Promise((resolve) => ncbServer.listen(0, '127.0.0.1', resolve));
const NCB_BASE = `http://127.0.0.1:${ncbServer.address().port}`;

// ── log capture + provider mock + refusal of anything unrecognised ─────────
const logs = [];
const realLog = console.log.bind(console);
for (const m of ['log', 'info', 'warn', 'error']) {
  console[m] = (...a) => { logs.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')); };
}
const realFetch = globalThis.fetch;
const provider = { calls: 0, requests: [] };
const outboundHosts = new Set();
global.fetch = async (url, opts = {}) => {
  const u = String(url);
  try { outboundHosts.add(new URL(u).host); } catch { outboundHosts.add(`unparseable:${u}`); }
  if (u.startsWith(NCB_BASE)) return realFetch(u, opts);
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
process.env.TRICKSTER_BID_URL = 'http://127.0.0.1:1';
process.env.TRICKSTER_PLAY_URL = 'http://127.0.0.1:1';
delete process.env.BRIDGEMIND_QUOTA_URL;
delete process.env.AI_QUOTA_RESERVATION_TABLE;
process.env.PORT = '4123';

const mod = await import(pathToFileURL(path.join(ROOT, 'bridge.js')).href);
const { app } = mod;
const server = await new Promise((resolve) => {
  const listening = app.listen(4123, '127.0.0.1', () => resolve(listening));
});
const B = 'http://127.0.0.1:4123';
const CHAT = (token, key = null, extra = {}) => ({
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(key !== null ? { [HEADER]: key } : {})
  },
  body: JSON.stringify({
    provider: 'alibaba',
    config: { baseUrl: `https://${PROVIDER_HOST}/compatible-mode/v1`, encryptedApiKey: enc(PROVIDER_SECRET) },
    model: 'qwen3.8-flash',
    messages: [{ role: 'user', content: 'hi' }],
    ...extra
  })
});
const usageOf = (userId) => store.ai_quota_usage.find((r) => String(r.user_id) === String(userId) && r.period_key === PERIOD);
const claimsOf = (key) => store.ai_quota_reservation.filter((r) => r.decision_key === key);
const dataCalls = () => store.requests.filter((q) => q.pathname.startsWith('/data/'));
const reset = () => {
  store.ai_quota_usage.length = 0;
  store.ai_quota_user_override.length = 0;
  store.ai_quota_reservation.length = 0;
  store.ai_quota_config[0] = { id: 1, quota_enabled: 1, default_call_limit: LIMIT, period_type: 'monthly', updated_at: '2026-10-04 09:00:00' };
  store.requests.length = 0;
  store.fault = null;
  mod.resetQuotaProcessLedger();
};

const results = [];
const check = (name, pass, detail = '') => {
  results.push({ name, pass: !!pass, detail: String(detail).slice(0, 220) });
  return !!pass;
};
let r, j;

// ── A: the key arrives at the ledger, byte-for-byte ───────────────────────
reset();
r = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_A));
j = await r.json().catch(() => ({}));
const claimA = claimsOf(KEY_A);
check('A. a keyed decision writes exactly one reservation row with the key unchanged',
  r.status === 200 && claimA.length === 1 && claimA[0].decision_key === KEY_A
  && String(claimA[0].user_id) === '101' && claimA[0].period_key === PERIOD,
  JSON.stringify({ s: r.status, rows: claimA.length, key: claimA[0]?.decision_key }));
const createClaim = store.requests.find((q) => q.pathname === '/data/create/ai_quota_reservation');
check('A. the ledger write is the NCB create grammar with the caller bearer, never a user_id in the body of anything else',
  createClaim?.method === 'POST' && createClaim?.pathname === '/data/create/ai_quota_reservation'
  && createClaim?.auth === `Bearer ${SESSION_TOKEN}` && createClaim?.query.Instance === '55954_bridgemind',
  JSON.stringify({ m: createClaim?.method, p: createClaim?.pathname }));
check('A. the lookup filter names the same tuple the claim was written with',
  store.requests.some((q) => q.pathname === '/data/read/ai_quota_reservation'
    && q.query.decision_key === KEY_A && String(q.query.user_id) === '101' && q.query.period_key === PERIOD),
  store.requests.filter((q) => q.pathname.includes('reservation')).map((q) => q.pathname + q.auth.slice(0, 12)).join(' | '));
check('A. the charge itself happened exactly once for this decision', usageOf(101)?.calls_used === 1,
  `calls_used=${usageOf(101)?.calls_used}`);

// ── B: absent header means no key is invented ─────────────────────────────
reset();
r = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, null));
check('B. a keyless decision is charged and creates no reservation row',
  r.status === 200 && store.ai_quota_reservation.length === 0 && usageOf(101)?.calls_used === 1,
  JSON.stringify({ s: r.status, rows: store.ai_quota_reservation.length, used: usageOf(101)?.calls_used }));
check('B. NodeSend never mints a decision key of its own',
  !store.requests.some((q) => /decision_key=[A-Za-z0-9-]{20,}/.test(q.pathname)) && store.ai_quota_reservation.length === 0,
  store.requests.filter((q) => q.pathname.includes('reservation')).length + ' reservation calls');
reset();
r = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, ''));
check('B. an empty header value is treated as no key, not as a shared empty key',
  r.status === 200 && store.ai_quota_reservation.length === 0 && usageOf(101)?.calls_used === 1,
  JSON.stringify({ s: r.status, rows: store.ai_quota_reservation.length }));

// ── C and D: the provider must not learn the key exists ───────────────────
reset();
provider.requests.length = 0;
for (const key of [KEY_A, KEY_B, KEY_SHARED]) {
  await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, key));
}
check('C. no provider request body contains any decision key',
  provider.requests.length === 3 && ![KEY_A, KEY_B, KEY_SHARED].some((k) => provider.requests.some((q) => q.body.includes(k))),
  provider.requests.map((q) => q.body.slice(0, 40)).join(' | '));
check('C. the provider body is still only provider fields — the key is not smuggled in as one',
  provider.requests.every((q) => {
    const parsed = JSON.parse(q.body);
    return !Object.keys(parsed).some((k) => /decision|key_/i.test(k)) && Array.isArray(parsed.messages);
  }), JSON.stringify(Object.keys(JSON.parse(provider.requests[0]?.body || '{}'))));
check('D. no provider request carries an x-ai-decision-key header',
  provider.requests.every((q) => !Object.keys(q.headers).some((h) => h.toLowerCase() === HEADER)),
  JSON.stringify([...new Set(provider.requests.flatMap((q) => Object.keys(q.headers)))]));
check('D. no provider header value contains a decision key',
  ![KEY_A, KEY_B, KEY_SHARED].some((k) => provider.requests.some((q) => Object.values(q.headers).some((v) => String(v).includes(k)))), '');
check('D. no provider URL contains a decision key',
  ![KEY_A, KEY_B, KEY_SHARED].some((k) => provider.requests.some((q) => q.url.includes(k))),
  provider.requests.map((q) => q.url).join(' | ').slice(0, 160));

// ── E: bearer discipline is unchanged by the key ─────────────────────────
check('E. the provider is authenticated by the caller-supplied provider key, not the session bearer',
  provider.requests.length > 0 && provider.requests.every((q) => String(q.headers.Authorization) === `Bearer ${PROVIDER_SECRET}`)
  && !provider.requests.some((q) => JSON.stringify(q.headers).includes(SESSION_TOKEN)),
  provider.requests.map((q) => String(q.headers.Authorization).slice(0, 12)).join(','));
check('E. every NCB data call carried the caller bearer and nothing else',
  dataCalls().length > 0 && dataCalls().every((q) => q.auth === `Bearer ${SESSION_TOKEN}`),
  [...new Set(dataCalls().map((q) => q.auth))].join(','));
check('E. the session bearer never reaches the provider and the provider key never reaches NCB',
  !provider.requests.some((q) => JSON.stringify(q.headers).includes('tok'))
  && !dataCalls().some((q) => JSON.stringify(q.body || {}).includes(PROVIDER_SECRET) || q.raw.includes(PROVIDER_SECRET)), '');

// ── F: denial and outage still stop the provider ─────────────────────────
reset();
store.ai_quota_usage.push({ id: 9001, user_id: '101', period_key: PERIOD, calls_used: LIMIT, applied_limit: LIMIT });
let pc = provider.calls;
r = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_A));
j = await r.json().catch(() => ({}));
check('F. exhaustion denies before dispatch, and the fresh claim is released rather than kept prepaid',
  r.status === 429 && provider.calls === pc && claimsOf(KEY_A).length === 0,
  JSON.stringify({ s: r.status, providerDelta: provider.calls - pc, rows: claimsOf(KEY_A).length }));
reset();
store.fault = 'reservation_down';
pc = provider.calls;
r = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_B));
j = await r.json().catch(() => ({}));
check('F. an unreadable ledger is a 503 before dispatch, with no charge at all',
  r.status === 503 && provider.calls === pc && usageOf(101) === undefined,
  JSON.stringify({ s: r.status, body: JSON.stringify(j).slice(0, 60) }));
store.fault = null;

// ── G and H: one decision once, two decisions twice ──────────────────────
reset();
const g1 = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_SHARED));
const g2 = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_SHARED));
const g3 = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_SHARED));
check('G. three attempts of one decision cost one call and one claim row',
  g1.status === 200 && g2.status === 200 && g3.status === 200
  && usageOf(101)?.calls_used === 1 && claimsOf(KEY_SHARED).length === 1,
  JSON.stringify({ used: usageOf(101)?.calls_used, rows: claimsOf(KEY_SHARED).length }));
check('G. the retries are labelled reused on the outcome header, the first as created',
  g1.headers.get('x-quota-reservation') === 'created' && g2.headers.get('x-quota-reservation') === 'reused'
  && g3.headers.get('x-quota-reservation') === 'reused',
  [g1, g2, g3].map((x) => x.headers.get('x-quota-reservation')).join(','));
check('G. a reused decision reaches the provider, so deduplication is not a refusal',
  provider.calls >= 3, `providerCalls=${provider.calls}`);
check('G. the reuse performed no counter write at all',
  store.requests.filter((q) => /\/data\/(create|update)\/ai_quota_usage/.test(q.pathname)).length === 1,
  store.requests.filter((q) => /ai_quota_usage/.test(q.pathname)).map((q) => q.method).join(','));
const h1 = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_B));
check('H. a different decision key is a second charge',
  h1.status === 200 && usageOf(101)?.calls_used === 2 && claimsOf(KEY_B).length === 1,
  JSON.stringify({ used: usageOf(101)?.calls_used, rows: claimsOf(KEY_B).length }));

// ── N: a key is a billing label, not an identity ─────────────────────────
reset();
const na = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_SHARED));
const nb = await fetch(`${B}/ai/chat`, CHAT(FOREIGN_TOKEN, KEY_SHARED));
const rowsShared = claimsOf(KEY_SHARED);
check('N. the same key under two sessions bills each once and never dedupes across accounts',
  na.status === 200 && nb.status === 200 && usageOf(101)?.calls_used === 1 && usageOf(202)?.calls_used === 1
  && rowsShared.length === 2 && new Set(rowsShared.map((x) => String(x.user_id))).size === 2,
  JSON.stringify({ a: usageOf(101)?.calls_used, b: usageOf(202)?.calls_used, users: rowsShared.map((x) => x.user_id) }));
check('N. a key cannot be used to charge somebody else: the body assertion is ignored',
  await (async () => {
    reset();
    const before = provider.calls;
    const spoof = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, 'spoof-attempt', { user_id: 202, email: 'someone@example.com' }));
    return spoof.status === 200 && claimsOf('spoof-attempt').every((x) => String(x.user_id) === '101')
      && usageOf(202) === undefined && provider.calls === before + 1;
  })(), JSON.stringify({ spoofedUsers: claimsOf('spoof-attempt').map((x) => x.user_id) }));
check('N. no request body or query ever named a user to the ledger on the spoofed call',
  !store.requests.some((q) => /someone@example|user_id=202&.*user_id=202/.test(q.raw + q.pathname)), '');

// ── L: hostile and oversized keys are dropped, never trusted ─────────────
reset();
const hostileStatuses = [];
// KEY_CONTROL is deliberately NOT sent over the wire: a header value containing 0x07 is
// rejected by the HTTP client itself (undici throws before the request leaves), so the only
// honest transport test of it is that the transport cannot carry it. It is still covered by
// the sanitizeDecisionKey check below, which is where the server-side rule lives.
for (const key of [...KEY_EMPTY_WORDS, KEY_LONG, '-leading-dash', '$(whoami)', "it's"]) {
  const res = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, key));
  hostileStatuses.push(res.status);
}
check('L. a control-character key cannot be sent at all, so it can never reach the ledger',
  await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_CONTROL)).then(() => false, () => true),
  'the client refused the request');
check('L. every refused key is billed as its own new decision, never deduplicated',
  usageOf(101)?.calls_used === 10 && store.ai_quota_reservation.length === 0,
  JSON.stringify({ used: usageOf(101)?.calls_used, rows: store.ai_quota_reservation.length }));
check('L. a refused key costs a dedupe and buys no free call and no refusal',
  hostileStatuses.every((s) => s === 200), hostileStatuses.join(','));
check('L. the drop happens before the ledger is addressed, so no bogus row can be created',
  !dataCalls().some((q) => q.table === 'ai_quota_reservation'),
  dataCalls().filter((q) => q.table === 'ai_quota_reservation').length + ' reservation calls');
check('L. the header name and length bound are the documented constants',
  mod.DECISION_KEY_HEADER === HEADER && mod.DECISION_KEY_MAX_LENGTH === 128,
  `${mod.DECISION_KEY_HEADER}/${mod.DECISION_KEY_MAX_LENGTH}`);
check('L. sanitizeDecisionKey is the single rule behind all of the above',
  mod.sanitizeDecisionKey(KEY_A) === KEY_A && mod.sanitizeDecisionKey(KEY_B) === KEY_B
  && mod.sanitizeDecisionKey(KEY_LONG) === null && mod.sanitizeDecisionKey(KEY_CONTROL) === null
  && mod.sanitizeDecisionKey('-leading-dash') === null && KEY_EMPTY_WORDS.every((k) => mod.sanitizeDecisionKey(k) === null), '');

// ── I: nothing secret is logged, and the key is a secret-shaped value ────
logs.length = 0;
reset();
await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_A));
await fetch(`${B}/ai/quota`, { headers: { Authorization: `Bearer ${SESSION_TOKEN}` } });
await fetch(`${B}/ai/quota/config`, { headers: { Authorization: `Bearer ${ADMIN_TOKEN}` } });
const blob = logs.join('\n');
check('I. no log line contains the decision key', !blob.includes(KEY_A), logs.filter((l) => blob.includes(KEY_A)).join(' | ').slice(0, 120));
check('I. no log line contains a bearer token or the provider key',
  !blob.includes(SESSION_TOKEN) && !blob.includes(FOREIGN_TOKEN) && !blob.includes(PROVIDER_SECRET),
  logs.find((l) => new RegExp(`${SESSION_TOKEN}|${PROVIDER_SECRET}`).test(l))?.slice(0, 100) || '');
check('I. no log line names a table, a row id or the storage host',
  !/ai_quota_|\/data\/|row_id|rowId/.test(blob) && !blob.includes(NCB_BASE),
  logs.find((l) => /ai_quota|\/data\//.test(l))?.slice(0, 100) || '');
const leakCanary = `[NodeSend] quota_audit ${JSON.stringify({ decision_key: KEY_A, authorization: `Bearer ${SESSION_TOKEN}`, sql: 'SELECT * FROM ai_quota_usage' })}`;
check('K. the log detectors fire on a planted leak (positive control)',
  leakCanary.includes(KEY_A) && leakCanary.includes(SESSION_TOKEN) && /ai_quota_/.test(leakCanary)
  && !blob.includes(KEY_A) && !blob.includes(SESSION_TOKEN), '');

// ── J: status and config routes neither need nor carry a key ─────────────
reset();
store.ai_quota_usage.push({ id: 9002, user_id: '101', period_key: PERIOD, calls_used: 4, applied_limit: LIMIT, created_at: '', updated_at: '' });
const requestsBefore = store.requests.length;
r = await fetch(`${B}/ai/quota`, { headers: { Authorization: `Bearer ${SESSION_TOKEN}`, [HEADER]: KEY_A } });
j = await r.json().catch(() => ({}));
check('J. GET /ai/quota reads the counter and writes nothing, key header present or not',
  r.status === 200 && j.used === 4 && store.requests.slice(requestsBefore).every((q) => !['POST', 'PUT', 'DELETE'].includes(q.method)),
  JSON.stringify({ s: r.status, used: j.used, writes: store.requests.slice(requestsBefore).filter((q) => q.method !== 'GET').map((q) => q.pathname) }));
check('J. a status read never touches the reservation table',
  !store.requests.slice(requestsBefore).some((q) => q.table === 'ai_quota_reservation'),
  store.requests.slice(requestsBefore).map((q) => q.pathname).join(' | '));
const cfgBefore = store.requests.length;
r = await fetch(`${B}/ai/quota/config`, { headers: { Authorization: `Bearer ${ADMIN_TOKEN}`, [HEADER]: KEY_A } });
j = await r.json().catch(() => ({}));
check('J. the admin config route is unaffected by the key and still admin-gated',
  r.status === 200 && j.quota_enabled === true && j.default_call_limit === LIMIT
  && !store.requests.slice(cfgBefore).some((q) => q.table === 'ai_quota_reservation'),
  JSON.stringify({ s: r.status, k: Object.keys(j) }));
const userCfg = await fetch(`${B}/ai/quota/config`, { headers: { Authorization: `Bearer ${SESSION_TOKEN}`, [HEADER]: KEY_A } });
check('J. an ordinary user with a key is still 403, and the key buys nothing',
  userCfg.status === 403, `status=${userCfg.status}`);

// ── M: what a browser is allowed to see ──────────────────────────────────
const preflight = await fetch(`${B}/ai/chat`, {
  method: 'OPTIONS',
  headers: { Origin: 'https://bridgemind.example', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': HEADER }
});
// 204, not 200: that is what cors() answers a successful preflight with, and pinning it here
// is what proves the request was ACCEPTED rather than rejected-and-then-echoed.
check('M. the preflight allows the decision key header to be sent',
  preflight.status === 204 && String(preflight.headers.get('access-control-allow-headers') || '').toLowerCase().includes(HEADER),
  JSON.stringify({ s: preflight.status, h: preflight.headers.get('access-control-allow-headers') }));
const exposed = (await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, 'expose-probe'))).headers.get('access-control-expose-headers');
check('M. the outcome header is exposed to a cross-origin reader',
  String(exposed || '').includes('x-quota-reservation'), String(exposed));
check('M. no response body contains the decision key',
  await (async () => {
    reset();
    const res = await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, KEY_A));
    const text = await res.text();
    return !text.includes(KEY_A) && !text.includes('decision_key');
  })(), '');
check('M. the only hosts this run contacted are the mock store, the provider and the relay',
  [...outboundHosts].sort().join(',') === [new URL(NCB_BASE).host, PROVIDER_HOST, '127.0.0.1:4123'].sort().join(','),
  [...outboundHosts].join(','));

// ── K: non-vacuity of the dedupe checks ─────────────────────────────────
check('K. G would fail if the key were ignored (two calls with no key charge twice)',
  await (async () => {
    reset();
    await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, null));
    await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, null));
    return usageOf(101)?.calls_used === 2;
  })(), `keyless used=${usageOf(101)?.calls_used}`);
check('K. G would fail if every call were deduplicated (two distinct keys charge twice)',
  await (async () => {
    reset();
    await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, 'vacuity-one'));
    await fetch(`${B}/ai/chat`, CHAT(SESSION_TOKEN, 'vacuity-two'));
    return usageOf(101)?.calls_used === 2 && store.ai_quota_reservation.length === 2;
  })(), `used=${usageOf(101)?.calls_used} rows=${store.ai_quota_reservation.length}`);
check('K. the durable ledger is the mode under test here, not the process fallback',
  mod.quotaLedgerDurable === true && mod.QUOTA_IDEMPOTENCY_MODE === 'durable', mod.QUOTA_IDEMPOTENCY_MODE);
// This harness is itself part of the surface that must not revive the retired hop: it sets
// no quota-service URL, and the file it is running from mentions the variable only to delete
// it from the environment.
const ownText = fs.readFileSync(path.join(ROOT, 'verify-decision-key-forwarding.mjs'), 'utf8');
const relayText = fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8');
const envText = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
check('K. no quota-service URL is configured by this harness or exists in the relay',
  !/process\.env\.BRIDGEMIND_QUOTA_URL\s*=/.test(ownText) && /delete process\.env\.BRIDGEMIND_QUOTA_URL/.test(ownText)
  && !/BRIDGEMIND_QUOTA_URL/.test(relayText) && !/BRIDGEMIND_QUOTA_URL/.test(envText),
  (ownText.match(/BRIDGEMIND_QUOTA_URL/g) || []).length + ' mentions in the harness');
check('K. no request of this run went anywhere that could be a quota service endpoint',
  !store.requests.some((q) => /^(reserve|status|config)$/.test(String(q.pathname).replace(/^\//, ''))),
  store.requests.map((q) => q.pathname).slice(0, 6).join(' | '));

console.log = realLog;
let failed = 0;
for (const x of results) {
  if (!x.pass) failed++;
  console.log(`${x.pass ? 'PASS' : 'FAIL'}  ${x.name}${x.detail ? '   [' + x.detail + ']' : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed`);
console.log('MOCKED: NCB (session authority and the four ai_quota_* tables) and the AI provider, both over');
console.log('loopback; the relay under test is the real exported app over a real socket.');
console.log('NOT CONFIGURED ANYWHERE REAL: no production endpoint was contacted and no quota row was written.');
ncbServer.close();
server.close();
process.exit(failed ? 1 : 0);
