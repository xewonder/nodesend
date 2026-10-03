// NodeSend session + NCB-authoritative quota verification harness.
//
//   node verify-session-quota.mjs
//
// Seam: global.fetch is replaced, so the NCB session authority (/auth/get-session),
// the NCB data API (/data/read|create|update over ai_quota_*) and the AI provider
// are all mocked in-process. No production endpoint is contacted and no real quota
// row is written.
//
// The mock models the contract BridgeMind's own client proves exists — equality
// filters only, a FLAT top-level column map on create/update,
// {status:"success",data:[…]} on read, 0/1 integer flags, NCB DATETIME timestamps —
// and it rejects an ISO 'Z' timestamp the way the real store does, so that
// regression fails here instead of in production. It also refuses a DELETE, so the
// relay is proven to issue no destructive write.
//
// What this harness deliberately does NOT prove, because NCB cannot: the
// reservation is not atomic. Its data API has no increment, upsert, transaction,
// batch, row version or conditional write. bridge.js therefore runs the whole
// read-check-write as one per-user critical section. Section 8 proves that holds
// for one process, and the two negative controls prove the check has teeth: the
// same sequence without the lock overshoots, and a duplicated row is refused
// rather than guessed at — which is exactly the multi-replica limitation documented
// in the source.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIV_B64 = Buffer.from(privateKey.export({ type: 'pkcs1', format: 'pem' })).toString('base64');
const PROVIDER_SECRET = 'sk-REAL-PROVIDER-KEY-should-never-be-logged-9f3a';
// Set only to prove they are inert now. If a leftover Coolify value ever changes
// behaviour again, the DSN checks below go red.
const STALE_DSN = 'postgres://quota_svc:sup3r-secretdsn-DO-NOT-LOG@db.internal:5432/bridgemind_quota';
const NCB_BASE = 'https://ncb.test.invalid';
const NCB_LAMBDA_HOST = 'rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url';
const enc = (s) => crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(s)).toString('base64');

// ── world ──────────────────────────────────────────────────────────────────
const USERS = {
  'tok-a': { id: 101, role: 'user' },
  'tok-b': { id: 202, role: 'user' },
  'tok-c': { id: 303, role: 'user' },
  'tok-d': { id: 203, role: 'user' },
  'tok-admin': { id: 900, role: 'administrator' }
};
// The relay derives the period from the UTC clock (`getCurrentPeriodKey` reads
// `new Date()`), so the harness must not pin a month: a literal '2026-09' becomes a
// missing usage row the moment the month rolls over. Derived once from the same UTC
// month the runtime computes, and cross-checked against the period the relay
// reports, so a divergence is a red check rather than a crash.
const QUOTA_CLOCK = new Date();
const PERIOD = `${QUOTA_CLOCK.getUTCFullYear()}-${String(QUOTA_CLOCK.getUTCMonth() + 1).padStart(2, '0')}`;
const NEXT_RESET_AT_UTC = (() => {
  const [year, month] = PERIOD.split('-').map(Number);
  return new Date(Date.UTC(year, month, 1)).toISOString();
})();
const tick = () => new Promise((r) => setImmediate(r));
const DATETIME_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;

// The tables already exist in the NCB instance — they were deliberately kept
// through the historical-game reset — so the harness seeds them and the relay is
// expected to issue no DDL and no schema bootstrap of its own.
const ncb = {
  tables: {
    ai_quota_config: [{ id: 9, quota_enabled: 1, default_call_limit: 100, period_type: 'monthly', updated_at: '2026-01-01 00:00:00' }],
    ai_quota_user_override: [],
    ai_quota_usage: []
  },
  nextId: 100,
  requests: [],
  violations: [],
  badTimestamps: [],
  // Fault injection. Each knob is a separate real failure mode of this store.
  failAuthTransport: false,
  failDataTransport: false,
  failDataHttp: 0,
  badEnvelope: false,
  rejectWrites: false,
  failCreate: false,
  failUpdate: false,
  ignoreFilters: false,
  wrapSingle: false
};
const rowsOf = (table, pred) => ncb.tables[table].filter(pred);
const rowOf = (table, pred) => rowsOf(table, pred)[0] || null;
const usageRows = (user, period) => rowsOf('ai_quota_usage', (r) => String(r.user_id) === String(user) && r.period_key === period);
const usageRow = (user, period) => usageRows(user, period)[0] || null;
const usedOf = (user, period) => Number(usageRow(user, period)?.calls_used ?? 0);
const dropUsage = (user, period) => {
  ncb.tables.ai_quota_usage = ncb.tables.ai_quota_usage.filter(
    (r) => !(String(r.user_id) === String(user) && r.period_key === period)
  );
};
const seedUsage = (user, calls, limit) => {
  dropUsage(user, PERIOD);
  ncb.tables.ai_quota_usage.push({
    id: ncb.nextId++, user_id: user, period_key: PERIOD,
    calls_used: calls, applied_limit: limit, updated_at: '2026-10-03 00:00:00'
  });
};
const seedOverride = (user, enabled, limit) => {
  ncb.tables.ai_quota_user_override.push({ id: ncb.nextId++, user_id: user, enabled, call_limit: limit });
};
const dropOverride = (user) => {
  ncb.tables.ai_quota_user_override = ncb.tables.ai_quota_user_override.filter((r) => String(r.user_id) !== String(user));
};
// A defect must show up as a red check, never as a stack trace that hides which
// assertion caught it — so every read of the config singleton goes through here,
// and setConfig re-seeds rather than throwing if the row is absent.
const config0 = () => ncb.tables.ai_quota_config[0] || {};
const setConfig = (values) => {
  if (ncb.tables.ai_quota_config.length === 0) {
    ncb.tables.ai_quota_config.push({ id: 9, quota_enabled: 1, default_call_limit: 3, period_type: 'monthly', updated_at: '2026-01-01 00:00:00' });
  }
  Object.assign(ncb.tables.ai_quota_config[0], values);
};
const resetConfig = (values = {}) => {
  ncb.tables.ai_quota_config.length = 0;
  ncb.tables.ai_quota_config.push({
    id: 9, quota_enabled: 1, default_call_limit: 3, period_type: 'monthly',
    updated_at: '2026-01-01 00:00:00', ...values
  });
};
const configCalls = () => ncb.requests.filter((q) => q.table === 'ai_quota_config').length;
const writesTo = (table) => ncb.requests.filter((q) => (q.op === 'create' || q.op === 'update') && q.table === table);

// One round trip of the retired design, run directly against the same fake store
// with no lock at all: the negative control that proves the concurrency checks
// would notice an overshoot.
async function unlockedReadCheckWrite(user, period, limit) {
  const row = usageRow(user, period);
  const used = row ? Number(row.calls_used) : 0;
  await tick();
  if (used >= limit) return false;
  await tick();
  if (row) row.calls_used = used + 1;
  else ncb.tables.ai_quota_usage.push({ id: ncb.nextId++, user_id: user, period_key: period, calls_used: 1, applied_limit: limit });
  return true;
}

// ── mocked NCB (session + data API) and mocked provider ────────────────────
const world = { providerCalls: 0, providerAuthHeaders: [], seenAuthHeaders: [], dataCalls: 0 };
const logs = [];
const realLog = console.log.bind(console);
for (const m of ['log', 'info', 'warn', 'error']) {
  console[m] = (...a) => { logs.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')); };
}

const jsonResponse = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

const realFetch = globalThis.fetch;

// The mock yields a real macrotask before answering. This is not cosmetic: with a
// purely synchronous mock, an await chain over already-resolved promises runs to
// completion before the next inbound socket is ever served, so twelve "concurrent"
// requests never interleave at all and the concurrency section would pass with or
// without the relay's per-user lock. Every check in section 8 depends on this lag.
const ncbLag = () => new Promise((resolve) => setImmediate(resolve));

// Same-user store-call overlap, counted from inside the store. One request issues
// three parallel reads, so a serialised relay peaks at 3; a relay without its lock
// peaks at multiples of that.
world.activeByUser = {};
world.peakByUser = {};

async function handleNcb(u, opts) {
  const parsed = new URL(u);
  const route = parsed.pathname;
  const method = String(opts.method || 'GET').toUpperCase();
  const auth = String(opts.headers?.Authorization || '');
  const query = Object.fromEntries(parsed.searchParams.entries());
  let body = null;
  if (opts.body) { try { body = JSON.parse(opts.body); } catch { body = null; } }
  world.seenAuthHeaders.push(auth);

  if (route === '/auth/get-session') {
    if (ncb.failAuthTransport) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
    const user = USERS[auth.replace('Bearer ', '')];
    return user ? jsonResponse({ status: 'success', data: { user } }) : jsonResponse({ status: 'error' }, 401);
  }

  const parts = route.replace(/^\//, '').split('/');
  if (parts[0] !== 'data') { ncb.violations.push(`${method} ${route}`); return jsonResponse({ status: 'error', error: 'unhandled route' }, 500); }
  const [, op, table, id] = parts;
  await ncbLag();
  world.dataCalls++;
  ncb.requests.push({ op, table, id, method, query, body, auth, userFilter: query.user_id ?? null });
  if (!auth.startsWith('Bearer tok-')) ncb.violations.push(`data call without a session bearer: ${op} ${table}`);
  if (ncb.failDataTransport) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
  if (ncb.failDataHttp) return jsonResponse({ status: 'error', message: 'Error creating record.' }, ncb.failDataHttp);
  if (!(table in ncb.tables)) { ncb.violations.push(`unknown table ${table}`); return jsonResponse({ status: 'error', error: `unknown table ${table}` }, 500); }

  if (op === 'delete') {
    // No destructive verb is legitimate on this path: the tables already exist
    // and NodeSend must never empty them.
    ncb.violations.push(`DELETE ${table}/${id}`);
    return jsonResponse({ status: 'error', error: 'delete refused by this harness' }, 500);
  }
  if (op === 'read') {
    if (ncb.badEnvelope) return jsonResponse({ status: 'success' });
    let rows = ncb.tables[table].map((r) => ({ ...r }));
    if (!ncb.ignoreFilters) {
      const filters = Object.entries(query).filter(([key]) => key !== 'Instance');
      rows = rows.filter((row) => filters.every(([key, value]) => String(row[key] ?? '') === String(value)));
    }
    if (ncb.wrapSingle) return jsonResponse({ status: 'success', data: rows[0] ?? null });
    return jsonResponse({ status: 'success', data: rows });
  }
  if (ncb.rejectWrites) return jsonResponse({ status: 'error', message: 'Error creating record.' });
  for (const [key, value] of Object.entries(body || {})) {
    if (key === 'updated_at' && !DATETIME_RE.test(String(value))) {
      ncb.badTimestamps.push(String(value));
      return jsonResponse({ status: 'error', message: 'Error creating record.' }, 500);
    }
  }
  if (op === 'create') {
    if (ncb.failCreate) return jsonResponse({ status: 'error', message: 'Error creating record.' }, 500);
    const row = { id: ncb.nextId++, ...body };
    ncb.tables[table].push(row);
    return jsonResponse({ status: 'success', data: { id: row.id } });
  }
  if (op === 'update') {
    if (ncb.failUpdate) return jsonResponse({ status: 'error', message: 'Error creating record.' }, 500);
    const row = ncb.tables[table].find((r) => String(r.id) === String(id));
    if (!row) return jsonResponse({ status: 'error', message: 'no such row' }, 404);
    Object.assign(row, body);
    return jsonResponse({ status: 'success', data: { id: row.id } });
  }
  ncb.violations.push(`unhandled data op ${op}`);
  return jsonResponse({ status: 'error', error: 'unhandled data op' }, 500);
}

global.fetch = async (url, opts = {}) => {
  const u = String(url);
  // The relay under test is reached over loopback like any browser would reach it.
  // Anything else that is not mocked above is refused outright, so this harness
  // cannot accidentally touch a real provider, a real NCB or a real Trickster.
  if (u.startsWith('http://127.0.0.1:') || u.startsWith('http://localhost:')) {
    return realFetch(u, opts);
  }
  if (u.startsWith(NCB_BASE) || u.includes(NCB_LAMBDA_HOST)) {
    const isData = !new URL(u).pathname.startsWith('/auth/');
    const user = String(opts.headers?.Authorization || '').replace('Bearer ', '');
    if (isData) {
      const now = (world.activeByUser[user] || 0) + 1;
      world.activeByUser[user] = now;
      world.peakByUser[user] = Math.max(world.peakByUser[user] || 0, now);
    }
    try {
      return await handleNcb(u, opts);
    } finally {
      if (isData) world.activeByUser[user]--;
    }
  }
  if (u.includes('dashscope.aliyuncs.com')) {
    world.providerCalls++;
    const providerAuth = String(opts.headers?.Authorization || '');
    world.providerAuthHeaders.push(providerAuth);
    world.seenAuthHeaders.push(providerAuth);
    return new Response(JSON.stringify({
      choices: [{ message: { role: 'assistant', content: 'P7N' } }],
      usage: { prompt_tokens: 11, completion_tokens: 5, total_tokens: 16 }
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  throw new Error(`harness refused an unexpected outbound request to ${u}`);
};

process.env.NODESEND_PRIVATE_KEY_B64 = PRIV_B64;
process.env.BRIDGE_API_KEY = 'server-only-bridge-key';
process.env.NCB_PROXY_BASE = NCB_BASE;
process.env.NCB_INSTANCE = '55954_bridgemind';
// Deliberately left set although nothing reads them any more.
process.env.BRIDGEMIND_QUOTA_DATABASE_URL = STALE_DSN;
process.env.DATABASE_URL = STALE_DSN;
process.env.PORT = '3999';

const mod = await import(pathToFileURL(path.join(ROOT, 'bridge.js')).href);
const { app, NODESEND_VERSION, getCurrentPeriodKey, getNextResetAt } = mod;
await new Promise((r) => app.listen(3999, '127.0.0.1', r));
const B = 'http://127.0.0.1:3999';
const bodyOf = async (res) => { try { return await res.json(); } catch { return {}; } };
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
// Bodies captured from failing surfaces, to prove an outage never describes the
// store it could not reach.
const outageBodies = [];
let r, j, pc;

// ── 1. the NCB session is still the identity authority ─────────────────────
r = await fetch(`${B}/ai/chat`, CHAT(null));
check('no session -> 401, provider untouched', r.status === 401 && world.providerCalls === 0, `status=${r.status} providerCalls=${world.providerCalls}`);
r = await fetch(`${B}/ai/chat`, CHAT('tok-nope'));
check('invalid session -> 401, provider untouched', r.status === 401 && world.providerCalls === 0, `status=${r.status}`);
ncb.failAuthTransport = true;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
outageBodies.push(JSON.stringify(j));
check('unreachable session authority -> 503, not 401', r.status === 503 && j.status === 'session_service_unavailable', `status=${r.status}`);
ncb.failAuthTransport = false;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('valid session accepted with no x-api-key', r.status === 200, `status=${r.status}`);
j = await bodyOf(r);
check('provider dispatched exactly once', world.providerCalls === 1, `providerCalls=${world.providerCalls}`);
check('first reservation creates used=1', j.quota && j.quota.used === 1 && j.quota.limit === 100, JSON.stringify(j.quota));

// ── 2. the quota store is NCB's own ai_quota_* tables ──────────────────────
const tablesRead = [...new Set(ncb.requests.filter((q) => q.op === 'read').map((q) => q.table))].sort();
check('all three ai_quota_* tables are read', ['ai_quota_config', 'ai_quota_usage', 'ai_quota_user_override'].every((t) => tablesRead.includes(t)) && tablesRead.length === 3, tablesRead.join(','));
check('the period row was created through /data/create', ncb.requests.some((q) => q.op === 'create' && q.table === 'ai_quota_usage'), JSON.stringify(ncb.requests.filter((q) => q.op === 'create').map((q) => q.body)));
check('the created row is stamped with the session user, not a supplied id', String(usageRow(101, PERIOD)?.user_id) === '101' && usedOf(101, PERIOD) === 1, JSON.stringify(usageRow(101, PERIOD)));
check('the created row carries the period key and applied limit', usageRow(101, PERIOD)?.period_key === PERIOD && Number(usageRow(101, PERIOD)?.applied_limit) === 100, JSON.stringify(usageRow(101, PERIOD)));
check('every data call carried a caller session bearer', ncb.violations.length === 0, ncb.violations.join(' | '));
check('the store is never addressed by a Postgres table name', !ncb.requests.some((q) => /^(quota_config|quota_usage|quota_user_override)$/.test(String(q.table))), '');
check('a config read never filters by user', !ncb.requests.some((q) => q.table === 'ai_quota_config' && q.userFilter !== null), '');
check('no DELETE was ever attempted', !ncb.violations.some((v) => /DELETE/.test(v)), '');
check('a stale DATABASE_URL is inert and never logged', !logs.join('\n').includes(STALE_DSN) && !logs.join('\n').includes('db.internal'), '');
check('timestamps go out as NCB DATETIME, never ISO with Z', ncb.badTimestamps.length === 0 && ncb.requests.filter((q) => q.body?.updated_at).every((q) => DATETIME_RE.test(q.body.updated_at)), ncb.badTimestamps.join(',') || ncb.requests.find((q) => q.body?.updated_at)?.body?.updated_at);

// ── 3. admin sets a small, deterministic limit ─────────────────────────────
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { quota_enabled: 1, default_call_limit: 3 }));
j = await bodyOf(r);
check('admin PUT config -> 200 and applies', r.status === 200 && j.saved === true && j.default_call_limit === 3 && j.quota_enabled === true, JSON.stringify({ e: j.quota_enabled, l: j.default_call_limit }));
check('the stored flag was written as 0/1, not a boolean', writesTo('ai_quota_config').some((q) => q.body?.quota_enabled === 1), JSON.stringify(writesTo('ai_quota_config')[0]?.body));
check('the write was read back before it was reported as saved', (() => {
  const at = ncb.requests.findIndex((q) => q.op === 'update' && q.table === 'ai_quota_config');
  return at >= 0 && ncb.requests.slice(at + 1).some((q) => q.op === 'read' && q.table === 'ai_quota_config');
})(), '');
check('an admin data call uses the admin own session bearer', writesTo('ai_quota_config').every((q) => q.auth === 'Bearer tok-admin'), writesTo('ai_quota_config').map((q) => q.auth).join(','));
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
j = await bodyOf(r);
check('admin GET config -> authoritative NCB values', r.status === 200 && j.quota_enabled === true && j.default_call_limit === 3 && j.period_type === 'monthly' && typeof j.updated_at === 'string', JSON.stringify(j).slice(0, 150));

// ── 4. GET /ai/quota is the session's own, never an imposed one ────────────
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('GET /ai/quota 200 + UI shape', r.status === 200 && ['enabled', 'unlimited', 'period', 'used', 'limit', 'remaining', 'percentage', 'resetAt'].every((k) => k in j), JSON.stringify(j));
check('used == 1, limit from the new config', j.used === 1 && j.limit === 3 && j.remaining === 2 && j.percentage === 33, `used=${j.used} limit=${j.limit}`);
check('the relay counts the same UTC period the harness derives', j.period === PERIOD && getCurrentPeriodKey() === PERIOD, `relay=${j.period} harness=${PERIOD}`);
check('resetAt is next month UTC', j.resetAt === NEXT_RESET_AT_UTC && getNextResetAt(PERIOD) === NEXT_RESET_AT_UTC, `resetAt=${j.resetAt}`);
r = await fetch(`${B}/ai/quota?user_id=202&period_key=1999-01`, AUTH('tok-a'));
j = await bodyOf(r);
check('query-string user_id cannot fetch another user quota', r.status === 200 && j.used === 1 && j.limit === 3, JSON.stringify({ used: j.used, limit: j.limit }));
check('query-string period_key cannot read another period', !usageRow(101, '1999-01') && j.period === PERIOD, '');
r = await fetch(`${B}/ai/quota`);
check('GET /ai/quota requires a session', r.status === 401, `status=${r.status}`);

// ── 5. body-supplied identity is inert; one increment per provider call ─────
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', { user_id: 999, userId: 999, period_key: '1999-01' }));
j = await bodyOf(r);
check('body user_id creates no foreign usage row', !usageRow(999, '1999-01') && !usageRow(999, PERIOD) && usedOf(101, PERIOD) === 2, ncb.tables.ai_quota_usage.map((x) => `${x.user_id}@${x.period_key}`).join(','));
check('a body period_key cannot open another period', !usageRow(101, '1999-01'), '');
check('no store request ever carried a client-supplied id', !ncb.requests.some((q) => String(q.userFilter) === '999' || String(q.body?.user_id) === '999'), '');
check('subsequent reservation increments exactly once', world.providerCalls === 2 && j.quota?.used === 2, `providerCalls=${world.providerCalls} used=${j.quota?.used}`);
check('the increment went through /data/update on the existing row', writesTo('ai_quota_usage').some((q) => q.op === 'update' && String(q.body?.calls_used) === '2'), JSON.stringify(writesTo('ai_quota_usage').map((q) => q.body)));

// ── 6. per-user override beats the default; a disabled one does not ────────
seedOverride(202, 1, 1);
r = await fetch(`${B}/ai/chat`, CHAT('tok-b'));
check('user B first call ok (override limit 1)', r.status === 200, `status=${r.status}`);
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-b'));
j = await bodyOf(r);
check('override exhausted -> 429', r.status === 429 && j.status === 'quota_exhausted', `status=${r.status}`);
check('exhausted does NOT call provider', world.providerCalls === pc, `before=${pc} after=${world.providerCalls}`);
check('exhausted reports remaining 0 / 100%', j.quota && j.quota.remaining === 0 && j.quota.limit === 1 && j.quota.percentage === 100, JSON.stringify(j.quota));
check('an exhausted user spends nothing further', usedOf(202, PERIOD) === 1, `used=${usedOf(202, PERIOD)}`);
r = await fetch(`${B}/ai/quota`, AUTH('tok-b'));
j = await bodyOf(r);
check('B sees its own exhausted state', j.used === 1 && j.limit === 1 && j.remaining === 0, JSON.stringify({ u: j.used, l: j.limit }));
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check("A's quota is independent of B", j.limit === 3 && j.used === 2, `limit=${j.limit} used=${j.used}`);
seedOverride(203, 0, 999);
r = await fetch(`${B}/ai/quota`, AUTH('tok-d'));
j = await bodyOf(r);
check('disabled override falls back to the default', j.limit === 3, `limit=${j.limit}`);
check('the override read was filtered by the session user', ncb.requests.some((q) => q.table === 'ai_quota_user_override' && String(q.userFilter) === '203'), '');

// ── 7. a filter the store ignores cannot make the relay read a stranger ────
// The per-table filter behaviour of this store is not documented anywhere, so the
// relay must not assume it was applied. With every row handed back, user 101 must
// still be held to their own usage, and no foreign row may be written.
ncb.ignoreFilters = true;
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('rows for other users are dropped by identity, not by trust in the filter', r.status === 200 && j.used === 2 && j.limit === 3, JSON.stringify({ s: r.status, u: j.used, l: j.limit }));
const writesBefore = writesTo('ai_quota_usage').length;
const ownRowId = String(usageRow(101, PERIOD)?.id);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
const lastWrite = writesTo('ai_quota_usage')[writesBefore];
check('a reservation under ignored filters still targets only its own row', r.status === 200
  && writesTo('ai_quota_usage').length === writesBefore + 1
  && String(lastWrite?.id) === ownRowId && lastWrite?.body?.period_key === undefined
  && usedOf(101, PERIOD) === 3 && usedOf(202, PERIOD) === 1, JSON.stringify({ ...lastWrite?.body, id: lastWrite?.id, ownRowId }));
ncb.ignoreFilters = false;
// Undo that increment so the counts in the sections below stay exact.
seedUsage(101, 2, 3);

// ── 8. concurrency: one per-user critical section, and its limits ─────────
dropUsage(101, PERIOD);
seedUsage(101, 2, 3);
seedOverride(303, 1, 5);
const before = world.providerCalls;
// Overlap is measured, not assumed. Reset the same-user window counter so this
// reads the race alone, and prove the counter can see overlap at all by first
// racing six UNLOCKED read-only calls for another user.
world.peakByUser['tok-c'] = 0;
await Promise.all(Array.from({ length: 6 }, () => fetch(`${B}/ai/quota`, AUTH('tok-d')).then((res) => res.status)));
const controlPeak = world.peakByUser['tok-d'] || 0;
check('INSTRUMENTATION CONTROL: overlapping store calls are observable', controlPeak > 3, `peak same-user store calls on six unlocked GETs=${controlPeak}`);
world.peakByUser['tok-d'] = 0;
const raceStart = ncb.requests.length;
const attempts = await Promise.all(Array.from({ length: 12 }, () => fetch(`${B}/ai/chat`, CHAT('tok-c')).then((res) => res.status)));
const racePeak = world.peakByUser['tok-c'] || 0;
const granted = attempts.filter((s) => s === 200).length;
const refused = attempts.filter((s) => s === 429).length;
// Serialisation is measured from inside the store: one reservation issues three
// parallel reads, so a serialised relay peaks at 3. Remove withUserQuotaLock and
// this climbs immediately, because twelve requests then share the window.
const race = ncb.requests.slice(raceStart);
const firstWriteAt = race.findIndex((q) => q.table === 'ai_quota_usage' && (q.op === 'create' || q.op === 'update'));
const readsBeforeFirstWrite = firstWriteAt < 0 ? -1
  : race.slice(0, firstWriteAt).filter((q) => q.op === 'read' && q.table === 'ai_quota_usage').length;
const writtenCounts = race.filter((q) => q.table === 'ai_quota_usage' && q.body?.calls_used !== undefined).map((q) => Number(q.body.calls_used));
check('the racers never shared the store window (one reservation at a time)', racePeak <= 3, `peak same-user store calls=${racePeak}`);
check('the 12 racers were serialised, not interleaved', readsBeforeFirstWrite === 1, `usage reads before the first write=${readsBeforeFirstWrite}`);
check('each reservation wrote the next counter value', writtenCounts.join(',') === '1,2,3,4,5', writtenCounts.join(','));
check('12 racing calls against a limit of 5 -> exactly 5 granted', granted === 5, `granted=${granted} statuses=${attempts.join(',')}`);
check('the other 7 get 429', refused === 7, `refused=${refused}`);
check('provider contacted exactly 5 times', world.providerCalls - before === 5, `delta=${world.providerCalls - before}`);
check('counter equals the limit, never above it', usageRows(303, PERIOD).length === 1 && usedOf(303, PERIOD) === 5, `rows=${usageRows(303, PERIOD).length} used=${usedOf(303, PERIOD)}`);
check('one usage row per (user, period) after the race', usageRows(303, PERIOD).length === 1, `rows=${usageRows(303, PERIOD).length}`);

// NEGATIVE CONTROL 1: the same twelve reservations without the relay's lock. If
// this overshoots (it must), the lock above is what prevents it, and the check is
// not vacuous.
dropUsage(303, PERIOD);
const unlocked = await Promise.all(Array.from({ length: 12 }, () => unlockedReadCheckWrite(303, PERIOD, 5)));
check('NEGATIVE CONTROL: an unlocked read-check-write overshoots', unlocked.filter(Boolean).length > 5, `granted=${unlocked.filter(Boolean).length} of 12 against limit 5`);

// NEGATIVE CONTROL 2: two rows for one (user, period) is the race the store itself
// cannot prevent (no unique constraint is expressible over HTTP). The relay must
// fail CLOSED on the ambiguity rather than quietly pick a winner and keep granting.
seedUsage(303, 5, 5);
ncb.tables.ai_quota_usage.push({ id: ncb.nextId++, user_id: 303, period_key: PERIOD, calls_used: 2, applied_limit: 5, updated_at: '2026-10-03 00:00:00' });
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-c'));
j = await bodyOf(r);
outageBodies.push(JSON.stringify(j));
check('duplicate usage rows -> 503 fail-closed, not a guessed counter', r.status === 503 && j.status === 'quota_service_unavailable', `status=${r.status}`);
check('an ambiguous counter does NOT call provider', world.providerCalls === pc, `before=${pc} after=${world.providerCalls}`);
seedUsage(303, 5, 5);

// ── 9. an unusable store fails closed on every surface ────────────────────
// 203 has no usage row, so this is the create path.
dropUsage(203, PERIOD);
ncb.failCreate = true;
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-d'));
j = await bodyOf(r);
outageBodies.push(JSON.stringify(j));
check('create failure -> 503', r.status === 503 && j.status === 'quota_service_unavailable', `status=${r.status}`);
check('503 does NOT call provider', world.providerCalls === pc, `before=${pc} after=${world.providerCalls}`);
check('a failed create left no row behind', !usageRow(203, PERIOD), '');
ncb.failCreate = false;
// 101 has a row, so this is the update path.
ncb.failUpdate = true;
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('update failure -> 503 and no provider', r.status === 503 && world.providerCalls === pc, `status=${r.status}`);
ncb.failUpdate = false;
ncb.rejectWrites = true;
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
outageBodies.push(JSON.stringify(j));
check('a 200 whose body says status:error is a rejected write -> 503', r.status === 503 && world.providerCalls === pc, `status=${r.status}`);
check('a rejected write spent nothing', usedOf(101, PERIOD) === 2, `used=${usedOf(101, PERIOD)}`);
ncb.rejectWrites = false;
ncb.failDataTransport = true;
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
outageBodies.push(JSON.stringify(j));
check('unreachable store -> 503 on GET /ai/quota', r.status === 503 && j.error === 'quota_service_unavailable', `status=${r.status}`);
check('unavailable quota reports nulls, never 0/limit', j.used === null && j.limit === null && j.remaining === null && j.percentage === null, JSON.stringify({ u: j.used, l: j.limit }));
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
j = await bodyOf(r);
outageBodies.push(JSON.stringify(j));
check('admin GET with the store down -> 503 and no fabricated config', r.status === 503 && j.quota_enabled === undefined && j.default_call_limit === undefined, `status=${r.status}`);
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 2 }));
j = await bodyOf(r);
outageBodies.push(JSON.stringify(j));
check('admin PUT with the store down -> 503 and no saved:true', r.status === 503 && j.saved === undefined, `status=${r.status}`);
check('a failed PUT left the stored limit unchanged', Number(config0().default_call_limit) === 3, `limit=${config0().default_call_limit}`);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('chat fails closed on an unreachable store', r.status === 503, `status=${r.status}`);
r = await fetch(`${B}/health`);
j = await bodyOf(r);
check('/health still serves while the quota store is down', r.status === 200 && j.quotaAuthority === 'ncb' && j.quotaStorage.configured === true && j.quotaStorage.status === 'unreachable', JSON.stringify(j.quotaStorage));
ncb.failDataTransport = false;
ncb.failDataHttp = 500;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('an HTTP 500 from the data API -> 503', r.status === 503, `status=${r.status}`);
ncb.failDataHttp = 0;
ncb.badEnvelope = true;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
outageBodies.push(JSON.stringify(j));
check('a read with no row list is unreadable -> 503, never unlimited', r.status === 503 && j.status === 'quota_service_unavailable', `status=${r.status}`);
check('an unreadable envelope marks the store invalid, not reachable', j.status === 'quota_service_unavailable', JSON.stringify(j).slice(0, 90));
ncb.badEnvelope = false;
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
check('service resumes after the store answers again', r.status === 200, `status=${r.status}`);
r = await fetch(`${B}/health`);
j = await bodyOf(r);
check('health reports ready after a successful round trip', r.status === 200 && j.quotaStorage.status === 'ready', JSON.stringify(j.quotaStorage));

// An empty ai_quota_config table is not a licence for unlimited usage.
ncb.tables.ai_quota_config.length = 0;
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('missing config singleton -> 503, never unlimited', r.status === 503 && world.providerCalls === pc, `status=${r.status}`);
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('missing config reports unavailable, not enabled', r.status === 503 && j.used === null, JSON.stringify({ s: r.status, u: j.used }));
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 4 }));
j = await bodyOf(r);
check('a partial PUT with no row to merge -> 400, never a fabricated default', r.status === 400 && j.status === 'quota_config_missing' && ncb.tables.ai_quota_config.length === 0, `status=${r.status}`);
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { quota_enabled: 1, default_call_limit: 3 }));
j = await bodyOf(r);
check('admin PUT with both fields creates the missing config row', r.status === 200 && j.saved === true && j.default_call_limit === 3 && ncb.tables.ai_quota_config.length === 1, `status=${r.status} rows=${ncb.tables.ai_quota_config.length}`);
check('a created config row stores the flag as 0/1', Number(config0().quota_enabled) === 1, JSON.stringify(config0()));
// Two config rows are two conflicting allowances.
ncb.tables.ai_quota_config.push({ id: 777, quota_enabled: 1, default_call_limit: 9999, period_type: 'monthly', updated_at: '2026-01-01 00:00:00' });
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('an ambiguous config singleton -> 503', r.status === 503, `status=${r.status}`);
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
check('an ambiguous config -> admin GET 503, no invented values', r.status === 503, `status=${r.status}`);
resetConfig();
r = await fetch(`${B}/ai/chat`, CHAT('tok-d'));
check('normal service resumes after the repair', r.status === 200, `status=${r.status}`);

// Hand-edited rows are broken state, not a licence.
setConfig({ period_type: 'weekly' });
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('a period_type this code does not implement -> 503', r.status === 503, `status=${r.status}`);
setConfig({ period_type: 'monthly' });
setConfig({ default_call_limit: 0 });
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('an out-of-range stored limit -> 503, never unlimited', r.status === 503, `status=${r.status}`);
setConfig({ default_call_limit: 3 });
seedUsage(101, 2, 3);
if (usageRow(101, PERIOD)) usageRow(101, PERIOD).calls_used = 'many';
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('a non-integer counter -> 503 instead of a coercion', r.status === 503, `status=${r.status}`);
seedUsage(101, 2, 3);
seedOverride(202, 1, null);
r = await fetch(`${B}/ai/quota`, AUTH('tok-b'));
check('an enabled override with no readable limit -> 503, not the default', r.status === 503, `status=${r.status}`);
dropOverride(202);
r = await fetch(`${B}/ai/quota`, AUTH('tok-b'));
check('B is readable again once the broken override row is gone', r.status === 200, `status=${r.status}`);
// A read that answers an object instead of a list is still a row list to us.
ncb.wrapSingle = true;
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('a single-object data payload is read as one row', r.status === 200 && j.used === 2 && j.limit === 3, JSON.stringify({ s: r.status, u: j.used }));
ncb.wrapSingle = false;

// ── 10. quota disabled is genuinely unlimited and spends nothing ───────────
setConfig({ quota_enabled: 0 });
dropUsage(101, PERIOD);
const usageWritesAtDisable = writesTo('ai_quota_usage').length;
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
check('quota disabled -> provider allowed', r.status === 200 && world.providerCalls === pc + 1, `status=${r.status}`);
check('quota disabled reports unlimited', j.quota && j.quota.unlimited === true && j.quota.enabled === false && j.quota.limit === null, JSON.stringify(j.quota));
check('quota disabled spends no counter row', !usageRow(101, PERIOD), ncb.tables.ai_quota_usage.map((x) => x.user_id).join(','));
check('quota disabled issues no write at all', writesTo('ai_quota_usage').length === usageWritesAtDisable, `before=${usageWritesAtDisable} after=${writesTo('ai_quota_usage').length}`);
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('GET /ai/quota reports unlimited when disabled', r.status === 200 && j.unlimited === true && j.enabled === false && j.used === 0, JSON.stringify({ u: j.used, un: j.unlimited }));
seedOverride(101, 1, 1);
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('disabled quota outranks even an override', r.status === 200 && j.unlimited === true, JSON.stringify({ un: j.unlimited }));
dropOverride(101);
seedUsage(101, 2, 3);
setConfig({ quota_enabled: 1 });
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('re-enabling resumes enforcement at the stored counter', r.status === 200 && j.used === 2 && j.limit === 3, JSON.stringify({ u: j.used, l: j.limit }));

// ── 11. admin endpoint authorization ───────────────────────────────────────
r = await fetch(`${B}/ai/quota/config`);
check('config GET without a session -> 401', r.status === 401, `status=${r.status}`);
const readsBefore = configCalls();
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-a'));
j = await bodyOf(r);
check('config GET as an ordinary user -> 403', r.status === 403 && j.status === 'forbidden', `status=${r.status}`);
check('a 403 runs no store request at all', configCalls() === readsBefore, `reads=${configCalls()} vs ${readsBefore}`);
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-a', { quota_enabled: 1, default_call_limit: 7 }));
check('config PUT as an ordinary user -> 403', r.status === 403, `status=${r.status}`);
check('an ordinary user cannot change the limit', Number(config0().default_call_limit) === 3, `limit=${config0().default_call_limit}`);
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', {}));
check('config PUT with no fields -> 400', r.status === 400, `status=${r.status}`);
for (const bad of [{ default_call_limit: 0 }, { default_call_limit: 100001 }, { default_call_limit: 'many' }, { quota_enabled: 'maybe' }]) {
  r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', bad));
  check(`rejected PUT ${JSON.stringify(bad)} -> 400`, r.status === 400, `status=${r.status}`);
}
check('rejected PUTs left the config untouched', Number(config0().default_call_limit) === 3 && Number(config0().quota_enabled) === 1, JSON.stringify(config0()));
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 7 }));
j = await bodyOf(r);
check('partial PUT keeps the other value', r.status === 200 && j.quota_enabled === true && j.default_call_limit === 7, JSON.stringify({ e: j.quota_enabled, l: j.default_call_limit }));
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('new default reaches the per-user status', j.limit === 7, `limit=${j.limit}`);
setConfig({ default_call_limit: 3 });

// ── 12. relay invariants preserved by this change ──────────────────────────
r = await fetch(`${B}/send`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
check('/send still 403 without x-api-key', r.status === 403, `status=${r.status}`);
r = await fetch(`${B}/rocketchat`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'server-only-bridge-key' }, body: JSON.stringify({ text: 'x' }) });
check('/rocketchat still accepts x-api-key', r.status !== 403 && r.status !== 401, `status=${r.status}`);
r = await fetch(`${B}/quota`, { headers: { Authorization: 'Bearer tok-a' } });
check('generic /quota unchanged (403 without key)', r.status === 403, `status=${r.status}`);
r = await fetch(`${B}/quota`, { headers: { 'x-api-key': 'server-only-bridge-key' } });
check('generic /quota still fails closed when unconfigured', r.status === 503, `status=${r.status}`);
r = await fetch(`${B}/ai/chat`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' },
  body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', apiKey: PROVIDER_SECRET }, model: 'qwen3.8-flash', messages: [{ role: 'user', content: 'hi' }] })
});
j = await bodyOf(r);
check('plaintext provider key refused (ALLOW_PLAINTEXT_AI_KEYS=false)', r.status === 400 && /disabled|required/i.test(String(j.error)), `status=${r.status}`);
check('a rejected key spends no quota', usedOf(101, PERIOD) === 2, `used=${usedOf(101, PERIOD)}`);
r = await fetch(`${B}/crypto/public-key`);
j = await bodyOf(r);
check('public key still served unauthenticated', r.status === 200 && j.publicKey?.includes('BEGIN PUBLIC KEY'), `status=${r.status}`);
r = await fetch(`${B}/ai/models`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider: 'alibaba', config: {} }) });
check('/ai/models 401 without session', r.status === 401, `status=${r.status}`);
r = await fetch(`${B}/ai/models`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' }, body: JSON.stringify({ provider: 'alibaba', config: {} }) });
j = await bodyOf(r);
check('/ai/models 200 with session', r.status === 200 && Array.isArray(j.models) && j.models.length === 2, `status=${r.status}`);
pc = world.providerCalls;
r = await fetch(`${B}/ai/test`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' }, body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', encryptedApiKey: enc(PROVIDER_SECRET) }, model: 'qwen3.8-flash' }) });
j = await bodyOf(r);
check('/ai/test 200 with session', r.status === 200 && r.status !== 429, `status=${r.status}`);
check('/ai/test dispatches the provider but spends no quota', world.providerCalls === pc + 1 && usedOf(101, PERIOD) === 2 && !('quota' in j), `calls=${world.providerCalls - pc} used=${usedOf(101, PERIOD)}`);
const rootInfo = await bodyOf(await fetch(`${B}/`));
check('root advertises the ncb quota authority and its tables', rootInfo.quotaStorage?.authority === 'ncb' && rootInfo.quotaStorage?.tables?.join(',') === 'ai_quota_config,ai_quota_user_override,ai_quota_usage', JSON.stringify(rootInfo.quotaStorage));
const tricksterRoutes = ['/trickster/bid/health', '/trickster/play/health'];
const guardStates = [];
const dataCallsBeforeTrickster = ncb.requests.length;
for (const route of tricksterRoutes) {
  guardStates.push((await fetch(`${B}${route}`)).status);
  guardStates.push((await fetch(`${B}${route}`, AUTH('tok-a'))).status);
}
check('Trickster routes still require the same session guard', guardStates.filter((s) => s === 401).length === 2 && guardStates.filter((s) => s === 502).length === 2, guardStates.join(','));
check('a Trickster call touches no quota row and no data route', ncb.requests.length === dataCallsBeforeTrickster, `before=${dataCallsBeforeTrickster} after=${ncb.requests.length}`);

// ── 13. secret hygiene ────────────────────────────────────────────────────
const blob = logs.join('\n');
check('no bearer token in logs', !blob.includes('tok-a') && !blob.includes('tok-admin'), '');
check('no provider secret in logs', !blob.includes(PROVIDER_SECRET), '');
check('no private key material in logs', !blob.includes('PRIVATE KEY'), '');
check('no store row or column payload in logs', !/calls_used|period_key|"user_id":|updated_at/.test(blob), blob.split('\n').find((l) => /calls_used|period_key/.test(l)) || '');
check('no stale DSN, host or DB user anywhere in logs', !blob.includes(STALE_DSN) && !blob.includes('db.internal') && !blob.includes('quota_svc'), '');
check('no NCB route or table name in any log line', !/\/data\/|ai_quota_/.test(blob), blob.split('\n').find((l) => /\/data\/|ai_quota_/.test(l)) || '');
check('an outage body never names a table, route or store detail', outageBodies.length >= 5 && outageBodies.every((b) => !/ai_quota|\/data\/|ncb\.test|postgres|db\.internal|Bearer/.test(b)), outageBodies.find((b) => /ai_quota|\/data\//.test(b)) || `${outageBodies.length} sampled`);
check('encrypted provider credential reaches the provider decrypted', world.providerAuthHeaders.includes(`Bearer ${PROVIDER_SECRET}`), `providerAuthCount=${world.providerAuthHeaders.length}`);
// The caller's bearer IS forwarded to NCB by design (NCB decides what that session
// may see); it must never be what authenticates a provider call.
check('provider is never authenticated by the user bearer', world.providerAuthHeaders.length > 0 && !world.providerAuthHeaders.some((h) => h.includes('tok-')), world.providerAuthHeaders.map((h) => h.slice(0, 12) + '…').join(','));
// A real response-text sweep, not a tautology: every session-gated surface is hit
// again and its raw body is searched for the caller's own bearer.
const echoProbes = [
  fetch(`${B}/ai/quota`, AUTH('tok-admin')).then((res) => res.text()),
  fetch(`${B}/ai/quota/config`, AUTH('tok-admin')).then((res) => res.text()),
  fetch(`${B}/ai/quota/config`, AUTH('tok-a')).then((res) => res.text()),
  fetch(`${B}/ai/chat`, CHAT('tok-a')).then((res) => res.text()),
  fetch(`${B}/health`).then((res) => res.text()),
  fetch(`${B}/`).then((res) => res.text()),
  fetch(`${B}/crypto/public-key`).then((res) => res.text())
];
const echoText = await Promise.all(echoProbes);
check('every probe returned a body to inspect', echoText.length === 7 && echoText.every((t) => typeof t === 'string' && t.length > 0), echoText.map((t) => typeof t).join(','));
// The secrets that must never appear in a body. Matched as literal strings, not
// as a loose word like "Bearer", which the relay legitimately uses in its own
// `auth: "BridgeMind Bearer session"` label — a check that fired on that would
// only teach whoever reads it next to ignore the result.
const SECRET_STRINGS = Object.keys(USERS).flatMap((t) => [t, `Bearer ${t}`])
  .concat([PROVIDER_SECRET, 'PRIVATE KEY', STALE_DSN]);
const leaked = echoText.map((t, i) => SECRET_STRINGS.filter((s) => t.includes(s)).map((s) => `${i}:${s}`)).flat();
check('no response body ever carries a bearer, a session token or the provider key', leaked.length === 0, leaked.join(','));
// Same detector, planted leak: proves the check above is not vacuous.
const canary = JSON.stringify({ authorization: 'Bearer tok-a', key: PROVIDER_SECRET });
check('the leak detector fires on a planted leak (positive control)', SECRET_STRINGS.some((s) => canary.includes(s)) && leaked.length === 0, SECRET_STRINGS.filter((s) => canary.includes(s))[0] || 'none');

// ── 14. source and configuration gates (structure, not a git diff) ─────────
const bridgeSrc = fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8');
// Comments are where the retired design is *described*, so an absence gate run on
// the whole file would either fire on that prose or be relaxed until it proves
// nothing. These gates judge the executable text only; the source's own narrative
// is checked separately for the concurrency disclosure.
const codeOnly = bridgeSrc
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/^[ \t]*\/\/.*$/gm, ' ');
const envExample = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
check('the NCB quota tables are the declared authority', ['ai_quota_config', 'ai_quota_user_override', 'ai_quota_usage'].every((t) => bridgeSrc.includes(`"${t}"`)), '');
check('quota reads, creates and update through /data/', /\/data\/read\//.test(bridgeSrc) && /\/data\/create\//.test(bridgeSrc) && /\/data\/update\//.test(bridgeSrc), '');
check('NCB /auth/get-session is still the one identity lookup', /ncbRequest\(req,\s*"\/auth\/get-session"\s*\)/.test(bridgeSrc), `mentions=${bridgeSrc.split('/auth/get-session').length - 1}`);
check('the session guard is still attached to all five AI surfaces', /app\.get\("\/ai\/quota",\s*requireBridgeSession/.test(bridgeSrc)
  && /app\.post\("\/ai\/models",\s*requireBridgeSession/.test(bridgeSrc)
  && /app\.post\("\/ai\/test",\s*requireBridgeSession/.test(bridgeSrc)
  && /app\.post\("\/ai\/chat",\s*requireBridgeSession/.test(bridgeSrc)
  && /app\.get\("\/ai\/quota\/config",\s*requireBridgeSession,\s*requireBridgeAdmin/.test(bridgeSrc)
  && /app\.put\("\/ai\/quota\/config",\s*requireBridgeSession,\s*requireBridgeAdmin/.test(bridgeSrc), '');
check('no PostgreSQL driver is required', !/\brequire\(\s*["']pg["']\s*\)/.test(codeOnly) && !pkg.dependencies?.pg && !pkg.devDependencies?.pg, Object.keys(pkg.dependencies || {}).join(','));
check('no quota database URL is read', !/QUOTA_DATABASE_URL|process\.env\.DATABASE_URL/.test(codeOnly), '');
check('no Postgres pool or bootstrap machinery survives', !/ensureQuotaPool|quotaPool|QUOTA_SCHEMA_SQL|RESERVE_QUOTA_SQL|READ_QUOTA_STATE_SQL|WRITE_QUOTA_CONFIG_SQL|QUOTA_DB_/.test(codeOnly), '');
check('no SQL statement is issued from the relay', !/\b(CREATE TABLE|ALTER TABLE|DROP TABLE|TRUNCATE|ON CONFLICT|INSERT INTO|UPSERT)\b/i.test(codeOnly) && !/\bSELECT\b[\s\S]{0,60}\bFROM\b/i.test(codeOnly), '');
check('the retired design is still disclosed in prose', /Postgres/.test(bridgeSrc) && /atomic UPSERT/.test(bridgeSrc), '');
check('identity is read only from the validated session', /req\.bridgeUser\?\.id/.test(codeOnly) && !/req\.body\??\.user_id|query\.user_id|req\.query\??\.user_id/.test(codeOnly), '');
check('.env.example carries no quota database configuration', !/BRIDGEMIND_QUOTA_DATABASE_URL|^DATABASE_URL|NODESEND_QUOTA_DB_/m.test(envExample), '');
check('.env.example documents the NCB quota authority', /ai_quota_config/.test(envExample) && /NCB_PROXY_BASE=/.test(envExample), '');
check('no browser-visible quota secret exists', !/VITE_[A-Z_]*(QUOTA|NCB|DATABASE|BEARER|SESSION)/i.test(envExample + bridgeSrc), '');
check('the obsolete Postgres harness is gone', !fs.existsSync(path.join(ROOT, 'verify-postgres-quota.mjs')), '');
check('the concurrency limitation is documented in the source', /CONCURRENCY/.test(bridgeSrc) && /More than one NodeSend replica/i.test(bridgeSrc) && /no atomic primitive|nothing equivalent/i.test(bridgeSrc), '');
check('version declares the ncb quota authority', NODESEND_VERSION === 'bridge-ncb-quota-v6', NODESEND_VERSION);

// ── 15. the exported predicates, and the lock itself ──────────────────────
const { ncbFlag, ncbInt, ncbDateTime, ncbRowList, resolveQuotaLimit, isSensibleQuotaLimit, isBridgeAdminRole, withUserQuotaLock } = mod;
check('ncbFlag reads 0/1, strings and booleans', ncbFlag(1, null) === true && ncbFlag(0, null) === false && ncbFlag('1', null) === true && ncbFlag(true, null) === true && ncbFlag(false, null) === false && ncbFlag(null, true) === true && ncbFlag(undefined, false) === false, '');
check('ncbInt accepts numeric columns and refuses junk', ncbInt('7') === 7 && ncbInt(7) === 7 && ncbInt(null) === null && ncbInt('') === null && ncbInt('many') === null && ncbInt(1.5) === null, '');
check('ncbDateTime is a NCB DATETIME, not ISO', ncbDateTime(new Date('2026-10-03T04:05:06.789Z')) === '2026-10-03 04:05:06', ncbDateTime(new Date('2026-10-03T04:05:06.789Z')));
check('ncbRowList models empty, list, single and unreadable', ncbRowList({ status: 'success', data: [] }).length === 0 && ncbRowList({ data: null }).length === 0 && ncbRowList({ data: [{ id: 1 }] }).length === 1 && ncbRowList({ data: { id: 1 } }).length === 1 && ncbRowList({ status: 'success' }) === null && ncbRowList(null) === null, '');
check('override beats the default only when enabled', resolveQuotaLimit({ default_call_limit: 3, override_enabled: true, override_call_limit: 9 }) === 9 && resolveQuotaLimit({ default_call_limit: 3, override_enabled: false, override_call_limit: 9 }) === 3 && resolveQuotaLimit({ default_call_limit: 3, override_enabled: true, override_call_limit: 'junk' }) === 3, '');
check('limits are bounded to 1..100000', isSensibleQuotaLimit(1) && isSensibleQuotaLimit(100000) && !isSensibleQuotaLimit(0) && !isSensibleQuotaLimit(100001) && !isSensibleQuotaLimit(1.5), '');
check('both admin role spellings are honoured', isBridgeAdminRole('admin') && isBridgeAdminRole('administrator') && isBridgeAdminRole(' Administrator ') && !isBridgeAdminRole('user') && !isBridgeAdminRole(''), '');
check('withUserQuotaLock serialises per user and survives a rejection', await (async () => {
  const order = [];
  let concurrency = 0;
  let peak = 0;
  const job = (tag, ms) => withUserQuotaLock('u1', async () => {
    concurrency++; peak = Math.max(peak, concurrency);
    order.push(`start:${tag}`);
    await new Promise((res) => setTimeout(res, ms));
    order.push(`end:${tag}`);
    concurrency--;
    if (tag === 'boom') throw new Error('planted failure');
  });
  const settled = await Promise.allSettled([job('a', 12), job('boom', 4), job('c', 1)]);
  const after = await withUserQuotaLock('u1', async () => 'unblocked');
  const otherUser = await withUserQuotaLock('u2', async () => 'independent');
  return peak === 1 && order.join(',') === 'start:a,end:a,start:boom,end:boom,start:c,end:c'
    && settled.map((s) => s.status).join(',') === 'fulfilled,rejected,fulfilled'
    && after === 'unblocked' && otherUser === 'independent';
})(), '');

console.log = realLog;
let failed = 0;
for (const x of results) {
  if (!x.pass) failed++;
  console.log(`${x.pass ? 'PASS' : 'FAIL'}  ${x.name}${x.detail ? '   [' + x.detail + ']' : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed`);
console.log('MOCKED: the NCB session authority, the NCB ai_quota_* data API and the AI provider are all in-process fakes.');
console.log('NOT PROVED: atomicity. NCB has no increment/upsert/transaction, so the reservation is a serialised');
console.log('read-check-write — exact within one NodeSend process; see the two negative controls in section 8.');
process.exit(failed ? 1 : 0);
