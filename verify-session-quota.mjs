// NodeSend session + authoritative-Postgres quota verification harness.
//
// Seam 1: global.fetch is replaced, so NCB /auth/get-session and the AI provider
// are mocked in-process. Any NCB /data/* call is recorded as a FAILURE: quota
// storage must be Postgres-only.
// Seam 2: the `pg` module is replaced through Module._load, so the SQL bridge.js
// issues runs against an in-process engine that serializes on the (user, period)
// row the way Postgres locks it. This proves the relay's ALGORITHM is atomic; it
// does NOT prove Postgres. For that, run verify-postgres-quota.mjs against a
// throwaway database (it refuses to run against anything else).
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIV_B64 = Buffer.from(privateKey.export({ type: 'pkcs1', format: 'pem' })).toString('base64');
const PROVIDER_SECRET = 'sk-REAL-PROVIDER-KEY-should-never-be-logged-9f3a';
// A recognisable DSN, so the leak checks mean something. The decoy proves which
// variable wins.
const FAKE_DSN = 'postgres://quota_svc:sup3r-secretdsn-DO-NOT-LOG@db.internal:5432/bridgemind_quota';
const DECOY_DSN = 'postgres://other_svc:DECOY-VALUE-must-lose@db.internal:5432/decoy';
const enc = (s) => crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(s)).toString('base64');

// ── world ──────────────────────────────────────────────────────────────────
const USERS = {
  'tok-a': { id: 101, role: 'user' },
  'tok-b': { id: 202, role: 'user' },
  'tok-c': { id: 303, role: 'user' },
  'tok-d': { id: 203, role: 'user' },
  'tok-admin': { id: 900, role: 'administrator' }
};
// The relay derives the quota period from the UTC clock (`getCurrentPeriodKey`
// reads `new Date()`), so the harness must not pin a month: a literal '2026-09'
// turns into a missing usage row the moment the month rolls over, which is what
// crashed this file. Derived once from the same UTC month the runtime will compute,
// and cross-checked against the period the relay itself reports (check below), so a
// divergence fails loudly instead of surfacing as an undefined row. Still fully
// deterministic within a run: nothing here reads the clock again per assertion.
const QUOTA_CLOCK = new Date();
const PERIOD = `${QUOTA_CLOCK.getUTCFullYear()}-${String(QUOTA_CLOCK.getUTCMonth() + 1).padStart(2, '0')}`;
const NEXT_RESET_AT_UTC = (() => {
  const [year, month] = PERIOD.split('-').map(Number);
  return new Date(Date.UTC(year, month, 1)).toISOString();
})();
const PERIOD_START_UTC = (() => {
  const [year, month] = PERIOD.split('-').map(Number);
  return new Date(Date.UTC(year, month - 1, 1));
})();
const tick = () => new Promise((r) => setImmediate(r));

const db = {
  config: null,
  overrides: new Map(),
  usage: new Map(),
  locks: new Map(),
  failMode: null, // null|all|state|reserve|usage|configRead|configWrite|bootstrap
  dropConfigRow: false,
  queries: 0,
  stateReads: 0,
  configSelects: 0,
  bootstrapRuns: 0,
  statements: [],
  poolConfig: null
};

const fails = (kind) => db.failMode === 'all' || db.failMode === kind;
const rowKey = (user, period) => `${user}|${period}`;

// Postgres serializes INSERT..ON CONFLICT..DO UPDATE against the row matched by
// the arbiter. Modelled as a per-(user, period) critical section held across an
// await, so a racing statement genuinely waits instead of interjecting.
function withRowLock(key, fn) {
  const prev = db.locks.get(key) || Promise.resolve();
  const tail = prev.then(fn, fn);
  db.locks.set(key, tail.catch(() => {}));
  return tail;
}

// Deliberately NOT locked: the retired read-check-write algorithm, kept so the
// concurrency check can prove it detects an overshoot.
async function legacyReadCheckWrite(user, period, limit) {
  const k = rowKey(user, period);
  const used = (db.usage.get(k) || {}).calls_used ?? 0;
  await tick();
  if (used >= limit) return false;
  await tick();
  db.usage.set(k, { calls_used: used + 1, applied_limit: limit });
  return true;
}

function stateRow(user, period) {
  const override = db.overrides.get(String(user));
  const usage = db.usage.get(rowKey(user, period));
  return {
    quota_enabled: db.config.quota_enabled,
    default_call_limit: db.config.default_call_limit,
    period_type: db.config.period_type,
    override_enabled: override ? override.enabled : null,
    override_call_limit: override ? override.call_limit : null,
    calls_used: usage ? usage.calls_used : null
  };
}

function fakeQuery(rawText, values = []) {
  // The relay's SQL constants are multi-line template literals, so classify the
  // trimmed statement or the leading newline hides the verb.
  const text = String(rawText).trim();
  db.queries++;
  db.statements.push(text.replace(/\s+/g, ' ').slice(0, 42));
  if (fails('all')) throw new Error('connection terminated unexpectedly');
  const one = (o) => ({ rows: [o], rowCount: 1 });
  const none = () => ({ rows: [], rowCount: 0 });

  if (/^CREATE (TABLE|UNIQUE INDEX)/i.test(text)) {
    if (fails('bootstrap')) throw new Error('schema blocked');
    db.bootstrapRuns++;
    return none();
  }
  if (/^INSERT INTO quota_config/i.test(text)) {
    if (fails('bootstrap')) throw new Error('schema blocked');
    db.bootstrapRuns++;
    // ON CONFLICT (id) DO NOTHING: seeding never overwrites an operator's row.
    if (!db.config) {
      db.config = { quota_enabled: true, default_call_limit: 100, period_type: 'monthly', updated_at: PERIOD_START_UTC };
    }
    return none();
  }
  if (/^SELECT c.quota_enabled/i.test(text)) {
    if (fails('state')) throw new Error('quota state unreadable');
    db.stateReads++;
    if (!db.config || db.dropConfigRow) return none();
    return one(stateRow(values[0], values[1]));
  }
  if (/^INSERT INTO quota_usage/i.test(text)) {
    if (fails('reserve')) throw new Error('reserve failed');
    const [user, period, limit] = values;
    return withRowLock(rowKey(user, period), async () => {
      await tick();
      const k = rowKey(user, period);
      const row = db.usage.get(k);
      if (!row) {
        if (1 > limit) return none();
        db.usage.set(k, { calls_used: 1, applied_limit: limit });
        return one({ calls_used: 1, applied_limit: limit });
      }
      // WHERE q.calls_used < EXCLUDED.applied_limit, evaluated under the lock.
      if (row.calls_used >= limit) return none();
      row.calls_used += 1;
      row.applied_limit = limit;
      return one({ calls_used: row.calls_used, applied_limit: limit });
    });
  }
  if (/^SELECT calls_used FROM quota_usage/i.test(text)) {
    if (fails('usage')) throw new Error('usage unreadable');
    const row = db.usage.get(rowKey(values[0], values[1]));
    return row ? one({ calls_used: row.calls_used }) : none();
  }
  if (/^SELECT quota_enabled, default_call_limit, period_type, updated_at FROM quota_config/i.test(text)) {
    if (fails('configRead')) throw new Error('config unreadable');
    db.configSelects++;
    if (!db.config) return none();
    return one(db.config);
  }
  if (/^UPDATE quota_config/i.test(text)) {
    if (fails('configWrite')) throw new Error('config unwritable');
    if (!db.config) return none();
    if (values[0] !== null && values[0] !== undefined) db.config.quota_enabled = values[0];
    if (values[1] !== null && values[1] !== undefined) db.config.default_call_limit = values[1];
    db.config.updated_at = new Date();
    return one(db.config);
  }
  throw new Error('unmocked SQL: ' + text.slice(0, 80));
}

const fakePg = {
  Pool: class FakePool {
    constructor(cfg) { db.poolConfig = cfg; this.cfg = cfg; }
    on() {}
    query(text, values) {
      try { return Promise.resolve(fakeQuery(text, values)); }
      catch (err) { return Promise.reject(err); }
    }
  }
};

const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'pg') return fakePg;
  return originalLoad.call(this, request, parent, isMain);
};

// ── mocked NCB (identity only) and mocked provider ─────────────────────────
const ncbViolations = [];
const world = { providerCalls: 0, seenAuthHeaders: [], providerAuthHeaders: [] };
const logs = [];
const realLog = console.log.bind(console);
for (const m of ['log', 'info', 'warn', 'error']) {
  console[m] = (...a) => { logs.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')); };
}

const realFetch = global.fetch;
global.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u.includes('rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url') || u.startsWith('mock://ncb')) {
    const route = new URL(u).pathname;
    const auth = String(opts.headers?.Authorization || '');
    world.seenAuthHeaders.push(auth);
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });
    if (route === '/auth/get-session') {
      const user = USERS[auth.replace('Bearer ', '')];
      return user ? json({ status: 'success', data: { user } }) : json({ status: 'error' }, 401);
    }
    ncbViolations.push(route); // quota storage must never come here
    return json({ error: 'NCB data API must not be used for quota' }, 500);
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
  return realFetch(url, opts);
};

process.env.NODESEND_PRIVATE_KEY_B64 = PRIV_B64;
process.env.BRIDGE_API_KEY = 'server-only-bridge-key';
process.env.BRIDGEMIND_QUOTA_DATABASE_URL = FAKE_DSN;
process.env.DATABASE_URL = DECOY_DSN;
process.env.PORT = '3999';

const mod = await import(pathToFileURL(path.join(ROOT, 'bridge.js')).href);
const { app, QUOTA_SCHEMA_SQL, NODESEND_VERSION } = mod;
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
const check = (name, pass, detail = '') => { results.push({ name, pass, detail }); };
const AUTH = (tok) => ({ headers: { Authorization: `Bearer ${tok}` } });
const PUTJSON = (tok, obj) => ({ method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok}` }, body: JSON.stringify(obj) });
let r, j, pc;

// ── 1. session identity is still the authority for WHO ─────────────────────
r = await fetch(`${B}/ai/chat`, CHAT(null));
check('no session -> 401, provider untouched', r.status === 401 && world.providerCalls === 0, `status=${r.status} providerCalls=${world.providerCalls}`);
r = await fetch(`${B}/ai/chat`, CHAT('tok-nope'));
check('invalid session -> 401, provider untouched', r.status === 401 && world.providerCalls === 0, `status=${r.status}`);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('valid session accepted with no x-api-key', r.status === 200, `status=${r.status}`);
j = await bodyOf(r);
check('provider dispatched exactly once', world.providerCalls === 1, `providerCalls=${world.providerCalls}`);
check('first reservation creates used=1', j.quota && j.quota.used === 1 && j.quota.limit === 100, JSON.stringify(j.quota));

// ── 2. storage authority is Postgres, and only Postgres ────────────────────
check('NCB /data/* never consulted for quota', ncbViolations.length === 0, ncbViolations.join(','));
check('quota SQL reached the pool', db.queries > 0 && db.statements.some((s) => s.startsWith('INSERT INTO quota_usage')), db.statements.join(' / '));
check('BRIDGEMIND_QUOTA_DATABASE_URL wins over DATABASE_URL', db.poolConfig && db.poolConfig.connectionString === FAKE_DSN, db.poolConfig && db.poolConfig.connectionString ? 'pool built' : 'no pool');
check('pool is bounded and time-boxed', db.poolConfig.max === 5 && db.poolConfig.statement_timeout === 5000 && db.poolConfig.connectionTimeoutMillis === 5000, JSON.stringify(db.poolConfig && { max: db.poolConfig.max, statement_timeout: db.poolConfig.statement_timeout }));
check('schema bootstrapped exactly once', db.bootstrapRuns === 5, `bootstrapRuns=${db.bootstrapRuns} (3 tables + index + seed)`);
check('DSN never appears in logs', !logs.join('\n').includes(FAKE_DSN) && !logs.join('\n').includes(DECOY_DSN), '');

// ── 3. admin sets a small, deterministic limit ─────────────────────────────
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { quota_enabled: 1, default_call_limit: 3 }));
j = await bodyOf(r);
check('admin PUT config -> 200 and applies', r.status === 200 && j.saved === true && j.default_call_limit === 3, JSON.stringify({ l: j.default_call_limit }));
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
j = await bodyOf(r);
check('admin GET config -> authoritative Postgres values', r.status === 200 && j.quota_enabled === true && j.default_call_limit === 3 && j.period_type === 'monthly' && typeof j.updated_at === 'string', JSON.stringify(j).slice(0, 120));
check('bootstrap is not re-run by later traffic', db.bootstrapRuns === 5, `bootstrapRuns=${db.bootstrapRuns}`);

// ── 4. GET /ai/quota is the session's own, never an imposed one ────────────
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('GET /ai/quota 200 + UI shape', r.status === 200 && ['enabled', 'unlimited', 'period', 'used', 'limit', 'remaining', 'percentage', 'resetAt'].every((k) => k in j), JSON.stringify(j));
check('used == 1, limit from the new config', j.used === 1 && j.limit === 3 && j.remaining === 2 && j.percentage === 33, `used=${j.used} limit=${j.limit}`);
// The relay and the harness must agree on WHICH month they are counting, or every
// usage-row assertion below is looking in the wrong key. Asserted rather than
// assumed, so a future change to either derivation is a red check, not a crash.
check('the relay counts the same UTC period the harness derives', j.period === PERIOD, `relay=${j.period} harness=${PERIOD}`);
check('resetAt is next month UTC', j.resetAt === NEXT_RESET_AT_UTC, `resetAt=${j.resetAt} expected=${NEXT_RESET_AT_UTC}`);
r = await fetch(`${B}/ai/quota?user_id=202&period_key=1999-01`, AUTH('tok-a'));
j = await bodyOf(r);
check('query-string user_id cannot fetch another user quota', r.status === 200 && j.used === 1 && j.limit === 3, JSON.stringify({ used: j.used, limit: j.limit }));
r = await fetch(`${B}/ai/quota`);
check('GET /ai/quota requires a session', r.status === 401, `status=${r.status}`);

// ── 5. body-supplied identity is inert; one increment per provider call ─────
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', { user_id: 999, userId: 999, period_key: '1999-01' }));
j = await bodyOf(r);
check('body user_id creates no foreign usage row', !db.usage.has(rowKey(999, '1999-01')) && db.usage.get(rowKey(101, PERIOD)).calls_used === 2, [...db.usage.keys()].join(','));
check('subsequent reservation increments exactly once', world.providerCalls === 2 && j.quota.used === 2, `providerCalls=${world.providerCalls} used=${j.quota && j.quota.used}`);

// ── 6. per-user override beats the default; a disabled one does not ─────────
db.overrides.set('202', { enabled: true, call_limit: 1 });
r = await fetch(`${B}/ai/chat`, CHAT('tok-b'));
check('user B first call ok (override limit 1)', r.status === 200, `status=${r.status}`);
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-b'));
j = await bodyOf(r);
check('override exhausted -> 429', r.status === 429 && j.status === 'quota_exhausted', `status=${r.status}`);
check('exhausted does NOT call provider', world.providerCalls === pc, `before=${pc} after=${world.providerCalls}`);
check('exhausted reports remaining 0 / 100%', j.quota && j.quota.remaining === 0 && j.quota.limit === 1 && j.quota.percentage === 100, JSON.stringify(j.quota));
r = await fetch(`${B}/ai/quota`, AUTH('tok-b'));
j = await bodyOf(r);
check('B sees its own exhausted state', j.used === 1 && j.limit === 1 && j.remaining === 0, JSON.stringify({ u: j.used, l: j.limit }));
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check("A's quota is independent of B", j.limit === 3 && j.used === 2, `limit=${j.limit} used=${j.used}`);
db.overrides.set('203', { enabled: false, call_limit: 999 });
r = await fetch(`${B}/ai/quota`, AUTH('tok-d'));
j = await bodyOf(r);
check('disabled override falls back to the default', j.limit === 3, `limit=${j.limit}`);

// ── 7. concurrency: the atomic guard, and proof the check has teeth ────────
db.overrides.set('303', { enabled: true, call_limit: 5 });
const before = world.providerCalls;
const attempts = await Promise.all(Array.from({ length: 12 }, () => fetch(`${B}/ai/chat`, CHAT('tok-c')).then((res) => res.status)));
const granted = attempts.filter((s) => s === 200).length;
const refused = attempts.filter((s) => s === 429).length;
check('12 racing calls against a limit of 5 -> exactly 5 granted', granted === 5, `granted=${granted} statuses=${attempts.join(',')}`);
check('the other 7 get 429', refused === 7, `refused=${refused}`);
check('provider contacted exactly 5 times', world.providerCalls - before === 5, `delta=${world.providerCalls - before}`);
check('counter never exceeded the limit', db.usage.get(rowKey(303, PERIOD)).calls_used === 5, `used=${db.usage.get(rowKey(303, PERIOD)).calls_used}`);
db.usage.delete(rowKey(303, PERIOD));
const legacy = await Promise.all(Array.from({ length: 12 }, () => legacyReadCheckWrite(303, PERIOD, 5)));
check('NEGATIVE CONTROL: read-check-write overshoots the limit', legacy.filter(Boolean).length > 5, `legacyGranted=${legacy.filter(Boolean).length} of 12 against limit 5`);
db.usage.set(rowKey(303, PERIOD), { calls_used: 5, applied_limit: 5 });

// ── 8. an unreachable store fails closed, on every surface ─────────────────
db.failMode = 'reserve';
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
check('DB reserve failure -> 503', r.status === 503 && j.status === 'quota_service_unavailable', `status=${r.status}`);
check('503 does NOT call provider', world.providerCalls === pc, `before=${pc} after=${world.providerCalls}`);
db.failMode = 'state';
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('DB state read failure -> 503 on GET /ai/quota', r.status === 503 && j.error === 'quota_service_unavailable', `status=${r.status}`);
check('unavailable quota reports nulls, never 0/limit', j.used === null && j.limit === null && j.remaining === null && j.percentage === null, JSON.stringify({ u: j.used, l: j.limit }));
db.failMode = 'configRead';
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
j = await bodyOf(r);
check('admin GET with DB down -> 503 and no fabricated config', r.status === 503 && j.quota_enabled === undefined && j.default_call_limit === undefined, `status=${r.status} body=${JSON.stringify(j).slice(0, 90)}`);
check('config 503 leaks no DSN or table name', !JSON.stringify(j).includes(FAKE_DSN) && !JSON.stringify(j).includes('quota_usage'), '');
db.failMode = 'configWrite';
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 2 }));
check('admin PUT with DB down -> 503', r.status === 503, `status=${r.status}`);
check('failed PUT left the stored limit unchanged', db.config.default_call_limit === 3, `limit=${db.config.default_call_limit}`);
db.failMode = 'all';
r = await fetch(`${B}/health`);
j = await bodyOf(r);
check('/health still serves while the quota store is down', r.status === 200 && j.quotaAuthority === 'postgres' && j.quotaStorage.configured === true, JSON.stringify(j.quotaStorage));
check('/health leaks no DSN', !JSON.stringify(j).includes(FAKE_DSN) && !JSON.stringify(j).includes('decoy'), '');
db.failMode = null;
db.dropConfigRow = true;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('missing config singleton -> 503, never unlimited', r.status === 503, `status=${r.status}`);
db.dropConfigRow = false;
db.failMode = 'bootstrap';
db.bootstrapRuns = 0;
r = await fetch(`${B}/health`);
check('health readable with bootstrap blocked', r.status === 200, `status=${r.status}`);
db.failMode = null;
db.bootstrapRuns = 5;

// ── 9. quota disabled is genuinely unlimited and spends nothing ────────────
db.config.quota_enabled = false;
db.usage.delete(rowKey(101, PERIOD));
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
check('quota disabled -> provider allowed', r.status === 200 && world.providerCalls === pc + 1, `status=${r.status}`);
check('quota disabled reports unlimited', j.quota && j.quota.unlimited === true && j.quota.enabled === false && j.quota.limit === null, JSON.stringify(j.quota));
check('quota disabled spends no counter row', !db.usage.has(rowKey(101, PERIOD)), [...db.usage.keys()].join(','));
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('GET /ai/quota reports unlimited when disabled', r.status === 200 && j.unlimited === true && j.enabled === false && j.used === 0, JSON.stringify({ u: j.used, un: j.unlimited }));
db.overrides.set('101', { enabled: true, call_limit: 1 });
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('disabled quota outranks even an override', r.status === 200 && j.unlimited === true, JSON.stringify({ un: j.unlimited }));
db.overrides.delete('101');
db.config.quota_enabled = true;

// ── 10. admin endpoint authorization ───────────────────────────────────────
r = await fetch(`${B}/ai/quota/config`);
check('config GET without a session -> 401', r.status === 401, `status=${r.status}`);
const selectsBefore = db.configSelects;
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-a'));
j = await bodyOf(r);
check('config GET as an ordinary user -> 403', r.status === 403 && j.status === 'forbidden', `status=${r.status}`);
check('a 403 runs no config query at all', db.configSelects === selectsBefore, `selects=${db.configSelects}`);
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-a', { quota_enabled: 1, default_call_limit: 7 }));
check('config PUT as an ordinary user -> 403', r.status === 403, `status=${r.status}`);
check('an ordinary user cannot change the limit', db.config.default_call_limit === 3, `limit=${db.config.default_call_limit}`);
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', {}));
check('config PUT with no fields -> 400', r.status === 400, `status=${r.status}`);
for (const bad of [{ default_call_limit: 0 }, { default_call_limit: 100001 }, { default_call_limit: 'many' }, { quota_enabled: 'maybe' }]) {
  r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', bad));
  check(`rejected PUT ${JSON.stringify(bad)} -> 400`, r.status === 400, `status=${r.status}`);
}
check('rejected PUTs left the config untouched', db.config.default_call_limit === 3 && db.config.quota_enabled === true, JSON.stringify(db.config));
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 7 }));
j = await bodyOf(r);
check('partial PUT keeps the other value', r.status === 200 && j.quota_enabled === true && j.default_call_limit === 7, JSON.stringify({ e: j.quota_enabled, l: j.default_call_limit }));
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('new default reaches the per-user status', j.limit === 7, `limit=${j.limit}`);
db.config.default_call_limit = 3;

// ── 11. relay invariants preserved by this change ──────────────────────────
r = await fetch(`${B}/send`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
check('/send still 403 without x-api-key', r.status === 403, `status=${r.status}`);
r = await fetch(`${B}/rocketchat`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'server-only-bridge-key' }, body: JSON.stringify({ text: 'x' }) });
check('/rocketchat still accepts x-api-key', r.status !== 403 && r.status !== 401, `status=${r.status}`);
r = await fetch(`${B}/quota`, { headers: { Authorization: 'Bearer tok-a' } });
check('generic /quota unchanged (403 without key)', r.status === 403, `status=${r.status}`);
const aKey = rowKey(101, PERIOD);
const usedBefore = (db.usage.get(aKey) || { calls_used: 0 }).calls_used;
const rowBefore = db.usage.has(aKey);
r = await fetch(`${B}/ai/chat`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' },
  body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', apiKey: PROVIDER_SECRET }, model: 'qwen3.8-flash', messages: [{ role: 'user', content: 'hi' }] })
});
j = await bodyOf(r);
check('plaintext provider key refused (ALLOW_PLAINTEXT_AI_KEYS=false)', r.status === 400 && /disabled|required/i.test(String(j.error)), `status=${r.status}`);
check('a rejected key spends no quota', db.usage.has(aKey) === rowBefore && (db.usage.get(aKey) || { calls_used: 0 }).calls_used === usedBefore, `used=${(db.usage.get(aKey) || { calls_used: 0 }).calls_used} hadRow=${rowBefore}`);
r = await fetch(`${B}/crypto/public-key`);
j = await bodyOf(r);
check('public key still served unauthenticated', r.status === 200 && j.publicKey?.includes('BEGIN PUBLIC KEY'), `status=${r.status}`);
r = await fetch(`${B}/ai/models`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider: 'alibaba', config: {} }) });
check('/ai/models 401 without session', r.status === 401, `status=${r.status}`);
r = await fetch(`${B}/ai/models`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' }, body: JSON.stringify({ provider: 'alibaba', config: {} }) });
j = await bodyOf(r);
check('/ai/models 200 with session', r.status === 200 && Array.isArray(j.models) && j.models.length === 2, `status=${r.status}`);
const bridgeSrc = fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8');
check('the retired NCB quota tables are gone from the source', !['ai_quota_config', 'ai_quota_user_override', 'ai_quota_usage'].some((t) => bridgeSrc.includes(t)), '');
const sessionCalls = bridgeSrc.split('ncbRequest(req, "/auth/get-session"').length - 1;
const ncbDataCalls = bridgeSrc.split('"/data/').length - 1;
check('NCB is used for /auth/get-session only', sessionCalls === 1 && ncbDataCalls === 0, `session=${sessionCalls} ncbDataPaths=${ncbDataCalls}`);

// ── 12. secret hygiene ─────────────────────────────────────────────────────
const blob = logs.join('\n');
check('no bearer token in logs', !blob.includes('tok-a') && !blob.includes('tok-admin'), '');
check('no provider secret in logs', !blob.includes(PROVIDER_SECRET), '');
check('no private key material in logs', !blob.includes('PRIVATE KEY'), '');
check('no DSN, host or DB user in logs', !blob.includes(FAKE_DSN) && !blob.includes('db.internal') && !blob.includes('quota_svc'), '');
check('encrypted provider credential reaches the provider decrypted', world.providerAuthHeaders.includes(`Bearer ${PROVIDER_SECRET}`), `providerAuthCount=${world.providerAuthHeaders.length}`);
// The caller's bearer IS forwarded to NCB by design (NCB decides what that
// session may see); it must never be what authenticates a provider call.
check('provider is never authenticated by the user bearer', world.providerAuthHeaders.length > 0 && !world.providerAuthHeaders.some((h) => h.includes('tok-')), world.providerAuthHeaders.map((h) => h.slice(0, 12) + '…').join(','));

// ── 13. bootstrap SQL: idempotent, non-destructive, atomic ─────────────────
const ddl = QUOTA_SCHEMA_SQL.join('\n');
check('version declares the postgres quota authority', NODESEND_VERSION === 'bridge-postgres-quota-v5', NODESEND_VERSION);
check('schema creates exactly 3 tables, all IF NOT EXISTS', QUOTA_SCHEMA_SQL.filter((s) => /^CREATE TABLE IF NOT EXISTS/.test(s)).length === 3, '');
check('usage is unique on (user_id, period_key)', /CREATE UNIQUE INDEX IF NOT EXISTS[\s\S]*ON quota_usage \(user_id, period_key\)/.test(ddl), '');
check('config seeded with ON CONFLICT DO NOTHING', /INSERT INTO quota_config[\s\S]*ON CONFLICT \(id\) DO NOTHING/.test(ddl), '');
check('schema contains no destructive verb', !/\b(DROP|TRUNCATE|DELETE FROM|ALTER TABLE)\b/i.test(ddl), '');
check('no session or bearer value is ever stored', !/token|session|bearer/i.test(ddl), '');

console.log = realLog;
let failed = 0;
for (const x of results) {
  if (!x.pass) failed++;
  console.log(`${x.pass ? 'PASS' : 'FAIL'}  ${x.name}${x.detail ? '   [' + x.detail + ']' : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed`);
console.log('MOCKED: NCB session, AI provider and Postgres are all in-process fakes.');
console.log('REAL-DB proof: node verify-postgres-quota.mjs with QUOTA_TEST_CONFIRM=1 and a throwaway DSN.');
process.exit(failed ? 1 : 0);
