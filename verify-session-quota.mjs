// NodeSend session + quota AUTHORITY verification harness.
//
//   node verify-session-quota.mjs
//   node verify-session-quota.mjs --variant=process-only   (run by the parent, not by hand)
//
// Architecture under test: NodeSend is the ONLY quota backend. It validates the caller's
// BridgeMind bearer against NCB /auth/get-session and then decides quota ITSELF, reading
// and writing the four ai_quota_* tables through the same NCB proxy with the same caller
// bearer. There is no external quota service to talk to, so there is no external-service
// mock here any more: the mock is of NCB, and it is a real loopback HTTP server rather than
// a fetch stub, because the thing worth proving is what this process actually puts on the
// wire — route, verb, filter, bearer, body — and a stub would only prove the stub.
//
// The mock NCB behaves like the measured surface: { status: "success", data: [...],
// metadata: {...} } envelopes, MySQL-ish string numbers and 0/1 flags, auto-increment ids,
// and a UNIQUE(user_id, period_key, decision_key) index on the reservation table that
// answers a duplicate create with 409. Fault knobs inject exactly the failures a real
// storage can produce (a write that refuses, a duplicate singleton row, a malformed flag, a
// service that never answers) so fail-closed behaviour is demonstrated rather than argued.
//
// Nothing here contacts a real endpoint. global.fetch is replaced for the AI provider and
// every non-loopback URL that is not the mock is refused outright, so an accidental call to
// a production host fails the run instead of making one.
//
// Section and check names carry the numbering of the refactor spec's required tests where a
// check answers one of them, so the report can be read against the spec.
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const VARIANT = (process.argv.find((a) => a.startsWith('--variant=')) || '').split('=')[1] || 'durable';

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIV_B64 = Buffer.from(privateKey.export({ type: 'pkcs1', format: 'pem' })).toString('base64');
const PROVIDER_SECRET = 'sk-REAL-PROVIDER-KEY-should-never-be-logged-9f3a';
const enc = (s) => crypto.publicEncrypt(
  { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  Buffer.from(s)).toString('base64');

const USERS = {
  'tok-a': { id: 101, role: 'user' },
  'tok-b': { id: 202, role: 'user' },
  'tok-c': { id: 204, role: 'user' },
  'tok-admin': { id: 900, role: 'administrator' }
};
// Never hardcode a calendar month into a gate: it would pass today and expire silently.
const PERIOD = new Date().toISOString().slice(0, 7);
const RESET_AT = (() => {
  const [y, m] = PERIOD.split('-').map(Number);
  return new Date(Date.UTC(y, m, 1)).toISOString();
})();
const DEFAULT_LIMIT = 3;

// Strings that must never appear in a response body or a log line. Table names are not
// secrets in themselves, but they are storage internals that the caller has no business
// learning, and a leak of one is how a storage bug becomes a reconnaissance report.
const LEAK_STRINGS = [...Object.keys(USERS), PROVIDER_SECRET, 'PRIVATE KEY', 'server-only-bridge-key'];
const STORAGE_STRINGS = ['ai_quota_config', 'ai_quota_user_override', 'ai_quota_usage', 'ai_quota_reservation'];

// ── the quota store: a real loopback NCB proxy mock ────────────────────────
const ncb = {
  requests: [],
  // `user_settings` is the AUTHORITATIVE ai_source table the relay now reads. It is in
  // this registry so a read for it is served like any other and, crucially, so a
  // missing-table bug would surface as a 404 rather than as a silent free pass.
  rows: { ai_quota_config: [], ai_quota_user_override: [], ai_quota_usage: [], ai_quota_reservation: [], user_settings: [], user_codes: [], ai_provider_credentials_1770000000: [] },
  nextId: {
    ai_quota_config: 1, ai_quota_user_override: 1, ai_quota_usage: 1, ai_quota_reservation: 1,
    user_settings: 1, user_codes: 1, ai_provider_credentials_1770000000: 1
  },
  // One fault at a time: mixing them makes a red check ambiguous about which fired.
  fault: null,
  faultHits: {},
  // Number of upcoming reservation reads that answer "no rows" even though rows exist.
  // This is how a lost race is simulated: our read committed before the other writer's.
  hideReservationReads: 0,
  counts: {}
};
const events = [];
const world = { providerCalls: 0, providerRequests: [], outboundUrls: [] };

const ncbServer = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (chunk) => { raw += chunk; });
  req.on('end', () => {
    const url = new URL(req.url, 'http://ncb.mock');
    const pathname = url.pathname;
    const query = Object.fromEntries(url.searchParams.entries());
    const auth = String(req.headers.authorization || '');
    const table = pathname.split('/')[3] || null;
    const rowId = pathname.split('/')[4] || null;
    let body = null;
    try { body = raw ? JSON.parse(raw) : null; } catch { body = raw; }
    ncb.requests.push({ method: req.method, pathname, table, rowId, query, raw, body, auth, contentType: req.headers['content-type'] || null });
    const send = (status, payload, type = 'application/json') => {
      res.writeHead(status, { 'content-type': type });
      res.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
    };
    const ok = (rows) => send(200, { status: 'success', data: rows, metadata: { page: 1, limit: 10, hasMore: false, hasPrev: false } });
    const fail = (status, message) => send(status, { status: 'error', message });
    ncb.faultHits[ncb.fault || 'none'] = (ncb.faultHits[ncb.fault || 'none'] || 0) + 1;

    if (pathname === '/auth/get-session') {
      events.push('session');
      if (ncb.fault === 'session_hang') return;
      // The session envelope is NOT the same shape as a data envelope: /auth/get-session
      // answers { status:"success", data:{ user:{...} } }, while /data/read answers
      // data:[rows]. Getting this backwards makes every call 401 and the whole gate blind,
      // which is exactly what happened on the first run of this harness.
      const user = USERS[auth.replace('Bearer ', '')];
      return user ? send(200, { status: 'success', data: { user } }) : fail(401, 'invalid session');
    }
    // NCB's PUBLIC data route: reachable with no session at all, and only for tables whose
    // policy allows it. It is modelled as strictly credential-free — a request that arrives
    // here carrying an Authorization is refused — because that is the whole property the
    // invitation route depends on: an anonymous pre-registration read must not be able to
    // present the caller's session, and a mock that tolerated a bearer here would let a real
    // regression pass.
    if (pathname.startsWith('/public-data/read/')) {
      const publicTable = pathname.split('/')[3] || null;
      events.push(`publicread:${publicTable}`);
      // The same outage the authenticated route can suffer: an anonymous read has to face a
      // timeout too, or the invitation route's fail-closed branch is untestable.
      if (ncb.fault === 'data_hang') return;
      if (auth) return fail(400, 'the public route accepts no credential');
      if (!ncb.rows[publicTable]) return fail(404, `unknown table ${publicTable}`);
      const publicRows = ncb.rows[publicTable].filter((row) => Object.entries(query).every(([key, value]) =>
        key === 'Instance' || String(row[key]) === String(value)));
      ncb.counts.publicRead = (ncb.counts.publicRead || 0) + 1;
      return ok(publicRows);
    }
    if (!pathname.startsWith('/data/')) return fail(404, 'no such route');
    if (ncb.fault === 'data_hang') return; // never answers: the NCB timeout must fire
    if (ncb.fault === 'data_html') return send(200, '<!DOCTYPE html><html><body>storage</body></html>', 'text/html');
    if (ncb.fault === 'data_status_error' && pathname.startsWith('/data/read')) {
      return send(200, { status: 'error', data: [], message: 'replica lag' });
    }

    if (pathname.startsWith('/data/read/')) {
      if (!ncb.rows[table]) return fail(404, `unknown table ${table}`);
      ncb.counts.read = (ncb.counts.read || 0) + 1;
      events.push(`read:${table}`);
      if (table === 'ai_quota_reservation' && ncb.hideReservationReads > 0) {
        ncb.hideReservationReads -= 1;
        return ok([]);
      }
      let rows = ncb.rows[table].filter((row) => Object.entries(query).every(([key, value]) =>
        key === 'Instance' || String(row[key]) === String(value)));
      if (ncb.fault === 'usage_duplicate' && table === 'ai_quota_usage') {
        rows = [...rows, ...rows.map((r) => ({ ...r, id: r.id + 900 }))];
      }
      if (ncb.fault === 'usage_malformed' && table === 'ai_quota_usage') rows = rows.map((r) => ({ ...r, calls_used: 'many' }));
      if (ncb.fault === 'usage_unaddressable' && table === 'ai_quota_usage') rows = rows.map(({ id, ...rest }) => rest);
      if (ncb.fault === 'config_missing' && table === 'ai_quota_config') rows = [];
      if (ncb.fault === 'config_duplicate' && table === 'ai_quota_config') {
        rows = [...rows, ...rows.map((r) => ({ ...r, id: r.id + 900 }))];
      }
      if (ncb.fault === 'config_malformed_flag' && table === 'ai_quota_config') rows = rows.map((r) => ({ ...r, quota_enabled: 'yes' }));
      if (ncb.fault === 'config_malformed_limit' && table === 'ai_quota_config') rows = rows.map((r) => ({ ...r, default_call_limit: -3 }));
      if (ncb.fault === 'config_unsupported_period' && table === 'ai_quota_config') rows = rows.map((r) => ({ ...r, period_type: 'weekly' }));
      if (ncb.fault === 'override_duplicate' && table === 'ai_quota_user_override') {
        rows = [...rows, ...rows.map((r) => ({ ...r, id: r.id + 900 }))];
      }
      if (ncb.fault === 'override_malformed' && table === 'ai_quota_user_override') rows = rows.map((r) => ({ ...r, enabled: null }));
      // The authoritative source lookup under stress: a storage error, and a doubled
      // row. Both must fall toward BILLING, so these are what prove the fail-closed
      // direction is real and not a comment.
      if (ncb.fault === 'settings_read_fail' && table === 'user_settings') return fail(500, 'storage unavailable');
      if (ncb.fault === 'settings_duplicate' && table === 'user_settings') {
        rows = [...rows, ...rows.map((r) => ({ ...r, id: r.id + 900 }))];
      }
      return ok(rows);
    }

    if (pathname.startsWith('/data/create/')) {
      if (!ncb.rows[table]) return fail(404, `unknown table ${table}`);
      if (ncb.fault === 'create_usage_fail' && table === 'ai_quota_usage') return fail(500, 'write rejected');
      if (ncb.fault === 'create_reservation_fail' && table === 'ai_quota_reservation') return fail(500, 'write rejected');
      if (table === 'ai_quota_reservation') {
        const clash = ncb.rows.ai_quota_reservation.some((r) => r.user_id === body.user_id
          && r.period_key === body.period_key && r.decision_key === body.decision_key);
        // The UNIQUE index: a duplicate claim is refused, and the row that won exists.
        if (clash) return fail(409, 'duplicate key on uk_reservation');
      }
      const row = { id: ncb.nextId[table]++, ...body };
      ncb.rows[table].push(row);
      ncb.counts.create = (ncb.counts.create || 0) + 1;
      events.push(`create:${table}`);
      return send(200, { status: 'success', data: [row] });
    }

    if (pathname.startsWith('/data/update/')) {
      const rows = ncb.rows[table];
      if (!rows) return fail(404, `unknown table ${table}`);
      if (ncb.fault === 'update_usage_fail' && table === 'ai_quota_usage') return fail(500, 'write rejected');
      if (ncb.fault === 'update_config_fail' && table === 'ai_quota_config') return fail(500, 'write rejected');
      // The legacy-repair fail-closed branch is only testable if a credential update can be
      // refused — and the row must then be left exactly as it was, which is why this fails
      // before `Object.assign` rather than after.
      if (ncb.fault === 'credential_update_fail' && table === 'ai_provider_credentials_1770000000') return fail(500, 'write rejected');
      const target = rows.find((r) => String(r.id) === String(rowId));
      if (!target) return fail(404, 'no such row');
      // config_no_persist: the write is ACKNOWLEDGED and then dropped. The only defence
      // against it is the read-back after the update, which is exactly what this proves.
      if (ncb.fault !== 'config_no_persist') Object.assign(target, body);
      ncb.counts.update = (ncb.counts.update || 0) + 1;
      events.push(`update:${table}`);
      return send(200, { status: 'success', data: [target] });
    }

    if (pathname.startsWith('/data/delete/')) {
      if (ncb.fault === 'delete_reservation_fail' && table === 'ai_quota_reservation') return fail(500, 'delete rejected');
      const before = ncb.rows[table]?.length ?? 0;
      ncb.rows[table] = (ncb.rows[table] || []).filter((r) => String(r.id) !== String(rowId));
      // Nothing removed is a 404 from a real store, and the release path has to be able to
      // tell "already gone" from "the delete did not work" — so the mock must not flatter it.
      if ((ncb.rows[table]?.length ?? 0) === before) return fail(404, 'no such row');
      ncb.counts.delete = (ncb.counts.delete || 0) + 1;
      events.push(`delete:${table}`);
      return send(200, { status: 'success', data: [] });
    }
    return fail(404, 'no such data route');
  });
});
await new Promise((resolve) => ncbServer.listen(0, '127.0.0.1', resolve));
const NCB_BASE = `http://127.0.0.1:${ncbServer.address().port}`;

// ── store helpers ──────────────────────────────────────────────────────────
const sqlDate = (d = new Date()) => d.toISOString().replace('T', ' ').slice(0, 19);
const seed = () => {
  ncb.rows.ai_quota_config = [{
    id: ncb.nextId.ai_quota_config++, quota_enabled: 1, default_call_limit: DEFAULT_LIMIT,
    period_type: 'monthly', updated_at: sqlDate()
  }];
  ncb.rows.ai_quota_user_override = [];
  ncb.rows.ai_quota_usage = [];
  ncb.rows.ai_quota_reservation = [];
  // Every seeded account starts on System AI, which is the app's own default and the
  // conservative answer: the pre-existing charging checks keep testing a billed path,
  // and an exemption is always an explicit choice made in this file.
  ncb.rows.user_settings = [
    { id: ncb.nextId.user_settings++, user_id: 101, ai_source: 'system' },
    { id: ncb.nextId.user_settings++, user_id: 202, ai_source: 'system' },
    { id: ncb.nextId.user_settings++, user_id: 204, ai_source: 'system' },
    { id: ncb.nextId.user_settings++, user_id: 900, ai_source: 'system' }
  ];
  ncb.fault = null;
  ncb.faultHits = {};
  ncb.hideReservationReads = 0;
  ncb.requests.length = 0;
  ncb.counts = {};
  events.length = 0;
  mod.resetQuotaProcessLedger();
  // The source cache is process state. Left warm, it would make a "the switch
  // propagated" check pass while reading a stale answer, so every scenario starts cold.
  mod.resetAiSourceCache();
};
// Set an account's AUTHORITATIVE source, as the app's own settings save would.
// `null` removes the row entirely, which is the "never opened Settings" case.
const setSource = (userId, value) => {
  const existing = ncb.rows.user_settings.find((r) => String(r.user_id) === String(userId));
  if (value === null) {
    ncb.rows.user_settings = ncb.rows.user_settings.filter((r) => String(r.user_id) !== String(userId));
    mod.resetAiSourceCache(userId);
    return null;
  }
  if (existing) existing.ai_source = value;
  else ncb.rows.user_settings.push({ id: ncb.nextId.user_settings++, user_id: userId, ai_source: value });
  mod.resetAiSourceCache(userId);
  return existing || ncb.rows.user_settings.find((r) => String(r.user_id) === String(userId));
};
const sourceReads = (userId) => ncb.requests.filter((q) => q.pathname === `/data/read/user_settings`
  && String(q.query.user_id) === String(userId));
const overrideRow = (userId) => ncb.rows.ai_quota_user_override.find((r) => String(r.user_id) === String(userId));
const usageRow = (userId) => ncb.rows.ai_quota_usage.find((r) => String(r.user_id) === String(userId) && r.period_key === PERIOD);
const setUsage = (userId, callsUsed, appliedLimit = DEFAULT_LIMIT) => {
  const existing = usageRow(userId);
  if (existing) existing.calls_used = callsUsed;
  else ncb.rows.ai_quota_usage.push({
    id: ncb.nextId.ai_quota_usage++, user_id: userId, period_key: PERIOD,
    calls_used: callsUsed, applied_limit: appliedLimit, created_at: sqlDate(), updated_at: sqlDate()
  });
  return existing || usageRow(userId);
};
const claim = (userId, decisionKey) => ncb.rows.ai_quota_reservation.find((r) => String(r.user_id) === String(userId) && r.decision_key === decisionKey);
const dataCalls = () => ncb.requests.filter((q) => q.pathname.startsWith('/data/'));

// ── mocked provider, and a refusal of anything else that is not loopback ────
const realFetch = globalThis.fetch;
global.fetch = async (url, opts = {}) => {
  const u = String(url);
  // Recorded for the "which machines did this run actually talk to" check: a second quota
  // backend cannot be added to the source without showing up here as an unexpected host.
  world.outboundUrls.push(u);
  if (u.includes('dashscope.aliyuncs.com') || u.includes('api.openai.com')) {
    world.providerCalls++;
    events.push('provider');
    const headers = opts.headers || {};
    const providerAuth = String(headers.Authorization || headers.authorization || '');
    let sentBody = null;
    try { sentBody = JSON.parse(opts.body); } catch { sentBody = opts.body; }
    world.providerRequests.push({ url: u, auth: providerAuth, body: sentBody, raw: String(opts.body || ''), headers });
    return new Response(JSON.stringify({
      choices: [{ message: { role: 'assistant', content: 'P7N' } }],
      usage: { prompt_tokens: 11, completion_tokens: 5, total_tokens: 16 }
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  }
  if (u.startsWith('http://127.0.0.1:') || u.startsWith('http://localhost:')) return realFetch(u, opts);
  throw new Error(`harness refused an unexpected outbound request to ${u}`);
};

// Logs are captured so "a decision key never reaches a log line" is an observation about
// this run rather than a reading of the source. realLog survives for the report itself.
const logs = [];
const realLog = console.log.bind(console);
for (const m of ['log', 'info', 'warn', 'error']) {
  console[m] = (...a) => { logs.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')); };
}

process.env.NODESEND_PRIVATE_KEY_B64 = PRIV_B64;
process.env.BRIDGE_API_KEY = 'server-only-bridge-key';
process.env.NCB_PROXY_BASE = NCB_BASE;
process.env.NCB_INSTANCE = '55954_bridgemind';
// Low enough that data_hang proves a timeout, high enough to be a real bound.
process.env.NODESEND_NCB_TIMEOUT_MS = '600';
process.env.TRICKSTER_BID_URL = 'http://127.0.0.1:1';
process.env.TRICKSTER_PLAY_URL = 'http://127.0.0.1:1';
// The retired external quota service: deliberately never set, in EITHER variant. If any
// remaining code path read it, the unconfigured state would answer 503 and the charging
// checks below would go red — which is the point.
delete process.env.BRIDGEMIND_QUOTA_URL;
if (VARIANT === 'process-only') process.env.AI_QUOTA_RESERVATION_TABLE = '';
const CHAT_PORT = VARIANT === 'process-only' ? 4111 : 4110;
process.env.PORT = String(CHAT_PORT);

const mod = await import(pathToFileURL(path.join(ROOT, 'bridge.js')).href + `?variant=${VARIANT}`);
const { app, NODESEND_VERSION } = mod;
await new Promise((r) => app.listen(CHAT_PORT, '127.0.0.1', r));
const B = `http://127.0.0.1:${CHAT_PORT}`;
const bodyOf = async (res) => { try { return await res.json(); } catch { return {}; } };
const CHAT = (tok, extra = {}, headers = {}) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: `Bearer ${tok}` } : {}), ...headers },
  body: JSON.stringify({
    provider: 'alibaba',
    config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', encryptedApiKey: enc(PROVIDER_SECRET) },
    model: 'qwen3.8-flash',
    messages: [{ role: 'user', content: 'hi' }],
    ...extra
  })
});
const AUTH = (tok) => ({ headers: { Authorization: `Bearer ${tok}` } });
const PUTJSON = (tok, obj, raw) => ({
  method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok}` },
  body: raw ?? JSON.stringify(obj)
});
const KEY = (k) => ({ 'x-ai-decision-key': k });

const results = [];
const check = (name, pass, detail = '') => {
  results.push({ name, pass: !!pass, detail: String(typeof pass === 'object' ? JSON.stringify(pass) : detail).slice(0, 240) });
};
let r, j, pc;

// ── 1. the authority's own reported state ──────────────────────────────────
seed();
check('T-A version declares NodeSend as the quota authority at v9',
  NODESEND_VERSION === 'bridge-nodesend-quota-v9', NODESEND_VERSION);
check('the ledger mode matches the configuration',
  VARIANT === 'process-only' ? mod.QUOTA_IDEMPOTENCY_MODE === 'process-only' && mod.quotaLedgerDurable === false
    : mod.QUOTA_IDEMPOTENCY_MODE === 'durable' && mod.quotaLedgerDurable === true,
  `${mod.QUOTA_IDEMPOTENCY_MODE} / durable=${mod.quotaLedgerDurable}`);
const rootInfo = await bodyOf(await fetch(`${B}/`));
check('T25 root reports authority nodesend, storage ncb, the single-replica invariant',
  rootInfo.quota?.authority === 'nodesend' && rootInfo.quota?.storage === 'ncb'
  && rootInfo.quota?.replicas === 'exactly-one-quota-service-replica'
  && rootInfo.quota?.note === 'multi-replica quota counting unsupported'
  && rootInfo.quota?.idempotency === (VARIANT === 'process-only' ? 'process-only' : 'durable'),
  JSON.stringify(rootInfo.quota));
const health0 = await bodyOf(await fetch(`${B}/health`));
check('T25 health says nodesend/ncb in the flat fields an operator greps for',
  health0.quotaAuthority === 'nodesend' && health0.quotaStorage === 'ncb'
  && health0.quotaIdempotency === (VARIANT === 'process-only' ? 'process-only' : 'durable')
  && health0.quotaReplicas === 'exactly-one-quota-service-replica'
  && health0.quotaMultiReplica === 'unsupported' && health0.status === 'healthy',
  JSON.stringify({ a: health0.quotaAuthority, s: health0.quotaStorage, i: health0.quotaIdempotency }));
// The Trickster block legitimately echoes its own upstream hosts (public by nature), which
// on this harness is a loopback decoy — so the check names the thing it actually cares
// about: no quota table and no storage endpoint on a route anyone can call.
check('the public routes name no quota table and no storage endpoint',
  !JSON.stringify(rootInfo).includes('ai_quota') && !JSON.stringify(health0).includes('ai_quota')
  && !JSON.stringify(health0).includes(NCB_BASE) && !JSON.stringify(rootInfo).includes(NCB_BASE),
  Object.keys(rootInfo).join(','));
check('T24 the retired remote-adapter surface is gone from the module',
  mod.bridgemindQuotaEndpoint === undefined && mod.bridgemindQuotaConfigured === undefined
  && mod.quotaServiceState === undefined && mod.sanitizeQuotaDecision === undefined
  && mod.isQuotaCount === undefined && mod.QUOTA_PUBLIC_FIELDS === undefined
  && mod.QUOTA_RESERVE_ROUTE === undefined && mod.QUOTA_STATUS_ROUTE === undefined
  && mod.QUOTA_CONFIG_ROUTE === undefined,
  Object.keys(mod).filter((k) => /bridgemind|sanitizeQuota|isQuotaCount|QUOTA_PUBLIC|_ROUTE/.test(k)).join(','));

if (VARIANT === 'process-only') {
  // ── the fallback branch: same decisions, weaker durability, said out loud ──
  check('P1 process-only mode still deduplicates within the process', await (async () => {
    setUsage('101', 0);
    const first = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('proc-key-1')));
    const second = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('proc-key-1')));
    const used = usageRow('101')?.calls_used;
    return first.status === 200 && second.status === 200 && used === 1 && mod.quotaProcessLedgerSize() === 1;
  })(), `used=${usageRow('101')?.calls_used} ledgerSize=${mod.quotaProcessLedgerSize()}`);
  check('P2 process-only mode writes no reservation rows',
    ncb.rows.ai_quota_reservation.length === 0 && !dataCalls().some((q) => q.table === 'ai_quota_reservation'),
    dataCalls().map((q) => `${q.method} ${q.pathname}`).join(' | '));
  check('P3 the process ledger is bounded, so a long-lived relay cannot grow without limit',
    await (async () => {
      mod.resetQuotaProcessLedger();
      // Past the cap: the oldest entry is evicted, so the map size stops at the limit while
      // the newest key is still deduplicated. An unbounded Map here is a memory leak that
      // only shows up after a month of traffic, which is exactly when nobody is looking.
      const keys = [];
      for (let i = 0; i < mod.QUOTA_PROCESS_LEDGER_LIMIT + 50; i++) keys.push(`k-${i}`);
      for (const key of keys) await mod.claimReservation({}, '101', PERIOD, key);
      const sizeAfter = mod.quotaProcessLedgerSize();
      const newestStillKnown = (await mod.findReservation({}, '101', PERIOD, keys[keys.length - 1])).found === true;
      const oldestEvicted = (await mod.findReservation({}, '101', PERIOD, keys[0])).found === false;
      return sizeAfter === mod.QUOTA_PROCESS_LEDGER_LIMIT && newestStillKnown && oldestEvicted;
    })(), `size=${mod.quotaProcessLedgerSize()} limit=${mod.QUOTA_PROCESS_LEDGER_LIMIT}`);
  check('P4 a restart of the process forgets the keys, which is the documented gap',
    (() => {
      mod.resetQuotaProcessLedger();
      return mod.quotaProcessLedgerSize() === 0;
    })(), `size=${mod.quotaProcessLedgerSize()}`);
  console.log = realLog;
  const out = results.map((x) => `${x.pass ? 'PASS' : 'FAIL'}  ${x.name}${x.detail ? '   [' + x.detail + ']' : ''}`).join('\n');
  const failed = results.filter((x) => !x.pass).length;
  console.log(JSON.stringify({ variant: 'process-only', passed: results.length - failed, total: results.length, failed, out }));
  process.exit(failed ? 1 : 0);
}

// ── 2. identity: the session bearer, and nothing else ──────────────────────
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT(null));
j = await bodyOf(r);
check('no session -> 401, no storage call at all, provider untouched',
  r.status === 401 && dataCalls().length === 0 && world.providerCalls === pc, `status=${r.status} dataCalls=${dataCalls().length}`);
r = await fetch(`${B}/ai/chat`, CHAT('tok-nope'));
check('invalid session -> 401 and no reservation is taken', r.status === 401 && dataCalls().length === 0, `status=${r.status}`);
r = await fetch(`${B}/ai/chat`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'server-only-bridge-key' },
  body: JSON.stringify({ provider: 'alibaba', messages: [{ role: 'user', content: 'hi' }] })
});
check('the relay key cannot unlock an AI endpoint instead of a session', r.status === 401, `status=${r.status}`);
r = await fetch(`${B}/ai/quota`);
check('GET /ai/quota requires a session', r.status === 401, `status=${r.status}`);

seed();
setUsage('101', 0);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
j = await bodyOf(r);
check('valid session accepted with no x-api-key', r.status === 200, `status=${r.status} ${JSON.stringify(j).slice(0, 80)}`);
check('a keyed request carries no key here, so it is charged plainly',
  usageRow('101')?.calls_used === 1, `calls_used=${usageRow('101')?.calls_used}`);

r = await fetch(`${B}/ai/quota?user_id=202&period_key=1999-01`, AUTH('tok-a'));
j = await bodyOf(r);
check('T-identity a query-string user_id cannot ask about another user',
  r.status === 200 && j.used === 1 && j.limit === DEFAULT_LIMIT, JSON.stringify({ s: r.status, u: j.used, l: j.limit }));
const beforeSpoof = ncb.requests.length;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', { user_id: 999, userId: 999, period_key: '1999-01', email: 'someone@example.com' }));
check('T-identity a body user_id never reaches the store',
  r.status === 200 && ncb.requests.slice(beforeSpoof).every((q) => !/999|1999-01|someone@example/.test(q.pathname + q.raw + JSON.stringify(q.query))),
  ncb.requests.slice(beforeSpoof).map((q) => q.pathname).join(' | '));
check('T-identity identity travels only as the caller bearer',
  dataCalls().every((q) => q.auth === 'Bearer tok-a') && dataCalls().length > 0,
  [...new Set(dataCalls().map((q) => q.auth))].join(','));
check('no request ever names a user_id in a body to the store',
  !dataCalls().some((q) => q.method === 'POST' && q.pathname.startsWith('/data/create/') && /999/.test(JSON.stringify(q.body))), '');

// ── 3. charging and idempotency (T1-T8, T15, T16) ──────────────────────────
// No counter row is seeded for the first scenarios on purpose: the state "this user has not
// used the month yet" is the create path, and it has to be the one that is actually taken.
seed();
pc = world.providerCalls;
const chargeOnce = await (async () => {
  const res = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('decision-1')));
  return { status: res.status, header: res.headers.get('x-quota-reservation'), body: await bodyOf(res) };
})();
check('T1 first decision charges once',
  chargeOnce.status === 200 && usageRow('101')?.calls_used === 1 && chargeOnce.header === 'created',
  JSON.stringify({ s: chargeOnce.status, used: usageRow('101')?.calls_used, h: chargeOnce.header }));
// No row was seeded, so this is the first charge of the period and must be a CREATE — the
// distinction matters because a create and an update are two different failure modes (T12
// and T13) and silently landing on the wrong one would leave half the ledger untested.
check('T1 the charge is a real create of the counter row, not only a header',
  dataCalls().some((q) => q.pathname === '/data/create/ai_quota_usage' && q.body?.calls_used === 1),
  dataCalls().map((q) => `${q.method} ${q.pathname}`).join(' | '));

const retry = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('decision-1')));
const retryHeader = retry.headers.get('x-quota-reservation');
check('T2 a retry of the same decision does not charge again',
  retry.status === 200 && usageRow('101')?.calls_used === 1 && retryHeader === 'reused',
  JSON.stringify({ s: retry.status, used: usageRow('101')?.calls_used, h: retryHeader }));
check('T2 a reused decision still reaches the provider (dedupe is not a refusal)',
  world.providerCalls === pc + 2, `providerCalls=${world.providerCalls}`);

seed();
setUsage('101', 0);
pc = world.providerCalls;
for (let i = 0; i < 10; i++) {
  const res = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('ten-retries')));
  if (res.status !== 200) break;
}
check('T3 ten retries of one decision cost exactly one call',
  usageRow('101')?.calls_used === 1 && world.providerCalls === pc + 10,
  `used=${usageRow('101')?.calls_used} providerCalls=${world.providerCalls - pc}`);
check('T3 only one reservation row exists for the ten attempts',
  ncb.rows.ai_quota_reservation.filter((row) => row.decision_key === 'ten-retries').length === 1,
  `rows=${ncb.rows.ai_quota_reservation.length}`);
check('T3 the store saw one claim and one counter write, not ten',
  ncb.requests.filter((q) => q.pathname === '/data/create/ai_quota_reservation').length === 1
  && ncb.requests.filter((q) => /\/data\/(create|update)\/ai_quota_usage/.test(q.pathname)).length === 1,
  ncb.requests.map((q) => `${q.method} ${q.pathname}`).join(' | '));

r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('decision-2')));
check('T4 a second decision costs a second call', r.status === 200 && usageRow('101')?.calls_used === 2,
  `used=${usageRow('101')?.calls_used}`);

seed();
setUsage('101', 0);
setUsage('202', 0);
const sharedKeyA = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('cross-user')));
const sharedKeyB = await fetch(`${B}/ai/chat`, CHAT('tok-b', {}, KEY('cross-user')));
check('T5 one decision key, two users: each is charged once, no sharing',
  sharedKeyA.status === 200 && sharedKeyB.status === 200
  && usageRow('101')?.calls_used === 1 && usageRow('202')?.calls_used === 1,
  JSON.stringify({ a: usageRow('101')?.calls_used, b: usageRow('202')?.calls_used }));
check('T5 the key is scoped per user in storage, never global',
  ncb.rows.ai_quota_reservation.filter((row) => row.decision_key === 'cross-user').length === 2
  && new Set(ncb.rows.ai_quota_reservation.filter((row) => row.decision_key === 'cross-user').map((row) => String(row.user_id))).size === 2,
  JSON.stringify(ncb.rows.ai_quota_reservation.map((x) => `${x.user_id}/${x.decision_key}`)));
check('T5 both claims carried the respective caller bearer, never a shared key',
  ncb.requests.filter((q) => q.pathname === '/data/create/ai_quota_reservation').map((q) => q.auth).join(',') === 'Bearer tok-a,Bearer tok-b',
  ncb.requests.filter((q) => q.pathname === '/data/create/ai_quota_reservation').map((q) => q.auth).join(','));

// T6: run up to the cap, keyless so each call is a new decision.
seed();
setUsage('101', 0);
const ladderStart = world.providerCalls;
const ladder = [];
for (let i = 0; i < 5; i++) {
  const res = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
  const body = await bodyOf(res);
  ladder.push({ s: res.status, used: body.quota?.used, remaining: body.quota?.remaining, reason: body.status });
}
check('T6 the cap is reached exactly, on the call that crosses it',
  ladder.slice(0, 3).every((x) => x.s === 200) && ladder[3].s === 429 && ladder[3].reason === 'quota_exhausted'
  && ladder[3].used === DEFAULT_LIMIT && usageRow('101')?.calls_used === DEFAULT_LIMIT,
  JSON.stringify(ladder));
check('T6 the denied call is not counted and not dispatched',
  world.providerCalls - ladderStart === DEFAULT_LIMIT && usageRow('101')?.calls_used === DEFAULT_LIMIT,
  `providerDelta=${world.providerCalls - ladderStart} used=${usageRow('101')?.calls_used}`);
check('T6 exhaustion reports the real figures, never nulls and never an invented headroom',
  ladder[3].used === 3 && ladder[3].remaining === 0, JSON.stringify(ladder[3]));

// T7/T8: at the cap, an already-billed decision is still honoured, a new one is refused.
const atLimitKey = 'billed-at-limit';
seed();
setUsage('101', DEFAULT_LIMIT);
ncb.rows.ai_quota_reservation.push({
  id: ncb.nextId.ai_quota_reservation++, user_id: '101', period_key: PERIOD,
  decision_key: atLimitKey, created_at: sqlDate()
});
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY(atLimitKey)));
const reusedAtLimit = r.headers.get('x-quota-reservation');
check('T7 a retry of an already-billed decision is allowed at the cap',
  r.status === 200 && reusedAtLimit === 'reused' && world.providerCalls === pc + 1,
  JSON.stringify({ s: r.status, h: reusedAtLimit, provider: world.providerCalls - pc }));
check('T7 the reuse reads the counter, it never writes it',
  usageRow('101')?.calls_used === DEFAULT_LIMIT
  && !ncb.requests.some((q) => q.pathname.startsWith('/data/update/ai_quota_usage') || q.pathname.startsWith('/data/create/ai_quota_usage')),
  ncb.requests.map((q) => `${q.method} ${q.pathname}`).join(' | '));
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('brand-new-at-limit')));
j = await bodyOf(r);
check('T8 a NEW decision at the cap is denied and the provider is not called',
  r.status === 429 && j.status === 'quota_exhausted' && world.providerCalls === pc,
  JSON.stringify({ s: r.status, provider: world.providerCalls - pc }));
check('T8 the denial that was not charged leaves no claim behind (claim released)',
  usageRow('101')?.calls_used === DEFAULT_LIMIT && claim('101', 'brand-new-at-limit') === undefined
  && ncb.requests.some((q) => q.pathname.startsWith('/data/delete/ai_quota_reservation')),
  JSON.stringify({ reservations: ncb.rows.ai_quota_reservation.map((x) => x.decision_key) }));

// T15: no key, no ledger, normal charge.
seed();
setUsage('101', 0);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
const keylessHeader = r.headers.get('x-quota-reservation');
check('T15 a keyless request is charged normally and reaches the provider',
  r.status === 200 && usageRow('101')?.calls_used === 1 && world.providerCalls > 0,
  JSON.stringify({ s: r.status, used: usageRow('101')?.calls_used }));
check('T15 a keyless request touches the reservation table not at all',
  !dataCalls().some((q) => q.table === 'ai_quota_reservation'),
  dataCalls().map((q) => q.pathname).join(' | '));
check('T15 a keyless charge is still labelled honestly on the outcome header',
  keylessHeader === 'charged', String(keylessHeader));

// T16: a malformed key must not become a universal free pass. Every value here is refused
// by the key rule, so each of these calls must be billed as its own new decision — a client
// that stringifies a missing value into "undefined" must not get one shared free allowance.
seed();
setUsage('101', 0);
// 13 hostile keys must each be billed, so the ceiling has to be above 13 or the cap — not
// the key rule — decides the outcome of the later iterations.
ncb.rows.ai_quota_config[0].default_call_limit = 100;
const hostile = ['undefined', 'null', 'NaN', '{}', '[object Object]', 'string', '', '   ',
  'x'.repeat(200), 'a'.repeat(129), '$(rm -rf /)', "quote'a", '-leading-dash'];
const hostileStatuses = [];
for (const value of hostile) {
  const res = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY(value)));
  hostileStatuses.push(res.status);
}
check('T16 a malformed decision key is charged as a new decision, never deduplicated',
  usageRow('101')?.calls_used === hostile.length,
  `used=${usageRow('101')?.calls_used} of ${hostile.length} statuses=${[...new Set(hostileStatuses)].join(',')}`);
check('T16 no refused key is ever recorded as a claim',
  ncb.rows.ai_quota_reservation.length === 0,
  JSON.stringify(ncb.rows.ai_quota_reservation.map((x) => x.decision_key)));
check('T16 dropping a key costs a dedupe and buys neither a free call nor a refusal',
  hostileStatuses.every((s) => s === 200), hostileStatuses.join(','));
check('sanitizeDecisionKey accepts the documented grammar and refuses the rest',
  mod.sanitizeDecisionKey('abc-123') === 'abc-123' && mod.sanitizeDecisionKey('a b:c+d#e-f') === 'a b:c+d#e-f'
  && mod.sanitizeDecisionKey('undefined') === null && mod.sanitizeDecisionKey('null') === null
  && mod.sanitizeDecisionKey('NaN') === null && mod.sanitizeDecisionKey('{}') === null
  && mod.sanitizeDecisionKey('[object Object]') === null && mod.sanitizeDecisionKey('') === null
  && mod.sanitizeDecisionKey('   ') === null && mod.sanitizeDecisionKey('x'.repeat(129)) === null
  && mod.sanitizeDecisionKey('-leading-dash') === null && mod.sanitizeDecisionKey('quote\'a') === null
  && mod.sanitizeDecisionKey('$(rm)') === null && mod.sanitizeDecisionKey(null) === null
  && mod.sanitizeDecisionKey(42) === null && mod.sanitizeDecisionKey(undefined) === null,
  JSON.stringify(['-leading-dash', 'quote\'a', '$(rm)'].map((v) => mod.sanitizeDecisionKey(v))));
check('the key length bound is a stated constant, not an accident',
  mod.DECISION_KEY_MAX_LENGTH === 128 && mod.DECISION_KEY_HEADER === 'x-ai-decision-key', '');

// ── 4. the reservation ledger's failure paths (T9-T14) ─────────────────────
// T9: lost race. Our first read sees nothing, the create is refused by the UNIQUE index
// because another writer won, the re-read finds the row: REUSED, and the counter is never
// touched. This is the case a naive implementation turns into a double charge.
seed();
setUsage('101', 1);
ncb.rows.ai_quota_reservation.push({
  id: ncb.nextId.ai_quota_reservation++, user_id: '101', period_key: PERIOD,
  decision_key: 'lost-race', created_at: sqlDate()
});
ncb.hideReservationReads = 1;
ncb.fault = null;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('lost-race')));
j = await bodyOf(r);
check('T9 a create refused by the unique index is re-read and answered as REUSED',
  r.status === 200 && r.headers.get('x-quota-reservation') === 'reused' && usageRow('101')?.calls_used === 1,
  JSON.stringify({ s: r.status, h: r.headers.get('x-quota-reservation'), used: usageRow('101')?.calls_used }));
check('T9 the exact tuple was re-read after the refusal',
  dataCalls().filter((q) => q.pathname === '/data/read/ai_quota_reservation').length >= 2
  && dataCalls().some((q) => q.pathname === '/data/create/ai_quota_reservation'),
  dataCalls().map((q) => `${q.method} ${q.pathname}`).join(' | '));
check('T9 no counter write happened on the refused create',
  !dataCalls().some((q) => q.pathname.startsWith('/data/create/ai_quota_usage') || q.pathname.startsWith('/data/update/ai_quota_usage')),
  dataCalls().map((q) => q.pathname).join(' | '));

// T10: the ledger is down. 503, and the counter must not be touched: a charge without a
// recorded claim is the double-bill this whole ordering exists to prevent.
seed();
setUsage('101', 1);
ncb.fault = 'create_reservation_fail';
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('ledger-down')));
j = await bodyOf(r);
check('T10 a failed claim with no existing row is 503, not a charge',
  r.status === 503 && j.status === 'quota_service_unavailable' && world.providerCalls === pc,
  JSON.stringify({ s: r.status, body: JSON.stringify(j).slice(0, 60) }));
check('T10 the usage counter was not written while the ledger refused',
  usageRow('101')?.calls_used === 1
  && !dataCalls().some((q) => q.pathname.startsWith('/data/create/ai_quota_usage') || q.pathname.startsWith('/data/update/ai_quota_usage')),
  JSON.stringify({ used: usageRow('101')?.calls_used, routes: dataCalls().map((q) => q.pathname).join(',') }));
check('T10 the outage is reported as an outage, never as exhaustion, and with no figures',
  j.status === 'quota_service_unavailable' && j.quota === null, JSON.stringify(j).slice(0, 120));
ncb.fault = null;

// T11 exhausted after a fresh claim -> released.
seed();
setUsage('101', DEFAULT_LIMIT);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('exhausted-release')));
j = await bodyOf(r);
check('T11 exhaustion after a fresh claim releases that claim',
  r.status === 429 && ncb.rows.ai_quota_reservation.length === 0
  && ncb.requests.some((q) => q.pathname.startsWith('/data/delete/ai_quota_reservation')),
  JSON.stringify({ s: r.status, rows: ncb.rows.ai_quota_reservation.length }));
check('T11 the released claim is the one this request made',
  ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage' || q.pathname.startsWith('/data/update/ai_quota_usage')) === false
  && usageRow('101')?.calls_used === DEFAULT_LIMIT, `used=${usageRow('101')?.calls_used}`);

// T12/T13: the charge fails after the claim -> released, and the failure is the answer.
// No usage row at all, so this is the first-charge CREATE path rather than the increment.
seed();
ncb.fault = 'create_usage_fail';
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('create-charge-fails')));
j = await bodyOf(r);
check('T12 a failed first-charge write is 503 and the claim is released',
  r.status === 503 && usageRow('101') === undefined && ncb.rows.ai_quota_reservation.length === 0,
  JSON.stringify({ s: r.status, rows: ncb.rows.ai_quota_reservation.map((x) => x.decision_key) }));
check('T12 the refusal is the storage failure, not a fabricated allowance, and no provider call',
  j.status === 'quota_service_unavailable' && j.quota === null && world.providerCalls === pc,
  JSON.stringify(j).slice(0, 100));
check('T12 the released claim was deleted, not left recorded as prepaid',
  ncb.requests.some((q) => q.pathname.startsWith('/data/delete/ai_quota_reservation')), '');
ncb.fault = null;

seed();
setUsage('101', 1);
ncb.fault = 'update_usage_fail';
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('update-charge-fails')));
check('T13 a failed increment write is 503 and the claim is released',
  r.status === 503 && usageRow('101')?.calls_used === 1 && ncb.rows.ai_quota_reservation.length === 0,
  JSON.stringify({ s: r.status, used: usageRow('101')?.calls_used, rows: ncb.rows.ai_quota_reservation.length }));
check('T13 the provider is not dispatched on the failed charge',
  world.providerCalls === pc, `delta=${world.providerCalls - pc}`);
ncb.fault = null;

// T14: release itself fails. The caller must still get the real failure, and the fact that
// a claim survived an unbilled decision must be in the log — never a silent success.
seed();
setUsage('101', DEFAULT_LIMIT);
logs.length = 0;
ncb.fault = 'delete_reservation_fail';
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('release-refused')));
j = await bodyOf(r);
const releaseLog = logs.find((l) => /claim_release_refused/.test(l)) || '';
check('T14 a failed release does not pretend success',
  r.status === 429 && j.status === 'quota_exhausted', JSON.stringify({ s: r.status, body: JSON.stringify(j).slice(0, 60) }));
check('T14 the underlying failure is what the caller is told, not a made-up 200',
  r.status !== 200 && !('reservation' in j), JSON.stringify(Object.keys(j)));
check('T14 the release failure is logged explicitly', /quota_claim_release_refused/.test(releaseLog), releaseLog.slice(0, 120));
check('T14 the release-failure log names a reason and nothing else',
  /reason/.test(releaseLog) && !/ai_quota|Bearer|tok-a|release-refused/.test(releaseLog), releaseLog.slice(0, 160));
ncb.fault = null;
check('T14 the abandoned claim is visible in storage for cleanup, and is not silently retried as free',
  ncb.rows.ai_quota_reservation.filter((x) => x.decision_key === 'release-refused').length === 1, '');

// ── 5. fail closed on every unusable storage answer ────────────────────────
// Each of these is a shape the real NCB surface can produce. None of them may become a
// guessed allowance: "we could not read the counter" and "you have 100 calls left" are
// opposite answers, and only one of them is safe to invent.
const readFaults = [
  ['config_missing', 'no configuration row at all'],
  ['config_duplicate', 'two configuration rows'],
  ['config_malformed_flag', 'a quota_enabled that is neither flag nor boolean'],
  ['config_malformed_limit', 'a negative default_call_limit'],
  ['config_unsupported_period', 'a period_type this build does not implement'],
  ['usage_duplicate', 'two usage rows for one user and period'],
  ['usage_malformed', 'a calls_used that is not a count'],
  ['usage_unaddressable', 'a usage row with no id to update'],
  ['override_duplicate', 'two override rows for one user'],
  ['override_malformed', 'an override enabled flag that is neither'],
  ['data_status_error', 'a 200 whose envelope says status:"error"'],
  ['data_html', 'an HTML page where JSON was expected'],
  ['data_hang', 'a storage call that never answers (timeout)']
];
for (const [fault, label] of readFaults) {
  seed();
  setUsage('101', 1);
  // A fault that duplicates or mangles override rows can only fire if there is an override
  // row to mangle — with none stored, "two rows" is still zero rows and the check would pass
  // while measuring nothing. Seeded here; the knob's effect is proven by section 5b below.
  if (fault.startsWith('override_')) ncb.rows.ai_quota_user_override.push({ id: 5100, user_id: '101', enabled: 1, call_limit: 4 });
  ncb.fault = fault;
  pc = world.providerCalls;
  r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY(`fault-${fault}`)));
  j = await bodyOf(r);
  check(`${label} -> /ai/chat 503, provider untouched, no charge`,
    r.status === 503 && world.providerCalls === pc && usageRow('101')?.calls_used === 1,
    `status=${r.status} providerDelta=${world.providerCalls - pc} used=${usageRow('101')?.calls_used}`);
  check(`${label} is never reported as exhaustion or as allowed`,
    r.status !== 429 && j.status === 'quota_service_unavailable' && !j.quota, JSON.stringify(j).slice(0, 90));
  const statusRes = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
  const statusBody = await bodyOf(statusRes);
  check(`${label} -> GET /ai/quota 503 with nulls, never 0 of limit`,
    statusRes.status === 503 && statusBody.used === null && statusBody.limit === null
    && statusBody.remaining === null && statusBody.percentage === null,
    JSON.stringify({ s: statusRes.status, used: statusBody.used, limit: statusBody.limit }));
  check(`${label} invents no period or reset date on a failed read`,
    !('period' in statusBody) || statusBody.period === undefined, Object.keys(statusBody).join(','));
  ncb.fault = null;
}
seed();
setUsage('101', 1);
ncb.fault = 'session_hang';
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('an unreachable session authority is 503, not "signed out"',
  r.status === 503 && (await bodyOf(r)).status === 'session_service_unavailable', `status=${r.status}`);
ncb.fault = null;

// ── 5b. the fault knobs themselves are alive ──────────────────────────────
// A fail-closed test that passes because the injected fault never fired is worse than no
// test: it says "storage corruption is handled" while measuring the happy path. Each knob is
// therefore poked directly against the mock, over the same socket the relay uses, and compared
// with the un-faulted answer.
const readRaw = async (table, qs = '') => {
  const res = await realFetch(`${NCB_BASE}/data/read/${table}?${qs}&Instance=55954_bridgemind`,
    { headers: { Authorization: 'Bearer tok-a' } });
  return res.json();
};
seed();
setUsage('101', 2);
ncb.rows.ai_quota_user_override.push({ id: 5200, user_id: '101', enabled: 1, call_limit: 4 });
const baseline = {
  config: (await readRaw('ai_quota_config')).data.length,
  usage: (await readRaw('ai_quota_usage', `user_id=101&period_key=${PERIOD}`)).data.length,
  override: (await readRaw('ai_quota_user_override', 'user_id=101')).data.length
};
const knobFires = async (fault, table, qs, shape) => {
  ncb.fault = fault;
  const answer = await readRaw(table, qs);
  ncb.fault = null;
  return shape(answer);
};
check('the usage_duplicate knob really returns two rows',
  baseline.usage === 1 && await knobFires('usage_duplicate', 'ai_quota_usage', `user_id=101&period_key=${PERIOD}`, (a) => a.data.length === 2), `baseline=${baseline.usage}`);
check('the usage_malformed knob really returns a non-count',
  await knobFires('usage_malformed', 'ai_quota_usage', `user_id=101&period_key=${PERIOD}`, (a) => a.data[0]?.calls_used === 'many'), '');
check('the usage_unaddressable knob really strips the row id',
  await knobFires('usage_unaddressable', 'ai_quota_usage', `user_id=101&period_key=${PERIOD}`, (a) => a.data[0]?.id === undefined), '');
check('the override_duplicate knob really returns two override rows',
  baseline.override === 1 && await knobFires('override_duplicate', 'ai_quota_user_override', 'user_id=101', (a) => a.data.length === 2), `baseline=${baseline.override}`);
check('the override_malformed knob really returns a neither-nor flag',
  await knobFires('override_malformed', 'ai_quota_user_override', 'user_id=101', (a) => a.data[0]?.enabled === null), '');
check('the config_missing knob really returns no rows',
  baseline.config === 1 && await knobFires('config_missing', 'ai_quota_config', '', (a) => a.data.length === 0), `baseline=${baseline.config}`);
check('the config_duplicate knob really returns two configuration rows',
  await knobFires('config_duplicate', 'ai_quota_config', '', (a) => a.data.length === 2), '');
check('the config_malformed_flag and config_malformed_limit knobs each change the field they name',
  await knobFires('config_malformed_flag', 'ai_quota_config', '', (a) => a.data[0]?.quota_enabled === 'yes')
  && await knobFires('config_malformed_limit', 'ai_quota_config', '', (a) => a.data[0]?.default_call_limit === -3), '');
check('the config_unsupported_period knob really changes period_type',
  await knobFires('config_unsupported_period', 'ai_quota_config', '', (a) => a.data[0]?.period_type === 'weekly'), '');
check('the data_status_error knob really contradicts its own 200',
  await knobFires('data_status_error', 'ai_quota_config', '', (a) => a.status === 'error'), '');
const writeKnob = async (fault, path, method, body) => {
  ncb.fault = fault;
  const res = await realFetch(`${NCB_BASE}${path}`, {
    method, headers: { Authorization: 'Bearer tok-a', 'content-type': 'application/json' }, body: JSON.stringify(body)
  });
  ncb.fault = null;
  return res.status;
};
check('the three write-failure knobs really refuse the write they name',
  await writeKnob('create_usage_fail', '/data/create/ai_quota_usage', 'POST', { user_id: '9', period_key: PERIOD, calls_used: 1, applied_limit: 3 }) >= 500
  && await writeKnob('update_usage_fail', `/data/update/ai_quota_usage/${ncb.rows.ai_quota_usage[0].id}`, 'PUT', { calls_used: 9 }) >= 500
  && await writeKnob('create_reservation_fail', '/data/create/ai_quota_reservation', 'POST', { user_id: '9', period_key: PERIOD, decision_key: 'knob' }) >= 500
  && await writeKnob('delete_reservation_fail', '/data/delete/ai_quota_reservation/1', 'DELETE', undefined) >= 500, '');
check('the unique index is enforced by the mock, not assumed (positive control for T9)',
  await (async () => {
    ncb.rows.ai_quota_reservation.push({ id: 9001, user_id: '101', period_key: PERIOD, decision_key: 'unique-probe', created_at: sqlDate() });
    ncb.fault = null;
    const dupe = await realFetch(`${NCB_BASE}/data/create/ai_quota_reservation`, {
      method: 'POST', headers: { Authorization: 'Bearer tok-a', 'content-type': 'application/json' },
      body: JSON.stringify({ user_id: '101', period_key: PERIOD, decision_key: 'unique-probe', created_at: sqlDate() })
    });
    const other = await realFetch(`${NCB_BASE}/data/create/ai_quota_reservation`, {
      method: 'POST', headers: { Authorization: 'Bearer tok-a', 'content-type': 'application/json' },
      body: JSON.stringify({ user_id: '202', period_key: PERIOD, decision_key: 'unique-probe', created_at: sqlDate() })
    });
    ncb.rows.ai_quota_reservation = ncb.rows.ai_quota_reservation.filter((x) => x.decision_key !== 'unique-probe');
    return dupe.status === 409 && other.status === 200;
  })(), '');
check('the hideReservationReads knob hides exactly the reads asked for, then stops',
  await (async () => {
    ncb.rows.ai_quota_reservation.push({ id: 9002, user_id: '101', period_key: PERIOD, decision_key: 'hidden-probe', created_at: sqlDate() });
    ncb.hideReservationReads = 1;
    const hidden = await readRaw('ai_quota_reservation', 'decision_key=hidden-probe');
    const shown = await readRaw('ai_quota_reservation', 'decision_key=hidden-probe');
    ncb.rows.ai_quota_reservation = ncb.rows.ai_quota_reservation.filter((x) => x.decision_key !== 'hidden-probe');
    // The row exists the whole time — only the answer changes — which is what a lost race
    // looks like from inside this process.
    return hidden.data.length === 0 && shown.data.length === 1;
  })(), '');
check('the view clamps are computed here, not relayed: percentage over 100 is preserved honestly',
  mod.quotaBoundedView(11, 10).remaining === 0 && mod.quotaBoundedView(11, 10).percentage === 110
  && mod.quotaBoundedView(0, 10).percentage === 0, JSON.stringify(mod.quotaBoundedView(11, 10)));

// ── 6. limit precedence: global config -> per-user override -> usage ───────
seed();
setUsage('101', 1);
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
check('with no override row the default limit applies',
  r.status === 200 && (await bodyOf(r)).limit === DEFAULT_LIMIT, `status=${r.status}`);
ncb.rows.ai_quota_user_override.push({ id: 5001, user_id: '101', enabled: 1, call_limit: 5 });
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('an enabled override wins over the default', j.limit === 5, JSON.stringify({ l: j.limit }));
ncb.rows.ai_quota_user_override[0].enabled = 0;
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
check('a disabled override falls back to the default, it is not a zero limit',
  (await bodyOf(r)).limit === DEFAULT_LIMIT, JSON.stringify({ l: (await bodyOf(r)).limit }));
ncb.rows.ai_quota_user_override[0] = { id: 5001, user_id: '101', enabled: '1', call_limit: '7' };
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
check('an override stored as strings is still read (MySQL returns strings)',
  r.status === 200 && (await bodyOf(r)).limit === 7, JSON.stringify({ s: r.status, l: (await bodyOf(r)).limit }));
r = await fetch(`${B}/ai/quota`, AUTH('tok-c'));
check('another user is unaffected by user 101 override',
  r.status === 200 && (await bodyOf(r)).limit === DEFAULT_LIMIT, JSON.stringify({ l: (await bodyOf(r)).limit }));
seed();
setUsage('101', DEFAULT_LIMIT);
ncb.rows.ai_quota_user_override.push({ id: 5002, user_id: '101', enabled: 1, call_limit: 5 });
r = await fetch(`${B}/ai/chat`, CHAT('tok-a'));
check('the override raises the ceiling for the same stored counter',
  r.status === 200 && usageRow('101')?.calls_used === 4, JSON.stringify({ s: r.status, used: usageRow('101')?.calls_used }));
// A clean period and no counter row: with the switch off, the whole point is that nothing is
// written anywhere — no usage row, no claim.
seed();
ncb.rows.ai_quota_config[0].quota_enabled = 0;
pc = world.providerCalls;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('disabled-key')));
j = await bodyOf(r);
check('quota_enabled false is unlimited, unbilled, and dispatched',
  r.status === 200 && j.quota.unlimited === true && j.quota.enabled === false && j.quota.limit === null
  && usageRow('101') === undefined && ncb.rows.ai_quota_reservation.length === 0 && world.providerCalls === pc + 1,
  JSON.stringify({ s: r.status, quota: j.quota, rows: ncb.rows.ai_quota_reservation.length }));
r = await fetch(`${B}/ai/quota`, AUTH('tok-a'));
j = await bodyOf(r);
check('GET /ai/quota reports unlimited when the configuration says so, with no counter row',
  r.status === 200 && j.unlimited === true && j.enabled === false && j.used === 0 && j.limit === null,
  JSON.stringify({ e: j.enabled, u: j.unlimited, used: j.used }));
check('T3b the same decision key is scoped to the period, not forever',
  ncb.rows.ai_quota_usage.every((row) => row.period_key === PERIOD)
  && ncb.rows.ai_quota_reservation.every((row) => row.period_key === PERIOD),
  JSON.stringify({ u: [...new Set(ncb.rows.ai_quota_usage.map((x) => x.period_key))], r: [...new Set(ncb.rows.ai_quota_reservation.map((x) => x.period_key))] }));

// ── 7. ordering: what is validated before a call is spent ──────────────────
// Nothing is seeded into the counter here: the claim being tested is that a request the
// provider would simply reject leaves NO usage row at all, which is only observable from the
// empty state.
seed();
const writesBefore = dataCalls().length;
r = await fetch(`${B}/ai/chat`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' },
  body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', apiKey: PROVIDER_SECRET }, model: 'qwen3.8-flash', messages: [{ role: 'user', content: 'hi' }] })
});
j = await bodyOf(r);
check('a plaintext provider key is refused at 400 and spends no quota',
  r.status === 400 && usageRow('101') === undefined && !dataCalls().some((q) => /create\/ai_quota_usage/.test(q.pathname)),
  `status=${r.status} used=${usageRow('101')?.calls_used}`);
r = await fetch(`${B}/ai/chat`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' },
  body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', encryptedApiKey: enc(PROVIDER_SECRET) }, messages: [{ role: 'user', content: 'hi' }] })
});
check('a missing model is refused before any reservation',
  r.status === 400 && usageRow('101') === undefined, `status=${r.status}`);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', { messages: [] }));
check('an empty message list is refused before any reservation',
  r.status === 400 && usageRow('101') === undefined, `status=${r.status}`);
check('the credential/model validations above made no counter write at all',
  !dataCalls().slice(writesBefore).some((q) => /create\/ai_quota_usage|update\/ai_quota_usage/.test(q.pathname)),
  dataCalls().slice(writesBefore).map((q) => q.pathname).join(' | '));

seed();
events.length = 0;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('order-check')));
const order = events.filter((e) => ['session', 'create:ai_quota_reservation', 'create:ai_quota_usage', 'update:ai_quota_usage', 'provider'].includes(e));
check('T-order the measured sequence is session -> claim -> charge -> provider',
  order.join(',') === 'session,create:ai_quota_reservation,create:ai_quota_usage,provider', order.join(','));
check('T-order the claim precedes the charge (never charge-then-record)',
  order.indexOf('create:ai_quota_reservation') > -1 && order.indexOf('create:ai_quota_reservation') < order.indexOf('create:ai_quota_usage'),
  order.join(','));
const claimReq = ncb.requests.find((q) => q.pathname === '/data/create/ai_quota_reservation');
check('the reservation write carries the exact tuple and nothing else',
  JSON.stringify(Object.keys(claimReq?.body || {}).sort()) === JSON.stringify(['created_at', 'decision_key', 'period_key', 'user_id'])
  && claimReq?.body?.user_id === '101' && claimReq?.body?.decision_key === 'order-check'
  && claimReq?.body?.period_key === PERIOD, JSON.stringify(claimReq?.body));
check('the reservation route is the configured table, on the NCB data grammar',
  claimReq?.pathname === '/data/create/ai_quota_reservation' && claimReq?.query.Instance === '55954_bridgemind',
  `${claimReq?.pathname} Instance=${claimReq?.query.Instance}`);
const usageWrite = ncb.requests.find((q) => q.pathname === '/data/create/ai_quota_usage');
check('the counter write is an absolute value computed here (read-check-write)',
  usageWrite?.body?.calls_used === 1 && usageWrite?.body?.applied_limit === DEFAULT_LIMIT
  && String(usageWrite?.body?.user_id) === '101' && usageWrite?.body?.period_key === PERIOD,
  JSON.stringify(usageWrite?.body));

// ── 7b. AUTHORITATIVE AI SOURCE: the quota governs System AI accounts only ──
// SECURITY INVARIANT proved here: the waiver is granted by `user_settings.ai_source`
// read for the SESSION's user, and by nothing the requester controls. Every check
// below that involves a header is therefore a FORGERY test — the interesting question
// is never "did the header work" but "is the header still powerless".
// The exemption claim is also strong on purpose: not "the counter grew more slowly"
// but "no quota table was read or written at all".
const FORGE_USER = { 'x-ai-billing-source': 'user' };
const FORGE_SYSTEM = { 'x-ai-billing-source': 'system' };
const quotaCalls = (from = 0) => ncb.requests.slice(from).filter((q) => /ai_quota_/.test(q.pathname || ''));

seed();
events.length = 0;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, { ...KEY('forge-1'), ...FORGE_USER }));
j = await bodyOf(r);
const forgedUsed = ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage');
check('S1 a forged "user" header CANNOT bypass the quota: stored system ⇒ the call is still charged',
  r.status === 200 && forgedUsed === true && usageRow('101')?.calls_used === 1
  && j?.quota?.enabled === true && r.headers.get('x-quota-reservation') === 'created',
  `charged=${forgedUsed} used=${usageRow('101')?.calls_used} header=${r.headers.get('x-quota-reservation')}`);
check('S1b the forgery is logged as a mismatch, and nothing else',
  events.filter((e) => e === 'read:user_settings').length === 1
  && usageRow('101')?.calls_used === 1, events.filter((e) => /user_settings/.test(e)).join(','));

seed();
setSource('101', 'user');
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, { ...KEY('forge-2'), ...FORGE_SYSTEM }));
j = await bodyOf(r);
check('S2 a forged "system" header cannot force an Own-AI account to consume System quota either',
  r.status === 200 && quotaCalls().length === 0 && usageRow('101') === undefined
  && j?.quota?.quota_applies === false,
  `quota calls=${quotaCalls().length} used=${usageRow('101')?.calls_used}`);

seed();
setSource('101', null);
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('no-row')));
check('S3 no settings row ⇒ System AI (the app default), so an account is never silently unbilled',
  r.status === 200 && ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage'),
  `charged=${ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage')}`);

seed();
setSource('101', 'user');
ncb.fault = 'settings_read_fail';
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('source-down')));
const readFailedCharged = ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage');
check('S4 a failed source read fails toward BILLING, never toward free usage',
  r.status === 200 && readFailedCharged === true,
  `charged=${readFailedCharged} status=${r.status}`);
ncb.fault = null;

seed();
setSource('101', 'banana');
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('odd-value')));
check('S5 an unrecognised stored value is System AI, not an exemption',
  ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage'),
  `charged=${ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage')}`);

seed();
setSource('101', 'user');
ncb.fault = 'settings_duplicate';
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('dup-settings')));
check('S6 duplicate settings rows never buy an exemption — ambiguous means billed',
  r.status === 200 && ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage'),
  `charged=${ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_usage')}`);
ncb.fault = null;

seed();
setSource('101', 'system');
const cachedStatuses = [];
for (const k of ['c1', 'c2', 'c3', 'c4', 'c5']) {
  const res = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY(k)));
  cachedStatuses.push(res.status);
}
// The cache claim is about READS, not about how many calls were allowed: the cap is
// DEFAULT_LIMIT (3), so calls 4 and 5 are correctly 429 — and they still cost no
// second source read, which is the point.
check('S7 the source is read once and then cached, including on calls the cap refuses',
  sourceReads('101').length === 1 && usageRow('101')?.calls_used === DEFAULT_LIMIT
  && cachedStatuses.filter((s) => s === 200).length === DEFAULT_LIMIT
  && cachedStatuses.filter((s) => s === 429).length === 5 - DEFAULT_LIMIT,
  `settings reads=${sourceReads('101').length} used=${usageRow('101')?.calls_used} statuses=${cachedStatuses.join('/')}`);
check('S7b the cache is bounded and in range: 45s TTL, 5s for a failed read',
  mod.AI_SOURCE_CACHE_TTL_MS === 45000 && mod.AI_SOURCE_FAILURE_CACHE_TTL_MS === 5000
  && mod.AI_SOURCE_CACHE_TTL_MS >= 30000 && mod.AI_SOURCE_CACHE_TTL_MS <= 60000,
  `ttl=${mod.AI_SOURCE_CACHE_TTL_MS} failureTtl=${mod.AI_SOURCE_FAILURE_CACHE_TTL_MS}`);

seed();
setSource('101', 'system');
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('d1')));
const readsBeforeInvalidate = sourceReads('101').length;
const requestsAtSwitch = ncb.requests.length;
setSource('101', 'user');   // setSource drops that user's cache entry, as a settings write would
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('d2')));
check('S8 the cache re-reads after the source changes, and the next call is exempt',
  sourceReads('101').length === readsBeforeInvalidate + 1 && r.status === 200
  && quotaCalls(requestsAtSwitch).length === 0 && usageRow('101')?.calls_used === 1,
  `reads=${sourceReads('101').length} quota calls after the switch=${quotaCalls(requestsAtSwitch).length}`);

seed();
setSource('101', 'user');
const raced = await Promise.all([1, 2, 3, 4, 5].map((n) => fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY(`race-${n}`)))));
check('S8b five concurrent exempt calls: no quota traffic at all, and one source read at most',
  raced.every((res) => res.status === 200) && quotaCalls().length === 0
  && sourceReads('101').length <= 1,
  `settings reads=${sourceReads('101').length} quota calls=${quotaCalls().length}`);

seed();
setSource('101', 'user');
const beforeDup = ncb.requests.length;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, { ...KEY('dup-exempt'), ...FORGE_SYSTEM }));
const dupSecond = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, { ...KEY('dup-exempt'), ...FORGE_SYSTEM }));
check('S9 an exempt account creates no reservation and no counter, on a retry or out of the box',
  claim('101', 'dup-exempt') === undefined && usageRow('101') === undefined
  && r.status === 200 && dupSecond.status === 200,
  `claims=${ncb.rows.ai_quota_reservation.length} usage=${ncb.rows.ai_quota_usage.length}`);
void beforeDup;

seed();
setSource('101', 'system');
const switchLadderStart = world.providerCalls;
for (let n = 1; n <= DEFAULT_LIMIT; n += 1) {
  r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY(`ladder-${n}`)));
}
const overCap = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('ladder-over')));
setSource('101', 'user');
mod.resetAiSourceCache('101');
const afterExemption = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('ladder-after-switch')));
check('S10 an account at the cap starts working the moment it moves to its own AI, and the quota is untouched',
  overCap.status === 429 && afterExemption.status === 200
  && usageRow('101')?.calls_used === DEFAULT_LIMIT
  && world.providerCalls === switchLadderStart + DEFAULT_LIMIT + 1,
  `cap=${overCap.status} exempt=${afterExemption.status} used=${usageRow('101')?.calls_used}`);

seed();
setSource('101', 'user');
r = await fetch(`${B}/ai/models`, CHAT('tok-a', {}, FORGE_USER));
check('S11 the source decision is confined to the chat path; a non-chat surface stays quota-free',
  r.status === 200 && quotaCalls().length === 0, `quota calls=${quotaCalls().length}`);

// ── ADMINISTRATOR PER-USER ROUTES ──────────────────────────────────────────
seed();
r = await fetch(`${B}/ai/quota/status?user_id=101`, AUTH('tok-a'));
check('R1 the per-account quota status is administrator-only (403 for an ordinary user)',
  r.status === 403 && quotaCalls().length === 0, `status=${r.status}`);
r = await fetch(`${B}/ai/quota/status?user_id=101`, { method: 'GET' });
check('R1b it requires a session at all', r.status === 401, `status=${r.status}`);

seed();
r = await fetch(`${B}/ai/quota/status?user_id=101`, AUTH('tok-admin'));
j = await bodyOf(r);
check('R2 an admin sees real System AI figures, computed by the same resolver that bills',
  r.status === 200 && j.aiSource === 'system' && j.quotaApplies === true
  && j.effectiveLimit === DEFAULT_LIMIT && j.used === 0 && j.globalLimit === DEFAULT_LIMIT
  && j.limitSource === 'default' && j.overrideEnabled === null,
  JSON.stringify({ s: r.status, a: j.aiSource, l: j.effectiveLimit, u: j.used }));

seed();
setSource('101', 'user');
r = await fetch(`${B}/ai/quota/status?user_id=101`, AUTH('tok-admin'));
j = await bodyOf(r);
check('R3 an Own-AI account is reported as not applicable, with no invented figures',
  r.status === 200 && j.aiSource === 'user' && j.quotaApplies === false
  && j.used === null && j.effectiveLimit === null && j.remaining === null && j.percentage === null,
  JSON.stringify({ a: j.aiSource, u: j.used, e: j.effectiveLimit }));

seed();
r = await fetch(`${B}/ai/quota/status?user_id=101`, {
  method: 'GET', headers: { Authorization: 'Bearer tok-admin', ...FORGE_USER }
});
j = await bodyOf(r);
check('R4 the admin view follows the stored source, never a header the caller sent',
  r.status === 200 && j.aiSource === 'system' && j.quotaApplies === true,
  JSON.stringify({ a: j.aiSource, q: j.quotaApplies }));

seed();
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-a', { user_id: '101', enabled: true, call_limit: 9 }));
check('R5 an ordinary user cannot set anyone\'s limit, and nothing is written',
  r.status === 403 && ncb.rows.ai_quota_user_override.length === 0, `status=${r.status}`);

seed();
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 9 }));
j = await bodyOf(r);
check('R6 an admin sets a System AI account\'s custom limit, persisted and read back',
  r.status === 200 && j.effectiveLimit === 9 && j.limitSource === 'override'
  && overrideRow('101')?.call_limit === 9 && overrideRow('101')?.enabled === 1,
  JSON.stringify({ s: r.status, e: j.effectiveLimit, row: overrideRow('101') }));
const usedAfterSet = usageRow('101')?.calls_used;
check('R6b setting a limit never touches the usage counter',
  usedAfterSet === undefined && !dataCalls().some((q) => /create\/ai_quota_usage|update\/ai_quota_usage/.test(q.pathname)),
  `usage rows=${ncb.rows.ai_quota_usage.length}`);

seed();
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 9 }));
const usedBeforeRemoval = setUsage('101', 2);
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: false, call_limit: 0 }));
j = await bodyOf(r);
check('R7 "return to global" clears the override the way the resolver reads it (enabled=0)',
  r.status === 200 && j.effectiveLimit === DEFAULT_LIMIT && j.limitSource === 'default'
  && overrideRow('101')?.enabled === 0,
  JSON.stringify({ s: r.status, e: j.effectiveLimit, row: overrideRow('101') }));
check('R7b and it still does not touch the usage counter',
  usageRow('101')?.calls_used === 2 && usageRow('101')?.id === usedBeforeRemoval.id,
  `used=${usageRow('101')?.calls_used}`);

seed();
setSource('101', 'user');
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 9 }));
j = await bodyOf(r);
check('R8 setting a limit for an Own-AI account is refused with a stable code, and nothing is written',
  r.status === 409 && j.reason === 'user_not_using_system_ai'
  && ncb.rows.ai_quota_user_override.length === 0
  && !dataCalls().some((q) => /create\/ai_quota_user_override|update\/ai_quota_user_override/.test(q.pathname)),
  JSON.stringify({ s: r.status, reason: j.reason, rows: ncb.rows.ai_quota_user_override.length }));

seed();
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 9 }));
check('R8b a stored limit survives the switch to Own AI and is dormant, not deleted',
  r.status === 200 && overrideRow('101')?.call_limit === 9, `row=${JSON.stringify(overrideRow('101'))}`);
setSource('101', 'user');
r = await fetch(`${B}/ai/quota/status?user_id=101`, AUTH('tok-admin'));
j = await bodyOf(r);
check('R8c the admin sees it as a dormant override while the account is on its own AI',
  r.status === 200 && j.quotaApplies === false && j.dormantOverride === true && j.overrideLimit === 9,
  JSON.stringify({ d: j.dormantOverride, l: j.overrideLimit }));
setSource('101', 'system');
r = await fetch(`${B}/ai/quota/status?user_id=101`, AUTH('tok-admin'));
j = await bodyOf(r);
check('R8d switching back to System AI makes the same stored override effective again',
  r.status === 200 && j.quotaApplies === true && j.effectiveLimit === 9 && j.limitSource === 'override',
  JSON.stringify({ e: j.effectiveLimit, s: j.limitSource }));
const rowBeforeReroute = overrideRow('101').id;
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('effective-after-switch')));
check('R8e and the chat path actually bills against it, with no new override row created',
  r.status === 200 && usageRow('101')?.applied_limit === 9
  && overrideRow('101')?.id === rowBeforeReroute,
  `applied=${usageRow('101')?.applied_limit}`);

seed();
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 0 }));
const zeroRow = overrideRow('101');
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 2.5 }));
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 'lots' }));
check('R9 an invalid limit is refused with 400 and never reaches storage',
  r.status === 400 && zeroRow === undefined && !dataCalls().some((q) => /ai_quota_user_override/.test(q.pathname)),
  `status=${r.status} rows=${ncb.rows.ai_quota_user_override.length}`);
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', call_limit: 9 }));
check('R9b a non-boolean enabled is refused rather than guessed at', r.status === 400, `status=${r.status}`);

seed();
// The duplicate fault doubles rows that EXIST; against an empty override table it
// would silently produce zero rows and the check would pass without ever testing the
// ambiguity it exists to cover. So a real row is written first.
await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 9 }));
ncb.fault = 'override_duplicate';
r = await fetch(`${B}/ai/quota/status?user_id=101`, AUTH('tok-admin'));
const dupBody = await bodyOf(r);
check('R10 an ambiguous override is reported as unavailable, never resolved by taking the first row',
  r.status === 503 && dupBody.reason === 'override_duplicate',
  `status=${r.status} reason=${dupBody.reason} rows=${ncb.rows.ai_quota_user_override.length}`);
ncb.fault = null;

seed();
r = await fetch(`${B}/ai/quota/status`, AUTH('tok-admin'));
check('R11 a missing target is a 400 and costs no storage read',
  r.status === 400 && quotaCalls().length === 0, `status=${r.status}`);

seed();
setSource('101', 'system');
r = await fetch(`${B}/ai/quota/user`, PUTJSON('tok-admin', { user_id: '101', enabled: true, call_limit: 9 }));
check('R12 a header claiming "user" cannot make the admin route refuse a legitimate write',
  r.status === 200 && overrideRow('101')?.call_limit === 9, `status=${r.status}`);

// ── 8. surfaces that must stay quota-free ─────────────────────────────────
seed();
setUsage('101', 0);
const beforeOther = ncb.requests.length;
r = await fetch(`${B}/ai/test`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' },
  body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', encryptedApiKey: enc(PROVIDER_SECRET) }, model: 'qwen3.8-flash' })
});
check('T21 /ai/test still dispatches the provider and charges nothing',
  r.status === 200 && ncb.requests.slice(beforeOther).every((q) => !/ai_quota/.test(q.pathname)),
  ncb.requests.slice(beforeOther).map((q) => q.pathname).join(' | '));
r = await fetch(`${B}/ai/models`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' }, body: JSON.stringify({ provider: 'alibaba', config: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', encryptedApiKey: enc(PROVIDER_SECRET) } }) });
check('T21 /ai/models still works and charges nothing',
  r.status === 200 && ncb.requests.slice(beforeOther).every((q) => !/ai_quota/.test(q.pathname)),
  JSON.stringify({ s: r.status, calls: ncb.requests.slice(beforeOther).map((q) => q.pathname).join(',') }));
const beforeTrickster = ncb.requests.length;
const tricksterStatuses = [];
for (const route of ['/trickster/bid/health', '/trickster/play/health', '/trickster/bid/suggest-bid', '/trickster/play/suggest-card']) {
  const post = route.includes('suggest');
  tricksterStatuses.push((await fetch(`${B}${route}`, {
    method: post ? 'POST' : 'GET',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' },
    ...(post ? { body: '{}' } : {})
  })).status);
}
check('T20 a Trickster call makes no quota storage request at all',
  ncb.requests.slice(beforeTrickster).every((q) => !/ai_quota/.test(q.pathname)),
  ncb.requests.slice(beforeTrickster).map((q) => `${q.method} ${q.pathname}`).join(' | '));
check('T20 Trickster billing is unchanged: proxied with a session, never a quota verdict',
  tricksterStatuses.every((s) => s === 502 || s === 504), tricksterStatuses.join(','));
r = await fetch(`${B}/trickster/bid/suggest-bid`, AUTH('tok-a'));
check('a wrong verb on a Trickster path still answers 405 with Allow: POST',
  r.status === 405 && r.headers.get('allow') === 'POST', `status=${r.status}`);

// ── 9. admin configuration (T19) ──────────────────────────────────────────
seed();
r = await fetch(`${B}/ai/quota/config`);
check('config GET without a session -> 401', r.status === 401, `status=${r.status}`);
// Counted on the /data/ traffic, not on every NCB request: the session lookup has to happen
// to learn the role, and refusing before THAT would mean answering 403 without knowing who
// is asking. What must not happen is a read or write of a quota table.
const readsBeforeAdmin = dataCalls().length;
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-a'));
j = await bodyOf(r);
check('config GET as an ordinary user -> 403 with no quota-table access',
  r.status === 403 && j.status === 'forbidden' && dataCalls().length === readsBeforeAdmin,
  JSON.stringify({ s: r.status, newCalls: dataCalls().length - readsBeforeAdmin }));
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-a', { quota_enabled: true, default_call_limit: 7 }));
check('config PUT as an ordinary user -> 403 before any quota-table read or write',
  r.status === 403 && dataCalls().length === readsBeforeAdmin, `calls=${dataCalls().length - readsBeforeAdmin}`);
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
j = await bodyOf(r);
check('T19 admin GET config reads the stored row',
  r.status === 200 && j.quota_enabled === true && j.default_call_limit === DEFAULT_LIMIT
  && j.period_type === 'monthly' && j.success === true, JSON.stringify(j).slice(0, 140));
check('the config read is an unfiltered read of the config table with the admin bearer',
  (() => { const q = ncb.requests.filter((x) => x.pathname === '/data/read/ai_quota_config').pop(); return q?.auth === 'Bearer tok-admin' && q?.method === 'GET'; })(), '');
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 5 }));
j = await bodyOf(r);
check('T19 admin PUT writes and reads back the new limit',
  r.status === 200 && j.default_call_limit === 5 && ncb.rows.ai_quota_config[0].default_call_limit === 5,
  JSON.stringify({ s: r.status, l: j.default_call_limit, stored: ncb.rows.ai_quota_config[0].default_call_limit }));
check('T19 a partial write does not reset the other field',
  j.quota_enabled === true && ncb.rows.ai_quota_config[0].quota_enabled === 1, JSON.stringify(j).slice(0, 120));
check('the write goes to the config row by id, not to a table-wide route',
  (() => { const q = ncb.requests.filter((x) => x.pathname.startsWith('/data/update/ai_quota_config/')).pop(); return q?.method === 'PUT' && /\d+$/.test(q?.pathname || '') && q?.body?.default_call_limit === 5; })(),
  ncb.requests.filter((x) => x.pathname.includes('ai_quota_config')).map((x) => `${x.method} ${x.pathname}`).join(' | '));
check('the update also stamps updated_at in the SQL format the store expects',
  /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(String(ncb.requests.filter((x) => x.pathname.startsWith('/data/update/ai_quota_config/')).pop()?.body?.updated_at)),
  String(ncb.requests.filter((x) => x.pathname.startsWith('/data/update/ai_quota_config/')).pop()?.body?.updated_at));
const badWrites = [
  ['quota_enabled as a number', { quota_enabled: 1 }],
  ['quota_enabled as a string', { quota_enabled: 'true' }],
  ['default_call_limit zero', { default_call_limit: 0 }],
  ['default_call_limit fractional', { default_call_limit: 2.5 }],
  ['default_call_limit as a string', { default_call_limit: '25' }],
  ['default_call_limit above the bound', { default_call_limit: 100001 }],
  ['period_type weekly', { period_type: 'weekly' }],
  ['an unrecognised field', { note: 'hello' }]
];
for (const [label, payload] of badWrites) {
  const stored = JSON.stringify(ncb.rows.ai_quota_config[0]);
  r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', payload));
  j = await bodyOf(r);
  check(`a rejected config write (${label}) answers 400 and never says saved`,
    r.status === 400 && j.success === false && j.status === 'invalid_quota_configuration', JSON.stringify(j).slice(0, 110));
  check(`a rejected config write (${label}) changes nothing in the row`,
    JSON.stringify(ncb.rows.ai_quota_config[0]) === stored, '');
}
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', null, 'not-an-object'));
check('a non-JSON admin body is refused locally', r.status === 400 || r.status === 415, `status=${r.status}`);
seed();
ncb.fault = 'config_duplicate';
r = await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'));
check('two config rows refuse the admin read rather than picking one',
  r.status === 503 && (await bodyOf(r)).status === 'quota_service_unavailable', `status=${r.status}`);
ncb.fault = 'update_config_fail';
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 9 }));
check('a failed config write is 503 and is never reported as saved',
  r.status === 503 && (await bodyOf(r)).success === false && ncb.rows.ai_quota_config[0].default_call_limit === DEFAULT_LIMIT,
  `status=${r.status} stored=${ncb.rows.ai_quota_config[0].default_call_limit}`);
ncb.fault = 'config_no_persist';
r = await fetch(`${B}/ai/quota/config`, PUTJSON('tok-admin', { default_call_limit: 9 }));
j = await bodyOf(r);
check('an acknowledged write that does not read back is refused (read-back verified)',
  r.status === 503 && j.success === false && j.status === 'quota_service_unavailable', JSON.stringify(j).slice(0, 110));
ncb.fault = null;
seed();
const noLeakText = await (await fetch(`${B}/ai/quota/config`, AUTH('tok-admin'))).text();
const noLeakBody = JSON.parse(noLeakText);
// Asserted on the parsed shape, not by substring: the response legitimately contains
// timestamps and a request id, and a row id like "9" is a substring of both. A digit
// search here would pass or fail on the clock, which is not a test of anything.
check('the config answer carries no table name, storage host or row address',
  !STORAGE_STRINGS.some((s) => noLeakText.includes(s)) && !noLeakText.includes(NCB_BASE)
  && !('id' in noLeakBody) && !('row_id' in noLeakBody) && !('rowId' in noLeakBody)
  && !('table' in noLeakBody) && !('sql' in noLeakBody)
  && Object.keys(noLeakBody).sort().join(',') === 'default_call_limit,period_type,quota_enabled,requestId,success,updated_at',
  Object.keys(noLeakBody).sort().join(','));

// ── 10. one mutex, one writer, one authority (T22) ────────────────────────
const observed = { active: 0, maxSameUser: 0, maxDistinct: 0, current: new Set() };
const hold = (userId, ms) => mod.withUserLock(userId, async () => {
  observed.active++;
  observed.current.add(userId);
  observed.maxSameUser = Math.max(observed.maxSameUser, [...observed.current].filter((u) => u === userId).length + observed.active - 1);
  observed.maxDistinct = Math.max(observed.maxDistinct, observed.current.size);
  // A macrotask yield, not a microtask: a synchronous body would let the mutex look
  // serialised when it is only being awaited in order.
  await new Promise((resolve) => setTimeout(resolve, ms));
  observed.active--;
  observed.current.delete(userId);
  return observed.active;
});
const maxActiveDuring = [];
const fiveSameUser = await Promise.all([1, 2, 3, 4, 5].map((i) => hold('same-user', 8).then(() => maxActiveDuring.push(observed.active))));
check('T22 the per-user mutex serialises five concurrent tasks for one user',
  fiveSameUser.length === 5 && observed.maxDistinct === 1 && mod.userLockCount() === 0,
  JSON.stringify({ maxDistinct: observed.maxDistinct, lockCount: mod.userLockCount() }));
await Promise.all([hold('user-x', 10), hold('user-y', 10), hold('user-z', 10)]);
check('T22 different users are not queued behind one global lock',
  observed.maxDistinct === 3, JSON.stringify({ maxDistinct: observed.maxDistinct }));
check('T22 the lock map is emptied, so no request can strand a user behind a dead promise',
  mod.userLockCount() === 0, `userLockCount=${mod.userLockCount()}`);
seed();
// The ceiling is raised so that five concurrent calls measure serialisation rather than the
// cap: with limit 3 two of them would be denied and the count would still come out at 3.
ncb.rows.ai_quota_config[0].default_call_limit = 10;
const burst = await Promise.all(Array.from({ length: 5 }, (_, i) => fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY(`burst-${i}`)))));
check('T22 five concurrent keyed calls for one user bill five, not fewer or more',
  usageRow('101')?.calls_used === 5 && burst.every((x) => x.status === 200),
  `used=${usageRow('101')?.calls_used} statuses=${burst.map((x) => x.status).join(',')}`);
const writtenValues = ncb.requests.filter((q) => q.pathname.startsWith('/data/update/ai_quota_usage') || q.pathname.startsWith('/data/create/ai_quota_usage')).map((q) => q.body?.calls_used);
check('T22 the counter never moved backwards or repeated a value (no lost update)',
  JSON.stringify(writtenValues) === JSON.stringify([1, 2, 3, 4, 5]), JSON.stringify(writtenValues));
// ── 8. INVITATION CODES and PER-USER CREDENTIALS (Stage 1 hardening) ───────
// Two different claims are tested here, and keeping them apart is the point. The invitation
// routes reduce what OUR browser receives; they do not make `user_codes` private, and nothing
// below is allowed to read as if they did. The credential routes move a per-account secret
// behind the account's own session, which is the one surface that a `private` policy can
// actually enforce later.
const CODE_SECRET = 'INVITATION-SECRET-must-never-leave-the-relay-4f2c';
const CODE_ROW_USER = 'admin-who-issued-the-code';
const A_SECRET = enc('sk-USER-A-own-provider-key-1a2b');
const B_SECRET = enc('sk-USER-B-own-provider-key-3c4d');
const resetCodes = (rows) => { ncb.rows.user_codes = rows; };
const resetCreds = (rows) => { ncb.rows.ai_provider_credentials_1770000000 = rows; };
const INVITE = (body, headers = {}) => fetch(`${B}/auth/validate-invitation`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body)
});
const CONSUME = (tok, body) => fetch(`${B}/auth/consume-invitation`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: `Bearer ${tok}` } : {}) },
  body: JSON.stringify(body)
});
const CHAT_WITH = (tok, config, key) => fetch(`${B}/ai/chat`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok}`, ...(key ? { 'x-ai-decision-key': key } : {}) },
  body: JSON.stringify({
    provider: 'alibaba', config, model: 'qwen3.8-flash',
    messages: [{ role: 'user', content: 'hi' }]
  })
});
// Every response body and log line produced from here on, searched for material that must
// never leave the relay. One accumulator, so a leak in ANY of these routes is caught.
const seenBodies = [];
const readBody = async (res) => { const b = await res.json().catch(() => ({})); seenBodies.push(JSON.stringify(b)); return b; };
const leakedInResponses = (needle) => seenBodies.some((text) => text.includes(needle));

resetCodes([
  { id: ncb.nextId.user_codes++, user_id: CODE_ROW_USER, secret_key: CODE_SECRET, code: 'INV-VALID', used: 0, created_at: sqlDate() },
  { id: ncb.nextId.user_codes++, user_id: CODE_ROW_USER, secret_key: CODE_SECRET, code: 'INV-USED', used: 1, created_at: sqlDate() }
]);
mod.resetInvitationRateBuckets();
// I-1/2/3 — the three answers, and nothing else.
r = await INVITE({ code: 'INV-VALID' }); j = await readBody(r);
check('I-1 an anonymous valid-code check succeeds and answers one boolean',
  r.status === 200 && j.valid === true && Object.keys(j).sort().join(',') === 'requestId,success,valid',
  JSON.stringify(j));
r = await INVITE({ code: 'INV-NOPE' }); j = await readBody(r);
check('I-2 an unknown code is answered valid:false, with no row and no status inflation',
  r.status === 200 && j.valid === false, JSON.stringify(j));
r = await INVITE({ code: 'INV-USED' }); j = await readBody(r);
check('I-3 a spent code cannot be validated again',
  r.status === 200 && j.valid === false, JSON.stringify(j));
// I-4/5 — the absence half, which is the entire reason this route exists.
check('I-4 no response of any kind carries the stored secret_key',
  !leakedInResponses(CODE_SECRET), `${seenBodies.length} responses searched`);
check('I-5 no response carries a row id, the issuing user, the used flag or the code object',
  !leakedInResponses('"secret_key"') && !leakedInResponses(CODE_ROW_USER) && !leakedInResponses('"used"') && !leakedInResponses('"id":'),
  seenBodies.filter((t) => /secret_key|"used"|admin-who/.test(t)).join(' | ').slice(0, 160));
// I-6 — runtime proof the anonymous read stayed anonymous: the MOCK refuses a credential on
// the public route, so a bearer-carrying transport would not merely be noticed, it would fail.
const publicReads = ncb.requests.filter((q) => q.pathname.startsWith('/public-data/'));
check('I-6 every public-data read carried no Authorization at all',
  publicReads.length >= 3 && publicReads.every((q) => q.auth === ''),
  `${publicReads.length} public reads; auths=${[...new Set(publicReads.map((q) => q.auth || '(none)'))].join(',')}`);
check('I-6b the public read is filtered by the typed code, not by an id the caller chose',
  publicReads.every((q) => String(q.query.code ?? '').startsWith('INV-')) && !publicReads.some((q) => q.query.id),
  JSON.stringify(publicReads.map((q) => q.query.code)));
// I-7/8 — fail closed, in both directions.
resetCodes([
  { id: 1, user_id: CODE_ROW_USER, secret_key: CODE_SECRET, code: 'INV-TWIN', used: 0 },
  { id: 2, user_id: CODE_ROW_USER, secret_key: CODE_SECRET, code: 'INV-TWIN', used: 0 }
]);
mod.resetInvitationRateBuckets();
r = await INVITE({ code: 'INV-TWIN' }); j = await readBody(r);
check('I-7 two live rows for one code is refused, not silently resolved by taking the first',
  r.status === 503 && j.valid === undefined && j.status === 'invitation_duplicate', JSON.stringify(j));
ncb.fault = 'data_hang';
resetCodes([{ id: 3, user_id: CODE_ROW_USER, secret_key: CODE_SECRET, code: 'INV-VALID', used: 0 }]);
mod.resetInvitationRateBuckets();
r = await INVITE({ code: 'INV-VALID' }); j = await readBody(r);
ncb.fault = null;
check('I-8 an unreachable store is 503, never a confident valid:false',
  r.status === 503 && j.valid === undefined && j.status === 'invitation_service_unavailable',
  JSON.stringify(j));
// I-9 — the abuse control, measured rather than described.
resetCodes([{ id: 4, user_id: CODE_ROW_USER, secret_key: CODE_SECRET, code: 'INV-VALID', used: 0 }]);
mod.resetInvitationRateBuckets();
const flood = [];
for (let i = 0; i < mod.INVITATION_RATE_MAX + 3; i += 1) flood.push((await INVITE({ code: 'INV-VALID' })).status);
check('I-9 the anonymous route is throttled per address, then answers 429 with Retry-After',
  flood.slice(0, mod.INVITATION_RATE_MAX).every((s) => s === 200)
  && flood.slice(mod.INVITATION_RATE_MAX).every((s) => s === 429),
  flood.join(','));
// The two refusal cases below are about LOCAL validation, so they need a fresh window:
// ordering is deliberate in the handler (an over-limit anonymous caller is turned away before
// the body is even parsed), and a test that wanted to see the 400 has to ask from an
// un-flooded address rather than reorder the production code to satisfy it.
mod.resetInvitationRateBuckets();
const readsBeforeLocal = ncb.counts.publicRead || 0;
r = await INVITE({ code: '' });
check('I-9b a missing code is refused locally, before any storage call',
  r.status === 400 && (ncb.counts.publicRead || 0) === readsBeforeLocal,
  `status=${r.status} storage reads added=${(ncb.counts.publicRead || 0) - readsBeforeLocal}`);
r = await INVITE({ code: 'x'.repeat(400) });
check('I-9c an over-long code is refused locally, so it cannot be used to spray the store',
  r.status === 400, String(r.status));
// The adversarial half of the bound: a code of EXACTLY the maximum length must still be
// accepted. Without this, an off-by-one that rejected every long-but-legal code — or a limit
// clamped to zero, which would refuse everything — would leave I-9c looking correct.
r = await INVITE({ code: 'y'.repeat(mod.INVITATION_CODE_MAX_LENGTH) });
check('I-9d a code at exactly the bound is validated, not rejected by an off-by-one',
  r.status === 200, String(r.status));
// I-10/11/12 — consumption needs a session and spends the code for THAT account only.
resetCodes([{ id: 5, user_id: CODE_ROW_USER, secret_key: CODE_SECRET, code: 'INV-FRESH', used: 0 }]);
mod.resetInvitationRateBuckets();
r = await CONSUME(null, { code: 'INV-FRESH' }); j = await readBody(r);
check('I-10 consumption requires a session (the code is spent for an account, not for a string)',
  r.status === 401 && j.success !== true, JSON.stringify(j));
r = await CONSUME('tok-a', { code: 'INV-FRESH', user_id: 999, userId: 'whoever' });
j = await readBody(r);
check('I-11 the spent code is assigned to the SESSION user and a forged body user_id is ignored',
  r.status === 200 && j.success === true
  && String(ncb.rows.user_codes.find((x) => x.code === 'INV-FRESH')?.user_id) === '101'
  && ncb.rows.user_codes.find((x) => x.code === 'INV-FRESH')?.used === 1,
  JSON.stringify(ncb.rows.user_codes.find((x) => x.code === 'INV-FRESH')));
r = await CONSUME('tok-b', { code: 'INV-FRESH' }); j = await readBody(r);
check('I-12 a code already spent cannot be spent by a second account',
  r.status === 200 && j.success === false && j.reason === 'invitation_not_found', JSON.stringify(j));
r = await CONSUME('tok-b', { code: 'INV-NEVER-EXISTED' }); j = await readBody(r);
check('I-12b an unknown code is a declined consumption, not a write attempt',
  r.status === 200 && j.success === false && j.reason === 'invitation_not_found', JSON.stringify(j));

// ── per-user credentials ───────────────────────────────────────────────────
resetCreds([]);
r = await fetch(`${B}/ai/credentials`);
check('C-1 the credential list requires a session', r.status === 401, String(r.status));
r = await fetch(`${B}/ai/credentials`, AUTH('tok-a')); j = await readBody(r);
check('C-2 an account with no credential gets an empty list, not an error',
  r.status === 200 && Array.isArray(j.credentials) && j.credentials.length === 0, JSON.stringify(j));
const baseUrl = 'https://dashscope.aliyuncs.com/compatible-mode/v1';
r = await fetch(`${B}/ai/credentials`, PUTJSON('tok-a', {
  usage: 'gameplay', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encryptedApiKey: A_SECRET,
  user_id: 202, userId: 'not-me'
})); j = await readBody(r);
check('C-3 saving one\'s own credential writes it for the SESSION user and ignores a forged user_id',
  r.status === 200 && j.credential?.usage === 'gameplay' && j.credential?.credentialPresent === true
  && ncb.rows.ai_provider_credentials_1770000000.length === 1
  && String(ncb.rows.ai_provider_credentials_1770000000[0].user_id) === '101',
  JSON.stringify(j));
const metaKeysC4 = Object.keys(j.credential ?? {}).sort();
check('C-4 the save response is metadata only and never contains the key material',
  r.status === 200 && !leakedInResponses(A_SECRET) && !leakedInResponses('encrypted_api_key')
  // Every field the client needs is present…
  && ['credentialPresent', 'id', 'model', 'provider', 'usage'].every((k) => metaKeysC4.includes(k))
  // …and nothing that could ever be a secret is, whatever it is called. A field list that
  // only forbids today's names would let `auth` or `apiKey` slip in later.
  && !metaKeysC4.some((k) => /key|secret|token|password|credential_(?!present)/i.test(k)),
  JSON.stringify(j.credential));
check('C-4b the stored ciphertext is what was sent, byte-for-byte, and no plaintext was ever written',
  ncb.rows.ai_provider_credentials_1770000000[0].encrypted_api_key === A_SECRET
  && !JSON.stringify(ncb.rows.ai_provider_credentials_1770000000).includes('sk-USER-A-own-provider-key'),
  'at-rest model preserved: ciphertext in, ciphertext stored');
r = await fetch(`${B}/ai/credentials`, PUTJSON('tok-a', {
  usage: 'gameplay', provider: 'alibaba', model: 'qwen-plus', endpoint: baseUrl, apiKey: 'sk-PLAINTEXT-NOPE'
})); j = await readBody(r);
check('C-5 a plaintext provider key is refused outright, never stored and never downgraded',
  r.status === 400 && j.status === 'invalid_credential', JSON.stringify(j));
r = await fetch(`${B}/ai/credentials`, PUTJSON('tok-a', {
  usage: 'gameplay', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encryptedApiKey: 'not-even-base64-ciphertext'
})); j = await readBody(r);
check('C-6 a blob this relay cannot decrypt is refused at save time rather than stored broken',
  r.status === 400 && j.status === 'invalid_credential', JSON.stringify(j));
r = await fetch(`${B}/ai/credentials`, PUTJSON('tok-a', {
  usage: 'gameplay', provider: 'alibaba', model: 'qwen-plus', endpoint: baseUrl
})); j = await readBody(r);
check('C-7 changing the model without a new key leaves the stored ciphertext untouched',
  r.status === 200 && j.credential.model === 'qwen-plus'
  && ncb.rows.ai_provider_credentials_1770000000[0].encrypted_api_key === A_SECRET,
  JSON.stringify(j.credential));
// Cross-account: user B may see, change, or spend nothing of A's.
resetCreds([
  { id: 11, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: A_SECRET, usage: 'gameplay' },
  { id: 22, user_id: '202', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: B_SECRET, usage: 'gameplay' }
]);
r = await fetch(`${B}/ai/credentials`, AUTH('tok-b')); j = await readBody(r);
check('C-8 user B\'s list contains only B\'s row, and the read sent to storage named B',
  r.status === 200 && j.credentials.length === 1 && j.credentials[0].id === 22
  && ncb.requests.slice(-1)[0].query.user_id === '202', JSON.stringify(j));
check('C-8b no listing response ever carried either account\'s ciphertext',
  !leakedInResponses(A_SECRET) && !leakedInResponses(B_SECRET) && !leakedInResponses('encrypted_api_key'), JSON.stringify(j));
r = await fetch(`${B}/ai/credentials`, PUTJSON('tok-b', {
  id: 11, usage: 'gameplay', provider: 'alibaba', model: 'qwen-turbo', endpoint: baseUrl
})); j = await readBody(r);
check('C-9 user B cannot overwrite user A\'s row by naming A\'s id — no id is accepted at all',
  r.status === 200 && j.credential?.id === 22
  && ncb.rows.ai_provider_credentials_1770000000.find((x) => x.id === 11).model === 'qwen3.8-flash'
  && ncb.requests.some((q) => q.pathname === '/data/update/ai_provider_credentials_1770000000/22')
  && !ncb.requests.some((q) => q.pathname === '/data/update/ai_provider_credentials_1770000000/11'),
  JSON.stringify(j.credential));
r = await fetch(`${B}/ai/credentials`, {
  method: 'DELETE', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-b' },
  body: JSON.stringify({ usage: 'gameplay', id: 11 })
}); j = await readBody(r);
check('C-10 user B cannot delete user A\'s credential; only B\'s own row went',
  r.status === 200 && j.removed === 1
  && ncb.rows.ai_provider_credentials_1770000000.some((x) => x.id === 11)
  && !ncb.rows.ai_provider_credentials_1770000000.some((x) => x.id === 22), JSON.stringify(j));
r = await fetch(`${B}/ai/credentials`, {
  method: 'DELETE', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-c' },
  body: JSON.stringify({ usage: 'gameplay' })
}); j = await readBody(r);
check('C-10b deleting a credential nobody holds is a clean no-op, not a failure',
  r.status === 200 && j.removed === 0, JSON.stringify(j));
r = await fetch(`${B}/ai/credentials`, PUTJSON('tok-a', { usage: 'sideways', provider: 'alibaba' })); j = await readBody(r);
check('C-11 an unknown usage scope is refused, so the two scopes stay two scopes',
  r.status === 400, JSON.stringify(j));
// The chat path: id-based resolution must work, must be able to deny, and must not spend quota
// when it denies.
resetCreds([
  { id: 31, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: A_SECRET, usage: 'gameplay' },
  { id: 32, user_id: '202', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: B_SECRET, usage: 'gameplay' }
]);
seed();
const providerBefore = world.providerCalls;
r = await CHAT_WITH('tok-a', { baseUrl, credentialId: 31 }); j = await readBody(r);
check('C-12 a chat that names only a credential id still reaches the provider with the right key',
  r.status === 200 && world.providerCalls === providerBefore + 1
  && world.providerRequests.slice(-1)[0].auth === `Bearer ${'sk-USER-A-own-provider-key-1a2b'}`,
  `status=${r.status} auth=${world.providerRequests.slice(-1)[0]?.auth}`);
check('C-12b the decrypted key never appears in the response body',
  !JSON.stringify(j).includes('sk-USER-A-own-provider-key'), JSON.stringify(j).slice(0, 120));
const callsBefore = ncb.requests.length;
const usedBefore = usageRow('202')?.calls_used ?? 0;
r = await CHAT_WITH('tok-a', { baseUrl, credentialId: 32 }); j = await readBody(r);
check('C-13 naming ANOTHER account\'s credential id is refused with 403, identically to "no such row"',
  r.status === 403 && j.code === 'CREDENTIAL_FORBIDDEN', JSON.stringify(j));
check('C-13b that refusal charged no quota, contacted no provider, and wrote nothing',
  world.providerCalls === providerBefore + 1
  && (usageRow('202')?.calls_used ?? 0) === usedBefore
  && !ncb.requests.slice(callsBefore).some((q) => /update|create|delete/.test(q.pathname) && q.pathname.includes('ai_quota')),
  ncb.requests.slice(callsBefore).map((q) => `${q.method} ${q.pathname}`).join(' | ').slice(0, 200));
r = await CHAT_WITH('tok-c', { baseUrl, credentialId: 99999 }); j = await readBody(r);
check('C-14 an id belonging to nobody is refused, and the answer is indistinguishable from C-13',
  r.status === 403 && j.code === 'CREDENTIAL_FORBIDDEN', JSON.stringify(j));
resetCreds([
  { id: 41, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: A_SECRET, usage: 'gameplay' },
  { id: 42, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: A_SECRET, usage: 'gameplay' }
]);
r = await fetch(`${B}/ai/credentials`, PUTJSON('tok-a', { usage: 'gameplay', provider: 'alibaba', model: 'qwen-turbo', endpoint: baseUrl }));
j = await readBody(r);
check('C-15 duplicate rows for one (user, usage) refuse the write instead of picking one',
  r.status === 503 && j.status === 'ai_credentials_unavailable' && j.error === 'credential_duplicate',
  JSON.stringify(j));
resetCreds([
  { id: 41, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: A_SECRET, usage: 'gameplay' },
  { id: 42, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: A_SECRET, usage: 'gameplay' }
]);
r = await CHAT_WITH('tok-a', { baseUrl, credentialId: 41 });
check('C-15b a chat naming one of two duplicates is served, because the id resolves uniquely',
  r.status === 200, String(r.status));
// Deployment-skew guard: the shipped bundle still sends the inline blob, and must keep working
// until it is replaced. This is the ONLY reason the inline branch exists.
resetCreds([]);
seed();
const before = usageRow('101')?.calls_used ?? 0;
r = await CHAT_WITH('tok-a', { baseUrl, encryptedApiKey: A_SECRET });
check('C-16 the inline ciphertext path still works, so deploying NodeSend first cannot break AI',
  r.status === 200 && (usageRow('101')?.calls_used ?? 0) === before + 1, `status=${r.status}`);
r = await CHAT_WITH('tok-a', { baseUrl, encryptedApiKey: A_SECRET }, 'cred-key-1');
const dup = await CHAT_WITH('tok-a', { baseUrl, encryptedApiKey: A_SECRET }, 'cred-key-1');
check('C-17 quota and idempotency are unchanged on the new path (one decision, one charge)',
  r.status === 200 && dup.status === 200
  && (usageRow('101')?.calls_used ?? 0) === before + 2, `used=${usageRow('101')?.calls_used}`);
// B was deliberately NOT migrated. Assert the consequence rather than the intention: no route
// here reads the system credential table, so nothing in this change pretends to server-only.
check('C-18 no route in this relay reads or writes system_ai_credentials (B deferred, not half-done)',
  !/system_ai_credentials/.test(bridgeSrcTextForCredCheck())
  && !ncb.requests.some((q) => String(q.pathname || '').includes('system_ai_credentials')),
  `${ncb.requests.filter((q) => String(q.pathname || '').includes('system_ai_credentials')).length} touches`);
// ── 6 of the next spec: no nested-ciphertext grace, because this key size cannot produce one ─
// There is deliberately NO compatibility branch for a double-encrypted blob. This is the
// measurement that justifies its absence rather than a judgement call: the deployed relay key is
// 3072-bit, so RSA-OAEP/SHA-256 carries at most 318 bytes through it while the base64 of one of
// its OWN ciphertexts is 512. An old bundle that read a repaired row therefore cannot re-encrypt
// it at all — the WebCrypto call throws inside the page, loudly, instead of sending a nested
// blob this relay would have to unfold and trust. Keeping a branch for an unreachable input
// would add a 403 path, an ownership lookup and a permanent "temporary" marker to the hot path
// for a case that cannot occur; if the key is ever rotated large enough for it to become
// reachable, the arithmetic below is what has to change, and this check is what fails first.
const OWN_PLAIN_KEY = 'sk-OWN-ACCOUNT-REAL-PROVIDER-KEY-7a3b';
resetCreds([{ id: 81, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: enc(OWN_PLAIN_KEY), usage: 'gameplay' }]);
const ownCiphertext = ncb.rows.ai_provider_credentials_1770000000[0].encrypted_api_key;
let nested = { possible: true, code: '' };
try { enc(ownCiphertext); } catch (error) { nested.possible = false; nested.code = error.code || error.message; }
check('K-1 a stored ciphertext cannot be re-encrypted through this key, so no nested-input grace is needed',
  nested.possible === false && /DATA_TOO_LARGE_FOR_KEY_SIZE/i.test(nested.code)
  && ownCiphertext.length > 318,
  'ciphertext is ' + ownCiphertext.length + ' chars against this 2048-bit harness key (carry 214); '
  + 'the deployed key measures 3072-bit (carry 318, its own ciphertext 512) — impossible on either',
  nested.code);
check('K-2 the relay contains no nested-ciphertext compatibility branch, and none can reappear silently',
  !/LEGACY_DEPLOYMENT_SKEW|resolveLegacyNestedKey|legacy_nested_ciphertext_served/.test(bridgeSrcTextForCredCheck()),
  're-adding the branch without re-running the key-size argument above fails here by construction');
const k3Calls = world.providerCalls;
r = await CHAT_WITH('tok-a', { baseUrl, encryptedApiKey: enc(OWN_PLAIN_KEY) });
check('K-3 the ordinary single-decrypt inline path is unaffected by all of this',
  r.status === 200 && world.providerCalls === k3Calls + 1
  && world.providerRequests.slice(-1)[0].auth === 'Bearer ' + OWN_PLAIN_KEY,
  'status=' + r.status);
check('K-4 the provider request carries only provider fields — no id, ciphertext, user id or table name',
  !JSON.stringify(world.providerRequests.slice(-1)[0].body).match(/credentialId|encryptedApiKey|user_id|ai_provider_credentials/)
  && !JSON.stringify(world.providerRequests.slice(-1)[0].headers).match(/credentialId|encryptedApiKey/)
  && Object.keys(world.providerRequests.slice(-1)[0].body).sort().join(',') === 'messages,model',
  'body keys=' + Object.keys(world.providerRequests.slice(-1)[0].body).join(','));

// ── legacy plaintext repair (§3) ───────────────────────────────────────────
// The emergency this exists for: rows written before the credential routes hold the provider
// key as PLAINTEXT, under a policy every session can read. Repair happens on the OWNER's use,
// on the SAME row, and refuses to continue when the repair cannot be confirmed.
const LEGACY_PLAINTEXT = 'sk-LEGACY-PLAINTEXT-PROVIDER-KEY-9d1e';
resetCreds([
  { id: 51, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: LEGACY_PLAINTEXT, usage: 'gameplay' },
  { id: 52, user_id: '202', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: LEGACY_PLAINTEXT, usage: 'gameplay' }
]);
seed();
const legacyCallsBefore = world.providerCalls;
const legacyUpdatesAt = () => ncb.requests.filter((q) => q.pathname === `/data/update/ai_provider_credentials_1770000000/51`).length;
r = await CHAT_WITH('tok-a', { baseUrl, credentialId: 51 });
check('L-1 the owner of a legacy plaintext row can still use it, and the provider gets the real key',
  r.status === 200 && world.providerCalls === legacyCallsBefore + 1
  && world.providerRequests.slice(-1)[0].auth === `Bearer ${LEGACY_PLAINTEXT}`,
  `status=${r.status}`);
const repairedRow = ncb.rows.ai_provider_credentials_1770000000.find((x) => x.id === 51);
check('L-2 the stored value is no longer the plaintext, and it is decryptable ciphertext',
  repairedRow.encrypted_api_key !== LEGACY_PLAINTEXT
  && mod.storedValueIsCiphertext(repairedRow.encrypted_api_key) === true
  && mod.encryptProviderApiKeyLocal(LEGACY_PLAINTEXT) !== repairedRow.encrypted_api_key,
  'ciphertext is RSA-OAEP; a fresh encryption differs per padding, so equality is not the test');
check('L-3 the repair rewrote the SAME row and created no second credential',
  ncb.rows.ai_provider_credentials_1770000000.filter((x) => String(x.user_id) === '101').length === 1
  && legacyUpdatesAt() === 1, `update calls to row 51: ${legacyUpdatesAt()}`);
const usedAfterFirst = usageRow('101')?.calls_used;
r = await CHAT_WITH('tok-a', { baseUrl, credentialId: 51 });
check('L-4 the repair is idempotent: the second use needs no further write',
  r.status === 200 && legacyUpdatesAt() === 1, `update calls now: ${legacyUpdatesAt()}`);
check('L-4b and the second use still charged exactly one call (no silent freebie)',
  (usageRow('101')?.calls_used ?? 0) === (usedAfterFirst ?? 0) + 1,
  `used=${usageRow('101')?.calls_used}`);
check('L-5 the plaintext never appeared in a response, a log line, or the stored row afterwards',
  !JSON.stringify(r).includes(LEGACY_PLAINTEXT)
  && !seenBodies.some((t) => t.includes(LEGACY_PLAINTEXT))
  && !logs.some((line) => line.includes(LEGACY_PLAINTEXT))
  && repairedRow.encrypted_api_key !== LEGACY_PLAINTEXT,
  `${logs.length} logs / ${seenBodies.length} bodies searched`);
// A stranger cannot cause a repair of somebody else's row — and the row must stay untouched.
const otherRow = ncb.rows.ai_provider_credentials_1770000000.find((x) => x.id === 52);
r = await CHAT_WITH('tok-a', { baseUrl, credentialId: 52 });
check('L-6 a non-owner naming a legacy row is refused and that row is not rewritten',
  r.status === 403 && otherRow.encrypted_api_key === LEGACY_PLAINTEXT
  && !ncb.requests.some((q) => q.pathname === '/data/update/ai_provider_credentials_1770000000/52'),
  `status=${r.status} still=${otherRow.encrypted_api_key === LEGACY_PLAINTEXT}`);
// Repair write failure ⇒ fail CLOSED. The provider must not be contacted and no unit spent.
resetCreds([{ id: 53, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: LEGACY_PLAINTEXT, usage: 'gameplay' }]);
// `seed()` clears the fault (and the request log), so the fault is armed AFTER it. Setting it
// first looked correct and tested nothing at all — the failure L-7 exists to prove was simply
// never armed, and the call went through and succeeded.
seed();
ncb.fault = 'credential_update_fail';
const failClosedCalls = world.providerCalls;
const failClosedUsed = usageRow('101')?.calls_used ?? 0;
r = await CHAT_WITH('tok-a', { baseUrl, credentialId: 53 });
j = await readBody(r);
ncb.fault = null;
check('L-7 a failed repair fails CLOSED: 503, no provider call, no quota charged',
  r.status === 503 && world.providerCalls === failClosedCalls
  && (usageRow('101')?.calls_used ?? 0) === failClosedUsed
  && j.code === 'CREDENTIAL_UNAVAILABLE',
  `status=${r.status} provider=${world.providerCalls - failClosedCalls} used=${(usageRow('101')?.calls_used ?? 0) - failClosedUsed}`);
check('L-7b the row is still plaintext after the failed repair, so it stays eligible for one',
  ncb.rows.ai_provider_credentials_1770000000.find((x) => x.id === 53).encrypted_api_key === LEGACY_PLAINTEXT,
  'no partial state, no flag, no destroyed credential');
// The §7 leak: only config.credentialId is a channel. A top-level id must be inert, because
// `buildProviderBody` forwards top-level fields to the provider.
resetCreds([{ id: 61, user_id: '101', provider: 'alibaba', model: 'qwen3.8-flash', endpoint: baseUrl, encrypted_api_key: A_SECRET, usage: 'gameplay' }]);
r = await fetch(`${B}/ai/chat`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' },
  body: JSON.stringify({
    provider: 'alibaba', config: { baseUrl }, model: 'qwen3.8-flash', credentialId: 61,
    messages: [{ role: 'user', content: 'hi' }]
  })
});
check('L-8 a TOP-LEVEL credentialId is not a second channel and cannot spend a credential',
  r.status === 400, `status=${r.status}`);
r = await CHAT_WITH('tok-a', { baseUrl, credentialId: 61 });
const leakedId = world.providerRequests.slice(-1).some((q) => JSON.stringify(q.body).includes('credentialId')
  || JSON.stringify(q.headers).includes('credentialId'));
check('L-9 credentialId never reaches the provider request body or headers',
  r.status === 200 && !leakedId,
  JSON.stringify(Object.keys(world.providerRequests.slice(-1)[0]?.body || {})));

function bridgeSrcTextForCredCheck() {
  return fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^[ \t]*\/\/.*$/gm, ' ');
}
const bridgeSrc = fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8');
const codeOnly = bridgeSrc.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^[ \t]*\/\/.*$/gm, ' ');
const dupes = (() => {
  const seen = new Map();
  for (const line of codeOnly.split('\n')) {
    const m = line.match(/^(?:async\s+)?function\s+([A-Za-z0-9_$]+)/) || line.match(/^const\s+([A-Za-z0-9_$]+)\s*=/) || line.match(/^let\s+([A-Za-z0-9_$]+)\s*=/);
    if (m) seen.set(m[1], (seen.get(m[1]) || 0) + 1);
  }
  return [...seen.entries()].filter(([, n]) => n > 1).map(([k, n]) => `${k}x${n}`);
})();
check('T22 there is no second copy of any quota decision function or state map',
  dupes.length === 0, dupes.join(','));
check('T22 exactly one mutex map and one ledger map exist',
  (codeOnly.match(/const userLocks = new Map\(\)/g) || []).length === 1
  && (codeOnly.match(/const processLedger = new Map\(\)/g) || []).length === 1
  && (codeOnly.match(/withUserLock\s*\(/g) || []).length === 2,
  `userLocks=${(codeOnly.match(/const userLocks = new Map\(\)/g) || []).length} withUserLock=${(codeOnly.match(/withUserLock\s*\(/g) || []).length}`);
check('T22 exactly one writer path exists for the usage counter',
  (codeOnly.match(/\/data\/create\/\$\{QUOTA_TABLES\.usage\}/g) || []).length === 1
  && (codeOnly.match(/\/data\/update\/\$\{QUOTA_TABLES\.usage\}/g) || []).length === 1,
  `create=${(codeOnly.match(/\/data\/create\/\$\{QUOTA_TABLES\.usage\}/g) || []).length} update=${(codeOnly.match(/\/data\/update\/\$\{QUOTA_TABLES\.usage\}/g) || []).length}`);
check('T22 exactly one reservation ledger path exists',
  (codeOnly.match(/\/data\/create\/\$\{QUOTA_TABLES\.reservation\}/g) || []).length === 1
  && (codeOnly.match(/\/data\/read\/\$\{QUOTA_TABLES\.reservation\}/g) || []).length === 1
  && (codeOnly.match(/\/data\/delete\/\$\{QUOTA_TABLES\.reservation\}/g) || []).length === 1, '');
check('T22 there is one quota decision entry point, and the route adapters only wrap it',
  (codeOnly.match(/async function reserveQuotaDecision/g) || []).length === 1
  && (codeOnly.match(/async function reserveAiCall/g) || []).length === 1
  && (codeOnly.match(/reserveQuotaDecision\(req, req\.bridgeUser\)/g) || []).length === 1
  && (codeOnly.match(/quotaStatusDecision\(req, req\.bridgeUser\)/g) || []).length === 1
  && (codeOnly.match(/withUserLock\(/g) || []).length === 2,
  `locks=${(codeOnly.match(/withUserLock\(/g) || []).length}`);

// ── 11. secret and leak hygiene ───────────────────────────────────────────
seed();
logs.length = 0;
world.providerRequests.length = 0;
const SECRET_KEY = 'decision-key-DO-NOT-LEAK-4d1c';
r = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY(SECRET_KEY)));
const chatBody = await r.text();
check('T17 the decision key never reaches the provider request body',
  world.providerRequests.every((q) => !q.raw.includes(SECRET_KEY) && !JSON.stringify(q.body).includes(SECRET_KEY)),
  world.providerRequests.map((q) => q.raw.slice(0, 60)).join(' | '));
check('T17 the decision key never reaches the provider request headers',
  world.providerRequests.every((q) => !Object.keys(q.headers).some((h) => /decision/i.test(h))
    && !Object.values(q.headers).some((v) => String(v).includes(SECRET_KEY))),
  JSON.stringify(world.providerRequests.map((q) => Object.keys(q.headers))));
check('T17 the provider is authenticated by the provider key, never the user bearer',
  world.providerRequests.length > 0 && world.providerRequests.every((q) => q.auth === `Bearer ${PROVIDER_SECRET}`),
  world.providerRequests.map((q) => q.auth.slice(0, 10)).join(','));
check('T17 the key is not echoed back in the response', !chatBody.includes(SECRET_KEY), chatBody.slice(0, 80));
check('T17 the key is not logged', !logs.join('\n').includes(SECRET_KEY), logs.filter((l) => /decision/.test(l)).join(' | ').slice(0, 120));
check('the reservation is the only place the key is written, to our own storage',
  ncb.requests.some((q) => q.pathname === '/data/create/ai_quota_reservation' && q.body?.decision_key === SECRET_KEY)
  && ncb.requests.filter((q) => JSON.stringify(q.body || {}).includes(SECRET_KEY)).length === 1,
  ncb.requests.filter((q) => JSON.stringify(q.body || {}).includes(SECRET_KEY)).map((q) => q.pathname).join(' | '));
const probes = await Promise.all([
  fetch(`${B}/ai/quota`, AUTH('tok-admin')).then((x) => x.text()),
  fetch(`${B}/ai/quota/config`, AUTH('tok-admin')).then((x) => x.text()),
  fetch(`${B}/ai/quota/config`, AUTH('tok-a')).then((x) => x.text()),
  fetch(`${B}/health`).then((x) => x.text()),
  fetch(`${B}/`).then((x) => x.text()),
  fetch(`${B}/crypto/public-key`).then((x) => x.text()),
  fetch(`${B}/nope`).then((x) => x.text())
]);
check('every probe returned a body to inspect', probes.length === 7 && probes.every((t) => typeof t === 'string' && t.length > 0), '');
const leaked = probes.map((t, i) => LEAK_STRINGS.filter((s) => t.includes(s)).map((s) => `${i}:${s}`)).flat();
check('no response body carries a bearer, a session token or a provider key', leaked.length === 0, leaked.join(','));
const blob = logs.join('\n');
check('no bearer token or provider secret appears in any log line',
  !blob.includes('tok-a') && !blob.includes('tok-admin') && !blob.includes(PROVIDER_SECRET),
  blob.split('\n').find((l) => /tok-|sk-REAL/.test(l))?.slice(0, 100) || '');
check('no log line names a table, a row id or the storage host',
  !STORAGE_STRINGS.some((s) => blob.includes(s)) && !blob.includes(NCB_BASE) && !/row_id|rowId/.test(blob),
  blob.split('\n').find((l) => STORAGE_STRINGS.some((s) => l.includes(s)))?.slice(0, 120) || '');
check('no log line carries the decision key of any request',
  !blob.includes(SECRET_KEY) && !/decision_key/.test(blob), blob.split('\n').find((l) => /decision/.test(l))?.slice(0, 120) || '');
const canary = `[NodeSend] quota_audit ${JSON.stringify({ decision_key: SECRET_KEY, table: 'ai_quota_usage', authorization: 'Bearer tok-a' })}`;
check('the leak detectors fire on a planted leak (positive control)',
  LEAK_STRINGS.some((s) => canary.includes(s)) && STORAGE_STRINGS.some((s) => canary.includes(s)) && leaked.length === 0, '');
check('the key never appears in a provider URL', world.providerRequests.every((q) => !q.url.includes(SECRET_KEY)), '');

// ── 12. relay invariants that must survive the move ───────────────────────
r = await fetch(`${B}/send`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
check('/send still 403 without x-api-key', r.status === 403, `status=${r.status}`);
r = await fetch(`${B}/rocketchat`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'server-only-bridge-key' }, body: JSON.stringify({ text: 'x' }) });
check('/rocketchat still accepts x-api-key', r.status !== 403 && r.status !== 401, `status=${r.status}`);
r = await fetch(`${B}/quota`, { headers: { Authorization: 'Bearer tok-a' } });
check('generic /quota unchanged (403 without key)', r.status === 403, `status=${r.status}`);
r = await fetch(`${B}/quota`, { headers: { 'x-api-key': 'server-only-bridge-key' } });
check('generic /quota still fails closed when its own service is unconfigured', r.status === 503, `status=${r.status}`);
check('the generic server-account adapter is still a separate surface',
  /NODESEND_QUOTA_URL/.test(codeOnly) && /quotaHandler/.test(codeOnly)
  && codeOnly.indexOf('NODESEND_QUOTA_URL') < codeOnly.indexOf('const QUOTA_TABLES'), '');
const beforeBadJson = ncb.requests.length;
r = await fetch(`${B}/ai/chat`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-a' }, body: '{"not json' });
check('a malformed JSON body is refused without touching quota',
  r.status === 400 && ncb.requests.length === beforeBadJson, `status=${r.status} newCalls=${ncb.requests.length - beforeBadJson}`);
check('the reservation outcome is a header, never a body field',
  !chatBody.includes('"reservation"') && !chatBody.includes('"claim"'), chatBody.slice(0, 60));
const granted = await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('header-shape')));
check('a charged call reports created and a retry reports reused on the header',
  granted.headers.get('x-quota-reservation') === 'created', String(granted.headers.get('x-quota-reservation')));
const reuseHeader = (await fetch(`${B}/ai/chat`, CHAT('tok-a', {}, KEY('header-shape')))).headers.get('x-quota-reservation');
check('the outcome header is exposed to a browser reader',
  reuseHeader === 'reused', String(reuseHeader));

// ── 13. source gates: the external hop must not come back ─────────────────
check('T23 BRIDGEMIND_QUOTA_URL appears nowhere in the relay source',
  !/BRIDGEMIND_QUOTA_URL/.test(bridgeSrc), (bridgeSrc.match(/BRIDGEMIND_QUOTA_URL/g) || []).length + ' hits');
const envExample = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
check('T23 BRIDGEMIND_QUOTA_URL is gone from .env.example',
  !/BRIDGEMIND_QUOTA_URL/.test(envExample), (envExample.match(/BRIDGEMIND_QUOTA_URL/g) || []).length + ' hits');
const bannedAdapterNames = ['bridgemindQuotaEndpoint', 'bridgemindQuotaConfigured', 'quotaServiceState',
  'markQuotaServiceOk', 'markQuotaServiceUnavailable', 'requestQuotaService', 'sanitizeQuotaDecision',
  'isQuotaCount', 'QUOTA_DENIAL_REASONS', 'QUOTA_SERVICE_CODES', 'unavailableQuotaSummary',
  'QUOTA_RESERVE_ROUTE', 'QUOTA_STATUS_ROUTE', 'QUOTA_CONFIG_ROUTE', 'QUOTA_PUBLIC_FIELDS',
  'quotaServiceUnavailable', 'quotaConfigRejected', 'QUOTA_DECISION_AUTHORITY'];
const adapterHits = bannedAdapterNames.filter((n) => bridgeSrc.includes(n));
check('T24 no external quota adapter symbol survives anywhere in the file',
  adapterHits.length === 0, adapterHits.join(','));
check('T24 the source contains no bare /reserve, /status or /config route literal',
  !/"\/(reserve|status|config)"/.test(codeOnly), (codeOnly.match(/"\/(reserve|status|config)"/g) || []).join(','));
// Every place this file talks to another machine, named. A new outbound call site is how a
// second quota hop would sneak back in, so the list is asserted to be exactly the four
// legitimate transports rather than merely "not too many".
const fetchTargets = (codeOnly.match(/fetch\(\s*[^,{)\s]+/g) || []).map((s) => s.replace('fetch(', '').trim());
// The token is cut at the first `,` `)` `{` or space, so `buildNcbUrl(path)` reads as
// `buildNcbUrl(path` — the name of the transport is what identifies it, not its argument.
// UPDATED 2026-10-05, disclosed old→new. This check listed FOUR sites and asserted exact
// set equality, so the invitation route's anonymous NCB read was a legitimate fifth. The set
// is now five named transports — the count is still exact, nothing is admitted by pattern, and
// a sixth site still fails this check. What was ADDED is the important half: the new site is
// pinned below as provably credential-free, which is a stronger claim than the four-site list
// ever made.
const KNOWN_TRANSPORTS = [
  'ROCKETCHAT_WEBHOOK_URL', 'buildNcbUrl(path', 'buildNcbPublicUrl(path', 'quotaUrl.href', 'url'
];
check('T24 the outbound call sites are the five known transports only (NCB authenticated, NCB anonymous public, provider, generic adapter, webhook)',
  fetchTargets.slice().sort().join(',') === KNOWN_TRANSPORTS.slice().sort().join(','),
  fetchTargets.join(' | '));
// The property that makes the fifth site safe: an anonymous read must stay anonymous. A
// `buildNcbPublicUrl` that also forwarded `Authorization` would turn the pre-registration
// route into a bearer-presenting one, so this is asserted on the function body, not assumed
// from its name.
const publicTransportBody = (bridgeSrc.match(/async function ncbPublicRead[\s\S]*?\n\}/) || [''])[0];
check('T24 the public transport can present no credential of any kind',
  publicTransportBody.length > 0
  && !/authorization|bearer|getBearerToken/i.test(publicTransportBody)
  && /fetch\(buildNcbPublicUrl\(path\)/.test(publicTransportBody),
  `public transport body chars: ${publicTransportBody.length}, bearer mentions: ${(publicTransportBody.match(/authorization|bearer|getBearerToken/gi) || []).length}`);
// The runtime half of the same claim, and the stronger one: whatever the source says, these
// are the machines this run actually sent bytes to. Nothing else is reachable — the stub
// throws for any other host, so an accidental production call would fail the run outright.
const NCB_HOST = new URL(NCB_BASE).host;
const RELAY_HOST = new URL(B).host;
const TRICKSTER_DECOY = '127.0.0.1:1';
const outboundHosts = [...new Set(world.outboundUrls.map((u) => { try { return new URL(u).host; } catch { return `unparseable:${u}`; } }))].sort();
check('T24 the only hosts contacted all run are the mock NCB, the provider, the decoy and the relay itself',
  outboundHosts.join(',') === [NCB_HOST, 'dashscope.aliyuncs.com', TRICKSTER_DECOY, RELAY_HOST].sort().join(','),
  outboundHosts.join(','));
check('T24 no outbound URL of this run is a quota service endpoint',
  !world.outboundUrls.some((u) => /\/(reserve|status|config)(\?|$)/.test(u) && !u.includes('/ai/quota')),
  world.outboundUrls.filter((u) => /\/(reserve|status|config)/.test(u)).join(' | ').slice(0, 200));
check('T24 nothing in this gate or the relay still calls a BridgeMind backend',
  !/bridgemindQuota|BRIDGEMIND_QUOTA|api\.bridgemind\.app\/(reserve|status|config)/.test(bridgeSrc + envExample), '');
check('the quota tables are named once each, from env with a documented default',
  ['ai_quota_config', 'ai_quota_user_override', 'ai_quota_usage', 'ai_quota_reservation'].every((t) => {
    const count = (bridgeSrc.match(new RegExp(`"${t}"`, 'g')) || []).length;
    return count === 1;
  }), JSON.stringify(['ai_quota_config', 'ai_quota_user_override', 'ai_quota_usage', 'ai_quota_reservation'].map((t) => `${t}:${(bridgeSrc.match(new RegExp(`"${t}"`, 'g')) || []).length}`)));
// Counted as env READS, not as mentions: the reservation name also appears inside the
// startup warning's text, and that mention has nothing to do with the wiring being checked.
const quotaEnvReads = [...new Set(codeOnly.match(/process\.env\.AI_QUOTA_[A-Z_]+/g) || [])].map((s) => s.split('.').pop());
check('the four table names are configurable by env, and no fifth table is addressed',
  quotaEnvReads.slice().sort().join(',') === ['AI_QUOTA_CONFIG_TABLE', 'AI_QUOTA_RESERVATION_TABLE', 'AI_QUOTA_USAGE_TABLE', 'AI_QUOTA_USER_OVERRIDE_TABLE'].sort().join(','),
  quotaEnvReads.join(','));
check('no SQL or DDL is issued from the relay',
  !/\b(CREATE TABLE|ALTER TABLE|DROP TABLE|TRUNCATE|ON CONFLICT|INSERT INTO|UPSERT)\b/i.test(codeOnly)
  && !/\bSELECT\b[\s\S]{0,60}\bFROM\b/i.test(codeOnly), '');
// UNCHANGED IN COUNT, EXTENDED IN SCOPE. The pin below still requires exactly THREE
// awaited `ncbRequest` sites (session, quota read, quota write). The authoritative
// AI-source lookup added no fourth one: it goes through the same read-only `quotaRead`
// the config, override and usage reads already use, so the transport surface did not
// grow — only the set of tables the read helper may touch. Because a new table is now
// reachable, this check additionally pins that the new one is READ-ONLY from this
// process, which is the property that actually matters: the relay never writes a
// player's AI source, so it cannot talk itself out of a bill.
const sourceAwaits = (codeOnly.match(/await ncbRequest\(/g) || []).length;
check('there is one NCB transport, still three call sites, and user_settings is reachable only by reading',
  (codeOnly.match(/async function ncbRequest/g) || []).length === 1
  && sourceAwaits === 3
  && (codeOnly.match(/ncbRequest\(req, "\/auth\/get-session"/g) || []).length === 1
  && /quotaRead\(req,\s*`\/data\/read\/\$\{USER_SETTINGS_TABLE\}/.test(codeOnly)
  && (codeOnly.match(/\/data\/(create|update|delete)\/\$\{USER_SETTINGS_TABLE\}/g) || []).length === 0
  // The source table is not folded into the write helper at all.
  && !/USER_SETTINGS_TABLE/.test((codeOnly.match(/quotaWrite\(req[^)]*\)/g) || []).join(' ')),
  `awaits=${sourceAwaits} (expected 3: session, read, write) sourceReadOnly=${/quotaRead\(req,\s*`\/data\/read\/\$\{USER_SETTINGS_TABLE\}/.test(codeOnly)}`);
check('no NCB service credential exists or is invented',
  !/NCB_SERVICE_TOKEN|NCB_ADMIN_TOKEN|NCB_API_KEY|NCB_BEARER|QUOTA_DATABASE_URL|DATABASE_URL/.test(codeOnly)
  && [...new Set(codeOnly.match(/NCB_[A-Z_]+/g) || [])].sort().join(',') === 'NCB_INSTANCE,NCB_PROXY_BASE,NCB_TIMEOUT_MS',
  [...new Set(codeOnly.match(/NCB_[A-Z_]+/g) || [])].join(','));
// Exactly two bearer expressions in the whole file: the caller's own session token, and the
// provider key the caller supplied. Anything else would be a credential this relay holds.
const bearerExpressions = (codeOnly.match(/Authorization: `Bearer \$\{[^}]*\}/g) || []).map((s) => s.replace(/\s+/g, ' ')).sort();
check('the only two bearers this relay puts on a request are the caller session token and the provider key',
  bearerExpressions.length === 2
  // The captured literal ends at the `}` of the interpolation, so the closing paren of the
  // call is outside the match: test for the function, not for its balanced brackets.
  && bearerExpressions.some((s) => /getBearerToken\(req/.test(s))
  && bearerExpressions.some((s) => /\$\{apiKey\}/.test(s))
  // SCREAMING_SNAKE is how a module-level credential is named here; `getBearerToken` is a
  // function reading the request, so a case-insensitive /TOKEN/ test would flag the very
  // thing this check exists to require.
  && !bearerExpressions.some((s) => /process\.env|_[A-Z0-9_]*TOKEN/.test(s)), bearerExpressions.join(' | '));
check('the caller bearer is the only credential the NCB transport can carry',
  (codeOnly.match(/Authorization: `Bearer \$\{getBearerToken\(req\)\}`/g) || []).length === 1
  && /headers: \{[\s\S]{0,120}getBearerToken\(req\)/.test(codeOnly)
  && !/getBearerToken\(req\)[\s\S]{0,400}process\.env/.test(codeOnly.match(/async function ncbRequest[\s\S]{0,400}/)[0] || ''), '');
// UNCHANGED IN SUBSTANCE, made precise: who a call is BILLABLE to still comes only
// from the validated session, and no chat, relay or quota-decision path may read a user
// id from the request. The two administrator per-user routes do read a TARGET id — that
// is their whole purpose — so the exemption is carved out by name and bounded, rather
// than the rule being relaxed to "whatever appears somewhere". A non-admin cannot reach
// those handlers at all (session + role guard, asserted separately), so a target id can
// never redirect a charge.
const adminHandlerBodies = ['quotaAdminStatusHandler', 'quotaAdminLimitHandler']
  .map((name) => (codeOnly.match(new RegExp(`async function ${name}\\([\\s\\S]*?\\n\\}`, 'u')) || [''])[0]);
const codeOutsideAdminTargets = codeOnly
  .split('\n')
  .filter((line) => !adminHandlerBodies.some((body) => body.includes(line)))
  .join('\n');
check('identity for billing is the session only; a request-supplied target id exists in no other path',
  /req\.bridgeUser\?\.id/.test(codeOnly)
  && !/req\.body\??\.user_id|req\.query\??\.user_id|query\.user_id/.test(codeOutsideAdminTargets)
  // the ledger and the reservation still take the id from the session user
  && !/user_id:\s*req\.(body|query)/.test(codeOnly)
  // and the target is only ever read inside the two handlers that are role-guarded
  && adminHandlerBodies.every((body) => /user_id/.test(body)),
  `leaks outside the admin handlers: ${(codeOutsideAdminTargets.match(/req\.body\??\.user_id|req\.query\??\.user_id|query\.user_id/g) || []).join(', ') || 'none'}`);
check('the session and admin guards are attached to all six AI surfaces',
  /app\.post\("\/ai\/models",\s*requireBridgeSession/.test(codeOnly)
  && /app\.post\("\/ai\/test",\s*requireBridgeSession/.test(codeOnly)
  && /app\.post\("\/ai\/chat",\s*requireBridgeSession,\s*\(req, res\) => relayAI\(req, res, "chat"\)/.test(codeOnly)
  && /app\.get\("\/ai\/quota",\s*requireBridgeSession/.test(codeOnly)
  && /app\.get\("\/ai\/quota\/config",\s*requireBridgeSession,\s*requireBridgeAdmin/.test(codeOnly)
  && /app\.put\("\/ai\/quota\/config",\s*requireBridgeSession,\s*requireBridgeAdmin/.test(codeOnly), '');
// The chat dispatch is the LAST requestProvider call in the file — the models path has one
// earlier — so the ordering claim is pinned with lastIndexOf, which is the only form that
// actually states it. Model validation must also precede the spend.
check('the reservation happens inside relayAI after credentials and model validation, before dispatch',
  codeOnly.indexOf('if (typeof model !== "string" || !model.trim())') < codeOnly.indexOf('reservation = await reserveAiCall(req, res)')
  && codeOnly.indexOf('resolvedApiKey = resolveProviderApiKey(config)') < codeOnly.indexOf('reservation = await reserveAiCall(req, res)')
  && codeOnly.indexOf('reservation = await reserveAiCall(req, res)') < codeOnly.lastIndexOf('result = await requestProvider({'),
  JSON.stringify({ model: codeOnly.indexOf('if (typeof model !== "string"'), creds: codeOnly.indexOf('resolvedApiKey = resolveProviderApiKey'), reserve: codeOnly.indexOf('reservation = await reserveAiCall'), dispatch: codeOnly.lastIndexOf('result = await requestProvider({') }));
check('T25 the single-replica invariant is stated once in code and printed three times',
  (bridgeSrc.match(/exactly-one-quota-service-replica/g) || []).length === 1
  && /QUOTA_SINGLE_REPLICA_INVARIANT/.test(codeOnly)
  && /quotaLedgerState\(\)/.test(codeOnly) && /quotaLedgerFields\(\)/.test(codeOnly),
  `literal=${(bridgeSrc.match(/exactly-one-quota-service-replica/g) || []).length}`);
check('the relay never claims multi-replica safety',
  !/multi-?replica (?:quota )?(?:counting )?safe|safe across replicas|replica-?safe|horizontally scal/i.test(bridgeSrc),
  (bridgeSrc.match(/.{0,60}multi-?replica.{0,60}/i) || []).join(' | ').slice(0, 200));
check('startup states the invariant and the process-only warning exists',
  /quotaLedgerFields\(\)/.test(codeOnly) && /process\.emitWarning\(/.test(codeOnly)
  && /NodeSendQuotaIdempotencyProcessOnly/.test(codeOnly) && /quotaLedgerDurable/.test(codeOnly), '');
// Prose is matched with comment markers and wrapping removed: the same sentence split over
// two comment lines must pass, and a revived stale claim must fail however it is wrapped.
const proseOf = (s) => s.replace(/^#\s?/gm, '').replace(/^\s*\/\/\s?/gm, '').replace(/\s+/g, ' ');
const envProse = proseOf(envExample);
check('.env.example states the new architecture, not the retired one',
  /NodeSend is the only quota backend/.test(envProse) && /NCB is the application database owner/.test(envProse)
  && /BridgeMind is a static frontend/.test(envProse) && /no second backend hop/.test(envProse), '');
check('.env.example no longer says NodeSend holds no quota data or reads no table',
  !/NodeSend owns no quota data/i.test(envProse) && !/reads and writes no NCB table/i.test(envProse)
  && !/BridgeMind-owned quota/i.test(envProse) && !/does not exist yet/i.test(envProse), '');
check('.env.example documents all four quota tables and the reservation table by name',
  ['AI_QUOTA_CONFIG_TABLE', 'AI_QUOTA_USER_OVERRIDE_TABLE', 'AI_QUOTA_USAGE_TABLE', 'AI_QUOTA_RESERVATION_TABLE'].every((k) => envExample.includes(k))
  && envProse.includes('ai_quota_reservation'), [...new Set(envExample.match(/AI_QUOTA_[A-Z_]*TABLE/g) || [])].join(','));
check('.env.example documents the header as a billing label and explicitly not identity',
  /x-ai-decision-key: <logical decision key>/.test(envProse) && /BILLING label/.test(envProse)
  && /never authentication, never identity/.test(envProse), '');
check('.env.example states the single-replica requirement and that multi-replica counting is unsupported',
  /SINGLE REPLICATION REQUIRED/.test(envProse) && /no atomic increment/.test(envProse)
  && /Multi-replica quota counting is unsupported/.test(envProse), '');
check('.env.example keeps the two quota URLs clearly distinct',
  /NODESEND_QUOTA_URL has nothing to do with whether per-user quota works/.test(envProse), '');
check('.env.example still carries no database credential and no new secret',
  !/^DATABASE_URL|^BRIDGEMIND_QUOTA_DATABASE_URL|^AI_QUOTA_[A-Z_]*TOKEN/m.test(envExample), '');
check('no browser-visible quota variable exists',
  !/VITE_[A-Z_]*(QUOTA|NCB|DATABASE|BEARER|SESSION|BRIDGEMIND|AI_QUOTA)/i.test(envExample + bridgeSrc), '');
check('the retired store-shaped harnesses never came back',
  !fs.existsSync(path.join(ROOT, 'verify-postgres-quota.mjs')) && !fs.existsSync(path.join(ROOT, 'verify-ncb-quota.mjs')), '');

// ── 14. the startup line, measured from a real boot ───────────────────────
const bootProbe = async (extraEnv) => new Promise((resolve) => {
  const child = spawn(process.execPath, [path.join(ROOT, 'bridge.js')], {
    env: { ...process.env, PORT: '0', ...extraEnv }, cwd: ROOT
  });
  let stdout = '';
  let stderr = '';
  const finish = () => { try { child.kill(); } catch { /* already gone */ } resolve({ stdout, stderr }); };
  child.stdout.on('data', (d) => {
    stdout += d.toString();
    if (/startup/.test(stdout)) setTimeout(finish, 120);
  });
  child.stderr.on('data', (d) => { stderr += d.toString(); });
  child.on('exit', finish);
  setTimeout(finish, 4000);
});
// The startup line is `[NodeSend] startup {json}`; parsing it out is a function rather than
// an inline IIFE so a bad line yields {} instead of throwing the harness away.
const parseStartup = (line) => {
  const start = String(line).indexOf('{');
  if (start < 0) return {};
  try { return JSON.parse(String(line).slice(start)); } catch { return {}; }
};
const bootDurable = await bootProbe({});
const startupLine = (bootDurable.stdout.split('\n').find((l) => /startup/.test(l)) || '');
const startupJson = parseStartup(startupLine);
check('T25 a real boot prints authority nodesend, storage ncb, idempotency durable',
  startupJson.quotaAuthority === 'nodesend' && startupJson.quotaStorage === 'ncb'
  && startupJson.quotaIdempotency === 'durable'
  && startupJson.quotaReplicas === 'exactly-one-quota-service-replica'
  && startupJson.quotaMultiReplica === 'unsupported',
  startupLine.slice(0, 200));
check('T25 a durable boot raises no process-only warning',
  !/NodeSendQuotaIdempotencyProcessOnly/.test(bootDurable.stderr), bootDurable.stderr.slice(0, 160));
check('the startup line names no secret, no bearer and no storage host',
  !LEAK_STRINGS.some((s) => startupLine.includes(s)) && !startupLine.includes(NCB_BASE)
  && !STORAGE_STRINGS.some((s) => startupLine.includes(s)), startupLine.slice(0, 120));

// ── 15. the process-only variant, in its own process ──────────────────────
const variantReport = await new Promise((resolve) => {
  const child = spawn(process.execPath, [path.join(ROOT, 'verify-session-quota.mjs'), '--variant=process-only'], {
    env: { ...process.env, AI_QUOTA_RESERVATION_TABLE: '' }, cwd: ROOT
  });
  let out = '';
  let err = '';
  child.stdout.on('data', (d) => { out += d.toString(); });
  child.stderr.on('data', (d) => { err += d.toString(); });
  child.on('close', (code) => resolve({ code, out, err }));
  setTimeout(() => { try { child.kill(); } catch { /* gone */ } resolve({ code: -1, out, err }); }, 60000);
});
let variant = { passed: 0, total: 0, failed: 0, out: '' };
try {
  variant = JSON.parse(String(variantReport.out).trim().split('\n').pop());
} catch { variant = { passed: 0, total: 1, failed: 1, out: `child produced no report (code=${variantReport.code}) ${variantReport.out.slice(0, 120)} ${variantReport.err.slice(0, 200)}` }; }
for (const line of String(variant.out).split('\n')) { if (line.trim()) results.push({ name: line.slice(6).split('[')[0].trim() || line.trim(), pass: line.startsWith('PASS'), detail: (line.match(/\[(.*)\]/) || [])[1] || '' }); }
check('the process-only variant runs clean in its own process',
  variantReport.code === 0 && variant.failed === 0 && variant.total >= 3,
  JSON.stringify({ code: variantReport.code, passed: variant.passed, total: variant.total, out: variant.out.slice(0, 160) }));
const bootProcessOnly = await bootProbe({ AI_QUOTA_RESERVATION_TABLE: '', PORT: '0' });
const startupPo = parseStartup(bootProcessOnly.stdout.split('\n').find((x) => /startup/.test(x)) || '');
check('P-boot a process-only boot reports idempotency process-only, and does not claim durable',
  startupPo.quotaIdempotency === 'process-only' && startupPo.quotaAuthority === 'nodesend'
  && startupPo.quotaReplicas === 'exactly-one-quota-service-replica', JSON.stringify(startupPo));
check('P-boot a process-only boot warns about the restart window',
  /NodeSendQuotaIdempotencyProcessOnly/.test(bootProcessOnly.stderr)
  && /restart can charge the same/i.test(bootProcessOnly.stderr), bootProcessOnly.stderr.slice(0, 200));

console.log = realLog;
let failed = 0;
for (const x of results) {
  if (!x.pass) failed++;
  console.log(`${x.pass ? 'PASS' : 'FAIL'}  ${x.name}${x.detail ? '   [' + x.detail + ']' : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed  (variant=${VARIANT})`);
console.log('MOCKED: NCB (session authority AND the four ai_quota_* tables) and the AI provider are loopback');
console.log('fakes; the relay under test is the real exported app over a real socket. Two child processes boot');
console.log('bridge.js on port 0 to read the real startup line, and the process-only variant runs itself.');
console.log('NOT CONFIGURED ANYWHERE REAL: no production endpoint was contacted and no quota row was written.');
ncbServer.close();
try { app.close?.(); } catch { /* Express 4 has no app.close */ }
process.exit(failed ? 1 : 0);
