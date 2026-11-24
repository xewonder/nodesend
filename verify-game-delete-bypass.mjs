/*
 * NodeSend — GAME-RECORD RELAY DELETE BYPASS GATE
 *
 * Proves the authorization gap around `DELETE /games/:id` is closed on the GENERIC relay path, without
 * breaking the two player workflows that legitimately delete through that relay (recorder cancel,
 * community unpublish).
 *
 * THE MODEL THAT MAKES THIS A TEST AND NOT A THEATRE: the fake vendor deliberately implements
 * `shared_readwrite` AS THE VENDOR BEHAVES — no per-row isolation whatsoever. Any authenticated session
 * can read, update and delete ANY row in these tables by id. Control `X1` proves that directly: the same
 * cross-account delete that the GATEWAY refuses SUCCEEDS when the gateway is bypassed. If the fake
 * enforced ownership, every arm here would pass because of the mock, which is exactly the mistake the
 * 2026-11-18 `offset=` incident records. So the only thing standing between player B and player A's game
 * is the code under test.
 *
 * Nothing here contacts production, no real credential exists in the file, and the seal key is a fixture.
 *
 *   node verify-game-delete-bypass.mjs
 */
import http from 'node:http';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));

const USERS = {
  'a@poc.invalid': { password: 'pw-a', id: 'user-aaaa', role: 'user' },
  'b@poc.invalid': { password: 'pw-b', id: 'user-bbbb', role: 'user' },
  // A session the vendor labels `administrator`. Role from a session is NOT the system-admin authority
  // (that lives in `system_admins`), and it must not buy a cross-account delete on the relay either.
  'c@poc.invalid': { password: 'pw-c', id: 'user-cccc', role: 'administrator' }
};
const COOKIE_NAME = '__Secure-better-auth.session_token';
const sessions = new Map();
const TABLES = {
  recorded_hands: [],
  community_games: [],
  game_analysis_reports: [],
  replay_attempts: [],
  user_settings: []
};
let nextRowId = 100;
const upstream = { deletes: [], reads: 0 };
let faultRead = false;      // the vendor itself becomes unreadable
let knownColumns = true;    // model `user_id` being absent from a legacy row

// Deterministic ids: every re-seed produces the same rows, so an arm can never compare against a
// shifted identifier. Rows are also looked up by MARKER rather than by index, because a successful
// deletion shrinks the array and a positional accessor would then describe a different row.
function seed() {
  nextRowId = 100;
  TABLES.recorded_hands = [
    { id: String(nextRowId++), user_id: 'user-aaaa', marker: 'A-own-game' },
    { id: String(nextRowId++), user_id: 'user-bbbb', marker: 'B-own-game' },
    { id: String(nextRowId++), user_id: null, marker: 'legacy-row-no-owner' }
  ];
  TABLES.community_games = [
    { id: String(nextRowId++), user_id: 'user-aaaa', source_hand_id: '100' },
    { id: String(nextRowId++), user_id: 'user-bbbb', source_hand_id: '101' }
  ];
  TABLES.game_analysis_reports = [{ id: String(nextRowId++), user_id: 'user-aaaa', recorded_hand_id: '100' }];
  TABLES.replay_attempts = [{ id: String(nextRowId++), user_id: 'user-aaaa', recorded_hand_id: '100' }];
}
seed();
const byMarker = (marker) => TABLES.recorded_hands.find((r) => r.marker === marker) ?? null;
const A_ROW = () => byMarker('A-own-game');
const B_ROW = () => byMarker('B-own-game');
const LEGACY_ROW = () => byMarker('legacy-row-no-owner');

function handler(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1');
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let body = null;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* none */ }
    const send = (status, payload, headers = {}) => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
    };
    const cookiePair = (req.headers.cookie ?? '').split(';').map((s) => s.trim()).find((s) => s.startsWith(`${COOKIE_NAME}=`)) ?? '';
    const cookieValue = cookiePair.split('=').slice(1).join('=');
    const userId = sessions.get(cookieValue);

    if (url.pathname.startsWith('/api/user-auth/')) {
      if (!req.headers['x-database-instance']) return send(400, { error: 'Missing database instance.' });
      const verb = url.pathname.slice('/api/user-auth/'.length);
      if (verb === 'sign-in/email') {
        const u = USERS[body?.email];
        if (!u || u.password !== body?.password) return send(401, { code: 'USER_NOT_FOUND' });
        const value = `fixture-cookie-${u.id}-${crypto.randomBytes(4).toString('hex')}`;
        sessions.set(value, u.id);
        return send(200, { user: { id: u.id, email: body.email, role: u.role }, token: `vendor-body-token-${u.id}` },
          { 'Set-Cookie': `${COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure` });
      }
      if (verb === 'get-session') {
        if (!userId) return send(200, null);
        const u = Object.entries(USERS).find(([, x]) => x.id === userId)?.[1];
        return send(200, { user: { id: u.id, email: u.email, role: u.role }, session: { userId } });
      }
      return send(404, { error: 'Auth Route Not Found' });
    }

    if (url.pathname.startsWith('/api/data/')) {
      if (!url.searchParams.get('Instance')) return send(400, { status: 'failed', error: 'Instance is required.' });
      if (!userId) return send(401, { status: 'failed', error: 'Unauthorized.' });
      const [, , verb, table, rowId] = url.pathname.split('/').filter(Boolean);
      const list = TABLES[table];
      if (!list) return send(404, { status: 'failed', error: `unknown table ${table}` });

      if (verb === 'read') {
        upstream.reads += 1;
        if (faultRead) return send(500, { status: 'failed', error: 'read refused by the vendor' });
        // SHARED_READWRITE: every session sees every row. No filter is a permission.
        let rows = list.map((r) => (knownColumns ? r : { ...r, user_id: undefined }));
        for (const [key, value] of url.searchParams.entries()) {
          if (['Instance', 'limit', 'page', 'sort', 'order'].includes(key)) continue;
          rows = rows.filter((r) => String(r[key] ?? '') === value);
        }
        const limit = Number(url.searchParams.get('limit'));
        if (Number.isFinite(limit) && limit > 0) rows = rows.slice(0, limit);
        return send(200, { status: 'success', data: rows });
      }
      if (verb === 'create') {
        const row = { id: String(nextRowId++), user_id: userId, ...(body ?? {}) };
        list.push(row);
        return send(201, { status: 'success', id: row.id });
      }
      if (verb === 'update') {
        const row = list.find((r) => String(r.id) === rowId);
        if (!row) return send(404, { status: 'error', message: 'Record not found' });
        Object.assign(row, body ?? {});
        return send(200, { status: 'success' });
      }
      if (verb === 'delete') {
        upstream.deletes.push({ table, id: String(rowId), by: userId });
        const index = list.findIndex((r) => String(r.id) === rowId);
        if (index === -1) return send(404, { status: 'error', message: 'Record not found' });
        list.splice(index, 1);
        return send(200, { status: 'success', message: 'Record deleted successfully' });
      }
      return send(404, { status: 'failed', error: 'no such verb' });
    }
    return send(404, { status: 'failed', error: 'no such path' });
  });
}

const fake = http.createServer(handler);
await new Promise((r) => fake.listen(0, '127.0.0.1', r));
const FAKE_BASE = `http://127.0.0.1:${fake.address().port}`;

const SEAL_KEY = 'bypass-fixture-seal-key-not-a-real-secret-32ch';
process.env = {
  ...process.env,
  BRIDGE_API_KEY: 'relay-key-not-a-secret',
  NCB_PROXY_BASE: FAKE_BASE,
  NCB_AUTH_API_URL: `${FAKE_BASE}/api/user-auth`,
  NCB_DATA_API_URL: `${FAKE_BASE}/api/data`,
  NCB_INSTANCE: '55954_bridgemind',
  NCB_ALLOW_INSECURE_UPSTREAM: '1',
  NCB_SESSION_SEAL_KEY: SEAL_KEY,
  NCB_GATEWAY_ALLOWED_ORIGINS: 'https://app.bridgemind.test',
  NCB_TABLE_ALLOWLIST: 'recorded_hands,community_games,game_analysis_reports,replay_attempts,user_settings',
  NODESEND_PRIVATE_KEY_B64: '',
  AI_QUOTA_RESERVATION_TABLE: ''
};
delete process.env.NODESEND_PRIVATE_KEY_PEM;

const bridge = require(path.join(ROOT, 'bridge.js'));
const { app } = bridge;
const gatewayRules = require(path.join(ROOT, 'ncb/gateway.js'));
const server = app.listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
const ORIGIN = 'https://app.bridgemind.test';

const results = [];
const check = (name, condition, detail = '') => {
  results.push({ name, pass: condition === true, detail: condition === true ? '' : String(detail ?? '').slice(0, 260) });
};
const call = async (method, route, { token = '', body, headers = {} } = {}) => {
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* none */ }
  return { status: res.status, json, text };
};
const signIn = async (email, password) => (await call('POST', '/ncb/auth/sign-in/email', { body: { email, password } })).json?.token ?? '';
const tokenA = await signIn('a@poc.invalid', 'pw-a');
const tokenB = await signIn('b@poc.invalid', 'pw-b');
const tokenC = await signIn('c@poc.invalid', 'pw-c');
const owns = (table, id) => TABLES[table].some((r) => String(r.id) === String(id));

check('B0. three sealed sessions exist, and the fake models a session rather than a permission',
  tokenA.startsWith('ncbs1.') && tokenB.startsWith('ncbs1.') && tokenC.startsWith('ncbs1.') && tokenA !== tokenB,
  `${tokenA.slice(0, 8)}/${tokenB.slice(0, 8)}`);

/* X1 — THE CONTROL THAT MAKES EVERY REFUSAL BELOW MEANINGFUL. With the gateway out of the way, player B
 * deletes player A's row at the vendor and it WORKS. shared_readwrite really does authorize nothing, so
 * any gateway permission is a real hole and every refusal below is the only thing between accounts. */
const victimId = A_ROW().id;
const rawBypass = await new Promise((resolve, reject) => {
  const cookieValue = [...sessions.entries()].find(([, u]) => u === 'user-bbbb')?.[0];
  const req = http.request(`${FAKE_BASE}/api/data/delete/recorded_hands/${A_ROW().id}?Instance=55954_bridgemind`, {
    method: 'DELETE', headers: { cookie: `${COOKIE_NAME}=${cookieValue}` }
  }, (res) => {
    const b = []; res.on('data', (c) => b.push(c));
    res.on('end', () => resolve({
      status: res.statusCode, body: Buffer.concat(b).toString('utf8'),
      // The point of the control is that the row REALLY went away at the vendor.
      rowGone: !TABLES.recorded_hands.some((r) => String(r.id) === victimId)
    }));
  });
  req.on('error', reject);
  req.end();
});
check('X1. control: the vendor alone does NOT protect a row — B deletes A\u2019s game straight through (so the relay guard is the only defense)',
  // Deliberately not `... || status === 200`: that passes on a 200 that deleted nothing, which would
  // make this control — and every refusal that depends on it — unfalsifiable.
  rawBypass.status === 200 && rawBypass.rowGone === true,
  `${rawBypass.status} rowGone=${rawBypass.rowGone} ${rawBypass.body.slice(0, 120)}`);
seed();   // restore the fixture rows the control just removed
/* From here on, arms judge only the deletes the GATEWAY forwarded. The control above deliberately
 * reached the vendor directly, and its ledger entry is otherwise indistinguishable from a breach —
 * mixing the two would make X2 fail on the very evidence that proves the hole is real. */
const ledgerMark = upstream.deletes.length;
const gatewayDeletes = () => upstream.deletes.slice(ledgerMark);

// ── 1. cross-account deletion ───────────────────────────────────────────────────────────────────
const beforeA = A_ROW().id;
const cross = await call('DELETE', `/ncb/data/delete/recorded_hands/${beforeA}`, { token: tokenB });
check('1. player B cannot delete player A\u2019s recorded game through the relay, and the row survives',
  cross.status === 403 && cross.json?.error === 'not_record_owner' && owns('recorded_hands', beforeA),
  `${cross.status} ${JSON.stringify(cross.json).slice(0, 160)} present=${owns('recorded_hands', beforeA)}`);
check('1b. the refusal is NAMED, not the generic table denial an operator would misread as config',
  String(cross.json?.detail ?? '').includes('own') && cross.json?.error !== 'table_not_allowed',
  JSON.stringify(cross.json).slice(0, 200));
/* The exact refactor this must survive: if anyone ever derives the owner from the REQUEST (a query
 * filter, a body field) instead of the sealed session, a caller could simply name the real owner and
 * walk in. B here supplies A's own id in the query AND the body; the refusal must not change. */
const claimed = await call('DELETE',
  `/ncb/data/delete/recorded_hands/${beforeA}?user_id=user-aaaa&owner_id=user-aaaa`,
  { token: tokenB, body: { user_id: 'user-aaaa', owner: 'user-aaaa', as: 'user-aaaa' } });
check('1d. claiming the real owner in the query or body buys nothing — identity comes from the seal only',
  claimed.status === 403 && claimed.json?.error === 'not_record_owner' && owns('recorded_hands', beforeA),
  `${claimed.status} ${JSON.stringify(claimed.json).slice(0, 160)}`);
const cancelRole = await call('DELETE', `/ncb/data/delete/recorded_hands/${beforeA}`, { token: tokenC });
check('1c. a session the vendor calls `administrator` is refused too — a session role is not ownership',
  cancelRole.status === 403 && cancelRole.json?.error === 'not_record_owner' && owns('recorded_hands', beforeA),
  `${cancelRole.status} ${JSON.stringify(cancelRole.json).slice(0, 140)}`);

// ── 2/3. the protected tables ───────────────────────────────────────────────────────────────────
const repId = TABLES.game_analysis_reports[0].id;
const attemptId = TABLES.replay_attempts[0].id;
const rep = await call('DELETE', `/ncb/data/delete/game_analysis_reports/${repId}`, { token: tokenA });
const att = await call('DELETE', `/ncb/data/delete/replay_attempts/${attemptId}`, { token: tokenA });
check('2. the OWNER of a report cannot single-row delete it either: the verb is closed on the relay',
  rep.status === 403 && rep.json?.error === gatewayRules.CALLER_DELETE_BLOCK_REFUSAL && owns('game_analysis_reports', repId),
  `${rep.status} ${JSON.stringify(rep.json).slice(0, 160)}`);
check('3. same for replay_attempts — the cascade route is the only removal path',
  att.status === 403 && att.json?.error === gatewayRules.CALLER_DELETE_BLOCK_REFUSAL && owns('replay_attempts', attemptId),
  `${att.status} ${JSON.stringify(att.json).slice(0, 160)}`);
check('3b. the block is on DELETE ONLY: reading and writing these tables still works for their owners',
  (await call('GET', `/ncb/data/read/game_analysis_reports?user_id=user-aaaa`, { token: tokenA })).status === 200
    && (await call('POST', `/ncb/data/create/replay_attempts`, { token: tokenA, body: { recorded_hand_id: '100' } })).status === 200
    && (await call('PUT', `/ncb/data/update/game_analysis_reports/${repId}`, { token: tokenA, body: { note: 'x' } })).status === 200,
  'a non-delete verb was narrowed too');

// ── 4/5. the legitimate player workflows survive ────────────────────────────────────────────────
const myRow = B_ROW().id;
const mine = await call('DELETE', `/ncb/data/delete/recorded_hands/${myRow}`, { token: tokenB });
check('4. recorder cancel still works: a player deletes their OWN recorded game through the relay',
  mine.status === 200 && !owns('recorded_hands', myRow),
  `${mine.status} ${JSON.stringify(mine.json).slice(0, 160)}`);
const myCommunity = TABLES.community_games.find((r) => r.user_id === 'user-aaaa').id;
const unpublish = await call('DELETE', `/ncb/data/delete/community_games/${myCommunity}`, { token: tokenA });
check('5. community unpublish still works: a player removes their OWN publication row',
  unpublish.status === 200 && !owns('community_games', myCommunity),
  `${unpublish.status} ${JSON.stringify(unpublish.json).slice(0, 160)}`);
const otherCommunity = TABLES.community_games.find((r) => r.user_id === 'user-bbbb').id;
const stealUnpublish = await call('DELETE', `/ncb/data/delete/community_games/${otherCommunity}`, { token: tokenA });
check('5b. and unpublish does not extend to another player\u2019s publication',
  stealUnpublish.status === 403 && owns('community_games', otherCommunity),
  `${stealUnpublish.status} ${JSON.stringify(stealUnpublish.json).slice(0, 140)}`);

// ── 6. fail-closed cases ────────────────────────────────────────────────────────────────────────
const legacy = LEGACY_ROW().id;
const legacyDelete = await call('DELETE', `/ncb/data/delete/recorded_hands/${legacy}`, { token: tokenA });
check('6a. a row with NO owner value is refused outright, never attributed to the caller',
  legacyDelete.status === 403 && legacyDelete.json?.error === 'ownership_unverifiable' && owns('recorded_hands', legacy),
  `${legacyDelete.status} ${JSON.stringify(legacyDelete.json).slice(0, 180)}`);
const ghost = await call('DELETE', `/ncb/data/delete/recorded_hands/999999`, { token: tokenA });
check('6b. an id that matches no row is a 404, and no delete reaches the vendor for it',
  ghost.status === 404 && !upstream.deletes.some((d) => d.id === '999999'),
  `${ghost.status} deletes=${JSON.stringify(upstream.deletes.slice(-2))}`);
seed();
const blindTarget = A_ROW().id;   // captured BEFORE the fault, while the row still exists to find
faultRead = true;
const blind = await call('DELETE', `/ncb/data/delete/recorded_hands/${blindTarget}`, { token: tokenA });
faultRead = false;
check('6c. when the ownership read itself fails, the delete is refused as 503 and nothing is removed',
  blind.status === 503 && blind.json?.error === 'storage_unavailable' && owns('recorded_hands', blindTarget)
    && !gatewayDeletes().some((d) => d.id === String(blindTarget)),
  `${blind.status} ${JSON.stringify(blind.json).slice(0, 160)}`);
seed();
const knownOffId = A_ROW().id;
knownColumns = false;
const noColumn = await call('DELETE', `/ncb/data/delete/recorded_hands/${knownOffId}`, { token: tokenA });
knownColumns = true;
check('6d. a table whose owner column is absent fails closed rather than guessing',
  noColumn.status === 403 && owns('recorded_hands', knownOffId),
  `${noColumn.status} ${JSON.stringify(noColumn.json).slice(0, 160)}`);
seed();

// ── 7/8. nothing else regressed ─────────────────────────────────────────────────────────────────
const ownSettings = await call('DELETE', `/ncb/data/delete/user_settings/${TABLES.user_settings[0]?.id ?? '1'}`, { token: tokenA });
check('7. an unrelated full-policy table is untouched by this change (no wildcard block was introduced)',
  ownSettings.status === 404 || ownSettings.status === 200,
  `${ownSettings.status} ${JSON.stringify(ownSettings.json).slice(0, 120)}`);
const adminRoute = await call('DELETE', '/games/100', { token: tokenA });
check('8. the admin route is still mounted and independent of the relay (it answers, and not with 404)',
  adminRoute.status !== 404 && adminRoute.json?.error?.code !== undefined,
  `${adminRoute.status} ${JSON.stringify(adminRoute.json).slice(0, 160)}`);
check('8b. the shipped constants, not copies: the block list and owner map are what the gate asserts',
  gatewayRules.CALLER_DELETE_BLOCKED.includes('game_analysis_reports')
    && gatewayRules.CALLER_DELETE_BLOCKED.includes('replay_attempts')
    && gatewayRules.CALLER_DELETE_OWNER_COLUMN.recorded_hands === 'user_id'
    && gatewayRules.CALLER_DELETE_OWNER_COLUMN.community_games === 'user_id'
    && !Object.keys(gatewayRules.CALLER_DELETE_OWNER_COLUMN).some((t) => gatewayRules.CALLER_DELETE_BLOCKED.includes(t)),
  JSON.stringify({ blocked: gatewayRules.CALLER_DELETE_BLOCKED, owned: gatewayRules.CALLER_DELETE_OWNER_COLUMN }));
check('X2. the gateway forwarded no DELETE for any refused request, and never touched the closed tables',
  gatewayDeletes().every((d) => d.table !== 'game_analysis_reports' && d.table !== 'replay_attempts')
    // the only recorded_hands delete allowed to reach the vendor is B deleting B's own row (case 4)
    && gatewayDeletes().filter((d) => d.table === 'recorded_hands').map((d) => `${d.by}:${d.id}`).join(',') === 'user-bbbb:101',
  JSON.stringify(gatewayDeletes()));

let failed = 0;
for (const r of results) {
  if (!r.pass) failed += 1;
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.pass ? '' : `   ${r.detail}`}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed  (game-record relay delete bypass gate)`);
server.close();
fake.close();
process.exit(failed ? 1 : 0);
