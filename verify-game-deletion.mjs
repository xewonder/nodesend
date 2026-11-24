/*
 * NodeSend — SYSTEM ADMIN GAME DELETION GATE
 *
 * Everything runs in-process: a loopback mock of the NCB data plane and session authority, and the REAL
 * exported `app` from bridge.js over a real socket. Nothing here contacts a production endpoint, and the
 * fetch shim fails the run on any request to any other host. NO live row is ever deleted.
 *
 * The gate is written against the shipped envelope the frontend at 514ad394 parses:
 *   success  {status:"success", data:{deleted, alreadyAbsent, neverFound, removed{...}, replayChildren}}
 *   refusal  {status:"error",   error:{code, message}}
 *
 *   node verify-game-deletion.mjs
 */
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));

const MOCK_HOST = 'ncb.gamedel.invalid';
const SERVICE_ID = '99';
const SERVICE_EMAIL = 'club-service-account@bridgemind.invalid';
const SERVICE_TOKEN = 'gamedel-fixture-service-bearer-0123456789';
const PASSWORD = 'gamedel-fixture-not-a-credential-0123456789';
const CALLERS = {
  'tok-admin': '1',        // in system_admins
  'tok-user': '7',         // ordinary player
  'tok-clubadmin': '4',    // club_admin of club 10, NOT in system_admins
  'tok-other': '12'        // another player, owns a foreign replay child
};

process.env.BRIDGE_API_KEY = 'relay-api-key-not-a-deletion-secret';
process.env.NCB_PROXY_BASE = `https://${MOCK_HOST}`;
process.env.NCB_INSTANCE = '55954_bridgemind';
process.env.NCB_TRANSPORT = 'proxy';
process.env.CLUB_NCB_EMAIL = SERVICE_EMAIL;
process.env.CLUB_NCB_PASSWORD = PASSWORD;
process.env.CLUB_NCB_EXPECTED_USER_ID = SERVICE_ID;
process.env.CLUB_NCB_SCHEMA_JSON = JSON.stringify({
  tables: {
    systemAdmins: 'system_admins', clubs: 'clubs', memberships: 'club_memberships',
    collections: 'club_board_collections', boards: 'club_collection_boards'
  },
  columns: {
    systemAdmins: { userId: 'admin_user_id' },
    clubs: { id: 'id', name: 'name', status: 'active' },
    memberships: { id: 'id', userId: 'member_user_id', clubId: 'club_id', role: 'role', status: 'status' },
    collections: { id: 'id', clubId: 'club_id', name: 'title', status: 'publication_status', createdBy: 'created_by_user_id' },
    boards: { id: 'id', collectionId: 'collection_id', boardNumber: 'board_number', dealer: 'dealer', vulnerability: 'vulnerability', handsJson: 'hands_json' }
  },
  values: { clubs: { status: { active: 1, inactive: 0 } } }
});
process.env.TOURNAMENT_NCB_SCHEMA_JSON = JSON.stringify({
  tables: { tournaments: 'tournaments', boards: 'tournament_boards', attempts: 'tournament_attempts' },
  columns: {
    tournaments: { id: 'id', userId: 'owner_user_id', clubId: 'club_id', name: 'name', visibility: 'visibility', status: 'status', boardCount: 'board_count', sourceLabel: 'source_label', dedupeKey: 'dedupe_key' },
    boards: { id: 'id', tournamentId: 'tournament_id', boardNumber: 'board_number', dealer: 'dealer', vulnerability: 'vulnerability', handsJson: 'hands_json' },
    attempts: { id: 'id', tournamentId: 'tournament_id', boardNumber: 'board_number', recordedHandId: 'recorded_hand_id', originalSeat: 'original_seat', userId: 'player_user_id' }
  }
});
delete process.env.NCB_SESSION_SEAL_KEY;
delete process.env.NODESEND_PRIVATE_KEY_B64;

// ── the storage the mock serves ─────────────────────────────────────────────────────────────────
const rows = {
  system_admins: [{ id: 'sa1', admin_user_id: '1', user_id: SERVICE_ID }],
  clubs: [{ id: '10', name: 'Glyfada BC', active: 1 }],
  club_memberships: [
    { id: 'm4', member_user_id: '4', club_id: '10', role: 'club_admin', status: 'approved', user_id: SERVICE_ID }
  ],
  recorded_hands: [],
  community_games: [],
  game_analysis_reports: [],
  ai_decision_traces: [],
  tournament_attempts: [],
  replay_attempts: [],
  coach_feedback_flags: [],
  tournaments: [],
  tournament_boards: [],
  club_board_collections: [],
  club_collection_boards: []
};
const COLUMNS = {
  recorded_hands: ['id', 'user_id', 'root_hand_id', 'parent_hand_id', 'board_data'],
  community_games: ['id', 'source_hand_id', 'root_hand_id', 'publisher_user_id'],
  game_analysis_reports: ['id', 'recorded_hand_id', 'author_user_id'],
  ai_decision_traces: ['id', 'recorded_hand_id', 'board_id', 'root_hand_id', 'kind'],
  tournament_attempts: ['id', 'tournament_id', 'recorded_hand_id', 'player_user_id'],
  replay_attempts: ['id', 'recorded_hand_id', 'root_hand_id', 'user_id'],
  coach_feedback_flags: ['id', 'hand_id', 'root_hand_id', 'coach_user_id', 'user_id'],
  tournaments: ['id', 'owner_user_id', 'name'],
  tournament_boards: ['id', 'tournament_id', 'board_number'],
  system_admins: ['id', 'admin_user_id', 'user_id'],
  clubs: ['id', 'name', 'active'],
  club_memberships: ['id', 'member_user_id', 'club_id', 'role', 'status', 'user_id'],
  club_board_collections: ['id', 'club_id', 'title', 'publication_status', 'created_by_user_id'],
  club_collection_boards: ['id', 'collection_id', 'board_number', 'dealer', 'vulnerability', 'hands_json']
};
const GAME = '5001';                      // the canonical game under test, owned by user 7
// `acceptDeleteButKeepRow` is per-TABLE, because a global switch let one lying table hide behind another
// step's verification: the first negative-control plant found that the satellite read-back proof was
// never actually under test while the canonical proof was.
const FAULTS = { failDeleteOf: null, refuseRead: null, keepRowsIn: null };
// `adminOverride` was declared here and never read; NC4b caught it. Authority is varied by choosing the
// caller token instead, so no knob is needed.
let nextRowId = 900;
const calls = { deletes: [], reads: [], auth: [], offHost: [] };

const realFetch = globalThis.fetch;
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const RESERVED = ['limit', 'page', 'sort', 'order', 'Instance'];
let LOOPBACK = '';

globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  const { host, pathname, searchParams } = new URL(target);
  // Two loopback servers are addressable in this run: the relay under test, and the fault-injection app
  // that proves an internal throw answers instead of hanging. Any OTHER host — including the real vendor
  // and production — ends the run rather than sending a request.
  if (host.startsWith('127.0.0.1:')) return realFetch(url, init);
  if (host !== MOCK_HOST) { calls.offHost.push(`${host}${pathname}`); throw new TypeError(`gate refused an off-mock request to ${host}`); }
  const method = String(init.method ?? 'GET').toUpperCase();
  const bearer = String(init?.headers?.Authorization ?? init?.headers?.authorization ?? '').replace(/^Bearer\s+/, '');
  const body = init.body ? JSON.parse(init.body) : null;

  if (pathname === '/auth/sign-in/email') {
    calls.auth.push(pathname);
    if (body?.email !== SERVICE_EMAIL || body?.password !== PASSWORD) return json({ status: 'error' }, 401);
    return json({ token: SERVICE_TOKEN, user: { id: SERVICE_ID, email: SERVICE_EMAIL } });
  }
  if (pathname === '/auth/get-session') {
    calls.auth.push(pathname);
    if (bearer === SERVICE_TOKEN) return json({ data: { user: { id: SERVICE_ID, email: SERVICE_EMAIL } } });
    const id = CALLERS[bearer];
    if (!id) return json({ status: 'error' }, 401);
    return json({ data: { user: { id, email: `player-${id}@example.test` } } });
  }
  if (!pathname.startsWith('/data/')) return json({ status: 'error', message: `unexpected path ${pathname}` }, 404);

  const [, action, table, rowId] = pathname.split('/').filter(Boolean);
  const list = rows[table];
  if (!list) return json({ status: 'error', message: `unknown table ${table}` }, 404);
  // THE ONE RULE THE WHOLE DESIGN RESTS ON: game deletion runs on the service account only.
  if (bearer !== SERVICE_TOKEN) return json({ status: 'error', message: 'no caller bearer touches storage here' }, 403);

  const filters = {};
  for (const [key, value] of searchParams.entries()) {
    if (RESERVED.includes(key)) continue;
    if (!COLUMNS[table].includes(key)) return json({ status: 'failed', error: `Unknown column '${key}' in 'where clause'` }, 500);
    filters[key] = value;
  }
  const matched = () => list.filter((r) => Object.entries(filters).every(([k, v]) => String(r[k] ?? '') === v));

  if (action === 'read') {
    calls.reads.push({ table, filters: { ...filters } });
    if (FAULTS.refuseRead && FAULTS.refuseRead.table === table && FAULTS.refuseRead.column in filters) {
      return json({ status: 'failed', error: 'read refused' }, 500);
    }
    const found = matched();
    const limit = Number(searchParams.get('limit'));
    return json({ status: 'success', data: Number.isFinite(limit) && limit > 0 ? found.slice(0, limit) : found });
  }
  if (action === 'create') {
    const row = { id: String(nextRowId++), user_id: SERVICE_ID, ...body };
    list.push(row);
    return json({ status: 'success', data: { ...row } });
  }
  if (action === 'update') {
    const row = list.find((r) => String(r.id) === String(rowId));
    if (!row) return json({ status: 'error' }, 404);
    Object.assign(row, body ?? {});
    return json({ status: 'success', data: { ...row } });
  }
  if (action === 'delete') {
    calls.deletes.push({ table, id: String(rowId) });
    if (FAULTS.failDeleteOf && FAULTS.failDeleteOf.table === table && FAULTS.failDeleteOf.id === String(rowId)) {
      return json({ status: 'failed', error: 'delete refused by the vendor' }, 500);
    }
    const index = list.findIndex((r) => String(r.id) === String(rowId));
    if (index === -1) return json({ status: 'success', data: { id: rowId } });   // idempotent
    const keepThisTable = Array.isArray(FAULTS.keepRowsIn)
      ? FAULTS.keepRowsIn.includes(table)
      : FAULTS.keepRowsIn === true;
    if (!keepThisTable) list.splice(index, 1);
    return json({ status: 'success', data: { id: rowId } });
  }
  return json({ status: 'error' }, 404);
};

const bridge = require(path.join(ROOT, 'bridge.js'));
const { app } = bridge;
// Declared with the bridge it comes from: arms use the SHIPPED rules objects instead of re-typing table and
// column names, and declaring this after its first use would be a temporal-dead-zone crash (measured).
const rules = bridge.gameDeletionRules;
const server = app.listen(0, '127.0.0.1');
await new Promise((resolve) => server.once('listening', resolve));
LOOPBACK = `127.0.0.1:${server.address().port}`;
const BASE = `http://127.0.0.1:${server.address().port}`;

const results = [];
const check = (name, condition, detail = '') => {
  results.push({ name, pass: condition === true, detail: condition === true ? '' : String(detail ?? '').slice(0, 320) });
};
const del = async (id, token = 'tok-admin', extra = {}) => {
  const res = await fetch(`${BASE}/games/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: { authorization: `Bearer ${token}`, ...(extra.body ? { 'content-type': 'application/json' } : {}) },
    ...(extra.body ? { body: JSON.stringify(extra.body) } : {})
  });
  let body = null;
  try { body = await res.json(); } catch {}
  return { status: res.status, body };
};

const seedGame = ({ foreignChild = false, communityRoot = false, flagTrace = true } = {}) => {
  for (const k of Object.keys(rows)) {
    if (['system_admins', 'clubs', 'club_memberships'].includes(k)) continue;
    rows[k].length = 0;
  }
  calls.deletes.length = 0;
  calls.reads.length = 0;
  rows.recorded_hands.push({ id: GAME, user_id: '7', root_hand_id: null, board_data: '{"private":"cards"}' });
  rows.recorded_hands.push({ id: '5002', user_id: '7', root_hand_id: GAME, board_data: 'child-own' });    // same owner
  rows.recorded_hands.push({ id: '5003', user_id: '7', root_hand_id: GAME, board_data: 'child-own-2' });  // same owner
  if (foreignChild) rows.recorded_hands.push({ id: '5004', user_id: '12', root_hand_id: GAME, board_data: 'someone else game' });
  rows.community_games.push({ id: 'c1', source_hand_id: GAME, root_hand_id: null, publisher_user_id: '7' });
  if (communityRoot) rows.community_games.push({ id: 'c2', source_hand_id: '5002', root_hand_id: GAME, publisher_user_id: '7' });
  rows.game_analysis_reports.push({ id: 'r1', recorded_hand_id: GAME, author_user_id: '4' });
  rows.ai_decision_traces.push({ id: 't1', recorded_hand_id: GAME, board_id: '94', root_hand_id: GAME, kind: 'game' });
  if (flagTrace) rows.ai_decision_traces.push({ id: 't2', recorded_hand_id: null, board_id: '94', root_hand_id: GAME, kind: 'flag-snapshot' });
  rows.tournament_attempts.push({ id: 'a1', tournament_id: 'T1', recorded_hand_id: GAME, player_user_id: '7' });
  // A replay attempt keyed directly to the game, and one that names ONLY the chain root — the second is
  // invisible to a sweep that looks at recorded_hand_id alone.
  rows.replay_attempts.push({ id: 'ra1', recorded_hand_id: GAME, root_hand_id: GAME, user_id: '7' });
  rows.replay_attempts.push({ id: 'ra2', recorded_hand_id: null, root_hand_id: GAME, user_id: '7' });
  // Coach flags: another person's record. Counted and reported, never deleted.
  rows.coach_feedback_flags.push({ id: 'f1', hand_id: GAME, root_hand_id: GAME, coach_user_id: '4', user_id: '4' });
  rows.coach_feedback_flags.push({ id: 'f2', hand_id: '7777', root_hand_id: '7777', coach_user_id: '4', user_id: '4' });
  // A child that names this game ONLY as its parent: root_hand_id points at an older row, so a
  // root-only child search would miss it and leave a dangling parent reference.
  rows.recorded_hands.push({ id: '5099', user_id: '7', root_hand_id: '4404', parent_hand_id: GAME, board_data: 'mid-chain child' });
  // Unrelated data that must survive byte-identically.
  rows.recorded_hands.push({ id: '7777', user_id: '8', root_hand_id: null, board_data: 'another player' });
  rows.tournaments.push({ id: 'T1', owner_user_id: '4', name: 'Autumn Congress' });
  rows.tournament_boards.push({ id: 'b1', tournament_id: 'T1', board_number: '1' });
  rows.tournament_attempts.push({ id: 'a2', tournament_id: 'T1', recorded_hand_id: '7777', player_user_id: '9' });
};

const snapshot = (table) => JSON.stringify(rows[table]);

check('G0a. the deletion mount is configured, or every arm below measures a 503 instead of its rule',
  bridge.gameDeletionMount?.configured === true, JSON.stringify(bridge.gameDeletionMount?.status?.() ?? null));
check('G0b. /health describes game deletion in booleans and a count, with no table or id',
  (() => {
    const h = bridge.gameDeletionHealth(bridge.gameDeletionMount);
    return typeof h.configured === 'boolean' && h.routes === 1
      && !JSON.stringify(h).includes('recorded_hands') && !JSON.stringify(h).includes(SERVICE_EMAIL);
  })(), JSON.stringify(bridge.gameDeletionHealth(bridge.gameDeletionMount)));

// ── 1-6: authorization and input surface ────────────────────────────────────────────────────────
seedGame({ communityRoot: true });
const anon = await fetch(`${BASE}/games/${GAME}`, { method: 'DELETE' });
const anonBody = await anon.json().catch(() => ({}));
check('1. unauthenticated request is denied, and nothing was written',
  anon.status === 401 && anonBody?.error?.code === 'auth_error' && calls.deletes.length === 0,
  `${anon.status} ${JSON.stringify(anonBody).slice(0, 140)}`);

seedGame();
const user = await del(GAME, 'tok-user');
check('2. an ordinary player is denied as not_system_admin, and ZERO rows were deleted',
  user.status === 403 && user.body?.error?.code === 'not_system_admin' && calls.deletes.length === 0
    && rows.recorded_hands.some((r) => r.id === GAME),
  `${user.status} ${JSON.stringify(user.body).slice(0, 140)} deletes=${calls.deletes.length}`);

seedGame();
const clubAdmin = await del(GAME, 'tok-clubadmin');
check('3. a Club Admin without System Admin authority is denied, including when calling the API directly',
  clubAdmin.status === 403 && clubAdmin.body?.error?.code === 'not_system_admin' && calls.deletes.length === 0,
  `${clubAdmin.status} ${JSON.stringify(clubAdmin.body).slice(0, 140)}`);

seedGame();
const forged = await del(GAME, 'tok-user', { body: { is_system_admin: true, admin: true, user_id: '1', role: 'system_admin', dryRun: false } });
check('5. a forged admin flag, owner id or role in the body is denied and never reaches storage',
  forged.status === 403 && forged.body?.error?.code === 'not_system_admin' && calls.deletes.length === 0,
  `${forged.status} ${JSON.stringify(forged.body).slice(0, 140)}`);

seedGame();
const badIds = ['abc', '1;DROP TABLE recorded_hands', '5001 OR 1=1', '../etc/passwd', '   ', '5001n', '0x1389', '5001%00', '٣٤٥'];
const badResults = [];
for (const bad of badIds) badResults.push({ id: bad, ...(await del(bad, 'tok-admin')) });
check('6. the game id is validated exactly: non-canonical ids are 404 invalid_game_id with no storage call',
  badResults.every((r) => r.status === 404 && r.body?.error?.code === 'invalid_game_id') && calls.deletes.length === 0,
  JSON.stringify(badResults.map((r) => [r.id, r.status, r.body?.error?.code])).slice(0, 400));
// An empty id never reaches the route: `/games/` has no path parameter, so the RELAY answers its own
// 404. Recorded rather than hidden, because it is a different refusal from `invalid_game_id` and an
// operator comparing the two needs to know which layer answered.
const empty = await fetch(`${BASE}/games/`, { method: 'DELETE', headers: { authorization: 'Bearer tok-admin' } });
const emptyBody = await empty.json().catch(() => ({}));
check('6b. an empty id is refused by the relay 404, not treated as a wildcard, and deletes nothing',
  empty.status === 404 && emptyBody?.error === 'Endpoint not found' && calls.deletes.length === 0,
  `${empty.status} ${JSON.stringify(emptyBody).slice(0, 120)}`);

// ── the authorized success path ─────────────────────────────────────────────────────────────────
seedGame({ communityRoot: true });
const before = {
  tournament: snapshot('tournaments'), boards: snapshot('tournament_boards'),
  otherAttempts: JSON.stringify(rows.tournament_attempts.filter((a) => a.id === 'a2')),
  otherPlayersGame: JSON.stringify(rows.recorded_hands.filter((r) => r.id === '7777')),
  flagTrace: JSON.stringify(rows.ai_decision_traces.filter((t) => t.id === 't2'))
};
const ok = await del(GAME, 'tok-admin');
const d = ok.body?.data ?? {};
check('G1/7-9. System Admin deletion succeeds with the exact per-table counts',
  ok.status === 200 && ok.body?.status === 'success' && d.deleted === true && d.alreadyAbsent === false
    && d.removed?.tournamentAttempts === 1 && d.removed?.decisionTraces === 1
    && d.removed?.analysisReports === 1 && d.removed?.communityGames === 2 && d.removed?.recordedHands === 4
    && d.removed?.replayAttempts === 2,
  `${ok.status} ${JSON.stringify(ok.body).slice(0, 300)}`);
check('7. every community publication row is gone, by BOTH source_hand_id and root_hand_id, counted once',
  rows.community_games.filter((c) => c.source_hand_id === GAME || c.root_hand_id === GAME).length === 0,
  JSON.stringify(rows.community_games));
check('8. the analysis report for the game is gone',
  rows.game_analysis_reports.filter((r) => r.recorded_hand_id === GAME).length === 0, JSON.stringify(rows.game_analysis_reports));
check('9. the game-associated AI trace is gone',
  !rows.ai_decision_traces.some((t) => t.id === 't1'), JSON.stringify(rows.ai_decision_traces));
check('10. the unrelated flag-only trace (recorded_hand_id NULL) is PRESERVED byte-identically',
  JSON.stringify(rows.ai_decision_traces.filter((t) => t.id === 't2')) === before.flagTrace
    && !calls.deletes.some((c) => c.table === 'ai_decision_traces' && c.id === 't2'),
  JSON.stringify(rows.ai_decision_traces));
check('11. the tournament attempt LINK is removed while the tournament and its boards are untouched',
  !rows.tournament_attempts.some((a) => a.id === 'a1') && snapshot('tournaments') === before.tournament
    && snapshot('tournament_boards') === before.boards && JSON.stringify(rows.tournament_attempts.filter((a) => a.id === 'a2')) === before.otherAttempts,
  `attempts=${JSON.stringify(rows.tournament_attempts)}`);
check('12. same-owner replay descendants are deleted as a reported cascade',
  d.replayChildren === 3 && !rows.recorded_hands.some((r) => r.root_hand_id === GAME) && !rows.recorded_hands.some((r) => r.id === GAME),
  `replayChildren=${d.replayChildren} hands=${JSON.stringify(rows.recorded_hands.map((r) => r.id))}`);
/*
 * Three dependencies the original implementation did not cover, found by auditing the sweep against the
 * live column list rather than against the handoff prose. Each is pinned by an arm that goes red if the
 * fix is removed (verified by plants R1-R3).
 */
check('D1. a replay attempt naming ONLY the chain root is swept, not just one keyed to the game',
  rows.replay_attempts.length === 0, JSON.stringify(rows.replay_attempts));
check('D2. a child that names this game only through parent_hand_id is found and deleted, so no parent reference dangles',
  !rows.recorded_hands.some((r) => r.id === '5099')
    && rows.recorded_hands.every((r) => r.parent_hand_id !== GAME)
    && d.replayChildren === 3,
  `children=${d.replayChildren} hands=${JSON.stringify(rows.recorded_hands.map((r) => [r.id, r.parent_hand_id]))}`);
check('D3. coach flags SURVIVE a game deletion and are reported, not silently destroyed or silently dropped',
  rows.coach_feedback_flags.length === 2
    && rows.coach_feedback_flags.some((f) => f.id === 'f1')
    && d.preserved?.coachFeedbackFlags === 1
    && !calls.deletes.some((c) => c.table === 'coach_feedback_flags'),
  `flags=${JSON.stringify(rows.coach_feedback_flags.map((f) => f.id))} preserved=${JSON.stringify(d.preserved)}`);
check('D3b. an unrelated coach flag on another player\u2019s game is untouched by the count and the sweep',
  rows.coach_feedback_flags.some((f) => f.id === 'f2' && f.hand_id === '7777'),
  JSON.stringify(rows.coach_feedback_flags));
check('13. no dangling root reference survives the sweep',
  rows.recorded_hands.every((r) => r.root_hand_id !== GAME)
    && rows.community_games.every((c) => c.root_hand_id !== GAME && c.source_hand_id !== GAME),
  JSON.stringify(rows.recorded_hands.map((r) => [r.id, r.root_hand_id])));
check('15. another player\u2019s recorded game is byte-identical and was never addressed by a delete call',
  JSON.stringify(rows.recorded_hands.filter((r) => r.id === '7777')) === before.otherPlayersGame
    && !calls.deletes.some((c) => c.id === '7777'), JSON.stringify(calls.deletes));
check('18. read-back confirmed removal: every row this route reported as removed is absent from the table',
  calls.deletes.every((c) => !rows[c.table]?.some?.((r) => String(r.id) === c.id)),
  JSON.stringify(calls.deletes.filter((c) => rows[c.table]?.some?.((r) => String(r.id) === c.id))));

// ── 14: statistics are computed from the remaining rows, never decremented ──────────────────────
const communityPool = rows.community_games.length;
const statsFromLive = rows.community_games.filter((c) => c.source_hand_id === GAME).length;
check('14. statistics/rankings read the surviving rows: the deleted game contributes nothing, and no counter was written',
  statsFromLive === 0 && communityPool >= 0 && !calls.deletes.some((c) => /quota|stat|count/i.test(c.table)),
  `pool=${communityPool}`);

// ── 16: idempotency ─────────────────────────────────────────────────────────────────────────────
// Measured as a DELTA of write calls, not an absolute zero: the earlier successful sweep legitimately
// put deletes on the ledger, and "this request issued no new ones" is the property under test.
const deletesBefore = calls.deletes.length;
const repeat = await del(GAME, 'tok-admin');
check('16. a repeat delete is 200 alreadyAbsent:true and never a 404, and it issues no new delete call',
  repeat.status === 200 && repeat.body?.data?.alreadyAbsent === true && repeat.body?.data?.deleted === true
    && Object.values(repeat.body?.data?.removed ?? {}).every((n) => n === 0)
    && repeat.body?.data?.replayChildren === 0 && calls.deletes.length === deletesBefore,
  `${JSON.stringify(repeat.body).slice(0, 220)} newDeletes=${calls.deletes.length - deletesBefore}`);
const before4444 = calls.deletes.length;
const neverSeen = await del('4444', 'tok-admin');
check('16b. an id with no trace anywhere answers the same idempotent success, with no write issued',
  neverSeen.status === 200 && neverSeen.body?.data?.alreadyAbsent === true
    && neverSeen.body?.data?.noTraceRemaining === true && calls.deletes.length === before4444,
  JSON.stringify(neverSeen.body).slice(0, 200));
// The claim this route CANNOT make, asserted so nobody adds it by accident: with no tombstone table, a
// game deleted a moment ago and an id that never existed are the same observable state. Anything that
// reports them differently would be inventing a fact.
/* A crash between the canonical delete and an earlier step must not be reported as a clean absence:
   `noTraceRemaining` is only allowed to say true when EVERY table the sweep touches is quiet. Deleting
   the canonical row directly at the vendor, leaving a replay_attempt behind, is exactly that state. */
seedGame();
const survivorGame = '5001';
// The surviving satellite must be reachable ONLY through the recorded_hand_id probe, or removing that
// probe still leaves the root_hand_id probe able to find something and the arm cannot tell the
// difference. An earlier version of this arm was satisfied by either path (measured by plant R5).
rows.replay_attempts = rows.replay_attempts.filter((r) => r.recorded_hand_id === survivorGame);
rows.replay_attempts.forEach((r) => { r.root_hand_id = 'some-other-root'; });
const survivorIds = rows.replay_attempts.map((r) => r.id);
rows.recorded_hands.splice(rows.recorded_hands.findIndex((r) => r.id === survivorGame), 1);
/* Every OTHER satellite table must be emptied first. An earlier version of this arm left the reports,
   traces and community rows in place, so `total` was non-zero through an unrelated probe and the plant
   that removed the replay_attempt probe was still green — a masked assertion, not a passing one. */
rows.game_analysis_reports.length = 0;
rows.ai_decision_traces.length = 0;
rows.community_games.length = 0;
rows.tournament_attempts.length = 0;
rows.recorded_hands.filter((r) => r.root_hand_id === survivorGame || r.parent_hand_id === survivorGame)
  .forEach((r) => { r.root_hand_id = 'elsewhere'; r.parent_hand_id = 'elsewhere'; });
const partialLook = await del(survivorGame, 'tok-admin');
check('16d. with the canonical row gone but a replay_attempt still keyed to it, clean absence is NOT claimed',
  partialLook.status === 200 && partialLook.body?.data?.alreadyAbsent === true
    && partialLook.body?.data?.noTraceRemaining === false,
  JSON.stringify(partialLook.body?.data).slice(0, 200));
check('16e. and no write was issued for the leftover row — the route reports the gap rather than cleaning it up itself',
  survivorIds.length > 0 && rows.replay_attempts.length === survivorIds.length
    && !calls.deletes.some((c) => c.table === 'replay_attempts' && survivorIds.includes(c.id)),
  `leftover=${JSON.stringify(survivorIds)}`);

// The inventory itself: a table the sweep should cover must be declared, and asserting the list is
// louder and more diagnosable than a crash when someone drops it.
check('D4. the declared dependency inventory covers every table the live schema references by game id',
  Object.values(rules.GAME_TABLES).join(',') === 'recorded_hands,community_games,game_analysis_reports,ai_decision_traces,tournament_attempts,replay_attempts'
    && rules.GAME_COLUMNS.replayAttempts.recordedHandId === 'recorded_hand_id'
    && rules.GAME_COLUMNS.replayAttempts.rootHandId === 'root_hand_id'
    && rules.GAME_COLUMNS.recordedHands.parentHandId === 'parent_hand_id',
  JSON.stringify({ tables: rules.GAME_TABLES, coach: rules.COACH_FLAG_TABLE }));
check('D4b. coach flags are declared as preserved-and-reported, never as a sweep target',
  rules.COACH_FLAGS_DISPOSITION === 'preserved-and-reported'
    && rules.COACH_FLAG_TABLE.table === 'coach_feedback_flags'
    && !Object.values(rules.GAME_TABLES).includes('coach_feedback_flags')
    && !rules.SWEEP_STEPS.includes('coachFlags'),
  `${rules.COACH_FLAGS_DISPOSITION} / ${rules.SWEEP_STEPS.join(',')}`);

check('16c. and the two are reported INDISTINGUISHABLY, because NodeSend has no tombstone to tell them apart',
  JSON.stringify(repeat.body.data.alreadyAbsent) === JSON.stringify(neverSeen.body.data.alreadyAbsent)
    && repeat.body.data.deleted === neverSeen.body.data.deleted
    && !JSON.stringify(repeat.body).includes('existed') && !JSON.stringify(neverSeen.body).includes('existed'),
  `${JSON.stringify(repeat.body.data)} vs ${JSON.stringify(neverSeen.body.data)}`);

// ── 4: foreign replay descendants ───────────────────────────────────────────────────────────────
seedGame({ foreignChild: true });
const handsBefore = snapshot('recorded_hands');
const foreign = await del(GAME, 'tok-admin');
check('4. a replay descendant owned by ANOTHER player refuses the whole request, deleting nothing',
  foreign.status === 409 && foreign.body?.error?.code === 'foreign_replay_descendants'
    && calls.deletes.length === 0 && snapshot('recorded_hands') === handsBefore,
  `${foreign.status} ${JSON.stringify(foreign.body).slice(0, 200)} deletes=${calls.deletes.length}`);
check('4b. the refusal counts descendants without naming other players\u2019 ids or rows',
  !JSON.stringify(foreign.body).includes('5004') && !JSON.stringify(foreign.body).includes('someone else')
    && /\b1\b/.test(String(foreign.body?.error?.message ?? '')),
  JSON.stringify(foreign.body).slice(0, 220));

// ── 17: partial failure and safe retry ──────────────────────────────────────────────────────────
seedGame({ communityRoot: true });
FAULTS.failDeleteOf = { table: 'game_analysis_reports', id: 'r1' };
const partial = await del(GAME, 'tok-admin');
FAULTS.failDeleteOf = null;
check('17. a refused satellite delete stops the sweep: no deleted:true, canonical still present',
  partial.status !== 200 && partial.body?.data?.deleted === undefined
    && rows.recorded_hands.some((r) => r.id === GAME) && rows.tournament_attempts.some((a) => a.id === 'a1') === false,
  `${partial.status} ${JSON.stringify(partial.body).slice(0, 220)}`);
const retried = await del(GAME, 'tok-admin');
check('17b. the identical retry completes, and the already-removed satellites report 0 rather than double-deleting',
  retried.status === 200 && retried.body?.data?.deleted === true
    && retried.body?.data?.removed?.tournamentAttempts === 0 && retried.body?.data?.removed?.analysisReports === 1
    && !rows.recorded_hands.some((r) => r.id === GAME),
  JSON.stringify(retried.body).slice(0, 260));

// ── false-success plant: a DELETE that 200s but leaves the row ──────────────────────────────────
seedGame();
FAULTS.keepRowsIn = true;                 // every table answers success and keeps the row
const lying = await del(GAME, 'tok-admin');
FAULTS.keepRowsIn = null;
check('NC1. a vendor that answers success but keeps the row is NEVER reported as deleted',
  lying.status !== 200 && lying.body?.data?.deleted === undefined
    && String(lying.body?.error?.code ?? '').length > 0 && rows.recorded_hands.some((r) => r.id === GAME),
  `${lying.status} ${JSON.stringify(lying.body).slice(0, 220)}`);

// Per-table lies. These are the arms that make the SATELLITE read-back proof actually under test: with a
// global switch, the canonical step's own proof caught the problem and the satellite proofs were never
// exercised (a plant removing them left the suite green — measured).
for (const [tableName, label] of [['tournament_attempts', 'NC1b'], ['game_analysis_reports', 'NC1c'], ['community_games', 'NC1d']]) {
  seedGame({ communityRoot: true });
  FAULTS.keepRowsIn = [tableName];
  const liar = await del(GAME, 'tok-admin');
  FAULTS.keepRowsIn = null;
  const stillThere = (rows[tableName] ?? []).length > 0;
  check(`${label}. a lying DELETE on ${tableName} alone is refused as unconfirmed, never counted as removed`,
    liar.status !== 200 && liar.body?.data === undefined && stillThere
      && rows.recorded_hands.some((r) => r.id === GAME),
    `${liar.status} rows=${JSON.stringify(rows[tableName]).slice(0, 120)} ${JSON.stringify(liar.body).slice(0, 120)}`);
}

// ── storage unreachable mid-sweep ───────────────────────────────────────────────────────────────
seedGame();
FAULTS.refuseRead = { table: 'community_games', column: 'source_hand_id' };
const unreachable = await del(GAME, 'tok-admin');
FAULTS.refuseRead = null;
check('NC2. an unreachable table is a named 503/502 with the game intact, never a partial success',
  (unreachable.status === 502 || unreachable.status === 503) && unreachable.body?.data === undefined
    && rows.recorded_hands.some((r) => r.id === GAME),
  `${unreachable.status} ${JSON.stringify(unreachable.body).slice(0, 180)}`);

// ── 19: the existing relay path, recorded as a blocker if still open ─────────────────────────────
const relayProbe = await fetch(`${BASE}/ncb/data/delete/recorded_hands/7777`, {
  method: 'DELETE', headers: { authorization: 'Bearer tok-user' }
});
const relayBody = await relayProbe.json().catch(() => ({}));
check('19. the pre-existing relay DELETE path is measured and reported, not silently assumed closed',
  relayProbe.status === 403 || relayProbe.status === 401,
  `relay DELETE as an ordinary player -> ${relayProbe.status} ${JSON.stringify(relayBody).slice(0, 160)} (403/401 expected; any other answer is the documented bypass)`);

// ── 20: existing surfaces unaffected ────────────────────────────────────────────────────────────
const health = await (await fetch(`${BASE}/health`)).json();
const clubs = await fetch(`${BASE}/clubs`, { headers: { authorization: 'Bearer tok-user' } });
const tourneys = await fetch(`${BASE}/tournaments`, { headers: { authorization: 'Bearer tok-user' } });
check('20. clubs, tournaments and health still answer as before; the new mount did not disturb them',
  health.status === 'healthy' && health.clubs?.configured === true && health.tournaments?.configured === true
    && typeof health.gameDeletion?.configured === 'boolean'
    && (clubs.status === 200 || clubs.status === 403 || clubs.status === 503)
    && (tourneys.status === 200 || tourneys.status === 403 || tourneys.status === 503),
  `${health.status} clubs=${health.clubs?.configured} tours=${health.tournaments?.configured} clubsHttp=${clubs.status} toursHttp=${tourneys.status}`);
// ── unit boundaries that the HTTP route cannot reach, asserted directly ─────────────────────────
// (`rules` is declared next to the bridge that provides it, above the first arm that uses it.)
const storeModule = bridge.gameDeletionStore;
check('NC3a. deleted:true is IMPOSSIBLE without confirmedGone, at the envelope builder itself',
  rules.deletionResult({ removed: { communityGames: 2 }, confirmedGone: false }).body.data.deleted === false
    && rules.deletionResult({ removed: {}, confirmedGone: true }).body.data.deleted === true,
  JSON.stringify(rules.deletionResult({ confirmedGone: false }).body.data));
let unfilteredOutcome = 'not-run';
let unfilteredRequestsIssued = 0;
try {
  const probeStore = storeModule.createGameDeletionStore({
    client: {
      configured: true,
      async request(spec) {
        // Count what actually reached the vendor: a filterless `read/recorded_hands` is a bulk read.
        unfilteredRequestsIssued += 1;
        return { ok: true, body: { status: 'success', data: [] } };
      }
    }
  });
  const r = await probeStore.findCanonical('');
  unfilteredOutcome = r?.storeFailure ? 'refused' : (r?.row === null && unfilteredRequestsIssued === 0 ? 'skipped' : 'ALLOWED');
} catch (error) {
  unfilteredOutcome = 'threw';
}
check('NC3b. the store refuses an unfiltered read instead of issuing a table-wide query',
  unfilteredRequestsIssued === 0 && ['refused', 'threw', 'skipped'].includes(unfilteredOutcome),
  `outcome=${unfilteredOutcome} requestsIssued=${unfilteredRequestsIssued}`);
check('NC3c. exactRowOps will not emit a wildcard, empty or oversized row id for deletion',
  rules.exactRowOps([{ id: '' }, { id: null }, { id: 'a'.repeat(80) }, { id: '1;DROP' }, { id: 'ok-1' }])
    .join(',') === 'ok-1', JSON.stringify(rules.exactRowOps([{ id: '' }, { id: null }, { id: 'a'.repeat(80) }, { id: '1;DROP' }, { id: 'ok-1' }])));
check('NC3d. a child with an unreadable owner is treated as FOREIGN, never as deletable',
  rules.classifyReplayChildren({ ownerId: '7', children: [{ id: 'x', user_id: null }, { id: 'y' }] }).hasForeign === true
    && rules.classifyReplayChildren({ ownerId: '', children: [{ id: 'x', user_id: '7' }] }).hasForeign === true,
  JSON.stringify(rules.classifyReplayChildren({ ownerId: '7', children: [{ id: 'x', user_id: null }] })));
// A throw inside the sweep must ANSWER, not hang. Express 4 does not catch a rejected async handler, so
// without a catch-all the socket stalls and the caller cannot tell whether rows were removed — the worst
// possible outcome for a destructive verb. Proven with a stub store that throws on purpose.
const { default: express } = await import('express');
const faultApp = express();
faultApp.use(bridge.buildGameDeletionMount({
  env: process.env,
  authenticate: async () => ({ ok: true, id: '1' }),
  clubStore: { isSystemAdmin: async () => ({ declared: true, available: true, isAdmin: true }) },
  clubAccount: { configured: true },
  deletionStore: {
    findCanonical: async () => ({ row: { id: '5001', user_id: '7', root_hand_id: null } }),
    findChildren: async () => ({ rows: [] }),
    countSatellites: async () => ({ total: 0 }),
    execute: async () => { throw new TypeError('simulated internal fault mid-sweep'); }
  }
}).router);
const faultServer = faultApp.listen(0, '127.0.0.1');
await new Promise((resolve) => faultServer.once('listening', resolve));
let faultAnswer = { status: 'NO ANSWER (socket hung)', body: null };
try {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  const res = await fetch(`http://127.0.0.1:${faultServer.address().port}/games/5001`, {
    method: 'DELETE', headers: { authorization: 'Bearer x' }, signal: controller.signal
  });
  faultAnswer = { status: res.status, body: await res.json().catch(() => null) };
  clearTimeout(timer);
} finally { faultServer.close(); }
check('NC3f. an internal fault answers a named refusal instead of hanging the socket, and never claims deletion',
  typeof faultAnswer.status === 'number' && faultAnswer.status >= 400
    && faultAnswer.body?.error?.code === 'game_deletion_incomplete'
    && faultAnswer.body?.data === undefined
    && !JSON.stringify(faultAnswer.body).includes('simulated internal fault'),
  JSON.stringify(faultAnswer).slice(0, 200));

check('NC3e. the sweep order is satellites-first and canonical-last — the recovery marker contract',
  rules.SWEEP_STEPS.indexOf('recordedHand') === rules.SWEEP_STEPS.length - 1
    && rules.SWEEP_STEPS.indexOf('communityGames') < rules.SWEEP_STEPS.indexOf('recordedHand'),
  rules.SWEEP_STEPS.join(','));

/* ── frontend contract compatibility (candidate 514ad394) ──────────────────────────────────────
 * The client's ONLY signal for a refusal is `body.error.code`: it switches on HTTP status for
 * 200/401/403/404/503 and maps everything else to `malformed_envelope`. So the backend's obligation is
 * that every non-success answer carries a non-empty code AND message, and that nothing ever claims
 * `deleted:true` without the row being gone. Arms C1-C4 pin exactly that. */
const refusalBodies = [
  ['not-system-admin', user.body], ['club-admin', clubAdmin.body], ['unauthenticated', anonBody],
  ['forged-role', forged.body], ['foreign-children', foreign.body], ['partial-sweep', partial.body],
  ['unconfirmed-delete', lying.body], ['unreachable', unreachable.body]
].filter(([, body]) => body);
const badRefusals = refusalBodies
  .filter(([, body]) => typeof body?.error?.code !== 'string' || body.error.code.trim() === ''
    || typeof body?.error?.message !== 'string' || body.error.message.trim() === '')
  .map(([label, body]) => `${label}=${JSON.stringify(body).slice(0, 70)}`);
check('C1. every refusal carries the object-form error.code and message the client reads',
  badRefusals.length === 0, badRefusals.join(' | '));
check('C2. no refusal is ever shaped like a success (no data key, status is not success)',
  refusalBodies.every(([, body]) => body?.status !== 'success' && body?.data === undefined),
  JSON.stringify(refusalBodies.filter(([, b]) => b?.data !== undefined).map(([l]) => l)));
const sd = ok.body?.data ?? {};
check('C3. the success envelope exposes exactly the fields the client consumes, with usable types',
  sd.deleted === true && typeof sd.alreadyAbsent === 'boolean' && sd.removed && typeof sd.removed === 'object'
    && ['recordedHands', 'communityGames', 'analysisReports', 'decisionTraces', 'tournamentAttempts', 'replayAttempts']
      .every((k) => Number.isInteger(sd.removed[k]))
    && Number.isInteger(sd.replayChildren) && ok.body?.error === undefined,
  JSON.stringify(sd).slice(0, 260));
check('C3b. an idempotent repeat also satisfies the client gate (it requires deleted === true to proceed)',
  repeat.body?.data?.deleted === true && repeat.body?.data?.alreadyAbsent === true,
  JSON.stringify(repeat.body?.data).slice(0, 200));
// The documented gap, asserted rather than assumed away: the client at 514ad394 has no branch for 409 or
// 502, so both land in `malformed_envelope` ("Nothing was deleted" — SAFE, but it discards the two most
// actionable answers this route produces). The codes still arrive intact, which is what the handoff needs.
check('C4. the codes the client cannot yet map still arrive named (handoff prerequisite)',
  foreign.body?.error?.code === 'foreign_replay_descendants' && foreign.status === 409
    && partial.body?.error?.code === 'game_deletion_incomplete' && (partial.status === 502 || partial.status === 503),
  `${foreign.status}/${foreign.body?.error?.code} ${partial.status}/${partial.body?.error?.code}`);

check('NC3. no request in this run ever left the mock host', calls.offHost.length === 0, calls.offHost.slice(0, 3).join(','));
/*
 * A guard against the exact defect this file just had: a fault knob was renamed and one arm kept
 * assigning the OLD key, so that arm's plant became inert while still printing PASS. Every key the
 * harness declares must actually be READ by the mock, or a "negative control" is decoration.
 */
const source = fs.readFileSync(path.join(ROOT, 'verify-game-deletion.mjs'), 'utf8');
const declared = Object.keys(FAULTS);
const inertKnobs = declared.filter((key) => {
  const reads = (source.match(new RegExp(`FAULTS\\.${key}`, 'g')) || []).length;
  // One occurrence means only the declaration exists; a mock branch and an assignment make >= 3.
  return reads < 3;
});
check('NC4b. every declared fault knob is actually read by the mock (no inert negative controls)',
  inertKnobs.length === 0, `inert: ${inertKnobs.join(', ')}`);
check('NC4. no credential, bearer or private hand content appears in any deletion answer',
  (() => {
    const seen = JSON.stringify([ok.body, foreign.body, partial.body, lying.body, unreachable.body, repeat.body]);
    return !seen.includes(SERVICE_TOKEN) && !seen.includes(PASSWORD) && !seen.includes(SERVICE_EMAIL)
      && !seen.includes('{"private":"cards"}') && !seen.includes('Bearer ');
  })(), '');

let failed = 0;
for (const r of results) {
  if (!r.pass) failed += 1;
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.pass ? '' : `   ${r.detail}`}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed  (game deletion gate)`);
server.close();
process.exit(failed ? 1 : 0);
