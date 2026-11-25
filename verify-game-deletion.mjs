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
  // `publisher_user_id` was invented by an earlier version of this file and exists nowhere in the
  // frontend; the live owner column is `user_id`, written on every insert. Uniform owner values across
  // these tables are precisely what let a missing owner predicate survive a green suite.
  community_games: ['id', 'source_hand_id', 'root_hand_id', 'user_id'],
  game_analysis_reports: ['id', 'recorded_hand_id', 'author_user_id', 'user_id'],
  ai_decision_traces: ['id', 'recorded_hand_id', 'board_id', 'root_hand_id', 'source', 'operation', 'decision_id', 'user_id'],
  tournament_attempts: ['id', 'tournament_id', 'recorded_hand_id', 'player_user_id', 'user_id'],
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
// `refuseDeleteWith403` is the OTHER vendor answer, and the one production actually gave: the storage was
// reached, said NO, and removed nothing. `failDeleteOf` answers 500, which the client classifies as
// `club_account_request_failed`; a 403 classifies as `club_account_forbidden`. The two must not collapse
// into one instruction, so the harness needs both knobs.
const FAULTS = { failDeleteOf: null, refuseRead: null, keepRowsIn: null, refuseDeleteWith403: null };
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
    // A permission refusal: the row survives and the vendor says so with a 403. This is the shape the
    // first production deletion hit, and it must NOT be reported the same way as a transport failure.
    if (FAULTS.refuseDeleteWith403) {
      const hit = Array.isArray(FAULTS.refuseDeleteWith403)
        ? FAULTS.refuseDeleteWith403.includes(table)
        : FAULTS.refuseDeleteWith403 === true;
      if (hit) return json({ status: 'error', error: 'you do not have permission to perform this action', message: 'Forbidden' }, 403);
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

/*
 * The fixture. Every satellite row carries the owner column the LIVE WRITER fills, because the shape that
 * hid the defect was a fixture in which every satellite belonged to the same account: an owner predicate
 * that is never exercised on a differing value is not a tested rule. `userB = '12'` is the other account.
 */
const OWNER_A = '7';
const OWNER_B = '12';
const seedGame = ({
  foreignChild = false, communityRoot = false, flagTrace = true,
  rootTraceOwn = true,              // a chain-root-linked trace owned by the game owner (must be swept)
  foreignRootTrace = false,         // the same shape owned by another account (must refuse)
  foreignCommunityRoot = false,   // B published A's game: matched via root_hand_id
  foreignCommunitySource = false, // B's publication naming A's game directly as its source
  foreignAttempt = false,         // B consumed a replay attempt on A's chain (replayEligibility.js:117)
  unownedSatellite = false,       // a selected row whose owner column is empty
  mixedForeign = false,           // foreign rows in three different cascade tables at once
  stranger = false,               // foreign rows keyed to OTHER games: must not block anything
  orphanOwner = false,            // the canonical game row itself has no readable owner
  noChildren = false              // no replay descendants, so the child rule cannot pre-empt the audit
} = {}) => {
  for (const k of Object.keys(rows)) {
    if (['system_admins', 'clubs', 'club_memberships'].includes(k)) continue;
    rows[k].length = 0;
  }
  calls.deletes.length = 0;
  calls.reads.length = 0;
  rows.recorded_hands.push({ id: GAME, user_id: orphanOwner ? null : OWNER_A, root_hand_id: null, board_data: '{"private":"cards"}' });
  if (!noChildren) {
    rows.recorded_hands.push({ id: '5002', user_id: OWNER_A, root_hand_id: GAME, board_data: 'child-own' });    // same owner
    rows.recorded_hands.push({ id: '5003', user_id: OWNER_A, root_hand_id: GAME, board_data: 'child-own-2' });  // same owner
  }
  if (foreignChild) rows.recorded_hands.push({ id: '5004', user_id: OWNER_B, root_hand_id: GAME, board_data: 'someone else game' });
  rows.community_games.push({ id: 'c1', source_hand_id: GAME, root_hand_id: null, user_id: OWNER_A });
  if (communityRoot) rows.community_games.push({ id: 'c2', source_hand_id: '5002', root_hand_id: GAME, user_id: OWNER_A });
  if (foreignCommunityRoot) rows.community_games.push({ id: 'cF1', source_hand_id: '6120', root_hand_id: GAME, user_id: OWNER_B });
  if (foreignCommunitySource) rows.community_games.push({ id: 'cF2', source_hand_id: GAME, root_hand_id: GAME, user_id: OWNER_B });
  if (unownedSatellite) rows.community_games.push({ id: 'cU1', source_hand_id: null, root_hand_id: GAME, user_id: null });
  if (stranger) {
    rows.community_games.push({ id: 'cS1', source_hand_id: '8801', root_hand_id: '8801', user_id: OWNER_B });
    rows.replay_attempts.push({ id: 'raS1', recorded_hand_id: '8801', root_hand_id: '8801', user_id: OWNER_B });
    rows.game_analysis_reports.push({ id: 'rS1', recorded_hand_id: '8801', author_user_id: OWNER_B, user_id: OWNER_B });
    rows.ai_decision_traces.push({ id: 'tS1', recorded_hand_id: '8801', board_id: '95', root_hand_id: '8801', source: 'gameplay', operation: 'play_card', decision_id: 'dS1', user_id: OWNER_B });
    rows.tournament_attempts.push({ id: 'aS2', tournament_id: 'T1', recorded_hand_id: '8801', player_user_id: OWNER_B, user_id: SERVICE_ID });
  }
  // A report authored by the coach but OWNED by the player: authorship is not ownership, and it must
  // still cascade. `gameAnalysisService.js:305` writes user_id = the hand owner.
  rows.game_analysis_reports.push({ id: 'r1', recorded_hand_id: GAME, author_user_id: '4', user_id: OWNER_A });
  if (mixedForeign) rows.game_analysis_reports.push({ id: 'rF1', recorded_hand_id: GAME, author_user_id: OWNER_B, user_id: OWNER_B });
  /* Three real trace shapes, taken from the live writers and readers in `aiDecisionTraces.js`. Field names
   * are the ones the writers actually send (`source`, `operation`, `decision_id`, `board_id`) — there is no
   * `kind` column in any writer, and a fixture that invents one is how the `publisher_user_id` audit passed
   * while testing a fictional field.
   *   t1 — `persistTraces(recordedHandId)` (:49-75): `recorded_hand_id` set. THIS is the hand's own audit
   *        trail, read back by `loadTracesByHand`, and it must cascade with the hand.
   *   t2 — `persistAnalysisTrace` (:120-152) with no chain value at all: out of scope for every probe, so
   *        it survives byte-identically and must never block anything.
   *   t3 — `persistTracesForFlag` (:87-115, called only when `recordedHandId == null`):
   *        `recorded_hand_id: null` WITH `board_id`/`root_hand_id` set. This is the durable full
   *        request/response audit an Auction Review flag resolves (`coachFlagSnapshot.js:64-89` keeps only
   *        `fullAuditAvailable: true`; `FlaggedGamesAdmin.jsx:177-186` reads the trace table by
   *        `decision_id`; `loadTracesByBoard` reads it by `board_id`). It is PROTECTED EVIDENCE: counted,
   *        reported as `preserved.flagSnapshotTraces`, never deleted.
   *   t4 — the same ledger row owned by another account (the coach who flagged it). Also protected:
   *        retaining a row needs no ownership claim, so it must not refuse the deletion either. */
  rows.ai_decision_traces.push({ id: 't1', recorded_hand_id: GAME, board_id: '94', root_hand_id: GAME, source: 'gameplay', operation: 'play_card', decision_id: 'd1', user_id: OWNER_A });
  if (flagTrace) rows.ai_decision_traces.push({ id: 't2', recorded_hand_id: null, board_id: '96', root_hand_id: null, source: 'coach', operation: 'analyze_hand', decision_id: 'd2', user_id: '4' });
  if (rootTraceOwn) rows.ai_decision_traces.push({ id: 't3', recorded_hand_id: null, board_id: '94', root_hand_id: GAME, source: 'coach', operation: 'analyze_hand', decision_id: 'd3', user_id: OWNER_A });
  if (foreignRootTrace) rows.ai_decision_traces.push({ id: 't4', recorded_hand_id: null, board_id: '94', root_hand_id: GAME, source: 'coach', operation: 'analyze_hand', decision_id: 'd4', user_id: OWNER_B });
  // NodeSend writes the attempt link on the SERVICE ACCOUNT, so its stamped user_id is NOT the player.
  // Resolution must prefer `player_user_id`, or every legitimate deletion refuses.
  rows.tournament_attempts.push({ id: 'a1', tournament_id: 'T1', recorded_hand_id: GAME, player_user_id: OWNER_A, user_id: SERVICE_ID });
  if (mixedForeign) rows.tournament_attempts.push({ id: 'aS1', tournament_id: 'T1', recorded_hand_id: '5002', player_user_id: OWNER_B, user_id: SERVICE_ID });
  // A replay attempt keyed directly to the game, and one that names ONLY the chain root — the second is
  // invisible to a sweep that looks at recorded_hand_id alone.
  rows.replay_attempts.push({ id: 'ra1', recorded_hand_id: GAME, root_hand_id: GAME, user_id: OWNER_A });
  rows.replay_attempts.push({ id: 'ra2', recorded_hand_id: null, root_hand_id: GAME, user_id: OWNER_A });
  if (foreignAttempt) rows.replay_attempts.push({ id: 'raF1', recorded_hand_id: null, root_hand_id: GAME, user_id: OWNER_B });
  if (stranger) rows.replay_attempts.push({ id: 'raS1', recorded_hand_id: '8801', root_hand_id: '8801', user_id: OWNER_B });
  if (mixedForeign) rows.replay_attempts.push({ id: 'raF2', recorded_hand_id: '5002', root_hand_id: GAME, user_id: OWNER_B });
  // Coach flags: another person's record. Counted and reported, never deleted.
  rows.coach_feedback_flags.push({ id: 'f1', hand_id: GAME, root_hand_id: GAME, coach_user_id: '4', user_id: '4' });
  rows.coach_feedback_flags.push({ id: 'f2', hand_id: '7777', root_hand_id: '7777', coach_user_id: '4', user_id: '4' });
  // A child that names this game ONLY as its parent: root_hand_id points at an older row, so a
  // root-only child search would miss it and leave a dangling parent reference.
  if (!noChildren) rows.recorded_hands.push({ id: '5099', user_id: OWNER_A, root_hand_id: '4404', parent_hand_id: GAME, board_data: 'mid-chain child' });
  // Unrelated data that must survive byte-identically.
  rows.recorded_hands.push({ id: '7777', user_id: '8', root_hand_id: null, board_data: 'another player' });
  rows.tournaments.push({ id: 'T1', owner_user_id: '4', name: 'Autumn Congress' });
  rows.tournament_boards.push({ id: 'b1', tournament_id: 'T1', board_number: '1' });
  rows.tournament_attempts.push({ id: 'a2', tournament_id: 'T1', recorded_hand_id: '7777', player_user_id: '9', user_id: SERVICE_ID });
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
    && d.removed?.replayAttempts === 2
    && d.preserved?.coachFeedbackFlags === 1 && d.preserved?.flagSnapshotTraces === 1,
  `${ok.status} ${JSON.stringify(ok.body).slice(0, 300)}`);
check('7. every community publication row is gone, by BOTH source_hand_id and root_hand_id, counted once',
  rows.community_games.filter((c) => c.source_hand_id === GAME || c.root_hand_id === GAME).length === 0,
  JSON.stringify(rows.community_games));
check('8. the analysis report for the game is gone',
  rows.game_analysis_reports.filter((r) => r.recorded_hand_id === GAME).length === 0, JSON.stringify(rows.game_analysis_reports));
check('9. the game-associated AI trace is gone',
  !rows.ai_decision_traces.some((t) => t.id === 't1'), JSON.stringify(rows.ai_decision_traces));
check('RT1. a chain-root-linked trace with recorded_hand_id NULL (the flag ledger row) is PRESERVED, never deleted',
  rows.ai_decision_traces.some((t) => t.id === 't3' && t.recorded_hand_id === null && t.root_hand_id === GAME)
    && !calls.deletes.some((c) => c.table === 'ai_decision_traces' && c.id === 't3'),
  `traces=${JSON.stringify(rows.ai_decision_traces.map((t) => [t.id, t.recorded_hand_id, t.root_hand_id]))} deletes=${JSON.stringify(calls.deletes.filter((c) => c.table === 'ai_decision_traces'))}`);
check('RT1b. the delete ledger for traces is exactly the hand-owned audit row, one call, no root-pass delete',
  calls.deletes.filter((c) => c.table === 'ai_decision_traces').map((c) => c.id).sort().join(',') === 't1',
  JSON.stringify(calls.deletes.filter((c) => c.table === 'ai_decision_traces')));
check('RT1c. and the retained evidence is REPORTED, not silent: preserved.flagSnapshotTraces counts it',
  d.preserved?.flagSnapshotTraces === 1, JSON.stringify(d.preserved ?? null));
/* The pair the retention contract is really about: a flag row survives (D3) AND the ledger row its
 * `fullAuditAvailable: true` / `decision_id` reference resolves through survives with it. Preserving the
 * pointer while deleting the target is the violation this gate exists to catch. */
check('RV1. the surviving coach flag can still resolve the audit it points at after the game is deleted',
  rows.coach_feedback_flags.some((f) => f.id === 'f1')
    && rows.ai_decision_traces.some((t) => t.id === 't3' && t.operation === 'analyze_hand' && t.decision_id === 'd3'),
  `flags=${JSON.stringify(rows.coach_feedback_flags.map((f) => f.id))} traces=${JSON.stringify(rows.ai_decision_traces.map((t) => [t.id, t.operation, t.decision_id]))}`);
check('10. the genuinely unlinked flag snapshot (no recorded_hand_id, no root_hand_id) is PRESERVED byte-identically',
  JSON.stringify(rows.ai_decision_traces.filter((t) => t.id === 't2')) === before.flagTrace
    && !calls.deletes.some((c) => c.table === 'ai_decision_traces' && c.id === 't2'),
  JSON.stringify(rows.ai_decision_traces));
check('RT4. and it never blocks the deletion either: out-of-scope data is not an ownership problem',
  ok.status === 200 && d.deleted === true && rows.ai_decision_traces.some((t) => t.id === 't2'),
  `${ok.status} ${JSON.stringify(rows.ai_decision_traces.map((t) => t.id))}`);
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
/* The cascade-complete proof for every table whose rows the deletion OWNS: nothing in the sweep scope may
 * still name the deleted game in any reference column. `ai_decision_traces` is checked separately, because
 * its root-linked ledger rows are retained on purpose — the contract being verified here is "no orphaned
 * ordinary analysis record", not "no row ever mentioned the game". */
check('RT2. no swept table still names the deleted game in any reference column',
  ['recorded_hands', 'community_games', 'game_analysis_reports', 'tournament_attempts', 'replay_attempts']
    .every((table) => (rows[table] ?? []).every((row) => row.recorded_hand_id !== GAME && row.root_hand_id !== GAME
      && row.source_hand_id !== GAME && row.hand_id !== GAME && row.parent_hand_id !== GAME))
    && !rows.ai_decision_traces.some((t) => t.recorded_hand_id === GAME),
  JSON.stringify(Object.fromEntries(Object.keys(rows).map((t) => [t, (rows[t] ?? []).map((r) => [r.id, r.recorded_hand_id, r.root_hand_id])]))));
check('RT2b. every retained trace row is a flag ledger row, never an ordinary analysis record of this hand',
  rows.ai_decision_traces.filter((t) => t.recorded_hand_id !== GAME)
    .every((t) => t.recorded_hand_id === null && t.board_id !== null),
  JSON.stringify(rows.ai_decision_traces.map((t) => [t.id, t.recorded_hand_id, t.board_id])));
check('RT2c. the deletion scope and the retention scope are disjoint, and their union is the whole inventory',
  rules.SWEEP_PROBES.every((p) => rules.INVENTORY_PROBES.some((q) => q.key === p.key && q.column === p.column))
    && rules.RETAINED_EVIDENCE_PROBES.every((p) => !rules.SWEEP_PROBES.some((q) => q.key === p.key && q.column === p.column))
    && rules.INVENTORY_PROBES.length === rules.SWEEP_PROBES.length + rules.RETAINED_EVIDENCE_PROBES.length
    && rules.SWEEP_PROBES.filter((p) => p.key === 'decisionTraces').map((p) => p.column).join(',') === 'recordedHandId'
    && rules.RETAINED_EVIDENCE_PROBES.map((p) => `${p.key}.${p.column}`).join(',') === 'decisionTraces.rootHandId',
  JSON.stringify({ sweep: rules.SWEEP_PROBES, retained: rules.RETAINED_EVIDENCE_PROBES }));
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
  JSON.stringify(partialLook.body?.data ?? null).slice(0, 200));
check('16e. and no write was issued for the leftover row — the route reports the gap rather than cleaning it up itself',
  survivorIds.length > 0 && rows.replay_attempts.length === survivorIds.length
    && !calls.deletes.some((c) => c.table === 'replay_attempts' && survivorIds.includes(c.id)),
  `leftover=${JSON.stringify(survivorIds)}`);

/* The same claim for the table the old satellite probe list omitted entirely. Everything else is emptied
 * so ONLY a community_games row can make the answer false — an arm satisfied by any probe is not testing
 * the probe it exists for (measured on 16d). */
seedGame();
rows.recorded_hands.splice(rows.recorded_hands.findIndex((r) => r.id === GAME), 1);
rows.game_analysis_reports.length = 0;
rows.ai_decision_traces.length = 0;
rows.tournament_attempts.length = 0;
rows.replay_attempts.length = 0;
rows.community_games.length = 0;
// One row that matches BOTH community probes: the count is of rows, not of matches.
rows.community_games.push({ id: 'cLeft', source_hand_id: GAME, root_hand_id: GAME, user_id: OWNER_A });
const leftoverPublication = await del(GAME, 'tok-admin');
check('16f. a surviving community publication keyed to the game also forbids the clean-absence claim',
  leftoverPublication.status === 200 && leftoverPublication.body?.data?.alreadyAbsent === true
    && leftoverPublication.body?.data?.noTraceRemaining === false,
  JSON.stringify(leftoverPublication.body?.data ?? null).slice(0, 200));
check('16g. and it is reported without touching the surviving row',
  rows.community_games.length === 1 && rows.community_games[0].id === 'cLeft'
    && !calls.deletes.some((c) => c.table === 'community_games' && c.id === 'cLeft'),
  JSON.stringify(rows.community_games));

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
  Boolean(repeat.body?.data && neverSeen.body?.data)
    && JSON.stringify(repeat.body.data.alreadyAbsent) === JSON.stringify(neverSeen.body.data.alreadyAbsent)
    && repeat.body.data.deleted === neverSeen.body.data.deleted
    && !JSON.stringify(repeat.body).includes('existed') && !JSON.stringify(neverSeen.body).includes('existed'),
  `${JSON.stringify(repeat.body?.data)} vs ${JSON.stringify(neverSeen.body?.data)}`);

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

/* ── 4c: SATELLITE OWNERSHIP ────────────────────────────────────────────────────────────────────
 * The defect this section exists for: the deployed sweep selected satellites by a REFERENCE column
 * alone, and `community_games.root_hand_id` / `replay_attempts.root_hand_id` name a replay chain's FIRST
 * game — so another player's publication or consumed attempt matched the filter and was deleted without
 * any refusal. Every arm below compares a FULL snapshot of every table, because "zero records deleted"
 * is only evidence if nothing at all moved.
 */
const AUDIT_TABLES = Object.keys(rows).filter((k) => !['system_admins', 'clubs', 'club_memberships'].includes(k));
const snapshotAll = () => AUDIT_TABLES.map((t) => `${t}=${snapshot(t)}`).join('|');
const idFree = (body) => {
  const text = JSON.stringify(body ?? {});
  return !['cF1', 'cF2', 'cU1', 'rF1', 'raF1', 'raF2', 'aS1', 't4', 'community_games', 'replay_attempts',
    'ai_decision_traces', 'game_analysis_reports', 'tournament_attempts', OWNER_B].some((leak) => text.includes(leak));
};

seedGame({ foreignCommunityRoot: true });
let worldBefore = snapshotAll();
const fRoot = await del(GAME, 'tok-admin');
check('F1. a publication owned by ANOTHER player, matched through root_hand_id, refuses the whole request',
  fRoot.status === 409 && fRoot.body?.error?.code === 'foreign_satellite_owners'
    && calls.deletes.length === 0 && snapshotAll() === worldBefore,
  `${fRoot.status} ${JSON.stringify(fRoot.body).slice(0, 200)} deletes=${calls.deletes.length}`);
check('F1b. the refusal counts the row and names no id, table or account',
  /\b1 record\(s\) belong to another account\b/.test(String(fRoot.body?.error?.message ?? '')) && idFree(fRoot.body),
  JSON.stringify(fRoot.body).slice(0, 200));

seedGame({ foreignCommunitySource: true });
worldBefore = snapshotAll();
const fSource = await del(GAME, 'tok-admin');
check('F2. ownership, not lineage, is the rule: a FOREIGN publication keyed DIRECTLY to the game also refuses',
  fSource.status === 409 && fSource.body?.error?.code === 'foreign_satellite_owners'
    && calls.deletes.length === 0 && snapshotAll() === worldBefore,
  `${fSource.status} ${JSON.stringify(fSource.body).slice(0, 200)}`);

seedGame({ foreignAttempt: true });
worldBefore = snapshotAll();
const fAttempt = await del(GAME, 'tok-admin');
check('F3. another player\u2019s consumed replay attempt refuses the deletion and is left intact',
  fAttempt.status === 409 && fAttempt.body?.error?.code === 'foreign_satellite_owners'
    && calls.deletes.length === 0 && snapshotAll() === worldBefore
    && rows.replay_attempts.some((r) => r.id === 'raF1' && r.user_id === OWNER_B),
  `${fAttempt.status} ${JSON.stringify(fAttempt.body).slice(0, 200)}`);

seedGame({ unownedSatellite: true });
worldBefore = snapshotAll();
const fUnowned = await del(GAME, 'tok-admin');
check('F4. a selected satellite with NO readable owner fails closed: unknown ownership never authorises a delete',
  fUnowned.status === 409 && fUnowned.body?.error?.code === 'foreign_satellite_owners'
    && /no readable owner/.test(String(fUnowned.body?.error?.message ?? ''))
    && calls.deletes.length === 0 && snapshotAll() === worldBefore,
  `${fUnowned.status} ${JSON.stringify(fUnowned.body).slice(0, 200)}`);

seedGame({ mixedForeign: true });
worldBefore = snapshotAll();
const fMixed = await del(GAME, 'tok-admin');
check('F5. mixed ownership across three cascade tables is one refusal counting all three, written nowhere',
  fMixed.status === 409 && fMixed.body?.error?.code === 'foreign_satellite_owners'
    && /^3 record\(s\) belong to another account/.test(String(fMixed.body?.error?.message ?? ''))
    && calls.deletes.length === 0 && snapshotAll() === worldBefore,
  `${fMixed.status} ${JSON.stringify(fMixed.body).slice(0, 220)}`);

seedGame({ orphanOwner: true, noChildren: true });
worldBefore = snapshotAll();
const fOrphan = await del(GAME, 'tok-admin');
check('F6. an unreadable owner on the canonical game is never assumed to cover its satellites',
  fOrphan.status === 409 && fOrphan.body?.error?.code === 'foreign_satellite_owners'
    && /the recorded game itself has no readable owner/.test(String(fOrphan.body?.error?.message ?? ''))
    && calls.deletes.length === 0 && snapshotAll() === worldBefore,
  `${fOrphan.status} ${JSON.stringify(fOrphan.body).slice(0, 220)}`);

seedGame({ stranger: true, communityRoot: true });
const strangers = {
  community: snapshot('community_games').includes('cS1'),
  attempts: rows.replay_attempts.filter((r) => r.user_id === OWNER_B).map((r) => r.id).join(','),
  reports: snapshot('game_analysis_reports').includes('rS1'),
  traces: rows.ai_decision_traces.filter((t) => t.user_id === OWNER_B).map((t) => t.id).join(','),
  links: rows.tournament_attempts.filter((a) => a.player_user_id === OWNER_B).map((a) => a.id).join(',')
};
const fStranger = await del(GAME, 'tok-admin');
check('F7. foreign rows elsewhere in the same tables, keyed to OTHER games, do not block a legitimate deletion',
  fStranger.status === 200 && fStranger.body?.data?.deleted === true,
  `${fStranger.status} ${JSON.stringify(fStranger.body).slice(0, 220)}`);
check('F7b. and every one of those unrelated foreign rows survives byte-identically, never addressed by a delete',
  snapshot('community_games').includes('cS1') && rows.replay_attempts.filter((r) => r.user_id === OWNER_B).map((r) => r.id).join(',') === strangers.attempts
    && snapshot('game_analysis_reports').includes('rS1') && rows.tournament_attempts.filter((a) => a.player_user_id === OWNER_B).map((a) => a.id).join(',') === strangers.links
    && rows.ai_decision_traces.filter((t) => t.user_id === OWNER_B).map((t) => t.id).join(',') === strangers.traces
    && !calls.deletes.some((c) => ['cS1', 'raS1', 'rS1', 'tS1', 'aS2'].includes(c.id)),
  `before=${JSON.stringify(strangers)} after=${JSON.stringify({ c: rows.community_games.map((r) => r.id), ra: rows.replay_attempts.map((r) => r.id) })}`);

/* A refusal has to be escapable by doing the right thing, or it is a broken feature rather than a guard:
   re-own the publication (the repair an administrator would actually make) and the same request completes. */
seedGame({ foreignCommunityRoot: true, communityRoot: true });
const fBlocked = await del(GAME, 'tok-admin');
rows.community_games.find((c) => c.id === 'cF1').user_id = OWNER_A;
const fRepaired = await del(GAME, 'tok-admin');
check('F8. the refusal is actionable: once the satellite belongs to the game owner, the same request completes',
  fBlocked.status === 409 && fRepaired.status === 200 && fRepaired.body?.data?.deleted === true
    && fRepaired.body?.data?.removed?.communityGames === 3
    && !rows.recorded_hands.some((r) => r.id === GAME),
  `${fBlocked.status} then ${fRepaired.status} ${JSON.stringify(fRepaired.body).slice(0, 200)}`);

/* ── RT3: the foreign-owned flag ledger row ─────────────────────────────────────────────────────
 * `persistTracesForFlag` stamps `user_id` from the SIGNED-IN session, so a coach who flagged a board on
 * somebody else's chain leaves a ledger row owned by the coach. It is retained, not deleted — and because
 * nothing is deleted, the ownership rule has nothing to refuse: the foreign-owner refusal exists to stop
 * another account's row being REMOVED, and making it block a legitimate deletion over a row the sweep never
 * touches would be a refusal with nothing to protect.
 */
seedGame({ foreignRootTrace: true });
const fRootTrace = await del(GAME, 'tok-admin');
check('RT3. a foreign-owned flag ledger row neither blocks the deletion nor is deleted by it',
  fRootTrace.status === 200 && fRootTrace.body?.data?.deleted === true
    && rows.ai_decision_traces.some((t) => t.id === 't4' && t.user_id === OWNER_B)
    && !calls.deletes.some((c) => c.id === 't4'),
  `${fRootTrace.status} ${JSON.stringify(fRootTrace.body).slice(0, 200)}`);
check('RT3b. and it is counted in the retained evidence, so the retention is visible rather than implied',
  fRootTrace.body?.data?.preserved?.flagSnapshotTraces === 2,
  JSON.stringify(fRootTrace.body?.data?.preserved ?? null));
// Re-owning the ledger row must not silently convert protected evidence into cascade residue.
seedGame({ foreignRootTrace: true });
rows.ai_decision_traces.find((t) => t.id === 't4').user_id = OWNER_A;
const fRootTraceRepaired = await del(GAME, 'tok-admin');
check('RT3c. re-owning that ledger row does NOT turn it into cascade residue: it is still preserved',
  fRootTraceRepaired.status === 200 && fRootTraceRepaired.body?.data?.deleted === true
    && rows.ai_decision_traces.some((t) => t.id === 't4')
    && !calls.deletes.some((c) => c.id === 't4'),
  `${fRootTraceRepaired.status} ${JSON.stringify(rows.ai_decision_traces.map((t) => t.id))}`);

/* ── RT5: resuming the production state (Game 524's residue) ─────────────────────────────────────
 * The exact shape the first live deletion left behind: the replay child and the tournament link are
 * ALREADY gone, the canonical game and a set of root-linked traces survive. A retry must sweep the
 * residue, report the residue (not the original scope), and issue no write for a row that is absent.
 */
seedGame({ communityRoot: true });
rows.recorded_hands.splice(rows.recorded_hands.findIndex((r) => r.id === '5002'), 1);
rows.recorded_hands.splice(rows.recorded_hands.findIndex((r) => r.id === '5003'), 1);
rows.recorded_hands.splice(rows.recorded_hands.findIndex((r) => r.id === '5099'), 1);
rows.tournament_attempts.splice(rows.tournament_attempts.findIndex((a) => a.id === 'a1'), 1);
rows.ai_decision_traces.splice(rows.ai_decision_traces.findIndex((t) => t.id === 't1'), 1);
calls.deletes.length = 0;
const resumed = await del(GAME, 'tok-admin');
check('RT5. a deletion resumed after a partial sweep completes, and counts only what it actually removed',
  resumed.status === 200 && resumed.body?.data?.deleted === true
    && resumed.body?.data?.removed?.tournamentAttempts === 0
    && resumed.body?.data?.removed?.recordedHands === 1
    && resumed.body?.data?.removed?.decisionTraces === 0
    && resumed.body?.data?.preserved?.flagSnapshotTraces === 1
    && resumed.body?.data?.replayChildren === 0,
  `${resumed.status} ${JSON.stringify(resumed.body).slice(0, 260)}`);
check('RT5b. and it never issues a delete for a row that is absent or retained: one call per swept row',
  calls.deletes.map((c) => `${c.table}/${c.id}`).sort().join(',') === 'community_games/c1,community_games/c2,game_analysis_reports/r1,recorded_hands/5001,replay_attempts/ra1,replay_attempts/ra2',
  JSON.stringify(calls.deletes.map((c) => `${c.table}/${c.id}`).sort()));
check('RT5c. the resumed run still leaves the retained ledger row, the unlinked snapshot and the other player\u2019s game untouched',
  rows.ai_decision_traces.some((t) => t.id === 't2') && rows.ai_decision_traces.some((t) => t.id === 't3')
    && rows.recorded_hands.some((r) => r.id === '7777') && rows.coach_feedback_flags.length === 2,
  `traces=${JSON.stringify(rows.ai_decision_traces.map((t) => t.id))}`);

/* ── RT6/RT7: what the storage ANSWERED, told apart ─────────────────────────────────────────────
 * Three different failures, three different instructions. A 403 means the account cannot do this and
 * retrying is a circle; a 2xx that removed nothing means the write was acknowledged but not applied;
 * a session/transport failure (RT8) means nothing was reached at all. Collapsing them is what made the
 * production 502 unreadable.
 */
seedGame({ communityRoot: true });
worldBefore = snapshotAll();
FAULTS.refuseDeleteWith403 = ['ai_decision_traces'];
const refused403 = await del(GAME, 'tok-admin');
FAULTS.refuseDeleteWith403 = null;
const traces403 = rows.ai_decision_traces.filter((t) => ['t1', 't3'].includes(t.id)).map((t) => t.id);
check('RT6. a vendor HTTP 403 on a cascade delete answers 502 game_deletion_incomplete, never 503',
  refused403.status === 502 && refused403.body?.error?.code === 'game_deletion_incomplete'
    && refused403.body?.data === undefined,
  `${refused403.status} ${JSON.stringify(refused403.body).slice(0, 200)}`);
check('RT6b. and it names the step, the column and the storage status in machine-readable form',
  refused403.body?.error?.detail?.class === 'authorization_refused'
    && refused403.body?.error?.detail?.reason === 'club_account_forbidden'
    && refused403.body?.error?.detail?.storageStatus === 403
    && refused403.body?.error?.detail?.retryable === false
    && /^decisionTraces\.(recorded_hand_id|root_hand_id)$/.test(String(refused403.body?.error?.detail?.step ?? '')),
  JSON.stringify(refused403.body?.error?.detail ?? null));
check('RT6c. the sentence says a retry cannot help, instead of telling the admin to retry it',
  /refused the delete at decisionTraces/.test(String(refused403.body?.error?.message ?? ''))
    && /cannot succeed until the service account is granted delete/.test(String(refused403.body?.error?.message ?? ''))
    && !/retry the same request/.test(String(refused403.body?.error?.message ?? '')),
  String(refused403.body?.error?.message ?? '').slice(0, 240));
check('RT6d. the refused rows survive, the canonical row survives, and the earlier successes are not re-issued',
  traces403.length === 2 && rows.recorded_hands.some((r) => r.id === GAME)
    && !rows.tournament_attempts.some((a) => a.id === 'a1')
    && calls.deletes.filter((c) => c.id === 'a1').length === 1,
  `traces=${JSON.stringify(traces403)} deletes=${JSON.stringify(calls.deletes.map((c) => `${c.table}/${c.id}`))}`);
check('RT6e. a 403 leaks no credential, bearer or row content into the answer',
  !JSON.stringify(refused403.body).includes(SERVICE_TOKEN) && !JSON.stringify(refused403.body).includes(SERVICE_EMAIL)
    && !JSON.stringify(refused403.body).includes(PASSWORD) && !JSON.stringify(refused403.body).includes('{"private":"cards"}'),
  JSON.stringify(refused403.body).slice(0, 200));

// A 403 on the canonical row specifically: the worst case, because the satellites are already gone. Seeded
// without replay children so the first `recorded_hands` write IS the canonical row — with a child present
// the stop would name `replayChildren`, which is a different (and separately correct) answer.
seedGame({ communityRoot: true, noChildren: true });
FAULTS.refuseDeleteWith403 = ['recorded_hands'];
const refusedCanonical = await del(GAME, 'tok-admin');
FAULTS.refuseDeleteWith403 = null;
check('RT6f. a 403 on the canonical row names that step and admits the partial sweep is not restorable',
  refusedCanonical.status === 502 && refusedCanonical.body?.error?.detail?.step === 'recordedHand'
    && /Records already removed are not restorable/.test(String(refusedCanonical.body?.error?.message ?? ''))
    && rows.recorded_hands.some((r) => r.id === GAME),
  JSON.stringify(refusedCanonical.body).slice(0, 240));
check('RT6g. and every satellite it did remove stayed removed: the answer describes residue, not a rollback',
  calls.deletes.filter((c) => c.table === 'recorded_hands').length === 1
    && !rows.community_games.some((c) => c.id === 'c1') && !rows.game_analysis_reports.some((r) => r.id === 'r1'),
  JSON.stringify(calls.deletes.map((c) => `${c.table}/${c.id}`)));

// A 2xx that removed nothing, on the table production actually failed on.
seedGame({ communityRoot: true });
FAULTS.keepRowsIn = ['ai_decision_traces'];
const lyingTraces = await del(GAME, 'tok-admin');
FAULTS.keepRowsIn = null;
check('RT7. a DELETE acknowledged with 2xx that leaves the trace row is refused as write_not_applied',
  lyingTraces.status === 502 && lyingTraces.body?.error?.code === 'game_deletion_incomplete'
    && lyingTraces.body?.error?.detail?.class === 'write_not_applied'
    && lyingTraces.body?.error?.detail?.reason === 'game_delete_unconfirmed'
    && lyingTraces.body?.data === undefined
    && rows.ai_decision_traces.some((t) => t.id === 't1'),
  JSON.stringify(lyingTraces.body).slice(0, 240));
check('RT7b. and no trace count is reported, because an acknowledged call is not a removed row',
  String(JSON.stringify(lyingTraces.body?.error?.message ?? '')).includes('still present')
    && lyingTraces.body?.data === undefined,
  JSON.stringify(lyingTraces.body).slice(0, 200));

/* ── RT9 / RT10: the proof list and the sweep list cannot disagree ─────────────────────────────── */
seedGame({ communityRoot: true });
rows.recorded_hands.splice(rows.recorded_hands.findIndex((r) => r.id === GAME), 1);
// Every OTHER satellite table is emptied first. A version of this arm that left the publications in place
// would be satisfied (here: falsified) by an unrelated probe, so a build blind to the root column could
// still claim clean absence — the masked-assertion failure already measured on arm 16d. With this setup
// ONLY a root-linked trace can make the answer false, and only a truly empty set can make it true.
rows.community_games.length = 0;
rows.game_analysis_reports.length = 0;
rows.tournament_attempts.length = 0;
rows.replay_attempts.length = 0;
rows.ai_decision_traces.splice(0, rows.ai_decision_traces.length,
  ...rows.ai_decision_traces.filter((t) => ['t2', 't3'].includes(t.id)));
const survivorLook = await del(GAME, 'tok-admin');
check('RT10. with the canonical row gone but a root-linked trace still naming it, clean absence is NOT claimed',
  survivorLook.status === 200 && survivorLook.body?.data?.alreadyAbsent === true
    && survivorLook.body?.data?.noTraceRemaining === false,
  JSON.stringify(survivorLook.body?.data ?? null).slice(0, 220));
check('RT10b. and the leftover row is reported, not cleaned up by a route that never audited it',
  rows.ai_decision_traces.some((t) => t.id === 't3')
    && !calls.deletes.some((c) => c.table === 'ai_decision_traces' && c.id === 't3'),
  JSON.stringify(rows.ai_decision_traces.map((t) => t.id)));
// The other side of the same assertion: with the root-linked row gone as well, the claim must flip to
// true. Without this half, an arm that merely always answered "not clean" would pass every plant.
rows.ai_decision_traces.splice(0, rows.ai_decision_traces.length,
  ...rows.ai_decision_traces.filter((t) => t.id !== 't3'));
const emptiedLook = await del(GAME, 'tok-admin');
check('RT10c. and once the root-linked trace is gone too, the same request DOES claim clean absence',
  emptiedLook.status === 200 && emptiedLook.body?.data?.alreadyAbsent === true
    && emptiedLook.body?.data?.noTraceRemaining === true && calls.deletes.length === 0,
  JSON.stringify(emptiedLook.body?.data ?? null).slice(0, 220));

// The structural invariant that makes this whole class of omission impossible to reintroduce quietly:
// every reference column the inventory DECLARES for a cascade table must be a probe. `root_hand_id` on
// traces was declared, documented as covered, and never swept — an assertion on the list is what turns
// that into a red arm on the day it happens instead of a production incident.
const declaredRefs = Object.entries(rules.GAME_COLUMNS)
  .filter(([key]) => key !== 'recordedHands')
  .flatMap(([key, cols]) => Object.keys(cols).filter((c) => c !== 'id').map((c) => `${key}.${c}`));
const seenPairs = rules.INVENTORY_PROBES.map((p) => `${p.key}.${p.column}`).sort();
check('RT9. every reference column declared for a cascade table is at least SEEN (swept or explicitly retained)',
  declaredRefs.slice().sort().join(',') === seenPairs.join(','),
  JSON.stringify({ declared: declaredRefs.slice().sort(), seen: seenPairs }));
check('RT9b. and the protected ledger column is in the retention list, never in the delete list',
  !rules.SWEEP_PROBES.some((p) => p.key === 'decisionTraces' && p.column === 'rootHandId')
    && rules.RETAINED_EVIDENCE_PROBES.some((p) => p.key === 'decisionTraces' && p.column === 'rootHandId')
    && new Set(seenPairs).size === seenPairs.length,
  JSON.stringify({ sweep: rules.SWEEP_PROBES, retained: rules.RETAINED_EVIDENCE_PROBES }));

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
/* ── NC5: the store's OWN backstop, and the rules behind it ──────────────────────────────────────
 * F1-F6 prove the mount refuses. They would all still pass if the STORE were the unsafe part and the
 * mount merely happened to ask first. These arms call the store directly, with no preflight, which is
 * exactly the shape of a row written between the audit and the sweep.
 */
const directClient = {
  configured: true,
  async request(spec) {
    const res = await fetch(`https://${MOCK_HOST}/data/${spec.path}`, {
      method: spec.method || 'GET', headers: { authorization: `Bearer ${SERVICE_TOKEN}` }
    });
    let body = null;
    try { body = await res.json(); } catch {}
    return { ok: res.ok && body?.status !== 'failed', body };
  }
};
seedGame({ foreignCommunityRoot: true });
const backstop = await storeModule.createGameDeletionStore({ client: directClient })
  .execute({ canonicalId: GAME, replayChildIds: ['5002', '5003', '5099'], ownerId: OWNER_A });
check('NC5. the sweep itself refuses a foreign satellite when no preflight ran: the store is not trusted to its caller',
  backstop.failure?.reason === 'foreign_satellite_owners' && backstop.failure?.step === 'communityGames'
    && backstop.failure?.verdict?.foreignCount === 1,
  JSON.stringify(backstop.failure ?? backstop.result ?? null).slice(0, 220));
check('NC5b. and the foreign row was never addressed by a delete call, survived, and the canonical row survived too',
  !calls.deletes.some((c) => c.id === 'cF1') && rows.community_games.some((c) => c.id === 'cF1')
    && rows.recorded_hands.some((r) => r.id === GAME) && backstop.result === undefined,
  `deletes=${JSON.stringify(calls.deletes.map((c) => `${c.table}/${c.id}`))}`);
/* Retention holds at the STORE level too, with no preflight in front of it: the sweep must never issue a
 * delete against a root-linked ledger row, whoever owns it, and must still report the ones it kept. */
seedGame({ foreignRootTrace: true });
const retainedStore = await storeModule.createGameDeletionStore({ client: directClient })
  .execute({ canonicalId: GAME, replayChildIds: ['5002', '5003', '5099'], ownerId: OWNER_A });
check('RT3d. the sweep never addresses a root-linked ledger row, even called directly with no preflight',
  retainedStore.result !== undefined && retainedStore.failure === undefined
    && retainedStore.result?.removed?.decisionTraces === 1
    && !calls.deletes.some((c) => c.table === 'ai_decision_traces' && ['t3', 't4'].includes(c.id)),
  JSON.stringify(retainedStore.result ?? retainedStore.failure ?? null).slice(0, 200));
check('RT3e. and countRetainedEvidence is the store\u2019s own read of that column, never a guess',
  (await storeModule.createGameDeletionStore({ client: directClient }).countRetainedEvidence([GAME])).count === 2,
  JSON.stringify(rows.ai_decision_traces.map((t) => [t.id, t.recorded_hand_id, t.root_hand_id])));
const blindRetained = await storeModule.createGameDeletionStore({
  client: { configured: true, async request() { return { ok: false, reason: 'club_account_unreachable', detail: 'unreachable' }; } }
}).countRetainedEvidence([GAME]);
check('RT3f. an unreadable retained read reports unavailable, never a confident zero',
  blindRetained.unavailable === true && blindRetained.count === 0,
  JSON.stringify(blindRetained));
seedGame({ foreignAttempt: true });
const noOwnerArg = await storeModule.createGameDeletionStore({ client: directClient })
  .execute({ canonicalId: GAME, replayChildIds: [] });
check('NC5c. an execute() call that omits the owner fails CLOSED rather than deleting everything it matched',
  noOwnerArg.failure?.reason === 'foreign_satellite_owners'
    && rows.replay_attempts.some((r) => r.id === 'raF1') && rows.recorded_hands.some((r) => r.id === GAME),
  JSON.stringify(noOwnerArg.failure ?? noOwnerArg.result ?? null).slice(0, 200));

check('NC5d. ownership resolves from player_user_id BEFORE the NCB-stamped user_id, so a service-account link is still the player\u2019s',
  rules.satelliteOwner({ row: { player_user_id: OWNER_A, user_id: SERVICE_ID }, key: 'tournamentAttempts' }).owner === OWNER_A
    && rules.satelliteOwner({ row: { user_id: OWNER_A }, key: 'communityGames' }).owner === OWNER_A
    && rules.satelliteOwner({ row: {}, key: 'communityGames' }).readable === false
    && rules.satelliteOwner({ row: { user_id: OWNER_A }, key: 'not_a_table' }).readable === false,
  JSON.stringify(rules.satelliteOwner({ row: { player_user_id: OWNER_A, user_id: SERVICE_ID }, key: 'tournamentAttempts' })));
// The audit and the write must read ONE list. If a probe is added to the sweep without an owner policy,
// or an owner policy exists for a table nothing selects, this reddens instead of becoming the next defect.
check('NC5e. every cascade probe has an owner policy, and the audited probe list is the sweep\u2019s own',
  rules.SWEEP_PROBES.every((probe) => Array.isArray(rules.SATELLITE_OWNER_COLUMNS[probe.key])
    && rules.SATELLITE_OWNER_COLUMNS[probe.key].length > 0
    && Boolean(rules.GAME_COLUMNS[probe.key][probe.column]))
    && rules.SWEEP_PROBES.filter((p) => p.key === 'communityGames').map((p) => p.column).sort().join(',') === 'rootHandId,sourceHandId'
    && rules.SWEEP_PROBES.map((p) => p.key).filter((k, i, all) => all.indexOf(k) === i).sort().join(',')
      === 'analysisReports,communityGames,decisionTraces,replayAttempts,tournamentAttempts'
    && rules.MULTI_COLUMN_SATELLITE === 'communityGames',
  JSON.stringify(rules.SWEEP_PROBES));
check('NC5f. a table with no declared owner policy is counted as unverifiable, never as safe to delete',
  rules.classifySatellites({ ownerId: OWNER_A, groups: { mysteryTable: [{ id: 'z', user_id: OWNER_A }] } }).blocked === true
    && rules.classifySatellites({ ownerId: OWNER_A, groups: { communityGames: [{ id: 'z', user_id: OWNER_A }] } }).blocked === false,
  JSON.stringify(rules.classifySatellites({ ownerId: OWNER_A, groups: { mysteryTable: [{ id: 'z' }] } })));
check('NC5g. an unreadable canonical owner never authorises a satellite delete, and never claims foreign ownership either',
  rules.classifySatellites({ ownerId: '', groups: { communityGames: [{ id: 'z', user_id: OWNER_A }] } }).unverifiableCount === 1
    && rules.classifySatellites({ ownerId: '', groups: { communityGames: [{ id: 'z', user_id: OWNER_A }] } }).foreignCount === 0
    && rules.classifySatellites({ ownerId: OWNER_A, groups: { communityGames: [{ id: 'z', user_id: OWNER_B }] } }).foreignCount === 1,
  JSON.stringify(rules.classifySatellites({ ownerId: '', groups: { communityGames: [{ id: 'z', user_id: OWNER_A }] } })));

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
    findSatellites: async () => ({ groups: {} }),
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

/* Two mount-level shapes the HTTP fixture cannot produce on its own, built with a stub store: a refusal
 * discovered DURING the sweep (its answer must keep the code, not degrade into "retry the same request"),
 * and a store that cannot supply the inventory at all (which must never be swept un-audited). */
async function callStubMount(deletionStore, id = '5001') {
  const stubApp = express();
  stubApp.use(bridge.buildGameDeletionMount({
    env: process.env,
    authenticate: async () => ({ ok: true, id: '1' }),
    clubStore: { isSystemAdmin: async () => ({ declared: true, available: true, isAdmin: true }) },
    clubAccount: { configured: true },
    deletionStore
  }).router);
  const stubServer = stubApp.listen(0, '127.0.0.1');
  await new Promise((resolve) => stubServer.once('listening', resolve));
  try {
    const res = await fetch(`http://127.0.0.1:${stubServer.address().port}/games/${id}`, {
      method: 'DELETE', headers: { authorization: 'Bearer x' }
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  } finally { stubServer.close(); }
}
const midSweep = await callStubMount({
  findCanonical: async () => ({ row: { id: '5001', user_id: OWNER_A, root_hand_id: null } }),
  findChildren: async () => ({ rows: [] }),
  findSatellites: async () => ({ groups: {} }),
  countSatellites: async () => ({ total: 0 }),
  execute: async () => ({
    failure: {
      storeFailure: true, reason: 'foreign_satellite_owners', step: 'communityGames',
      verdict: { foreignCount: 2, unverifiableCount: 1, ownerUnreadable: false },
      removedSoFar: { communityGames: 0 }
    }
  })
});
check('NC5h. an ownership stop discovered mid-sweep keeps its code as a 409 and says the cleanup is partial',
  midSweep.status === 409 && midSweep.body?.error?.code === 'foreign_satellite_owners'
    && /2 record\(s\) belong to another account and 1 record\(s\) have no readable owner/.test(String(midSweep.body?.error?.message ?? ''))
    && /not restorable/.test(String(midSweep.body?.error?.message ?? ''))
    && midSweep.body?.data === undefined,
  JSON.stringify(midSweep).slice(0, 240));
const noInventory = await callStubMount({
  findCanonical: async () => ({ row: { id: '5001', user_id: OWNER_A, root_hand_id: null } }),
  findChildren: async () => ({ rows: [] }),
  countSatellites: async () => ({ total: 0 }),
  execute: async () => { throw new Error('the sweep must not be entered without an ownership audit'); }
});
check('NC5i. a store that cannot produce the satellite inventory is refused before any write, never swept un-audited',
  noInventory.status === 503 && noInventory.body?.error?.code === 'club_store_unavailable'
    && noInventory.body?.data === undefined
    && !JSON.stringify(noInventory.body).includes('must not be entered'),
  JSON.stringify(noInventory).slice(0, 200));

/* ── RT8: the reasons that mean "nothing was reached" must not read as "half-deleted" ────────────
 * The deployed classifier enumerated four transport names, so a session that could not be established or
 * verified mid-sweep fell through to 502 `game_deletion_incomplete` — telling an administrator rows had
 * been left half-removed when no write had reached any table. These three stubs are the three answers an
 * operator must be able to tell apart from the same request shape.
 */
const midSweepStub = (reason, extra = {}) => callStubMount({
  findCanonical: async () => ({ row: { id: '5001', user_id: OWNER_A, root_hand_id: null } }),
  findChildren: async () => ({ rows: [] }),
  findSatellites: async () => ({ groups: {} }),
  countSatellites: async () => ({ total: 0 }),
  execute: async () => ({ failure: { storeFailure: true, reason, step: 'decisionTraces', detail: '', ...extra } })
});
const sessionFault = await midSweepStub('club_account_identity_unverifiable');
const coolingFault = await midSweepStub('club_account_cooling_down');
const unreachableFault = await midSweepStub('club_account_unreachable');
check('RT8. a mid-sweep session or identity failure is 503 club_store_unavailable, not a 502 about rows',
  sessionFault.status === 503 && sessionFault.body?.error?.code === 'club_store_unavailable'
    && coolingFault.status === 503 && unreachableFault.status === 503
    && sessionFault.body?.data === undefined,
  `${sessionFault.status}/${sessionFault.body?.error?.code} ${coolingFault.status} ${unreachableFault.status}`);
const forbiddenFault = await midSweepStub('club_account_forbidden', { storageStatus: 403 });
const unconfirmedFault = await midSweepStub('game_delete_unconfirmed');
const rowIdFault = await midSweepStub('game_row_id_unusable');
check('RT8b. refusal, acknowledged-but-unapplied and unusable-id stops stay 502 and stay three different sentences',
  forbiddenFault.status === 502 && unconfirmedFault.status === 502 && rowIdFault.status === 502
    && forbiddenFault.body?.error?.detail?.class === 'authorization_refused'
    && unconfirmedFault.body?.error?.detail?.class === 'write_not_applied'
    && rowIdFault.body?.error?.detail?.class === 'unaddressable_row'
    && new Set([forbiddenFault, unconfirmedFault, rowIdFault].map((a) => a.body?.error?.message)).size === 3,
  JSON.stringify([forbiddenFault.body?.error?.detail, unconfirmedFault.body?.error?.detail, rowIdFault.body?.error?.detail]));
check('RT8c. the refusal carries the storage status and the retry verdict; the others do not invent one',
  forbiddenFault.body?.error?.detail?.storageStatus === 403 && forbiddenFault.body?.error?.detail?.retryable === false
    && unconfirmedFault.body?.error?.detail?.storageStatus === null
    && unreachableFault.body?.error?.detail?.retryable === true,
  JSON.stringify([forbiddenFault.body?.error?.detail, unconfirmedFault.body?.error?.detail, unreachableFault.body?.error?.detail]));

// The classifier must be TOTAL over the reasons the shipped code can actually emit — an enumeration that
// misses a name is exactly how the identity variants fell through to a data-claiming 502. Reasons are
// harvested from the sources rather than typed out here, so adding a reason to the client without
// declaring its class reddens this arm instead of silently defaulting it.
const clientSrc = fs.readFileSync(path.join(ROOT, 'clubs/ncbAccountClient.js'), 'utf8');
const storeSrc = fs.readFileSync(path.join(ROOT, 'games/gameDeletionStore.js'), 'utf8');
const harvested = [...new Set([
  ...[...clientSrc.matchAll(/'((?:club|game|ncb)_[a-z_]+)'/g)].map((m) => m[1]),
  ...[...storeSrc.matchAll(/storeFailure\(\s*'([a-z_]+)'/g)].map((m) => m[1])
])].sort();
const EXPECTED_FAULT_CLASS = {
  club_account_forbidden: 'authorization_refused',
  club_account_request_failed: 'storage_error',
  club_account_unreachable: 'storage_unreachable',
  club_account_login_failed: 'storage_unreachable',
  club_account_rejected: 'storage_unreachable',
  club_account_cooling_down: 'storage_unreachable',
  club_account_unconfigured: 'storage_unreachable',
  club_account_identity_unverifiable: 'storage_unreachable',
  club_account_identity_mismatch: 'storage_unreachable',
  club_credentials_must_not_be_frontend_env: 'storage_unreachable',
  game_read_unreadable: 'storage_unreachable',
  game_store_request_failed: 'storage_unreachable',
  game_delete_unconfirmed: 'write_not_applied',
  game_row_id_unusable: 'unaddressable_row',
  foreign_satellite_owners: 'incomplete'
};
const classDrift = harvested
  .filter((r) => EXPECTED_FAULT_CLASS[r] === undefined || rules.classifyStoreFailure(r) !== EXPECTED_FAULT_CLASS[r])
  .map((r) => `${r}=${rules.classifyStoreFailure(r)}${EXPECTED_FAULT_CLASS[r] ? `(want ${EXPECTED_FAULT_CLASS[r]})` : '(undeclared)'}`);
check('RT8d. every reason the shipped client or store can emit is declared in the fault table, with the class it must get',
  harvested.length >= 10 && classDrift.length === 0,
  `harvested=${JSON.stringify(harvested)} drift=${JSON.stringify(classDrift)}`);
check('RT8e. and no club_account_* session/transport reason can answer 502 any more (the production misclassification)',
  harvested.filter((r) => /^club_account_(unreachable|login_failed|rejected|cooling_down|unconfigured|identity_)/.test(r))
    .every((r) => rules.classifyStoreFailure(r) === 'storage_unreachable'
      && rules.DELETION_FAULT_CLASSES[rules.classifyStoreFailure(r)].http === 503)
    && rules.classifyStoreFailure('club_account_forbidden') === 'authorization_refused',
  JSON.stringify(Object.fromEntries(harvested.map((r) => [r, rules.classifyStoreFailure(r)]))));

/* ── RT11: a destructive verb's failure must leave a trace ────────────────────────────────────────
 * The deployed route audited four outcomes and NOT the catch-all, so during the production incident an
 * operator could only infer a crash from the ABSENCE of a log line. This stub captures what the mount
 * hands `onAudit` and asserts every failing answer writes a sanitized record naming the step and class.
 */
const auditLines = [];
const auditApp = express();
auditApp.use(bridge.buildGameDeletionMount({
  env: process.env,
  authenticate: async () => ({ ok: true, id: '1' }),
  clubStore: { isSystemAdmin: async () => ({ declared: true, available: true, isAdmin: true }) },
  clubAccount: { configured: true },
  onAudit: (record) => auditLines.push(record),
  deletionStore: {
    findCanonical: async () => ({ row: { id: '5001', user_id: OWNER_A, root_hand_id: null } }),
    findChildren: async () => ({ rows: [] }),
    findSatellites: async () => ({ groups: {} }),
    countSatellites: async () => ({ total: 0 }),
    execute: async () => { throw new TypeError('simulated internal fault naming a bearer and a row'); }
  }
}).router);
const auditServer = auditApp.listen(0, '127.0.0.1');
await new Promise((resolve) => auditServer.once('listening', resolve));
try {
  await fetch(`http://127.0.0.1:${auditServer.address().port}/games/5001`, {
    method: 'DELETE', headers: { authorization: 'Bearer x' }
  });
} finally { auditServer.close(); }
const crashLine = auditLines.find((r) => r?.fault?.class === 'internal_fault') ?? null;
check('RT11. an internal fault is AUDITED, not just answered: the log names the step and the class',
  crashLine !== null && crashLine.fault.step === 'sweep'
    && crashLine.deleted === false && crashLine.recordedHandId === '5001',
  JSON.stringify(auditLines).slice(0, 240));
check('RT11b. and the audit record carries no exception text, bearer or row content',
  crashLine !== null && !JSON.stringify(crashLine).includes('bearer')
    && !JSON.stringify(crashLine).includes('simulated internal fault') && !JSON.stringify(crashLine).includes('Bearer '),
  JSON.stringify(crashLine).slice(0, 220));

/* ── RT12: the log line an operator actually reads, captured from the shipped wiring ─────────────
 * `auditRecord` used to read `result.data.x` while every call site hands it the payload object itself, so
 * the bridge logged `deleted:false, removed:null` for a SUCCESSFUL deletion and dropped the partial tally
 * for a refused one. A unit test of the builder cannot see that — only the emitted line can. Captured here
 * by wrapping the console, so it asserts `bridge.js`'s real `onAudit` wiring rather than a copy.
 */
async function captureAudit(run) {
  const lines = [];
  const realInfo = console.info;
  console.info = (...args) => { lines.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')); };
  try { await run(); } finally { console.info = realInfo; }
  return lines.filter((l) => l.includes('admin_game_deletion')).map((l) => {
    try { return JSON.parse(l.slice(l.indexOf('{'))); } catch { return { unparsable: l.slice(0, 80) }; }
  });
}
seedGame({ communityRoot: true });
const [successLine] = await captureAudit(() => del(GAME, 'tok-admin'));
check('RT12. a completed deletion is LOGGED as completed, with the per-table counts (the shipped console line)',
  successLine?.deleted === true && successLine?.alreadyAbsent === false
    && successLine?.recordedHandId === GAME && Number(successLine?.removed?.decisionTraces) === 1
    && Number(successLine?.removed?.recordedHands) === 4 && successLine?.replayChildren === 3,
  JSON.stringify(successLine ?? null).slice(0, 240));
seedGame({ communityRoot: true });
FAULTS.keepRowsIn = ['ai_decision_traces'];
const [refusedLine] = await captureAudit(() => del(GAME, 'tok-admin'));
FAULTS.keepRowsIn = null;
check('RT12b. a refused sweep logs the residue it DID remove and the fault class, never a bare null',
  refusedLine?.deleted === false && refusedLine?.fault?.class === 'write_not_applied'
    && Number(refusedLine?.removed?.tournamentAttempts) === 1 && /decisionTraces/.test(String(refusedLine?.failure ?? '')),
  JSON.stringify(refusedLine ?? null).slice(0, 260));
check('RT12c. and the log line names no email, bearer, hand or account value',
  [successLine, refusedLine].every((l) => {
    const text = JSON.stringify(l ?? {});
    return !text.includes(SERVICE_TOKEN) && !text.includes(SERVICE_EMAIL) && !text.includes(PASSWORD)
      && !text.includes('{"private":"cards"}') && !text.includes('Bearer ');
  }), JSON.stringify([successLine, refusedLine]).slice(0, 200));

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
  ['unconfirmed-delete', lying.body], ['unreachable', unreachable.body],
  ['foreign-satellites', fRoot.body], ['foreign-direct', fSource.body], ['foreign-attempt', fAttempt.body],
  ['unowned-satellite', fUnowned.body], ['mixed-satellites', fMixed.body], ['orphan-owner', fOrphan.body],
  ['mid-sweep-stop', midSweep.body], ['inventory-unavailable', noInventory.body],
  ['vendor-403', refused403.body], ['vendor-403-canonical', refusedCanonical.body],
  ['acknowledged-keeps-row', lyingTraces.body],
  ['session-fault', sessionFault.body], ['refusal-fault', forbiddenFault.body]
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
  JSON.stringify(repeat.body?.data ?? null).slice(0, 200));
// The documented gap, asserted rather than assumed away: the client at 514ad394 has no branch for 409 or
// 502, so both land in `malformed_envelope` ("Nothing was deleted" — SAFE, but it discards the two most
// actionable answers this route produces). The codes still arrive intact, which is what the handoff needs.
check('C4. the codes the client cannot yet map still arrive named (handoff prerequisite)',
  foreign.body?.error?.code === 'foreign_replay_descendants' && foreign.status === 409
    && fRoot.body?.error?.code === 'foreign_satellite_owners' && fRoot.status === 409
    && partial.body?.error?.code === 'game_deletion_incomplete' && (partial.status === 502 || partial.status === 503),
  `${foreign.status}/${foreign.body?.error?.code} ${fRoot.status}/${fRoot.body?.error?.code} ${partial.status}/${partial.body?.error?.code}`);

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
    const seen = JSON.stringify([ok.body, foreign.body, partial.body, lying.body, unreachable.body, repeat.body,
      fRoot.body, fMixed.body, fOrphan.body, midSweep.body, noInventory.body,
      refused403.body, refusedCanonical.body, lyingTraces.body, fRootTrace.body, resumed.body,
      sessionFault.body, forbiddenFault.body, unconfirmedFault.body, JSON.stringify(auditLines)]);
    return !seen.includes(SERVICE_TOKEN) && !seen.includes(PASSWORD) && !seen.includes(SERVICE_EMAIL)
      && !seen.includes('{"private":"cards"}') && !seen.includes('Bearer ');
  })(), '');
check('NC4c. no ownership refusal names a table, a row id or another account id',
  [fRoot, fSource, fAttempt, fUnowned, fMixed, fOrphan, midSweep].every((answer) => idFree(answer.body))
    && idFree(noInventory.body),
  [fRoot, fSource, fAttempt, fUnowned, fMixed, fOrphan, midSweep].map((a) => JSON.stringify(a.body).slice(0, 90)).join(' | '));

let failed = 0;
for (const r of results) {
  if (!r.pass) failed += 1;
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.pass ? '' : `   ${r.detail}`}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed  (game deletion gate)`);
server.close();
process.exit(failed ? 1 : 0);
