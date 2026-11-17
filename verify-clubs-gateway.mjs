// NodeSend CLUBS verification harness.
//
// Everything runs in-process: a loopback mock of the NCB proxy (session lookup, the dedicated club
// account's sign-in, and the five club tables) behind global.fetch, and a throwaway mock for the
// scenarios that need their OWN club client (a wrong identity, a token that expires mid-flight).
// NO production endpoint is contacted, NO club table is created, and nothing is written outside
// this process. The relay under test is the REAL exported `app` served over HTTP, so a pass is a
// claim about the code that ships rather than about a copy of it.
//
// Why the authority arms go over HTTP and not by calling the rules directly: a permission function
// that is correct in isolation still means nothing if the guard is not attached to the route, if
// the route order lets a parameter swallow a literal, or if the envelope maps a refusal to a 200.
// Only a request proves all three.
//
//   node verify-clubs-gateway.mjs
import { createRequire } from 'node:module';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));

// ── the cast ────────────────────────────────────────────────────────────────
// Caller sessions. Each is a distinct person with a distinct club fact, because every interesting
// denial here is a question about WHO is asking, not about what they asked for.
// The dedicated account's address here is a FIXTURE on a reserved TLD, not the real one. This repo
// is public, and naming the live service account in source tells an attacker exactly which identity
// to aim a credential-stuffing or phishing attempt at. `.invalid` can never resolve, so the mock
// below cannot be mistaken for a real endpoint either.
const CLUB_ACCOUNT_ID = '99';
const CLUB_ACCOUNT_EMAIL = 'club-service-account@bridgemind.invalid';
// Deliberately self-labelling: this string is a harness constant that the leak arms search response
// bodies for, and it must never be mistaken for a credential that exists anywhere.
const CLUB_PASSWORD = 'gate-fixture-not-a-credential-0123456789';
// A secret the mock NCB returns in a sign-in body. If it ever appears in a response or a log line
// this harness prints, the leak arms go red — which is the only way to test for a leak rather than
// assert one is absent.
const CLUB_SESSION_TOKEN = 'gate-fixture-club-bearer-0123456789ab';
const CALLER_TOKEN = 'gate-fixture-caller-bearer-0123456789ab';

const SESSIONS = {
  [CALLER_TOKEN]: { id: '1', role: 'administrator' }, // in system_admins
  'tok-admin10': { id: '2', role: 'user' },           // club_admin of 10
  'tok-member10': { id: '3', role: 'user' },          // member of 10
  'tok-member11': { id: '4', role: 'user' },          // member of 11
  'tok-noclub': { id: '5', role: 'user' },            // one club OR none: this one has none
  'tok-administrator-impersonator': { id: '6', role: 'administrator' }, // NCB role, NOT in system_admins
  // One session per non-approved state, plus a no-club control. The battery below walks all five
  // through the same endpoints and requires all five answers to be identical.
  'tok-pending': { id: '20', role: 'user' },
  'tok-rejected': { id: '21', role: 'user' },
  'tok-removed': { id: '22', role: 'user' },
  'tok-pending-admin': { id: '23', role: 'user' },
  'tok-inactive-club': { id: '24', role: 'user' },
  // The account a Super Admin appoints mid-run in arm 2Rk. It has NO row until that appointment
  // creates one, which is the point: the appointee must be able to administer straight away.
  'tok-appointed': { id: '30', role: 'user' }
};

// ── the environment the REAL relay boots with ───────────────────────────────
// Set before bridge.js is required, because the club mount is built once at module load.
process.env.BRIDGE_API_KEY = 'relay-api-key-not-a-club-secret';
process.env.NCB_PROXY_BASE = 'https://ncb.test.invalid';
process.env.NCB_INSTANCE = '55954_bridgemind';
process.env.CLUB_NCB_EMAIL = CLUB_ACCOUNT_EMAIL;
process.env.CLUB_NCB_PASSWORD = CLUB_PASSWORD;
process.env.CLUB_NCB_EXPECTED_USER_ID = CLUB_ACCOUNT_ID;
// The agreed five-table schema, spelled exactly as .env.example documents it. Table names here are
// the AGREED ones, which is also what proves the store is schema-driven rather than hard-coded.
process.env.CLUB_NCB_SCHEMA_JSON = JSON.stringify({
  tables: {
    systemAdmins: 'system_admins',
    clubs: 'clubs',
    memberships: 'club_memberships',
    collections: 'club_board_collections',
    boards: 'club_collection_boards'
  },
  columns: {
    systemAdmins: { userId: 'user_id' },
    clubs: { id: 'id', name: 'name', status: 'status' },
    memberships: { id: 'id', userId: 'user_id', clubId: 'club_id', role: 'role', status: 'status' },
    collections: { id: 'id', clubId: 'club_id', name: 'name', status: 'status' },
    boards: { id: 'id', collectionId: 'collection_id', boardNumber: 'board_number', dealer: 'dealer', vulnerability: 'vulnerability', handsJson: 'hands_json', sourcePbn: 'source_pbn' }
  }
});
delete process.env.AI_QUOTA_RESERVATION_TABLE;
delete process.env.NODESEND_PRIVATE_KEY_B64;

const bridge = require(path.join(ROOT, 'bridge.js'));
const { app, buildClubMount, clubRoutes, clubAuthorize, clubValidateShape, clubValidateInput,
  clubBoardValidateOne, clubSchemaConfig, clubAccountConfig, clubHealth } = bridge;

// ── the mock NCB ────────────────────────────────────────────────────────────
const tables = {
  system_admins: [{ id: 'sa1', user_id: '1' }],
  clubs: [
    { id: '10', name: 'Glyfada BC', status: 'active' },
    { id: '11', name: 'Thessaloniki BC', status: 'active' },
    { id: '12', name: 'Piraeus CC', status: 'inactive' }
  ],
  club_memberships: [
    // Approved members are the only ones holding a club. Every fixture below states its status
    // explicitly, because after this change a row's mere existence means nothing.
    { id: 'm2', user_id: '2', club_id: '10', role: 'club_admin', status: 'approved' },
    { id: 'm3', user_id: '3', club_id: '10', role: 'member', status: 'approved' },
    { id: 'm4', user_id: '4', club_id: '11', role: 'member', status: 'approved' },
    // The three non-approved states, one per user id, all pointing at club 10 — the club whose
    // published boards an approved member CAN read. If any of these gains access, the difference
    // shows up as a 200 where the no-club baseline answers 403.
    { id: 'm5', user_id: '20', club_id: '10', role: 'member', status: 'pending' },
    { id: 'm6', user_id: '21', club_id: '10', role: 'member', status: 'rejected' },
    { id: 'm7', user_id: '22', club_id: '10', role: 'member', status: 'removed' },
    // A pending CLUB ADMIN elect: the role field says club_admin, the status says not yet. This is
    // the row that would hand out admin powers if role were ever trusted without status.
    { id: 'm8', user_id: '23', club_id: '10', role: 'club_admin', status: 'pending' },
    // Approved, but of the INACTIVE club 12 — the fifth state, which must behave like None too.
    { id: 'm9', user_id: '24', club_id: '12', role: 'member', status: 'approved' }
  ],
  club_board_collections: [],
  club_collection_boards: []
};
let rowSequence = 100;
// Every /data/ call the club store made, with the bearer that authorised it. This is the witness
// for "all actual club-data operations use the server-owned account" — the only honest way to test
// it is to record what the process actually sent rather than to read the code and agree.
const dataCalls = [];
// Set to a board number to make the create of THAT board fail: the way a partial import is
// reproduced without touching a real store.
let failBoardCreateNumber = null;
// How many consecutive club-data reads answer "no rows" while the rows exist, which is how a
// read-back disagreement between write and verify is reproduced.
let hideBoardReads = 0;

const realFetch = globalThis.fetch;
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json' }
});
const ncbError = (message, status = 500) => json({ status: 'error', message, data: [] }, status);

function bearerOf(init) {
  const headers = init?.headers ?? {};
  const raw = headers.Authorization ?? headers.authorization ?? '';
  return String(raw).replace(/^Bearer\s+/, '');
}

function matches(row, filters) {
  return Object.entries(filters).every(([column, value]) => String(row[column] ?? '') === value);
}

globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  if (!target.startsWith('https://ncb.test.invalid')) {
    return realFetch(url, init);
  }
  const { pathname, searchParams } = new URL(target);
  const method = String(init.method ?? 'GET').toUpperCase();
  const bearer = bearerOf(init);
  const body = init.body ? JSON.parse(init.body) : null;

  // The caller's own session lookup — the relay's existing authority, unchanged by Clubs.
  if (pathname === '/auth/get-session') {
    // NodeSend turns a THROWN lookup into 503 and a rejected one into 401, so this is the only way
    // to make the two branches observable rather than asserted from a reading of the code.
    if (bearer === 'tok-session-down') throw new TypeError('mock: session authority unreachable');
    const user = SESSIONS[bearer];
    if (bearer === CLUB_SESSION_TOKEN) return json({ data: { user: { id: CLUB_ACCOUNT_ID, email: CLUB_ACCOUNT_EMAIL } } });
    if (!user) return json({ status: 'error', message: 'invalid session' }, 401);
    return json({ data: { user: { id: user.id, email: `user${user.id}@example.test`, role: user.role } } });
  }

  // The dedicated club account's sign-in. Only the club client may use this path, and only with
  // the configured credential pair.
  if (pathname === '/auth/sign-in/email') {
    if (body?.email !== CLUB_ACCOUNT_EMAIL || body?.password !== CLUB_PASSWORD) {
      return json({ status: 'error', message: 'invalid credentials' }, 401);
    }
    return json({ token: CLUB_SESSION_TOKEN, user: { id: CLUB_ACCOUNT_ID, email: CLUB_ACCOUNT_EMAIL } });
  }

  if (pathname.startsWith('/data/')) {
    dataCalls.push({ pathname, method, bearer, body });
    // The one rule the whole design rests on, enforced by the mock so a fallback cannot hide:
    // club data does not move on a caller's token.
    if (bearer !== CLUB_SESSION_TOKEN) {
      return ncbError(`club data call carried a non-club bearer (${pathname})`, 403);
    }
    // `pathname` is `/data/<action>/<table>[/<rowId>]`, so after dropping the empty leading
    // segment the action is index 1. Reading it from index 2 answers "unknown table" for every
    // call; the relay would report a 503 and the harness would print fail-closed PASSes for fifty
    // arms that never touched a table at all.
    const [, action, table, rowId] = pathname.split('/').filter(Boolean);
    const rows = tables[table];
    if (!rows) return ncbError(`unknown table ${table}`, 404);

    if (action === 'read') {
      const filters = {};
      for (const [key, value] of searchParams.entries()) {
        if (['limit', 'offset', 'sort', 'order', 'Instance'].includes(key)) continue;
        filters[key] = value;
      }
      let found = rows.filter((row) => matches(row, filters));
      if (table === 'club_collection_boards' && hideBoardReads > 0) {
        hideBoardReads -= 1;
        found = [];
      }
      const limit = Number(searchParams.get('limit'));
      if (Number.isFinite(limit)) found = found.slice(0, limit);
      return json({ status: 'success', data: found });
    }

    if (action === 'create') {
      // UNIQUE(user_id) is what "one club or none" rests on, so the mock refuses a second row for
      // the same user the way MySQL would — in prose, because that is all a REST layer passes back.
      if (table === 'club_memberships' && rows.some((row) => String(row.user_id) === String(body.user_id))) {
        return ncbError('Duplicate entry for key user_id', 400);
      }
      if (table === 'club_collection_boards' && failBoardCreateNumber !== null
        && String(body.board_number) === String(failBoardCreateNumber)) {
        return ncbError('simulated write failure mid-import', 500);
      }
      const row = { id: String(++rowSequence), ...body };
      rows.push(row);
      return json({ status: 'success', data: { ...row } });
    }

    if (action === 'update') {
      const row = rows.find((candidate) => String(candidate.id) === String(rowId));
      if (!row) return ncbError('no such row', 404);
      Object.assign(row, body);
      return json({ status: 'success', data: { ...row } });
    }

    if (action === 'delete') {
      const index = rows.findIndex((candidate) => String(candidate.id) === String(rowId));
      if (index === -1) return ncbError('no such row', 404);
      rows.splice(index, 1);
      return json({ status: 'success', data: { id: rowId } });
    }
  }

  return ncbError(`unexpected mock path ${pathname}`, 404);
};

// ── harness ─────────────────────────────────────────────────────────────────
const results = [];
function check(name, condition, detail = '') {
  results.push({ name, pass: condition === true, detail: condition === true ? '' : String(detail ?? '').slice(0, 220) });
}

const server = app.listen(0, '127.0.0.1');
await new Promise((resolve) => server.once('listening', resolve));
const BASE = `http://127.0.0.1:${server.address().port}`;

async function call(method, route, { token = '', body, base = BASE } = {}) {
  const response = await fetch(`${base}${route}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const payload = await response.json().catch(() => ({}));
  return { status: response.status, body: payload, text: JSON.stringify(payload) };
}

// One deal, generated rather than pasted, so "valid" here means valid against the same rank and
// suit vocabulary the server uses. A pasted fixture that was wrong would redden correct code, and
// a hand-typed 52-card string is exactly where that mistake lives.
const RANKS = ['2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A'];
const SUITS = ['S', 'H', 'D', 'C'];
function legalBoard(number, { dealer = 'North', vulnerability = 'None' } = {}) {
  const deck = RANKS.flatMap((rank) => SUITS.map((suit) => `${rank}${suit}`));
  const hands = {};
  ['North', 'East', 'South', 'West'].forEach((seat, seatIndex) => {
    hands[seat] = deck.slice(seatIndex * 13, seatIndex * 13 + 13);
  });
  return { board_number: String(number), dealer, vulnerability, hands };
}

// Seeds one published and one draft collection for club 10, straight into the mock tables. Seeding
// through the store would test the store's happy path before testing anything else, and would hide
// a broken import behind a working read.
function seedCollections() {
  tables.club_board_collections.length = 0;
  tables.club_collection_boards.length = 0;
  tables.club_board_collections.push(
    { id: 'c-pub', club_id: '10', name: 'Round 1', status: 'published' },
    { id: 'c-draft', club_id: '10', name: 'Round 2', status: 'draft' },
    { id: 'c-other', club_id: '11', name: 'Opponent round', status: 'published' }
  );
  for (const number of [1, 2, 3]) {
    tables.club_collection_boards.push({
      id: `pb${number}`, collection_id: 'c-pub', board_number: String(number),
      dealer: 'North', vulnerability: 'None', hands_json: JSON.stringify(legalBoard(number).hands)
    });
  }
  tables.club_collection_boards.push({
    id: 'db1', collection_id: 'c-draft', board_number: '4',
    dealer: 'East', vulnerability: 'NS', hands_json: JSON.stringify(legalBoard(4).hands)
  });
  tables.club_collection_boards.push({
    id: 'ob1', collection_id: 'c-other', board_number: '1',
    dealer: 'South', vulnerability: 'EW', hands_json: JSON.stringify(legalBoard(1).hands)
  });
}
seedCollections();

// Responses seen by a client, for the leak arms at the end.
const seenBodies = [];
async function ask(method, route, options) {
  const answer = await call(method, route, options);
  seenBodies.push(answer.text);
  return answer;
}

// ── R1 — Super Admin ────────────────────────────────────────────────────────
const superList = await ask('GET', '/clubs?limit=10', { token: CALLER_TOKEN });
check('1a. an authenticated Super Admin reads the club list',
  superList.status === 200 && Array.isArray(superList.body.data) && superList.body.data.length === 3,
  `${superList.status} ${superList.text.slice(0, 120)}`);

const memberAsSuper = await ask('GET', '/clubs', { token: 'tok-member10' });
check('1b. an ordinary user is refused as Super Admin',
  memberAsSuper.status === 403 && memberAsSuper.body.error === 'super_admin_required',
  `${memberAsSuper.status} ${memberAsSuper.text.slice(0, 120)}`);

// The arm that decides whether `system_admins` is real or decorative. User 6 carries the NCB role
// `administrator` — the role the rest of this relay treats as admin — and holds no system_admins
// row. If this returns 200, club-wide power is a writable application field.
const roleOnly = await ask('GET', '/clubs', { token: 'tok-administrator-impersonator' });
check('1c. an NCB administrator role with no system_admins row is refused (role is not the authority)',
  roleOnly.status === 403 && roleOnly.body.error === 'super_admin_required',
  `${roleOnly.status} ${roleOnly.text.slice(0, 120)}`);

const anonymous = await ask('GET', '/clubs');
check('1d. an unauthenticated club request is refused with the relay session vocabulary',
  anonymous.status === 401 && anonymous.body.error === 'auth_error',
  `${anonymous.status} ${anonymous.text.slice(0, 120)}`);

// 401 and 503 are DIFFERENT answers here and the difference is user-visible: a 401 tells the client
// to discard a session and sign in again. NodeSend already draws that line for /ai/*, and a club
// mount that flattened an unreachable authority into "not signed in" would log people out of a
// working account every time NCB blipped.
const sessionDown = await ask('GET', '/clubs', { token: 'tok-session-down' });
check('1e. an unreachable session authority answers 503, never a 401 that discards a valid session',
  sessionDown.status === 503 && sessionDown.body.error === 'session_service_unavailable',
  `${sessionDown.status} ${sessionDown.text.slice(0, 120)}`);

const created = await ask('POST', '/clubs', { token: CALLER_TOKEN, body: { name: 'Raftina   BC' } });
check('1f. a Super Admin creates a club, and the created row reads back',
  created.status === 200 && created.body?.data?.name === 'Raftina BC' && created.body?.data?.status === 'active',
  `${created.status} ${created.text.slice(0, 140)}`);
const createdId = created.body?.data?.id;
const createdRow = tables.clubs.find((row) => String(row.id) === String(createdId));
check('1g. the created club exists in exactly one row (read-back verified, not assumed)',
  Boolean(createdRow) && tables.clubs.filter((row) => String(row.id) === String(createdId)).length === 1,
  JSON.stringify(tables.clubs.map((row) => row.id)));

const appointed = await ask('POST', '/clubs/10/admins', { token: CALLER_TOKEN, body: { user_id: '5', role: 'club_admin' } });
check('1h. a Super Admin assigns a Club Admin',
  appointed.status === 200 && appointed.body?.data?.club_role === 'club_admin' && appointed.body?.data?.club_id === '10',
  `${appointed.status} ${appointed.text.slice(0, 140)}`);
// Clean up: user 5 must go back to having no club or the membership arms below measure the wrong
// starting state.
tables.club_memberships = tables.club_memberships.filter((row) => String(row.user_id) !== '5');

// ── R2 — one club or none ───────────────────────────────────────────────────
const noClubView = await ask('GET', '/me/club', { token: 'tok-noclub' });
check('2a. a user with no club is told so truthfully (a real null, not a service failure)',
  noClubView.status === 200 && noClubView.body.data === null,
  `${noClubView.status} ${noClubView.text.slice(0, 120)}`);

const requested = await ask('POST', '/me/club', { token: 'tok-noclub', body: { club_id: '10' } });
check('2b. a user selecting a club creates a PENDING request, not a membership',
  requested.status === 200 && requested.body?.data?.outcome === 'requested'
  && requested.body?.data?.clubId === '10' && requested.body?.data?.status === 'pending',
  `${requested.status} ${requested.text.slice(0, 140)}`);

// The rule that matters: requesting is not joining. A pending user must reach nothing.
const pendingBoardAccess = await ask('GET', '/clubs/collections/c-pub/boards', { token: 'tok-noclub' });
const pendingCollectionList = await ask('GET', '/me/club/board-collections', { token: 'tok-noclub' });
check('2c. a pending request grants no board access and no collection list',
  pendingBoardAccess.status === 403 && pendingBoardAccess.body.error === 'not_a_club_member'
  && pendingCollectionList.status === 403 && pendingCollectionList.body.error === 'not_a_club_member',
  `${pendingBoardAccess.status}/${pendingCollectionList.status}`);

const pendingView = await ask('GET', '/me/club', { token: 'tok-noclub' });
check('2d. Profile sees the request, but with club_id null exactly as a no-club user does',
  pendingView.status === 200 && pendingView.body?.data?.club_id === null
  && pendingView.body?.data?.membership_status === 'pending'
  && pendingView.body?.data?.request?.club_id === '10',
  `${pendingView.status} ${pendingView.text.slice(0, 170)}`);

const repeatRequest = await ask('POST', '/me/club', { token: 'tok-noclub', body: { club_id: '10' } });
const rowsForUser5 = tables.club_memberships.filter((row) => String(row.user_id) === '5');
check('2e. repeating the same request is idempotent and creates no second row',
  repeatRequest.status === 200 && rowsForUser5.length === 1,
  `${rowsForUser5.length} row(s) ${repeatRequest.text.slice(0, 90)}`);

// UNIQUE(user_id) allows one row, so a pending user who changes their mind has that ONE row moved.
// Refusing here would leave them with less than a user who never requested anything at all.
const retarget = await ask('POST', '/me/club', { token: 'tok-noclub', body: { club_id: '11' } });
const movedRow = tables.club_memberships.find((row) => String(row.user_id) === '5');
check('2f. a pending user may re-choose a club (the single row is re-targeted, never refused)',
  retarget.status === 200 && retarget.body?.data?.outcome === 'requested'
  && String(movedRow?.club_id) === '11' && movedRow?.status === 'pending'
  && tables.club_memberships.filter((row) => String(row.user_id) === '5').length === 1,
  `${retarget.status} ${JSON.stringify(movedRow)}`);

// Approval is what turns the request into a membership. A super admin can always do it; that a
// club's OWN admin can too is covered in section 2Q below.
const approved = await ask('POST', '/clubs/11/members/5/status', { token: CALLER_TOKEN, body: { status: 'approved' } });
check('2g. a Super Admin approves the request, and the write reads back',
  approved.status === 200 && approved.body?.data?.membership_status === 'approved'
  && tables.club_memberships.find((row) => String(row.user_id) === '5')?.status === 'approved',
  `${approved.status} ${approved.text.slice(0, 150)}`);

const afterApproval = await ask('GET', '/me/club', { token: 'tok-noclub' });
check('2h. approval is what creates the club, not the request',
  afterApproval.status === 200 && afterApproval.body?.data?.club_id === '11'
  && afterApproval.body?.data?.membership_status === 'approved',
  afterApproval.text.slice(0, 150));

const secondClub = await ask('POST', '/me/club', { token: 'tok-noclub', body: { club_id: '10' } });
check('2i. an APPROVED member is refused a second club, never silently replaced',
  secondClub.status === 409 && secondClub.body.error === 'already_in_club',
  `${secondClub.status} ${secondClub.text.slice(0, 140)}`);
const stillEleven = tables.club_memberships.find((row) => String(row.user_id) === '5');
check('2j. the refused second join changed nothing in storage',
  stillEleven && String(stillEleven.club_id) === '11',
  JSON.stringify(stillEleven));

// The caller's identity is never a parameter. `user_id` on a self-scoped route is refused by the
// positive field list, which means a future field cannot slip in by being forgotten.
const forgedWho = await ask('POST', '/me/club', { token: 'tok-noclub', body: { club_id: '11', user_id: '3' } });
check('2k. a forged user_id in the body is refused, not ignored',
  forgedWho.status === 400 && forgedWho.body.error === 'client_identity_refused',
  `${forgedWho.status} ${forgedWho.text.slice(0, 140)}`);

const forgedRole = await ask('POST', '/clubs', { token: CALLER_TOKEN, body: { name: 'Ghost', role: 'super_admin' } });
check('2l. a forged role in the body is refused',
  forgedRole.status === 400 && forgedRole.body.error === 'client_identity_refused',
  `${forgedRole.status} ${forgedRole.text.slice(0, 140)}`);

const forgedQuery = await ask('GET', '/clubs/10/members?role=club_admin', { token: CALLER_TOKEN });
check('2m. an identity-bearing query field is refused too',
  forgedQuery.status === 400 && forgedQuery.body.error === 'client_identity_refused',
  `${forgedQuery.status} ${forgedQuery.text.slice(0, 140)}`);

// A forged STATUS must not let a caller approve themselves either — the transition route takes a
// target user from the path, never from the body, and only an approved admin of that club may call it.
const selfApprove = await ask('POST', '/clubs/10/members/5/status', { token: 'tok-noclub', body: { status: 'approved' } });
check('2n. a user cannot approve their own request',
  selfApprove.status === 403 && selfApprove.body.error === 'not_a_club_admin',
  `${selfApprove.status} ${selfApprove.text.slice(0, 140)}`);

// Leaving is always available and is the one path that DELETES the row, returning the user to None.
const left = await ask('DELETE', '/me/club', { token: 'tok-noclub' });
check('2o. an approved user may leave their club',
  left.status === 200 && left.body?.data?.outcome === 'left',
  `${left.status} ${left.text.slice(0, 120)}`);
check('2p. leaving removed the row rather than masking it',
  !tables.club_memberships.some((row) => String(row.user_id) === '5'),
  JSON.stringify(tables.club_memberships.map((row) => `${row.user_id}:${row.club_id}`)));

// ── 2Q. non-approved == no club, everywhere ─────────────────────────────────
// The owner's rule is not "deny pending users", it is "a pending user IS a no-club user". So this
// battery does not check five expected statuses one by one — it computes the no-club baseline and
// requires every other state to be INDISTINGUISHABLE from it, endpoint by endpoint. A new club
// route added later that forgets the status gate shows up here as a mismatch, not as a silent hole.
const CLUB_SURFACE = [
  { name: 'own published collections', method: 'GET', path: '/me/club/board-collections' },
  { name: 'club 10 published boards', method: 'GET', path: '/clubs/collections/c-pub/boards' },
  { name: 'club 10 collection list', method: 'GET', path: '/clubs/10/board-collections' },
  { name: 'club 10 member list', method: 'GET', path: '/clubs/10/members' },
  { name: 'club 10 import', method: 'POST', path: '/clubs/10/board-collections', body: { name: 'nope', boards: [legalBoard(1)] } },
  { name: 'start a published board', method: 'POST', path: '/clubs/collections/c-pub/boards/1/start', body: { original_seat: 'North' } },
  { name: 'publish a collection', method: 'POST', path: '/clubs/collections/c-pub/publish' },
  { name: 'create a club', method: 'POST', path: '/clubs', body: { name: 'Nope CC' } }
];
const NONE_TOKEN = 'tok-noclub';
const NON_APPROVED = {
  pending: 'tok-pending',
  rejected: 'tok-rejected',
  removed: 'tok-removed',
  'inactive club': 'tok-inactive-club',
  'pending admin elect': 'tok-pending-admin'
};

const baseline = [];
for (const endpoint of CLUB_SURFACE) {
  baseline.push((await ask(endpoint.method, endpoint.path, { token: NONE_TOKEN, body: endpoint.body })).status);
}
check('2Qa. the no-club baseline is denied on every club surface (positive control)',
  baseline.every((status) => status === 403),
  `statuses ${baseline.join(',')}`);

let mismatches = [];
for (const [label, token] of Object.entries(NON_APPROVED)) {
  const got = [];
  for (const endpoint of CLUB_SURFACE) {
    got.push((await ask(endpoint.method, endpoint.path, { token, body: endpoint.body })).status);
  }
  for (let i = 0; i < CLUB_SURFACE.length; i += 1) {
    if (got[i] !== baseline[i]) mismatches.push(`${label} / ${CLUB_SURFACE[i].name}: ${got[i]} vs baseline ${baseline[i]}`);
  }
}
check(`2Qb. all ${Object.keys(NON_APPROVED).length} non-approved states are indistinguishable from no-club on all ${CLUB_SURFACE.length} surfaces`,
  mismatches.length === 0,
  mismatches.join(' | '));

// And the same five must not be able to smuggle a club in through the Profile read either: none of
// them may ever see a non-null club_id.
let leakedClub = [];
for (const [label, token] of Object.entries({ ...NON_APPROVED, none: NONE_TOKEN })) {
  const view = await ask('GET', '/me/club', { token });
  const data = view.body?.data;
  if (data && data.club_id != null) leakedClub.push(`${label} -> club_id=${data.club_id}`);
}
check('2Qc. no non-approved state is ever told it belongs to a club',
  leakedClub.length === 0, leakedClub.join(' | '));

// The rule's other half, and the half a gate like this most easily forgets: club state must not
// touch ORDINARY BridgeMind access. These five users get byte-identical treatment on a non-club
// route, and no club error can appear there. This measures equality, not success — the AI surface
// answers from the quota tables this harness does not implement.
let ordinary = [];
for (const token of [NONE_TOKEN, ...Object.values(NON_APPROVED)]) {
  const answer = await ask('POST', '/ai/models', { token, body: {} });
  ordinary.push({ token, status: answer.status, clubError: /club_/.test(answer.text) });
}
check('2Qd. ordinary non-club routes treat all five states identically',
  new Set(ordinary.map((row) => row.status)).size === 1,
  ordinary.map((row) => `${row.token}=${row.status}`).join(' '));
check('2Qe. no club authorization error can appear on a non-club route',
  ordinary.every((row) => row.clubError === false),
  ordinary.filter((row) => row.clubError).map((row) => row.token).join(','));
check('2Qf. health stays open to everyone regardless of club state',
  (await call('GET', '/health')).status === 200, '');

// Transitions: who may move a membership, and what the move actually does.
const adminApproves = await ask('POST', '/clubs/10/members/20/status', { token: 'tok-admin10', body: { status: 'approved' } });
const approvedNowSees = await ask('GET', '/me/club', { token: 'tok-pending' });
check('2Qg. a club admin approves a request to THEIR club and access begins on the next read',
  adminApproves.status === 200 && approvedNowSees.body?.data?.club_id === '10'
  && approvedNowSees.body?.data?.membership_status === 'approved',
  `${adminApproves.status} ${approvedNowSees.text.slice(0, 140)}`);

const approvedCanRead = await ask('GET', '/me/club/board-collections', { token: 'tok-pending' });
check('2Qh. the approved user now reaches club boards (the gate is status, not identity)',
  approvedCanRead.status === 200, `${approvedCanRead.status} ${approvedCanRead.text.slice(0, 120)}`);

const adminCrossApprove = await ask('POST', '/clubs/10/members/4/status', { token: 'tok-admin10', body: { status: 'approved' } });
check('2Qi. an admin cannot act on a membership belonging to another club',
  adminCrossApprove.status === 403 && adminCrossApprove.body.error === 'club_scope_mismatch',
  `${adminCrossApprove.status} ${adminCrossApprove.text.slice(0, 140)}`);

const otherClubAdminApprove = await ask('POST', '/clubs/11/members/21/status', { token: 'tok-admin10', body: { status: 'approved' } });
check('2Qj. an admin of one club cannot approve in another club',
  otherClubAdminApprove.status === 403 && otherClubAdminApprove.body.error === 'not_a_club_admin',
  `${otherClubAdminApprove.status}`);

const pendingImposed = await ask('POST', '/clubs/10/members/21/status', { token: 'tok-admin10', body: { status: 'pending' } });
check('2Qk. an administrator cannot impose a pending state on someone else',
  pendingImposed.status === 400 && pendingImposed.body.error === 'bad_request',
  `${pendingImposed.status} ${pendingImposed.text.slice(0, 140)}`);

const nonsenseStatus = await ask('POST', '/clubs/10/members/21/status', { token: 'tok-admin10', body: { status: 'superuser' } });
check('2Ql. a status outside the lifecycle is refused, not coerced',
  nonsenseStatus.status === 400 && nonsenseStatus.body.error === 'bad_request',
  `${nonsenseStatus.status} ${nonsenseStatus.text.slice(0, 140)}`);

const noRowTarget = await ask('POST', '/clubs/10/members/77/status', { token: 'tok-admin10', body: { status: 'approved' } });
check('2Qm. approving a user with no membership row is a 404, not a created row',
  noRowTarget.status === 404 && noRowTarget.body.error === 'not_found',
  `${noRowTarget.status} ${noRowTarget.text.slice(0, 140)}`);

const revoked = await ask('POST', '/clubs/10/members/20/status', { token: 'tok-admin10', body: { status: 'removed' } });
const afterRevoke2Q = await ask('GET', '/me/club/board-collections', { token: 'tok-pending' });
const stillThere = tables.club_memberships.find((row) => String(row.user_id) === '20');
check('2Qn. a removed member loses club access on the very next request',
  revoked.status === 200 && afterRevoke2Q.status === 403 && afterRevoke2Q.body.error === 'not_a_club_member',
  `${revoked.status}/${afterRevoke2Q.status} ${afterRevoke2Q.text.slice(0, 120)}`);
check('2Qo. removal keeps the row as an auditable status rather than erasing the person',
  stillThere && stillThere.status === 'removed' && stillThere.club_id === '10',
  JSON.stringify(stillThere));

const removedCanReRequest = await ask('POST', '/me/club', { token: 'tok-removed', body: { club_id: '11' } });
check('2Qp. a removed user may request a club again, exactly as a no-club user can',
  removedCanReRequest.status === 200 && removedCanReRequest.body?.data?.outcome === 'requested'
  && tables.club_memberships.filter((row) => String(row.user_id) === '22').length === 1,
  `${removedCanReRequest.status} ${removedCanReRequest.text.slice(0, 140)}`);
// Reset the two rows this section moved, so the battery above is reproducible on a re-run and the
// later R3/R4 arms still measure the fixture they were written against.
const resetRow = (userId, patch) => {
  const row = tables.club_memberships.find((candidate) => String(candidate.user_id) === String(userId));
  if (row) Object.assign(row, patch);
};
resetRow('20', { club_id: '10', role: 'member', status: 'pending' });
resetRow('22', { club_id: '10', role: 'member', status: 'removed' });

// A pending club_admin elect holds no admin power. This is the single most valuable arm in the
// battery: it is what stops `role` from being a privilege that a row can carry before approval.
const pendingAdminSurface = await ask('GET', '/clubs/10/board-collections', { token: 'tok-pending-admin' });
const pendingAdminMembers = await ask('GET', '/clubs/10/members', { token: 'tok-pending-admin' });
check('2Qq. a PENDING club_admin elect has no admin surface at all',
  pendingAdminSurface.status === 403 && pendingAdminMembers.status === 403
  && pendingAdminMembers.body.error === 'not_a_club_admin',
  `${pendingAdminSurface.status}/${pendingAdminMembers.status}`);

// ── 2R. the approval workflow an admin actually drives ──────────────────────
// 2Q proved the DENIALS. This section proves the positive workflow an owner can operate, because a
// rule that only ever returns 403 is not a membership system. Each arm here maps to one of the ten
// operations in the approval spec.

// (Op 2) The member list is where a club admin finds the applications. `membership_status` must be
// ON THE ROW — a list without it forces a second endpoint, and a second endpoint means a second
// place to get the club-scope check wrong.
const adminMemberList = await ask('GET', '/clubs/10/members', { token: 'tok-admin10' });
const listedPending = (adminMemberList.body?.data ?? []).filter((row) => row.membership_status === 'pending');
check('2Ra. a Club Admin lists their own club and sees each row\'s membership_status (op 2)',
  adminMemberList.status === 200
  && (adminMemberList.body?.data ?? []).every((row) => 'membership_status' in row)
  && listedPending.some((row) => String(row.user_id) === '20'),
  `${adminMemberList.status} ${JSON.stringify(adminMemberList.body?.data ?? []).slice(0, 160)}`);
const superMemberList = await ask('GET', '/clubs/10/members', { token: CALLER_TOKEN });
check('2Rb. a Super Admin reads the same list (op 2, authority path)',
  superMemberList.status === 200 && superMemberList.body.data.length === (adminMemberList.body?.data ?? []).length,
  `${superMemberList.status} vs ${adminMemberList.status}`);
const crossMemberList = await ask('GET', '/clubs/11/members', { token: 'tok-admin10' });
check('2Rc. an admin cannot list another club\'s members, so no pending application crosses clubs',
  crossMemberList.status === 403 && crossMemberList.body.error === 'not_a_club_admin',
  `${crossMemberList.status} ${crossMemberList.text.slice(0, 120)}`);
const memberListNeedsSession = await call('GET', '/clubs/10/members');
check('2Rd. the member list is not a public endpoint',
  memberListNeedsSession.status === 401, `${memberListNeedsSession.status}`);

// (Op 4) Rejection. A rejected applicant must end up exactly where a no-club user is.
const rejected = await ask('POST', '/clubs/10/members/20/status', { token: 'tok-admin10', body: { status: 'rejected' } });
const rejectedRow = tables.club_memberships.find((row) => String(row.user_id) === '20');
const rejectedSees = await ask('GET', '/me/club', { token: 'tok-pending' });
const rejectedDenied = await ask('GET', '/me/club/board-collections', { token: 'tok-pending' });
check('2Re. a Club Admin rejects an applicant, and rejection grants nothing (op 4)',
  rejected.status === 200 && rejected.body?.data?.membership_status === 'rejected'
  && rejectedRow?.status === 'rejected' && rejectedSees.body?.data?.club_id === null
  && rejectedSees.body?.data?.membership_status === 'rejected' && rejectedDenied.status === 403,
  `${rejected.status} row=${rejectedRow?.status} view=${JSON.stringify(rejectedSees.body?.data).slice(0, 90)} denied=${rejectedDenied.status}`);
check('2Rf. rejection preserves the row and the club it referred to, so Profile can explain it',
  rejectedRow?.club_id === '10', JSON.stringify(rejectedRow));

// (Op 6) A rejected applicant may apply again — the same single row, back to pending.
const reapplied = await ask('POST', '/me/club', { token: 'tok-pending', body: { club_id: '10' } });
const reappliedRow = tables.club_memberships.find((row) => String(row.user_id) === '20');
check('2Rg. a REJECTED player can apply again and lands back at pending (op 6)',
  reapplied.status === 200 && reapplied.body?.data?.outcome === 'requested'
  && reappliedRow?.status === 'pending'
  && tables.club_memberships.filter((row) => String(row.user_id) === '20').length === 1,
  `${reapplied.status} ${reapplied.text.slice(0, 120)} row=${JSON.stringify(reappliedRow)}`);

// (Op 7) Switching clubs must never carry an approval across.
const inactiveSwitch = await ask('POST', '/me/club', { token: 'tok-inactive-club', body: { club_id: '10' } });
const switchedRow = tables.club_memberships.find((row) => String(row.user_id) === '24');
check('2Rh. switching clubs resets status to pending, never reusing the old approval (op 7)',
  inactiveSwitch.status === 200 && inactiveSwitch.body?.data?.outcome === 'requested'
  && String(switchedRow?.club_id) === '10' && switchedRow?.status === 'pending',
  `${inactiveSwitch.status} ${inactiveSwitch.text.slice(0, 120)} row=${JSON.stringify(switchedRow)}`);
const switchedDenied = await ask('GET', '/me/club/board-collections', { token: 'tok-inactive-club' });
check('2Ri. and the switched player reaches nothing until the new club approves them',
  switchedDenied.status === 403, `${switchedDenied.status}`);

// Leave, then re-choose: approval is gone, pending is what returns.
const joiner = await ask('POST', '/me/club', { token: 'tok-noclub', body: { club_id: '10' } });
await ask('POST', '/clubs/10/members/5/status', { token: CALLER_TOKEN, body: { status: 'approved' } });
await ask('DELETE', '/me/club', { token: 'tok-noclub' });
const rejoined = await ask('POST', '/me/club', { token: 'tok-noclub', body: { club_id: '11' } });
const rejoinedRow = tables.club_memberships.find((row) => String(row.user_id) === '5');
check('2Rj. a returning player starts again at pending, with no memory of the prior approval (op 7)',
  joiner.status === 200 && rejoined.status === 200
  && rejoined.body?.data?.outcome === 'requested' && rejoinedRow?.status === 'pending'
  && String(rejoinedRow?.club_id) === '11',
  `${rejoined.status} ${JSON.stringify(rejoinedRow)}`);
await ask('DELETE', '/me/club', { token: 'tok-noclub' });

// (Op 8) A direct appointment IS the approval — no separate approve step, no pending limbo.
const directAppointment = await ask('POST', '/clubs/11/admins', { token: CALLER_TOKEN, body: { user_id: '30', role: 'club_admin' } });
const appointedRow = tables.club_memberships.find((row) => String(row.user_id) === '30');
check('2Rk. a Super Admin appoints a Club Admin already APPROVED, not pending (op 8)',
  directAppointment.status === 200 && directAppointment.body?.data?.membership_status === 'approved'
  && appointedRow?.status === 'approved' && appointedRow?.role === 'club_admin',
  `${directAppointment.status} ${directAppointment.text.slice(0, 130)} row=${JSON.stringify(appointedRow)}`);
// The appointee acting with the row the appointment just created — the real proof of op 8, and the
// reason this arm uses tok-appointed (user 30) rather than the plain member of club 11.
const appointedAdminCanAct = await ask('GET', '/clubs/11/members', { token: 'tok-appointed' });
check('2Rl. an appointed club admin immediately has their own club\'s admin surface (op 8)',
  appointedAdminCanAct.status === 200
  && (appointedAdminCanAct.body?.data ?? []).some((row) => String(row.user_id) === '30'),
  `${appointedAdminCanAct.status} ${appointedAdminCanAct.text.slice(0, 100)}`);
const appointedCannotReachOtherClub = await ask('GET', '/clubs/10/members', { token: 'tok-appointed' });
check('2Rm. while their authority stops at their own club (op 8 + op 10)',
  appointedCannotReachOtherClub.status === 403 && appointedCannotReachOtherClub.body.error === 'not_a_club_admin',
  `${appointedCannotReachOtherClub.status}`);

// (Op 10) The sharpest form of "cannot approve themselves": a PENDING club_admin elect. Their row
// says club_admin, so any check that trusts `role` without `status` lets them induct themselves.
const electSelfApprove = await ask('POST', '/clubs/10/members/23/status', { token: 'tok-pending-admin', body: { status: 'approved' } });
const electRow = tables.club_memberships.find((row) => String(row.user_id) === '23');
check('2Rn. a pending club_admin elect cannot approve themselves (op 10)',
  electSelfApprove.status === 403 && electSelfApprove.body.error === 'not_a_club_admin'
  && electRow?.status === 'pending',
  `${electSelfApprove.status} ${electSelfApprove.text.slice(0, 120)} row=${electRow?.status}`);
const electApproveOther = await ask('POST', '/clubs/10/members/21/status', { token: 'tok-pending-admin', body: { status: 'approved' } });
check('2Ro. nor can they approve anyone else, despite the club_admin role on their row (op 10)',
  electApproveOther.status === 403 && electApproveOther.body.error === 'not_a_club_admin',
  `${electApproveOther.status} ${electApproveOther.text.slice(0, 120)}`);
const electCantRemoveMember = await ask('POST', '/clubs/10/members/3/status', { token: 'tok-pending-admin', body: { status: 'removed' } });
check('2Rp. and an elect cannot remove an approved member of the club they are waiting to join (op 10)',
  electCantRemoveMember.status === 403, `${electCantRemoveMember.status}`);

// (Op 5) Removal of an existing approved member by that club's admin, with the scope wall intact.
const removeTarget = await ask('POST', '/clubs/10/members/21/status', { token: 'tok-admin10', body: { status: 'removed' } });
check('2Rq. an admin can also move a rejected row to removed, and the write reads back (op 5)',
  removeTarget.status === 200 && removeTarget.body?.data?.membership_status === 'removed'
  && tables.club_memberships.find((row) => String(row.user_id) === '21')?.status === 'removed',
  `${removeTarget.status} ${removeTarget.text.slice(0, 120)}`);

// Reset every row this section moved, so 2Q's equivalence battery and the R3/R4 arms below still
// measure the fixture they were written against.
resetRow('20', { club_id: '10', role: 'member', status: 'pending' });
resetRow('21', { club_id: '10', role: 'member', status: 'rejected' });
resetRow('24', { club_id: '12', role: 'member', status: 'approved' });
tables.club_memberships = tables.club_memberships.filter((row) => String(row.user_id) !== '30' && String(row.user_id) !== '5');

// ── R3 — a Club Admin reaches only their own club ───────────────────────────
const ownCollections = await ask('GET', '/clubs/10/board-collections', { token: 'tok-admin10' });
check('3a. a Club Admin lists their own club collections',
  ownCollections.status === 200 && ownCollections.body.data.length === 2,
  `${ownCollections.status} ${ownCollections.text.slice(0, 140)}`);

const otherCollections = await ask('GET', '/clubs/11/board-collections', { token: 'tok-admin10' });
check('3b. a Club Admin is refused another club listings',
  otherCollections.status === 403 && otherCollections.body.error === 'not_a_club_admin',
  `${otherCollections.status} ${otherCollections.text.slice(0, 140)}`);

const crossImport = await ask('POST', '/clubs/11/board-collections', {
  token: 'tok-admin10', body: { name: 'Intrusion', boards: [legalBoard(9)] }
});
check('3c. a Club Admin is refused a write into another club',
  crossImport.status === 403 && crossImport.body.error === 'not_a_club_admin',
  `${crossImport.status} ${crossImport.text.slice(0, 140)}`);
check('3d. the refused cross-club import stored nothing',
  !tables.club_board_collections.some((row) => row.name === 'Intrusion'),
  JSON.stringify(tables.club_board_collections.map((row) => row.name)));

const memberImport = await ask('POST', '/clubs/10/board-collections', {
  token: 'tok-member10', body: { name: 'By a member', boards: [legalBoard(9)] }
});
check('3e. a plain member cannot import at all',
  memberImport.status === 403 && memberImport.body.error === 'not_a_club_admin',
  `${memberImport.status} ${memberImport.text.slice(0, 140)}`);

const inactiveImport = await ask('POST', '/clubs/12/board-collections', {
  token: CALLER_TOKEN, body: { name: 'Dead club', boards: [legalBoard(1)] }
});
check('3f. an inactive club cannot import, even for a Super Admin',
  inactiveImport.status === 403 && inactiveImport.body.error === 'club_inactive',
  `${inactiveImport.status} ${inactiveImport.text.slice(0, 140)}`);

// ── server-side board validation (the client is not the boundary) ───────────
async function refuseBoard(label, board, expectedReason) {
  const answer = await ask('POST', '/clubs/10/board-collections', {
    token: 'tok-admin10', body: { name: `bad ${label}`, boards: [board] }
  });
  check(`4${label}. ${expectedReason} is refused before any row is written`,
    answer.status === 400 && answer.body.error === expectedReason,
    `${answer.status} ${answer.text.slice(0, 150)}`);
}
const shortHand = legalBoard(50);
shortHand.hands.East = shortHand.hands.East.slice(0, 12);
await refuseBoard('a', shortHand, 'incomplete_hands');

const duplicateCard = legalBoard(51);
duplicateCard.hands.West[0] = duplicateCard.hands.North[0];
await refuseBoard('b', duplicateCard, 'incomplete_hands');

const notACard = legalBoard(52);
notACard.hands.North[0] = '1S';
await refuseBoard('c', notACard, 'incomplete_hands');

await refuseBoard('d', legalBoard(53, { vulnerability: 'All' }), 'invalid_vulnerability');
await refuseBoard('e', legalBoard(54, { dealer: 'Northeast' }), 'invalid_dealer');

const sameNumber = [legalBoard(55), { ...legalBoard(56), board_number: '55' }];
const dupeAnswer = await ask('POST', '/clubs/10/board-collections', {
  token: 'tok-admin10', body: { name: 'dupes', boards: sameNumber }
});
check('4f. a repeated board number inside one collection is refused',
  dupeAnswer.status === 400 && dupeAnswer.body.error === 'duplicate_board_number',
  `${dupeAnswer.status} ${dupeAnswer.text.slice(0, 150)}`);

// The arm that separates NodeSend's validation from the client path's. 14 cards in one hand and 12
// in another still totals exactly 52 distinct cards, so a total-count check — which is all the
// browser-side validator does — accepts it. This is the shape an illegal board actually arrives in.
const lopsided = legalBoard(49);
lopsided.hands.North = [...lopsided.hands.North, lopsided.hands.East.pop()];
check('4i. a 14/12 seat split that still totals 52 distinct cards is refused (per-seat, not total)',
  lopsided.hands.North.length === 14 && lopsided.hands.East.length === 12
  && clubBoardValidateOne(lopsided).ok === false,
  `North=${lopsided.hands.North.length} East=${lopsided.hands.East.length}`);
const lopsidedAnswer = await ask('POST', '/clubs/10/board-collections', {
  token: 'tok-admin10', body: { name: 'lopsided', boards: [lopsided] }
});
check('4j. and the route refuses it too, before a row exists',
  lopsidedAnswer.status === 400 && lopsidedAnswer.body.error === 'incomplete_hands',
  `${lopsidedAnswer.status} ${lopsidedAnswer.text.slice(0, 150)}`);

const oversized = await ask('POST', '/clubs/10/board-collections', {
  token: 'tok-admin10',
  body: { name: 'too many', boards: Array.from({ length: 201 }, (unused, index) => legalBoard(index + 1)) }
});
check('4g. an oversized submission is refused by the batch limit',
  oversized.status === 400 && oversized.body.error === 'too_many_boards',
  `${oversized.status} ${oversized.text.slice(0, 150)}`);
check('4h. no rejected import left a collection or board row behind',
  tables.club_board_collections.length === 3 && tables.club_collection_boards.length === 5,
  `${tables.club_board_collections.length}/${tables.club_collection_boards.length}`);

// ── the publish workflow: draft, boards, verify, only then published ────────
const imported = await ask('POST', '/clubs/10/board-collections', {
  token: 'tok-admin10', body: { name: 'Round 3', boards: [legalBoard(7), legalBoard(8)] }
});
const importedId = imported.body?.data?.id;
check('5a. an import creates a DRAFT collection, verified board-for-board',
  imported.status === 200 && imported.body?.data?.status === 'draft'
  && imported.body?.data?.board_count === 2 && imported.body?.data?.verified === true,
  `${imported.status} ${imported.text.slice(0, 160)}`);

const memberBeforePublish = await ask('GET', `/clubs/collections/${importedId}/boards`, { token: 'tok-member10' });
check('5b. a draft is invisible to a member of that club',
  memberBeforePublish.status === 403 && memberBeforePublish.body.error === 'collection_not_published',
  `${memberBeforePublish.status} ${memberBeforePublish.text.slice(0, 150)}`);

const adminPreview = await ask('GET', `/clubs/collections/${importedId}/boards`, { token: 'tok-admin10' });
check('5c. the owning club admin can preview the draft',
  adminPreview.status === 200 && adminPreview.body.data.length === 2,
  `${adminPreview.status} ${adminPreview.text.slice(0, 150)}`);

const published = await ask('POST', `/clubs/collections/${importedId}/publish`, { token: 'tok-admin10' });
check('5d. publish succeeds only after the board set verified',
  published.status === 200 && published.body?.data?.status === 'published',
  `${published.status} ${published.text.slice(0, 150)}`);

const memberAfterPublish = await ask('GET', `/clubs/collections/${importedId}/boards`, { token: 'tok-member10' });
check('5e. published boards are visible to a member of the owning club',
  memberAfterPublish.status === 200 && memberAfterPublish.body.data.length === 2
  && memberAfterPublish.body.data.every((board) => board.hands.North.length === 13),
  `${memberAfterPublish.status} ${memberAfterPublish.text.slice(0, 150)}`);

const unpublished = await ask('POST', `/clubs/collections/${importedId}/unpublish`, { token: 'tok-admin10' });
const memberAfterUnpublish = await ask('GET', `/clubs/collections/${importedId}/boards`, { token: 'tok-member10' });
check('5f. unpublishing withdraws the boards from members immediately',
  unpublished.status === 200 && memberAfterUnpublish.status === 403
  && memberAfterUnpublish.body.error === 'collection_not_published',
  `${unpublished.status}/${memberAfterUnpublish.status} ${memberAfterUnpublish.text.slice(0, 120)}`);
await ask('POST', `/clubs/collections/${importedId}/publish`, { token: 'tok-admin10' });

// ── R4 — a member reaches only published boards of their own club ───────────
const otherClubBoards = await ask('GET', '/clubs/collections/c-other/boards', { token: 'tok-member10' });
check('6a. a direct request for another club boards is refused',
  otherClubBoards.status === 403 && otherClubBoards.body.error === 'other_club_board',
  `${otherClubBoards.status} ${otherClubBoards.text.slice(0, 150)}`);

const noClubBoards = await ask('GET', '/clubs/collections/c-pub/boards', { token: 'tok-noclub' });
check('6b. a user with no club is denied published boards',
  noClubBoards.status === 403 && noClubBoards.body.error === 'not_a_club_member',
  `${noClubBoards.status} ${noClubBoards.text.slice(0, 150)}`);

const noClubCollections = await ask('GET', '/me/club/board-collections', { token: 'tok-noclub' });
check('6c. a user with no club gets no collection list at all',
  noClubCollections.status === 403 && noClubCollections.body.error === 'not_a_club_member',
  `${noClubCollections.status} ${noClubCollections.text.slice(0, 150)}`);

const memberOwn = await ask('GET', '/me/club/board-collections', { token: 'tok-member10' });
check('6d. the member list is published-only and club-scoped',
  memberOwn.status === 200 && Array.isArray(memberOwn.body.data)
  && memberOwn.body.data.every((row) => row.status === 'published')
  && !memberOwn.body.data.some((row) => row.id === 'c-other'),
  `${memberOwn.status} ${memberOwn.text.slice(0, 160)}`);

// Revocation, measured as a change of answer rather than asserted from the code path.
const membershipRow = tables.club_memberships.find((row) => String(row.user_id) === '3');
const savedMembership = { ...membershipRow };
tables.club_memberships = tables.club_memberships.filter((row) => String(row.user_id) !== '3');
const afterRevoke = await ask('GET', '/clubs/collections/c-pub/boards', { token: 'tok-member10' });
check('6e. removing a membership revokes board access on the next request',
  afterRevoke.status === 403 && afterRevoke.body.error === 'not_a_club_member',
  `${afterRevoke.status} ${afterRevoke.text.slice(0, 150)}`);
tables.club_memberships.push(savedMembership);
const afterRestore = await ask('GET', '/clubs/collections/c-pub/boards', { token: 'tok-member10' });
check('6f. and it comes back when the membership does (the denial was the row, not a cache)',
  afterRestore.status === 200,
  `${afterRestore.status} ${afterRestore.text.slice(0, 150)}`);

// A demotion is a revocation too: the same user, the same club, a different role. Looked up again
// from the live array, because the restore above inserted a copy and a stale reference would make
// this arm mutate nothing and still print a pass-shaped verdict.
const adminMembership = tables.club_memberships.find((row) => String(row.user_id) === '2');
adminMembership.role = 'member';
const demoted = await ask('GET', '/clubs/10/board-collections', { token: 'tok-admin10' });
check('6g. a club admin appointment revoked server-side takes the admin surface with it',
  demoted.status === 403 && demoted.body.error === 'not_a_club_admin',
  `${demoted.status} ${demoted.text.slice(0, 150)}`);
adminMembership.role = 'club_admin';
const restoredAdmin = await ask('GET', '/clubs/10/board-collections', { token: 'tok-admin10' });
check('6h. and the admin surface returns when the appointment does',
  restoredAdmin.status === 200,
  `${restoredAdmin.status} ${restoredAdmin.text.slice(0, 150)}`);

const missingCollection = await ask('GET', '/clubs/collections/does-not-exist/boards', { token: 'tok-member10' });
check('6i. an unknown collection is a 404, not an empty successful list',
  missingCollection.status === 404 && missingCollection.body.error === 'collection_not_found',
  `${missingCollection.status} ${missingCollection.text.slice(0, 150)}`);

const pathInjection = await ask('PATCH', '/clubs/%24%7Bsql%7D', { token: CALLER_TOKEN, body: { name: 'x' } });
check('6j. a non identifier path parameter is refused before it reaches storage',
  pathInjection.status === 400 && pathInjection.body.error === 'bad_request',
  `${pathInjection.status} ${pathInjection.text.slice(0, 150)}`);

// The `/clubs/options` literal must answer as a list of clubs, never as the club whose id is
// "options". This is what the registration dropdown calls.
const options = await ask('GET', '/clubs/options', { token: 'tok-member10' });
check('6k. the literal /clubs/options is routed to the option list, not to a club named options',
  options.status === 200 && Array.isArray(options.body.data)
  && options.body.data.every((row) => row.status === undefined && row.name && row.id),
  `${options.status} ${options.text.slice(0, 160)}`);

// ── a failed import never becomes visible content ───────────────────────────
const collectionsBefore = tables.club_board_collections.length;
failBoardCreateNumber = '2';
const broken = await ask('POST', '/clubs/10/board-collections', {
  token: 'tok-admin10', body: { name: 'half import', boards: [legalBoard(1), legalBoard(2), legalBoard(3)] }
});
failBoardCreateNumber = null;
check('7a. an import whose board write fails mid-way is reported as a failure, not a success',
  broken.status === 422 && broken.body.error === 'import_incomplete',
  `${broken.status} ${broken.text.slice(0, 180)}`);
const brokenRow = tables.club_board_collections.find((row) => row.id === String(broken.body?.data?.collectionId));
check('7b. a failed import published nothing',
  broken.status === 422 && (!brokenRow || brokenRow.status === 'draft'),
  JSON.stringify(brokenRow));
check('7c. the partial board rows were cleaned up rather than left to be discovered later',
  !tables.club_collection_boards.some((row) => String(row.collection_id) === String(broken.body?.data?.collectionId)),
  `${tables.club_collection_boards.length} board rows remain`);
check('7d. no orphan collection survived the failed import',
  tables.club_board_collections.length === collectionsBefore,
  `${collectionsBefore} -> ${tables.club_board_collections.length}`);

// The read-back that gates publish: the writes are accepted, then the verification read is told
// there are no rows. That disagreement is the only honest signal a sequential REST store can give.
hideBoardReads = 5;
const unverifiable = await ask('POST', '/clubs/10/board-collections', {
  token: 'tok-admin10', body: { name: 'unverifiable', boards: [legalBoard(101), legalBoard(102)] }
});
hideBoardReads = 0;
check('7e. an import whose read-back disagrees with its writes is refused, and stays unpublished',
  unverifiable.status === 422 && unverifiable.body.error === 'import_unverified',
  `${unverifiable.status} ${unverifiable.text.slice(0, 180)}`);

// A collection this process did not import must be re-read before it can be published, so a
// corrupted stored hand is refused rather than shipped to members.
tables.club_board_collections.push({ id: 'c-corrupt', club_id: '10', name: 'Corrupt', status: 'draft' });
tables.club_collection_boards.push({
  id: 'cc1', collection_id: 'c-corrupt', board_number: '1', dealer: 'North',
  vulnerability: 'None', hands_json: JSON.stringify({ North: ['XX'], East: [], South: [], West: [] })
});
const publishCorrupt = await ask('POST', '/clubs/collections/c-corrupt/publish', { token: 'tok-admin10' });
check('7f. publishing a collection with a corrupt stored board is refused',
  publishCorrupt.status === 422 && publishCorrupt.body.error === 'publish_refused_unverified',
  `${publishCorrupt.status} ${publishCorrupt.text.slice(0, 180)}`);
check('7g. the refused collection is still a draft',
  tables.club_board_collections.find((row) => row.id === 'c-corrupt')?.status === 'draft',
  String(tables.club_board_collections.find((row) => row.id === 'c-corrupt')?.status));
const memberSeesCorrupt = await ask('GET', '/clubs/collections/c-corrupt/boards', { token: 'tok-member10' });
check('7h. and a member is refused it as unpublished, not served a broken board',
  memberSeesCorrupt.status === 403 && memberSeesCorrupt.body.error === 'collection_not_published',
  `${memberSeesCorrupt.status} ${memberSeesCorrupt.text.slice(0, 150)}`);

const crossPublish = await ask('POST', '/clubs/collections/c-other/publish', { token: 'tok-admin10' });
check('7i. an admin of one club cannot publish another club collection',
  crossPublish.status === 403 && crossPublish.body.error === 'not_a_club_admin',
  `${crossPublish.status} ${crossPublish.text.slice(0, 150)}`);

// ── the server-owned account is the only thing that touched a club table ────
// The positive control comes FIRST. An assertion over an empty list passes for the wrong reason,
// and "no club data call ever carried a caller bearer" is worthless if no club data call happened.
check('8a. the harness really did drive the club store (otherwise 8b is vacuous)',
  dataCalls.length > 20,
  `only ${dataCalls.length} club data calls were recorded`);
const foreignBearers = dataCalls.filter((row) => row.bearer !== CLUB_SESSION_TOKEN);
check('8b. every club-data operation ran on the dedicated account, never a caller bearer',
  foreignBearers.length === 0,
  `${foreignBearers.length} call(s) carried a caller token`);
check('8c. no club-data call went to a table outside the agreed five',
  new Set(dataCalls.map((row) => row.pathname.split('/')[3])).size === 5
  && new Set(dataCalls.map((row) => row.pathname.split('/')[3])).has('club_collection_boards'),
  [...new Set(dataCalls.map((row) => row.pathname.split('/')[3]))].join(','));

// ── board-start: a read and a validation, never a write ─────────────────────
const AGREED = ['system_admins', 'clubs', 'club_memberships', 'club_board_collections', 'club_collection_boards'];
const tableOf = (row) => row.pathname.split('/')[3];

const badSeat = await ask('POST', '/clubs/collections/c-pub/boards/1/start', { token: 'tok-member10', body: { original_seat: 'Northeast' } });
check('8d. an out-of-vocabulary seat is refused',
  badSeat.status === 400 && badSeat.body.error === 'bad_request',
  `${badSeat.status} ${badSeat.text.slice(0, 150)}`);

const forgedStart = await ask('POST', '/clubs/collections/c-pub/boards/1/start', {
  token: 'tok-member10', body: { original_seat: 'West', user_id: '9', role: 'club_admin' }
});
check('8e. a forged identity field on board-start is refused, not ignored',
  forgedStart.status === 400 && forgedStart.body.error === 'client_identity_refused',
  `${forgedStart.status} ${forgedStart.text.slice(0, 150)}`);

const anonymousStart = await ask('POST', '/clubs/collections/c-pub/boards/1/start', { body: { original_seat: 'West' } });
check('8f. an anonymous board-start is refused',
  anonymousStart.status === 401, `${anonymousStart.status}`);

// The happy path, measured against the payload the engine consumes.
const callsBeforeStart = dataCalls.length;
const startOk = await ask('POST', '/clubs/collections/c-pub/boards/2/start', { token: 'tok-member10', body: { original_seat: 'East' } });
const startedBoard = startOk.body?.data ?? {};
check('8g. a published board of the caller own club starts, with the canonical payload',
  startOk.status === 200 && startedBoard.board_number === '2' && startedBoard.dealer === 'North'
  && startedBoard.vulnerability === 'None' && startedBoard.original_seat === 'East'
  && startedBoard.club_id === '10' && startedBoard.collection_id === 'c-pub'
  && ['North', 'East', 'South', 'West'].every((seat) => (startedBoard.hands?.[seat] ?? []).length === 13)
  && new Set(['North', 'East', 'South', 'West'].flatMap((seat) => startedBoard.hands?.[seat] ?? [])).size === 52,
  `${startOk.status} ${startOk.text.slice(0, 170)}`);

// Positive control for the detector itself. If `method` were never recorded, or were always 'GET',
// the "zero writes" claim below would pass while proving nothing — so first show the same
// instrumentation catching a write where a write genuinely happens (the imports above).
check('8h. the call recorder does see writes (otherwise the next two arms are vacuous)',
  dataCalls.some((row) => row.method === 'POST') && dataCalls.some((row) => row.method === 'GET'),
  `methods seen: ${[...new Set(dataCalls.map((row) => row.method))].join(',')}`);
const startWindow = dataCalls.slice(callsBeforeStart);
check('8i. board-start performed zero writes (positive control: it did perform reads)',
  startWindow.length > 0 && startWindow.every((row) => row.method === 'GET'),
  `${startWindow.filter((row) => row.method !== 'GET').length} write(s) of ${startWindow.length} calls`);
const liveSchema = clubSchemaConfig({ CLUB_NCB_SCHEMA_JSON: process.env.CLUB_NCB_SCHEMA_JSON });
check('8j. board-start touched no table outside the agreed five, and the live schema IS those five',
  startWindow.length > 0 && startWindow.every((row) => AGREED.includes(tableOf(row)))
  && liveSchema.ok === true && Object.keys(liveSchema.schema.tables).length === 5
  && !Object.values(liveSchema.schema.tables).includes('club_board_attempts'),
  `${[...new Set(startWindow.map(tableOf).filter((name) => !AGREED.includes(name)))].join(',')} / ${JSON.stringify(liveSchema.schema?.tables ?? liveSchema.problems)}`);

// A deployment that declares the old sixth table is refused at boot, not quietly tolerated.
const sixthTable = clubSchemaConfig({
  CLUB_NCB_SCHEMA_JSON: JSON.stringify({
    tables: { ...JSON.parse(process.env.CLUB_NCB_SCHEMA_JSON).tables, attempts: 'club_board_attempts' },
    columns: JSON.parse(process.env.CLUB_NCB_SCHEMA_JSON).columns
  })
});
check('8k. a schema declaring a sixth attempts table is refused, naming the role',
  sixthTable.ok === false && sixthTable.problems.some((problem) => /attempts/.test(problem)),
  JSON.stringify(sixthTable.problems));

// Draft, cross-club, no-club and unknown-board refusals.
const draftStartMember = await ask('POST', '/clubs/collections/c-draft/boards/4/start', { token: 'tok-member10', body: { original_seat: 'North' } });
check('8l. a draft board cannot be put into play by a member',
  draftStartMember.status === 403 && draftStartMember.body.error === 'collection_not_published',
  `${draftStartMember.status} ${draftStartMember.text.slice(0, 150)}`);

// The strictness this task asked for: even the OWNING club admin, who may legitimately PREVIEW a
// draft, may not START one. Reviewing an unreleased deal and dealing it to a table are different
// permissions, and the list route's exemption must not leak into this one.
const draftStartAdmin = await ask('POST', '/clubs/collections/c-draft/boards/4/start', { token: 'tok-admin10', body: { original_seat: 'North' } });
check('8m. a draft cannot be started even by an admin of the owning club',
  draftStartAdmin.status === 403 && draftStartAdmin.body.error === 'collection_not_published',
  `${draftStartAdmin.status} ${draftStartAdmin.text.slice(0, 150)}`);
const adminCanStillListDraft = await ask('GET', '/clubs/collections/c-draft/boards', { token: 'tok-admin10' });
check('8n. while the admin keeps the read-only draft preview (the two powers stay distinct)',
  adminCanStillListDraft.status === 200, `${adminCanStillListDraft.status}`);

const crossStart = await ask('POST', '/clubs/collections/c-other/boards/1/start', { token: 'tok-member10', body: { original_seat: 'North' } });
check('8o. a board of another club is refused on start',
  crossStart.status === 403 && crossStart.body.error === 'other_club_board',
  `${crossStart.status} ${crossStart.text.slice(0, 150)}`);

const noClubStart = await ask('POST', '/clubs/collections/c-pub/boards/1/start', { token: 'tok-noclub', body: { original_seat: 'North' } });
check('8p. a user with no club is refused on start',
  noClubStart.status === 403 && noClubStart.body.error === 'not_a_club_member',
  `${noClubStart.status} ${noClubStart.text.slice(0, 150)}`);

// A super admin who belongs to no club holds no club's board to play.
const superStart = await ask('POST', '/clubs/collections/c-pub/boards/1/start', { token: CALLER_TOKEN, body: { original_seat: 'North' } });
check('8q. a Super Admin with no club membership is refused on start (rank is not membership)',
  superStart.status === 403 && superStart.body.error === 'not_a_club_member',
  `${superStart.status} ${superStart.text.slice(0, 150)}`);

const missingBoard = await ask('POST', '/clubs/collections/c-pub/boards/999/start', { token: 'tok-member10', body: { original_seat: 'North' } });
check('8r. an unknown board number in a reachable collection is a 404, not an empty success',
  missingBoard.status === 404 && missingBoard.body.error === 'board_not_found',
  `${missingBoard.status} ${missingBoard.text.slice(0, 150)}`);

// Validation is enforced on the STORED row at start time, not only at import: a board that was sound
// when published and has since been corrupted must not reach a table.
tables.club_board_collections.push({ id: 'c-bad-live', club_id: '10', name: 'Corrupted after publish', status: 'published' });
tables.club_collection_boards.push({
  id: 'bl1', collection_id: 'c-bad-live', board_number: '77', dealer: 'North', vulnerability: 'None',
  hands_json: JSON.stringify({ North: ['2S'], East: [], South: [], West: [] })
});
const corruptStart = await ask('POST', '/clubs/collections/c-bad-live/boards/77/start', { token: 'tok-member10', body: { original_seat: 'South' } });
check('8s. a stored board that no longer validates is refused at start, never dealt',
  corruptStart.status === 422 && corruptStart.body.error === 'invalid_board_record',
  `${corruptStart.status} ${corruptStart.text.slice(0, 170)}`);

tables.club_collection_boards.push(
  { id: 'dup1', collection_id: 'c-bad-live', board_number: '78', dealer: 'North', vulnerability: 'None', hands_json: JSON.stringify(legalBoard(78).hands) },
  { id: 'dup2', collection_id: 'c-bad-live', board_number: '78', dealer: 'East', vulnerability: 'NS', hands_json: JSON.stringify(legalBoard(24).hands) }
);
const ambiguousStart = await ask('POST', '/clubs/collections/c-bad-live/boards/78/start', { token: 'tok-member10', body: { original_seat: 'North' } });
check('8t. two rows claiming one board number is a service failure, not an arbitrary choice',
  ambiguousStart.status === 503 && ambiguousStart.body.error === 'club_store_unavailable',
  `${ambiguousStart.status} ${ambiguousStart.text.slice(0, 150)}`);
tables.club_collection_boards = tables.club_collection_boards.filter((row) => !['dup1', 'dup2', 'bl1'].includes(row.id));
tables.club_board_collections = tables.club_board_collections.filter((row) => row.id !== 'c-bad-live');

// Revocation reaches start too, on the very next request.
const memberStartRow = tables.club_memberships.find((row) => String(row.user_id) === '3');
tables.club_memberships = tables.club_memberships.filter((row) => String(row.user_id) !== '3');
const revokedStart = await ask('POST', '/clubs/collections/c-pub/boards/1/start', { token: 'tok-member10', body: { original_seat: 'North' } });
check('8u. a membership removal revokes board-start on the next request',
  revokedStart.status === 403 && revokedStart.body.error === 'not_a_club_member',
  `${revokedStart.status} ${revokedStart.text.slice(0, 150)}`);
tables.club_memberships.push(memberStartRow);

// ── nothing a client can see names a secret ─────────────────────────────────
const allText = seenBodies.join('\n') + await (await fetch(`${BASE}/health`)).text() + await (await fetch(BASE)).text();
const leaked = [CLUB_PASSWORD, CLUB_SESSION_TOKEN, CALLER_TOKEN, CLUB_ACCOUNT_EMAIL]
  .filter((secret) => allText.includes(secret));
check('8v. no credential, token or account address appears in any response body',
  leaked.length === 0,
  `leaked: ${leaked.map((x) => x.slice(0, 6)).join(',')}`);
const healthText = JSON.stringify(clubHealth(bridge.clubMount));
check('8w. the club health view reports state without a table name or an address',
  !healthText.includes('club_memberships') && !healthText.includes(CLUB_ACCOUNT_EMAIL)
  && !healthText.includes(CLUB_PASSWORD),
  healthText.slice(0, 160));

// ── the routes that were here before still behave as before ─────────────────
const root = await (await fetch(BASE)).json();
check('9a. the service root still advertises the pre-existing surface',
  root.version === 'bridge-nodesend-quota-v9'
  && root.endpoints?.aiChat === 'POST /ai/chat'
  && root.endpoints?.tricksterPlaySuggest === 'POST /trickster/play/suggest-card'
  && root.endpoints?.invitationConsume === 'POST /auth/consume-invitation'
  && root.endpoints?.quota === 'GET|POST /quota',
  JSON.stringify(Object.keys(root.endpoints ?? {})));
const health = await (await fetch(`${BASE}/health`)).json();
check('9b. /health is still healthy, still v9, and now also describes Clubs',
  health.status === 'healthy' && health.version === 'bridge-nodesend-quota-v9'
  && health.clubs && health.clubs.configured === true && health.clubs.routes === clubRoutes.length,
  JSON.stringify(health.clubs));
check('9c. /health exposes no club secret and no NCB host',
  !JSON.stringify(health).includes(CLUB_PASSWORD) && !JSON.stringify(health).includes('ncb.test.invalid')
  && !JSON.stringify(health).includes(CLUB_ACCOUNT_EMAIL),
  JSON.stringify(health).slice(0, 160));

const aiNoToken = await call('POST', '/ai/chat', { body: { model: 'x' } });
check('9d. /ai/chat still demands a session (the club mount did not displace the guard)',
  aiNoToken.status === 401, `${aiNoToken.status} ${aiNoToken.text.slice(0, 120)}`);
const tricksterNoToken = await call('GET', '/trickster/bid/health');
check('9e. /trickster/bid/health still demands a session',
  tricksterNoToken.status === 401, `${tricksterNoToken.status}`);
const relayNoKey = await call('POST', '/send', { body: {} });
check('9f. the x-api-key relay guard is unchanged',
  relayNoKey.status === 403 || relayNoKey.status === 400, `${relayNoKey.status}`);
const unknown = await call('GET', '/definitely-not-a-route');
check('9g. the catch-all 404 still answers for an unknown path',
  unknown.status === 404 && unknown.body.error === 'Endpoint not found',
  `${unknown.status} ${unknown.text.slice(0, 120)}`);
const clubIdNoRoute = await call('GET', '/clubs/999', { token: CALLER_TOKEN });
check('9h. the club router does not over-match: GET /clubs/:id is not a route',
  clubIdNoRoute.status === 404, `${clubIdNoRoute.status} ${clubIdNoRoute.text.slice(0, 120)}`);

// ── the prepared client operation list matches the mounted routes exactly ───
// The unprefixed spelling of every operation in the client contract
// (BridgeMind src/services/clubContracts.js CLUB_ENDPOINTS, `/api` removed by its transport).
// Inlined deliberately: a NodeSend gate must not need a second repository checked out to know what
// its own surface should be, and must not silently pass because that repository is absent.
const CLIENT_EXPECTED = Object.freeze([
  'GET /clubs', 'POST /clubs', 'PATCH /clubs/:clubId', 'POST /clubs/:clubId/status',
  'GET /clubs/:clubId/members', 'POST /clubs/:clubId/admins', 'DELETE /clubs/:clubId/admins/:userId',
  'GET /clubs/options', 'GET /me/club', 'POST /me/club', 'DELETE /me/club',
  'GET /clubs/:clubId/board-collections', 'POST /clubs/:clubId/board-collections',
  'PATCH /clubs/collections/:collectionId', 'POST /clubs/collections/:collectionId/publish',
  'POST /clubs/collections/:collectionId/unpublish', 'DELETE /clubs/collections/:collectionId',
  'GET /me/club/board-collections', 'GET /clubs/collections/:collectionId/boards',
  'POST /clubs/collections/:collectionId/boards/:boardNumber/start'
]);

// Read the surface off the REAL Express stack rather than off the declaration, so a route added to
// the list but not mounted — or mounted but not listed — reddens this arm.
function mountedClubPaths() {
  const found = [];
  for (const layer of app._router.stack) {
    if (layer.name !== 'router' || !layer.handle?.stack) continue;
    for (const route of layer.handle.stack) {
      const entry = route?.route;
      if (!entry) continue;
      for (const method of Object.keys(entry.methods ?? {})) {
        found.push(`${method.toUpperCase()} ${entry.path}`);
      }
    }
  }
  return found;
}
const mounted = mountedClubPaths();
const declared = clubRoutes.map((route) => `${route.method} ${route.path}`);
const notMounted = declared.filter((route) => !mounted.includes(route));
const undeclared = mounted.filter((route) => !declared.includes(route));
const notExpected = CLIENT_EXPECTED.filter((route) => !mounted.includes(route));
check('10a. every declared club route is actually mounted on the live app',
  notMounted.length === 0, notMounted.join(' | '));
check('10b. nothing is mounted that the module does not declare',
  undeclared.length === 0, undeclared.join(' | '));
check('10c. every operation the prepared club client can call has a matching NodeSend route',
  notExpected.length === 0, notExpected.join(' | '));
// Routes NodeSend serves that the prepared browser client does NOT call. Each is a deliberate
// server-side addition, enumerated rather than tolerated: an arm that merely asserted
// "mounted == client list" would have gone red on the membership-transition route, and the tempting
// fix for a red parity arm is to delete the route. Naming the additions keeps an accidental new
// public surface as loud as a missing one.
const SERVER_ONLY_ROUTES = Object.freeze([
  // Approving, rejecting or revoking a membership is an authority action. BridgeMind's client has no
  // such call yet, and the server must not wait for it to exist before it can enforce approval.
  'POST /clubs/:clubId/members/:userId/status'
]);
const beyondClient = mounted.filter((route) => !CLIENT_EXPECTED.includes(route));
const unexplained = beyondClient.filter((route) => !SERVER_ONLY_ROUTES.includes(route));
const missingAdditions = SERVER_ONLY_ROUTES.filter((route) => !mounted.includes(route));
check('10d. the mounted surface equals the client contract plus exactly the declared server-only additions',
  unexplained.length === 0 && missingAdditions.length === 0,
  `unexplained: ${unexplained.join(',') || 'none'} | missing: ${missingAdditions.join(',') || 'none'}`);
check('10e. the mounted surface has no duplicate registration',
  new Set(mounted).size === mounted.length,
  mounted.filter((route, i) => mounted.indexOf(route) !== i).join(','));
check('10f. club routes are unprefixed, so /api/clubs is NOT served here',
  mounted.every((route) => !route.includes('/api/'))
  && !mounted.some((route) => route.endsWith(' /api/clubs')),
  mounted.filter((route) => route.includes('/api/')).join(' | '));

// ── pure authority decision, without any I/O at all ─────────────────────────
const pureDenials = [
  ['no session', clubAuthorize({ op: 'myClub', session: null }).status === 401],
  ['role alone is not super admin', clubAuthorize({
    op: 'listClubs', session: { id: '6', role: 'administrator' }, storeSuperAdmin: false
  }).status === 403],
  ['admin of another club', clubAuthorize({
    op: 'listCollections', session: { id: '2', role: 'user' },
    membership: { clubId: '10', role: 'club_admin' }, targetClubId: '11', storeSuperAdmin: false
  }).status === 403],
  ['member reading another club boards', clubAuthorize({
    op: 'listCollectionBoards', session: { id: '3', role: 'user' },
    membership: { clubId: '10', role: 'member' }, ownerClubId: '11', collectionStatus: 'published',
    targetClubStatus: 'active', storeSuperAdmin: false
  }).body?.error === 'other_club_board'],
  ['draft is not published', clubAuthorize({
    op: 'listCollectionBoards', session: { id: '3', role: 'user' },
    membership: { clubId: '10', role: 'member' }, ownerClubId: '10', collectionStatus: 'draft',
    targetClubStatus: 'active', storeSuperAdmin: false
  }).body?.error === 'collection_not_published'],
  ['unknown club status is not active', clubAuthorize({
    op: 'listPublishedCollections', session: { id: '3', role: 'user' },
    membership: { clubId: '10', role: 'member' }, targetClubStatus: null, storeSuperAdmin: false
  }).body?.error === 'club_inactive'],
  ['no club is refused the member list', clubAuthorize({
    op: 'listPublishedCollections', session: { id: '5', role: 'user' }, storeSuperAdmin: false
  }).body?.error === 'not_a_club_member'],
  // Board-start is deliberately NOT the same rule as board-listing. These three are the asymmetry
  // written down as data: rank grants nothing a membership would not, and preview does not imply play.
  ['super admin with no club cannot start', clubAuthorize({
    op: 'startClubBoard', session: { id: '1', role: 'administrator' }, membership: null,
    ownerClubId: '10', collectionStatus: 'published', targetClubStatus: 'active', storeSuperAdmin: true
  }).body?.error === 'not_a_club_member'],
  ['owning club admin cannot start a draft', clubAuthorize({
    op: 'startClubBoard', session: { id: '2', role: 'user' }, membership: { clubId: '10', role: 'club_admin' },
    ownerClubId: '10', collectionStatus: 'draft', targetClubStatus: 'active', storeSuperAdmin: false
  }).body?.error === 'collection_not_published'],
  ['an admin of another club cannot start', clubAuthorize({
    op: 'startClubBoard', session: { id: '2', role: 'user' }, membership: { clubId: '10', role: 'club_admin' },
    ownerClubId: '11', collectionStatus: 'published', targetClubStatus: 'active', storeSuperAdmin: false
  }).body?.error === 'other_club_board']
];
check(`11a. the pure authority decision denies all ${pureDenials.length} unsafe shapes`,
  pureDenials.every(([, verdict]) => verdict === true),
  pureDenials.filter(([, verdict]) => !verdict).map(([label]) => label).join(' | '));
check('11b. and permits the safe ones (member on a published active board; admin previewing a draft)',
  clubAuthorize({
    op: 'listCollectionBoards', session: { id: '3', role: 'user' },
    membership: { clubId: '10', role: 'member' }, ownerClubId: '10', collectionStatus: 'published',
    targetClubStatus: 'active', storeSuperAdmin: false
  }).allow === true
  && clubAuthorize({
    op: 'startClubBoard', session: { id: '3', role: 'user' },
    membership: { clubId: '10', role: 'member' }, ownerClubId: '10', collectionStatus: 'published',
    targetClubStatus: 'active', storeSuperAdmin: false
  }).allow === true
  // The half that keeps 11a's third denial from being a blanket refusal: the SAME admin on the SAME
  // draft is allowed to LIST it. If this ever flips, the two powers collapsed back into one.
  && clubAuthorize({
    op: 'listCollectionBoards', session: { id: '2', role: 'user' },
    membership: { clubId: '10', role: 'club_admin' }, ownerClubId: '10', collectionStatus: 'draft',
    targetClubStatus: 'active', storeSuperAdmin: false
  }).allow === true);
check('11c. the shape validator refuses an identity field and accepts a legitimate body',
  clubValidateShape('setMyClub', { query: {}, body: { club_id: '10', user_id: '9' } })?.status === 400
  && clubValidateShape('setMyClub', { query: {}, body: { club_id: '10' } }) === null);
check('11d. board validation rejects a 12-card hand and accepts a generated 52-card deal',
  clubBoardValidateOne(legalBoard(1)).ok === true
  && clubBoardValidateOne(shortHand).ok === false);

// ── the fail-closed states that need their OWN club client ──────────────────
// These cannot be exercised through the app booted above (the mount is built once at module load),
// and they are the arms that matter most for a first deployment: the tables do not exist yet, so
// "what happens when the schema is missing" is not an edge case, it is the default state.
const expressLib = require('express');
const SCHEMA_OBJECT = JSON.parse(READY_ENV_SOURCE_SCHEMA());
function READY_ENV_SOURCE_SCHEMA() { return process.env.CLUB_NCB_SCHEMA_JSON; }

async function serveIsolated({ env, fetchImpl }) {
  const instance = expressLib();
  instance.use(expressLib.json({ limit: '1mb' }));
  const mount = buildClubMount({
    env,
    fetchImpl,
    authenticate: async (req) => {
      const token = String(req.get('authorization') ?? '').replace(/^Bearer\s+/, '');
      const user = SESSIONS[token];
      return user
        ? { ok: true, id: user.id, role: user.role }
        : { ok: false, status: 401, code: 'authentication_required' };
    }
  });
  instance.use(mount.router);
  const listener = instance.listen(0, '127.0.0.1');
  await new Promise((resolve) => listener.once('listening', resolve));
  return {
    mount,
    base: `http://127.0.0.1:${listener.address().port}`,
    close: () => new Promise((resolve) => listener.close(resolve))
  };
}

const READY_ENV = {
  NCB_PROXY_BASE: 'https://ncb.test.invalid', NCB_INSTANCE: '55954_bridgemind',
  CLUB_NCB_EMAIL: CLUB_ACCOUNT_EMAIL, CLUB_NCB_PASSWORD: CLUB_PASSWORD,
  CLUB_NCB_EXPECTED_USER_ID: CLUB_ACCOUNT_ID,
  CLUB_NCB_SCHEMA_JSON: process.env.CLUB_NCB_SCHEMA_JSON
};
const noOpsFetch = async () => new Response(JSON.stringify({ status: 'error', message: 'no network expected' }), { status: 500 });

const noPassword = await serveIsolated({ env: { ...READY_ENV, CLUB_NCB_PASSWORD: '' }, fetchImpl: noOpsFetch });
const noPasswordAnswer = await call('GET', '/clubs', { token: CALLER_TOKEN, base: noPassword.base });
check('12a. a missing club password fails closed at boot and answers 503',
  noPassword.mount.configured === false && noPassword.mount.reason === 'club_account_unconfigured'
  && noPasswordAnswer.status === 503,
  `${noPassword.mount.reason} / ${noPasswordAnswer.status}`);
await noPassword.close();

const noSchema = await serveIsolated({
  env: Object.fromEntries(Object.entries(READY_ENV).filter(([key]) => !key.startsWith('CLUB_NCB_SCHEMA'))),
  fetchImpl: noOpsFetch
});
const noSchemaAnswer = await call('GET', '/me/club', { token: 'tok-member10', base: noSchema.base });
check('12b. a missing schema fails closed rather than answering "you have no club"',
  noSchema.mount.reason === 'club_schema_unconfigured' && noSchemaAnswer.status === 503
  && noSchemaAnswer.body.error === 'club_store_unavailable',
  `${noSchema.mount.reason} / ${noSchemaAnswer.status} ${noSchemaAnswer.text.slice(0, 120)}`);
await noSchema.close();

const partialSchema = clubSchemaConfig({
  ...READY_ENV,
  CLUB_NCB_SCHEMA_JSON: JSON.stringify({
    tables: { clubs: 'clubs', memberships: 'club_memberships', collections: 'club_board_collections', boards: 'club_collection_boards' },
    columns: SCHEMA_OBJECT.columns
  })
});
check('12c. a schema missing system_admins is refused, naming the missing role',
  partialSchema.ok === false && partialSchema.problems.some((problem) => problem.includes('systemAdmins')),
  JSON.stringify(partialSchema.problems));

const columnGap = clubSchemaConfig({
  ...READY_ENV,
  CLUB_NCB_SCHEMA_JSON: JSON.stringify({
    tables: SCHEMA_OBJECT.tables,
    columns: { ...SCHEMA_OBJECT.columns, boards: { ...SCHEMA_OBJECT.columns.boards, handsJson: '' } }
  })
});
check('12d. a required column left blank is refused (a partial schema is never guessed at)',
  columnGap.ok === false && columnGap.problems.some((problem) => problem.includes('boards.handsJson')),
  JSON.stringify(columnGap.problems));

const twoSources = clubSchemaConfig({ ...READY_ENV, CLUB_NCB_SCHEMA_FILE: 'also-set.json' });
check('12e. two authorities for one contract is refused rather than settled by precedence',
  twoSources.ok === false && /both set/.test(twoSources.problems.join(' ')),
  JSON.stringify(twoSources.problems));

// The forbidden name is assembled rather than spelled out. This repo carries a source-wide gate
// (verify-session-quota.mjs) that bans any browser-visible variable name for an NCB secret from
// appearing as literal text in the shipped files, and a test fixture is not a reason to break it.
// The arm still exercises the real boot path: the string that reaches readClubAccountConfig is the
// same one a mistaken deployment would set.
const FRONTEND_LEAK_NAME = `VITE_CLUB_${'NCB'}_PASSWORD`;
const frontendEnv = clubAccountConfig({ ...READY_ENV, [FRONTEND_LEAK_NAME]: 'published-password' });
check('12f. a VITE_-prefixed club credential is refused at boot (it would ship inside the bundle)',
  frontendEnv.ok === false && frontendEnv.reason === 'club_credentials_must_not_be_frontend_env',
  JSON.stringify(frontendEnv));

// The dedicated account signed in, but the session belongs to somebody else. Every club request
// must then fail, and not one data call may be made with that token.
let wrongIdentityDataCalls = 0;
const wrongIdentity = await serveIsolated({
  env: READY_ENV,
  fetchImpl: async (url) => {
    const target = String(url);
    if (target.includes('/auth/sign-in/email')) return json({ token: 'someone-elses-token' });
    if (target.includes('/auth/get-session')) return json({ data: { user: { id: '1234', email: 'somebody.else@example.test' } } });
    if (target.includes('/data/')) wrongIdentityDataCalls += 1;
    return json({ status: 'error', message: 'unreachable' }, 500);
  }
});
const wrongIdentityAnswer = await call('GET', '/clubs', { token: CALLER_TOKEN, base: wrongIdentity.base });
check('13a. a sign-in accepted for the WRONG account is refused and never used to read club rows',
  wrongIdentityAnswer.status === 503 && wrongIdentityDataCalls === 0,
  `${wrongIdentityAnswer.status} with ${wrongIdentityDataCalls} data calls`);
const wrongIdentityText = JSON.stringify(wrongIdentity.mount.status());
check('13b. and the account address of the intruder is not quoted back to the operator',
  !wrongIdentityText.includes('somebody.else@example.test'),
  wrongIdentityText.slice(0, 160));
await wrongIdentity.close();

// Token lifecycle: a burst of concurrent requests must share ONE sign-in, and a 401 from the
// account's session must cost exactly one re-sign-in plus one retry — not a retry loop.
let signIns = 0;
let dataAttempts = 0;
let expireArmed = false;
const renewing = await serveIsolated({
  env: READY_ENV,
  fetchImpl: async (url, init = {}) => {
    const target = String(url);
    if (target.includes('/auth/sign-in/email')) {
      signIns += 1;
      return json({ token: `club-token-${signIns}` });
    }
    if (target.includes('/auth/get-session')) return json({ data: { user: { id: CLUB_ACCOUNT_ID, email: CLUB_ACCOUNT_EMAIL } } });
    if (target.includes('/data/')) {
      dataAttempts += 1;
      if (expireArmed) { expireArmed = false; return json({ status: 'error', message: 'session expired' }, 401); }
      const table = target.split('/data/')[1].split('?')[0].split('/')[1];
      // Rich enough for the request to reach a 200: the caller must actually be a system admin,
      // otherwise every arm here would measure a 403 and prove nothing about the token lifecycle.
      const rows = table === 'clubs' ? [{ id: '10', name: 'Glyfada BC', status: 'active' }]
        : table === 'system_admins' ? [{ id: 'sa1', user_id: '1' }] : [];
      return json({ status: 'success', data: rows });
    }
    return json({ status: 'error', message: 'unreachable' }, 500);
  }
});
const fiveAtOnce = await Promise.all([1, 2, 3, 4, 5].map(() => call('GET', '/clubs', { token: CALLER_TOKEN, base: renewing.base })));
check('13c. five concurrent club requests caused exactly one sign-in (no login stampede)',
  signIns === 1 && fiveAtOnce.every((answer) => answer.status === 200),
  `sign-ins=${signIns} statuses=${fiveAtOnce.map((answer) => answer.status).join(',')}`);

const attemptsBefore = dataAttempts;
expireArmed = true;
const afterExpiry = await call('GET', '/clubs', { token: CALLER_TOKEN, base: renewing.base });
// The bound matters more than the exact number: one 401 must cost one renewal and one retry. If a
// second 401 could trigger a second renewal in the same request, a dead token would turn every page
// view into an auth storm, so "no more than 6 data calls for one GET" is the claim being made.
const renewalDelta = dataAttempts - attemptsBefore;
check('13d. an expired account session renews once and the retried read succeeds',
  afterExpiry.status === 200 && signIns === 2 && renewalDelta >= 3 && renewalDelta <= 6,
  `status=${afterExpiry.status} sign-ins=${signIns} attempts=+${renewalDelta}`);

// A sign-in that keeps failing must not be retried per request: the cooldown is what stops a dead
// password from turning every page view into an auth-endpoint call.
await renewing.close();
let hostileSignIns = 0;
const hostile = await serveIsolated({
  env: READY_ENV,
  fetchImpl: async (url) => {
    const target = String(url);
    if (target.includes('/auth/sign-in/email')) {
      hostileSignIns += 1;
      return json({ status: 'error', message: `invalid credentials for ${CLUB_ACCOUNT_EMAIL}` }, 401);
    }
    return json({ status: 'error', message: 'unreachable' }, 500);
  }
});
const hostiles = await Promise.all([1, 2, 3, 4, 5, 6].map(() => call('GET', '/clubs', { token: CALLER_TOKEN, base: hostile.base })));
check('13e. a failing sign-in enters a cooldown instead of retrying once per request',
  hostileSignIns <= 2 && hostiles.every((answer) => answer.status === 503),
  `sign-ins=${hostileSignIns} statuses=${[...new Set(hostiles.map((answer) => answer.status))].join(',')}`);
const hostileEcho = hostiles.map((answer) => answer.text).join(' ');
check('13f. the failed sign-in detail never echoes the configured credential',
  !hostileEcho.includes(CLUB_PASSWORD) && !hostileEcho.includes(CLUB_ACCOUNT_EMAIL),
  hostileEcho.slice(0, 160));
await hostile.close();

// ── the shipped shape: could this actually run where NodeSend runs? ─────────
const fs = require('node:fs');
const clubDir = path.join(ROOT, 'clubs');
const clubFiles = fs.readdirSync(clubDir).filter((name) => name.endsWith('.js')).sort();
const clubSource = clubFiles.map((name) => fs.readFileSync(path.join(clubDir, name), 'utf8')).join('\n');
const shippedText = clubSource
  + fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8')
  + fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
check('14a. no browser-visible name for a club secret appears anywhere in the shipped text',
  !new RegExp(`VITE_[A-Z_]*${'NCB'}`, 'i').test(shippedText),
  (shippedText.match(new RegExp(`VITE_[A-Z_]*${'NCB'}[A-Z_]*`, 'gi')) ?? []).join(','));
// Tested on CODE, not on prose: these files explain in comments why an MCP secret_key must never
// appear, so a plain substring scan would flag the very documentation that forbids it. Stripping
// comments leaves the accessor and string-literal forms, which is the claim actually being made.
const clubCode = clubSource.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
check('14b. no club module reaches for an MCP secret_key or a database credential in code',
  !/\.\s*secret_key\b|\[['"]secret_key['"]\]|DATABASE_URL/.test(clubCode),
  (clubCode.match(/\.\s*secret_key|DATABASE_URL/gi) ?? []).slice(0, 3).join(','));
check('14c. every club module is CommonJS, because the relay is loaded with require()',
  clubFiles.every((name) => !/^\s*(import|export)\s/m.test(fs.readFileSync(path.join(clubDir, name), 'utf8')))
  && clubFiles.length === 6,
  clubFiles.join(','));
// NodeSend's image copies named files, not the whole WORKDIR. A module the Dockerfile forgets
// builds green and dies at container start, which is the worst time to discover an integration.
const dockerfile = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');
check('14d. the Dockerfile ships the clubs directory the relay requires at startup',
  /COPY\s+clubs\/?\s+\.\/clubs\/?/.test(dockerfile),
  dockerfile.split(/\r?\n/).filter((line) => line.startsWith('COPY')).join(' | '));
// A real child boot, in the harness's own configured environment: the claim being tested is that
// adding the club mount did not make the relay fail to start.
const liveStartup = spawnSync(process.execPath, [path.join(ROOT, 'bridge.js')], {
  env: { ...process.env, PORT: '0', BRIDGE_API_KEY: 'x' }, cwd: ROOT, encoding: 'utf8', timeout: 6000
});
const bootLine = `${liveStartup.stdout ?? ''}${liveStartup.stderr ?? ''}`;
check('14e. the relay still boots with Clubs mounted, and prints its club state',
  /club storage/i.test(bootLine) && !/Cannot find module|SyntaxError|ReferenceError/i.test(bootLine),
  bootLine.slice(0, 200));

// ── teardown and verdict ────────────────────────────────────────────────────
await new Promise((resolve) => server.close(resolve));
globalThis.fetch = realFetch;

const failed = results.filter((row) => !row.pass);
for (const row of results) {
  console.log(`${row.pass ? 'PASS' : 'FAIL'}  ${row.name}${row.detail ? `   [${row.detail}]` : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed.length} passed, ${failed.length} failed`);
if (failed.length) {
  console.log('NEW FAILURES:');
  for (const row of failed) console.log(`  - ${row.name} ${row.detail}`);
}
process.exit(failed.length ? 1 : 0);
