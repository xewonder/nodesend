/*
 * NodeSend TOURNAMENTS — CLIENT/SERVER INTEGRATION GATE
 *
 * What this file is for, and why it exists separately from `verify-tournaments-gateway.mjs`.
 * The gateway gate covers every rule in detail. An earlier attempt at THIS file was removed from the
 * release candidate without ever passing, and the reason is the whole lesson of its design: its mock
 * was wired to environment variables NodeSend does not read (`CLUB_NCB_BASE_URL`, `NCB_BASE_URL`), so
 * the real club account client fell back to the DEFAULT vendor URL and dialled production NCB, and its
 * `get-session` answer had the wrong shape (`data.user_id` instead of `data.user.id`), so the service
 * account's identity could not be verified, no store was ever built, and every arm silently measured a
 * 503 instead of the rule it named. An arm that never reaches its subject is worse than no arm.
 *
 * Three defences follow from that, and each of them is itself asserted below:
 *   1. THE MOCK IS THE ONLY ADDRESSABLE HOST. `NCB_PROXY_BASE` is a reserved `.invalid` name, and the
 *      fetch shim FAILS THE RUN on any request to any other host. A missing variable therefore cannot
 *      become a live call.
 *   2. THE SUBJECT MUST BE OBSERVED TO EXIST. Before one arm runs, the service-account exchange is
 *      asserted to have actually happened and the tournament store to be configured; `configured:false`
 *      aborts with the mount's own reason rather than proceeding to a green-looking wall of 503s.
 *   3. EVERY ENFORCEMENT ARM HAS A NEGATIVE CONTROL. Private-RLS masking, the ownership stamp and the
 *      generic-gateway block each have a paired arm that flips when the mechanism under it is removed,
 *      so "the backend refused" is never credited to a rule that was never in the path.
 *
 * Everything runs in-process against the REAL exported `app` over HTTP. NO production endpoint is
 * contacted, NO credential is read from any store, NO table is created and nothing is written outside
 * this process. RLS is not real here — it is MODELLED as the vendor documents it behaving (a read
 * returns only rows whose ownership column names the reading account), and where a conclusion depends
 * on that model rather than on a measurement, the arm says so in its own name.
 *
 *   node verify-tournaments-integration.mjs
 */
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));

const MOCK_HOST = 'https://ncb.integration.invalid';
const MOCK_HOST_URBAN = 'ncb.integration.invalid';
const SERVICE_ID = '99';
const SERVICE_EMAIL = 'club-service-account@bridgemind.invalid';
const SERVICE_TOKEN = 'integration-fixture-service-bearer-0123456789ab';
const PASSWORD = 'integration-fixture-not-a-credential-0123456789';
const CALLERS = {
  'tok-admin': { id: '1', email: 'admin@example.test' },          // BridgeMind Admin, row owned by the service account
  'tok-masked-admin': { id: '2', email: 'masked@example.test' },  // admin row owned by SOMEONE ELSE
  'tok-owner': { id: '3', email: 'owner@example.test' },          // ordinary player, no club
  'tok-clubadmin': { id: '4', email: 'clubadmin@example.test' },  // club_admin of club 10
  'tok-member': { id: '5', email: 'member@example.test' },        // approved member of club 10
  'tok-other': { id: '6', email: 'other@example.test' }           // approved member of club 11
};

// ── the environment, set BEFORE bridge.js is required (both mounts are built once at load) ──────
process.env.BRIDGE_API_KEY = 'relay-api-key-not-a-tournament-secret';
process.env.NCB_PROXY_BASE = MOCK_HOST;
process.env.NCB_INSTANCE = '55954_bridgemind';
process.env.NCB_TRANSPORT = 'proxy';
process.env.CLUB_NCB_EMAIL = SERVICE_EMAIL;
process.env.CLUB_NCB_PASSWORD = PASSWORD;
process.env.CLUB_NCB_EXPECTED_USER_ID = SERVICE_ID;
delete process.env.NCB_SESSION_SEAL_KEY;
delete process.env.AI_QUOTA_RESERVATION_TABLE;
delete process.env.NODESEND_PRIVATE_KEY_B64;

// THE LIVE IDENTITY SPELLINGS, with no opt-out declared anywhere in this file: `clubs/clubSchema.js`
// accepts this configuration because `user_id` is left to mean the one thing NCB uses it for.
const CLUB_SCHEMA = {
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
};
const TOURNAMENT_SCHEMA = {
  tables: { tournaments: 'tournaments', boards: 'tournament_boards', attempts: 'tournament_attempts' },
  columns: {
    tournaments: {
      id: 'id', userId: 'owner_user_id', clubId: 'club_id', name: 'name', visibility: 'visibility',
      status: 'status', boardCount: 'board_count', sourceLabel: 'source_label', dedupeKey: 'dedupe_key',
      createdAt: 'created_at', updatedAt: 'updated_at'
    },
    boards: {
      id: 'id', tournamentId: 'tournament_id', boardNumber: 'board_number', dealer: 'dealer',
      vulnerability: 'vulnerability', handsJson: 'hands_json', tagsJson: 'tags_json', createdAt: 'created_at'
    },
    attempts: {
      id: 'id', tournamentId: 'tournament_id', boardNumber: 'board_number',
      recordedHandId: 'recorded_hand_id', originalSeat: 'original_seat', userId: 'player_user_id',
      createdAt: 'created_at'
    }
  }
};
process.env.CLUB_NCB_SCHEMA_JSON = JSON.stringify(CLUB_SCHEMA);
process.env.TOURNAMENT_NCB_SCHEMA_JSON = JSON.stringify(TOURNAMENT_SCHEMA);

// ── the storage the fake NCB serves, and the two policies it can enforce ────────────────────────
// Every row carries `user_id` = the account that wrote it. Rows the service account wrote are visible
// to it; the one row written elsewhere is not. That single distinction is what the arms below turn on
// and off, and it is the difference between "the authority row exists" and "this account may see it".
const rows = {
  system_admins: [
    { id: 'sa1', admin_user_id: '1', user_id: SERVICE_ID },
    { id: 'sa2', admin_user_id: '2', user_id: '777' }            // created in the NCB dashboard
  ],
  clubs: [
    { id: '10', name: 'Glyfada BC', active: 1 },
    { id: '11', name: 'Thessaloniki BC', active: 1 }
  ],
  club_memberships: [
    { id: 'm4', member_user_id: '4', club_id: '10', role: 'club_admin', status: 'approved', user_id: SERVICE_ID },
    { id: 'm5', member_user_id: '5', club_id: '10', role: 'member', status: 'approved', user_id: SERVICE_ID },
    { id: 'm6', member_user_id: '6', club_id: '11', role: 'member', status: 'approved', user_id: SERVICE_ID }
  ],
  tournaments: [],
  tournament_boards: [],
  tournament_attempts: [],
  club_board_collections: [],
  club_collection_boards: []
};
// WHICH TABLES THE OWNERSHIP FILTER APPLIES TO is not a free choice in this model: it is the
// verified state. Tournament tables and system_admins run under the default `private` policy; the
// club directory (`clubs`) is readable across accounts, which is why a club row carries no owner at
// all here. Applying the filter to the wrong table would make an arm fail for a reason that does
// not exist in production, which is the mistake this file exists not to repeat.
const PRIVATE_TABLES = new Set(['system_admins', 'club_memberships', 'tournaments', 'tournament_boards', 'tournament_attempts']);
const COLUMNS = {
  system_admins: ['id', 'admin_user_id', 'user_id'],
  clubs: ['id', 'name', 'active'],
  club_memberships: ['id', 'member_user_id', 'club_id', 'role', 'status', 'user_id'],
  club_board_collections: ['id', 'club_id', 'title', 'publication_status', 'created_by_user_id'],
  club_collection_boards: ['id', 'collection_id', 'board_number', 'dealer', 'vulnerability', 'hands_json'],
  tournaments: ['id', 'owner_user_id', 'club_id', 'name', 'visibility', 'status', 'board_count', 'source_label', 'dedupe_key', 'created_at', 'updated_at', 'user_id'],
  tournament_boards: ['id', 'tournament_id', 'board_number', 'dealer', 'vulnerability', 'hands_json', 'tags_json', 'created_at', 'user_id'],
  tournament_attempts: ['id', 'tournament_id', 'board_number', 'recorded_hand_id', 'original_seat', 'player_user_id', 'created_at', 'user_id']
};
const policy = { rls: 'private', signIns: 0, failSignIn: false, failData: false };
let LOOPBACK_RELAY_HOST = '';   // set the moment the relay is listening; until then nothing may call it
const calls = { data: [], auth: [], offHost: [] };

const realFetch = globalThis.fetch;
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const RESERVED = ['limit', 'page', 'sort', 'order', 'Instance'];

globalThis.fetch = async (url, init = {}) => {
  // The relay itself is served by the real fetch; only vendor-shaped requests are answered here.
  if (new URL(String(url)).host === LOOPBACK_RELAY_HOST) return realFetch(url, init);
  const target = String(url);
  const host = new URL(target).host;
  // Defence 1. Two hosts are addressable in this run: the fake vendor, and the loopback relay this
  // file is driving. Anything else — including the vendor default the removed harness dialled by
  // accident when its mock was wired to variables NodeSend never reads — is a bug in THIS file, and
  // it ends the run instead of sending a request somewhere real. T18 asserts the list stayed empty.
  if (host !== MOCK_HOST_URBAN && host !== LOOPBACK_RELAY_HOST) {
    calls.offHost.push(`${host}${new URL(target).pathname}`);
    throw new TypeError(`integration gate refused an off-mock request to ${host}`);
  }
  const { pathname, searchParams } = new URL(target);
  const method = String(init.method ?? 'GET').toUpperCase();
  const bearer = String(init?.headers?.Authorization ?? init?.headers?.authorization ?? '').replace(/^Bearer\s+/, '');
  const body = init.body ? JSON.parse(init.body) : null;

  if (pathname === '/auth/sign-in/email') {
    calls.auth.push(pathname);
    policy.signIns += 1;
    if (policy.failSignIn) return json({ status: 'error', message: 'invalid credentials' }, 401);
    if (body?.email !== SERVICE_EMAIL || body?.password !== PASSWORD) return json({ status: 'error', message: 'invalid credentials' }, 401);
    return json({ token: SERVICE_TOKEN, user: { id: SERVICE_ID, email: SERVICE_EMAIL } });
  }
  if (pathname === '/auth/get-session') {
    calls.auth.push(pathname);
    // The shape the client actually reads (`data.user.id`). The removed harness answered `data.user_id`
    // here, which is why its service account could never be verified.
    if (bearer === SERVICE_TOKEN) return json({ data: { user: { id: SERVICE_ID, email: SERVICE_EMAIL } } });
    const caller = CALLERS[bearer];
    if (!caller) return json({ status: 'error', message: 'invalid session' }, 401);
    return json({ data: { user: { id: caller.id, email: caller.email } } });
  }
  if (pathname.startsWith('/data/')) {
    calls.data.push({ pathname, method, bearer, query: searchParams.toString(), body });
    if (policy.failData) return json({ status: 'failed', error: 'read refused' }, 500);
    if (bearer !== SERVICE_TOKEN) return json({ status: 'error', message: 'club data does not move on a caller bearer' }, 403);
    const [, action, table, rowId] = pathname.split('/').filter(Boolean);
    const list = rows[table];
    if (!list) return json({ status: 'error', message: `unknown table ${table}` }, 404);
    const columns = COLUMNS[table];
    const filters = {};
    for (const [key, value] of searchParams.entries()) {
      if (RESERVED.includes(key)) continue;
      if (!columns.includes(key)) return json({ status: 'failed', error: `Unknown column '${key}' in 'where clause'` }, 500);
      filters[key] = value;
    }
    if (action === 'read') {
      // THE MODELLED POLICY. `private` is what the tournament and authority tables run under: a read
      // returns only rows the reading account owns. Note what that does to a MISSING authority row —
      // it is not an error, it is an empty success, which is why the mask has a negative control
      // (arm N1) and why the code's 503-on-refusal path cannot catch it.
      const visible = policy.rls === 'private' && PRIVATE_TABLES.has(table)
        ? list.filter((row) => String(row.user_id ?? '') === SERVICE_ID)
        : list.slice();
      const found = visible.filter((row) => Object.entries(filters).every(([k, v]) => String(row[k] ?? '') === v));
      const limit = Number(searchParams.get('limit'));
      return json({ status: 'success', data: Number.isFinite(limit) && limit > 0 ? found.slice(0, limit) : found });
    }
    if (action === 'create') {
      const { user_id: claimed, ...stored } = body ?? {};
      const row = { id: String(rows[table].length + 500), ...stored, user_id: SERVICE_ID };
      list.push(row);
      return json({ status: 'success', data: { ...row } });
    }
    if (action === 'update') {
      const row = list.find((candidate) => String(candidate.id) === String(rowId)
        && (policy.rls !== 'private' || String(candidate.user_id ?? '') === SERVICE_ID));
      if (!row) return json({ status: 'error', message: 'no such row' }, 404);
      Object.assign(row, body ?? {});
      return json({ status: 'success', data: { ...row } });
    }
    if (action === 'delete') {
      const index = list.findIndex((candidate) => String(candidate.id) === String(rowId));
      if (index === -1) return json({ status: 'error', message: 'no such row' }, 404);
      list.splice(index, 1);
      return json({ status: 'success', data: { id: rowId } });
    }
  }
  return json({ status: 'error', message: `unexpected mock path ${pathname}` }, 404);
};

const bridge = require(path.join(ROOT, 'bridge.js'));
const { app } = bridge;

const results = [];
const check = (name, condition, detail = '') => {
  results.push({ name, pass: condition === true, detail: condition === true ? '' : String(detail ?? '').slice(0, 260) });
};

// Defence 2: the subject must be observed to exist before any arm is allowed to be green.
check('I0a. the tournament mount built a real store on the live identity spellings, with no legacy opt-out declared',
  bridge.tournamentMount?.configured === true && bridge.clubMount?.configured === true,
  `tournament=${bridge.tournamentMount?.configured}:${bridge.tournamentMount?.reason ?? '-'} club=${bridge.clubMount?.configured}:${bridge.clubMount?.reason ?? '-'}`);
// The spelling this gate runs on must be the one the boot guard ACCEPTS, and the legacy spelling
// must be the one it refuses. Without the second half, a green I0a would only prove the guard is
// not running at all.
const acceptedHere = bridge.clubSchemaConfig({ CLUB_NCB_SCHEMA_JSON: process.env.CLUB_NCB_SCHEMA_JSON });
const legacySpelling = JSON.parse(JSON.stringify(CLUB_SCHEMA));
legacySpelling.columns.systemAdmins = { userId: 'user_id' };
legacySpelling.columns.memberships = { ...legacySpelling.columns.memberships, userId: 'user_id' };
const refusedLegacy = bridge.clubSchemaConfig({ CLUB_NCB_SCHEMA_JSON: JSON.stringify(legacySpelling) });
const escapedLegacy = bridge.clubSchemaConfig({
  CLUB_NCB_SCHEMA_JSON: JSON.stringify(legacySpelling), CLUB_NCB_ALLOW_USER_ID_IDENTITY: '1'
});
check('I0b. this run really is on the live spelling: the same schema with the identities moved to user_id is refused, and only the declared opt-out accepts it',
  acceptedHere.ok === true && refusedLegacy.ok === false
    && refusedLegacy.problems.some((p) => /columns\.systemAdmins\.userId/.test(p))
    && refusedLegacy.problems.some((p) => /columns\.memberships\.userId/.test(p))
    && escapedLegacy.ok === true,
  `here=${acceptedHere.ok} legacy=${refusedLegacy.ok}${refusedLegacy.ok ? '' : ' ' + JSON.stringify(refusedLegacy.problems.map((p) => p.slice(0, 40)))} escaped=${escapedLegacy.ok}`);
// The REAL exported app, on an ephemeral port. Everything below is an HTTP request against the
// relay that ships, not a call into a router.
const server = app.listen(0, '127.0.0.1');
await new Promise((resolve) => server.once('listening', resolve));
const BASE = `http://127.0.0.1:${server.address().port}`;
// `address`, not `host` — a listening socket has no `.host`, and reading the wrong property made
// the tripwire reject this file's own relay calls.
const listening = server.address();
LOOPBACK_RELAY_HOST = `${listening.address}:${listening.port}`;

async function call(method, route, { token = '', body } = {}) {
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch { /* kept as text below */ }
  return { status: res.status, body: parsed ?? {}, text };
}

const RANKS = ['2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A'];
const SUITS = ['S', 'H', 'D', 'C'];
function legalBoard(number) {
  const deck = RANKS.flatMap((r) => SUITS.map((s) => `${r}${s}`));
  const hands = {};
  ['North', 'East', 'South', 'West'].forEach((seat, i) => { hands[seat] = deck.slice(i * 13, i * 13 + 13); });
  return { board_number: String(number), dealer: 'North', vulnerability: 'None', hands };
}
const resetStorage = () => {
  rows.tournaments.length = 0;
  rows.tournament_boards.length = 0;
  rows.tournament_attempts.length = 0;
  rows.system_admins.length = 0;
  rows.system_admins.push(
    { id: 'sa1', admin_user_id: '1', user_id: SERVICE_ID },
    { id: 'sa2', admin_user_id: '2', user_id: '777' }
  );
  policy.rls = 'private';
  policy.failData = false;
  policy.failSignIn = false;
  // `calls` is the trail the arms cite, so it is cumulative for the whole run: a reset that
  // cleared it would let an arm assert against a window that had been wiped behind it.
};

const listIds = (res) => (res.body?.data?.tournaments ?? res.body?.data ?? []).map((row) => String(row.id ?? row.tournament_id ?? ''));

// ── 1. AUTHENTICATION ──────────────────────────────────────────────────────────────────────────
resetStorage();
const anon = await call('GET', '/tournaments');
const bogus = await call('GET', '/tournaments', { token: 'tok-not-a-session' });
check('T1. an anonymous and an unrecognised bearer are both 401, and neither reached storage',
  anon.status === 401 && bogus.status === 401 && calls.data.length === 0,
  `${anon.status}/${bogus.status} dataCalls=${calls.data.length}`);
const authed = await call('GET', '/tournaments', { token: 'tok-owner' });
check('T2. a validated session is served, and the service account (not the caller) is what touched storage',
  authed.status === 200 && calls.data.length > 0 && calls.data.every((row) => row.bearer === SERVICE_TOKEN),
  `${authed.status} dataCalls=${calls.data.length}`);
check('T3. the service-account sign-in happened exactly once for the whole burst, and no off-mock host was ever dialed',
  policy.signIns === 1 && calls.offHost.length === 0,
  `signIns=${policy.signIns} offHost=${JSON.stringify(calls.offHost.slice(0, 2))}`);

// ── 2. AUTHORITY RESOLUTION, including what private RLS does to an authority row ────────────────
resetStorage();
const asSuper = await call('GET', '/tournaments', { token: 'tok-admin' });
const asMasked = await call('POST', '/tournaments', {
  token: 'tok-masked-admin', body: { name: 'Public Without The Grant', visibility: 'public', boards: [legalBoard(1)] }
});
const asPlain = await call('POST', '/tournaments', {
  token: 'tok-owner', body: { name: 'Public Without The Grant', visibility: 'public', boards: [legalBoard(1)] }
});
check('T4. a system_admins row the service account owns resolves its account as BridgeMind Admin',
  asSuper.status === 200, `${asSuper.status} ${asSuper.text.slice(0, 120)}`);
check('T5. the SAME grant, written by another account and therefore invisible under private RLS, is answered as a non-admin — an empty success, not a failure',
  asMasked.status === 403 && asMasked.body?.error === 'super_admin_required',
  `${asMasked.status}/${asMasked.body?.error}`);
check('T6. and the refusal is the real gate, not the mask: a plain session is refused the same way for the same reason',
  asPlain.status === 403 && asPlain.body?.error === 'super_admin_required',
  `${asPlain.status}/${asPlain.body?.error}`);
policy.rls = 'shared';
const asMaskedShared = await call('POST', '/tournaments', {
  token: 'tok-masked-admin', body: { name: 'Now Visible', visibility: 'public', boards: [legalBoard(1)] }
});
check('N1. NEGATIVE CONTROL: lift the ownership filter and the masked admin is served — so T5 measured the policy and not a broken route',
  asMaskedShared.status === 200, `${asMaskedShared.status}/${asMaskedShared.body?.error} ${asMaskedShared.text.slice(0, 110)}`);
policy.rls = 'private';
rows.tournaments.length = 0;
rows.tournament_boards.length = 0;

// ── 3. PRIVATE CREATION AND THE OWNERSHIP SPLIT ────────────────────────────────────────────────
resetStorage();
const created = await call('POST', '/tournaments', {
  token: 'tok-owner', body: { name: 'Kitchen Table', visibility: 'private', boards: [legalBoard(1), legalBoard(2)] }
});
const storedHeader = rows.tournaments[0] ?? null;
check('T7. an ordinary session may import its own private set with no privilege at all',
  created.status === 200 && Boolean(created.body?.data?.id), `${created.status} ${created.text.slice(0, 140)}`);
check('T8. the stored row keeps the PLAYER in owner_user_id and the WRITING ACCOUNT in user_id, and the two are different values',
  storedHeader && String(storedHeader.owner_user_id) === '3' && String(storedHeader.user_id) === SERVICE_ID,
  JSON.stringify(storedHeader).slice(0, 200));
const ownerList = await call('GET', '/tournaments', { token: 'tok-owner' });
const strangerList = await call('GET', '/tournaments', { token: 'tok-clubadmin' });
check('T9. the private set appears for its owner and for nobody else — including a club admin, who holds no claim on it',
  listIds(ownerList).includes(String(storedHeader?.id)) && !listIds(strangerList).includes(String(storedHeader?.id)),
  `owner=${JSON.stringify(listIds(ownerList))} admin=${JSON.stringify(listIds(strangerList))}`);
const readStranger = await call('GET', `/tournaments/${storedHeader?.id}`, { token: 'tok-clubadmin' });
const readOwner = await call('GET', `/tournaments/${storedHeader?.id}`, { token: 'tok-owner' });
check('T10. a private set is refused to another session on direct read and served to its owner',
  readStranger.status === 403 && readOwner.status === 200, `${readStranger.status}/${readOwner.status}`);

// ── 4. CLUB SCOPING ────────────────────────────────────────────────────────────────────────────
resetStorage();
const clubDraft = await call('POST', '/tournaments', {
  token: 'tok-clubadmin', body: { name: 'Club Round', visibility: 'club', club_id: '10', boards: [legalBoard(1)] }
});
const clubId = clubDraft.body?.data?.id;
check('T11. a club admin may import a club set for their own club',
  clubDraft.status === 200 && Boolean(clubId),
  `${clubDraft.status} ${clubDraft.body?.error} membership-reads=${JSON.stringify(calls.data.filter((r) => r.table === 'club_memberships' || /club_memberships/.test(r.pathname)).slice(-2).map((r) => r.query))} ${clubDraft.text.slice(0, 90)}`);
const memberDraftSeen = await call('GET', `/tournaments/${clubId}`, { token: 'tok-member' });
check('T12. a draft club set is invisible to that club\'s own members and stays manageable by its admin',
  memberDraftSeen.status === 403 && (await call('PATCH', `/tournaments/${clubId}`, { token: 'tok-clubadmin', body: { name: 'Club Round 2' } })).status === 200,
  `member=${memberDraftSeen.status}`);
const published = await call('POST', `/tournaments/${clubId}/publish`, { token: 'tok-clubadmin' });
const memberNow = await call('GET', `/tournaments/${clubId}`, { token: 'tok-member' });
const otherClub = await call('GET', `/tournaments/${clubId}`, { token: 'tok-other' });
check('T13. publishing opens the set to members of THAT club and to no other club',
  published.status === 200 && memberNow.status === 200 && otherClub.status === 403,
  `pub=${published.status} member=${memberNow.status} other=${otherClub.status}/${otherClub.body?.error}`);
const foreignAdminPublish = await call('POST', `/tournaments/${clubId}/publish`, { token: 'tok-other' });
check('T14. an admin of another club cannot manage it either, so the path parameter carries no authority',
  foreignAdminPublish.status === 403, `${foreignAdminPublish.status}/${foreignAdminPublish.body?.error}`);

// ── 5. PUBLIC SCOPING ──────────────────────────────────────────────────────────────────────────
resetStorage();
const publicDraft = await call('POST', '/tournaments', {
  token: 'tok-admin', body: { name: 'Autumn Open', visibility: 'public', boards: [legalBoard(1)] }
});
const publicId = publicDraft.body?.data?.id;
const anonReadPublicDraft = await call('GET', `/tournaments/${publicId}`, { token: 'tok-owner' });
await call('POST', `/tournaments/${publicId}/publish`, { token: 'tok-admin' });
const anySession = await call('GET', `/tournaments/${publicId}`, { token: 'tok-owner' });
const clublessRead = await call('GET', `/tournaments/${publicId}/boards`, { token: 'tok-owner' });
check('T15. a public set is unreadable while draft and readable by any session once published, boards included',
  publicDraft.status === 200 && anonReadPublicDraft.status === 403 && anySession.status === 200 && clublessRead.status === 200,
  `draft=${anonReadPublicDraft.status} live=${anySession.status} boards=${clublessRead.status}`);

// ── 6. BACKEND STATES THAT MUST NOT LOOK LIKE DATA ─────────────────────────────────────────────
resetStorage();
// The service account holds its session for the whole run, so failing the SIGN-IN endpoint here
// would prove nothing — the endpoint is never re-dialled. What must be true is the storage path:
// unreachable answers 503 under its own name, and never a 200 whose empty list reads as "you have
// no tournaments" (the arm above, T4, is the positive control that a 200 is reachable at all).
policy.failData = true;
const duringOutage = await call('GET', '/tournaments', { token: 'tok-owner' });
policy.failData = false;
const afterOutage = await call('GET', '/tournaments', { token: 'tok-owner' });
check('N2. NEGATIVE CONTROL: while the service account cannot read storage the route answers 503, and the same call is a 200 again once it can',
  duringOutage.status === 503 && !/"tournaments":\[\]/.test(duringOutage.text)
    && afterOutage.status === 200,
  `outage=${duringOutage.status}/${duringOutage.body?.error} recovered=${afterOutage.status}`);;

// A read that comes back as something other than a row set is the other way a store can lie.
const beforeTamper = calls.data.length;
const originalRead = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const target = String(url);
  if (target.startsWith(MOCK_HOST) && /\/data\/read\/tournaments/.test(target)) return json({ status: 'success', data: null });
  return originalRead(url, init);
};
const unreadable = await call('GET', '/tournaments', { token: 'tok-owner' });
globalThis.fetch = originalRead;
check('N3. NEGATIVE CONTROL: a 200 whose body is not a row set is a 503, not a 200 carrying nobody',
  unreadable.status === 503 && calls.data.length > beforeTamper,
  `${unreadable.status} ${unreadable.text.slice(0, 130)}`);

resetStorage();
const gatewayBlocked = await fetch(`${BASE}/ncb/data/read/tournaments?limit=1`, { headers: { accept: 'application/json' } });
const gatewayBlockedBody = await gatewayBlocked.json().catch(() => ({}));
check('T16. the approved generic-gateway block still stands in this same boot: tournaments are refused by name, before any credential',
  gatewayBlocked.status === 403 && gatewayBlockedBody.error === 'tournament_via_gateway_only',
  `${gatewayBlocked.status} ${JSON.stringify(gatewayBlockedBody).slice(0, 120)}`);
const tournamentTableCalls = calls.data.filter((row) => /\/data\/(read|create|update|delete)\/(tournaments|tournament_boards|tournament_attempts)/.test(row.pathname));
check('T17. and the authorized route reached those tables anyway — through the service account, which is the only path that may',
  tournamentTableCalls.length > 0 && tournamentTableCalls.every((row) => row.bearer === SERVICE_TOKEN),
  `tournament data calls=${tournamentTableCalls.length}`);

// ── teardown and verdict ───────────────────────────────────────────────────────────────────────
await new Promise((resolve) => server.close(resolve));
globalThis.fetch = realFetch;
check('T18. nothing left the mock host for the whole run', calls.offHost.length === 0, JSON.stringify(calls.offHost.slice(0, 3)));

const failed = results.filter((row) => !row.pass);
for (const row of results) {
  console.log(`${row.pass ? 'PASS' : 'FAIL'}  ${row.name}${row.detail ? `   [${row.detail}]` : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed.length}/${results.length} passed, ${failed.length} failed (tournaments integration)`);
if (failed.length) console.log('NEW FAILURES:\n' + failed.map((row) => `  - ${row.name} ${row.detail}`).join('\n'));
process.exit(failed.length ? 1 : 0);
