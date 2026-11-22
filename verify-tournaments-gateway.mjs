// NodeSend TOURNAMENTS verification harness.
//
// Everything runs in-process: a loopback mock of the NCB proxy (the caller's session lookup, the
// dedicated service account's sign-in, and the three tournament tables plus the club authority tables)
// behind global.fetch, and a scripted fake client for the storage arms that need an exact call sequence.
// NO production endpoint is contacted, NO tournament table is created, and nothing is written outside
// this process. The relay under test is the REAL exported `app` served over HTTP, so a pass is a claim
// about the code that ships rather than about a copy of it.
//
// WHY THE AUTHORITY ARMS GO OVER HTTP. A permission function that is correct in isolation still means
// nothing if the guard is not attached to the route, if the route order lets a parameter swallow a
// literal, or if the envelope maps a refusal to a 200. Only a request proves all three.
//
// WHY THE RULES ARE ALSO CALLED DIRECTLY. `resolveTournamentAccess` and friends are NodeSend's copies of
// the predicates in BridgeMind-Greta's frozen `src/services/tournamentContracts.js`. Section 12 extracts
// the contract file's own function bodies, evaluates them here, and compares truth tables over an
// exhaustive input matrix — so "the two repos agree" is measured, not asserted. That arm goes RED when
// the contract file is missing, because an unmeasured claim is not a pass.
//
// NO ARM IN THIS FILE IS CAPABLE OF PASSING WITHOUT ITS SUBJECT. 14f scans this file's own source and
// fails on a `check(label, true, …)` constant, and every refusal arm names the reason it expects rather
// than accepting "not 200".
//
//   node verify-tournaments-gateway.mjs
import { createRequire } from 'node:module';
import path from 'node:path';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));

// ── the cast ────────────────────────────────────────────────────────────────
// Each identity is a DISTINCT PERSON with a distinct club fact, because every interesting denial here is
// a question about who is asking, not about what they asked for.
// The dedicated account's address is a FIXTURE on a reserved TLD, not the real one: this repo is public,
// and naming the live service account tells an attacker exactly which identity to aim at. `.invalid` can
// never resolve, so the mock below cannot be mistaken for a real endpoint either.
const CLUB_ACCOUNT_ID = '99';
const CLUB_ACCOUNT_EMAIL = 'tournament-service-account@bridgemind.invalid';
// Self-labelling: the leak arms search every response body for this string, so it must never be a
// credential that exists anywhere.
const CLUB_PASSWORD = 'gate-fixture-not-a-credential-0123456789';
const CLUB_SESSION_TOKEN = 'gate-fixture-club-bearer-0123456789ab';
const SUPER_TOKEN = 'tok-super';

const SESSIONS = {
  [SUPER_TOKEN]: { id: '1', role: 'administrator' },  // in system_admins → the BridgeMind Admin
  'tok-admin10': { id: '2', role: 'user' },           // club_admin of 10, approved
  'tok-member10': { id: '3', role: 'user' },          // member of 10, approved
  'tok-member11': { id: '4', role: 'user' },          // member of 11, approved
  'tok-noclub': { id: '5', role: 'user' },            // one club OR none: this one has none
  'tok-impersonator': { id: '6', role: 'administrator' }, // NCB role, NOT in system_admins
  'tok-admin11': { id: '7', role: 'user' },           // club_admin of 11, approved
  'tok-pending10': { id: '20', role: 'user' },        // requested club 10, not approved
  'tok-inactive12': { id: '24', role: 'user' },       // approved member of the INACTIVE club 12
  'tok-session-down': { id: '31', role: 'user' }      // the mock throws for this one
};

// ── the environment the REAL relay boots with ───────────────────────────────
// Set before bridge.js is required, because the tournament mount is built once at module load.
process.env.BRIDGE_API_KEY = 'relay-api-key-not-a-tournament-secret';
process.env.NCB_PROXY_BASE = 'https://ncb.test.invalid';
process.env.NCB_INSTANCE = '55954_bridgemind';
process.env.CLUB_NCB_EMAIL = CLUB_ACCOUNT_EMAIL;
process.env.CLUB_NCB_PASSWORD = CLUB_PASSWORD;
process.env.CLUB_NCB_EXPECTED_USER_ID = CLUB_ACCOUNT_ID;
// The club five-table schema, spelled as .env.example documents it. Tournaments DEPENDS on it: the club
// and super-admin facts are the club store's authority to answer, and this feature re-derives neither.
process.env.CLUB_NCB_SCHEMA_JSON = JSON.stringify({
  tables: {
    systemAdmins: 'system_admins',
    clubs: 'clubs',
    memberships: 'club_memberships',
    collections: 'club_board_collections',
    boards: 'club_collection_boards'
  },
  columns: {
    // The LIVE identity columns, per the owner's NCB MCP schema verification of 2026-11-22.
    // `user_id` is deliberately NOT among them: on this vendor it is the row-ownership slot NCB
    // stamps from the WRITING session, and the mock stamps it with the service account's id, so a
    // store that read it as the person's identity gets the answer it would get in production.
    systemAdmins: { userId: 'admin_user_id' },
    clubs: { id: 'id', name: 'name', status: 'active' },
    memberships: { id: 'id', userId: 'member_user_id', clubId: 'club_id', role: 'role', status: 'status' },
    collections: { id: 'id', clubId: 'club_id', name: 'title', status: 'publication_status', createdBy: 'created_by_user_id' },
    boards: { id: 'id', collectionId: 'collection_id', boardNumber: 'board_number', dealer: 'dealer', vulnerability: 'vulnerability', handsJson: 'hands_json' }
  },
  values: { clubs: { status: { active: 1, inactive: 0 } } }
});
// THE AGREED THREE-TABLE TOURNAMENT SCHEMA, with the live column names the migration ask documents.
const MAIN_TOURNAMENT_SCHEMA = {
  tables: {
    tournaments: 'tournaments',
    boards: 'tournament_boards',
    attempts: 'tournament_attempts'
  },
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
process.env.TOURNAMENT_NCB_SCHEMA_JSON = JSON.stringify(MAIN_TOURNAMENT_SCHEMA);
delete process.env.TOURNAMENT_NCB_SCHEMA_FILE;
delete process.env.AI_QUOTA_RESERVATION_TABLE;
delete process.env.NODESEND_PRIVATE_KEY_B64;

const bridge = require(path.join(ROOT, 'bridge.js'));
const { app, buildTournamentMount, tournamentRoutes, tournamentBodyFields, tournamentMount,
  tournamentAccessRule, tournamentListScopeRule, tournamentCreateRule, tournamentVisibilityRule,
  tournamentAuthorize, tournamentValidateShape, tournamentValidateInput, tournamentStoreErrorStatus,
  tournamentSchemaConfig, createTournamentNcbStore, ncbGatewayTables, ncbGatewayClubTables } = bridge;
const gatewayModule = require(path.join(ROOT, 'ncb/gateway.js'));
const express = require('express');

// ── the table registry the mock serves ──────────────────────────────────────
// Column lists are declared per table so the mock can enforce the LIVE read grammar: every query name
// that is not `limit`/`page`/`sort`/`order`/`Instance` is a COLUMN FILTER, and an unknown one fails the
// whole read with HTTP 500. That is what makes this harness able to catch a store that invents a filter
// (`?offset=`, `?search=`) instead of silently returning nothing.
const REGISTRY = {
  // `admin_user_id` is the grant. The ownership column is stamped on the way out, never stored here,
  // which is the live shape: nullable, and holding whoever wrote the row.
  system_admins: { columns: ['id', 'admin_user_id', 'user_id'], rows: [{ id: 'sa1', admin_user_id: '1' }], uniques: [] },
  clubs: {
    columns: ['id', 'name', 'active'],
    rows: [
      { id: '10', name: 'Glyfada BC', active: 1 },
      { id: '11', name: 'Thessaloniki BC', active: 1 },
      { id: '12', name: 'Piraeus CC', active: 0 }
    ],
    uniques: []
  },
  club_memberships: {
    columns: ['id', 'member_user_id', 'club_id', 'role', 'status', 'user_id'],
    rows: [
      { id: 'm2', member_user_id: '2', club_id: '10', role: 'club_admin', status: 'approved' },
      { id: 'm3', member_user_id: '3', club_id: '10', role: 'member', status: 'approved' },
      { id: 'm4', member_user_id: '4', club_id: '11', role: 'member', status: 'approved' },
      { id: 'm7', member_user_id: '7', club_id: '11', role: 'club_admin', status: 'approved' },
      // A pending request for club 10 by the SAME person who owns private set `p3`'s neighbour. If a
      // pending row ever counted, the club-10 arms below change answer for this id — and it is checked
      // directly in 5i.
      { id: 'm8', member_user_id: '20', club_id: '10', role: 'club_admin', status: 'pending' },
      // Approved, but of the INACTIVE club 12: the state that must behave exactly like no club.
      { id: 'm9', member_user_id: '24', club_id: '12', role: 'member', status: 'approved' }
    ],
    uniques: [{ fields: ['member_user_id'], name: 'member_user_id' }]
  },
  club_board_collections: { columns: ['id', 'club_id', 'title', 'publication_status', 'created_by_user_id'], rows: [], uniques: [] },
  club_collection_boards: { columns: ['id', 'collection_id', 'board_number', 'dealer', 'vulnerability', 'hands_json'], rows: [], uniques: [] },

  tournaments: {
    columns: ['id', 'owner_user_id', 'club_id', 'name', 'visibility', 'status', 'board_count', 'source_label', 'dedupe_key', 'created_at', 'updated_at'],
    rows: [
      // A PRIVATE published set owned by a club-10 member. The super admin must not see it (T1).
      { id: 'p3', owner_user_id: '3', club_id: null, name: 'Kitchen Table Sets', visibility: 'private', status: 'published', board_count: 2, source_label: 'hand-pbn', dedupe_key: null },
      // A private set owned by a user who IS a club admin — the only importer from whom a move INTO the
      // club category is a legal write, which is what makes 15c able to fail. It is a DRAFT so 15n
      // measures the claim it makes: a set promoted into the club is not thereby released to its members.
      { id: 'p2', owner_user_id: '2', club_id: null, name: 'Admins Own Private', visibility: 'private', status: 'draft', board_count: 1, source_label: null, dedupe_key: null },
      // A PRIVATE draft owned by a club-11 member, for the "status and visibility are orthogonal" arms.
      { id: 'p4', owner_user_id: '4', club_id: null, name: 'Sunday Scratch', visibility: 'private', status: 'draft', board_count: 1, source_label: null, dedupe_key: 'p4-key' },
      // CLUB 10, published and draft. The draft is readable by club 10's ADMIN and invisible to its
      // MEMBERS — the two halves of T2 measured separately.
      { id: 'c10p', owner_user_id: '2', club_id: '10', name: 'Glyfada Round 1', visibility: 'club', status: 'published', board_count: 3, source_label: 'mfpp', dedupe_key: 'c10p-key' },
      { id: 'c10d', owner_user_id: '2', club_id: '10', name: 'Glyfada Round 2', visibility: 'club', status: 'draft', board_count: 2, source_label: null, dedupe_key: null },
      // Another club's published set, for the cross-club arms.
      { id: 'c11p', owner_user_id: '7', club_id: '11', name: 'Thessaloniki Round 1', visibility: 'club', status: 'published', board_count: 1, source_label: null, dedupe_key: null },
      // An INACTIVE club's published set: nobody may play it, because its members' rows collapse.
      { id: 'c12x', owner_user_id: '2', club_id: '12', name: 'Piraeus Frozen', visibility: 'club', status: 'published', board_count: 1, source_label: null, dedupe_key: null },
      // PUBLIC, both statuses. Management is the BridgeMind Admin's alone (T3).
      { id: 'pubp', owner_user_id: '1', club_id: null, name: 'Autumn Open', visibility: 'public', status: 'published', board_count: 2, source_label: null, dedupe_key: null },
      { id: 'pubd', owner_user_id: '1', club_id: null, name: 'Autumn Trial', visibility: 'public', status: 'draft', board_count: 1, source_label: null, dedupe_key: null },
      // A club-visible row whose club_id is empty: `club_required`, the state no import can produce but a
      // hand-edited row can.
      { id: 'orphan', owner_user_id: '2', club_id: null, name: 'Homeless Club Set', visibility: 'club', status: 'published', board_count: 1, source_label: null, dedupe_key: null },
      // A row whose category is outside the vocabulary. The rule must refuse it, not guess.
      { id: 'badv', owner_user_id: '3', club_id: null, name: 'Corrupt Category', visibility: 'legacy', status: 'published', board_count: 1, source_label: null, dedupe_key: null },
      // A row whose owner column is EMPTY. Reported as a store problem, never as "nobody owns it so
      // nobody may see it" — which would look like an ordinary 404.
      { id: 'noowner', owner_user_id: null, club_id: null, name: 'Ownerless', visibility: 'private', status: 'published', board_count: 1, source_label: null, dedupe_key: null }
    ],
    // UNIQUE(dedupe_key) is the duplicate-import guard. Enforced here the way MySQL would: in prose, on
    // insert, and only against a NON-NULL value — two NULLs never collide, which is why the store omits
    // the column instead of sending an empty string.
    uniques: [{ fields: ['dedupe_key'], name: 'dedupe_key', ignoreNull: true }]
  },
  tournament_boards: {
    columns: ['id', 'tournament_id', 'board_number', 'dealer', 'vulnerability', 'hands_json', 'tags_json', 'created_at'],
    rows: [],
    // THE COMPOSITE UNIQUE. Two single-column uniques here is the live `club_collection_boards` defect;
    // the mock enforces the PAIR, so an arm that re-uses board number 1 in a second tournament passes
    // for the right reason and an arm that repeats it inside one tournament is refused.
    uniques: [{ fields: ['tournament_id', 'board_number'], name: 'tournament_id_board_number', composite: true }]
  },
  tournament_attempts: {
    columns: ['id', 'tournament_id', 'board_number', 'recorded_hand_id', 'original_seat', 'player_user_id', 'created_at'],
    rows: [],
    uniques: [{ fields: ['recorded_hand_id'], name: 'recorded_hand_id', ignoreNull: true }]
  },

  // The ALTERNATELY SPELLED tables, for 2k: a mount configured with different column and table names must
  // read and write THOSE, which is what proves the store is schema-driven rather than hard-coded.
  tm_tournaments: {
    columns: ['id', 'owner_col', 'team_col', 'title', 'category', 'publication_status', 'n_boards', 'origin', 'dup_key'],
    rows: [{ id: 'alt1', owner_col: '3', team_col: null, title: 'Alt Named Set', category: 'private', publication_status: 'published', n_boards: 1, origin: null, dup_key: null }],
    uniques: [{ fields: ['dup_key'], name: 'dup_key', ignoreNull: true }]
  },
  tm_boards: {
    columns: ['id', 'owner_tournament', 'board_no', 'dealer', 'vulnerability', 'hands_json'],
    rows: [],
    uniques: [{ fields: ['owner_tournament', 'board_no'], name: 'owner_tournament_board_no', composite: true }]
  },
  tm_attempts: {
    columns: ['id', 'owner_tournament', 'board_no', 'hand_row', 'seat', 'owner_col'],
    rows: [],
    uniques: [{ fields: ['hand_row'], name: 'hand_row', ignoreNull: true }]
  }
};

// ── one legal deal, generated rather than pasted ────────────────────────────
// A hand-typed 52-card string is exactly where a wrong fixture lives, and a wrong fixture reddens
// correct code. This builds the deck from the same rank and suit vocabulary the server uses.
const RANKS = ['2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A'];
const SUITS = ['S', 'H', 'D', 'C'];
const SEATS = ['North', 'East', 'South', 'West'];
const DEALERS = SEATS;
const VULNS = ['None', 'NS', 'EW', 'Both'];
function dealHands(offset = 0) {
  const deck = [];
  for (const suit of SUITS) for (const rank of RANKS) deck.push(`${rank}${suit}`);
  const rotated = deck.slice(offset % 52).concat(deck.slice(0, offset % 52));
  const hands = {};
  SEATS.forEach((seat, index) => { hands[seat] = rotated.slice(index * 13, index * 13 + 13); });
  return hands;
}
function legalBoard(number, { dealer = 'North', vulnerability = 'None', offset = 0 } = {}) {
  return { board_number: String(number), dealer, vulnerability, hands: dealHands(offset) };
}
function boardRow(tournamentId, number, { dealer = 'North', vulnerability = 'None', hands = null, tags = null, id = null } = {}) {
  return {
    id: id ?? `${tournamentId}-b${number}`,
    tournament_id: tournamentId,
    board_number: String(number),
    dealer,
    vulnerability,
    hands_json: JSON.stringify(hands ?? dealHands(Number(number) * 4)),
    tags_json: tags ? JSON.stringify(tags) : null
  };
}
// Seed boards to match each header's board_count, straight into the registry. Seeding through the store
// would test the store's happy path before testing anything else.
const SEED_BOARDS = [
  ['p3', 1], ['p3', 2], ['p2', 1], ['p4', 1], ['c10p', 1], ['c10p', 2], ['c10p', 3], ['c10d', 1], ['c10d', 2],
  ['c11p', 1], ['c12x', 1], ['pubp', 1], ['pubp', 2], ['pubd', 1], ['orphan', 1], ['badv', 1], ['noowner', 1]
];
for (const [tournamentId, number] of SEED_BOARDS) {
  REGISTRY.tournament_boards.rows.push(boardRow(tournamentId, number, {
    dealer: DEALERS[Number(number) % 4],
    vulnerability: VULNS[Number(number) % 4],
    tags: number === 1 ? { contract: '4S', declarer: 'S', result: '=' } : null
  }));
}
REGISTRY.tournament_attempts.rows.push(
  // Two attempt rows on ONE public board, owned by two different accounts. This is the fixture that makes
  // the self-scope arm able to fail: both men can read `pubp`, so a list that ignored the session id would
  // show the other's row and there is no "maybe they cannot see it anyway" escape.
  { id: 'a1', tournament_id: 'pubp', board_number: '1', recorded_hand_id: 'rh-3-1', original_seat: 'South', player_user_id: '3' },
  { id: 'a2', tournament_id: 'pubp', board_number: '1', recorded_hand_id: 'rh-4-1', original_seat: 'North', player_user_id: '4' },
  // One row under a PRIVATE set, so the delete arm has to remove attempt rows or be caught not doing it.
  { id: 'a3', tournament_id: 'p3', board_number: '1', recorded_hand_id: 'rh-3-p3', original_seat: 'East', player_user_id: '3' }
);

// ── the mock NCB ────────────────────────────────────────────────────────────
const realFetch = globalThis.fetch;
const dataCalls = [];
let rowSequence = 500;
const mock = { ownershipWrites: [],
  // Set by an arm, cleared by that same arm. Each knob models ONE documented NCB behaviour, and the
  // arms that depend on it assert the knob actually fired — a green measured against a stub that never
  // ran is not a green.
  failBoardCreate: null,      // { table, boardNumber } → that one insert is refused
  refuseRead: null,           // { table, fragment, status, body } → a read that comes back refused
  ignoreFilters: null,        // table name → reads return every row, filters dropped
  emptyReadTables: null,      // table name → reads answer a NON-row-set body (200 with data:null)
  dropDelete: null            // table name → deletes are accepted and do nothing
};
const RESERVED_QUERY = ['limit', 'page', 'sort', 'order', 'Instance'];
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json' }
});
const ncbError = (message, status = 400) => json({ status: 'failed', error: message }, status);
function bearerOf(init) {
  const headers = init?.headers ?? {};
  const raw = headers.Authorization ?? headers.authorization ?? '';
  return String(raw).replace(/^Bearer\s+/, '');
}
function uniqueViolation(entry, body, excludeId = null) {
  for (const unique of entry.uniques) {
    const values = unique.fields.map((field) => body[field]);
    if (unique.ignoreNull && values.some((value) => value === undefined || value === null || value === '')) continue;
    const clash = entry.rows.some((row) => (excludeId === null || String(row.id) !== String(excludeId))
      && unique.fields.every((field, index) => String(row[field] ?? '') === String(values[index])));
    if (clash) return `Duplicate entry for key '${unique.name}'`;
  }
  // THE COMPOSITE IS ENFORCED AS A PAIR, and this negative control is what keeps the two single-column
  // spellings from being quietly equivalent in this harness: re-using a board number across tournaments
  // must be ACCEPTED. If someone rewrites the registry with two single uniques, arm 8f goes red here.
  return null;
}

globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  if (!target.startsWith('https://ncb.test.invalid')) return realFetch(url, init);
  const { pathname, searchParams } = new URL(target);
  const method = String(init.method ?? 'GET').toUpperCase();
  const bearer = bearerOf(init);
  const body = init.body ? JSON.parse(init.body) : null;

  if (pathname === '/auth/get-session') {
    if (bearer === 'tok-session-down') throw new TypeError('mock: session authority unreachable');
    if (bearer === CLUB_SESSION_TOKEN) return json({ data: { user: { id: CLUB_ACCOUNT_ID, email: CLUB_ACCOUNT_EMAIL } } });
    const user = SESSIONS[bearer];
    if (!user) return json({ status: 'error', message: 'invalid session' }, 401);
    return json({ data: { user: { id: user.id, email: `user${user.id}@example.test`, role: user.role } } });
  }

  if (pathname === '/auth/sign-in/email') {
    if (body?.email !== CLUB_ACCOUNT_EMAIL || body?.password !== CLUB_PASSWORD) {
      return json({ status: 'error', message: 'invalid credentials' }, 401);
    }
    return json({ token: CLUB_SESSION_TOKEN, user: { id: CLUB_ACCOUNT_ID, email: CLUB_ACCOUNT_EMAIL } });
  }

  if (pathname.startsWith('/data/')) {
    dataCalls.push({ pathname, search: searchParams.toString(), method, bearer, body });
    // THE ONE RULE THE WHOLE DESIGN RESTS ON, enforced by the mock so a caller-bearer fallback cannot
    // hide: tournament data never moves on a caller's token. Every authority read and every write here
    // rides the dedicated account's session, because NCB runtime access is shared_readwrite and a read
    // of rows the caller can rewrite is not authorization.
    if (bearer !== CLUB_SESSION_TOKEN) {
      return ncbError(`tournament data call carried a non-club bearer (${pathname})`, 403);
    }
    const [, action, table, rowId] = pathname.split('/').filter(Boolean);
    const entry = REGISTRY[table];
    if (!entry) return ncbError(`unknown table ${table}`, 404);

    if (action === 'read') {
      const query = searchParams.toString();
      if (mock.refuseRead && mock.refuseRead.table === table && query.includes(mock.refuseRead.fragment)) {
        return json(mock.refuseRead.body, mock.refuseRead.status);
      }
      if (mock.emptyReadTables === table) return json({ status: 'success', data: null });
      const filters = {};
      for (const [key, value] of searchParams.entries()) {
        if (RESERVED_QUERY.includes(key)) continue;
        // The live backend's behaviour, reproduced rather than smoothed over: an unknown query name is
        // taken for a column filter and the whole read fails.
        if (!entry.columns.includes(key)) {
          return json({ status: 'failed', error: `Unknown column '${key}' in 'where clause'` }, 500);
        }
        filters[key] = value;
      }
      const rows = mock.ignoreFilters === table
        ? entry.rows.slice()
        : entry.rows.filter((row) => Object.entries(filters).every(([column, value]) => String(row[column] ?? '') === value));
      const sort = searchParams.get('sort');
      let found = rows;
      if (sort !== null) {
        if (!entry.columns.includes(sort)) return json({ status: 'failed', error: `unknown column in sort: ${sort}` }, 500);
        const direction = searchParams.get('order') === 'desc' ? -1 : 1;
        found = rows.slice().sort((a, b) => direction * String(a[sort] ?? '').localeCompare(String(b[sort] ?? '')));
      }
      const limit = Number(searchParams.get('limit'));
      if (Number.isFinite(limit) && limit > 0) found = found.slice(0, Math.floor(limit));
      const page = Number(searchParams.get('page'));
      if (Number.isFinite(page) && page > 1 && Number.isFinite(limit) && limit > 0) {
        const size = Math.floor(limit);
        found = found.slice((Math.floor(page) - 1) * size, (Math.floor(page) - 1) * size + size);
      }
      // NCB's row-ownership stamp, applied on the way out rather than stored in the fixtures, so every
      // row demonstrably carries an owner that is NOT the person the row is about: NodeSend writes with
      // the dedicated service account, so under private RLS `user_id` is that account on every row it
      // made. A store that read identity out of that column would match nothing, and the arms naming a
      // particular player's answer would go red instead of nodding along.
      return json({ status: 'success', data: found.map((row) => ({ user_id: CLUB_ACCOUNT_ID, ...row })) });
    }

    if (action === 'create') {
      if (mock.failBoardCreate && table === mock.failBoardCreate.table
        && String(body[mock.failBoardCreate.column] ?? '') === String(mock.failBoardCreate.value)) {
        return ncbError('simulated write failure mid-import', 500);
      }
      const clash = uniqueViolation(entry, body);
      if (clash) return ncbError(clash, 400);
      const { user_id: claimedOwner, ...stored } = body;
      if (claimedOwner !== undefined) mock.ownershipWrites.push({ table, claimed: String(claimedOwner) });
      const row = { id: String(++rowSequence), ...stored, user_id: CLUB_ACCOUNT_ID };
      entry.rows.push(row);
      return json({ status: 'success', data: { ...row } });
    }

    if (action === 'update') {
      const row = entry.rows.find((candidate) => String(candidate.id) === String(rowId));
      if (!row) return ncbError('no such row', 404);
      // MySQL checks a unique index against the OTHER rows. Excluding the row being updated is what keeps
      // a rename from looking like a duplicate-key collision on the row's own dedupe_key.
      const clash = uniqueViolation(entry, { ...row, ...body }, rowId);
      if (clash) return ncbError(clash, 400);
      Object.assign(row, body);
      return json({ status: 'success', data: { ...row } });
    }

    if (action === 'delete') {
      const index = entry.rows.findIndex((candidate) => String(candidate.id) === String(rowId));
      if (index === -1) return ncbError('no such row', 404);
      // A delete the backend ACCEPTS AND IGNORES. This is the only way to test that the route reports a
      // cleanup that did not happen instead of claiming a rollback it did not perform.
      if (mock.dropDelete === table) return json({ status: 'success', data: { id: rowId } });
      entry.rows.splice(index, 1);
      return json({ status: 'success', data: { id: rowId } });
    }
  }

  return ncbError(`unexpected mock path ${pathname}`, 404);
};

// ── harness ─────────────────────────────────────────────────────────────────
const results = [];
function check(name, condition, detail = '') {
  // The condition must be a real boolean expression at every call site. Recorded here so 14f can prove
  // no arm was handed a constant.
  results.push({ name, pass: condition === true, detail: condition === true ? '' : String(detail ?? '').slice(0, 260) });
}

const server = app.listen(0, '127.0.0.1');
await new Promise((resolve) => server.once('listening', resolve));
const BASE = `http://127.0.0.1:${server.address().port}`;

async function call(method, route, { token = SUPER_TOKEN, body, base = BASE } = {}) {
  const response = await fetch(`${base}${route}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const payload = await response.json().catch(() => ({}));
  return { status: response.status, body: payload, text: JSON.stringify(payload) };
}
// Responses a browser could see, for the leak arms at the end.
const seenBodies = [];
async function ask(method, route, options) {
  const answer = await call(method, route, options);
  seenBodies.push(answer.text);
  return answer;
}
const CATCH_ALL = 'Endpoint not found';

// A tournament header, read straight out of the mock. `rows()` is how the arms prove what STORAGE holds
// (compensating deletes, orphan boards) rather than what an endpoint said about it.
const rowsOf = (table) => REGISTRY[table].rows;
const rowOf = (table, id) => rowsOf(table).find((row) => String(row.id) === String(id)) ?? null;
const boardsOf = (tournamentId) => rowsOf('tournament_boards').filter((row) => String(row.tournament_id) === String(tournamentId));
const attemptsOf = (tournamentId) => rowsOf('tournament_attempts').filter((row) => String(row.tournament_id) === String(tournamentId));
function resetTournamentTables() {
  REGISTRY.tournaments.rows.length = 0;
  REGISTRY.tournament_boards.rows.length = 0;
  REGISTRY.tournament_attempts.rows.length = 0;
  REGISTRY.tournaments.rows.push(...TOURNAMENT_SEED.tournaments.map((row) => ({ ...row })));
  for (const [tournamentId, number] of SEED_BOARDS) {
    REGISTRY.tournament_boards.rows.push(boardRow(tournamentId, number, {
      dealer: DEALERS[Number(number) % 4], vulnerability: VULNS[Number(number) % 4],
      tags: number === 1 ? { contract: '4S', declarer: 'S', result: '=' } : null
    }));
  }
  REGISTRY.tournament_attempts.rows.push(
    { id: 'a1', tournament_id: 'pubp', board_number: '1', recorded_hand_id: 'rh-3-1', original_seat: 'South', player_user_id: '3' },
    { id: 'a2', tournament_id: 'pubp', board_number: '1', recorded_hand_id: 'rh-4-1', original_seat: 'North', player_user_id: '4' },
    { id: 'a3', tournament_id: 'p3', board_number: '1', recorded_hand_id: 'rh-3-p3', original_seat: 'East', player_user_id: '3' }
  );
  mock.failBoardCreate = null;
  mock.refuseRead = null;
  mock.ignoreFilters = null;
  mock.ownershipWrites.length = 0;
  mock.emptyReadTables = null;
  mock.dropDelete = null;
}
const TOURNAMENT_SEED = {
  tournaments: REGISTRY.tournaments.rows.map((row) => ({ ...row }))
};
resetTournamentTables();

// ── an isolated mount, for the configuration and alternate-schema arms ──────
// Built with `buildTournamentMount` over the same mock, on its own express app, so a deployment-state arm
// measures the real builder rather than a description of it.
async function serveIsolated({ env, limits } = {}) {
  const mount = buildTournamentMount({
    env,
    limits,
    authenticate: async (req) => {
      // `req.headers` IS the header map (it has no `.headers` of its own), so the bearer is read directly
      // rather than through the init-shaped `bearerOf` helper. Routing it through that helper produced an
      // empty token, and every isolated-mount arm then answered 401 for the harness's own fault.
      const token = String(req.headers?.authorization ?? '').replace(/^Bearer\s+/, '');
      const user = SESSIONS[token];
      return user ? { ok: true, id: user.id, role: user.role } : { ok: false, status: 401, code: 'auth_error' };
    }
  });
  const isolated = express();
  isolated.use(mount.router);
  isolated.use((req, res) => res.status(404).json({ success: false, error: CATCH_ALL }));
  const listener = isolated.listen(0, '127.0.0.1');
  await new Promise((resolve) => listener.once('listening', resolve));
  const base = `http://127.0.0.1:${listener.address().port}`;
  return {
    mount,
    base,
    async close() { await new Promise((resolve) => listener.close(resolve)); }
  };
}
const baseEnv = () => ({ ...process.env });

// ══ 1. THE MOUNTED SURFACE ══════════════════════════════════════════════════
// The twelve routes, inlined rather than imported from the other repo, so this gate cannot go green
// because BridgeMind-Greta happens to be absent. Section 12 separately proves they are THE SAME twelve
// the frozen contract names.
const EXPECTED_ROUTES = Object.freeze([
  { op: 'listTournaments', method: 'GET', path: '/tournaments', guard: 'any-session', ownerFromStore: false },
  { op: 'createTournament', method: 'POST', path: '/tournaments', guard: 'visibility-depends', ownerFromStore: false },
  { op: 'readTournament', method: 'GET', path: '/tournaments/:tournamentId', guard: 'read', ownerFromStore: true },
  { op: 'listBoards', method: 'GET', path: '/tournaments/:tournamentId/boards', guard: 'read', ownerFromStore: true },
  { op: 'updateTournament', method: 'PATCH', path: '/tournaments/:tournamentId', guard: 'manage', ownerFromStore: true },
  { op: 'setVisibility', method: 'POST', path: '/tournaments/:tournamentId/visibility', guard: 'manage', ownerFromStore: true },
  { op: 'publish', method: 'POST', path: '/tournaments/:tournamentId/publish', guard: 'manage', ownerFromStore: true },
  { op: 'unpublish', method: 'POST', path: '/tournaments/:tournamentId/unpublish', guard: 'manage', ownerFromStore: true },
  { op: 'deleteTournament', method: 'DELETE', path: '/tournaments/:tournamentId', guard: 'manage', ownerFromStore: true },
  { op: 'startBoard', method: 'POST', path: '/tournaments/:tournamentId/boards/:boardNumber/start', guard: 'play', ownerFromStore: true },
  { op: 'listAttempts', method: 'GET', path: '/tournaments/:tournamentId/attempts', guard: 'self', ownerFromStore: true },
  { op: 'recordAttempt', method: 'POST', path: '/tournaments/:tournamentId/attempts', guard: 'self', ownerFromStore: true }
]);
const shape = (route) => `${route.method} ${route.path}`;

function collectRoutes(stack, depth, out) {
  for (const layer of stack) {
    const entry = layer?.route;
    if (entry) {
      for (const method of Object.keys(entry.methods ?? {})) {
        (depth === 0 ? out.direct : out.nested).push(`${method.toUpperCase()} ${entry.path}`);
      }
      continue;
    }
    if (layer?.handle?.stack && Array.isArray(layer.handle.stack)) collectRoutes(layer.handle.stack, depth + 1, out);
  }
  return out;
}
const emptyBucket = () => ({ direct: [], nested: [] });
const tournamentBucket = collectRoutes(tournamentMount.router.stack ?? [], 0, emptyBucket());
const mounted = tournamentBucket.direct;
const declared = tournamentRoutes.map(shape);
const expected = EXPECTED_ROUTES.map(shape);
check('1a. the surface declares exactly the twelve contract routes',
  JSON.stringify(declared.slice().sort()) === JSON.stringify(expected.slice().sort()),
  `declared ${declared.length}: ${declared.join(' | ')}`);
const notMounted = expected.filter((route) => !mounted.includes(route));
check('1b. every declared tournament route is actually mounted on the live app',
  notMounted.length === 0, notMounted.join(' | '));
const undeclared = mounted.filter((route) => !expected.includes(route));
check('1c. nothing is mounted that the contract does not name (no accidental surface)',
  undeclared.length === 0, undeclared.join(' | '));
check('1d. the mounted surface has no duplicate registration',
  new Set(mounted).size === mounted.length,
  mounted.filter((route, index) => mounted.indexOf(route) !== index).join(','));
check('1e. the declared guard per route is the contract guard, and every row-scoped one reads storage',
  JSON.stringify(tournamentRoutes.map((route) => `${route.op}:${route.guard}:${route.ownerFromStore}`))
    === JSON.stringify(EXPECTED_ROUTES.map((route) => `${route.op}:${route.guard}:${route.ownerFromStore}`)),
  tournamentRoutes.map((route) => `${route.op}:${route.guard}:${route.ownerFromStore}`).join(' | '));
check('1f. ten of the twelve routes resolve their target from storage, not from the path',
  tournamentRoutes.filter((route) => route.ownerFromStore).length === 10
    && tournamentRoutes.every((route) => EXPECTED_ROUTES.find((e) => e.op === route.op).ownerFromStore === route.ownerFromStore),
  tournamentRoutes.filter((route) => route.ownerFromStore).map((route) => route.op).join(','));
check('1g. tournament routes are unprefixed, so /api/tournaments is NOT served here',
  mounted.every((route) => !route.includes('/api/')),
  mounted.filter((route) => route.includes('/api/')).join(' | '));
check('1h. the mount is always registered, even when the store cannot be built',
  tournamentMount.router !== undefined && typeof tournamentMount.router.stack === 'object'
    && mounted.length === 12,
  `stack ${tournamentMount.router?.stack?.length ?? 'none'} mounted ${mounted.length}`);
check('1i. no parameter route swallows a literal segment (publish is not read as an id-verb)',
  mounted.includes('POST /tournaments/:tournamentId/publish')
    && mounted.includes('POST /tournaments/:tournamentId/visibility')
    && mounted.includes('POST /tournaments/:tournamentId/unpublish'),
  mounted.join(' | '));

// Each route must answer as a TOURNAMENT route. The relay's catch-all says `Endpoint not found`; a route
// that was not registered falls through to it, so this is the arm that distinguishes "403 because I
// refused you" from "404 because nobody mounted anything".
const surfaceProbes = [
  ['GET', '/tournaments', undefined],
  ['POST', '/tournaments', { name: 'probe', visibility: 'private', boards: [legalBoard(1)] }],
  ['GET', '/tournaments/p3', undefined],
  ['GET', '/tournaments/p3/boards', undefined],
  ['PATCH', '/tournaments/p3', { name: 'probe' }],
  ['POST', '/tournaments/p3/visibility', { visibility: 'private' }],
  ['POST', '/tournaments/p3/publish', {}],
  ['POST', '/tournaments/p3/unpublish', {}],
  ['DELETE', '/tournaments/p3', { confirm_name: 'probe' }],
  ['POST', '/tournaments/p3/boards/1/start', { original_seat: 'North' }],
  ['GET', '/tournaments/p3/attempts', undefined],
  ['POST', '/tournaments/p3/attempts', { board_number: '1', original_seat: 'North', recorded_hand_id: 'rh-1' }]
];
// A route that was never registered falls through to the relay's catch-all, which answers
// `{success:false, error:"Endpoint not found"}`. A tournament route answers either a tournament refusal
// (`error` + `detail`) or the relay success envelope (`status:'success'` + `data`) — and a 200 whose body
// is the catch-all would be the shape a missing route leaves behind.
const fellThrough = [];
for (const [method, route, body] of surfaceProbes) {
  const answer = await call(method, route, { token: 'tok-noclub', ...(body === undefined ? {} : { body }) });
  const text = JSON.stringify(answer.body);
  const refused = answer.body?.error && answer.body.error !== CATCH_ALL;
  const served = answer.body?.status === 'success' && 'data' in answer.body;
  if (text.includes(CATCH_ALL) || !(refused || served)) {
    fellThrough.push(`${method} ${route} = ${answer.status} ${text.slice(0, 60)}`);
  }
}
check('1j. all twelve routes answer in the tournament envelope and none falls to the relay catch-all',
  fellThrough.length === 0, fellThrough.join(' | '));
const stray = await call('GET', '/tournaments/p3/boards/1/nonsense', { token: SUPER_TOKEN });
check('1k. a path NO tournament route claims is still the relay 404, not a 500',
  stray.status === 404 && stray.body?.error === CATCH_ALL, `${stray.status} ${stray.text.slice(0, 90)}`);

// ══ 2. IDENTITY, STORAGE AND CONFIGURATION PREREQUISITES ════════════════════
const noToken = await call('GET', '/tournaments', { token: '' });
check('2a. an unauthenticated list is 401, and no rows are served to a stranger',
  noToken.status === 401 && noToken.body?.error === 'auth_error', `${noToken.status} ${noToken.text.slice(0, 120)}`);
const forgedToken = await call('POST', '/tournaments/p3/publish', { token: 'tok-not-a-person', body: {} });
check('2b. an unknown bearer is 401 on a management route before any row is read',
  forgedToken.status === 401, `${forgedToken.status} ${forgedToken.text.slice(0, 120)}`);
const sessionDown = await call('GET', '/tournaments', { token: 'tok-session-down' });
check('2c. an unreachable session authority answers 503, never a 401 that discards a valid session',
  sessionDown.status === 503 && sessionDown.body?.error === 'session_service_unavailable',
  `${sessionDown.status} ${sessionDown.text.slice(0, 120)}`);
// A GET cannot carry a body over fetch (and Express would not populate one), so the body-shape arms use
// the verbs that really do take one. This arm covers the other half of the same discipline: a QUERY value
// that is nonsense must be bounded, not trusted — an unbounded `limit` on a shared relay is a memory
// incident, and a NaN one is an empty list someone will be told is a fact about their data.
const garbagePaging = await call('GET', '/tournaments?limit=abc&page=-4', { token: 'tok-member10' });
check('2d. a nonsense page and limit fall back to bounded defaults instead of throwing or going wide',
  garbagePaging.status === 200 && garbagePaging.body?.data?.page === 1 && garbagePaging.body.data.limit === 25,
  `${garbagePaging.status} ${garbagePaging.text.slice(0, 160)}`);
const hugeLimit = await call('GET', '/tournaments?limit=100000', { token: 'tok-member10' });
check('2e. a limit above the ceiling is clamped to it',
  hugeLimit.status === 200 && hugeLimit.body.data.limit === 100,
  `${hugeLimit.status} ${hugeLimit.text.slice(0, 120)}`);
const badStatus = await call('GET', '/tournaments?status=live', { token: 'tok-member10' });
check('2f. a status outside the lifecycle vocabulary is refused with invalid_status',
  badStatus.status === 400 && badStatus.body?.error === 'invalid_status', `${badStatus.status} ${badStatus.text.slice(0, 120)}`);

// ── the fail-closed configuration states, each measured against the REAL builder ──
const noSchema = await serveIsolated({ env: (() => { const e = baseEnv(); delete e.TOURNAMENT_NCB_SCHEMA_JSON; return e; })() });
const noSchemaAnswer = await call('GET', '/tournaments', { token: SUPER_TOKEN, base: noSchema.base });
check('2g. no tournament schema → the mount is configured:false with the named reason, and routes 503',
  noSchema.mount.configured === false
    && noSchema.mount.reason === 'tournament_schema_unconfigured'
    && /no tournament schema configured/.test(noSchema.mount.detail)
    && noSchemaAnswer.status === 503 && noSchemaAnswer.body?.error === 'tournament_store_unavailable',
  `${noSchema.mount.reason} | ${noSchemaAnswer.status} ${noSchemaAnswer.text.slice(0, 120)}`);
await noSchema.close();

const noAccount = await serveIsolated({ env: (() => { const e = baseEnv(); delete e.CLUB_NCB_EMAIL; return e; })() });
check('2h. no service account → the store is never built, with the account reason named (not a schema one)',
  noAccount.mount.configured === false && noAccount.mount.reason === 'club_account_unconfigured',
  `${noAccount.mount.reason} | ${noAccount.mount.detail}`);
await noAccount.close();

const noClubSchema = await serveIsolated({ env: (() => { const e = baseEnv(); delete e.CLUB_NCB_SCHEMA_JSON; return e; })() });
const clubSchemaAnswer = await call('GET', '/tournaments', { token: SUPER_TOKEN, base: noClubSchema.base });
check('2i. no CLUB schema → tournaments refuses to build, because membership authority is the club store',
  noClubSchema.mount.configured === false && noClubSchema.mount.reason === 'club_schema_unconfigured'
    && clubSchemaAnswer.status === 503,
  `${noClubSchema.mount.reason} | ${clubSchemaAnswer.status} ${clubSchemaAnswer.text.slice(0, 120)}`);
await noClubSchema.close();

const bothSchema = await serveIsolated({ env: { ...baseEnv(), TOURNAMENT_NCB_SCHEMA_FILE: 'does/not/exist.json' } });
check('2j. inline AND file schema is a refused misconfiguration, never a silent precedence rule',
  bothSchema.mount.configured === false
    && /both set/.test(bothSchema.mount.detail)
    && bothSchema.mount.reason === 'tournament_schema_unconfigured',
  `${bothSchema.mount.reason} | ${bothSchema.mount.detail}`);
await bothSchema.close();

for (const [label, schema, expect] of [
  ['2k. a missing required column is named', {
    tables: { tournaments: 'tournaments', boards: 'tournament_boards', attempts: 'tournament_attempts' },
    columns: {
      tournaments: { id: 'id', userId: 'owner_user_id', clubId: 'club_id', name: 'name', visibility: 'visibility', boardCount: 'board_count', sourceLabel: 'source_label', dedupeKey: 'dedupe_key' },
      boards: { id: 'id', tournamentId: 'tournament_id', boardNumber: 'board_number', dealer: 'dealer', vulnerability: 'vulnerability', handsJson: 'hands_json' },
      attempts: { id: 'id', tournamentId: 'tournament_id', boardNumber: 'board_number', recordedHandId: 'recorded_hand_id', originalSeat: 'original_seat', userId: 'player_user_id' }
    }
  }, 'columns.tournaments.status is missing'],
  ['2l. a club table declared here is REFUSED, not ignored', {
    ...MAIN_TOURNAMENT_SCHEMA,
    tables: { ...MAIN_TOURNAMENT_SCHEMA.tables, memberships: 'club_memberships' },
    columns: { ...MAIN_TOURNAMENT_SCHEMA.columns, memberships: { userId: 'member_user_id', clubId: 'club_id', role: 'role', status: 'status' } }
  }, 'not one of the agreed three tournament table roles'],
  ['2m. an unknown column key is refused rather than left looking supported', {
    tables: MAIN_TOURNAMENT_SCHEMA.tables,
    columns: { ...MAIN_TOURNAMENT_SCHEMA.columns, tournaments: { ...MAIN_TOURNAMENT_SCHEMA.columns.tournaments, secretAuthority: 'is_admin' } }
  }, 'is not a column this contract uses'],
  ['2n. two roles pointing at one table is refused', {
    tables: { tournaments: 'tournaments', boards: 'tournaments', attempts: 'tournament_attempts' },
    columns: MAIN_TOURNAMENT_SCHEMA.columns
  }, 'two schema roles point at the same table'],
  ['2o. a half-mapped status axis is refused (a missing code writes literal text)', {
    ...MAIN_TOURNAMENT_SCHEMA,
    values: { tournaments: { status: { published: 1 } } }
  }, 'values.tournaments.status.draft is required'],
  // THE OWNERSHIP SEPARATION, as a boot-time refusal rather than a paragraph in a document. NodeSend
  // writes every tournament row with the dedicated service account, so an application owner stored in
  // NCB's own row-ownership column cannot work whichever way the vendor resolves the collision — either
  // the service account cannot read the row back, or `user_id` is constant and no player ever matches
  // their own private tournament. Both answers look like an empty list, which is why this is refused at
  // startup instead of discovered by a player.
  ['2w. mapping the tournament application owner onto NCB\'s user_id is refused at boot', {
    ...MAIN_TOURNAMENT_SCHEMA,
    columns: { ...MAIN_TOURNAMENT_SCHEMA.columns, tournaments: { ...MAIN_TOURNAMENT_SCHEMA.columns.tournaments, userId: 'user_id' } }
  }, 'row-ownership slot'],
  ['2x. mapping the attempt player onto NCB\'s user_id is refused at boot', {
    ...MAIN_TOURNAMENT_SCHEMA,
    columns: { ...MAIN_TOURNAMENT_SCHEMA.columns, attempts: { ...MAIN_TOURNAMENT_SCHEMA.columns.attempts, userId: 'user_id' } }
  }, 'columns.attempts.userId']
]) {
  const probe = tournamentSchemaConfig({ TOURNAMENT_NCB_SCHEMA_JSON: JSON.stringify(schema) });
  check(`${label} (named: ${expect})`,
    probe.ok === false && probe.problems.some((problem) => problem.includes(expect)),
    probe.ok === true ? 'schema was ACCEPTED' : probe.problems.join(' | '));
}
const goodSchema = tournamentSchemaConfig({ TOURNAMENT_NCB_SCHEMA_JSON: JSON.stringify(MAIN_TOURNAMENT_SCHEMA) });
check('2p. the documented schema IS accepted (so the arms above fail on content, not on shape)',
  goodSchema.ok === true && goodSchema.schema.tables.boards === 'tournament_boards'
    && goodSchema.schema.columns.attempts.recordedHandId === 'recorded_hand_id',
  goodSchema.ok ? 'ok' : goodSchema.problems.join(' | '));
check('2q. the schema carries the composite board unique and names it as composite',
  goodSchema.ok === true && goodSchema.schema.uniqueKeys.boards.composite === true
    && JSON.stringify(goodSchema.schema.uniqueKeys.boards.fields) === JSON.stringify(['tournamentId', 'boardNumber']),
  JSON.stringify(goodSchema.ok ? goodSchema.schema.uniqueKeys.boards : null));
// The counterpart of 2w/2x, and the arm that keeps them honest: the rule forbids ONE column, not any
// rename. Without this, a guard that refused every schema would pass 2w and 2x while breaking the feature.
const renamedOwner = tournamentSchemaConfig({
  TOURNAMENT_NCB_SCHEMA_JSON: JSON.stringify({
    ...MAIN_TOURNAMENT_SCHEMA,
    columns: {
      ...MAIN_TOURNAMENT_SCHEMA.columns,
      tournaments: { ...MAIN_TOURNAMENT_SCHEMA.columns.tournaments, userId: 'imported_by' },
      attempts: { ...MAIN_TOURNAMENT_SCHEMA.columns.attempts, userId: 'played_by' }
    }
  })
});
check('2y. any OTHER column spelling for the application owner is accepted (the guard is about the collision, not the name)',
  renamedOwner.ok === true && renamedOwner.schema.columns.tournaments.userId === 'imported_by'
    && renamedOwner.schema.columns.attempts.userId === 'played_by',
  renamedOwner.ok ? 'ok' : renamedOwner.problems.join(' | '));

// The store must refuse to be built without the membership bridge: constructing one anyway would leave it
// free to invent its own membership rule.
let bridgeRequired = 'no throw';
try {
  createTournamentNcbStore({
    client: { configured: true }, schema: goodSchema.schema,
    clubBridge: { getMembership: async () => null }
  });
} catch (error) {
  bridgeRequired = error?.name === 'TypeError' ? 'TypeError' : String(error?.message ?? error);
}
check('2r. a half club bridge is a construction failure, so no store can run with a partial authority set',
  bridgeRequired === 'TypeError', String(bridgeRequired));
let clientRequired = 'no throw';
try {
  createTournamentNcbStore({ client: null, schema: goodSchema.schema, clubBridge: { getMembership: async () => null, clubStatus: async () => null, isSystemAdmin: async () => null } });
} catch (error) {
  clientRequired = error?.name === 'TypeError' ? 'TypeError' : String(error?.message ?? error);
}
check('2s. no client, no store (a tournament route must never read NCB any other way)',
  clientRequired === 'TypeError', String(clientRequired));

// The ALTERNATE-SPELLING mount: table and column names come from config, so a deployment that named its
// columns differently is served by the SAME code. If anything were hard-coded, the mock's live read
// grammar would answer HTTP 500 `Unknown column` and these arms would go red.
const altSchema = {
  tables: { tournaments: 'tm_tournaments', boards: 'tm_boards', attempts: 'tm_attempts' },
  columns: {
    tournaments: { id: 'id', userId: 'owner_col', clubId: 'team_col', name: 'title', visibility: 'category', status: 'publication_status', boardCount: 'n_boards', sourceLabel: 'origin', dedupeKey: 'dup_key' },
    boards: { id: 'id', tournamentId: 'owner_tournament', boardNumber: 'board_no', dealer: 'dealer', vulnerability: 'vulnerability', handsJson: 'hands_json' },
    attempts: { id: 'id', tournamentId: 'owner_tournament', boardNumber: 'board_no', recordedHandId: 'hand_row', originalSeat: 'seat', userId: 'owner_col' }
  }
};
const alt = await serveIsolated({ env: { ...baseEnv(), TOURNAMENT_NCB_SCHEMA_JSON: JSON.stringify(altSchema) } });
const altRead = await call('GET', '/tournaments/alt1', { token: 'tok-member10', base: alt.base });
check('2t. an alternate column spelling is honoured end-to-end (the store is schema-driven)',
  altRead.status === 200 && altRead.body?.data?.id === 'alt1' && altRead.body?.data?.name === 'Alt Named Set',
  `${altRead.status} ${altRead.text.slice(0, 160)}`);
const altList = await call('GET', '/tournaments', { token: 'tok-member10', base: alt.base });
check('2u. the list read filters on the deployment\u2019s column names, not on the vocabulary words',
  altList.status === 200 && Array.isArray(altList.body?.data?.tournaments)
    && altList.body.data.tournaments.some((row) => row.id === 'alt1'),
  `${altList.status} ${altList.text.slice(0, 200)}`);
const altDenied = await call('GET', '/tournaments/alt1', { token: 'tok-noclub', base: alt.base });
check('2v. the alternate mount still refuses a non-owner (renaming columns grants nobody anything)',
  altDenied.status === 403 && altDenied.body?.error === 'owner_only', `${altDenied.status} ${altDenied.text.slice(0, 120)}`);
await alt.close();

// ══ 3. THE POSITIVE BODY ALLOW-LIST ═════════════════════════════════════════
// The arm the whole design is judged on: no route takes an identity, a club or a status from a field.
const identityAttempts = [
  ['POST', '/tournaments', { name: 'X', visibility: 'private', boards: [legalBoard(1)], user_id: '1' }, 'body.user_id'],
  ['POST', '/tournaments', { name: 'X', visibility: 'public', boards: [legalBoard(1)], is_super_admin: true }, 'body.is_super_admin'],
  ['POST', '/tournaments', { name: 'X', visibility: 'club', club_id: '10', boards: [legalBoard(1)], status: 'published' }, 'body.status'],
  ['POST', '/tournaments', { name: 'X', visibility: 'private', boards: [legalBoard(1)], board_count: 99 }, 'body.board_count'],
  ['POST', '/tournaments', { name: 'X', visibility: 'private', boards: [legalBoard(1)], role: 'club_admin' }, 'body.role'],
  ['PATCH', '/tournaments/p3', { name: 'Renamed', user_id: '1' }, 'body.user_id'],
  ['PATCH', '/tournaments/p3', { name: 'Renamed', visibility: 'public' }, 'body.visibility'],
  ['POST', '/tournaments/p3/visibility', { visibility: 'private', user_id: '9' }, 'body.user_id'],
  ['POST', '/tournaments/p3/publish', { user_id: '1' }, 'body.user_id'],
  ['POST', '/tournaments/p3/unpublish', { force: true }, 'body.force'],
  ['DELETE', '/tournaments/p3', { confirm_name: 'Kitchen Table Sets', user_id: '1' }, 'body.user_id'],
  ['POST', '/tournaments/p3/boards/1/start', { original_seat: 'North', hands: dealHands(0) }, 'body.hands'],
  ['POST', '/tournaments/p3/boards/1/start', { original_seat: 'North', dealer: 'East' }, 'body.dealer'],
  ['POST', '/tournaments/p3/attempts', { board_number: '1', original_seat: 'North', recorded_hand_id: 'rh-9', user_id: '9' }, 'body.user_id'],
  ['POST', '/tournaments/p3/attempts', { board_number: '1', original_seat: 'North', recorded_hand_id: 'rh-9', score: 7 }, 'body.score']
];
// A GET cannot carry a body, so these probes put the identity claim in the QUERY — the third slot is the
// body (none), the fourth is the field name the refusal must print.
const listIdentityQueries = [
  ['GET', '/tournaments?user_id=1', undefined, 'query.user_id'],
  ['GET', '/tournaments?owner=1', undefined, 'query.owner'],
  ['GET', '/tournaments?page=1&limit=5&is_super_admin=1', undefined, 'query.is_super_admin'],
  ['GET', '/tournaments/p3/attempts?user_id=4', undefined, 'query.user_id'],
  ['GET', '/tournaments/p3/boards?club_id=10', undefined, 'query.club_id'],
  ['GET', '/tournaments/p3?status=private', undefined, 'query.status']
];
const refused = [];
for (const [method, route, body, needle] of [...identityAttempts, ...listIdentityQueries]) {
  const answer = await call(method, route, { token: 'tok-noclub', ...(body === undefined ? {} : { body }) });
  const named = String(answer.body?.detail ?? '').includes(needle.replace(/^body\./, '').replace(/^query\./, ''));
  if (!(answer.status === 400 && answer.body?.error === 'client_identity_refused' && named)) {
    refused.push(`${method} ${route} = ${answer.status}/${answer.body?.error}${named ? '' : ' (field not named)'}`);
  }
}
check('3a. every identity-bearing or undeclared field is refused 400 client_identity_refused, naming the field',
  refused.length === 0, refused.join(' | '));
check('3b. `user_id` appears in NO allow-list, for query or body, on ANY operation',
  Object.values(tournamentBodyFields).every((spec) => !spec.body.includes('user_id') && !spec.query.includes('user_id'))
    && Object.keys(tournamentBodyFields).length === 12,
  Object.entries(tournamentBodyFields).filter(([, spec]) => spec.body.includes('user_id') || spec.query.includes('user_id')).map(([k]) => k).join(','));
// The positive control. Without it, 3a would be satisfied by a route that refuses EVERYTHING, and the
// feature would be broken while the gate looked green.
const legalList = await call('GET', '/tournaments?page=1&limit=5&visibility=private', { token: 'tok-member10' });
check('3c. the declared query fields ARE accepted (3a refuses names, not requests)',
  legalList.status === 200 && Array.isArray(legalList.body?.data?.tournaments),
  `${legalList.status} ${legalList.text.slice(0, 160)}`);
const legalClubFilter = await call('GET', '/tournaments?club_id=10', { token: 'tok-admin10' });
check('3d. club_id is accepted as a narrowing filter for a club admin',
  legalClubFilter.status === 200 && legalClubFilter.body.data.tournaments.every((row) => row.visibility !== 'club' || row.club_id === '10'),
  `${legalClubFilter.status} ${legalClubFilter.text.slice(0, 200)}`);
check('3e. a filter cannot WIDEN the scope: an ordinary member asking for visibility=public sees no private or club row',
  (await call('GET', '/tournaments?visibility=private', { token: 'tok-member11' })).body.data.tournaments.every((row) => row.user_id === '4')
    && (await call('GET', '/tournaments?visibility=club&club_id=10', { token: 'tok-noclub' })).body.data.tournaments.length === 0,
  'widening observed');
const unknownOp = tournamentValidateShape('deleteAnything', { query: {}, body: {} });
check('3f. an operation no route declares has no allow-list to inherit',
  unknownOp?.status === 400 && unknownOp.body?.error === 'unknown_operation', JSON.stringify(unknownOp));

// ══ 4. T1 — A PRIVATE SET BELONGS TO ITS OWNER AND TO NOBODY ELSE ═══════════
const ownerRead = await ask('GET', '/tournaments/p3', { token: 'tok-member10' });
check('4a. the owner reads their own private set, with the owner id from storage',
  ownerRead.status === 200 && ownerRead.body?.data?.id === 'p3' && ownerRead.body.data.user_id === '3'
    && ownerRead.body.data.visibility === 'private',
  `${ownerRead.status} ${ownerRead.text.slice(0, 160)}`);
const strangerRead = await ask('GET', '/tournaments/p3', { token: 'tok-member11' });
check('4b. another signed-in account is refused a private set with owner_only',
  strangerRead.status === 403 && strangerRead.body?.error === 'owner_only', `${strangerRead.status} ${strangerRead.text.slice(0, 120)}`);
const superOnPrivate = await ask('GET', '/tournaments/p3', { token: SUPER_TOKEN });
check('4c. the BridgeMind Admin is refused a private set too — "only the owner" is not widened server-side',
  superOnPrivate.status === 403 && superOnPrivate.body?.error === 'owner_only',
  `${superOnPrivate.status} ${superOnPrivate.text.slice(0, 120)}`);
const superListPrivate = await ask('GET', '/tournaments', { token: SUPER_TOKEN });
check('4d. a private row never appears in the admin\u2019s list either',
  superListPrivate.status === 200 && superListPrivate.body.data.tournaments.every((row) => row.id !== 'p3' && row.id !== 'p4'),
  JSON.stringify(superListPrivate.body?.data?.tournaments?.map((row) => row.id)));
const privateProbes = [
  ['GET', '/tournaments/p3/boards', undefined],
  ['PATCH', '/tournaments/p3', { name: 'Hijacked' }],
  ['POST', '/tournaments/p3/visibility', { visibility: 'public' }],
  ['POST', '/tournaments/p3/publish', {}],
  ['POST', '/tournaments/p3/unpublish', {}],
  ['DELETE', '/tournaments/p3', { confirm_name: 'Kitchen Table Sets' }],
  ['POST', '/tournaments/p3/boards/1/start', { original_seat: 'North' }],
  ['GET', '/tournaments/p3/attempts', undefined],
  ['POST', '/tournaments/p3/attempts', { board_number: '1', original_seat: 'North', recorded_hand_id: 'rh-x' }]
];
const privateLeaks = [];
for (const [method, route, body] of privateProbes) {
  const answer = await call(method, route, { token: 'tok-noclub', ...(body === undefined ? {} : { body }) });
  if (!(answer.status === 403 && answer.body?.error === 'owner_only')) {
    privateLeaks.push(`${method} ${route} = ${answer.status}/${answer.body?.error}`);
  }
}
check('4e. all nine verbs on somebody else\u2019s private set answer 403 owner_only',
  privateLeaks.length === 0, privateLeaks.join(' | '));
const afterProbes = rowOf('tournaments', 'p3');
check('4f. and every refused write left the row exactly as it was',
  afterProbes?.name === 'Kitchen Table Sets' && afterProbes?.visibility === 'private' && afterProbes?.status === 'published',
  JSON.stringify(afterProbes));
check('4g. no attempt row was written by the refused attempt POST',
  !rowsOf('tournament_attempts').some((row) => row.recorded_hand_id === 'rh-x')
    && attemptsOf('p3').every((row) => row.player_user_id === '3'),
  JSON.stringify(attemptsOf('p3')));
const guessed = await ask('GET', '/tournaments/nope-not-here', { token: SUPER_TOKEN });
check('4h. a path id that names no row is 404 tournament_not_found, not a permission answer',
  guessed.status === 404 && guessed.body?.error === 'tournament_not_found', `${guessed.status} ${guessed.text.slice(0, 120)}`);
const badId = await call('GET', '/tournaments/%24%7BtournamentId%7D', { token: SUPER_TOKEN });
check('4i. a path id outside the id grammar is refused before storage is read',
  badId.status === 400 && badId.body?.error === 'bad_request', `${badId.status} ${badId.text.slice(0, 120)}`);
const ownerDraft = await ask('GET', '/tournaments/p4', { token: 'tok-member10' });
check('4j. a private DRAFT is refused to a stranger as owner_only, not as tournament_not_published',
  ownerDraft.status === 403 && ownerDraft.body?.error === 'owner_only', `${ownerDraft.status} ${ownerDraft.text.slice(0, 120)}`);
const ownerSeesOwnDraft = await call('GET', '/tournaments/p4', { token: 'tok-member11' });
const p4Owner = await call('GET', '/tournaments', { token: 'tok-member11' });
check('4k. the owner\u2019s own list carries their private draft (status and visibility are separate axes)',
  p4Owner.status === 200 && p4Owner.body.data.tournaments.some((row) => row.id === 'p4' && row.status === 'draft'),
  JSON.stringify(p4Owner.body?.data?.tournaments?.map((row) => `${row.id}:${row.status}`)));
void ownerDraft; void ownerSeesOwnDraft;
const malformed = await ask('GET', '/tournaments/noowner', { token: SUPER_TOKEN });
check('4l. a row with an empty owner column is a store problem (503), never a silent "nobody may see it"',
  malformed.status === 503, `${malformed.status} ${malformed.text.slice(0, 160)}`);
const corruptCategory = await ask('GET', '/tournaments/badv', { token: 'tok-member10' });
check('4m. a row whose category is outside the vocabulary is refused, not guessed at',
  corruptCategory.status === 403 && corruptCategory.body?.error === 'invalid_visibility',
  `${corruptCategory.status} ${corruptCategory.text.slice(0, 120)}`);

// ══ 5. T2 — CLUB SETS: ADMINS OF THE OWNING CLUB, MEMBERS OF PUBLISHED ONES ══
const memberRead = await ask('GET', '/tournaments/c10p', { token: 'tok-member10' });
check('5a. an approved member reads their club\u2019s PUBLISHED set',
  memberRead.status === 200 && memberRead.body?.data?.club_id === '10', `${memberRead.status} ${memberRead.text.slice(0, 160)}`);
const memberBoards = await ask('GET', '/tournaments/c10p/boards', { token: 'tok-member10' });
check('5b. a member gets every board of the published set, complete with hands',
  memberBoards.status === 200 && memberBoards.body.data.boards.length === 3
    && memberBoards.body.data.boards.every((board) => Object.keys(board.hands).length === 4),
  `${memberBoards.status} ${memberBoards.text.slice(0, 180)}`);
const memberDraftRead = await ask('GET', '/tournaments/c10d', { token: 'tok-member10' });
check('5c. an UNPUBLISHED club set is invisible to its own members (tournament_not_published)',
  memberDraftRead.status === 403 && memberDraftRead.body?.error === 'tournament_not_published',
  `${memberDraftRead.status} ${memberDraftRead.text.slice(0, 120)}`);
const memberDraftList = await call('GET', '/tournaments', { token: 'tok-member10' });
check('5d. and it does not appear in the member\u2019s list either',
  memberDraftList.body.data.tournaments.every((row) => row.id !== 'c10d'),
  JSON.stringify(memberDraftList.body?.data?.tournaments?.map((row) => row.id)));
const memberDraftStart = await ask('POST', '/tournaments/c10d/boards/1/start', { token: 'tok-member10', body: { original_seat: 'North' } });
check('5e. a member cannot start a board of the unpublished set',
  memberDraftStart.status === 403 && memberDraftStart.body?.error === 'tournament_not_published',
  `${memberDraftStart.status} ${memberDraftStart.text.slice(0, 120)}`);
const adminDraftRead = await ask('GET', '/tournaments/c10d', { token: 'tok-admin10' });
check('5f. the club\u2019s own admin reads the draft (review before release is an admin action)',
  adminDraftRead.status === 200 && adminDraftRead.body?.data?.status === 'draft',
  `${adminDraftRead.status} ${adminDraftRead.text.slice(0, 160)}`);
const memberCannotManage = [];
for (const [method, route, body] of [
  ['PATCH', '/tournaments/c10p', { name: 'Member Renames' }],
  ['POST', '/tournaments/c10p/visibility', { visibility: 'private' }],
  ['POST', '/tournaments/c10p/publish', {}],
  ['POST', '/tournaments/c10p/unpublish', {}],
  ['DELETE', '/tournaments/c10p', { confirm_name: 'Glyfada Round 1' }]
]) {
  const answer = await call(method, route, { token: 'tok-member10', body });
  if (!(answer.status === 403 && answer.body?.error === 'not_a_club_admin')) {
    memberCannotManage.push(`${method} ${route} = ${answer.status}/${answer.body?.error}`);
  }
}
check('5g. a plain member may read and play but never rename, recategorise, publish or delete',
  memberCannotManage.length === 0, memberCannotManage.join(' | '));
const otherClubAdmin = [];
for (const [method, route, body] of [
  ['GET', '/tournaments/c10p', undefined],
  ['PATCH', '/tournaments/c10p', { name: 'Cross Club' }],
  ['POST', '/tournaments/c10p/publish', {}],
  ['DELETE', '/tournaments/c10p', { confirm_name: 'Glyfada Round 1' }]
]) {
  const answer = await call(method, route, { token: 'tok-admin11', ...(body === undefined ? {} : { body }) });
  // The admin of ANOTHER club is not a member of this one, and reads 403 club_scope_mismatch — with the
  // row's club from storage, not from the path.
  if (!(answer.status === 403 && answer.body?.error === 'club_scope_mismatch')) {
    otherClubAdmin.push(`${method} ${route} = ${answer.status}/${answer.body?.error}`);
  }
}
check('5h. a club admin of a DIFFERENT club reaches none of it (path id names a target, not a permission)',
  otherClubAdmin.length === 0, otherClubAdmin.join(' | '));
const strangerMember = await call('GET', '/tournaments/c10p', { token: 'tok-noclub' });
check('5i. a session with no club is refused a club set with not_a_club_member',
  strangerMember.status === 403 && strangerMember.body?.error === 'not_a_club_member',
  `${strangerMember.status} ${strangerMember.text.slice(0, 120)}`);
const pendingLikeNone = [];
const inactiveLikeNone = [];
for (const [label, token, bucket] of [
  ['pending admin-elect', 'tok-pending10', pendingLikeNone],
  ['approved member of an INACTIVE club', 'tok-inactive12', inactiveLikeNone]
]) {
  for (const [method, route, body] of [
    ['GET', '/tournaments/c10p', undefined],
    ['POST', '/tournaments/c10p/boards/1/start', { original_seat: 'North' }],
    ['POST', '/tournaments/c10p/publish', {}]
  ]) {
    const answer = await call(method, route, { token, ...(body === undefined ? {} : { body }) });
    bucket.push(`${answer.status}/${answer.body?.error}`);
  }
  void label;
}
check('5j. a PENDING club_admin row collapses to no-club (role is not the authority, approval is)',
  pendingLikeNone.every((answer) => answer === '403/not_a_club_member'), pendingLikeNone.join(','));
check('5k. an approved member of an INACTIVE club behaves exactly the same',
  inactiveLikeNone.every((answer) => answer === '403/not_a_club_member'), inactiveLikeNone.join(','));
const inactiveClubSet = await call('GET', '/tournaments/c12x', { token: 'tok-inactive12' });
check('5l. and the frozen club\u2019s own published set is invisible to its former members',
  inactiveClubSet.status === 403 && inactiveClubSet.body?.error === 'not_a_club_member',
  `${inactiveClubSet.status} ${inactiveClubSet.text.slice(0, 120)}`);
const superOnFrozen = await call('GET', '/tournaments/c12x', { token: SUPER_TOKEN });
check('5m. a system admin may still read the frozen club\u2019s set (they act for the field, not as a member)',
  superOnFrozen.status === 200, `${superOnFrozen.status} ${superOnFrozen.text.slice(0, 120)}`);
const adminImportsForOwnClub = await call('POST', '/tournaments', {
  token: 'tok-admin10',
  body: { name: 'Glyfada Round 9', visibility: 'club', club_id: '10', boards: [legalBoard(1), legalBoard(2)] }
});
check('5n. a club admin imports into their OWN club, and the row lands club-visible',
  adminImportsForOwnClub.status === 200 && adminImportsForOwnClub.body?.data?.visibility === 'club'
    && adminImportsForOwnClub.body.data.club_id === '10' && adminImportsForOwnClub.body.data.status === 'draft',
  `${adminImportsForOwnClub.status} ${adminImportsForOwnClub.text.slice(0, 200)}`);
const memberTriesClubImport = await call('POST', '/tournaments', {
  token: 'tok-member10', body: { name: 'Member Club Set', visibility: 'club', club_id: '10', boards: [legalBoard(1)] }
});
check('5o. a plain member importing a club set is refused loudly, never filed as private',
  memberTriesClubImport.status === 403 && memberTriesClubImport.body?.error === 'not_a_club_admin',
  `${memberTriesClubImport.status} ${memberTriesClubImport.text.slice(0, 120)}`);
const adminImportsForOtherClub = await call('POST', '/tournaments', {
  token: 'tok-admin10', body: { name: 'Cross Club Import', visibility: 'club', club_id: '11', boards: [legalBoard(1)] }
});
check('5p. a club admin cannot import INTO another club',
  adminImportsForOtherClub.status === 403 && adminImportsForOtherClub.body?.error === 'not_a_club_admin',
  `${adminImportsForOtherClub.status} ${adminImportsForOtherClub.text.slice(0, 120)}`);
const noClubNamed = await call('POST', '/tournaments', {
  token: 'tok-admin10', body: { name: 'Clubless Club Set', visibility: 'club', boards: [legalBoard(1)] }
});
check('5q. visibility=club with no club_id is 400 invalid_club_id (the row would name nobody)',
  noClubNamed.status === 400 && noClubNamed.body?.error === 'invalid_club_id', `${noClubNamed.status} ${noClubNamed.text.slice(0, 120)}`);
const clubRequiredRow = await call('GET', '/tournaments/orphan', { token: 'tok-admin10' });
check('5r. a club-visible row whose club_id is empty is refused as club_required, never read as public',
  clubRequiredRow.status === 403 && clubRequiredRow.body?.error === 'club_required',
  `${clubRequiredRow.status} ${clubRequiredRow.text.slice(0, 120)}`);

// ══ 6. T3 — THE PUBLIC FIELD: ANY SESSION READS IT, THE ADMIN OWNS IT ═══════
const publicRead = await ask('GET', '/tournaments/pubp', { token: 'tok-noclub' });
check('6a. any authenticated session reads a published public set',
  publicRead.status === 200 && publicRead.body?.data?.visibility === 'public', `${publicRead.status} ${publicRead.text.slice(0, 120)}`);
const publicStart = await ask('POST', '/tournaments/pubp/boards/1/start', { token: 'tok-noclub', body: { original_seat: 'West' } });
check('6b. and may start one of its boards',
  publicStart.status === 200 && publicStart.body?.data?.original_seat === 'West', `${publicStart.status} ${publicStart.text.slice(0, 160)}`);
const publicDraft = await ask('GET', '/tournaments/pubd', { token: 'tok-member10' });
check('6c. an unpublished public set is invisible to everyone but the admin',
  publicDraft.status === 403 && publicDraft.body?.error === 'tournament_not_published',
  `${publicDraft.status} ${publicDraft.text.slice(0, 120)}`);
const adminSeesPublicDraft = await call('GET', '/tournaments/pubd', { token: SUPER_TOKEN });
check('6d. the BridgeMind Admin reads their own field\u2019s draft',
  adminSeesPublicDraft.status === 200 && adminSeesPublicDraft.body.data.status === 'draft',
  `${adminSeesPublicDraft.status} ${adminSeesPublicDraft.text.slice(0, 120)}`);
const publicManagement = [];
for (const [method, route, body] of [
  ['PATCH', '/tournaments/pubp', { name: 'Renamed By Nobody' }],
  ['POST', '/tournaments/pubp/publish', {}],
  ['POST', '/tournaments/pubp/unpublish', {}],
  ['DELETE', '/tournaments/pubp', { confirm_name: 'Autumn Open' }],
  ['POST', '/tournaments/pubp/visibility', { visibility: 'private' }]
]) {
  const answer = await call(method, route, { token: 'tok-member10', body });
  if (!(answer.status === 403 && answer.body?.error === 'super_admin_required')) {
    publicManagement.push(`${method} ${route} = ${answer.status}/${answer.body?.error}`);
  }
}
check('6e. no ordinary account manages the public field (five verbs, one named reason)',
  publicManagement.length === 0, publicManagement.join(' | '));
const impersonatorImport = await call('POST', '/tournaments', {
  token: 'tok-impersonator', body: { name: 'Role Is Not The Authority', visibility: 'public', boards: [legalBoard(1)] }
});
check('6f. an NCB `administrator` role with no system_admins row is NOT the BridgeMind Admin',
  impersonatorImport.status === 403 && impersonatorImport.body?.error === 'super_admin_required',
  `${impersonatorImport.status} ${impersonatorImport.text.slice(0, 120)}`);
const impersonatorList = await call('GET', '/tournaments', { token: 'tok-impersonator' });
check('6g. and the same row-invisible account sees the published public sets like anybody else',
  impersonatorList.status === 200 && impersonatorList.body.data.tournaments.some((row) => row.id === 'pubp')
    && impersonatorList.body.data.tournaments.every((row) => row.id !== 'pubd'),
  JSON.stringify(impersonatorList.body?.data?.tournaments?.map((row) => row.id)));
const adminImportsPublic = await call('POST', '/tournaments', {
  token: SUPER_TOKEN, body: { name: 'Winter Open', visibility: 'public', boards: [legalBoard(1)] }
});
check('6h. the admin imports a public set, and it lands as a draft (import never publishes)',
  adminImportsPublic.status === 200 && adminImportsPublic.body.data.visibility === 'public'
    && adminImportsPublic.body.data.status === 'draft',
  `${adminImportsPublic.status} ${adminImportsPublic.text.slice(0, 160)}`);
// The list scope, measured as data: a public list must never carry a private or club row, and the row
// that decides this is the server's clause, not the caller's filter.
const scopedList = await call('GET', '/tournaments?visibility=public', { token: 'tok-noclub' });
check('6i. `?visibility=public` returns ONLY published public rows for an ordinary session',
  scopedList.status === 200 && scopedList.body.data.tournaments.length > 0
    && scopedList.body.data.tournaments.every((row) => row.visibility === 'public' && row.status === 'published'),
  JSON.stringify(scopedList.body?.data?.tournaments?.map((row) => `${row.id}:${row.visibility}:${row.status}`)));
const adminListWide = await call('GET', '/tournaments', { token: SUPER_TOKEN });
check('6j. the admin\u2019s list carries every public row including the drafts, and nothing private',
  adminListWide.status === 200 && adminListWide.body.data.tournaments.some((row) => row.id === 'pubd')
    && adminListWide.body.data.tournaments.every((row) => row.visibility !== 'private'),
  JSON.stringify(adminListWide.body?.data?.tournaments?.map((row) => row.id)));

// ══ 7. THE MEMBERSHIP BRIDGE IS THE CLUB STORE, AND ITS FAILURE IS A 503 ═════
// Each of these arms drives a real authority read into a refusal at the mock, and asserts the knob fired
// (the call was seen) — a 503 measured against a read that never happened would be a false green.
function clubCallSeen(fragment) {
  return dataCalls.some((entry) => entry.pathname.startsWith('/data/') && entry.search.includes(fragment));
}
mock.refuseRead = {
  table: 'club_memberships', fragment: 'member_user_id=3',
  status: 500, body: { status: 'failed', error: 'membership read refused' }
};
const membershipDown = await call('GET', '/tournaments/c10p', { token: 'tok-member10' });
check('7a. an unreadable membership answers 503 with a named reason — never "not a member"',
  membershipDown.status === 503 && membershipDown.body?.error === 'club_store_unavailable'
    && clubCallSeen('user_id=3'),
  `${membershipDown.status} ${membershipDown.text.slice(0, 140)}`);
mock.refuseRead = null;

mock.refuseRead = {
  table: 'clubs', fragment: 'id=10',
  status: 500, body: { status: 'failed', error: 'club read refused' }
};
// The club store's `clubStatus` cannot distinguish "no such club" from "the read failed" (its own
// `one()` collapses both to null), so a failed activity read collapses the caller to NO CLUB — which is
// exactly what the club feature does, and is the safe direction. What this arm therefore measures is that
// a broken activity read never GRANTS anything: the answer is the same 403 a no-club user gets, never a
// 200 and never an "admin" answer. Restating it as a 503 would have pinned a behaviour the reused store
// does not have.
const clubStatusDown = await call('GET', '/tournaments/c10p', { token: 'tok-member10' });
const noClubAnswer = await call('GET', '/tournaments/c10p', { token: 'tok-noclub' });
check('7b. an unreadable club record never grants access — the caller is answered as a no-club user',
  clubStatusDown.status === 403 && clubStatusDown.body?.error === 'not_a_club_member'
    && clubCallSeen('id=10')
    && `${clubStatusDown.status}/${clubStatusDown.body?.error}` === `${noClubAnswer.status}/${noClubAnswer.body?.error}`,
  `${clubStatusDown.status}/${clubStatusDown.body?.error} vs no-club ${noClubAnswer.status}/${noClubAnswer.body?.error}`);
mock.refuseRead = null;

mock.refuseRead = {
  table: 'system_admins', fragment: 'admin_user_id=3',
  status: 500, body: { status: 'failed', error: 'admin read refused' }
};
const adminDown = await call('GET', '/tournaments/c10p', { token: 'tok-member10' });
check('7c. an unreadable system_admins verdict is 503, never "you are not the admin"',
  adminDown.status === 503 && adminDown.body?.error === 'club_store_unavailable'
    && clubCallSeen('user_id=3'),
  `${adminDown.status} ${adminDown.text.slice(0, 140)}`);
mock.refuseRead = null;

// The row read itself. A tournament header that cannot be read is not "no such tournament".
mock.refuseRead = {
  table: 'tournaments', fragment: 'id=c10p',
  status: 500, body: { status: 'failed', error: 'header read refused' }
};
const headerDown = await call('GET', '/tournaments/c10p', { token: 'tok-member10' });
check('7d. an unreadable tournament row is a 503, not a 404 that hides a storage fault',
  headerDown.status === 503 && headerDown.body?.error === 'club_store_unavailable'
    && clubCallSeen('id=c10p'),
  `${headerDown.status} ${headerDown.text.slice(0, 140)}`);
mock.refuseRead = null;

// A list read that comes back as something other than a row set must not become an empty success. This
// is the exact bug the club list had; the arm reproduces the shape, not the story.
mock.emptyReadTables = 'tournaments';
const unreadableList = await call('GET', '/tournaments', { token: 'tok-member10' });
check('7e. a list read whose body is not a row set answers 503, never `data: []`',
  unreadableList.status === 503 && unreadableList.body?.error === 'tournament_read_unreadable'
    && dataCalls.some((entry) => entry.pathname === '/data/read/tournaments'),
  `${unreadableList.status} ${unreadableList.text.slice(0, 160)}`);
mock.emptyReadTables = null;
const healthyListAgain = await call('GET', '/tournaments', { token: 'tok-member10' });
check('7f. and the same route serves rows again once the read is well-formed (the knob, not the code)',
  healthyListAgain.status === 200 && healthyListAgain.body.data.tournaments.length > 0,
  `${healthyListAgain.status} ${healthyListAgain.text.slice(0, 120)}`);

// THE STORE NEVER RIDES THE CALLER'S BEARER. The mock refuses any /data call without the service
// account's bearer, so a caller-bearer fallback anywhere would have reddened every arm above. Asserted
// directly as well: no tournament data call in this whole run carried a caller's token.
const callerBearerCalls = dataCalls.filter((entry) => entry.pathname.startsWith('/data/') && entry.bearer !== CLUB_SESSION_TOKEN);
check('7g. no authority read or write ever went to NCB on a caller\u2019s bearer',
  callerBearerCalls.length === 0,
  callerBearerCalls.slice(0, 3).map((entry) => `${entry.pathname} ${entry.bearer}`).join(' | '));
check('7h. the service account is the identity that reads tournament storage',
  dataCalls.some((entry) => entry.pathname === '/data/read/tournaments' && entry.bearer === CLUB_SESSION_TOKEN),
  'no club-bearer tournament read was seen');
// ══ 8. THE IMPORT IS ALL-OR-NOTHING, AND THE CLEANUP IS MEASURED ════════════
// These arms run the REAL store over a scripted rig, because "no partial tournament is ever readable"
// is a claim about the SEQUENCE of writes and deletes. An HTTP arm cannot show that a compensating delete
// ran in the right order against the right rows; the rig can, and it can fail exactly one call.
function makeRig({ rows, fail = null, breakReadBack = null } = {}) {
  const registry = {};
  for (const [name, spec] of Object.entries(rows)) {
    registry[name] = { columns: spec.columns, uniques: spec.uniques ?? [], rows: (spec.rows ?? []).map((row) => ({ ...row })) };
  }
  const log = [];
  let seq = 1000;
  const client = {
    configured: true,
    async request(spec) {
      log.push(spec);
      // `spec.path` is ALREADY relative (`read/tournaments?…`) — the account client puts the group in the
      // URL, not in the spec. Splitting it like a proxy pathname would shift every field by one and the
      // rig would answer "unknown table undefined" for calls the real mock serves fine.
      const [rawPath, rawQuery] = String(spec.path).split('?');
      const [action, table, rowId] = rawPath.split('/').filter(Boolean);
      const entry = registry[table];
      if (!entry) return { ok: false, reason: 'club_account_request_failed', detail: `unknown table ${table}` };
      const query = new URLSearchParams(rawQuery ?? '');
      if (action === 'read') {
        const filters = {};
        for (const [key, value] of query.entries()) {
          if (RESERVED_QUERY.includes(key)) continue;
          if (!entry.columns.includes(key)) return { ok: false, reason: 'club_account_request_failed', detail: `Unknown column '${key}'` };
          filters[key] = value;
        }
        let found = entry.rows.filter((row) => Object.entries(filters).every(([column, value]) => String(row[column] ?? '') === value));
        if (typeof breakReadBack === 'function') found = breakReadBack(table, found, log.length);
        const limit = Number(query.get('limit'));
        if (Number.isFinite(limit) && limit > 0) found = found.slice(0, Math.floor(limit));
        return { ok: true, body: { status: 'success', data: found.map((row) => ({ ...row })) } };
      }
      if (action === 'create') {
        if (typeof fail === 'function') {
          const stop = fail(table, spec.body, log.length);
          if (stop) return { ok: false, reason: 'club_account_request_failed', detail: stop };
        }
        for (const unique of entry.uniques) {
          const values = unique.fields.map((field) => spec.body[field]);
          if (unique.ignoreNull && values.some((value) => value === undefined || value === null || value === '')) continue;
          if (entry.rows.some((row) => unique.fields.every((field, index) => String(row[field] ?? '') === String(values[index])))) {
            return { ok: false, reason: 'club_account_request_failed', detail: `Duplicate entry for key '${unique.name}'` };
          }
        }
        const row = { id: String(++seq), ...spec.body };
        entry.rows.push(row);
        return { ok: true, body: { status: 'success', data: { ...row } } };
      }
      if (action === 'update') {
        const row = entry.rows.find((candidate) => String(candidate.id) === String(rowId));
        if (!row) return { ok: false, reason: 'club_account_request_failed', detail: 'no such row' };
        Object.assign(row, spec.body);
        return { ok: true, body: { status: 'success', data: { ...row } } };
      }
      if (action === 'delete') {
        if (typeof fail === 'function') {
          const stop = fail(`delete:${table}`, null, log.length);
          if (stop) return { ok: false, reason: 'club_account_request_failed', detail: stop };
        }
        const index = entry.rows.findIndex((candidate) => String(candidate.id) === String(rowId));
        if (index === -1) return { ok: false, reason: 'club_account_request_failed', detail: 'no such row' };
        entry.rows.splice(index, 1);
        return { ok: true, body: { status: 'success', data: { id: rowId } } };
      }
      return { ok: false, reason: 'club_account_request_failed', detail: `unexpected ${action}` };
    },
    registry
  };
  return { client, log, registry };
}
const TOURNAMENT_COLUMNS = MAIN_TOURNAMENT_SCHEMA.columns;
// The rig enforces the SAME three uniqueness rules the migration ask states, so a duplicate arm fails
// for the right reason instead of passing because the fake store silently allowed two rows.
const RIG_UNIQUES = {
  tournaments: [{ fields: [TOURNAMENT_COLUMNS.tournaments.dedupeKey], name: 'dedupe_key', ignoreNull: true }],
  tournament_boards: [{ fields: [TOURNAMENT_COLUMNS.boards.tournamentId, TOURNAMENT_COLUMNS.boards.boardNumber], name: 'tournament_id_board_number', composite: true }],
  tournament_attempts: [{ fields: [TOURNAMENT_COLUMNS.attempts.recordedHandId], name: 'recorded_hand_id', ignoreNull: true }]
};
function emptyRows() {
  return {
    tournaments: { columns: Object.values(TOURNAMENT_COLUMNS.tournaments), uniques: RIG_UNIQUES.tournaments, rows: [] },
    tournament_boards: { columns: Object.values(TOURNAMENT_COLUMNS.boards), uniques: RIG_UNIQUES.tournament_boards, rows: [] },
    tournament_attempts: { columns: Object.values(TOURNAMENT_COLUMNS.attempts), uniques: RIG_UNIQUES.tournament_attempts, rows: [] }
  };
}
const quietBridge = {
  getMembership: async () => null,
  clubStatus: async () => null,
  isSystemAdmin: async () => ({ declared: true, available: true, isAdmin: false })
};
function rigStore(options) {
  const rig = makeRig(options);
  const store = createTournamentNcbStore({ client: rig.client, schema: goodSchema.schema, clubBridge: quietBridge });
  return { rig, store };
}
const twoBoards = [legalBoard(1), legalBoard(2)];

const happy = rigStore({ rows: emptyRows() });
const happyResult = await happy.store.importTournament({
  ownerId: '3', clubId: null, visibility: 'private', name: 'Happy Path', sourceLabel: 'pbn', dedupeKey: null, boards: twoBoards
});
const happyWrites = happy.rig.log.filter((spec) => String(spec.path).startsWith('create/tournaments'));
const happyHeader = JSON.parse(JSON.stringify(happyWrites[0]?.body ?? {}));
check('8a. a clean import writes a DRAFT header naming the session id as owner, then one row per board',
  happyResult.status === 'draft' && happyResult.verified === true && happyResult.board_count === 2
    && happyHeader[TOURNAMENT_COLUMNS.tournaments.status] === 'draft'
    && happyHeader[TOURNAMENT_COLUMNS.tournaments.userId] === '3'
    && happyWrites.length === 1
    && happy.rig.registry.tournament_boards.rows.length === 2,
  JSON.stringify({ happyResult, happyHeader, calls: happy.rig.log.length }));
check('8b. an import NEVER publishes (no status update is issued, so a half-trusted flag cannot leak)',
  !happy.rig.log.some((spec) => String(spec.path).startsWith('update/tournaments')),
  happy.rig.log.map((spec) => spec.path).join(' | '));
check('8c. club_id and dedupe_key are OMITTED for a keyless private import, never sent as empty strings',
  !(TOURNAMENT_COLUMNS.tournaments.clubId in happyHeader)
    && !(TOURNAMENT_COLUMNS.tournaments.dedupeKey in happyHeader),
  JSON.stringify(happyHeader));

const failing = rigStore({
  rows: emptyRows(),
  fail: (table, body) => (table === 'tournament_boards' && String(body[TOURNAMENT_COLUMNS.boards.boardNumber]) === '2'
    ? 'simulated write failure mid-import' : null)
});
const failedImport = await failing.store.importTournament({
  ownerId: '3', clubId: null, visibility: 'private', name: 'Half Written', sourceLabel: null, dedupeKey: null, boards: twoBoards
});
check('8d. a board write that fails produces import_incomplete naming the board',
  failedImport.error === 'import_incomplete'
    && JSON.stringify(failedImport.failedBoardNumbers) === JSON.stringify(['2']),
  JSON.stringify(failedImport));
check('8e. the compensating delete removed BOTH the landed board and the draft header',
  failing.rig.registry.tournament_boards.rows.length === 0
    && failing.rig.registry.tournaments.rows.length === 0
    && failing.rig.log.filter((spec) => String(spec.path).startsWith('delete/')).length >= 2,
  `boards ${failing.rig.registry.tournament_boards.rows.length} headers ${failing.rig.registry.tournaments.rows.length}`);
check('8f. no partial tournament is left readable by the account that owns it',
  (await failing.store.listTournaments({ clauses: [{ [TOURNAMENT_COLUMNS.tournaments.visibility]: 'private', [TOURNAMENT_COLUMNS.tournaments.userId]: '3' }] })).tournaments.length === 0,
  JSON.stringify(failing.rig.registry.tournaments.rows));
check('8g. the failure answer carries no id to publish (a caller cannot be tempted on a dead row)',
  failedImport.tournamentId === null && failedImport.published === false,
  JSON.stringify({ id: failedImport.tournamentId, published: failedImport.published }));

// The rig lies about exactly ONE read and is truthful afterwards, so this arm measures what it claims:
// a verification read that disagrees with the writes. A permanent filter would also blind the store's
// post-cleanup re-read, and the arm would then be reporting the harness's own blindness as leftovers.
let liedOnce = false;
const mismatch = rigStore({
  rows: emptyRows(),
  breakReadBack: (table, found) => {
    if (table === 'tournament_boards' && !liedOnce && found.length > 1) {
      liedOnce = true;
      return found.slice(0, 1);
    }
    return found;
  }
});
const mismatchResult = await mismatch.store.importTournament({
  ownerId: '3', clubId: null, visibility: 'private', name: 'Lied About', sourceLabel: null, dedupeKey: null, boards: twoBoards
});
// What the store can delete is what its read showed it. The lie made exactly one of the two written rows
// visible, so the cleanup removed that one and the other STAYS — and the honest claim is that the answer
// says so. Asserting an empty table here would demand the store delete a row nothing told it about, and
// asserting "cleaned up" would be the false green this whole file exists to refuse.
const mismatchDetail = String(mismatchResult.detail ?? '');
const mismatchLeftoverId = String(mismatch.rig.registry.tournament_boards.rows[0]?.id ?? '');
check('8h. a read-back that disagrees is import_unverified, removes the header, and names what it left',
  mismatchResult.error === 'import_unverified'
    && mismatch.rig.registry.tournaments.rows.length === 0
    && mismatch.rig.registry.tournament_boards.rows.length === 1
    && liedOnce === true && mismatchLeftoverId !== '' && mismatchDetail.includes(mismatchLeftoverId),
  `${mismatchResult.error} headers=${mismatch.rig.registry.tournaments.rows.length} boards=${mismatch.rig.registry.tournament_boards.rows.length} | ${mismatchDetail.slice(0, 200)}`);

const dupe = rigStore({
  rows: {
    tournaments: {
      columns: Object.values(TOURNAMENT_COLUMNS.tournaments),
      uniques: RIG_UNIQUES.tournaments,
      rows: [{ id: 'first', [TOURNAMENT_COLUMNS.tournaments.userId]: '3', [TOURNAMENT_COLUMNS.tournaments.name]: 'First', [TOURNAMENT_COLUMNS.tournaments.visibility]: 'private', [TOURNAMENT_COLUMNS.tournaments.status]: 'draft', [TOURNAMENT_COLUMNS.tournaments.boardCount]: 1, [TOURNAMENT_COLUMNS.tournaments.dedupeKey]: 'K1' }]
    },
    tournament_boards: { columns: Object.values(TOURNAMENT_COLUMNS.boards), uniques: RIG_UNIQUES.tournament_boards, rows: [] },
    tournament_attempts: { columns: Object.values(TOURNAMENT_COLUMNS.attempts), uniques: RIG_UNIQUES.tournament_attempts, rows: [] }
  }
});
const dupeResult = await dupe.store.importTournament({
  ownerId: '3', clubId: null, visibility: 'private', name: 'Second', sourceLabel: null, dedupeKey: 'K1', boards: twoBoards
});
check('8i. a colliding dedupe_key is duplicate_import, not a silent second copy',
  dupeResult.error === 'duplicate_import', JSON.stringify(dupeResult));
check('8j. a duplicate import deletes NOTHING — the row that collided belongs to an earlier import',
  dupe.rig.registry.tournaments.rows.length === 1 && rowExists(dupe.rig, 'first')
    && !dupe.rig.log.some((spec) => String(spec.path).startsWith('delete/')),
  dupe.rig.log.map((spec) => spec.path).join(' | '));
function rowExists(rig, id) {
  return rig.registry.tournaments.rows.some((row) => String(row.id) === id);
}

// The composite unique, measured both ways. These two arms are the negative control that keeps the mock
// honest: if its board constraint were spelled as two single-column uniques, 8k would go red.
const crossReuse = await call('POST', '/tournaments', {
  token: SUPER_TOKEN, body: { name: 'Movement A', visibility: 'public', boards: [legalBoard(1), legalBoard(2)] }
});
const crossReuseB = await call('POST', '/tournaments', {
  token: SUPER_TOKEN, body: { name: 'Movement B', visibility: 'public', boards: [legalBoard(1), legalBoard(2)] }
});
check('8k. the SAME board numbers in TWO tournaments is accepted (the unique is a pair, not one column)',
  crossReuse.status === 200 && crossReuseB.status === 200
    && crossReuseB.body.data.board_count === 2
    && crossReuse.body.data.id !== crossReuseB.body.data.id,
  `${crossReuse.status}/${crossReuseB.status} ${crossReuseB.text.slice(0, 140)}`);
const repeatInside = await call('POST', '/tournaments', {
  token: SUPER_TOKEN, body: { name: 'Repeated Number', visibility: 'public', boards: [legalBoard(1), legalBoard(1)] }
});
check('8l. a board number repeated INSIDE one import is refused before any row exists',
  repeatInside.status === 400 && repeatInside.body?.error === 'duplicate_board_number'
    && !rowsOf('tournaments').some((row) => row.name === 'Repeated Number'),
  `${repeatInside.status} ${repeatInside.text.slice(0, 140)}`);
// A stored pair that duplicates anyway (a broken index in production) must be REFUSED as a board list,
// not resolved by picking one row.
REGISTRY.tournament_boards.rows.push(boardRow('c10d', 1, { id: 'dupe-board' }));
const duplicatedBoards = await call('GET', '/tournaments/c10d/boards', { token: 'tok-admin10' });
check('8m. two rows for one (tournament, board number) is a refusal, never an arbitrary pick',
  duplicatedBoards.status === 422 && duplicatedBoards.body?.error === 'duplicate_board_number',
  `${duplicatedBoards.status} ${duplicatedBoards.text.slice(0, 140)}`);
REGISTRY.tournament_boards.rows = REGISTRY.tournament_boards.rows.filter((row) => row.id !== 'dupe-board');
const ambiguousStart = REGISTRY.tournament_boards.rows.push(boardRow('c10p', 3, { id: 'dupe-start' }));
const startedAmbiguous = await call('POST', '/tournaments/c10p/boards/3/start', { token: 'tok-member10', body: { original_seat: 'North' } });
check('8n. and an ambiguous board is never started — a 503, not one of the two deals at random',
  startedAmbiguous.status === 503 && /ambiguous|could not be read/.test(startedAmbiguous.text),
  `${startedAmbiguous.status} ${startedAmbiguous.text.slice(0, 160)}`);
void ambiguousStart;
REGISTRY.tournament_boards.rows = REGISTRY.tournament_boards.rows.filter((row) => row.id !== 'dupe-start');

// A cleanup that itself fails must be REPORTED, not trusted.
const stuckCleanup = rigStore({
  rows: emptyRows(),
  fail: (table, body) => (table === 'tournament_boards' && String(body?.[TOURNAMENT_COLUMNS.boards.boardNumber] ?? '') === '2'
    ? 'simulated write failure mid-import'
    : (table === 'delete:tournament_boards' ? 'delete refused' : null))
});
const stuckResult = await stuckCleanup.store.importTournament({
  ownerId: '3', clubId: null, visibility: 'private', name: 'Stuck', sourceLabel: null, dedupeKey: null, boards: twoBoards
});
check('8o. when the compensating delete is refused, the answer SAYS so instead of claiming a rollback',
  stuckResult.error === 'import_incomplete' && /left .*dupe|left \d|REMAINS|left /.test(stuckResult.detail)
    && stuckCleanup.rig.registry.tournament_boards.rows.length > 0,
  JSON.stringify(stuckResult).slice(0, 300));

// ── publish is gated on verification, measured over HTTP ────────────────────
const emptySet = rowOf('tournaments', 'c10d');
void emptySet;
REGISTRY.tournaments.rows.push({
  id: 'empty1', owner_user_id: '2', club_id: '10', name: 'No Boards', visibility: 'club', status: 'draft',
  board_count: 1, source_label: null, dedupe_key: null
});
const publishEmpty = await call('POST', '/tournaments/empty1/publish', { token: 'tok-admin10', body: {} });
check('8p. publishing a set with no readable board rows is refused 422 publish_refused_unverified',
  publishEmpty.status === 422 && publishEmpty.body?.error === 'publish_refused_unverified'
    && rowOf('tournaments', 'empty1').status === 'draft',
  `${publishEmpty.status} ${publishEmpty.text.slice(0, 160)}`);
REGISTRY.tournament_boards.rows.push({
  id: 'bad-hands', tournament_id: 'empty1', board_number: '1', dealer: 'North', vulnerability: 'None',
  hands_json: '{"North":["AS"]}', tags_json: null
});
const publishCorrupt = await call('POST', '/tournaments/empty1/publish', { token: 'tok-admin10', body: {} });
check('8q. a stored board that no longer validates blocks the publish (a corrupted row cannot be released)',
  publishCorrupt.status === 422 && publishCorrupt.body?.error === 'publish_refused_unverified'
    && /board 1/.test(String(publishCorrupt.body?.detail)),
  `${publishCorrupt.status} ${publishCorrupt.text.slice(0, 200)}`);
REGISTRY.tournament_boards.rows = REGISTRY.tournament_boards.rows.filter((row) => row.id !== 'bad-hands');
// Now the count-mismatch branch: ONE board reads back while the header claims TWO. With zero rows the
// store answers the earlier "no board row could be read back" path instead, and this arm would have
// measured that other branch while claiming to measure this one.
REGISTRY.tournament_boards.rows.push(boardRow('empty1', 1, { id: 'only-1' }));
REGISTRY.tournaments.rows.find((row) => row.id === 'empty1').board_count = 2;
const publishCountLie = await call('POST', '/tournaments/empty1/publish', { token: 'tok-admin10', body: {} });
check('8r. a header whose board_count disagrees with the rows is refused too',
  publishCountLie.status === 422 && /says 2 board/.test(String(publishCountLie.body?.detail))
    && rowOf('tournaments', 'empty1').status === 'draft',
  `${publishCountLie.status} ${publishCountLie.text.slice(0, 200)}`);
REGISTRY.tournaments.rows.find((row) => row.id === 'empty1').board_count = 1;
const publishNow = await call('POST', '/tournaments/empty1/publish', { token: 'tok-admin10', body: {} });
check('8s. once the board set reads back complete, the SAME publish succeeds (the gate, not a grudge)',
  publishNow.status === 200 && publishNow.body?.data?.status === 'published',
  `${publishNow.status} ${publishNow.text.slice(0, 160)}`);
const unpublish = await call('POST', '/tournaments/empty1/unpublish', { token: 'tok-admin10', body: {} });
check('8t. unpublish returns the set to draft, and the member\'s view closes again',
  unpublish.status === 200 && unpublish.body?.data?.status === 'draft'
    && (await call('GET', '/tournaments/empty1', { token: 'tok-member10' })).status === 403,
  `${unpublish.status} ${unpublish.text.slice(0, 140)}`);
REGISTRY.tournaments.rows = REGISTRY.tournaments.rows.filter((row) => row.id !== 'empty1');
REGISTRY.tournament_boards.rows = REGISTRY.tournament_boards.rows.filter((row) => row.tournament_id !== 'empty1');

// ── board validation on the way in ──────────────────────────────────────────
const badBoardArms = [
  ['8u. 101 boards is refused with too_many_boards', [legalBoard(1), ...Array.from({ length: 100 }, (_, i) => legalBoard(i + 2))], 'too_many_boards'],
  ['8v. an empty board list is refused with no_boards', [], 'no_boards'],
  ['8w. a board with 14 cards in one seat is refused (a total-only check would pass it)',
    [{ ...legalBoard(1), hands: { ...dealHands(0), North: [...dealHands(0).North, '2S'] } }], 'incomplete_hands'],
  ['8x. a repeated card across two seats is refused', [{
    ...legalBoard(1),
    hands: { North: dealHands(0).North, East: [...dealHands(0).East.slice(1), dealHands(0).North[0]], South: dealHands(0).South, West: dealHands(0).West }
  }], 'incomplete_hands'],
  ['8y. the wire spelling "All" for vulnerability is refused, not normalised', [{ ...legalBoard(1), vulnerability: 'All' }], 'invalid_vulnerability'],
  ['8z. a dealer outside the four seats is refused', [{ ...legalBoard(1), dealer: 'Z' }], 'invalid_dealer'],
  ['8aa. a card token the deck cannot contain is refused', [{
    ...legalBoard(1), hands: { ...dealHands(0), North: dealHands(0).North.map((card, i) => (i === 0 ? '1S' : card)) }
  }], 'incomplete_hands']
];
for (const [label, boards, reason] of badBoardArms) {
  const before = rowsOf('tournament_boards').length;
  const answer = await call('POST', '/tournaments', { token: SUPER_TOKEN, body: { name: 'Bad Boards', visibility: 'public', boards } });
  check(`${label} (reason ${reason})`,
    answer.status === 400 && answer.body?.error === reason && rowsOf('tournament_boards').length === before
      && !rowsOf('tournaments').some((row) => row.name === 'Bad Boards'),
    `${answer.status}/${answer.body?.error} rows ${before}->${rowsOf('tournament_boards').length}`);
}
const tagsKept = await call('POST', '/tournaments', {
  token: SUPER_TOKEN,
  body: { name: 'With Tags', visibility: 'public', boards: [{ ...legalBoard(1), tags: { contract: '3NT', declarer: 'S', result: '+1' } }] }
});
const tagsRow = boardsOf(String(tagsKept.body?.data?.id ?? ''))[0];
check('8ab. the source [Contract]/[Declarer]/[Result] metadata is stored as history and echoed back',
  tagsKept.status === 200 && tagsRow?.tags_json === JSON.stringify({ contract: '3NT', declarer: 'S', result: '+1' }),
  `${tagsKept.status} ${JSON.stringify(tagsRow?.tags_json)}`);
const tagsStarted = await call('POST', `/tournaments/${tagsKept.body?.data?.id}/boards/1/start`, { token: 'tok-noclub', body: { original_seat: 'North' } });
check('8ab2. an imported public set starts as a DRAFT, so it is not playable before a publish',
  tagsStarted.status === 403 && tagsStarted.body?.error === 'tournament_not_published',
  `${tagsStarted.status} ${tagsStarted.text.slice(0, 140)}`);
const tagsPublished = await call('POST', `/tournaments/${tagsKept.body?.data?.id}/publish`, { token: SUPER_TOKEN, body: {} });
const tagsStartedLive = await call('POST', `/tournaments/${tagsKept.body?.data?.id}/boards/1/start`, { token: 'tok-noclub', body: { original_seat: 'North' } });
check('8ac. and those tags NEVER reach the table as a playable auction (start carries no contract)',
  tagsPublished.status === 200 && tagsStartedLive.status === 200
    && !('contract' in (tagsStartedLive.body?.data ?? {}))
    && !('auction' in (tagsStartedLive.body?.data ?? {})) && tagsStartedLive.body.data.tags?.contract === '3NT',
  JSON.stringify(tagsStartedLive.body?.data ?? {}).slice(0, 220));
REGISTRY.tournaments.rows = REGISTRY.tournaments.rows.filter((row) => row.name !== 'With Tags');
REGISTRY.tournament_boards.rows = REGISTRY.tournament_boards.rows.filter((row) => String(row.tournament_id) !== String(tagsKept.body?.data?.id));

// ══ 9. START RETURNS THE SERVER'S RECORD; ATTEMPTS ARE SELF-SCOPED ══════════
const storedBoard = boardsOf('c10p').find((row) => row.board_number === '2');
const started = await ask('POST', '/tournaments/c10p/boards/2/start', { token: 'tok-member10', body: { original_seat: 'South' } });
check('9a. start returns the STORED dealer, vulnerability, hands and board number',
  started.status === 200 && started.body.data.dealer === storedBoard.dealer
    && started.body.data.vulnerability === storedBoard.vulnerability
    && started.body.data.board_number === '2'
    && JSON.stringify(started.body.data.hands) === JSON.stringify(JSON.parse(storedBoard.hands_json)),
  `${started.status} ${started.text.slice(0, 180)}`);
check('9b. and it names the caller\'s seat plus the row it came from, so the engine plays a record',
  started.body.data.original_seat === 'South' && started.body.data.tournament_id === 'c10p'
    && started.body.data.club_id === '10',
  JSON.stringify(started.body?.data ?? {}).slice(0, 200));
const allFourDeals = new Set(boardsOf('c10p').map((row) => row.dealer));
check('9c. the seeded set spans dealers, so 9a could not have passed on a constant',
  allFourDeals.size >= 2, [...allFourDeals].join(','));

const mineAttempt = await call('POST', '/tournaments/pubp/attempts', {
  token: 'tok-member10', body: { board_number: '2', original_seat: 'South', recorded_hand_id: 'rh-new-3' }
});
const attemptRow = rowsOf('tournament_attempts').find((row) => row.recorded_hand_id === 'rh-new-3');
check('9d. an attempt records the SESSION id into the player column, and the board and seat it names',
  mineAttempt.status === 200 && attemptRow?.player_user_id === '3' && attemptRow?.board_number === '2'
    && attemptRow?.original_seat === 'South' && attemptRow?.tournament_id === 'pubp',
  `${mineAttempt.status} ${JSON.stringify(attemptRow)}`);
// The ownership separation, measured on the row rather than asserted in prose: the application player is
// recorded in its OWN column, and nothing the caller could send has landed in NCB's row-ownership slot.
// The real production property, which the old predicate could not express: NCB ALWAYS stamps the
// ownership slot from the writing session, so what must hold is that the slot never carries the
// player and never comes from the request. Proving `user_id` was merely absent would only have
// proved the mock leaves it alone; proving it carries the service account WHILE the application
// column carries the player is what proves the two are never conflated.
check('9d2. the attempt row keeps the application player out of NCB\'s user_id slot, which holds the writing service account',
  !!attemptRow && attemptRow.user_id === CLUB_ACCOUNT_ID
    && String(attemptRow[TOURNAMENT_COLUMNS.attempts.userId]) === '3'
    && attemptRow.user_id !== attemptRow[TOURNAMENT_COLUMNS.attempts.userId],
  JSON.stringify(attemptRow).slice(0, 160));
check('9d3. no store call ever sent NCB\'s ownership column in a body, so the stamp is the vendor\'s and not ours',
  mock.ownershipWrites.length === 0, JSON.stringify(mock.ownershipWrites.slice(0, 3)));
const myAttempts = await call('GET', '/tournaments/pubp/attempts', { token: 'tok-member10' });
const otherAttempts = await call('GET', '/tournaments/pubp/attempts', { token: 'tok-member11' });
check('9e. the attempts list is self-scoped on a set BOTH can read: each sees only their own rows',
  myAttempts.status === 200 && otherAttempts.status === 200
    && myAttempts.body.data.attempts.length === 2
    && myAttempts.body.data.attempts.every((row) => row.user_id === '3')
    && myAttempts.body.data.attempts.some((row) => row.recorded_hand_id === 'rh-new-3')
    && otherAttempts.body.data.attempts.length === 1
    && otherAttempts.body.data.attempts.every((row) => row.user_id === '4')
    && !otherAttempts.body.data.attempts.some((row) => row.recorded_hand_id === 'rh-3-1'),
  JSON.stringify({ mine: myAttempts.body?.data?.attempts?.map((r) => r.recorded_hand_id), theirs: otherAttempts.body?.data?.attempts?.map((r) => r.recorded_hand_id) }));
const boardFiltered = await call('GET', '/tournaments/pubp/attempts?board_number=1', { token: 'tok-member11' });
check('9f. board_number narrows the self-scope without widening it',
  boardFiltered.status === 200 && boardFiltered.body.data.attempts.length === 1
    && boardFiltered.body.data.attempts.every((row) => row.board_number === '1' && row.user_id === '4'),
  JSON.stringify(boardFiltered.body?.data ?? {}).slice(0, 180));
const attemptReplay = await call('POST', '/tournaments/pubp/attempts', {
  token: 'tok-member10', body: { board_number: '2', original_seat: 'South', recorded_hand_id: 'rh-new-3' }
});
check('9g. replaying the same attempt is idempotent, not a second row and not a lost write',
  attemptReplay.status === 200 && attemptReplay.body?.data?.replayed === true
    && rowsOf('tournament_attempts').filter((row) => row.recorded_hand_id === 'rh-new-3').length === 1,
  `${attemptReplay.status} ${attemptReplay.text.slice(0, 160)}`);
const handStolen = await call('POST', '/tournaments/c11p/attempts', {
  token: 'tok-member11', body: { board_number: '1', original_seat: 'North', recorded_hand_id: 'rh-new-3' }
});
check('9h. filing a different attempt under a recorded hand that exists is refused, not duplicated',
  handStolen.status === 400 && /already recorded/.test(String(handStolen.body?.detail))
    && rowsOf('tournament_attempts').filter((row) => row.recorded_hand_id === 'rh-new-3').length === 1,
  `${handStolen.status} ${handStolen.text.slice(0, 180)}`);
const attemptOnMissingBoard = await call('POST', '/tournaments/pubp/attempts', {
  token: 'tok-member10', body: { board_number: '77', original_seat: 'North', recorded_hand_id: 'rh-nope' }
});
check('9i. an attempt on a board the tournament does not hold is 404 and writes nothing',
  attemptOnMissingBoard.status === 404 && attemptOnMissingBoard.body?.error === 'board_not_found'
    && !rowsOf('tournament_attempts').some((row) => row.recorded_hand_id === 'rh-nope'),
  `${attemptOnMissingBoard.status} ${attemptOnMissingBoard.text.slice(0, 140)}`);
const attemptOutsideSeat = await call('POST', '/tournaments/c10p/attempts', {
  token: 'tok-member10', body: { board_number: '1', original_seat: 'North2', recorded_hand_id: 'rh-seat' }
});
check('9j. a seat outside the four is refused with invalid_original_seat',
  attemptOutsideSeat.status === 400 && attemptOutsideSeat.body?.error === 'invalid_original_seat',
  `${attemptOutsideSeat.status} ${attemptOutsideSeat.text.slice(0, 140)}`);
// A club member may not record an attempt into the club's DRAFT set, and the refusal must precede the
// write — an attempt row on a board nobody may play yet is a claim about a game that cannot have happened.
const draftAttempt = await call('POST', '/tournaments/c10d/attempts', {
  token: 'tok-member10', body: { board_number: '1', original_seat: 'North', recorded_hand_id: 'rh-draft' }
});
check('9k. no attempt is recorded on an unpublished club set (the decision comes before the write)',
  draftAttempt.status === 403 && draftAttempt.body?.error === 'tournament_not_published'
    && !rowsOf('tournament_attempts').some((row) => row.recorded_hand_id === 'rh-draft'),
  `${draftAttempt.status} ${draftAttempt.text.slice(0, 140)}`);
REGISTRY.tournament_attempts.rows = REGISTRY.tournament_attempts.rows.filter((row) => !['rh-new-3'].includes(row.recorded_hand_id));

// ══ 10. DELETION IS CONFIRMED AGAINST THE STORED NAME ══════════════════════
const deleteNoConfirm = await call('DELETE', '/tournaments/p3', { token: 'tok-member10', body: {} });
check('10a. a delete with no confirm_name is refused with delete_requires_confirmation',
  deleteNoConfirm.status === 400 && deleteNoConfirm.body?.error === 'delete_requires_confirmation'
    && rowOf('tournaments', 'p3') !== null,
  `${deleteNoConfirm.status} ${deleteNoConfirm.text.slice(0, 140)}`);
const deleteWrongName = await call('DELETE', '/tournaments/p3', { token: 'tok-member10', body: { confirm_name: 'Kitchen Table Set' } });
check('10b. a near-miss name is refused 409 tournament_name_mismatch and nothing is removed',
  deleteWrongName.status === 409 && deleteWrongName.body?.error === 'tournament_name_mismatch'
    && rowOf('tournaments', 'p3') !== null && boardsOf('p3').length === 2,
  `${deleteWrongName.status} ${deleteWrongName.text.slice(0, 160)}`);
const deleteCaseWrong = await call('DELETE', '/tournaments/p3', { token: 'tok-member10', body: { confirm_name: 'kitchen table sets' } });
check('10c. the match is exact on letters (whitespace is normalised, case is not)',
  deleteCaseWrong.status === 409 && rowOf('tournaments', 'p3') !== null,
  `${deleteCaseWrong.status} ${deleteCaseWrong.text.slice(0, 140)}`);
const deleteWhitespace = await call('DELETE', '/tournaments/p3', { token: 'tok-member10', body: { confirm_name: '  Kitchen    Table Sets  ' } });
check('10d. run-of-space differences are the same name (a paste must not fail on padding)',
  deleteWhitespace.status === 200, `${deleteWhitespace.status} ${deleteWhitespace.text.slice(0, 160)}`);
check('10e. and the delete removed the header, every board AND every attempt row under it',
  rowOf('tournaments', 'p3') === null && boardsOf('p3').length === 0 && attemptsOf('p3').length === 0,
  JSON.stringify({ header: rowOf('tournaments', 'p3'), boards: boardsOf('p3').length, attempts: attemptsOf('p3').length }));
check('10f. after the delete the id answers 404 tournament_not_found to its own owner',
  (await call('GET', '/tournaments/p3', { token: 'tok-member10' })).status === 404, 'still readable');
// An attempt delete that the backend silently ignores must be REPORTED, not folded into a success.
resetTournamentTables();
// Exactly ONE attempt row under p3, so `attemptsLeftBehind.length === 1` below counts the row this arm
// planted and nothing else that happened to be seeded.
REGISTRY.tournament_attempts.rows = REGISTRY.tournament_attempts.rows.filter((row) => row.tournament_id !== 'p3');
REGISTRY.tournament_attempts.rows.push(
  { id: 'a-keep', tournament_id: 'p3', board_number: '1', recorded_hand_id: 'rh-keep', original_seat: 'South', user_id: '3' }
);
mock.dropDelete = 'tournament_attempts';
const partialDelete = await call('DELETE', '/tournaments/p3', { token: 'tok-member10', body: { confirm_name: 'Kitchen Table Sets' } });
check('10g. a delete whose attempt rows the backend kept says so instead of claiming a clean removal',
  partialDelete.status === 200 && partialDelete.body?.data?.tournamentRemoved === true
    && partialDelete.body.data.attemptsLeftBehind.length === 1
    && /need attention/.test(String(partialDelete.body.data.note))
    && mock.dropDelete === 'tournament_attempts',
  `${partialDelete.status} ${JSON.stringify(partialDelete.body?.data ?? {}).slice(0, 240)}`);
mock.dropDelete = null;
REGISTRY.tournament_attempts.rows = REGISTRY.tournament_attempts.rows.filter((row) => row.recorded_hand_id !== 'rh-keep');
resetTournamentTables();
const strangerDeletePublic = await call('DELETE', '/tournaments/pubp', { token: 'tok-admin10', body: { confirm_name: 'Autumn Open' } });
check('10h. a club admin cannot delete the public field\'s set',
  strangerDeletePublic.status === 403 && strangerDeletePublic.body?.error === 'super_admin_required'
    && rowOf('tournaments', 'pubp') !== null,
  `${strangerDeletePublic.status} ${strangerDeletePublic.text.slice(0, 140)}`);

// ══ 11. THE GENERIC TABLE RELAY NO LONGER SERVES THESE TABLES ═══════════════
const blockedTables = ['tournaments', 'tournament_boards', 'tournament_attempts'];
const blockedVerbs = [
  ['GET', (table) => `/ncb/data/read/${table}?limit=1`],
  ['POST', (table) => `/ncb/data/create/${table}`],
  ['PUT', (table) => `/ncb/data/update/${table}/1`],
  ['DELETE', (table) => `/ncb/data/delete/${table}/1`]
];
const relayLeaks = [];
for (const table of blockedTables) {
  for (const [method, build] of blockedVerbs) {
    for (const token of ['', SUPER_TOKEN, 'tok-noclub']) {
      const answer = await call(method, build(table), { token, ...(method === 'GET' ? {} : { body: { name: 'via relay' } }) });
      if (!(answer.status === 403 && answer.body?.error === 'tournament_via_gateway_only')) {
        relayLeaks.push(`${method} ${build(table)} tok=${token ? 'set' : 'none'} = ${answer.status}/${answer.body?.error}`);
      }
    }
  }
  const publicRoute = await call('GET', `/ncb/public-data/read/${table}?limit=1`, { token: '' });
  if (!(publicRoute.status === 403 && publicRoute.body?.error === 'tournament_via_gateway_only')) {
    relayLeaks.push(`anon public ${table} = ${publicRoute.status}/${publicRoute.body?.error}`);
  }
}
check('11a. all three tables are refused on read, create, update, delete and the anonymous public route',
  relayLeaks.length === 0, relayLeaks.slice(0, 6).join(' | '));
check('11b. the refusal is NAMED, so a stale client learns where the tables went',
  relayLeaks.length === 0 && gatewayModule.TOURNAMENT_GATEWAY_REFUSAL === 'tournament_via_gateway_only'
    && /\/tournaments/.test(gatewayModule.TOURNAMENT_GATEWAY_DETAIL ?? ''),
  String(gatewayModule.TOURNAMENT_GATEWAY_DETAIL).slice(0, 120));
check('11c. the three tables are out of DEFAULT_TABLES and in the blocked-by-name set',
  blockedTables.every((table) => !ncbGatewayTables.includes(table))
    && blockedTables.every((table) => ncbGatewayClubTables.includes(table))
    && blockedTables.every((table) => gatewayModule.TOURNAMENT_TABLES.includes(table)),
  `DEFAULT ${ncbGatewayTables.filter((t) => t.startsWith('tournament')).join(',') || 'clean'} | NEVER ${ncbGatewayClubTables.filter((t) => t.startsWith('tournament')).join(',')}`);
check('11d. and they have no write-policy entry to fall back on',
  blockedTables.every((table) => !(table in gatewayModule.PLAYER_TABLE_WRITE_POLICY)),
  blockedTables.filter((table) => table in gatewayModule.PLAYER_TABLE_WRITE_POLICY).join(','));
// The allow-list variable must not be a door. A deployment that names the tables in
// NCB_TABLE_ALLOWLIST gets the same refusal, because the block is applied AFTER the list is parsed.
const forcedGateway = gatewayModule.buildNcbGateway({
  env: { ...process.env, NCB_TABLE_ALLOWLIST: 'tournaments,tournament_boards,user_settings', NCB_SESSION_SEAL_KEY: 'x'.repeat(32) },
  event: () => {}
});
const forcedTables = forcedGateway._internals.tables;
check('11e. NCB_TABLE_ALLOWLIST cannot re-open them (the blocked set is applied after parsing)',
  !forcedTables.includes('tournaments') && !forcedTables.includes('tournament_boards')
    && forcedTables.includes('user_settings'),
  forcedTables.join(','));
const forcedAnswer = await call('POST', '/ncb/data/create/tournaments', { token: SUPER_TOKEN, body: { name: 'forged' } });
check('11f. the pre-fix defect is gone: a signed-in session can no longer insert a tournament row',
  forcedAnswer.status === 403 && forcedAnswer.body?.error === 'tournament_via_gateway_only'
    && !rowsOf('tournaments').some((row) => row.name === 'forged'),
  `${forcedAnswer.status} ${forcedAnswer.text.slice(0, 140)}`);
// A player table still moves on the same path: the block scopes the tournament tables and nothing else.
const untouched = await call('GET', '/ncb/data/read/user_settings?limit=1', { token: SUPER_TOKEN });
check('11g. the narrowing did not widen or break any other table\'s answer',
  untouched.status !== 403 || untouched.body?.error !== 'tournament_via_gateway_only',
  `${untouched.status} ${JSON.stringify(untouched.body).slice(0, 120)}`);

// ══ 12. THE RULES AGAINST THE PUBLISHED CONTRACT ═══════════════════════════════════════════
// Compares truth tables with the contract fixture, which is the approved ownership rule restated as
// executable code inside this repository. Section 12i asserts nothing here reaches into another repo.
// Section 12 of the ORIGINAL form read the frontend working tree and paid for it: see 12b4.
// The contract is now the in-repo fixture `test-fixtures/tournamentClientContract.mjs`, restated from
// the ownership spec. This block used to read `../BridgeMind-Greta/src/services/tournamentContracts.js`
// off disk, which made the backend's gate depend on whatever a different repository's working tree
// happened to hold — and it then pinned a private scope keyed on `user_id`, the one column that can
// never name the owner of a row NodeSend wrote (NCB stamps it with the writing session, which is the
// service account). The fixture carries both the approved rule and the superseded one, so 12b4 can run
// NodeSend against the old contract and require refusal. 12i asserts the sibling dependency is gone.
let contract = null;
let legacyContract = null;
let approvedColumns = null;
let contractNote = '';
try {
  const fixture = await import('./test-fixtures/tournamentClientContract.mjs');
  contract = fixture;
  legacyContract = fixture.LEGACY_USER_ID_CONTRACT;
  approvedColumns = fixture.APPROVED_TOURNAMENT_COLUMNS;
} catch (error) {
  contractNote = `the contract fixture could not be loaded (${error?.name}: ${String(error?.message).slice(0, 120)})`;
}
// Shared by every arm below, so "NCB's own slot" is one name and not a repeated literal.
const NCB_ROW_OWNER_COLUMN = approvedColumns?.ncbRowOwner ?? 'user_id';
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
};
const same = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const CLUB_IDS = ['10', '11', ''];
const MEMBERSHIPS = [
  null,
  { clubId: '10', role: 'member' },
  { clubId: '10', role: 'club_admin' },
  { clubId: '11', role: 'member' },
  { clubId: '11', role: 'club_admin' }
];
const ROW_CASES = [];
for (const visibility of ['private', 'club', 'public', 'legacy']) {
  for (const status of ['draft', 'published']) {
    for (const owner of ['3', '4']) {
      for (const clubId of CLUB_IDS) ROW_CASES.push({ visibility, status, ownerId: owner, clubId });
    }
  }
}
const accessMismatches = [];
if (contract) {
  for (const row of ROW_CASES) {
    for (const userId of ['3', '5']) {
      for (const isSuperAdmin of [true, false]) {
        for (const membership of MEMBERSHIPS) {
          const session = { userId, isSuperAdmin };
          const mine = tournamentAccessRule({ row, session, membership });
          const theirs = contract.resolveTournamentAccess({ row, session, membership });
          if (!same({ r: mine.read, m: mine.manage, p: mine.play, reason: mine.reason }, { r: theirs.read, m: theirs.manage, p: theirs.play, reason: theirs.reason })) {
            accessMismatches.push(`${row.visibility}/${row.status}/owner=${row.ownerId}/club=${row.clubId} u=${userId} super=${isSuperAdmin} mem=${JSON.stringify(membership)}: node ${JSON.stringify(canonical(mine))} vs ${JSON.stringify(canonical(theirs))}`);
          }
        }
      }
    }
  }
}
check(`12a. resolveTournamentAccess agrees with the contract over ${ROW_CASES.length * 2 * 2 * MEMBERSHIPS.length} cases`,
  contract !== null && accessMismatches.length === 0,
  contractNote || accessMismatches.slice(0, 3).join(' | '));

// The contract's own literal column names, spelled as the frozen client spells them — except the
// owner, which is the entire disagreement, and which NodeSend now refuses to default.
// NodeSend's schema role is called `userId`; the contract says the column behind it is the OWNER.
// Deriving it here means a fixture that moves the column moves these arms with it.
const CONTRACT_LITERAL_TOURNAMENT_COLUMNS = Object.freeze({
  visibility: 'visibility', userId: approvedColumns?.ownerId ?? 'owner_user_id',
  clubId: 'club_id', status: 'status'
});

const scopeMismatches = [];
if (contract) {
  for (const userId of ['3', '5']) {
    for (const isSuperAdmin of [true, false]) {
      for (const membership of MEMBERSHIPS) {
        const session = { userId, isSuperAdmin };
        const mine = tournamentListScopeRule({ session, membership, columns: CONTRACT_LITERAL_TOURNAMENT_COLUMNS });
        const theirs = contract.tournamentListScope({ session, membership });
        // Whole clauses, keys included. The comparison that used to sit here had to EXCLUDE the owner
        // key because the two sides genuinely disagreed about it; excluding a key is how a difference
        // stops being visible, so now that the contract names the owner column both sides are compared
        // as they are. Any move away from `owner_user_id` on either side goes red here.
        if (!same(mine.clauses, theirs.clauses)
          || !same({ u: mine.userId, s: mine.isSuper, m: mine.memberClub, a: mine.adminClub },
            { u: theirs.userId, s: theirs.isSuper, m: theirs.memberClub, a: theirs.adminClub })) {
          scopeMismatches.push(`u=${userId} super=${isSuperAdmin} mem=${JSON.stringify(membership)}: ${JSON.stringify(canonical(mine.clauses))} vs ${JSON.stringify(canonical(theirs.clauses))}`);
        }
        // Property 2, asserted on both sides at once: no clause in any caller's scope may be keyed on
        // NCB's row-ownership slot, whatever else it is keyed on.
        const keyedOnRowOwner = (clauses) => (clauses ?? []).filter((c) => Object.prototype.hasOwnProperty.call(c, NCB_ROW_OWNER_COLUMN));
        if (keyedOnRowOwner(mine.clauses).length || keyedOnRowOwner(theirs.clauses).length) {
          scopeMismatches.push(`a scope clause is keyed on ${NCB_ROW_OWNER_COLUMN}: ${JSON.stringify([mine.clauses, theirs.clauses].flat())}`);
        }
      }
    }
  }
}
check(`12b. tournamentListScope's clauses agree with the contract over ${2 * 2 * MEMBERSHIPS.length} cases`,
  contract !== null && scopeMismatches.length === 0,
  contractNote || scopeMismatches.slice(0, 3).join(' | '));

// Property 1, as a fact about two implementations: the private clause names the owner column, and
// both sides name the same one, produced from the same session id.
const approvedPrivate = contract
  ? contract.tournamentListScope({ session: { userId: '3', isSuperAdmin: false }, membership: null }) : null;
const nodePrivate = tournamentListScopeRule({
  session: { userId: '3', isSuperAdmin: false }, membership: null, columns: CONTRACT_LITERAL_TOURNAMENT_COLUMNS
});
check('12b2. the contract scopes a private set on owner_user_id and NodeSend builds the identical clause (property 1)',
  contract !== null && approvedPrivate?.clauses?.[0]?.owner_user_id === '3'
    && !Object.prototype.hasOwnProperty.call(approvedPrivate.clauses[0], NCB_ROW_OWNER_COLUMN)
    && nodePrivate.error === undefined && same(approvedPrivate.clauses, nodePrivate.clauses),
  `contract=${JSON.stringify(approvedPrivate?.clauses?.[0])} node=${JSON.stringify(nodePrivate?.clauses?.[0])} ${nodePrivate?.error ?? ''}`);

// 12b4 — THE NEGATIVE CONTROL. NodeSend is asked to build the scope exactly as the superseded
// contract did: identity in NCB's own row slot. It must refuse outright rather than answer with the
// clause it used to answer with. A comparison of two texts could never show this, because two texts
// can agree on a rule that the server would reject on being handed it.
const legacyShapedScope = tournamentListScopeRule({
  session: { userId: '3', isSuperAdmin: false }, membership: null,
  columns: {
    visibility: legacyContract?.columns.visibility ?? 'visibility',
    userId: legacyContract?.columns.ownerId ?? 'user_id',
    clubId: 'club_id', status: 'status'
  }
});
const legacyBootSchema = tournamentSchemaConfig({
  TOURNAMENT_NCB_SCHEMA_JSON: JSON.stringify({
    tables: MAIN_TOURNAMENT_SCHEMA.tables,
    columns: { ...MAIN_TOURNAMENT_SCHEMA.columns,
      tournaments: { ...MAIN_TOURNAMENT_SCHEMA.columns.tournaments, userId: 'user_id' } }
  })
});
check('12b4. NEGATIVE CONTROL: handed the old user_id contract, NodeSend refuses the scope AND refuses the schema that would carry it',
  legacyContract !== null && legacyContract.columns.ownerId === NCB_ROW_OWNER_COLUMN
    && legacyShapedScope.error === 'tournament_identity_column_unconfigured' && legacyShapedScope.clauses.length === 0
    && legacyShapedScope.detail.includes(NCB_ROW_OWNER_COLUMN)
    && legacyBootSchema.ok === false,
  `scope=${JSON.stringify(legacyShapedScope).slice(0, 150)} schema=${legacyBootSchema.ok} ${(legacyBootSchema.problems ?? [])[0]?.slice(0, 60) ?? ''}`);

const unconfiguredListDecision = tournamentAuthorize({ op: 'listTournaments', session: { userId: '3' } });
check('12b3. a refused scope answers 503 under its own name, never the 200-with-no-rows a user_id clause would have produced',
  unconfiguredListDecision.status === 503
    && unconfiguredListDecision.body.error === 'tournament_identity_column_unconfigured'
    && tournamentStoreErrorStatus.tournament_identity_column_unconfigured === 503,
  JSON.stringify(unconfiguredListDecision).slice(0, 170));

// Compared on what the contract actually governs: WHO is allowed to create WHICH category, and
// whose id the created row belongs to. NodeSend's scope object carries fields the client never
// sees and the contract does not specify, so comparing those would either force this fixture to
// re-type the server (which proves nothing) or go red on a difference that is not a violation.
const createMismatches = [];
if (contract) {
  for (const target of ['private', 'club', 'public', 'legacy', null]) {
    for (const targetClubId of CLUB_IDS) {
      for (const userId of ['3', '']) {
        for (const isSuperAdmin of [true, false]) {
          for (const membership of MEMBERSHIPS) {
            for (const clubActive of [true, false, null]) {
              const session = { userId, isSuperAdmin };
              const args = { target, targetClubId, session, membership, clubActive };
              const mine = tournamentCreateRule(args);
              const theirs = contract.authorizeTournamentCreate(args);
              const project = (d) => ({ allow: d.allow === true, reason: d.allow === true ? null : (d.reason ?? null), visibility: d.scope?.visibility ?? null, clubId: d.scope?.clubId ?? null });
              if (!same(project(mine), project(theirs))) {
                createMismatches.push(`${JSON.stringify(canonical(args))}: ${JSON.stringify(canonical(project(mine)))} vs ${JSON.stringify(canonical(project(theirs)))}`);
              }
              // Property 4, measured over every input rather than asserted once: when a creation is
// allowed, the owner it stamps is the SESSION. There is no input in this space —
              // including a body field naming another account, which the shape guard refuses long
              // before here — under which a permitted create carries an owner the caller did not
              // authenticate as.
              if (mine.allow === true && String(mine.scope?.ownerId ?? '') !== String(userId)) {
                createMismatches.push(`owner not the session: u=${userId} -> ${JSON.stringify(mine.scope)}`);
              }
            }
          }
        }
      }
    }
  }
}
check('12c. authorizeTournamentCreate agrees with the contract over its whole input space, and never owners a set to anyone but the session',
  contract !== null && createMismatches.length === 0,
  contractNote || `${createMismatches.length} mismatches: ${createMismatches.slice(0, 2).join(' | ')}`);

// A category change is decided by its DESTINATION. That is the contract sentence, and it is what is
// compared here — allow/refuse/reason, plus the two consequences the ownership contract depends on:
// a set cannot be moved to a club its admin does not admin, and a change TO private re-keys the row
// to the session doing it. What the decision object additionally carries is the server's business.
const visibilityMismatches = [];
if (contract) {
  for (const row of ROW_CASES) {
    for (const target of ['private', 'club', 'public', 'legacy', undefined]) {
      for (const targetClubId of CLUB_IDS) {
        for (const isSuperAdmin of [true, false]) {
          for (const membership of MEMBERSHIPS) {
            const session = { userId: '3', isSuperAdmin };
            const args = { row, target, targetClubId, session, membership };
            const mine = tournamentVisibilityRule(args);
            const theirs = contract.authorizeVisibilityTarget(args);
            const project = (d) => ({ allow: d.allow === true, reason: d.allow === true ? null : (d.reason ?? null),
              visibility: d.scope?.visibility ?? null, clubId: d.scope?.clubId ?? null });
            if (!same(project(mine), project(theirs))) {
              visibilityMismatches.push(`${JSON.stringify(canonical(args))}: ${JSON.stringify(canonical(project(mine)))} vs ${JSON.stringify(canonical(project(theirs)))}`);
            }
            // Property 3, on the management side and stated exactly as the contract states it: a set
            // cannot move between clubs BY A CLUB ADMIN. The bridge that may act for any club is the
            // system admin, and that flag is a server read of system_admins, never a field. So for
            // every session that is not one, an allowed decision either leaves the row in its own club
            // or takes the club from the membership the server found.
            const clubMovedBySomeoneElse = mine.allow === true && !isSuperAdmin
              && String(row.visibility) === 'club' && String(row.clubId ?? '') !== ''
              && String(mine.scope?.clubId ?? row.clubId) !== String(row.clubId);
            const clubNotTheSessionOwn = mine.allow === true && !isSuperAdmin
              && String(mine.scope?.clubId ?? '') !== ''
              && String(mine.scope?.clubId ?? '') !== String(membership?.clubId ?? '');
            if (clubMovedBySomeoneElse || clubNotTheSessionOwn) {
              visibilityMismatches.push(`a club decision came from anywhere but the session's own server-read membership: ${JSON.stringify(args)} -> ${JSON.stringify(canonical(mine))}`);
            }
          }
        }
      }
    }
  }
}
check('12d. authorizeVisibilityTarget agrees with the contract on the destination rule, and moves no club set to another club',
  contract !== null && visibilityMismatches.length === 0,
  contractNote || `${visibilityMismatches.length} mismatches: ${visibilityMismatches.slice(0, 2).join(' | ')}`);

const endpointShape = (endpoint) => `${endpoint.method} ${String(endpoint.path).replace(/\{tournamentId\}/g, ':tournamentId').replace(/\{boardNumber\}/g, ':boardNumber')}`;
const contractEndpoints = contract ? Object.entries(contract.TOURNAMENT_ENDPOINTS) : [];
const routeMismatch = contractEndpoints.filter(([op, endpoint]) => {
  const mine = tournamentRoutes.find((route) => route.op === op);
  return !mine || `${mine.method} ${mine.path}` !== endpointShape(endpoint);
});
check('12e. the twelve route paths and verbs are the contract\'s, path grammar included',
  contract !== null && routeMismatch.length === 0 && contractEndpoints.length === 12
    && tournamentRoutes.length === 12,
  contractNote || routeMismatch.map(([op, e]) => `${op} ${endpointShape(e)}`).join(' | '));
const fieldMismatch = contract
  ? Object.entries(contract.TOURNAMENT_BODY_FIELDS).filter(([op, spec]) => !same(spec, tournamentBodyFields[op]))
  : ['missing'];
check('12f. the positive field allow-list is the contract\'s, per operation',
  contract !== null && fieldMismatch.length === 0 && Object.keys(contract.TOURNAMENT_BODY_FIELDS).length === 12,
  contractNote || fieldMismatch.map(([op]) => op).join(','));
// Reason-name drift, in BOTH directions, which is the only form of this check that means anything:
//  • every name NodeSend can answer must be a name the contract publishes — otherwise the browser has no
//    translation for it and the user sees a fallback message;
//  • EXCEPT a short, inlined list of NodeSend-only storage-failure names, which the club feature also
//    keeps (`club_read_unreadable`, `club_directory_unconfigured`): they describe a backend state, never a
//    caller mistake, so they are deliberately not part of the client's switch.
const NODE_ONLY_REASONS = Object.freeze(['tournament_read_unreadable', 'tournament_store_unavailable',
  'club_store_unavailable', 'club_account_request_failed',
  // A deployment that never named the column holding the application owner. The browser needs no
  // translation for it: it is a server state, not something the caller did, and the generic
  // "unavailable" copy is the honest rendering of it.
  'tournament_identity_column_unconfigured']);
const contractReasons = contract ? contract.TOURNAMENT_GATEWAY_REASONS : [];
// Server-answerable names, minus the ones that describe a backend state no caller caused.
const statusReasonNames = Object.keys(tournamentStoreErrorStatus);
const unusedContractReasons = contract
  ? contract.TOURNAMENT_GATEWAY_REASONS.filter((r) => !statusReasonNames.includes(r)
    && !contract.TOURNAMENT_CLIENT_ONLY_REASONS.includes(r))
  : [];
const unpublishedReasonsAll = Object.keys(tournamentStoreErrorStatus)
  .concat(Object.keys(bridge.tournamentRefusalCopy ?? {}));
const unpublishedReasons = unpublishedReasonsAll
  .filter((reason) => !contractReasons.includes(reason) && !NODE_ONLY_REASONS.includes(reason)
    && !/^club_account_/.test(reason));
const refusedReasons = new Set();
for (const row of ROW_CASES) {
  for (const isSuperAdmin of [true, false]) {
    for (const membership of MEMBERSHIPS) {
      const access = tournamentAccessRule({ row, session: { userId: '3', isSuperAdmin }, membership });
      if (access.reason) refusedReasons.add(access.reason);
    }
  }
}
const unknownRefusals = [...refusedReasons].filter((reason) => !contractReasons.includes(reason));
// The contract's vocabulary and NodeSend's answerable names must be the SAME SET, once the
// storage-only names the client never sees are set aside. The old arm checked one direction and
// required `> 40` names, which a padded list could satisfy; a two-way check cannot be padded, and
// it catches the failure the list exists to prevent in both of its forms: a name the server can
// answer that the client cannot translate (the user gets a fallback message about a refusal that
// had a precise reason), and a translation the client carries for a name nobody can answer.
check('12g. the reason vocabulary is the contract\'s set exactly, in both directions, once storage-only names are set aside',
  contract !== null && unpublishedReasons.length === 0 && unknownRefusals.length === 0
    && unusedContractReasons.length === 0 && contractReasons.length >= 30
    && contract.TOURNAMENT_CLIENT_ONLY_REASONS.every((r) => !statusReasonNames.includes(r)),
  contractNote || `server names the contract lacks: ${unpublishedReasons.join(',')} | contract names nothing answers: ${unusedContractReasons.join(',')}`);

check('12g2. every reason the access rule can return is in the contract vocabulary',
  contract !== null && refusedReasons.size >= 5 && unknownRefusals.length === 0,
  [...refusedReasons].join(','));
// The board validator, compared on OUTCOME rather than on wording: a board the contract's own validator
// rejects must not be storable here, and one it accepts must be. The board-number length bound is NO
// LONGER a divergence: the tournament contract is 1-32 and NodeSend now enforces exactly that
// (tournaments/tournamentBoardValidator.js), so this loop is a true agreement test. The club validator's
// 10-character cap still exists for club boards, and it is deliberately not what tournaments use.
// 12h2 measures the ceiling from above and 12h3 measures it from inside, so the widened contract cannot
// silently regress to the club bound without one of the two going red.
const boardCases = [
  [legalBoard(1)], [legalBoard(1), legalBoard(2)], [], [legalBoard(1), legalBoard(1)],
  [{ ...legalBoard(1), dealer: 'X' }], [{ ...legalBoard(1), vulnerability: 'All' }],
  [{ ...legalBoard(1), hands: { ...dealHands(0), North: dealHands(0).North.slice(1) } }],
  [{ ...legalBoard(1), board_number: '1' }]
];
const boardAgreement = boardCases.map((boards) => {
  const theirs = contract ? contract.validateTournamentBoards(boards) : { valid: null };
  const checked = tournamentValidateInput('createTournament', { name: 'X', visibility: 'private', boards }, { query: {} });
  return { n: boards.length, theirs: theirs.valid, mine: checked.ok === true };
}).filter((row) => row.theirs !== row.mine);
check('12h. board validation accepts and rejects the same deals as the contract',
  contract !== null && boardAgreement.length === 0 && boardCases.length === 8,
  contractNote || JSON.stringify(boardAgreement));
const longNumber = await call('POST', '/tournaments', {
  token: SUPER_TOKEN, body: { name: 'Long Number', visibility: 'public', boards: [{ ...legalBoard(1), board_number: 'x'.repeat(33) }] }
});
check('12h2. a board number past the published 32-character tournament ceiling is refused, and nothing is stored',
  longNumber.status === 400 && longNumber.body?.error === 'invalid_board_record'
    && !rowsOf('tournaments').some((row) => row.name === 'Long Number'),
  `${longNumber.status}/${longNumber.body?.error}`);
// The other side of the same contract, and the arm that makes the widening real rather than a comment:
// a dotted, session-prefixed label of 27 characters is legal in the frontend contract and was refused by
// the club validator's 10-character cap. If tournaments ever fall back to that cap, this goes red.
const longButLegal = '2026-10-11-Round-1-Board-14';
const legalNumber = await call('POST', '/tournaments', {
  token: SUPER_TOKEN,
  body: { name: 'Long But Legal', visibility: 'public', boards: [{ ...legalBoard(1), board_number: longButLegal }] }
});
const storedLegal = rowsOf('tournament_boards').some((row) => String(row.board_number) === longButLegal);
check(`12h3. a ${longButLegal.length}-character board label (over the club cap, under the tournament ceiling) imports and is stored verbatim`,
  legalNumber.status === 200 && storedLegal,
  `${legalNumber.status}/${legalNumber.body?.error} stored=${storedLegal}`);
const legalTournamentId = legalNumber.body?.data?.id ?? legalNumber.body?.id ?? 0;
const startedLegal = await call('POST', `/tournaments/${encodeURIComponent(String(legalTournamentId))}/boards/${encodeURIComponent(longButLegal)}/start`,
  { token: SUPER_TOKEN, body: { original_seat: 'North' } });
// Read the label back from wherever the start route actually puts it, but require it to be PRESENT:
// defaulting to the value we asked for would make this arm unable to go red.
const echoed = startedLegal.body?.data?.board_number ?? startedLegal.body?.board_number
  ?? startedLegal.body?.data?.board?.board_number ?? startedLegal.body?.board?.board_number;
check('12h3b. the same long label is addressable on the start route, so nothing importable is unreachable',
  startedLegal.status === 200 && echoed === longButLegal,
  `${startedLegal.status} echoed=${JSON.stringify(echoed)} body=${JSON.stringify(startedLegal.body).slice(0, 110)}`);
// An empty `contract` used to be survivable in spirit: every arm in the section was written
// `contract !== null && ...`, so a missing sibling file turned the whole section red at once, which
// is honest but confusing. The two claims that matter now are separate and both are measured: the
// fixture loaded, and NO path out of this repository is read for it.
check('12i. the contract fixture loaded and its rules are callable (a load failure is a red arm, never a skipped one)',
  contract !== null && typeof contract.tournamentListScope === 'function'
    && typeof contract.resolveTournamentAccess === 'function' && legacyContract !== null && approvedColumns !== null,
  contractNote || 'ok');
// Read this file back and look for a sibling checkout being OPENED, not mentioned: the prose above
// explains what used to happen and would otherwise trip its own detector, and a needle built by
// concatenation does not match the line that builds it.
const gateSource = fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n');
const SIBLING_NEEDLES = ['Bridge' + 'Mind-Greta', 'BRIDGEMIND_' + 'REPO', 'gre' + 'taRepo'];
const OPENER = /(readFileSync|existsSync|createRequire|import\s*\(|resolve\s*\()/;
const siblingReads = gateSource
  .map((text, no) => ({ text, no }))
  .filter(({ text }) => !/^\s*(\/\/|\*|\/)\s/.test(text) && OPENER.test(text)
    && SIBLING_NEEDLES.some((needle) => text.includes(needle)));
check('12i2. this gate opens nothing outside its own repository — the contract dependency is a fixture, not a checkout',
  siblingReads.length === 0,
  siblingReads.map((r) => `line ${r.no + 1}: ${r.text.trim().slice(0, 100)}`).join(' | '));

// ── the ownership contract, over HTTP, on rows where the NCB slot is deliberately identical ──
// Properties 3-6 are not settled by a rule table: they are about what the storage layer writes and
// what the wire carries. Every row below is created by the relay through the service account, so the
// vendor ownership column holds the same id on all of them while the application columns hold the
// people. That is the state in which a user_id-keyed identity rule is silent rather than loud, so
// these arms assert the two columns are DIFFERENT values, not merely that a name came back.
{
  resetTournamentTables();
  // The list envelope carries the sets under data.tournaments. Read the ids out of whatever
  // answered; never default to the ids that were asked for, or an arm could not be wrong.
  const listIdsOf = (res) => (((res.body?.data ?? {}).tournaments ?? res.body?.data ?? [])
    .map((row) => String(row.id)));

  const forgedOwner = await call('POST', '/tournaments', { token: 'tok-member10',
    body: { name: 'Forged', visibility: 'private', owner_user_id: '4', user_id: '4', boards: [legalBoard(1)] } });
  const forgedQuery = await call('GET', '/tournaments?owner_user_id=4', { token: 'tok-member10' });
  const forgedRole = await call('POST', '/tournaments', { token: 'tok-member10',
    body: { name: 'Role Player', visibility: 'public', is_super_admin: true, role: 'administrator', boards: [legalBoard(1)] } });
  const nothingForged = rowsOf('tournaments').filter((row) => ['Forged', 'Role Player'].includes(String(row.name)));

  check('12j. property 4 and 5: an owner, a player or an admin flag sent by the client is refused by name, and no row is written under it',
    forgedOwner.status === 400 && forgedOwner.body?.error === 'client_identity_refused'
      && forgedQuery.status === 400 && forgedQuery.body?.error === 'client_identity_refused'
      && forgedRole.status === 400 && forgedRole.body?.error === 'client_identity_refused'
      && nothingForged.length === 0,
    `owner=${forgedOwner.status}/${forgedOwner.body?.error} query=${forgedQuery.status}/${forgedQuery.body?.error} role=${forgedRole.status}/${forgedRole.body?.error} stored=${nothingForged.length}`);

  const aCreate = await call('POST', '/tournaments', { token: 'tok-member10',
    body: { name: 'A Private', visibility: 'private', boards: [legalBoard(1), legalBoard(2)] } });
  const bCreate = await call('POST', '/tournaments', { token: 'tok-member11',
    body: { name: 'B Private', visibility: 'private', boards: [legalBoard(1)] } });
  const aId = String(aCreate.body?.data?.id ?? aCreate.body?.id ?? '');
  const bId = String(bCreate.body?.data?.id ?? bCreate.body?.id ?? '');
  const pair = rowsOf('tournaments').filter((row) => [aId, bId].includes(String(row.id)));

  check('12k. property 3 precondition: two private sets, two different owners, ONE identical vendor row owner',
    aCreate.status === 200 && bCreate.status === 200 && pair.length === 2
      && pair.map((r) => String(r.owner_user_id)).sort().join(',') === '3,4'
      && new Set(pair.map((r) => String(r.user_id))).size === 1
      && pair.every((r) => String(r.user_id) === CLUB_ACCOUNT_ID),
    JSON.stringify(pair.map((r) => ({ id: r.id, owner: r.owner_user_id, vendorOwner: r.user_id }))).slice(0, 180));

  const aList = await call('GET', '/tournaments', { token: 'tok-member10' });
  const bList = await call('GET', '/tournaments', { token: 'tok-member11' });
  const aSees = listIdsOf(aList);
  const bSees = listIdsOf(bList);
  check('12k2. property 3: A sees their own private set and not Bs, B sees theirs and not As, on rows the vendor owns identically',
    aList.status === 200 && bList.status === 200 && aSees.includes(aId) && !aSees.includes(bId)
      && bSees.includes(bId) && !bSees.includes(aId),
    `A sees ${JSON.stringify(aSees)} (own ${aId}) | B sees ${JSON.stringify(bSees)} (own ${bId})`);

  // The superseded rule, run over the very rows above. Keyed on the vendor slot it can only answer
  // for both players at once or for neither, which is the concrete form of the bug 12b4 refuses.
  const legacyScoped = ['3', '4', CLUB_ACCOUNT_ID].map((who) => ({ who,
    matched: pair.filter((row) => String(row.user_id) === who).map((row) => String(row.id)) }));
  check('12k3. and the old user_id clause is not a stylistic difference: on these rows it matches nobody who asked and everybody who did not',
    legacyScoped.find((r) => r.who === '3').matched.length === 0
      && legacyScoped.find((r) => r.who === '4').matched.length === 0
      && legacyScoped.find((r) => r.who === CLUB_ACCOUNT_ID).matched.length === 2,
    JSON.stringify(legacyScoped));

  // …and the projection, which is the half the storage columns cannot show. A response may carry the
  // field the client has always called `user_id` ONLY because the relay puts the application owner in
  // it; the account that actually owns the stored row must appear nowhere in the answer. Asserted on
  // the list and on the single read, because they are shaped by two different functions and either
  // one drifting would put the service account on the screen as the owner of a player set.
  const aReadOwn = await call('GET', `/tournaments/${aId}`, { token: 'tok-member10' });
  const aListRow = (aList.body?.data?.tournaments ?? []).find((row) => String(row.id) === aId) ?? null;
  const bListRow = ((await call('GET', '/tournaments', { token: 'tok-member11' })).body?.data?.tournaments ?? [])
    .find((row) => String(row.id) === bId) ?? null;
  // A value search over the answer, not a substring over its serialisation: a bare `includes` on
  // '99' would be satisfied or broken by an unrelated id, and neither result would mean anything.
  const carriesValue = (node, wanted) => {
    if (node === null || node === undefined) return false;
    if (Array.isArray(node)) return node.some((item) => carriesValue(item, wanted));
    if (typeof node === 'object') return Object.values(node).some((item) => carriesValue(item, wanted));
    return String(node) === String(wanted);
  };
  check('12k4. property 1 and 3 on the wire: every tournament response names the OWNER in user_id, and the service account appears in no answer at all',
    aListRow?.user_id === '3' && bListRow?.user_id === '4'
      && aReadOwn.status === 200 && String(aReadOwn.body?.data?.user_id) === '3'
      && !carriesValue(aList.body?.data, CLUB_ACCOUNT_ID)
      && !carriesValue(aReadOwn.body?.data, CLUB_ACCOUNT_ID)
      && !carriesValue(bList.body?.data, CLUB_ACCOUNT_ID),
    `A=${JSON.stringify(aListRow?.user_id)} B=${JSON.stringify(bListRow?.user_id)} read=${JSON.stringify(aReadOwn.body?.data?.user_id)} `
      + `onTheWire=${JSON.stringify([aListRow, bListRow, aReadOwn.body?.data].map((r) => r?.user_id))}`);

  // Property 6, on the write and on the read. The attempt belongs to the player in the player
  // column; the wire's legacy user_id field carries that player because the relay projected it
  // there, and not the account whose stored row it is.
  const recorded = await call('POST', `/tournaments/${bId}/attempts`, { token: 'tok-member11',
    body: { board_number: '1', original_seat: 'North', recorded_hand_id: 'rh-12l-4' } });
  const attemptRow = rowsOf('tournament_attempts').find((row) => String(row.recorded_hand_id) === 'rh-12l-4');
  const aReadB = await call('GET', `/tournaments/${bId}/attempts`, { token: 'tok-member10' });
  check('12l. property 6: an attempt is attributed by player_user_id, its wire user_id is that player and never the row owner, and another player cannot read it',
    recorded.status === 200 && !!attemptRow
      && String(attemptRow.player_user_id) === '4' && String(attemptRow.user_id) === CLUB_ACCOUNT_ID
      && String(recorded.body?.data?.user_id ?? recorded.body?.user_id ?? '') === '4'
      && aReadB.status === 403,
    `stored=${JSON.stringify(attemptRow ?? null).slice(0, 150)} wire=${JSON.stringify(recorded.body?.data ?? recorded.body).slice(0, 90)} otherPlayer=${aReadB.status}`);
}

// ══ 13. ONE MEMBERSHIP RULE, ONE ENVELOPE, NO LEAKS ════════════════════════
const tournamentDir = path.join(ROOT, 'tournaments');
const tournamentFiles = fs.readdirSync(tournamentDir).filter((name) => name.endsWith('.js')).sort();
const tournamentSources = tournamentFiles.map((name) => ({ name, text: fs.readFileSync(path.join(tournamentDir, name), 'utf8') }));
// Comments stripped, because these files DOCUMENT the tables they refuse to name, and a scan over prose
// would flag the sentence that forbids it.
const codeOnly = (text) => text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
// A store reaches a table by NAME, so the scan looks for the quoted identifier a read would carry — not
// for the word. These files DOCUMENT that they refuse to name the club tables, and a prose scan would
// flag the sentence that forbids it (the same trap the club gate documents for `secret_key`).
const clubTableMentions = [];
for (const { name, text } of tournamentSources) {
  for (const clubTable of ['system_admins', 'club_memberships', 'club_board_collections', 'club_collection_boards', 'clubs']) {
    if (new RegExp(`['"\`]${clubTable}['"\`]`).test(codeOnly(text))) clubTableMentions.push(`${name}:${clubTable}`);
  }
}
check('13a. no file in tournaments/ names a club or system_admins table as an identifier',
  clubTableMentions.length === 0 && tournamentFiles.length === 5,
  `${clubTableMentions.join(',')} | files ${tournamentFiles.join(',')}`);
// CALLS on an object, not identifiers: the decision file legitimately passes a property NAMED
// `clubStatus:` into the club feature's own predicate, and matching the bare word would flag the reuse
// rather than the duplication this arm is looking for.
const clubAuthorityCallers = [...new Set(tournamentSources
  .filter(({ text }) => /\.(getMembership|clubStatus|isSystemAdmin)\s*\(/.test(codeOnly(text)))
  .map((entry) => entry.name))].sort();
check('13b. club authority is called only from the bridge wiring and the store, never from the decision file',
  JSON.stringify(clubAuthorityCallers) === JSON.stringify(['index.js', 'tournamentNcbStore.js'])
    && tournamentSources.some(({ text }) => /require\(['"]\.\.\/clubs\/clubSchema\.js['"]\)/.test(codeOnly(text)))
    && /isEffectiveMembership\(/.test(codeOnly(tournamentSources.find((entry) => entry.name === 'tournamentAuthorization.js').text)),
  clubAuthorityCallers.join(','));
// The header NAME is quoted here on purpose: `tournamentAuthorization.js` contains the letters
// "Authorization" in its own file name, and a loose scan flags the module for being named after what it
// refuses to read.
const bearerReads = tournamentSources.filter(({ text }) => /req\.headers|getBearerToken|resolveSessionUser|\[['"]authorization['"]\]|["']Authorization["']/i.test(codeOnly(text)));
check('13c. no tournament module reads a bearer; identity arrives only through the injected resolver',
  bearerReads.length === 0, bearerReads.map((entry) => entry.name).join(','));
const credentialNames = ['CLUB_NCB_EMAIL', 'CLUB_NCB_PASSWORD', 'secret_key', 'DATABASE_URL', 'NCB_SECRET'];
const credentialHits = [];
for (const { name, text } of tournamentSources) {
  for (const needle of credentialNames) {
    // The account is reached through the shared client, so these names may appear only in `index.js`,
    // which builds it — never in a store or a route.
    if (codeOnly(text).includes(needle) && name !== 'index.js') credentialHits.push(`${name}:${needle}`);
  }
}
check('13d. no credential name appears in a store, a route or the schema (only the mount builds the client)',
  credentialHits.length === 0, credentialHits.join(','));
const successEnvelope = await call('GET', '/tournaments/pubp', { token: SUPER_TOKEN });
check('13e. success is `{status:"success", data}` and a refusal is `{error, detail}` — the relay envelope',
  successEnvelope.body?.status === 'success' && 'data' in successEnvelope.body
    && strangerReadProbe(),
  `${successEnvelope.status} ${successEnvelope.text.slice(0, 120)}`);
function strangerReadProbe() {
  // Checked synchronously against the refusals already collected in `seenBodies`: every refusal this run
  // served carried both names.
  const refusals = seenBodies.filter((text) => text.includes('"error"'));
  return refusals.length > 5 && refusals.every((text) => text.includes('"detail"'));
}
const knownRedReasons = Object.entries(tournamentStoreErrorStatus).filter(([, status]) => !(Number.isInteger(status) && status >= 400 && status <= 599));
check('13f. every entry in the store-error status table is a real HTTP failure status',
  Object.keys(tournamentStoreErrorStatus).length > 20 && knownRedReasons.length === 0,
  knownRedReasons.map(([k, v]) => `${k}=${v}`).join(','));
check('13g. the reasons the contract calls AMBIGUOUS are all mapped away from 200 here',
  ['write_unverified', 'import_unverified', 'publish_refused_unverified'].every((reason) => tournamentStoreErrorStatus[reason] >= 422)
    && tournamentStoreErrorStatus.import_incomplete === 422
    && tournamentStoreErrorStatus.duplicate_import === 409
    && tournamentStoreErrorStatus.tournament_name_mismatch === 409,
  JSON.stringify(canonical(tournamentStoreErrorStatus)).slice(0, 200));
const leakables = [CLUB_PASSWORD, CLUB_SESSION_TOKEN, 'secret_key', SUPER_TOKEN, 'tok-member10', 'Bearer '];
const leaked = leakables.filter((needle) => seenBodies.some((text) => text.includes(needle)));
check('13h. no service-account credential, caller token or bearer value appeared in any response body',
  leaked.length === 0, leaked.join(','));
const health = await (await realFetch(`${BASE}/health`)).json().catch(() => ({}));
check('13i. /health describes tournaments in booleans and counts, with no table, column or credential',
  health?.tournaments && typeof health.tournaments.configured === 'boolean'
    && health.tournaments.routes === 12 && health.tournaments.membershipBridge === 'club-store'
    && !JSON.stringify(health.tournaments).includes(CLUB_ACCOUNT_EMAIL)
    && !JSON.stringify(health.tournaments).includes('hands_json'),
  JSON.stringify(health?.tournaments ?? {}));

// ══ 14. THE SHIP SURFACE, AND THIS GATE ITSELF ═════════════════════════════
const dockerfile = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');
// INSTRUCTIONS ONLY. A `#`-commented COPY line is not a Dockerfile instruction: the image would ship without
// the directory while a raw regex still found the text. A negative control proved the previous form was
// decoration — commenting the line out left this arm green while the container could not have started.
const dockerInstructions = dockerfile.split(/\r?\n/).filter((line) => !/^\s*#/.test(line)).join('\n');
check('14a. the Dockerfile ships the tournaments directory the relay requires at startup',
  /COPY\s+tournaments\/?\s+\.\/tournaments\/?/.test(dockerInstructions)
    && /require\(["']\.\/tournaments["']\)/.test(fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8')),
  dockerInstructions.split(/\r?\n/).filter((line) => line.startsWith('COPY')).join(' | '));
check('14b. every tournament module is CommonJS, because the relay is loaded with require()',
  tournamentSources.every(({ text }) => !/^\s*(import|export)\s/m.test(text)),
  tournamentSources.filter(({ text }) => /^\s*(import|export)\s/m.test(text)).map((entry) => entry.name).join(','));
const envExample = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
check('14c. .env.example documents both schema variables and the composite unique, and drops the old grant',
  /TOURNAMENT_NCB_SCHEMA_JSON/.test(envExample) && /TOURNAMENT_NCB_SCHEMA_FILE/.test(envExample)
    && /UNIQUE\(tournament_id, board_number\)/.test(envExample)
    && /tournament_via_gateway_only/.test(envExample)
    && !/recorded_hands, community_games, replay_attempts, game_analysis_reports, tournaments/.test(envExample),
  envExample.split(/\r?\n/).filter((line) => /tournaments,$|TOURNAMENT_NCB_SCHEMA|via_gateway/.test(line)).slice(0, 4).join(' | '));
// Tested on ASSIGNMENTS and CODE, not on prose: this very file documents that no
// `TOURNAMENT_NCB_EMAIL` exists, and a substring scan would flag the sentence that forbids it.
check('14d. no tournament-specific credential name was introduced (and none is read in code)',
  !/^\s*TOURNAMENT_NCB_(EMAIL|PASSWORD|TOKEN|SECRET|KEY)\s*=/m.test(envExample)
    && !/TOURNAMENT_NCB_(EMAIL|PASSWORD|TOKEN|SECRET|KEY)/.test(tournamentSources.map((entry) => codeOnly(entry.text)).join('')),
  (envExample.match(/^\s*TOURNAMENT_NCB_[A-Z_]+\s*=/gm) ?? []).join(',').trim());
const boot = spawnSync(process.execPath, [path.join(ROOT, 'bridge.js')], {
  env: { ...process.env, PORT: '0', BRIDGE_API_KEY: 'x' }, cwd: ROOT, encoding: 'utf8', timeout: 8000
});
const bootLine = `${boot.stdout ?? ''}${boot.stderr ?? ''}`;
check('14e. the relay still boots with tournaments mounted, and prints its tournament state',
  /tournament storage/i.test(bootLine) && !/Cannot find module|SyntaxError|ReferenceError|TypeError/.test(bootLine),
  bootLine.slice(0, 220));
check('14f. the boot line names the config reason when the schema is absent (inert is visible)',
  /tournament storage (CONFIGURED|INACTIVE)/.test(bootLine), bootLine.slice(0, 200));
const ownLines = fs.readFileSync(path.join(ROOT, 'verify-tournaments-gateway.mjs'), 'utf8').split(/\r?\n/);
// Comment lines are dropped BEFORE this file is scanned. The comments explaining this very arm contain the
// string `check(${label} …)`, and a scanner that reads its own prose counts its own examples as code —
// which is how a self-audit quietly stops describing the arms.
const ownCode = ownLines.filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line));
const ownLabels = [];
const dynamicLabelArms = [];
ownCode.forEach((line, index) => {
  const match = line.match(/check\(\s*[`'"]\s*([0-9]+[a-z0-9]*)\./);
  if (match) ownLabels.push({ label: match[1], line: index + 1 });
  // A loop arm builds its label from a fixture table (`check(\`${label} …\`)`) or forwards one held in a
  // variable (`check(label, …)`). Both are labelled — by a string this file holds as data — and 14j proves
  // the table labels are unique too.
  else if (/check\(\s*(`\$\{|label\s*,)/.test(line)) dynamicLabelArms.push(index + 1);
});
const labelCounts = {};
for (const entry of ownLabels) labelCounts[entry.label] = (labelCounts[entry.label] || 0) + 1;
const duplicatedLabels = Object.keys(labelCounts).filter((label) => labelCounts[label] > 1);
check('14g. no two checks share an arm label (a duplicate makes a FAIL ambiguous)',
  ownLabels.length > 90 && duplicatedLabels.length === 0,
  `duplicates: ${duplicatedLabels.join(',') || 'none'} of ${ownLabels.length} labeled arms`);
// The gate must not be able to congratulate itself. A `check(label, true)` or a condition that is a
// literal cannot go red, and an arm that cannot go red is worse than no arm: it buys the run a PASS.
const constantArms = ownCode
  .map((line, index) => ({ line, index }))
  .filter(({ line }) => /check\(\s*[`'"]\s*[0-9]+[a-z0-9]*\.[^)]*?,\s*(true|1|!0)\s*[,)]/.test(line));
check('14h. no arm passes a constant as its condition (every arm is capable of going red)',
  constantArms.length === 0, constantArms.map((entry) => entry.index + 1).join(','));
const labelled = ownCode.filter((line) => /^\s*check\(/.test(line)).length;
check('14i. every check() call is labelled, literally or from a fixture table',
  labelled === ownLabels.length + dynamicLabelArms.length && ownLabels.length + dynamicLabelArms.length > 150,
  `${labelled} call lines vs ${ownLabels.length} literal + ${dynamicLabelArms.length} dynamic labels`);

// ══ 15. THE CATEGORY-CHANGE MATRIX ═════════════════════════════════════════
// Which destination a caller may move a set INTO, decided by the destination and not by the source. This
// is the most damaging write the surface takes — one field would move a whole club's deals in front of
// another club's members, and every board row keeps its tournament_id so nothing else changes — so each
// cell of the matrix is measured over HTTP against storage, not against a boolean.
const VIS_MATRIX = [
  // [label, target visibility, target club, token, source row, expected status, expected reason, expected stored visibility]
  ['15a. a private owner cannot hand their set to the whole field', 'public', null, 'tok-member10', 'p3', 403, 'super_admin_required', 'private'],
  ['15b. a club admin cannot promote a club set past the field', 'public', null, 'tok-admin10', 'c10p', 403, 'super_admin_required', 'club'],
  ['15c. a private owner who admins a club may file their set under it', 'club', '10', 'tok-admin10', 'p2', 200, null, 'club'],
  ['15d. a club admin may NOT file their private set under a club they do not admin', 'club', '11', 'tok-admin10', 'p2', 403, 'not_a_club_admin', 'private'],
  ['15e. a plain member cannot move their private set into the club at all', 'club', '10', 'tok-member10', 'p3', 403, 'not_a_club_admin', 'private'],
  ['15f. the BridgeMind Admin may act for any club', 'club', '11', SUPER_TOKEN, 'pubp', 200, null, 'club'],
  ['15g. only the row\'s owner may hide it, and an admin cannot hide someone else\'s set', 'private', null, SUPER_TOKEN, 'c10p', 403, 'owner_only', 'club'],
  ['15h. a club set cannot be demoted to private even by its own importer', 'private', null, 'tok-admin10', 'c10p', 403, 'club_scope_mismatch', 'club'],
  ['15i. the public field cannot be pulled into a private account by anybody', 'private', null, SUPER_TOKEN, 'pubd', 403, 'super_admin_required', 'public'],
  ['15j. a category outside the vocabulary is refused with invalid_visibility', 'shared', null, SUPER_TOKEN, 'pubd', 400, 'invalid_visibility', 'public'],
  ['15k. the club category without a club is refused with invalid_club_id', 'club', null, SUPER_TOKEN, 'pubd', 400, 'invalid_club_id', 'public']
];
const normClub = (value) => (value === null || value === undefined ? '' : String(value));
function rowFixtureClub(id) {
  const found = TOURNAMENT_SEED.tournaments.find((row) => row.id === id);
  return normClub(found?.club_id);
}
for (const [label, visibility, clubId, token, source, wantStatus, wantReason, wantStored] of VIS_MATRIX) {
  resetTournamentTables();
  const body = clubId === null ? { visibility } : { visibility, club_id: clubId };
  const answer = await call('POST', `/tournaments/${source}/visibility`, { token, body });
  const stored = rowOf('tournaments', source);
  // The club the row must carry afterwards: the NEW one on a successful move into the club category, the
  // fixture's own value in every other case. Comparing it is what distinguishes "the write applied the
  // scope the decision named" from "the write changed visibility and quietly dropped the club".
  const wantClub = wantStatus === 200 && visibility === 'club' ? clubId : rowFixtureClub(source);
  check(`${label} (stored visibility stays ${wantStored})`,
    answer.status === wantStatus && (wantReason === null || answer.body?.error === wantReason)
      && stored?.visibility === wantStored && normClub(stored?.club_id) === wantClub,
    `${answer.status}/${answer.body?.error} stored=${stored?.visibility}/${stored?.club_id} want ${wantStored}/${wantClub}`);
}
resetTournamentTables();
const sameCategoryNoop = await call('POST', '/tournaments/c10p/visibility', { token: 'tok-admin10', body: { visibility: 'club', club_id: '10' } });
check('15l. re-stating the current category AND club is a no-op, not a refusal (a screen may post what it shows)',
  sameCategoryNoop.status === 200 && sameCategoryNoop.body?.data?.visibility === 'club'
    && sameCategoryNoop.body.data.club_id === '10',
  `${sameCategoryNoop.status} ${sameCategoryNoop.text.slice(0, 160)}`);
const sameCategoryOtherClub = await call('POST', '/tournaments/c10p/visibility', { token: 'tok-admin10', body: { visibility: 'club', club_id: '11' } });
// The contract names two refusals for a cross-club move — `not_a_club_admin` (the caller does not admin
// the club they are aiming at) and `club_scope_mismatch` (the row belongs elsewhere) — and the first test
// is reached first, so an admin of club 10 aiming at club 11 is answered `not_a_club_admin`. The
// `club_scope_mismatch` line inside `visibilityTargetDecision` is therefore unreachable for a non-super
// caller: any caller who passes the admin-of-target test and still manages the row must already have the
// row in the same club. Measured, not assumed, and reported as a contract observation rather than
// "fixed" here — 15mc proves the refusal that IS reached, and 12d proves NodeSend matches the contract
// over the whole input space including that line.
check('15m. club→club with a DIFFERENT club is refused, not treated as the no-op above',
  sameCategoryOtherClub.status === 403 && sameCategoryOtherClub.body?.error === 'not_a_club_admin'
    && rowOf('tournaments', 'c10p').club_id === '10',
  `${sameCategoryOtherClub.status} ${sameCategoryOtherClub.text.slice(0, 160)}`);
const strangerClubMove = await call('POST', '/tournaments/c10p/visibility', { token: 'tok-admin11', body: { visibility: 'club', club_id: '11' } });
check('15mc. and the admin of the club being aimed at still cannot pull another club\u2019s set',
  strangerClubMove.status === 403 && strangerClubMove.body?.error === 'club_scope_mismatch'
    && rowOf('tournaments', 'c10p').club_id === '10',
  `${strangerClubMove.status} ${strangerClubMove.text.slice(0, 160)}`);
resetTournamentTables();
const promotedThenVisible = await call('POST', '/tournaments/p2/visibility', { token: 'tok-admin10', body: { visibility: 'club', club_id: '10' } });
const memberNowSeesIt = await call('GET', '/tournaments/p2', { token: 'tok-member10' });
check('15n. a set moved into the club is still unpublished, so its members cannot read it yet',
  promotedThenVisible.status === 200 && memberNowSeesIt.status === 403
    && memberNowSeesIt.body?.error === 'tournament_not_published',
  `${promotedThenVisible.status} → ${memberNowSeesIt.status}/${memberNowSeesIt.body?.error}`);
resetTournamentTables();
const renamed = await call('PATCH', '/tournaments/c10p', { token: 'tok-admin10', body: { name: 'Glyfada   Round  One' } });
check('15o. rename writes the collapsed name and reads back (a 200 over an unconfirmed write is refused)',
  renamed.status === 200 && renamed.body?.data?.name === 'Glyfada Round One'
    && renamed.body.data.unverified === false && rowOf('tournaments', 'c10p').name === 'Glyfada Round One',
  `${renamed.status} ${renamed.text.slice(0, 200)}`);
const renameEmpty = await call('PATCH', '/tournaments/c10p', { token: 'tok-admin10', body: { name: '   ' } });
check('15p. a blank rename is refused and the stored name is untouched',
  renameEmpty.status === 400 && rowOf('tournaments', 'c10p').name === 'Glyfada Round One',
  `${renameEmpty.status} ${JSON.stringify(rowOf('tournaments', 'c10p').name)}`);
const renameNothing = await call('PATCH', '/tournaments/c10p', { token: 'tok-admin10', body: {} });
check('15q. a PATCH naming no field is refused rather than silently succeeding',
  renameNothing.status === 400, `${renameNothing.status} ${renameNothing.text.slice(0, 140)}`);
const sourceLabelCleared = await call('PATCH', '/tournaments/c10p', { token: 'tok-admin10', body: { source_label: '' } });
check('15r. source_label may be cleared, and the clear is confirmed against the stored row',
  sourceLabelCleared.status === 200 && sourceLabelCleared.body?.data?.source_label === null
    && rowOf('tournaments', 'c10p').source_label === null,
  `${sourceLabelCleared.status} ${JSON.stringify(rowOf('tournaments', 'c10p').source_label)}`);
resetTournamentTables();
const clubRenameDenied = await call('PATCH', '/tournaments/c10p', { token: 'tok-member11', body: { name: 'Nobody Renames' } });
check('15s. another club\'s admin cannot rename this club\'s set (and the row says so)',
  clubRenameDenied.status === 403 && rowOf('tournaments', 'c10p').name === 'Glyfada Round 1',
  `${clubRenameDenied.status} ${JSON.stringify(rowOf('tournaments', 'c10p').name)}`);

// The pure decision, called with a fake identity and a fake row — no storage, no HTTP. Section 12 proves
// it agrees with the contract; these arms prove the ROUTER's dispatch table maps each refusal to the
// status the published vocabulary expects.
const pureArms = [
  ['15t. an empty session id is 401, not a permission answer', { op: 'readTournament', session: { userId: '' }, row: { visibility: 'private', status: 'published', ownerId: '', clubId: '' } }, 401, 'authentication_required'],
  ['15u. list has no permission to refuse (scope, not gate)', { op: 'listTournaments', session: { userId: '5' }, columns: CONTRACT_LITERAL_TOURNAMENT_COLUMNS }, 0, null],
  ['15u2. list with no owner column named is a 503 under its own name, not an empty scope', { op: 'listTournaments', session: { userId: '5' } }, 503, 'tournament_identity_column_unconfigured'],
  ['15v. a create aimed at public by an ordinary session is 403', { op: 'createTournament', session: { userId: '5' }, targetVisibility: 'public' }, 403, 'super_admin_required'],
  ['15w. a create with a malformed category is 400, not 403', { op: 'createTournament', session: { userId: '5' }, targetVisibility: 'weird' }, 400, 'invalid_visibility'],
  ['15x. an unknown operation is 400, never allowed by default', { op: 'deleteEverything', session: { userId: '5' } }, 400, 'unknown_operation'],
  ['15y. a club admin moving a set to a club they do not admin is 403 not_a_club_admin', {
    op: 'setVisibility', session: { userId: '2' }, membership: { clubId: '10', role: 'club_admin' },
    row: { visibility: 'club', status: 'published', ownerId: '2', clubId: '10' }, targetVisibility: 'club', targetClubId: '11'
  }, 403, 'not_a_club_admin'],
  ['15z. importing for an INACTIVE club is 403 club_inactive even for the BridgeMind Admin', {
    op: 'createTournament', session: { userId: '1' }, targetVisibility: 'club', targetClubId: '12', clubActive: false, storeSuperAdmin: true
  }, 403, 'club_inactive'],
  ['15aa. importing a private set needs no privilege at all', { op: 'createTournament', session: { userId: '5' }, targetVisibility: 'private' }, 0, null]
];
for (const [label, args, wantStatus, wantReason] of pureArms) {
  const decision = tournamentAuthorize(args);
  const allowed = decision.allow === true;
  check(label,
    (wantStatus === 0 && allowed)
      || (!allowed && decision.status === wantStatus && decision.body?.error === wantReason),
    JSON.stringify(decision).slice(0, 160));
}
// The 15y arm above must not be the only thing standing between a bug and a cross-club move: prove the
// decision ALSO refuses to hand back a scope that could be applied.
const crossScopeCheck = tournamentAuthorize({
  op: 'setVisibility', session: { userId: '2' }, membership: { clubId: '10', role: 'club_admin' },
  row: { visibility: 'club', status: 'published', ownerId: '2', clubId: '10' }, targetVisibility: 'club', targetClubId: '11'
});
check('15ab. a refused category change carries no scope to apply',
  crossScopeCheck.allow !== true && crossScopeCheck.scope === undefined,
  JSON.stringify(crossScopeCheck).slice(0, 160));

// ══ 14j. THE FIXTURE-TABLE LABELS TOO (evaluated last, once every table exists) ══
// A loop arm takes its label from a data table, so a duplicate can hide there exactly as it can in a
// literal — and two arms sharing a label make a printed FAIL ambiguous about which one broke.
// Only the tables whose FIRST column is a label are scanned here — the probe tables (`identityAttempts`,
// `privateProbes`, `listIdentityQueries`) start with a method name, so their arm labels live in the
// `check(...)` call itself and are already covered by 14g.
const loopLabelTables = [VIS_MATRIX, badBoardArms, pureArms];
const loopLabelSources = loopLabelTables
  .flatMap((table) => table.map((row) => String(row[0] ?? '')))
  .filter((value) => /^[0-9]+[a-z0-9]*\./.test(value));
const loopLabelCounts = {};
for (const value of loopLabelSources) {
  const key = value.split('.')[0];
  loopLabelCounts[key] = (loopLabelCounts[key] || 0) + 1;
}
const duplicatedLoopLabels = Object.keys(loopLabelCounts).filter((key) => loopLabelCounts[key] > 1);
check('14j. no two loop arms share a label either (the fixture tables are label sources too)',
  loopLabelSources.length >= 25 && duplicatedLoopLabels.length === 0,
  `duplicates: ${duplicatedLoopLabels.join(',') || 'none'} of ${loopLabelSources.length} table labels`);

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

