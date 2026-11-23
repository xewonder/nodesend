/*
 * NodeSend TOURNAMENTS — LIVE IMPORT-FAILURE REGRESSION GATE
 *
 * WHY THIS FILE EXISTS. On 2026-11-23 the first real PBN import against production (32 boards) answered
 * 422 `import_incomplete` with "0/32 board write(s) reported success" — and the answer carried NOTHING
 * that identifies why NCB refused. Neither existing gate could see it: `verify-tournaments-gateway.mjs`
 * fails a board write only through its own `failBoardCreate` knob, and `verify-tournaments-integration
 * .mjs` answers `create` unconditionally with `{status:"success",data:{...row}}`. Both mocks therefore
 * accept any body a legal import can produce, so a vendor that rejects a legal deal on a STORAGE rule
 * was unreachable from CI. This is the `offset=` lesson again, one layer down: a mock that enforces only
 * the rules its author thought of proves the code against those rules and nothing else.
 *
 * So this gate models a vendor with COLUMN DEFINITIONS and a GRANT, and turns each on as a knob:
 *   · VARCHAR(255) on hands_json   — a complete legal deal serialises to 299 characters (measured, and
 *                                    asserted below), so EVERY board of a real PBN set is refused while
 *                                    the header row, whose values are all short, is accepted. That is the
 *                                    exact production signature: 1 header written, 32/32 boards refused.
 *   · NOT NULL without a default   — refuses every insert that omits the column.
 *   · no INSERT grant              — answers 403, which the account client reports as its own reason.
 *   · accepted-but-not-stored      — 2xx with nothing written, the path that must yield
 *                                    `import_unverified` and must NEVER claim an upstream refusal.
 *   · echoes the submitted value   — the safety test for the new diagnostic: a vendor that quotes the
 *                                    deal back must not turn the player's cards into an API response.
 *
 * READ-ONLY OUTSIDE THIS PROCESS. Nothing here contacts a real endpoint: `NCB_PROXY_BASE` is a reserved
 * `.invalid` name and the fetch shim fails the run on any other host.
 *
 *   node verify-tournament-import-failure.mjs
 */
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));

const MOCK_HOST = 'https://ncb.importfail.invalid';
const MOCK_HOST_URBAN = 'ncb.importfail.invalid';
const SERVICE_ID = '99';
const SERVICE_EMAIL = 'club-service-account@bridgemind.invalid';
const SERVICE_TOKEN = 'importfail-fixture-service-bearer-0123456789';
const PASSWORD = 'importfail-fixture-not-a-credential-0123456789';
const OWNER_TOKEN = 'tok-owner-1';
const OWNER = { id: '3', email: 'owner@example.test' };

process.env.BRIDGE_API_KEY = 'relay-api-key-not-a-tournament-secret';
process.env.NCB_PROXY_BASE = MOCK_HOST;
process.env.NCB_INSTANCE = '55954_bridgemind';
process.env.NCB_TRANSPORT = 'proxy';
process.env.CLUB_NCB_EMAIL = SERVICE_EMAIL;
process.env.CLUB_NCB_PASSWORD = PASSWORD;
process.env.CLUB_NCB_EXPECTED_USER_ID = SERVICE_ID;
delete process.env.NCB_SESSION_SEAL_KEY;
delete process.env.NODESEND_PRIVATE_KEY_B64;

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
// The live spellings, including the optional roles a real deployment declares.
const TOURNAMENT_SCHEMA = {
  tables: { tournaments: 'tournaments', boards: 'tournament_boards', attempts: 'tournament_attempts' },
  columns: {
    tournaments: {
      id: 'id', userId: 'owner_user_id', clubId: 'club_id', name: 'name', visibility: 'visibility',
      status: 'status', boardCount: 'board_count', sourceLabel: 'source_label', dedupeKey: 'dedupe_key'
    },
    boards: {
      id: 'id', tournamentId: 'tournament_id', boardNumber: 'board_number', dealer: 'dealer',
      vulnerability: 'vulnerability', handsJson: 'hands_json', tagsJson: 'tags_json'
    },
    attempts: {
      id: 'id', tournamentId: 'tournament_id', boardNumber: 'board_number',
      recordedHandId: 'recorded_hand_id', originalSeat: 'original_seat', userId: 'player_user_id'
    }
  }
};
process.env.CLUB_NCB_SCHEMA_JSON = JSON.stringify(CLUB_SCHEMA);
process.env.TOURNAMENT_NCB_SCHEMA_JSON = JSON.stringify(TOURNAMENT_SCHEMA);

// ── the vendor this gate models ────────────────────────────────────────────────────────────────
const rows = {
  system_admins: [], clubs: [{ id: '10', name: 'Glyfada BC', active: 1 }],
  club_memberships: [], tournaments: [], tournament_boards: [], tournament_attempts: []
};
const COLUMNS = {
  system_admins: ['id', 'admin_user_id', 'user_id'],
  clubs: ['id', 'name', 'active'],
  club_memberships: ['id', 'id2', 'member_user_id', 'club_id', 'role', 'status', 'user_id'],
  tournaments: ['id', 'owner_user_id', 'club_id', 'name', 'visibility', 'status', 'board_count', 'source_label', 'dedupe_key', 'user_id'],
  tournament_boards: ['id', 'tournament_id', 'board_number', 'dealer', 'vulnerability', 'hands_json', 'tags_json', 'user_id'],
  tournament_attempts: ['id', 'tournament_id', 'board_number', 'recorded_hand_id', 'original_seat', 'player_user_id', 'user_id']
};
// Per-column storage definitions. This is the half the other two mocks are missing: a column is not a
// name, it has a TYPE and a WIDTH, and it can be missing from the grant.
const VENDOR = {
  handsJsonColumnChars: 4096,      // TEXT-ish today; 255 reproduces the leading production hypothesis
  requiredNoDefault: null,         // a column name that is NOT NULL with no default value
  insertGrantDenied: new Set(),    // tables the service account may not insert into
  refuseBoardNumbers: new Set(),   // per-row refusal, the only way to get a PARTIAL landing left
  plantedProse: '',                // vendor prose carrying a secret the account client was never given
  rawProse: null,                  // an ARBITRARY upstream error sentence, for the disclosure matrix
  acceptButDoNotStore: false,      // 2xx that writes nothing (the documented NCB behaviour)
  echoSubmittedValue: false,       // an error body that quotes the value back
  createResponseShape: 'id'        // 'id' | 'no-id' | 'bare'
};
let nextId = 500;
const calls = { data: [], auth: [], offHost: [] };

// The three uniques the migration is said to have created, enforced here because duplicate-import
// handling cannot be tested against a vendor that has no indexes. NULL/absent never collides — that is
// why the store OMITS dedupe_key rather than sending an empty string.
const UNIQUE = {
  tournaments: [{ cols: ['dedupe_key'], key: 'uk_dedupe' }],
  tournament_boards: [{ cols: ['tournament_id', 'board_number'], key: 'uk_tournament_board' }],
  tournament_attempts: [{ cols: ['recorded_hand_id'], key: 'uk_recorded_hand' }]
};
function uniqueViolation(table, body) {
  for (const u of UNIQUE[table] ?? []) {
    if (u.cols.some((c) => body[c] === undefined || body[c] === null || body[c] === '')) continue;
    const clash = rows[table].some((row) => u.cols.every((c) => String(row[c] ?? '') === String(body[c])));
    if (clash) return `Duplicate entry '${u.cols.map((c) => body[c]).join('-')}' for key '${u.key}'`;
  }
  return null;
}

const realFetch = globalThis.fetch;
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const RESERVED = ['limit', 'page', 'sort', 'order', 'Instance'];
let LOOPBACK = '';

globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  const { host, pathname, searchParams } = new URL(target);
  if (host === LOOPBACK) return realFetch(url, init);
  if (host !== MOCK_HOST_URBAN) {
    calls.offHost.push(`${host}${pathname}`);
    throw new TypeError(`import-failure gate refused an off-mock request to ${host}`);
  }
  const method = String(init.method ?? 'GET').toUpperCase();
  const bearer = String(init?.headers?.Authorization ?? init?.headers?.authorization ?? '').replace(/^Bearer\s+/, '');
  const body = init.body ? JSON.parse(init.body) : null;

  if (pathname === '/auth/sign-in/email') {
    calls.auth.push(pathname);
    if (body?.email !== SERVICE_EMAIL || body?.password !== PASSWORD) return json({ status: 'error', message: 'invalid credentials' }, 401);
    return json({ token: SERVICE_TOKEN, user: { id: SERVICE_ID, email: SERVICE_EMAIL } });
  }
  if (pathname === '/auth/get-session') {
    calls.auth.push(pathname);
    if (bearer === SERVICE_TOKEN) return json({ data: { user: { id: SERVICE_ID, email: SERVICE_EMAIL } } });
    if (bearer === OWNER_TOKEN) return json({ data: { user: { id: OWNER.id, email: OWNER.email } } });
    return json({ status: 'error', message: 'invalid session' }, 401);
  }
  if (!pathname.startsWith('/data/')) return json({ status: 'error', message: `unexpected mock path ${pathname}` }, 404);

  calls.data.push({ pathname, method, bearer, body });
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
    const found = list.filter((row) => String(row.user_id ?? '') === SERVICE_ID)
      .filter((row) => Object.entries(filters).every(([k, v]) => String(row[k] ?? '') === v));
    const limit = Number(searchParams.get('limit'));
    return json({ status: 'success', data: Number.isFinite(limit) && limit > 0 ? found.slice(0, limit) : found });
  }
  if (action === 'create') {
    if (VENDOR.insertGrantDenied.has(table)) {
      return json({ status: 'error', message: `permission denied for table ${table}` }, 403);
    }
    // THE DISCLOSURE MATRIX HOOK. Whatever sentence a vendor might answer with, verbatim — this is how
    // the arms below put a complete deal, a JWT, an internal host or a connection string in front of the
    // store and then check what came out of the HTTP response.
    if (VENDOR.rawProse !== null && table === 'tournament_boards') {
      return json({ status: 'failed', error: VENDOR.rawProse }, 500);
    }
    // A per-row refusal. Needed because a LEGAL deal is always 299 characters, so a width rule refuses
    // every board or none — and "every board or none" cannot produce the partial landing that the
    // compensating delete is designed for. This is the only honest way to reach that path.
    if (table === 'tournament_boards' && VENDOR.refuseBoardNumbers.has(String(body?.board_number ?? ''))) {
      return json({ status: 'failed', error: `Data too long for column 'hands_json' at row 1` }, 500);
    }
    // THE COLUMN-DEFERENCE CHECKS A NAME-ONLY MOCK CANNOT MAKE.
    if (VENDOR.requiredNoDefault && table === 'tournament_boards' && !(VENDOR.requiredNoDefault in (body ?? {}))) {
      return json({ status: 'failed', error: `Field '${VENDOR.requiredNoDefault}' doesn't have a default value` }, 500);
    }
    const clash = uniqueViolation(table, body ?? {});
    if (clash) return json({ status: 'failed', error: clash }, 500);
    const hands = String(body?.hands_json ?? '');
    if (table === 'tournament_boards' && hands.length > VENDOR.handsJsonColumnChars) {
      const echoed = VENDOR.echoSubmittedValue ? ` value '${hands}'` : '';
      // Planted prose the account client knows nothing about, so only the store's OWN scrubbing can
      // remove it. Without this arm a green "no credential in the body" would only prove the client's
      // redaction covers the three secrets it was handed.
      const planted = VENDOR.plantedProse ? ` ${VENDOR.plantedProse}` : '';
      return json({
        status: 'failed',
        error: `Data too long for column 'hands_json' at row 1${echoed}${planted}`
      }, 500);
    }
    if (VENDOR.acceptButDoNotStore) {
      // 2xx, "success", nothing written — exactly what the invitation probe measured on deletes.
      return json({ status: 'success', data: { id: String(nextId++) } });
    }
    const { user_id: claimed, ...stored } = body ?? {};
    const row = { id: String(nextId++), ...stored, user_id: SERVICE_ID };
    list.push(row);
    if (VENDOR.createResponseShape === 'no-id') return json({ status: 'success', data: { ...row, id: undefined } });
    if (VENDOR.createResponseShape === 'bare') return json({ status: 'success' });
    return json({ status: 'success', data: { ...row } });
  }
  if (action === 'update') {
    const row = list.find((c) => String(c.id) === String(rowId) && String(c.user_id ?? '') === SERVICE_ID);
    if (!row) return json({ status: 'error', message: 'no such row' }, 404);
    Object.assign(row, body ?? {});
    return json({ status: 'success', data: { ...row } });
  }
  if (action === 'delete') {
    const index = list.findIndex((c) => String(c.id) === String(rowId));
    if (index === -1) return json({ status: 'error', message: 'no such row' }, 404);
    list.splice(index, 1);
    return json({ status: 'success', data: { id: rowId } });
  }
  return json({ status: 'error', message: `unexpected mock action ${action}` }, 404);
};

const bridge = require(path.join(ROOT, 'bridge.js'));
const { app } = bridge;
const server = app.listen(0, '127.0.0.1');
await new Promise((resolve) => server.once('listening', resolve));
LOOPBACK = `127.0.0.1:${server.address().port}`;
const BASE = `http://127.0.0.1:${server.address().port}`;

// ── legal PBN deals, built from the repository's own deck ───────────────────────────────────────
const SUITS = ['S', 'H', 'D', 'C'];
const RANKS = ['2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A'];
const DECK = SUITS.flatMap((s) => RANKS.map((r) => r + s));
// A rotation of the 52-card deck, not a window: a window that wraps past card 52 hands out 9 cards to
// West and the validator refuses the board, which would test the harness's own arithmetic instead of
// the vendor's. Rotating keeps every deal a partition of one deck, so 13 cards per seat always holds.
const deal = (offset) => {
  const rot = ((offset % 52) + 52) % 52;
  const d = DECK.slice(rot).concat(DECK.slice(0, rot));
  return Object.fromEntries(['North', 'East', 'South', 'West'].map((seat, i) => [seat, d.slice(i * 13, i * 13 + 13)]));
};
const board = (n, offset = n * 4) => ({
  board_number: String(n), dealer: ['North', 'East', 'South', 'West'][(n - 1) % 4],
  vulnerability: ['None', 'NS', 'EW', 'Both'][(n - 1) % 4], hands: deal(offset),
  tags: { Contract: '1NT', Declarer: ['N', 'E', 'S', 'W'][(n - 1) % 4], Result: '=1' }
});
const boards = (count) => Array.from({ length: count }, (_, i) => board(i + 1));

const resetVendor = () => {
  Object.assign(VENDOR, {
    handsJsonColumnChars: 4096, requiredNoDefault: null, acceptButDoNotStore: false,
    echoSubmittedValue: false, createResponseShape: 'id', plantedProse: '', rawProse: null
  });
  VENDOR.insertGrantDenied = new Set();
  VENDOR.refuseBoardNumbers = new Set();
  for (const k of Object.keys(rows)) rows[k].length = 0;
  calls.data.length = 0;
  calls.offHost.length = 0;
};
const ask = async (method, p, body) => {
  const res = await fetch(BASE + p, {
    method,
    headers: { authorization: `Bearer ${OWNER_TOKEN}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  let json = null;
  try { json = await res.json(); } catch {}
  return { status: res.status, body: json };
};
const importWith = async (count) => ask('POST', '/tournaments', {
  name: 'Autumn Congress — Section A', visibility: 'private', source_label: 'pbn', boards: boards(count)
});

const results = [];
const check = (name, condition, detail = '') => {
  results.push({ name, pass: condition === true, detail: condition === true ? '' : String(detail ?? '').slice(0, 400) });
};
const text = (r) => JSON.stringify(r.body ?? {});

check('G0a. the tournament mount is configured and a real store is built, or nothing below means anything',
  bridge.tournamentMount?.configured === true && bridge.clubMount?.configured === true,
  `tournaments=${bridge.tournamentMount?.configured}:${bridge.tournamentMount?.reason ?? '-'}`);
check('G0b. a complete legal deal serialises to 299 characters, which is what a 255-column refuses',
  JSON.stringify(deal(0)).length === 299, `len=${JSON.stringify(deal(0)).length}`);

// ── the happy paths this incident needs as a reference ───────────────────────────────────────────
resetVendor();
const one = await importWith(1);
check('R1. single-board import succeeds against an unconstrained vendor',
  one.status === 200 && one.body?.data?.board_count === 1 && rows.tournament_boards.length === 1,
  `${one.status} ${text(one).slice(0, 200)}`);

resetVendor();
const thirty = await importWith(32);
check('R2. 32-board import succeeds, and every board reads back',
  thirty.status === 200 && thirty.body?.data?.board_count === 32 && rows.tournament_boards.length === 32,
  `${thirty.status} ${text(thirty).slice(0, 200)}`);
check('R3. PBN tags are stored verbatim where the deployment declares tags_json',
  rows.tournament_boards.every((r) => JSON.parse(r.tags_json).Contract === '1NT'),
  rows.tournament_boards[0]?.tags_json ?? '(no board rows)');

// ── THE INCIDENT: a storage rule refuses every board of a legal set ──────────────────────────────
resetVendor();
VENDOR.handsJsonColumnChars = 255;
const incident = await importWith(32);
const incText = text(incident);
check('R4. the production signature reproduces: 422 import_incomplete with 0/32 and all 32 named',
  incident.status === 422 && incident.body?.error === 'import_incomplete'
    && incText.includes('0/32 board write(s) reported success')
    && incident.body?.failedBoardNumbers?.length === 32,
  `${incident.status} ${incText.slice(0, 260)}`);
check('R5. the answer now NAMES the upstream refusal, which is what production could not say',
  incText.includes('upstream=') && /Data too long for column/.test(incText)
    && incText.includes('club_account_request_failed'),
  incText.slice(0, 320));
check('R6. one refusal reason is summarised once, not pasted 32 times',
  (incText.match(/Data too long for column/g) || []).length <= 2, `count=${(incText.match(/Data too long for column/g) || []).length}`);
check('R7. the failed import left no orphan: no header, no board, no attempt row',
  rows.tournaments.length === 0 && rows.tournament_boards.length === 0 && rows.tournament_attempts.length === 0,
  `hdr=${rows.tournaments.length} boards=${rows.tournament_boards.length} attempts=${rows.tournament_attempts.length}`);
check('R8. nothing was published: no status update was ever issued for the failed set',
  !calls.data.some((c) => c.pathname.startsWith('/data/update/tournaments') && /status/.test(JSON.stringify(c.body ?? {}))),
  JSON.stringify(calls.data.filter((c) => c.method === 'PUT').slice(0, 3)));
check('R9. the dead id from the failed import answers 404, not a phantom',
  (await ask('GET', `/tournaments/${incident.body?.tournamentId ?? 'zz'}`)).status === 404,
  `id=${incident.body?.tournamentId}`);

// ── the card data must not turn into an API response ─────────────────────────────────────────────
resetVendor();
VENDOR.handsJsonColumnChars = 255;
VENDOR.echoSubmittedValue = true;
const echoing = await importWith(2);
const echoText = text(echoing);
check('R10. a vendor that quotes the deal back does not put 13-card hands in the response',
  echoText.includes('Data too long for column')
    && !/("N|E|S|W?orth"\):?\[)?"?2S","?3S"?/.test(echoText) && !echoText.includes('"2S","3S","4S","5S"'),
  echoText.slice(0, 300));
check('R11. the diagnostic digest stays bounded', echoText.length < 1400, `len=${echoText.length}`);

// ── the two refusals the owner must be able to tell apart ─────────────────────────────────────────
resetVendor();
VENDOR.insertGrantDenied.add('tournament_boards');
const forbidden = await importWith(4);
check('R12. a denied INSERT grant is reported as a permission refusal, not a data problem',
  forbidden.status === 422 && text(forbidden).includes('club_account_forbidden'),
  text(forbidden).slice(0, 300));

resetVendor();
VENDOR.requiredNoDefault = 'created_at';
const noDefault = await importWith(4);
// The CATEGORY and the column survive; the vendor's verbatim sentence no longer does, because the
// diagnostic is rendered from the store's own literals now (see safeUpstreamFragment). Asserting the
// raw MySQL prose here would assert the pre-hardening behaviour this commit exists to remove.
check('R13. a NOT NULL column without a default is categorised and its column named',
  noDefault.status === 422 && /column_no_default/.test(text(noDefault)) && /created_at/.test(text(noDefault)),
  text(noDefault).slice(0, 300));

// ── refused vs accepted-but-unrecognized: the distinction the mission asks for ────────────────────
resetVendor();
VENDOR.acceptButDoNotStore = true;
const silent = await importWith(3);
check('R14. 2xx-with-nothing-stored is import_unverified, never import_incomplete',
  silent.status === 422 && silent.body?.error === 'import_unverified',
  `${silent.status} ${text(silent).slice(0, 240)}`);
check('R15. and it does NOT claim an upstream refusal, because no write was refused',
  !text(silent).includes('upstream='), text(silent).slice(0, 240));

resetVendor();
VENDOR.createResponseShape = 'no-id';
const headerNoId = await importWith(2);
check('R16. a header create whose response names no id is write_unverified, not a silent retry',
  headerNoId.status === 502 || headerNoId.body?.error === 'write_unverified' || /write_unverified/.test(text(headerNoId)),
  `${headerNoId.status} ${text(headerNoId).slice(0, 200)}`);

// ── partial failure and cleanup reliability ──────────────────────────────────────────────────────
resetVendor();
const partial = await ask('POST', '/tournaments', { name: 'Partial', visibility: 'private', boards: boards(8) });
check('R17. a clean 8-board import lands and reads back complete',
  partial.status === 200 && rows.tournament_boards.length === 8, `${partial.status} ${text(partial).slice(0, 160)}`);
resetVendor();
// Board 5 only. With a width rule every board is the same size, so this knob is what puts ONE refusal in
// the middle of seven successes — the case the compensating delete actually exists for.
VENDOR.refuseBoardNumbers = new Set(['5']);
const midFail = await ask('POST', '/tournaments', { name: 'Mid', visibility: 'private', boards: boards(8) });
const midText = text(midFail);
check('R18. one refused board in a landed set: 422 import_incomplete naming exactly board 5',
  midFail.status === 422 && midFail.body?.error === 'import_incomplete'
    && JSON.stringify(midFail.body?.failedBoardNumbers) === '["5"]',
  `${midFail.status} ${midText.slice(0, 240)}`);
check('R18b. the seven boards that DID land were removed, and the removal is counted not claimed',
  /cleanup removed 7 board row\(s\)/.test(midText) && rows.tournaments.length === 0 && rows.tournament_boards.length === 0,
  `${midText.slice(0, 240)} | hdr=${rows.tournaments.length} boards=${rows.tournament_boards.length}`);

// ── duplicate import stays intact ────────────────────────────────────────────────────────────────
resetVendor();
const dup = await ask('POST', '/tournaments', { name: 'D', visibility: 'private', dedupe_key: 'k-1', boards: boards(1) });
const dupAgain = await ask('POST', '/tournaments', { name: 'D', visibility: 'private', dedupe_key: 'k-1', boards: boards(1) });
check('R19. a duplicate dedupe_key is 409 duplicate_import and deletes nothing',
  dup.status === 200 && dupAgain.status === 409 && dupAgain.body?.error === 'duplicate_import'
    && rows.tournaments.length === 1 && rows.tournament_boards.length === 1,
  `${dup.status}/${dupAgain.status} hdr=${rows.tournaments.length} boards=${rows.tournament_boards.length}`);

// ── safety invariants of the new diagnostic ──────────────────────────────────────────────────────
resetVendor();
VENDOR.handsJsonColumnChars = 255;
VENDOR.echoSubmittedValue = true;
const leaky = await importWith(2);
const leakText = text(leaky);
check('R20. no service-account credential, bearer or email appears in the import answer',
  !leakText.includes(SERVICE_TOKEN) && !leakText.includes(PASSWORD) && !leakText.includes(SERVICE_EMAIL)
    && !leakText.includes(SERVICE_ID + '"'), leakText.slice(0, 300));
check('R21. the user-visible reason name is still the stable contract word',
  leaky.body?.error === 'import_incomplete', String(leaky.body?.error));

// A secret the account client was NEVER given, so R20 cannot be what makes this pass. Scoped to what
// the digest actually claims (credential pairs and addresses), not to arbitrary vendor text.
const PLANTED_TOKEN = 'planted-bearer-AbCdEf1234567890XYZ';
resetVendor();
VENDOR.handsJsonColumnChars = 255;
VENDOR.plantedProse = `token=${PLANTED_TOKEN} Authorization: Bearer ${PLANTED_TOKEN} owner=svc@vendor.invalid`;
const planted = await importWith(2);
const plantedText = text(planted);
check('R23. the store scrubs a secret the account client never held, because prose now reaches the body',
  planted.status === 422 && plantedText.includes('Data too long for column')
    && !plantedText.includes(PLANTED_TOKEN) && !plantedText.includes('svc@vendor.invalid'),
  plantedText.slice(0, 320));
check('R23b. and the reason still survives its own scrubbing (it is not a redaction black hole)',
  plantedText.includes('upstream=club_account_request_failed') && plantedText.includes('x2'),
  plantedText.slice(0, 320));

// ── HARDENING: the disclosure matrix (audit findings 1, 2 and 3) ─────────────────────────────────
// Each case is the VERBATIM sentence a vendor might answer with, driven end-to-end through the HTTP
// response — not through a unit call — because the claim under test is "nothing of this leaves the
// process", and only the wire can show that. The forbidden list per case is the sensitive substring the
// case is designed to smuggle.
const storeRules = require(path.join(ROOT, 'tournaments/tournamentNcbStore.js'));
const DEAL_JSON = JSON.stringify(deal(0));
const DEAL_FLAT = DECK.join(' ');
const DEAL_CSV = DECK.map((c) => `"${c}"`).join(',');
const DEAL_COMPACT = DECK.join('');
const B64_DEAL = Buffer.from(DEAL_JSON).toString('base64');
const B64URL_DEAL = Buffer.from(DEAL_JSON).toString('base64url');
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6eyJzdWIiOiI5OSJ9.abcDEF123';

const DISCLOSURE_CASES = [
  // Every `secret` is a needle that WOULD appear verbatim in the response if the vendor sentence were
  // emitted unchanged (after the sanitizer's own whitespace collapse). A needle that could never appear
  // even in the broken build is a decoration, not a test.
  { name: 'deal as quoted JSON', prose: `Data too long for column 'hands_json' at row 1 value '${DEAL_JSON}'`, secret: [DEAL_JSON.slice(0, 20), '"2S","3S"'] },
  { name: 'deal unquoted, single spaces', prose: `Data too long for column 'hands_json' value: ${DEAL_FLAT}`, secret: ['2S 3S 4S 5S', DEAL_FLAT.slice(0, 40)] },
  { name: 'deal unquoted, irregular spacing', prose: `value: ${DECK.join('   ')} rejected`, secret: ['2S 3S 4S 5S'] },
  { name: 'deal as quoted comma list', prose: `rejected cards ${DEAL_CSV}`, secret: ['"2S","3S"'] },
  { name: 'deal concatenated', prose: `hands ${DEAL_COMPACT} invalid`, secret: [DEAL_COMPACT.slice(0, 24), '2S3S4S5S'] },
  { name: 'deal as base64', prose: `invalid hands_json ${B64_DEAL}`, secret: [B64_DEAL.slice(0, 24)] },
  { name: 'deal as base64url', prose: `invalid hands_json ${B64URL_DEAL}`, secret: [B64URL_DEAL.slice(0, 24)] },
  { name: 'bearer JWT in prose', prose: `upstream rejected Authorization: Bearer ${JWT}`, secret: [JWT, 'eyJhbGci'] },
  { name: 'sk-prefixed api key', prose: `failed api_key: sk-liveABCDEFGHIJKLMNOP1234`, secret: ['sk-liveABCDEFGHIJKLMNOP1234'] },
  { name: 'connection string', prose: `psql postgres://svc:hunter2@db.internal:5432/ncb failed`, secret: ['hunter2', 'db.internal', 'postgres://'] },
  { name: 'internal hostname', prose: `host ncb-proxy.us-east-2.lambda.amazonaws.com refused`, secret: ['lambda.amazonaws.com', 'us-east-2'] },
  { name: 'ipv4 of the vendor', prose: `connect to 10.0.0.5:3306 timed out`, secret: ['10.0.0.5'] },
  { name: 'service account address', prose: `grant denied for svc-account@bridgemind.invalid`, secret: ['svc-account@bridgemind.invalid'] },
  { name: 'bare unnamed query value', prose: `bad url https://vendor.internal/api?abcdef0123456789&type=insert`, secret: ['abcdef0123456789', 'vendor.internal'] },
  { name: 'whole stored row echoed', prose: `row {id: 4412, tournament_id: 77, board_number: 12, hands_json: ${DEAL_JSON}} rejected`, secret: [DEAL_JSON.slice(0, 20), '"2S","3S"'] },
  // Too short for every length-based rule: only the labeled-secret rule sees these, and the prose is
  // unrecognised, so no category saves it either. This is the case the first test set could not see.
  { name: 'short labeled secret', prose: `write refused token=abc123 while inserting board 1`, secret: ['abc123'] },
  { name: 'password value, short', prose: `login failed for password=hunter2 status=failed`, secret: ['hunter2'] }
];

const detailLengths = [];
for (const [index, c] of DISCLOSURE_CASES.entries()) {
  resetVendor();
  VENDOR.rawProse = c.prose;
  const r = await importWith(2);
  const bodyText = text(r);
  const detail = String(r.body?.detail ?? '');
  detailLengths.push(detail.length);
  const survivors = c.secret.filter((needle) => bodyText.includes(needle));
  check(`D${index + 1}. ${c.name} cannot reach the response body`,
    r.status === 422 && r.body?.error === 'import_incomplete'
      && survivors.length === 0
      && bodyText.includes('upstream=club_account_request_failed')
      && storeRules.containsSensitiveShape(detail) === false
      && Array.isArray(r.body?.failedBoardNumbers) && r.body.failedBoardNumbers.length === 2,
    `survivors=${JSON.stringify(survivors)} ${bodyText.slice(0, 220)}`);
}

check('D16. the gate itself fires on a planted leak (otherwise every D arm above is a dead detector)',
  storeRules.containsSensitiveShape(DEAL_FLAT) === true
    && storeRules.containsSensitiveShape(DEAL_JSON) === true
    && storeRules.containsSensitiveShape(DEAL_COMPACT) === true
    && storeRules.containsSensitiveShape(B64_DEAL) === true
    && storeRules.containsSensitiveShape(JWT) === true
    && storeRules.containsSensitiveShape('a@b.internal') === true
    && storeRules.containsSensitiveShape('http://x.internal/y') === true
    && storeRules.containsSensitiveShape('10.0.0.5') === true
    // The two shapes no length rule can see: a labeled secret with a short value.
    && storeRules.containsSensitiveShape('token=abc123') === true
    && storeRules.containsSensitiveShape('password=hunter2') === true,
  'gate failed to flag a planted shape');
check('D17. and the gate does NOT fire on the ordinary diagnostic vocabulary',
  storeRules.containsSensitiveShape("club_account_request_failed x32 value_too_long(Data too long for column 'hands_json')") === false
    && storeRules.containsSensitiveShape('tournament_boards') === false
    && storeRules.containsSensitiveShape("Duplicate entry for key 'uk_tournament_board'") === false,
  'gate over-fires and would blank the diagnostic');

// The point of the hotfix survives the hardening: these are the answers an operator needs to act.
const CATEGORY_EXPECTATIONS = [
  [`Data too long for column 'hands_json' at row 1`, 'value_too_long', "Data too long for column 'hands_json'"],
  [`Field 'created_at' doesn't have a default value`, 'column_no_default', "Column cannot be null: 'created_at'"],
  [`Column 'board_number' cannot be null`, 'column_no_default', 'Column cannot be null'],
  [`permission denied for table tournament_boards`, 'permission_denied', "INSERT permission denied for table 'tournament_boards'"],
  [`Unknown column 'tags_json' in 'field list'`, 'unknown_column', "Unknown column 'tags_json'"],
  [`Duplicate entry '77-12' for key 'uk_tournament_board'`, 'duplicate_entry', "Duplicate entry for key 'uk_tournament_board'"],
  [`a foreign key constraint fails`, 'foreign_key', 'Foreign key constraint fails'],
  // The three shapes the shipped category table missed, found by asking what the live 422 would say for
  // each SURVIVING candidate cause rather than by re-reading the code that produced them.
  [`Data truncated for column 'vulnerability' at row 1`, 'value_truncated', "Data truncated for column 'vulnerability'"],
  [`Invalid JSON value for column 'hands_json'`, 'invalid_json', "Invalid JSON value for column 'hands_json'"],
  [`Table 'bridgemind.tournament_boards' doesn't exist`, 'unknown_table', "Table 'bridgemind.tournament_boards' does not exist"]
];
const categoryMisses = CATEGORY_EXPECTATIONS
  .map(([raw, id, phrase]) => {
    const got = storeRules.safeUpstreamFragment(raw);
    return got.includes(id) && got.includes(phrase) ? null : `${id} -> ${got}`;
  })
  .filter(Boolean);
check('D18. every safe database category the hotfix exists to surface still reaches the answer',
  categoryMisses.length === 0, categoryMisses.join(' | '));
check('D18b. and the colliding VALUE inside a duplicate message is never quoted back',
  !storeRules.safeUpstreamFragment(`Duplicate entry '77-12' for key 'uk_tournament_board'`).includes('77-12'),
  storeRules.safeUpstreamFragment(`Duplicate entry '77-12' for key 'uk_tournament_board'`));
check('D19. an unknown but harmless sentence keeps its prose (the store is not censoring everything)',
  storeRules.safeUpstreamFragment('read timeout after 12000ms').includes('read timeout'),
  storeRules.safeUpstreamFragment('read timeout after 12000ms'));

// A captured identifier is the ONE piece of vendor text this store re-emits inside its own sentence, so
// it is the one place a hostile or merely weird upstream string can be re-served as if it were ours.
const HOSTILE_IDENTS = [
  "Data too long for column '<img src=x>' at row 1",
  "Data too long for column 'hands_json; DROP TABLE tournaments;--' at row 1",
  "Unknown column 'https://x.internal/y' in 'field list'",
  "Unknown column 'a b c d e f g h' in 'where clause'",
  "permission denied for table tournament_boards; GRANT ALL ON *.* TO 'evil'@'%'",
  "Duplicate entry 'x' for key '<script>alert(1)</script>'",
  "Unknown column 'user_id' in 'field list'",
  `Data too long for column '${'A'.repeat(300)}' at row 1`
];
const hostileEscapes = HOSTILE_IDENTS
  .map((raw) => {
    const got = storeRules.safeUpstreamFragment(raw);
    // The canonical sentence may contain letters, digits, underscore, spaces, apostrophes, parentheses,
    // hyphens and the ellipsis. Nothing else — no angle bracket, no semicolon, no scheme, no address.
    return (/[<>;]|:\/\/|@/.test(got) || got.length > 140) ? `${got.slice(0, 120)}` : null;
  })
  .filter(Boolean);
check('D21. a hostile or malformed identifier is never re-emitted inside the canonical sentence',
  hostileEscapes.length === 0, hostileEscapes.join(' | '));
check('D21b. and a hostile identifier still yields a usable CATEGORY, so the operator is not left blind',
  storeRules.safeUpstreamFragment(`Data too long for column '<img src=x>' at row 1`).includes('value_too_long')
    && storeRules.safeUpstreamFragment(`Unknown column 'https://x.internal/y' in 'field list'`).length > 'unknown'.length,
  `${storeRules.safeUpstreamFragment(`Data too long for column '<img src=x>' at row 1`)} | ${storeRules.safeUpstreamFragment(`Unknown column 'https://x.internal/y' in 'field list'`)}`);

/*
 * The one case where the redaction pass earns its keep, found by mutation-testing rather than by
 * writing it first: an UNRECOGNISED sentence that carries a full quoted deal. Nothing collapses to a
 * category here, so it is the gate alone that decides — and with the deal left in place the gate is
 * obliged to drop the whole sentence, losing the operator's only clue ("hands_json rejected"). Collapse
 * the payload and the same sentence is safe AND useful. If this arm ever goes red while D1-D17 stay
 * green, the regression is in the redaction pass, not in the gate.
 */
const RESCUE_PROSE = `hands_json rejected at row 1 ${DEAL_JSON}`;
const rescueFragment = storeRules.safeUpstreamFragment(RESCUE_PROSE);
check('D22. an unrecognised sentence with an embedded deal is collapsed, not dropped whole',
  rescueFragment.includes('hands_json rejected') && rescueFragment.includes('{…}')
    && !rescueFragment.includes('"2S"') && storeRules.containsSensitiveShape(rescueFragment) === false,
  rescueFragment.slice(0, 200));
check('D22b. and the gate still refuses the SAME sentence with the collapse disabled (so D22 is not luck)',
  storeRules.containsSensitiveShape(RESCUE_PROSE) === true, 'deal sentence judged clean without collapsing');

/*
 * The `key=value` defect, pinned. The shipped sanitizer collapsed every `longkey=value` pair, which
 * includes the vendor's OWN envelope keys, so an unrecognized error reached the operator as
 * `unrecognised([param] [param])`. The proxy-outage signature below is not hypothetical: production has
 * answered `403 {"Message":null}` before, and that is precisely the sentence this rule destroyed.
 */
const PROXY_OUTAGE = 'status=failed Message=null';
const outageFragment = storeRules.safeUpstreamFragment(PROXY_OUTAGE);
check('D23. an unrecognised envelope keeps its own diagnostic keys readable',
  outageFragment.includes('status=failed') && /Message=/.test(outageFragment),
  outageFragment);
check('D23b. no fragment is ever reduced to a redaction placeholder alone',
  DISCLOSURE_CASES.map((c) => storeRules.safeUpstreamFragment(c.prose))
    .concat([outageFragment, storeRules.safeUpstreamFragment('read timeout after 12000ms')])
    .every((f) => f !== 'unrecognised([param])' && !/^\s*unrecognised\((\[param\]\s*)+\)$/.test(f) && !/^\s*unrecognised\(\s*\)$/.test(f))
    && DISCLOSURE_CASES.map((c) => storeRules.safeUpstreamFragment(c.prose))
      .filter((f) => f.startsWith('unrecognised(')).every((f) => f.length > 'unrecognised()'.length),
  'a fragment collapsed to placeholders only');
const DIAGNOSTIC_ENVELOPES = [
  'error=lock wait timeout exceeded status=failed code=1205',
  'status=failed Message=null',
  'error=Deadlock found when trying to get lock; try restarting transaction errno=1213',
  'reason=gateway_timeout status=failed attempt=2'
];
check('D24. a real vendor envelope survives with its words intact, not as placeholders',
  DIAGNOSTIC_ENVELOPES.every((raw) => {
    const got = storeRules.safeUpstreamFragment(raw);
    return got.includes('error=') || got.includes('status=failed') || got.includes('reason=') || got.includes('Message=');
  }), DIAGNOSTIC_ENVELOPES.map((r) => storeRules.safeUpstreamFragment(r)).join(' | '));
// The narrowing must not reopen the hole the broad rule was closing: an UNLABELED value is still collapsed.
check('D24b. and an unlabeled key value is still collapsed, so this fix did not undo finding 3',
  !storeRules.safeUpstreamFragment('zorbflux=Sup3rSecretValue99 while writing').includes('Sup3rSecretValue99')
    && !storeRules.safeUpstreamFragment('https://x.internal/p?abcdef0123456789&type=insert').includes('abcdef0123456789'),
  `${storeRules.safeUpstreamFragment('zorbflux=Sup3rSecretValue99 while writing')} | ${storeRules.safeUpstreamFragment('https://x.internal/p?abcdef0123456789&type=insert')}`);
check('D24c. prose containing an ordinary question mark is not eaten as a query string (the words AFTER the mark must survive)',
  storeRules.safeUpstreamFragment('is the column nullable? check the migration').includes('nullable?')
    && storeRules.safeUpstreamFragment('is the column nullable? check the migration').includes('check the migration'),
  storeRules.safeUpstreamFragment('is the column nullable? check the migration'));
// A query tail with NO scheme in front of it (`/path?somevalue&x=1`) is invisible to the URL rule, and a
// lowercase-plus-digit token under 24 characters is invisible to every length rule. The token below is
// deliberately NOT pure hex — `abcdef0123456789` was caught by HEX_RUN and proved nothing about this
// path — so g/h/i/j are what leave the query-tail pass as the only thing standing between it and the
// response body.
check('D25. a scheme-less query tail is redacted even when the URL, hex and length rules all miss it',
  !storeRules.safeUpstreamFragment('POST /v1/data/create/tournament_boards?abcdefghij123456&type=insert failed')
    .includes('abcdefghij123456'),
  storeRules.safeUpstreamFragment('POST /v1/data/create/tournament_boards?abcdefghij123456&type=insert failed'));
/*
 * The two defects found by asking WHY a green arm was green rather than accepting it.
 *  · Over-blocking: base64's character class contains `/`, so `{24,}` alone matched the REST path
 *    `/v1/data/create/tournament` and blanked any message naming an endpoint.
 *  · Under-blocking: HOSTISH's `{2,6}` suffix bound did not match `internal`, so `db.internal:3306`
 *    passed the gate and an internal hostname would have reached the response body.
 */
const PATH_PROSE = 'error at /api/v1/data/create/tournament_boards row 5 rejected';
const pathFragment = storeRules.safeUpstreamFragment(PATH_PROSE);
check('D26. a REST path in an unrecognised message is not mistaken for an encoded payload',
  pathFragment.includes('/api/v1/data/create/tournament_boards') && pathFragment.includes('row 5'),
  pathFragment);
check('D26b. and a genuine encoded payload is STILL caught after that fix (D26 is not a loosening)',
  storeRules.containsSensitiveShape(Buffer.from(DEAL_JSON).toString('base64')) === true
    && storeRules.containsSensitiveShape('blob ' + Buffer.from('{\"a\":1,\"b\":2,\"c\":[3,4,5]}').toString('base64')) === true,
  'encoded run no longer flagged');
const HOST_PROSE = 'connect to db.internal:3306 timed out';
check('D27. an internal hostname with a long suffix is not leaked into the diagnostic',
  !storeRules.safeUpstreamFragment(HOST_PROSE).includes('db.internal'),
  storeRules.safeUpstreamFragment(HOST_PROSE));
check('D27b. and the hostname rule does not flag an ordinary dotted sentence or a qualified table name',
  storeRules.containsSensitiveShape("Unknown column 'tags_json' in 'field list'") === false
    && storeRules.containsSensitiveShape('e.g. board 12 is rejected') === false
    && storeRules.safeUpstreamFragment("Table 'bridgemind.tournament_boards' doesn't exist").includes('bridgemind.tournament_boards'),
  'host rule now over-fires on plain prose or on db-qualified names');
// A dotted host whose suffix is NOT on the private list is reachable only by HOST_PORT, so without this
// arm the port rule could be deleted and the suite would still be green (measured: it was).
check('D27c. an unlisted dotted host is still caught when it arrives with a port',
  !storeRules.safeUpstreamFragment('connect to mysql-host-node7.private:3306 timed out').includes('mysql-host-node7.private')
    && storeRules.containsSensitiveShape('mysql-host-node7.private:3306') === true,
  storeRules.safeUpstreamFragment('connect to mysql-host-node7.private:3306 timed out'));
check(`D20. the diagnostic stays a status message, not a paragraph, across all ${DISCLOSURE_CASES.length} shapes`,
  detailLengths.length === DISCLOSURE_CASES.length
    && detailLengths.every((n) => n > 0 && n < 700), `n=${detailLengths.length} max=${Math.max(...detailLengths)} min=${Math.min(...detailLengths)}`);
check('R22. nothing left the mock host for the whole run', calls.offHost.length === 0, calls.offHost.slice(0, 3).join(','));

let failed = 0;
for (const r of results) {
  if (!r.pass) failed += 1;
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.pass ? '' : `   ${r.detail}`}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed  (tournament import-failure gate)`);
server.close();
process.exit(failed ? 1 : 0);
