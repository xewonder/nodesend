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
    echoSubmittedValue: false, createResponseShape: 'id', plantedProse: ''
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
check('R13. a NOT NULL column without a default is named, which no name-only mock can see',
  noDefault.status === 422 && /Field 'created_at' doesn't have a default value/.test(text(noDefault)),
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
check('R22. nothing left the mock host for the whole run', calls.offHost.length === 0, calls.offHost.slice(0, 3).join(','));

let failed = 0;
for (const r of results) {
  if (!r.pass) failed += 1;
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.pass ? '' : `   ${r.detail}`}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed, ${failed} failed  (tournament import-failure gate)`);
server.close();
process.exit(failed ? 1 : 0);
