'use strict';

/*
 * CLUB STORE ON THE DEDICATED NCB ACCOUNT
 *
 * Implements exactly the method set clubAuthorization.js calls, over NCB's `/data/...` routes,
 * using the DEDICATED ACCOUNT's session (ncbAccountClient.js) and never the caller's bearer.
 * Table and column names come from the deployment's validated schema (clubSchema.js); nothing
 * here hard-codes one.
 *
 * WHAT NCB CANNOT DO, AND WHAT THIS FILE THEREFORE DOES NOT CLAIM.
 * The runtime data route is sequential REST: no transaction, no conditional write, no
 * affected-row count, no upsert. So:
 *   * Nothing here is called atomic, and no method pretends a multi-call operation rolled back,
 *     because it cannot.
 *   * Every write is READ BACK. NCB answers success on a write it may not have applied; a row that
 *     cannot be read again is reported as `write_unverified`, never as saved.
 *   * Collection import follows the ordered recipe: create the collection as a DRAFT, write the
 *     boards one at a time, then read the board rows back and verify the count AND the board-number
 *     identity set against what was submitted. Only a collection that passed may be published.
 *   * On a failed import the collection is LEFT A DRAFT — so no member can see it — the rows this
 *     call wrote are deleted best-effort, and the failure reports what remained. A cleanup delete
 *     is reported, not trusted.
 *   * Publish re-verifies from storage when this process did not do the import, because the
 *     verified set is process memory: a restarted relay must not publish a half-written collection
 *     just because nobody told it about it.
 *   * Duplicate-key refusals map to `already_in_club`, which is how UNIQUE(user_id) surfaces
 *     through a REST layer that gives no other signal.
 *
 * `club_board_attempts` does not exist. Board-start is a READ of one validated board, never a
 * write: BridgeMind's existing gameplay and recorded-hands infrastructure owns game recording, so
 * a second record of the same attempt would be one nobody can reconcile. The five agreed tables are
 * the whole storage footprint of this store.
 */

const { validateBoardRecord } = require('./clubBoardValidator.js');
const {
  MEMBERSHIP_STATUSES, APPROVED_MEMBERSHIP_STATUS, isEffectiveMembership, CLUB_ACTIVE
} = require('./clubSchema.js');

const READ = (table, query) => ({ group: 'data', path: `read/${table}${query ? `?${query}` : ''}`, method: 'GET' });
const CREATE = (table, body) => ({ group: 'data', path: `create/${table}`, method: 'POST', body });
const UPDATE = (table, id, body) => ({ group: 'data', path: `update/${table}/${encodeURIComponent(id)}`, method: 'PUT', body });
const REMOVE = (table, id) => ({ group: 'data', path: `delete/${table}/${encodeURIComponent(id)}`, method: 'DELETE' });

const eq = (value) => String(value ?? '').trim();

/**
 * Reads the row set out of an NCB response, and returns NULL when the response is not a row set.
 *
 * This is the same discipline `envelopeRows()` already applies to every quota read in bridge.js
 * (bridge.js:821-830), and the club modules were not doing it. The consequence was silent and
 * serious: NCB can answer HTTP 200 with a body that means "refused" or "unexpected" —
 * `{ "status":"error", "message":"<refused>", "data":[] }`, or `{ "data": null }`, or a payload
 * whose rows sit under another key. Treating any of those as ZERO ROWS makes a denied or malformed
 * read indistinguishable from an empty table, and on an AUTHORITY table that is the difference
 * between
 * telling an operator "the club account could not read system_admins" (503, actionable) and telling
 * a legitimate Super Admin "you are not one" (403, a dead end that invites someone to re-run a
 * grant that may already have landed).
 *
 * A genuine empty success — `{status:'success', data:[]}` — still returns an empty array. Only
 * "this is not a row set" becomes null.
 */
function rowsOf(body) {
  if (body && typeof body === 'object' && !Array.isArray(body) && 'status' in body && body.status !== 'success') {
    return null;
  }
  if (Array.isArray(body?.data)) return body.data;
  if (Array.isArray(body)) return body;
  return null;
}

// NCB reports a unique-index refusal in prose, and the prose is the only signal a sequential REST
// layer passes back. Scoped to the duplicate-key families: a 500 that merely mentions "exist"
// must not be turned into a clean `already_in_club` answer.
const DUPLICATE_KEY = /duplicate|unique|constraint|already exists/i;

/*
 * THE COST MODEL OF RESOLVING A ROSTER'S NAMES PAST THE FIRST DIRECTORY WINDOW.
 *
 * Two primitives reach a directory row that the first window did not name, and which one is cheap
 * depends on how many ids are missing:
 *   * a targeted equality read — narrow (it asks only for rows this caller is already entitled to,
 *     never for the directory at large) and O(missing), but its answer is only as trustworthy as
 *     the filter;
 *   * the filter-free paginated scan — O(directory), but it depends on nothing but `page`/`limit`,
 *     which is the grammar measured against the live proxy on 2026-11-18 rather than inferred.
 *
 * TARGETED_LOOKUP_MAX_IDS is the switch between them, and the scan is ALSO what runs when the
 * targeted reads come back empty for every id: a filtered list read answering 200-with-no-rows while
 * the rows are stored is a measured behaviour of this backend (2026-11-20, on a marker column that
 * demonstrably held rows), so zero hits does not prove those accounts have no profile.
 */
const TARGETED_LOOKUP_MAX_IDS = 20;
const TARGETED_LOOKUP_CONCURRENCY = 5;
// Pages beyond the first, for a directory this relay is willing to page through for one roster.
// Exhausting the table ends the loop early, so this is a runaway guard, not the expected cost.
const DIRECTORY_SCAN_PAGE_BUDGET = 10;

/**
 * @param {object} options
 * @param {object} options.client   a configured ncbAccountClient
 * @param {object} options.schema   a validated readClubSchemaConfig().schema
 */
function createClubNcbStore({ client, schema }) {
  if (!client?.configured || !schema) {
    throw new TypeError('createClubNcbStore needs a configured client and a validated schema');
  }
  const T = schema.tables;
  const C = schema.columns;
  const failures = [];
  // Collections whose board set THIS process has read back and matched. Publishing anything else
  // is refused until it is verified here, so a half-written import cannot be flipped visible.
  const verified = new Set();

  async function run(spec) {
    const answer = await client.request(spec);
    if (!answer.ok) {
      failures.push(answer.reason);
      if (failures.length > 50) failures.shift();
      return { ok: false, duplicate: Boolean(answer.detail && DUPLICATE_KEY.test(answer.detail)), reason: answer.reason, detail: answer.detail ?? '' };
    }
    return { ok: true, body: answer.body };
  }

  async function find(table, query) {
    const result = await run(READ(table, query));
    return result.ok ? rowsOf(result.body) : null;
  }

  /**
   * The same read as `find()`, for the methods whose caller would be told a LIE by an empty array.
   *
   * `find()` collapses "the backend refused" and "the table is empty" into null-vs-[] only weakly:
   * it returns null for both a transport failure and a non-row-set body, and every list method that
   * wrote `Array.isArray(rows) ? rows : []` turned that null into a successful empty list. On
   * `GET /clubs` that is how a created club disappeared: NCB answered the paginated read HTTP 500
   * `{status:"failed"}` (see `listClubs`), the store reported zero clubs, and the router — which
   * maps a payload array straight to 200 — served `{"status":"success","data":[]}`.
   *
   * So a list read that could not be made returns an in-band refusal, and the router answers 503.
   * `readSystemAdmins()` already did this for the authority table; this is the same rule applied to
   * the reads that face a user.
   */
  async function rowsOrRefusal(table, query) {
    const result = await run(READ(table, query));
    if (!result.ok) return { refusal: result.reason || 'club_account_request_failed', detail: result.detail };
    const rows = rowsOf(result.body);
    if (rows === null) return { refusal: 'club_read_unreadable', detail: 'the club read returned a body that is not a row set' };
    return { rows };
  }

  async function one(table, query) {
    // `query` arrives as a bare filter (`id=7`) and READ() adds the `?`, so the separator here is
    // always `&`. Getting this wrong yields `id=7limit=1`, which reads as "no row" and would make
    // every successful write look unverified.
    const rows = await find(table, `${query}&limit=1`);
    return rows?.[0] ?? null;
  }

  function newIdOf(body) {
    return eq(body?.data?.id ?? body?.id ?? '');
  }

  // ── identity resolution (what the router decides authority from) ──────────

  async function getMembership(userId) {
    const rows = await find(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}&limit=2`);
    if (rows === null) return { unavailable: true };
    if (rows.length > 1) {
      // UNIQUE(user_id) is broken underneath us. Refusing is correct: choosing one row would
      // decide "their club" from an arbitrary record, and would look exactly like a normal answer.
      return { unavailable: true, reason: 'ambiguous_membership_row' };
    }
    const row = rows[0];
    // A row missing its club is not "no club": reporting it as one would silently strip a member's
    // access and tell them they never had any.
    if (!row) return null;
    const clubId = eq(row[C.memberships.clubId]);
    if (clubId === '') return { unavailable: true, reason: 'malformed_membership_row' };
    // `status` is returned raw and deliberately NOT interpreted here. Whether a row means "in a
    // club" is one decision, made once in clubAuthorization, so no read path can forget it.
    return { clubId, role: eq(row[C.memberships.role]), status: eq(row[C.memberships.status]) };
  }

  // Every club-status read and write in this file goes through these two, so the numeric live
  // column and the 'active'/'inactive' domain cannot drift apart at one call site and quietly
  // leave another comparing text against 1.
  async function clubStatus(clubId) {
    const row = await one(T.clubs, `${C.clubs.id}=${encodeURIComponent(clubId)}`);
    return row ? schema.clubStatus.decode(row[C.clubs.status]) : null;
  }

  async function collectionScope(collectionId) {
    const row = await one(T.collections, `${C.collections.id}=${encodeURIComponent(collectionId)}`);
    return row ? { clubId: eq(row[C.collections.clubId]), status: eq(row[C.collections.status]) } : null;
  }

  // `system_admins` is required by clubSchema.js, so this is always the authority here. Declared
  // and unreadable denies through the router's 503, never through a "not an admin" answer that
  // would be a false statement about a real person.
  async function isSystemAdmin(userId) {
    const rows = await find(T.systemAdmins, `${C.systemAdmins.userId}=${encodeURIComponent(userId)}&limit=1`);
    if (rows === null) return { declared: true, available: false, isAdmin: false };
    return { declared: true, available: true, isAdmin: rows.length > 0 };
  }

  /**
   * Reads the whole (bounded) system_admins set as user ids, for the bootstrap's empty-table test.
   * Deliberately separate from `isSystemAdmin`, which answers one yes/no about one caller: a
   * per-user probe cannot distinguish "the table is empty" from "the table holds somebody else",
   * and that distinction is the entire safety property of the bootstrap.
   * `available:false` means the READ FAILED, which the caller must treat as write-nothing.
   */
  async function readSystemAdmins() {
    const rows = await find(T.systemAdmins, `limit=${Math.min(schema.rowLimit, 50)}`);
    if (rows === null) return { available: false, userIds: [], reason: 'read_failed' };
    return {
      available: true,
      userIds: rows.map((row) => eq(row[C.systemAdmins.userId])).filter((id) => id !== '')
    };
  }

  /**
   * Inserts one system_admins row, carrying only the column this contract declares (`user_id`):
   * created_by/created_at are not in the agreed five-table schema, and writing an undeclared column
   * is exactly the failure this whole adapter exists to prevent. Confirmed by reading the row back
   * by that same column, because a 2xx from NCB is not evidence that a row exists.
   */
  async function createSystemAdmin(userId) {
    const id = eq(userId);
    if (id === '') return { error: 'bad_request', detail: 'a user id is required' };
    const result = await run(CREATE(T.systemAdmins, { [C.systemAdmins.userId]: id }));
    if (!result.ok) {
      return { error: result.duplicate ? 'already_admin' : result.reason, detail: result.detail };
    }
    const confirmed = await one(T.systemAdmins, `${C.systemAdmins.userId}=${encodeURIComponent(id)}`);
    if (!confirmed) return { error: 'write_unverified', detail: 'the system_admins row could not be read back' };
    return { user_id: eq(confirmed[C.systemAdmins.userId]) };
  }

  // ── THE ACCOUNT DIRECTORY ────────────────────────────────────────────────
  // Read-only, optional, and never written: this is the application table that already holds the
  // name a person chose for themselves. It exists so a Super Admin can appoint a teacher by typing
  // that name instead of pasting an NCB user id.
  const D = schema.directory ? schema.directory.columns : null;
  const directoryTable = schema.directory ? schema.directory.table : '';

  /**
   * One bounded page of the directory table. `scanDirectory()` (page 1) is what account search
   * reads; member-name enrichment pages forward from it when page 1 does not cover the roster.
   *
   * WHY A SCAN AT ALL: the live backend offers no partial-match operator — `?search=`, `?q=` and
   * `?like=` each answer HTTP 500 `Unknown column 'search' in 'where clause'` and a wildcard value
   * matches nothing (clubSchema.js records the measurement). So "find me anyone called *gly*" can
   * only be a bounded read with the comparison made here. The bound is `CLUB_NCB_ROW_LIMIT`, and the
   * scan is sorted by the identity column so the window is DETERMINISTIC: with an unspecified MySQL
   * row order the same query could match a person today and miss them tomorrow, and a missed person
   * is reported as "no such account".
   *
   * A REFUSAL STAYS A REFUSAL. An unreadable directory that answers `[]` tells a Super Admin that
   * nobody in BridgeMind holds that name — the same class of lie the club list was fixed for, aimed
   * at real people instead of at rows.
   */
  async function directoryWindow({ page = 1 } = {}) {
    if (!schema.directory) return { unconfigured: true };
    // `page` is sent only when the caller needs something the first page cannot hold, so an
    // unpaged read stays byte-identical to the read this deployment has always made.
    const query = `limit=${schema.rowLimit}${page > 1 ? `&page=${page}` : ''}&sort=${D.userId}&order=asc`;
    const found = await rowsOrRefusal(directoryTable, query);
    if (found.refusal) return { refusal: found.refusal, detail: found.detail };
    return { rows: found.rows, truncated: found.rows.length >= schema.rowLimit };
  }

  function scanDirectory() {
    return directoryWindow();
  }

  function directoryLabel(row) {
    return {
      user_id: eq(row[D.userId]),
      nickname: D.nickname ? eq(row[D.nickname]) : '',
      display_name: D.displayName ? eq(row[D.displayName]) : '',
      normalized: D.nicknameNormalized ? eq(row[D.nicknameNormalized]).toLowerCase() : ''
    };
  }

  /**
   * The only user fields this feature ever returns: the id, and the two names. Not email (the
   * directory has no email column and the account table is not readable through the data route), not
   * `avatar_url`, not `ai_source`, and never anything that could be a credential — a search that
   * returns an AI-provider waiver or a session field turns a name lookup into an identity dump.
   */
  async function searchAccounts({ q = '', limit = 20 } = {}) {
    const needle = String(q).trim().toLowerCase();
    if (needle === '') return { error: 'bad_request', detail: 'a search term is required' };
    const scan = await scanDirectory();
    if (scan.unconfigured) {
      return { error: 'club_directory_unconfigured', detail: 'this deployment declares no account directory (CLUB_NCB_SCHEMA_JSON tables.users), so accounts cannot be searched by name' };
    }
    if (scan.refusal) return { error: scan.refusal, detail: scan.detail };

    const matches = [];
    for (const row of scan.rows) {
      const label = directoryLabel(row);
      if (label.user_id === '') continue;
      // Every field is folded to lowercase before the comparison, not just the stored normalized
      // column. `nickname` and `display_name` hold what the player typed — "Glyfada Teacher" — and
      // comparing them against a lowercased query without folding them is how a search answers
      // "nobody called that" about a row it is looking straight at. Case-insensitivity here is
      // NodeSend's own, so it does not depend on the column collation being CI or on NCB offering a
      // case-insensitive operator, which it does not.
      const fields = [label.nickname, label.display_name, label.normalized]
        .map((value) => String(value ?? '').toLowerCase())
        .filter((value) => value !== '');
      if (!fields.some((value) => value.includes(needle))) continue;
      // A whole-nickname hit ranks first. The exact `nickname_normalized` read is what the rest of
      // the product treats as authoritative, and burying it under substring matches is how an admin
      // appoints the wrong person from a list they believed was ordered by relevance.
      matches.push({ ...label, exact: label.normalized !== '' && label.normalized === needle });
    }
    matches.sort((a, b) => (a.exact === b.exact ? 0 : a.exact ? -1 : 1));

    const size = Math.min(Number(limit) || 20, 100, schema.rowLimit);
    return {
      users: matches.slice(0, size).map(({ exact, nickname, display_name, user_id, normalized }) => ({ user_id, nickname, display_name })),
      matched_count: matches.length,
      // Not "did the page fill up" — "the account set was not fully looked at, or the matches were
      // not all shown". A search that says nothing more has to be trusted to be complete.
      truncated: scan.truncated || matches.length > size
    };
  }

  /**
   * Records, per account id, the directory row that names it — of the ids still outstanding and no
   * others. Rows for people this roster does not contain are walked past, never collected.
   *
   * The first row for an id wins, because `user_settings` has no unique constraint on the user id
   * and a second row is storage noise rather than a second person. The one exception is a row that
   * carries no name text at all: it must not mask a later row that does, which is what the same
   * account looks like after a half-finished profile write.
   */
  function collectLabels(into, rows, outstanding) {
    for (const row of rows) {
      const label = directoryLabel(row);
      if (label.user_id === '' || !outstanding.has(label.user_id)) continue;
      const held = into.get(label.user_id);
      if (held && (held.nickname !== '' || held.display_name !== '')) continue;
      into.set(label.user_id, label);
    }
  }

  /**
   * One bounded read per account id, for ids the first directory window did not name.
   *
   * The ids come from the authorized roster rows and nowhere else, so this narrows directory access
   * rather than widening it: it asks for the people this caller has already been allowed to list.
   * `limit=2`, not 1, because `user_settings` carries no unique constraint on the user id (the app
   * deletes its own leftover rows) — a second row is then visible to the caller instead of
   * invisible, and a row holding no name text must not mask one that does.
   *
   * Each answer is re-checked against the id it was asked for. That is the half of "do not trust the
   * filter" that runs the other way: were this backend to IGNORE a filter it does not understand and
   * hand back rows it was not asked for, an unchecked read would attribute a stranger's name to a
   * club member.
   *
   * `refused` counts reads that could not be made. A refusal is not a fact about a person, and it
   * never becomes one here.
   */
  async function targetedDirectoryLabels(ids) {
    const labels = new Map();
    let hits = 0;
    let refused = 0;
    const outstanding = new Set(ids);
    for (let i = 0; i < ids.length; i += TARGETED_LOOKUP_CONCURRENCY) {
      const answers = await Promise.all(ids.slice(i, i + TARGETED_LOOKUP_CONCURRENCY).map(async (userId) => {
        const found = await rowsOrRefusal(directoryTable, `${D.userId}=${encodeURIComponent(userId)}&limit=2`);
        return { userId, found };
      }));
      for (const { userId, found } of answers) {
        if (found.refusal) {
          refused += 1;
          continue;
        }
        const mine = found.rows.map(directoryLabel).filter((label) => label.user_id === userId);
        if (mine.length === 0) continue;
        hits += 1;
        labels.set(userId, mine.find((label) => label.nickname !== '' || label.display_name !== '') ?? mine[0]);
        outstanding.delete(userId);
      }
    }
    return { labels, hits, refused, outstanding };
  }

  /**
   * The display labels for the account ids an AUTHORIZED roster already names.
   *
   * WHY IT IS NOT ONE WINDOW READ ANYMORE. `GET /clubs/{clubId}/members` used to enrich every row
   * from a single `limit=CLUB_NCB_ROW_LIMIT` read of the directory sorted by user id, and the members
   * past that window came back as `null` names on a 200 that looked complete — `scanDirectory()`
   * computed a `truncated` flag and `directoryLabels()` discarded it, so an account the relay never
   * looked at was indistinguishable from an account with no profile. On a directory of more than
   * `CLUB_NCB_ROW_LIMIT` rows that silently understated the roster for exactly the members whose ids
   * sort late.
   *
   * The window read stays first: one call covers every member of any deployment whose directory fits
   * in it, and that is the common case whose cost must not change. What changes is that a FULL
   * window is now read as incomplete rather than as the directory, and the ids it missed are
   * resolved by id (small residual) or by paging forward (large one, or a residual a blind equality
   * filter cannot be trusted to have answered).
   *
   * A name that still cannot be resolved stays `null` on a row that is still returned: the
   * membership is the authority, and this is decoration. Only the FIRST read failing is a refusal
   * (`{ error }`), which is the roster's own rule — an unreadable directory has never been allowed
   * to read as "nobody is a member".
   */
  async function directoryLabelsFor(userIds = []) {
    const labels = new Map();
    const wanted = [...new Set(userIds.map(eq).filter((id) => id !== ''))].sort();
    if (!schema.directory || wanted.length === 0) return { labels };

    const first = await directoryWindow();
    if (first.refusal) return { error: first.refusal, detail: first.detail };
    collectLabels(labels, first.rows, new Set(wanted));
    // A window that did not fill up IS the whole table, so an id it did not name provably has no
    // directory row. This is the only branch entitled to answer without looking again.
    if (!first.truncated) return { labels };

    let outstanding = new Set(wanted.filter((id) => !labels.has(id)));
    if (outstanding.size <= TARGETED_LOOKUP_MAX_IDS) {
      const targeted = await targetedDirectoryLabels([...outstanding]);
      for (const [id, label] of targeted.labels) labels.set(id, label);
      outstanding = targeted.outstanding;
      if (outstanding.size === 0) return { labels };
      // Any one hit proves the equality filter reaches this table, so the ids it still says nothing
      // about are ids with no row. Zero hits over a non-empty residual proves nothing.
      if (targeted.hits > 0 && targeted.refused === 0) return { labels };
    }

    for (let page = 2; outstanding.size > 0 && page <= 1 + DIRECTORY_SCAN_PAGE_BUDGET; page += 1) {
      const next = await directoryWindow({ page });
      // Names are decoration: a page this relay cannot read leaves those members unnamed on a
      // roster it can still answer, and says so in the store's failure list rather than in the
      // status code. The window read above is the one whose failure is a refusal.
      if (next.refusal) break;
      collectLabels(labels, next.rows, outstanding);
      for (const id of [...outstanding]) if (labels.has(id)) outstanding.delete(id);
      if (next.rows.length < schema.rowLimit) break;
    }
    return { labels };
  }

  // ── SUPER ADMIN ───────────────────────────────────────────────────────────

  /**
   * NCB's read filter is an exact match, not a substring, so `search` is applied to the rows this
   * page returned. That means a search can report fewer clubs than exist rather than more — it can
   * never reveal a club the caller may not see, which is the only direction that would matter here.
   *
   * PAGINATION IS `page`, 1-BASED, NOT `offset`. Measured against the live proxy on 2026-11-18:
   * `limit`, `page`, `sort` and `order` are honoured (`page=999&limit=1` returns zero rows), while
   * any other query name is taken for a COLUMN filter — `offset=1` fails the read with HTTP 500
   * `{status:"failed"}`, exactly like a filter on a column that does not exist. Every working read in
   * this deployment already spells it this way (`BridgeMind src/services/adminExportService.js`
   * builds `sort/order/page/limit`), and the club list was the only read that did not, which is why
   * `POST /clubs` could succeed while `GET /clubs` answered an empty list.
   */
  async function listClubs({ search = '', page = 1, limit = 25 } = {}) {
    const size = Math.min(Number(limit) || 25, schema.rowLimit);
    const found = await rowsOrRefusal(T.clubs,
      `limit=${size}&page=${Math.max(1, Number(page) || 1)}&sort=${C.clubs.name}&order=asc`);
    if (found.refusal) return { error: found.refusal, detail: found.detail };
    const shaped = found.rows.map((row) => ({
      id: eq(row[C.clubs.id]),
      name: eq(row[C.clubs.name]),
      // Decoded, so the admin screen and the authorization rule see the same domain value.
      status: schema.clubStatus.decode(row[C.clubs.status])
    }));
    const needle = String(search ?? '').trim().toLowerCase();
    return needle ? shaped.filter((club) => club.name.toLowerCase().includes(needle)) : shaped;
  }

  async function listActiveClubs() {
    // The FILTER is encoded too. A query of `active=active` matches no row and would return an
    // empty club picker that looks like a legitimately empty database.
    const activeRaw = schema.clubStatus.encode(CLUB_ACTIVE);
    const found = await rowsOrRefusal(T.clubs, `${C.clubs.status}=${encodeURIComponent(activeRaw)}&limit=${schema.rowLimit}`);
    if (found.refusal) return { error: found.refusal, detail: found.detail };
    return found.rows
      .filter((row) => schema.clubStatus.decode(row[C.clubs.status]) === CLUB_ACTIVE)
      .map((row) => ({ id: eq(row[C.clubs.id]), name: eq(row[C.clubs.name]) }));
  }

  async function createClub({ name }) {
    const result = await run(CREATE(T.clubs, {
      [C.clubs.name]: name, [C.clubs.status]: schema.clubStatus.encode(CLUB_ACTIVE)
    }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const id = newIdOf(result.body);
    const row = id ? await one(T.clubs, `${C.clubs.id}=${encodeURIComponent(id)}`) : null;
    if (!row) return { error: 'write_unverified', detail: 'the club row could not be read back' };
    return { id: eq(row[C.clubs.id]), name: eq(row[C.clubs.name]), status: schema.clubStatus.decode(row[C.clubs.status]) };
  }

  async function updateClub({ clubId, name }) {
    const result = await run(UPDATE(T.clubs, clubId, { [C.clubs.name]: name }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const row = await one(T.clubs, `${C.clubs.id}=${encodeURIComponent(clubId)}`);
    if (!row) return { error: 'write_unverified', detail: 'the club row could not be read back after the update' };
    const storedName = eq(row[C.clubs.name]);
    return { id: eq(row[C.clubs.id]), name: storedName, status: schema.clubStatus.decode(row[C.clubs.status]), unverified: storedName !== name };
  }

  async function setClubStatus({ clubId, status }) {
    const result = await run(UPDATE(T.clubs, clubId, { [C.clubs.status]: schema.clubStatus.encode(status) }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const row = await one(T.clubs, `${C.clubs.id}=${encodeURIComponent(clubId)}`);
    if (!row) return { error: 'write_unverified', detail: 'the club row could not be read back after the update' };
    const stored = schema.clubStatus.decode(row[C.clubs.status]);
    // Compare the decoded value: `1` written and `1` read back are equal, but a raw string compare
    // against the domain 'active' would report every successful change as unverified.
    return { id: eq(row[C.clubs.id]), status: stored, unverified: stored !== status };
  }

  async function listMembers({ clubId }) {
    const found = await rowsOrRefusal(T.memberships, `${C.memberships.clubId}=${encodeURIComponent(clubId)}&limit=${schema.rowLimit}`);
    if (found.refusal) return { error: found.refusal, detail: found.detail };
    // `status` rides along so a club admin sees the pending requests they are being asked to act on
    // through the SAME read that lists members. A separate requests endpoint would be a second
    // surface deciding the same thing.
    const rows = found.rows.map((row) => ({
      user_id: eq(row[C.memberships.userId]),
      club_role: eq(row[C.memberships.role]),
      membership_status: eq(row[C.memberships.status]),
      membership_id: eq(row[C.memberships.id])
    }));
    if (rows.length === 0 || !schema.directory) return rows;
    // Names are decoration on a row whose authority is the membership itself, so an unresolved name
    // is `null` and not a missing member. Resolution is driven by the ids THIS roster holds and
    // starts from one window read, because a roster is the list an admin acts on and a 500-member
    // club must not cost 500 REST calls. Only the members that window could not name cost more.
    const directory = await directoryLabelsFor(rows.map((row) => row.user_id));
    if (directory.error) return { error: directory.error, detail: directory.detail };
    for (const row of rows) {
      const label = directory.labels.get(row.user_id);
      row.display_name = label?.display_name || null;
      row.nickname = label?.nickname || null;
    }
    return rows;
  }

  /**
   * Appoints a club admin. An appointment is a grant BY the authority, so the row it writes is
   * APPROVED: naming someone a club admin already decided they belong to that club. Because
   * membership is UNIQUE(user_id), it is a role change on the target's one row, or the creation of
   * that row — it can never move somebody out of the club they already belong to.
   */
  async function assignClubAdmin({ clubId, userId, role = 'club_admin' }) {
    const existing = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
    if (existing && eq(existing[C.memberships.clubId]) !== eq(clubId)) {
      return { error: 'already_in_club', detail: 'that user belongs to another club' };
    }
    // Same club: one write sets the role AND answers the pending request, so an approval can never
    // half-land as a role change on a row that still grants nothing.
    const result = existing
      ? await run(UPDATE(T.memberships, eq(existing[C.memberships.id]), { [C.memberships.role]: role, [C.memberships.status]: APPROVED_MEMBERSHIP_STATUS }))
      : await run(CREATE(T.memberships, {
        [C.memberships.userId]: userId, [C.memberships.clubId]: clubId,
        [C.memberships.role]: role, [C.memberships.status]: APPROVED_MEMBERSHIP_STATUS
      }));
    if (!result.ok) return { error: result.duplicate ? 'already_in_club' : result.reason, detail: result.detail };
    const row = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
    if (!row) return { error: 'write_unverified', detail: 'the membership row could not be read back' };
    return {
      user_id: userId,
      club_id: eq(row[C.memberships.clubId]),
      club_role: eq(row[C.memberships.role]),
      membership_status: eq(row[C.memberships.status])
    };
  }

  /**
   * The lifecycle transition a Super Admin, or an admin of THAT club, performs: pending -> approved
   * | rejected, approved -> removed.
   *
   * `removed` is a STATUS, not a delete, so the person can still see in Profile what became of their
   * request while holding no club privilege whatsoever; a voluntary leave deletes the row instead.
   * Refused when the target's row belongs to a different club — that would be a cross-club write
   * wearing a same-club URL.
   */
  async function setMembershipStatus({ clubId, userId, status }) {
    if (!MEMBERSHIP_STATUSES.includes(status)) {
      return { error: 'bad_request', detail: `status must be one of ${MEMBERSHIP_STATUSES.join(', ')}` };
    }
    const row = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
    if (!row) return { error: 'not_found', detail: 'that user has no club membership row to change' };
    if (eq(row[C.memberships.clubId]) !== eq(clubId)) return { error: 'club_scope_mismatch' };
    const result = await run(UPDATE(T.memberships, eq(row[C.memberships.id]), { [C.memberships.status]: status }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const after = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
    if (eq(after?.[C.memberships.status]) !== status) {
      return { error: 'write_unverified', detail: 'the membership did not read back with the new status' };
    }
    return {
      user_id: userId,
      club_id: eq(after[C.memberships.clubId]),
      club_role: eq(after[C.memberships.role]),
      membership_status: status
    };
  }

  async function removeClubAdmin({ clubId, userId }) {
    const row = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
    if (!row || eq(row[C.memberships.clubId]) !== eq(clubId)) return { removed: false };
    const result = await run(UPDATE(T.memberships, eq(row[C.memberships.id]), { [C.memberships.role]: 'member' }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const after = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
    return { removed: eq(after?.[C.memberships.role]) === 'member' };
  }

  /**
   * One club or none, enforced by UNIQUE(user_id) rather than by a dropdown.
   *
   * A user's own choice creates a PENDING row: selection is a request, and only an approval makes it
   * a membership. `already_in_club` (409) is therefore reserved for a user who is ALREADY APPROVED
   * somewhere — for them, leaving first is the way to change club.
   *
   * A pending / rejected / removed row does NOT block a new choice; the row is re-targeted instead of
   * a second one being created, because UNIQUE(user_id) permits only one. That is required by the
   * "a removed user reverts to the normal None access level" rule: a user with no row may request a
   * club, so a user whose request was rejected or revoked must be able to as well, or the row that
   * grants them nothing would also take away the one thing a no-club user still has.
   */
  async function setClubMembership({ userId, clubId }) {
    const existing = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
    if (clubId === null) {
      if (!existing) return { outcome: 'left' };
      const result = await run(REMOVE(T.memberships, eq(existing[C.memberships.id])));
      if (!result.ok) return { outcome: 'error', reason: result.reason, detail: result.detail };
      const after = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
      return after ? { outcome: 'error', reason: 'write_unverified' } : { outcome: 'left' };
    }

    const existingStatus = existing ? eq(existing[C.memberships.status]) : '';
    if (existing && existingStatus === APPROVED_MEMBERSHIP_STATUS) {
      // Approved is not enough to block a new choice: only an approved member OF AN ACTIVE CLUB
      // holds a club, which is the same test the authorization gate applies. Without this read here,
      // a member whose club was deactivated would be refused a new club while being denied every
      // feature of the old one — a worse position than a user who never joined, which the rule
      // forbids. An unreadable club status blocks the change rather than guessing either way.
      const memberClubStatus = await clubStatus(eq(existing[C.memberships.clubId]));
      if (memberClubStatus === null) {
        return { outcome: 'error', reason: 'club_account_request_failed', detail: 'the membership club record could not be read' };
      }
      if (isEffectiveMembership({ status: existingStatus, clubStatus: memberClubStatus })) {
        return { outcome: 'already_in_club', clubId: eq(existing[C.memberships.clubId]) };
      }
    }
    if (existing && eq(existing[C.memberships.clubId]) === eq(clubId) && existingStatus === 'pending') {
      // Same request, still waiting. Answered without a write so a double-click cannot churn the row.
      return { outcome: 'already_requested', clubId: eq(existing[C.memberships.clubId]), status: 'pending' };
    }

    const result = existing
      ? await run(UPDATE(T.memberships, eq(existing[C.memberships.id]), {
        [C.memberships.clubId]: clubId, [C.memberships.role]: 'member', [C.memberships.status]: 'pending'
      }))
      : await run(CREATE(T.memberships, {
        [C.memberships.userId]: userId, [C.memberships.clubId]: clubId,
        [C.memberships.role]: 'member', [C.memberships.status]: 'pending'
      }));
    if (!result.ok) return { outcome: result.duplicate ? 'already_in_club' : 'error', reason: result.reason, detail: result.detail };
    const row = await one(T.memberships, `${C.memberships.userId}=${encodeURIComponent(userId)}`);
    if (!row) return { outcome: 'error', reason: 'write_unverified' };
    // `joined` would be a lie: nothing has been joined yet. The outcome names the request, and the
    // status says plainly that it is not a membership.
    return {
      outcome: 'requested',
      clubId: eq(row[C.memberships.clubId]),
      status: eq(row[C.memberships.status])
    };
  }

  // ── COLLECTIONS ───────────────────────────────────────────────────────────

  function shapeCollection(row) {
    return {
      id: eq(row[C.collections.id]),
      name: eq(row[C.collections.name]),
      status: eq(row[C.collections.status]),
      club_id: eq(row[C.collections.clubId])
    };
  }

  async function listCollections({ clubId }) {
    const found = await rowsOrRefusal(T.collections, `${C.collections.clubId}=${encodeURIComponent(clubId)}&limit=${schema.rowLimit}`);
    if (found.refusal) return { error: found.refusal, detail: found.detail };
    return found.rows.map(shapeCollection);
  }

  // Scope is re-asserted on the row itself, not trusted to the query filter: this is the read that
  // decides whether a member may see a board, so a filter the backend ignored must not become a
  // cross-club read.
  async function listPublishedCollections({ clubId }) {
    const found = await rowsOrRefusal(T.collections,
      `${C.collections.clubId}=${encodeURIComponent(clubId)}&${C.collections.status}=published&limit=${schema.rowLimit}`);
    if (found.refusal) return { error: found.refusal, detail: found.detail };
    return found.rows
      .filter((row) => eq(row[C.collections.clubId]) === eq(clubId) && eq(row[C.collections.status]) === 'published')
      .map((row) => ({ id: eq(row[C.collections.id]), name: eq(row[C.collections.name]), status: 'published' }));
  }

  async function renameCollection({ collectionId, name }) {
    const result = await run(UPDATE(T.collections, collectionId, { [C.collections.name]: name }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const row = await one(T.collections, `${C.collections.id}=${encodeURIComponent(collectionId)}`);
    if (!row) return { error: 'write_unverified', detail: 'the collection row could not be read back' };
    return { id: eq(row[C.collections.id]), name: eq(row[C.collections.name]) };
  }

  /**
   * One stored row -> the board record the client and the engine consume. Both `listBoards` and
   * `getBoard` go through here, so the board a player SEES in the list and the board the start
   * route HANDS to the engine are shaped by one function and cannot drift apart.
   */
  function shapeBoard(row) {
    let hands = { North: [], East: [], South: [], West: [] };
    try {
      const parsed = JSON.parse(row[C.boards.handsJson]);
      if (parsed && typeof parsed === 'object') hands = parsed;
    } catch {
      // Left empty on purpose: the caller's validation then refuses the board. A stored row
      // that will not parse is damage to report, not damage to paper over with a default.
    }
    const board = {
      board_number: eq(row[C.boards.boardNumber]),
      dealer: eq(row[C.boards.dealer]),
      vulnerability: eq(row[C.boards.vulnerability]),
      hands,
      row_id: eq(row[C.boards.id])
    };
    // No verbatim-source field: the live table has no `source_pbn`, and the board a player receives
    // is fully described by the four hands, the dealer and the vulnerability.
    return board;
  }

  async function listBoards({ collectionId }) {
    const rows = await find(T.boards, `${C.boards.collectionId}=${encodeURIComponent(collectionId)}&limit=${schema.rowLimit}`);
    if (!Array.isArray(rows)) return null;
    // Scope is re-asserted on the row, not trusted to the query filter: this read decides whether a
    // player may see a deal, so a filter the backend ignored must not become a cross-club leak.
    return rows
      .filter((row) => eq(row[C.boards.collectionId]) === eq(collectionId))
      .map(shapeBoard);
  }

  /**
   * The ordered import. DRAFT row, boards one by one, read-back verification of count AND
   * board-number identity. This method never publishes — publishing is a separate authorised call
   * that this verification then permits.
   */
  async function createCollection({ clubId, name, boards, createdBy }) {
    // NCB requires `created_by_user_id` on this insert. It is the VERIFIED caller id passed down
    // from the router's session resolution — never a body field — and it is refused here rather
    // than sent as an empty value, because an empty author column is worse than a failed import:
    // it produces a collection that looks published-by-nobody and cannot be traced.
    const author = eq(createdBy);
    if (author === '') return { error: 'bad_request', detail: 'the verified caller identity is required to create a collection' };

    const created = await run(CREATE(T.collections, {
      [C.collections.clubId]: clubId,
      [C.collections.name]: name,
      [C.collections.status]: 'draft',
      [C.collections.createdBy]: author
    }));
    if (!created.ok) return { error: created.reason, detail: created.detail };
    const collectionId = newIdOf(created.body);
    if (!collectionId) return { error: 'write_unverified', detail: 'the draft collection row returned no id' };

    const written = [];
    for (const board of boards) {
      const result = await run(CREATE(T.boards, {
        [C.boards.collectionId]: collectionId,
        [C.boards.boardNumber]: eq(board.board_number),
        [C.boards.dealer]: eq(board.dealer),
        [C.boards.vulnerability]: eq(board.vulnerability),
        [C.boards.handsJson]: JSON.stringify(board.hands)
      }));
      if (!result.ok) {
        const before = await listBoards({ collectionId });
        const cleanup = await removeCollectionRows({ collectionId, clubId, rows: before });
        return {
          error: 'import_incomplete',
          collectionId,
          published: false,
          detail: `a board write failed after ${written.length}/${boards.length}; ${before?.length ?? 0} row(s) remained, cleanup removed ${cleanup.removed}${cleanup.leftovers.length ? ` and left ${cleanup.leftovers.join(',')}` : ''}`,
          failedBoardNumber: eq(board.board_number)
        };
      }
      written.push(eq(board.board_number));
    }

    const stored = await listBoards({ collectionId });
    const expected = new Set(written);
    const got = new Set((stored ?? []).map((row) => row.board_number));
    const missing = [...expected].filter((n) => !got.has(n));
    const extra = [...got].filter((n) => !expected.has(n));
    if (!stored || missing.length || extra.length || stored.length !== boards.length) {
      const cleanup = await removeCollectionRows({ collectionId, clubId, rows: stored });
      return {
        error: 'import_unverified',
        collectionId,
        published: false,
        detail: `read-back disagreed with the write (expected ${boards.length}, read ${stored?.length ?? 0}${missing.length ? `, missing ${missing.join(',')}` : ''}${extra.length ? `, unexpected ${extra.join(',')}` : ''}); cleanup removed ${cleanup.removed}${cleanup.leftovers.length ? `, left ${cleanup.leftovers.join(',')}` : ''}`
      };
    }

    verified.add(collectionId);
    return { id: collectionId, club_id: eq(clubId), name, status: 'draft', board_count: stored.length, verified: true };
  }

  async function removeCollectionRows({ collectionId, rows }) {
    const leftovers = [];
    for (const row of (Array.isArray(rows) ? rows : [])) {
      const result = await run(REMOVE(T.boards, row.row_id));
      if (!result.ok) leftovers.push(row.row_id);
    }
    const parent = await run(REMOVE(T.collections, collectionId));
    verified.delete(collectionId);
    return { removed: (Array.isArray(rows) ? rows.length : 0) - leftovers.length, leftovers, collectionRemoved: parent.ok };
  }

  /**
   * Publish is refused unless the board set is VERIFIED complete and internally sound. A
   * collection this process did not import is read back and checked first, so a half-written or
   * corrupted set cannot be flipped visible to members by a call.
   */
  async function setCollectionStatus({ collectionId, status, clubId }) {
    if (status === 'published') {
      const scope = await collectionScope(collectionId);
      if (!scope) return { error: 'collection_not_found', detail: 'the collection has no row' };
      // Ownership comes from the row, always. This is the check that makes a guessed collection id
      // useless to a caller who is an admin of a different club.
      if (eq(scope.clubId) !== eq(clubId)) return { error: 'club_scope_mismatch' };

      if (!verified.has(collectionId)) {
        const stored = await listBoards({ collectionId });
        if (!Array.isArray(stored) || stored.length === 0) {
          return { error: 'publish_refused_unverified', detail: 'no board row could be read back for this collection' };
        }
        const numbers = new Set();
        for (const board of stored) {
          const checked = validateBoardRecord(board);
          if (!checked.ok) {
            return { error: 'publish_refused_unverified', detail: `board ${board.board_number}: ${checked.detail}` };
          }
          if (numbers.has(board.board_number)) {
            return { error: 'publish_refused_unverified', detail: `board number "${board.board_number}" appears twice` };
          }
          numbers.add(board.board_number);
        }
      }
    }

    const result = await run(UPDATE(T.collections, collectionId, { [C.collections.status]: status }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const after = await collectionScope(collectionId);
    if (status === 'published' && eq(after?.status) !== 'published') {
      return { error: 'write_unverified', detail: 'the collection did not read back as published' };
    }
    if (status === 'draft') {
      // Un-publishing invalidates the proof: the set may be edited while draft, so a later publish
      // has to re-read it rather than trust this earlier one.
      verified.delete(collectionId);
    } else {
      verified.add(collectionId);
    }
    return { id: collectionId, status: eq(after?.status) };
  }

  async function deleteCollection({ collectionId, clubId }) {
    const scope = await collectionScope(collectionId);
    if (!scope) return { error: 'collection_not_found', detail: 'the collection has no row' };
    if (eq(scope.clubId) !== eq(clubId)) return { error: 'club_scope_mismatch' };
    const rows = await listBoards({ collectionId }) ?? [];
    const outcome = await removeCollectionRows({ collectionId, clubId, rows });
    return {
      boardsRemoved: outcome.removed,
      boardsLeftBehind: outcome.leftovers,
      collectionRemoved: outcome.collectionRemoved,
      note: outcome.leftovers.length || !outcome.collectionRemoved
        ? 'sequential delete; the listed rows remain and need attention'
        : 'ok'
    };
  }

  // ── BOARD START: a READ, never a write ────────────────────────────────────
  /**
   * Reads ONE board of one collection, scoped by collection id in the query AND re-checked on the
   * row, and returns it in the shape `listBoards` returns so the two routes cannot disagree about
   * what a board is.
   *
   * There is no attempt row. Starting a board records nothing here: BridgeMind's existing gameplay
   * and recorded-hands infrastructure owns game recording, and a second store of the same attempt
   * would be a record nobody can reconcile. This is also why no sixth table is needed.
   *
   * `{ unavailable: true }` (the read failed) and `null` (the board is not there) stay distinct:
   * reporting a store failure as "no such board" would send a player to a 404 for a problem that is
   * the backend's, not theirs.
   */
  async function getBoard({ collectionId, boardNumber }) {
    const rows = await find(T.boards,
      `${C.boards.collectionId}=${encodeURIComponent(collectionId)}&${C.boards.boardNumber}=${encodeURIComponent(boardNumber)}&limit=2`);
    if (rows === null) return { unavailable: true };
    const owned = rows.filter((row) => eq(row[C.boards.collectionId]) === eq(collectionId)
      && eq(row[C.boards.boardNumber]) === eq(boardNumber));
    if (owned.length === 0) return null;
    if (owned.length > 1) {
      // Two rows under one (collection, board number) means the board a player is about to play is
      // ambiguous. Choosing one would silently deal a different deal than the list showed.
      return { unavailable: true, reason: 'ambiguous_board_row' };
    }
    return shapeBoard(owned[0]);
  }

  return {
    getMembership,
    clubStatus,
    collectionScope,
    isSystemAdmin,
    readSystemAdmins,
    createSystemAdmin,
    listClubs,
    listActiveClubs,
    searchAccounts,
    createClub,
    updateClub,
    setClubStatus,
    listMembers,
    assignClubAdmin,
    removeClubAdmin,
    setMembershipStatus,
    setClubMembership,
    listCollections,
    listPublishedCollections,
    renameCollection,
    createCollection,
    listBoards,
    setCollectionStatus,
    deleteCollection,
    getBoard,
    diagnostics: () => ({ failures: failures.slice(-20), verifiedCollections: [...verified] }),
    verifiedCollections: verified
  };
}

module.exports = { createClubNcbStore };
