'use strict';

/*
 * TOURNAMENT STORE ON THE DEDICATED NCB ACCOUNT
 *
 * Implements exactly the method set tournamentAuthorization.js calls, over NCB's `/data/...` routes,
 * using the SAME dedicated service account the club feature uses (`clubs/ncbAccountClient.js` — no new
 * credential name exists in this file and none is accepted from a request). Table and column names come
 * from the deployment's validated schema (tournamentSchema.js); nothing here hard-codes one.
 *
 * WHAT THIS FILE DOES NOT DO, and each is a rule rather than an omission:
 *   * It does not decide authority. Every method takes the scope the ROUTE proved (an owner id from the
 *     validated session, a club id read from the club store) and returns rows. A caller that expects a
 *     method to filter by "who may see this" is holding the wrong end of the design: the list scope is
 *     built in tournamentAuthorization.js from `tournamentListScope`'s clauses and passed in as data.
 *   * It does not read `club_memberships`, `clubs` or `system_admins`. Membership, club activity and
 *     super-admin status arrive through the injected club store (`readMembership` / `readClubStatus` /
 *     `readSuperAdmin` below), so there is exactly one membership rule in this deployment — the club
 *     feature's — and this store cannot drift from it. If that bridge is unavailable, these methods
 *     report `{ unavailable: true }` and the route answers 503 with a named reason; there is no
 *     caller-bearer fallback anywhere in this file and no second read path.
 *   * It does not claim atomicity. NCB's runtime data route is sequential REST: no transaction, no
 *     conditional write, no affected-row count, no upsert. So every write is READ BACK, a write that
 *     cannot be read again is `write_unverified` and never "saved", and a failed import runs a
 *     best-effort compensating delete whose outcome is REPORTED rather than trusted.
 *
 * IMPORT IS ALL-OR-NOTHING AS FAR AS A READER IS CONCERNED. The header is created as `draft`, every
 * board is written one at a time, and the whole set is read back and matched on COUNT and BOARD-NUMBER
 * IDENTITY before the method returns anything. A failure deletes the header and the landed boards, so a
 * partial tournament is never readable — and the answer names each board that did not land. Publishing
 * remains a separate authorised call that this verification is what permits.
 *
 * SCOPE IS RE-ASSERTED ON THE ROW, not trusted to the query filter. This is the read that decides
 * whether a person may see a deal, and a filter the backend ignored must not become a cross-owner or
 * cross-club leak.
 */

/* Read-back re-validates the stored deal against the TOURNAMENT board contract (1-32 label characters),
   not the club one (1-10). A board the route was allowed to import must not be reported as damage when it
   is read back — that mismatch is how a successful import turns into `import_incomplete`. The deck rules
   themselves stay shared; see tournaments/tournamentBoardValidator.js. */
const { validateBoardRecord } = require('./tournamentBoardValidator.js');

const READ = (table, query) => ({ group: 'data', path: `read/${table}${query ? `?${query}` : ''}`, method: 'GET' });
const CREATE = (table, body) => ({ group: 'data', path: `create/${table}`, method: 'POST', body });
const UPDATE = (table, id, body) => ({ group: 'data', path: `update/${table}/${encodeURIComponent(id)}`, method: 'PUT', body });
const REMOVE = (table, id) => ({ group: 'data', path: `delete/${table}/${encodeURIComponent(id)}`, method: 'DELETE' });

const eq = (value) => String(value ?? '').trim();

/**
 * Reads the row set out of an NCB response, and returns NULL when the response is not a row set.
 *
 * Same discipline as `clubs/clubNcbStore.js`: NCB can answer HTTP 200 with a body that means "refused"
 * (`{status:"error", …, data:[]}`) or carries nothing (`{data:null}`). Collapsing those into ZERO ROWS
 * makes a denied or malformed read indistinguishable from an empty table — on a tournament list that is
 * "you have no tournaments", said to a person who has some. A genuine empty success still returns [].
 */
function rowsOf(body) {
  if (body && typeof body === 'object' && !Array.isArray(body) && 'status' in body && body.status !== 'success') {
    return null;
  }
  if (Array.isArray(body?.data)) return body.data;
  if (Array.isArray(body)) return body;
  return null;
}

// NCB reports a unique-index refusal in prose, and prose is the only signal a sequential REST layer
// passes back. Scoped to the duplicate-key families: a 500 that merely mentions "exist" must not be
// turned into a clean duplicate answer.
const DUPLICATE_KEY = /duplicate|unique|constraint|already exists/i;

/**
 * @param {object} options
 * @param {object} options.client     a configured ncbAccountClient (the dedicated service account)
 * @param {object} options.schema     a validated readTournamentSchemaConfig().schema
 * @param {object} options.clubBridge `{ getMembership, clubStatus, isSystemAdmin }` from the club store
 */
function createTournamentNcbStore({ client, schema, clubBridge }) {
  if (!client?.configured || !schema) {
    throw new TypeError('createTournamentNcbStore needs a configured client and a validated schema');
  }
  if (!clubBridge
    || typeof clubBridge.getMembership !== 'function'
    || typeof clubBridge.clubStatus !== 'function'
    || typeof clubBridge.isSystemAdmin !== 'function') {
    // Constructing without the bridge would leave the store free to invent its own membership rule,
    // which is the one thing this file exists to make impossible.
    throw new TypeError('createTournamentNcbStore needs the club store as its membership bridge');
  }
  const T = schema.tables;
  const C = schema.columns;
  const AXIS_V = schema.visibility;
  const AXIS_S = schema.status;
  const failures = [];
  // Tournaments whose board set THIS process has read back and matched. Publishing anything else is
  // refused until it is verified here, so a half-written set cannot be flipped visible.
  const verified = new Set();

  async function run(spec) {
    const answer = await client.request(spec);
    if (!answer.ok) {
      failures.push(answer.reason);
      if (failures.length > 50) failures.shift();
      return {
        ok: false,
        duplicate: Boolean(answer.detail && DUPLICATE_KEY.test(answer.detail)),
        reason: answer.reason,
        detail: answer.detail ?? ''
      };
    }
    return { ok: true, body: answer.body };
  }

  /** `{rows}` or `{refusal, detail}`. A refusal never becomes an empty list. */
  async function rowsOrRefusal(table, query) {
    const result = await run(READ(table, query));
    if (!result.ok) return { refusal: result.reason || 'club_account_request_failed', detail: result.detail };
    const rows = rowsOf(result.body);
    if (rows === null) return { refusal: 'tournament_read_unreadable', detail: 'the tournament read returned a body that is not a row set' };
    return { rows };
  }

  async function one(table, query) {
    // `query` arrives as a bare filter (`id=7`) and READ() adds the `?`, so the separator here is
    // always `&`. Getting this wrong yields `id=7limit=1`, which reads as "no row".
    const found = await rowsOrRefusal(table, `${query}&limit=1`);
    if (found.refusal) return { unavailable: true };
    return found.rows?.[0] ?? null;
  }

  function newIdOf(body) {
    return eq(body?.data?.id ?? body?.id ?? '');
  }

  // ── THE MEMBERSHIP BRIDGE (the club store, or nothing) ────────────────────
  // Thin wrappers, deliberately: they normalize the club store's shapes into
  // `{ unavailable }` | value, and they are the ONLY way this file learns a club fact.
  async function readMembership(userId) {
    try {
      const membership = await clubBridge.getMembership(userId);
      if (!membership) return { membership: null };
      if (membership.unavailable) return { unavailable: true, reason: membership.reason ?? 'membership_unreadable' };
      return { membership };
    } catch {
      return { unavailable: true, reason: 'membership_unreadable' };
    }
  }

  async function readClubStatus(clubId) {
    if (eq(clubId) === '') return { status: null };
    try {
      // The club store's own answer, undecorated: `null` means "no readable club row", which the club
      // feature's collapse treats as no-club rather than as inactive. This file does not re-decide it.
      const status = await clubBridge.clubStatus(clubId);
      return { status: status === undefined ? null : status };
    } catch {
      // The bridge itself failed. That is unknown, not false: answering "no club" here would be a
      // statement about a person built on a read that did not happen.
      return { unknown: true };
    }
  }

  async function readSuperAdmin(userId) {
    try {
      const grant = await clubBridge.isSystemAdmin(userId);
      if (!grant || grant.declared !== true || grant.available !== true) return { unknown: true };
      return { isSuperAdmin: grant.isAdmin === true };
    } catch {
      return { unknown: true };
    }
  }

  // ── THE HEADER ROW (the authority read every decision is made from) ───────
  function shapeTournament(row) {
    return {
      id: eq(row[C.tournaments.id]),
      ownerId: eq(row[C.tournaments.userId]),
      clubId: eq(row[C.tournaments.clubId]),
      name: eq(row[C.tournaments.name]),
      visibility: AXIS_V.decode(row[C.tournaments.visibility]),
      status: AXIS_S.decode(row[C.tournaments.status]),
      boardCount: Number(row[C.tournaments.boardCount]) || 0,
      sourceLabel: row[C.tournaments.sourceLabel] === undefined || row[C.tournaments.sourceLabel] === null
        ? null : eq(row[C.tournaments.sourceLabel]),
      dedupeKey: row[C.tournaments.dedupeKey] === undefined || row[C.tournaments.dedupeKey] === null
        ? null : eq(row[C.tournaments.dedupeKey])
    };
  }

  /**
   * Reads the header row a path id names. `null` means there is no such tournament; `{unavailable}`
   * means this process could not tell. The route must not answer 404 for the second case — "not found"
   * is a fact about the row, and inventing one hides a storage failure behind a plausible page.
   */
  async function tournamentScope(tournamentId) {
    const id = eq(tournamentId);
    if (id === '') return null;
    const row = await one(T.tournaments, `${C.tournaments.id}=${encodeURIComponent(id)}`);
    if (row === null) return null;
    if (row === undefined) return { unavailable: true };
    if (row.unavailable) return { unavailable: true };
    // A header whose owner column is empty is not "owned by nobody" — it is a row this feature cannot
    // authorize against. Reporting it as readable-by-nothing would look like an ordinary 404.
    if (eq(row[C.tournaments.userId]) === '') return { unavailable: true, reason: 'malformed_tournament_row' };
    return shapeTournament(row);
  }

  /**
   * The LIST read, over the clauses the route proved. Each clause is a conjunction of column equals
   * (`{visibility:'club', club_id:'10', status:'published'}`), the clauses are OR'd by merging the row
   * sets on their primary key, and every returned row is re-checked against its own clause.
   *
   * WHY MERGE RATHER THAN ONE QUERY: NCB's read filter is exact-match column equality with no OR, no
   * `IN` and no grouping (measured and recorded in `clubs/clubSchema.js`), and `tournamentListScope`
   * needs up to three disjunctions — my private rows, my club's rows, the published public rows. The
   * alternative is a full-table read filtered here, which is how a private row gets into a public
   * answer the moment someone's limit is raised.
   *
   * NO `page` IS SENT UPSTREAM, on purpose. Paging each clause independently and merging would produce a
   * page 2 that depends on how the rows happened to split across the three reads. The route pages the
   * merged, de-duplicated, re-checked set instead, so `page`/`limit` mean the same thing on every call.
   */
  async function listTournaments({ clauses = [], limit = 25 } = {}) {
    const size = Math.min(Number(limit) || 25, schema.rowLimit);
    const merged = new Map();
    for (const clause of clauses) {
      const filters = Object.entries(clause)
        .filter(([column, value]) => eq(column) !== '' && value !== null && value !== undefined && eq(value) !== '')
        .map(([column, value]) => `${encodeURIComponent(column)}=${encodeURIComponent(eq(value))}`);
      const found = await rowsOrRefusal(T.tournaments,
        `${filters.length ? `${filters.join('&')}&` : ''}limit=${size}&sort=${C.tournaments.id}&order=asc`);
      if (found.refusal) return { error: found.refusal, detail: found.detail };
      for (const row of found.rows) {
        const shaped = shapeTournament(row);
        // Re-assert the clause on the row. A filter the backend ignored must not turn a club-scoped
        // page into a public one, and this is the read that decides what a person may see.
        const matches = Object.entries(clause).every(([column, value]) => columnEq(clauseColumnValue(shaped, column), value));
        if (!matches) continue;
        if (shaped.id !== '') merged.set(shaped.id, shaped);
      }
    }
    // The API shape, not the internal one. A list that returned the store's private field names
    // (`ownerId`, `clubId`, `boardCount`) while the single-row read returned `user_id`, `club_id`,
    // `board_count` would give one client two vocabularies for the same row, and the filter a caller
    // writes against the list would silently match nothing on the detail.
    return { tournaments: [...merged.values()].map(toResponse) };
  }

  /** Maps a clause key (a real column name) onto the shaped field, for the re-assertion above. */
  function clauseColumnValue(shaped, column) {
    if (column === C.tournaments.id) return shaped.id;
    if (column === C.tournaments.userId) return shaped.ownerId;
    if (column === C.tournaments.clubId) return shaped.clubId;
    if (column === C.tournaments.visibility) return shaped.visibility;
    if (column === C.tournaments.status) return shaped.status;
    return undefined;
  }

  // Comparison for the re-assertion: the shaped value is DOMAIN-decoded (visibility/status), so the
  // clause is compared in the same domain rather than against a storage spelling.
  const columnEq = (left, right) => eq(left) === eq(right);

  // ── BOARDS ────────────────────────────────────────────────────────────────
  /**
   * One stored row -> the board record the engine consumes. `listBoards` and `getBoard` both go
   * through here, so the board a player SEES in the list is shaped by the same function as the board
   * the start route HANDS to the table, and the two cannot drift.
   *
   * `tags` is the historical PBN metadata. It is carried out for display and never in: no rule reads
   * it, and it never contributes a bid to an auction.
   */
  function shapeBoard(row) {
    let hands = {};
    try {
      const parsed = JSON.parse(row[C.boards.handsJson]);
      if (parsed && typeof parsed === 'object') hands = parsed;
    } catch {
      // Left empty on purpose: the caller's validation then refuses the board. A stored row that will
      // not parse is damage to report, not damage to paper over with a default.
    }
    let tags = null;
    if (C.boards.tagsJson) {
      try {
        const parsed = row[C.boards.tagsJson] ? JSON.parse(row[C.boards.tagsJson]) : null;
        tags = parsed && typeof parsed === 'object' ? parsed : null;
      } catch {
        tags = null;
      }
    }
    return {
      board_number: eq(row[C.boards.boardNumber]),
      dealer: eq(row[C.boards.dealer]),
      vulnerability: eq(row[C.boards.vulnerability]),
      hands,
      tags,
      row_id: eq(row[C.boards.id]),
      tournament_id: eq(row[C.boards.tournamentId])
    };
  }

  async function boardRows({ tournamentId }) {
    const found = await rowsOrRefusal(T.boards,
      `${C.boards.tournamentId}=${encodeURIComponent(eq(tournamentId))}&limit=${schema.rowLimit}&sort=${C.boards.id}&order=asc`);
    if (found.refusal) return { error: found.refusal, detail: found.detail };
    return {
      boards: found.rows
        .filter((row) => eq(row[C.boards.tournamentId]) === eq(tournamentId))
        .map(shapeBoard)
    };
  }

  /** Every board of one tournament, complete or a refusal. A partial list is never served as a set. */
  async function listBoards({ tournamentId }) {
    const read = await boardRows({ tournamentId });
    if (read.error) return { error: read.error, detail: read.detail };
    const numbers = new Set();
    for (const board of read.boards) {
      if (numbers.has(board.board_number)) {
        // Two rows for one (tournament, board number): which deal is the tournament's board 3? Serving
        // either would silently deal a different board than the list showed, so this is a refusal.
        return { error: 'duplicate_board_number', detail: `board "${board.board_number}" has more than one row` };
      }
      numbers.add(board.board_number);
      const checked = validateBoardRecord(board);
      if (!checked.ok) return { error: checked.reason, detail: checked.detail };
    }
    return { boards: read.boards };
  }

  /**
   * Reads ONE board of one tournament, scoped in the query AND re-checked on the row, shaped exactly
   * as `listBoards` shapes it. `{ unavailable: true }` (the read failed) and `null` (no such board)
   * stay distinct: reporting a store failure as "no such board" sends a player to a 404 for a problem
   * that belongs to the backend.
   */
  async function getBoard({ tournamentId, boardNumber }) {
    const found = await rowsOrRefusal(T.boards,
      `${C.boards.tournamentId}=${encodeURIComponent(eq(tournamentId))}&${C.boards.boardNumber}=${encodeURIComponent(eq(boardNumber))}&limit=2`);
    if (found.refusal) return { unavailable: true };
    const owned = found.rows.filter((row) => eq(row[C.boards.tournamentId]) === eq(tournamentId)
      && eq(row[C.boards.boardNumber]) === eq(boardNumber));
    if (owned.length === 0) return null;
    if (owned.length > 1) return { unavailable: true, reason: 'ambiguous_board_row' };
    return shapeBoard(owned[0]);
  }

  // ── THE IMPORT (draft → boards → verify; never publish) ───────────────────
  /**
   * Writes the header as `draft`, then every board, then reads the set back and matches count AND
   * board-number identity. Returns a `draft` row and never flips the status: publishing is a separate
   * authorised call, which is what makes "verified" mean something rather than being a flag this one
   * method sets and trusts.
   *
   * On any failure the header and the boards this call wrote are deleted, and the answer names each
   * board that did not land (`{ error: 'import_incomplete', failedBoardNumbers }`). `duplicate_import`
   * is the one failure that deletes NOTHING, because the row that collided belongs to an earlier import
   * and removing it would be a write this request has no authority to make.
   */
  async function importTournament({ ownerId, clubId, visibility, name, sourceLabel, dedupeKey, boards }) {
    const author = eq(ownerId);
    if (author === '') return { error: 'bad_request', detail: 'the verified caller identity is required to create a tournament' };

    const header = {
      [C.tournaments.userId]: author,
      [C.tournaments.name]: eq(name),
      [C.tournaments.visibility]: AXIS_V.encode(eq(visibility)),
      [C.tournaments.status]: AXIS_S.encode('draft'),
      [C.tournaments.boardCount]: Array.isArray(boards) ? boards.length : 0
    };
    // `club_id` and `dedupe_key` are OMITTED rather than sent empty. An empty string is a value: a
    // second private import with `dedupe_key=''` would collide on UNIQUE(dedupe_key) and be refused as
    // a duplicate of an unrelated set, and `club_id=''` on a private row is a club id that names
    // nothing. NULL is the absence both columns mean.
    if (eq(clubId) !== '') header[C.tournaments.clubId] = eq(clubId);
    if (eq(dedupeKey) !== '') header[C.tournaments.dedupeKey] = eq(dedupeKey);
    if (eq(sourceLabel) !== '') header[C.tournaments.sourceLabel] = eq(sourceLabel);

    const created = await run(CREATE(T.tournaments, header));
    if (!created.ok) {
      if (created.duplicate && eq(dedupeKey) !== '') {
        return { error: 'duplicate_import', detail: `a tournament with dedupe_key "${eq(dedupeKey)}" already exists; nothing was written` };
      }
      return { error: created.reason, detail: created.detail };
    }
    const tournamentId = newIdOf(created.body);
    if (!tournamentId) return { error: 'write_unverified', detail: 'the draft tournament row returned no id' };

    const landed = [];
    const failed = [];
    for (const board of (Array.isArray(boards) ? boards : [])) {
      const row = {
        [C.boards.tournamentId]: tournamentId,
        [C.boards.boardNumber]: eq(board.board_number),
        [C.boards.dealer]: eq(board.dealer),
        [C.boards.vulnerability]: eq(board.vulnerability),
        [C.boards.handsJson]: JSON.stringify(board.hands ?? {})
      };
      if (C.boards.tagsJson && board.tags && typeof board.tags === 'object') {
        row[C.boards.tagsJson] = JSON.stringify(board.tags);
      }
      const result = await run(CREATE(T.boards, row));
      if (!result.ok) {
        failed.push({ boardNumber: eq(board.board_number), detail: result.detail || result.reason });
        continue;
      }
      landed.push(eq(board.board_number));
    }

    const readBack = await boardRows({ tournamentId });
    const stored = readBack.error ? null : readBack.boards;
    const expected = new Set(landed);
    const got = new Set((stored ?? []).map((board) => board.board_number));
    const missing = [...expected].filter((number) => !got.has(number));
    const extra = [...got].filter((number) => !expected.has(number));
    const incomplete = failed.length > 0
      || !stored
      || missing.length > 0
      || extra.length > 0
      || stored.length !== (Array.isArray(boards) ? boards.length : 0);

    if (incomplete) {
      const cleanup = await removeTournamentRows({ tournamentId, rows: stored ?? [] });
      const names = [...failed.map((f) => f.boardNumber), ...missing, ...extra].filter((n) => n !== '');
      // The two failure names mean different things to the caller and are not interchangeable:
      // `import_incomplete` says a write was REFUSED and names the board — the importer can fix that board
      // and re-run. `import_unverified` says every write was accepted but the set that reads back is not
      // the set that was written — nothing the caller sent is wrong, and re-sending is the wrong advice.
      const refused = failed.length > 0;
      return {
        error: refused ? 'import_incomplete' : 'import_unverified',
        tournamentId: null,
        published: false,
        detail: `${landed.length}/${Array.isArray(boards) ? boards.length : 0} board write(s) reported success; `
          + (readBack.error ? `the read-back itself failed (${readBack.error}); ` : '')
          + (names.length ? `board(s) ${[...new Set(names)].join(', ')} did not land; ` : '')
          + `cleanup removed ${cleanup.boardsRemoved} board row(s)${cleanup.leftovers.length ? ` and left ${cleanup.leftovers.join(',')}` : ''}`
          + (cleanup.headerRemoved ? ' and removed the draft header' : ' BUT THE DRAFT HEADER REMAINS'),
        failedBoardNumbers: [...new Set(names)]
      };
    }

    verified.add(tournamentId);
    return {
      id: tournamentId,
      user_id: author,
      club_id: eq(clubId) === '' ? null : eq(clubId),
      name: eq(name),
      visibility: eq(visibility),
      status: 'draft',
      board_count: stored.length,
      source_label: eq(sourceLabel) === '' ? null : eq(sourceLabel),
      dedupe_key: eq(dedupeKey) === '' ? null : eq(dedupeKey),
      verified: true
    };
  }

  /**
   * Deletes the board rows and attempt rows of one tournament and then its header.
   *
   * A sequential REST layer cannot roll anything back, so a delete is only evidence of itself when the row
   * is gone afterwards — and NCB answers 2xx for deletes it did not apply (measured on the invitation
   * probe table, where the first cleanup pass FAILED and a retry by primary key removed the rows). So this
   * method RE-READS both child tables after removing and reports what is actually left, rather than
   * counting the calls it made. `leftovers` therefore means "this row is still in storage", which is the
   * only claim an operator can act on.
   */
  async function removeTournamentRows({ tournamentId, rows }) {
    const attempted = (Array.isArray(rows) ? rows : []);
    for (const row of attempted) {
      await run(REMOVE(T.boards, row.row_id));
    }
    const attempts = await removeAttemptRows({ tournamentId });
    const header = await run(REMOVE(T.tournaments, eq(tournamentId)));
    verified.delete(eq(tournamentId));
    const stillBoards = await boardRows({ tournamentId });
    const remaining = Array.isArray(stillBoards.boards) ? stillBoards.boards : [];
    return {
      boardsRemoved: Math.max(0, attempted.length - remaining.length),
      leftovers: remaining.map((row) => row.row_id),
      boardsUnreadable: Boolean(stillBoards.error),
      attemptsRemoved: attempts.removed,
      attemptLeftovers: attempts.leftovers,
      headerRemoved: header.ok
    };
  }

  async function attemptRows({ tournamentId, userId = null, boardNumber = null }) {
    const filters = [`${C.attempts.tournamentId}=${encodeURIComponent(eq(tournamentId))}`];
    if (userId !== null) filters.push(`${C.attempts.userId}=${encodeURIComponent(eq(userId))}`);
    if (boardNumber !== null) filters.push(`${C.attempts.boardNumber}=${encodeURIComponent(eq(boardNumber))}`);
    const found = await rowsOrRefusal(T.attempts,
      `${filters.join('&')}&limit=${schema.rowLimit}&sort=${C.attempts.id}&order=asc`);
    if (found.refusal) return { error: found.refusal, detail: found.detail };
    // Scope re-asserted on every row, again because this read answers a question about who may see
    // what: an ignored filter must not hand one player another player's attempt history.
    const rows = found.rows.filter((row) => eq(row[C.attempts.tournamentId]) === eq(tournamentId)
      && (userId === null || eq(row[C.attempts.userId]) === eq(userId))
      && (boardNumber === null || eq(row[C.attempts.boardNumber]) === eq(boardNumber)));
    return { rows };
  }

  async function removeAttemptRows({ tournamentId }) {
    const read = await attemptRows({ tournamentId });
    if (read.error) return { removed: 0, leftovers: [], unreadable: true };
    for (const row of read.rows) {
      await run(REMOVE(T.attempts, eq(row[C.attempts.id])));
    }
    const after = await attemptRows({ tournamentId });
    if (after.error) return { removed: 0, leftovers: read.rows.map((row) => eq(row[C.attempts.id])), unreadable: true };
    return { removed: Math.max(0, read.rows.length - after.rows.length), leftovers: after.rows.map((row) => eq(row[C.attempts.id])) };
  }

  async function deleteTournament({ tournamentId }) {
    const scope = await tournamentScope(tournamentId);
    if (!scope || scope.unavailable) return { error: 'tournament_not_found', detail: 'the tournament has no readable row' };
    const boards = await boardRows({ tournamentId });
    const outcome = await removeTournamentRows({ tournamentId, rows: boards.boards ?? [] });
    const stillThere = await tournamentScope(tournamentId);
    if (outcome.headerRemoved && stillThere && !stillThere.unavailable) {
      // The delete said it worked and the row is still readable. That is a lie to cover with a success.
      return {
        error: 'write_unverified',
        detail: 'the header delete was accepted but the row still reads back',
        boardsLeftBehind: outcome.leftovers
      };
    }
    return {
      tournamentRemoved: outcome.headerRemoved,
      boardsRemoved: outcome.boardsRemoved,
      boardsLeftBehind: outcome.leftovers,
      attemptsRemoved: outcome.attemptsRemoved,
      attemptsLeftBehind: outcome.attemptLeftovers,
      note: outcome.leftovers.length || outcome.attemptLeftovers.length || !outcome.headerRemoved
        ? 'sequential delete; the listed rows remain and need attention'
        : 'ok'
    };
  }

  // ── HEADER WRITES (each confirmed by a read-back of the same row) ────────
  async function updateHeader({ tournamentId, changes }) {
    const body = {};
    for (const [field, value] of Object.entries(changes ?? {})) {
      const column = C.tournaments[field];
      if (!column) continue;
      if (field === 'visibility') body[column] = AXIS_V.encode(eq(value));
      else if (field === 'status') body[column] = AXIS_S.encode(eq(value));
      else if (value === null) body[column] = null;
      else body[column] = value;
    }
    if (!Object.keys(body).length) return { error: 'bad_request', detail: 'no change was named' };
    const result = await run(UPDATE(T.tournaments, eq(tournamentId), body));
    if (!result.ok) {
      return { error: result.duplicate ? 'duplicate_import' : result.reason, detail: result.detail };
    }
    const after = await tournamentScope(tournamentId);
    if (!after || after.unavailable) return { error: 'write_unverified', detail: 'the tournament row could not be read back after the update' };
    return after;
  }

  async function renameTournament({ tournamentId, name, sourceLabel }) {
    const changes = {};
    if (name !== undefined) changes.name = name;
    if (sourceLabel !== undefined) changes.sourceLabel = sourceLabel;
    const updated = await updateHeader({ tournamentId, changes });
    if (updated.error) return updated;
    const unverified = (name !== undefined && updated.name !== eq(name))
      || (sourceLabel !== undefined && (sourceLabel === null ? updated.sourceLabel !== null : updated.sourceLabel !== eq(sourceLabel)));
    return { ...toResponse(updated), unverified };
  }

  async function setVisibility({ tournamentId, visibility, clubId }) {
    const updated = await updateHeader({
      tournamentId,
      changes: { visibility, clubId: eq(clubId) === '' ? null : clubId }
    });
    if (updated.error) return updated;
    if (updated.visibility !== eq(visibility)) {
      return { error: 'write_unverified', detail: 'the tournament did not read back with the new visibility' };
    }
    if (eq(clubId) !== '' && updated.clubId !== eq(clubId)) {
      return { error: 'write_unverified', detail: 'the tournament did not read back with the new club' };
    }
    verified.delete(eq(tournamentId));
    return toResponse(updated);
  }

  /**
   * Publish or unpublish. Publishing is the one transition that hands deals to people who did not
   * import them, so it is gated on a verification this store performs from STORAGE — a set this process
   * did not import is read back and validated first, because the verified set is process memory and a
   * restarted relay must not publish a half-written tournament just because nobody told it about it.
   */
  async function setStatus({ tournamentId, status }) {
    if (status === 'published') {
      const scope = await tournamentScope(tournamentId);
      if (!scope || scope.unavailable) return { error: 'tournament_not_found', detail: 'the tournament has no readable row' };
      if (!verified.has(eq(tournamentId))) {
        const read = await listBoards({ tournamentId });
        if (read.error) return { error: 'publish_refused_unverified', detail: read.detail ?? read.error };
        if (read.boards.length === 0) {
          return { error: 'publish_refused_unverified', detail: 'no board row could be read back for this tournament' };
        }
        if (scope.boardCount > 0 && read.boards.length !== scope.boardCount) {
          return {
            error: 'publish_refused_unverified',
            detail: `the header says ${scope.boardCount} board(s) and ${read.boards.length} read back`
          };
        }
      }
    }
    const updated = await updateHeader({ tournamentId, changes: { status } });
    if (updated.error) return updated;
    if (status === 'published' && updated.status !== 'published') {
      return { error: 'write_unverified', detail: 'the tournament did not read back as published' };
    }
    if (status === 'draft') {
      // Un-publishing invalidates the proof: the set may be edited while draft, so a later publish has
      // to re-read it rather than trust this earlier one.
      verified.delete(eq(tournamentId));
    } else {
      verified.add(eq(tournamentId));
    }
    return toResponse(updated);
  }

  function toResponse(shaped) {
    return {
      id: shaped.id,
      user_id: shaped.ownerId,
      club_id: shaped.clubId === '' ? null : shaped.clubId,
      name: shaped.name,
      visibility: shaped.visibility,
      status: shaped.status,
      board_count: shaped.boardCount,
      source_label: shaped.sourceLabel,
      dedupe_key: shaped.dedupeKey
    };
  }

  // ── ATTEMPTS (self-scoped by construction) ───────────────────────────────
  /**
   * The caller's own attempts, and only their own: `userId` is the session id the route proved, and it
   * is re-asserted on every row. There is no route that lists another person's attempts, so there is
   * deliberately no way to ask this method for one.
   */
  async function listAttempts({ tournamentId, userId, boardNumber = null, page = 1, limit = 25 }) {
    const size = Math.min(Number(limit) || 25, schema.rowLimit);
    const read = await attemptRows({ tournamentId, userId, boardNumber: boardNumber === null ? null : eq(boardNumber) });
    if (read.error) return { error: read.error, detail: read.detail };
    const shaped = read.rows.map((row) => ({
      id: eq(row[C.attempts.id]),
      board_number: eq(row[C.attempts.boardNumber]),
      recorded_hand_id: eq(row[C.attempts.recordedHandId]),
      original_seat: eq(row[C.attempts.originalSeat]),
      user_id: eq(row[C.attempts.userId])
    }));
    const start = (Math.max(1, Number(page) || 1) - 1) * size;
    return { attempts: shaped.slice(start, start + size), total: shaped.length };
  }

  /**
   * Records that this account played this board, pointing at BridgeMind's recorded hand. The id of that
   * recording is the only handle stored: no score, no result, no replay — the gameplay layer owns the
   * content, this row owns the link, and UNIQUE(recorded_hand_id) is what stops one hand being filed
   * as two players' attempts.
   */
  async function recordAttempt({ tournamentId, boardNumber, recordedHandId, originalSeat, userId }) {
    const handId = eq(recordedHandId);
    if (handId === '') return { error: 'invalid_recorded_hand_id', detail: 'recorded_hand_id is required' };
    const body = {
      [C.attempts.tournamentId]: eq(tournamentId),
      [C.attempts.boardNumber]: eq(boardNumber),
      [C.attempts.recordedHandId]: handId,
      [C.attempts.originalSeat]: eq(originalSeat),
      [C.attempts.userId]: eq(userId)
    };
    const result = await run(CREATE(T.attempts, body));
    if (!result.ok) {
      if (!result.duplicate) return { error: result.reason, detail: result.detail };
      // UNIQUE(recorded_hand_id) fired. Look at the row that holds it: the SAME attempt re-sent is a
      // replay, and answering 409 for it would make a client that retried after a timeout believe it
      // lost its own write. A DIFFERENT attempt on that hand id is a caller error, and `bad_request`
      // because there is no conflict reason in the published vocabulary that means "that recording is
      // already filed elsewhere".
      const existing = await one(T.attempts, `${C.attempts.recordedHandId}=${encodeURIComponent(handId)}`);
      if (existing && !existing.unavailable
        && eq(existing[C.attempts.tournamentId]) === eq(tournamentId)
        && eq(existing[C.attempts.boardNumber]) === eq(boardNumber)
        && eq(existing[C.attempts.userId]) === eq(userId)) {
        return {
          id: eq(existing[C.attempts.id]),
          board_number: eq(existing[C.attempts.boardNumber]),
          recorded_hand_id: handId,
          original_seat: eq(existing[C.attempts.originalSeat]),
          user_id: eq(existing[C.attempts.userId]),
          replayed: true
        };
      }
      return { error: 'bad_request', detail: `recorded_hand_id "${handId}" is already recorded as a different attempt` };
    }
    const attemptId = newIdOf(result.body);
    const confirmed = attemptId
      ? await one(T.attempts, `${C.attempts.id}=${encodeURIComponent(attemptId)}`)
      : await one(T.attempts, `${C.attempts.recordedHandId}=${encodeURIComponent(handId)}`);
    if (!confirmed || confirmed.unavailable) {
      return { error: 'write_unverified', detail: 'the attempt row could not be read back' };
    }
    return {
      id: eq(confirmed[C.attempts.id]),
      board_number: eq(confirmed[C.attempts.boardNumber]),
      recorded_hand_id: handId,
      original_seat: eq(confirmed[C.attempts.originalSeat]),
      user_id: eq(confirmed[C.attempts.userId])
    };
  }

  /**
   * The state a management screen shows beside a tournament, and the only place a board count is
   * counted for display. `MAX_BOARD_NUMBER_CHARS` is exported through the module below so the route can
   * bound a path parameter with the same grammar the store wrote it with.
   */
  async function tournamentBoardCount(tournamentId) {
    const read = await boardRows({ tournamentId });
    if (read.error) return { error: read.error, detail: read.detail };
    return { count: read.boards.length };
  }

  return {
    // authority reads
    tournamentScope,
    listTournaments,
    readMembership,
    readClubStatus,
    readSuperAdmin,
    // boards
    listBoards,
    getBoard,
    tournamentBoardCount,
    // writes
    importTournament,
    renameTournament,
    setVisibility,
    setStatus,
    deleteTournament,
    // attempts
    listAttempts,
    recordAttempt,
    // diagnostics: names and counts, never row contents, never a credential
    diagnostics: () => ({ failures: failures.slice(-20), verifiedTournaments: [...verified] }),
    verifiedTournaments: verified
  };
}

module.exports = { createTournamentNcbStore, rowsOf, DUPLICATE_KEY };
