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
const { MEMBERSHIP_STATUSES, APPROVED_MEMBERSHIP_STATUS, isEffectiveMembership } = require('./clubSchema.js');

const READ = (table, query) => ({ group: 'data', path: `read/${table}${query ? `?${query}` : ''}`, method: 'GET' });
const CREATE = (table, body) => ({ group: 'data', path: `create/${table}`, method: 'POST', body });
const UPDATE = (table, id, body) => ({ group: 'data', path: `update/${table}/${encodeURIComponent(id)}`, method: 'PUT', body });
const REMOVE = (table, id) => ({ group: 'data', path: `delete/${table}/${encodeURIComponent(id)}`, method: 'DELETE' });

const eq = (value) => String(value ?? '').trim();
const rowsOf = (body) => (Array.isArray(body?.data) ? body.data : (Array.isArray(body) ? body : []));

// NCB reports a unique-index refusal in prose, and the prose is the only signal a sequential REST
// layer passes back. Scoped to the duplicate-key families: a 500 that merely mentions "exist"
// must not be turned into a clean `already_in_club` answer.
const DUPLICATE_KEY = /duplicate|unique|constraint|already exists/i;

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

  async function clubStatus(clubId) {
    const row = await one(T.clubs, `${C.clubs.id}=${encodeURIComponent(clubId)}`);
    return row ? eq(row[C.clubs.status]) : null;
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

  // ── SUPER ADMIN ───────────────────────────────────────────────────────────

  /**
   * NCB's read filter is an exact match, not a substring, so `search` is applied to the rows this
   * page returned. That means a search can report fewer clubs than exist rather than more — it can
   * never reveal a club the caller may not see, which is the only direction that would matter here.
   */
  async function listClubs({ search = '', page = 1, limit = 25 } = {}) {
    const size = Math.min(Number(limit) || 25, schema.rowLimit);
    const rows = await find(T.clubs, `limit=${size}&offset=${(Math.max(1, Number(page) || 1) - 1) * size}&sort=${C.clubs.name}&order=asc`);
    const shaped = (Array.isArray(rows) ? rows : []).map((row) => ({
      id: eq(row[C.clubs.id]),
      name: eq(row[C.clubs.name]),
      status: eq(row[C.clubs.status])
    }));
    const needle = String(search ?? '').trim().toLowerCase();
    return needle ? shaped.filter((club) => club.name.toLowerCase().includes(needle)) : shaped;
  }

  async function listActiveClubs() {
    const rows = await find(T.clubs, `${C.clubs.status}=active&limit=${schema.rowLimit}`);
    return (Array.isArray(rows) ? rows : []).map((row) => ({ id: eq(row[C.clubs.id]), name: eq(row[C.clubs.name]) }));
  }

  async function createClub({ name }) {
    const result = await run(CREATE(T.clubs, { [C.clubs.name]: name, [C.clubs.status]: 'active' }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const id = newIdOf(result.body);
    const row = id ? await one(T.clubs, `${C.clubs.id}=${encodeURIComponent(id)}`) : null;
    if (!row) return { error: 'write_unverified', detail: 'the club row could not be read back' };
    return { id: eq(row[C.clubs.id]), name: eq(row[C.clubs.name]), status: eq(row[C.clubs.status]) };
  }

  async function updateClub({ clubId, name }) {
    const result = await run(UPDATE(T.clubs, clubId, { [C.clubs.name]: name }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const row = await one(T.clubs, `${C.clubs.id}=${encodeURIComponent(clubId)}`);
    if (!row) return { error: 'write_unverified', detail: 'the club row could not be read back after the update' };
    const storedName = eq(row[C.clubs.name]);
    return { id: eq(row[C.clubs.id]), name: storedName, status: eq(row[C.clubs.status]), unverified: storedName !== name };
  }

  async function setClubStatus({ clubId, status }) {
    const result = await run(UPDATE(T.clubs, clubId, { [C.clubs.status]: status }));
    if (!result.ok) return { error: result.reason, detail: result.detail };
    const row = await one(T.clubs, `${C.clubs.id}=${encodeURIComponent(clubId)}`);
    if (!row) return { error: 'write_unverified', detail: 'the club row could not be read back after the update' };
    return { id: eq(row[C.clubs.id]), status: eq(row[C.clubs.status]) };
  }

  async function listMembers({ clubId }) {
    const rows = await find(T.memberships, `${C.memberships.clubId}=${encodeURIComponent(clubId)}&limit=${schema.rowLimit}`);
    // `status` rides along so a club admin sees the pending requests they are being asked to act on
    // through the SAME read that lists members. A separate requests endpoint would be a second
    // surface deciding the same thing.
    return (Array.isArray(rows) ? rows : []).map((row) => ({
      user_id: eq(row[C.memberships.userId]),
      club_role: eq(row[C.memberships.role]),
      membership_status: eq(row[C.memberships.status]),
      membership_id: eq(row[C.memberships.id])
    }));
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
    const rows = await find(T.collections, `${C.collections.clubId}=${encodeURIComponent(clubId)}&limit=${schema.rowLimit}`);
    return (Array.isArray(rows) ? rows : []).map(shapeCollection);
  }

  // Scope is re-asserted on the row itself, not trusted to the query filter: this is the read that
  // decides whether a member may see a board, so a filter the backend ignored must not become a
  // cross-club read.
  async function listPublishedCollections({ clubId }) {
    const rows = await find(T.collections,
      `${C.collections.clubId}=${encodeURIComponent(clubId)}&${C.collections.status}=published&limit=${schema.rowLimit}`);
    return (Array.isArray(rows) ? rows : [])
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
    if (C.boards.sourcePbn) board.source = eq(row[C.boards.sourcePbn]);
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
  async function createCollection({ clubId, name, boards }) {
    const created = await run(CREATE(T.collections, {
      [C.collections.clubId]: clubId, [C.collections.name]: name, [C.collections.status]: 'draft'
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
        [C.boards.handsJson]: JSON.stringify(board.hands),
        ...(C.boards.sourcePbn && board.source ? { [C.boards.sourcePbn]: eq(board.source) } : {})
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
    listClubs,
    listActiveClubs,
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
