'use strict';

/*
 * TOURNAMENT AUTHORIZATION — NodeSend's server-side authority for the tournament feature.
 *
 * THE FOUR RULES, and where each is enforced:
 *   T1 Every authenticated account imports and manages its OWN private sets. Only the owner may list,
 *      read, update or delete them — NOT the BridgeMind Admin. "Only the owner" is the product rule,
 *      and widening it in the backend would be the defect, so a super admin reads 403 on a private row.
 *   T2 A club set is managed by an approved Club Admin OF THE OWNING CLUB (or a system admin acting for
 *      that club), and reached by approved members of that club only when it is published.
 *   T3 A public set is managed by the BridgeMind Admin, and reached by any authenticated session only
 *      when it is published.
 *   T4 An attempt belongs to the account that played it. Attempts are listed and written for the
 *      session's own id and no other, and only into a set that session may play.
 *
 * WHY THESE ROUTES EXIST AT ALL. Before them, the three tournament tables were in the player gateway's
 * allow-list with write policy `full` for every authenticated session (`ncb/gateway.js`), so "private"
 * was a client-side opinion: any signed-in account could read, rewrite or delete any tournament row
 * through `/ncb/data/{create,update,delete}/tournaments`. Those tables are now blocked by name there,
 * and this file is the only way in.
 *
 * IDENTITY COMES FROM THE VALIDATED SESSION AND NOTHING ELSE. The caller's own id is resolved by the
 * relay's existing `resolveSessionUser` (injected as `authenticate`, the same seam the club routes use).
 * The row's OWNER, CLUB, VISIBILITY and STATUS are read FROM STORAGE before any decision — an id in the
 * path names a TARGET, never a permission. A body or query field never supplies any of them:
 * `validateRequestShape` refuses unexpected fields outright with a positive per-operation allow-list,
 * so `user_id` is rejected by construction rather than by a denylist somebody has to remember when a
 * field is added. Note what is absent from every list in TOURNAMENT_BODY_FIELDS: `user_id`, `role`,
 * `is_super_admin`, `status` on a create, and `board_count`.
 *
 * SUPER ADMIN COMES FROM `system_admins`, THROUGH THE CLUB STORE. The session's NCB `role` string is
 * never a tournament privilege — a role is application data, and letting it grant field-wide power would
 * mean a row edit promotes a member. `store.readSuperAdmin` delegates to the club store's
 * `isSystemAdmin`, and an unreadable verdict is a 503, never a "not an admin" answer that would be a
 * false statement about a real person. Same rule as `clubs/clubAuthorization.js`.
 *
 * CLUB MEMBERSHIP IS NOT RE-DERIVED HERE. `store.readMembership` / `readClubActive` delegate to the club
 * store's `getMembership` / `clubStatus`, and the approved-and-active collapse is the club feature's own
 * `isEffectiveMembership` predicate imported from `clubs/clubSchema.js`. This file therefore contains no
 * club table name and no second membership rule; if the club backend is unavailable the answer is a
 * named 503, and nothing falls back to a caller-bearer read. Two rules deciding "is this person in that
 * club" is two answers, and the product would have to pick one at request time.
 *
 * THE ACCESS RULE IS ONE FUNCTION, copied from the frozen contract. `resolveTournamentAccess`,
 * `tournamentListScope`, `authorizeTournamentCreate` and `authorizeVisibilityTarget` below are NodeSend's
 * server-side copies of the predicates in the frontend's `src/services/tournamentContracts.js`. They are
 * copies because a deployed container cannot import a browser-module path, and NodeSend already keeps its
 * own route list for exactly that reason (see `verify-clubs-gateway.mjs`). The copies are NOT trusted to
 * stay in agreement: `verify-tournaments-gateway.mjs` extracts the contract file's own function bodies,
 * evaluates them in-process, and compares truth tables against these over an exhaustive input matrix. A
 * divergence goes red there rather than showing up as a button the backend refuses.
 *
 * THE LIST SCOPE IS SERVER-DERIVED. `tournamentListScope` returns the disjunction of row sets this
 * caller may see, built from the session and the membership alone. A `visibility` or `club_id` in the
 * query is a FILTER inside that set and can only narrow it, never widen it — which is the property that
 * makes "a public list must never carry private or club rows" a fact rather than a hope.
 *
 * ROUTES ARE UNPREFIXED: `/tournaments/...`, the same grammar as `/clubs/...`, `/ai/...` and
 * `/ncb/...`. BridgeMind's browser transport strips the `/api` prefix it uses against its local server
 * before dialling this host.
 */

const { Router } = require('express');
/* The tournament board contract, not the club one. `clubs/clubBoardValidator.js` caps board_number at the
   10 characters its own VARCHAR(10) column can hold; tournaments publish 1-32 (tournamentContracts.js,
   and the VARCHAR(32) migration ask). The deck rules — seats, dealers, vulnerabilities, the card alphabet,
   13 per hand and 52 per board — are still the club module's exported primitives, so nothing here defines a
   second idea of what a card is. See tournaments/tournamentBoardValidator.js. */
const {
  validateBoardSubmission, isBoardNumber, MAX_BOARD_NUMBER_CHARS, SEATS
} = require('./tournamentBoardValidator.js');
const { APPROVED_MEMBERSHIP_STATUS, isEffectiveMembership } = require('../clubs/clubSchema.js');

const ID = /^[A-Za-z0-9_-]{1,32}$/;
// A recorded-hand id names a row in another table, so it takes the relay's row-id grammar (1-64) rather
// than the short path-parameter one. It is never a path segment on these routes.
const HAND_ID = /^[A-Za-z0-9_-]{1,64}$/;
const TOURNAMENT_VISIBILITIES = Object.freeze(['private', 'club', 'public']);
const TOURNAMENT_STATUSES = Object.freeze(['draft', 'published']);
const MAX_TOURNAMENT_NAME_LENGTH = 200;
const MAX_TOURNAMENT_SOURCE_LABEL_LENGTH = 200;
// The contract's ceiling for ONE import. `MAX_BOARDS_PER_COLLECTION` in the club validator is 200 and is
// a ceiling it enforces, never raises: a deployment may lower this, never past 200.
const MAX_TOURNAMENT_BOARDS = 100;
const DEFAULT_TOURNAMENT_LIST_LIMIT = 25;
const MAX_TOURNAMENT_LIST_LIMIT = 100;

const isId = (value) => ID.test(String(value ?? '').trim());
const isHandId = (value) => HAND_ID.test(String(value ?? '').trim());

/**
 * Positive field allow-lists, per operation — a transcription of `TOURNAMENT_BODY_FIELDS` in the frozen
 * contract, and pinned to it arm-for-arm by the differential section of the gate. A denylist fails the
 * moment a field is added and only needs one name nobody thought of; a positive list refuses the new
 * name on sight.
 */
const TOURNAMENT_BODY_FIELDS = Object.freeze({
  listTournaments: { query: ['page', 'limit', 'visibility', 'club_id', 'status'], body: [] },
  createTournament: { query: [], body: ['name', 'visibility', 'club_id', 'boards', 'source_label', 'dedupe_key'] },
  readTournament: { query: [], body: [] },
  listBoards: { query: [], body: [] },
  updateTournament: { query: [], body: ['name', 'source_label'] },
  setVisibility: { query: [], body: ['visibility', 'club_id'] },
  publish: { query: [], body: [] },
  unpublish: { query: [], body: [] },
  deleteTournament: { query: [], body: ['confirm_name'] },
  startBoard: { query: [], body: ['original_seat'] },
  listAttempts: { query: ['board_number', 'page', 'limit'], body: [] },
  recordAttempt: { query: [], body: ['board_number', 'original_seat', 'recorded_hand_id'] }
});

/**
 * The mounted surface, as data — exactly the twelve routes of `TOURNAMENT_ENDPOINTS`, in that order, with
 * the path parameter grammar these routes actually register (`:tournamentId`, not `{tournamentId}`).
 * `guard` names who the ROUTE must authorise, and `ownerFromStore: true` marks the routes that read the
 * row's owner/club/visibility/status from storage before deciding anything.
 */
const TOURNAMENT_ROUTES = Object.freeze([
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

/** Which store method each operation needs, so an incomplete adapter fails closed with 503 on the
 * specific missing method instead of throwing mid-request. */
const TOURNAMENT_STORE_METHOD_FOR = Object.freeze({
  listTournaments: 'listTournaments',
  createTournament: 'importTournament',
  readTournament: 'tournamentScope',
  listBoards: 'listBoards',
  updateTournament: 'renameTournament',
  setVisibility: 'setVisibility',
  publish: 'setStatus',
  unpublish: 'setStatus',
  deleteTournament: 'deleteTournament',
  startBoard: 'getBoard',
  listAttempts: 'listAttempts',
  recordAttempt: 'recordAttempt'
});

function refuseIdentityFieldsIn(path) {
  return {
    status: 400,
    body: {
      error: 'client_identity_refused',
      detail: `Ownership, club scope and visibility are derived from the session and from storage by this route; unexpected or identity-bearing fields in the request (${path}) are refused rather than ignored.`
    }
  };
}

/** Rejects unknown or misplaced fields. Returns an error object or null. */
function validateTournamentRequestShape(op, { query = {}, body = {} } = {}) {
  const spec = TOURNAMENT_BODY_FIELDS[op];
  if (!spec) {
    return { status: 400, body: { error: 'unknown_operation', detail: 'This route does not name a tournament operation.' } };
  }
  const extraBody = Object.keys(body ?? {}).filter((key) => !spec.body.includes(key));
  const extraQuery = Object.keys(query ?? {}).filter((key) => !spec.query.includes(key));
  if (extraBody.length || extraQuery.length) {
    return refuseIdentityFieldsIn([...extraBody.map((k) => `body.${k}`), ...extraQuery.map((k) => `query.${k}`)].join(', '));
  }
  return null;
}

// Validation results are `{ ok, value }` or `{ ok: false, status, body }`, so a caller that forgets to
// branch cannot fall through into `input.value` on a rejected request.
function badRequest(detail, error = 'bad_request') {
  return { ok: false, status: 400, body: { error, detail } };
}

function hasControlChars(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

// ── THE ACCESS RULE (NodeSend's copy of the frozen contract's predicate) ─────
/*
 * Pure, no I/O. Inputs are all SERVER-derived:
 *   row         { visibility, status, ownerId, clubId }   read from the tournaments table
 *   session     { userId, isSuperAdmin }                  from the validated session + system_admins
 *   membership  { clubId, role } | null                   the APPROVED row of an ACTIVE club
 *
 * `owner_only` for a private row is asserted, not defaulted: a private tournament is invisible to the
 * BridgeMind Admin too. Read, manage and play are three axes because they have three different answers
 * — a club member may read and play a published set and manage none of it.
 */
function resolveTournamentAccess({ row = null, session = null, membership = null } = {}) {
  const userId = session?.userId == null ? '' : String(session.userId);
  const isSuper = session?.isSuperAdmin === true;
  const memberClub = membership?.clubId == null ? '' : String(membership.clubId);
  const adminOfClub = (clubId) => isSuper
    || (memberClub !== '' && String(clubId ?? '') !== '' && memberClub === String(clubId) && membership?.role === 'club_admin');
  const isMemberOfClub = (clubId) => memberClub !== '' && String(clubId ?? '') === memberClub;

  const visibility = String(row?.visibility ?? '');
  const status = String(row?.status ?? '');
  const ownerId = row?.ownerId == null ? '' : String(row.ownerId);
  const clubId = row?.clubId == null ? '' : String(row.clubId);

  if (!TOURNAMENT_VISIBILITIES.includes(visibility)) {
    return { read: false, manage: false, play: false, reason: 'invalid_visibility' };
  }

  if (visibility === 'private') {
    const mine = userId !== '' && ownerId === userId;
    return { read: mine, manage: mine, play: mine, reason: mine ? null : 'owner_only' };
  }

  if (visibility === 'club') {
    if (clubId === '') return { read: false, manage: false, play: false, reason: 'club_required' };
    if (adminOfClub(clubId)) {
      // An admin of the owning club (or a system admin acting for the club) manages and reads it
      // whatever its status, so a draft can be reviewed before it is published.
      return { read: true, manage: true, play: true, reason: null, asAdmin: true };
    }
    if (!isMemberOfClub(clubId)) {
      return { read: false, manage: false, play: false, reason: memberClub === '' ? 'not_a_club_member' : 'club_scope_mismatch' };
    }
    if (status !== 'published') return { read: false, manage: false, play: false, reason: 'tournament_not_published' };
    return { read: true, manage: false, play: true, reason: null, asMember: true };
  }

  // public
  if (isSuper) return { read: true, manage: true, play: true, reason: null, asSuperAdmin: true };
  if (status !== 'published') return { read: false, manage: false, play: false, reason: 'tournament_not_published' };
  return { read: true, manage: false, play: true, reason: null, asPublic: true };
}

/**
 * The list scope, as data the route applies. The caller never chooses it: `visibility=public` in a query
 * is a filter INSIDE the allowed set. Each clause is a conjunction of real column names, which the store
 * turns into NCB equality filters, so a public list cannot carry a private row even if one filter were
 * ignored — the row is re-checked against its own clause on the way out.
 *
 * THE OWNER COLUMN IS NOT DEFAULTED, and `user_id` in particular is never a fallback. On this vendor
 * `user_id` is the row-ownership slot NCB stamps from the WRITING session, and NodeSend writes every
 * tournament row with its dedicated service account, so a private clause built on `user_id` asks
 * "which tournaments does the service account own" about the one column that can answer it: it matches
 * either nothing or everything, and the caller is told "you have no tournaments" — a wrong answer that
 * looks like a fact about the player. `tournaments/tournamentSchema.js` refuses that mapping in CONFIG
 * at boot; this is the same rule enforced where the clause is actually built, so no call site can
 * reach it by forgetting to thread the schema through. A missing owner column is a deployment fault
 * and answers 503, which is the truth; an empty list would not be.
 */
const NCB_ROW_OWNER_COLUMN = 'user_id';

function tournamentListScope({ session = null, membership = null, columns = null } = {}) {
  const userId = session?.userId == null ? '' : String(session.userId);
  const isSuper = session?.isSuperAdmin === true;
  const memberClub = membership?.clubId == null ? '' : String(membership.clubId);
  const adminClub = memberClub !== '' && membership?.role === 'club_admin' ? memberClub : '';
  const ownerColumn = columns?.userId == null ? '' : String(columns.userId).trim();
  if (ownerColumn === '' || ownerColumn === NCB_ROW_OWNER_COLUMN) {
    return {
      userId, isSuper, memberClub, adminClub, clauses: [],
      error: 'tournament_identity_column_unconfigured',
      detail: ownerColumn === NCB_ROW_OWNER_COLUMN
        ? `columns.tournaments.userId resolves to "${NCB_ROW_OWNER_COLUMN}", which is NCB's row-ownership slot and not the application owner.`
        : 'columns.tournaments.userId was not supplied, so the private-tournament scope cannot name the owner column.'
    };
  }
  const col = {
    visibility: columns?.visibility ?? 'visibility',
    userId: ownerColumn,
    clubId: columns?.clubId ?? 'club_id',
    status: columns?.status ?? 'status'
  };
  const clauses = [{ [col.visibility]: 'private', [col.userId]: userId }];
  if (memberClub !== '') {
    clauses.push(adminClub === memberClub
      ? { [col.visibility]: 'club', [col.clubId]: memberClub }
      : { [col.visibility]: 'club', [col.clubId]: memberClub, [col.status]: 'published' });
  }
  if (isSuper) clauses.push({ [col.visibility]: 'public' });
  else clauses.push({ [col.visibility]: 'public', [col.status]: 'published' });
  return { userId, isSuper, memberClub, adminClub, clauses };
}

/*
 * Authority for a NEW tournament. The category the importer asks for decides who may do it, so a normal
 * player importing a private set needs no privilege at all, while a club or public import is refused
 * loudly rather than quietly filed as private.
 */
function authorizeTournamentCreate({ target = null, targetClubId = null, session = null, membership = null, clubActive = null } = {}) {
  const validated = validateVisibilityChange(target);
  if (!validated.valid) return { allow: false, reason: validated.error };
  const userId = session?.userId == null ? '' : String(session.userId);
  if (validated.visibility === 'private') {
    return userId === ''
      ? { allow: false, reason: 'unauthorized' }
      : { allow: true, scope: { visibility: 'private', ownerId: userId, clubId: null } };
  }
  if (validated.visibility === 'club') {
    const club = idToString(targetClubId);
    if (club === '') return { allow: false, reason: 'invalid_club_id' };
    const memberClub = membership?.clubId == null ? '' : String(membership.clubId);
    if (!(session?.isSuperAdmin === true || (memberClub === club && membership?.role === 'club_admin'))) {
      return { allow: false, reason: 'not_a_club_admin' };
    }
    if (clubActive === false) return { allow: false, reason: 'club_inactive' };
    // `ownerId` is spelled exactly as the contract spells it (`null` only for an absent id, the empty
    // string kept as `''` for a present-but-blank one). The router rejects a blank session id before this
    // is reached, so the distinction never carries a privilege — but a differential arm that compared the
    // two implementations would report every other field as agreeing while this one quietly differed.
    return { allow: true, scope: { visibility: 'club', clubId: club, ownerId: session?.userId == null ? null : String(session.userId) } };
  }
  return session?.isSuperAdmin === true
    ? { allow: true, scope: { visibility: 'public', clubId: null, ownerId: session.userId == null ? null : String(session.userId) } }
    : { allow: false, reason: 'super_admin_required' };
}

/*
 * THE ONE destination rule for a category change, decided by the DESTINATION rather than the source:
 *   into `public`  — the BridgeMind Admin only.
 *   into `club`    — an admin OF THE TARGET CLUB (or the BridgeMind Admin, who may act for any club),
 *                    checked against the session's approved membership and never taken as granted. A
 *                    club's set cannot move to another club, not even by its own admin.
 *   into `private` — the row's own owner only, and never a row the field or a club can see.
 * A row already in the destination category AND the destination club is a no-op, not a refusal, so a
 * management screen can show the current value as selected. The club half of that test is load-bearing:
 * `club -> club` with a different club id is the most damaging write this route can take, because every
 * board row keeps its `tournament_id` and nothing else changes.
 */
function visibilityTargetDecision({ row = null, target = null, targetClubId = null, session = null, membership = null } = {}) {
  const current = String(row?.visibility ?? '');
  const isSuper = session?.isSuperAdmin === true;
  const userId = session?.userId == null ? '' : String(session.userId);
  const ownerId = row?.ownerId == null ? '' : String(row.ownerId);
  const isOwner = ownerId !== '' && ownerId === userId;
  const memberClub = membership?.clubId == null ? '' : String(membership.clubId);
  const isClubAdmin = memberClub !== '' && membership?.role === 'club_admin';
  const club = idToString(targetClubId);
  const rowClub = String(row?.clubId ?? '');

  if (target === current && (target !== 'club' || club === rowClub)) {
    return { allow: true, noop: true, scope: { visibility: current, clubId: target === 'club' ? rowClub : null } };
  }

  if (target === 'public') {
    return isSuper
      ? { allow: true, scope: { visibility: 'public', clubId: null } }
      : { allow: false, reason: 'super_admin_required' };
  }

  if (target === 'club') {
    if (club === '') return { allow: false, reason: 'invalid_club_id' };
    if (!(isSuper || (isClubAdmin && memberClub === club))) return { allow: false, reason: 'not_a_club_admin' };
    if (current === 'club' && rowClub !== club && !isSuper) return { allow: false, reason: 'club_scope_mismatch' };
    return { allow: true, scope: { visibility: 'club', clubId: club } };
  }

  if (target === 'private') {
    if (!isOwner) return { allow: false, reason: 'owner_only' };
    if (current === 'public') return { allow: false, reason: 'super_admin_required' };
    // A club set cannot become private — not even for its importer, who may also be the club's admin.
    // Such a row carries TWO authorities (`user_id` names the importer, `club_id` names the members) and
    // demoting it would revoke the club's access as a one-person decision that leaves no trace.
    if (current === 'club') return { allow: false, reason: 'club_scope_mismatch' };
    return { allow: true, scope: { visibility: 'private', clubId: null } };
  }

  return { allow: false, reason: 'invalid_visibility' };
}

/*
 * Name WHY management is refused. `resolveTournamentAccess` answers the read/play question, so its
 * `reason` is null for a caller who may legitimately look at a row but not change it — a club member, or
 * an ordinary user facing the published field. An untranslatable refusal with no name is undebuggable,
 * so the manage axis gets its own reason rather than borrowing a null from another axis.
 */
function manageRefusalReason({ row = null } = {}) {
  const visibility = String(row?.visibility ?? '');
  if (!TOURNAMENT_VISIBILITIES.includes(visibility)) return 'invalid_visibility';
  if (visibility === 'private') return 'owner_only';
  if (visibility === 'club') return 'not_a_club_admin';
  return 'super_admin_required';
}

/* What the route calls before it touches storage, and what the frontend's gateway calls identically:
 * `{ allow, scope }` or `{ allow: false, reason }`. */
function authorizeVisibilityTarget({ row = null, target = null, targetClubId = null, session = null, membership = null } = {}) {
  const validated = validateVisibilityChange(target);
  if (!validated.valid) return { allow: false, reason: validated.error };
  const access = resolveTournamentAccess({ row, session, membership });
  if (!access.manage) {
    return { allow: false, reason: access.reason ?? manageRefusalReason({ row, session, membership }) };
  }
  return visibilityTargetDecision({ row, target: validated.visibility, targetClubId, session, membership });
}

/*
 * THE AUTHORITY DECISION FOR ONE REQUEST — pure, no I/O. The router calls it after resolving the session,
 * the membership bridge, the super-admin grant and the stored row; a test calls it directly with a fake
 * identity and a fake row and no database.
 *
 * `storeSuperAdmin` is the `system_admins` verdict and only `true` grants; `null` (unreadable) is refused
 * by the router with a 503 BEFORE this is ever reached, so it cannot be mistaken for "not an admin".
 */
function authorizeTournamentOperation({
  op,
  session = null,
  row = null,
  membership = null,
  targetClubId = null,
  targetVisibility = null,
  storeSuperAdmin = null,
  clubActive = null,
  columns = null
} = {}) {
  if (!session || session.userId === undefined || session.userId === null || String(session.userId).trim() === '') {
    return { status: 401, body: { error: 'authentication_required', detail: 'A validated session is required.' } };
  }
  const identity = { userId: String(session.userId), isSuperAdmin: storeSuperAdmin === true };

  switch (op) {
    case 'listTournaments': {
      // Any session may list; WHAT it may see is the scope, never a query parameter. `columns` carries the
      // deployment's real column names into the clauses, so the store filters on columns that exist
      // rather than on the vocabulary this feature speaks. A scope that could not be built at all is a
      // deployment fault and answers 503 — never the 200-with-no-rows a wrong owner column would give,
      // because that answer is a false statement about the player's own tournaments.
      const scope = tournamentListScope({ session: identity, membership, columns });
      return scope.error
        ? { status: 503, body: { error: scope.error, detail: scope.detail } }
        : { allow: true, scope };
    }

    case 'createTournament': {
      const decision = authorizeTournamentCreate({
        target: targetVisibility, targetClubId, session: identity, membership, clubActive
      });
      return decision.allow
        ? { allow: true, scope: decision.scope }
        : refuse(decision.reason, visibilityReasonStatus(decision.reason));
    }

    case 'readTournament':
    case 'listBoards': {
      const access = resolveTournamentAccess({ row, session: identity, membership });
      return access.read
        ? { allow: true, scope: access }
        : refuse(access.reason ?? 'owner_only', 403);
    }

    case 'updateTournament':
    case 'publish':
    case 'unpublish':
    case 'deleteTournament': {
      const access = resolveTournamentAccess({ row, session: identity, membership });
      return access.manage
        ? { allow: true, scope: access }
        : refuse(access.reason ?? manageRefusalReason({ row }), 403);
    }

    case 'setVisibility': {
      const decision = authorizeVisibilityTarget({
        row, target: targetVisibility, targetClubId, session: identity, membership
      });
      return decision.allow
        ? { allow: true, scope: decision.scope, noop: decision.noop === true }
        : refuse(decision.reason, visibilityReasonStatus(decision.reason));
    }

    case 'startBoard': {
      const access = resolveTournamentAccess({ row, session: identity, membership });
      return access.play
        ? { allow: true, scope: access }
        : refuse(access.reason ?? 'owner_only', 403);
    }

    case 'listAttempts': {
      const access = resolveTournamentAccess({ row, session: identity, membership });
      return access.read
        ? { allow: true, scope: { ...access, userId: identity.userId } }
        : refuse(access.reason ?? 'owner_only', 403);
    }

    case 'recordAttempt': {
      // Playing a board is what earns an attempt row on it. Reading a set is not: a club member may LIST
      // a published set's attempts and must still be able to play it, which they can — but a row that
      // claims somebody played a board they may not touch would be a write wearing a read's permission.
      const access = resolveTournamentAccess({ row, session: identity, membership });
      return access.play
        ? { allow: true, scope: { ...access, userId: identity.userId } }
        : refuse(access.reason ?? 'owner_only', 403);
    }

    default:
      return { status: 400, body: { error: 'unknown_operation', detail: 'This route does not name a tournament operation.' } };
  }
}

// A category problem is either a malformed value (the caller's 400) or a refusal of who they are (403).
// Collapsing them means a client cannot tell "type a different category" from "you are not the admin".
function visibilityReasonStatus(reason) {
  if (reason === 'invalid_visibility' || reason === 'invalid_club_id') return 400;
  if (reason === 'unauthorized') return 401;
  return 403;
}

function refuse(reason, status) {
  return { status, body: { error: reason, detail: TOURNAMENT_REFUSAL_COPY[reason] ?? `This tournament route refused the request (${reason}).` } };
}

const TOURNAMENT_REFUSAL_COPY = Object.freeze({
  owner_only: 'Only the account that imported a private tournament may see it.',
  not_tournament_owner: 'Only the account that imported this tournament may do that to it.',
  not_a_club_member: 'No club is attached to this session.',
  not_a_club_admin: 'Only an admin of the owning club may manage this tournament.',
  super_admin_required: 'This action needs the BridgeMind Admin (a system_admins entry).',
  club_required: 'This tournament is marked club-visible but names no club.',
  club_inactive: 'That club is not active.',
  club_scope_mismatch: 'This tournament belongs to a different club.',
  tournament_not_published: 'This tournament is not published yet.'
});

// ── field-level validation ──────────────────────────────────────────────────
function idToString(value) {
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(Math.trunc(value));
  return '';
}

function validateVisibilityChange(raw) {
  if (typeof raw !== 'string') return { valid: false, error: 'invalid_visibility' };
  const visibility = raw.trim();
  return TOURNAMENT_VISIBILITIES.includes(visibility)
    ? { valid: true, visibility }
    : { valid: false, error: 'invalid_visibility' };
}

function validateTournamentName(raw) {
  if (typeof raw !== 'string') return { valid: false, error: 'invalid_name' };
  const name = raw.trim().replace(/\s+/g, ' ');
  if (name === '') return { valid: false, error: 'invalid_name' };
  if (hasControlChars(name)) return { valid: false, error: 'invalid_name' };
  if (name.length > MAX_TOURNAMENT_NAME_LENGTH) return { valid: false, error: 'invalid_name' };
  return { valid: true, name };
}

function validateTournamentSourceLabel(raw) {
  if (raw === null || raw === undefined || raw === '') return { valid: true, label: null };
  if (typeof raw !== 'string') return { valid: false, error: 'invalid_name' };
  const label = raw.trim().replace(/\s+/g, ' ');
  if (hasControlChars(label) || label.length > MAX_TOURNAMENT_SOURCE_LABEL_LENGTH) {
    return { valid: false, error: 'invalid_name' };
  }
  return { valid: true, label: label || null };
}

/**
 * The board shape, checked from the STORE's point of view. `pbnImport` in the browser already rejected
 * malformed blocks and this file's own `validateBoardSubmission` is the second gate — the one that
 * matters, because a client that skipped its own validation must not be able to persist a 51-card board.
 *
 * Input accepts either spelling of the board number (`boardNumber` from a JS caller, `board_number` from
 * a stored row), and carries `tags` — the source PBN `[Contract]/[Declarer]/[Result]` metadata — through
 * as historical data. Nothing downstream reads `tags` for a decision, and it never contributes a bid.
 */
function normalizeBoardInput(boards) {
  if (!Array.isArray(boards)) return { ok: false, status: 400, body: { error: 'invalid_board_record', detail: 'boards must be an array' } };
  if (boards.length === 0) return { ok: false, status: 400, body: { error: 'no_boards', detail: 'at least one board is required' } };
  if (boards.length > MAX_TOURNAMENT_BOARDS) {
    return { ok: false, status: 400, body: { error: 'too_many_boards', detail: `a tournament holds at most ${MAX_TOURNAMENT_BOARDS} boards` } };
  }
  const seen = new Set();
  const normalized = [];
  for (const board of boards) {
    if (!board || typeof board !== 'object' || Array.isArray(board)) {
      return { ok: false, status: 400, body: { error: 'invalid_board_record', detail: 'each board must be an object' } };
    }
    const rawNumber = board.board_number ?? board.boardNumber;
    const boardNumber = typeof rawNumber === 'number' && Number.isFinite(rawNumber)
      ? String(Math.trunc(rawNumber))
      : String(rawNumber ?? '').trim();
    normalized.push({
      board_number: boardNumber,
      dealer: String(board.dealer ?? '').trim(),
      vulnerability: String(board.vulnerability ?? '').trim(),
      hands: board.hands && typeof board.hands === 'object' && !Array.isArray(board.hands) ? board.hands : {},
      tags: board.tags && typeof board.tags === 'object' && !Array.isArray(board.tags) ? board.tags
        : (board.source && typeof board.source === 'object' && !Array.isArray(board.source) ? board.source : null)
    });
    if (seen.has(boardNumber)) {
      return { ok: false, status: 400, body: { error: 'duplicate_board_number', detail: `board number "${boardNumber}" appears twice in this import` } };
    }
    seen.add(boardNumber);
  }
  const checked = validateBoardSubmission(normalized, { maxBoards: MAX_TOURNAMENT_BOARDS });
  if (!checked.ok) {
    return {
      ok: false,
      status: 400,
      body: { error: checked.reason, detail: checked.detail, rejected: checked.rejected.slice(0, 10) }
    };
  }
  return { ok: true, value: { boards: normalized } };
}

/**
 * Field-level validation of the values an ALLOWED request may carry. Shape (which fields exist at all) is
 * already settled by `validateTournamentRequestShape`; this settles whether their values make sense.
 */
function validateTournamentInput(op, body = {}, { query = {}, maxBoards = MAX_TOURNAMENT_BOARDS, maxRowLimit = MAX_TOURNAMENT_LIST_LIMIT } = {}) {
  switch (op) {
    case 'listTournaments': {
      if (query.visibility !== undefined && !TOURNAMENT_VISIBILITIES.includes(String(query.visibility))) {
        return badRequest(`visibility must be one of ${TOURNAMENT_VISIBILITIES.join(', ')}.`, 'invalid_visibility');
      }
      if (query.status !== undefined && !TOURNAMENT_STATUSES.includes(String(query.status))) {
        return badRequest(`status must be one of ${TOURNAMENT_STATUSES.join(', ')}.`, 'invalid_status');
      }
      if (query.club_id !== undefined && !isId(query.club_id)) {
        return badRequest('club_id must be a short alphanumeric identifier.', 'invalid_club_id');
      }
      return {
        ok: true,
        value: {
          page: boundedPage(query.page),
          limit: boundedLimit(query.limit, maxRowLimit),
          visibility: query.visibility === undefined ? null : String(query.visibility),
          status: query.status === undefined ? null : String(query.status),
          clubId: query.club_id === undefined ? null : String(query.club_id).trim()
        }
      };
    }
    case 'createTournament': {
      const name = validateTournamentName(body.name);
      if (!name.valid) return badRequest('A tournament name of 1-200 characters is required.', name.error);
      const visibility = validateVisibilityChange(body.visibility);
      if (!visibility.valid) return badRequest(`visibility must be one of ${TOURNAMENT_VISIBILITIES.join(', ')}.`, visibility.error);
      let clubId = null;
      if (body.club_id !== undefined && body.club_id !== null && body.club_id !== '') {
        if (!isId(body.club_id)) return badRequest('club_id must be a short alphanumeric identifier.', 'invalid_club_id');
        clubId = String(body.club_id).trim();
      }
      if (visibility.visibility === 'club' && clubId === null) {
        return badRequest('A club tournament must name the club it belongs to.', 'invalid_club_id');
      }
      if (visibility.visibility !== 'club' && clubId !== null) {
        // A private or public set carrying a club id would leave a `club_id` on a row nobody can reach
        // through that club — a value with no owner and no rule, and exactly the half-state that makes a
        // later category change ambiguous.
        return badRequest('club_id is only meaningful for a club tournament.', 'club_scope_mismatch');
      }
      let sourceLabel = null;
      if (body.source_label !== undefined) {
        const label = validateTournamentSourceLabel(body.source_label);
        if (!label.valid) return badRequest('source_label must be 200 characters or fewer, without control characters.', label.error);
        sourceLabel = label.label;
      }
      let dedupeKey = null;
      if (body.dedupe_key !== undefined && body.dedupe_key !== null && body.dedupe_key !== '') {
        if (typeof body.dedupe_key !== 'string' || !isId(body.dedupe_key)) {
          return badRequest('dedupe_key must be a short alphanumeric identifier.', 'bad_request');
        }
        dedupeKey = body.dedupe_key.trim();
      }
      const boards = normalizeBoardInput(body.boards);
      if (boards.ok === false) return boards;
      return { ok: true, value: { name: name.name, visibility: visibility.visibility, clubId, sourceLabel, dedupeKey, boards: boards.value.boards, maxBoards } };
    }
    case 'updateTournament': {
      const changes = {};
      if (body.name !== undefined) {
        const name = validateTournamentName(body.name);
        if (!name.valid) return badRequest('A tournament name of 1-200 characters is required.', name.error);
        changes.name = name.name;
      }
      if (body.source_label !== undefined) {
        const label = validateTournamentSourceLabel(body.source_label);
        if (!label.valid) return badRequest('source_label must be 200 characters or fewer, without control characters.', label.error);
        changes.sourceLabel = label.label;
      }
      if (!Object.keys(changes).length) return badRequest('Nothing to change was named.');
      return { ok: true, value: changes };
    }
    case 'setVisibility': {
      const visibility = validateVisibilityChange(body.visibility);
      if (!visibility.valid) return badRequest(`visibility must be one of ${TOURNAMENT_VISIBILITIES.join(', ')}.`, visibility.error);
      let clubId = null;
      if (body.club_id !== undefined && body.club_id !== null && body.club_id !== '') {
        if (!isId(body.club_id)) return badRequest('club_id must be a short alphanumeric identifier.', 'invalid_club_id');
        clubId = String(body.club_id).trim();
      }
      if (visibility.visibility === 'club' && clubId === null) {
        return badRequest('Moving a tournament into the club category must name the club.', 'invalid_club_id');
      }
      return { ok: true, value: { visibility: visibility.visibility, clubId } };
    }
    case 'deleteTournament': {
      if (typeof body.confirm_name !== 'string' || body.confirm_name.trim() === '') {
        return badRequest('confirm_name is required and must match the stored tournament name.', 'delete_requires_confirmation');
      }
      return { ok: true, value: { confirmName: body.confirm_name } };
    }
    case 'startBoard':
      return SEATS.includes(body.original_seat)
        ? { ok: true, value: { originalSeat: body.original_seat } }
        : badRequest(`original_seat must be one of ${SEATS.join(', ')}.`, 'invalid_original_seat');
    case 'listAttempts': {
      if (query.board_number !== undefined && !isBoardNumber(query.board_number)) {
        return badRequest(`board_number must be 1-${MAX_BOARD_NUMBER_CHARS} characters.`, 'invalid_board_number');
      }
      return {
        ok: true,
        value: {
          boardNumber: query.board_number === undefined ? null : String(query.board_number).trim(),
          page: boundedPage(query.page),
          limit: boundedLimit(query.limit, maxRowLimit)
        }
      };
    }
    case 'recordAttempt': {
      if (!isBoardNumber(body.board_number)) {
        return badRequest(`board_number must be 1-${MAX_BOARD_NUMBER_CHARS} characters.`, 'invalid_board_number');
      }
      if (!SEATS.includes(body.original_seat)) {
        return badRequest(`original_seat must be one of ${SEATS.join(', ')}.`, 'invalid_original_seat');
      }
      if (!isHandId(body.recorded_hand_id)) {
        return badRequest('recorded_hand_id must be a short alphanumeric identifier.', 'invalid_recorded_hand_id');
      }
      return {
        ok: true,
        value: {
          boardNumber: String(body.board_number).trim(),
          originalSeat: body.original_seat,
          recordedHandId: String(body.recorded_hand_id).trim()
        }
      };
    }
    case 'readTournament':
    case 'listBoards':
    case 'publish':
    case 'unpublish':
      return { ok: true, value: {} };
    default:
      return { ok: true, value: {} };
  }
}

function boundedPage(value) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 ? n : 1;
}

function boundedLimit(value, ceiling) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) return DEFAULT_TOURNAMENT_LIST_LIMIT;
  return Math.min(n, ceiling);
}

/*
 * The store reports a failed or unverified write IN BAND (`{ error }`), because a sequential REST layer
 * has no exception channel that survives it. Forwarding that as a 200 would be the worst possible
 * outcome — the admin screen would say "Imported" over a tournament that never landed — so every error
 * object maps to a status matching what actually happened. Anything not on this list is 502 (the store
 * answered, and its answer was not one we recognise) rather than 200, because "we do not know what
 * happened" is never "it worked".
 *
 * `TOURNAMENT_GATEWAY_REASONS` in the frozen contract is the published vocabulary; every name the store
 * can produce appears here, and `verify-tournaments-gateway.mjs` asserts that.
 */
const TOURNAMENT_STORE_ERROR_STATUS = Object.freeze({
  import_incomplete: 422, import_unverified: 422, publish_refused_unverified: 422,
  invalid_board_record: 422, duplicate_board_number: 422, incomplete_hands: 422,
  duplicate_import: 409, tournament_name_mismatch: 409,
  owner_only: 403, not_tournament_owner: 403, not_a_club_member: 403, not_a_club_admin: 403,
  super_admin_required: 403, club_required: 403, club_inactive: 403, club_scope_mismatch: 403,
  tournament_not_published: 403,
  tournament_not_found: 404, board_not_found: 404, not_found: 404,
  bad_request: 400, invalid_visibility: 400, invalid_status: 400, invalid_club_id: 400,
  invalid_name: 400, invalid_board_number: 400, invalid_original_seat: 400,
  invalid_recorded_hand_id: 400, invalid_dealer: 400, invalid_vulnerability: 400,
  no_boards: 400, too_many_boards: 400, delete_requires_confirmation: 400,
  write_unverified: 502,
  // "The storage could not be read" is the only honest answer for a list read that came back as
  // something other than a row set. As a 200 with `data: []` it is indistinguishable from an empty
  // table, which is how a successfully imported tournament would appear to have vanished.
  tournament_read_unreadable: 503, tournament_store_unavailable: 503,
  // Not a fact about a player's tournaments: the deployment never named the column that holds the
  // application owner, so no honest scope could be built. 503 and never an empty list.
  tournament_identity_column_unconfigured: 503,
  unauthorized: 401
});

function respondStoreResult(res, payload) {
  if (res.headersSent) return;
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    if (payload.unavailable === true) {
      return void res.status(503).json({
        error: 'tournament_store_unavailable',
        detail: String(payload.detail ?? payload.reason ?? '')
      });
    }
    if (payload.error) {
      const status = TOURNAMENT_STORE_ERROR_STATUS[payload.error]
        ?? (/^club_account_|^club_store_/.test(String(payload.error)) ? 503 : 502);
      const body = { error: payload.error, detail: String(payload.detail ?? '') };
      /* Which boards the failed call named, as DATA. The store already computed this list and the
         responder used to drop it, leaving the caller to recover board numbers out of a sentence — and a
         32-board failure puts all thirty-two in the prose anyway, which is a retry list nobody parses.
         Additive only: the `{error, detail}` envelope a caller already depends on is unchanged, the list
         is bounded, and it is never sent when the store names nothing. */
      if (Array.isArray(payload.failedBoardNumbers) && payload.failedBoardNumbers.length > 0) {
        body.failedBoardNumbers = payload.failedBoardNumbers.slice(0, 100).map((n) => String(n));
      }
      return void res.status(status).json(body);
    }
  }
  return void res.status(200).json({ status: 'success', data: payload ?? null });
}

function respondServiceUnavailable(res, detail, error = 'tournament_store_unavailable') {
  if (res.headersSent) return;
  return void res.status(503).json({ error, detail });
}

/**
 * Builds the tournament router.
 *
 * @param {object} options
 * @param {object|null} options.store       the privileged adapter, or null (every route then 503s)
 * @param {Function} options.authenticate   resolves the caller's OWN session; `{ ok, id }` or
 *   `{ ok:false, status, code }`. Required: there is no second auth path and no bearer read here.
 * @param {object} [options.limits]         `{ maxBoards, maxRowLimit }`, both lowered-only
 * @param {object} [options.columns]        the resolved tournament column names, so the list clauses the
 *   authority builds name the deployment's real columns (`{ visibility, userId, clubId, status }`)
 */
function createTournamentRouter({ store = null, authenticate, limits = {}, columns = null } = {}) {
  if (typeof authenticate !== 'function') {
    throw new TypeError('createTournamentRouter needs the session authenticator');
  }
  const router = Router();
  const listScopeColumns = columns
    ? {
      visibility: columns.visibility ?? null,
      userId: columns.userId ?? null,
      clubId: columns.clubId ?? null,
      status: columns.status ?? null
    }
    : null;
  const bounds = {
    // A deployment may tighten the contract's ceiling; it may never raise it, because the ceiling is
    // what bounds one request's storage writes.
    maxBoards: Math.min(limits.maxBoards ?? MAX_TOURNAMENT_BOARDS, MAX_TOURNAMENT_BOARDS),
    maxRowLimit: Math.min(limits.maxRowLimit ?? MAX_TOURNAMENT_LIST_LIMIT, MAX_TOURNAMENT_LIST_LIMIT)
  };

  /**
   * Everything that must be true before an operation is dispatched: shape, identity, storage, the
   * STORE-derived row the path names, the membership bridge, the `system_admins` verdict, and the
   * authority decision. Returns the context, or null after having already answered the request.
   */
  async function resolveContext(op, req, res, { tournamentId = null, boardNumber = null } = {}) {
    const shape = validateTournamentRequestShape(op, { query: req.query, body: req.body ?? {} });
    if (shape) return void res.status(shape.status).json(shape.body);

    let session = null;
    try {
      session = await authenticate(req);
    } catch {
      session = null;
    }
    if (!session || session.ok === false) {
      // A session authority that could not be reached is NOT a signed-out user. Answering 401 here would
      // make the client throw away a valid session on a transient NCB failure, so the distinction the
      // rest of this relay already draws is kept.
      const status = session && session.status === 503 ? 503 : 401;
      const code = session?.code || 'authentication_required';
      return void res.status(status).json({
        error: code,
        detail: status === 503
          ? 'The session could not be verified; the tournament request was not decided.'
          : 'A validated session is required.'
      });
    }
    const userId = String(session.id);

    if (!store) {
      // Before any decision, and with no fallback: without storage there is no row to read the owner
      // from, so every answer except "the tournament backend is not configured" would be invented.
      return void respondServiceUnavailable(res,
        'No privileged tournament store adapter is configured; the operation was not performed and no session-scoped NCB fallback was attempted.');
    }

    // THE ROW, READ FROM STORAGE BEFORE THE DECISION. A path id names a target, never a permission, and
    // `null` (no such tournament) and `{unavailable}` (could not tell) are different answers.
    let row = null;
    if (tournamentId) {
      try {
        row = await store.tournamentScope(tournamentId);
      } catch {
        row = { unavailable: true };
      }
      if (row?.unavailable) {
        return void respondServiceUnavailable(res,
          'The tournament row could not be read, so the request was not decided; nothing was assumed about its owner.',
          'club_store_unavailable');
      }
      if (!row) {
        return void res.status(404).json({ error: 'tournament_not_found', detail: 'The tournament was not found.' });
      }
    }

    // THE MEMBERSHIP BRIDGE — the club store's own collapse, imported, not re-implemented.
    const bridge = await store.readMembership(userId);
    if (bridge.unavailable) {
      return void respondServiceUnavailable(res,
        'The club membership could not be read; no club authority was assumed in either direction.',
        'club_store_unavailable');
    }
    let membership = bridge.membership && bridge.membership.status === APPROVED_MEMBERSHIP_STATUS
      ? bridge.membership
      : null;
    if (membership) {
      // THE SAME COLLAPSE THE CLUB FEATURE APPLIES, using its own predicate: a row is a membership only
      // when it is APPROVED and its CLUB is ACTIVE. Pending, rejected, removed, unknown-status and
      // approved-but-club-inactive all become `null`, the identical value a user with no row produces, so
      // no tournament endpoint can tell those users apart and no half-rule leaks in here. A bridge that
      // THROWS is a 503, never an assumed "no club" — that would strip a member's access on a bad day at
      // the vendor. A club row that is simply absent collapses, exactly as it does in club routes.
      const active = await store.readClubStatus(membership.clubId);
      if (active.unknown) {
        return void respondServiceUnavailable(res,
          'The club record could not be read, so membership could not be confirmed; nothing was assumed in either direction.',
          'club_store_unavailable');
      }
      if (!isEffectiveMembership({ status: membership.status, clubStatus: active.status })) {
        membership = null;
      }
    }

    const grant = await store.readSuperAdmin(userId);
    if (grant.unknown) {
      return void respondServiceUnavailable(res,
        'The system_admins authority could not be read; the request was not decided.',
        'club_store_unavailable');
    }

    // The activity of the club a CREATE is aimed at. Read only for that case, because it costs an NCB
    // round trip and no other decision consults it — and it is reachable: a system admin acting for an
    // inactive club passes the admin test and is stopped here, which is the difference between acting
    // FOR a club and acting over a club that has been switched off. The two fields are read here in
    // their validated-against-the-vocabulary form only; the full body validation runs once, after the
    // decision, in `guarded`.
    const targetVisibility = (req.body ?? {}).visibility ?? null;
    const rawTargetClub = (req.body ?? {}).club_id ?? null;
    let clubActive = null;
    if (op === 'createTournament' && validateVisibilityChange(targetVisibility).valid
      && targetVisibility === 'club' && isId(rawTargetClub)) {
      const read = await store.readClubStatus(String(rawTargetClub).trim());
      if (read.unknown) {
        return void respondServiceUnavailable(res,
          'The target club record could not be read, so the import was not decided.',
          'club_store_unavailable');
      }
      clubActive = read.status === 'active';
    }

    const targetClubId = op === 'createTournament'
      ? (isId(rawTargetClub) ? String(rawTargetClub).trim() : null)
      : (op === 'setVisibility' ? (isId(rawTargetClub) ? String(rawTargetClub).trim() : (row?.clubId ?? null))
        : (row?.clubId ?? null));

    const decision = authorizeTournamentOperation({
      op,
      session: { userId },
      row,
      membership,
      targetClubId,
      targetVisibility,
      storeSuperAdmin: grant.isSuperAdmin === true,
      clubActive,
      columns: listScopeColumns
    });
    if (!decision.allow) {
      return void res.status(decision.status).json(decision.body);
    }

    const method = TOURNAMENT_STORE_METHOD_FOR[op];
    if (!method || typeof store[method] !== 'function') {
      return void respondServiceUnavailable(res, 'The configured tournament store does not implement this operation; nothing was written.');
    }

    return {
      userId, row, membership, decision, boardNumber, tournamentId,
      isSuperAdmin: grant.isSuperAdmin === true, clubActive
    };
  }

  async function guarded(op, req, res, options, dispatch) {
    try {
      const context = await resolveContext(op, req, res, options);
      if (!context) return;
      const input = validateTournamentInput(op, req.body ?? {}, { query: req.query ?? {}, ...bounds });
      if (input.ok === false) return void res.status(input.status).json(input.body);
      const payload = await dispatch(context, input.value, req);
      return void respondStoreResult(res, payload);
    } catch (error) {
      // Express 4 does not catch a rejected handler, so nothing may propagate out of a route: an
      // uncaught throw would hang the socket rather than answer it.
      return void respondServiceUnavailable(res, `The tournament operation failed before it could be answered (${error?.name || 'Error'}).`);
    }
  }

  function tournamentIdParam(req, res) {
    if (!isId(req.params.tournamentId)) {
      res.status(400).json({ error: 'bad_request', detail: 'tournamentId is invalid.' });
      return null;
    }
    return idToString(req.params.tournamentId);
  }

  // ── the collection routes ─────────────────────────────────────────────────
  router.get('/tournaments', (req, res) => guarded('listTournaments', req, res, {},
    (context, value) => store.listTournaments({ clauses: context.decision.scope.clauses, limit: bounds.maxRowLimit })
      .then((read) => {
        if (read.error) return read;
        // The query filter can only narrow the server-derived scope, never widen it: every row here
        // already satisfied one of the caller's clauses, and these three predicates remove more.
        const filtered = read.tournaments.filter((row) => (value.visibility === null || row.visibility === value.visibility)
          && (value.status === null || row.status === value.status)
          && (value.clubId === null || row.clubId === value.clubId));
        const start = (value.page - 1) * value.limit;
        return {
          tournaments: filtered.slice(start, start + value.limit),
          total: filtered.length,
          page: value.page,
          limit: value.limit,
          // What the server actually scoped by, echoed for debuggability. Names and ids of the CALLER's
          // own scope, so it discloses nothing they did not already have.
          scope: {
            private_owner: context.decision.scope.userId,
            member_club: context.decision.scope.memberClub || null,
            admin_club: context.decision.scope.adminClub || null,
            public_all: context.decision.scope.isSuperAdmin === true
          }
        };
      })));

  router.post('/tournaments', (req, res) => guarded('createTournament', req, res, {},
    (context, value) => store.importTournament({
      // The OWNER is the session this relay proved. There is no path by which a body field arrives here,
      // because `user_id` is not in the allow-list for this operation and storage is never consulted for
      // it on a create.
      ownerId: context.userId,
      clubId: context.decision.scope.clubId,
      visibility: context.decision.scope.visibility,
      name: value.name,
      sourceLabel: value.sourceLabel,
      dedupeKey: value.dedupeKey,
      boards: value.boards
    })));

  // ── the parameterised routes ─────────────────────────────────────────────
  router.get('/tournaments/:tournamentId', (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    return guarded('readTournament', req, res, { tournamentId },
      (context) => storeShapeForResponse(context.row));
  });

  router.get('/tournaments/:tournamentId/boards', (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    return guarded('listBoards', req, res, { tournamentId },
      (context) => store.listBoards({ tournamentId: context.tournamentId }).then((read) => {
        if (read.error) return read;
        // COMPLETE OR REFUSE. A short board list served as a success is how a half-imported set becomes
        // a tournament a club believes it holds.
        if (context.row.boardCount > 0 && read.boards.length !== context.row.boardCount) {
          return {
            error: 'import_unverified',
            detail: `the header says ${context.row.boardCount} board(s) and ${read.boards.length} read back`
          };
        }
        return { boards: read.boards, tournament_id: context.tournamentId, board_count: read.boards.length };
      }));
  });

  router.patch('/tournaments/:tournamentId', (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    return guarded('updateTournament', req, res, { tournamentId },
      (context, value) => store.renameTournament({
        tournamentId: context.tournamentId,
        name: value.name,
        sourceLabel: value.sourceLabel
      }));
  });

  router.post('/tournaments/:tournamentId/visibility', (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    return guarded('setVisibility', req, res, { tournamentId },
      (context, value) => {
        if (context.decision.noop) {
          // Same category, same club: a no-op the caller may always perform on a row they manage, so a
          // screen can post the value it is already showing without pretending a change happened.
          return storeShapeForResponse(context.row);
        }
        return store.setVisibility({
          tournamentId: context.tournamentId,
          visibility: context.decision.scope.visibility,
          clubId: context.decision.scope.clubId
        });
      });
  });

  const statusRoute = (status) => (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    return guarded(status === 'published' ? 'publish' : 'unpublish', req, res, { tournamentId },
      (context) => store.setStatus({ tournamentId: context.tournamentId, status }));
  };
  router.post('/tournaments/:tournamentId/publish', statusRoute('published'));
  router.post('/tournaments/:tournamentId/unpublish', statusRoute('draft'));

  router.delete('/tournaments/:tournamentId', (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    return guarded('deleteTournament', req, res, { tournamentId },
      (context, value) => {
        // The confirmation is checked against the STORED name, which only this route has read. A name in
        // a body would be the client telling the server what it thinks the row says; matching the two is
        // the point of the exercise, so the comparison happens here, after the row is in hand.
        const expected = String(context.row.name ?? '').trim().replace(/\s+/g, ' ');
        const given = String(value.confirmName ?? '').trim().replace(/\s+/g, ' ');
        if (given === '' || given !== expected) {
          return {
            error: 'tournament_name_mismatch',
            detail: 'Type the tournament name exactly as stored to delete it and every board and attempt row under it.'
          };
        }
        return store.deleteTournament({ tournamentId: context.tournamentId });
      });
  });

  /*
   * Board-start returns THE STORED BOARD — dealer, vulnerability, hands and board number — so the game
   * engine plays the server's record rather than a deal the client supplied. The request carries one
   * field (`original_seat`, which seat the caller took at import) and it is echoed back unaltered; no
   * part of the deal can arrive from the caller. The row is re-validated on the way out from storage, so
   * a board that was sound at import and corrupted since never reaches a table.
   */
  router.post('/tournaments/:tournamentId/boards/:boardNumber/start', (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    const boardNumber = String(req.params.boardNumber ?? '').trim();
    if (!isBoardNumber(boardNumber)) {
      return void res.status(400).json({ error: 'invalid_board_number', detail: `boardNumber must be 1-${MAX_BOARD_NUMBER_CHARS} characters.` });
    }
    return guarded('startBoard', req, res, { tournamentId, boardNumber },
      async (context, value) => {
        const board = await store.getBoard({ tournamentId: context.tournamentId, boardNumber });
        if (board?.unavailable) {
          return { unavailable: true, detail: 'the board could not be read, or its rows disagree; no board was started' };
        }
        if (!board) return { error: 'board_not_found', detail: `board ${boardNumber} is not in this tournament` };
        const checked = validateBoardSubmission([board], { maxBoards: bounds.maxBoards });
        if (!checked.ok) return { error: checked.reason, detail: checked.detail };
        return {
          tournament_id: context.tournamentId,
          board_number: board.board_number,
          dealer: board.dealer,
          vulnerability: board.vulnerability,
          hands: board.hands,
          tags: board.tags ?? null,
          original_seat: value.originalSeat,
          visibility: context.row.visibility,
          club_id: context.row.clubId === '' ? null : context.row.clubId
        };
      });
  });

  router.get('/tournaments/:tournamentId/attempts', (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    return guarded('listAttempts', req, res, { tournamentId },
      (context, value) => store.listAttempts({
        tournamentId: context.tournamentId,
        // SELF-SCOPED. The only user id this read can take is the one the session proved, so there is no
        // parameter an attacker could set to read somebody else's history.
        userId: context.userId,
        boardNumber: value.boardNumber,
        page: value.page,
        limit: value.limit
      }));
  });

  router.post('/tournaments/:tournamentId/attempts', (req, res) => {
    const tournamentId = tournamentIdParam(req, res);
    if (tournamentId === null) return undefined;
    return guarded('recordAttempt', req, res, { tournamentId },
      async (context, value) => {
        const board = await store.getBoard({ tournamentId: context.tournamentId, boardNumber: value.boardNumber });
        if (board?.unavailable) {
          return { unavailable: true, detail: 'the board could not be read; no attempt was recorded' };
        }
        if (!board) return { error: 'board_not_found', detail: `board ${value.boardNumber} is not in this tournament` };
        return store.recordAttempt({
          tournamentId: context.tournamentId,
          boardNumber: value.boardNumber,
          recordedHandId: value.recordedHandId,
          originalSeat: value.originalSeat,
          userId: context.userId
        });
      });
  });

  return router;
}

/** The header row as the API answers it: domain names, no storage column names, no secrets. */
function storeShapeForResponse(row) {
  if (!row || typeof row !== 'object') return null;
  return {
    id: row.id,
    user_id: row.ownerId,
    club_id: row.clubId === '' ? null : row.clubId,
    name: row.name,
    visibility: row.visibility,
    status: row.status,
    board_count: Number(row.boardCount) || 0,
    source_label: row.sourceLabel ?? null,
    dedupe_key: row.dedupeKey ?? null
  };
}

module.exports = {
  ID,
  HAND_ID,
  TOURNAMENT_VISIBILITIES,
  TOURNAMENT_STATUSES,
  MAX_TOURNAMENT_NAME_LENGTH,
  MAX_TOURNAMENT_BOARDS,
  DEFAULT_TOURNAMENT_LIST_LIMIT,
  MAX_TOURNAMENT_LIST_LIMIT,
  TOURNAMENT_BODY_FIELDS,
  TOURNAMENT_ROUTES,
  TOURNAMENT_STORE_METHOD_FOR,
  TOURNAMENT_STORE_ERROR_STATUS,
  TOURNAMENT_REFUSAL_COPY,
  isId,
  isHandId,
  hasControlChars,
  idToString,
  validateTournamentRequestShape,
  validateTournamentInput,
  validateVisibilityChange,
  validateTournamentName,
  validateTournamentSourceLabel,
  normalizeBoardInput,
  resolveTournamentAccess,
  tournamentListScope,
  authorizeTournamentCreate,
  authorizeVisibilityTarget,
  manageRefusalReason,
  authorizeTournamentOperation,
  createTournamentRouter,
  storeShapeForResponse
};

