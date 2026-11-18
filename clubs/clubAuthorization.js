'use strict';

/*
 * CLUB AUTHORIZATION — NodeSend's server-side authority for the club feature.
 *
 * THE FOUR RULES, and where each is enforced:
 *   R1 Super Admin creates clubs and assigns Club Admins.
 *   R2 A user selects one club, or none — a selection is a REQUEST until it is approved.
 *   R3 A Club Admin imports and publishes collections of THEIR OWN club.
 *   R4 A Club Member reaches published boards of their CURRENT club only.
 *
 * WHO COUNTS AS A CLUB MEMBER. Only `club_memberships.status = 'approved'` for an ACTIVE club. A
 * user with no club selected, a pending request, a rejected request, a removed membership or an
 * inactive club are ONE case to this file, not five: the raw row is collapsed to `null` at a single
 * point in `resolveContext` before any rule sees it, which is the same value "no club at all"
 * produces. No endpoint can therefore tell those five users apart, and no club state can leak a
 * restriction into ordinary play — nothing outside these routes reads a membership, so a pending or
 * rejected user keeps every other BridgeMind capability unchanged. Approval affects club features
 * and is not able to affect anything else.
 *
 * Identity comes from the caller's own validated NCB session — the same `resolveSessionUser`
 * every AI and quota route in this relay uses. The caller's club, the caller's club role and
 * whether the caller is a super admin are read FROM STORAGE for that session id. A body or query
 * field never supplies any of them: `validateRequestShape` refuses unexpected fields outright, so
 * `user_id` on a self-scoped route and `role` anywhere are rejected by construction rather than by
 * a denylist that has to be remembered whenever a field is added. `assignClubAdmin` does accept
 * `user_id`, because there it names the TARGET of a super-admin action, which is a different thing
 * from a caller describing themselves.
 *
 * WHY THE STORE IS NOT THE CALLER'S BEARER. NCB runtime access is `shared_readwrite`, so an
 * authority read done with the caller's own session is a read of rows the caller can rewrite.
 * That is not authorization, it is a formality. So every persistence call here goes through the
 * dedicated club account (ncbAccountClient.js) and there is no caller-bearer fallback anywhere in
 * this file — no `create/<table>` path, no "if the store is missing, try the session token".
 *
 * MISSING STORE IS A 503, BEFORE ANY DECISION. Without storage there is no membership to read, so
 * `GET /me/club` would have to answer "you have no club" — a false statement about a real person
 * dressed as a successful empty read. Every club route therefore answers a controlled 503 once the
 * request is authenticated and validated, and nothing degrades into an empty success.
 *
 * SUPER ADMIN COMES FROM `system_admins` AND NOTHING ELSE. The session's NCB role is not a club
 * privilege: a role string is application data, and letting it grant club-wide power would mean a
 * row edit promotes a member. The store requires that table, so a missing verdict is impossible in
 * a working deployment, and `storeSuperAdmin !== true` denies. This is deliberately stricter than
 * the local gateway's role fallback.
 *
 * ROUTES ARE UNPREFIXED. NodeSend serves `/clubs/...` and `/me/club/...` — the same grammar as
 * `/ai/...` and `/trickster/...`. BridgeMind's browser transport strips the `/api` prefix it uses
 * against its local Express server before dialing this host, so the two agree without either one
 * knowing the other's file layout.
 */

const { Router } = require('express');
const {
  validateBoardSubmission, validateBoardRecord, isBoardNumber,
  MAX_BOARDS_PER_COLLECTION, MAX_BOARD_NUMBER_CHARS, SEATS
} = require('./clubBoardValidator.js');
const { MEMBERSHIP_STATUSES, APPROVED_MEMBERSHIP_STATUS, isEffectiveMembership } = require('./clubSchema.js');

const ID = /^[A-Za-z0-9_-]{1,32}$/;
const MEMBERSHIP_ROLES = new Set(['member', 'club_admin']);
const CLUB_STATUSES = new Set(['active', 'inactive']);
// The subset of the lifecycle an approver may set. `pending` is created only by the user's own
// request, never imposed on someone else.
const MEMBERSHIP_TRANSITIONS = new Set(MEMBERSHIP_STATUSES.filter((status) => status !== 'pending'));

const isId = (value) => ID.test(String(value ?? '').trim());

// Positive field lists, per operation. A denylist fails the moment a field is added and only needs
// one name nobody thought of; a positive list refuses the new name on sight.
const BODY_FIELDS = Object.freeze({
  listClubs: { query: ['search', 'page', 'limit'], body: [] },
  listClubMembers: { query: [], body: [] },
  setMembershipStatus: { query: [], body: ['status'] },
  createClub: { query: [], body: ['name'] },
  updateClub: { query: [], body: ['name'] },
  setClubStatus: { query: [], body: ['status'] },
  assignClubAdmin: { query: [], body: ['user_id', 'role'] },
  removeClubAdmin: { query: [], body: [] },
  clubOptions: { query: [], body: [] },
  myClub: { query: [], body: [] },
  setMyClub: { query: [], body: ['club_id'] },
  clearMyClub: { query: [], body: [] },
  listCollections: { query: [], body: [] },
  importCollection: { query: [], body: ['name', 'boards'] },
  renameCollection: { query: [], body: ['name'] },
  setCollectionStatus: { query: [], body: [] },
  deleteCollection: { query: [], body: [] },
  listPublishedCollections: { query: [], body: [] },
  listCollectionBoards: { query: [], body: [] },
  startClubBoard: { query: [], body: ['original_seat'] }
});

// The mounted surface, as data. Exported so a gate can assert that every operation the client
// prepares is actually served here and that nothing extra is — a route that exists only in a
// comment protects nobody, and a route nobody declared is surface nobody reviewed.
const CLUB_ROUTES = Object.freeze([
  { op: 'listClubs', method: 'GET', path: '/clubs' },
  { op: 'createClub', method: 'POST', path: '/clubs' },
  { op: 'clubOptions', method: 'GET', path: '/clubs/options' },
  { op: 'updateClub', method: 'PATCH', path: '/clubs/:clubId' },
  { op: 'setClubStatus', method: 'POST', path: '/clubs/:clubId/status' },
  { op: 'listClubMembers', method: 'GET', path: '/clubs/:clubId/members' },
  { op: 'setMembershipStatus', method: 'POST', path: '/clubs/:clubId/members/:userId/status' },
  { op: 'assignClubAdmin', method: 'POST', path: '/clubs/:clubId/admins' },
  { op: 'removeClubAdmin', method: 'DELETE', path: '/clubs/:clubId/admins/:userId' },
  { op: 'listCollections', method: 'GET', path: '/clubs/:clubId/board-collections' },
  { op: 'importCollection', method: 'POST', path: '/clubs/:clubId/board-collections' },
  { op: 'renameCollection', method: 'PATCH', path: '/clubs/collections/:collectionId' },
  { op: 'setCollectionStatus', method: 'POST', path: '/clubs/collections/:collectionId/publish' },
  { op: 'setCollectionStatus', method: 'POST', path: '/clubs/collections/:collectionId/unpublish' },
  { op: 'deleteCollection', method: 'DELETE', path: '/clubs/collections/:collectionId' },
  { op: 'myClub', method: 'GET', path: '/me/club' },
  { op: 'setMyClub', method: 'POST', path: '/me/club' },
  { op: 'clearMyClub', method: 'DELETE', path: '/me/club' },
  { op: 'listPublishedCollections', method: 'GET', path: '/me/club/board-collections' },
  { op: 'listCollectionBoards', method: 'GET', path: '/clubs/collections/:collectionId/boards' },
  { op: 'startClubBoard', method: 'POST', path: '/clubs/collections/:collectionId/boards/:boardNumber/start' }
]);

// Which store method each operation needs, so an incomplete adapter fails closed with 503 on the
// specific missing method instead of throwing mid-request.
const STORE_METHOD_FOR = Object.freeze({
  listClubs: 'listClubs', createClub: 'createClub', updateClub: 'updateClub', setClubStatus: 'setClubStatus',
  listClubMembers: 'listMembers', setMembershipStatus: 'setMembershipStatus',
  assignClubAdmin: 'assignClubAdmin', removeClubAdmin: 'removeClubAdmin',
  clubOptions: 'listActiveClubs', myClub: 'getMembership', setMyClub: 'setClubMembership', clearMyClub: 'setClubMembership',
  listCollections: 'listCollections', importCollection: 'createCollection', renameCollection: 'renameCollection',
  setCollectionStatus: 'setCollectionStatus', deleteCollection: 'deleteCollection',
  listPublishedCollections: 'listPublishedCollections', listCollectionBoards: 'listBoards', startClubBoard: 'getBoard'
});

// The operations whose rule consults the club's activity. Reading a status costs an NCB round
// trip, so it is read for exactly these and never for the others.
const CLUB_ACTIVE_OPS = new Set(['importCollection', 'listPublishedCollections', 'listCollectionBoards', 'startClubBoard']);

function refuseIdentityFieldsIn(path) {
  return {
    status: 400,
    body: {
      error: 'client_identity_refused',
      detail: `Identity and club scope are derived from the session by this route; unexpected or identity-bearing fields in the request (${path}) are refused rather than ignored.`
    }
  };
}

/** Rejects unknown or misplaced fields. Returns an error object or null. */
function validateRequestShape(op, { query = {}, body = {} } = {}) {
  const spec = BODY_FIELDS[op];
  if (!spec) return { status: 400, body: { error: 'unknown_operation', detail: 'This route does not name a club operation.' } };
  const extraBody = Object.keys(body ?? {}).filter((key) => !spec.body.includes(key));
  const extraQuery = Object.keys(query ?? {}).filter((key) => !spec.query.includes(key));
  if (extraBody.length || extraQuery.length) {
    return refuseIdentityFieldsIn([...extraBody.map((k) => `body.${k}`), ...extraQuery.map((k) => `query.${k}`)].join(', '));
  }
  return null;
}

// Validation results are `{ ok, value }` or `{ ok: false, status, body }`, so a caller that forgets
// to branch cannot fall through into `input.value` on a rejected request.
function badRequest(detail) {
  return { ok: false, status: 400, body: { error: 'bad_request', detail } };
}

/**
 * THE AUTHORITY DECISION — pure, no I/O. The router calls it after resolving the session and the
 * membership; a test calls it directly with a fake identity and no database.
 *
 * `targetClubStatus` is REQUIRED to be read as 'active' by every rule that consults it, so the
 * router reads the status of the club that decision is about (`targetClubId`, else the
 * collection's owner, else the caller's own club). Treating "unknown" as active would let a
 * deleted or switched-off club keep serving its members, which is the opposite of what an
 * owner-side revocation is for.
 *
 * @param {object} input
 * @param {string} input.op
 * @param {object|null} input.session        { id, role } from the VALIDATED SESSION only
 * @param {object|null} input.membership     { clubId, role } read from the store for that session
 * @param {string|null} [input.targetClubId] club the route addresses (path-derived)
 * @param {string|null} [input.ownerClubId]  club that owns the collection (STORE-derived)
 * @param {string} [input.collectionStatus]
 * @param {string|null} [input.targetClubStatus] the status of whichever club this decision is about
 * @param {boolean|null} [input.storeSuperAdmin] the `system_admins` verdict; only `true` grants
 */
function authorizeClubOperation({
  op,
  session = null,
  membership = null,
  targetClubId = null,
  ownerClubId = null,
  collectionStatus = null,
  targetClubStatus = null,
  storeSuperAdmin = null
} = {}) {
  if (!session || session.id === undefined || session.id === null || String(session.id).trim() === '') {
    return { status: 401, body: { error: 'authentication_required', detail: 'A validated session is required.' } };
  }

  const isSuper = storeSuperAdmin === true;
  const userId = String(session.id);
  const membershipClub = membership?.clubId ? String(membership.clubId) : '';
  // A super admin also satisfies the club-admin tests, which is what lets R1 hold without
  // duplicating every branch below. It does NOT satisfy the member-only reads, which need a real
  // club: an administrator with no club has no club's boards to browse.
  const isClubAdminOf = (clubId) => isSuper
    || (membershipClub !== '' && clubId !== '' && membershipClub === String(clubId) && membership?.role === 'club_admin');
  const isMemberOf = (clubId) => membershipClub !== '' && membershipClub === String(clubId);
  const clubActive = (clubId) => targetClubStatus === 'active' && String(clubId) !== '';

  switch (op) {
    // ── R1: only a Super Admin manages clubs and Club Admins ──────────────
    case 'listClubs':
    case 'createClub':
    case 'updateClub':
    case 'setClubStatus':
    case 'assignClubAdmin':
    case 'removeClubAdmin':
      return isSuper
        ? { allow: true, scope: { isSuper: true } }
        : { status: 403, body: { error: 'super_admin_required', detail: 'This action needs an entry in the club system_admins table.' } };

    case 'listClubMembers':
      if (isSuper) return { allow: true, scope: { clubId: String(targetClubId ?? '') } };
      if (!targetClubId) return badRequest('A club id is required.');
      return isClubAdminOf(targetClubId)
        ? { allow: true, scope: { clubId: String(targetClubId) } }
        : { status: 403, body: { error: 'not_a_club_admin', detail: 'Only an admin of that club may read its members.' } };

    // Approving, rejecting or removing a membership. Note WHO can reach this: an approver must
    // already be an APPROVED admin of the same club (or a super admin), because `membership` here is
    // the effective one. A pending admin-elect therefore cannot approve anyone, including themselves.
    case 'setMembershipStatus':
      if (!targetClubId) return badRequest('A club id is required.');
      return isClubAdminOf(targetClubId)
        ? { allow: true, scope: { clubId: String(targetClubId) } }
        : { status: 403, body: { error: 'not_a_club_admin', detail: 'Only an admin of that club may act on its membership requests.' } };

    // ── R2: a user chooses one club, or none ─────────────────────────────
    case 'clubOptions':
    case 'myClub':
      return { allow: true, scope: { userId, membershipClub: membershipClub || null } };
    case 'setMyClub':
    case 'clearMyClub':
      return { allow: true, scope: { userId } };

    // ── R3: a Club Admin manages ONLY their own club's collections ───────
    case 'listCollections':
      if (!targetClubId) return badRequest('A club id is required.');
      return isClubAdminOf(targetClubId)
        ? { allow: true, scope: { clubId: String(targetClubId) } }
        : { status: 403, body: { error: 'not_a_club_admin', detail: 'Collections are visible to an admin of that club.' } };

    case 'importCollection':
      if (!targetClubId) return badRequest('A club id is required.');
      if (!isClubAdminOf(targetClubId)) {
        return { status: 403, body: { error: 'not_a_club_admin', detail: 'Only an admin of that club may import a collection.' } };
      }
      if (!clubActive(targetClubId)) {
        return { status: 403, body: { error: 'club_inactive', detail: 'An inactive club cannot import boards.' } };
      }
      return { allow: true, scope: { clubId: String(targetClubId) } };

    case 'renameCollection':
    case 'setCollectionStatus':
    case 'deleteCollection':
      // The owning club comes from the STORE. If the caller addressed a collection belonging to
      // another club, the owner — not the request — decides.
      if (!ownerClubId) return { status: 404, body: { error: 'collection_not_found', detail: 'The collection was not found or has no owning club.' } };
      return isClubAdminOf(ownerClubId)
        ? { allow: true, scope: { clubId: String(ownerClubId) } }
        : { status: 403, body: { error: 'not_a_club_admin', detail: 'Only an admin of the owning club may change this collection.' } };

    // ── R4: a member reaches only published boards of their own club ─────
    case 'listPublishedCollections':
      if (!membershipClub) return { status: 403, body: { error: 'not_a_club_member', detail: 'No club is attached to this session.' } };
      if (!clubActive(membershipClub)) return { status: 403, body: { error: 'club_inactive', detail: 'Your club is not active.' } };
      return { allow: true, scope: { clubId: membershipClub, publishedOnly: true } };

    case 'listCollectionBoards': {
      if (!ownerClubId) return { status: 404, body: { error: 'collection_not_found', detail: 'The collection was not found or has no owning club.' } };
      // An admin of the OWNING club may preview a draft. A plain member reaches only a PUBLISHED
      // collection of the club they actually belong to. Each denial names its own reason, so
      // "another club" is never reported to a player as "not published".
      if (isClubAdminOf(ownerClubId)) return { allow: true, scope: { clubId: String(ownerClubId) } };
      if (!membershipClub) return { status: 403, body: { error: 'not_a_club_member', detail: 'No club is attached to this session.' } };
      if (!isMemberOf(ownerClubId)) return { status: 403, body: { error: 'other_club_board', detail: 'These boards belong to a different club.' } };
      if (!clubActive(ownerClubId)) return { status: 403, body: { error: 'club_inactive', detail: 'Your club is not active.' } };
      if (collectionStatus !== 'published') return { status: 403, body: { error: 'collection_not_published', detail: 'This collection is not published yet.' } };
      return { allow: true, scope: { clubId: String(ownerClubId) } };
    }

    // Starting a board is how a deal reaches the engine, so this is the strictest read in the file
    // and it deliberately does NOT share the list route's draft-preview exemption: reviewing an
    // unreleased deal is an admin action, putting it into play is not. Membership in the owning club
    // is required on its own terms — a super admin, or an admin of some other club, holds no club's
    // board to play — and the club must be active and the collection published.
    case 'startClubBoard': {
      if (!ownerClubId) return { status: 404, body: { error: 'collection_not_found', detail: 'The collection was not found or has no owning club.' } };
      if (!membershipClub) return { status: 403, body: { error: 'not_a_club_member', detail: 'No club is attached to this session.' } };
      if (!isMemberOf(ownerClubId)) return { status: 403, body: { error: 'other_club_board', detail: 'These boards belong to a different club.' } };
      if (!clubActive(ownerClubId)) return { status: 403, body: { error: 'club_inactive', detail: 'Your club is not active.' } };
      if (collectionStatus !== 'published') return { status: 403, body: { error: 'collection_not_published', detail: 'This collection is not published yet.' } };
      return { allow: true, scope: { clubId: String(ownerClubId) } };
    }

    default:
      return { status: 400, body: { error: 'unknown_operation', detail: 'This route does not name a club operation.' } };
  }
}

// Control characters are tested by code point rather than by an escaped character-class literal,
// which is unreadable in a diff and easy to type in a way that silently never matches.
function hasControlChars(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * Field-level validation of the values an ALLOWED body may carry. Shape (which fields exist) is
 * already settled by validateRequestShape; this settles whether their values make sense.
 */
function validateClubInput(op, body = {}, { maxBoards = MAX_BOARDS_PER_COLLECTION } = {}) {
  switch (op) {
    case 'createClub':
    case 'updateClub':
    case 'renameCollection': {
      const name = String(body.name ?? '').trim().replace(/\s+/g, ' ');
      if (!name || name.length > 200) return badRequest('A name of 1-200 characters is required.');
      if (hasControlChars(name)) return badRequest('The name contains invalid characters.');
      return { ok: true, value: { name } };
    }
    case 'setClubStatus':
      return CLUB_STATUSES.has(body.status)
        ? { ok: true, value: { status: body.status } }
        : badRequest(`status must be one of ${[...CLUB_STATUSES].join(', ')}.`);
    // The transitions an approver may perform. `pending` is deliberately absent: nobody is placed
    // into a waiting state by an administrator, and an admin who wants to un-approve someone says so
    // with `rejected` or `removed`. Accepting `pending` here would let an approved member be demoted
    // into a state that reads as "still waiting", which is a different claim about the past.
    case 'setMembershipStatus':
      return MEMBERSHIP_TRANSITIONS.has(body.status)
        ? { ok: true, value: { status: body.status } }
        : badRequest(`status must be one of ${[...MEMBERSHIP_TRANSITIONS].join(', ')}.`);
    case 'assignClubAdmin': {
      const userId = String(body.user_id ?? '').trim();
      if (!isId(userId)) return badRequest('user_id must be a short alphanumeric identifier.');
      const role = body.role === undefined ? 'club_admin' : String(body.role);
      return MEMBERSHIP_ROLES.has(role)
        ? { ok: true, value: { userId, role } }
        : badRequest(`role must be one of ${[...MEMBERSHIP_ROLES].join(', ')}.`);
    }
    case 'setMyClub': {
      const clubId = String(body.club_id ?? '').trim();
      return isId(clubId) ? { ok: true, value: { clubId } } : badRequest('club_id must be a short alphanumeric identifier.');
    }
    // NodeSend's OWN board validation. The browser parsed and checked this file, and its answer is
    // what made the admin's preview look right — none of that is evidence to a server. A board with
    // 14 cards in one seat, a repeated card, a raw "All" vulnerability or a number the routes
    // cannot address is refused here, before any row exists.
    case 'importCollection': {
      const name = String(body.name ?? '').trim().replace(/\s+/g, ' ');
      if (!name || name.length > 200) return badRequest('A collection name of 1-200 characters is required.');
      if (hasControlChars(name)) return badRequest('The collection name contains invalid characters.');
      const checked = validateBoardSubmission(body.boards, { maxBoards });
      if (!checked.ok) {
        return {
          ok: false,
          status: 400,
          body: { error: checked.reason, detail: checked.detail, rejected: checked.rejected.slice(0, 10) }
        };
      }
      return { ok: true, value: { name, boards: checked.boards } };
    }
    case 'startClubBoard':
      return SEATS.includes(body.original_seat)
        ? { ok: true, value: { originalSeat: body.original_seat } }
        : badRequest(`original_seat must be one of ${SEATS.join(', ')}.`);
    default:
      return { ok: true, value: {} };
  }
}

/*
 * The store reports a failed or unverified write IN BAND (`{ error }`), because a sequential REST
 * layer has no exception channel that survives it. Forwarding that as a 200 would be the worst
 * possible outcome — the admin screen would say "Saved" over a row that was never written — so
 * every error object is mapped to a status that matches what actually happened. Anything not on
 * this list is a 502 (the store answered, and its answer was not one we recognise) rather than a
 * 200, because "we do not know what happened" is never "it worked".
 */
const STORE_ERROR_STATUS = {
  already_in_club: 409,
  import_incomplete: 422, import_unverified: 422, publish_refused_unverified: 422,
  invalid_board_record: 422,
  club_scope_mismatch: 403, not_a_club_admin: 403, super_admin_required: 403,
  collection_not_found: 404, board_not_found: 404, not_found: 404, bad_request: 400, write_unverified: 502,
  // A club list read that came back as something other than a row set. 503, because "the storage
  // could not be read" is the only honest answer: as a 200 with `data: []` it is indistinguishable
  // from an empty table, which is how a successfully created club vanished from the admin screen.
  club_read_unreadable: 503
};

function respondStoreResult(res, payload) {
  if (res.headersSent) return;
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    if (payload.unavailable === true) {
      return void res.status(503).json({ error: 'club_store_unavailable', detail: String(payload.detail ?? payload.reason ?? '') });
    }
    if (payload.error) {
      const status = STORE_ERROR_STATUS[payload.error]
        ?? (/^club_account_/.test(String(payload.error)) ? 503 : 502);
      return void res.status(status).json({ error: payload.error, detail: String(payload.detail ?? '') });
    }
  }
  return void res.status(200).json({ status: 'success', data: payload ?? null });
}

function respondServiceUnavailable(res, detail) {
  if (res.headersSent) return;
  return void res.status(503).json({ error: 'club_store_unavailable', detail });
}

/**
 * Builds the club router.
 *
 * @param {object} options
 * @param {object|null} options.store     the privileged adapter, or null (every route then 503s)
 * @param {Function} options.authenticate resolves the caller's OWN session; must return
 *   `{ ok, id, role }` or `{ ok: false, status, code }`. Required: there is no second auth path.
 * @param {object} [options.limits]
 */
function createClubRouter({ store = null, authenticate, limits = {} } = {}) {
  if (typeof authenticate !== 'function') {
    throw new TypeError('createClubRouter needs the session authenticator');
  }
  const router = Router();
  // `maxBoards` bounds one import; `maxRowLimit` bounds one list. The client clamps its own page
  // size to 100 and the server must not trust that clamp — an unbounded `limit` is how a list
  // endpoint turns into a memory incident on a shared relay.
  const boardLimits = {
    maxBoards: limits.maxBoards ?? MAX_BOARDS_PER_COLLECTION,
    maxRowLimit: Math.min(limits.maxRowLimit ?? 100, 100)
  };

  /**
   * Everything that must be true before an operation is dispatched: shape, identity, storage,
   * the store-derived scope facts, and the authority decision. Returns the context, or null after
   * having already answered the request.
   */
  async function resolveContext(op, req, res, { targetClubId = null, collectionId = null, boardNumber = null } = {}) {
    const shape = validateRequestShape(op, { query: req.query, body: req.body ?? {} });
    if (shape) {
      return void res.status(shape.status).json(shape.body);
    }

    let session = null;
    try {
      session = await authenticate(req);
    } catch {
      session = null;
    }
    if (!session || session.ok === false) {
      // A session authority that could not be reached is NOT a signed-out user. NodeSend's own
      // resolver makes that distinction for /ai/* and the club routes keep it: answering 401 here
      // would make the client throw away a valid session on a transient NCB failure.
      const status = session && session.status === 503 ? 503 : 401;
      const code = session?.code || 'authentication_required';
      return void res.status(status).json({
        error: code,
        detail: status === 503
          ? 'The session could not be verified; the club request was not decided.'
          : 'A validated session is required.'
      });
    }
    const userId = String(session.id);

    if (!store) {
      // Before any decision, and with no fallback: without storage there is no membership to read,
      // so every answer except "the club backend is not configured" would be invented.
      return void respondServiceUnavailable(res,
        'No privileged club store adapter is configured; the operation was not performed and no session-scoped NCB fallback was attempted.');
    }

    let membership = null;
    try {
      membership = await store.getMembership(userId);
    } catch {
      membership = { unavailable: true };
    }
    if (membership?.unavailable) {
      // "No club" and "you are not an admin" would both be false statements about this caller, so
      // the honest answer is a service failure.
      return void respondServiceUnavailable(res,
        'The club membership could not be read; no authority was assumed in either direction.');
    }

    // ── THE MEMBERSHIP GATE, applied ONCE, here ────────────────────────────
    // A row is a membership only when its status is 'approved' AND its club is 'active'. Pending,
    // rejected, removed, unknown-status, and approved-but-club-inactive all collapse to `null`, which
    // is the identical value a user with no row at all produces. That is deliberate and it is the
    // whole enforcement of the owner's rule: because every rule below reads `membership`, and there
    // is no other place a club is derived, those five users CANNOT be distinguished from a no-club
    // user by any endpoint — including Profile, which is the one place a half-collapse would leak.
    // They keep every ordinary BridgeMind capability, because nothing outside these routes reads a
    // membership at all. Approval affects club features and cannot affect anything else.
    const membershipRequest = membership ?? null;
    let effectiveMembership = membership && membership.status === APPROVED_MEMBERSHIP_STATUS
      ? membership
      : null;
    if (effectiveMembership) {
      // The activity read is part of the gate, not a later courtesy. If it cannot be made, the
      // membership cannot be confirmed, so the caller is treated as no-club rather than assumed in.
      let memberClubStatus = null;
      try {
        memberClubStatus = await store.clubStatus(effectiveMembership.clubId);
      } catch {
        return void respondServiceUnavailable(res,
          'The club record could not be read, so membership could not be confirmed; nothing was assumed in either direction.');
      }
      if (!isEffectiveMembership({ status: effectiveMembership.status, clubStatus: memberClubStatus })) {
        effectiveMembership = null;
      }
    }

    let superAdmin = false;
    try {
      const grant = await store.isSystemAdmin(userId);
      if (grant?.declared && grant.available !== true) {
        return void respondServiceUnavailable(res,
          'The system_admins authority could not be read; the request was not decided.');
      }
      superAdmin = grant?.isAdmin === true;
    } catch {
      return void respondServiceUnavailable(res,
        'The system_admins authority could not be read; the request was not decided.');
    }

    let ownerClubId = null;
    let collectionStatus = null;
    if (collectionId) {
      let scope = null;
      try {
        scope = await store.collectionScope(collectionId);
      } catch {
        return void respondServiceUnavailable(res, 'The collection could not be read; the request was not decided.');
      }
      if (!scope) {
        return void res.status(404).json({ error: 'collection_not_found', detail: 'The collection was not found.' });
      }
      ownerClubId = scope.clubId ?? null;
      collectionStatus = scope.status ?? null;
    }

    // The status read follows the club THIS decision is about, which is not always the club named
    // in the path: a member browsing their own published collections has no path club id at all.
    // Only the four rules that consult activity read it — a super-admin list is not a statement
    // about any club's status, and should not cost an NCB round trip to answer.
    const statusClubId = CLUB_ACTIVE_OPS.has(op) ? (targetClubId || ownerClubId || effectiveMembership?.clubId || null) : null;
    let targetClubStatus = null;
    if (statusClubId) {
      try {
        targetClubStatus = await store.clubStatus(statusClubId);
      } catch {
        return void respondServiceUnavailable(res, 'The club record could not be read; the request was not decided.');
      }
    }

    const decision = authorizeClubOperation({
      op, session: { id: userId, role: session.role }, membership: effectiveMembership, targetClubId,
      ownerClubId, collectionStatus, targetClubStatus, storeSuperAdmin: superAdmin
    });
    if (!decision.allow) {
      return void res.status(decision.status).json(decision.body);
    }

    const method = STORE_METHOD_FOR[op];
    if (!method || typeof store[method] !== 'function') {
      return void respondServiceUnavailable(res, 'The configured club store does not implement this operation; nothing was written.');
    }

    return {
      userId, session: { id: userId, role: session.role },
      // `membership` is the EFFECTIVE one (approved only). `membershipRequest` is the raw row, for
      // reporting the state of a request, and is never an input to a decision.
      membership: effectiveMembership, membershipRequest, decision, ownerClubId, collectionStatus, boardNumber
    };
  }

  async function guarded(op, req, res, options, dispatch) {
    try {
      const context = await resolveContext(op, req, res, options);
      if (!context) return;
      const input = validateClubInput(op, req.body ?? {}, boardLimits);
      if (input.ok === false) {
        return void res.status(input.status).json(input.body);
      }
      const payload = await dispatch(context, input.value, req);
      return void respondStoreResult(res, payload);
    } catch (error) {
      // Express 4 does not catch a rejected handler, so nothing may propagate out of a route: an
      // uncaught throw here would hang the socket rather than answer it.
      return void respondServiceUnavailable(res, `The club operation failed before it could be answered (${error?.name || 'Error'}).`);
    }
  }

  // ── R1 — Super Admin manages clubs and Club Admins ────────────────────────
  // Literal paths are registered before the parameterised ones that could shadow them: `options`
  // is a legal club id under ID, so `PATCH /clubs/options` must never be reachable as a club edit.
  router.get('/clubs/options', (req, res) => guarded('clubOptions', req, res, {},
    () => store.listActiveClubs()));

  router.get('/clubs', (req, res) => guarded('listClubs', req, res, {},
    (context, value, request) => store.listClubs({
      search: String(request.query.search ?? ''),
      page: boundedPage(request.query.page),
      limit: boundedLimit(request.query.limit, boardLimits.maxRowLimit)
    })));

  router.post('/clubs', (req, res) => guarded('createClub', req, res, {},
    (context, value) => store.createClub({ name: value.name, createdBy: context.userId })));

  router.patch('/clubs/:clubId', (req, res) => {
    if (!isId(req.params.clubId)) return void res.status(400).json({ error: 'bad_request', detail: 'clubId is invalid.' });
    return guarded('updateClub', req, res, { targetClubId: req.params.clubId },
      (context, value) => store.updateClub({ clubId: req.params.clubId, name: value.name }));
  });

  router.post('/clubs/:clubId/status', (req, res) => {
    if (!isId(req.params.clubId)) return void res.status(400).json({ error: 'bad_request', detail: 'clubId is invalid.' });
    return guarded('setClubStatus', req, res, { targetClubId: req.params.clubId },
      (context, value) => store.setClubStatus({ clubId: req.params.clubId, status: value.status }));
  });

  router.get('/clubs/:clubId/members', (req, res) => {
    if (!isId(req.params.clubId)) return void res.status(400).json({ error: 'bad_request', detail: 'clubId is invalid.' });
    return guarded('listClubMembers', req, res, { targetClubId: req.params.clubId },
      () => store.listMembers({ clubId: req.params.clubId }));
  });

  // The membership lifecycle transition: pending -> approved | rejected, approved -> removed.
  // Reachable only by a super admin or an APPROVED admin of THIS club, and the store refuses a
  // target whose row belongs to another club, so the path parameter cannot be used to reach across.
  router.post('/clubs/:clubId/members/:userId/status', (req, res) => {
    if (!isId(req.params.clubId) || !isId(req.params.userId)) {
      return void res.status(400).json({ error: 'bad_request', detail: 'clubId/userId is invalid.' });
    }
    return guarded('setMembershipStatus', req, res, { targetClubId: req.params.clubId },
      (context, value) => store.setMembershipStatus({
        clubId: req.params.clubId, userId: req.params.userId, status: value.status
      }));
  });

  router.post('/clubs/:clubId/admins', (req, res) => {
    if (!isId(req.params.clubId)) return void res.status(400).json({ error: 'bad_request', detail: 'clubId is invalid.' });
    return guarded('assignClubAdmin', req, res, { targetClubId: req.params.clubId },
      (context, value) => store.assignClubAdmin({ clubId: req.params.clubId, userId: value.userId, role: value.role }));
  });

  router.delete('/clubs/:clubId/admins/:userId', (req, res) => {
    if (!isId(req.params.clubId) || !isId(req.params.userId)) {
      return void res.status(400).json({ error: 'bad_request', detail: 'clubId/userId is invalid.' });
    }
    return guarded('removeClubAdmin', req, res, { targetClubId: req.params.clubId },
      () => store.removeClubAdmin({ clubId: req.params.clubId, userId: req.params.userId }));
  });

  // ── R2 — a user selects one club, or none ─────────────────────────────────
  router.get('/me/club/board-collections', (req, res) => guarded('listPublishedCollections', req, res, {},
    (context) => store.listPublishedCollections({ clubId: context.decision.scope.clubId })));

  // Profile reads this. A non-approved user gets `club_id: null` — the SAME value a user with no row
  // gets — because the answer this route gives must not be a second source of club scope for the
  // client to trust. The request is reported alongside it so the person can see what became of it.
  router.get('/me/club', (req, res) => guarded('myClub', req, res, {},
    (context) => {
      if (context.membership) {
        return {
          club_id: context.membership.clubId,
          role: context.membership.role,
          membership_status: APPROVED_MEMBERSHIP_STATUS
        };
      }
      const request = context.membershipRequest;
      if (!request) return null;
      return {
        club_id: null,
        role: null,
        membership_status: request.status || 'pending',
        request: { club_id: request.clubId, status: request.status || 'pending', role: request.role || 'member' }
      };
    }));

  // UNIQUE(user_id) surfaces here. The store answers an IN-BAND outcome rather than throwing, and
  // "you are already in another club" must reach the browser as a 409 it can show — a 200 over a
  // refusal would render "Joined" on a row that was never written.
  router.post('/me/club', (req, res) => guarded('setMyClub', req, res, {},
    async (context, value) => {
      const result = await store.setClubMembership({ userId: context.userId, clubId: value.clubId });
      if (result?.outcome === 'already_in_club') {
        return { error: 'already_in_club', detail: 'This account already belongs to a club; leave it before joining another.' };
      }
      if (result?.outcome === 'error') {
        return { error: result.reason ?? 'write_unverified', detail: result.detail ?? '' };
      }
      return result;
    }));

  router.delete('/me/club', (req, res) => guarded('clearMyClub', req, res, {},
    (context) => store.setClubMembership({ userId: context.userId, clubId: null })));

  // ── R3 — a Club Admin manages their own club's collections ────────────────
  router.get('/clubs/:clubId/board-collections', (req, res) => {
    if (!isId(req.params.clubId)) return void res.status(400).json({ error: 'bad_request', detail: 'clubId is invalid.' });
    return guarded('listCollections', req, res, { targetClubId: req.params.clubId },
      () => store.listCollections({ clubId: req.params.clubId }));
  });

  router.post('/clubs/:clubId/board-collections', (req, res) => {
    if (!isId(req.params.clubId)) return void res.status(400).json({ error: 'bad_request', detail: 'clubId is invalid.' });
    return guarded('importCollection', req, res, { targetClubId: req.params.clubId },
      (context, value) => store.createCollection({
        // `createdBy` is the id THIS relay proved from the caller's session. The client never sends
        // an author, and `created_by_user_id` is refused upstream if this is ever empty.
        clubId: req.params.clubId, name: value.name, boards: value.boards, createdBy: context.userId
      }));
  });

  router.patch('/clubs/collections/:collectionId', (req, res) => {
    if (!isId(req.params.collectionId)) return void res.status(400).json({ error: 'bad_request', detail: 'collectionId is invalid.' });
    return guarded('renameCollection', req, res, { collectionId: req.params.collectionId },
      (context, value) => store.renameCollection({
        collectionId: req.params.collectionId, name: value.name, clubId: context.decision.scope.clubId
      }));
  });

  // Publish and unpublish share the `setCollectionStatus` authority decision but not the outcome:
  // publishing is the one transition that hands content to members, so it is the store's verified
  // read-back that permits it, not this route's permission.
  const collectionStatusRoute = (status) => (req, res) => {
    if (!isId(req.params.collectionId)) return void res.status(400).json({ error: 'bad_request', detail: 'collectionId is invalid.' });
    return guarded('setCollectionStatus', req, res, { collectionId: req.params.collectionId },
      (context) => store.setCollectionStatus({
        collectionId: req.params.collectionId, status, clubId: context.decision.scope.clubId
      }));
  };
  router.post('/clubs/collections/:collectionId/publish', collectionStatusRoute('published'));
  router.post('/clubs/collections/:collectionId/unpublish', collectionStatusRoute('draft'));

  router.delete('/clubs/collections/:collectionId', (req, res) => {
    if (!isId(req.params.collectionId)) return void res.status(400).json({ error: 'bad_request', detail: 'collectionId is invalid.' });
    return guarded('deleteCollection', req, res, { collectionId: req.params.collectionId },
      (context) => store.deleteCollection({
        collectionId: req.params.collectionId, clubId: context.decision.scope.clubId
      }));
  });

  // ── R4 — a member reaches published boards of their own club only ─────────
  router.get('/clubs/collections/:collectionId/boards', (req, res) => {
    if (!isId(req.params.collectionId)) return void res.status(400).json({ error: 'bad_request', detail: 'collectionId is invalid.' });
    return guarded('listCollectionBoards', req, res, { collectionId: req.params.collectionId },
      (context) => store.listBoards({
        collectionId: req.params.collectionId, clubId: context.decision.scope.clubId
      }));
  });

  // Board-start is a READ and a VALIDATION, not a write. It returns the canonical board record the
  // engine consumes — same shape, and the same shaper, as `GET .../boards`, so the deal a player saw
  // in the list is provably the deal handed to the table. Nothing is recorded here: BridgeMind's
  // gameplay and recorded-hands layer owns that, which is why this feature needs no sixth table.
  router.post('/clubs/collections/:collectionId/boards/:boardNumber/start', (req, res) => {
    if (!isId(req.params.collectionId) || !isId(req.params.boardNumber)) {
      return void res.status(400).json({ error: 'bad_request', detail: 'collectionId/boardNumber is invalid.' });
    }
    // The board number has its own, tighter grammar than an id: it must fit the column it was
    // stored in as well as the route it is addressed by.
    if (!isBoardNumber(req.params.boardNumber)) {
      return void res.status(400).json({ error: 'bad_request', detail: `boardNumber must be 1-${MAX_BOARD_NUMBER_CHARS} characters.` });
    }
    return guarded('startClubBoard', req, res, { collectionId: req.params.collectionId },
      async (context, value) => {
        const collectionId = req.params.collectionId;
        const boardNumber = req.params.boardNumber;
        const board = await store.getBoard({ collectionId, boardNumber });
        if (board?.unavailable) {
          return { unavailable: true, detail: 'the board could not be read, or its rows disagree; no board was started' };
        }
        if (!board) return { error: 'board_not_found', detail: `board ${boardNumber} is not in this collection` };
        // Re-validated on the way out, from the stored row rather than from anything the client
        // sent. A board that was sound at import and corrupted since must not reach a table.
        const checked = validateBoardRecord(board);
        if (!checked.ok) return { error: 'invalid_board_record', detail: checked.detail };
        return {
          board_number: board.board_number,
          dealer: board.dealer,
          vulnerability: board.vulnerability,
          hands: board.hands,
          original_seat: value.originalSeat,
          club_id: context.decision.scope.clubId,
          collection_id: collectionId
        };
      });
  });

  return router;
}

function boundedPage(value) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 ? n : 1;
}

function boundedLimit(value, ceiling) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) return 25;
  return Math.min(n, ceiling);
}

module.exports = {
  ID,
  MEMBERSHIP_ROLES,
  CLUB_STATUSES,
  BODY_FIELDS,
  CLUB_ROUTES,
  STORE_METHOD_FOR,
  STORE_ERROR_STATUS,
  isId,
  hasControlChars,
  validateRequestShape,
  validateClubInput,
  authorizeClubOperation,
  createClubRouter
};
