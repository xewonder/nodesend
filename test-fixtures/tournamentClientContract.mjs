/*
 * THE PUBLISHED TOURNAMENT CLIENT CONTRACT — a fixture, not a copy.
 *
 * WHY THIS FILE EXISTS. `verify-tournaments-gateway.mjs` section 12 used to read
 * `../BridgeMind-Greta/src/services/tournamentContracts.js` off disk and compare truth tables with it.
 * That made the backend gate depend on whatever happened to be in a DIFFERENT repository's working
 * tree, and the arms it built on it asserted a rule the ownership contract has since corrected: a
 * private tournament scoped on `user_id`, which on this vendor is NCB's row-ownership slot. NodeSend
 * writes every tournament row with its service account, so that column names the writer, never the
 * owner — the clause could only ever be wrong.
 *
 * WHAT THIS IS, precisely: the contract as the owner specified it, restated as executable rules.
 *   · `tournaments.owner_user_id`      = the application owner
 *   · `tournament_attempts.player_user_id` = the player who recorded the attempt
 *   · `user_id`                        = NCB row ownership, normally the NodeSend service account
 *   · a private scope is therefore `owner_user_id = <session id>` and never `user_id = <session id>`;
 *   · a client may read the legacy `user_id` field of a RESPONSE only because NodeSend projects the
 *     application owner into it, and a client-supplied owner field never decides ownership;
 *   · club-admin and system-admin rights come from the server's own reads, not from anything sent.
 *
 * WHAT IT IS NOT — the limit, stated rather than buried. This fixture is NOT the frontend's source.
 * The arms below therefore measure NodeSend's CONFORMANCE TO THE SPEC. They can no longer catch a
 * second implementation drifting from this spec; that is the frontend's own gate's job against the
 * same published contract, and it is a real reduction from what reading the sibling file used to give.
 * Two rules are additionally restated here because the spec fixes them and prose hides an off-by-one:
 * the club-visible draft reviewable by that club's own admin, and the fact that a system admin acting
 * for an INACTIVE club is still refused. Both were measured off the sibling module before it was
 * detached, and both are asserted here so a change in either direction goes red somewhere.
 *
 * `LEGACY_USER_ID_CONTRACT` at the bottom is the OLD, WRONG contract, kept ON PURPOSE: the negative
 * controls in section 12 run NodeSend against it and require it to fail. A control that cannot fail is
 * not a control.
 */

export const APPROVED_TOURNAMENT_COLUMNS = Object.freeze({
  visibility: 'visibility',
  status: 'status',
  clubId: 'club_id',
  ownerId: 'owner_user_id',      // the application owner
  playerOwnerId: 'owner_user_id',
  attemptPlayerId: 'player_user_id', // the player who recorded the attempt
  ncbRowOwner: 'user_id'            // NCB's ownership slot; never an application identity
});

/** The clause names the column that holds the owner, given the deployment's mapping. */
export function approvedPrivateClause({ ownerIdColumn, userId }) {
  return { visibility: 'private', [ownerIdColumn]: userId };
}

export const TOURNAMENT_VISIBILITIES = Object.freeze(['private', 'club', 'public']);
export const TOURNAMENT_STATUSES = Object.freeze(['draft', 'published']);
export const MAX_TOURNAMENT_BOARDS = 100;
export const MAX_TOURNAMENT_NAME_LENGTH = 200;
export const SEATS = Object.freeze(['North', 'East', 'South', 'West']);
export const VULNERABILITIES = Object.freeze(['None', 'NS', 'EW', 'Both']);

const idToString = (value) => (value === null || value === undefined ? '' : String(value).trim());

/*
 * Row access, as the contract states it in words:
 *   private  — the owner alone reads, manages and plays it. Nobody else, including an admin.
 *   club     — an admin OF THE OWNING CLUB (or a system admin acting for it) reads, manages and plays
 *              it whatever its status, so a draft can be reviewed; a member of that club may read and
 *              play it once published, and may not touch a draft; anybody outside the club is refused
 *              for every verb, and a club set that names no club is refused outright.
 *   public   — readable and playable by any session once published; management is the system admin's.
 *              A draft public set is not reachable by an ordinary session at all.
 */
export function resolveTournamentAccess({ row = null, session = null, membership = null } = {}) {
  const userId = idToString(session?.userId);
  const isSuper = session?.isSuperAdmin === true;
  const memberClub = idToString(membership?.clubId);
  const visibility = String(row?.visibility ?? '');
  const status = String(row?.status ?? '');
  const ownerId = idToString(row?.ownerId);
  const clubId = idToString(row?.clubId);
  if (!TOURNAMENT_VISIBILITIES.includes(visibility)) {
    return { read: false, manage: false, play: false, reason: 'invalid_visibility' };
  }
  if (visibility === 'private') {
    const mine = userId !== '' && ownerId === userId;
    return { read: mine, manage: mine, play: mine, reason: mine ? null : 'owner_only' };
  }
  if (visibility === 'club') {
    if (clubId === '') return { read: false, manage: false, play: false, reason: 'club_required' };
    const adminOfIt = isSuper || (memberClub !== '' && memberClub === clubId && membership?.role === 'club_admin');
    if (adminOfIt) return { read: true, manage: true, play: true, reason: null, asAdmin: true };
    if (memberClub !== clubId) {
      return { read: false, manage: false, play: false, reason: memberClub === '' ? 'not_a_club_member' : 'club_scope_mismatch' };
    }
    if (status !== 'published') return { read: false, manage: false, play: false, reason: 'tournament_not_published' };
    return { read: true, manage: false, play: true, reason: null, asMember: true };
  }
  if (isSuper) return { read: true, manage: true, play: true, reason: null, asSuperAdmin: true };
  if (status !== 'published') return { read: false, manage: false, play: false, reason: 'tournament_not_published' };
  return { read: true, manage: false, play: true, reason: null, asPublic: true };
}

/*
 * The list scope. One clause per category the caller is entitled to, ANDed inside, ORed across — and
 * the private clause is keyed on the OWNER COLUMN, which is what this fixture exists to pin.
 */
export function tournamentListScope({ session = null, membership = null, columns = APPROVED_TOURNAMENT_COLUMNS } = {}) {
  const userId = idToString(session?.userId);
  const isSuper = session?.isSuperAdmin === true;
  const memberClub = idToString(membership?.clubId);
  const adminClub = memberClub !== '' && membership?.role === 'club_admin' ? memberClub : '';
  const ownerColumn = columns.ownerId;
  const clauses = [{ [columns.visibility]: 'private', [ownerColumn]: userId }];
  if (memberClub !== '') {
    clauses.push(adminClub === memberClub
      ? { [columns.visibility]: 'club', [columns.clubId]: memberClub }
      : { [columns.visibility]: 'club', [columns.clubId]: memberClub, [columns.status]: 'published' });
  }
  if (isSuper) clauses.push({ [columns.visibility]: 'public' });
  else clauses.push({ [columns.visibility]: 'public', [columns.status]: 'published' });
  return { userId, isSuper, memberClub, adminClub, clauses };
}

/*
 * Who may create what, and who the created row belongs to. The owner is the SESSION, always: the
 * contract has no field through which a caller states an owner, so supplying one is a shape error
 * rather than a claim to be weighed. A club import needs an admin of that club (or a system admin) and
 * an active club; a public import needs a system admin.
 */
export function authorizeTournamentCreate({ target = null, targetClubId = null, session = null, membership = null, clubActive = null } = {}) {
  const userId = idToString(session?.userId);
  if (!TOURNAMENT_VISIBILITIES.includes(String(target ?? ''))) return { allow: false, reason: 'invalid_visibility' };
  if (target === 'private') {
    return userId === ''
      ? { allow: false, reason: 'unauthorized' }
      : { allow: true, scope: { visibility: 'private', ownerId: userId, clubId: null } };
  }
  const club = idToString(targetClubId);
  if (target === 'club') {
    if (club === '') return { allow: false, reason: 'invalid_club_id' };
    const memberClub = idToString(membership?.clubId);
    if (!(session?.isSuperAdmin === true || (memberClub === club && membership?.role === 'club_admin'))) {
      return { allow: false, reason: 'not_a_club_admin' };
    }
    if (clubActive === false) return { allow: false, reason: 'club_inactive' };
    return { allow: true, scope: { visibility: 'club', clubId: club, ownerId: userId === '' ? null : userId } };
  }
  return session?.isSuperAdmin === true
    ? { allow: true, scope: { visibility: 'public', clubId: null, ownerId: userId } }
    : { allow: false, reason: 'super_admin_required' };
}

/*
 * A category change is decided by its DESTINATION, never by the caller's account of the source. The
 * contract states the rule in four sentences, and this is that text made executable:
 *   · into `public`  — the system admin only.
 *   · into `club`    — an admin OF THE TARGET CLUB, from the server's own membership read, or a system
 *                      admin who may act for any club. A club's set cannot move to another club, not
 *                      even by its own admin: every board row keeps its `tournament_id`, so that one
 *                      write re-parents a whole set while changing nothing else.
 *   · into `private` — the row's owner only, and never a row that `public` or `club` has opened up.
 *                      A published set going private is a system-admin decision; a club set going
 *                      private is refused outright, because the row carries two authorities at once
 *                      (an owner and a club) and demoting it would revoke the club's access as a
 *                      one-person decision that leaves no trace.
 *   · already in the destination category AND club is a NO-OP, not a refusal, so a management screen
 *     can render the current value as selected without the save being an accusation.
 * A caller who cannot manage the row is refused before the destination is looked at.
 */
export function authorizeVisibilityTarget({ row = null, target = null, targetClubId = null, session = null, membership = null } = {}) {
  if (typeof target !== 'string' || !TOURNAMENT_VISIBILITIES.includes(target.trim())) {
    return { allow: false, reason: 'invalid_visibility' };
  }
  const to = target.trim();
  const access = resolveTournamentAccess({ row, session, membership });
  if (!access.manage) {
    const visibility = String(row?.visibility ?? '');
    const fallback = !TOURNAMENT_VISIBILITIES.includes(visibility) ? 'invalid_visibility'
      : visibility === 'private' ? 'owner_only' : visibility === 'club' ? 'not_a_club_admin' : 'super_admin_required';
    return { allow: false, reason: access.reason ?? fallback };
  }
  const current = String(row?.visibility ?? '');
  const isSuper = session?.isSuperAdmin === true;
  const club = idToString(targetClubId);
  const rowClub = idToString(row?.clubId);
  const memberClub = idToString(membership?.clubId);
  const isClubAdmin = memberClub !== '' && membership?.role === 'club_admin';
  if (to === current && (to !== 'club' || club === rowClub)) {
    return { allow: true, noop: true, scope: { visibility: current, clubId: to === 'club' ? rowClub : null } };
  }
  if (to === 'public') {
    return isSuper ? { allow: true, scope: { visibility: 'public', clubId: null } }
      : { allow: false, reason: 'super_admin_required' };
  }
  if (to === 'club') {
    if (club === '') return { allow: false, reason: 'invalid_club_id' };
    if (!(isSuper || (isClubAdmin && memberClub === club))) return { allow: false, reason: 'not_a_club_admin' };
    if (current === 'club' && rowClub !== club && !isSuper) return { allow: false, reason: 'club_scope_mismatch' };
    return { allow: true, scope: { visibility: 'club', clubId: club } };
  }
  const ownerId = idToString(row?.ownerId);
  const userId = idToString(session?.userId);
  if (ownerId === '' || ownerId !== userId) return { allow: false, reason: 'owner_only' };
  if (current === 'public') return { allow: false, reason: 'super_admin_required' };
  if (current === 'club') return { allow: false, reason: 'club_scope_mismatch' };
  return { allow: true, scope: { visibility: 'private', clubId: null } };
}

/** The boards an import may carry. Structural only — the contract sends no identity here. */
export function validateTournamentBoards(boards) {
  if (!Array.isArray(boards) || boards.length === 0) return { valid: false, reason: 'no_boards' };
  if (boards.length > MAX_TOURNAMENT_BOARDS) return { valid: false, reason: 'too_many_boards' };
  const seen = new Set();
  for (const board of boards) {
    const number = idToString(board?.board_number);
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(number)) return { valid: false, reason: 'invalid_board_number' };
    if (seen.has(number)) return { valid: false, reason: 'duplicate_board_number' };
    seen.add(number);
    if (!['North', 'East', 'South', 'West'].includes(board?.dealer)) return { valid: false, reason: 'invalid_dealer' };
    if (!VULNERABILITIES.includes(board?.vulnerability)) return { valid: false, reason: 'invalid_vulnerability' };
    const hands = board?.hands;
    if (!hands || typeof hands !== 'object' || SEATS.some((s) => !Array.isArray(hands[s]) || hands[s].length !== 13)) {
      return { valid: false, reason: 'incomplete_hands' };
    }
    const cards = SEATS.flatMap((s) => hands[s]);
    if (new Set(cards).size !== 52) return { valid: false, reason: 'incomplete_hands' };
  }
  return { valid: true, reason: null };
}

/** The twelve endpoints, as the client calls them. */
export const TOURNAMENT_ENDPOINTS = Object.freeze({
  listTournaments: { method: 'GET', path: '/tournaments' },
  createTournament: { method: 'POST', path: '/tournaments' },
  readTournament: { method: 'GET', path: '/tournaments/{tournamentId}' },
  listBoards: { method: 'GET', path: '/tournaments/{tournamentId}/boards' },
  updateTournament: { method: 'PATCH', path: '/tournaments/{tournamentId}' },
  setVisibility: { method: 'POST', path: '/tournaments/{tournamentId}/visibility' },
  publish: { method: 'POST', path: '/tournaments/{tournamentId}/publish' },
  unpublish: { method: 'POST', path: '/tournaments/{tournamentId}/unpublish' },
  deleteTournament: { method: 'DELETE', path: '/tournaments/{tournamentId}' },
  startBoard: { method: 'POST', path: '/tournaments/{tournamentId}/boards/{boardNumber}/start' },
  listAttempts: { method: 'GET', path: '/tournaments/{tournamentId}/attempts' },
  recordAttempt: { method: 'POST', path: '/tournaments/{tournamentId}/attempts' }
});

/**
 * What the client may SEND. No operation carries an owner, a player, a role or an admin flag: the
 * server derives all four, so a field naming one is refused rather than weighed.
 */
export const TOURNAMENT_BODY_FIELDS = Object.freeze({
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

/** Response fields the client reads as an identity, and where each one comes from. */
export const TOURNAMENT_RESPONSE_IDENTITY_FIELDS = Object.freeze({
  tournamentOwner: { wireField: 'user_id', sourceColumn: APPROVED_TOURNAMENT_COLUMNS.ownerId, projectedByServer: true },
  attemptPlayer: { wireField: 'user_id', sourceColumn: APPROVED_TOURNAMENT_COLUMNS.attemptPlayerId, projectedByServer: true }
});

/*
 * The refusal names the client translates — enumerated from the contract's own decision tables, not
 * copied from a server map, so this is what the CLIENT promised to handle. Arm 12g reads it in BOTH
 * directions: a name NodeSend can answer that is missing here leaves the browser on a fallback
 * message, and a name here that NodeSend can never answer is a translation nobody will use.
 */
export const TOURNAMENT_GATEWAY_REASONS = Object.freeze([
  'bad_request', 'board_not_found', 'club_inactive', 'club_required', 'club_scope_mismatch',
  'delete_requires_confirmation', 'duplicate_board_number', 'duplicate_import', 'import_incomplete',
  'import_unverified', 'incomplete_hands', 'invalid_board_number', 'invalid_board_record',
  'invalid_club_id', 'invalid_dealer', 'invalid_name', 'invalid_original_seat', 'invalid_recorded_hand_id',
  'invalid_status', 'invalid_visibility', 'invalid_vulnerability', 'no_boards', 'not_a_club_admin',
  'not_a_club_member', 'not_found', 'not_tournament_owner', 'owner_only', 'publish_refused_unverified',
  'super_admin_required', 'too_many_boards', 'tournament_name_mismatch', 'tournament_not_found',
  'tournament_not_published', 'unauthorized', 'write_unverified'
]);

/** Names the client handles that are not a store outcome at all. */
export const TOURNAMENT_CLIENT_ONLY_REASONS = Object.freeze(['authentication_required']);

/*
 * THE CONTRACT THIS GATE USED TO PIN, AND WHICH WAS WRONG. `user_id` where the owner belongs. It is
 * kept so the negative controls can run NodeSend against it and require refusal — see 12b4/12b5.
 */
export const LEGACY_USER_ID_CONTRACT = Object.freeze({
  columns: Object.freeze({ ...APPROVED_TOURNAMENT_COLUMNS, ownerId: 'user_id', attemptPlayerId: 'user_id', ncbRowOwner: 'user_id' }),
  privateClause(userId) { return { visibility: 'private', user_id: userId }; },
  attemptPlayer(row) { return idToString(row?.user_id); }
});
