'use strict';

/*
 * games/gameDeletion.js — the RULES of an authorized permanent game deletion, with no storage in them.
 *
 * Separated from `gameDeletionStore.js` for the same reason `tournaments/tournamentAuthorization.js` is
 * separated from its store: the destructive decisions (what is in scope, what order, what may never be
 * touched, what counts as success) must be testable without a vendor, and a test that needs a mock to
 * assert a rule can always pass by weakening the mock.
 *
 * CONTRACT SOURCE. The frontend candidate `514ad394` ships both the client
 * (`src/services/gameDeletionService.js`) and `BRIDGEMIND-NODESEND-GAME-DELETION-HANDOFF.md`. Those
 * documents are the contract below, with ONE deliberate departure, stated in §4 and asserted by
 * `verify-game-deletion.mjs`: the handoff proposes LEAVING replay children with a dangling
 * `root_hand_id`, while the release instruction forbids dangling references. This module implements the
 * stricter rule.
 *
 * WHAT IS NOT HERE, and why each is a rule rather than an omission:
 *   * no bulk path, no wildcard, no filter-delete. Every operation names one row id (`exactRowOps`).
 *   * no counter arithmetic. Statistics are computed live from `community_games` rows, so removing those
 *     rows IS the correction; a decrement would invent a stored total that does not exist.
 *   * no `deleted: true` unless the canonical row was confirmed gone.
 *   * no client-supplied authority. `removed`/`alreadyAbsent`/`replayChildren` are all computed here.
 *   * no cascade row deleted on a reference match alone. Every satellite the sweep can reach is audited
 *     against the canonical game's owner BEFORE the first write, and an unreadable owner refuses (§4b).
 */

/** The five tables one canonical game touches, and the column that ties each to it. */
const GAME_TABLES = Object.freeze({
  recordedHands: 'recorded_hands',
  communityGames: 'community_games',
  analysisReports: 'game_analysis_reports',
  decisionTraces: 'ai_decision_traces',
  tournamentAttempts: 'tournament_attempts',
  // Found by the storage-readiness review rather than by the original handoff. A replay attempt's whole
  // meaning is "an attempt at this recorded hand", so leaving one behind is a dangling reference of
  // exactly the kind this route exists to prevent — and it is invisible to a sweep that knows only about
  // tournament_attempts.
  replayAttempts: 'replay_attempts'
});

/*
 * COACH FLAGS ARE DELIBERATELY NOT IN THE SWEEP.
 * A `coach_feedback_flags` row belongs to the COACH who raised it, not to the player whose game is being
 * deleted: it is the reviewer's work product and, on this deployment, evidence about a player. Deleting
 * it would destroy another person's record behind an admin's click on someone else's game — the same
 * principle that refuses a foreign replay child. Leaving it is the lesser harm, and it is NOT silent: the
 * count is returned as `preserved.coachFeedbackFlags`, so the administrator knows a flag now points at a
 * game that is gone, and the coach-facing cleanup is carried as a separate decision in the handoff.
 */
const COACH_FLAG_TABLE = Object.freeze({ table: 'coach_feedback_flags', handId: 'hand_id', rootHandId: 'root_hand_id' });
const COACH_FLAGS_DISPOSITION = 'preserved-and-reported';

/**
 * Column names as the live schema spells them. NodeSend has no games schema config (these tables are
 * reached today only through the generic relay), so these names are the documented contract, and every
 * one of them is used ONLY as an exact-match equality filter — an unknown name fails the whole read on
 * this backend rather than silently widening it, and `gameDeletionStore` treats that as a refusal.
 */
const GAME_COLUMNS = Object.freeze({
  // parent_hand_id is as much a reference as root_hand_id. A chain is root -> child -> grandchild, and
  // every row carries the ROOT in root_hand_id (App.jsx: `const rootId = hand.rootHandId ?? hand.id`),
  // while parent_hand_id names the previous row. So a game that is itself a replay has a child whose
  // parent_hand_id is this id but whose root_hand_id is a DIFFERENT row: sweeping only on root_hand_id
  // deletes this row and leaves that child pointing at nothing. Both columns are therefore searched.
  recordedHands: { id: 'id', userId: 'user_id', rootHandId: 'root_hand_id', parentHandId: 'parent_hand_id' },
  communityGames: { id: 'id', sourceHandId: 'source_hand_id', rootHandId: 'root_hand_id' },
  analysisReports: { id: 'id', recordedHandId: 'recorded_hand_id' },
  decisionTraces: { id: 'id', recordedHandId: 'recorded_hand_id', rootHandId: 'root_hand_id' },
  tournamentAttempts: { id: 'id', recordedHandId: 'recorded_hand_id' },
  replayAttempts: { id: 'id', recordedHandId: 'recorded_hand_id', rootHandId: 'root_hand_id' }
});

/**
 * Sweep order. Satellites first, canonical LAST. NCB has no transactions, so the canonical row is the
 * recovery marker: while it exists, Game Review still shows the game and the same request can be issued
 * again, and every step is an equality-filtered delete-by-id, so a re-run finds nothing to remove and is
 * a no-op. A crash between the last satellite and the canonical row therefore self-heals on retry.
 */
const SWEEP_STEPS = Object.freeze([
  'tournamentAttempts',
  'decisionTraces',
  'analysisReports',
  'replayAttempts',
  'communityGames',
  'replayChildren',
  'recordedHand'
]);

/** A canonical recorded-game id is a numeric string. The frontend refuses anything else client-side. */
const isCanonicalGameId = (value) => /^\d{1,20}$/.test(String(value ?? '').trim());

const eq = (value) => String(value ?? '').trim();

/*
 * ── 4. REPLAY DESCENDANTS — the policy, and the departure from the handoff ───────────────────────
 *
 * A replay is its own `recorded_hands` row whose `root_hand_id` points at the canonical game, and the
 * frontend's own rule is that "a row carrying a root_hand_id must never claim to be an original"
 * (App.jsx, replay-chain section). So there are exactly three candidate policies and only one of them
 * is honest about both constraints:
 *
 *   · Leave the children (the handoff's choice)          → dangling references. Forbidden by the
 *                                                          release instruction, so not implemented.
 *   · Rewrite the children's root to NULL                 → makes a replay row claim to be an original.
 *                                                          That FABRICATES provenance. Rejected.
 *   · Delete the children when they belong to the SAME    → they are that player's own recorded versions
 *     owner; refuse the whole request when any child      of the game being destroyed. Safe to cascade,
 *     belongs to a DIFFERENT owner                        and reported, not silent.
 *
 * A child owned by someone else is a different person's recorded game. Deleting it would be destroying
 * another player's data behind an admin's click; nulling its root would lie about it. Neither is
 * available, so the request is refused BEFORE any write, which leaves the dataset untouched and the
 * refusal actionable.
 */
function classifyReplayChildren({ ownerId = null, children = [] } = {}) {
  const owner = eq(ownerId);
  const own = [];
  const foreign = [];
  for (const child of (Array.isArray(children) ? children : [])) {
    const childOwner = eq(child?.userId ?? child?.user_id);
    // An unreadable owner is treated as FOREIGN: "unknown" never entitles a delete of another account's
    // row, and a missing owner column is a storage problem, not a licence.
    if (owner !== '' && childOwner !== '' && childOwner === owner) own.push(child);
    else foreign.push(child);
  }
  return { own, foreign, hasForeign: foreign.length > 0 };
}

/*
 * ── 4b. SATELLITE OWNERSHIP ──────────────────────────────────────────────────────────────────────
 *
 * THE DEFECT THIS SECTION EXISTS TO PREVENT. `recorded_hands` descendants are owner-checked, but the
 * SATELLITES (publications, replay attempts, reports, traces, attempt links) are selected by a reference
 * column alone. `replay_attempts` and `community_games` both carry a `root_hand_id`, which names the
 * FIRST row of a replay chain rather than the row being described — so another player's row is matched by
 * a filter on the deleted game's id. Without an owner predicate, deleting A's game silently destroyed
 * B's publication of it and B's consumed replay attempt. `replayEligibility.js:112-121` is the proof that
 * this shape exists in production data: `startReplayAttempt` writes `{ root_hand_id: A's game, user_id: B }`.
 *
 * THE POLICY, and why each clause is a rule rather than a preference:
 *   · Ownership is read from the column the LIVE WRITER fills, never from the NCB-stamped `user_id`
 *     alone. `tournament_attempts` is written by NodeSend on the service account, so its stamped
 *     `user_id` is the service account and its real owner is `player_user_id`; reports, traces,
 *     publications and attempts all carry an explicit `user_id` set to the HAND OWNER by the frontend
 *     (gameAnalysisService.js:305, aiDecisionTraces.js:62/105/139, replayEligibility.js:117).
 *     `publisher_user_id` does not exist in the frontend at all — a fixture that invented it is the
 *     reason this class of defect survived a green gate.
 *   · An author is not an owner. A report written by a coach about the player's game is owned by the
 *     player (`user_id`) and is part of the game; `author_user_id` is not consulted.
 *   · A row whose owner cannot be read REFUSES the request. "Unknown" is never a licence to delete
 *     someone else's record, and the canonical row's own unreadable owner authorises nothing either.
 *   · The check runs over the SAME probe list the sweep deletes from, so the audit and the write can
 *     never disagree about what was in scope.
 *   · A refusal is scoped to the selected rows. Foreign rows elsewhere in the same table, keyed to other
 *     games, do not block a deletion — otherwise one stray row would make every game undeletable.
 */

/** Per cascade table: the columns that may name the owning account, in resolution order. */
const SATELLITE_OWNER_COLUMNS = Object.freeze({
  tournamentAttempts: Object.freeze(['player_user_id', 'user_id']),
  decisionTraces: Object.freeze(['user_id']),
  analysisReports: Object.freeze(['user_id']),
  replayAttempts: Object.freeze(['user_id']),
  communityGames: Object.freeze(['user_id'])
});

/**
 * The (table, column) pairs through which a satellite is selected for deletion. THE SINGLE SOURCE: the
 * ownership preflight and the sweep both iterate this, so a probe added here is audited automatically and
 * a probe that exists in one place only cannot be introduced silently.
 */
const SWEEP_PROBES = Object.freeze([
  { key: 'tournamentAttempts', column: 'recordedHandId' },
  { key: 'decisionTraces', column: 'recordedHandId' },
  { key: 'analysisReports', column: 'recordedHandId' },
  { key: 'replayAttempts', column: 'recordedHandId' },
  { key: 'replayAttempts', column: 'rootHandId' },
  // Two passes, deduplicated by row id: NCB has no OR in its filter grammar.
  { key: 'communityGames', column: 'sourceHandId' },
  { key: 'communityGames', column: 'rootHandId' }
]);

/** The key whose rows are collected across several columns before deletion (its own read-back proof). */
const MULTI_COLUMN_SATELLITE = 'communityGames';

/** Resolve the account that owns one satellite row, or report that it cannot be resolved. */
function satelliteOwner({ row = null, key = null } = {}) {
  const candidates = SATELLITE_OWNER_COLUMNS[key];
  if (!Array.isArray(candidates)) return { readable: false, owner: '' };
  for (const column of candidates) {
    const value = eq(row?.[column]);
    if (value !== '') return { readable: true, owner: value, column };
  }
  return { readable: false, owner: '' };
}

/**
 * Sort selected satellite rows into own / foreign / unreadable. `groups` is `{ [tableKey]: rows }`.
 * Counts and table keys are returned, never row ids or account ids: this feeds an API response, and
 * naming which accounts hold a publication of a game discloses exactly the private relationship the
 * route must not leak.
 */
function classifySatellites({ ownerId = null, groups = {} } = {}) {
  const owner = eq(ownerId);
  const own = [];
  const foreign = [];
  const unverifiable = [];
  for (const [key, tableRows] of Object.entries(groups && typeof groups === 'object' ? groups : {})) {
    if (!SATELLITE_OWNER_COLUMNS[key]) {
      // A selected table with no declared owner policy is a hole in the audit, not a free pass.
      unverifiable.push({ key, count: (Array.isArray(tableRows) ? tableRows : []).length });
      continue;
    }
    for (const row of (Array.isArray(tableRows) ? tableRows : [])) {
      const found = satelliteOwner({ row, key });
      // No reference owner means nothing can be established about ANY row, in either direction. That is
      // reported as unverifiable rather than "foreign", because the repair is different: the game row
      // itself needs its owner backfilled, not somebody else's record moved.
      if (owner === '' || !found.readable) unverifiable.push({ key, count: 1 });
      else if (found.owner === owner) own.push({ key, count: 1 });
      else foreign.push({ key, count: 1 });
    }
  }
  const fold = (list) => list.reduce((total, entry) => total + entry.count, 0);
  return {
    ownCount: fold(own),
    foreignCount: fold(foreign),
    unverifiableCount: fold(unverifiable),
    ownerUnreadable: owner === '',
    blockedTables: [...new Set([...foreign, ...unverifiable].map((entry) => entry.key))],
    blocked: foreign.length + unverifiable.length > 0
  };
}

/**
 * The pre-write refusal. Same code whether the rows are foreign or merely unreadable, because the
 * administrator's action is the same and the envelope stays one vocabulary; the MESSAGE separates them,
 * because "3 of these are somebody else's" and "1 has no owner recorded" are different repairs.
 */
function checkSatelliteOwnership({ ownerId = null, groups = {} } = {}) {
  const verdict = classifySatellites({ ownerId, groups });
  if (!verdict.blocked) return { ok: true, verdict };
  return { ok: false, verdict, refusal: { http: 409, ...satelliteRefusal(verdict) } };
}

/** The refusal body, and its partial-sweep variant (see the store's per-row backstop). */
function satelliteRefusal({ foreignCount = 0, unverifiableCount = 0, ownerUnreadable = false } = {}, { partial = false } = {}) {
  const parts = [];
  if (foreignCount > 0) parts.push(`${foreignCount} record(s) belong to another account`);
  if (unverifiableCount > 0) {
    parts.push(ownerUnreadable
      ? `${unverifiableCount} record(s) cannot be checked because the recorded game itself has no readable owner`
      : `${unverifiableCount} record(s) have no readable owner`);
  }
  // A caller that reports a block without counts still gets a true sentence, never a leading comma.
  if (parts.length === 0) parts.push('at least one cascade record is not established as this game owner\u2019s');
  const tail = partial
    ? 'The cascade stopped there; records already removed by this request are not restorable.'
    : 'Nothing was deleted.';
  return {
    code: 'foreign_satellite_owners',
    message: `${parts.join(' and ')}, so the cascade cannot be completed safely. ${tail}`
  };
}

/**
 * The deletion plan. Returns `{ ok:false, refusal }` rather than a partial plan whenever the cascade
 * cannot be completed honestly, so the caller cannot accidentally write first and ask later.
 */
function planGameDeletion({ gameId = null, canonical = null, children = [] } = {}) {
  if (!isCanonicalGameId(gameId)) return { ok: false, refusal: { http: 404, code: 'invalid_game_id' } };
  if (!canonical) {
    // Nothing to delete. The caller decides between alreadyAbsent (the id never existed OR a completed
    // earlier sweep) and game_not_found; see `alreadyAbsentResult`, which distinguishes them by evidence.
    return { ok: false, noCanonical: true, gameId: eq(gameId) };
  }
  const { own, foreign, hasForeign } = classifyReplayChildren({
    ownerId: canonical[GAME_COLUMNS.recordedHands.userId],
    children
  });
  if (hasForeign) {
    return {
      ok: false,
      refusal: {
        http: 409,
        code: 'foreign_replay_descendants',
        // A count, never the other players' ids: naming them in an API response would disclose which
        // accounts replayed a game, which is exactly the private metadata this route must not leak.
        message: `${foreign.length} replay descendant(s) of this game belong to another account. Nothing was deleted. Delete those games individually, or repair the replay chain, then retry.`
      }
    };
  }
  return {
    ok: true,
    gameId: eq(gameId),
    canonicalId: eq(canonical[GAME_COLUMNS.recordedHands.id] || gameId),
    replayChildIds: own.map((c) => eq(c?.[GAME_COLUMNS.recordedHands.id])).filter((id) => id !== ''),
    steps: SWEEP_STEPS.slice()
  };
}

/** The only ids whose satellites may be swept: the canonical row and its own-owner replays. */
function sweepTargetIds(plan) {
  return [plan.canonicalId, ...plan.replayChildIds].filter((id, index, all) => id !== '' && all.indexOf(id) === index);
}

/** Exact-ID delete ops only. A step may never be issued without a concrete row id. */
function exactRowOps(rows) {
  return (Array.isArray(rows) ? rows : [])
    .map((row) => eq(row?.id ?? row?.row_id))
    .filter((id) => id !== '' && /^[A-Za-z0-9_-]{1,64}$/.test(id));
}

/* ── envelopes ─────────────────────────────────────────────────────────────────────────────────
 * The frontend reads `body.error.code` (an OBJECT), not NodeSend's tournament-style
 * `{ error: 'name', detail }` (a STRING). Verified against gameDeletionService.js at 514ad394:
 * `const code = body?.error?.code ?? ''`, and a 403 whose code is not exactly `not_system_admin` is
 * reported to the administrator as "not authenticated" — the wrong instruction. This route therefore
 * emits the object form the client parses, and says so in the module header rather than silently
 * diverging from the tournament convention.
 */
function deletionRefusal(http, code, message) {
  return { http, body: { status: 'error', error: { code, message } } };
}

const REFUSALS = Object.freeze({
  invalid_game_id: () => deletionRefusal(404, 'invalid_game_id', 'The game id is not a canonical recorded-game id.'),
  not_system_admin: () => deletionRefusal(403, 'not_system_admin', 'System administrator role required for this operation.'),
  game_store_unavailable: () => deletionRefusal(503, 'club_store_unavailable', 'The game store could not be reached; nothing was deleted. Retry later.'),
  foreign_replay_descendants: (count) => deletionRefusal(409, 'foreign_replay_descendants',
    `${count} replay descendant(s) of this game belong to another account. Nothing was deleted.`),
  foreign_satellite_owners: (verdict, options) => {
    const body = satelliteRefusal(verdict, options);
    return deletionRefusal(409, body.code, body.message);
  },
  incomplete: (detail) => deletionRefusal(502, 'game_deletion_incomplete',
    `The deletion stopped before it completed (${detail}). The game is still recorded; retry the same request to finish the cleanup.`)
});

/**
 * Success, and only success, from confirmed evidence. `deleted` is true ONLY when the canonical row was
 * read back absent, and `alreadyAbsent` marks the idempotent repeat.
 *
 * `noTraceRemaining` replaces an earlier field called `neverFound`, and the rename is the honest version
 * of a claim this route cannot make: with no tombstone table (schema changes are out of scope) a repeat
 * delete of a game that WAS swept a minute ago and a delete of an id that never existed are the same
 * observable state — no canonical row, no satellite, no child. So this field reports only that nothing
 * mentioning the id remains, which is what was actually read, and the gate asserts the two cases are
 * indistinguishable rather than pretending otherwise.
 */
function deletionResult({ removed = {}, replayChildren = 0, preserved = {}, alreadyAbsent = false, noTraceRemaining = false, confirmedGone = false }) {
  const counts = {
    recordedHands: Number(removed.recordedHands) || 0,
    communityGames: Number(removed.communityGames) || 0,
    analysisReports: Number(removed.analysisReports) || 0,
    decisionTraces: Number(removed.decisionTraces) || 0,
    tournamentAttempts: Number(removed.tournamentAttempts) || 0,
    replayAttempts: Number(removed.replayAttempts) || 0
  };
  // Reported, never deleted — see COACH_FLAG_TABLE. A zero here means the game had no flags; a non-zero
  // means the administrator should expect a flag pointing at a game that is now gone.
  const kept = { coachFeedbackFlags: Number(preserved.coachFeedbackFlags) || 0 };
  return {
    http: 200,
    body: {
      status: 'success',
      data: {
        deleted: confirmedGone === true,
        alreadyAbsent: alreadyAbsent === true,
        noTraceRemaining: noTraceRemaining === true,
        removed: counts,
        preserved: kept,
        replayChildren: Number(replayChildren) || 0
      }
    }
  };
}

/** What the bridge log may carry: names and counts, never a hand, an email or a player id. */
function auditRecord({ adminUserId, gameId, result }) {
  return {
    adminUserId: eq(adminUserId),
    recordedHandId: eq(gameId),
    deleted: result?.data?.deleted === true,
    alreadyAbsent: result?.data?.alreadyAbsent === true,
    removed: result?.data?.removed ?? null,
    replayChildren: result?.data?.replayChildren ?? 0,
    ts: new Date().toISOString()
  };
}

module.exports = {
  GAME_TABLES,
  GAME_COLUMNS,
  COACH_FLAG_TABLE,
  COACH_FLAGS_DISPOSITION,
  SWEEP_STEPS,
  SWEEP_PROBES,
  SATELLITE_OWNER_COLUMNS,
  MULTI_COLUMN_SATELLITE,
  REFUSALS,
  isCanonicalGameId,
  classifyReplayChildren,
  satelliteOwner,
  classifySatellites,
  checkSatelliteOwnership,
  satelliteRefusal,
  planGameDeletion,
  sweepTargetIds,
  exactRowOps,
  deletionRefusal,
  deletionResult,
  auditRecord
};
