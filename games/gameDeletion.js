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
 */

/** The five tables one canonical game touches, and the column that ties each to it. */
const GAME_TABLES = Object.freeze({
  recordedHands: 'recorded_hands',
  communityGames: 'community_games',
  analysisReports: 'game_analysis_reports',
  decisionTraces: 'ai_decision_traces',
  tournamentAttempts: 'tournament_attempts'
});

/**
 * Column names as the live schema spells them. NodeSend has no games schema config (these tables are
 * reached today only through the generic relay), so these names are the documented contract, and every
 * one of them is used ONLY as an exact-match equality filter — an unknown name fails the whole read on
 * this backend rather than silently widening it, and `gameDeletionStore` treats that as a refusal.
 */
const GAME_COLUMNS = Object.freeze({
  recordedHands: { id: 'id', userId: 'user_id', rootHandId: 'root_hand_id' },
  communityGames: { id: 'id', sourceHandId: 'source_hand_id', rootHandId: 'root_hand_id' },
  analysisReports: { id: 'id', recordedHandId: 'recorded_hand_id' },
  decisionTraces: { id: 'id', recordedHandId: 'recorded_hand_id' },
  tournamentAttempts: { id: 'id', recordedHandId: 'recorded_hand_id' }
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
function deletionResult({ removed = {}, replayChildren = 0, alreadyAbsent = false, noTraceRemaining = false, confirmedGone = false }) {
  const counts = {
    recordedHands: Number(removed.recordedHands) || 0,
    communityGames: Number(removed.communityGames) || 0,
    analysisReports: Number(removed.analysisReports) || 0,
    decisionTraces: Number(removed.decisionTraces) || 0,
    tournamentAttempts: Number(removed.tournamentAttempts) || 0
  };
  return {
    http: 200,
    body: {
      status: 'success',
      data: {
        deleted: confirmedGone === true,
        alreadyAbsent: alreadyAbsent === true,
        noTraceRemaining: noTraceRemaining === true,
        removed: counts,
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
  SWEEP_STEPS,
  REFUSALS,
  isCanonicalGameId,
  classifyReplayChildren,
  planGameDeletion,
  sweepTargetIds,
  exactRowOps,
  deletionRefusal,
  deletionResult,
  auditRecord
};
