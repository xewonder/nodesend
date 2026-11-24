'use strict';

/*
 * games/index.js — the System Admin permanent-game-deletion mount bridge.js uses.
 *
 *   buildGameDeletionMount({ env, authenticate, clubAccount, onAudit }) -> { router, configured, reason, status() }
 *
 * Mounted ALWAYS, on the rule `clubs/index.js` and `tournaments/index.js` already state: a route that is
 * absent answers 404, and a 404 is indistinguishable from "NodeSend has no deletion feature", which would
 * tell an administrator the click was rejected by the product rather than by configuration. Mounted and
 * 503-ing with a named reason says the true thing.
 *
 * AUTHORIZATION IS THREE STEPS, IN THIS ORDER, ALL SERVER-SIDE:
 *   1. the relay's own session verification (`authenticate`, which bridge.js wires to the SAME
 *      `resolveSessionUser` that `requireBridgeSession` uses, so there is one session truth in this
 *      process and this route cannot have a weaker one);
 *   2. `system_admins` through `clubs/clubNcbStore.js` `isSystemAdmin` — the only super-admin authority
 *      in the deployment. A club_admin is NOT an admin here, and an unreadable authority table is a 503,
 *      never a "you are not an admin";
 *   3. only then the store, on the dedicated service account.
 * Nothing in this file reads an admin flag, a role, an owner id or a table name from a request body or
 * query: the verb is DELETE, the parameter is one id, and that is the whole input surface.
 */

const { Router } = require('express');
const { createClubNcbStore } = require('../clubs/clubNcbStore.js');
const { readClubSchemaConfig } = require('../clubs/clubSchema.js');
const { createGameDeletionStore } = require('./gameDeletionStore.js');
const {
  isCanonicalGameId, planGameDeletion, deletionResult, REFUSALS, auditRecord, GAME_COLUMNS, GAME_TABLES
} = require('./gameDeletion.js');

const eq = (value) => String(value ?? '').trim();

/**
 * The declared surface, in the same role `TOURNAMENT_ROUTES` plays: `verify-clubs-gateway.mjs` asserts
 * the mounted stack against THIS list, so a route added here without being declared — or declared and
 * never mounted — reddens an arm instead of vanishing into an excluded bucket.
 */
const GAME_DELETION_ROUTES = Object.freeze([
  { op: 'deleteRecordedGame', method: 'DELETE', path: '/games/:recordedHandId' }
]);

/*
 * Two different failures were being collapsed into one 503.
 *
 * A TRANSPORT failure means the storage was never consulted: retrying later is genuinely the right
 * instruction, and 503 says that. A REFUSED write means the storage answered and said NO — most likely
 * the dedicated account has no delete grant on the table (the open capability question in the release
 * notes). Telling an administrator "the game store could not be reached, try again later" about a
 * permission refusal sends them to wait instead of to fix it, and a retry can never succeed. So the two
 * are separated: transport -> 503 `club_store_unavailable`; refusal/unconfirmed -> 502
 * `game_deletion_incomplete`, whose detail names the step. Both remain retry-safe, because the sweep is
 * satellites-first and the canonical row survives either way.
 */
const TRANSPORT_REASONS = /^(?:club_account_unreachable|club_account_login_failed|club_account_rejected|club_account_cooling_down|game_store_request_failed|game_read_unreadable|club_store_|club_schema_|club_account_unconfigured)/;
/** Kept for the pre-sweep checks, where these names still mean "cannot be consulted at all". */
const UNAVAILABLE_REASONS = /^(?:club_account_|club_store_|game_store_request_failed|game_read_unreadable|club_schema_)/;

/**
 * @param {object} options
 * @param {object} [options.env]
 * @param {Function} options.authenticate  relay session resolver; `{ ok, id }` or `{ ok:false, status, code }`
 * @param {object} [options.clubAccount]   the LIVE service-account client the club mount holds
 * @param {object} [options.clubStore]     prebuilt club store (tests); otherwise built over clubAccount
 * @param {object} [options.deletionStore] prebuilt deletion store (tests)
 * @param {Function} [options.onAudit]     receives `auditRecord(...)` on every answered request
 */
function buildGameDeletionMount({
  env = process.env, authenticate, clubAccount = null, clubStore = null,
  deletionStore = null, onAudit = null
} = {}) {
  if (typeof authenticate !== 'function') {
    throw new TypeError('buildGameDeletionMount needs the relay session authenticator');
  }
  const router = Router();

  const schema = readClubSchemaConfig(env);
  const accountUsable = Boolean(clubAccount && clubAccount.configured === true);
  let authority = clubStore;
  if (!authority && accountUsable && schema.ok) {
    try { authority = createClubNcbStore({ client: clubAccount, schema: schema.schema }); } catch { authority = null; }
  }
  let store = deletionStore;
  if (!store && accountUsable) {
    try { store = createGameDeletionStore({ client: clubAccount }); } catch { store = null; }
  }

  const configured = Boolean(store && authority);
  const reason = configured ? null
    : (!accountUsable ? 'club_account_unconfigured' : (!schema.ok ? 'club_schema_unconfigured' : 'game_store_construction_failed'));

  const reply = (res, answer) => {
    if (res.headersSent) return;
    return res.status(answer.http).json(answer.body);
  };

  router.delete('/games/:recordedHandId', async (req, res) => {
    /* Express 4 does not catch a rejected handler, so nothing may escape this route: an uncaught throw
     * hangs the socket instead of answering it, and a hung DELETE on a destructive route is worse than a
     * refused one — the caller cannot tell whether any row was removed. Same rule `tournaments/` states
     * for `guarded()`. An unexpected fault can never yield `deleted:true`, because success here comes
     * only from a confirmed read-back. */
    try {
    const gameId = eq(req.params.recordedHandId);

    // 1. session — the existing relay semantics, unchanged.
    let session = null;
    try { session = await authenticate(req); } catch { session = { ok: false, status: 503, code: 'session_service_unavailable' }; }
    if (!session || session.ok !== true || eq(session.id) === '') {
      const status = session?.status === 503 ? 503 : 401;
      const code = status === 503 ? 'session_service_unavailable' : 'auth_error';
      return reply(res, { http: status, body: { status: 'error', error: { code, message: status === 503
        ? 'The session authority could not be reached.' : 'A validated session is required.' } } });
    }

    // Exact-id only, validated before any storage is touched.
    if (!isCanonicalGameId(gameId)) return reply(res, REFUSALS.invalid_game_id());

    // 2. system_admins, through the club store's own authority.
    let verdict = null;
    try { verdict = await authority.isSystemAdmin(session.id); } catch { verdict = { available: false }; }
    if (!verdict || verdict.available !== true) return reply(res, REFUSALS.game_store_unavailable());
    if (verdict.isAdmin !== true) {
      // Denied BEFORE any read of the game, so a non-admin cannot probe which ids exist.
      return reply(res, REFUSALS.not_system_admin());
    }

    if (!store) return reply(res, REFUSALS.game_store_unavailable());

    // 3. the sweep.
    const canonical = await store.findCanonical(gameId);
    if (canonical.storeFailure) {
      return reply(res, canonical.reason.match(UNAVAILABLE_REASONS) ? REFUSALS.game_store_unavailable()
        : REFUSALS.incomplete(canonical.reason));
    }

    if (!canonical.row) {
      // Never 404 a repeat delete: the answer is the idempotent success. `noTraceRemaining` reports only
      // that nothing mentioning this id was found — it cannot claim the game never existed, because a
      // completed sweep looks identical without a tombstone table (see gameDeletion.js).
      const traces = await store.countSatellites([gameId]);
      const noTrace = traces.storeFailure ? false : traces.total === 0;
      const answer = deletionResult({ removed: {}, replayChildren: 0, alreadyAbsent: true, noTraceRemaining: noTrace, confirmedGone: true });
      if (typeof onAudit === 'function') onAudit(auditRecord({ adminUserId: session.id, gameId, result: answer.body.data }));
      return reply(res, answer);
    }

    const children = await store.findChildren(gameId);
    if (children.storeFailure) {
      return reply(res, children.reason.match(UNAVAILABLE_REASONS) ? REFUSALS.game_store_unavailable()
        : REFUSALS.incomplete(children.reason));
    }

    const plan = planGameDeletion({ gameId, canonical: canonical.row, children: children.rows });
    if (plan.ok !== true) {
      if (plan.refusal) {
        const r = plan.refusal;
        return reply(res, { http: r.http, body: { status: 'error', error: { code: r.code, message: r.message } } });
      }
      const answer = deletionResult({ alreadyAbsent: true, noTraceRemaining: true, confirmedGone: true });
      return reply(res, answer);
    }

    const executed = await store.execute({ canonicalId: plan.canonicalId, replayChildIds: plan.replayChildIds });
    if (executed.failure) {
      const f = executed.failure;
      // A partial sweep is NEVER a success. The canonical row is still present (steps run satellites
      // first), so the caller can retry the identical request and finish the job.
      const code = TRANSPORT_REASONS.test(f.reason || '') ? 'club_store_unavailable' : 'game_deletion_incomplete';
      const http = code === 'club_store_unavailable' ? 503 : 502;
      const detail = `${f.step || 'sweep'}: ${eq(f.detail) || eq(f.reason)}`;
      if (typeof onAudit === 'function') {
        onAudit({ ...auditRecord({ adminUserId: session.id, gameId, result: { deleted: false, alreadyAbsent: false, removed: f.removedSoFar ?? null, replayChildren: 0 } }), failure: detail });
      }
      return reply(res, { http, body: { status: 'error', error: { code, message: `Nothing was reported as deleted. ${detail}` } } });
    }

    /* Coach flags are counted AFTER the sweep so the number describes what is actually left pointing at
     * a deleted game. An unreadable count is reported as `unavailable`, never as a confident 0: an
     * administrator reading "0 flags" when the read failed would draw the opposite conclusion from the
     * truth, which is the refused-vs-empty failure this codebase already refuses to make twice. */
    const flagged = typeof store.countCoachFlags === 'function'
      ? await store.countCoachFlags([plan.canonicalId, ...plan.replayChildIds])
      : { count: 0, unavailable: true };
    const answer = deletionResult({
      removed: executed.result.removed,
      replayChildren: executed.result.replayChildren,
      // A failed count is reported as unknown (null), never as a confident 0.
      preserved: { coachFeedbackFlags: flagged?.unavailable ? null : (flagged?.count ?? 0) },
      alreadyAbsent: false,
      confirmedGone: true
    });
    if (typeof onAudit === 'function') onAudit(auditRecord({ adminUserId: session.id, gameId, result: answer.body.data }));
    return reply(res, answer);
    } catch (error) {
      // Named, non-sensitive, and never a success: an internal fault says the deletion state is unknown
      // rather than claiming anything about rows. No error text from the vendor is echoed here.
      return reply(res, {
        http: 502,
        body: { status: 'error', error: { code: 'game_deletion_incomplete', message: 'The deletion could not be completed. The game is still recorded; retry the same request.' } }
      });
    }
  });

  return {
    router,
    configured,
    reason,
    account: clubAccount || null,
    status: () => ({ configured, reason, routes: 1 }),
    routes: GAME_DELETION_ROUTES,
    // Exported for the gate: the names this route will actually use, so a test cannot pass against a
    // table or column the code never reads.
    tables: GAME_TABLES,
    columns: GAME_COLUMNS
  };
}

/** The `/health` view: booleans and a count. No table names, no ids, no credential. */
function gameDeletionHealth(mount) {
  if (!mount) return { configured: false, reason: 'game_deletion_mount_not_built', routes: 0 };
  return { configured: mount.configured === true, reason: mount.reason ?? null, routes: 1 };
}

module.exports = { buildGameDeletionMount, gameDeletionHealth, GAME_DELETION_ROUTES };
