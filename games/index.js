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
  isCanonicalGameId, planGameDeletion, deletionResult, REFUSALS, auditRecord, GAME_COLUMNS, GAME_TABLES,
  sweepTargetIds, checkSatelliteOwnership, incompleteDeletion, classifyStoreFailure, failureWhere
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
 * THREE DIFFERENT FAILURES, THREE DIFFERENT SENTENCES.
 *
 * A storage that was never reached (session, transport, configuration, an unreadable read) means retrying
 * later is the right instruction, and 503 says that. A storage that was reached and ANSWERED — 403 refused,
 * 5xx error, or a 2xx that removed nothing — means the cascade stopped with rows already gone, and 502
 * `game_deletion_incomplete` says that. Conflating them is what made an unusable feature look like a
 * transient one: the deployed build enumerated four transport names, so `club_account_identity_*` (a session
 * that could not be established, nothing written) fell through to 502, and the refusal copy told the
 * administrator to "retry the same request to finish the cleanup" about a permission grant that a retry can
 * never change.
 *
 * The classes and their wording live in `gameDeletion.js`, which owns the rules; this file only decides
 * which step the route was in. Both the response body and the audit record come from the SAME builder, so
 * the log and the answer cannot disagree. Every class remains retry-safe, because the sweep is
 * satellites-first and the canonical row survives either way.
 */
const storeUnreachable = (reason) => classifyStoreFailure(reason) === 'storage_unreachable';

/**
 * The same answer for a read that failed before the sweep, named by the phase it stopped in. It returns the
 * fault alongside the reply so the audit record and the API body come from ONE construction — building the
 * description twice is how a log line and an answer start disagreeing about where the sweep stopped.
 */
const readRefusal = (failure, phase) => {
  const answer = incompleteDeletion({
    reason: failure.reason,
    step: phase,
    column: failure.column ?? null,
    storageStatus: failure.storageStatus ?? null,
    detail: failure.detail ?? ''
  });
  if (storeUnreachable(failure.reason)) {
    // A storage that was never consulted keeps the existing, already-mapped 503 sentence; the fault object
    // still travels so the log says which step never got a request.
    const refusal = REFUSALS.game_store_unavailable();
    return { http: refusal.http, body: refusal.body, fault: answer.fault };
  }
  return answer;
};

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
    const gameId = eq(req.params.recordedHandId);
    /* Declared outside the try so the catch can still say WHO asked and WHERE it stopped. Without this, an
     * internal fault answered 502 and logged nothing, so an operator reading the log could not tell a
     * refused write from a crash — the absence of a line was the only signal. */
    let session = null;
    /* Which phase the route is in, so a failure — including one that escapes as a throw — can name where
     * the deletion stopped instead of only that it stopped. Never a row, an account or a value. */
    let phase = 'validate';
    try {
    // 1. session — the existing relay semantics, unchanged.
    try { session = await authenticate(req); } catch { session = { ok: false, status: 503, code: 'session_service_unavailable' }; }
    if (!session || session.ok !== true || eq(session.id) === '') {
      const status = session?.status === 503 ? 503 : 401;
      const code = status === 503 ? 'session_service_unavailable' : 'auth_error';
      return reply(res, { http: status, body: { status: 'error', error: { code, message: status === 503
        ? 'The session authority could not be reached.' : 'A validated session is required.' } } });
    }

    // Exact-id only, validated before any storage is touched.
    if (!isCanonicalGameId(gameId)) return reply(res, REFUSALS.invalid_game_id());
    phase = 'authority';

    // 2. system_admins, through the club store's own authority.
    let verdict = null;
    try { verdict = await authority.isSystemAdmin(session.id); } catch { verdict = { available: false }; }
    if (!verdict || verdict.available !== true) return reply(res, REFUSALS.game_store_unavailable());
    if (verdict.isAdmin !== true) {
      // Denied BEFORE any read of the game, so a non-admin cannot probe which ids exist.
      return reply(res, REFUSALS.not_system_admin());
    }

    if (!store) return reply(res, REFUSALS.game_store_unavailable());
    phase = 'canonicalRead';

    // 3. the sweep.
    const canonical = await store.findCanonical(gameId);
    if (canonical.storeFailure) {
      const answer = readRefusal(canonical, phase);
      if (typeof onAudit === 'function') {
        onAudit(auditRecord({ adminUserId: session.id, gameId, result: { deleted: false, alreadyAbsent: false, removed: null, replayChildren: 0 }, fault: answer.fault }));
      }
      return reply(res, answer);
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

    phase = 'childRead';
    const children = await store.findChildren(gameId);
    if (children.storeFailure) {
      const answer = readRefusal(children, phase);
      if (typeof onAudit === 'function') {
        onAudit(auditRecord({ adminUserId: session.id, gameId, result: { deleted: false, alreadyAbsent: false, removed: null, replayChildren: 0 }, fault: answer.fault }));
      }
      return reply(res, answer);
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

    /*
     * 3b. SATELLITE OWNERSHIP — audited here, after the child policy and before the first write.
     *
     * The children are already owner-checked by `planGameDeletion`, but the satellites are selected by
     * REFERENCE columns that name a whole replay chain: `community_games.root_hand_id` and
     * `replay_attempts.root_hand_id` point at the chain's FIRST game, so another player's publication or
     * consumed attempt is matched by a filter on THIS game's id. A reference match is not ownership, and
     * the canonical row's owner is never assumed to extend to them — an unreadable owner fails closed.
     * If the store cannot produce the inventory, the request is refused rather than swept un-audited.
     */
    const ownerId = eq(canonical.row[GAME_COLUMNS.recordedHands.userId]);
    if (typeof store.findSatellites !== 'function') return reply(res, REFUSALS.game_store_unavailable());
    phase = 'satelliteInventory';
    const satellites = await store.findSatellites(sweepTargetIds(plan));
    if (satellites.storeFailure) {
      // The store names the probe it died on when it knows (`decisionTraces`), which is more useful than
      // the route's phase label, so it wins when present.
      const where = eq(satellites.step) || phase;
      const answer = readRefusal(satellites, where);
      if (typeof onAudit === 'function') {
        onAudit(auditRecord({ adminUserId: session.id, gameId, result: { deleted: false, alreadyAbsent: false, removed: null, replayChildren: 0 }, fault: answer.fault }));
      }
      return reply(res, answer);
    }
    const ownership = checkSatelliteOwnership({ ownerId, groups: satellites.groups });
    if (ownership.ok !== true) {
      const r = ownership.refusal;
      return reply(res, { http: r.http, body: { status: 'error', error: { code: r.code, message: r.message } } });
    }

    phase = 'sweep';
    const executed = await store.execute({ canonicalId: plan.canonicalId, replayChildIds: plan.replayChildIds, ownerId });
    if (executed.failure) {
      const f = executed.failure;
      // A row the sweep found that the audit did not clear is a REFUSAL with the same code the preflight
      // uses, not an incomplete-write report: the administrator needs to know which accounts are in the
      // way, and "retry the same request" would be an instruction that can never succeed.
      if (f.reason === 'foreign_satellite_owners') {
        if (typeof onAudit === 'function') {
          onAudit({ ...auditRecord({ adminUserId: session.id, gameId, result: { deleted: false, alreadyAbsent: false, removed: f.removedSoFar ?? null, replayChildren: 0 } }), failure: `${failureWhere({ step: f.step, column: f.column })}: foreign_satellite_owners` });
        }
        return reply(res, REFUSALS.foreign_satellite_owners(f.verdict ?? f, { partial: true }));
      }
      /* A partial sweep is NEVER a success. The canonical row is still present (steps run satellites
       * first), so the caller can retry the identical request and finish the job — UNLESS the class says a
       * retry cannot help (a 403 grant, a row with no id), which is why the class and the storage status
       * travel into both the answer and the log line instead of being flattened into one instruction. */
      const answer = incompleteDeletion({
        reason: f.reason,
        step: f.step,
        column: f.column ?? f.probeColumn ?? null,
        storageStatus: f.storageStatus ?? null,
        detail: f.detail ?? ''
      });
      const where = answer.fault.step;
      const detail = `${where}: ${eq(f.detail) || eq(f.reason)}`;
      if (typeof onAudit === 'function') {
        onAudit({ ...auditRecord({ adminUserId: session.id, gameId, result: { deleted: false, alreadyAbsent: false, removed: f.removedSoFar ?? null, replayChildren: 0 }, fault: answer.fault }), failure: detail });
      }
      return reply(res, { http: answer.http, body: answer.body });
    }

    /* Coach flags are counted AFTER the sweep so the number describes what is actually left pointing at
     * a deleted game. An unreadable count is reported as `unavailable`, never as a confident 0: an
     * administrator reading "0 flags" when the read failed would draw the opposite conclusion from the
     * truth, which is the refused-vs-empty failure this codebase already refuses to make twice. */
    phase = 'flagCount';
    const flagged = typeof store.countCoachFlags === 'function'
      ? await store.countCoachFlags([plan.canonicalId, ...plan.replayChildIds])
      : { count: 0, unavailable: true };
    /* The flag-snapshot ledger rows are counted over the same id set and reported, never removed: they are
     * where an Auction Review flag resolves its full request/response audit
     * (`coach_feedback_flags` keeps only `fullAuditAvailable: true` plus a `decision_id`). Deleting them
     * would leave the preserved flag pointing at a row that no longer exists — the same dangling-reference
     * harm the replay-child rule refuses to create, arriving from the other direction. */
    phase = 'retainedEvidenceCount';
    const snapshots = typeof store.countRetainedEvidence === 'function'
      ? await store.countRetainedEvidence([plan.canonicalId, ...plan.replayChildIds])
      : { count: 0, unavailable: true };
    const answer = deletionResult({
      removed: executed.result.removed,
      replayChildren: executed.result.replayChildren,
      // A failed count is reported as unknown (null), never as a confident 0.
      preserved: {
        coachFeedbackFlags: flagged?.unavailable ? null : (flagged?.count ?? 0),
        flagSnapshotTraces: snapshots?.unavailable ? null : (snapshots?.count ?? 0)
      },
      alreadyAbsent: false,
      confirmedGone: true
    });
    if (typeof onAudit === 'function') onAudit(auditRecord({ adminUserId: session.id, gameId, result: answer.body.data }));
    return reply(res, answer);
    } catch {
      /* Named, non-sensitive, and never a success: an internal fault says the deletion state is unknown
       * rather than claiming anything about rows. No error text from the vendor — and none from the
       * exception — is echoed here, because either can carry a URL, a bearer or a row value. The phase is
       * reported so the answer and the log line agree on where it stopped, and the fault IS logged: a
       * destructive verb whose failure leaves no trace is the diagnostic this route could not offer during
       * the first production refusal. */
      const answer = incompleteDeletion({ reason: 'internal_fault', step: phase });
      if (typeof onAudit === 'function') {
        onAudit(auditRecord({
          adminUserId: eq(session?.id), gameId,
          result: { deleted: false, alreadyAbsent: false, removed: null, replayChildren: 0 },
          fault: answer.fault
        }));
      }
      return reply(res, { http: answer.http, body: answer.body });
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
