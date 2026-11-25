'use strict';

/*
 * games/gameDeletionStore.js — the sweep, executed on the DEDICATED SERVICE ACCOUNT.
 *
 * Every read and write here runs through the same `clubs/ncbAccountClient.js` instance the club and
 * tournament features use. No caller bearer ever reaches NCB on this path: on this deployment the game
 * tables are `shared_readwrite`, which means a bearer proves a SESSION and not a PERMISSION, so a
 * caller-scoped delete would authorize nothing (that is the existing relay's defect, assessed in the
 * report). Authorization was decided by the mount before this file was entered.
 *
 * THREE RULES THE CODE IS BUILT AROUND.
 *   1. NCB has no transactions. So the order is satellites-first, canonical-LAST (`SWEEP_STEPS`), and any
 *      failing step STOPS the sweep: the canonical row survives as the marker that the deletion is
 *      unfinished, and the same request re-executed completes it. Every step is equality-filtered and
 *      delete-by-row-id, so re-runs are no-ops rather than second deletions.
 *   2. A delete call is not a delete. Every table is RE-READ after its removals and the row count is
 *      reported only if the filter now returns nothing. A send-without-removal is a failure, not a 200.
 *   3. No filter ever goes wider than one id. `null`/empty ids throw instead of issuing an unfiltered
 *      request, because an unfiltered delete on a shared table is a bulk deletion wearing a filter.
 *   4. A reference match is not an ownership claim. `root_hand_id` names a chain's FIRST row, so a filter
 *      on the deleted game's id selects OTHER players' publications and replay attempts. The mount audits
 *      every row `findSatellites` can return and refuses before entering this file, and `execute` repeats
 *      the same per-row test at the moment of deletion — the backstop is here because a row written
 *      between the audit and the sweep must still not be removable. (§4b of `gameDeletion.js`.)
 */

const { GAME_TABLES, GAME_COLUMNS, COACH_FLAG_TABLE, exactRowOps, SWEEP_PROBES, INVENTORY_PROBES, RETAINED_EVIDENCE_PROBES, MULTI_COLUMN_SATELLITE, classifySatellites, satelliteRefusal } = require('./gameDeletion.js');

const READ = (table, query) => ({ group: 'data', path: `read/${table}${query ? `?${query}` : ''}`, method: 'GET' });
const REMOVE = (table, id) => ({ group: 'data', path: `delete/${table}/${encodeURIComponent(id)}`, method: 'DELETE' });

const eq = (value) => String(value ?? '').trim();
const MAX_ROWS_PER_TABLE = 1000;

/**
 * A refusal object, in the shape the mount maps to an HTTP answer. Nothing here throws past a crash.
 *
 * `storageStatus` is the vendor's HTTP status when one was received, or null when the storage was never
 * reached. It travels with the failure because the reason name alone cannot separate "NCB answered 403"
 * from "NCB answered 500" from "the fetch timed out", and those three need three different sentences. The
 * number is metadata, not record content, so it is safe to log and safe to return.
 */
const storeFailure = (reason, detail, storageStatus = null) => ({
  storeFailure: true,
  reason: eq(reason) || 'game_store_request_failed',
  detail: eq(detail),
  storageStatus: Number.isInteger(Number(storageStatus)) && Number(storageStatus) > 0 ? Number(storageStatus) : null
});

/**
 * The mid-sweep ownership stop. `partial` is true because other satellites may already be gone: the
 * message must not promise "nothing was deleted" when that is no longer the state, and the mount maps
 * this reason to 409 with the same code the preflight uses.
 */
const foreignSatelliteFailure = ({ key, column = null, blocked }) => ({
  ...storeFailure('foreign_satellite_owners', satelliteRefusal(blocked, { partial: true }).message),
  step: key,
  column,
  // The verdict travels with the failure so the mount can rebuild the same precise message the preflight
  // would have produced — including whether the game's OWN owner is the unreadable part.
  verdict: blocked,
  foreignCount: blocked.foreignCount,
  unverifiableCount: blocked.unverifiableCount
});

function rowsOf(body) {
  if (body && typeof body === 'object' && !Array.isArray(body) && 'status' in body && body.status !== 'success') return null;
  if (Array.isArray(body?.data)) return body.data;
  if (Array.isArray(body)) return body;
  return null;
}

/**
 * @param {object} options
 * @param {object} options.client  a configured service-account client (`clubMount.account`)
 * @param {number} [options.rowLimit]
 */
function createGameDeletionStore({ client, rowLimit = 200 } = {}) {
  if (!client?.configured) throw new TypeError('createGameDeletionStore needs a configured service-account client');

  async function run(spec) {
    const answer = await client.request(spec);
    if (!answer.ok) return storeFailure(answer.reason || 'game_store_request_failed', answer.detail, answer.httpStatus);
    return { body: answer.body };
  }

  /** Rows for one exact equality filter, or a refusal. Never an empty list standing in for a failure. */
  async function findBy(table, column, value, extra = '') {
    const id = eq(value);
    if (id === '') throw new Error(`gameDeletionStore refused an unfiltered read on ${table}.${column}`);
    const result = await run(READ(table, `${column}=${encodeURIComponent(id)}&limit=${Math.min(rowLimit, MAX_ROWS_PER_TABLE)}${extra}`));
    if (result.storeFailure) return result;
    const rows = rowsOf(result.body);
    if (rows === null) return { ...storeFailure('game_read_unreadable', `the read of ${table} did not return a row set`), column };
    // Re-assert the filter locally. A backend that ignored the filter would otherwise turn a
    // single-game sweep into a bulk delete, and this route must not be able to do that even by accident.
    const matched = rows.filter((row) => eq(row?.[column]) === id);
    return { rows: matched };
  }

  /** Delete each row by its own id, then PROVE it is gone by re-reading the same filter. */
  async function removeRows({ table, column, value, rows }) {
    const ids = exactRowOps(rows);
    if (ids.length !== rows.length) {
      return { ...storeFailure('game_row_id_unusable', `${table} returned a row without an addressable id; nothing was deleted from it`), column };
    }
    for (const id of ids) {
      const removed = await run(REMOVE(table, id));
      if (removed.storeFailure) return { ...removed, table, column };
    }
    const after = await findBy(table, column, value);
    if (after.storeFailure) return { ...after, table, column };
    if (after.rows.length > 0) {
      return {
        ...storeFailure('game_delete_unconfirmed',
          `${after.rows.length} row(s) of ${table} are still present after the delete calls; nothing was reported as removed`),
        column
      };
    }
    return { removed: ids.length };
  }

  /** Rows of a table that reference one of the sweep's ids, deduplicated by row id. */
  async function rowsForAny(table, column, ids) {
    const seen = new Map();
    for (const id of ids) {
      const found = await findBy(table, column, id);
      if (found.storeFailure) return found;
      for (const row of found.rows) {
        const rowId = eq(row?.id);
        if (rowId !== '' && !seen.has(rowId)) seen.set(rowId, row);
      }
    }
    return { rows: [...seen.values()] };
  }

  const C = GAME_COLUMNS;
  const T = GAME_TABLES;
  const COACH = COACH_FLAG_TABLE;

  async function findCanonical(gameId) {
    const found = await findBy(T.recordedHands, C.recordedHands.id, gameId);
    if (found.storeFailure) return found;
    return { row: found.rows[0] ?? null };
  }

  /*
   * Children are rows that reference this game by EITHER chain column, deduplicated by row id.
   * Searching only `root_hand_id` is the bug this comment exists to prevent: root_hand_id points at the
   * chain's FIRST row, while parent_hand_id points at the previous one. So when the game being deleted is
   * itself a replay (root_hand_id = some older row), its child has parent_hand_id = this id and
   * root_hand_id = that older row — invisible to a root-only search, and left dangling by the sweep.
   */
  async function findChildren(gameId) {
    const byId = new Map();
    for (const column of [C.recordedHands.rootHandId, C.recordedHands.parentHandId]) {
      const found = await findBy(T.recordedHands, column, gameId);
      if (found.storeFailure) return found;
      for (const row of found.rows) {
        const rowId = eq(row[C.recordedHands.id]);
        // A row that IS the canonical game can never be its own child; dropping any self-reference keeps
        // a weird stored value from turning the canonical row into a "descendant".
        if (rowId !== '' && rowId !== eq(gameId) && !byId.has(rowId)) byId.set(rowId, row);
      }
    }
    return { rows: [...byId.values()] };
  }

  /**
   * Coach flags that reference this chain — counted and reported, never deleted (see rules module).
   * Deduplicated by row id: a flag typically carries the SAME value in hand_id and root_hand_id, so
   * summing per-column hits would report one flag twice. That is the same trap the community publication
   * sweep avoids, and the gate caught it here by asserting an exact count rather than a non-zero one.
   */
  async function countCoachFlags(ids) {
    const seen = new Set();
    for (const column of [COACH.handId, COACH.rootHandId]) {
      for (const id of ids) {
        const found = await findBy(COACH.table, column, id);
        if (found.storeFailure) return { unavailable: true, count: seen.size };   // unknown, never a confident 0
        for (const row of found.rows) {
          const rowId = eq(row?.id);
          if (rowId !== '') seen.add(rowId);
        }
      }
    }
    return { count: seen.size };
  }

  /**
   * Every satellite row the sweep can select, grouped by table key and deduplicated by row id. Driven by
   * `SWEEP_PROBES`, which is the same list `execute` deletes from — so an added probe is audited on the
   * day it is added instead of becoming the next silent cascade.
   */
  async function findSatellites(ids) {
    const groups = {};
    for (const probe of SWEEP_PROBES) {
      const table = T[probe.key];
      const column = C[probe.key] && C[probe.key][probe.column];
      if (!table || !column) {
        return {
          ...storeFailure('game_read_unreadable', `the deletion inventory declares no column for ${probe.key}.${probe.column}`),
          step: probe.key, column: eq(probe.column) || null
        };
      }
      const found = await rowsForAny(table, column, ids);
      if (found.storeFailure) return { ...found, step: probe.key };
      const seen = groups[probe.key] || new Map();
      for (const row of found.rows) {
        const rowId = eq(row?.id);
        if (rowId !== '' && !seen.has(rowId)) seen.set(rowId, row);
      }
      groups[probe.key] = seen;
    }
    const out = {};
    for (const key of Object.keys(groups)) out[key] = [...groups[key].values()];
    return { groups: out };
  }

  /**
   * Satellite count without deleting — used to tell "already swept" from "never existed", and to answer
   * `noTraceRemaining` honestly.
   *
   * It iterates INVENTORY_PROBES (swept columns PLUS deliberately retained ones), not SWEEP_PROBES: a
   * retained flag-snapshot ledger row still NAMES the deleted game, so claiming "nothing mentioning this id
   * remains" while it stands would be the same false absence proof that hid the residue in the first
   * production deletion. Retained rows are never removed; they are simply not invisible.
   */
  async function countSatellites(ids) {
    // Every table AND column the cascade knows about is probed, or a game that still has a satellite row
    // could be reported as "no trace remaining" — the one claim this function exists to make honestly.
    let total = 0;
    const counted = new Set();
    let unique = 0;
    for (const probe of INVENTORY_PROBES) {
      const found = await rowsForAny(T[probe.key], C[probe.key][probe.column], ids);
      if (found.storeFailure) return found;
      // rowsForAny deduplicates within one column, so a row matched by two probes of the same table would
      // still count twice across probes. `total` is a count of ROWS, not of matches.
      for (const row of found.rows) counted.add(eq(row?.id) || `${probe.key}:${++unique}`);
      total = counted.size;
    }
    return { total };
  }

  /**
   * The rows the cascade deliberately keeps: trace rows linked to the chain only through `root_hand_id`,
   * which is where an Auction Review flag's full request/response audit lives
   * (`persistTracesForFlag` → `loadTracesByBoard`, referenced by `coach_feedback_flags`). Counted and
   * reported, NEVER deleted — the same disposition as the flag row itself. An unreadable count is
   * `unavailable`, never a confident 0.
   */
  async function countRetainedEvidence(ids) {
    const seen = new Set();
    for (const probe of RETAINED_EVIDENCE_PROBES) {
      const found = await rowsForAny(T[probe.key], C[probe.key][probe.column], ids);
      if (found.storeFailure) return { unavailable: true, count: seen.size };
      for (const row of found.rows) {
        const rowId = eq(row?.id);
        if (rowId !== '') seen.add(rowId);
      }
    }
    return { count: seen.size };
  }

  /**
   * Execute the plan. Returns `{ result }` on a confirmed sweep, `{ failure }` on any stop, never a
   * partial success. `removedSoFar` is returned with the failure so a retry (and an operator) can see
   * exactly what state the data is in.
   *
   * `ownerId` is the canonical game's owner. It is re-tested per row here, not only by the mount's
   * preflight, because the preflight and the sweep are two reads: a row that is not owned by the game's
   * owner stops the sweep at that row rather than being deleted.
   */
  async function execute({ canonicalId, replayChildIds, ownerId = '' }) {
    const ids = [canonicalId, ...replayChildIds];
    const removed = { recordedHands: 0, communityGames: 0, analysisReports: 0, decisionTraces: 0, tournamentAttempts: 0, replayAttempts: 0 };

    // 1-4: satellites keyed to any id in scope, by exact equality, one PROBE at a time. `SWEEP_PROBES` is
    // the whole scope declaration and this loop reads nothing else, so a table listed there with two
    // reference columns (traces, replay attempts) is swept by both — a row that names only the chain root
    // still describes a game that is about to stop existing. The gate asserts every reference column
    // `GAME_COLUMNS` declares for a satellite is present in that list, which is what turns "declared but
    // never probed" from a silent omission into a red arm.
    for (const probe of SWEEP_PROBES) {
      if (probe.key === MULTI_COLUMN_SATELLITE) continue;
      await sweepTable({ key: probe.key, probeColumn: probe.column, table: T[probe.key], column: C[probe.key][probe.column], ids, ownerId, removed });
      if (removed.__failure) break;
    }
    if (removed.__failure) {
      const failure = removed.__failure;
      delete removed.__failure;
      return { failure, removedSoFar: removed };
    }

    async function sweepTable({ key, probeColumn = null, table, column, ids: targetIds, ownerId: owner, removed: tally }) {
      const named = (extra) => ({ ...extra, step: key, probeColumn, removedSoFar: { ...tally } });
      for (const id of targetIds) {
        const found = await findBy(table, column, id);
        if (found.storeFailure) { tally.__failure = named(found); return; }
        if (found.rows.length === 0) continue;
        // Only rows whose column really equals this id are deleted (`findBy` already re-asserted it), so
        // a trace whose recorded_hand_id is NULL is reached only by the root-hand probe, never by this one.
        // This is the per-write backstop: a row written between the mount's preflight and this moment is
        // re-tested here, so a foreign-owned row cannot be deleted even when the audit cleared the set.
        const audit = classifySatellites({ ownerId: owner, groups: { [key]: found.rows } });
        if (audit.blocked) { tally.__failure = named(foreignSatelliteFailure({ key, column, blocked: audit })); return; }
        const done = await removeRows({ table, column, value: id, rows: found.rows });
        if (done.storeFailure) { tally.__failure = named(done); return; }
        tally[key] += done.removed;
      }
    }

    // 4: community publications. The contract's "source_hand_id = id OR root_hand_id = id" cannot be one
    // NCB query (no OR in its grammar), so it is two equality passes over the same id set, deduplicated
    // by row id so a row matching both is counted and deleted exactly once.
    const communityRows = new Map();
    const communityColumns = SWEEP_PROBES
      .filter((probe) => probe.key === MULTI_COLUMN_SATELLITE)
      .map((probe) => C[MULTI_COLUMN_SATELLITE][probe.column]);
    for (const id of ids) {
      for (const column of communityColumns) {
        const found = await findBy(T.communityGames, column, id);
        if (found.storeFailure) return { failure: { ...found, step: 'communityGames', removedSoFar: { ...removed } } };
        for (const row of found.rows) {
          const rowId = eq(row.id);
          if (rowId !== '' && !communityRows.has(rowId)) communityRows.set(rowId, row);
        }
      }
    }
    const publications = [...communityRows.values()];
    if (publications.length > 0) {
      // Same backstop as the generic sweep, over the whole deduplicated set: a publication belonging to
      // another account is the single most likely foreign row, because publishing someone's replay is a
      // normal thing for that player to do.
      const audit = classifySatellites({ ownerId, groups: { communityGames: publications } });
      if (audit.blocked) return { failure: foreignSatelliteFailure({ key: 'communityGames', blocked: audit }), removedSoFar: { ...removed } };
      const ids2 = exactRowOps(publications);
      if (ids2.length !== publications.length) {
        return { failure: storeFailure('game_row_id_unusable', 'community_games returned a row without an addressable id'), step: 'communityGames', removedSoFar: { ...removed } };
      }
      for (const rowId of ids2) {
        const done = await run(REMOVE(T.communityGames, rowId));
        if (done.storeFailure) return { failure: { ...done, step: 'communityGames', removedSoFar: { ...removed } } };
      }
      const still = await readBackPublications(ids);
      if (still.storeFailure) return { failure: { ...still, step: 'communityGames', removedSoFar: { ...removed } } };
      if (still.count > 0) {
        return { failure: storeFailure('game_delete_unconfirmed', `${still.count} community row(s) remain after the delete calls`), step: 'communityGames', removedSoFar: { ...removed } };
      }
      removed.communityGames = ids2.length;
    }

    // 5: replay children (same-owner only; the plan refused anything else), each by its own row id.
    for (const childId of replayChildIds) {
      const done = await run(REMOVE(T.recordedHands, childId));
      if (done.storeFailure) return { failure: { ...done, step: 'replayChildren', removedSoFar: { ...removed } } };
      const still = await findBy(T.recordedHands, C.recordedHands.id, childId);
      if (still.storeFailure) return { failure: { ...still, step: 'replayChildren', removedSoFar: { ...removed } } };
      if (still.rows.length > 0) {
        return { failure: storeFailure('game_delete_unconfirmed', 'a replay descendant is still present'), step: 'replayChildren', removedSoFar: { ...removed } };
      }
      removed.recordedHands += 1;
    }

    // 6: the canonical row LAST, then proof.
    const gone = await run(REMOVE(T.recordedHands, canonicalId));
    if (gone.storeFailure) return { failure: { ...gone, step: 'recordedHand', removedSoFar: { ...removed } } };
    const verify = await findBy(T.recordedHands, C.recordedHands.id, canonicalId);
    if (verify.storeFailure) return { failure: { ...verify, step: 'recordedHand', removedSoFar: { ...removed } } };
    if (verify.rows.length > 0) {
      return { failure: storeFailure('game_delete_unconfirmed', 'the canonical game row is still present after the delete call'), step: 'recordedHand', removedSoFar: { ...removed } };
    }
    removed.recordedHands += 1;

    return { result: { removed, replayChildren: replayChildIds.length } };
  }

  async function readBackPublications(ids) {
    let count = 0;
    for (const id of ids) {
      for (const column of [C.communityGames.sourceHandId, C.communityGames.rootHandId]) {
        const found = await findBy(T.communityGames, column, id);
        if (found.storeFailure) return found;
        count += found.rows.length;
      }
    }
    return { count };
  }

  return { findCanonical, findChildren, findSatellites, countSatellites, countRetainedEvidence, countCoachFlags, execute, readBackPublications };
}

module.exports = { createGameDeletionStore, rowsOf, MAX_ROWS_PER_TABLE };
