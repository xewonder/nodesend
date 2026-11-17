'use strict';

/*
 * ONE-TIME SUPER-ADMIN BOOTSTRAP
 *
 * WHY THIS EXISTS. `system_admins` is the only authority for the Super Admin role, and an empty
 * table means nobody can add the first row: every route that could insert one already requires a
 * Super Admin. Some first-run path is unavoidable. The one taken here is deliberately the narrowest
 * shape available — an operation that can only ever grant ONE pre-chosen identity, can only fire
 * while the table is EMPTY, and is inert for everyone once it has succeeded.
 *
 * THE IDENTITY IS NEVER A PARAMETER. The caller is proven by their own validated NCB session
 * (`authenticate`, the relay's single session resolver) and the ONLY admissible grant target is
 * `CLUB_BOOTSTRAP_SUPER_ADMIN_USER_ID`, read from the server environment. The request body is
 * rejected if it carries ANY field, so there is nothing to forge: a caller cannot name a victim,
 * cannot name themselves, and cannot ask a question. The most a forged request can achieve is a 400.
 *
 * WHY THE TABLE-EMPTY GATE IS THE REAL CONTROL. Once any row exists the endpoint refuses everyone,
 * including the configured id. So this operation can never displace, override or add to an existing
 * authority — the only state in which it acts is "there is no authority at all yet". It also means
 * the endpoint is self-retiring: a completed bootstrap needs no urgent second change, and removing
 * the environment variable afterwards is hygiene, not damage control.
 *
 * WHY A RACE CANNOT GRANT ANYONE ELSE. Because the target comes from configuration and not from the
 * request, every concurrent would-be bootstrap is trying to insert the SAME user id. The worst a
 * race can produce is a duplicate row for the one person the operator already chose — never a
 * foreign grant. It is still prevented (single-flight) and still detected (the post-insert check
 * requires exactly one row), and it is fail-closed rather than best-effort: a table this endpoint
 * cannot read is a table it will not write.
 *
 * SINGLE-REPLICA ASSUMPTION, stated because it is load-bearing: the serialization here is in-process
 * (one promise, plus the latched result), which is sufficient for the one-replica deployment this
 * relay is built for — the same assumption `/health` prints as `quota.replicas`. Two replicas that
 * race would be caught by the "exactly one row" check and reported, not silently accepted.
 *
 * NOTHING SECRET IS READ, RETURNED OR LOGGED: no account token, no password, no NCB host, no other
 * user's row.
 */

const { Router } = require('express');

const ID = /^[A-Za-z0-9_-]{1,32}$/;
const BOOTSTRAP_PATH = '/clubs/bootstrap/super-admin';

// The declared surface of this module, kept separate from CLUB_ROUTES on purpose: CLUB_ROUTES is
// the permanent client contract, and counting a temporary activation route inside it would make
// /health.clubs.routes a number that changes when the feature is switched off.
const BOOTSTRAP_ROUTES = Object.freeze([
  { op: 'bootstrapSuperAdmin', method: 'POST', path: BOOTSTRAP_PATH, temporary: true }
]);

/**
 * @param {object} options
 * @param {object|null} options.store       the privileged club store (or null: nothing is writable)
 * @param {Function} options.authenticate   the relay's own session resolver
 * @param {object} [options.env]
 * @param {Function} [options.now]
 */
function createClubBootstrapRouter({ store = null, authenticate, env = process.env, now = Date.now } = {}) {
  if (typeof authenticate !== 'function') {
    throw new TypeError('createClubBootstrapRouter needs the session authenticator');
  }
  const router = Router();

  // Latched on success OR on discovering a non-empty table. In-memory, so a restart re-reads the
  // truth from system_admins — which is the authority; this is only the fast path.
  let completed = null;
  // Single-flight: concurrent callers await one attempt rather than each performing their own
  // read-then-write.
  let inflight = null;

  const configuredId = () => String(env.CLUB_BOOTSTRAP_SUPER_ADMIN_USER_ID ?? '').trim();

  function send(res, status, body) {
    if (res.headersSent) return;
    return void res.status(status).json(body);
  }

  async function handle(req, res) {
    // Any body at all is refused. This route takes no input, and a route that "ignores" an
    // unexpected field is a route a future edit will start reading.
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      return void send(res, 400, {
        error: 'client_identity_refused',
        detail: 'The bootstrap takes no input; the granted id comes from the server environment and the caller from the session.'
      });
    }
    const queryKeys = Object.keys(req.query ?? {});
    if (queryKeys.length) {
      return void send(res, 400, { error: 'client_identity_refused', detail: `Unexpected query field(s): ${queryKeys.join(', ')}` });
    }

    const target = configuredId();
    if (target === '') {
      // Disabled, and said so plainly. A 404 here would read as "NodeSend has no bootstrap",
      // which is a different and less actionable statement.
      return void send(res, 503, {
        error: 'club_bootstrap_disabled',
        detail: 'CLUB_BOOTSTRAP_SUPER_ADMIN_USER_ID is not set, so no bootstrap can be performed on this deployment.'
      });
    }
    if (!ID.test(target)) {
      return void send(res, 503, {
        error: 'club_bootstrap_misconfigured',
        detail: 'CLUB_BOOTSTRAP_SUPER_ADMIN_USER_ID is not a valid user id (1-32 characters of A-Z a-z 0-9 _ -).'
      });
    }

    if (completed) {
      return void send(res, 409, { error: 'bootstrap_already_completed', detail: 'This process has already completed a bootstrap; the operation is closed.' });
    }

    let session = null;
    try {
      session = await authenticate(req);
    } catch {
      session = null;
    }
    if (!session || session.ok === false) {
      const status = session && session.status === 503 ? 503 : 401;
      return void send(res, status, {
        error: status === 503 ? 'session_service_unavailable' : 'authentication_required',
        detail: 'A validated BridgeMind session is required for the bootstrap.'
      });
    }
    const callerId = String(session.id);

    if (!store) {
      return void send(res, 503, {
        error: 'club_store_unavailable',
        detail: 'Club storage is not configured, so system_admins can be neither read nor written.'
      });
    }

    if (inflight) return void send(res, ...(await inflight));

    const attempt = (async () => {
      // (6) READ FIRST, and fail closed on an unreadable result. Assuming "empty" because the read
      // failed would be the one mistake that can grant a stranger.
      let state = null;
      try {
        state = await store.readSystemAdmins();
      } catch {
        state = { available: false, userIds: [], reason: 'read_threw' };
      }
      if (!state || state.available !== true) {
        return [503, {
          error: 'club_store_unavailable',
          detail: `system_admins could not be read (${state?.reason ?? 'unreadable'}), so nothing was written.`
        }];
      }
      if (state.userIds.length > 0) {
        // Non-empty is terminal, whether or not the configured id is among them. A table that
        // already has an authority is not this endpoint's to extend or to argue with.
        completed = { at: now(), reason: 'table_not_empty' };
        return [409, {
          error: 'bootstrap_already_completed',
          detail: `system_admins already holds ${state.userIds.length} row(s); the bootstrap only runs on an empty table.`
        }];
      }

      // (4)(5) The verified caller must BE the configured identity. Compared as trimmed strings;
      // nothing about the configured value is echoed back beyond the caller's own id, which the
      // caller already knows.
      if (callerId !== target) {
        return [403, {
          error: 'bootstrap_caller_mismatch',
          detail: `This session's verified user id is ${callerId}; the bootstrap grants only the id configured on the server.`,
          own_user_id: callerId
        }];
      }

      // (8) Insert through the dedicated account, then read the row back. Success is a row NCB
      // confirms, never a 2xx from the write call.
      const created = await store.createSystemAdmin(target);
      if (created?.unavailable) {
        return [503, { error: 'club_store_unavailable', detail: 'the system_admins write could not be confirmed by the club account.' }];
      }
      // "The insert was refused" and "the insert was accepted but no row can be found" are kept
      // apart on purpose. The first is safe to retry; the second may have landed, so the operator
      // must LOOK before trying again — collapsing them into one failure would invite a blind retry
      // that is exactly how a duplicate authority row gets created.
      if (created?.error === 'write_unverified') {
        return [502, {
          error: 'bootstrap_unverified',
          detail: `the write was acknowledged but the row was not found afterwards: ${created.detail ?? ''}. Inspect system_admins before retrying.`
        }];
      }
      if (created?.error) {
        return [502, { error: 'bootstrap_write_failed', detail: String(created.detail ?? created.error) }];
      }
      const after = await store.readSystemAdmins();
      if (!after?.available) {
        // The write may have landed and we cannot prove it. Say that, and do not latch: the next
        // call re-reads and the non-empty gate decides, so this can never double-grant.
        return [502, { error: 'bootstrap_unverified', detail: 'the row was written but system_admins could not be read back to confirm it.' }];
      }
      const ours = after.userIds.filter((id) => id === target).length;
      if (after.userIds.length !== 1 || ours !== 1) {
        return [502, {
          error: 'bootstrap_unverified',
          detail: `expected exactly one system_admins row for the granted id; found ${after.userIds.length} row(s) with ${ours} for that id. Fix the table before continuing.`
        }];
      }
      completed = { at: now(), userId: target };
      return [200, {
        status: 'success',
        data: { bootstrapped: true, user_id: target, system_admin_rows: after.userIds.length }
      }];
    })().then((reply) => {
      inflight = null;
      return reply;
    });
    inflight = attempt;
    return void send(res, ...(await attempt));
  }

  router.post(BOOTSTRAP_PATH, (req, res) => {
    handle(req, res).catch((error) => {
      // Nothing may propagate: Express 4 does not catch a rejected handler, and an uncaught throw
      // would hang the socket instead of answering it.
      if (!res.headersSent) {
        res.status(503).json({ error: 'club_bootstrap_failed', detail: `the bootstrap aborted before it could be answered (${error?.name || 'Error'})` });
      }
    });
  });

  // Exposed for the health view and for tests: the state that decides whether this can still run.
  router.__bootstrapState = () => ({
    enabled: configuredId() !== '',
    targetConfigured: ID.test(configuredId()),
    completed: Boolean(completed),
    inflight: Boolean(inflight)
  });

  return router;
}

module.exports = { createClubBootstrapRouter, BOOTSTRAP_ROUTES, BOOTSTRAP_PATH };
