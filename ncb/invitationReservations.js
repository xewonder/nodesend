'use strict';

/*
THE INVITATION RESERVATION STORE — the piece that makes single-use a fact of the DATABASE.

What it is: a thin adapter over `invitation_reservations`, an NCB table whose `code_row_id` column
carries a database-enforced UNIQUE constraint. Reserving a record is an INSERT. If two callers aim at
the same `user_codes` record, exactly one INSERT can succeed, because the store refuses the other one —
not because anything in this process remembered to be careful. That is the property the previous design
did not have: an in-process lease dies with the container, and an unconditional REST update has no
compare-and-set, so "the loser fails closed after the fact" was the best it could do.

What the key is, and what it is not. The unique column holds the RECORD ID, never the code value.
`user_codes.code` legitimately repeats — ten rows can carry `123` and that is how bulk codes are
issued — so a UNIQUE on the code string would have destroyed the feature while looking like it was
being protected. Reserving a record does not reserve a code.

States: `pending` (reserved, account not yet created or not yet claimed), `completed` (spent and
linked to an account), `abandoned` (an operator's judgement, never this code's). There is no `expired`
state and no age-based release, deliberately: a reservation that could be stolen because it sat still
is a reservation that can be stolen. Recovery reads state and identity, it never overwrites them.

What is stored, and what never is: the record id, a keyed digest of the normalized invitee email, the
status, and after completion the invitee's user id. Never a password, never an upstream cookie, never a
bearer, never a vendor session identifier. The email digest is a LOOKUP CANDIDATE, not an
authenticator — see ncb/invitationClaim.js for why holding an email proves nothing and how recovery is
actually authorized.
*/

const RESERVED = 'pending';
const COMPLETED = 'completed';
const ABANDONED = 'abandoned';

// A unique-constraint refusal reaches us as prose, because the REST data family has no error code
// table. This is the same signal `clubs/clubNcbStore.js` already relies on for memberships; the
// vendor's documented answer is `400 Duplicate entry`, and 422 is reserved for validation faults, so
// a 422 must NOT be read as "already taken" — that would silently treat a malformed row as a rival.
const DUPLICATE_KEY = /duplicate|unique|constraint|already exists/i;

function textOf(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function looksLikeDuplicate(httpStatus, body, detail) {
  if (httpStatus !== 400) return false;
  // The prose is the signal, and it arrives in different fields depending on which privileged channel
  // carried the request: the native client returns the vendor body, the proxy client returns a
  // whitelisted, redacted `detail`. Reading only one of the two made a duplicate refusal look like a
  // store outage, which is the direction that fails CLOSED — correct, but it turned an ordinary
  // contention into a 503 and made the pool appear broken.
  const text = `${textOf(body?.error)} ${textOf(body?.message)} ${textOf(body?.status)} ${textOf(detail)}`;
  return DUPLICATE_KEY.test(text);
}

/**
 * @param {object} options
 * @param {(spec:{path:string,method?:string,body?:object,query?:string})=>Promise<{ok:boolean,httpStatus?:number,body?:any,reason?:string}>} options.request
 *   the privileged channel — the club service account's own session, the same one the claim write
 *   uses. Nothing here can be reached by a player: `invitation_reservations` is in the gateway's
 *   NEVER_THROUGH_THE_GATEWAY set, so a signed-in account cannot pre-empt reservations and starve
 *   every code in the table.
 * @param {string} [options.table]
 * @param {Function} [options.log]
 * @param {number} [options.storeAttempts]
 *   how often one store operation is driven before it is called a failure. Bounded and small on
 *   purpose: the probe on the disposable table showed a DELETE that failed and then SUCCEEDED on an
 *   explicit retry by primary key (records 8, 12 and 14), so a single attempt is not a failed
 *   operation, it is an unfinished one. It is capped so a wedged store cannot hold a request open
 *   forever — reconciliation stays bounded rather than heroic.
 * @param {number} [options.retryDelayMs] base back-off between those attempts (linear).
 * @param {(ms:number)=>Promise<void>} [options.wait] the sleep, injectable so a harness waits in
 *   nanoseconds instead of real time and can still observe the retry ORDER.
 */
function createInvitationReservations({
  request, table = 'invitation_reservations', log = () => {},
  storeAttempts = 3, retryDelayMs = 200, wait = null
} = {}) {
  const ATTEMPTS = Math.max(1, Math.min(5, Number(storeAttempts) || 1));
  const DELAY_MS = Math.max(0, Math.min(2000, Number(retryDelayMs) || 0));
  const settle = typeof wait === 'function'
    ? wait
    : (ms) => new Promise((resolve) => { const t = setTimeout(resolve, ms); t.unref?.(); });
  const path = (verb, id) => `${verb}/${table}${id ? `/${encodeURIComponent(String(id))}` : ''}`;

  function rowsOf(body) {
    return Array.isArray(body?.data) ? body.data : (body?.data ? [body.data] : []);
  }

  async function readByRecordId(recordId) {
    const res = await request({
      path: path('read'), method: 'GET',
      query: `code_row_id=${encodeURIComponent(String(recordId))}&limit=5`
    });
    if (!res || res.ok !== true) return { ok: false, reason: res?.reason || 'reservation_read_failed' };
    const rows = rowsOf(res.body).filter((r) => String(r?.code_row_id ?? '') === String(recordId));
    return { ok: true, rows };
  }

  /**
   * The atomic step. Returns `{ok:true}` when THIS call created the reservation,
   * `{ok:false, taken:true}` when the record is already reserved by anyone, and
   * `{ok:false}` with a reason when the store could not answer — which is never treated as free.
   */
  async function reserve({ recordId, emailHash }) {
    if (recordId === null || recordId === undefined || recordId === '') return { ok: false, reason: 'no_record_id' };
    const attempt = await request({
      path: path('create'), method: 'POST',
      body: { code_row_id: String(recordId), invitee_email_hash: String(emailHash || ''), status: RESERVED }
    });
    if (attempt && attempt.ok === true) {
      const id = attempt.body?.id ?? attempt.body?.data?.id ?? null;
      log('invitation_reserved', { recordId, reservationId: id });
      return { ok: true, reservationId: id, created: true };
    }
    if (looksLikeDuplicate(attempt?.httpStatus, attempt?.body, attempt?.detail)) {
      // The normal outcome under contention, and the one that must not be logged as an error.
      return { ok: false, taken: true, recordId };
    }
    /* THE ANSWER WE NEVER GOT. A create that times out or dies in transit tells us nothing about
       whether the row landed — and the probe proved this vendor's writes do survive a lost response
       (the reservation records were readable by primary key after the request that made them looked
       to have failed). Retrying the INSERT blindly here would consume a SECOND record for one
       registration, so the store is asked instead: if a row naming this record now carries OUR
       digest, this call already owns it. Only an address digest makes that ours, which is why an
       unkeyed deployment (no HMAC secret, empty digest) reconciles nothing rather than adopting a
       stranger's reservation. */
    if (emailHash) {
      const back = await readByRecordId(recordId);
      if (back && back.ok === true) {
        const mine = (back.rows || []).find((r) => String(r?.invitee_email_hash ?? '') === String(emailHash));
        if (mine) {
          log('invitation_reservation_reconciled_after_lost_response', { recordId, reservationId: mine.id });
          return { ok: true, reservationId: mine.id ?? null, recordId, reconciled: true };
        }
        if ((back.rows || []).length) return { ok: false, taken: true, recordId };
      }
    }
    // A store that cannot answer is not a store that said no. Callers must stop, not proceed
    // unprotected, or an outage silently degrades the design back to a read-then-write.
    return { ok: false, reason: attempt?.reason || 'reservation_store_unavailable', httpStatus: attempt?.httpStatus ?? 0 };
  }

  async function complete({ reservationId, recordId, inviteeUserId }) {
    const target = reservationId ?? (await findIdForRecord(recordId));
    if (!target) return { ok: false, reason: 'reservation_not_found' };
    const body = { status: COMPLETED, invitee_user_id: String(inviteeUserId ?? '') };
    let lastReason = 'reservation_update_failed';
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      const res = await request({ path: path('update', target), method: 'PUT', body });
      if (res && res.ok === true) lastReason = null;
      else lastReason = res?.reason || 'reservation_update_failed';
      // THE READ-BACK IS THE AUTHORITY, not the response. Completion is an idempotent write of two
      // fixed fields to one primary key, so re-driving it after a lost answer is safe, and an update
      // that reported failure but landed is still a completion — reported from what the row says.
      const back = await request({ path: path('read', target), method: 'GET' });
      const row = rowsOf(back?.body)[0] || {};
      if (String(row?.status ?? '') === COMPLETED) {
        log('invitation_reservation_completed', { reservationId: target, attempts: attempt });
        return { ok: true, reservationId: target, attempts: attempt };
      }
      if (attempt < ATTEMPTS) await settle(DELAY_MS * attempt);
    }
    /* Unconfirmed, not denied. The record it describes is already spent and already names this
       account — that half was verified by the claim read-back before this function was called. A
       reservation left `pending` is therefore bookkeeping the recovery route can still finish for
       the SAME account, so this returns rather than throwing, and the caller reports the
       registration as what it is. */
    log('invitation_reservation_completion_unconfirmed', { reservationId: target, reason: lastReason });
    return { ok: false, unconfirmed: true, reason: lastReason, reservationId: target, attempts: ATTEMPTS };
  }

  async function findIdForRecord(recordId) {
    const found = await readByRecordId(recordId);
    return found.ok && found.rows.length ? found.rows[0].id : null;
  }

  /** Recovery candidates in one state. `pending` by default; `completed` is asked for separately. */
  async function forEmailHash(emailHash, status = RESERVED) {
    if (!emailHash) return { ok: true, rows: [] };
    const res = await request({
      path: path('read'), method: 'GET',
      query: `invitee_email_hash=${encodeURIComponent(String(emailHash))}&limit=25`
    });
    if (!res || res.ok !== true) return { ok: false, reason: res?.reason || 'reservation_read_failed' };
    const rows = rowsOf(res.body).filter((r) => String(r?.invitee_email_hash ?? '') === String(emailHash)
      && String(r?.status ?? '') === String(status));
    return { ok: true, rows };
  }

  /**
   * `completed` is queried by the recovery path for one reason: to tell "this registration already
   * finished" apart from "nothing was ever reserved for you". Without that second reading, a client
   * whose sign-up response was lost in transit is told its valid code failed, when the truth is that
   * it succeeded a minute ago — and the retry writes nothing either way.
   */
  async function pendingForEmailHash(emailHash) {
    return forEmailHash(emailHash, RESERVED);
  }

  /**
   * Release a reservation THIS call created, and only when the record it holds was never spent.
   *
   * This is not an age-based release and it is not somebody else's reservation: it takes the id our
   * own INSERT returned, and refuses if the `user_codes` record now says otherwise. Without it, every
   * sign-up that failed at the vendor — wrong password, malformed payload, an outage mid-request —
   * would strand a record out of a ten-record pool, and a caller with a dictionary could empty the
   * pool without ever creating an account. Reservations that survived far enough to have an account
   * created for them are NEVER abandoned here: those are what recovery exists for.
   */
  async function abandon({ reservationId, recordId, spentChecker = null }) {
    if (!reservationId) return { ok: false, reason: 'no_reservation_id' };
    if (typeof spentChecker === 'function') {
      const spent = await spentChecker(recordId);
      if (spent === null) return { ok: false, reason: 'record_state_unreadable' };
      if (spent) return { ok: false, reason: 'record_no_longer_releasable', reservationId };
    }
    /* BOUNDED RETRIES, AND THE READ-BACK DECIDES — NOT THE RESPONSE.
       Measured on the disposable table: the first cleanup pass failed and an explicit retry by
       primary key removed records 8, 12 and 14. So a refusal here is a reason to try again within a
       cap, and a response that never arrived is not evidence that the row survived. Each attempt
       ends by asking the store whether OUR reservation id is still there, which also settles the
       inverse fault — a DELETE that reported failure after the row was already gone. Reporting that
       as a stuck reservation would strand a record out of a small pool forever, because nothing in
       this design ages a reservation out. */
    let lastReason = 'reservation_release_failed';
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      const res = await request({ path: path('delete', reservationId), method: 'DELETE' });
      if (res && res.ok === true) lastReason = null;
      // 404 on a DELETE is the wanted end state reached by another route: the row is not there.
      else if (res?.httpStatus === 404) lastReason = null;
      else lastReason = res?.reason || 'delete_failed';
      const back = await readByRecordId(recordId);
      if (back && back.ok === true) {
        const stillThere = (back.rows || []).some((r) => String(r?.id) === String(reservationId));
        if (!stillThere) {
          log('invitation_reservation_released', { reservationId, recordId, attempts: attempt });
          return { ok: true, reservationId, attempts: attempt };
        }
      } else {
        // Nothing could be confirmed about the row. Keep the reason honest: an unreadable store is
        // not a released reservation, whatever the DELETE itself claimed.
        lastReason = back?.reason || 'reservation_release_unconfirmed';
      }
      if (attempt < ATTEMPTS) await settle(DELAY_MS * attempt);
    }
    log('invitation_reservation_release_failed', { reservationId, recordId, reason: lastReason, attempts: ATTEMPTS });
    return { ok: false, reason: lastReason, reservationId, attempts: ATTEMPTS };
  }

  return {
    RESERVED, COMPLETED, ABANDONED, table,
    reserve, complete, abandon, readByRecordId, findIdForRecord,
    forEmailHash, pendingForEmailHash,
    looksLikeDuplicate
  };
}

module.exports = { createInvitationReservations, RESERVATION_STATES: Object.freeze({ RESERVED, COMPLETED, ABANDONED }) };
