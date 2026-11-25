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

THIS TABLE IS APPEND-ONLY, AND THAT IS A MEASURED CONSTRAINT, NOT A PREFERENCE. Live diagnosis on
2026-11-20 (report §4.4b): against `invitation_reservations`, INSERT, the UNIQUE refusal, the filtered
read, the primary-key read and DELETE all behave correctly, while `PUT /update/invitation_reservations/<id>`
answers `200 application/json` and persists NOTHING — with the NCB-stamped `user_id` echoed back, and
with it omitted, identically. The same request carrying a 60-character `status` into `VARCHAR(16)`
answers `400` with a database validation error, so the request is reaching the database layer: this is
not a routing failure, not a payload shape, and not a row we cannot see. It is the vendor's UPDATE path
declining to write to a `private` table. `ncba_rls_config` carries no row for this table (private) and
`public_read,shared_readwrite` for `user_codes` — which is the one behavioural difference between the
endpoint that works and the endpoint that does not.

So no code in this file issues an UPDATE, and none ever will. Consequences, stated where they matter:
the reservation row is written once and never revised; `status` keeps the value it was inserted with;
completion is NOT recorded here — it is derived from `user_codes.registered_user_id`, which the claim
verifies by read-back. A row that remains `pending` forever is therefore the normal state of a
successful registration, not a stuck one, and it is exactly what makes the record unclaimable twice:
the UNIQUE still holds. There is no `expired` state and no age-based release, deliberately: a
reservation that could be stolen because it sat still is a reservation that can be stolen.

What is stored, and what never is: the record id, a keyed digest of the normalized invitee email, and
the status at insertion. Never a password, never an upstream cookie, never a bearer, never a vendor
session identifier. The email digest is a LOOKUP CANDIDATE, not an authenticator — see
ncb/invitationClaim.js for why holding an email proves nothing and how recovery is authorized.
*/

const RESERVED = 'pending';
// Read-only constants. `completed` is NOT a state this relay can write — it is kept so that a row an
// operator or the vendor has advanced is recognised rather than treated as corrupt, and so that the
// vocabulary in the table matches the vocabulary in the dashboard.
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
   * The atomic step. Returns `{ok:true}` when THIS call created the reservation - or when the record
   * turns out to be held under OUR OWN digest, which is the same entitlement arriving by a different
   * route - `{ok:false, taken:true}` when a STRANGER holds it, and `{ok:false}` with a reason when the
   * store could not answer, which is never treated as free.
   */
  async function reserve({ recordId, emailHash }) {
    if (recordId === null || recordId === undefined || recordId === '') return { ok: false, reason: 'no_record_id' };
    /* OUR OWN RESERVATION IS NOT A RIVAL. A retry of a registration whose response the browser could not
       read (the CORS rejection this route had, a dropped socket, a page reload) arrives here with a
       reservation on the table that WE made. Treating that as "taken by someone else" makes the caller
       take the NEXT record, so one person quietly holds two invitations and a pool of 100 drains one
       retry at a time - the exact double-consumption the reservation exists to prevent, performed
       correctly. The digest is the only thing that can tell the two cases apart, and it is the same
       digest that made the original row, so this is a re-read of our own write and never an adoption:
       an unkeyed deployment (no HMAC secret, empty digest) cannot prove ownership and therefore takes
       nothing here. */
    const heldByUs = async () => {
      if (!emailHash) return { ours: null, unreadable: true };
      const back = await readByRecordId(recordId);
      if (!back || back.ok !== true) return { ours: null, unreadable: true };
      const mine = (back.rows || []).find((r) => String(r?.invitee_email_hash ?? '') === String(emailHash));
      return { ours: mine ? { ok: true, reservationId: mine.id ?? null, recordId, reused: true } : null,
        holders: (back.rows || []).length, unreadable: false };
    };
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
      const seen = await heldByUs();
      if (seen.ours) {
        log('invitation_reservation_reused_ours', { recordId, reservationId: seen.ours.reservationId });
        return seen.ours;
      }
      // The normal outcome under contention, and the one that must not be logged as an error. An
      // UNREADABLE holder list still answers `taken`, because saying "free" without evidence is how a
      // record gets spent twice.
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
      const seen = await heldByUs();
      if (seen.ours) {
        log('invitation_reservation_reconciled_after_lost_response', { recordId, reservationId: seen.ours.reservationId });
        return { ok: true, reservationId: seen.ours.reservationId, recordId, reconciled: true };
      }
      if (!seen.unreadable && seen.holders > 0) return { ok: false, taken: true, recordId };
    }
    // A store that cannot answer is not a store that said no. Callers must stop, not proceed
    // unprotected, or an outage silently degrades the design back to a read-then-write.
    return { ok: false, reason: attempt?.reason || 'reservation_store_unavailable', httpStatus: attempt?.httpStatus ?? 0 };
  }

  /* NO UPDATE IS ISSUED AGAINST THIS TABLE. There is no payload builder here on purpose: the only
     writes are the reservation INSERT and the release DELETE, both of which the live diagnosis proved
     to work. A previous revision of this file built a full read-modify-write body for a completion
     PUT; that PUT was measured answering 200 and persisting nothing, with and without the vendor's
     `user_id`, so the shape of the body was never the question and the code that built it is gone. */

  /* CONFIRM HELD — read-only, and it replaces the completion UPDATE entirely.

     The reservation row is the whole record of the claim. What this checks is the one thing still
     worth checking after the account exists and `user_codes` has been written and read back: that OUR
     row is still the row holding this record. It writes nothing, so the vendor's silent no-op cannot
     mislead it, and it is not a state transition. Completion itself is derived from
     `user_codes.registered_user_id` by ncb/invitationClaim.js — that column answers "who got this
     invitation", and it is the only place on this instance where a registration outcome has been
     observed to persist (its policy is `public_read,shared_readwrite`, and it is verified by
     read-back, never by the response). */
  async function confirmHeld({ reservationId, recordId, emailHash = '' }) {
    const target = reservationId ?? (await findIdForRecord(recordId));
    if (!target) return { ok: false, reason: 'reservation_not_found' };
    const found = await request({ path: path('read', target), method: 'GET' });
    if (!found || found.ok !== true) {
      /* A 404 and a 500 mean different things and the operator has to be able to tell them apart:
         the first is "this row is not here any more" (someone deleted it, and the record it protected
         is now reservable again by anyone), the second is "the store did not answer" and says nothing
         at all about the row. Both refuse the confirmation — neither is ever read as held. */
      if (found?.httpStatus === 404) return { ok: false, reason: 'reservation_row_absent', reservationId: target };
      return { ok: false, reason: found?.reason || 'reservation_read_failed', reservationId: target };
    }
    const row = rowsOf(found.body)[0] || null;
    if (!row) return { ok: false, reason: 'reservation_row_absent', reservationId: target };
    // The row must name the record it was taken for. Anything else is somebody else's reservation and
    // a reply this call has no business presenting as its own.
    if (String(row.code_row_id ?? '') !== String(recordId)) {
      log('invitation_reservation_record_mismatch', {
        reservationId: target, expected: String(recordId), found: String(row.code_row_id ?? '')
      });
      return { ok: false, reason: 'reservation_record_mismatch', reservationId: target };
    }
    if (emailHash && String(row.invitee_email_hash ?? '') !== String(emailHash)) {
      return { ok: false, reason: 'reservation_digest_mismatch', reservationId: target };
    }
    const state = String(row.status ?? '');
    // `abandoned` is an operator's decision, made in the dashboard because nothing here can write it.
    // A row a human retired is not a claim this registration may present as its own, whatever
    // `user_codes` now says, so it is refused rather than reinterpreted.
    if (state === ABANDONED) return { ok: false, reason: 'reservation_abandoned_by_operator', reservationId: target };
    return { ok: true, reservationId: target, state, held: true };
  }

  async function findIdForRecord(recordId) {
    const found = await readByRecordId(recordId);
    return found.ok && found.rows.length ? found.rows[0].id : null;
  }

  /* Recovery candidates for one digest — ALL of them, with no status filter.

     Filtering on `pending` was harmless when this code wrote `completed`, and is now silently
     load-bearing in the wrong direction: every row this relay creates stays as inserted, so a status
     filter would only ever exclude rows an operator changed by hand. What recovery actually needs is
     every record this address ever reserved, and the ANSWER to "did it finish" comes from the record
     itself. A row an operator retired is still returned here, and `confirmHeld` is what refuses it. */
  async function forEmailHash(emailHash) {
    if (!emailHash) return { ok: true, rows: [] };
    const res = await request({
      path: path('read'), method: 'GET',
      query: `invitee_email_hash=${encodeURIComponent(String(emailHash))}&limit=25`
    });
    if (!res || res.ok !== true) return { ok: false, reason: res?.reason || 'reservation_read_failed' };
    const rows = rowsOf(res.body).filter((r) => String(r?.invitee_email_hash ?? '') === String(emailHash));
    return { ok: true, rows };
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
    /* Was it visible to us before we tried to remove it? Under a private policy a 404 afterwards means
       either "deleted" or "still there, but no longer readable by this session", and the REST API
       cannot distinguish them. Only the first may be reported as a release, so the pre-delete read is
       what makes the claim mean something rather than merely sound clean. */
    let wasVisible = true;
    {
      const pre = await request({ path: path('read', reservationId), method: 'GET' });
      wasVisible = Boolean(rowsOf(pre?.body)[0]);
    }
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
          if (!wasVisible) {
            // Never visible, so never provably released by this call. Report it rather than banking it.
            log('invitation_reservation_release_not_attributable', { reservationId, recordId });
            return { ok: false, reason: 'reservation_never_visible_to_release', reservationId, attempts: attempt };
          }
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
    // `reserve` (INSERT) and `abandon` (DELETE) are the only two writes this store performs, and
    // `confirmHeld` is a read. There is no `complete` any more: the vendor's UPDATE on this table was
    // measured answering 200 and persisting nothing, so completion is derived from
    // `user_codes.registered_user_id` by the claim module.
    reserve, confirmHeld, abandon, readByRecordId, findIdForRecord, forEmailHash,
    looksLikeDuplicate
  };
}

module.exports = { createInvitationReservations, RESERVATION_STATES: Object.freeze({ RESERVED, COMPLETED, ABANDONED }) };
