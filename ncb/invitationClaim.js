'use strict';

/*
THE INVITATION CLAIM — one code, a POOL of records, and a reservation that the database arbitrates.

Two corrections are encoded here, and both came from measurement rather than preference.

1. A code is not a row. Production `user_codes` legitimately holds many rows sharing one value — ten
   rows of `123` is how a bulk code is issued — so eligibility means "at least one record with this
   exact value that is unused and unallocated", and the record spent is the FIRST such record by
   ascending numeric id. The previous version of this file treated two rows for one code as a fault
   (`duplicate_rows`, 409) which, apart from being wrong, is what the deployed validator route already
   does to every multi-row code: `POST /auth/validate-invitation` answers 503 for a code with ten free
   records. Uniqueness, where it is needed, belongs on the RECORD ID (see ncb/invitationReservations.js),
   never on the shared code string.

2. A lock in this process is not a guarantee. Reservations are inserted into a table whose
   `code_row_id` column carries a database-enforced UNIQUE constraint, so the store — not this
   container's memory — decides who gets each record. It survives a restart, it survives a second
   replica, and it survives Greta's self-hosted server running the same claim. Where the reservation
   store is not configured, this module REFUSES. It does not degrade into read-then-write, and it does
   not fall back to an in-process mutex as the sole protection; an unavailable claim is a visible
   failure, which is the rule the owner set for this feature on 2026-11-11 and repeated on 2026-11-20.

RECOVERY, and what does not count as proof of ownership. A pending reservation is looked up by a keyed
digest of the normalized invitee email — but that digest is a CANDIDATE FILTER ONLY, never an
authorization. Knowing an email address proves nothing: anyone can type one. The account a recovery
credits is established by the VENDOR's own answer for the caller's authenticated session
(`sessionAuthority.resolve()` → the `email` and `id` that NCB's get-session returns), and a reservation
is only ever completed for the account that authenticates now. A digest match with no verified session
completes nothing, and a verified session never adopts a reservation whose record already names a
different account. There is no age-based release anywhere in this file: a reservation that could be
taken because it sat still is a reservation that can be taken.
*/

const {
  normalizeInvitationCode, codeMatches, compareRecordIds, isUsed, allocatedTo, INVITATION_CODE_MAX_LENGTH
} = require('./invitationCode.js');

const OUTCOME = Object.freeze({
  CLAIMED: 'claimed',
  ALREADY_CLAIMED: 'already_claimed',
  NO_CODE: 'code_required',
  NOT_FOUND: 'code_not_found',
  EXHAUSTED: 'invitation_exhausted',
  RESERVED_ELSEWHERE: 'record_reserved_by_another_registration',
  STORE_UNAVAILABLE: 'reservation_store_unavailable',
  TRUNCATED: 'invitation_pool_unpaged',
  UNAVAILABLE: 'claim_unavailable',
  WRITE_FAILED: 'claim_write_failed',
  UNCONFIRMED: 'claim_unconfirmed',
  CONFLICT: 'claim_conflict',
  READ_FAILED: 'invitation_read_failed'
});

function hashOf(email, secret) {
  const value = String(email ?? '').trim().toLowerCase();
  if (!value || !secret) return '';
  return require('node:crypto').createHmac('sha256', String(secret)).update(value).digest('hex').slice(0, 48);
}

/**
 * @param {object} options
 * @param {(filter:{code:string})=>Promise<{ok:boolean,rows?:any[],reason?:string}>} options.readRows
 *   reads the candidate records for one EXACT code value, privileged, projected by the caller.
 * @param {(args:{recordId:string|number,userId:string})=>Promise<{ok:boolean,reason?:string}>} options.writeRow
 *   the privileged claim write: `used = 1` and `registered_user_id`, never `user_id`.
 * @param {object|null} options.reservations  createInvitationReservations() instance, or null.
 * @param {(args:{recordId:string|number})=>Promise<{ok:boolean,row?:any,reason?:string}>} [options.readRecord]
 *   reads ONE record by id, used only by recovery to learn which code a held record belongs to.
 * @param {(args:{userId:string})=>Promise<{ok:boolean,rows?:any[],reason?:string}>} [options.assignedTo]
 *   reads the `user_codes` records that name one account as `registered_user_id`. Recovery needs it
 *   because completion no longer lives in the reservation table: with no writable status column, the
 *   only way to tell "this account already registered" from "nothing was ever reserved" after a
 *   bookkeeping row has been deleted is to ask the records themselves.
 * @param {string} options.emailSecret  key for the candidate digest (never the authenticator).
 * @param {Function} [options.event]
 */
function createInvitationClaim({ readRows, writeRow, reservations = null, readRecord = null, assignedTo = null, emailSecret = '', event = () => {} } = {}) {
  /** Records that could still be spent: right value, unused, and not already somebody's invitee. */
  async function eligible(code, forAccount = '') {
    const read = await readRows({ code });
    if (!read || read.ok !== true) return { ok: false, outcome: OUTCOME.READ_FAILED, reason: read?.reason || 'read_failed' };
    const all = (Array.isArray(read.rows) ? read.rows : []).filter((row) => codeMatches(row, code));
    if (!all.length) return { ok: true, pool: [], candidates: [], outcome: OUTCOME.NOT_FOUND };
    const mine = String(forAccount || '').trim();
    const candidates = all.filter((row) => !isUsed(row) && (!allocatedTo(row) || allocatedTo(row) === mine))
      .sort(compareRecordIds);
    /* THE POOL MAY NOT HAVE FIT ON THE PAGE. `readRows` reports whether it filled the page it asked
       for, and an empty candidate list on a truncated page answers a different question than
       exhaustion does: it says nothing in the slice we were given can be spent, not that the code has
       no records left. Reporting that as `invitation_exhausted` would be a 409 telling a holder of a
       perfectly good bulk code that it is finished, on a pool that merely continues on the next page —
       and it would be indistinguishable from the real thing afterwards. So it is a deployment fault,
       named, and the caller is told 503. */
    if (!candidates.length && read.truncated === true) {
      return { ok: false, outcome: OUTCOME.TRUNCATED, pool: all, records: all.length };
    }
    // Every record for the value exists but none can be spent: used, or allocated to somebody else,
    // or both. That is exhaustion, and it is a different answer from "no such code".
    return { ok: true, pool: all, candidates, outcome: candidates.length ? 'eligible' : OUTCOME.EXHAUSTED };
  }

  /**
   * Step 1-2 of registration: validate the code and take one record atomically. Returns the record
   * this caller is now entitled to create an account against, or a reason it may not.
   */
  async function begin({ code: rawCode, email } = {}) {
    const code = normalizeInvitationCode(rawCode);
    if (!code) return { ok: false, outcome: OUTCOME.NO_CODE };
    if (!reservations) {
      event('invitation_claim_unavailable', {});
      return { ok: false, outcome: OUTCOME.UNAVAILABLE };
    }
    const emailHash = hashOf(email, emailSecret);
    const pool = await eligible(code);
    if (!pool.ok) {
      event('invitation_claim_read_failed', { reason: pool.reason });
      return { ok: false, outcome: pool.outcome, reason: pool.reason };
    }
    if (!pool.candidates.length) return { ok: false, outcome: pool.outcome, records: pool.pool.length };

    for (const row of pool.candidates) {
      const recordId = row?.id;
      if (recordId === null || recordId === undefined || recordId === '') continue;
      const attempt = await reservations.reserve({ recordId, emailHash });
      if (attempt.ok) {
        event('invitation_reservation_taken', { recordId });
        return { ok: true, code, recordId, reservationId: attempt.reservationId, emailHash, row };
      }
      if (attempt.taken) continue;                      // somebody else holds it: the next record is ours
      // The store could not answer. Trying another record would be guessing at a database that is
      // not speaking, and creating an account without a reservation would be the old design again.
      event('invitation_reservation_store_unavailable', { recordId, reason: attempt.reason });
      return { ok: false, outcome: OUTCOME.STORE_UNAVAILABLE, reason: attempt.reason };
    }
    return { ok: false, outcome: OUTCOME.EXHAUSTED, records: pool.candidates.length };
  }

  /** Steps 3-6: the account exists, so spend the reserved record and prove it did. */
  async function finish({ code: rawCode, recordId, reservationId, userId, emailHash }) {
    const code = normalizeInvitationCode(rawCode);
    const account = String(userId ?? '').trim();
    if (!code || !account || recordId === null || recordId === undefined || recordId === '') {
      return { ok: false, outcome: OUTCOME.NO_CODE };
    }
    if (!reservations) return { ok: false, outcome: OUTCOME.UNAVAILABLE };

    const before = await eligible(code, account);
    const row = (before.pool || []).find((r) => String(r?.id) === String(recordId)) || null;
    if (row && isUsed(row) && allocatedTo(row) === account) {
      /* OUR OWN CLAIM, ALREADY LANDED — a retry after a lost response, or the recovery route doing
         its job. The evidence is `user_codes` itself, which is the only place on this instance where
         a registration outcome has been observed to persist, so nothing is written a second time and
         nothing has to be. The reservation row is confirmed by read alone. */
      const held = await reservations.confirmHeld({ reservationId, recordId, emailHash });
      return { ok: true, outcome: OUTCOME.ALREADY_CLAIMED, recordId, reservationHeld: held.ok === true };
    }
    if (row && (isUsed(row) || (allocatedTo(row) && allocatedTo(row) !== account))) {
      event('invitation_claim_conflict', { recordId, claimedBy: allocatedTo(row), attemptedBy: account });
      return { ok: false, outcome: OUTCOME.CONFLICT, recordId, claimedBy: allocatedTo(row) || null };
    }

    const written = await writeRow({ recordId, userId: account });
    if (!written || written.ok !== true) {
      // The reservation stays. It is the only durable evidence that this record was spoken for, and
      // deleting it on a failed write would hand a half-registered record to the next caller.
      event('invitation_claim_write_failed', { recordId, reason: written?.reason || 'write_failed' });
      return { ok: false, outcome: OUTCOME.WRITE_FAILED, recordId, reason: written?.reason || 'write_failed' };
    }

    /* THE VERIFICATION IS NOT RELAXED, AND IT MUST NOT BE. The write's own response is worth nothing
       here: this vendor has been measured answering a PUT on `invitation_reservations` with
       `200 application/json` and persisting nothing, so an acknowledged write is exactly what a
       failed one looks like. Success therefore requires what the row says AFTER the write — `used = 1`
       AND `registered_user_id` naming this account — and a write that answers well and leaves the row
       untouched is reported `claim_unconfirmed`, never claimed. This is the one place the whole
       feature could have quietly become a lie, so the rule is stated at the line that enforces it. */
    const after = await readRows({ code });
    const spent = (after?.rows || []).find((r) => String(r?.id) === String(recordId)) || null;
    if (!spent || Number(spent.used ?? 0) !== 1 || allocatedTo(spent) !== account) {
      event('invitation_claim_unconfirmed', { recordId, spent: Boolean(spent?.used), owner: allocatedTo(spent) || null });
      return { ok: false, outcome: OUTCOME.UNCONFIRMED, recordId };
    }
    const held = await reservations.confirmHeld({ reservationId, recordId, emailHash });
    event('invitation_claimed', { recordId, reservationHeld: held.ok === true });
    return { ok: true, outcome: OUTCOME.CLAIMED, recordId, reservationHeld: held.ok === true };
  }

  /**
   * Authenticated recovery: a session NCB has already vouched for, and the records that session
   * reserved. The session is the authorization; the digest is how the candidates are FOUND. Nothing
   * here reads a body-supplied identity, and nothing here releases, reassigns or ages out a row.
   *
   * Completion is derived, never recalled. The reservation table cannot record it — the vendor's
   * UPDATE on that table is a measured no-op — so every question this function asks about outcome is
   * answered by reading `user_codes`: does the reserved record name THIS account (finished), name a
   * DIFFERENT account (conflict), or name nobody (unfinished, so drive the claim write now)? And when
   * the address holds no reservation rows at all, `assignedTo` asks the records directly whether this
   * account already owns one, because a registration whose bookkeeping row was deleted by hand is
   * still a registration that happened, and telling that player their valid code failed is the same
   * class of lie the `used` flag alone used to tell.
   */
  async function recover({ email, userId } = {}) {
    const account = String(userId ?? '').trim();
    const sessionEmail = String(email ?? '').trim();
    if (!account || !sessionEmail) return { ok: false, outcome: OUTCOME.NO_CODE, reason: 'authenticated_session_required' };
    if (!reservations) return { ok: false, outcome: OUTCOME.UNAVAILABLE };
    const emailHash = hashOf(sessionEmail, emailSecret);
    if (!emailHash) return { ok: false, outcome: OUTCOME.UNAVAILABLE, reason: 'reservation_key_unconfigured' };
    const held = await reservations.forEmailHash(emailHash);
    if (!held.ok) return { ok: false, outcome: OUTCOME.STORE_UNAVAILABLE, reason: held.reason };
    const rows = (held.rows || []).slice().sort((a, b) => compareRecordIds(
      { id: a?.code_row_id }, { id: b?.code_row_id }
    ));
    if (!rows.length) {
      /* Nothing reserved under this address. That is not the same as nothing having happened, so the
         record side is asked before the caller is declined — and if a record already names THIS
         account, the answer is success with nothing left to do. */
      if (typeof assignedTo === 'function') {
        const owned = await assignedTo({ userId: account });
        const record = (owned?.rows || [])[0] || null;
        if (record && allocatedTo(record) === account) {
          event('invitation_recovery_already_assigned_from_record', { recordId: record?.id ?? null });
          return { ok: true, outcome: OUTCOME.ALREADY_CLAIMED, recovered: true, alreadyFinished: true,
            recordId: record?.id ?? null };
        }
      }
      return { ok: false, outcome: OUTCOME.NOT_FOUND, candidates: 0 };
    }
    if (typeof readRecord !== 'function') {
      event('invitation_recovery_unavailable', { reason: 'record_reader_not_configured' });
      return { ok: false, outcome: OUTCOME.UNAVAILABLE, reason: 'record_reader_not_configured' };
    }
    // The code value is recovered FROM THE RECORD, never supplied by the caller: a retry that trusted
    // a body field could be pointed at any record id in the table.
    for (const reservation of rows) {
      const recordId = reservation?.code_row_id;
      if (recordId === null || recordId === undefined || recordId === '') continue;
      const record = await readRecord({ recordId });
      if (!record || record.ok !== true || !record.row) continue;
      const codeValue = normalizeInvitationCode(record.row.code);
      if (!codeValue) continue;
      const outcome = await finish({ code: codeValue, recordId, reservationId: reservation.id, userId: account, emailHash });
      if (outcome.ok) return { ...outcome, recovered: true, code: codeValue };
      if (outcome.outcome === OUTCOME.CONFLICT) event('invitation_recovery_conflict', { recordId, attemptedBy: account });
    }
    return { ok: false, outcome: OUTCOME.UNCONFIRMED, candidates: rows.length };
  }

  /** Is this record still releasable? Unknown is answered as NOT releasable, never as a guess. */
  async function recordSpent(recordId) {
    if (typeof readRecord !== 'function') return null;
    const found = await readRecord({ recordId });
    if (!found || found.ok !== true) return null;
    if (!found.row) return false;                       // gone from the pool entirely: nothing to hold
    return isUsed(found.row) || Boolean(allocatedTo(found.row));
  }

  /**
   * Give back a reservation whose registration never reached an account. The guard is the record
   * itself: if it is used or allocated, the release is refused even when the caller is our own
   * request, because at that point something else has already happened to that record.
   */
  async function release(held) {
    if (!held || !reservations || !held.reservationId) return { ok: false, reason: 'nothing_to_release' };
    if (held.settled) return { ok: false, reason: 'reservation_already_settled' };
    const spent = await recordSpent(held.recordId);
    if (spent === null) return { ok: false, reason: 'record_state_unreadable' };
    if (spent === true) return { ok: false, reason: 'record_no_longer_releasable' };
    const done = await reservations.abandon({
      reservationId: held.reservationId, recordId: held.recordId,
      spentChecker: async () => (await recordSpent(held.recordId)) === true
    });
    if (done.ok) held.settled = 'released';
    return done;
  }

  return { OUTCOME, eligible, begin, finish, recover, release, recordSpent, normalize: normalizeInvitationCode, INVITATION_CODE_MAX_LENGTH };
}

module.exports = { createInvitationClaim, INVITATION_CLAIM_OUTCOME: OUTCOME, hashOf: hashOf };
