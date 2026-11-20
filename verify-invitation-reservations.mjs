/*
THE INVITATION RESERVATION GATE — the single-use guarantee, tested against a store that ENFORCES it.

Why a new file rather than more arms in verify-ncb-integration.mjs: every existing fake in this repo
models NCB as a permissive key-value store, and a permissive fake cannot falsify a uniqueness claim.
An arm that "proves" concurrent claims are safe against a store that never refuses a duplicate is not
evidence — it is a description of the mock. So the store below implements the one property the design
depends on: a UNIQUE index on `invitation_reservations.code_row_id`, refused in band with
`400 Duplicate entry`, exactly as the vendor documents it, with 422 kept separate for validation so a
malformed row can never be mistaken for a rival claimant.

The code under test is imported, never reimplemented: ncb/invitationReservations.js,
ncb/invitationClaim.js, ncb/invitationCode.js. Only the transport adapter is local, and it is the
same shape bridge.js supplies over the club service account.

What a restart means here: a NEW reservations instance and a NEW claim instance built over the SAME
store object, with fresh in-process state. That is the honest simulation of a container restart, and
it is the case an in-process mutex would silently fail.
*/
import { createRequire } from 'node:module';
import path from 'node:path';
const require = createRequire(import.meta.url);
const ROOT = process.cwd();
const { createInvitationReservations } = require(path.join(ROOT, 'ncb/invitationReservations.js'));
const { createInvitationClaim } = require(path.join(ROOT, 'ncb/invitationClaim.js'));
const { normalizeInvitationCode, INVITATION_CODE_MAX_LENGTH } = require(path.join(ROOT, 'ncb/invitationCode.js'));

const results = [];
const check = (name, fn) => Promise.resolve().then(fn).then((detail) => {
  results.push({ name, pass: detail === true || (detail && detail.ok === true), detail: detail === true ? '' : String(detail?.why ?? '') });
}).catch((e) => results.push({ name, pass: false, detail: `threw ${e?.message}` }));

const KEY = 'gate-reservation-hmac-key-not-a-real-secret-32';
// A pool with a DELIBERATE MIX: five records that can be spent, one already used, one allocated to
// somebody else but not yet spent, and codes whose values and cases must not be conflated. Ids are
// out of order on purpose — "first available" has to mean ascending id, not first row returned.
const freshPool = () => ([
  { id: 12, code: '123', used: 0, registered_user_id: null, user_id: 'issuer' },
  { id: 8, code: '123', used: 0, registered_user_id: null, user_id: 'issuer' },
  { id: 3, code: '123', used: 1, registered_user_id: 'somebody-else', user_id: 'issuer' },
  { id: 99, code: '123', used: 0, registered_user_id: null, user_id: 'issuer' },
  { id: 7, code: '123', used: 0, registered_user_id: 'allocated-not-spent', user_id: 'issuer' },
  { id: 102, code: '123', used: 0, registered_user_id: null, user_id: 'issuer' },
  { id: 101, code: '123', used: 0, registered_user_id: null, user_id: 'issuer' }
]).concat(
  // A TEN-record pool, for the concurrency arm the spec asks for at the size a bulk issue really is.
  // Ids descend on purpose: ascending order has to be produced by the claim, not inherited from the
  // order the vendor happened to return them in.
  [209, 208, 207, 206, 205, 204, 203, 202, 201, 200].map((id) => (
    { id, code: 'TEN', used: 0, registered_user_id: null, user_id: 'issuer' }
  ))
).concat([
  { id: 500, code: '777', used: 0, registered_user_id: null, user_id: 'issuer' },
  { id: 4, code: 'BRIDGE-2026-KEY', used: 0, registered_user_id: null, user_id: 'issuer' },
  { id: 6, code: 'aB_3-x', used: 0, registered_user_id: null, user_id: 'issuer' },
  { id: 5, code: 'AB_3-X', used: 0, registered_user_id: null, user_id: 'issuer' }
]);

function makeStore({ enforceUnique = true, readFails = false, writeFails = false, failCreate = false, down = false, faults = {} } = {}) {
  const s = {
    codes: freshPool(), reservations: [], nextReservationId: 1, writes: [], refused: 0, storeFaults: 0,
    // Counters the retry arms read: how many times each operation was actually driven.
    deletes: 0, reservationUpdates: 0, reservationCreates: 0
  };
  // A fault that fires for the first N ATTEMPTS and then stops firing, judged on how many attempts
  // PRECEDED this one. Which is the shape the probe showed (the cleanup pass failed, the retry by
  // primary key succeeded) and the only shape that can tell a retry loop from a single attempt that got
  // lucky. Pass `Infinity` for a store that never recovers.
  const fires = (prior, limit) => Number(limit) > 0 && prior < Number(limit);
  // The unique index is a property of the TABLE, not of the connection: it lives in `s.reservations`,
  // so two instances sharing the store share the constraint — which is what "restart" and "second
  // replica" have to mean here. A per-closure Set would have let a new instance forget the rule, and
  // that would have been a bug in the fake, not in the design.
  const heldIndex = () => new Set(s.reservations.map((r) => String(r.code_row_id)));
  async function request({ path: p, method = 'GET', body, query }) {
    if (down) { s.storeFaults++; return { ok: false, httpStatus: 0, reason: 'club_account_unreachable' }; }
    // `<verb>/<table>[/<id>]` — the shape both the reservations adapter and the claim transport send.
    const [verb, table, idPart] = String(p).split('/');
    if (readFails && verb === 'read') return { ok: false, httpStatus: 500, reason: 'read_failed' };
    if (verb === 'read' && table === 'user_codes') {
      const code = new URLSearchParams(query || '').get('code');
      const rowId = new URLSearchParams(query || '').get('id');
      let rows = s.codes;
      if (code !== null) rows = rows.filter((r) => r.code === code);
      if (rowId !== null) rows = rows.filter((r) => String(r.id) === rowId);
      return { ok: true, httpStatus: 200, body: { status: 'success', data: rows.map((r) => ({ ...r })) } };
    }
    if (verb === 'update' && table === 'user_codes') {
      if (writeFails) return { ok: false, httpStatus: 500, reason: 'write_refused' };
      const row = s.codes.find((r) => String(r.id) === idPart);
      if (!row) return { ok: false, httpStatus: 404, reason: 'record_not_found' };
      s.writes.push({ recordId: row.id, body: { ...body } });
      // `user_id` is the vendor's ownership column: dropped on update, measured. A claim that sent it
      // would therefore LOOK successful here and do nothing — which is the original defect.
      const sent = { ...body }; delete sent.user_id;
      // A write that answers 200 and persists something ELSE. The claim must be verified against the
      // row rather than against the response, and this is the only way to prove it does: the fault
      // looks exactly like success from the caller's side.
      if (faults.writeLies) sent.registered_user_id = faults.writeLies;
      Object.assign(row, sent);
      return { ok: true, httpStatus: 200, body: { status: 'success', data: { ...row } } };
    }
    if (verb === 'read' && table === 'invitation_reservations') {
      const q = new URLSearchParams(query || '');
      const rowId = q.get('code_row_id'); const hash = q.get('invitee_email_hash');
      let rows = s.reservations;
      if (rowId !== null) rows = rows.filter((r) => String(r.code_row_id) === rowId);
      if (hash !== null) rows = rows.filter((r) => String(r.invitee_email_hash) === hash);
      return { ok: true, httpStatus: 200, body: { status: 'success', data: rows.map((r) => ({ ...r })) } };
    }
    if (verb === 'create' && table === 'invitation_reservations') {
      const createsBefore = s.reservationCreates; s.reservationCreates++;
      const rid = String(body?.code_row_id ?? '');
      if (enforceUnique && !writeFails && heldIndex().has(rid)) {
        s.refused++;
        // The vendor's documented answer: 400 Duplicate entry.
        return { ok: false, httpStatus: 400, body: { status: 'error', message: 'Duplicate entry for key code_row_id' } };
      }
      if (body?.validationBad) return { ok: false, httpStatus: 422, body: { status: 'error', message: 'validation failed' } };
      if (failCreate) return { ok: false, httpStatus: 500, reason: 'reservation_insert_failed' };
      const row = { id: s.nextReservationId++, code_row_id: rid, invitee_email_hash: body?.invitee_email_hash ?? '', status: 'pending' };
      s.reservations.push(row);
      // THE WRITE LANDS AND THE ANSWER DOES NOT. This is the fault a blind retry would double-spend:
      // the row is in the table, the caller heard nothing, and a second INSERT would either be
      // refused (harmless) or, without the index, take a second record for one registration.
      if (fires(createsBefore, faults.createLostResponses)) {
        return { ok: false, httpStatus: 0, reason: 'socket hang up' };
      }
      return { ok: true, httpStatus: 201, body: { status: 'success', id: row.id } };
    }
    if (verb === 'update' && table === 'invitation_reservations') {
      const updatesBefore = s.reservationUpdates; s.reservationUpdates++;
      const row = s.reservations.find((r) => String(r.id) === idPart);
      if (!row) return { ok: false, httpStatus: 404, reason: 'reservation_not_found' };
      if (fires(updatesBefore, faults.updateRefusals)) {
        return { ok: false, httpStatus: 500, reason: 'reservation_update_failed' };
      }
      Object.assign(row, body);
      // The completion wrote, and the response was lost. Only a read-back can tell this from a
      // failure, which is why `complete()` reads the row instead of believing the call.
      if (fires(updatesBefore, faults.updateLostResponses)) {
        return { ok: false, httpStatus: 0, reason: 'socket hang up' };
      }
      return { ok: true, httpStatus: 200, body: { status: 'success', data: { ...row } } };
    }
    if (verb === 'delete' && table === 'invitation_reservations') {
      const deletesBefore = s.deletes; s.deletes++;
      const i = s.reservations.findIndex((r) => String(r.id) === idPart);
      if (i < 0) return { ok: false, httpStatus: 404, reason: 'not_found' };
      if (fires(deletesBefore, faults.deleteRefusals)) {
        return { ok: false, httpStatus: 500, reason: 'delete_failed' };
      }
      s.reservations.splice(i, 1);
      // Measured on the live probe table: the first cleanup pass failed and the retry by primary key
      // succeeded. The inverse fault is modelled here — the row IS gone and the answer that says so
      // never arrived — because it is the one that strands a record forever if the caller believes the
      // response instead of the state.
      if (fires(deletesBefore, faults.deleteLostResponses)) {
        return { ok: false, httpStatus: 0, reason: 'socket hang up' };
      }
      return { ok: true, httpStatus: 200, body: { status: 'success', data: null } };
    }
    return { ok: false, httpStatus: 404, reason: 'route_missing' };
  }
  return { s, request };
}

function build(storeOpts = {}) {
  const { s, request } = makeStore(storeOpts);
  // `wait` is injected so a retry arm measures the retry SEQUENCE in nanoseconds instead of sleeping
  // through the production back-off. The back-off itself is the module's default and is unchanged.
  const reservations = createInvitationReservations({
    request, log: () => {}, wait: async () => {},
    storeAttempts: storeOpts.storeAttempts ?? 3, retryDelayMs: 0
  });
  const claim = createInvitationClaim({
    readRows: async ({ code }) => {
      const r = await request({ path: 'read/user_codes', method: 'GET', query: `code=${encodeURIComponent(code)}` });
      return r.ok
        ? { ok: true, rows: r.body?.data ?? [], truncated: storeOpts.truncated === true }
        : { ok: false, reason: r.reason };
    },
    readRecord: async ({ recordId }) => {
      const r = await request({ path: 'read/user_codes', method: 'GET', query: `id=${encodeURIComponent(String(recordId))}` });
      return r.ok ? { ok: true, row: (r.body?.data ?? [])[0] ?? null } : { ok: false, reason: r.reason };
    },
    writeRow: async ({ recordId, userId }) => {
      const r = await request({ path: `update/user_codes/${recordId}`, method: 'PUT', body: { used: 1, registered_user_id: String(userId) } });
      return r.ok ? { ok: true } : { ok: false, reason: r.reason };
    },
    reservations, emailSecret: KEY, event: () => {}
  });
  return { claim, reservations, store: s, request };
}

const emailA = 'Player.One@Example.com';
const emailB = 'player.two@example.com';

// ── THE POOL ───────────────────────────────────────────────────────────────
await check('R1. a code with many records is a POOL: the eligible ones are the unused, unallocated ones, ordered by ascending id', async () => {
  const { claim } = build();
  const pool = await claim.eligible('123');
  const ids = pool.candidates.map((r) => r.id);
  return ids.join(',') === '8,12,99,101,102' || { ok: false, why: ids.join(',') };
});
await check('R2. the first registration takes the LOWEST eligible record id, not the first returned', async () => {
  const { claim, store } = build();
  const begun = await claim.begin({ code: '123', email: emailA });
  return begun.ok && begun.recordId === 8
    && store.reservations.length === 1 && String(store.reservations[0].code_row_id) === '8'
    || { ok: false, why: `record=${begun.recordId} outcome=${begun.outcome}` };
});
await check('R3. the second registration on the same code moves to the NEXT record, and no reservation is shared', async () => {
  const { claim, store } = build();
  const a = await claim.begin({ code: '123', email: emailA });
  await claim.finish({ code: '123', recordId: a.recordId, reservationId: a.reservationId, userId: 'acct-a', emailHash: a.emailHash });
  const b = await claim.begin({ code: '123', email: emailB });
  return b.recordId === 12 && store.reservations.length === 2 || { ok: false, why: `b=${b.recordId} rows=${store.reservations.length}` };
});
await check('R4. sequential registrations consume the pool in id order and stop when it is empty', async () => {
  const { claim } = build();
  const taken = [];
  for (let i = 0; i < 7; i++) {
    const b = await claim.begin({ code: '123', email: `player${i}@example.com` });
    if (!b.ok) { taken.push(b.outcome); break; }
    taken.push(b.recordId);
    await claim.finish({ code: '123', recordId: b.recordId, reservationId: b.reservationId, userId: `acct-${i}`, emailHash: b.emailHash });
  }
  return taken.join(',') === '8,12,99,101,102,invitation_exhausted' || { ok: false, why: taken.join(',') };
});
await check('R5. a fully used and allocated pool is EXHAUSTED, not "not found": the code exists, it is just spent', async () => {
  const { claim, store } = build();
  for (const row of store.codes.filter((r) => r.code === '123')) { row.used = 1; row.registered_user_id = 'other'; }
  const r = await claim.begin({ code: '123', email: emailA });
  return r.ok === false && r.outcome === 'invitation_exhausted' || { ok: false, why: r.outcome };
});
await check('R6. an unknown code value is refused before any reservation is written', async () => {
  const { claim, store } = build();
  const r = await claim.begin({ code: 'NO-SUCH-CODE', email: emailA });
  return r.outcome === 'code_not_found' && store.reservations.length === 0 || { ok: false, why: `${r.outcome}/${store.reservations.length}` };
});
// ── UNIQUENESS AND CONCURRENCY (the point of the whole design) ─────────────
await check('R7. two concurrent registrations cannot hold the same RECORD: the second INSERT is refused by the store', async () => {
  const { claim, store } = build();
  const [a, b] = await Promise.all([
    claim.begin({ code: '123', email: emailA }),
    claim.begin({ code: '123', email: emailB })
  ]);
  const recordIds = store.reservations.map((r) => String(r.code_row_id)).sort();
  const distinct = new Set(recordIds).size === recordIds.length;
  return a.ok && b.ok && a.recordId !== b.recordId && distinct && store.refused >= 1
    || { ok: false, why: `${a.recordId}/${b.recordId} rows=${recordIds.join(',')} refused=${store.refused}` };
});
await check('R8. five concurrent registrations of a five-record pool produce five distinct holders and strand nothing', async () => {
  const { claim, store } = build();
  const begun = await Promise.all([1, 2, 3, 4, 5].map((n) => claim.begin({ code: '123', email: `p${n}@example.com` })));
  const ok = begun.filter((b) => b.ok);
  const ids = ok.map((b) => String(b.recordId));
  return ok.length === 5 && new Set(ids).size === 5 && store.reservations.length === 5
    || { ok: false, why: `ok=${ok.length} ids=${ids.join(',')} held=${store.reservations.length}` };
});
await check('R9. duplicate insertion is refused in the STORE, not remembered by the process: a second claimant is turned away', async () => {
  const a = build();
  const begun = await a.claim.begin({ code: '123', email: emailA });
  // A wholly separate instance — a second replica — aiming at the same record id.
  const b = makeStore();
  b.s.reservations = a.store.reservations; b.s.nextReservationId = a.store.nextReservationId;
  const second = createInvitationReservations({ request: b.request, log: () => {} });
  const trySame = await second.reserve({ recordId: begun.recordId, emailHash: 'whatever' });
  return trySame.ok === false && trySame.taken === true || { ok: false, why: JSON.stringify(trySame) };
});
await check('R10. a restart does not free a reservation: a new instance over the same store still cannot take the held record', async () => {
  const first = build();
  const held = await first.claim.begin({ code: '123', email: emailA });
  const afterRestart = build();
  afterRestart.store.reservations = first.store.reservations;
  afterRestart.store.codes = first.store.codes;
  afterRestart.store.nextReservationId = first.store.nextReservationId;
  const again = await afterRestart.claim.begin({ code: '123', email: emailB });
  // The restarted process must skip the record it cannot get and take the next one: a held record
  // stays held, which is the whole reason this design replaced the in-process lock.
  return again.ok && again.recordId === 12 || { ok: false, why: `record=${again.recordId} outcome=${again.outcome}` };
});
await check('R11. NOTHING ages a reservation out: an hour later the held record is still unavailable to everyone else', async () => {
  const { claim, store } = build();
  const held = await claim.begin({ code: '123', email: emailA });
  for (const r of store.reservations) r.created_at = new Date(Date.now() - 3600_000).toISOString();
  const rival = await claim.begin({ code: '123', email: emailB });
  return held.recordId === 8 && rival.recordId === 12 || { ok: false, why: `rival=${rival.recordId}` };
});
// ── FAILURE AND RECOVERY ──────────────────────────────────────────────────
await check('R12. account creation never happened: the reservation is given back, so a failed password cannot drain the pool', async () => {
  const { claim, store } = build();
  const held = await claim.begin({ code: '123', email: emailA });
  const released = await claim.release(held);
  const afterRelease = store.reservations.length;
  const next = await claim.begin({ code: '123', email: emailB });
  // Measured in two steps on purpose: the second begin() puts a NEW row back in the table, so counting
  // afterwards would say "1" and prove nothing either way.
  return released.ok === true && afterRelease === 0 && next.recordId === 8
    || { ok: false, why: `${JSON.stringify(released)} afterRelease=${afterRelease} next=${next.recordId}` };
});
await check('R12b. the store refusing the INSERT alone (reads still working) is a reservation-store failure, not a silent pass', async () => {
  const { claim, store } = build({ failCreate: true });
  const r = await claim.begin({ code: '123', email: emailA });
  return r.ok === false && r.outcome === 'reservation_store_unavailable' && store.reservations.length === 0
    || { ok: false, why: `${r.outcome}/${store.reservations.length}` };
});
await check('R13. release refuses a record that became spent in the meantime — the guard is the record, not the caller', async () => {
  const { claim, store } = build();
  const held = await claim.begin({ code: '123', email: emailA });
  store.codes.find((r) => r.id === held.recordId).used = 1;
  const refused = await claim.release(held);
  return refused.ok === false && refused.reason === 'record_no_longer_releasable'
    || { ok: false, why: JSON.stringify(refused) };
});
await check('R14. account created, claim write refused: the reservation SURVIVES and the record is not double-held', async () => {
  const store1 = makeStore({ writeFails: true });
  const reservations = createInvitationReservations({ request: store1.request, log: () => {} });
  const claim = createInvitationClaim({
    readRows: async ({ code }) => { const r = await store1.request({ path: 'read/user_codes', query: `code=${code}` }); return r.ok ? { ok: true, rows: r.body.data } : { ok: false }; },
    readRecord: async ({ recordId }) => { const r = await store1.request({ path: 'read/user_codes', query: `id=${recordId}` }); return { ok: true, row: (r.body?.data || [])[0] }; },
    writeRow: async () => ({ ok: false, reason: 'write_refused' }),
    reservations, emailSecret: KEY, event: () => {}
  });
  const begun = await claim.begin({ code: '123', email: emailA });
  const finished = await claim.finish({ code: '123', recordId: begun.recordId, reservationId: begun.reservationId, userId: 'acct-a', emailHash: begun.emailHash });
  const released = await claim.release({ ...begun, settled: 'held_for_recovery' });
  return finished.ok === false && finished.outcome === 'claim_write_failed'
    && store1.s.reservations.length === 1 && String(store1.s.reservations[0].status) === 'pending'
    && released.ok === false
    || { ok: false, why: `${finished.outcome} held=${store1.s.reservations.length} ${JSON.stringify(released)}` };
});
await check('R15. recovery completes the interrupted registration for the account the SESSION proves, in one call', async () => {
  const { claim, store } = build();
  const begun = await claim.begin({ code: '123', email: emailA });
  const recovered = await claim.recover({ email: emailA, userId: 'acct-new-1' });
  const row = store.codes.find((r) => r.id === begun.recordId);
  return recovered.ok === true && recovered.recovered === true && Number(row.used) === 1
    && row.registered_user_id === 'acct-new-1' && store.reservations[0].status === 'completed'
    || { ok: false, why: JSON.stringify(recovered) };
});
await check('R16. recovery is authorized by the session, not by knowing an address: a different verified account completes nothing', async () => {
  const { claim, store } = build();
  const held = await claim.begin({ code: '123', email: emailA });
  const thief = await claim.recover({ email: emailB, userId: 'acct-thief' });
  const record = store.codes.find((r) => r.id === held.recordId);
  // Measured on the HELD record, not on "is anything spent": the pool ships with one record that is
  // already used, and a thief who cannot touch record 8 has failed however many rows exist elsewhere.
  return thief.ok === false && Number(record.used) === 0 && record.registered_user_id === null
    && store.reservations[0].status === 'pending'
    || { ok: false, why: `${thief.outcome} record=${JSON.stringify(record)}` };
});
await check('R17. recovery with no verified address in the session refuses instead of guessing', async () => {
  const { claim } = build();
  const r = await claim.recover({ email: '', userId: 'acct-x' });
  return r.ok === false && r.reason === 'authenticated_session_required' || { ok: false, why: JSON.stringify(r) };
});
await check('R18. a completed claim is never re-driven: the same account recovering again reports already_claimed with NO second write', async () => {
  const { claim, store } = build();
  const begun = await claim.begin({ code: '123', email: emailA });
  await claim.finish({ code: '123', recordId: begun.recordId, reservationId: begun.reservationId, userId: 'acct-a', emailHash: begun.emailHash });
  const writesBefore = store.writes.length;
  const again = await claim.finish({ code: '123', recordId: begun.recordId, reservationId: begun.reservationId, userId: 'acct-a', emailHash: begun.emailHash });
  return again.ok === true && again.outcome === 'already_claimed' && store.writes.length === writesBefore
    || { ok: false, why: `${again.outcome} writes=${store.writes.length}` };
});
await check('R18b. a retry after completion reports already_claimed with NO second write — a finished registration is never called a failed code', async () => {
  const { claim, store } = build();
  const begun = await claim.begin({ code: '123', email: emailA });
  await claim.finish({ code: '123', recordId: begun.recordId, reservationId: begun.reservationId, userId: 'acct-a', emailHash: begun.emailHash });
  const writesBefore = store.writes.length;
  const recovered = await claim.recover({ email: emailA, userId: 'acct-a' });
  return recovered.ok === true && recovered.outcome === 'already_claimed' && recovered.alreadyFinished === true
    && store.writes.length === writesBefore
    || { ok: false, why: JSON.stringify(recovered) };
});
await check('R18c. and that completed reservation is invisible to a different account, which is still declined', async () => {
  const { claim, store } = build();
  const begun = await claim.begin({ code: '123', email: emailA });
  await claim.finish({ code: '123', recordId: begun.recordId, reservationId: begun.reservationId, userId: 'acct-a', emailHash: begun.emailHash });
  const other = await claim.recover({ email: emailB, userId: 'acct-b' });
  const record = store.codes.find((r) => r.id === begun.recordId);
  return other.ok === false && other.outcome === 'code_not_found' && String(record.registered_user_id) === 'acct-a'
    || { ok: false, why: JSON.stringify(other) };
});
await check('R19. a claim can never move ownership: no write in this run ever carried the reserved user_id column', async () => {
  const { claim, store } = build();
  const b = await claim.begin({ code: '777', email: emailA });
  await claim.finish({ code: '777', recordId: b.recordId, reservationId: b.reservationId, userId: 'acct-777', emailHash: b.emailHash });
  const row = store.codes.find((r) => r.id === 500);
  return store.writes.every((w) => !('user_id' in w.body)) && row.user_id === 'issuer'
    && row.registered_user_id === 'acct-777' || { ok: false, why: JSON.stringify(store.writes) };
});
// ── STORE FAULTS ───────────────────────────────────────────────────────────
await check('R20. a database that cannot be reached is a refusal with no reservation and no claim, whichever call failed first', async () => {
  const { claim, store } = build({ down: true });
  const r = await claim.begin({ code: '123', email: emailA });
  return r.ok === false && store.reservations.length === 0 && store.writes.length === 0
    && ['reservation_store_unavailable', 'invitation_read_failed'].includes(r.outcome)
    || { ok: false, why: `${r.outcome} held=${store.reservations.length}` };
});
await check('R21. a store that cannot be READ is unavailable too: eligibility is never assumed from silence', async () => {
  const { claim } = build({ readFails: true });
  const r = await claim.begin({ code: '123', email: emailA });
  return r.ok === false && (r.outcome === 'reservation_store_unavailable' || r.outcome === 'invitation_read_failed')
    || { ok: false, why: r.outcome };
});
await check('R22. no reservation store configured at all means the claim refuses outright — the atomic-only default', async () => {
  const claim = createInvitationClaim({ readRows: async () => ({ ok: true, rows: freshPool() }), writeRow: async () => ({ ok: true }), reservations: null, emailSecret: KEY });
  const r = await claim.begin({ code: '123', email: emailA });
  return r.ok === false && r.outcome === 'claim_unavailable' || { ok: false, why: r.outcome };
});
await check('R23. a UNIQUE constraint that is NOT enforced in the store is detected, not trusted: two inserts both succeed only when the fake stops enforcing', async () => {
  const { claim, store } = build({ enforceUnique: false });
  const a = await claim.begin({ code: '123', email: emailA });
  const b = await claim.begin({ code: '123', email: emailB });
  // This arm PASSES by showing the design's dependence: with no enforcement two callers can hold the
  // same record, which is precisely why the live probe must prove enforcement before release.
  const same = a.recordId === b.recordId;
  return same && store.refused === 0 || { ok: false, why: `${a.recordId}/${b.recordId} refused=${store.refused}` };
});
// ── THE SHARED CODE RULE ───────────────────────────────────────────────────
await check('R24. one validator: short codes, punctuation and case survive; empty, control and over-long do not', async () => {
  const keep = ['777', '7', '123', 'aB_3-x', 'BRIDGE-2026-KEY', `${'z'.repeat(INVITATION_CODE_MAX_LENGTH)}`];
  const drop = ['', '   ', 'x'.repeat(INVITATION_CODE_MAX_LENGTH + 1), 'null', 'undefined', 'abc\u0000def', 'NaN', 42, null];
  return keep.every((c) => normalizeInvitationCode(c) === String(c).trim())
    && drop.every((c) => normalizeInvitationCode(c) === '') || { ok: false, why: 'form rejected or accepted wrongly' };
});
await check('R25. code matching stays case-sensitive: AB_3-X and aB_3-x are two different invitations', async () => {
  const { claim, store } = build();
  const lower = await claim.begin({ code: 'aB_3-x', email: emailA });
  const upper = await claim.begin({ code: 'AB_3-X', email: emailB });
  return lower.recordId === 6 && upper.recordId === 5
    && store.codes.find((r) => r.id === 6).code === 'aB_3-x' || { ok: false, why: `${lower.recordId}/${upper.recordId}` };
});
await check('R26. the reserved test code 777 registers end to end, which the three-validators build could not do', async () => {
  const { claim, store } = build();
  const b = await claim.begin({ code: '777', email: emailA });
  const done = await claim.finish({ code: '777', recordId: b.recordId, reservationId: b.reservationId, userId: 'acct-777', emailHash: b.emailHash });
  return b.ok && b.recordId === 500 && done.ok === true && Number(store.codes.find((r) => r.id === 500).used) === 1
    || { ok: false, why: `${b.outcome}/${done.outcome}` };
});

// ── TEN CONCURRENT REGISTRATIONS ON ONE CODE VALUE (the size a bulk issue really is) ──
await check('R27. eleven simultaneous registrations against a ten-record pool: exactly ten are granted, one is exhausted, no record is held twice', async () => {
  const { claim, store } = build();
  const begun = await Promise.all(
    Array.from({ length: 11 }, (_, n) => claim.begin({ code: 'TEN', email: `ten${n}@example.com` }))
  );
  const granted = begun.filter((b) => b.ok === true);
  const refused = begun.filter((b) => b.ok !== true);
  const held = store.reservations.map((r) => String(r.code_row_id));
  const distinct = new Set(held).size === held.length;
  return granted.length === 10 && refused.length === 1 && refused[0].outcome === 'invitation_exhausted'
    && held.length === 10 && distinct
    || { ok: false, why: `granted=${granted.length} refused=${refused.map((r) => r.outcome)} held=${held.length} distinct=${distinct}` };
});
await check('R28. and each of those ten registrations spends a DIFFERENT record end to end — one account per record, none shared, none skipped', async () => {
  const { claim, store } = build();
  const begun = await Promise.all(
    Array.from({ length: 10 }, (_, n) => claim.begin({ code: 'TEN', email: `ten${n}@example.com` }))
  );
  const done = await Promise.all(begun.map((b, n) => claim.finish({
    code: 'TEN', recordId: b.recordId, reservationId: b.reservationId, userId: `acct-${n}`, emailHash: b.emailHash
  })));
  const spent = store.codes.filter((r) => r.code === 'TEN' && Number(r.used) === 1);
  const owners = spent.map((r) => String(r.registered_user_id));
  return done.every((d) => d.ok === true) && spent.length === 10
    && new Set(owners).size === 10 && new Set(begun.map((b) => String(b.recordId))).size === 10
    || { ok: false, why: `spent=${spent.length} owners=${new Set(owners).size} records=${new Set(begun.map((b) => b.recordId)).size} outcomes=${done.map((d) => d.outcome)}` };
});
// ── CLEANUP / RECOVERY RETRY (measured: the first DELETE failed, the retry by primary key worked) ──
await check('R29. a DELETE that fails is retried and reconciled: released on the third attempt, and the record is spendable again', async () => {
  const { claim, store } = build({ faults: { deleteRefusals: 2 } });
  const held = await claim.begin({ code: 'TEN', email: emailA });
  const released = await claim.release(held);
  const afterRelease = store.reservations.length;
  const next = await claim.begin({ code: 'TEN', email: emailB });
  // Counted in two steps on purpose: `next` puts a NEW row back in the table, so reading the length
  // afterwards would say "1" and prove nothing either way.
  return released.ok === true && released.attempts === 3 && store.deletes === 3
    && afterRelease === 0 && next.ok === true && next.recordId === 200
    || { ok: false, why: `${JSON.stringify(released)} deletes=${store.deletes} afterRelease=${afterRelease} next=${next.recordId}` };
});
await check('R30. a DELETE whose ANSWER was lost but whose row is gone is reconciled as released in ONE attempt — never reported as a stuck record', async () => {
  const { claim, store } = build({ faults: { deleteLostResponses: Infinity } });
  const held = await claim.begin({ code: 'TEN', email: emailA });
  const released = await claim.release(held);
  const afterRelease = store.reservations.length;
  const next = await claim.begin({ code: 'TEN', email: emailB });
  // Nothing ages a reservation out, so a false "stuck" here is a record lost forever — and the retry
  // loop must not be what saves it. The read-back settles the first attempt on its own.
  return released.ok === true && released.attempts === 1 && store.deletes === 1
    && afterRelease === 0 && next.recordId === 200
    || { ok: false, why: `${JSON.stringify(released)} deletes=${store.deletes} afterRelease=${afterRelease} next=${next.recordId}` };
});
await check('R31. a store that never accepts the DELETE is reported as a failure, not as a release: the reservation stays pending and the record stays held', async () => {
  const { claim, store } = build({ faults: { deleteRefusals: Infinity } });
  const held = await claim.begin({ code: 'TEN', email: emailA });
  const released = await claim.release(held);
  const stillHeld = store.reservations.map((r) => `${r.code_row_id}:${r.status}`);
  const rival = await claim.begin({ code: 'TEN', email: emailB });
  return released.ok === false && released.attempts === 3 && store.deletes === 3
    && stillHeld.join(',') === '200:pending'
    && rival.ok === true && rival.recordId === 201
    || { ok: false, why: `${JSON.stringify(released)} deletes=${store.deletes} held=${stillHeld} rival=${rival.recordId}` };
});
// ── RESERVATION COMPLETION, AND THE ANSWERS THAT NEVER ARRIVED ──────────────
await check('R32. completion cannot be confirmed: the registration is still claimed (the record proves it), the reservation stays pending, and recovery neither re-writes nor re-claims it', async () => {
  const { claim, store } = build({ faults: { updateRefusals: Infinity } });
  const begun = await claim.begin({ code: 'TEN', email: emailA });
  const done = await claim.finish({ code: 'TEN', recordId: begun.recordId, reservationId: begun.reservationId, userId: 'acct-a', emailHash: begun.emailHash });
  const row = store.codes.find((r) => r.id === 200);
  const writesAfterClaim = store.writes.length;
  // The bookkeeping fault is still in force here, which is the point: recovery must read the RECORD
  // and conclude "this account already owns it", not take a second record or write the row twice
  // because the reservation never said `completed`.
  const recovered = await claim.recover({ email: emailA, userId: 'acct-a' });
  return done.ok === true && done.outcome === 'claimed' && done.reservationConfirmed === false
    && Number(row.used) === 1 && String(row.registered_user_id) === 'acct-a'
    && String(store.reservations[0].status) === 'pending'
    && recovered.ok === true && recovered.outcome === 'already_claimed'
    && writesAfterClaim === store.writes.length && store.reservations.length === 1
    || { ok: false, why: `${JSON.stringify(done)} status=${store.reservations[0]?.status} recovered=${JSON.stringify(recovered)} writes=${store.writes.length}/${writesAfterClaim}` };
});
await check('R33. completion wrote but its answer was lost: the read-back is the authority, and the reservation is reported completed', async () => {
  const { claim, store } = build({ faults: { updateLostResponses: Infinity } });
  const begun = await claim.begin({ code: 'TEN', email: emailA });
  const done = await claim.finish({ code: 'TEN', recordId: begun.recordId, reservationId: begun.reservationId, userId: 'acct-a', emailHash: begun.emailHash });
  return done.ok === true && done.reservationConfirmed === true
    && String(store.reservations[0].status) === 'completed' && String(store.reservations[0].invitee_user_id) === 'acct-a'
    || { ok: false, why: `${JSON.stringify(done)} row=${JSON.stringify(store.reservations[0])}` };
});
await check('R34. the reservation INSERT landed but its answer did not: the store is asked who holds the record, and NO second record is consumed', async () => {
  const { claim, store } = build({ faults: { createLostResponses: Infinity } });
  const first = await claim.begin({ code: 'TEN', email: emailA });
  const heldAfterFirst = store.reservations.map((r) => `${r.code_row_id}:${r.status}`);
  const second = await claim.begin({ code: 'TEN', email: emailB });
  // Measured between the two calls on purpose: one registration must leave EXACTLY ONE row before the
  // next caller arrives, or this is the double-spend it is meant to prevent — two records out of a
  // ten-record pool for one sign-up.
  return first.ok === true && first.recordId === 200 && heldAfterFirst.join(',') === '200:pending'
    && second.ok === true && second.recordId === 201 && store.reservations.length === 2
    || { ok: false, why: `first=${first.recordId}/${first.outcome} held=${heldAfterFirst} second=${second.recordId} rows=${store.reservations.length}` };
});
await check('R35. a claim write that answers 200 and persists ANOTHER account is caught by the read-back: unconfirmed, and the reservation is NOT completed', async () => {
  const { claim, store } = build({ faults: { writeLies: 'acct-somebody-else' } });
  const begun = await claim.begin({ code: 'TEN', email: emailA });
  const done = await claim.finish({ code: 'TEN', recordId: begun.recordId, reservationId: begun.reservationId, userId: 'acct-a', emailHash: begun.emailHash });
  return done.ok === false && done.outcome === 'claim_unconfirmed'
    && String(store.reservations[0].status) === 'pending'
    && String(store.codes.find((r) => r.id === 200).registered_user_id) === 'acct-somebody-else'
    || { ok: false, why: `${JSON.stringify(done)} res=${store.reservations[0]?.status}` };
});
// ── THE POOL THAT DID NOT FIT ON THE PAGE ──────────────────────────────────
await check('R36. a code whose visible page is fully spent but whose pool may continue is a NAMED FAULT, never a false exhaustion', async () => {
  const { claim, store } = build({ truncated: true });
  for (const row of store.codes.filter((r) => r.code === '123')) row.used = 1;
  const r = await claim.begin({ code: '123', email: emailA });
  return r.ok === false && r.outcome === 'invitation_pool_unpaged' && store.reservations.length === 0
    || { ok: false, why: JSON.stringify(r) };
});
await check('R37. and the same truncated page that DOES hold a free record still claims normally — the fault is for an empty candidate set only', async () => {
  const { claim, store } = build({ truncated: true });
  store.codes.find((r) => r.id === 3).used = 0;
  const r = await claim.begin({ code: '123', email: emailA });
  return r.ok === true && r.recordId === 8 || { ok: false, why: JSON.stringify(r) };
});

const failed = results.filter((r) => !r.pass);
for (const r of results) console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `   [${r.detail}]` : ''}`);
console.log(`\nRESULTS: ${results.length - failed.length}/${results.length} passed, ${failed.length} failed  (invitation reservations)`);
process.exit(failed.length ? 1 : 0);
