# P1 — System Admin Game Deletion: Evidence and Release Assessment

**Date:** 2026-11-24 · **Backend baseline:** `da49f8441c11ca2070bdf2bae677b6c32e8f1e8a` (verified as current `origin/main` by both `git ls-remote` and `gh api commits/main`, not assumed)
**Isolated worktree:** `C:\Users\denis\Github\ns-gamedel`, branch `feature/admin-game-deletion-backend`. The original dirty `NodeSend` checkout was not read into this branch and remains untouched.
**Frontend candidate:** `514ad394` on `feature/admin-game-deletion` (read-only inspected; **not modified**). Its `BRIDGEMIND-NODESEND-GAME-DELETION-HANDOFF.md` and `src/services/gameDeletionService.js` were available locally and were used as the contract of record.
**No production write, no live deletion, no deployment, no push, no NCB DDL, no frontend change.**

---

## 1. Verified contracts (MEASURED, not assumed)

**Data dependencies**, confirmed against the frontend source rather than only the prompt:

| Relationship | Evidence |
|---|---|
| Canonical game = `recorded_hands.id` | `gameDeletionService.js`: id validated `/^\d+$/`, route `DELETE /games/{recordedHandId}` |
| Replays reference the root via `recorded_hands.root_hand_id` | `App.jsx` replay chain: original stores `root_hand_id = NULL`; children carry the root's id; `UNIQUE(user_id, root_hand_id, version_number)` |
| Frontend seat vocabulary is **full names** | `TOURNAMENT_SEATS = ['North','East','South','West']`; `readSeat("N") === null` |
| Community publications | `community_games.source_hand_id`, `community_games.root_hand_id` |
| Reports / traces / attempt links | `game_analysis_reports.recorded_hand_id`, `ai_decision_traces.recorded_hand_id`, `tournament_attempts.recorded_hand_id` |
| Statistics are **live-computed**, no stored aggregate | handoff §3/§5: leaderboards read a `community_games` window; "there is no materialized aggregate table anywhere in the frontend" |

Because there is no stored counter, **nothing decrements**: deleting the `community_games` rows *is* the statistics correction. Arm `14` asserts no counter table was ever written.

**Response contract.** The frontend parses `body.error.code` — an **object** — and maps a 403 whose code is not exactly `not_system_admin` to "not authenticated". NodeSend's tournament routes instead emit `{error:'name', detail:'...'}` (a string). This route therefore emits the **object form** the client reads, and the divergence is stated in the module header rather than left for the integrator to discover.

## 2. Route implemented

`DELETE /games/:recordedHandId`, mounted in `bridge.js` beside `/clubs` and `/tournaments`, always registered (an absent route answers 404 and a 404 reads as "the feature does not exist").

Authorization chain, in order, all server-side:
1. the relay's own session verification — `authenticate` is wired to the **same `resolveSessionUser`** that `requireBridgeSession` uses, so this route cannot hold a weaker session truth than the rest of the relay;
2. `system_admins` through `clubs/clubNcbStore.js` → `isSystemAdmin`; an **unreadable** authority table is a 503, never a "you are not an admin";
3. only then the store, and **every** NCB call runs on the dedicated service account.

Input surface is one path parameter: no body field, query field, role, owner id or admin flag is ever read as authority (arm `5` proves a forged `is_system_admin`/`admin`/`user_id`/`role` body changes nothing and issues no write).

## 3. Replay-descendant policy — a deliberate departure from the handoff

The handoff (§3) proposes **leaving** replay children with a dangling `root_hand_id` and merely reporting them. The release instruction forbids dangling references. Both cannot be honoured, so the implemented policy is the stricter one:

- children whose `user_id` equals the canonical owner → **deleted as part of the sweep and reported** (`replayChildren`, and included in `removed.recordedHands`);
- any child belonging to a **different** owner → the request is **refused with 409 `foreign_replay_descendants` before any write**, deleting nothing and leaving the dataset byte-identical;
- rewriting a child's `root_hand_id` to NULL is **rejected outright**: the frontend's own rule is that "a row carrying a root_hand_id must never claim to be an original", so nulling it would fabricate provenance;
- a child whose owner cannot be read is classified **foreign**, because "unknown" must never license deleting another account's row (arm `NC3d`).

Refusing before the first write is what keeps this retry-safe: a refusal leaves no partial state to reason about.

## 4. Ordering, partial failure and idempotency

`SWEEP_STEPS` = tournamentAttempts → decisionTraces → analysisReports → communityGames → replayChildren → **recordedHand last**. NCB has no transactions, so the canonical row is the recovery marker: while it exists the game still shows in Game Review and the identical request completes the job, and every step is an equality-filtered delete-by-row-id, so re-runs are no-ops.

- **A delete call is never a delete.** Each table is re-read after its removals; a row still present is `game_delete_unconfirmed` and no count is reported.
- **Any failure stops the sweep** and answers 502 `game_deletion_incomplete` or 503 `club_store_unavailable`. No path returns `deleted:true` without `confirmedGone` (arm `NC3a` asserts this at the envelope builder, where a plant could otherwise hide).
- **The "OR" in the community contract is two queries.** NCB's grammar has no OR, so `source_hand_id` and `root_hand_id` are separate equality passes, deduplicated by row id so a row matching both is deleted and counted once (arm `7`).
- **Nothing goes unfiltered.** An empty id throws inside the store rather than issuing a filterless read on a shared table (arm `NC3b` counts the requests that actually reached the vendor).
- **Repeat delete** → 200 `alreadyAbsent:true`, never 404, and no new write (arm `16`).
- **Audit** goes to the bridge log as `{adminUserId, recordedHandId, deleted, alreadyAbsent, removed, replayChildren, ts}` — names and counts only, never a hand, an email or a table name. No audit table was created.

## 5. Existing relay DELETE — SECURITY ASSESSMENT: **the bypass is real and still open**

Read from the shipped gateway, not inferred:

```
PLAYER_TABLE_WRITE_POLICY: recorded_hands = full, community_games = full,
                           game_analysis_reports = full, replay_attempts = full
"full" grants create/update/delete to any session: TRUE
blocked-by-name (AUTHORITY/TOURNAMENT/SERVER_ONLY/CREDENTIAL): recorded_hands NO,
                           community_games NO, game_analysis_reports NO, replay_attempts NO
```

So **any authenticated player can today issue** `DELETE /ncb/data/delete/recorded_hands/<id>` and the relay forwards it on their bearer, which proves a session and not a permission (`shared_readwrite` = no row isolation). The new route is therefore **not** a complete authorization guarantee: it is the only *cascade-correct* path, while the *single-row* path remains open. Stating this plainly is required by the brief; claiming otherwise would be false.

It cannot simply be closed here, and the reason is a real dependency, not a convenience:

- The frontend's recorder-cancel and tutor-deletion flows still call `deleteRecordedHand()` through the relay (handoff §6, `src/services/recordedHandsService.js`). Dropping `delete` from those tables' policy breaks live, legitimate owner flows.
- Owner-scoping the relay instead would require the caller's `user_id` to be reliably populated on every `recorded_hands` row. **Unverified from here**: `recorded_hands` and `community_games` are not public-read tables (measured: `/ncb/public-data/read/recorded_hands` → 403 `table_not_allowed`), so no credential-free probe can show whether the column is populated, and I will not guess on a destructive path.

### Handoff — required before the authorization guarantee can be claimed

**Greta/Questera (frontend), in order:**
1. Add an owner-authorized route for the non-admin flows (e.g. `POST /games/:id/withdraw`) that proves `recorded_hands.user_id == session id` server-side, and migrate `deleteRecordedHand()` callers to it.
2. Confirm `recorded_hands.user_id` (and the owner column on `community_games`) is populated on **all** live rows, including rows written before NodeSend owned the write path. If it is not, backfill first — owner-scoping on a NULL column would deny every legitimate cancel.

**NodeSend (follow-up PR, after 1 and 2):**
3. Drop `delete` from the caller-bearer relay for `recorded_hands`, `community_games`, `game_analysis_reports`, `replay_attempts` (block by name like `TOURNAMENT_TABLES`, with a named refusal so a stale bundle learns where the verbs went), or restrict relay deletes on those tables to owner-matched rows.
4. Until step 3 ships, treat admin deletion as **cascade-correct but not exclusive**.

## 6. Statistics and cache

Server side: no stored aggregates exist, so nothing is decremented; the sweep removes the rows the leaderboards read live. Client side (verified in `514ad394`, unchanged): `invalidateGlobalLeaderboard()`, `invalidateSeasonLeaderboard()` and both first-page caches drop **only after** the server confirms `deleted:true` — the ordering the brief requires. The 60-second leaderboard cache is a bounded TTL and needs no server action; a listing may serve stale rows for up to that window after a confirmed delete, which is documented rather than hidden.

## 7. Files changed

- `games/gameDeletion.js` (new) — tables/columns, sweep order, id grammar, replay classification, plan, refusal and success envelopes, audit shape.
- `games/gameDeletionStore.js` (new) — exact-ID reads/deletes on the service account, per-step read-back proof, satellites-first execution, refusal on any unfiltered request.
- `games/index.js` (new) — the mount: authorization chain, declared route surface, 503-when-unconfigured, catch-all so no fault can escape a destructive handler.
- `bridge.js` — require, mount build on the club account, router registration, `gameDeletion` in `/health` and at boot, gate exports.
- `Dockerfile` — `COPY games/ ./games/` (without it the image builds green, passes a health check, then crash-loops on `Cannot find module` — the exact failure recorded for `tournaments/`).
- `verify-game-deletion.mjs` (new) — 42 arms.
- `verify-clubs-gateway.mjs` — arm `10j` re-aimed to account for the fourth router.

## 8. Test results

**New gate `verify-game-deletion.mjs`: 42/42.** Covering the 20 required cases (admin success; ordinary user, club admin and unauthenticated denial; forged identity; exact-id validation incl. injection and non-ASCII shapes; community/report/trace removal; flag-only trace preserved; attempt link removed with tournament, boards and other players' attempts byte-identical; replay cascade and foreign refusal; no dangling roots; statistics from live rows; idempotent repeat; partial failure and safe retry; read-back confirmation; relay path assessed; existing flows unaffected) plus negative controls `NC1`–`NC4b`.

**Seven-plant validation** — each plant breaks one guard, and every plant is caught:
`P1` authority check bypassed → 3 red (arms 2, 3, 5) · `P2` `deleted` always true → 1 red (`NC3a`) · `P3` replay children skipped → 3 red (`G1/7-9`, 12, 13) · `P4` satellite read-back proof removed → 2 red (`NC1b`, `NC1c`) · `P5` foreign-owner check removed → 2 red (4, 4b) · `P6` unfiltered-read guard removed → 1 red (`NC3b`) · `P7` community read-back guard removed → 1 red (`NC1d`).

Three of those plants **initially went undetected**, and the arms added to catch them are the real product of this section: a global "keep the row" knob let one lying table hide behind another step's proof; the `P2` plant was unreachable from HTTP; and an inert fault key left over from a rename (`acceptDeleteButKeepRow` → `keepRowsIn`) was caught only after adding arm `NC4b`, which now fails if any declared fault knob is never read. `NC4b` immediately found a second dead knob.

**Existing suites, all re-run at the final state:** tournaments gateway 221/221 · tournament HTTP integration 24/24 · import-failure gate 65/65 · clubs 287/287 · NCB gateway 132/132 · NCB integration 98/98 · session quota 407/407 · invitation reservations 50/50 · invitation-code rule 57/57 · decision-key forwarding 48/48 · system-AI credentials 32/32 · trickster 21/21 · sign-in guardrails 8/8 · game deletion 42/42 — **1,492 arms, 0 failures.**

One existing arm legitimately moved: `verify-clubs-gateway.mjs` **10j** asserts the *complete* mounted-route inventory, and a new router is exactly what it exists to notice. It was re-aimed to name the fourth router and drift-check it against its declared surface — not excluded — and hardened from `!== null` to `Array.isArray`, because a dropped inventory key returned `undefined`, and `undefined !== null` is true. That bug was introduced by my own edit and was caught by the crash it caused, not by luck.

## 9. Remaining risks

1. **The relay bypass (§5)** — the single most important one; a release blocker for claiming the authorization guarantee, not for the route working.
2. **Service-account reach is unproven.** Whether the `CLUB_NCB` account may delete rows in `recorded_hands`/`community_games`/`game_analysis_reports`/`ai_decision_traces` under their live RLS has not been exercised anywhere — no mock can prove a vendor's grant. If it cannot, every sweep fails closed with a named 502/503 and nothing is reported as deleted. **Verify on a staging row before the first production use.**
3. **Table/column names are the documented contract, not an inspected schema.** NodeSend has no games schema config; an unknown filter name fails the whole read on this backend and is reported as a refusal, never as an empty result.
4. **`user_id` population on legacy rows** is unverified (see §5, handoff item 2).
5. **Bounded staleness** of the leaderboard caches after a confirmed delete (≤60 s), by design.
6. **`alreadyAbsent` cannot distinguish a completed earlier sweep from an id that never existed** without a tombstone table; the response therefore reports `noTraceRemaining` — what was actually read — and arm `16c` asserts the two stay indistinguishable rather than inventing a difference.

## 10. Recommendation

**GO** to integrate with frontend `514ad394` for the *authorized* deletion path, **conditional on**:
- verifying service-account delete reach on a disposable row (risk 2) before any real game is deleted, and
- accepting §5's handoff as a tracked release blocker, so the relay path is closed in a follow-up and the guarantee is eventually true.

**NO-GO** on describing the authorization story as complete today: the relay still lets any session delete a single game row, and that is outside this change's permitted scope.

---

# PART 2 — the relay bypass is now closed (§5 supersedes §5 above)

Follow-up commit on the same branch. `§5`'s "still open" finding is resolved for the tables the player app
does not legitimately delete from, and reduced to an ownership check for the two it does.

## What was measured before designing

The decisive unknown was not "can we block relay deletes" but **which player workflows actually issue
them**. Enumerated literally in Greta `src/` (read-only; a loose first regex over-matched and produced
false hits for all five tables — corrected to literal `delete/${TABLE}` and `method: 'DELETE'` sites):

| Table | Frontend relay DELETE call site | Consequence |
|---|---|---|
| `recorded_hands` | `recordedHandsService.js:1493`, used at `App.jsx:1975` and `:2465` (recorder cancel, abandoned cleanup) | must keep working → owner-verified |
| `community_games` | `recordedHandsService.js:1506` (`deleteCommunityGameBySource`, unpublish) | must keep working → owner-verified |
| `game_analysis_reports` | none | `delete` closed on the relay |
| `replay_attempts` | none | `delete` closed on the relay |

Ownership is checkable because the app writes the owner itself: `user_id` appears in the recorded-hand
payload (`App.jsx:2135`, `recordedHandsService:1222/1280/1341/1392`) and in the community payload
(`App.jsx:2294`, `recordedHandsService:1341`). No assumption was made about rows the app did not write —
see the fail-closed rule below.

## The correction (`ncb/gateway.js`)

`CALLER_DELETE_BLOCKED = [game_analysis_reports, replay_attempts]` → refused **on the delete verb only**,
before the credential is parsed, with the named `game_record_via_admin_route_only` (not
`table_not_allowed`, which an operator would misread as a missing deployment variable). Reads, creates and
updates on those tables are untouched, so tutoring and analysis flows are unaffected.

`CALLER_DELETE_OWNER_COLUMN = { recorded_hands: 'user_id', community_games: 'user_id' }` → before any
caller delete is forwarded, the row is read **on the caller's own credential** and its owner column is
compared to the identity inside the **sealed handle** (`resolved.session.userId`, verified against the
mint site — `seal.seal({cookie, userId, instance, email})`). Nothing is ever read from the request body or
query. Every ambiguous case denies:

| Condition | Answer | Why |
|---|---|---|
| read fails / vendor unreadable | 503 `storage_unavailable` | a transport fault is not evidence of permission; answering 401 here is the mass-sign-out failure this gateway exists to prevent |
| no row with that id | 404 `not_found_or_not_yours` | preserves the verb's existing answer, so a double cancel gets no new error class |
| owner column empty/absent | 403 `ownership_unverifiable` | legacy rows are **not** attributed by guesswork; backfill or the admin route serves them |
| owner ≠ session id | 403 `not_record_owner` | the bypass itself |

The constants are exported so the gate asserts the shipped sets rather than a copy, matching the pattern
`TOURNAMENT_TABLES` already uses.

## Verification

**`verify-game-delete-bypass.mjs` 20/20.** The fake vendor deliberately implements `shared_readwrite`
**with no row isolation whatsoever** — control `X1` proves it by deleting player A's row directly at the
vendor as player B and asserting the row *actually disappeared* (not merely that the call returned 200,
which would be unfalsifiable). Every refusal below is therefore the gateway's doing, not the mock's. This
matters: the neighbouring gateway fixture scopes reads by owner, and copying that would have made all 20
arms pass for the wrong reason — the exact `offset=` failure mode.

Arms: 1 cross-account denied and row survives · 1b refusal is named · 1c a vendor-`administrator` session
is refused too (role is not ownership) · **1d claiming the real owner in the query and body buys nothing**
· 2/3 the closed tables refuse even their own owner, with the reason named · 3b the block is DELETE-only
(read/create/update still work) · 4 recorder cancel on the caller's own row still succeeds · 5 community
unpublish still succeeds · 5b unpublish does not extend to another player's row · 6a no-owner row refused
· 6b unknown id is 404 with no delete forwarded · 6c unreadable ownership read is 503 with nothing removed
· 6d absent owner column fails closed · 7 an unrelated full-policy table is untouched (no wildcard block)
· 8/8b the admin route still answers, and the gate asserts the shipped constants · X2 the gateway forwarded
exactly one delete for the whole run — the legitimate one.

**Eight plants, all detected** (`gateway.js` restored byte-identically each time): block removed → 4 red;
ownership check removed → 10 red; empty-owner fail-open → 1 red; compared identity not from the session →
7 red (caught by 1d); narrowing widened to every verb → 1 red; unreadable read allowed → 1 red; missing row
treated as owned → 2 red; owner map pointed at a column no row carries → 6 red.

Two harness bugs surfaced on the way and are worth recording, because both would have produced a
misleading report: the first Q4 plant was **inert** (a `claimedUserId ??` fallback that can never fire on a
real seal), and a rewritten plant loop destructured a *string* into `[from, to]`, turning all eight edits
into no-ops and printing eight impossible "NOT DETECTED" results. The second failure is why the harness now
refuses to run a plant that changes no bytes, and why arm `NC4b`-style inertness checks are worth their
cost in test code.

## Residual items after Part 2

1. **Legacy rows with an empty `user_id` cannot be cancelled by their owner** — they answer
   `403 ownership_unverifiable`. This is deliberate fail-closed behaviour, and it makes the backfill
   handoff user-visible rather than silent: until `recorded_hands.user_id` / `community_games.user_id` are
   confirmed populated, affected players must use the admin route. **This is the one user-visible
   regression risk in Part 2 and should be checked against live data before deploy.**
2. Service-account delete reach for the cascade route is still unproven (Part 1 §9.2) — unchanged.
3. The relay still *reads* these tables for any session (`shared_readwrite` has no row isolation), so
   cross-account disclosure is a separate, pre-existing issue; this change only closes the destructive
   verb. Not claimed as fixed.

**Status:** the authorization bypass on the deletion *workflow* is closed. `DELETE /games/:id` is now the
only way to remove a game completely, no player can delete another player's game through the relay, and
the two legitimate player workflows are pinned by tests as still working.

---

# PART 3 — storage readiness: identity, permissions, cascade completeness

## 1. Which identity actually deletes (verified in code, not assumed)

`clubs/ncbAccountClient.js` → `authenticatedRequest()` calls `rawFetch(url, { method, body, bearer: token })`,
where `token` is obtained from `/auth/sign-in/email` using `CLUB_NCB_EMAIL` / `CLUB_NCB_PASSWORD`, and the
session identity is pinned by `CLUB_NCB_EXPECTED_USER_ID` (identity mismatch ⇒ refusal). So:

- **The deleting identity is the dedicated club service account's own NCB session** — the same account Clubs
  and Tournaments use. One credential pool, one sign-in, one cooldown. The caller's bearer never touches
  storage on this path (arm-proved in Part 1: `7g`/`T2`).
- It is **not** an administrative identity. NCB exposes no admin bypass through this API: the route surface is
  `path + Instance + bearer` with no caller-type discriminator, so the account can be no more privileged than
  an ordinary NCB session holding the same table grants.
- It is **not** a row owner for the rows this cascade deletes. `recorded_hands` and `community_games` rows were
  created by *players'* sessions, so under NCB's ownership stamping (`user_id` is auto-stamped from the
  writing session) the service account is a stranger to those rows.
- Under `private` RLS the same property is what makes the account able to read `system_admins` rows it wrote
  (Part 1) — and equally unable to assume ownership of rows it did not write.

Read-back after each delete uses the same account and the same equality filters, so **read-back capability is
the same open question as delete capability** — not an independent assumption.

## 2. Does `community_games` = `shared_read` block it? **Unproven, and the obvious evidence is void**

Two facts make this the binding unknown, and one of them removes what looked like proof:

1. `recordedHandsService.js:1506` performs the player-side community delete as
   `dataFetch(...).catch(() => {})` — **the error is swallowed**. So "players unpublish today, therefore
   DELETE on `community_games` is permitted" does not follow: a denied delete would look like a successful
   unpublish to the UI. The only production signal we thought we had is not a signal.
2. If `shared_read` is accurate, non-owner writes are refused, and the service account is a non-owner — so
   step 4 of the sweep fails and the whole deletion correctly answers **502/503 with the canonical row
   intact** (fail-closed, verified by plants in Parts 1–2). The feature would then be a no-op in production
   rather than a data hazard.

Consequence for the release decision: **the route is safe to deploy but cannot be assumed to work.** Nothing
about `shared_read` needs to change, and per §2 of the brief it must not be broadened to `shared_readwrite`
to make deletion "succeed" — that would hand destructive power over other players' publications to ordinary
sessions, which is the exact hole Part 2 closed.

The narrowly scoped alternatives, in preference order, all requiring separate authorization:

- **A. Grant the dedicated account a scoped delete privilege** on the game tables (`recorded_hands`,
  `community_games`, `game_analysis_reports`, `ai_decision_traces`, `tournament_attempts`, `replay_attempts`)
  at the vendor — no RLS class change, no player-facing widening. Preferred.
- **B. A vendor-side cascade executed by an already-privileged channel** (NCB MCP) with NodeSend issuing one
  audited request per game — only if A is unavailable.
- **C. Ownership transfer before delete** — rejected: NCB's `UPDATE` of `user_id` moves row ownership
  (measured 2026-11-17), so "transferring" a row to the service account to delete it is a silent ownership
  rewrite of a player's data, and it mutates the very column the deletion is supposed to be neutral about.

## 3. Cascade completeness — three real gaps found and fixed

Auditing the implemented sweep against the live column list (not the handoff prose) found that my own
implementation was incomplete:

| Dependency | Before | Now |
|---|---|---|
| `replay_attempts.recorded_hand_id` / `.root_hand_id` | **table absent from the sweep entirely** | swept by both columns; `removed.replayAttempts` reported |
| `recorded_hands.parent_hand_id` | children found by `root_hand_id` **only** | children found by both columns, deduplicated by row id |
| `coach_feedback_flags.hand_id` / `.root_hand_id` | unaccounted for | **preserved and reported** as `preserved.coachFeedbackFlags`; never deleted |

- `parent_hand_id` matters concretely: `root_hand_id` names the chain's *first* row while `parent_hand_id`
  names the previous one (`App.jsx: const rootId = hand.rootHandId ?? hand.id`). Deleting a game that is
  itself a replay therefore left a child whose parent no longer existed — precisely the dangling reference
  the brief forbids. Arm `D2` reproduces it with a mid-chain child.
- Coach flags are **not** deletion dependencies. They are another person's work product about a game;
  deleting them would destroy a coach's record behind an admin's click, and nulling their reference would
  be provenance damage again. They are counted so the outcome is visible, and `D3`/`D3b` fail if anything
  ever issues a delete against that table.
- `countCoachFlags` initially double-counted a flag carrying the same value in both columns; the gate caught
  it by asserting an exact number rather than "non-zero", and it now deduplicates by row id.

## 4. Verification

`verify-game-deletion.mjs` **50/50** (was 42; +8 arms: `D1`, `D2`, `D3`, `D3b`, `D4`, `D4b`, `16d`, `16e`).
Six new plants, **all detected**: chain-root-only attempt not swept → 2 red; `parent_hand_id` discovery
removed → 3 red; coach flags swept → 2 red; flag count not deduplicated → 1 red; absence-probe ignoring
`replay_attempts` → 1 red; `replay_attempts` dropped from the inventory → the gate refuses to produce a
report (loud, though less diagnosable than `D4`'s assertion).

Two of these arms were **masked** at first and had to be rewritten: `16d` initially left the other satellite
tables populated, so an unrelated probe satisfied it and plant R5 stayed green; and `R3` was first written as
an inert edit that changed no bytes. Both failures are recorded here because a plant that cannot fail is not
a control.

Full regression at the final state — **1,550 arms, 0 failures**: game deletion 50 · relay bypass 20 · NCB
gateway 132 · NCB integration 98 · clubs 287 · tournaments 221 · tournaments integration 24 · import-failure
65 · session quota 407 · invitation reservations 50 · invitation-code rule 57 · decision-key 48 · system-AI
32 · trickster 21 · sign-in guardrails 8.

## 5. Disposable-data verification plan (owner-executed; nothing here was run)

**Where:** a staging database with the same schema *and the same RLS classes*, never production, and never the
13 recorded games / 2 community rows / 6 reports / 271 traces / 1 attempt / 1 flag that exist today.

**Setup (one disposable owner):** create disposable NCB accounts `qa-owner` and `qa-other`; through the
existing relay with each account's own session, create: 1 `recorded_hands` (owner A) with 2 replay children
(one `root_hand_id`-linked, one **`parent_hand_id`-only**), 2 `community_games` (one keyed by
`source_hand_id`, one by `root_hand_id`), 1 `game_analysis_reports`, 2 `ai_decision_traces` (one
`recorded_hand_id = game`, one **`recorded_hand_id = NULL` flag snapshot**), 1 `replay_attempts` keyed only
by `root_hand_id`, 1 `tournament_attempts` on a disposable tournament, and 1 `coach_feedback_flags` for a
disposable `qa-other` game (must survive).

**Steps and expected results** — one paste-able command per step, run against the deployed NodeSend with the
operator's own session:

1. As `qa-other` (ordinary player): `DELETE /ncb/data/delete/recorded_hands/<A's id>` → expect **403
   `not_record_owner`**, row still present. *Fails if Part 2 regressed.*
2. As a System Admin: `DELETE /games/<A's id>` → expect **200** `deleted:true`, and
   `removed = {recordedHands:4, communityGames:2, analysisReports:1, decisionTraces:1, tournamentAttempts:1,
   replayAttempts:2}`, `preserved.coachFeedbackFlags:1`, `replayChildren:3`.
   **If this answers 502/503 naming `club_account_forbidden` or `game_delete_unconfirmed` at the
   `communityGames` step, §2 is answered: the dedicated account cannot delete, and option A is required.**
3. Read back through existing routes only: `GET /games/<id>` → 404; the owner's `GET /tournaments` and the
   community/My Games lists no longer return the game; the flag-snapshot trace and `qa-other`'s flag are
   still present.
4. Repeat step 2 → **200 `alreadyAbsent:true`**, zero new writes.
5. Statistics: confirm the owner's standing drops by exactly the deleted publication and no other row changed.
6. Stop conditions: any 503 naming the club account, any `BUT THE DRAFT HEADER REMAINS`, any deletion of a row
   not in the disposable set → **STOP**, keep the canonical row as the recovery marker, and report.

If staging cannot reproduce the vendor's RLS classes, this plan proves *code paths* only, and §2's permission
question stays open until resolved with Questera — a staging environment with different grants would give a
false GO.

## 6. GO / NO-GO

**NO-GO for release to players** as of this commit: the deletion cannot be assumed to reach `community_games`,
and the one piece of evidence that suggested it could (player unpublish works) is void because the frontend
swallows that error.

**GO for integration**: merge and deploy behind the existing System-Admin-only surface, then run §5 on
disposable staging rows. Step 2 of that plan is the actual capability test, and it is read-only with respect
to real data. Do not broaden `community_games` beyond `shared_read` to make it pass; escalate to option A.

---

# PART 4 — integration readiness against frontend `514ad394`

## 1. Candidate state (verified, not recalled)

| Item | Result |
|---|---|
| Worktree `ns-gamedel` | clean (`git status --short` empty) |
| HEAD | `cf70be478d565fa8868f35eefb433f05e1d763fb` |
| Remote `main` | `da49f84…` by both `ls-remote` and `gh api` — **nothing pushed** |
| Stack | `838c295` → `81d9141` → `cf70be4` |
| Dirty `NodeSend` checkout | preserved, 14 entries, never read into the branch |
| Greta | read-only; its 34 modified files predate this session (checked `src/App.jsx` mtime `2026-11-22`) and the deletion client exists only as a committed object |

Feature presence, read from the loaded modules rather than from this document: route `DELETE /games/:recordedHandId`
registered; `isSystemAdmin` present in the mount; sweep `tournamentAttempts, decisionTraces, analysisReports,
replayAttempts, communityGames, replayChildren, recordedHand` (canonical last); tables
`recorded_hands, community_games, game_analysis_reports, ai_decision_traces, tournament_attempts,
replay_attempts`; coach disposition `preserved-and-reported`; gateway `CALLER_DELETE_BLOCKED =
[game_analysis_reports, replay_attempts]`, `CALLER_DELETE_OWNER_COLUMN = {recorded_hands: user_id,
community_games: user_id}`; `game_delete_unconfirmed` present in the store.

## 2. Contract compatibility with the client of record

**Compatible, verified by reading both sides:**

| Contract point | Evidence |
|---|---|
| URL and verb | client `` `${GATEWAY}/games/${encodeURIComponent(id)}` `` ↔ route `/games/:recordedHandId` |
| Bearer header | `sessionAuth.js` emits `{ Authorization: 'Bearer <token>' }` from `SESSION_TOKEN_KEY`; `api.js:153-155` stores the gateway's own `body.token`, i.e. the **sealed `ncbs1.` handle** — which is what `resolveSessionUser` requires under `native` transport (a raw token is refused 401 `unsupported_credential`, by design) |
| Success shape | client needs `status==='success'`, `data.deleted===true`; route emits exactly that, plus `alreadyAbsent`, `neverFound`→`noTraceRemaining`, `removed`, `replayChildren` |
| 401 / 403 `not_system_admin` / 503 | all mapped by the client, and produced with those exact codes |
| Cache invalidation | client drops leaderboards and both first-page caches **only after** `deleted===true`; an idempotent repeat still sets `deleted:true`, so the caches are not left stale (arm `C3b`) |
| No false success | every refusal is `{status:'error', error:{code,message}}` with **no** `data` key (arms `C1`/`C2`), so the client's `deleted !== true` guard always trips |

**Two mismatches, both on the client's side, neither a data risk:**

1. **Unmapped statuses.** The client branches on 200/401/403/404/503 only (verified: `mentions 409: false,
   mentions 502: false`). The route's two most actionable answers — **409 `foreign_replay_descendants`** and
   **502 `game_deletion_incomplete`** — therefore fall into `malformed_envelope` and render as *"The server
   answer was not a deletion confirmation. Nothing was deleted."* Safe (nothing is claimed, caches stay), but
   it throws away "delete the other players' replays first" and "retry the same request to finish".
2. **One code shares a status.** A malformed id is 404 `invalid_game_id`, and the client maps every 404 to
   `game_not_found` (*"no game with this id"*). Harmless in practice — the client validates `/^\d+$/` first,
   so it can only arise from a hand-built request — but the message would be wrong.

**Handoff (Greta, small and exact):** in `gameDeletionService.js`, after the status branches, switch on
`code` before defaulting: `foreign_replay_descendants` → new reason `replay_conflict`;
`game_deletion_incomplete` → new reason `deletion_incomplete`; then add `gameDeletionErrReplayConflict` and
`gameDeletionErrIncomplete` to `en/admin.json` and `el/admin.json`, extend `DELETE_REASON_KEYS` in
`GameReviewAdmin.jsx`, and prefer `invalid_game_id` over `game_not_found` when the code says so. The
backend already sends everything needed; **no backend status should be changed to fit the gap**, because
mapping a refusal to "storage unavailable" would tell an administrator to wait for something that will never
recover.

## 3. Backend correction made here — one minimal, and it was my own bug

While asserting the contract I found two refusals that had been collapsing into the same 503: a
**transport** failure (storage never consulted — "try again later" is right) and a **vendor-refused write**
(the storage answered *no*, which under the open capability question most likely means the dedicated account
lacks a delete grant). Telling an admin "the game store could not be reached, try later" about a permission
refusal sends them to wait instead of to fix it, and the retry can never succeed. `TRANSPORT_REASONS` now
separates them: transport → 503 `club_store_unavailable`; refusal or unconfirmed removal → 502
`game_deletion_incomplete` naming the step. Arms `C1`–`C4` and plants `T1`–`T4` pin it (T1 → `C4` red,
T2 → `C1` red, T3 → `C3` + `G1/7-9` red, T4 → `16` + `C3b` red).

## 4. Staging availability — **none exists**

Scanned both repos for instance identifiers and staging-style names. Real instances found:
**`55954_bridgemind` only** (`.env.example`); the other values (`diag_instance`, `inst`, `test_instance`) are
in-file test fixtures in gate scripts, and every "staging/sandbox" mention is either this document or an
unrelated script. There is no second database, no staging deploy target, and no configuration in either repo
that would point NodeSend at an equivalent-but-disposable instance.

Consequences, stated plainly:

- §5's plan as written ("preferably a separate staging database") **cannot be executed today**. Building one
  is a Questera task, not a NodeSend change: an instance whose RLS classes differ from production would give
  a **false GO** on the only question that matters (whether the service account can delete).
- Until a faithful staging exists, the capability question can only be answered by a **disposable test inside
  production**, which is a separately authorized act and is not performed here. The minimal safe form of it:
  two throwaway NCB accounts, one game chain created through the normal relay flows by `qa-owner` (never
  touching the existing 13 games / 2 community rows / 6 reports / 271 traces / 1 attempt / 1 flag), one
  System Admin `DELETE /games/:id`, read-back, then stop. A 200 with the expected counts answers §2 of Part
  3; a 502 naming `club_account_forbidden` at `communityGames` proves the grant is missing and escalates to
  option A. **No production write is authorized by this document.**

## 5. Final verdict

| Question | Answer |
|---|---|
| Backend ↔ frontend contract | Compatible on every path that claims success; two client-side mapping gaps, no data risk, handoff specified |
| Staging available | **No** — single instance `55954_bridgemind`, no second database in either repo |
| Can true delete permission be tested today | **Not safely** — only in production with explicit authorization, or after staging is provisioned with equivalent RLS |
| Tests | gate 55/55 (+C1–C4, T1–T4 plants), full suite **1,525 arms, 0 failures** |
| Commit | this commit on `feature/admin-game-deletion-backend`, nothing pushed |
| **GO / NO-GO** | **GO** to merge and deploy behind the System-Admin surface for a *staged* rollout where the first deletion is a throwaway chain owned by a test account, with a stop on any 502. **NO-GO** for announcing the feature as working, and **NO-GO** on any bulk or routine admin use, until §4's capability test has actually returned 200 with the expected counts |
---

# PART 5 — P0: the cascade deleted other players' satellites. Fixed, and proven falsifiable.

Deployed premise for this part: `0f868b8` on main and live. Found while preparing the Game 524
acceptance, while auditing `execute()` against its own filters — not from a test failure.

## 1. The defect (MEASURED in source, live-reachable in shape)

`recorded_hands` descendants were owner-checked (`§3`). The satellites were not: `execute()` built
`ids = [canonicalId, ...replayChildIds]` and deleted every row whose reference column equalled one of
them. **`user_id` / `userId` / `ownerId` occur 0 times in the whole of `gameDeletionStore.js` at
`0f868b8`** (measured against `git show 0f868b8:games/gameDeletionStore.js`, not from memory).

Why that reaches real data, from the frontend's own writers:

| Row | Written by | Shape |
|---|---|---|
| `replay_attempts` | `replayEligibility.js:112-121` `startReplayAttempt` | `{ root_hand_id: A's game, user_id: B }` |
| `community_games` | publish path, `user_id` on every insert | B publishes a replay of A's game → `root_hand_id: A's game`, `user_id: B` |

`root_hand_id` names a chain's FIRST row, so a filter on the deleted game's id selects those rows.
Deleting player A's game therefore destroyed B's publication (removing it from the Community pool and
the live statistics computed from it) and B's consumed replay attempt — silently, with a 200 and no
refusal. The existing `409 foreign_replay_descendants` covered only `recorded_hands` children.

**Why the green gate could not have caught it.** Every seeded satellite carried the same
`publisher_user_id: '7'` as the target owner. That column does not exist in the frontend at all — the
fixture invented it. A fixture uniform on the one dimension the code never filters makes the whole bug
class invisible. The fixture is now corrected to the live column and deliberately seeded to DIFFER.

## 2. Ownership policy implemented

| Cascade table | Owner column(s), resolution order | Proof |
|---|---|---|
| `community_games` | `user_id` | relay owner rule already used it (`CALLER_DELETE_OWNER_COLUMN`) |
| `replay_attempts` | `user_id` | `replayEligibility.js:117` |
| `game_analysis_reports` | `user_id` (= hand owner) | `gameAnalysisService.js:305` |
| `ai_decision_traces` | `user_id` | `aiDecisionTraces.js:62/105/139` |
| `tournament_attempts` | `player_user_id`, then `user_id` | `tournamentNcbStore.js:927` writes the player; NCB stamps the service account |

Rules, each pinned by an arm:
* **A reference match is not ownership.** Audited for direct matches (`source_hand_id`, `recorded_hand_id`)
  as well as lineage matches (`root_hand_id`) — F2.
* **Authorship is not ownership.** A report authored by a coach but owned by the player still cascades (r1).
* **The service account is not the owner.** `tournament_attempts` resolves from `player_user_id` first, or
  every legitimate deletion would refuse (P3 proves 24 arms redden if that priority flips).
* **Unreadable fails closed.** A selected row with no readable owner refuses; so does a canonical row with
  no readable owner — and that case is reported as *unverifiable*, not as *foreign*, because the repair differs.
* **Scoped to selected rows.** Foreign rows keyed to OTHER games must not make a game undeletable (F7/F7b).
* **One probe list.** `SWEEP_PROBES` drives the audit, the sweep and the absence proof, so they cannot
  disagree about what was in scope (NC5e).
* Preserved unchanged: the child policy, tournament-attempt link handling, coach-flag preservation,
  canonical-last ordering, read-back proof, the transport/refusal 503-vs-502 split.

## 3. Answer shape

`409` with `body.error.code = "foreign_satellite_owners"` — object envelope unchanged, one new code.
Message carries counts, never ids, table names or account ids (NC4c). Two variants of one code:
* pre-flight (before any write): *"… so the cascade cannot be completed safely. Nothing was deleted."*
* mid-sweep backstop: *"… The cascade stopped there; records already removed by this request are not
  restorable."* — it never claims nothing was deleted when earlier satellites are already gone.
A store that cannot produce the inventory is refused 503 rather than swept un-audited (NC5i).

## 4. Verification

`verify-game-deletion.mjs`: **77/77** (was 55; +22 arms — F1–F8, NC5–NC5i, 16f/16g, NC4c).
Full affected suites, all green: game-deletion 77, game-delete-bypass 20, ncb-gateway 132,
ncb-integration 98, clubs-gateway 287, tournaments-gateway 221, tournaments-integration 24,
session-quota 407, signin-guardrails 8, invitation-reservations 50, invitation-code-rule 57,
decision-key 48, system-AI 32, trickster 21, import-failure 65 → **1,547 arms, 0 failures**.

Negative controls — each plant disables one clause; every one reddened at least one arm, and every file
was restored byte-identically (digest-verified):

| Plant | Red arms |
|---|---|
| P1 pre-flight refusal disabled | F1 F2 F3 F4 F5 |
| P2 sweep backstop disabled | NC5 NC5b NC5c |
| P3 owner priority flipped to `user_id` | 24 red, incl. G1/7-9, F7, NC5d |
| P4 unreadable owner treated as own (fail OPEN) | F4 F6 NC5c NC5g C1 C2 |
| P5 `community_games.root_hand_id` probe removed | F1 F1b F4 F8 NC5 NC5e C4 |
| P6 mid-sweep stop degraded to generic 502 | NC5h |
| P7 inventory-less store allowed to sweep | NC5i |
| P8 absence proof ignores `community_games` | 16f |
| P9 table with no owner policy waved through | NC5f |
| P10 only the canonical id audited | F5 |

P1 leaves F6 green on purpose: with the pre-flight disabled, F6's row is still caught by the sweep
backstop — two independent layers, separately tested.

## 5. BridgeMind-Greta handoff (exact, 4 edits)

Client at `9430fb8` maps named codes at `gameDeletionService.js:137-143`; an unmapped code reaches
`:151` → `malformed_envelope` ("not a recognized deletion error — treated as NOT deleted"). **Safe** (it
never claims deletion) but it discards the most actionable answer this route produces.

1. `src/services/gameDeletionService.js` — `GAME_DELETION_REASONS`: add
   `foreign_satellite_owners: 'foreign_satellite_owners'`.
2. same file, `GAME_DELETION_REASON_DOCS`: add
   `foreign_satellite_owners: '409 — refused intact: a publication, replay attempt or report in the cascade belongs to another account (or has no readable owner); NOTHING was deleted'`.
3. same file, after `:138`: add
   `if (code === 'foreign_satellite_owners') return refusal(GAME_DELETION_REASONS.foreign_satellite_owners, code);`
4. `src/components/admin/GameReviewAdmin.jsx` `DELETE_REASON_KEYS` (`:303-320`): add
   `foreign_satellite_owners: 'gameDeletionErrForeignSatellites'`, plus that key in
   `src/locales/en/admin.json` and `src/locales/el/admin.json`. Suggested EN text: *"Another player's
   publication or replay attempt is attached to this game, so nothing was deleted. Remove those records
   first."* Do NOT reuse the replay-descendants line: it tells the admin to delete replay descendants,
   which is a different repair. `verifyAdminGameDeletion` B16 pins the reason table, so it must be
   extended with the new key in the same change.

## 6. Still uncertain after this fix

* **Service-account DELETE reach** remains unproven (Part 3 §2). No mock can prove a vendor grant; the
  unpublish-success evidence is void because `recordedHandsService.js:1506` swallows the delete error.
* **Legacy rows with an empty `user_id`** now fail closed for their whole cascade, matching the documented
  backfill handoff. A game with no satellites is still deletable — the unreadable owner blocks the
  cascade, not the single row.
* **Race between audit and sweep** is closed for deletion (the backstop tests the same predicate at the
  write) but a row created between them can leave a dangling reference; NCB has no transactions, so this
  is reported as a partial sweep, not prevented.
* **No staging instance** exists (Part 4 §4); nothing in this part was executed against production.

## 7. Verdict

| Question | Answer |
|---|---|
| Defect confirmed | Yes — no owner predicate existed in the satellite sweep at `0f868b8` |
| Fixed | Yes, pre-flight + per-write backstop + single probe list |
| Protection falsifiable | Yes — 10 plants, all detected, tree restored |
| Live rows affected so far | Unknown; no deletion has ever been executed by this project |
| GO / NO-GO — backend safety release | **GO**, as a recommendation only: nothing was pushed or deployed here, per instruction. If released, it must be the prerequisite for any further deletion acceptance, and health + the verb control re-verified after deploy (the deployed SHA changes) |
| GO / NO-GO — deleting Game 524 on the CURRENT build | **NO-GO** until the corrected inventory is returned. Foreign-owned satellites were reachable by `root_hand_id`; on `0f868b8` they would be deleted, not refused |
