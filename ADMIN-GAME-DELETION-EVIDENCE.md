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
