# P0 — Live Tournament Import Failure (0/32 boards): Evidence Report

**Date:** 2026-11-23 · **Production:** https://nodesend.waveloc.com · **Instance:** `55954_bridgemind`
**Baseline at investigation start:** `76d297b1e2ae5d72e5e0dc2d862626680dc51347`
**Repair branch:** `fix/tournament-import-diagnostics` (isolated worktree `ns-tourn-repair`)
**Constraint honoured:** no production write, no schema/RLS/credential change, no push without authorization.

---

## 1. Symptom

`POST /tournaments` (32 boards, valid PBN) → **422 `import_incomplete`**

> 0/32 board write(s) reported success; board(s) 1..32 did not land; cleanup removed 0 board row(s) and
> removed the draft header

Duration ≈ 9.5 s. UI then showed "No tournament is stored yet." Read-only checks after the event:
`/health` healthy, `tournaments{configured:true,routes:12,membershipBridge:"club-store"}`,
`clubs{configured:true,routes:22}`, `ncb.transport:native`, `tablesAllowlisted:15`,
`/tournaments` 401 `auth_error`, `/ncb/data/read/tournaments` 403 `tournament_via_gateway_only`,
unknown path 404 — i.e. the tables are still empty and no partial set is readable.

## 2. What the message proves (branch analysis, not assumption)

`tournamentNcbStore.importTournament` chooses the error name from `refused = failed.length > 0`, and
`failed[]` is appended **only** where `run(CREATE(...))` returns `!ok`:

| Observation | Conclusion |
|---|---|
| `import_incomplete`, not `import_unverified` | NCB **refused** the board writes → **cause class A**. Excludes B (accepted-but-misparsed) and C (written-but-read-back-failed), both of which yield `import_unverified` |
| Header was created, then removed by cleanup | The service account, its session and the `tournaments` table path all work — the fault is board-specific, not credential-specific |
| ≈9.5 s for ~35 round-trips (~270 ms each) | NCB **answered** each request. `REQUEST_TIMEOUT_MS` is 12 000, so an unreachable/timeout class is excluded |
| `cleanup removed 0 board row(s)` | No board row ever landed. Empty tables confirmed read-only above |
| Writes are `await`ed sequentially in one loop | No concurrency defect is possible in this path |
| Table was empty before the import | A composite-unique collision cannot explain 32/32 |

## 3. Surviving candidate causes and what the diagnostic now says

Measured by driving the **shipped** `safeUpstreamFragment()` (commit in §5), not by reasoning:

| Candidate cause | 422 `upstream=` will read |
|---|---|
| `hands_json` column narrower than the deal (**leading**) | `value_too_long(Data too long for column 'hands_json')` |
| ENUM/domain mismatch on `vulnerability`/`dealer` | `value_truncated(Data truncated for column 'vulnerability' …)` |
| `NOT NULL` without default (`created_at`) | `column_no_default(Column cannot be null: 'created_at' …)` |
| `NOT NULL` explicit (MySQL 8 strict) | `column_no_default(Column cannot be null)` |
| No INSERT grant for the service account | `permission_denied(INSERT permission denied for table 'tournament_boards')` |
| Composite unique already satisfied | `duplicate_entry(Duplicate entry for key 'uk_tournament_board')` |
| Column absent from the table | `unknown_column(Unknown column 'tags_json')` |
| Table absent | `unknown_table(Table '…' does not exist)` |
| JSON column rejects the value | `invalid_json(Invalid JSON value for column 'hands_json')` |
| INT overflow / out of range | `value_out_of_range(Value out of range for column)` |
| Vendor envelope we cannot classify | `unrecognised(status=failed Message=null)` — readable, no longer placeholders |

**Why width leads:** a legal 52-card deal serialises to **exactly 299 characters** (asserted as arm
`G0b`); every value in the header row is short. So a `VARCHAR(255)`-class `hands_json` refuses **all 32
boards and the header alone**, which is the observed signature. `tags_json` is ~47 chars and is not a
suspect. This is still a hypothesis: NCB MCP does not expose column definitions or grants, and NodeSend
cannot read the vendor catalogue, so **the cause is not confirmed** — the shipped diagnostic exists to
make one import attempt confirm it.

## 4. Why 221 + 24 existing arms could not see any of this

Both harness mocks answer `create` with `{status:"success", data:{…row}}` for **any** legal body:
`verify-tournaments-gateway.mjs` fails a board write only via its own `failBoardCreate` knob, and
`verify-tournaments-integration.mjs` never refuses one. A mock that enforces only the rules its author
imagined cannot see a vendor that refuses legal data on a storage rule — the `offset=` lesson, one layer
down. The new gate models **column definitions and a grant** instead of only names.

## 5. Defects found and fixed (each pinned by arms that go red when the fix is removed)

| # | Defect | Where | Found by |
|---|---|---|---|
| 1 | Upstream reason captured into `failed[]` then **discarded** — the 422 carried a count, no cause | `importTournament` | Reading the message against the code |
| 2 | `failedBoardNumbers` computed by the store, **dropped by the responder** → retry list locked in prose | `respondStoreResult` | New gate |
| 3 | `Authorization: Bearer <tok>` — pair rule ate the word "Bearer", orphaning the token | sanitizer | Mutation `M1` |
| 4 | Scrub marker literally contained `"Bearer "`, which arm 13h counts as a leak | sanitizer | Existing 13h |
| 5 | Short **labeled** secret (`token=abc123`) protected by redaction only, untested | gate | `M3` produced 0 red |
| 6 | Unobservable redaction layer (removing it changed nothing) | sanitizer | `M3` |
| 7 | `[param]` collapsed the vendor's **own** envelope keys → `unrecognised([param] [param])`, destroying `status=failed Message=null` (the proxy-outage signature this deployment has lived before) | sanitizer | Asking what the live 422 would say per candidate cause |
| 8 | `B64_CLASSIC` matched REST paths (`/v1/data/create/tournament` = 26 chars of its class) → **over-blocking**: any message naming an endpoint was blanked | gate | Asking *why* a green arm was green |
| 9 | `HOSTISH` required two dots, so `db.internal:3306` was **never** matched → internal hostname could leak; widening `{2,6}`→`{2,12}` did not fix it | gate | `D27` going red, then re-measuring |
| 10 | Three plausible causes (truncated/invalid-JSON/dotted table) were unnamed | category table | Coverage measurement |

## 6. Tests

`verify-tournament-import-failure.mjs` **65/65** — 17 end-to-end disclosure shapes driven through the
HTTP response, gate positive/negative controls (`D16`/`D17`), hostile identifiers (`D21`/`D21b`),
redaction-earnings (`D22`/`D22b`), envelope readability (`D23`–`D24c`), query tail (`D25`), path
over-block guard (`D26`/`D26b`), hostname coverage (`D27`–`D27c`), and the original incident arms.

Mutation validation (each mutant is a temporary, byte-restored edit; `restored byte-identical: true`):
gate disarmed 8 red · categories disabled 6 red · redaction removed 2 red · labeled-secret removed 1 red
· diagnostic clause removed 23 red · `[param]` rule restored 3 red · key=value removed 1 red ·
new categories disabled 1 red · query rule removed (see `D25` note) · host rules removed 2 red ·
`HOST_PORT` removed 1 red · base64 length-only restored 1 red · whitelist emptied 1 red ·
`refused` flag forced false **26 red** (safety arms fire hardest). Two arms were strengthened after
measuring that they passed for the wrong reason (`D24c`, `D25`, `D27c`).

Full suite re-run at the repair commit: 221 · 24 · 287 · 132 · 98 · 407 · 50 · 57 · 48 · 32 · 21 · 8,
plus this gate's 65 → **1,450 arms, 0 failures**.

## 7. Data-integrity and cleanup assessment

Arms `R7`, `R18`/`R18b`, `R19`, `R8` confirm: a failed import leaves **0** headers, **0** boards, **0**
attempts; a partial set removes exactly the boards that landed, counted by **re-reading storage** rather
than counting DELETE calls issued; `duplicate_import` deletes nothing (it must not touch an earlier
import's rows); and no status update is ever issued for a failed set, so nothing can be published by
accident. When a delete is refused, the answer says `BUT THE DRAFT HEADER REMAINS` instead of claiming a
rollback. Production tables are verified empty by read-only probe today, so the failed import left no
residue.

## 8. Residual risks

* Gate detectors are **redundant by design**: `M18` (encoded-run detector removed) and the earlier
  `M7`/`M8` stay green because other rules also catch the sample. The composite property is asserted;
  individual rules are not each essential.
* Sub-threshold values survive by choice: ≤5 card tokens, identifiers shorter than 24 chars, short
  numeric IDs, and public hostnames not on the private-suffix list and without a port.
* An entirely novel vendor phrasing can only ever be reported as `unrecognised(<sanitized prose>)`.
* The cause itself remains **unconfirmed** until one post-deploy import attempt is made.

## 9. Required production action

1. Confirm the deploy landed (`cf7d45b`'s successor is on `main`; `/health` cannot prove a revision —
   the image has no `.git` and this patch adds no route or health key). The container-local marker check
   is the only instrument.
2. Run **one** 32-board import through the existing authorized UI, read the `upstream=` clause, and stop.
3. Only after the clause names the cause: if `value_too_long`, widen `tournament_boards.hands_json`
   (a vendor-side migration, separately authorized). No NodeSend code change is expected to be needed.
4. Do not repeat failed imports automatically; do not change RLS or permissions to "fix" a refusal that
   the diagnostic has not yet explained.
