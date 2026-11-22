'use strict';

/*
 * THE AGREED TOURNAMENT SCHEMA CONTRACT — the one place in NodeSend that names what Tournament
 * storage must look like.
 *
 * THE THREE TABLES ARE THE AGREED ONES, and there are exactly three:
 *
 *   tournaments         one header row per imported set: who owns it, its category, its lifecycle
 *   tournament_boards   the deals of one tournament, addressed by board number
 *   tournament_attempts which board a given account has played, as the id of the recorded hand
 *
 * THE LIVE SCHEMA AND THE MIGRATION ASK, stated once, here, against the owner's NCB MCP schema
 * verification of 2026-11-22 on instance 55954_bridgemind. THE THREE TABLES EXIST and are under the
 * default `private` RLS policy; what is missing is the columns this contract needs, and they are
 * named per table below. Nothing in this relay adds a column: `ADD COLUMN` works on this vendor
 * without recreating a table (measured 2026-11-17), but it is the owner's operation through NCB
 * MCP, not NodeSend's.
 *
 *   tournaments        PRESENT: id, club_id, name, visibility, status, board_count, source_label,
 *                      created_at, updated_at, and `user_id` — which is NCB's row-ownership slot,
 *                      NOT the application owner (see THE OWNERSHIP SEPARATION below).
 *                      MISSING: owner_user_id, dedupe_key.
 *                      WANTED: UNIQUE(dedupe_key) — duplicate-import protection.
 *   tournament_boards  PRESENT: id, tournament_id, board_number, and the required PBN columns
 *                      (dealer, vulnerability, hands_json; tags_json where kept).
 *                      WANTED: UNIQUE(tournament_id, board_number) — ONE COMPOSITE KEY.
 *   tournament_attempts PRESENT: id, tournament_id, board_number, recorded_hand_id, original_seat,
 *                      created_at, and `user_id` (ownership again).
 *                      MISSING: player_user_id.
 *                      WANTED: UNIQUE(recorded_hand_id) — one attempt row per recorded hand.
 *
 * UNTIL THOSE COLUMNS EXIST, no valid TOURNAMENT_NCB_SCHEMA_JSON can be written for this contract,
 * which is the intended outcome: the mount builds no store and every /tournaments route answers 503.
 * A schema that named `user_id` as the owner would be accepted by NCB and would answer
 * authoritatively WRONG things, so it is refused at boot below instead.
 *
 * WHY THE BOARD UNIQUE IS COMPOSITE, and why it is written in capitals. The live
 * `club_collection_boards` table carries TWO single-column uniques — one on `collection_id`, one on
 * `board_number` — and that is precisely what makes a second club unable to store a board numbered
 * "1": the uniqueness is global per column, so the second insert is refused by an index that has
 * nothing to do with the club it belongs to. A tournament board number is only meaningful INSIDE its
 * tournament (every imported set starts at board 1), so the constraint must span both columns. A
 * deployment that provisions the two-column pair of single uniques here reproduces a known, already
 * painful defect, and no code change can fix it afterwards without a data migration.
 *
 * `visibility` and `status` are TWO AXES, not one enum: `private|club|public` says who may see the
 * set, `draft|published` says whether it is released. An unpublished club set is invisible to club
 * members and still readable by that club's admins, which is a sentence that cannot be written with
 * a single column.
 *
 * `tags_json` is HISTORICAL DATA ONLY. It keeps the original PBN `[Contract]/[Declarer]/[Result]`
 * metadata from the source file so an imported set remains traceable to its record. It is never read
 * by any authorization rule and never used to build a playable auction: a board is played from its
 * four hands, its dealer and its vulnerability, all of which the server holds. Column absent is a
 * legal deployment (the field is optional); a written-but-unreadable column would be an unused
 * dependency, so it stays optional and the store never sends it when the deployment omits it.
 *
 * NodeSend deliberately owns NO default table names — the same rule `clubs/clubSchema.js` states. The
 * tables exist but the columns this contract requires do not yet: they are provisioned by the owner
 * through NCB after this implementation is reviewed. A default would be a guess, and a guessed name
 * does not fail loudly: it writes real rows
 * into whatever table happens to answer, reads them back and reports success. So an unconfigured or
 * partially configured schema returns `ok: false`, `buildTournamentMount` builds no store, and every
 * `/tournaments` route answers 503 after authentication and body validation. Nothing degrades into an
 * empty success, and no tournament is ever invented because a table was missing.
 *
 * Column NAMES arrive from config because NCB exposes what the owner actually created. The keys below
 * are stable ROLE names used by the store code; their values are the real columns. That indirection is
 * what lets a column be renamed in deployment without touching one authorization rule.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT DECLARE: `clubs`, `club_memberships` and `system_admins`. The
 * club and super-admin facts are the club feature's authority, and `buildTournamentMount` reaches them
 * through the club STORE (getMembership / clubStatus / isSystemAdmin), never by naming the tables
 * again here. A second schema role would be the first step toward a second membership rule, and two
 * rules deciding "is this person in that club" is two answers. `tournaments/*.js` therefore contains
 * no club table name at all, which `verify-tournaments-gateway.mjs` asserts by scanning this
 * directory rather than by trusting this paragraph.
 */

const fs = require('node:fs');

/** The agreed three. Every one must be named by the deployment's schema config, and nothing else. */
const AGREED_TABLE_ROLES = Object.freeze({
  tournaments: 'tournaments',
  boards: 'tournament_boards',
  attempts: 'tournament_attempts'
});

const REQUIRED_COLUMNS = Object.freeze({
  tournaments: ['id', 'userId', 'clubId', 'name', 'visibility', 'status', 'boardCount', 'sourceLabel', 'dedupeKey'],
  boards: ['id', 'tournamentId', 'boardNumber', 'dealer', 'vulnerability', 'handsJson'],
  attempts: ['id', 'tournamentId', 'boardNumber', 'recordedHandId', 'originalSeat', 'userId']
});

/**
 * Columns a deployment MAY name and this feature will then fill. Optional means "the store sends it
 * when you declare it", never "the store needs it": every authorization decision reads only the
 * required set, so an installation whose table has no timestamps still authorizes identically.
 */
const OPTIONAL_COLUMNS = Object.freeze({
  tournaments: ['createdAt', 'updatedAt'],
  boards: ['tagsJson', 'createdAt'],
  attempts: ['createdAt']
});

/**
 * The uniqueness the authorization model depends on, as DATA rather than as prose, so a gate can
 * print exactly what the migration must create and the store can map a duplicate-key refusal onto
 * the reason name the route answers with.
 */
const REQUIRED_UNIQUE_KEYS = Object.freeze({
  tournaments: { fields: ['dedupeKey'], composite: false, purpose: 'duplicate_import' },
  // composite: true is the load-bearing flag. See the header.
  boards: { fields: ['tournamentId', 'boardNumber'], composite: true, purpose: 'one row per board per tournament' },
  attempts: { fields: ['recordedHandId'], composite: false, purpose: 'one attempt row per recorded hand' }
});

/** The category axis. Domain vocabulary, storage-agnostic. */
const TOURNAMENT_VISIBILITIES = Object.freeze(['private', 'club', 'public']);
/** The lifecycle axis. Orthogonal to visibility — see the header. */
const TOURNAMENT_STATUSES = Object.freeze(['draft', 'published']);

const eq = (value) => String(value ?? '').trim();

/**
 * Validates the deployment-supplied schema. Never mutates, never defaults a name.
 *
 * @param {object} env
 * @param {{fs?: object}} [deps] injectable for tests
 * @returns {{ok: true, schema: object, problems: []}|{ok: false, schema: null, problems: string[]}}
 */
function readTournamentSchemaConfig(env = {}, deps = {}) {
  const problems = [];
  let raw = null;

  const inline = eq(env.TOURNAMENT_NCB_SCHEMA_JSON);
  const file = eq(env.TOURNAMENT_NCB_SCHEMA_FILE);
  if (inline && file) {
    // Two authorities for one contract is a misconfiguration, not a precedence rule. Silently
    // preferring one would let a deployment carry a stale schema nobody is reading.
    return {
      ok: false,
      schema: null,
      problems: ['TOURNAMENT_NCB_SCHEMA_JSON and TOURNAMENT_NCB_SCHEMA_FILE are both set; keep exactly one']
    };
  }
  if (inline) {
    try {
      raw = JSON.parse(inline);
    } catch (error) {
      return { ok: false, schema: null, problems: [`TOURNAMENT_NCB_SCHEMA_JSON is not valid JSON (${error?.name || 'ParseError'})`] };
    }
  } else if (file) {
    try {
      raw = JSON.parse((deps.fs || fs).readFileSync(file, 'utf8'));
    } catch (error) {
      // The name only: a read error can carry the path, and a path is deployment detail with no
      // business in a response body or a log line.
      return { ok: false, schema: null, problems: [`TOURNAMENT_NCB_SCHEMA_FILE could not be read as JSON (${error?.name || 'ReadError'})`] };
    }
  } else {
    return {
      ok: false,
      schema: null,
      problems: ['no tournament schema configured (set TOURNAMENT_NCB_SCHEMA_JSON or TOURNAMENT_NCB_SCHEMA_FILE to the agreed three-table schema)']
    };
  }

  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, schema: null, problems: ['the tournament schema must be a JSON object'] };
  }

  const declaredTables = raw.tables && typeof raw.tables === 'object' ? raw.tables : {};
  const declaredColumns = raw.columns && typeof raw.columns === 'object' ? raw.columns : {};

  const tables = {};
  for (const [role, agreedName] of Object.entries(AGREED_TABLE_ROLES)) {
    const name = eq(declaredTables[role]);
    if (!name) {
      problems.push(`tables.${role} is missing (agreed table name: ${agreedName})`);
      continue;
    }
    tables[role] = name;
  }
  // A role outside the agreed three is refused, not ignored. The club tables are the ones that would
  // otherwise creep in — and reading a membership through a tournament schema is exactly the second
  // membership rule this design forbids.
  for (const role of Object.keys(declaredTables)) {
    if (!AGREED_TABLE_ROLES[role]) problems.push(`tables.${role} is not one of the agreed three tournament table roles`);
  }
  for (const role of Object.keys(declaredColumns)) {
    if (!AGREED_TABLE_ROLES[role]) problems.push(`columns.${role} is not one of the agreed three tournament table roles`);
  }

  const columns = {};
  for (const [role, required] of Object.entries(REQUIRED_COLUMNS)) {
    if (!tables[role]) continue;
    const optional = OPTIONAL_COLUMNS[role] ?? [];
    const declared = declaredColumns[role] && typeof declaredColumns[role] === 'object' ? declaredColumns[role] : {};
    const resolved = {};
    for (const field of [...required, ...optional]) {
      const value = eq(declared[field]);
      if (!value) {
        if (optional.includes(field)) continue;
        problems.push(`columns.${role}.${field} is missing`);
        continue;
      }
      resolved[field] = value;
    }
    // Two roles of one table resolving to the SAME column is a read that answers two questions at
    // once. `tournamentId`/`recordedHandId` collapsing onto one column would, for example, make
    // every attempt look like it belonged to the tournament named by the hand id.
    const seen = new Map();
    for (const [field, name] of Object.entries(resolved)) {
      if (seen.has(name)) {
        problems.push(`columns.${role}.${field} duplicates the column "${name}" already used by columns.${role}.${seen.get(name)}`);
        continue;
      }
      seen.set(name, field);
    }
    columns[role] = resolved;
  }

  // An unknown column key is refused, not ignored: a leftover entry reads as a supported feature
  // until someone wonders why it never worked.
  for (const [role, declared] of Object.entries(declaredColumns)) {
    if (!AGREED_TABLE_ROLES[role] || !declared || typeof declared !== 'object') continue;
    const allowed = new Set([...(REQUIRED_COLUMNS[role] ?? []), ...(OPTIONAL_COLUMNS[role] ?? [])]);
    for (const field of Object.keys(declared)) {
      if (!allowed.has(field)) {
        problems.push(`columns.${role}.${field} is not a column this contract uses (allowed: ${[...allowed].join(', ')})`);
      }
    }
  }

  // Two roles on one table means one read answers for two different questions. `tournaments` and
  // `tournament_boards` sharing a name would, for instance, make a board count decide whether a
  // header row is published.
  const names = Object.values(tables).map(eq).filter(Boolean);
  if (new Set(names).size !== names.length) problems.push('two schema roles point at the same table');

  // Optional storage translation for the two axes, declared the same way the club activity flag is
  // (`values.tournaments.status` / `values.tournaments.visibility`). A HALF-SPECIFIED mapping is
  // refused: `{ "published": 1 }` alone would leave 'draft' writing the literal text into a numeric
  // column, which is the exact mismatch this block exists to prevent, and it would fail on the
  // second-ever tournament rather than the first.
  const declaredValues = raw.values && typeof raw.values === 'object' ? raw.values : {};
  const axes = [
    ['visibility', TOURNAMENT_VISIBILITIES],
    ['status', TOURNAMENT_STATUSES]
  ];
  const codecs = {};
  for (const [axis, domain] of axes) {
    const map = declaredValues.tournaments?.[axis];
    if (map === undefined || map === null) {
      codecs[axis] = axisCodec(null, domain);
      continue;
    }
    for (const value of domain) {
      if (map[value] === undefined || map[value] === null || eq(map[value]) === '') {
        problems.push(`values.tournaments.${axis}.${value} is required once values.tournaments.${axis} is declared (a half-mapped axis writes literal text into a coded column)`);
      }
    }
    codecs[axis] = problems.some((p) => p.startsWith(`values.tournaments.${axis}`)) ? axisCodec(null, domain) : axisCodec(map, domain);
  }

  /* THE OWNERSHIP SEPARATION, ENFORCED AT BOOT.

     `columns.tournaments.userId` and `columns.attempts.userId` are the APPLICATION owner — the player the
     authorization rules compare against the session. `user_id` is something else entirely on this vendor:
     the row-ownership slot NCB stamps from the writing session. NodeSend writes every tournament row with
     the dedicated service account, so mapping the application owner onto `user_id` cannot work, and it
     fails in the worst available way — silently:

       · if NCB honours an explicit `user_id`, the row ends up owned by a player who is not the writing
         session, the service account cannot read it back, and every import reports `write_unverified`;
       · if NCB stamps the writer, `user_id` is constant across every tournament, so `ownerId === userId`
         is never true for a real player, the private list scope matches nothing, and the app answers an
         empty list that reads exactly like "you have no tournaments".

     Both are fatal, so a configuration that names `user_id` here is refused rather than started. The
     columns that DO satisfy the role are deployment-chosen (`owner_user_id` / `player_user_id` are the
     proposed spellings; the club feature's convention is `admin_user_id` / `member_user_id`), which is why
     this is a check on the VALUE and not a hard-coded rename. */
  const NCB_ROW_OWNER_COLUMN = 'user_id';
  for (const role of ['tournaments', 'attempts']) {
    const resolvedName = columns[role]?.userId;
    if (!resolvedName) continue;
    if (resolvedName === NCB_ROW_OWNER_COLUMN) {
      problems.push(`columns.${role}.userId is "${NCB_ROW_OWNER_COLUMN}", which is NCB's own row-ownership slot, not the application owner. `
        + `Because NodeSend writes tournament rows with the dedicated service account, that mapping makes every private tournament invisible to the player who imported it. `
        + `Point it at a separate column (proposed: ${role === 'tournaments' ? 'owner_user_id' : 'player_user_id'}) and add that column to the table.`);
    }
  }

  if (problems.length) return { ok: false, schema: null, problems };

  return {
    ok: true,
    schema: {
      tables,
      columns,
      // The two codecs the storage layer uses, kept on the schema rather than imported ad hoc so no
      // call site can reach the store without them.
      visibility: codecs.visibility,
      status: codecs.status,
      uniqueKeys: REQUIRED_UNIQUE_KEYS,
      rowLimit: clampRowLimit(env.TOURNAMENT_NCB_ROW_LIMIT),
      problems: []
    },
    problems: []
  };
}

/**
 * Domain <-> storage translation for one axis, kept out of the store so a rule never compares a
 * domain word against a storage value by accident. Absent mapping means the column holds the domain
 * text and the codec is the identity — which is what a plain VARCHAR needs, and why identity rather
 * than a guessed code is the safe fallback.
 *
 * An unrecognised stored value is returned as-is and therefore fails every equality test: mapping an
 * unknown status to 'published' would release a set on a representation change.
 */
function axisCodec(declaredValues, domain) {
  const toStorage = Object.create(null);
  const toDomain = Object.create(null);
  for (const value of domain) toDomain[value] = value;
  for (const [value, raw] of Object.entries(declaredValues ?? {})) {
    toStorage[value] = raw;
    toDomain[normalizeFlag(raw)] = value;
  }
  return {
    domain,
    encode: (value) => (value in toStorage ? toStorage[value] : value),
    decode: (raw) => {
      const key = normalizeFlag(raw);
      if (key in toDomain) return toDomain[key];
      return key === '' ? '' : String(raw);
    }
  };
}

// MySQL drivers hand back 1, "1" or true for the same column depending on the route. They are one
// value, and treating them as three is how a decoded status silently stops matching.
function normalizeFlag(raw) {
  if (raw === true) return '1';
  if (raw === false || raw === null || raw === undefined) return '0';
  return String(raw).trim();
}

// A read that returns the whole table is a memory incident waiting to happen on a shared relay. 1000
// sits above the largest legitimate set (the contract caps an import at 100 boards, and the product
// recommends 24-32) and below anything that could threaten the process.
function clampRowLimit(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) return 500;
  return Math.min(n, 1000);
}

module.exports = {
  AGREED_TABLE_ROLES,
  REQUIRED_COLUMNS,
  OPTIONAL_COLUMNS,
  REQUIRED_UNIQUE_KEYS,
  TOURNAMENT_VISIBILITIES,
  TOURNAMENT_STATUSES,
  readTournamentSchemaConfig,
  axisCodec,
  clampRowLimit
};
