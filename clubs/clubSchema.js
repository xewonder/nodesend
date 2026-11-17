'use strict';

/*
 * THE AGREED CLUB SCHEMA CONTRACT — the one place in NodeSend that names what Clubs storage
 * must look like.
 *
 * THE FIVE TABLES ARE THE AGREED ONES, and there are exactly five:
 *
 *   system_admins            the super-admin registry (R1)
 *   clubs                    one row per club
 *   club_memberships         one row per user, UNIQUE(user_id) — "one club or none"
 *   club_board_collections   a club's draft/published collections
 *   club_collection_boards   the validated boards of one collection
 *
 * NodeSend deliberately owns NO default table names. The tables do not exist yet: they are
 * created by the owner through NCB MCP after this implementation is reviewed. A default would
 * be a guess, and a guessed name does not fail loudly — it writes real rows into whatever table
 * happens to answer, then reads them back and reports success. So an unconfigured or partially
 * configured schema returns `ok: false`, the factory builds no store, and every club route
 * answers 503 after authentication and body validation. Nothing degrades into an empty success.
 *
 * `system_admins` is REQUIRED, not optional (it is optional in BridgeMind's local gateway, where
 * the session role is the fallback). Here the session role is never a club privilege, so there
 * has to be a table that says who a super admin is; without it R1 is unenforceable, and a
 * feature that cannot enforce its top rule must not start.
 *
 * Column NAMES arrive from config because NCB exposes what the owner actually created. The keys
 * below are stable ROLE names used by the store code; their values are the real columns. The
 * role-name indirection is what lets a column be renamed in deployment without touching an
 * authorization rule.
 *
 * `club_board_attempts` does NOT exist in this contract. Board-start is a READ and a VALIDATION,
 * never a write: game recording belongs to BridgeMind's existing gameplay and recorded-hands
 * infrastructure, so a sixth table would be a second, unowned record of the same attempt. A
 * deployment that declares one is refused below — silently ignoring an extra role would let the
 * dependency come back without anyone noticing.
 */

const fs = require('node:fs');

/** The agreed five. Every one must be named by the deployment's schema config, and nothing else. */
const AGREED_TABLE_ROLES = Object.freeze({
  systemAdmins: 'system_admins',
  clubs: 'clubs',
  memberships: 'club_memberships',
  collections: 'club_board_collections',
  boards: 'club_collection_boards'
});

const REQUIRED_COLUMNS = Object.freeze({
  systemAdmins: ['userId'],
  clubs: ['id', 'name', 'status'],
  memberships: ['id', 'userId', 'clubId', 'role', 'status'],
  collections: ['id', 'clubId', 'name', 'status', 'createdBy'],
  boards: ['id', 'collectionId', 'boardNumber', 'dealer', 'vulnerability', 'handsJson']
});

/**
 * Optional board columns a deployment may offer. Deliberately EMPTY, and the reason belongs here:
 * the live `club_collection_boards` table has `tags_json` (free-form, unused by this relay) and NO
 * `source_pbn` at all. The earlier contract named `sourcePbn` and would have written a column that
 * does not exist, so it is removed rather than left optional — an optional column that is not there
 * is a runtime failure waiting for someone to set it. `tags_json` is not referenced at all: reading
 * or writing a column whose meaning this feature does not define would invent semantics nobody
 * agreed to.
 */
const OPTIONAL_BOARD_COLUMNS = Object.freeze([]);

/**
 * The club's activity flag, as the rest of this relay names it. The DOMAIN vocabulary is
 * 'active'/'inactive' everywhere in the code — authorization, responses, this file's predicates —
 * and the storage representation is translated only at the boundary (see encode/decode below).
 * Keeping the domain separate is what lets a numeric column and a text column both be served
 * without a single authorization rule changing.
 */
const CLUB_ACTIVE = 'active';
const CLUB_INACTIVE = 'inactive';

/**
 * Value translation for `clubs.status`.
 *
 * The live NCB column is `active`, a numeric 1/0 — not a text status. Translation lives here, one
 * place for reads, writes and query filters, because three separate string comparisons spread across
 * the store is how a filter keeps saying `active='active'` while every write says `1`.
 *
 * The raw values come from the deployment's `values.clubs.status` block, so no column representation
 * is guessed by this code. Absent that block means the column really does hold 'active'/'inactive'
 * text, and the mapping is the identity — which is what a text-shaped deployment needs and why
 * identity, not a default of 1/0, is the safe fallback.
 */
function clubStatusCodec(declaredValues) {
  const toDomain = Object.create(null);
  const toStorage = Object.create(null);
  for (const [domain, raw] of Object.entries(declaredValues ?? {})) {
    toStorage[domain] = raw;
    toDomain[normalizeFlag(raw)] = domain;
  }
  return {
    encode: (domain) => (domain in toStorage ? toStorage[domain] : domain),
    decode: (raw) => {
      const key = normalizeFlag(raw);
      if (key in toDomain) return toDomain[key];
      // Unrecognised is returned as-is and therefore fails every `=== 'active'` test. Mapping an
      // unknown value to 'active' would activate a club on a representation change.
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

/**
 * The membership lifecycle. `club_memberships.status` is REQUIRED, not optional: it is what makes
 * "a user is in a club" a decision the server holds rather than a fact a row's mere existence
 * asserts. Only APPROVED members, of an ACTIVE club, have a club at all for authorization
 * purposes — pending, rejected and removed rows are treated exactly as if no row existed, which is
 * the owner's rule that club approval affects club features and nothing else.
 *
 * A voluntary leave DELETES the row (so the user is genuinely "none"); an admin removal sets
 * `removed`, which keeps the fact visible to Profile without keeping any privilege.
 */
const MEMBERSHIP_STATUSES = Object.freeze(['pending', 'approved', 'rejected', 'removed']);
const APPROVED_MEMBERSHIP_STATUS = 'approved';
const ACTIVE_CLUB_STATUS = 'active';

/**
 * THE ONE DEFINITION of "this user is an active club member": an APPROVED row whose CLUB is ACTIVE.
 *
 * Both places that must agree call this — the authorization gate that decides what a request may
 * reach, and the join path that decides whether an existing row blocks a new choice. Written as a
 * predicate precisely so the two cannot drift: if only the gate checked activity, a member of a
 * deactivated club would be denied every club surface while still being told by Profile that they
 * belong to that club, which is the half-of-the-rule bug this exists to prevent.
 */
function isEffectiveMembership({ status, clubStatus } = {}) {
  return status === APPROVED_MEMBERSHIP_STATUS && clubStatus === ACTIVE_CLUB_STATUS;
}

/**
 * The storage rule the whole authorization model rests on. Membership is one row PER USER, not
 * one row per (user, club) — the second spelling lets a player accumulate clubs and makes
 * "their club" ambiguous on every read that decides an authorization.
 */
const MEMBERSHIP_UNIQUE_KEY = Object.freeze(['userId']);

const eq = (value) => String(value ?? '').trim();

/**
 * Validates the deployment-supplied schema. Never mutates, never defaults a name.
 *
 * @param {object} env
 * @param {{fs?: object}} [deps] injectable for tests
 * @returns {{ok: true, schema: object, problems: []}|{ok: false, schema: null, problems: string[]}}
 */
function readClubSchemaConfig(env = {}, deps = {}) {
  const problems = [];
  let raw = null;

  const inline = eq(env.CLUB_NCB_SCHEMA_JSON);
  const file = eq(env.CLUB_NCB_SCHEMA_FILE);
  if (inline && file) {
    // Two authorities for one contract is a misconfiguration, not a precedence rule. Silently
    // preferring one would let a deployment carry a stale schema that nobody is reading.
    return { ok: false, schema: null, problems: ['CLUB_NCB_SCHEMA_JSON and CLUB_NCB_SCHEMA_FILE are both set; keep exactly one'] };
  }
  if (inline) {
    try {
      raw = JSON.parse(inline);
    } catch (error) {
      return { ok: false, schema: null, problems: [`CLUB_NCB_SCHEMA_JSON is not valid JSON (${error?.name || 'ParseError'})`] };
    }
  } else if (file) {
    try {
      raw = JSON.parse((deps.fs || fs).readFileSync(file, 'utf8'));
    } catch (error) {
      // The name only: a read error can carry the path, and a path is deployment detail with no
      // business in a response body or a log line.
      return { ok: false, schema: null, problems: [`CLUB_NCB_SCHEMA_FILE could not be read as JSON (${error?.name || 'ReadError'})`] };
    }
  } else {
    return {
      ok: false,
      schema: null,
      problems: ['no club schema configured (set CLUB_NCB_SCHEMA_JSON or CLUB_NCB_SCHEMA_FILE to the agreed five-table schema)']
    };
  }

  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, schema: null, problems: ['the club schema must be a JSON object'] };
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
  // A role outside the agreed five is refused, not ignored. `attempts` is the one that would
  // otherwise creep back: accepting it silently is how a sixth table becomes a live dependency
  // again after the contract said there would not be one.
  for (const role of Object.keys(declaredTables)) {
    if (!AGREED_TABLE_ROLES[role]) problems.push(`tables.${role} is not one of the agreed five club table roles`);
  }
  for (const role of Object.keys(declaredColumns)) {
    if (!AGREED_TABLE_ROLES[role]) problems.push(`columns.${role} is not one of the agreed five club table roles`);
  }

  const columns = {};
  for (const [role, required] of Object.entries(REQUIRED_COLUMNS)) {
    if (!tables[role]) continue;
    const optional = role === 'boards' ? OPTIONAL_BOARD_COLUMNS : [];
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
    columns[role] = resolved;
  }

  // An unknown column key is refused, not ignored. `sourcePbn` is the case this exists for: the
  // column does not exist in NCB, and a leftover config entry that was silently dropped would sit
  // there looking like a supported feature until someone wondered why the source was never stored.
  // The accepted keys are the required ones plus the documented optional set, per role.
  for (const [role, declared] of Object.entries(declaredColumns)) {
    if (!AGREED_TABLE_ROLES[role] || !declared || typeof declared !== 'object') continue;
    const allowed = new Set([
      ...(REQUIRED_COLUMNS[role] ?? []),
      ...(role === 'boards' ? OPTIONAL_BOARD_COLUMNS : [])
    ]);
    for (const field of Object.keys(declared)) {
      if (!allowed.has(field)) problems.push(`columns.${role}.${field} is not a column this contract uses (allowed: ${[...allowed].join(', ')})`);
    }
  }

  // Two roles on one table means one read answers for two different questions. `clubs` and
  // `collections` sharing a name would, for example, make a club status read decide whether a
  // collection is published — a wrong answer that looks exactly like a right one.
  const names = Object.values(tables).map(eq).filter(Boolean);
  if (new Set(names).size !== names.length) problems.push('two schema roles point at the same table');

  // Optional value translation, currently only for the club activity flag. A HALF-SPECIFIED mapping
  // is refused: `{ "active": 1 }` alone would leave 'inactive' writing the literal text into a
  // numeric column, which is the exact mismatch this block exists to prevent, and it would fail on
  // the second-ever club rather than the first.
  const declaredValues = raw.values && typeof raw.values === 'object' ? raw.values : {};
  const declaredClubStatusValues = declaredValues.clubs?.status;
  let clubStatus = clubStatusCodec(null);
  if (declaredClubStatusValues !== undefined && declaredClubStatusValues !== null) {
    const map = declaredClubStatusValues;
    for (const domain of [CLUB_ACTIVE, CLUB_INACTIVE]) {
      if (map[domain] === undefined || map[domain] === null || eq(map[domain]) === '') {
        problems.push(`values.clubs.status.${domain} is required once values.clubs.status is declared (a half-mapped flag writes literal text into a numeric column)`);
      }
    }
    if (!problems.some((p) => p.startsWith('values.clubs.status'))) clubStatus = clubStatusCodec(map);
  }

  if (problems.length) return { ok: false, schema: null, problems };

  return {
    ok: true,
    schema: {
      tables,
      columns,
      // The one codec the storage layer uses for the club activity flag. Kept on the schema rather
      // than imported ad hoc so no call site can reach the store without it.
      clubStatus,
      rowLimit: clampRowLimit(env.CLUB_NCB_ROW_LIMIT),
      problems: []
    },
    problems: []
  };
}

// A read that returns the whole table is a memory incident waiting to happen on a shared
// relay. 1000 is well above the largest legitimate collection (200 boards) and below anything
// that could threaten the process.
function clampRowLimit(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) return 500;
  return Math.min(n, 1000);
}

module.exports = {
  AGREED_TABLE_ROLES,
  REQUIRED_COLUMNS,
  OPTIONAL_BOARD_COLUMNS,
  MEMBERSHIP_UNIQUE_KEY,
  MEMBERSHIP_STATUSES,
  APPROVED_MEMBERSHIP_STATUS,
  ACTIVE_CLUB_STATUS,
  CLUB_ACTIVE,
  CLUB_INACTIVE,
  isEffectiveMembership,
  clubStatusCodec,
  readClubSchemaConfig
};
