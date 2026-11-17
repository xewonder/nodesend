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
  collections: ['id', 'clubId', 'name', 'status'],
  boards: ['id', 'collectionId', 'boardNumber', 'dealer', 'vulnerability', 'handsJson']
});

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

/** Optional board columns a deployment may offer; used only when present. */
const OPTIONAL_BOARD_COLUMNS = Object.freeze(['sourcePbn']);

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

  // Two roles on one table means one read answers for two different questions. `clubs` and
  // `collections` sharing a name would, for example, make a club status read decide whether a
  // collection is published — a wrong answer that looks exactly like a right one.
  const names = Object.values(tables).map(eq).filter(Boolean);
  if (new Set(names).size !== names.length) problems.push('two schema roles point at the same table');

  if (problems.length) return { ok: false, schema: null, problems };

  return {
    ok: true,
    schema: {
      tables,
      columns,
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
  MEMBERSHIP_UNIQUE_KEY,
  MEMBERSHIP_STATUSES,
  APPROVED_MEMBERSHIP_STATUS,
  ACTIVE_CLUB_STATUS,
  isEffectiveMembership,
  readClubSchemaConfig
};
