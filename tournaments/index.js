'use strict';

/*
 * TOURNAMENTS — the mount point bridge.js uses.
 *
 * One function builds the whole feature, and it is built ONCE at boot:
 *
 *   buildTournamentMount({ env, authenticate, clubAccount })  ->  { router, configured, reason, status() }
 *
 * THE MOUNT IS ALWAYS RETURNED, whether or not the feature can work — the rule `clubs/index.js` states
 * and this feature inherits. Registering the tournament routes only when everything is configured would
 * make a misconfigured deployment answer 404, and a 404 is indistinguishable from "NodeSend has no
 * tournament feature": the browser would render "no tournaments exist" and an operator would conclude the
 * code was never shipped. Mounted-always with a 503 says the true thing — the routes are here, the
 * tournament backend is not — and the client already maps it to a named reason.
 *
 * A STORE IS BUILT ONLY WHEN ALL THREE HALVES ARE PRESENT AND VALID:
 *   1. CLUB_NCB_EMAIL + CLUB_NCB_PASSWORD             the dedicated service account. There is NO
 *                                                      tournament-specific credential name: this feature
 *                                                      runs on the same server-only account the club
 *                                                      feature uses, through the same client.
 *   2. CLUB_NCB_SCHEMA_FILE | CLUB_NCB_SCHEMA_JSON     because tournament authorization reads club
 *                                                      membership and the `system_admins` verdict, and
 *                                                      those are the club store's authority to answer
 *   3. TOURNAMENT_NCB_SCHEMA_FILE | _JSON              the agreed three-table tournament schema
 * Anything else leaves the store null and every route answers a named 503. A schema is never guessed to
 * make a screen happy, and no credential is ever accepted from a request.
 *
 * WHY THE CLUB STORE IS A DEPENDENCY RATHER THAN A SECOND IMPLEMENTATION. The rules "is this person an
 * approved member of that active club" and "is this person the BridgeMind Admin" already have exactly one
 * answer in this deployment, and it lives in `clubs/clubNcbStore.js` (`getMembership`, `clubStatus`,
 * `isSystemAdmin`) plus `clubs/clubSchema.js` (`isEffectiveMembership`). This mount constructs that store
 * over the SAME account client the club mount holds, so there is one credential pool and one sign-in
 * state, and it imports those functions rather than re-deriving a membership from another table. Two
 * membership rules is two answers, and the product would have to pick one at request time.
 *
 * NO SIGN-IN HAPPENS AT BOOT. The first sign-in is lazy, inside the client, on the first tournament
 * request — so a relay that has a broken tournament schema still starts and serves every existing route
 * (AI, quota, Trickster, invitations, clubs, email). That is what keeps this integration from being able
 * to break the thing it was added to.
 */

const { createNcbAccountClient, readClubAccountConfig, assertNotFrontendFacing } = require('../clubs/ncbAccountClient.js');
const { createClubNcbStore } = require('../clubs/clubNcbStore.js');
const { readClubSchemaConfig } = require('../clubs/clubSchema.js');
const { readTournamentSchemaConfig } = require('./tournamentSchema.js');
const { createTournamentNcbStore } = require('./tournamentNcbStore.js');
const { createTournamentRouter, TOURNAMENT_ROUTES } = require('./tournamentAuthorization.js');

/**
 * @param {object} options
 * @param {object} [options.env]
 * @param {Function} options.authenticate the relay's OWN session resolver, adapted to
 *   `{ ok, id }` / `{ ok:false, status, code }`. Required — this module never reads a bearer, so there is
 *   exactly one way any route in it can learn who is calling.
 * @param {object} [options.clubAccount] the LIVE account client the club mount already holds
 *   (`clubMount.account`). Preferred when supplied: one client means one sign-in pool, one session and one
 *   place a cooldown lives. Absent, this mount builds its own from the same credential names.
 * @param {Function} [options.fetchImpl] injected for tests
 * @param {object} [options.limits]
 */
function buildTournamentMount({ env = process.env, authenticate, clubAccount = null, fetchImpl, limits = {} } = {}) {
  if (typeof authenticate !== 'function') {
    throw new TypeError('buildTournamentMount needs the relay session authenticator');
  }

  const account = readClubAccountConfig(env);
  if (!account.ok) return finish({ store: null, client: null, reason: account.reason, detail: account.detail });
  const frontend = assertNotFrontendFacing(env);
  if (!frontend.ok) return finish({ store: null, client: null, reason: frontend.reason, detail: frontend.detail });

  let client = clubAccount && clubAccount.configured === true ? clubAccount : null;
  if (!client) {
    const built = createNcbAccountClient({ env, ...(fetchImpl ? { fetchImpl } : {}) });
    if (built.unavailable) {
      return finish({ store: null, client: null, reason: built.unavailable.reason, detail: built.unavailable.detail });
    }
    client = built;
  }
  if (!client?.configured) {
    return finish({ store: null, client: null, reason: 'club_account_unconfigured', detail: 'The dedicated service account client is not usable.' });
  }

  const clubSchema = readClubSchemaConfig(env);
  if (!clubSchema.ok) {
    return finish({ store: null, client, reason: 'club_schema_unconfigured', detail: clubSchema.problems.join('; ') });
  }

  const tournamentSchema = readTournamentSchemaConfig(env);
  if (!tournamentSchema.ok) {
    return finish({ store: null, client, reason: 'tournament_schema_unconfigured', detail: tournamentSchema.problems.join('; ') });
  }

  let store = null;
  let reason = null;
  let detail = '';
  try {
    // THE MEMBERSHIP BRIDGE: the club store, constructed over the shared client. Its methods are the
    // only way this feature learns a club or super-admin fact, and nothing in `tournaments/` names a
    // club table.
    const clubStore = createClubNcbStore({ client, schema: clubSchema.schema });
    store = createTournamentNcbStore({
      client,
      schema: tournamentSchema.schema,
      clubBridge: {
        getMembership: (userId) => clubStore.getMembership(userId),
        clubStatus: (clubId) => clubStore.clubStatus(clubId),
        isSystemAdmin: (userId) => clubStore.isSystemAdmin(userId)
      }
    });
    store.__clubStore = clubStore;
  } catch (error) {
    // A store that cannot be constructed must not leave a half-working router behind: `store` stays null
    // and every tournament route answers 503.
    store = null;
    reason = 'tournament_store_construction_failed';
    detail = String(error?.name || error || 'failed');
  }
  return finish({ store, client, reason, detail, schema: tournamentSchema.schema });

  function finish({ store: builtStore, client: builtClient, reason: why, detail: whyDetail, schema = null }) {
    const columns = schema ? schema.columns.tournaments : null;
    return {
      router: createTournamentRouter({ store: builtStore, authenticate, limits, ...(columns ? { columns } : {}) }),
      configured: Boolean(builtStore),
      reason: builtStore ? null : (why || 'tournament_store_unavailable'),
      detail: builtStore ? '' : String(whyDetail || ''),
      routes: TOURNAMENT_ROUTES,
      store: builtStore,
      status() {
        return {
          configured: Boolean(builtStore),
          reason: builtStore ? null : (why || 'tournament_store_unavailable'),
          // An account PRESENCE flag and the client's own booleans: no email, no password, no token, no
          // table contents. Safe to print at boot and to serve from /health.
          account: builtClient ? builtClient.status() : { configured: false, sessionActive: false, identityVerified: false },
          routes: TOURNAMENT_ROUTES.length,
          // Where the club and super-admin facts come from. A constant string, printed so an operator can
          // see that this feature has no second membership path to configure.
          membershipBridge: builtStore ? 'club-store' : null
        };
      }
    };
  }
}

/**
 * One line for the boot log, with no secret and no table contents. The point of printing it is that
 * "tournament storage is inert" must be visible to whoever starts the container, not something a user
 * discovers by being told their tournament is missing.
 */
function describeTournamentStoreState(env = process.env) {
  const account = readClubAccountConfig(env);
  if (!account.ok) return `tournament storage INACTIVE — ${account.reason}`;
  const clubSchema = readClubSchemaConfig(env);
  if (!clubSchema.ok) return `tournament storage INACTIVE — club_schema_unconfigured (${clubSchema.problems[0]})`;
  const schema = readTournamentSchemaConfig(env);
  if (!schema.ok) return `tournament storage INACTIVE — tournament_schema_unconfigured (${schema.problems[0]})`;
  return 'tournament storage CONFIGURED (signs in lazily on first tournament request)';
}

/** What /health reports about Tournaments. Deliberately small: the state, not the data. */
function tournamentHealth(mount) {
  if (!mount) {
    return { configured: false, reason: 'tournament_mount_not_built', routes: 0 };
  }
  const state = mount.status();
  return {
    configured: state.configured,
    reason: state.reason,
    routes: state.routes,
    membershipBridge: state.membershipBridge,
    // No table or column name appears here, in line with every other route in this relay: the surface is
    // described by what it does, not by where it reads. `/health` is unauthenticated, and a published
    // schema is a map of what an attacker should try to write to.
    sessionActive: state.account.sessionActive === true,
    identityVerified: state.account.identityVerified === true
  };
}

module.exports = {
  buildTournamentMount,
  describeTournamentStoreState,
  tournamentHealth,
  TOURNAMENT_ROUTES
};
