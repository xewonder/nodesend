'use strict';

/*
 * CLUBS — the mount point bridge.js uses.
 *
 * One function builds the whole feature, and it is built ONCE at boot:
 *
 *   buildClubMount({ env, authenticate })  ->  { router, configured, reason, status() }
 *
 * THE MOUNT IS ALWAYS RETURNED, WHETHER OR NOT THE FEATURE CAN WORK. Registering the club routes
 * only when the configuration is complete would make a misconfigured deployment answer 404, and a
 * 404 is the worst possible signal here: it is indistinguishable from "NodeSend has no club
 * feature", so a browser would render "no clubs exist" and an operator would conclude the code was
 * never shipped. Mounted-always with a 503 says the true thing — the routes are here, the club
 * backend is not — and the client already maps it to a named reason.
 *
 * A STORE IS BUILT ONLY WHEN BOTH HALVES ARE PRESENT AND VALID:
 *   1. CLUB_NCB_EMAIL + CLUB_NCB_PASSWORD            the dedicated account, server-side names only
 *   2. CLUB_NCB_SCHEMA_FILE | CLUB_NCB_SCHEMA_JSON   the agreed five-table schema
 * Anything else leaves the store null. A schema is never guessed to make a screen happy, and
 * credentials are never accepted from a request.
 *
 * NO SIGN-IN HAPPENS AT BOOT. The first sign-in is lazy, inside the client, on the first club
 * request. So a relay can start and serve every existing route — AI, quota, Trickster,
 * invitations, email — even when the club account is misconfigured or NCB is unreachable. That is
 * what keeps this integration from being able to break the thing it was added to.
 */

const { createNcbAccountClient, readClubAccountConfig, assertNotFrontendFacing } = require('./ncbAccountClient.js');
const { createClubNcbStore } = require('./clubNcbStore.js');
const { readClubSchemaConfig, AGREED_TABLE_ROLES } = require('./clubSchema.js');
const { createClubRouter, CLUB_ROUTES } = require('./clubAuthorization.js');
const { createClubBootstrapRouter, BOOTSTRAP_ROUTES } = require('./clubBootstrap.js');

/**
 * @param {object} options
 * @param {object} [options.env]
 * @param {Function} options.authenticate the relay's OWN session resolver, adapted to
 *   `{ ok, id, role }` / `{ ok:false, status, code }`. Required — this module never reads a
 *   bearer, so there is exactly one way any route in it can learn who is calling.
 * @param {Function} [options.fetchImpl] injected for tests
 * @param {object} [options.limits]
 */
function buildClubMount({ env = process.env, authenticate, fetchImpl, limits } = {}) {
  if (typeof authenticate !== 'function') {
    throw new TypeError('buildClubMount needs the relay session authenticator');
  }

  const account = readClubAccountConfig(env);
  const frontend = assertNotFrontendFacing(env);
  const schema = account.ok ? readClubSchemaConfig(env) : { ok: false, schema: null, problems: ['club account is not configured'] };

  if (!account.ok) return finish({ authenticate, store: null, client: null, reason: account.reason, detail: account.detail, limits });
  if (!frontend.ok) return finish({ authenticate, store: null, client: null, reason: frontend.reason, detail: frontend.detail, limits });
  if (!schema.ok) return finish({ authenticate, store: null, client: null, reason: 'club_schema_unconfigured', detail: schema.problems.join('; '), limits });

  const client = createNcbAccountClient({ env, ...(fetchImpl ? { fetchImpl } : {}) });
  if (client.unavailable) {
    return finish({ authenticate, store: null, client: null, reason: client.unavailable.reason, detail: client.unavailable.detail, limits });
  }

  let store = null;
  let reason = null;
  let detail = '';
  try {
    store = createClubNcbStore({ client, schema: schema.schema });
  } catch (error) {
    // A store that cannot be constructed must not leave a half-working router behind: `store` stays
    // null and every club route answers 503.
    store = null;
    reason = 'club_store_construction_failed';
    detail = String(error?.name || error || 'failed');
  }
  return finish({ authenticate, store, client, reason, detail, limits });

  function finish({ store: builtStore, client: builtClient, reason: why, detail: whyDetail }) {
    // The bootstrap is mounted INSIDE the club router rather than as a second `app.use` in
    // bridge.js. That is not tidiness: bridge.js carries the owner's uncommitted work, and a
    // composition that needs no edit there keeps the shipped diff to the Clubs modules alone.
    const clubRouter = createClubRouter({ store: builtStore, authenticate, limits });
    const bootstrap = createClubBootstrapRouter({ store: builtStore, authenticate, env });
    clubRouter.use(bootstrap);
    return {
      router: clubRouter,
      configured: Boolean(builtStore),
      reason: builtStore ? null : (why || 'club_store_unavailable'),
      detail: builtStore ? '' : String(whyDetail || ''),
      routes: CLUB_ROUTES,
      bootstrapRoutes: BOOTSTRAP_ROUTES,
      bootstrapState: () => bootstrap.__bootstrapState(),
      status() {
        return {
          configured: Boolean(builtStore),
          reason: builtStore ? null : (why || 'club_store_unavailable'),
          // An account PRESENCE flag and the client's own booleans: no email, no password, no
          // token, no table contents. Safe to print at boot and to serve from /health.
          account: builtClient ? builtClient.status() : { configured: false, sessionActive: false, identityVerified: false },
          routes: CLUB_ROUTES.length,
          bootstrap: bootstrap.__bootstrapState()
        };
      }
    };
  }
}

/**
 * One line for the boot log, with no secret and no table contents. The point of printing it is
 * that "club storage is inert" must be visible to whoever starts the container, not something a
 * user discovers by being told they have no club.
 */
function describeClubStoreState(env = process.env) {
  const account = readClubAccountConfig(env);
  if (!account.ok) return `club storage INACTIVE — ${account.reason}`;
  const schema = readClubSchemaConfig(env);
  if (!schema.ok) return `club storage INACTIVE — club_schema_unconfigured (${schema.problems[0]})`;
  return 'club storage CONFIGURED (signs in lazily on first club request)';
}

/** What /health and / report about Clubs. Deliberately small: an operator needs the state, not the data. */
function clubHealth(mount) {
  if (!mount) {
    return { configured: false, reason: 'club_mount_not_built', routes: 0 };
  }
  const state = mount.status();
  return {
    configured: state.configured,
    reason: state.reason,
    routes: state.routes,
    // Two booleans only, and deliberately no id: whether the temporary first-run grant is currently
    // switchable and whether it has been used. Neither names a person, and neither is needed to
    // attempt the operation (which is closed by the table, not by this field).
    bootstrapEnabled: state.bootstrap?.enabled === true,
    bootstrapCompleted: state.bootstrap?.completed === true,
    // No table or column name appears here, in line with every other route in this relay: the
    // surface is described by what it does, not by where it reads. `/health` is unauthenticated,
    // and a published schema is a map of what an attacker should try to write to.
    sessionActive: state.account.sessionActive === true,
    identityVerified: state.account.identityVerified === true
  };
}

module.exports = {
  buildClubMount,
  describeClubStoreState,
  clubHealth,
  CLUB_ROUTES,
  BOOTSTRAP_ROUTES,
  AGREED_TABLE_ROLES,
  readClubAccountConfig,
  readClubSchemaConfig
};
