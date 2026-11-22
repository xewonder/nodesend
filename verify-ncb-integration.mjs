/*
INTEGRATION GATE — the shipped BridgeMind client against the shipped NodeSend relay, with a
contract-faithful NCB behind it.

WHY THIS FILE EXISTS SEPARATELY FROM verify-ncb-gateway.mjs
-----------------------------------------------------------
That gate proves the gateway's own rules. It cannot prove the thing that actually broke in
production: a credential shape, a base URL, and a table name. So this gate loads `src/api.js`,
`src/services/sessionAuth.js` and `src/services/appBootstrap.js` from the frontend repository
UNMODIFIED, through the same Vite SSR loader the frontend's own gates use, and drives them against
`bridge.js` booted in the configuration a real deployment uses (`NCB_TRANSPORT=native`). Every
assertion below is therefore about code that ships on both sides, not about a translation of it.

WHAT IS FAKED, AND WHY THAT IS THE RIGHT CHOICE
-----------------------------------------------
NCB itself. The vendor is not ours to write to from a test, and requirement constraints forbid
production writes. The fake reproduces the MEASURED contract: the auth family takes the instance by
header and answers `get-session` with a bare `null` when unsigned; the data family takes it by query;
`Authorization` is the database-secret slot and answers 403; create answers 201 with a top-level id;
read-by-id answers `data` as an OBJECT; a missing or denied row answers 404 with
"Record not found or access denied"; and there is NO public-data family (four candidate paths each
return an HTML 404 from the real host, which is the measurement that forced the invitation read
behind the service account). Row visibility is enforced per session, so the two-user isolation arms
here test the relay's behaviour under real RLS rather than under a permissive stub.

The AWS proxy is ALSO faked — by a second server whose only job is to record that nothing ever
dialed it. "The Lambda dependency is gone" is not a comment; it is a count of zero, checked after
the entire lifecycle has run.
*/

import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = HERE;
const GRETA = process.env.BRIDGEMIND_REPO || 'C:/Users/denis/Github/BridgeMind-Greta';
if (!fs.existsSync(path.join(GRETA, 'src/api.js'))) {
  console.error(`FRONTEND REPO NOT FOUND at ${GRETA} — set BRIDGEMIND_REPO. This gate proves the integration`);
  console.error('between the two repositories and refuses to report a pass without it.');
  process.exit(2);
}

const require = createRequire(path.join(GRETA, 'noop.cjs'));
const { createServer: createViteServer } = require('vite');

// ── the two upstreams: native NCB, and a Lambda that must never be called ───
const COOKIE = '__Secure-better-auth.session_token';
const USERS = {
  'player-a@poc.invalid': { password: 'pw-a-fixture', id: 'user-aaaa', name: 'Ada A' },
  'player-b@poc.invalid': { password: 'pw-b-fixture', id: 'user-bbbb', name: 'Bo B' },
  'club-service@poc.invalid': { password: 'club-fixture-password', id: 'club-svc-1', name: 'Club Service' }
};
const sessions = new Map();          // cookie value -> user id
const rows = [];                     // {id, table, user_id, ...fields}
let nextRowId = 1;
let newUserId = 1000;
// Two fault knobs, for the two failure points a registration can split across: the vendor refusing
// (or never answering) the account creation, and the vendor refusing the claim that must follow it.
// The second is the one that used to be invisible — an account created with no code spent against it.
let signUpFault = null;
let claimFault = null;
const nativeLog = [];
const lambdaLog = [];
const SECRET_MARKER = 'ncb_sec_real_looking_database_secret';

function answer(req, res, which) {
  const url = new URL(req.url, 'http://127.0.0.1');
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let body = null;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* non-json */ }
    const send = (status, payload, headers = {}) => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(payload === null ? 'null' : JSON.stringify(payload));
    };
    const cookiePair = (req.headers.cookie || '').split(';').map((s) => s.trim())
      .find((s) => s.startsWith(`${COOKIE}=`)) || '';
    const cookieValue = cookiePair ? cookiePair.slice(`${COOKIE}=`.length) : '';
    const who = sessions.get(cookieValue) || null;
    (which === 'native' ? nativeLog : lambdaLog).push({
      path: url.pathname, query: Object.fromEntries(url.searchParams), method: req.method,
      hasAuthorization: req.headers.authorization !== undefined,
      authorization: req.headers.authorization ?? null,
      hasCookie: Boolean(cookiePair), who, instanceHeader: req.headers['x-database-instance'] ?? null,
      body
    });

    if (which === 'lambda') return send(403, { Message: null });   // exactly what the real one does now

    // The measured rule: the Authorization header is the database secret slot. A secret-shaped value
    // is refused here AND asserted never to have been sent, so both directions of the mistake are
    // covered — including the "correct-looking" one where the relay forwards the browser bearer.
    if (req.headers.authorization !== undefined) {
      return send(403, { status: 'error', error: 'Invalid secret_key.', message: 'Invalid secret_key.' });
    }
    // An HTML 404 for a public family that does not exist on the real host, so a regression that
    // reaches for it fails loudly rather than returning empty rows.
    if (url.pathname.includes('/public-data')) {
      res.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
      return res.end('<!DOCTYPE html><html><head><title>Error</title></head><body>Not Found</body></html>');
    }

    if (url.pathname.startsWith('/api/user-auth/')) {
      const verb = url.pathname.slice('/api/user-auth/'.length);
      if (verb === 'sign-in/email' || verb === 'sign-up/email') {
        if (signUpFault) {
          // `destroy` is the silence case: the vendor accepts the connection and then says nothing,
          // which is the shape an operator actually sees during an outage and the one most likely to
          // be answered with a misleading 401.
          if (signUpFault.destroy) { req.socket?.destroy(); return; }
          return send(signUpFault.status, signUpFault.body ?? { status: 'error' });
        }
        const email = String(body?.email || '').toLowerCase();
        // SIGN-UP CREATES. The real vendor does, and an account the fake refuses to make would turn
        // every registration arm into a test of a refusal. A sign-up for an email that already exists
        // is the duplicate case, and it is answered the way better-auth answers it.
        if (verb === 'sign-up/email' && USERS[email]) {
          return send(422, { status: 'error', message: 'User already exists' });
        }
        if (!USERS[email]) {
            if (verb === 'sign-in/email') return send(401, { status: 'error', message: 'Invalid email or password' });
            USERS[email] = { id: `user-new-${++newUserId}`, password: body?.password, name: body?.name || 'New Player' };
        }
        const u = USERS[email];
        if (verb === 'sign-in/email' && u.password !== body?.password) {
          return send(401, { status: 'error', message: 'Invalid email or password' });
        }
        const value = `fixture-cookie-${u.id}`;
        sessions.set(value, u.id);
        return send(200, {
          status: 'success', token: 'vendor-body-token-not-a-session-channel',
          user: { id: u.id, email, name: u.name, role: email.startsWith('club-service') ? 'administrator' : 'user' }
        }, { 'Set-Cookie': `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=app.nocodebackend.com` });
      }
      if (verb === 'get-session') {
        if (!who) return send(200, null);                       // measured: bare null, unsigned
        const email = Object.keys(USERS).find((k) => USERS[k].id === who);
        return send(200, {
          status: 'success',
          data: { user: { id: who, email, name: USERS[email]?.name, role: email?.startsWith('club-service') ? 'administrator' : 'user' }, session: { expiresAt: 'later' } }
        });
      }
      if (verb === 'sign-out') { sessions.delete(cookieValue); return send(200, { status: 'success', data: null }); }
      if (verb === 'change-password') return send(200, { status: 'success', data: true });
      return send(404, { status: 'error', message: 'not found' });
    }

    if (url.pathname.startsWith('/api/data/')) {
      const [, , , verb, table, ...rest] = url.pathname.split('/');
      const id = rest.join('/');
      if (!who) return send(401, { status: 'error', message: 'Unauthorized. Provide a valid session cookie.' });
      const q = url.searchParams;
      // The club service account is privileged over the authority tables and only over them; a
      // player session stays scoped to its own rows. Both halves of that rule are asserted below, so
      // this line is a description of the arrangement rather than a convenience.
      const AUTHORITY = ['system_admins', 'clubs', 'club_memberships', 'club_board_collections', 'club_collection_boards', 'user_codes', 'invitation_reservations'];
      // `ai_quota_*` run under a documented `shared_readwrite` policy: every authenticated session in
      // the instance can reach the same rows, so there is NO per-user isolation there. Modelling that
      // honestly is what makes arm 9a mean something — the reason the quota tables are excluded from
      // the player gateway is that nothing downstream would have hidden them.
      const SHARED = ['ai_quota_config', 'ai_quota_usage', 'ai_quota_user_override', 'ai_quota_reservation'];
      const visible = () => (who === 'club-svc-1' && AUTHORITY.includes(table)) || SHARED.includes(table)
        ? rows.filter((r) => r.table === table)
        : rows.filter((r) => r.table === table && r.user_id === who);
      if (verb === 'read') {
        if (id) {
          const one = visible().find((r) => String(r.id) === id);
          return one ? send(200, { status: 'success', data: one })
            : send(404, { status: 'error', message: 'Record not found or access denied' });
        }
        let list = visible();
        for (const [k, v] of q.entries()) {
          if (['Instance', 'limit', 'page', 'sort', 'order'].includes(k)) continue;
          list = list.filter((r) => String(r[k]) === v);
        }
        const limit = Math.max(1, Number(q.get('limit') || 20) || 20);
        return send(200, { status: 'success', data: list.slice(0, limit), metadata: { page: 1, limit, hasMore: false, hasPrev: false } });
      }
      if (verb === 'create') {
        // The reservation table's UNIQUE(code_row_id), enforced HERE. Without it every concurrency arm
        // in section 14 would be measuring a mock that always says yes, and a green result would mean
        // nothing about the guarantee the design claims.
        if (table === 'invitation_reservations'
          && rows.some((r) => r.table === table && String(r.code_row_id) === String(body?.code_row_id))) {
          return send(400, { status: 'error', message: 'Duplicate entry for key code_row_id' });
        }
        // Ownership is assigned from the SESSION, and a `user_id` in the body is discarded — which is
        // the vendor's measured behaviour (`user_id` is a reserved, session-assigned column that a
        // client cannot write). Spreading the body first and the session last is what encodes that;
        // the reverse order would model a database where anybody can claim anybody else's rows.
        const row = { ...body, id: nextRowId++, table, user_id: who };
        rows.push(row);
        return send(201, { status: 'success', message: 'Record created successfully', id: row.id });
      }
      if (verb === 'update') {
        const row = visible().find((r) => String(r.id) === id);
        if (!row) return send(404, { status: 'error', message: 'Record not found or access denied' });
        if (table === 'user_codes' && claimFault) {
          return send(claimFault.status, claimFault.body ?? { status: 'error', message: 'write refused' });
        }
        /* MEASURED VENDOR BEHAVIOUR, per table. On `invitation_reservations` the PUT is answered with
           `200 application/json` and NOTHING is persisted — diagnosed live on 2026-11-20 with the
           NCB-stamped `user_id` echoed back and with it omitted, while an over-long `status` earns a
           400 from the database. The fake reproduces that, because a fake that writes would let this
           gate certify a completion UPDATE that the real vendor silently discards. On `user_codes` the
           write does land, and `user_id` is dropped (measured, code 891) — modelling that drop is what
           makes arm 14n's "the claim never writes user_id" assertion mean something. */
        const fields = { ...body };
        delete fields.user_id;
        if (table === 'invitation_reservations') {
          // The attempt itself is already in nativeLog, recorded centrally per request — so no second
          // ledger is kept here, and an arm that wants to prove the relay never asks can read that.
          return send(200, { status: 'success', message: 'Record updated successfully' });
        }
        Object.assign(row, fields);
        return send(200, { status: 'success', data: row });
      }
      if (verb === 'delete') {
        const row = visible().find((r) => String(r.id) === id);
        if (!row) return send(404, { status: 'error', message: 'Record not found or access denied' });
        rows.splice(rows.indexOf(row), 1);
        return send(200, { status: 'success', data: null });
      }
    }
    return send(404, { status: 'error', message: 'not found' });
  });
}

const native = http.createServer((req, res) => answer(req, res, 'native'));
const lambda = http.createServer((req, res) => answer(req, res, 'lambda'));
await new Promise((r) => native.listen(0, '127.0.0.1', r));
await new Promise((r) => lambda.listen(0, '127.0.0.1', r));
const NATIVE = `http://127.0.0.1:${native.address().port}`;
const LAMBDA = `http://127.0.0.1:${lambda.address().port}`;

// Seed the invitation row the registration flow looks up, and a row that must never be reachable
// through the anonymous route.
rows.push({ id: 900, table: 'user_codes', user_id: 'club-svc-1', code: 'BRIDGE-2026-KEY', used: 0, registered_user_id: null, issued_by: 'club-svc-1', note: 'internal note that must not be projected', api_key: SECRET_MARKER });
// The codes section 11 spends. Each arm gets its own row so a failure in one cannot make another
// pass by accident, and the used-by-another row exists so the refusal is measured rather than
// asserted: a claim that could not see a spent code would also happily overwrite one.
rows.push(
  { id: 930, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-VALID-1', used: 0, registered_user_id: null },
  { id: 931, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-RACE-1', used: 0, registered_user_id: null },
  { id: 932, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-CLAIMFAIL-1', used: 0, registered_user_id: null },
  { id: 933, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-USED-1', used: 1, registered_user_id: 'user-somebody-else' },
  { id: 934, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-DUP-1', used: 0, registered_user_id: null },
  { id: 935, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-DUP-1', used: 0, registered_user_id: null },
  { id: 936, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-OUTAGE-1', used: 0, registered_user_id: null },
  // allocated-but-unspent: the flag says free, the owner column says otherwise. Handing this to a new
  // registration would reassign an administrator's audit record; the rule is refused, not judged.
  { id: 937, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-ALLOC-1', used: 0, registered_user_id: 'user-previous' },
  // A two-record code, so concurrency can be measured as the store actually resolves it: two callers,
  // two DIFFERENT records, both registrations succeeding. One record cannot show this.
  { id: 939, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-POOL2', used: 0, registered_user_id: null },
  { id: 938, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-POOL2', used: 0, registered_user_id: null },
  // A record whose registration is refused by the VENDOR because the address already has an account.
  // That is a DECIDED outcome — no account was created — so the record must go back in the pool, which
  // is the opposite of the ambiguous case arm 14w measures.
  { id: 940, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-DEMAIL-1', used: 0, registered_user_id: null },
  // A TEN-record pool, ids descending on purpose: at the size a bulk invitation is actually issued,
  // ascending selection has to be produced by the claim, not inherited from the return order.
  { id: 950, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 949, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 948, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 947, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 946, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 945, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 944, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 943, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 942, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null },
  { id: 941, table: 'user_codes', user_id: 'club-svc-1', code: 'FLOW-TEN-1', used: 0, registered_user_id: null }
);
// The club authority data, as the service-account path sees it. These rows belong to no player:
// `clubs/ncbAccountClient.js` reads them as the dedicated club account, which is exactly the model
// the club feature runs on, so the fake makes that account privileged over the authority tables and
// leaves every player session scoped to its own rows.
rows.push(
  { id: 901, table: 'system_admins', user_id: 'user-aaaa' },
  { id: 10, table: 'clubs', user_id: 'club-svc-1', name: 'Glyfada BC', active: 1 },
  { id: 902, table: 'club_memberships', user_id: 'user-aaaa', club_id: '10', role: 'admin', status: 'approved' },
  // The global quota configuration row, spelled exactly as the quota ledger reads it (the same
  // columns verify-session-quota.mjs seeds): it belongs to no player, which is why a per-user filter
  // over it would read as "no configuration" and 503 a call that was perfectly payable.
  {
    id: 1, table: 'ai_quota_config', quota_enabled: 1, default_call_limit: 50,
    period_type: 'monthly',
    updated_at: new Date().toISOString().slice(0, 19).replace('T', ' ')
  }
);

// ── the relay, in the configuration a real deployment uses ─────────────────
const SEAL_KEY = 'integration-gate-seal-key-not-a-real-secret-32';
const PROD_ORIGINS = ['https://app.bridgemind.app', 'https://live.bridgemind.app', 'https://bid.bridgemind.app', 'https://play.bridgemind.app'];
const DEV_ORIGIN = 'http://localhost:5173';
// The agreed five-table schema plus the optional directory role, spelled as .env.example and
// verify-clubs-gateway.mjs spell it: the store is schema-driven, so a schema this relay's own
// validator refuses leaves the club routes 503 and the gate would be testing nothing.
const CLUB_SCHEMA = JSON.stringify({
  tables: {
    systemAdmins: 'system_admins',
    clubs: 'clubs',
    memberships: 'club_memberships',
    collections: 'club_board_collections',
    boards: 'club_collection_boards',
    users: 'user_settings'
  },
  columns: {
    systemAdmins: { userId: 'user_id' },
    clubs: { id: 'id', name: 'name', status: 'active' },
    memberships: { id: 'id', userId: 'user_id', clubId: 'club_id', role: 'role', status: 'status' },
    collections: { id: 'id', clubId: 'club_id', name: 'title', status: 'publication_status', createdBy: 'created_by_user_id' },
    boards: { id: 'id', collectionId: 'collection_id', boardNumber: 'board_number', dealer: 'dealer', vulnerability: 'vulnerability', handsJson: 'hands_json' },
    users: { userId: 'user_id', nickname: 'nickname', displayName: 'display_name', nicknameNormalized: 'nickname_normalized' }
  },
  values: { clubs: { status: { active: 1, inactive: 0 } } }
});

process.env = {
  ...process.env,
  BRIDGE_API_KEY: 'relay-key-not-a-club-secret',
  // The two bases the native transport needs, and the legacy one pointed at a Lambda that must
  // record zero calls for the whole run.
  NCB_AUTH_API_URL: `${NATIVE}/api/user-auth`,
  NCB_DATA_API_URL: `${NATIVE}/api/data`,
  NCB_PROXY_BASE: LAMBDA,
  NCB_TRANSPORT: 'native',
  NCB_INSTANCE: '55954_bridgemind',
  NCB_ALLOW_INSECURE_UPSTREAM: '1',
  NCB_SESSION_SEAL_KEY: SEAL_KEY,
  NCB_GATEWAY_ALLOWED_ORIGINS: [...PROD_ORIGINS, DEV_ORIGIN].join(','),
  // This mount models a deployment where registration has been deliberately reopened, because section
  // 6 needs the sign-up envelope Login.jsx branches on. The shipped default is the OPPOSITE — no flag,
  // registration refused — and arms 6j/6k measure that default on its own mount rather than leaving
  // it to a comment.
  NCB_GATEWAY_ALLOW_SIGN_UP: '1',
  // The claim channel this gate measures is the one the owner approved on 2026-11-20: single use
  // arbitrated by a database UNIQUE index on the individual user_codes RECORD id. The fake above
  // enforces that index, so a green concurrency arm here means the arbitration was actually tested.
  // The SHIPPED default remains `atomic-only` — no store, every claim refused — and arms 14p/14s
  // measure that state on their own mount and unit, so this line cannot make fail-closed untested.
  INVITATION_CLAIM_MODE: 'reservation',
  INVITATION_RESERVATION_HMAC_KEY: 'integration-gate-reservation-hmac-key-not-a-secret',
  // Every request in this gate arrives from 127.0.0.1, and section 14 now drives ten concurrent
  // registrations plus a dozen sequential ones. At the shipped throttle of 20 per window the arm would
  // measure a 429 and call it a claim outcome — the same false negative the anonymous-read throttle
  // already forces this gate to route around above. The throttle itself is measured where it belongs,
  // on its own mount in verify-ncb-gateway.mjs section 12.
  NCB_GATEWAY_AUTH_RATE_MAX: '5000',
  CLUB_NCB_EMAIL: 'club-service@poc.invalid',
  CLUB_NCB_PASSWORD: 'club-fixture-password',
  CLUB_NCB_EXPECTED_USER_ID: 'club-svc-1',
  CLUB_NCB_SCHEMA_JSON: CLUB_SCHEMA,
  CLUB_BOOTSTRAP_ENABLED: 'false',
  NODESEND_QUOTA_URL: '',
  AI_QUOTA_RESERVATION_TABLE: '',
  NODESEND_PRIVATE_KEY_B64: ''
};
delete process.env.NODESEND_PRIVATE_KEY_PEM;

const nodeRequire = createRequire(path.join(ROOT, 'noop.cjs'));
const bridge = nodeRequire(path.join(ROOT, 'bridge.js'));
const relay = bridge.app.listen(0, '127.0.0.1');
await new Promise((r) => relay.once('listening', r));
const BASE = `http://127.0.0.1:${relay.address().port}`;

// Capture what the relay prints, so "no credential in logs" is measured rather than asserted.
const logs = [];
const realLog = console.log, realErr = console.error, realWarn = console.warn;
console.log = (...a) => { logs.push(a.map(String).join(' ')); realLog(...a); };
console.error = (...a) => { logs.push(a.map(String).join(' ')); realErr(...a); };
console.warn = (...a) => { logs.push(a.map(String).join(' ')); realWarn(...a); };

// ── the real client, loaded the way the frontend's own gates load it ───────
// `envDir` is a generated directory holding `.env`, because the base is now configuration: this is
// the same path a production build takes (`import.meta.env.VITE_NCB_PROXY_BASE`), so the gate proves
// the variable works rather than proving a monkey-patch works.
const envDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bm-ncb-integration-'));
fs.writeFileSync(path.join(envDir, '.env'), `VITE_NCB_PROXY_BASE=${BASE}/ncb\n`);
const vite = await createViteServer({
  configFile: false, root: GRETA, appType: 'custom', logLevel: 'error', envDir,
  server: { middlewareMode: true }, resolve: { alias: { '@': path.join(GRETA, 'src') } }
});
const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(String(k), String(v)),
  removeItem: (k) => store.delete(String(k)),
  clear: () => store.clear()
};

const results = [];
const check = (name, condition, detail = '') => results.push({
  name, pass: condition === true, detail: condition === true ? '' : String(detail ?? '').slice(0, 240)
});

let api = await vite.ssrLoadModule('/src/api.js');
const sessionAuth = await vite.ssrLoadModule('/src/services/sessionAuth.js');
const { runAppBootstrap } = await vite.ssrLoadModule('/src/services/appBootstrap.js');

// 0: what does the shipped buildProxyUrl produce, given that configuration? Probed by intercepting
// fetch, so the answer is the URL the browser would send rather than a reading of the source.
{
  const seenPaths = [];
  const real = globalThis.fetch;
  globalThis.fetch = (u, init) => { try { seenPaths.push(new URL(String(u)).pathname); } catch { /* */ } return Promise.resolve(new Response('{}', { status: 500 })); };
  // Caught rather than allowed to throw: `buildProxyUrl` can raise ERR_INVALID_URL if the base or the
  // joining rule regresses, and a gate that dies reports nothing. This way the arm goes red and the
  // rest of the run continues.
  let buildThrew = null;
  try {
    await api.authFetch('get-session');
    await api.dataFetch('read/user_settings?limit=1');
    await api.publicDataFetch('read/user_codes?code=BRIDGE-2026-KEY');
  } catch (error) { buildThrew = String(error?.message || error).slice(0, 80); }
  globalThis.fetch = real;
  check('0b. buildProxyUrl keeps the /ncb prefix on the auth, data and public-data families',
    buildThrew === null && seenPaths.length === 3 && seenPaths[0] === '/ncb/auth/get-session'
    && seenPaths[1] === '/ncb/data/read/user_settings' && seenPaths[2] === '/ncb/public-data/read/user_codes',
    buildThrew ? `threw: ${buildThrew}` : seenPaths.join(' , '));
}

// ── 1. sign-in, and what reaches the browser ───────────────────────────────
const signedIn = await api.authFetch('sign-in/email', { method: 'POST', body: JSON.stringify({ email: 'player-a@poc.invalid', password: 'pw-a-fixture' }) });
const handleA = String(signedIn?.token || '');
check('1a. the shipped client signs in through the gateway', signedIn?.status === 'success' && signedIn?.data?.user?.id === 'user-aaaa', JSON.stringify(signedIn));
check('1b. the handle lands where the client stores it, without any app-side code', handleA.startsWith('ncbs1.') && localStorage.getItem(api.SESSION_TOKEN_KEY) === handleA, `${handleA.slice(0, 10)}… stored=${String(localStorage.getItem(api.SESSION_TOKEN_KEY)).slice(0, 10)}…`);
check('1c. the vendor body token is NOT the stored credential', handleA !== 'vendor-body-token' && ![...store.values()].includes('vendor-body-token'), JSON.stringify([...store.keys()]));
check('1d. sessionAuth hands the AI/Trickster transports the same handle the gateway issued',
  sessionAuth.getSessionToken() === handleA && sessionAuth.sessionAuthHeaders().Authorization === `Bearer ${handleA}`, JSON.stringify(sessionAuth.sessionAuthHeaders()).slice(0, 40));
check('1e. no upstream cookie or secret is present in anything the client holds',
  ![...store.values()].join('|').includes('fixture-cookie') && ![...store.values()].join('|').includes(SECRET_MARKER), JSON.stringify([...store.values()].map((v) => String(v).slice(0, 12))));

// ── 2. data CRUD as the player, through the real module ────────────────────
const list = await api.dataFetch('read/user_settings?limit=10&sort=created_at&order=desc');
check('2a. an authenticated read answers the vendor list envelope', list?.status === 'success' && Array.isArray(list?.data) && 'metadata' in (list ?? {}), JSON.stringify(list));
const created = await api.dataFetch('create/user_settings', { method: 'POST', body: JSON.stringify({ nickname: 'ada', ai_source: 'user' }) });
const createdId = created?.data?.id ?? created?.id ?? null;
check('2b. create is readable through the app’s own expression, response.data.id ?? response.id',
  created?.status === 'success' && Number(createdId) >= 1, JSON.stringify(created));
const byId = await api.dataFetch(`read/user_settings/${createdId}`);
check('2c. read-by-id returns data as an OBJECT, not a one-item array',
  byId?.status === 'success' && byId?.data?.nickname === 'ada' && !Array.isArray(byId?.data), JSON.stringify(byId));
const updated = await api.dataFetch(`update/user_settings/${createdId}`, { method: 'PUT', body: JSON.stringify({ nickname: 'ada2' }) });
check('2d. update round-trips', updated?.status === 'success' && updated?.data?.nickname === 'ada2', JSON.stringify(updated));
const removed = await api.dataFetch(`delete/user_settings/${createdId}`, { method: 'DELETE' });
const afterDelete = await api.dataFetch(`read/user_settings/${createdId}`);
check('2e. delete then reads back as an error, which is the shape userProfileService maps to "no row"',
  removed?.status === 'success' && afterDelete?.status === 'error' && afterDelete?.httpStatus === 404, JSON.stringify(afterDelete));

// ── 3. page refresh: a NEW module instance, the same localStorage ──────────
// A page refresh, modelled the way a refresh actually behaves: the module's in-memory state is gone
// (Vite's SSR cache returns the SAME instance, so the cache is cleared explicitly rather than
// pretending a second load is a second process) while `localStorage` survives. That is exactly the
// pair of facts restart-safety has to hold against.
const apiReloaded = await vite.ssrLoadModule('/src/api.js', { fixStacktrace: true });
apiReloaded.clearSessionCache();
const refreshed = await apiReloaded.authSession();
check('3a. with the module cache cold and only storage left, the session is re-established from the handle',
  refreshed?.status === 'success' && refreshed?.data?.user?.id === 'user-aaaa', JSON.stringify(refreshed));
check('3b. get-session re-mints the handle and the client persists it without app code',
  String(refreshed?.token).startsWith('ncbs1.') && localStorage.getItem(apiReloaded.SESSION_TOKEN_KEY) === refreshed?.token, '');
const preRenewalWorks = await (await fetch(`${BASE}/ncb/data/read/user_settings?limit=1`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } })).status;
check('3c. the pre-renewal handle still works, so a second tab is not locked out', preRenewalWorks === 200, `status=${preRenewalWorks}`);

// ── 4. the surfaces that used to depend on the Lambda, driven by the client ─
const quota = await (await fetch(`${BASE}/ai/quota`, { headers: { ...sessionAuth.sessionAuthHeaders(), Origin: PROD_ORIGINS[0] } }));
const quotaBody = await quota.json().catch(() => ({}));
check('4a. GET /ai/quota authenticates the sealed handle and returns the player’s own usage',
  quota.status === 200 && quotaBody?.error === undefined && quotaBody?.used !== undefined, `${quota.status} ${JSON.stringify(quotaBody).slice(0, 120)}`);
const myClub = await (await fetch(`${BASE}/me/club`, { headers: { ...sessionAuth.sessionAuthHeaders(), Origin: PROD_ORIGINS[0] } }));
const myClubBody = await myClub.json().catch(() => ({}));
check('4b. GET /me/club authenticates the handle and keeps its own club authorization model',
  myClub.status === 200 && myClubBody?.status === 'success', `${myClub.status} ${JSON.stringify(myClubBody).slice(0, 120)}`);
const clubsList = await (await fetch(`${BASE}/clubs`, { headers: { ...sessionAuth.sessionAuthHeaders(), Origin: PROD_ORIGINS[0] } }));
check('4c. GET /clubs is served without the AWS proxy and without a member row inventing a club',
  clubsList.status === 200, `${clubsList.status}`);
const trickster = await (await fetch(`${BASE}/trickster/bid/health`, { headers: { ...sessionAuth.sessionAuthHeaders(), Origin: PROD_ORIGINS[0] } }));
check('4d. the Trickster gateway accepts the same handle', trickster.status === 200, `${trickster.status}`);
// The multiplayer routes, discovered from the live app rather than assumed. A seat-ticket refusal is
// the PASS here: it means the session guard let the request through and the ticket check is what
// answered — which is the only thing this arm is about.
const mpRoutes = [];
{
  const walk = (stack) => { for (const l of stack) { if (l?.route) { for (const m of Object.keys(l.route.methods || {})) if (l.route.path.startsWith('/mp')) mpRoutes.push(`${m.toUpperCase()} ${l.route.path}`); } else if (l?.handle?.stack) walk(l.handle.stack); } };
  walk(bridge.app._router.stack);
}
const [mpMethod, mpPath] = (mpRoutes.find((r) => r.startsWith('POST ')) || mpRoutes[0] || '').split(' ');
if (mpMethod) {
  const r = await fetch(`${BASE}${mpPath.replace(/:[A-Za-z0-9_]+/g, 'x')}`, {
    method: mpMethod,
    headers: { ...sessionAuth.sessionAuthHeaders(), Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json' },
    ...(mpMethod === 'POST' ? { body: JSON.stringify({}) } : {})
  });
  const text = await r.text();
  check('4e. a multiplayer route resolves the sealed handle rather than rejecting it as a bad credential',
    !/auth_error|session_service_unavailable/.test(text), `${r.status} ${text.slice(0, 90)}`);
} else {
  // Option B: the release candidate under test deliberately carries no multiplayer surface. Reporting
  // that as a PASS with the route inventory as evidence, rather than as a red line or as silence — and
  // this arm goes red again the moment the unfinished endpoints come back, so it stays a real check.
  check('4e. [multiplayer out of this release] the candidate mounts no /mp endpoint, so nothing unfinished is reachable',
    mpRoutes.length === 0, `found ${JSON.stringify(mpRoutes.slice(0, 3))}`);
}
check('4f. the Lambda recorded ZERO requests across every authenticated surface above',
  lambdaLog.length === 0, JSON.stringify(lambdaLog.slice(0, 2)));

// ── 5. two players, one table: RLS through the gateway ─────────────────────
// SCOPE OF THE EVIDENCE, stated because the difference matters to anyone reading a green line here.
// The fake enforces a PRIVATE policy on `llm_preferences`. The real instance documents that table as
// `shared_readwrite` — measured 2026-11-17, and the frontend filters those reads by `user_id` itself,
// which nobody does when the database already scopes them. So what these arms prove is conditional and
// important in its own right: GIVEN an upstream that scopes rows by session, the relay forwards each
// request as that session and adds no reach of its own. What they do not prove is that production
// isolates those tables — it does not, and `verify-ncb-live.mjs` section 5 is where that distinction
// is measured per table, comparing each gateway read against the vendor's own answer for the same
// session. A rig is a statement about the code; only the live run is a statement about the database.
const inB = await api.authFetch('sign-in/email', { method: 'POST', body: JSON.stringify({ email: 'player-b@poc.invalid', password: 'pw-b-fixture' }) });
const handleB = String(inB?.token || '');
localStorage.setItem(api.SESSION_TOKEN_KEY, handleA);
const rowA = await api.dataFetch('create/llm_preferences', { method: 'POST', body: JSON.stringify({ usage: 'gameplay', marker: 'A-ONLY' }) });
localStorage.setItem(api.SESSION_TOKEN_KEY, handleB);
const rowB = await api.dataFetch('create/llm_preferences', { method: 'POST', body: JSON.stringify({ usage: 'gameplay', marker: 'B-ONLY' }) });
check('5a. both players can create their own row', rowA?.status === 'success' && rowB?.status === 'success', `${JSON.stringify(rowA).slice(0, 60)} ${JSON.stringify(rowB).slice(0, 60)}`);
const aList = await (await fetch(`${BASE}/ncb/data/read/llm_preferences?limit=50`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } })).json();
const bList = await (await fetch(`${BASE}/ncb/data/read/llm_preferences?limit=50`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleB}` } })).json();
const markers = (j) => (j?.data ?? []).map((r) => r.marker);
check('5b. each player sees their own row, and the other’s is invisible',
  markers(aList).includes('A-ONLY') && !markers(aList).includes('B-ONLY')
  && markers(bList).includes('B-ONLY') && !markers(bList).includes('A-ONLY'), JSON.stringify({ a: markers(aList), b: markers(bList) }));
const aOnB = await (await fetch(`${BASE}/ncb/data/llm_preferences/never-mind`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } })).status;
const crossRead = await (await fetch(`${BASE}/ncb/data/read/llm_preferences/${rowB?.data?.id ?? rowB?.id}`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } }));
check('5c. A addressing B’s row by primary key is not served', crossRead.status === 404, `${crossRead.status} ${aOnB}`);
const crossWrite = await (await fetch(`${BASE}/ncb/data/update/llm_preferences/${rowB?.data?.id ?? rowB?.id}`, {
  method: 'PUT', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', Authorization: `Bearer ${handleA}` }, body: JSON.stringify({ marker: 'hijacked' })
}));
check('5d. A cannot overwrite B’s row', crossWrite.status === 404, `${crossWrite.status}`);
const bStill = await (await fetch(`${BASE}/ncb/data/read/llm_preferences/${rowB?.data?.id ?? rowB?.id}`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleB}` } })).json();
check('5e. and B’s row is untouched afterwards — the negative arms have a positive control',
  bStill?.data?.marker === 'B-ONLY', JSON.stringify(bStill).slice(0, 100));
// A body-supplied `user_id` must never decide ownership: A tries to create a row INTO B's account.
localStorage.setItem(api.SESSION_TOKEN_KEY, handleA);
const forged = await api.dataFetch('create/llm_preferences', { method: 'POST', body: JSON.stringify({ user_id: 'user-bbbb', marker: 'FORGED-INTO-B' }) });
localStorage.setItem(api.SESSION_TOKEN_KEY, handleB);
const bSees = await api.dataFetch('read/llm_preferences?limit=50');
const aSees = await (await fetch(`${BASE}/ncb/data/read/llm_preferences?limit=50`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } })).json();
check('5f. a user_id in the body is never believed — the forged row belongs to A, not to B',
  forged?.status === 'success' && !markers(bSees).includes('FORGED-INTO-B') && markers(aSees).includes('FORGED-INTO-B'),
  JSON.stringify({ forged: forged?.status, b: markers(bSees), a: markers(aSees) }));

// ── 6. registration and the invitation code ────────────────────────────────
localStorage.removeItem(api.SESSION_TOKEN_KEY);          // a visitor with no session at all
const codeRow = await api.publicDataFetch('read/user_codes?code=BRIDGE-2026-KEY');
check('6a. the anonymous invitation read is served, in the envelope Login.jsx branches on',
  codeRow?.status === 'success' && Array.isArray(codeRow?.data) && codeRow.data.length === 1, JSON.stringify(codeRow));
check('6b. the row is projected to the fields the flow reads, and no column beyond them',
  codeRow?.data?.[0] && Object.keys(codeRow.data[0]).every((k) => ['id', 'code', 'used', 'registered_user_id'].includes(k))
  && codeRow.data[0].code === 'BRIDGE-2026-KEY', JSON.stringify(codeRow?.data?.[0] ?? {}));
check('6c. no secret or credential field survives the projection',
  !JSON.stringify(codeRow).includes(SECRET_MARKER) && !JSON.stringify(codeRow).includes('internal note'),
  JSON.stringify(codeRow).slice(0, 140));
const unfiltered = await (await fetch(`${BASE}/ncb/public-data/read/user_codes`, { headers: { Origin: PROD_ORIGINS[0] } }));
check('6d. an unfiltered public read is refused — the route cannot enumerate invitation codes',
  unfiltered.status === 400, `${unfiltered.status}`);
const wrongPublicTable = await (await fetch(`${BASE}/ncb/public-data/read/user_settings?code=X`, { headers: { Origin: PROD_ORIGINS[0] } }));
check('6e. the public route serves one table and no other',
  wrongPublicTable.status === 403, `${wrongPublicTable.status}`);
const codelessBefore = nativeLog.filter((e) => String(e.path).includes('sign-up')).length;
const codelessSignUp = await api.authFetch('sign-up/email', { method: 'POST', body: JSON.stringify({ name: 'Cy New', email: 'walk-in@poc.invalid', password: 'pw-walk-in-fixture' }) });
const codelessUpstream = nativeLog.filter((e) => String(e.path).includes('sign-up')).length - codelessBefore;
check('6f. a sign-up with no invitation is refused by the SERVER, not by the page, and never reaches NCB',
  codelessSignUp?.httpStatus === 403 && codelessSignUp?.error === 'invitation_required' && codelessUpstream === 0,
  JSON.stringify(codelessSignUp).slice(0, 140));

// ── 6g-6i. REGISTRATION CLAIMING IS UNAVAILABLE, and that has to be measured, not intended.
//
// `Login.jsx` claims an invitation by PUT-ing the row itself (`claimInvitationCode`, line ~214):
// `update/user_codes/<id>` with `{used:1, registered_user_id}`. Under a uniform CRUD grant that is a
// signed-in player writing an invitation table shared by every account — any of them could spend any
// code. `user_codes` is therefore read-only through the player gateway, and this is the arm that
// proves the claim actually fails rather than assuming the policy file says so. An unverified claim
// path means public registration cannot complete, which is the current release decision: sign-in for
// existing accounts works, and registration resumes only once the server-side claim route
// (`POST /auth/consume-invitation`) is fixed to record `registered_user_id` and verified live.
const claimTarget = codeRow?.data?.[0]?.id;
localStorage.setItem(api.SESSION_TOKEN_KEY, handleA);
const writesBeforeClaim = nativeLog.filter((e) => e.method === 'PUT' && e.path.includes('/api/data/')).length;
const claim = await api.dataFetch(`update/user_codes/${claimTarget}`, {
  method: 'PUT', body: JSON.stringify({ used: 1, registered_user_id: 'user-aaaa' })
});
check('6g. the invitation claim a player would perform is refused at the gateway',
  claim?.status === 'error' && claim?.httpStatus === 403 && claim?.error === 'write_not_allowed',
  JSON.stringify(claim).slice(0, 140));
const rowAfterClaim = await api.publicDataFetch('read/user_codes?code=BRIDGE-2026-KEY');
const rowBeforeJson = JSON.stringify(codeRow?.data?.[0] ?? {});
const rowAfterJson = JSON.stringify(rowAfterClaim?.data?.[0] ?? {});
check('6h. and the invitation row is unchanged — the refusal happened before NCB was contacted',
  rowAfterClaim?.data?.[0]?.used === 0 && rowAfterClaim?.data?.[0]?.registered_user_id === null
  && rowAfterJson === rowBeforeJson, rowAfterJson);
// Counted as a delta across the claim, not as a total: section 2 performs legitimate PUTs of its own,
// and a whole-run count would report those as leaks.
const claimPutReachesUpstream = nativeLog.filter((e) => e.method === 'PUT' && e.path.includes('/api/data/')).length - writesBeforeClaim;
check('6i. the refused claim issued no upstream write at all',
  claimPutReachesUpstream === 0, `${claimPutReachesUpstream} upstream PUT(s) after the claim attempt`);

// 6j/6k. THE SHIPPED DEFAULT, measured rather than intended. The relay above runs with registration
// reopened deliberately (section 6 needs the sign-up envelope); a deployment that sets nothing gets the
// opposite, and that is the state the release decision rests on. So this is the real Login.jsx request,
// against the vendor recorder, on a default-configured mount of the shipped builder.
{
  const closedEnv = { ...process.env };
  delete closedEnv.NCB_GATEWAY_ALLOW_SIGN_UP;
  // A standalone mount has no service account to borrow for the anonymous read, so the guest reader is
  // stubbed with the same projected row the real one returns. It exists to prove the lookup route is
  // not what the flag turns off; the real reader is exercised end to end in 6a-6c on the main relay.
  const closedMount = bridge.buildNcbGateway({
    env: closedEnv,
    guestRead: async () => ({ ok: true, rows: [{ id: 900, code: 'BRIDGE-2026-KEY', used: 0, registered_user_id: null }] })
  });
  const express = nodeRequire('express');
  const closedApp = express(); closedApp.use(express.json()); closedApp.use(closedMount.router);
  const closedServer = closedApp.listen(0, '127.0.0.1');
  await new Promise((r) => closedServer.once('listening', r));
  const closedBase = `http://127.0.0.1:${closedServer.address().port}`;
  const vendorBefore = nativeLog.length;
  const regAttempt = await fetch(`${closedBase}/ncb/auth/sign-up/email`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: PROD_ORIGINS[0] },
    body: JSON.stringify({ email: 'walk-in@poc.invalid', password: 'pw-walk-in-fixture', name: 'No Code' })
  });
  const regBody = await regAttempt.json().catch(() => ({}));
  const dialledForReg = nativeLog.slice(vendorBefore).filter((e) => String(e.path).includes('sign-up')).length;
  check('6j. with the shipped defaults a walk-in cannot create an account — refused before the vendor is dialled',
    regAttempt.status === 403 && regBody?.error === 'sign_up_unavailable' && dialledForReg === 0,
    `${regAttempt.status}/${regBody?.error}; upstream sign-up calls ${dialledForReg}`);
  const signInStill = await fetch(`${closedBase}/ncb/auth/sign-in/email`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: PROD_ORIGINS[0] },
    body: JSON.stringify({ email: 'player-a@poc.invalid', password: 'pw-a-fixture' })
  });
  const renewedStill = await fetch(`${closedBase}/ncb/auth/get-session`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } });
  const invitationStillReadable = await fetch(`${closedBase}/ncb/public-data/read/user_codes?code=BRIDGE-2026-KEY`, { headers: { Origin: PROD_ORIGINS[0] } });
  check('6k. the restriction is registration only — sign-in, session refresh and the invitation lookup all still work on the same mount',
    signInStill.status === 200 && renewedStill.status === 200 && invitationStillReadable.status === 200,
    `sign-in=${signInStill.status} get-session=${renewedStill.status} codes=${invitationStillReadable.status}`);
  check('6l. and the state is visible in the health report, so nobody has to remember which lever was pulled',
    closedMount.health().signUpAllowed === false, `${closedMount.health().signUpAllowed}`);
  await new Promise((r) => closedServer.close(r));
}

// ── 7. sign-out, and the exact residue of a handle ─────────────────────────
localStorage.setItem(api.SESSION_TOKEN_KEY, handleB);
const out = await api.authFetch('sign-out', { method: 'POST' });
check('7a. sign-out answers the success envelope App.jsx needs before it will clear the session',
  out?.status === 'success', JSON.stringify(out));
// Asked of the network, not of `authSession()`: the client caches a successful session for 60 s by
// design (api.js:40, SESSION_FRESH_MS), so a cache read here would report yesterday's answer and the
// arm would pass or fail on timing rather than on the gateway's behaviour.
const afterOut = await api.authFetch('get-session');
check('7b. after sign-out the client is told 401 invalid_session, not that the service is down',
  afterOut?.status === 'error' && afterOut?.httpStatus === 401, JSON.stringify(afterOut));
api.clearSessionCache();
const cacheCleared = await api.authSession();
check('7b2. and the same answer holds through the cache-aware path once the cache is cleared',
  cacheCleared?.status === 'error' && cacheCleared?.httpStatus === 401, JSON.stringify(cacheCleared).slice(0, 120));
check('7c. the released handle can no longer read any data upstream',
  (await fetch(`${BASE}/ncb/data/read/user_settings?limit=1`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleB}` } })).status === 401, '');
const ttlLeft = bridge.ncbSeal({ env: process.env }).open(handleB);
check('7d. its remaining LOCAL validity is bounded by the configured TTL, which is the documented residue',
  ttlLeft.ok === true && ttlLeft.session?.expiresAt > Date.now()
  && ttlLeft.session.expiresAt - Date.now() <= 12 * 60 * 60 * 1000,
  ttlLeft.ok ? `${Math.round((ttlLeft.session.expiresAt - Date.now()) / 60000)} min` : `reason=${ttlLeft.reason} handle=${String(handleB).slice(0, 12)}`);

// ── 8. an NCB outage must not sign anybody out ─────────────────────────────
{
  const real = globalThis.fetch;
  globalThis.fetch = () => Promise.reject(new Error('simulated outage'));
  let cleared = false; let unavailableWith = null;
  const r = await runAppBootstrap({
    fetchSession: async () => ({ status: 'error', data: null, error: 'auth_service_unavailable', httpStatus: 503 }),
    onSessionInvalid: () => { cleared = true; },
    onSessionUnavailable: (info) => { unavailableWith = info; },
    loadCloudSettings: async () => ({}), loadSystemAIConfig: async () => ({})
  });
  globalThis.fetch = real;
  check('8a. a 503 from the session service does NOT clear the stored session', cleared === false && r.sessionUnavailable === true && unavailableWith?.httpStatus === 503, JSON.stringify({ cleared, r: { ...r, background: undefined } }));
  let clearedOn401 = false;
  await runAppBootstrap({
    fetchSession: async () => ({ status: 'error', data: null, error: 'invalid_session', httpStatus: 401 }),
    onSessionInvalid: () => { clearedOn401 = true; },
    loadCloudSettings: async () => ({}), loadSystemAIConfig: async () => ({})
  });
  check('8b. a confirmed 401 DOES clear it — the gate still lets a real sign-out happen', clearedOn401 === true, '');
  let clearedOnNetwork = false;
  await runAppBootstrap({
    fetchSession: async () => ({ status: 'error', data: null, error: 'Request timed out. Please try again.' }),
    onSessionInvalid: () => { clearedOnNetwork = true; },
    loadCloudSettings: async () => ({}), loadSystemAIConfig: async () => ({})
  });
  check('8c. a timeout or network error does not clear it either', clearedOnNetwork === false, '');
}
// …and the relay side of the same promise: with NCB unreachable, /ncb and /ai/* answer 503, not 401.
{
  const deadEnv = { ...process.env, NCB_AUTH_API_URL: 'http://127.0.0.1:1/api/user-auth', NCB_DATA_API_URL: 'http://127.0.0.1:1/api/data' };
  const deadMount = bridge.buildNcbGateway({ env: deadEnv });
  const express = nodeRequire('express');
  const deadApp = express(); deadApp.use(express.json()); deadApp.use(deadMount.router);
  const deadServer = deadApp.listen(0, '127.0.0.1');
  await new Promise((r) => deadServer.once('listening', r));
  const deadBase = `http://127.0.0.1:${deadServer.address().port}`;
  const signInDead = await fetch(`${deadBase}/ncb/auth/sign-in/email`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: PROD_ORIGINS[0] }, body: JSON.stringify({ email: 'player-a@poc.invalid', password: 'pw-a-fixture' }) });
  const readDead = await fetch(`${deadBase}/ncb/data/read/user_settings?limit=1`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } });
  check('8d. with NCB unreachable the gateway answers 503/502 and never 401 on a live handle',
    signInDead.status === 503 && readDead.status === 502, `sign-in=${signInDead.status} read=${readDead.status}`);
  await new Promise((r) => deadServer.close(r));
}

// ── 9. the server-only tables stay server-only, and the browser set stays open ─
localStorage.setItem(api.SESSION_TOKEN_KEY, handleA);
const serverOnly = ['ai_quota_usage', 'ai_quota_config', 'ai_quota_user_override', 'ai_quota_reservation', 'ai_provider_credentials_1770000000',
  // The arbitration table itself. A signed-in account that could INSERT here could hold every record
  // of a code it has no right to spend and starve the whole pool — the exact abuse the reservation
  // exists to prevent, reachable through the route that is deliberately broad.
  'invitation_reservations'];
const authorityTables = ['system_admins', 'clubs', 'club_memberships', 'club_board_collections', 'club_collection_boards'];
// The tournament tables moved here on 2026-11-22. They used to be allow-listed with write policy `full`,
// which is what made "private" and "club" tournaments meaningless: any signed-in session could rewrite
// any row through the generic relay. They are now served only by the authorized /tournaments routes
// (tournaments/ in this repo), on the club service account, and blocked here by name.
const tournamentTables = ['tournaments', 'tournament_boards', 'tournament_attempts'];
const leakedTables = [];
for (const t of [...serverOnly, ...authorityTables, ...tournamentTables]) {
  const r = await (await fetch(`${BASE}/ncb/data/read/${t}?limit=1`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } })).status;
  if (r !== 403) leakedTables.push(`${t}=${r}`);
}
check('9a. quota, credential, reservation, club-authority and tournament tables are all refused through the player gateway',
  leakedTables.length === 0, leakedTables.join(' '));
// Reads AND every write verb, each answered with the NAMED reason rather than the generic
// `table_not_allowed`, so a stale bundle learns where the tables went. This is the arm that would go red
// if the block were loosened to "writes only" — leaving private rows readable by any session.
const tournamentLeaks = [];
for (const table of tournamentTables) {
  const probes = [
    ['GET', `/ncb/data/read/${table}?limit=1`, undefined],
    ['POST', `/ncb/data/create/${table}`, { name: 'forged via relay' }],
    ['PUT', `/ncb/data/update/${table}/1`, { name: 'forged via relay' }],
    ['DELETE', `/ncb/data/delete/${table}/1`, undefined],
    ['GET', `/ncb/public-data/read/${table}?limit=1`, undefined]
  ];
  for (const [method, route, body] of probes) {
    for (const token of [handleA, '']) {
      const res = await fetch(`${BASE}${route}`, {
        method,
        headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) })
      });
      const payload = await res.json().catch(() => ({}));
      if (!(res.status === 403 && payload?.error === 'tournament_via_gateway_only')) {
        tournamentLeaks.push(`${method} ${route} tok=${token ? 'set' : 'none'} = ${res.status}/${payload?.error}`);
      }
    }
  }
}
check('9a3. the three tournament tables are refused on read, create, update, delete and the anonymous public route, each with the named reason',
  tournamentLeaks.length === 0, tournamentLeaks.slice(0, 6).join(' | '));
// Read is only the easiest verb. The reservation table must be unreachable in ALL FOUR, because a
// player-controlled INSERT is a denial of the pool and a player-controlled DELETE is a free re-spend.
const reservationVerbs = [
  ['GET', '/ncb/data/read/invitation_reservations?limit=1'],
  ['POST', '/ncb/data/create/invitation_reservations'],
  ['PUT', '/ncb/data/update/invitation_reservations/1'],
  ['DELETE', '/ncb/data/delete/invitation_reservations/1'],
  ['GET', '/ncb/public-data/read/invitation_reservations?limit=1']
];
const reservationLeaks = [];
for (const [method, route] of reservationVerbs) {
  const res = await fetch(`${BASE}${route}`, {
    method, headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', Authorization: `Bearer ${handleA}` },
    ...(method === 'GET' ? {} : { body: JSON.stringify({ code_row_id: '1', status: 'pending' }) })
  });
  const json = await res.json().catch(() => ({}));
  // Refused at the TABLE (403 table_not_allowed), before the credential is even parsed — and an
  // anonymous caller must not reach it through the public family either.
  if (!(res.status === 403 && ['table_not_allowed', 'write_not_allowed'].includes(json?.error))) reservationLeaks.push(`${method} ${route}=${res.status}/${json?.error}`);
}
check('9a2. invitation_reservations is refused to a signed-in player on read, create, update, delete AND the public route — the arbitration is server-only',
  reservationLeaks.length === 0, reservationLeaks.join(' '));
// Tables a player's own flow reads or writes through THIS path. `system_ai_credentials` is deliberately
// NOT among them: the shipped admin screen reads it, but it holds the system provider key material, and a
// general player CRUD path is not where that belongs. The refusal is asserted below, so the decision is
// recorded in evidence rather than left as a comment.
// The three TOURNAMENT tables are no longer here either — they moved to the blocked set above, because a
// player's tournament flow now runs on the authorized /tournaments routes and a generic read of these
// tables would leak private rows (9a3 measures the refusal, and the tournament gate measures the routes).
const browserTables = ['user_settings', 'llm_preferences', 'recorded_hands', 'community_games', 'ai_providers', 'ai_models',
  'ai_model_parameters', 'ai_decision_traces', 'ai_usage_events', 'app_config', 'coach_feedback_flags',
  'game_analysis_reports', 'replay_attempts', 'system_ai_config'];
const refusedBrowser = [];
for (const t of browserTables) {
  const r = await (await fetch(`${BASE}/ncb/data/read/${t}?limit=1`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } })).status;
  if (r === 403) refusedBrowser.push(t);
}
check('9b. every table a player flow reads is served (measured against the live mount, not a list)',
  refusedBrowser.length === 0, refusedBrowser.join(','));
const credReadRes = await fetch(`${BASE}/ncb/data/read/system_ai_credentials?limit=1`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } });
const credReadBody = await credReadRes.json().catch(() => ({}));
check('9b2. system_ai_credentials is refused outright — provider key material stays off a player CRUD path',
  credReadRes.status === 403 && credReadBody?.error === 'table_not_allowed', `${credReadRes.status} ${JSON.stringify(credReadBody).slice(0, 60)}`);
// The write policy is the other half of the same decision: reads that inform a player are allowed,
// writes that repoint the deployment are not.
const adminWrites = [
  ['PUT', '/ncb/data/update/system_ai_config/1'],
  ['PUT', '/ncb/data/update/app_config/1'],
  ['POST', '/ncb/data/create/ai_models'],
  ['PUT', '/ncb/data/update/user_codes/900'],
  ['PUT', '/ncb/data/update/coach_feedback_flags/5']
];
const wronglyAllowed = [];
for (const [method, route] of adminWrites) {
  const r = await fetch(`${BASE}${route}`, {
    method, headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', Authorization: `Bearer ${handleA}` },
    body: JSON.stringify({ marker: 'should-never-reach-ncb' })
  });
  const json = await r.json().catch(() => ({}));
  if (!(r.status === 403 && json?.error === 'write_not_allowed')) wronglyAllowed.push(`${method} ${route}=${r.status}/${json?.error}`);
}
check('9d. administrative writes are refused at the gateway before the credential is even read — no player repoints the system',
  wronglyAllowed.length === 0, wronglyAllowed.join(' '));
// A write the policy MUST allow, on the row this very run created as player A. Without this arm the
// policy above could be satisfied by refusing every write, which would look secure and break the app.
const ownRowId = rowA?.data?.id ?? rowA?.id ?? null;
const playerWriteOk = ownRowId === null
  ? { status: 0, body: { error: 'no row created earlier in this run' } }
  : await (async () => {
    const r = await fetch(`${BASE}/ncb/data/update/llm_preferences/${ownRowId}`, {
      method: 'PUT', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', Authorization: `Bearer ${handleA}` },
      body: JSON.stringify({ usage: 'gameplay' })
    });
    return { status: r.status, body: await r.json().catch(() => ({})) };
  })();
check('9e. and the player\'s own table still writes — the policy scopes verbs, it does not lock the app down',
  playerWriteOk.status === 200 && playerWriteOk.body?.status === 'success', `${playerWriteOk.status} ${JSON.stringify(playerWriteOk.body).slice(0, 90)}`);
check('9c. the quota ledger the relay itself uses ran natively and never touched the Lambda',
  nativeLog.some((e) => e.path.includes('/api/data/read/ai_quota_config')) && lambdaLog.length === 0,
  JSON.stringify(nativeLog.filter((e) => e.path.includes('ai_quota')).slice(0, 2).map((e) => e.path)));

// ── 10. credentials must not appear anywhere a browser or an operator can read ─
const textOfAll = JSON.stringify([signedIn, list, created, byId, updated, refreshed, quotaBody, myClubBody, codeRow, out, afterOut]);
const leakables = [SEAL_KEY, 'fixture-cookie', SECRET_MARKER, 'vendor-body-token', COOKIE, 'club-fixture-password', 'pw-a-fixture'];
const leakedInBodies = leakables.filter((s) => textOfAll.includes(s));
check('10a. no seal key, upstream cookie, database secret, account password or vendor token in any response body',
  leakedInBodies.length === 0, leakedInBodies.join(','));
const health = await (await fetch(`${BASE}/health`)).json();
const healthText = JSON.stringify(health);
const leakedInHealth = leakables.filter((s) => healthText.includes(s));
check('10b. /health leaks no credential and describes the gateway in booleans and counts only',
  leakedInHealth.length === 0 && health.ncbGateway?.sessionState === 'stateless_sealed_handle' && health.ncbGateway?.upstreamCookieExposedToClient === false,
  leakedInHealth.join(','));
console.log = realLog; console.error = realErr; console.warn = realWarn;
const leakedInLogs = leakables.filter((s) => logs.join('\n').includes(s));
check('10c. nothing secret reached the log, including the error paths exercised above',
  leakedInLogs.length === 0, leakedInLogs.join(','));
check('10d. and no request to NCB ever carried an Authorization header',
  nativeLog.every((e) => !e.hasAuthorization), JSON.stringify(nativeLog.filter((e) => e.hasAuthorization).slice(0, 2).map((e) => e.path)));

// ── 11. CORS, as each real origin will see it ──────────────────────────────
for (const origin of [...PROD_ORIGINS, DEV_ORIGIN]) {
  const pre = await fetch(`${BASE}/ncb/data/read/user_settings`, { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization,content-type' } });
  const act = await fetch(`${BASE}/ncb/data/read/user_settings`, { headers: { Origin: origin } });
  check(`11. ${origin} preflights and reads with an exact-origin echo and credentials`,
    pre.status === 204 && pre.headers.get('access-control-allow-origin') === origin
    && act.headers.get('access-control-allow-origin') === origin && act.headers.get('access-control-allow-credentials') === 'true',
    `pre=${pre.status}/${pre.headers.get('access-control-allow-origin')} act=${act.status}/${act.headers.get('access-control-allow-origin')}`);
}
const stranger = await fetch(`${BASE}/ncb/data/read/user_settings`, { headers: { Origin: 'https://evil.example' } });
const strangerPre = await fetch(`${BASE}/ncb/data/read/user_settings`, { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'GET' } });
check('11z. an unconfigured origin is refused on both the preflight and the read, with no CORS header',
  stranger.status === 403 && strangerPre.status === 403
  && !stranger.headers.get('access-control-allow-origin') && !strangerPre.headers.get('access-control-allow-origin'),
  `${stranger.status}/${strangerPre.status}`);
const otherRoute = await fetch(`${BASE}/ai/quota`, { headers: { Origin: 'https://anything.example' } });
check('11y. existing non-gateway routes keep their pre-existing wildcard CORS and gain no credentials',
  otherRoute.headers.get('access-control-allow-origin') === '*' && !otherRoute.headers.get('access-control-allow-credentials'),
  JSON.stringify(Object.fromEntries(otherRoute.headers)));

// ── 12. restart safety, which is the reason a session map was not used ──────
const rebuilt = bridge.buildNcbGateway({ env: process.env });
const reopened = bridge.ncbSeal({ env: process.env }).open(localStorage.getItem(api.SESSION_TOKEN_KEY));
const wrongKey = bridge.ncbSeal({ env: { ...process.env, NCB_SESSION_SEAL_KEY: 'a-completely-different-fixture-seal-key-32' } }).open(localStorage.getItem(api.SESSION_TOKEN_KEY));
check('12. a rebuilt relay with the same key opens the live handle; a different key cannot',
  rebuilt.configured === true && reopened.ok === true && reopened.session?.userId === 'user-aaaa' && wrongKey.ok === false,
  JSON.stringify({ rebuilt: rebuilt.configured, reopened: reopened.ok, userId: reopened.session?.userId ?? null, wrongKey: wrongKey.reason }));

// ── 13. what an operator can see, without a credential ─────────────────────
{
  const root = await (await fetch(`${BASE}/`)).json();
  const h = await (await fetch(`${BASE}/health`)).json();
  check('13a. / and /health both name the live NCB transport, so a half-migrated deployment is visible',
    h.ncb?.transport === 'native' && root.ncb?.transport === 'native' && h.ncb.sealedSessions === true
    && h.ncb.nativeBasesUsable === true, JSON.stringify(h.ncb));
  check('13b. / advertises the player gateway family that the frontend transport targets',
    typeof root.endpoints?.playerGateway === 'string' && root.endpoints.playerGateway.includes('/ncb/'),
    JSON.stringify(Object.keys(root.endpoints ?? {})).slice(0, 120));
  check('13c. and neither one leaks a URL, an instance, a table name or the seal key',
    !JSON.stringify([root.ncb, h.ncb]).includes(NATIVE) && !JSON.stringify([root.ncb, h.ncb]).includes('55954')
    && !JSON.stringify(h.ncb).includes('user_codes') && !JSON.stringify(h.ncb).includes(SEAL_KEY),
    JSON.stringify([root.ncb, h.ncb]).slice(0, 160));
  // The authority's own answer for a credential it cannot use. Built from the shipped module so this
  // is the behaviour that ships, not a description of it.
  const authority = bridge.ncbSessionAuthority({ env: process.env });
  const legacyAnswer = await authority.resolve('ordinary-ncb-body-token');
  check('13d. the shipped authority answers a non-sealed credential as unusable, never as an outage',
    legacyAnswer.ok === false && legacyAnswer.status === 401 && legacyAnswer.reason === 'not_sealed',
    JSON.stringify(legacyAnswer));
}

// ── 14. REGISTRATION, END TO END, INCLUDING THE PARTS THAT USED TO BE INVISIBLE ──
//
// Section 6 measured the pieces: the lookup, the projection, and the refusal that made the browser's
// own claim impossible. This section measures the flow that replaced it — the gateway requiring an
// invitation server-side, NodeSend writing the claim with the service account, and what happens when
// either half fails. The scenarios are the ones the release decision turns on, not a tour of the code:
// valid, invalid, spent, duplicated, concurrent, vendor refusal, vendor silence, a claim that dies
// AFTER the account exists, and the retry that has to recover it.
{
  const rowOf = async (code) => {
    const r = await (await fetch(`${BASE}/ncb/public-data/read/user_codes?code=${encodeURIComponent(code)}`, { headers: { Origin: PROD_ORIGINS[0] } })).json().catch(() => ({}));
    return (r?.data ?? []).find((x) => String(x.code) === code) ?? null;
  };
  const signUp = async ({ email, code, password = 'pw-flow-fixture', name = 'Flow Player', origin = PROD_ORIGINS[0] }) => {
    const res = await fetch(`${BASE}/ncb/auth/sign-up/email`, {
      method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password, ...(code === undefined ? {} : { invitationCode: code }) })
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };
  const consume = async (handle, code) => {
    const res = await fetch(`${BASE}/auth/consume-invitation`, {
      method: 'POST', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', Authorization: `Bearer ${handle}` },
      body: JSON.stringify({ code })
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };

  const fresh = await signUp({ email: 'flow-valid@poc.invalid', code: 'FLOW-VALID-1' });
  const spentRow = await rowOf('FLOW-VALID-1');
  check('14a. a valid unused invitation registers: account created, handle minted, code spent on THAT account',
    fresh.status === 200 && fresh.body?.status === 'success' && String(fresh.body?.token || '').startsWith('ncbs1')
    && fresh.body?.invitationClaimed === true && Number(spentRow?.used) === 1
    && String(spentRow?.registered_user_id) === String(fresh.body?.data?.user?.id),
    JSON.stringify({ status: fresh.status, claimed: fresh.body?.invitationClaimed, row: spentRow }));
  check('14b. and the response is still the envelope Login.jsx branches on — data.user plus one top-level token',
    Boolean(fresh.body?.data?.user?.id) && typeof fresh.body?.token === 'string' && !('tokens' in fresh.body),
    JSON.stringify(Object.keys(fresh.body ?? {})));

  const rowsFor = async (code) => {
    const r = await (await fetch(`${BASE}/ncb/public-data/read/user_codes?code=${encodeURIComponent(code)}`, { headers: { Origin: PROD_ORIGINS[0] } })).json().catch(() => ({}));
    return (r?.data ?? []).filter((x) => String(x.code) === code);
  };
  // The anonymous public route is throttled per address on purpose (10/window), and by this point in
  // the run that window is spent — a 429 here would look like "the record does not exist", which is
  // precisely the kind of false negative that makes a gate lie. So the later arms read the STORE the
  // write went to. Same rows, no throttle, and strictly stronger evidence: it is the vendor's own
  // state, not a projected copy of it. Projected fields only are ever printed.
  const storeRows = (code) => rows.filter((r) => r.table === 'user_codes' && String(r.code) === code)
    .map(({ id, code: c, used, registered_user_id }) => ({ id, code: c, used, registered_user_id }));
  const dup = await signUp({ email: 'flow-dup@poc.invalid', code: 'FLOW-DUP-1' });
  const dupRows = await rowsFor('FLOW-DUP-1');
  check('14c. two live records for one code are a POOL, not a fault: the lowest id is spent and the next record stays available',
    dup.status === 200 && dup.body?.invitationClaimed === true
    && dupRows.length === 2 && Number(dupRows[0]?.used) === 1 && Number(dupRows[0]?.id) === 934
    && Number(dupRows[1]?.used) === 0 && String(dupRows[1]?.registered_user_id ?? '') === '',
    JSON.stringify({ status: dup.status, claimed: dup.body?.invitationClaimed, rows: dupRows.map((r) => `${r.id}:${r.used}`) }));
  const allocated = await signUp({ email: 'flow-alloc@poc.invalid', code: 'FLOW-ALLOC-1' });
  const afterAlloc = await rowOf('FLOW-ALLOC-1');
  check('14t. a code whose only record is allocated to somebody else is refused as exhausted, and that owner is left standing',
    allocated.status === 409 && allocated.body?.error === 'invitation_exhausted'
    && String(afterAlloc?.registered_user_id) === 'user-previous' && Number(afterAlloc?.used) === 0,
    JSON.stringify({ status: allocated.status, error: allocated.body?.error, row: afterAlloc }));
  const spent = await signUp({ email: 'flow-used@poc.invalid', code: 'FLOW-USED-1' });
  const afterUsed = await rowOf('FLOW-USED-1');
  check('14d. a code already spent on another account is refused and NOTHING is created or overwritten',
    spent.status === 409 && spent.body?.error === 'invitation_exhausted'
    && String(afterUsed?.registered_user_id) === 'user-somebody-else' && Number(afterUsed?.used) === 1,
    JSON.stringify({ status: spent.status, error: spent.body?.error, row: afterUsed }));
  const noShape = await signUp({ email: 'flow-shape@poc.invalid' });
  check('14e. omitting the field entirely is the same refusal — the page is not the authority',
    noShape.status === 403 && noShape.body?.error === 'invitation_required', `${noShape.status}/${noShape.body?.error}`);
  const badShape = await signUp({ email: 'flow-shape2@poc.invalid', code: 'NO-SUCH-CODE-XYZ' });
  check('14f. an unknown code is refused before the vendor is asked to create anything',
    badShape.status === 403 && badShape.body?.error === 'code_not_found', `${badShape.status}/${badShape.body?.error}`);

  const raced = await Promise.all([
    signUp({ email: 'race-a@poc.invalid', code: 'FLOW-RACE-1' }),
    signUp({ email: 'race-b@poc.invalid', code: 'FLOW-RACE-1' })
  ]);
  const raceRow = await rowOf('FLOW-RACE-1');
  const winners = raced.filter((r) => r.status === 200 && r.body?.invitationClaimed === true).length;
  const refused = raced.filter((r) => r.status === 409).length;
  check('14g. two simultaneous registrations on one code: exactly one is granted, the other is refused, and the row names one owner',
    winners === 1 && refused === 1 && Number(raceRow?.used) === 1
    && raced.some((r) => String(r.body?.data?.user?.id) === String(raceRow?.registered_user_id)),
    JSON.stringify({ statuses: raced.map((r) => `${r.status}/${r.body?.invitationClaimed ?? r.body?.error}`), owner: raceRow?.registered_user_id }));

  const writesBeforeOutage = nativeLog.filter((e) => e.method === 'PUT' && String(e.path).includes('/user_codes/')).length;
  signUpFault = { destroy: true };
  const broke = await signUp({ email: 'flow-outage@poc.invalid', code: 'FLOW-OUTAGE-1' });
  signUpFault = null;
  const afterBreak = await rowOf('FLOW-OUTAGE-1');
  const outageWrites = nativeLog.filter((e) => e.method === 'PUT' && String(e.path).includes('/user_codes/')).length - writesBeforeOutage;
  check('14h. a vendor that dies during creation gives 503, spends nothing, issues no handle and attempts no claim',
    broke.status === 503 && broke.body?.error === 'auth_service_unavailable' && !broke.body?.token
    && Number(afterBreak?.used) === 0 && String(afterBreak?.registered_user_id ?? '') === '' && outageWrites === 0,
    JSON.stringify({ status: broke.status, error: broke.body?.error, row: afterBreak, claimWrites: outageWrites }));
  /* THE AMBIGUOUS ANSWER HOLDS THE RECORD. The socket died, so whether NCB created that account is
     unknown, and "unknown" is not a licence to hand the record to somebody else — that is how one
     invitation ends up behind two accounts, which is the single failure this whole design exists to
     make impossible. So the reservation stays, the next registrant is told the pool is spent rather
     than being quietly given the same record, and the response says so the client does not go and try
     a DIFFERENT code (each of those retries would cost another record). */
  const heldAfterAmbiguity = rows.filter((r) => r.table === 'invitation_reservations' && String(r.code_row_id) === '936')
    .map((r) => `${r.id}:${r.status}`);
  const secondOnHeld = await signUp({ email: 'flow-outage2@poc.invalid', code: 'FLOW-OUTAGE-1' });
  const afterSecond = storeRows('FLOW-OUTAGE-1')[0] || null;
  check('14w. and the reservation is HELD, not returned to the pool: a second registrant cannot take the record whose account-creation answer was lost',
    broke.body?.invitationHeldForRecovery === true && heldAfterAmbiguity.length === 1
    && String(heldAfterAmbiguity[0]).endsWith(':pending')
    && secondOnHeld.status === 409 && secondOnHeld.body?.error === 'invitation_exhausted'
    && Number(afterSecond?.used) === 0 && String(afterSecond?.registered_user_id ?? '') === '',
    JSON.stringify({ held: heldAfterAmbiguity, second: `${secondOnHeld.status}/${secondOnHeld.body?.error}`, row: afterSecond, heldFlag: broke.body?.invitationHeldForRecovery }));
  // The opposite half: the vendor DID answer, and answered "that address already has an account". No
  // account was created by this request, so the record belongs back in the pool — otherwise every
  // mistyped email would drain a ten-record pool by one, permanently.
  const dupe = await signUp({ email: 'player-a@poc.invalid', code: 'FLOW-DEMAIL-1' });
  // The release runs in the response's `finish` hook, which is AFTER the client has the answer, so the
  // row is polled rather than assumed absent: a single immediate read would measure the scheduler, not
  // the design. Bounded, and the bound is reported on failure.
  const reservationRowsFor = (recordId) => rows.filter((r) => r.table === 'invitation_reservations' && String(r.code_row_id) === String(recordId));
  const releasedWithin = async (recordId, limitMs = 4000) => {
    const started = Date.now();
    for (;;) {
      if (reservationRowsFor(recordId).length === 0) return Date.now() - started;
      if (Date.now() - started > limitMs) return null;
      await new Promise((r) => setTimeout(r, 25));
    }
  };
  const releaseLatency = await releasedWithin(940);
  const thenFresh = await signUp({ email: 'flow-demail-new@poc.invalid', code: 'FLOW-DEMAIL-1' });
  const dupeRow = storeRows('FLOW-DEMAIL-1')[0] || null;
  check('14x. a DECIDED vendor refusal (duplicate email) gives the record back: the next registrant gets the same record and spends it once',
    dupe.status === 400 && dupe.body?.error === 'request_rejected' && dupe.body?.invitationHeldForRecovery === undefined
    && releaseLatency !== null
    && thenFresh.status === 200 && thenFresh.body?.invitationClaimed === true
    && Number(dupeRow?.used) === 1 && String(dupeRow?.registered_user_id) === String(thenFresh.body?.data?.user?.id),
    JSON.stringify({ dupe: `${dupe.status}/${dupe.body?.error}`, releasedInMs: releaseLatency, fresh: `${thenFresh.status}/${thenFresh.body?.invitationClaimed}`, row: dupeRow }));
  // TEN concurrent registrations against one code value, over HTTP, through the real mount — the size
  // at which a bulk invitation is issued and the count an in-process lock would have passed at while
  // still being wrong across two replicas.
  const ten = await Promise.all(Array.from({ length: 10 }, (_, n) => signUp({ email: `ten-${n}@poc.invalid`, code: 'FLOW-TEN-1' })));
  const tenRows = storeRows('FLOW-TEN-1');
  const tenSpent = tenRows.filter((r) => Number(r.used) === 1);
  const tenOwners = new Set(tenSpent.map((r) => String(r.registered_user_id)));
  check('14y. ten simultaneous registrations on one code value: ten accounts, ten DIFFERENT records, no record spent twice and none left behind',
    ten.every((r) => r.status === 200 && r.body?.invitationClaimed === true)
    && tenSpent.length === 10 && tenOwners.size === 10
    && new Set(tenSpent.map((r) => String(r.id))).size === 10
    && tenRows.find((r) => Number(r.used) === 0) === undefined,
    JSON.stringify({ statuses: ten.map((r) => `${r.status}/${r.body?.invitationClaimed ?? r.body?.error}`), spent: tenSpent.length, owners: tenOwners.size, free: tenRows.filter((r) => Number(r.used) === 0).map((r) => r.id) }));

  claimFault = { status: 500, body: { status: 'error', message: 'write refused' } };
  const partial = await signUp({ email: 'flow-partial@poc.invalid', code: 'FLOW-CLAIMFAIL-1' });
  claimFault = null;
  const partialRow = storeRows('FLOW-CLAIMFAIL-1')[0] || null;
  check('14i. failure AFTER account creation is reported honestly: a session is issued, the claim is said to be unconfirmed, and no success is implied',
    partial.status === 200 && String(partial.body?.token || '').startsWith('ncbs1')
    && partial.body?.invitationClaimed === false && partial.body?.invitationClaim === 'claim_write_failed'
    && Number(partialRow?.used) === 0, JSON.stringify({ status: partial.status, claimed: partial.body?.invitationClaimed, outcome: partial.body?.invitationClaim, row: partialRow }));
  const retry = await consume(partial.body?.token, 'FLOW-CLAIMFAIL-1');
  const retriedRow = storeRows('FLOW-CLAIMFAIL-1')[0] || null;
  check('14j. and the retry through the authorized route recovers it — same account, spent once',
    retry.status === 200 && retry.body?.success === true && Number(retriedRow?.used) === 1
    && String(retriedRow?.registered_user_id) === String(partial.body?.data?.user?.id),
    JSON.stringify({ status: retry.status, body: retry.body, row: retriedRow }));
  const writesBeforeSecondRetry = nativeLog.filter((e) => e.method === 'PUT' && String(e.path).includes('/user_codes/')).length;
  const retryAgain = await consume(partial.body?.token, 'FLOW-CLAIMFAIL-1');
  // The retry after a COMPLETED reservation is a success, not a decline: this account already owns the
  // record, and telling it otherwise would report a finished registration as a failed code. Nothing is
  // written a second time — that is the half that makes the answer safe rather than merely friendly.
  check('14k. a second retry is idempotent and honest: alreadyClaimed, and not one more write attempted',
    retryAgain.status === 200 && retryAgain.body?.success === true && retryAgain.body?.alreadyClaimed === true
    && retryAgain.body?.recovered === true
    && nativeLog.filter((e) => e.method === 'PUT' && String(e.path).includes('/user_codes/')).length === writesBeforeSecondRetry,
    JSON.stringify(retryAgain.body));
  const strangerClaimRes = await fetch(`${BASE}/auth/consume-invitation`, {
    method: 'POST', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', Authorization: `Bearer ${handleA}` },
    body: JSON.stringify({ code: 'FLOW-USED-1', record_id: 933 })
  });
  const strangerClaim = await strangerClaimRes.json().catch(() => ({}));
  const afterStranger = storeRows('FLOW-USED-1')[0] || null;
  check('14l. an existing account cannot seize a code that is already somebody else\'s, and cannot address it by id either',
    strangerClaimRes.status === 200 && strangerClaim.success === false
    && strangerClaim.reason === 'invitation_not_found'
    && String(afterStranger?.registered_user_id) === 'user-somebody-else',
    JSON.stringify({ status: strangerClaimRes.status, body: strangerClaim, row: afterStranger }));
  const anonymousClaim = await fetch(`${BASE}/auth/consume-invitation`, {
    method: 'POST', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json' }, body: JSON.stringify({ code: 'FLOW-VALID-1' })
  });
  check('14m. the claim route needs a session — an anonymous caller cannot spend a code at all',
    anonymousClaim.status === 401, `${anonymousClaim.status}`);

  const claimWrites = nativeLog.filter((e) => e.method === 'PUT' && String(e.path).includes('/user_codes/'));
  const wroteOwnId = claimWrites.every((e) => e.body?.user_id === undefined && String(e.body?.registered_user_id ?? '').length > 0);
  check('14n. every claim write records registered_user_id and NEVER user_id, the vendor\'s ownership column',
    claimWrites.length >= 2 && wroteOwnId,
    JSON.stringify({ count: claimWrites.length, bodies: claimWrites.map((e) => Object.keys(e.body ?? {})) }));
  const crudClaim = await fetch(`${BASE}/ncb/data/update/user_codes/930`, {
    method: 'PUT', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', Authorization: `Bearer ${handleA}` },
    body: JSON.stringify({ used: 1, registered_user_id: 'user-aaaa' })
  });
  check('14o. the player CRUD path is still refused — restoring registration did not reopen the table',
    crudClaim.status === 403, `${crudClaim.status}`);

  // The shipped default, measured on its own mount: the lever on but no atomic store configured.
  const atomicEnv = { ...process.env, NCB_GATEWAY_ALLOW_SIGN_UP: '1' };
  delete atomicEnv.INVITATION_CLAIM_MODE;
  const atomicMount = bridge.buildNcbGateway({ env: atomicEnv });
  const atomicApp = nodeRequire('express')();
  atomicApp.use(nodeRequire('express').json());
  atomicApp.use(atomicMount.router);
  const atomicServer = atomicApp.listen(0, '127.0.0.1');
  await new Promise((r) => atomicServer.once('listening', r));
  const atomicSignUp = await fetch(`http://127.0.0.1:${atomicServer.address().port}/ncb/auth/sign-up/email`, {
    method: 'POST', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'No Store', email: 'no-store@poc.invalid', password: 'pw-flow-fixture', invitationCode: 'FLOW-VALID-1' })
  });
  const atomicBody = await atomicSignUp.json().catch(() => ({}));
  check('14p. in the shipped atomic-only mode a valid code is not enough: registration answers 503 rather than attempt a non-atomic claim',
    atomicSignUp.status === 503 && atomicBody?.error === 'invitation_claim_unavailable', `${atomicSignUp.status}/${atomicBody?.error}`);
  const atomicConsume = await fetch(`${BASE}/auth/consume-invitation`, {
    method: 'POST', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json', Authorization: `Bearer ${handleA}` },
    body: JSON.stringify({ code: 'FLOW-VALID-1' })
  });
  check('14q. and the live mount reports the mode it is honouring, so the choice is visible without reading env',
    (await (await fetch(`${BASE}/health`)).json())?.ncb?.invitationClaim === 'reservation'
    && (await (await fetch(`${BASE}/health`)).json())?.ncb?.reservationStoreWired === true
    && atomicMount.health().invitationClaimWired === false,
    `live=${JSON.stringify((await (await fetch(`${BASE}/health`)).json())?.ncb)} atomic=${atomicMount.health().invitationClaimWired}`);
  // The reservation table itself, read from the fake: this is the durable artefact the design claims
  // to produce, so it is asserted rather than inferred from a 200.
  const reservationRows = rows.filter((r) => r.table === 'invitation_reservations');
  /* APPEND-ONLY, AND PROVED SO. The reservation table has no writable completion flag on this vendor
     (§4.4b: PUT answers 200 and persists nothing), so every row this run created must still say
     `pending` — and that is only honest if the OUTCOME is recorded where it can be, which is
     `user_codes`. So this arm asserts the pair together: a row that is `pending` and a spent record
     naming the account, per successful registration. A future edit that "fixes" the row status would
     fail here, because it would mean writing to an endpoint that does not write.
     What must NEVER appear: a row naming nothing, a row in a state this code cannot write, a row that
     carries a credential, or a spent record with no row holding it. */
  const spentRecords = rows.filter((r) => r.table === 'user_codes' && Number(r.used) === 1
    && String(r.registered_user_id ?? '').length > 0 && String(r.registered_user_id) !== 'user-somebody-else');
  const heldRecordIds = new Set(reservationRows.map((r) => String(r.code_row_id)));
  const orphanSpends = spentRecords.filter((r) => !heldRecordIds.has(String(r.id))).map((r) => r.id);
  check('14u. append-only proven: every reservation row is still pending, every successful registration is proved by a spent record naming its account, and no row carries a credential',
    reservationRows.length >= 15
    && reservationRows.every((r) => String(r.code_row_id ?? '').length > 0)
    && reservationRows.every((r) => String(r.status ?? '') === 'pending')
    && reservationRows.every((r) => String(r.invitee_user_id ?? '') === '')
    && spentRecords.length >= 14 && orphanSpends.length === 0
    && !JSON.stringify(reservationRows).includes('fixture-cookie') && !JSON.stringify(reservationRows).includes(COOKIE)
    && !JSON.stringify(reservationRows).includes(SEAL_KEY) && !JSON.stringify(reservationRows).includes('pw-flow-fixture'),
    JSON.stringify({ rows: reservationRows.length, statuses: [...new Set(reservationRows.map((r) => r.status))], spent: spentRecords.length, orphans: orphanSpends }).slice(0, 320));
  /* THE INVARIANT, END TO END. Not "the completion failed gracefully" — the relay must never ASK.
     Every registration, retry, recovery and release in this run went through the real mount and the
     real claim module, so if any of them issued a PUT at the reservation table, somebody has wired a
     dependency onto the one endpoint this vendor has been measured ignoring. `user_codes` PUTs are
     expected and asserted elsewhere; these must be zero. */
  const reservationPuts = nativeLog.filter((e) => e.method === 'PUT' && /\/api\/data\/update\/invitation_reservations\//.test(String(e.path)));
  check('14x2. the relay never issues an UPDATE against invitation_reservations, at any point in the run — completion is derived, not written',
    reservationPuts.length === 0,
    JSON.stringify(reservationPuts.map((e) => `${e.method} ${e.path} ${JSON.stringify(e.body || '')}`).slice(0, 4)));
  // And the positive half: the writes that DO carry the meaning went to `user_codes`, with the two
  // fields that make a claim real. If those ever stop persisting, arm 14a/14c already reddens — this
  // is here so the pair "no reservation PUT, yes record PUT" is on the record together.
  const claimPuts = nativeLog.filter((e) => e.method === 'PUT' && /\/api\/data\/update\/user_codes\//.test(String(e.path)));
  check('14x3. while the registration outcome is written where it persists: every claim is a user_codes PUT carrying used=1 and registered_user_id, and never user_id',
    claimPuts.length >= 14 && claimPuts.every((e) => Number(e.body?.used) === 1
      && String(e.body?.registered_user_id ?? '').length > 0 && !('user_id' in (e.body || {}))),
    JSON.stringify({ puts: claimPuts.length, sample: claimPuts.slice(0, 2).map((e) => e.body) }).slice(0, 260));
  // Two concurrent registrations against a TWO-record code: the store must let both through, on
  // DIFFERENT records — the property a mutex-in-one-process could never deliver across replicas.
  const race2 = await Promise.all([
    signUp({ email: 'race2-a@poc.invalid', code: 'FLOW-POOL2' }),
    signUp({ email: 'race2-b@poc.invalid', code: 'FLOW-POOL2' })
  ]);
  // Read from the fake's own rows, not the throttled anonymous route: the window is spent by this
  // point in the run, and a 404-shaped null would look like "the record was never spent".
  const pool2Rows = storeRows('FLOW-POOL2');
  check('14v. a two-record code served by two simultaneous registrations spends two DIFFERENT records and both register',
    race2.every((r) => r.status === 200 && r.body?.invitationClaimed === true)
    && pool2Rows.filter((r) => Number(r.used) === 1).length === 2
    && new Set(pool2Rows.map((r) => String(r.registered_user_id))).size === 2,
    JSON.stringify({ statuses: race2.map((r) => r.status), rows: pool2Rows.map((r) => `${r.id}:${r.used}:${r.registered_user_id}`) }));
  void atomicConsume;
  // The other half of the same fail-closed rule, at the unit the mode switch cannot reach inside this
  // process: INVITATION_CLAIM_MODE is read once at module load, so a second relay would need a child
  // process. What can be measured here is that the shipped module refuses when no privileged writer
  // was handed to it — which is precisely what the atomic-only mode relies on.
  const writerless = bridge.createInvitationClaim({ readRows: async () => ({ ok: true, rows: [] }) });
  const refusedWriterless = await writerless.begin({ code: 'FLOW-OUTAGE-1', email: 'nobody@example.test' });
  check('14s. a claim with no reservation store refuses outright instead of half-claiming',
    refusedWriterless.ok === false && refusedWriterless.outcome === 'claim_unavailable',
    JSON.stringify({ claim: refusedWriterless.outcome }));
  await new Promise((r) => atomicServer.close(r));

  const signInStill = await fetch(`${BASE}/ncb/auth/sign-in/email`, {
    method: 'POST', headers: { Origin: PROD_ORIGINS[0], 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'player-a@poc.invalid', password: 'pw-a-fixture' })
  });
  const refreshedStill = await fetch(`${BASE}/ncb/auth/get-session`, { headers: { Origin: PROD_ORIGINS[0], Authorization: `Bearer ${handleA}` } });
  const leakables14 = [COOKIE, 'club-fixture-password', 'pw-flow-fixture', 'pw-a-fixture', SEAL_KEY, SECRET_MARKER];
  const leaked14 = leakables14.filter((s) => JSON.stringify([fresh.body, spent.body, partial.body, retry.body, atomicBody]).includes(s));
  check('14r. existing-account sign-in and session refresh are untouched, and no credential appears in any registration response',
    signInStill.status === 200 && refreshedStill.status === 200 && leaked14.length === 0,
    `sign-in=${signInStill.status} get-session=${refreshedStill.status} leaked=${leaked14.join(',')}`);
}

await new Promise((r) => relay.close(r));
await vite.close();
await new Promise((r) => native.close(r));
await new Promise((r) => lambda.close(r));

if (process.env.NCB_GATE_DEBUG) {
  console.log('\n--- native calls mentioning quota ---');
  console.log(JSON.stringify(nativeLog.filter((e) => /quota/i.test(e.path)), null, 1));
  console.log('--- rows held by the fake ---');
  console.log(JSON.stringify(rows.map((r) => ({ id: r.id, table: r.table, user_id: r.user_id })), null, 1));
}
const failed = results.filter((x) => !x.pass);
console.log('');
for (const x of results) console.log(`${x.pass ? 'PASS' : 'FAIL'}  ${x.name}${x.detail ? `   [${x.detail}]` : ''}`);
console.log(`\nRESULTS: ${results.length - failed.length}/${results.length} passed, ${failed.length} failed`);
if (failed.length) { console.log('NEW FAILURES:'); for (const x of failed) console.log(`  - ${x.name} ${x.detail}`); }
process.exit(failed.length ? 1 : 0);
