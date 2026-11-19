/*
LIVE PRE-FLIGHT — real NoCodeBackend, zero credentials, nothing written.

Run this before the credentialed smoke test and before any deploy. It answers the questions that do
not need an account, against the production vendor rather than a fake:

  * is the native transport reaching the real host at all, and does the host answer the way the
    integration assumes (an invalid session as 401, not as an outage)?  Both families are exercised:
    the auth family on `get-session`, the data family on a read.
  * is the database SECRET staying in its slot? Every outbound request is audited; a `Bearer` value
    on the vendor is the secret-key channel, so "none carried one" is the claim, measured on the wire.
  * did anything go to AWS? The host list from the same audit says so, or doesn't.
  * do the three failure classes stay distinct — invalid handle, unsealed credential, unreachable
    authority — because collapsing the last two into a 401 is what signed every player out.
  * is CORS what the shipped frontend needs, for the production origin AND a localhost dev origin,
    with no wildcard and no reflection for anything else.
  * does the actual `src/api.js` module, unmodified except for its base, round-trip against the live
    relay and map the vendor's answer into the envelope its 101 call sites branch on.

WHY THERE IS NO SIGN-IN HERE. `sign-in/email` on a better-auth instance can create an account, and
this run must write nothing — not even a row in a user table. A handle minted locally around a cookie
that cannot exist forces the same outbound calls and the same vendor decision path, with zero writes.
If a live step needs an actual session, that is `verify-ncb-live.mjs`, which the owner runs with the
two authorised test accounts.

  node verify-ncb-live-preflight.mjs
  (optional) NCB_GATEWAY_ALLOWED_ORIGINS, NCB_SESSION_SEAL_KEY, NCB_INSTANCE, BRIDGEMIND_REPO
*/
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(HERE, 'noop.cjs'));
const GRETA = process.env.BRIDGEMIND_REPO || 'C:/Users/denis/Github/BridgeMind-Greta';

const AUTH_URL = process.env.NCB_AUTH_API_URL || 'https://app.nocodebackend.com/api/user-auth';
const DATA_URL = process.env.NCB_DATA_API_URL || 'https://app.nocodebackend.com/api/data';
const INSTANCE = process.env.NCB_INSTANCE || '55954_bridgemind';
const LAMBDA = process.env.NCB_PROXY_BASE || 'https://rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url.us-east-2.on.aws';
// Test-only, never a deployment value: a throwaway key is generated when none is supplied, so this
// file cannot be the reason a real seal key ends up in a shell history.
const SEAL_KEY = process.env.NCB_SESSION_SEAL_KEY || `preflight-only-${crypto.randomBytes(24).toString('hex')}`;
const PROD_ORIGINS = (process.env.NCB_GATEWAY_ALLOWED_ORIGINS || 'https://app.bridgemind.app').split(',').map((s) => s.trim()).filter(Boolean);
const DEV_ORIGIN = 'http://localhost:5173';
const ORIGIN = PROD_ORIGINS[0] || DEV_ORIGIN;

const outbound = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (url, init = {}) => {
  let host = '', pathname = '';
  try { const u = new URL(String(url)); host = u.host; pathname = u.pathname; } catch { /* not a url */ }
  const names = Object.keys(init?.headers ?? {}).map((k) => k.toLowerCase());
  outbound.push({ host, pathname, authorization: names.includes('authorization'), cookie: names.includes('cookie') });
  return realFetch(url, init);
};

process.env = {
  ...process.env,
  BRIDGE_API_KEY: process.env.BRIDGE_API_KEY || 'preflight-relay-key',
  NCB_TRANSPORT: 'native',
  NCB_AUTH_API_URL: AUTH_URL,
  NCB_DATA_API_URL: DATA_URL,
  NCB_PROXY_BASE: LAMBDA,
  NCB_INSTANCE: INSTANCE,
  NCB_SESSION_SEAL_KEY: SEAL_KEY,
  NCB_GATEWAY_ALLOWED_ORIGINS: [...PROD_ORIGINS, DEV_ORIGIN].join(','),
  NODESEND_PRIVATE_KEY_B64: ''
};
delete process.env.NODESEND_PRIVATE_KEY_PEM;
delete process.env.NCB_ALLOW_INSECURE_UPSTREAM;   // live NCB is https; the loopback escape stays off

const bridge = require(path.join(HERE, 'bridge.js'));
const relay = bridge.app.listen(0, '127.0.0.1');
await new Promise((r) => relay.once('listening', r));
const BASE = `http://127.0.0.1:${relay.address().port}`;

const results = [];
const check = (name, cond, detail = '') => results.push({ name, pass: cond === true, detail: cond === true ? '' : String(detail ?? '').slice(0, 200) });
// `origin` is a parameter, not a constant: the two CORS arms below must send DIFFERENT origins, and
// a helper that silently always sends the default makes "the dev origin was refused" and "a stranger
// was allowed" unobservable. That is exactly how this file first reported two false failures.
const call = async (method, route, { token = '', body, origin = ORIGIN } = {}) => {
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(origin ? { Origin: origin } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text, headers: Object.fromEntries(res.headers.entries()) };
};

console.log(`relay ${BASE}  ->  ${AUTH_URL}   instance ${INSTANCE}`);
console.log('no credentials are used and nothing is written by this run\n');

// ── live reachability, with a cookie that cannot exist ────────────────────
const fakeCookie = `__Secure-better-auth.session_token=${crypto.randomBytes(16).toString('hex')}-not-a-real-session`;
const probeHandle = bridge.ncbSeal({ env: process.env }).seal({ cookie: fakeCookie, userId: 'preflight-no-user', instance: INSTANCE, email: '' });
const liveSession = await call('GET', '/ncb/auth/get-session', { token: probeHandle });
const liveData = await call('GET', '/ncb/data/read/user_settings?limit=1', { token: probeHandle });
check('P1. real NCB was reached and refused the session as INVALID (401) — not as an outage (503)',
  liveSession.status === 401 && ['upstream_no_session', 'upstream_rejected'].includes(liveSession.json?.reason),
  `${liveSession.status} ${JSON.stringify(liveSession.json)}`);
check('P2. the data family was reached too, and the vendor refused the same way',
  liveData.status === 401 && liveData.json?.reason === 'upstream_rejected', `${liveData.status} ${JSON.stringify(liveData.json)}`);

// ── the credential audit, per leg ─────────────────────────────────────────
const vendorHost = new URL(AUTH_URL).host;
const toVendor = outbound.filter((o) => o.host === vendorHost && o.pathname.startsWith('/api/'));
const toAws = outbound.filter((o) => /lambda-url|on\.aws/i.test(o.host));
check('P3. no relay→NCB request carried an Authorization header (the secret-key slot stayed empty)',
  toVendor.length >= 2 && toVendor.every((o) => !o.authorization),
  JSON.stringify(toVendor.filter((o) => o.authorization).map((o) => o.pathname)));
check('P4. the relay→NCB leg presented only the caller cookie; the browser→relay leg carried the handle',
  toVendor.every((o) => o.cookie) && outbound.filter((o) => o.authorization).every((o) => o.host === `127.0.0.1:${relay.address().port}`),
  JSON.stringify({ vendor: toVendor.length, withCookie: toVendor.filter((o) => o.cookie).length }));
check('P5. nothing was sent to the AWS Lambda host, and the only external host was the vendor',
  toAws.length === 0 && outbound.every((o) => o.host === vendorHost || o.host.startsWith('127.0.0.1')),
  JSON.stringify([...new Set(outbound.map((o) => o.host))]));
check('P6. the instance travelled by header on the auth family and by query on the data family',
  outbound.filter((o) => o.pathname.includes('/api/user-auth/')).every((o) => o.authorization === false && o.cookie)
  && outbound.filter((o) => o.pathname.includes('/api/data/')).length > 0,
  JSON.stringify(outbound.filter((o) => o.host === vendorHost).map((o) => o.pathname)));

// ── the failure classes stay separate ─────────────────────────────────────
const anon = await call('GET', '/ncb/data/read/user_settings?limit=1');
const forged = await call('GET', '/ncb/data/read/user_settings?limit=1', { token: `ncbs1.${'A'.repeat(22)}.x.y.z` });
const stale = await call('GET', '/ncb/data/read/user_settings?limit=1', { token: 'an-old-quest-proxy-body-token' });
check('P7. anonymous is named missing, a forged handle is named invalid, a legacy token is named unsealed — all 401, none an outage',
  anon.status === 401 && anon.json?.reason === 'missing'
  && forged.status === 401 && forged.json?.reason === 'invalid'
  && stale.status === 401 && stale.json?.reason === 'not_sealed',
  JSON.stringify([anon.json?.reason, forged.json?.reason, stale.json?.reason]));
check('P8. no upstream cookie or sealing key appears in any answer an attacker can read',
  ![liveSession, liveData, anon, forged, stale].some((r) => JSON.stringify(r.json).includes('not-a-real-session') || JSON.stringify(r.json).includes(SEAL_KEY)), '');

// ── the invitation route fails CLOSED, not open ───────────────────────────
const invitation = await call('GET', '/ncb/public-data/read/user_codes?code=PROBE-CODE');
const unfiltered = await call('GET', '/ncb/public-data/read/user_codes');
const otherTable = await call('GET', '/ncb/public-data/read/user_settings?code=X');
check('P9. without a service account the anonymous invitation read fails closed with a named reason',
  invitation.status === 503 && invitation.json?.error === 'invitation_service_unavailable', `${invitation.status}`);
check('P10. an unfiltered invitation read is refused, and no other table is served by that route',
  unfiltered.status === 400 && otherTable.status === 403, `${unfiltered.status}/${otherTable.status}`);

// ── operator-visible state ────────────────────────────────────────────────
const health = await (await fetch(`${BASE}/health`)).json();
check('P11. /health reports the native transport, a usable seal and the live gateway surface',
  health.ncb?.transport === 'native' && health.ncb.sealedSessions === true && health.ncb.nativeBasesUsable === true
  && health.ncbGateway?.configured === true && health.ncbGateway?.routes === 14, JSON.stringify({ ncb: health.ncb, gw: health.ncbGateway }));
check('P12. and publishes no base URL, no instance, no table name and no key',
  !JSON.stringify(health.ncb).includes(vendorHost) && !JSON.stringify(health.ncb).includes(INSTANCE)
  && !JSON.stringify(health.ncbGateway).includes('user_codes') && !JSON.stringify(health).includes(SEAL_KEY), '');

// ── CORS, for the origins that matter ─────────────────────────────────────
for (const origin of [ORIGIN, DEV_ORIGIN]) {
  const pre = await fetch(`${BASE}/ncb/auth/get-session`, { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization,content-type' } });
  const act = await call('GET', '/ncb/data/read/user_settings', { origin });
  check(`P13. ${origin} preflights and reads with an exact echo and credentialed CORS`,
    pre.status === 204 && pre.headers.get('access-control-allow-origin') === origin
    && act.headers['access-control-allow-origin'] === origin && act.headers['access-control-allow-credentials'] === 'true',
    `pre=${pre.status} act=${act.status}/${act.headers['access-control-allow-origin']}`);
}
const stranger = await call('GET', '/ncb/data/read/user_settings', { origin: 'https://evil.example' });
check('P14. an unlisted origin gets no CORS header and a refusal — no wildcard, no reflection',
  stranger.status === 403 && !stranger.headers['access-control-allow-origin'], `${stranger.status}`);

// ── the shipped client module, against the live relay ─────────────────────
if (!fs.existsSync(path.join(GRETA, 'src/api.js'))) {
  check('P15. the shipped client module round-trips against the live gateway', false, `frontend repo not found at ${GRETA} (set BRIDGEMIND_REPO)`);
} else {
  const apiSrc = fs.readFileSync(path.join(GRETA, 'src/api.js'), 'utf8').replace(/proxyBase:\s*String\([^)]*\)/, `proxyBase: '${BASE}/ncb'`);
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(String(k), String(v)),
    removeItem: (k) => store.delete(String(k))
  };
  const api = await import(`data:text/javascript,${encodeURIComponent(apiSrc)}`);
  store.set(api.SESSION_TOKEN_KEY, probeHandle);
  const clientSession = await api.authSession();
  const clientData = await api.dataFetch('read/user_settings?limit=1');
  check('P15. the unmodified client reaches live NCB through the gateway and maps the answer into its own envelope',
    clientSession?.status === 'error' && clientSession?.httpStatus === 401
    && clientData?.status === 'error' && clientData?.httpStatus === 401,
    JSON.stringify([clientSession?.httpStatus, clientData?.httpStatus]));
  check('P16. the client holds only the sealed handle — no vendor cookie, no body token, no secret',
    store.get(api.SESSION_TOKEN_KEY) === probeHandle && !JSON.stringify([...store.values()]).includes('not-a-real-session'),
    JSON.stringify([...store.keys()]));
}

// ── the outage rule, against a deliberately unreachable authority ─────────
{
  const deadMount = bridge.buildNcbGateway({ env: { ...process.env, NCB_AUTH_API_URL: 'https://127.0.0.1:1/api/user-auth', NCB_DATA_API_URL: 'https://127.0.0.1:1/api/data' } });
  const express = require('express');
  const app = express(); app.use(express.json()); app.use(deadMount.router);
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const b = `http://127.0.0.1:${srv.address().port}`;
  const r1 = await fetch(`${b}/ncb/auth/sign-in/email`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ORIGIN }, body: JSON.stringify({}) });
  const r2 = await fetch(`${b}/ncb/data/read/user_settings?limit=1`, { headers: { Origin: ORIGIN, Authorization: `Bearer ${probeHandle}` } });
  check('P17. with the authority unreachable the gateway answers 503/502 — never the 401 that discards a session',
    r1.status === 503 && [502, 503].includes(r2.status), `sign-in ${r1.status}, data ${r2.status}`);
  await new Promise((r) => srv.close(r));
}

await new Promise((r) => relay.close(r));
globalThis.fetch = realFetch;

console.log('');
for (const r of results) console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `   [${r.detail}]` : ''}`);
const failed = results.filter((r) => !r.pass).length;
console.log(`\nLIVE PRE-FLIGHT: ${results.length - failed}/${results.length} passed, ${failed} failed`);
console.log(failed === 0
  ? 'VERDICT: the vendor is reachable through the gateway, no secret was sent, no AWS host was touched.'
  : 'VERDICT: pre-flight failed — do not proceed to the credentialed smoke test until this is explained.');
process.exit(failed === 0 ? 0 : 1);
