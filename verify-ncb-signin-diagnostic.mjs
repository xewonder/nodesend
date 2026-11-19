/*
ONE SIGN-IN. ONE DIAGNOSIS. NO RETRY.

The live failure is an upstream HTTP 403 whose cause cannot be reached without a real credential:
every request-shape difference between NodeSend and the PoC that authenticated has now been either
eliminated by measurement or removed by code, and four probes against the vendor with a
non-existent address produced 401 INVALID_EMAIL_OR_PASSWORD — that is, they got PAST whatever
rejects the real attempt. So the next answer can only come from one genuine sign-in, and it must
come from ONE: the vendor rate-limits sign-in per address (a probe of mine already drew a 429), and
repeated failures against a real account is how a test account gets locked or banned.

This file is built so that cannot happen by accident:

  * exactly one auth request per invocation, and it exits immediately after the verdict;
  * a cooldown FILE records the timestamp of the last attempt. Re-running within
    NCB_SIGNIN_COOLDOWN_MS (default 120000) refuses to send anything and says when to come back;
  * no retry, no loop, no second account unless the operator names one with --account=B;
  * the credential is read from the environment and is never printed, never logged and never written
    to the state file;
  * what IS printed is what settles the question: the outbound request exactly as the vendor sees it
    (method, URL shape, header NAMES with the Origin value, body key names), the response status, the
    vendor's error CODE, a whitelisted short message, the Set-Cookie names and attributes without
    values, and whether a sealed handle came out of it.

  node verify-ncb-signin-diagnostic.mjs
  set NCB_TEST_EMAIL_A=...&& set NCB_TEST_PASSWORD_A=...&& node verify-ncb-signin-diagnostic.mjs
*/
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(HERE, 'noop.cjs'));

const WHICH = (process.argv.find((a) => a.startsWith('--account=')) || '--account=A').split('=')[1].toUpperCase();
const COOLDOWN_MS = Number(process.env.NCB_SIGNIN_COOLDOWN_MS || 120000);
const STATE_FILE = path.join(os.tmpdir(), 'nodesend-ncb-signin-diagnostic.json');
const EMAIL = String(process.env[`NCB_TEST_EMAIL_${WHICH}`] || '');
const PASSWORD = String(process.env[`NCB_TEST_PASSWORD_${WHICH}`] || '');

if (!EMAIL || !PASSWORD) {
  console.log(`REFUSING TO RUN: NCB_TEST_EMAIL_${WHICH} / NCB_TEST_PASSWORD_${WHICH} are not both present.`);
  console.log('Nothing was sent. This file will not guess a credential, try an empty one, or read one');
  console.log('out of a repository file — a sign-in attempt is the one action this diagnosis cannot afford to waste.');
  process.exit(3);
}

// ── the cooldown gate ───────────────────────────────────────────────────────
const now = Date.now();
let state = null;
try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { /* first run */ }
if (state && typeof state.attemptedAt === 'number' && now - state.attemptedAt < COOLDOWN_MS) {
  const waitSeconds = Math.ceil((COOLDOWN_MS - (now - state.attemptedAt)) / 1000);
  console.log(`NOT SENT: the last attempt was ${Math.round((now - state.attemptedAt) / 1000)}s ago and the cooldown is ${Math.round(COOLDOWN_MS / 1000)}s.`);
  console.log(`Wait ${waitSeconds}s before running again. Repeated sign-ins against a live account is how it gets rate-limited, locked or banned —`);
  console.log('and a throttled answer would tell the next reader nothing about the 403 being diagnosed.');
  process.exit(4);
}
fs.writeFileSync(STATE_FILE, JSON.stringify({ attemptedAt: now, which: WHICH, emailHash: crypto.createHash('sha256').update(EMAIL).digest('hex').slice(0, 8) }));

// ── the vendor, observed rather than assumed ───────────────────────────────
const AUTH = String(process.env.NCB_AUTH_API_URL || 'https://app.nocodebackend.com/api/user-auth').replace(/\/$/, '');
const DATA = String(process.env.NCB_DATA_API_URL || 'https://app.nocodebackend.com/api/data').replace(/\/$/, '');
const INST = process.env.NCB_INSTANCE || '55954_bridgemind';
const SEAL_KEY = process.env.NCB_SESSION_SEAL_KEY || `diagnostic-only-${crypto.randomBytes(24).toString('hex')}`;
const TRUSTED = process.env.NCB_TRUSTED_ORIGIN || 'https://app.bridgemind.app';

const seen = [];
const realFetch = globalThis.fetch;
// The point of wrapping fetch here is not to intercept the result — the gateway handles that — it is to
// report the request the VENDOR actually received. A claim about headers that is read out of the source
// file is a claim about intent; this is a measurement.
globalThis.fetch = (url, init = {}) => {
  const headers = init?.headers ?? {};
  seen.push({
    url: String(url).replace(/[?&](db|Instance)=([^&]*)/, (m) => m),
    method: init?.method ?? 'GET',
    headerNames: Object.keys(headers).sort(),
    origin: headers.Origin ?? headers.origin ?? null,
    instanceHeader: headers['X-Database-Instance'] ?? null,
    hasAuthorization: Object.keys(headers).some((k) => k.toLowerCase() === 'authorization'),
    bodyKeys: (() => { try { return Object.keys(JSON.parse(String(init?.body ?? '{}'))).sort(); } catch { return null; } })()
  });
  return realFetch(url, init);
};

const bridge = require(path.join(HERE, 'bridge.js'));
// The gateway refuses any origin it was not told to trust — correctly, and it would have made this
// diagnostic report `origin_not_allowed` instead of the answer it exists to collect. So the origin this
// file presents is by construction in the list it dials, while whatever the operator configured is
// kept alongside it.
const configuredOrigins = String(process.env.NCB_GATEWAY_ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
const probeOrigins = [...new Set([TRUSTED, ...configuredOrigins])].join(',');
const mount = bridge.buildNcbGateway({
  env: { ...process.env, NCB_SESSION_SEAL_KEY: SEAL_KEY, NCB_GATEWAY_ALLOWED_ORIGINS: probeOrigins },
  log: null
});
const express = require('express');
const app = express();
app.use(express.json({ limit: '256kb' }));
app.use(mount.router);
const server = app.listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${server.address().port}`;

console.log(`ONE sign-in attempt: account ${WHICH} (hash ${crypto.createHash('sha256').update(EMAIL).digest('hex').slice(0, 8)}), instance ${INST}`);
console.log(`cooldown recorded in ${STATE_FILE}\n`);

const started = Date.now();
const res = await fetch(`${BASE}/ncb/auth/sign-in/email`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Origin: TRUSTED },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD })
});
const text = await res.text();
let json = null; try { json = JSON.parse(text); } catch { /* non-json */ }

console.log('--- what the vendor received (measured on the outgoing request) ---');
for (const s of seen) {
  console.log(`  ${s.method} ${s.url}`);
  console.log(`    headers: ${s.headerNames.join(', ')}${s.hasAuthorization ? '   <-- AUTHORIZATION PRESENT, THIS IS THE BUG' : '   (no Authorization: the secret slot is untouched)'}`);
  console.log(`    Origin=${s.origin}  X-Database-Instance=${s.instanceHeader}  body keys=${JSON.stringify(s.bodyKeys)}`);
}

console.log('\n--- what came back ---');
console.log(`  gateway HTTP ${res.status} in ${Date.now() - started}ms`);
console.log(`  body: status=${json?.status ?? '-'} error=${json?.error ?? '-'} code=${json?.code ?? '-'} upstream_status=${json?.upstream_status ?? '-'}`);
if (typeof json?.message === 'string') console.log(`  message: ${json.message.slice(0, 120)}`);
// A vendor session is a cookie; only its NAME and attributes are reportable, never its value.
const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
console.log(`  set-cookie on the gateway answer: ${setCookies.length ? JSON.stringify(setCookies.map((c) => `${c.split('=')[0]}[${c.split(';').slice(1).map((p) => p.trim().split('=')[0]).join(',')}]`)) : 'none (correct: the cookie is never forwarded to a browser)'}`);

const handle = json?.token;
const minted = typeof handle === 'string' && handle.startsWith('ncbs1.');
console.log(`  sealed handle issued: ${minted ? `YES (${handle.slice(0, 10)}…, ${handle.length} chars)` : 'NO'}`);

console.log('\n--- reading the answer ---');
if (res.status === 200 && minted) {
  console.log('  SIGN-IN WORKS from this machine with the current code. The 403 is behind you: re-run');
  console.log('  `node verify-ncb-live.mjs` for the rest of the lifecycle, and note the cooldown.');
} else if (res.status === 502 && json?.error === 'upstream_forbidden') {
  console.log(`  REPRODUCED. The vendor refused a validated credential on policy grounds (code ${json?.code ?? 'not supplied'}).`);
  console.log('  This is NOT the password, NOT the headers this relay can control, and NOT fixable in code:');
  console.log('  it is an NCB-side restriction on that account or that origin. Take the code above to the');
  console.log('  NCB dashboard — email verification, account ban, 2FA requirement, or trusted-origin list.');
} else if (res.status === 403 && json?.error === 'origin_not_allowed') {
  console.log('  REFUSED BY THIS RELAY, not by NCB: the Origin on the request is not in');
  console.log(`  NCB_GATEWAY_ALLOWED_ORIGINS (${process.env.NCB_GATEWAY_ALLOWED_ORIGINS || 'unset'}). Nothing was sent upstream.`);
} else if (res.status === 429) {
  console.log('  THROTTLED by this relay or by the vendor. Wait out the window before the next single attempt.');
} else if (res.status === 401) {
  console.log(`  Credentials refused (code ${json?.code ?? '-'}). If these are the accounts the PoC signed in with, the`);
  console.log('  password rotated or the account changed — nothing about the gateway is implicated.');
} else if (res.status === 503) {
  console.log('  The vendor was unreachable. Nothing was decided about the credential; retry once later.');
} else {
  console.log(`  UNMAPPED ANSWER (${res.status}). Read ` + 'authUpstreamStatus() in ncb/gateway.js before deciding what it means.');
}

await new Promise((r) => server.close(r));
globalThis.fetch = realFetch;
console.log(`\nOne attempt made. Next allowed after ${Math.ceil(COOLDOWN_MS / 1000)}s (NCB_SIGNIN_COOLDOWN_MS to change).`);
process.exit(0);
