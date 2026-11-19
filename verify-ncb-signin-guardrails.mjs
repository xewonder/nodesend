/*
OFFLINE GUARDRAILS for verify-ncb-signin-diagnostic.mjs — the file the owner runs when a live sign-in
must be attempted exactly once.

That diagnostic spends a real authentication attempt, so it has to be right the first time, and it
cannot be rehearsed against production without spending the very thing it protects. This file exercises
it against a loopback fake instead and asserts the four properties that make it safe to hand over:

  1. it refuses to run without a credential, and sends nothing at all;
  2. an upstream 403 is diagnosed as a policy refusal rather than a bad password;
  3. a second invocation inside the cooldown sends NO request (no accidental lockout);
  4. the report shows what the vendor received — Origin present, Authorization absent, only the
     credential fields in the body — and leaks no password and no cookie value.

Run it whenever either file changes:  node verify-ncb-signin-guardrails.mjs
*/
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const STATE = path.join(os.tmpdir(), 'nodesend-ncb-signin-diagnostic.json');
if (fs.existsSync(STATE)) fs.unlinkSync(STATE);

let mode = 'forbidden';
const received = [];
const fake = http.createServer((req, res) => {
  const chunks = []; req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let body = null; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* none */ }
    received.push({ url: req.url, headers: { ...req.headers }, body });
    const send = (s, p, h = {}) => { for (const [k, v] of Object.entries(h)) res.setHeader(k, v); res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(p)); };
    if (req.url.includes('sign-in')) {
      if (mode === 'forbidden') return send(403, { status: 'failed', code: 'EMAIL_NOT_VERIFIED', message: 'Email is not verified. Please verify your email.' });
      return send(200, { user: { id: 'diag-user', email: body?.email, role: 'user' }, token: 'vendor-body-token' },
        { 'Set-Cookie': '__Secure-better-auth.session_token=diag-cookie; Path=/; HttpOnly; Secure; SameSite=Lax' });
    }
    return send(404, { status: 'failed' });
  });
});
await new Promise((r) => fake.listen(0, '127.0.0.1', r));
const FAKE = `http://127.0.0.1:${fake.address().port}`;

const envFor = (extra = {}) => ({
  ...process.env,
  NCB_AUTH_API_URL: `${FAKE}/api/user-auth`, NCB_DATA_API_URL: `${FAKE}/api/data`,
  NCB_ALLOW_INSECURE_UPSTREAM: '1', NCB_INSTANCE: 'diag_instance',
  NCB_SESSION_SEAL_KEY: 'diagnostic-self-test-seal-key-not-a-secret-32',
  NCB_SIGNIN_COOLDOWN_MS: '60000', ...extra
});
// Asynchronous by necessity: the fake lives in THIS process, so a blocking spawn would freeze the
// event loop that has to answer it.
const run = (env) => new Promise((resolve) => {
  const child = spawn(process.execPath, [path.join(ROOT, 'verify-ncb-signin-diagnostic.mjs')], { env, cwd: ROOT });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += String(d); });
  child.stderr.on('data', (d) => { stderr += String(d); });
  child.on('close', (status) => resolve({ status, stdout, stderr }));
});

const results = [];
const check = (n, c, d = '') => results.push({ n, pass: c === true, d: c === true ? '' : String(d).slice(0, 220) });

received.length = 0;
const noCreds = await run(envFor({}));
check('1. refuses to run without a credential and sends nothing',
  noCreds.status === 3 && received.length === 0 && /REFUSING TO RUN/.test(noCreds.stdout),
  `exit ${noCreds.status} received=${received.length}`);

received.length = 0;
const forbidden = await run(envFor({ NCB_TEST_EMAIL_A: 'diag@a.test', NCB_TEST_PASSWORD_A: 'diag-password' }));
const outboundAuth = received[0];
check('2. an upstream 403 is diagnosed as a policy refusal, not a bad password',
  /REPRODUCED/.test(forbidden.stdout) && /policy grounds/.test(forbidden.stdout) && /EMAIL_NOT_VERIFIED/.test(forbidden.stdout),
  forbidden.stdout.split('\n').filter((l) => /gateway HTTP|code=|REPRODUCED|policy/.test(l)).join(' | '));
check('3. the report shows the Origin the vendor received and states no Authorization was sent',
  /Origin=https:\/\/app\.bridgemind\.app/.test(forbidden.stdout) && /secret slot is untouched/.test(forbidden.stdout),
  forbidden.stdout.match(/headers:.*/)?.[0] ?? 'no header line');
check('4. the vendor received exactly the credential fields and the instance by both channels',
  outboundAuth && JSON.stringify(Object.keys(outboundAuth.body).sort()) === '["email","password"]'
  && outboundAuth.headers.origin === 'https://app.bridgemind.app'
  && !('authorization' in outboundAuth.headers) && outboundAuth.headers['x-database-instance'] === 'diag_instance',
  JSON.stringify({ keys: Object.keys(outboundAuth?.body ?? {}), origin: outboundAuth?.headers?.origin }));
check('5. the password appears nowhere in the report',
  !forbidden.stdout.includes('diag-password') && !forbidden.stdout.includes('diag-cookie'), '');

received.length = 0;
const second = await run(envFor({ NCB_TEST_EMAIL_A: 'diag@a.test', NCB_TEST_PASSWORD_A: 'diag-password' }));
check('6. a second invocation inside the cooldown sends no request at all',
  second.status === 4 && received.length === 0 && /NOT SENT/.test(second.stdout),
  `exit ${second.status} received=${received.length}`);

fs.unlinkSync(STATE);
mode = 'ok';
received.length = 0;
const ok = await run(envFor({ NCB_TEST_EMAIL_A: 'diag@a.test', NCB_TEST_PASSWORD_A: 'diag-password' }));
check('7. when sign-in succeeds, a sealed handle is issued and reported',
  /sealed handle issued: YES/.test(ok.stdout) && /SIGN-IN WORKS/.test(ok.stdout),
  ok.stdout.split('\n').filter((l) => /handle|WORKS/.test(l)).join(' | '));
check('8. and no vendor cookie is forwarded to the caller',
  /set-cookie on the gateway answer: none/.test(ok.stdout) && !ok.stdout.includes('diag-cookie'),
  ok.stdout.match(/set-cookie.*/)?.[0] ?? 'no set-cookie line');

await new Promise((r) => fake.close(r));
if (fs.existsSync(STATE)) fs.unlinkSync(STATE);
for (const r of results) console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.n}${r.d ? `   [${r.d}]` : ''}`);
const failed = results.filter((r) => !r.pass).length;
console.log(`\nSIGN-IN DIAGNOSTIC GUARDRAILS: ${results.length - failed}/${results.length} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
