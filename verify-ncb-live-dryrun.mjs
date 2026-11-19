/*
OFFLINE DRY RUN of verify-ncb-live.mjs — run this whenever either file changes.

The live smoke script needs credentials only the owner holds, so without this file it can rot
silently: an edit to it is untestable, and a script that throws at arm one produces no verdict at
all. (It has already earned its keep twice — a Set/Array confusion and a `spawnSync` that blocked
the very event loop its own fake needed.) Here it runs against a contract-faithful fake NCB in the
same process, so its plumbing is checked on every change: the env gate that refuses to run without
credentials, the two-leg credential audit, the fresh-child restart test, the NOT TESTED reporting
path, exit codes, and its own guarantee that no secret reaches its report.

It differs from the shipped script in exactly ONE line, asserted below rather than assumed: the
loopback escape stays enabled so a local fake can be dialled. Everything the script decides is the
real thing. This file proves nothing about live NCB — verify-ncb-live.mjs does that, on the
owner's machine, with the owner's credentials.

  node verify-ncb-live-dryrun.mjs
*/

import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const COOKIE = '__Secure-better-auth.session_token';
const USERS = {
  'a@live.test': { password: 'pw-a', id: 'live-user-a' },
  'b@live.test': { password: 'pw-b', id: 'live-user-b' },
  'club@live.test': { password: 'pw-club', id: 'club-svc-live' }
};
const sessions = new Map();
const rows = [
  { id: 11, table: 'user_settings', user_id: 'live-user-a', nickname: 'ada' },
  { id: 12, table: 'user_settings', user_id: 'live-user-b', nickname: 'bo' },
  { id: 13, table: 'llm_preferences', user_id: 'live-user-a' },
  { id: 90, table: 'user_codes', user_id: 'club-svc-live', code: 'DISPOSABLE-1', used: 0, registered_user_id: null, api_key: 'ncb_sec_must_not_leak', note: 'internal' },
  { id: 91, table: 'ai_quota_usage', user_id: 'live-user-a', calls_used: 1 },
  { id: 1, table: 'ai_quota_config', quota_enabled: 1, default_call_limit: 50, period_type: 'monthly', updated_at: '2026-11-19 00:00:00' },
  // The private scratch table, as the earlier native RLS test left it: one row per identity, so the
  // corrected section 5 has something real to assert on. The live run finds this table empty (its row
  // was deleted after that test), and the corrected arms then report NOT PROVEN instead of failing.
  { id: 301, table: 'tmp_rls_isolation_20261119', user_id: 'live-user-a', marker: 'A-PRIVATE' },
  { id: 302, table: 'tmp_rls_isolation_20261119', user_id: 'live-user-b', marker: 'B-PRIVATE' },
  { id: 95, table: 'system_admins', user_id: 'live-user-a' },
  { id: 5, table: 'clubs', user_id: 'club-svc-live', name: 'Smoke Club', active: 1 },
  { id: 6, table: 'club_memberships', user_id: 'live-user-a', club_id: '5', role: 'admin', status: 'approved' }
];
const AUTHORITY = ['system_admins', 'clubs', 'club_memberships', 'club_board_collections', 'club_collection_boards', 'user_codes'];
let nextId = 200;
const seen = [];

const fake = http.createServer((req, res) => {
  const chunks = []; req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const u = new URL(req.url, 'http://127.0.0.1');
    let body = null; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* none */ }
    const pair = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(`${COOKIE}=`)) || '';
    const who = sessions.get(pair.replace(`${COOKIE}=`, '')) || null;
    seen.push({ path: u.pathname, auth: Boolean(req.headers.authorization), cookie: Boolean(pair) });
    const send = (s, p, h = {}) => { for (const [k, v] of Object.entries(h)) res.setHeader(k, v); res.writeHead(s, { 'content-type': 'application/json' }); res.end(p === null ? 'null' : JSON.stringify(p)); };
    if (req.headers.authorization) return send(403, { status: 'error', error: 'Invalid secret_key.', message: 'Invalid secret_key.' });
    const verb = u.pathname.includes('/api/user-auth/') ? u.pathname.slice('/api/user-auth/'.length) : null;
    if (verb === 'sign-in/email') {
      const key = String(body?.email || '').toLowerCase();
      const usr = USERS[key];
      if (!usr || usr.password !== body?.password) return send(401, { status: 'error', message: 'Invalid email or password' });
      const value = `ck-${usr.id}`;
      sessions.set(value, usr.id);
      return send(200, { status: 'success', token: 'body-token-not-a-session', user: { id: usr.id, email: key, name: key, role: 'user' } },
        { 'Set-Cookie': `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax` });
    }
    if (verb === 'get-session') {
      if (!who) return send(200, null);
      const email = Object.keys(USERS).find((k) => USERS[k].id === who);
      return send(200, { status: 'success', data: { user: { id: who, email, role: who === 'club-svc-live' ? 'administrator' : 'user' } } });
    }
    if (verb === 'sign-out') { sessions.delete(pair.replace(`${COOKIE}=`, '')); return send(200, { status: 'success', data: null }); }
    if (u.pathname.startsWith('/api/data/')) {
      if (!who) return send(401, { status: 'error', message: 'Unauthorized. Provide a valid session cookie.' });
      // '/api/data/read/user_settings/11' -> ['', 'api','data','read','user_settings','11']: the verb
      // is the fourth element. Skipping it makes every read look like a read-by-id of a table called
      // "user_settings", which is exactly the false failure this dry run reported first.
      const [, , , verb, table, id] = u.pathname.split('/');
      const q = u.searchParams;
      // The fake mirrors the LIVE vendor's documented policies, not an idealised one: `user_settings`
      // and `llm_preferences` are shared_readwrite (both sessions legitimately see the same rows) and
      // the scratch table is private. That is what lets this dry run exercise BOTH branches of the
      // corrected section 5 — a shared table must not be reported as an isolation failure, and a
      // private one must refuse cross-user reads.
      const SHARED = ['user_settings', 'llm_preferences'];
      const scope = ((who === 'club-svc-live' && AUTHORITY.includes(table)) || table.startsWith('ai_quota') || SHARED.includes(table))
        ? rows.filter((r) => r.table === table) : rows.filter((r) => r.table === table && r.user_id === who);
      if (verb === 'read') {
        if (id) {
          const one = scope.find((r) => String(r.id) === id);
          return one ? send(200, { status: 'success', data: one }) : send(404, { status: 'error', message: 'Record not found or access denied' });
        }
        let list = scope;
        for (const [k, v] of q.entries()) if (!['Instance', 'limit', 'page', 'sort', 'order'].includes(k)) list = list.filter((r) => String(r[k]) === v);
        return send(200, { status: 'success', data: list.slice(0, Number(q.get('limit') || 20)), metadata: { page: 1, limit: 20, hasMore: false, hasPrev: false } });
      }
      return send(404, { status: 'error', message: 'this dry run performs no writes' });
    }
    return send(404, { status: 'error', message: 'nf' });
  });
});
await new Promise((r) => fake.listen(0, '127.0.0.1', r));
const FAKE = `http://127.0.0.1:${fake.address().port}`;

const original = fs.readFileSync(path.join(ROOT, 'verify-ncb-live.mjs'), 'utf8');
const patched = original.replace("delete process.env.NCB_ALLOW_INSECURE_UPSTREAM;", "process.env.NCB_ALLOW_INSECURE_UPSTREAM = '1'; // DRY RUN ONLY");
const differs = patched !== original;
// The copy must live IN the repository: the script resolves `bridge.js` and its child relative to its
// own directory, so a copy in a temp dir would fail for a reason that has nothing to do with it. The
// dry-run file is created, executed and deleted below, and never left behind.
const copy = path.join(ROOT, 'verify-ncb-live.dryrun.mjs');
fs.writeFileSync(copy, patched);

console.log(`dry-run copy differs from the shipped script by the loopback escape only: ${differs}`);
// Asynchronous on purpose. `spawnSync` blocks THIS process, and the fake NCB is a server in this
// process — so every request the child made would time out and the dry run would report a relay that
// cannot reach NCB. That was the first thing this file caught.
const run = await new Promise((resolve) => {
  const child = spawn(process.execPath, [copy], {
    cwd: ROOT,
    env: {
      ...process.env,
      NCB_AUTH_API_URL: `${FAKE}/api/user-auth`,
      NCB_DATA_API_URL: `${FAKE}/api/data`,
      NCB_PROXY_BASE: 'http://127.0.0.1:1/never-dialled',
      NCB_INSTANCE: '55954_bridgemind',
      NCB_SESSION_SEAL_KEY: 'dry-run-seal-key-not-a-real-secret-32chars!',
      // The private scratch table is served only because this dry run has to exercise the PRIVATE
      // branch of section 5 end to end; the shipped allow-list deliberately does not include it.
      NCB_TABLE_ALLOWLIST: 'user_settings,llm_preferences,tmp_rls_isolation_20261119,user_codes,system_admins,clubs,club_memberships,ai_quota_config',
      NCB_TEST_EMAIL_A: 'a@live.test', NCB_TEST_PASSWORD_A: 'pw-a',
      NCB_TEST_EMAIL_B: 'b@live.test', NCB_TEST_PASSWORD_B: 'pw-b',
      CLUB_NCB_EMAIL: 'club@live.test', CLUB_NCB_PASSWORD: 'pw-club',
      CLUB_NCB_SCHEMA_JSON: JSON.stringify({
        tables: { systemAdmins: 'system_admins', clubs: 'clubs', memberships: 'club_memberships', collections: 'club_board_collections', boards: 'club_collection_boards', users: 'user_settings' },
        columns: {
          systemAdmins: { userId: 'user_id' }, clubs: { id: 'id', name: 'name', status: 'active' },
          memberships: { id: 'id', userId: 'user_id', clubId: 'club_id', role: 'role', status: 'status' },
          collections: { id: 'id', clubId: 'club_id', name: 'title', status: 'publication_status', createdBy: 'created_by_user_id' },
          boards: { id: 'id', collectionId: 'collection_id', boardNumber: 'board_number', dealer: 'dealer', vulnerability: 'vulnerability', handsJson: 'hands_json' },
          users: { userId: 'user_id', nickname: 'nickname', displayName: 'display_name', nicknameNormalized: 'nickname_normalized' }
        },
        values: { clubs: { status: { active: 1, inactive: 0 } } }
      }),
      LIVE_TEST_INVITATION_CODE: 'DISPOSABLE-1',
      LIVE_ALLOW_SIGNOUT: '1'
    }
  });
  let out = '';
  child.stdout.on('data', (d) => { out += String(d); process.stdout.write(String(d)); });
  child.stderr.on('data', (d) => { out += String(d); });
  child.on('close', (status) => resolve({ status, out }));
});
console.log(`exit code: ${run.status}`);
console.log(run.out.includes('Error') || run.status !== 0 ? `--- child output tail ---\n${run.out.split('\n').slice(-24).join('\n')}` : '(clean run)');
console.log(`fake saw ${seen.length} request(s); with an Authorization header: ${seen.filter((s) => s.auth).length}`);
console.log(`credential leakage in the report: ${/pw-a|pw-b|pw-club|ck-live-user|body-token-not-a-session|ncb_sec_must_not_leak/.test(run.out)}`);
fs.rmSync(copy, { force: true });
console.log(`dry-run file removed and not left in the repository: ${!fs.existsSync(copy)}`);
await new Promise((r) => fake.close(r));
process.exit(run.status === 0 && differs ? 0 : 1);
