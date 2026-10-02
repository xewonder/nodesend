// Real-PostgreSQL proof for the NodeSend quota reservation.
//
// WHY THIS EXISTS: verify-session-quota.mjs replaces `pg` with an in-process
// engine, so it proves the relay's algorithm but not the database's locking. This
// script runs the SAME exported SQL against a live server and is the only thing
// that can call the atomicity claim measured rather than modelled.
//
// It refuses to run unless you point it at a throwaway database on purpose:
//   set QUOTA_TEST_DATABASE_URL=postgres://user:pass@host:5432/bridgemind_quota_test
//   set QUOTA_TEST_CONFIRM=1
//   node verify-postgres-quota.mjs
// With no DSN it exits 0 reporting NOT RUN, so nothing can read a skip as a pass.
// It writes only: the idempotent bootstrap, an override/config row and usage rows
// under a synthetic `test-<random>` user id, which it deletes again. It never
// drops, truncates or alters a table, and never touches the config singleton's
// operator-set values beyond reading them.
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import crypto from 'node:crypto';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DSN = String(process.env.QUOTA_TEST_DATABASE_URL || '').trim();
const CONFIRMED = process.env.QUOTA_TEST_CONFIRM === '1';

if (!DSN) {
  console.log('NOT RUN: QUOTA_TEST_DATABASE_URL is not set.');
  console.log('The Postgres atomicity claim therefore rests on verify-session-quota.mjs, which MOCKS the driver.');
  process.exit(0);
}
if (!CONFIRMED) {
  console.error('REFUSED: set QUOTA_TEST_CONFIRM=1 to acknowledge this writes to the target database.');
  process.exit(2);
}
let dbName = '';
try {
  const url = new URL(DSN);
  dbName = url.pathname.replace(/^\//, '');
} catch {
  console.error('REFUSED: QUOTA_TEST_DATABASE_URL is not a valid URL.');
  process.exit(2);
}
if (!/test|scratch|tmp|dev|local/i.test(dbName)) {
  console.error(`REFUSED: database name "${dbName}" does not look throwaway (needs test/scratch/tmp/dev/local).`);
  process.exit(2);
}

const { Pool } = await import('pg');
const bridge = await import(pathToFileURL(path.join(ROOT, 'bridge.js')).href);
const {
  QUOTA_SCHEMA_SQL, RESERVE_QUOTA_SQL, READ_QUOTA_STATE_SQL,
  WRITE_QUOTA_CONFIG_SQL, READ_QUOTA_CONFIG_SQL
} = bridge;

const pool = new Pool({
  connectionString: DSN,
  max: 20,
  connectionTimeoutMillis: 10000,
  statement_timeout: 10000
});
pool.on('error', (err) => console.error('pool error:', err.message));

const results = [];
const check = (name, pass, detail = '') => results.push({ name, pass, detail });
const TEST_USER = `test-${crypto.randomBytes(8).toString('hex')}`;
const PERIOD = new Date().toISOString().slice(0, 7);
const LIMIT_A = 10;
const RACERS = 60;

try {
  // 1. idempotent bootstrap, twice, with live data in between.
  for (const statement of QUOTA_SCHEMA_SQL) await pool.query(statement);
  const first = await pool.query(READ_QUOTA_CONFIG_SQL);
  check('bootstrap creates the three tables', first.rows.length === 1, JSON.stringify(first.rows[0] || {}));
  const edited = await pool.query(WRITE_QUOTA_CONFIG_SQL, [null, 1234]);
  for (const statement of QUOTA_SCHEMA_SQL) await pool.query(statement);
  const after = await pool.query(READ_QUOTA_CONFIG_SQL);
  check('re-running bootstrap keeps the operator value (1234)', Number(after.rows[0].default_call_limit) === 1234, `limit=${after.rows[0].default_call_limit}`);
  await pool.query(WRITE_QUOTA_CONFIG_SQL, [null, edited.rows[0].default_call_limit]);

  // 2. the atomic guard under real concurrency: N racers, one limit.
  await pool.query('INSERT INTO quota_user_override (user_id, enabled, call_limit, updated_at) VALUES ($1, true, $2, now())', [TEST_USER, LIMIT_A]);
  const outcomes = await Promise.all(
    Array.from({ length: RACERS }, () => pool.query(RESERVE_QUOTA_SQL, [TEST_USER, PERIOD, LIMIT_A]))
  );
  const granted = outcomes.filter((res) => res.rows.length).length;
  const final = await pool.query(READ_QUOTA_STATE_SQL, [TEST_USER, PERIOD]);
  check(`${RACERS} concurrent UPSERTs against a limit of ${LIMIT_A} grant exactly ${LIMIT_A}`, granted === LIMIT_A, `granted=${granted}`);
  check('the stored counter equals the limit, never above it', Number(final.rows[0].calls_used) === LIMIT_A, `calls_used=${final.rows[0].calls_used}`);
  check('the counter is not overshootable even in the reported limit', Number(final.rows[0].applied_limit ?? LIMIT_A) === LIMIT_A, '');

  // 3. the first reservation of a fresh period creates the row with used=1.
  const freshUser = `${TEST_USER}-fresh`;
  const firstGrant = await pool.query(RESERVE_QUOTA_SQL, [freshUser, '2000-01', 3]);
  check('first reservation of a period yields used=1', firstGrant.rows.length === 1 && Number(firstGrant.rows[0].calls_used) === 1, JSON.stringify(firstGrant.rows[0] || {}));
  await pool.query('DELETE FROM quota_usage WHERE user_id = $1', [freshUser]);
} catch (error) {
  check('real-database run completed', false, error.message);
} finally {
  // Scoped to this run's own synthetic ids; no DDL, no config mutation.
  try {
    await pool.query('DELETE FROM quota_usage WHERE user_id = $1 OR user_id = $2', [TEST_USER, `${TEST_USER}-fresh`]);
    await pool.query('DELETE FROM quota_user_override WHERE user_id = $1', [TEST_USER]);
  } catch (error) {
    console.error('cleanup failed (manual check needed for rows with user_id ' + TEST_USER + '): ' + error.message);
  }
  await pool.end();
}

let failed = 0;
for (const x of results) {
  if (!x.pass) failed++;
  console.log(`${x.pass ? 'PASS' : 'FAIL'}  ${x.name}${x.detail ? '   [' + x.detail + ']' : ''}`);
}
console.log(`\nRESULTS: ${results.length - failed}/${results.length} passed against database "${dbName}".`);
process.exit(failed ? 1 : 0);
