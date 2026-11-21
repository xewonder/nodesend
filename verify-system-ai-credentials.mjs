/*
 * SYSTEM AI CREDENTIAL AUTHORITY — security and regression gate
 * Offline. No live NCB, no provider inference, no paid call. Every provider and storage interaction
 * is a deterministic in-process fake.
 *
 * EVIDENCE KINDS, labelled per arm because they are not equally strong:
 *   [EXEC]  runs the deliverable: ncb/systemAiCredentials.js against a fake privileged account client
 *           that reproduces the measured NCB semantics (unfiltered list, primary-key read as the only
 *           presence oracle, acknowledged-but-unverifiable writes).
 *   [SRC]   reads the shipped source for a property that cannot be executed without live credentials
 *           (which decryptor is injected, which middleware guards which route). Source-verified is not
 *           the same claim as measured, and is never reported as it.
 */
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
// fileURLToPath, not `.pathname`: on Windows that yields /C:/Users/... and every resolve below misses.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)));
const { createSystemAiCredentials, CATEGORY } = require(path.join(ROOT, 'ncb', 'systemAiCredentials.js'));

const results = [];
const check = (id, pass, detail = '') => {
  results.push({ id, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${id}${detail ? `   [${detail}]` : ''}`);
};

// The relay's real key material is not needed to test the plumbing; what matters is that the injected
// decryptor's CONTRACT is honoured: throws on bad ciphertext, returns ''-safe values, never leaks.
const GOOD = 'good-cipher-A1';
const ROTATED = 'good-cipher-A2';
const decrypt = (blob) => {
  if (blob === GOOD) return 'sk-system-good';
  if (blob === ROTATED) return 'sk-system-rotated';
  if (blob === 'legacy-plaintext-key') return 'sk-system-good';
  throw new Error('Provider API key decryption failed');
};

function makeAccount(seed = {}) {
  const state = {
    config: (seed.config ?? []).map((r) => ({ ...r })),
    creds: (seed.creds ?? []).map((r) => ({ ...r })),
    faults: seed.faults ?? {},
    calls: []
  };
  const ok = (body, httpStatus = 200) => ({ ok: true, body, httpStatus });
  const bad = (reason, httpStatus) => ({ ok: false, reason, httpStatus });
  return {
    configured: true,
    state,
    async request({ group = 'data', path: p, method = 'GET', body }) {
      const [verb, table, id] = p.split('?')[0].split('/');
      state.calls.push({ verb, table, id: id ?? null, method, body });
      if (group !== 'data') return bad('club_account_route_missing', 404);
      if (state.faults.unreachable) return bad('club_account_unreachable', 0);
      if (state.faults.denyAll) return bad('club_account_forbidden', 403);
      if (table === 'system_ai_credentials' && state.faults.denyCredentialRead && method === 'GET') {
        return bad('club_account_forbidden', 403);
      }
      // Denies only the mutating verbs, so a save that reads fine and is then refused on the WRITE is
      // distinguishable from one refused at the read. Those are different operator problems.
      if (state.faults.denyWrites && ['PUT', 'POST', 'DELETE'].includes(method)) {
        return bad('club_account_forbidden', 403);
      }
      if (state.faults.configWriteFails && table === 'system_ai_config' && ['PUT', 'POST'].includes(method)) {
        return bad('club_account_forbidden', 403);
      }
      if (table === 'system_ai_config' && state.faults.denyConfigRead && method === 'GET') {
        return bad('club_account_forbidden', 403);
      }
      if (table === 'system_ai_credentials' && method === 'GET') {
        if (id === undefined) {
          // A list read here is the pattern the module must NOT use for presence; if it ever does,
          // the fault below makes that visible instead of letting it look like an empty table.
          if (state.faults.listHidesRows) return ok({ status: 'success', data: [] });
          return ok({ status: 'success', data: state.creds });
        }
        const row = state.creds.find((r) => String(r.id) === String(decodeURIComponent(id)));
        if (!row) return bad('not_found', 404);
        if (state.faults.pkReturnsWrongRow) return ok({ status: 'success', data: [{ ...row, id: 'other-1' }] });
        if (state.faults.pkReturnsTwoRows) return ok({ status: 'success', data: [row, row] });
        return ok({ status: 'success', data: [row] });
      }
      if (table === 'system_ai_config' && method === 'GET') {
        return ok({ status: 'success', data: state.config });
      }
      if (method === 'PUT' && id !== undefined) {
        const rows = table === 'system_ai_config' ? state.config : state.creds;
        const row = rows.find((r) => String(r.id) === String(decodeURIComponent(id)));
        if (!row) return bad('not_found', 404);
        if (state.faults.writeIgnored) return ok({ status: 'success' });
        Object.assign(row, body);
        return ok({ status: 'success', data: row });
      }
      if (method === 'POST') {
        if (state.faults.writeIgnored) return ok({ status: 'success' });
        const rows = table === 'system_ai_config' ? state.config : state.creds;
        const created = { ...body, id: String(state.faults.nextId ?? 19) };
        const result = state.faults.createWithoutId ? { status: 'success' } : { status: 'success', data: created };
        if (!state.faults.createLost) rows.push(created);
        return ok(result);
      }
      if (method === 'DELETE') {
        const rows = table === 'system_ai_config' ? state.config : state.creds;
        const at = rows.findIndex((r) => String(r.id) === String(decodeURIComponent(id)));
        if (at < 0) return bad('not_found', 404);
        if (state.faults.deleteIgnored) return ok({ status: 'success' });
        rows.splice(at, 1);
        return ok({ status: 'success' });
      }
      return bad('club_account_route_missing', 404);
    }
  };
}

const baseSeed = {
  config: [{ id: '1', usage_scope: 'gameplay', enabled: 1, provider: 'alibaba', model: 'qwen3.8-flash', endpoint: '', credential_id: '19', parameter_overrides: '{"a":1}' }],
  creds: [{ id: '19', provider: 'alibaba', endpoint: '', encrypted_api_key: GOOD, user_id: 'svc' }],
  faults: {}
};
const svcFor = (seed) => createSystemAiCredentials({ account: makeAccount(seed), decrypt, event: () => {} });

// ── resolution and category separation ────────────────────────────────────
{
  const svc = svcFor(baseSeed);
  const got = await svc.resolve('gameplay');
  check('S10 [EXEC] gameplay resolves the configured credential server-side', got.ok === true && got.apiKey === 'sk-system-good' && got.provider === 'alibaba' && got.model === 'qwen3.8-flash', `ok=${got.ok}`);
  check('S11 [EXEC] the resolved key is the stored ciphertext decrypted, not a browser-supplied value', got.apiKey === 'sk-system-good' && got.credentialId === '19');

  const tutor = await svc.resolve('tutor');
  check('S13 [EXEC] a usage with no configuration row is config_absent, never an inherited gameplay config', tutor.ok === false && tutor.category === CATEGORY.CONFIG_ABSENT, `category=${tutor.category}`);
  check('S5 [EXEC] usage is validated server-side; anything else is refused before storage is touched',
    (await svc.resolve('GamePlay ')).usage === 'gameplay' && (await svc.resolve('anything-else')).category === 'bad_usage'
    && (await svc.resolve(null)).category === 'bad_usage' && (await svc.resolve('tutor;drop')).category === 'bad_usage');

  const noRef = svcFor({ config: [{ id: '1', usage_scope: 'gameplay', enabled: 1, provider: 'alibaba', model: 'm', credential_id: null }], creds: [], faults: {} });
  const missingRef = await noRef.resolve('gameplay');
  const denied = svcFor({ ...baseSeed, faults: { denyCredentialRead: true } });
  const deniedRes = await denied.resolve('gameplay');
  check('S5b [EXEC] a missing credential REFERENCE is its own category', missingRef.category === CATEGORY.CREDENTIAL_REFERENCE_MISSING, missingRef.category);
  check('S5c [EXEC] ACCESS DENIED is never reported as a missing credential',
    deniedRes.category === CATEGORY.ACCESS_DENIED && missingRef.category !== deniedRes.category,
    `denied=${deniedRes.category} missing=${missingRef.category}`);
  const absent = svcFor({ config: baseSeed.config, creds: [], faults: {} });
  const absentRes = await absent.resolve('gameplay');
  check('S5d [EXEC] an absent row is proven by the PRIMARY-KEY route, and is distinct from a denial',
    absentRes.category === CATEGORY.CREDENTIAL_ABSENT && absentRes.category !== CATEGORY.ACCESS_DENIED, absentRes.category);

  const emptyVal = svcFor({ config: baseSeed.config, creds: [{ id: '19', provider: 'alibaba', encrypted_api_key: '', user_id: 'svc' }], faults: {} });
  check('S6b [EXEC] an empty key column is credential_value_empty, not a decryption failure',
    (await emptyVal.resolve('gameplay')).category === CATEGORY.CREDENTIAL_VALUE_EMPTY);
  const corrupt = svcFor({ config: baseSeed.config, creds: [{ id: '19', provider: 'alibaba', encrypted_api_key: 'not-this-relays-ciphertext', user_id: 'svc' }], faults: {} });
  const corruptRes = await corrupt.resolve('gameplay');
  check('S6 [EXEC] corrupt ciphertext yields a safe decryption-failure category and no key',
    corruptRes.category === CATEGORY.CREDENTIAL_DECRYPT_FAILED && corruptRes.apiKey === undefined, corruptRes.category);
}

// ── the unfiltered-config + PK discipline (the filter is not an oracle) ────
{
  const account = makeAccount({ ...baseSeed, faults: { listHidesRows: true } });
  const svc = createSystemAiCredentials({ account, decrypt, event: () => {} });
  const got = await svc.resolve('gameplay');
  const credReads = account.state.calls.filter((c) => c.table === 'system_ai_credentials');
  check('S1b [EXEC] credential presence is decided by /read/<table>/<id>, never by an equality filter',
    got.ok === true && credReads.length > 0 && credReads.every((c) => c.id !== null),
    JSON.stringify(credReads.map((c) => `${c.verb}/${c.id}`)));
  const cfgReads = account.state.calls.filter((c) => c.table === 'system_ai_config');
  check('S1c [EXEC] the config set is read unfiltered and matched in code',
    cfgReads.every((c) => c.verb === 'read' && (c.id ?? '') === ''), JSON.stringify(cfgReads));

  const mismatched = svcFor({ ...baseSeed, faults: { pkReturnsWrongRow: true } });
  check('S15 [EXEC] a read that answers a different row than the requested id is refused, not used',
    (await mismatched.resolve('gameplay')).category === CATEGORY.RESPONSE_UNREADABLE);
  const duplicated = svcFor({ ...baseSeed, faults: { pkReturnsTwoRows: true } });
  const dupPk = await duplicated.resolve('gameplay');
  const dupCfgResult = await svcFor({ config: [baseSeed.config[0], { ...baseSeed.config[0], id: '2' }], creds: baseSeed.creds, faults: {} }).resolve('gameplay');
  // Same category by design (both are "the answer to one question is not one row"), different reason:
  // an operator has to be able to tell a duplicated authority row from a duplicated config row.
  check('S15b [EXEC] a PK route returning two rows is refused rather than taking the first',
    dupPk.category === CATEGORY.DUPLICATE_ROWS && dupPk.detail === 'credential_pk_read_returned_many_rows',
    `${dupPk.category}/${dupPk.detail}`);
  check('S13b [EXEC] two config rows for one usage is refused, not a coin flip on which provider bills',
    dupCfgResult.category === CATEGORY.DUPLICATE_ROWS && dupCfgResult.detail === 'config_duplicate_usage_rows',
    `${dupCfgResult.category}/${dupCfgResult.detail}`);
}

// ── SAVE: rotation, blank-key preservation, ambiguity, orphaning ──────────
{
  const account = makeAccount(baseSeed);
  const svc = createSystemAiCredentials({ account, decrypt, event: () => {} });
  const saved = await svc.save({ usage: 'gameplay', enabled: true, provider: 'alibaba', model: 'qwen3.9-max', encryptedApiKey: ROTATED });
  check('S12 [EXEC] rotation is IN PLACE: the referenced row is updated, no second credential row is created',
    saved.ok === true && account.state.creds.length === 1 && account.state.creds[0].id === '19'
    && account.state.creds[0].encrypted_api_key === ROTATED && !account.state.calls.some((c) => c.verb === 'create/system_ai_credentials' || (c.method === 'POST' && c.table === 'system_ai_credentials')),
    `creds=${account.state.creds.length} rotated=${saved.credentialRotated}`);
  check('S12b [EXEC] the configuration write is verified by read-back before success is reported',
    account.state.config[0].model === 'qwen3.9-max' && account.state.config[0].credential_id === '19');

  const blank = makeAccount(baseSeed);
  const svcBlank = createSystemAiCredentials({ account: blank, decrypt, event: () => {} });
  const kept = await svcBlank.save({ usage: 'gameplay', enabled: true, provider: 'alibaba', model: 'qwen3.9-plus' });
  check('S14 [EXEC] a blank replacement field leaves the stored credential untouched',
    kept.ok === true && kept.credentialPreserved === true && blank.state.creds[0].encrypted_api_key === GOOD
    && !blank.state.calls.some((c) => c.table === 'system_ai_credentials' && c.method !== 'GET'),
    `key still stored=${blank.state.creds[0].encrypted_api_key === GOOD}`);
  check('S14b [EXEC] parameter_overrides survives a save that does not carry one', account.state.config[0].parameter_overrides === '{"a":1}');

  const noCred = makeAccount({ config: [{ id: '1', usage_scope: 'gameplay', enabled: 1, provider: 'alibaba', model: 'm', credential_id: null }], creds: [], faults: {} });
  check('S14c [EXEC] a blank key with no existing reference is refused rather than saved as a null pointer',
    (await createSystemAiCredentials({ account: noCred, decrypt, event: () => {} }).save({ usage: 'gameplay', provider: 'alibaba', model: 'm' })).category
    === CATEGORY.CREDENTIAL_REFERENCE_MISSING);

  const plaintext = makeAccount(baseSeed);
  const badKey = await createSystemAiCredentials({ account: plaintext, decrypt, event: () => {} })
    .save({ usage: 'gameplay', provider: 'alibaba', model: 'm', encryptedApiKey: 'not-this-relays-ciphertext' });
  check('S8b [EXEC] a value this relay cannot decrypt is refused BEFORE any write',
    badKey.category === 'bad_ciphertext' && !plaintext.state.calls.some((c) => ['PUT', 'POST', 'DELETE'].includes(c.method)),
    `writes=${plaintext.state.calls.filter((c) => ['PUT', 'POST', 'DELETE'].includes(c.method)).length}`);

  const lostId = makeAccount({ ...baseSeed, config: [{ id: '1', usage_scope: 'gameplay', enabled: 1, provider: 'alibaba', model: 'm', credential_id: null }], creds: [], faults: { createWithoutId: true, nextId: '77' } });
  const lostIdSvc = createSystemAiCredentials({ account: lostId, decrypt, event: () => {} });
  const lost = await lostIdSvc.save({ usage: 'gameplay', provider: 'alibaba', model: 'm', encryptedApiKey: GOOD });
  check('S16 [EXEC] an acknowledged create with no id is write_unconfirmed, is NOT retried, and leaves config untouched',
    lost.category === CATEGORY.WRITE_UNCONFIRMED && lostId.state.calls.filter((c) => c.method === 'POST' && c.table === 'system_ai_credentials').length === 1
    && lostId.state.config[0].credential_id === null && lostId.state.calls.every((c) => c.table !== 'system_ai_config' || c.method === 'GET'),
    `creates=${lostId.state.calls.filter((c) => c.method === 'POST' && c.table === 'system_ai_credentials').length}`);

  // (a) The vendor acknowledges the create, but the row cannot be read back. The save must stop there:
  // writing config that points at an unproven row is how a dangling reference is created on purpose.
  const lostRow = makeAccount({ ...baseSeed, config: [{ id: '1', usage_scope: 'gameplay', enabled: 1, provider: 'alibaba', model: 'm', credential_id: null }], creds: [], faults: { createLost: true, nextId: '77' } });
  const lostRowSave = await createSystemAiCredentials({ account: lostRow, decrypt, event: () => {} })
    .save({ usage: 'gameplay', provider: 'alibaba', model: 'm', encryptedApiKey: GOOD });
  check('S16b [EXEC] a create that cannot be read back stops before the configuration is written',
    lostRowSave.category === CATEGORY.WRITE_UNCONFIRMED
    && lostRow.state.calls.every((c) => c.table !== 'system_ai_config' || c.method === 'GET')
    && lostRow.state.config[0].credential_id === null,
    JSON.stringify({ c: lostRowSave.category }));

  // (b) The credential row DID land and the configuration write then failed. This is the exact shape
  // that used to leave an orphan, so the cleanup is asserted AND read back, not trusted.
  const orphan = makeAccount({ ...baseSeed, config: [{ id: '1', usage_scope: 'gameplay', enabled: 1, provider: 'alibaba', model: 'm', credential_id: null }], creds: [], faults: { nextId: '77', configWriteFails: true } });
  const orphanSave = await createSystemAiCredentials({ account: orphan, decrypt, event: () => {} })
    .save({ usage: 'gameplay', provider: 'alibaba', model: 'm', encryptedApiKey: GOOD });
  check('S16c [EXEC] a landed create whose configuration is refused deletes the new row and confirms it',
    orphanSave.ok === false && orphanSave.orphanCleanup === 'confirmed' && orphan.state.creds.length === 0,
    JSON.stringify({ c: orphanSave.category, cleanup: orphanSave.orphanCleanup, rows: orphan.state.creds.length }));

  const unreachable = await svcFor({ ...baseSeed, faults: { unreachable: true } }).resolve('gameplay');
  const deniedRead = await createSystemAiCredentials({ account: makeAccount({ ...baseSeed, faults: { denyAll: true } }), decrypt, event: () => {} })
    .save({ usage: 'gameplay', provider: 'alibaba', model: 'm', encryptedApiKey: ROTATED });
  const deniedWriteAccount = makeAccount({ ...baseSeed, faults: { denyWrites: true } });
  const deniedWrite = await createSystemAiCredentials({ account: deniedWriteAccount, decrypt, event: () => {} })
    .save({ usage: 'gameplay', provider: 'alibaba', model: 'm', encryptedApiKey: ROTATED });
  check('S7 [EXEC] a refused channel fails closed with its own category and never falls back to anything',
    unreachable.category === CATEGORY.STORAGE_UNREACHABLE
    && deniedRead.category === CATEGORY.ACCESS_DENIED
    && deniedWrite.category === CATEGORY.WRITE_REFUSED
    && !deniedRead.credentialRotated
    // The stored key and the stored configuration must both survive a refused write: a partial
    // failure cannot silently blank a credential or half-apply a model change.
    && deniedWriteAccount.state.creds[0].encrypted_api_key === GOOD
    && deniedWriteAccount.state.config[0].model === 'qwen3.8-flash'
    && !deniedWriteAccount.state.calls.some((c) => c.table === 'system_ai_config' && c.method !== 'GET'),
    `unreachable=${unreachable.category} read=${deniedRead.category} write=${deniedWrite.category}`);
}

// ── describe: metadata only ───────────────────────────────────────────────
{
  const svc = svcFor(baseSeed);
  const d = await svc.describe('gameplay');
  const serialized = JSON.stringify(d);
  check('S8 [EXEC] describe() returns configuration metadata and credential STATE, never key material',
    d.ok === true && d.configured === true && d.credential.state === CATEGORY.OK && d.credential.keyBytes > 0
    && !serialized.includes(GOOD) && !serialized.includes('sk-system-good') && !('encrypted_api_key' in JSON.parse(serialized)),
    `bytes=${d.credential.keyBytes}`);
  const denied = await svcFor({ ...baseSeed, faults: { denyCredentialRead: true } }).describe('gameplay');
  check('S8c [EXEC] a denied credential read is reported as a state, not as an absent or configured credential',
    denied.ok === true && denied.credential.state === CATEGORY.ACCESS_DENIED && denied.configured === true,
    denied.credential.state);
}

// ── source-pinned properties that need no live credential ─────────────────
{
  const bridge = fs.readFileSync(path.join(ROOT, 'bridge.js'), 'utf8');
  const oneScheme = /createSystemAiCredentials\(\{[\s\S]{0,400}?decrypt:\s*decryptProviderApiKey/.test(bridge);
  check('S9 [SRC] the authority is wired to the relay\'s ONE existing decryptor, not a second scheme', oneScheme);
  const routes = ['/ai/system-config", requireBridgeSession, requireBridgeAdmin', '/ai/system-credentials/test", requireBridgeSession, requireBridgeAdmin'];
  check('S1 [SRC] every System AI route is registered behind session AND admin middleware',
    routes.every((needle) => bridge.includes(needle)), routes.filter((r) => !bridge.includes(r)).join(' | '));
  const testTakesUsageOnly = /Object\.keys\(body\)\.filter\(\(key\) => key !== "usage"\)/.test(bridge);
  check('S2 [SRC] the TEST route accepts no credential material from the caller', testTakesUsageOnly);
  check('S3 [SRC] a plaintext key is refused outright on SAVE rather than silently dropped',
    /plaintext_provider_keys_are_not_accepted/.test(bridge));
  const gateway = require(path.join(ROOT, 'ncb', 'gateway.js'));
  check('S17 [SRC] the gateway prohibition on the credential table is unchanged',
    gateway.NEVER_THROUGH_THE_GATEWAY.includes('system_ai_credentials') && gateway.CREDENTIAL_TABLES?.includes?.('system_ai_credentials') !== false);
  const noBrowserCrud = !fs.readFileSync(path.join(ROOT, 'clubs', 'ncbAccountClient.js'), 'utf8').includes('system_ai');
  check('S18 [SRC] no club or player-scoped route was widened to reach the credential table',
    noBrowserCrud && !bridge.includes('/ncb/data/read/system_ai_credentials'));
}

const failed = results.filter((r) => !r.pass);
console.log(`\n===== ${results.length - failed.length}/${results.length} passed =====`);
if (failed.length) { console.log('NEW FAILURES:'); failed.forEach((f) => console.log(`  - ${f.id}  ${f.detail}`)); }
console.log(failed.length ? 'VERDICT: FAIL' : 'VERDICT: PASS');
process.exitCode = failed.length ? 1 : 0;
