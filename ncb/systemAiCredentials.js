'use strict';

/*
 * SYSTEM AI CREDENTIAL AUTHORITY
 *
 * One internal, server-side resolver for the two tables the browser used to touch directly:
 * `system_ai_config` (which provider, model and credential reference a usage scope uses) and
 * `system_ai_credentials` (the RSA-OAEP ciphertext for the System AI provider key).
 *
 * WHY THIS EXISTS. The browser-facing gateway refuses both tables (`ncb/gateway.js`: the credential
 * table is excluded outright, and the write policy grades `system_ai_config` read-only), so every
 * System AI workflow that used to reach for them through `/ncb/data/...` was dead-ended — and the
 * client converted that refusal into a missing credential. Both halves were correct; only the shape
 * was wrong. Reading and writing administrative AI configuration is an authorized ACTION on a route,
 * not a CRUD grant on a table, and this module is the single place that performs it.
 *
 * THE PRIVILEGED IDENTITY. Every call goes through the account client passed in as `account` — the
 * relay's only privileged NCB identity (see bridge.js: "the only privileged NCB identity this relay
 * holds"). A caller's bearer is never used here, so no session can read or repoint the system key.
 *
 * TWO MEASURED BACKEND FACTS SHAPE THE CODE:
 *  1. an equality column filter is NOT a presence oracle on this backend — a filtered read can
 *     answer HTTP 200 with zero rows while the rows exist. So the config set is read UNFILTERED and
 *     matched here in code, and a credential is read by PRIMARY KEY (`/read/<table>/<id>`), which is
 *     the only route allowed to say a record is present or absent;
 *  2. `shared_readwrite` on both tables is an NCB RLS fact, NOT a security property. Any authenticated
 *     NCB session that addresses the vendor directly can read the ciphertext and WRITE both tables.
 *     This module does not make that safe and must never be described as having done so; it removes
 *     the browser from the path, which is a different and smaller claim.
 *
 * NOTHING THAT LEAVES THIS MODULE IS SECRET. Callers get metadata and a status category; the resolved
 * key goes only to the provider call, never into a response body or a log line.
 */

const DEFAULT_TABLES = {
  config: String(process.env.SYSTEM_AI_CONFIG_TABLE || 'system_ai_config').trim(),
  credentials: String(process.env.SYSTEM_AI_CREDENTIALS_TABLE || 'system_ai_credentials').trim()
};

// The column spellings verified against the live schema (Swagger + MCP read, 2026-11-21).
const COLUMNS = Object.freeze({
  config: { id: 'id', usage: 'usage_scope', enabled: 'enabled', provider: 'provider', model: 'model', endpoint: 'endpoint', credentialId: 'credential_id', overrides: 'parameter_overrides' },
  credentials: { id: 'id', provider: 'provider', endpoint: 'endpoint', key: 'encrypted_api_key', owner: 'user_id' }
});

const AI_USAGES = Object.freeze(['gameplay', 'tutor']);
const AI_PROVIDERS = Object.freeze(['alibaba', 'openai']);
const MAX_ROWS = 50;

// Access failures keep their own category, because "no such credential" and "we were not allowed to
// look" are different facts for an operator, and collapsing them is how a policy problem gets
// "fixed" by retyping a key that was never the issue.
const CATEGORY = Object.freeze({
  OK: 'ok',
  CONFIG_ABSENT: 'config_absent',
  CREDENTIAL_REFERENCE_MISSING: 'credential_reference_missing',
  CREDENTIAL_ABSENT: 'credential_absent',
  CREDENTIAL_VALUE_EMPTY: 'credential_value_empty',
  CREDENTIAL_DECRYPT_FAILED: 'credential_decrypt_failed',
  ACCESS_DENIED: 'credential_access_denied',
  STORAGE_UNREACHABLE: 'storage_unreachable',
  RESPONSE_UNREADABLE: 'storage_response_unreadable',
  WRITE_UNCONFIRMED: 'write_unconfirmed',
  WRITE_REFUSED: 'write_refused',
  DUPLICATE_ROWS: 'duplicate_rows'
});

const normalizeUsage = (value) => {
  const usage = String(value ?? '').trim().toLowerCase();
  return AI_USAGES.includes(usage) ? usage : null;
};
const normalizeProvider = (value) => {
  const provider = String(value ?? '').trim().toLowerCase();
  return AI_PROVIDERS.includes(provider) ? provider : null;
};
const eq = (value) => String(value ?? '').trim();
const truthy = (value) => value === true || value === 1 || value === '1';

/* The decision engine, derived server-side with the SAME rule the client already applies: read the
   `decisionEngine` key of the stored overrides document, and fall back to 'ai' for a missing, blank
   or unrecognised value, because that is the engine with no external dependency and an operator typo
   must never route a whole installation onto a third-party service. Restating it here is what lets
   the player endpoint hand back one derived value instead of the administrator's whole tuning
   document — and if the two rules ever diverge, boards would be stamped differently from the settings
   screen, which is the drift this function exists to prevent. */
const DECISION_ENGINE_KEY = 'decisionEngine';
const DECISION_ENGINES = Object.freeze(['ai', 'trickster']);
function decisionEngineFromOverrides(overrides) {
  let doc = overrides;
  if (typeof doc === 'string') {
    try { doc = JSON.parse(doc); } catch { doc = null; }
  }
  const requested = String(doc?.[DECISION_ENGINE_KEY] ?? '').trim().toLowerCase();
  return DECISION_ENGINES.includes(requested) ? requested : 'ai';
}

function rowsOf(body) {
  if (body && typeof body === 'object' && !Array.isArray(body) && 'status' in body && body.status !== 'success') return null;
  if (Array.isArray(body?.data)) return body.data;
  if (Array.isArray(body)) return body;
  // A read addressed to ONE row — `/read/<table>/<id>` — answers with a single OBJECT under `data`,
  // not an array (measured: this is the shape the player gateway passes through, and the shape
  // verify-ncb-gateway pins as "the read-by-id OBJECT shape"). Accepting only arrays here made a
  // successful primary-key read look unreadable and turned a resolvable System AI credential into a
  // 503: the first HTTP-level arm ever run against this path found it, which is exactly why the path
  // needed executing rather than reasoning about.
  if (body?.data && typeof body.data === 'object') return [body.data];
  if (body && typeof body === 'object' && 'id' in body) return [body];
  return null;
}

// The client's own refusal reasons, mapped once: a 403 is a policy answer, an unreachable account or
// a non-JSON route is an infrastructure answer, and only the first may be reported as "denied".
function accessFailure(answer) {
  const reason = eq(answer?.reason);
  if (reason === 'club_account_forbidden') return CATEGORY.ACCESS_DENIED;
  if (reason === 'club_account_rejected') return CATEGORY.ACCESS_DENIED;
  if (reason === 'club_account_unreachable' || reason === 'club_account_cooling_down') return CATEGORY.STORAGE_UNREACHABLE;
  if (reason === 'club_account_route_missing') return CATEGORY.RESPONSE_UNREADABLE;
  return reason || CATEGORY.RESPONSE_UNREADABLE;
}

/**
 * @param {object} options
 * @param {object} options.account       a configured privileged account client (`request(spec)`)
 * @param {Function} options.decrypt     the relay's ONE RSA-OAEP decryptor (never a second scheme)
 * @param {Function} [options.encrypt]   the matching encryptor, used only to validate a value this
 *                                       relay could not have produced
 * @param {Function} [options.event]     sanitized audit sink
 */
function createSystemAiCredentials({ account, decrypt, event = () => {} } = {}) {
  if (typeof account?.request !== 'function') {
    throw new TypeError('createSystemAiCredentials needs the privileged account client');
  }
  if (typeof decrypt !== 'function') {
    throw new TypeError('createSystemAiCredentials needs the relay decryptor');
  }

  const call = async (spec) => {
    const answer = await account.request(spec);
    return answer && answer.ok === true
      ? { ok: true, body: answer.body, httpStatus: answer.httpStatus }
      : { ok: false, category: accessFailure(answer), reason: eq(answer?.reason), httpStatus: answer?.httpStatus ?? 0 };
  };

  // Config is read UNFILTERED and matched in code: `?usage_scope=` is a filter, and a filter is not an
  // oracle on this backend. A refusal is returned as such — never as "no configuration".
  async function readConfigRows() {
    const read = await call({ group: 'data', path: `read/${DEFAULT_TABLES.config}?limit=${MAX_ROWS}`, method: 'GET' });
    if (!read.ok) return { ok: false, category: read.category, reason: read.reason };
    const rows = rowsOf(read.body);
    if (rows === null) return { ok: false, category: CATEGORY.RESPONSE_UNREADABLE, reason: 'config_read_not_a_row_set' };
    return { ok: true, rows };
  }

  async function findConfigRow(usage) {
    const all = await readConfigRows();
    if (!all.ok) return all;
    const matches = all.rows.filter((row) => normalizeUsage(row?.[COLUMNS.config.usage]) === usage);
    if (matches.length > 1) {
      // Two rows for one usage means "the system configuration" has no answer. Choosing the first
      // would let an orphaned row decide which provider the deployment bills.
      return { ok: false, category: CATEGORY.DUPLICATE_ROWS, reason: 'config_duplicate_usage_rows', count: matches.length };
    }
    return { ok: true, row: matches[0] ?? null };
  }

  // The PK route is the only presence oracle, so it is the only thing allowed to report absent.
  async function readCredentialRow(id) {
    const read = await call({ group: 'data', path: `read/${DEFAULT_TABLES.credentials}/${encodeURIComponent(String(id))}`, method: 'GET' });
    if (!read.ok) {
      if (read.httpStatus === 404) return { ok: true, row: null, absent: true };
      return { ok: false, category: read.category, reason: read.reason };
    }
    const rows = rowsOf(read.body);
    if (rows === null) return { ok: false, category: CATEGORY.RESPONSE_UNREADABLE, reason: 'credential_read_not_a_row_set' };
    if (rows.length === 0) return { ok: true, row: null, absent: true };
    const row = rows.length === 1 ? rows[0] : null;
    if (!row) return { ok: false, category: CATEGORY.DUPLICATE_ROWS, reason: 'credential_pk_read_returned_many_rows' };
    // Identity is re-checked even though the id was in the path: a route that answers with a
    // different row than it was asked for must never be trusted with a key.
    if (eq(row[COLUMNS.credentials.id]) !== eq(id)) {
      return { ok: false, category: CATEGORY.RESPONSE_UNREADABLE, reason: 'credential_pk_read_identity_mismatch' };
    }
    return { ok: true, row };
  }

  function classifyCredential(row) {
    const stored = eq(row?.[COLUMNS.credentials.key]);
    if (!stored) return CATEGORY.CREDENTIAL_VALUE_EMPTY;
    try {
      if (!decrypt(stored)) return CATEGORY.CREDENTIAL_VALUE_EMPTY;
      return CATEGORY.OK;
    } catch {
      return CATEGORY.CREDENTIAL_DECRYPT_FAILED;
    }
  }

  /**
   * The full resolution used by USE and TEST: config row -> credential reference -> row -> key.
   * Every failure returns a category and nothing else. `apiKey` is present ONLY on success and is
   * the sole reason this function is not exported to a response.
   */
  async function resolve(usage) {
    const scope = normalizeUsage(usage);
    if (!scope) return { ok: false, category: 'bad_usage', detail: 'usage must be gameplay or tutor' };
    const found = await findConfigRow(scope);
    if (!found.ok) return { ok: false, category: found.category, detail: found.reason };
    const row = found.row;
    if (!row) return { ok: false, category: CATEGORY.CONFIG_ABSENT, detail: `no ${scope} configuration row` };

    const provider = normalizeProvider(row[COLUMNS.config.provider]);
    const model = eq(row[COLUMNS.config.model]);
    if (!provider || !model) return { ok: false, category: 'config_incomplete', detail: 'the configuration row lacks a provider or a model' };
    const credentialId = eq(row[COLUMNS.config.credentialId]);
    if (!credentialId) return { ok: false, category: CATEGORY.CREDENTIAL_REFERENCE_MISSING, detail: 'the configuration references no credential' };

    const cred = await readCredentialRow(credentialId);
    if (!cred.ok) return { ok: false, category: cred.category, detail: cred.reason };
    if (cred.row === null) return { ok: false, category: CATEGORY.CREDENTIAL_ABSENT, detail: 'the referenced credential row is not there' };

    const state = classifyCredential(cred.row);
    if (state !== CATEGORY.OK) return { ok: false, category: state, detail: 'the referenced credential carries no usable key' };

    let apiKey = '';
    try {
      apiKey = decrypt(eq(cred.row[COLUMNS.credentials.key]));
    } catch {
      return { ok: false, category: CATEGORY.CREDENTIAL_DECRYPT_FAILED, detail: 'decryption failed' };
    }
    if (!apiKey) return { ok: false, category: CATEGORY.CREDENTIAL_VALUE_EMPTY, detail: 'decrypted value is empty' };

    return {
      ok: true,
      usage: scope,
      enabled: truthy(row[COLUMNS.config.enabled]),
      provider,
      model,
      endpoint: eq(row[COLUMNS.config.endpoint]) || eq(cred.row[COLUMNS.credentials.endpoint]),
      credentialId,
      apiKey
    };
  }

  /**
   * What an authorized admin screen is allowed to see: configuration metadata, the credential
   * REFERENCE state, and no key material in either direction.
   */
  async function describe(usage) {
    const scope = normalizeUsage(usage);
    if (!scope) return { ok: false, category: 'bad_usage', detail: 'usage must be gameplay or tutor' };
    const found = await findConfigRow(scope);
    if (!found.ok) return { ok: false, category: found.category, detail: found.reason };
    const row = found.row;
    if (!row) {
      return {
        ok: true,
        usage: scope,
        configured: false,
        enabled: false,
        provider: '',
        model: '',
        endpointSet: false,
        credential: { referenced: false, state: CATEGORY.CREDENTIAL_REFERENCE_MISSING, keyBytes: 0, keyShaped: false }
      };
    }
    const credentialId = eq(row[COLUMNS.config.credentialId]);
    let credential = { referenced: credentialId !== '', state: CATEGORY.CREDENTIAL_REFERENCE_MISSING, keyBytes: 0, keyShaped: false, id: credentialId || null };
    if (credentialId) {
      const cred = await readCredentialRow(credentialId);
      if (!cred.ok) credential = { ...credential, state: cred.category };
      else if (cred.row === null) credential = { ...credential, state: CATEGORY.CREDENTIAL_ABSENT };
      else {
        const stored = eq(cred.row[COLUMNS.credentials.key]);
        credential = {
          referenced: true,
          id: credentialId,
          state: classifyCredential(cred.row),
          keyBytes: Buffer.byteLength(stored, 'utf8'),
          keyShaped: /^[A-Za-z0-9+/]{16,}={0,2}$/.test(stored)
        };
      }
    }
    return {
      ok: true,
      usage: scope,
      configured: true,
      configId: eq(row[COLUMNS.config.id]) || null,
      enabled: truthy(row[COLUMNS.config.enabled]),
      provider: normalizeProvider(row[COLUMNS.config.provider]) || eq(row[COLUMNS.config.provider]),
      model: eq(row[COLUMNS.config.model]),
      endpointSet: eq(row[COLUMNS.config.endpoint]) !== '',
      parameterOverrides: row[COLUMNS.config.overrides] ?? null,
      credential
    };
  }

  /*
   * SAVE, with in-place rotation.
   *
   * Three properties carry the requirements:
   *  • a blank key NEVER touches the credential row — "replace the model" must not erase a secret the
   *    administrator cannot see, and the old browser code already refused to null the reference;
   *  • a supplied key UPDATES the referenced row in place. The previous flow INSERTED a new row on
   *    every save and left the old one behind, so key material accumulated with every retype;
   *  • the config row is written only after the credential it references has been read back and
   *    verified, so configuration can never end up pointing at a row that is not there.
   * An acknowledged-but-unverifiable write is reported as `write_unconfirmed` and is NOT retried:
   * retrying a create whose response was lost is exactly how duplicate credential rows are born.
   */
  /* SAVE — partial, explicitly validated, never destructive.
   *
   * A field the caller did not send is PRESERVED, not cleared. The old browser flow wrote the whole
   * row from whatever the form happened to hold, which is how "change the model" could blank an
   * endpoint and how a decision-engine save could drop a credential reference. Blank-but-present
   * provider/model/endpoint are treated as "not sent" rather than as an instruction to erase: no
   * screen has a legitimate way to type an empty provider, so the only thing that arrives is a form
   * that lost a value it never showed the administrator.
   *
   * A credential reference is required only of a row that claims to speak a provider. A
   * decision-engine-only save (Trickster installs, where the AI provider is not configured at all)
   * must be savable on its own, and the USE path already refuses to bill a row with no provider.
   */
  async function save({ usage, enabled, provider, model, endpoint, parameterOverrides, encryptedApiKey } = {}) {
    const scope = normalizeUsage(usage);
    if (!scope) return { ok: false, category: 'bad_usage', detail: 'usage must be gameplay or tutor' };
    const supplied = eq(encryptedApiKey);
    if (supplied) {
      try {
        if (!decrypt(supplied)) return { ok: false, category: 'bad_ciphertext', detail: 'the supplied value is not a usable credential' };
      } catch {
        // Refused rather than stored: a blob this relay cannot decrypt is a broken credential, and
        // discovering that now is the whole point of validating at the boundary.
        return { ok: false, category: 'bad_ciphertext', detail: 'the supplied value could not be decrypted with this relay key' };
      }
    }

    const sendsProvider = eq(provider) !== '';
    const sendsModel = eq(model) !== '';
    const sendsEndpoint = endpoint !== undefined && endpoint !== null;
    const setsEnabled = enabled !== undefined && enabled !== null;
    const sendsOverrides = parameterOverrides !== undefined;
    if (!supplied && !sendsProvider && !sendsModel && !sendsEndpoint && !setsEnabled && !sendsOverrides) {
      // An empty save is refused rather than reported as success: the client would otherwise show a
      // tick for a request that changed nothing at all.
      return { ok: false, category: 'nothing_to_update', detail: 'no field was supplied, so nothing would change' };
    }
    if (sendsProvider && !normalizeProvider(provider)) {
      return { ok: false, category: 'bad_provider', detail: 'provider must be alibaba or openai' };
    }

    const found = await findConfigRow(scope);
    if (!found.ok) return { ok: false, category: found.category, detail: found.reason };
    const configRow = found.row;
    const stored = configRow ?? {};
    const prov = sendsProvider ? normalizeProvider(provider) : normalizeProvider(stored[COLUMNS.config.provider]) || '';
    const modelName = sendsModel ? eq(model).slice(0, 200) : eq(stored[COLUMNS.config.model]).slice(0, 200);
    const endpointName = sendsEndpoint ? eq(endpoint).slice(0, 500) : eq(stored[COLUMNS.config.endpoint]).slice(0, 500);
    const enabledValue = setsEnabled ? truthy(enabled) : truthy(stored[COLUMNS.config.enabled]);
    const existingCredentialId = eq(stored[COLUMNS.config.credentialId]);

    if (!supplied && prov !== '' && modelName !== '' && existingCredentialId === '') {
      return { ok: false, category: CATEGORY.CREDENTIAL_REFERENCE_MISSING, detail: 'a provider configuration needs a credential; a key is required to save' };
    }

    let credentialId = existingCredentialId;
    // Tracked so a configuration write that fails AFTER a successful create cannot leave the new row
    // unreferenced — that is precisely the orphan the old browser flow accumulated on every save.
    let createdRowId = null;
    if (supplied) {
      if (existingCredentialId) {
        // In-place rotation. Confirm the row exists first, so a dangling reference is repaired by the
        // create below rather than updated into nothing.
        const before = await readCredentialRow(existingCredentialId);
        if (!before.ok) return { ok: false, category: before.category, detail: before.reason };
        if (before.row === null) {
          // The reference dangles. Clearing the local id is what routes this save to the create
          // below: leaving it set would write the configuration with a pointer to a row that is not
          // there, which is the state this repair exists to end.
          credentialId = '';
          event('system_ai_credential_reference_dangling', { usage: scope });
        } else {
          const written = await call({
            group: 'data',
            method: 'PUT',
            path: `update/${DEFAULT_TABLES.credentials}/${encodeURIComponent(existingCredentialId)}`,
            body: { [COLUMNS.credentials.provider]: prov, [COLUMNS.credentials.endpoint]: endpointName, [COLUMNS.credentials.key]: supplied }
          });
          if (!written.ok) return { ok: false, category: written.category === CATEGORY.ACCESS_DENIED ? CATEGORY.WRITE_REFUSED : (written.category || CATEGORY.WRITE_UNCONFIRMED), detail: written.reason };
          const after = await readCredentialRow(existingCredentialId);
          if (!after.ok) return { ok: false, category: after.category, detail: after.reason };
          if (after.row === null) return { ok: false, category: CATEGORY.WRITE_UNCONFIRMED, detail: 'the update was acknowledged but the row cannot be read back' };
          if (classifyCredential(after.row) !== CATEGORY.OK) {
            return { ok: false, category: CATEGORY.WRITE_UNCONFIRMED, detail: 'the stored credential did not come back usable' };
          }
          credentialId = existingCredentialId;
        }
      }
      if (!eq(credentialId)) {
        // First-time configuration, or the repair of a dangling reference: exactly one create, never
        // retried from here, because a lost response is how a second row is born.
        const created = await call({
          group: 'data',
          method: 'POST',
          path: `create/${DEFAULT_TABLES.credentials}`,
          // `endpoint` is NOT NULL with a default of '' on the live table; omitting it makes the
          // vendor reject the insert, which the old browser code already knew.
          body: { [COLUMNS.credentials.provider]: prov, [COLUMNS.credentials.endpoint]: endpointName, [COLUMNS.credentials.key]: supplied }
        });
        if (!created.ok) return { ok: false, category: created.category === CATEGORY.ACCESS_DENIED ? CATEGORY.WRITE_REFUSED : (created.category || CATEGORY.WRITE_REFUSED), detail: created.reason };
        const newId = eq(created.body?.data?.id ?? created.body?.id);
        if (!newId) {
          // The write may have landed. Reporting success would risk a retry and a second row, and
          // reporting failure while leaving config untouched is the safe half of the ambiguity.
          event('system_ai_credential_create_unconfirmed', { usage: scope });
          return { ok: false, category: CATEGORY.WRITE_UNCONFIRMED, detail: 'the credential write was acknowledged but returned no id; nothing was retried and the configuration was left unchanged' };
        }
        const confirm = await readCredentialRow(newId);
        if (!confirm.ok) return { ok: false, category: confirm.category, detail: confirm.reason };
        if (confirm.row === null) return { ok: false, category: CATEGORY.WRITE_UNCONFIRMED, detail: 'the new credential row cannot be read back' };
        if (classifyCredential(confirm.row) !== CATEGORY.OK) return { ok: false, category: CATEGORY.WRITE_UNCONFIRMED, detail: 'the new credential did not come back usable' };
        credentialId = newId;
        createdRowId = newId;
      }
    }

    // Every column is written from the MERGED value, so a partial update cannot blank a stored one.
    const configBody = {
      [COLUMNS.config.usage]: scope,
      [COLUMNS.config.enabled]: enabledValue ? 1 : 0,
      [COLUMNS.config.provider]: prov,
      [COLUMNS.config.model]: modelName,
      [COLUMNS.config.endpoint]: endpointName,
      [COLUMNS.config.credentialId]: credentialId,
      // Owned by the model-parameter editor. Absent means "leave the stored document alone"; the
      // old flow sending null here is what erased it.
      [COLUMNS.config.overrides]: sendsOverrides ? parameterOverrides : (stored[COLUMNS.config.overrides] ?? null)
    };

    const configId = eq(configRow?.[COLUMNS.config.id]);
    const write = configId
      ? await call({ group: 'data', method: 'PUT', path: `update/${DEFAULT_TABLES.config}/${encodeURIComponent(configId)}`, body: configBody })
      : await call({ group: 'data', method: 'POST', path: `create/${DEFAULT_TABLES.config}`, body: configBody });
    if (!write.ok) {
      /* A create that succeeded and then lost its configuration write would leave a fresh credential
         row that nothing references — precisely the orphan the old browser flow accumulated. So the
         new row is deleted best-effort, and the ATTEMPT is reported rather than trusted: only a
         read-back that cannot see the row is called confirmed. An in-place rotation has nothing to
         clean up — the configuration still points at the same id, now holding the new key — and that
         half-applied state is surfaced as `credentialRotated: true, configWritten: false` rather than
         hidden behind a generic failure. */
      let orphanCleanup = 'not_applicable';
      if (createdRowId) {
        const removed = await call({ group: 'data', method: 'DELETE', path: `delete/${DEFAULT_TABLES.credentials}/${encodeURIComponent(createdRowId)}` });
        if (!removed.ok) {
          orphanCleanup = 'failed';
          event('system_ai_credential_orphan_cleanup_failed', { usage: scope, reason: removed.reason || 'unknown' });
        } else {
          const gone = await readCredentialRow(createdRowId);
          orphanCleanup = gone.ok && gone.row === null ? 'confirmed' : 'unconfirmed';
          event('system_ai_credential_orphan_cleanup', { usage: scope, result: orphanCleanup });
        }
      }
      return {
        ok: false,
        category: write.category === CATEGORY.ACCESS_DENIED ? CATEGORY.WRITE_REFUSED : (write.category || CATEGORY.WRITE_UNCONFIRMED),
        detail: write.reason,
        credentialRotated: Boolean(supplied),
        configWritten: false,
        orphanCleanup
      };
    }

    const verify = await findConfigRow(scope);
    if (!verify.ok) return { ok: false, category: verify.category, detail: verify.reason, credentialRotated: Boolean(supplied) };
    if (!verify.row) return { ok: false, category: CATEGORY.WRITE_UNCONFIRMED, detail: 'the configuration write was acknowledged but no row can be read back', credentialRotated: Boolean(supplied) };
    const back = verify.row;
    // Normalized on BOTH sides. `normalizeProvider('')` is null, not '', so comparing it against the
    // merged string would report every Trickster-only save (a row with no provider by design) as
    // "did not come back as written" — the first HTTP-level arm run against that path found it.
    const backProvider = normalizeProvider(back[COLUMNS.config.provider]) || '';
    if (eq(back[COLUMNS.config.credentialId]) !== eq(credentialId) || eq(back[COLUMNS.config.model]) !== modelName
      || backProvider !== prov) {
      return { ok: false, category: CATEGORY.WRITE_UNCONFIRMED, detail: 'the stored configuration did not come back as written', credentialRotated: Boolean(supplied) };
    }

    return {
      ok: true,
      usage: scope,
      provider: prov,
      model: modelName,
      enabled: enabledValue ? 1 : 0,
      credentialId,
      credentialRotated: Boolean(supplied),
      credentialPreserved: !supplied,
      // Named so the client can say what it left alone instead of implying it wrote it.
      preserved: [
        !sendsProvider && 'provider', !sendsModel && 'model', !sendsEndpoint && 'endpoint',
        !setsEnabled && 'enabled', !sendsOverrides && 'parameterOverrides', !supplied && 'credential'
      ].filter(Boolean)
    };
  }

  /* THE PLAYER-FACING STATUS — one config read, and NOT one credential-table read.
   *
   * This is the endpoint that lets the browser stop reading `system_ai_config` directly. It answers
   * exactly one question — would a System AI call have something to run — and nothing that would help
   * someone map the instance: no credential id, no reference, no key metadata, no endpoint value, no
   * storage detail. A player does not need to know WHICH credential the deployment uses; the relay is
   * the only thing that ever had to.
   *
   * `configured` is deliberately provider-and-model, so a Trickster-only installation reports
   * configured:false while still handing back the decision-engine document the client reads. That is
   * the honest pair: no provider is configured, and the engine setting is real.
   */
  async function publicStatus(usage) {
    const scope = normalizeUsage(usage);
    if (!scope) return { ok: false, category: 'bad_usage', detail: 'usage must be gameplay or tutor' };
    const found = await findConfigRow(scope);
    if (!found.ok) return { ok: false, category: found.category, detail: found.reason };
    const row = found.row ?? {};
    const provider = normalizeProvider(row[COLUMNS.config.provider]) || '';
    const model = eq(row[COLUMNS.config.model]);
    const enabled = truthy(row[COLUMNS.config.enabled]);
    const credentialReferenced = eq(row[COLUMNS.config.credentialId]) !== '';
    return {
      ok: true,
      usage: scope,
      configured: provider !== '' && model !== '',
      enabled,
      provider,
      model,
      available: enabled && provider !== '' && model !== '' && credentialReferenced,
      decisionEngine: decisionEngineFromOverrides(row[COLUMNS.config.overrides])
    };
  }

  return {
    resolve, describe, save, publicStatus, readCredentialRow, findConfigRow,
    normalizeUsage, normalizeProvider, CATEGORY, COLUMNS, DEFAULT_TABLES
  };
}

module.exports = { createSystemAiCredentials, AI_USAGES, AI_PROVIDERS, COLUMNS, CATEGORY };
