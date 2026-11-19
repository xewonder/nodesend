'use strict';

/*
FROM A BROWSER CREDENTIAL TO A PROVEN NCB IDENTITY — in one place.

`resolveSessionUser` (bridge.js) and every `/ncb` route need the same answer, and the outage proved
what happens when they disagree: the relay told a caller it was signed out because the authority could
not be reached. So the rule lives here once, and both callers read it from here.

The credential is the `ncbs1.…` handle that `sessionSeal.js` mints at sign-in. Opening it yields the
vendor's own session cookie, and the cookie is what proves the identity:

  * the user id and role come from NCB's `get-session` ANSWER, never from the handle's own claim. The
    handle carries a copy of the id so a mismatch can be DETECTED, not so it can be believed — a
    client-supplied identity is the exact thing this relay refuses to read elsewhere (`user_id` in a
    club body, `user_id` in a credential row, and here `user_id` in a credential it was handed).
  * a handle minted for another instance is refused before any upstream call.
  * three answers, not two. `invalid` means the credential is genuinely unusable and the client may
    discard it; `unavailable` means the authority could not be asked, so the client must NOT;
    `unsupported` means the caller presented something that is not a NodeSend session at all — an old
    body token left in localStorage from the AWS proxy — which is an honest 401 and heals itself on
    the next sign-in.

`cookie` is returned to the caller because the caller IS this relay's own NCB transport: the quota
ledger, the AI routes and the club routes must keep acting AS THE PLAYER, which is what preserves
per-user RLS. It is never placed on a response, in a log line, or in anything a browser can read —
enforced by the gates, which grep the captured output for the exact fixture cookie.
*/

const { createSessionSeal, PREFIX } = require('./sessionSeal.js');
const { createNcbNativeClient } = require('./nativeClient.js');

const REASONS = Object.freeze({
  missing: { status: 401, code: 'auth_error' },
  not_sealed: { status: 401, code: 'auth_error' },
  invalid: { status: 401, code: 'auth_error' },
  expired: { status: 401, code: 'auth_error' },
  wrong_instance: { status: 401, code: 'auth_error' },
  identity_mismatch: { status: 401, code: 'auth_error' },
  upstream_rejected: { status: 401, code: 'auth_error' },
  upstream_no_session: { status: 401, code: 'auth_error' },
  misconfigured: { status: 503, code: 'session_service_unavailable' },
  unavailable: { status: 503, code: 'session_service_unavailable' }
});

function looksSealed(value) {
  return String(value || '').startsWith(`${PREFIX}.`);
}

/**
 * @param {object} options
 * @param {object} [options.env]
 * @param {Function} [options.fetchImpl] so a gate can dial a contract-faithful fake
 * @param {Function} [options.log]
 */
function createNcbSessionAuthority({ env = process.env, fetchImpl = null, log = null } = {}) {
  const seal = createSessionSeal({ env });
  const ncb = createNcbNativeClient({
    env, fetchImpl, timeoutMs: Number(env.NODESEND_NCB_TIMEOUT_MS || 8000)
  });
  const event = (name, data) => { if (typeof log === 'function') log(name, data); };

  /**
   * @param {string} handle the bearer value a browser presented
   * @returns {{ok:true, userId, role, cookie, email, via:'sealed_handle'}
   *          | {ok:false, status, code, reason}}
   */
  async function resolve(handle) {
    const value = String(handle || '');
    if (!value) return { ok: false, ...REASONS.missing, reason: 'missing' };
    if (!looksSealed(value)) return { ok: false, ...REASONS.not_sealed, reason: 'not_sealed' };
    if (!seal.configured) {
      // A missing seal key is a deployment fault, never a sign-out: naming it is how an operator
      // finds the missing variable instead of chasing an NCB outage.
      event('ncb_session_seal_unconfigured', {});
      return { ok: false, ...REASONS.misconfigured, reason: 'gateway_unconfigured' };
    }
    const opened = seal.open(value);
    if (!opened.ok) {
      const reason = opened.reason === 'expired' ? 'expired' : 'invalid';
      return { ok: false, ...(REASONS[reason] || REASONS.invalid), reason };
    }
    if (opened.session.instance && opened.session.instance !== ncb.instance) {
      return { ok: false, ...REASONS.wrong_instance, reason: 'wrong_instance' };
    }

    const check = await ncb.auth('get-session', { method: 'GET', cookie: opened.session.cookie });
    if (check.kind === 'unreachable' || check.kind === 'upstream_error') {
      // NOT 401. This is the branch that turned a dead proxy into a mass sign-out.
      event('ncb_session_authority_unavailable', { kind: check.kind, status: check.httpStatus });
      return { ok: false, ...REASONS.unavailable, reason: 'authority_unavailable' };
    }
    if (check.kind === 'secret_key_rejected') {
      // Unreachable by construction (the transport refuses an Authorization header), kept because it
      // is the failure this design exists to prevent and it must be loud if it ever somehow happens.
      event('ncb_session_secret_rejected', {});
      return { ok: false, status: 502, code: 'session_service_unavailable', reason: 'gateway_misconfigured' };
    }
    if (check.kind !== 'ok') {
      return { ok: false, ...REASONS.upstream_rejected, reason: 'upstream_rejected' };
    }
    const body = check.json ?? {};
    const user = body?.data?.user ?? body?.user ?? null;
    if (!user?.id) {
      // The authority answered and named nobody: the vendor session behind this handle has ended.
      return { ok: false, ...REASONS.upstream_no_session, reason: 'upstream_no_session' };
    }
    const userId = String(user.id);
    if (opened.session.userId && opened.session.userId !== userId) {
      // The handle claims one account and the session answers another. Either the handle was edited
      // while still authenticating, or the vendor's cookie was swapped under it. Neither is a
      // session this relay should act on as either identity.
      event('ncb_session_identity_mismatch', {});
      return { ok: false, ...REASONS.identity_mismatch, reason: 'identity_mismatch' };
    }
    return {
      ok: true, userId, role: String(user.role || ''), email: String(user.email || ''),
      cookie: opened.session.cookie, via: 'sealed_handle'
    };
  }

  return {
    resolve,
    looksSealed,
    configured: seal.configured && ncb.configured,
    reason: !seal.configured ? seal.reason : (!ncb.configured ? 'ncb_api_urls_unconfigured' : null),
    health() {
      return {
        sealConfigured: seal.configured,
        transportConfigured: ncb.configured,
        sessionState: 'stateless_sealed_handle',
        restartSafe: true,
        identitySource: 'ncb_get_session'
      };
    }
  };
}

module.exports = { createNcbSessionAuthority, looksSealed, REASONS };
