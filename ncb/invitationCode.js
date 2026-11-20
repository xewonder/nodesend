'use strict';

/*
ONE INVITATION-CODE RULE, SHARED BY EVERY ROUTE THAT SEES A CODE.

Why a separate module exists: three different validators were measured in one deployment.

  * `bridge.js normalizeInvitationCode`  — 1..128 characters, control words refused
  * `ncb/gateway.js` public read route   — /^[A-Za-z0-9-]{4,64}$/
  * `ncb/invitationClaim.js`             — 1..64 with a wider punctuation class

The consequence was not cosmetic. The owner's reserved test code `777` answered `valid:true` from
POST /auth/validate-invitation and `400 bad_code` from GET /ncb/public-data/read/user_codes?code=777
— the same string was simultaneously a legitimate invitation and a malformed request, and a
three-character code could never complete a registration through the route the browser uses. One
predicate, exported and reused, is the only fix that prevents the next route from inventing a fourth.

THE RULE: the code is the administrator's string, compared EXACTLY.

  * leading/trailing whitespace is trimmed — nothing else is rewritten. Case is significant, because
    production rows are matched case-sensitively today and lower-casing would silently merge codes
    that were issued as distinct.
  * no minimum length. `777`, `7` and a 1-character code are valid forms. The length floor that used
    to exist was an input-hygiene guess, and it broke a real code.
  * maximum 64, which is the ceiling the deployed rows respect. A longer value cannot be a code.
  * control characters and DEL are refused: they are transport noise, and a code that carries them is
    not a code someone typed.
  * nothing else is rejected. `123`, `BRIDGE-2026-KEY`, `a_b.c` and `+44` are all accepted, because
    the store is the authority on what a code looks like and an administrator may change that
    tomorrow without a redeploy.
*/

const INVITATION_CODE_MAX_LENGTH = 64;
const CONTROL_OR_DEL = /[\u0000-\u001f\u007f]/;
// The pre-existing bridge.js guard: a code that spells a placeholder is a misconfiguration, not an
// invitation. Kept here so the behaviour does not silently disappear when the validators merge.
const UNSET_WORDS = /^(?:undefined|null|nan|none|empty|unknown|\?+)$/i;

/** Trimmed, length-bounded, control-free, otherwise byte-for-byte the caller's string. */
function normalizeInvitationCode(value) {
  if (typeof value !== 'string') return '';
  const code = value.trim();
  if (!code || code.length > INVITATION_CODE_MAX_LENGTH) return '';
  if (CONTROL_OR_DEL.test(code)) return '';
  if (UNSET_WORDS.test(code)) return '';
  return code;
}

/** EXACT match, case-sensitive: `Code` and `code` are two different invitations. */
function codeMatches(row, code) {
  return String(row?.code ?? '') === code;
}

/**
 * Record ids are ordered NUMERICALLY, because eligibility is "the first available record" and the
 * vendor's ids in `user_codes` are integers. A non-numeric id is not an error — old or foreign rows
 * may carry one — it sorts last, stably, so numeric rows always win their place in the queue and the
 * ordering never depends on the order the vendor happened to return.
 */
function recordIdOf(row) {
  const raw = row?.id ?? row?.Id ?? null;
  if (raw === null || raw === undefined || raw === '') return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

function compareRecordIds(a, b) {
  const an = recordIdOf(a);
  const bn = recordIdOf(b);
  if (an === null && bn === null) return 0;
  if (an === null) return 1;
  if (bn === null) return -1;
  return an - bn;
}

/** A spent flag is anything that is not zero-or-absent; the vendor stores 0/1, not booleans. */
function isUsed(row) {
  return Number(row?.used ?? 0) !== 0;
}

/** The invitee column. `user_id` is the vendor's ownership column and is deliberately NOT read here. */
function allocatedTo(row) {
  return String(row?.registered_user_id ?? '').trim();
}

module.exports = {
  INVITATION_CODE_MAX_LENGTH,
  normalizeInvitationCode,
  codeMatches,
  compareRecordIds,
  recordIdOf,
  isUsed,
  allocatedTo
};
