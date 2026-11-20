/*
CROSS-IMPLEMENTATION AGREEMENT — the same input table put through the BACKEND rule and the FRONTEND
rule, case by case.

One rule was the owner's decision, but a rule that lives twice drifts silently, and the failure mode
is not a red test: it is the browser accepting a string the relay then refuses (or the reverse). That
is exactly how production came to answer `777` as `valid:true` on one route and `400 bad_code` on
another. So both implementations are EXECUTED here and compared, not described.

If the sibling repository is not present (a NodeSend-only checkout), this reports NOT-MEASURED and
exits non-zero rather than passing vacuously — a skipped comparison is the one result that must never
look like a pass.
*/
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const NS = path.resolve(process.cwd());
const backend = require(path.join(NS, 'ncb/invitationCode.js'));
const GRETA_FILE = path.resolve(NS, '..', 'BridgeMind-Greta', 'src/services/invitationCode.js');

const CASES = [
  ['777', '777'], ['7', '7'], ['123', '123'], ['  12  ', '12'], ['\t99\n', '99'],
  ['BRIDGE-2026-KEY', 'BRIDGE-2026-KEY'], ['aB_3-x', 'aB_3-x'], ['AB_3-X', 'AB_3-X'],
  ['x?y', 'x?y'], ['-lead', '-lead'], ['trail-', 'trail-'], ['1.2.3', '1.2.3'],
  ['q'.repeat(64), 'q'.repeat(64)], ['q'.repeat(65), ''], ['q'.repeat(128), ''],
  ['', ''], ['   ', ''], ['null', ''], ['NULL', ''], ['undefined', ''], ['NaN', ''],
  ['none', ''], ['empty', ''], ['unknown', ''], ['???', ''], ['abc\u0000def', ''],
  ['a\u001fb', ''], ['\u007f', '']
];

const mismatches = [];
for (const [input, expect] of CASES) {
  const got = backend.normalizeInvitationCode(input);
  if (got !== expect) mismatches.push(`backend  ${JSON.stringify(input).slice(0, 28)} -> ${JSON.stringify(got)} want ${JSON.stringify(expect)}`);
}
console.log(`backend rule: ${CASES.length - mismatches.length}/${CASES.length} cases agree with the pinned table`);

if (!existsSync(GRETA_FILE)) {
  console.log(`FRONTEND RULE NOT PRESENT at ${GRETA_FILE} — cross-implementation agreement NOT MEASURED.`);
  process.exit(1);
}
const front = await import(pathToFileURL(GRETA_FILE).href);
const cross = [];
for (const [input] of CASES) {
  const a = backend.normalizeInvitationCode(input);
  const b = front.normalizeInvitationCode(input);
  if (a !== b) cross.push(`  ${JSON.stringify(input).slice(0, 30)}: backend=${JSON.stringify(a)} frontend=${JSON.stringify(b)}`);
}
const maxAgreement = backend.INVITATION_CODE_MAX_LENGTH === front.INVITATION_CODE_MAX_LENGTH;
console.log(`max-length constant: backend=${backend.INVITATION_CODE_MAX_LENGTH} frontend=${front.INVITATION_CODE_MAX_LENGTH} ${maxAgreement ? 'SAME' : 'DIFFERENT'}`);
if (cross.length) {
  console.log(`CROSS-IMPLEMENTATION DRIFT on ${cross.length} case(s):`);
  console.log(cross.join('\n'));
} else {
  console.log(`both implementations agree on all ${CASES.length} cases (including the three-character code 777).`);
}
const ok = mismatches.length === 0 && cross.length === 0 && maxAgreement;
const passed = (mismatches.length === 0 ? CASES.length : 0) + (cross.length === 0 ? CASES.length : 0) + (maxAgreement ? 1 : 0);
const total = CASES.length + CASES.length + 1;
console.log(`\nRESULTS: ${passed}/${total} passed, ${total - passed} failed  (one invitation-code rule across backend and frontend)`);
console.log(ok ? 'VERDICT: AGREEMENT — every pinned case normalizes identically in both implementations.'
  : 'VERDICT: DRIFT — the two implementations disagree; the case list above names where.');
process.exit(ok ? 0 : 1);
