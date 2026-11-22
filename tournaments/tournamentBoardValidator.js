/*
 * tournaments/tournamentBoardValidator.js — the board contract for TOURNAMENT imports.
 *
 * WHY THIS FILE EXISTS
 * `clubs/clubBoardValidator.js` caps `board_number` at 10 characters because the live
 * `club_collection_boards.board_number` column is VARCHAR(10). Tournaments are a different table with a
 * different column and a different published contract: `tournamentContracts.js` (the frontend) and
 * `docs/NCB-TOURNAMENT-SCHEMA-RECONCILIATION-2026-11-22.md` §2 both say 1–32, and the migration asks for
 * VARCHAR(32). Importing the club rule here would refuse real PBN labels — a dotted movement number, a
 * session-prefixed board like `2026-10-11-R1-14`, an event code — while accepting the same string on the
 * other surface. Importing the club *ceiling* is also a coupling: tightening a club column would silently
 * tighten tournaments.
 *
 * WHAT IS STILL SHARED, DELIBERATELY
 * Everything that decides what a BRIDGE BOARD is comes from the club validator's exported primitives:
 * the seat names, the dealer domain, the vulnerability domain, the rank and suit alphabets, and the
 * 13-per-hand / 52-per-board counts. There is exactly one definition of a card in this repository, and
 * this file does not redefine it. Only the LABEL GRAMMAR differs, because only the label differs.
 *
 * NORMALISATION, and why it is not cosmetic
 * A label is trimmed before it is validated and the TRIMMED value is what the store writes. NCB compares
 * these strings exactly, so storing `1` and `1 ` side by side would create two rows that every later
 * lookup resolves to the same key — an ambiguity the composite unique cannot see, because the raw column
 * values differ. Trimming at the boundary makes the stored identity and the addressed identity the same
 * string. Internal whitespace is refused rather than collapsed: `1 2` and `12` are different labels and
 * silently merging them would invent a duplicate board identity out of two distinct ones.
 */

const {
  SEATS,
  DEALERS,
  VULNERABILITIES,
  RANKS,
  SUITS,
  CARDS_PER_HAND,
  CARDS_PER_BOARD,
  MAX_BOARDS_PER_COLLECTION
} = require('../clubs/clubBoardValidator.js');

/** The tournament ceiling. Matches `tournamentContracts.js` and the VARCHAR(32) migration ask. */
const MAX_BOARD_NUMBER_CHARS = 32;

// Built from the constant so the grammar and the advertised limit cannot drift apart — the club module
// documents a detail string that promises 32 while its regex allows 10, and that is exactly the kind of
// disagreement a caller cannot see from the outside.
const BOARD_NUMBER = new RegExp(`^[A-Za-z0-9_-]{1,${MAX_BOARD_NUMBER_CHARS}}$`);

// Character classes, not capture groups: `^(2345...)(SHDC)$` would match one literal 21-character string
// and reject every real card. Same warning the club module carries, because the same mistake is possible.
const CARD = new RegExp(`^[${RANKS.join('')}][${SUITS.join('')}]$`);

const isPlainObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
const text = (value) => String(value ?? '').trim();

/** True for a board number a tournament route can both store and address. */
function isBoardNumber(value) {
  return BOARD_NUMBER.test(text(value));
}

/**
 * Validates one imported board: its label, its dealer, its vulnerability, and the 52-card deck.
 * @returns {{ok: true, boardNumber: string} | {ok: false, reason: string, detail: string}}
 */
function validateBoardRecord(board) {
  if (!isPlainObject(board)) return { ok: false, reason: 'invalid_board_record', detail: 'a board must be an object' };

  const boardNumber = text(board.board_number);
  if (!BOARD_NUMBER.test(boardNumber)) {
    return {
      ok: false,
      reason: 'invalid_board_record',
      detail: `board_number must be 1-${MAX_BOARD_NUMBER_CHARS} characters of A-Z a-z 0-9 _ -`
    };
  }

  if (!DEALERS.includes(board.dealer)) {
    return { ok: false, reason: 'invalid_dealer', detail: `board ${boardNumber}: dealer must be ${DEALERS.join(', ')}` };
  }
  if (!VULNERABILITIES.includes(board.vulnerability)) {
    return {
      ok: false,
      reason: 'invalid_vulnerability',
      detail: `board ${boardNumber}: vulnerability must be one of ${VULNERABILITIES.join(', ')} (the importer normalises "All" to "Both")`
    };
  }

  const hands = board.hands;
  if (!isPlainObject(hands)) return { ok: false, reason: 'incomplete_hands', detail: `board ${boardNumber}: hands must name all four seats` };
  const unexpectedSeats = Object.keys(hands).filter((seat) => !SEATS.includes(seat));
  if (unexpectedSeats.length) {
    return { ok: false, reason: 'incomplete_hands', detail: `board ${boardNumber}: hands name unknown seat(s) ${unexpectedSeats.join(', ')}` };
  }

  const seen = new Set();
  let total = 0;
  for (const seat of SEATS) {
    const cards = hands[seat];
    if (!Array.isArray(cards)) return { ok: false, reason: 'incomplete_hands', detail: `board ${boardNumber}: ${seat} must name an array of cards` };
    if (cards.length !== CARDS_PER_HAND) {
      return { ok: false, reason: 'incomplete_hands', detail: `board ${boardNumber}: ${seat} holds ${cards.length} cards, expected ${CARDS_PER_HAND}` };
    }
    for (const card of cards) {
      const token = text(card);
      if (!CARD.test(token)) {
        return {
          ok: false,
          reason: 'incomplete_hands',
          detail: `board ${boardNumber}: "${token.slice(0, 8)}" in ${seat} is not a card (rank ${RANKS.join(' ')}, suit ${SUITS.join(' ')})`
        };
      }
      if (seen.has(token)) {
        return { ok: false, reason: 'incomplete_hands', detail: `board ${boardNumber}: ${token} appears in more than one hand` };
      }
      seen.add(token);
      total += 1;
    }
  }
  if (total !== CARDS_PER_BOARD || seen.size !== CARDS_PER_BOARD) {
    return {
      ok: false,
      reason: 'incomplete_hands',
      detail: `board ${boardNumber}: ${seen.size} distinct cards of ${total}; a board must hold the 52-card deck exactly`
    };
  }

  return { ok: true, boardNumber };
}

/**
 * Validates a whole tournament submission: bounded size, every board sound, no repeated label.
 * Duplicate detection is per tournament here; the composite unique in NCB is what makes it durable across
 * processes, and this is the layer that gives the player a named reason instead of a database refusal.
 */
function validateBoardSubmission(boards, { maxBoards = MAX_BOARDS_PER_COLLECTION } = {}) {
  const rejected = [];
  if (!Array.isArray(boards)) {
    return {
      ok: false,
      reason: 'invalid_board_record',
      detail: 'boards must be an array',
      rejected: [{ index: -1, reason: 'invalid_board_record', detail: 'boards must be an array' }]
    };
  }
  if (boards.length === 0) return { ok: false, reason: 'no_boards', detail: 'at least one board is required', rejected };
  if (!Number.isFinite(maxBoards) || boards.length > maxBoards) {
    return { ok: false, reason: 'too_many_boards', detail: `a tournament holds at most ${maxBoards} boards`, rejected };
  }

  const numbers = new Set();
  boards.forEach((board, index) => {
    const checked = validateBoardRecord(board);
    if (!checked.ok) {
      rejected.push({ index, reason: checked.reason, detail: checked.detail });
      return;
    }
    if (numbers.has(checked.boardNumber)) {
      rejected.push({ index, reason: 'duplicate_board_number', detail: `board number "${checked.boardNumber}" appears twice in this tournament` });
      return;
    }
    numbers.add(checked.boardNumber);
  });

  if (rejected.length) {
    return { ok: false, reason: rejected[0].reason, detail: `${rejected.length} board(s) refused; first: ${rejected[0].detail}`, rejected };
  }
  return { ok: true, boards, rejected: [] };
}

module.exports = {
  SEATS,
  DEALERS,
  VULNERABILITIES,
  CARD,
  BOARD_NUMBER,
  MAX_BOARD_NUMBER_CHARS,
  isBoardNumber,
  validateBoardRecord,
  validateBoardSubmission
};
