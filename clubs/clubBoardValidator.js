'use strict';

/*
 * SERVER-SIDE BOARD VALIDATION — NodeSend's own gate on every board it is asked to store.
 *
 * BridgeMind parses PBN in the browser and validates it there. That validation is useful and is
 * kept, but it is a UX step, not a boundary: anyone can POST a hand-built body to these routes,
 * so NodeSend re-checks the facts a board must satisfy before a row is written. §7 of the
 * integration contract names them: 13 cards per seat, 52 distinct cards, a valid dealer and
 * vulnerability, correct board numbering, no duplicate boards.
 *
 * THIS IS STRICTER THAN THE CLIENT PATH ON PURPOSE, in two places that matter:
 *   * 13 cards PER SEAT, not merely 52 unique in total. A body with North holding 14 and East 12
 *     passes a total-count check and then plays an illegal board — the exact defect a total-only
 *     check hides.
 *   * Each card matched against the deck itself, so `2S` twice and `1S` are both refused rather
 *     than counted as two distinct tokens.
 *
 * VOCABULARIES are the app's stored ones, not invented here. Cards are `${rank}${suit}` with
 * ranks 2-9,T,J,Q,K,A and suits S,H,D,C (src/engine/cards.js, which is what the PBN importer
 * emits). Vulnerability is the STORED set None/NS/EW/Both; `All` is an input spelling the
 * importer normalises to `Both`, so a body still carrying `All` never went through the importer
 * and is refused rather than quietly corrected. Nothing here rewrites a value — a rejected board
 * stays rejected, because a "corrected" deal is a different deal.
 *
 * BOARD NUMBERS must satisfy the same ID shape the ROUTES accept. That is not tidiness: a board
 * is addressed later at `/clubs/collections/:id/boards/:boardNumber/start`, whose parameter is
 * validated against this same pattern. Storing a number the route cannot address would create a
 * board no member can ever play, and the admin would see it in the list.
 *
 * Only reason NAMES from the client's published vocabulary are returned (CLUB_REASONS), so a
 * failure is always classifiable by the caller rather than being dropped as unknown.
 */

const SEATS = Object.freeze(['North', 'East', 'South', 'West']);
const DEALERS = SEATS;
const VULNERABILITIES = Object.freeze(['None', 'NS', 'EW', 'Both']);
const RANKS = Object.freeze(['2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A']);
const SUITS = Object.freeze(['S', 'H', 'D', 'C']);

const CARDS_PER_HAND = 13;
const CARDS_PER_BOARD = 52;
const MAX_BOARDS_PER_COLLECTION = 200;
// The live column is `board_number VARCHAR(10)`. Accepting more would reach NCB as a truncated or
// refused insert and surface as an unexplained import failure, so the limit is enforced here with a
// named reason instead. Standard duplicate movements number boards 1..28, so 10 characters is not a
// practical constraint on real files.
const MAX_BOARD_NUMBER_CHARS = 10;

// Same ID grammar as every other path parameter these routes take, bounded to the column width.
const BOARD_NUMBER = new RegExp(`^[A-Za-z0-9_-]{1,${MAX_BOARD_NUMBER_CHARS}}$`);
// Character classes, not capture groups: `^(2345...)(SHDC)$` would match one literal 21-character
// string and reject every real card, which is the kind of defect that makes a validation gate pass
// for exactly the wrong reason.
const CARD = new RegExp(`^[${RANKS.join('')}][${SUITS.join('')}]$`);

const isPlainObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
const text = (value) => String(value ?? '').trim();

/**
 * Validates one board's deal against the deck.
 * @returns {{ok: true} | {ok: false, reason: string, detail: string}}
 */
function validateBoardRecord(board) {
  if (!isPlainObject(board)) return { ok: false, reason: 'invalid_board_record', detail: 'a board must be an object' };

  const boardNumber = text(board.board_number);
  if (!BOARD_NUMBER.test(boardNumber)) {
    return { ok: false, reason: 'invalid_board_record', detail: 'board_number must be 1-32 characters of A-Z a-z 0-9 _ -' };
  }

  if (!DEALERS.includes(board.dealer)) {
    return { ok: false, reason: 'invalid_dealer', detail: `board ${boardNumber}: dealer must be North, East, South or West` };
  }
  if (!VULNERABILITIES.includes(board.vulnerability)) {
    return { ok: false, reason: 'invalid_vulnerability', detail: `board ${boardNumber}: vulnerability must be one of ${VULNERABILITIES.join(', ')} (the importer normalises "All" to "Both")` };
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
        return { ok: false, reason: 'incomplete_hands', detail: `board ${boardNumber}: "${token.slice(0, 8)}" in ${seat} is not a card (rank 2-9 T J Q K A, suit S H D C)` };
      }
      if (seen.has(token)) {
        return { ok: false, reason: 'incomplete_hands', detail: `board ${boardNumber}: ${token} appears in more than one hand` };
      }
      seen.add(token);
      total += 1;
    }
  }
  // Per-seat 13 × 4 already totals 52, so this only fires on a future edit that relaxes one
  // check; it stays because "the board is exactly the deck" is the invariant worth protecting.
  if (total !== CARDS_PER_BOARD || seen.size !== CARDS_PER_BOARD) {
    return { ok: false, reason: 'incomplete_hands', detail: `board ${boardNumber}: ${seen.size} distinct cards of ${total}; a board must hold the 52-card deck exactly` };
  }

  // The verbatim `source` the browser sends is NOT stored (there is no source column), so it is
  // ignored rather than measured. Refusing a payload over a field this relay discards would be a
  // limit that rejects files which previously imported.
  return { ok: true, boardNumber };
}

/**
 * Validates a whole submission: bounded size, every board sound, no repeated board number.
 *
 * @param {unknown} boards
 * @param {object} [options]
 * @param {number} [options.maxBoards] a deployment may lower the ceiling, never raise it past the
 *   published bound.
 * @returns {{ok: true, boards: object[], rejected: []}|{ok: false, reason: string, detail: string, rejected: Array<{index:number,reason:string,detail:string}>}}
 */
function validateBoardSubmission(boards, { maxBoards = MAX_BOARDS_PER_COLLECTION } = {}) {
  const ceiling = Math.min(Number(maxBoards) || MAX_BOARDS_PER_COLLECTION, MAX_BOARDS_PER_COLLECTION);
  const rejected = [];
  if (!Array.isArray(boards)) {
    return { ok: false, reason: 'invalid_board_record', detail: 'boards must be an array', rejected: [{ index: -1, reason: 'invalid_board_record', detail: 'boards must be an array' }] };
  }
  if (boards.length === 0) return { ok: false, reason: 'no_boards', detail: 'at least one board is required', rejected };
  if (boards.length > ceiling) {
    return { ok: false, reason: 'too_many_boards', detail: `a collection holds at most ${ceiling} boards`, rejected };
  }

  const numbers = new Set();
  boards.forEach((board, index) => {
    const checked = validateBoardRecord(board);
    if (!checked.ok) {
      rejected.push({ index, reason: checked.reason, detail: checked.detail });
      return;
    }
    if (numbers.has(checked.boardNumber)) {
      rejected.push({ index, reason: 'duplicate_board_number', detail: `board number "${checked.boardNumber}" appears twice in this collection` });
      return;
    }
    numbers.add(checked.boardNumber);
  });

  if (rejected.length) {
    return { ok: false, reason: rejected[0].reason, detail: `${rejected.length} board(s) refused; first: ${rejected[0].detail}`, rejected };
  }
  return { ok: true, boards, rejected: [] };
}

/**
 * True for a board number this relay can both STORE (VARCHAR(10)) and ADDRESS — the start route's
 * `:boardNumber` parameter is checked with the same grammar, so no board can be imported that the
 * route cannot reach, and none can be sought with a number too long to have been stored.
 */
function isBoardNumber(value) {
  return BOARD_NUMBER.test(String(value ?? '').trim());
}

module.exports = {
  SEATS,
  DEALERS,
  VULNERABILITIES,
  RANKS,
  SUITS,
  CARDS_PER_HAND,
  CARDS_PER_BOARD,
  MAX_BOARDS_PER_COLLECTION,
  MAX_BOARD_NUMBER_CHARS,
  isBoardNumber,
  validateBoardRecord,
  validateBoardSubmission
};
