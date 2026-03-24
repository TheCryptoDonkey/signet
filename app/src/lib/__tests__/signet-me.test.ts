import { describe, it, expect } from 'vitest';
import { getSignetMeDisplay, verifySignetMe } from '../signet-me';

// Fixed test inputs — deterministic across all runs
const SHARED_SECRET = 'a'.repeat(64); // 32-byte hex string
const ALICE_PUBKEY = '1'.repeat(64);  // realistic 64-char hex pubkey
const BOB_PUBKEY = '2'.repeat(64);    // realistic 64-char hex pubkey
const FIXED_TS = 1710000000000;       // arbitrary fixed millisecond timestamp

describe('getSignetMeDisplay', () => {
  it('returns different words for each side', () => {
    const display = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    expect(display.myWords.join(' ')).not.toBe(display.theirWords.join(' '));
  });

  it('returns consistent words for the same inputs and timestamp', () => {
    const first = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    const second = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    expect(first.myWords).toEqual(second.myWords);
    expect(first.theirWords).toEqual(second.theirWords);
  });

  it('swapping pubkeys swaps the words', () => {
    const alicePov = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    const bobPov = getSignetMeDisplay(SHARED_SECRET, BOB_PUBKEY, ALICE_PUBKEY, 1, FIXED_TS);
    // Alice's words become Bob's theirWords, and vice versa
    expect(alicePov.myWords).toEqual(bobPov.theirWords);
    expect(alicePov.theirWords).toEqual(bobPov.myWords);
  });

  it('expiresIn is between 1 and 30 (default rotation period)', () => {
    const display = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    expect(display.expiresIn).toBeGreaterThanOrEqual(1);
    expect(display.expiresIn).toBeLessThanOrEqual(30);
  });

  it('wordCount of 1 produces one word per side', () => {
    const display = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    expect(display.myWords).toHaveLength(1);
    expect(display.theirWords).toHaveLength(1);
  });

  it('wordCount of 2 produces two words per side', () => {
    const display = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 2, FIXED_TS);
    expect(display.myWords).toHaveLength(2);
    expect(display.theirWords).toHaveLength(2);
  });

  it('wordCount of 3 produces three words per side', () => {
    const display = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 3, FIXED_TS);
    expect(display.myWords).toHaveLength(3);
    expect(display.theirWords).toHaveLength(3);
  });
});

describe('verifySignetMe', () => {
  it('correct words verify successfully', () => {
    const display = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    // Alice verifies what Bob should say (theirWords from Alice's perspective)
    const result = verifySignetMe(
      SHARED_SECRET,
      ALICE_PUBKEY,
      BOB_PUBKEY,
      display.theirWords,
      1,
      FIXED_TS,
    );
    expect(result).toBe(true);
  });

  it('wrong words fail verification', () => {
    const result = verifySignetMe(
      SHARED_SECRET,
      ALICE_PUBKEY,
      BOB_PUBKEY,
      ['notaword'],
      1,
      FIXED_TS,
    );
    expect(result).toBe(false);
  });

  it('words from the previous epoch still verify (tolerance window)', () => {
    // Advance one full rotation period (30 000 ms) from the fixed timestamp
    const laterTs = FIXED_TS + 30_000;
    // Get the words that were valid at FIXED_TS
    const previousDisplay = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    // Verify at laterTs — previous-epoch words should still pass within tolerance of 1
    const result = verifySignetMe(
      SHARED_SECRET,
      ALICE_PUBKEY,
      BOB_PUBKEY,
      previousDisplay.theirWords,
      1,
      laterTs,
    );
    expect(result).toBe(true);
  });

  it('words from far in the future fail', () => {
    // Words from 10 rotation periods ahead are well outside the tolerance window
    const futureTs = FIXED_TS + 300_000;
    const futureDisplay = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, futureTs);
    const result = verifySignetMe(
      SHARED_SECRET,
      ALICE_PUBKEY,
      BOB_PUBKEY,
      futureDisplay.theirWords,
      1,
      FIXED_TS,
    );
    expect(result).toBe(false);
  });

  it('case-insensitive matching works', () => {
    const display = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    const uppercased = display.theirWords.map(w => w.toUpperCase());
    const result = verifySignetMe(
      SHARED_SECRET,
      ALICE_PUBKEY,
      BOB_PUBKEY,
      uppercased,
      1,
      FIXED_TS,
    );
    expect(result).toBe(true);
  });

  it("swapped roles: Bob verifying Alice's words uses the reciprocal view", () => {
    // From Bob's perspective, Alice is "them" — so Bob verifies alicePov.myWords
    const alicePov = getSignetMeDisplay(SHARED_SECRET, ALICE_PUBKEY, BOB_PUBKEY, 1, FIXED_TS);
    // Bob calls verifySignetMe with his own pubkey as myPubkey
    const result = verifySignetMe(
      SHARED_SECRET,
      BOB_PUBKEY,
      ALICE_PUBKEY,
      alicePov.myWords, // Alice's words === Bob's theirWords
      1,
      FIXED_TS,
    );
    expect(result).toBe(true);
  });
});
