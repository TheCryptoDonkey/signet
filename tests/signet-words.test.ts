import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { WORDLIST } from 'canary-kit/wordlist';
import {
  SIGNET_EPOCH_SECONDS,
  SIGNET_WORD_COUNT,
  MAX_WORD_COUNT,
  getEpoch,
  deriveWords,
  getSignetWords,
  verifySignetWords,
  formatSignetWords,
  getSignetDisplay,
} from '../src/signet-words.js';

// Deterministic test secret
const testSecret = bytesToHex(sha256(utf8ToBytes('test-shared-secret')));

// A second, different secret for comparison
const otherSecret = bytesToHex(sha256(utf8ToBytes('other-shared-secret')));

// Fixed timestamp aligned to the start of an epoch so +10s stays within the same window
const fixedTimestamp = 1700000010000; // 10ms into an epoch (1700000010000 % 30000 == 10000)

describe('signet-words', () => {
  describe('getSignetWords (default 3 words)', () => {
    it('returns exactly 3 words by default', () => {
      const words = getSignetWords(testSecret, fixedTimestamp);
      expect(words).toHaveLength(SIGNET_WORD_COUNT);
    });

    it('all 3 words are in the Canary spoken-clarity wordlist', () => {
      const words = getSignetWords(testSecret, fixedTimestamp);
      for (const word of words) {
        expect(WORDLIST).toContain(word);
      }
    });

    it('same shared secret + same timestamp produces same words (deterministic)', () => {
      const words1 = getSignetWords(testSecret, fixedTimestamp);
      const words2 = getSignetWords(testSecret, fixedTimestamp);
      expect(words1).toEqual(words2);
    });

    it('different shared secrets produce different words', () => {
      const words1 = getSignetWords(testSecret, fixedTimestamp);
      const words2 = getSignetWords(otherSecret, fixedTimestamp);
      expect(words1).not.toEqual(words2);
    });

    it('same secret at different epochs produces different words', () => {
      const words1 = getSignetWords(testSecret, fixedTimestamp);
      // Move forward by more than one epoch (31 seconds)
      const words2 = getSignetWords(testSecret, fixedTimestamp + 31_000);
      expect(words1).not.toEqual(words2);
    });
  });

  describe('configurable word count', () => {
    it('returns 1 word when configured', () => {
      const words = getSignetWords(testSecret, fixedTimestamp, { wordCount: 1 });
      expect(words).toHaveLength(1);
      expect(WORDLIST).toContain(words[0]);
    });

    it('returns 2 words when configured', () => {
      const words = getSignetWords(testSecret, fixedTimestamp, { wordCount: 2 });
      expect(words).toHaveLength(2);
      for (const w of words) expect(WORDLIST).toContain(w);
    });

    it('returns 4 words when configured', () => {
      const words = getSignetWords(testSecret, fixedTimestamp, { wordCount: 4 });
      expect(words).toHaveLength(4);
      for (const w of words) expect(WORDLIST).toContain(w);
    });

    it('throws for word count < 1', () => {
      expect(() => deriveWords(testSecret, 0, 0)).toThrow();
    });

    it('throws for word count > MAX_WORD_COUNT', () => {
      expect(() => deriveWords(testSecret, 0, MAX_WORD_COUNT + 1)).toThrow();
    });

    it('handles max word count', () => {
      const words = getSignetWords(testSecret, fixedTimestamp, { wordCount: MAX_WORD_COUNT });
      expect(words).toHaveLength(MAX_WORD_COUNT);
      for (const w of words) expect(WORDLIST).toContain(w);
    });
  });

  describe('configurable epoch interval', () => {
    it('uses custom epoch interval', () => {
      const config = { epochSeconds: 60 };
      // Use a timestamp aligned to the start of a 60s epoch
      const alignedTs = Math.floor(fixedTimestamp / 60000) * 60000 + 5000; // 5s into a 60s epoch
      const words1 = getSignetWords(testSecret, alignedTs, config);
      // 31 seconds later should still be the same epoch with 60s intervals
      const words2 = getSignetWords(testSecret, alignedTs + 31_000, config);
      expect(words1).toEqual(words2);
    });

    it('different epoch intervals produce different words at same timestamp', () => {
      const words30 = getSignetWords(testSecret, fixedTimestamp, { epochSeconds: 30 });
      const words60 = getSignetWords(testSecret, fixedTimestamp, { epochSeconds: 60 });
      // Different epoch = different epoch number = likely different words
      const epoch30 = getEpoch(fixedTimestamp, 30);
      const epoch60 = getEpoch(fixedTimestamp, 60);
      if (epoch30 !== epoch60) {
        expect(words30).not.toEqual(words60);
      }
    });
  });

  describe('configurable tolerance', () => {
    it('tolerance 0 rejects previous epoch words', () => {
      const prevEpochTime = fixedTimestamp - SIGNET_EPOCH_SECONDS * 1000;
      const words = getSignetWords(testSecret, prevEpochTime);
      expect(verifySignetWords(testSecret, words, fixedTimestamp, { tolerance: 0 })).toBe(false);
    });

    it('tolerance 0 accepts current epoch words', () => {
      const words = getSignetWords(testSecret, fixedTimestamp);
      expect(verifySignetWords(testSecret, words, fixedTimestamp, { tolerance: 0 })).toBe(true);
    });

    it('tolerance 2 accepts words from 2 epochs ago', () => {
      const oldTime = fixedTimestamp - SIGNET_EPOCH_SECONDS * 1000 * 2;
      const words = getSignetWords(testSecret, oldTime);
      expect(verifySignetWords(testSecret, words, fixedTimestamp, { tolerance: 2 })).toBe(true);
    });
  });

  describe('verifySignetWords (defaults)', () => {
    it('returns true for current epoch words', () => {
      const words = getSignetWords(testSecret, fixedTimestamp);
      expect(verifySignetWords(testSecret, words, fixedTimestamp)).toBe(true);
    });

    it('returns true for previous epoch (tolerance)', () => {
      const prevEpochTime = fixedTimestamp - SIGNET_EPOCH_SECONDS * 1000;
      const words = getSignetWords(testSecret, prevEpochTime);
      expect(verifySignetWords(testSecret, words, fixedTimestamp)).toBe(true);
    });

    it('returns true for next epoch (tolerance)', () => {
      const nextEpochTime = fixedTimestamp + SIGNET_EPOCH_SECONDS * 1000;
      const words = getSignetWords(testSecret, nextEpochTime);
      expect(verifySignetWords(testSecret, words, fixedTimestamp)).toBe(true);
    });

    it('returns false for words from 2 epochs ago', () => {
      const oldTime = fixedTimestamp - SIGNET_EPOCH_SECONDS * 1000 * 2;
      const words = getSignetWords(testSecret, oldTime);
      expect(verifySignetWords(testSecret, words, fixedTimestamp)).toBe(false);
    });

    it('returns false for random/wrong words', () => {
      const wrongWords = ['abandon', 'abandon', 'abandon'];
      expect(verifySignetWords(testSecret, wrongWords, fixedTimestamp)).toBe(false);
    });
  });

  describe('cross-config verification', () => {
    it('verifier must use same config as generator', () => {
      const words = getSignetWords(testSecret, fixedTimestamp, { wordCount: 2 });
      expect(verifySignetWords(testSecret, words, fixedTimestamp, { wordCount: 2 })).toBe(true);
      expect(verifySignetWords(testSecret, words, fixedTimestamp)).toBe(false);
    });
  });

  describe('both parties see same words', () => {
    it('two parties with the same secret at the same time get identical words', () => {
      const aliceWords = getSignetWords(testSecret, fixedTimestamp);
      const bobWords = getSignetWords(testSecret, fixedTimestamp);
      expect(aliceWords).toEqual(bobWords);
    });
  });

  describe('formatSignetWords', () => {
    it('joins words with " · " (middle dot separator)', () => {
      const words = ['ocean', 'tiger', 'marble'];
      expect(formatSignetWords(words)).toBe('ocean · tiger · marble');
    });

    it('works with 1 word', () => {
      expect(formatSignetWords(['ocean'])).toBe('ocean');
    });

    it('works with 4 words', () => {
      expect(formatSignetWords(['a', 'b', 'c', 'd'])).toBe('a · b · c · d');
    });
  });

  describe('getSignetDisplay', () => {
    it('returns words, formatted string, and expiresIn > 0', () => {
      const display = getSignetDisplay(testSecret, fixedTimestamp);
      expect(display.words).toHaveLength(SIGNET_WORD_COUNT);
      expect(display.formatted).toContain(' · ');
      expect(display.expiresIn).toBeGreaterThan(0);
      expect(display.expiresIn).toBeLessThanOrEqual(SIGNET_EPOCH_SECONDS);
    });

    it('respects custom config', () => {
      const display = getSignetDisplay(testSecret, fixedTimestamp, { wordCount: 2, epochSeconds: 60 });
      expect(display.words).toHaveLength(2);
      expect(display.expiresIn).toBeLessThanOrEqual(60);
    });
  });

  describe('getEpoch', () => {
    it('returns same value within the same 30-second window', () => {
      const epoch1 = getEpoch(fixedTimestamp);
      const epoch2 = getEpoch(fixedTimestamp + 10_000);
      expect(epoch1).toBe(epoch2);
    });

    it('returns different values 31 seconds apart', () => {
      const epoch1 = getEpoch(fixedTimestamp);
      const epoch2 = getEpoch(fixedTimestamp + 31_000);
      expect(epoch1).not.toBe(epoch2);
    });

    it('respects custom epoch interval', () => {
      const alignedTs = Math.floor(fixedTimestamp / 60000) * 60000 + 5000;
      const epoch1 = getEpoch(alignedTs, 60);
      const epoch2 = getEpoch(alignedTs + 31_000, 60);
      expect(epoch1).toBe(epoch2);
    });
  });

  describe('word index range', () => {
    it('word indices are always in valid range (0-2047) across several secrets', () => {
      const secrets = [
        bytesToHex(sha256(utf8ToBytes('secret-a'))),
        bytesToHex(sha256(utf8ToBytes('secret-b'))),
        bytesToHex(sha256(utf8ToBytes('secret-c'))),
        bytesToHex(sha256(utf8ToBytes('secret-d'))),
        bytesToHex(sha256(utf8ToBytes('secret-e'))),
      ];

      for (const secret of secrets) {
        for (let epochOffset = 0; epochOffset < 10; epochOffset++) {
          const words = deriveWords(secret, epochOffset);
          expect(words).toHaveLength(SIGNET_WORD_COUNT);
          for (const word of words) {
            const idx = WORDLIST.indexOf(word);
            expect(idx).toBeGreaterThanOrEqual(0);
            expect(idx).toBeLessThanOrEqual(2047);
          }
        }
      }
    });

    it('valid range holds for variable word counts', () => {
      for (const count of [1, 2, 4, 8]) {
        const words = deriveWords(testSecret, 0, count);
        expect(words).toHaveLength(count);
        for (const word of words) {
          expect(WORDLIST).toContain(word);
        }
      }
    });
  });
});
