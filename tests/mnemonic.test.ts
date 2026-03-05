import { describe, it, expect } from 'vitest';
import {
  generateEntropy,
  entropyToMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
  mnemonicToSeed,
  generateMnemonic,
} from '../src/mnemonic.js';
import { BIP39_WORDLIST } from '../src/wordlist.js';
import { TEST_MNEMONIC } from './fixtures.js';

/** Convert a hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to a lowercase hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('mnemonic', () => {
  // ─── generateMnemonic ───────────────────────────────────────────────

  describe('generateMnemonic', () => {
    it('produces 12 words with all words in the BIP-39 wordlist', () => {
      const mnemonic = generateMnemonic();
      const words = mnemonic.split(' ');
      expect(words).toHaveLength(12);
      for (const word of words) {
        expect(BIP39_WORDLIST).toContain(word);
      }
    });

    it('produces 24 words when given 256 bits', () => {
      const mnemonic = generateMnemonic(256);
      const words = mnemonic.split(' ');
      expect(words).toHaveLength(24);
      for (const word of words) {
        expect(BIP39_WORDLIST).toContain(word);
      }
    });

    it('produces different results on successive calls', () => {
      const a = generateMnemonic();
      const b = generateMnemonic();
      // Statistically impossible for two random 128-bit mnemonics to collide
      expect(a).not.toBe(b);
    });
  });

  // ─── validateMnemonic ──────────────────────────────────────────────

  describe('validateMnemonic', () => {
    it('returns true for a valid mnemonic', () => {
      const mnemonic = generateMnemonic();
      expect(validateMnemonic(mnemonic)).toBe(true);
    });

    it('returns false for wrong word count', () => {
      expect(validateMnemonic('abandon abandon abandon')).toBe(false);
    });

    it('returns false for words not in the wordlist', () => {
      // 12 nonsense words
      const fake = Array(12).fill('zzzznotaword').join(' ');
      expect(validateMnemonic(fake)).toBe(false);
    });

    it('returns false for a bad checksum (two words swapped)', () => {
      // Swap first two meaningful words to break checksum
      const words = TEST_MNEMONIC.split(' ');
      // Swap positions 0 and 10 — "abandon" and "abandon" are the same, so swap 0 and 11
      const swapped = [...words];
      [swapped[0], swapped[11]] = [swapped[11], swapped[0]];
      // "about abandon ... abandon" should fail checksum
      expect(validateMnemonic(swapped.join(' '))).toBe(false);
    });
  });

  // ─── roundtrip: mnemonicToEntropy ↔ entropyToMnemonic ──────────────

  describe('roundtrip', () => {
    it('mnemonicToEntropy → entropyToMnemonic roundtrips', () => {
      const mnemonic = generateMnemonic();
      const entropy = mnemonicToEntropy(mnemonic);
      const recovered = entropyToMnemonic(entropy);
      expect(recovered).toBe(mnemonic);
    });

    it('entropyToMnemonic → mnemonicToEntropy roundtrips', () => {
      const entropy = generateEntropy();
      const mnemonic = entropyToMnemonic(entropy);
      const recovered = mnemonicToEntropy(mnemonic);
      expect(bytesToHex(recovered)).toBe(bytesToHex(entropy));
    });
  });

  // ─── mnemonicToSeed ────────────────────────────────────────────────

  describe('mnemonicToSeed', () => {
    it('produces a 64-byte seed', () => {
      const mnemonic = generateMnemonic();
      const seed = mnemonicToSeed(mnemonic);
      expect(seed).toHaveLength(64);
      expect(seed).toBeInstanceOf(Uint8Array);
    });

    it('produces a different seed with a passphrase than without', () => {
      const mnemonic = generateMnemonic();
      const seedNoPass = mnemonicToSeed(mnemonic);
      const seedWithPass = mnemonicToSeed(mnemonic, 'my secret passphrase');
      expect(bytesToHex(seedNoPass)).not.toBe(bytesToHex(seedWithPass));
    });

    it('is deterministic (same input yields same output)', () => {
      const mnemonic = generateMnemonic();
      const seed1 = mnemonicToSeed(mnemonic, 'test');
      const seed2 = mnemonicToSeed(mnemonic, 'test');
      expect(bytesToHex(seed1)).toBe(bytesToHex(seed2));
    });
  });

  // ─── generateEntropy ──────────────────────────────────────────────

  describe('generateEntropy', () => {
    it('throws for invalid bit lengths', () => {
      expect(() => generateEntropy(100)).toThrow();
      expect(() => generateEntropy(0)).toThrow();
      expect(() => generateEntropy(64)).toThrow();
      expect(() => generateEntropy(512)).toThrow();
    });

    it('returns correct byte lengths for valid bit counts', () => {
      expect(generateEntropy(128)).toHaveLength(16);
      expect(generateEntropy(160)).toHaveLength(20);
      expect(generateEntropy(192)).toHaveLength(24);
      expect(generateEntropy(224)).toHaveLength(28);
      expect(generateEntropy(256)).toHaveLength(32);
    });
  });

  // ─── Known BIP-39 test vector ─────────────────────────────────────

  describe('BIP-39 test vector', () => {
    const entropyHex = '00000000000000000000000000000000';
    const expectedMnemonic = TEST_MNEMONIC;
    const expectedSeedHex =
      '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4';

    it('entropyToMnemonic produces the expected mnemonic', () => {
      const entropy = hexToBytes(entropyHex);
      const mnemonic = entropyToMnemonic(entropy);
      expect(mnemonic).toBe(expectedMnemonic);
    });

    it('mnemonicToEntropy recovers the original entropy', () => {
      const entropy = mnemonicToEntropy(expectedMnemonic);
      expect(bytesToHex(entropy)).toBe(entropyHex);
    });

    it('mnemonicToSeed (no passphrase) produces the expected seed', () => {
      const seed = mnemonicToSeed(expectedMnemonic);
      expect(bytesToHex(seed)).toBe(expectedSeedHex);
    });

    it('validateMnemonic returns true for the test vector', () => {
      expect(validateMnemonic(expectedMnemonic)).toBe(true);
    });
  });
});
