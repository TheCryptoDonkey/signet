import { describe, it, expect } from 'vitest';
import {
  gf256Add,
  gf256Mul,
  gf256Inv,
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
} from '../src/shamir.js';
import { wordlist as BIP39_WORDLIST } from '@scure/bip39/wordlists/english.js';

describe('shamir', () => {
  // A known 16-byte secret (128-bit, standard for 12-word mnemonic entropy)
  const secret16 = new Uint8Array([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
  ]);

  // A 32-byte secret (256-bit)
  const secret32 = new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
  ]);

  describe('GF(256) arithmetic', () => {
    it('addition is XOR', () => {
      expect(gf256Add(0x57, 0x83)).toBe(0x57 ^ 0x83);
      expect(gf256Add(0, 0xff)).toBe(0xff);
      expect(gf256Add(0xff, 0xff)).toBe(0);
    });

    it('multiplication by 1 is identity', () => {
      for (let i = 0; i < 256; i++) {
        expect(gf256Mul(i, 1)).toBe(i);
      }
    });

    it('multiplication by 0 is 0', () => {
      for (let i = 0; i < 256; i++) {
        expect(gf256Mul(i, 0)).toBe(0);
        expect(gf256Mul(0, i)).toBe(0);
      }
    });

    it('multiplication is commutative', () => {
      expect(gf256Mul(0x57, 0x83)).toBe(gf256Mul(0x83, 0x57));
    });

    it('inverse is correct: a * inv(a) = 1', () => {
      for (let i = 1; i < 256; i++) {
        expect(gf256Mul(i, gf256Inv(i))).toBe(1);
      }
    });

    it('inverse of zero throws', () => {
      expect(() => gf256Inv(0)).toThrow('No inverse for zero');
    });
  });

  describe('split and reconstruct', () => {
    it('reconstructs a 16-byte secret with 2-of-3', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(shares).toHaveLength(3);
      const recovered = reconstructSecret(shares, 2);
      expect(recovered).toEqual(secret16);
    });

    it('reconstructs a 16-byte secret with 3-of-5', () => {
      const shares = splitSecret(secret16, 3, 5);
      expect(shares).toHaveLength(5);
      const recovered = reconstructSecret(shares, 3);
      expect(recovered).toEqual(secret16);
    });

    it('any 2 of 3 shares reconstruct (all 3 combinations)', () => {
      const shares = splitSecret(secret16, 2, 3);

      // Combination: shares[0], shares[1]
      expect(reconstructSecret([shares[0], shares[1]], 2)).toEqual(secret16);
      // Combination: shares[0], shares[2]
      expect(reconstructSecret([shares[0], shares[2]], 2)).toEqual(secret16);
      // Combination: shares[1], shares[2]
      expect(reconstructSecret([shares[1], shares[2]], 2)).toEqual(secret16);
    });

    it('any 3 of 5 shares reconstruct (several combinations)', () => {
      const shares = splitSecret(secret16, 3, 5);

      // Test several combinations of 3 shares
      const combos = [
        [0, 1, 2],
        [0, 1, 3],
        [0, 1, 4],
        [0, 2, 3],
        [0, 2, 4],
        [0, 3, 4],
        [1, 2, 3],
        [1, 2, 4],
        [1, 3, 4],
        [2, 3, 4],
      ];

      for (const [a, b, c] of combos) {
        const subset = [shares[a], shares[b], shares[c]];
        const recovered = reconstructSecret(subset, 3);
        expect(recovered).toEqual(secret16);
      }
    });

    it('fewer shares than threshold gives wrong result', () => {
      const shares = splitSecret(secret16, 2, 3);
      // Using only 1 share with threshold=1 is not meaningful,
      // but we can check that 1 share does not equal the secret
      // (the share data at x != 0 should differ from the secret at x = 0)
      const singleShareData = shares[0].data;
      const matches = secret16.every((b, i) => b === singleShareData[i]);
      expect(matches).toBe(false);
    });

    it('works with 16-byte secrets (128-bit)', () => {
      const secret = new Uint8Array(16);
      secret.fill(0x42);
      const shares = splitSecret(secret, 2, 3);
      const recovered = reconstructSecret(shares, 2);
      expect(recovered).toEqual(secret);
    });

    it('works with 32-byte secrets (256-bit)', () => {
      const shares = splitSecret(secret32, 3, 5);
      const recovered = reconstructSecret(shares, 3);
      expect(recovered).toEqual(secret32);
    });

    it('shares are different from each other', () => {
      const shares = splitSecret(secret16, 2, 3);
      // Each pair of shares should differ
      for (let i = 0; i < shares.length; i++) {
        for (let j = i + 1; j < shares.length; j++) {
          const same = shares[i].data.every(
            (b, idx) => b === shares[j].data[idx],
          );
          expect(same).toBe(false);
        }
      }
    });

    it('shares are different from the original secret', () => {
      const shares = splitSecret(secret16, 2, 3);
      for (const share of shares) {
        const same = share.data.every((b, idx) => b === secret16[idx]);
        expect(same).toBe(false);
      }
    });

    it('deterministic: same shares always reconstruct the same secret', () => {
      const shares = splitSecret(secret16, 3, 5);
      const r1 = reconstructSecret([shares[0], shares[2], shares[4]], 3);
      const r2 = reconstructSecret([shares[0], shares[2], shares[4]], 3);
      expect(r1).toEqual(r2);
      expect(r1).toEqual(secret16);
    });
  });

  describe('validation', () => {
    it('throws when threshold < 2', () => {
      expect(() => splitSecret(secret16, 1, 3)).toThrow('at least 2');
    });

    it('throws when shares < threshold', () => {
      expect(() => splitSecret(secret16, 4, 3)).toThrow('>= threshold');
    });

    it('throws when shares > 255', () => {
      expect(() => splitSecret(secret16, 2, 256)).toThrow('<= 255');
    });

    it('throws when not enough shares for reconstruction', () => {
      const shares = splitSecret(secret16, 3, 5);
      expect(() => reconstructSecret([shares[0], shares[1]], 3)).toThrow(
        'Need at least 3',
      );
    });

    it('throws when a share has ID 0', () => {
      const shares = splitSecret(secret16, 2, 3);
      const zeroIdShare = { id: 0, data: shares[0].data };
      expect(() => reconstructSecret([zeroIdShare, shares[1]], 2)).toThrow(
        'Invalid share ID: 0 is not a valid x-coordinate',
      );
    });

    it('throws when shares have inconsistent data lengths', () => {
      const shares16 = splitSecret(secret16, 2, 3);
      const shares32 = splitSecret(secret32, 2, 3);
      // Mix shares from different secret lengths
      expect(() => reconstructSecret([shares16[0], shares32[1]], 2)).toThrow(
        'Inconsistent share lengths',
      );
    });
  });

  describe('BIP-39 word encoding', () => {
    it('shareToWords produces words all in the BIP-39 wordlist', () => {
      const shares = splitSecret(secret16, 2, 3);
      for (const share of shares) {
        const words = shareToWords(share);
        for (const word of words) {
          expect(BIP39_WORDLIST).toContain(word);
        }
      }
    });

    it('shareToWords -> wordsToShare roundtrips', () => {
      const shares = splitSecret(secret16, 2, 3);
      for (const share of shares) {
        const words = shareToWords(share);
        const recovered = wordsToShare(words);
        expect(recovered.id).toBe(share.id);
        expect(recovered.data).toEqual(share.data);
      }
    });

    it('roundtrips with 32-byte secret shares', () => {
      const shares = splitSecret(secret32, 3, 5);
      for (const share of shares) {
        const words = shareToWords(share);
        const recovered = wordsToShare(words);
        expect(recovered.id).toBe(share.id);
        expect(recovered.data).toEqual(share.data);
      }
    });

    it('full pipeline: split -> words -> reconstruct', () => {
      const shares = splitSecret(secret16, 2, 3);
      const wordShares = shares.map(shareToWords);
      const recoveredShares = wordShares.map(wordsToShare);
      const recovered = reconstructSecret(recoveredShares, 2);
      expect(recovered).toEqual(secret16);
    });
  });
});
