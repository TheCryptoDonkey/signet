import { describe, it, expect } from 'vitest';
import {
  commit,
  verifyCommitment,
  createRangeProof,
  verifyRangeProof,
  createAgeRangeProof,
  verifyAgeRangeProof,
  serializeRangeProof,
  deserializeRangeProof,
} from '../src/range-proof.js';

describe('range-proof', () => {
  describe('Pedersen commitments', () => {
    it('creates and verifies a commitment', () => {
      const c = commit(42);
      expect(c.commitment).toHaveLength(66); // compressed point
      expect(c.value).toBe(42);
      expect(verifyCommitment(c.commitment, c.value, c.blinding)).toBe(true);
    });

    it('rejects wrong value', () => {
      const c = commit(42);
      expect(verifyCommitment(c.commitment, 43, c.blinding)).toBe(false);
    });

    it('rejects wrong blinding', () => {
      const c = commit(42);
      expect(verifyCommitment(c.commitment, 42, 'ff'.repeat(32))).toBe(false);
    });

    it('different values produce different commitments', () => {
      const c1 = commit(10);
      const c2 = commit(20);
      expect(c1.commitment).not.toBe(c2.commitment);
    });
  });

  describe('range proofs', () => {
    it('proves value in small range [0, 3]', () => {
      const proof = createRangeProof(2, 0, 3);
      expect(verifyRangeProof(proof)).toBe(true);
    });

    it('proves value at range minimum', () => {
      const proof = createRangeProof(5, 5, 10);
      expect(verifyRangeProof(proof)).toBe(true);
    });

    it('proves value at range maximum', () => {
      const proof = createRangeProof(10, 5, 10);
      expect(verifyRangeProof(proof)).toBe(true);
    });

    it('proves value in middle of range', () => {
      const proof = createRangeProof(7, 5, 10);
      expect(verifyRangeProof(proof)).toBe(true);
    });

    it('rejects value below range', () => {
      expect(() => createRangeProof(4, 5, 10)).toThrow('not in range');
    });

    it('rejects value above range', () => {
      expect(() => createRangeProof(11, 5, 10)).toThrow('not in range');
    });

    it('proves single-value range', () => {
      const proof = createRangeProof(7, 7, 7);
      expect(verifyRangeProof(proof)).toBe(true);
    });
  });

  describe('age range proofs', () => {
    it('proves age 10 in range 8-12', () => {
      const proof = createAgeRangeProof(10, '8-12');
      expect(verifyAgeRangeProof(proof)).toBe(true);
      expect(proof.min).toBe(8);
      expect(proof.max).toBe(12);
    });

    it('proves age 8 in range 8-12 (boundary)', () => {
      const proof = createAgeRangeProof(8, '8-12');
      expect(verifyAgeRangeProof(proof)).toBe(true);
    });

    it('proves age 12 in range 8-12 (boundary)', () => {
      const proof = createAgeRangeProof(12, '8-12');
      expect(verifyAgeRangeProof(proof)).toBe(true);
    });

    it('proves age 15 in range 13-17', () => {
      const proof = createAgeRangeProof(15, '13-17');
      expect(verifyAgeRangeProof(proof)).toBe(true);
    });

    it('rejects age 7 for range 8-12', () => {
      expect(() => createAgeRangeProof(7, '8-12')).toThrow();
    });

    it('rejects age 13 for range 8-12', () => {
      expect(() => createAgeRangeProof(13, '8-12')).toThrow();
    });
  });

  describe('binding context', () => {
    it('rejects proof when verified with a different context', () => {
      const proof = createRangeProof(7, 5, 10, 'pubkey_A');
      // Manually swap the context to simulate transplanting the proof to a different credential
      const transplanted = { ...proof, context: 'pubkey_B' };
      expect(verifyRangeProof(transplanted)).toBe(false);
    });

    it('rejects proof created with context when verified without context', () => {
      const proof = createRangeProof(7, 5, 10, 'pubkey_A');
      const stripped = { ...proof, context: undefined };
      expect(verifyRangeProof(stripped)).toBe(false);
    });
  });

  describe('serialization', () => {
    it('round-trips through JSON', () => {
      const proof = createAgeRangeProof(10, '8-12');
      const json = serializeRangeProof(proof);
      const deserialized = deserializeRangeProof(json);

      expect(verifyAgeRangeProof(deserialized)).toBe(true);
      expect(deserialized.min).toBe(8);
      expect(deserialized.max).toBe(12);
    });
  });

  describe('security hardening', () => {
    it('rejects max < min in createRangeProof', () => {
      expect(() => createRangeProof(5, 10, 3)).toThrow('Maximum must be >= minimum');
    });

    it('rejects range too large (> 2^32)', () => {
      expect(() => createRangeProof(0, 0, 2 ** 33)).toThrow('Range too large');
    });

    it('verifyRangeProof rejects when min > max', () => {
      const proof = createRangeProof(5, 0, 10);
      const tampered = { ...proof, min: 10, max: 0 };
      expect(verifyRangeProof(tampered)).toBe(false);
    });

    it('verifyRangeProof rejects when proof.bits is tampered', () => {
      const proof = createRangeProof(5, 0, 10);
      const tampered = { ...proof, bits: 0, lowerProof: [], upperProof: [] };
      expect(verifyRangeProof(tampered)).toBe(false);
    });

    it('verifyRangeProof rejects when proof.bits mismatches range', () => {
      const proof = createRangeProof(5, 0, 10);
      const tampered = { ...proof, bits: proof.bits + 1 };
      expect(verifyRangeProof(tampered)).toBe(false);
    });
  });
});
