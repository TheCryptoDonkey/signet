import { describe, it, expect } from 'vitest';
import {
  computeJurisdictionConfidence,
  getJurisdictionConfidence,
  rankJurisdictionsByConfidence,
  getJurisdictionCodes,
} from 'jurisdiction-kit';

describe('jurisdiction confidence', () => {
  describe('computeJurisdictionConfidence', () => {
    it('returns a confidence object for GB', () => {
      const result = computeJurisdictionConfidence('GB');
      expect(result).toBeDefined();
      expect(result!.code).toBe('GB');
      expect(result!.score).toBeGreaterThan(0);
      expect(result!.score).toBeLessThanOrEqual(100);
    });

    it('returns undefined for unknown jurisdiction', () => {
      expect(computeJurisdictionConfidence('XX')).toBeUndefined();
    });

    it('GB scores high (strong professional bodies, common law, good data protection)', () => {
      const gb = computeJurisdictionConfidence('GB');
      expect(gb!.score).toBeGreaterThanOrEqual(60);
    });

    it('US scores reasonably high', () => {
      const us = computeJurisdictionConfidence('US');
      expect(us!.score).toBeGreaterThanOrEqual(30);
    });

    it('breakdown fields are all non-negative', () => {
      const result = computeJurisdictionConfidence('GB');
      const b = result!.breakdown;
      expect(b.professionalBodyCoverage).toBeGreaterThanOrEqual(0);
      expect(b.publicRegisterAvailability).toBeGreaterThanOrEqual(0);
      expect(b.digitalCredentialIssuance).toBeGreaterThanOrEqual(0);
      expect(b.dataProtectionMaturity).toBeGreaterThanOrEqual(0);
      expect(b.mutualRecognition).toBeGreaterThanOrEqual(0);
      expect(b.eSignatureRecognition).toBeGreaterThanOrEqual(0);
      expect(b.legalSystemScore).toBeGreaterThanOrEqual(0);
    });

    it('breakdown fields sum to total score', () => {
      const result = computeJurisdictionConfidence('GB');
      const b = result!.breakdown;
      const sum =
        b.professionalBodyCoverage +
        b.publicRegisterAvailability +
        b.digitalCredentialIssuance +
        b.dataProtectionMaturity +
        b.mutualRecognition +
        b.eSignatureRecognition +
        b.legalSystemScore;
      // Score is min(sum, 100)
      expect(result!.score).toBe(Math.min(sum, 100));
    });

    it('eSignatureRecognition is 10 when recognised', () => {
      const gb = computeJurisdictionConfidence('GB');
      expect(gb!.breakdown.eSignatureRecognition).toBe(10);
    });

    it('common-law and civil-law jurisdictions get legal system score of 10', () => {
      const gb = computeJurisdictionConfidence('GB'); // common-law
      const fr = computeJurisdictionConfidence('FR'); // civil-law
      expect(gb!.breakdown.legalSystemScore).toBe(10);
      expect(fr!.breakdown.legalSystemScore).toBe(10);
    });

    it('mixed legal system jurisdictions get lower legal system score', () => {
      const za = computeJurisdictionConfidence('ZA'); // mixed
      expect(za!.breakdown.legalSystemScore).toBe(7);
    });
  });

  describe('getJurisdictionConfidence', () => {
    it('returns a number for GB', () => {
      const score = getJurisdictionConfidence('GB');
      expect(typeof score).toBe('number');
      expect(score).toBeGreaterThan(0);
    });

    it('returns 0 for unknown jurisdiction', () => {
      expect(getJurisdictionConfidence('XX')).toBe(0);
    });

    it('is case-insensitive', () => {
      expect(getJurisdictionConfidence('gb')).toBe(getJurisdictionConfidence('GB'));
    });
  });

  describe('rankJurisdictionsByConfidence', () => {
    it('returns all jurisdictions sorted by score descending', () => {
      const ranked = rankJurisdictionsByConfidence();
      expect(ranked.length).toBe(getJurisdictionCodes().length);

      // Verify descending order
      for (let i = 1; i < ranked.length; i++) {
        expect(ranked[i - 1].score).toBeGreaterThanOrEqual(ranked[i].score);
      }
    });

    it('first entry has the highest score', () => {
      const ranked = rankJurisdictionsByConfidence();
      const maxScore = Math.max(...ranked.map(r => r.score));
      expect(ranked[0].score).toBe(maxScore);
    });

    it('all entries have valid codes', () => {
      const ranked = rankJurisdictionsByConfidence();
      const codes = getJurisdictionCodes();
      for (const entry of ranked) {
        expect(codes).toContain(entry.code);
      }
    });
  });

  describe('all jurisdictions have valid confidence scores', () => {
    it('every jurisdiction produces a score between 0 and 100', () => {
      const codes = getJurisdictionCodes();
      for (const code of codes) {
        const result = computeJurisdictionConfidence(code);
        expect(result, `${code} should have confidence`).toBeDefined();
        expect(result!.score, `${code} score should be >= 0`).toBeGreaterThanOrEqual(0);
        expect(result!.score, `${code} score should be <= 100`).toBeLessThanOrEqual(100);
      }
    });
  });
});
