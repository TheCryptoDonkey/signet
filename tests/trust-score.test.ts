import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createProfessionalCredential,
  createVouch,
  computeTrustScore,
  formatTrustDisplay,
  verifySignalOrdering,
} from '../src/index.js';

describe('trust-score', () => {
  it('computes score for professional verification', async () => {
    const verifier = generateKeyPair();
    const subject = generateKeyPair();

    const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, {
      profession: 'solicitor',
      jurisdiction: 'UK',
    });

    const breakdown = computeTrustScore(subject.publicKey, [cred], []);

    expect(breakdown.score).toBeGreaterThan(0);
    expect(breakdown.tier).toBe(3);
    expect(breakdown.professionalVerifications).toBe(1);
    expect(breakdown.signals).toHaveLength(1);
    expect(breakdown.signals[0].type).toBe('professional-verification');
  });

  it('computes score from vouches', async () => {
    const subject = generateKeyPair();
    const voucher1 = generateKeyPair();
    const voucher2 = generateKeyPair();

    const vouches = await Promise.all([
      createVouch(voucher1.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'in-person',
        voucherTier: 3,
        voucherScore: 80,
      }),
      createVouch(voucher2.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'online',
        voucherTier: 2,
        voucherScore: 50,
      }),
    ]);

    const breakdown = computeTrustScore(subject.publicKey, [], vouches);

    expect(breakdown.score).toBeGreaterThan(0);
    expect(breakdown.inPersonVouches).toBe(1);
    expect(breakdown.onlineVouches).toBe(1);
  });

  it('includes account age in score', async () => {
    const subject = generateKeyPair();
    const twoYearsAgo = Math.floor(Date.now() / 1000) - 2 * 365 * 24 * 60 * 60;

    const breakdown = computeTrustScore(subject.publicKey, [], [], twoYearsAgo);

    expect(breakdown.score).toBeGreaterThan(0);
    expect(breakdown.accountAgeDays).toBeGreaterThan(700);
    expect(breakdown.signals.some((s) => s.type === 'account-age')).toBe(true);
  });

  it('combines all signals', async () => {
    const verifier = generateKeyPair();
    const subject = generateKeyPair();
    const voucher = generateKeyPair();

    const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, {
      profession: 'solicitor',
      jurisdiction: 'UK',
    });

    const vouch = await createVouch(voucher.privateKey, {
      subjectPubkey: subject.publicKey,
      method: 'in-person',
      voucherTier: 3,
      voucherScore: 90,
    });

    const oneYearAgo = Math.floor(Date.now() / 1000) - 365 * 24 * 60 * 60;
    const breakdown = computeTrustScore(subject.publicKey, [cred], [vouch], oneYearAgo);

    expect(breakdown.score).toBeGreaterThan(80);
    expect(breakdown.professionalVerifications).toBe(1);
    expect(breakdown.inPersonVouches).toBe(1);
    expect(breakdown.accountAgeDays).toBeGreaterThan(360);
  });

  it('caps at 200', async () => {
    const verifier = generateKeyPair();
    const subject = generateKeyPair();

    // Create many professional verifications
    const creds = await Promise.all(
      Array.from({ length: 5 }, () => {
        const v = generateKeyPair();
        return createProfessionalCredential(v.privateKey, subject.publicKey, {
          profession: 'solicitor',
          jurisdiction: 'UK',
        });
      })
    );

    const vouches = await Promise.all(
      Array.from({ length: 20 }, () => {
        const v = generateKeyPair();
        return createVouch(v.privateKey, {
          subjectPubkey: subject.publicKey,
          method: 'in-person',
          voucherTier: 3,
          voucherScore: 95,
        });
      })
    );

    const breakdown = computeTrustScore(subject.publicKey, creds, vouches);
    expect(breakdown.score).toBeLessThanOrEqual(200);
  });

  it('deduplicates vouches from same person', async () => {
    const subject = generateKeyPair();
    const voucher = generateKeyPair();

    const vouches = await Promise.all([
      createVouch(voucher.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'in-person',
        voucherTier: 3,
        voucherScore: 90,
      }),
      createVouch(voucher.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'online',
        voucherTier: 3,
        voucherScore: 90,
      }),
    ]);

    const breakdown = computeTrustScore(subject.publicKey, [], vouches);
    expect(breakdown.inPersonVouches + breakdown.onlineVouches).toBe(1);
  });

  describe('formatTrustDisplay', () => {
    it('formats tier 3 display correctly', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();

      const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, {
        profession: 'solicitor',
        jurisdiction: 'UK',
      });

      const breakdown = computeTrustScore(subject.publicKey, [cred], []);
      const display = formatTrustDisplay(breakdown);

      expect(display).toContain('Tier 3');
      expect(display).toContain('Professional');
      expect(display).toContain('Prof verified');
    });
  });

  describe('verifySignalOrdering', () => {
    it('validates correct ordering', () => {
      const signals = [
        { type: 'professional-verification' as const, weight: 80 },
        { type: 'in-person-vouch' as const, weight: 16 },
        { type: 'online-vouch' as const, weight: 4 },
        { type: 'account-age' as const, weight: 10 },
      ];
      expect(verifySignalOrdering(signals)).toBe(true);
    });
  });
});
