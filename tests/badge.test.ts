import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createSelfDeclaredCredential,
  createPeerVouchedCredential,
  createProfessionalCredential,
  createVouch,
  SIGNET_KINDS,
} from '../src/index.js';
import {
  computeBadge,
  getTrustLevel,
  meetsMinimumTier,
  filterEventsForPubkey,
  buildBadgeFilters,
} from '../src/badge.js';
import type { NostrEvent } from '../src/types.js';

describe('badge display (Level 1)', () => {
  describe('computeBadge', () => {
    it('returns unverified badge for no events', async () => {
      const kp = generateKeyPair();
      const badge = await computeBadge(kp.publicKey, []);

      expect(badge.pubkey).toBe(kp.publicKey);
      expect(badge.tier).toBe(1);
      expect(badge.score).toBe(0);
      expect(badge.isVerified).toBe(false);
      expect(badge.displayLabel).toBe('Unverified');
      expect(badge.credentialCount).toBe(0);
      expect(badge.vouchCount).toBe(0);
    });

    it('computes badge for Tier 1 (self-declared) credential', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      const badge = await computeBadge(kp.publicKey, [cred]);

      expect(badge.isVerified).toBe(true);
      expect(badge.tier).toBe(1);
      expect(badge.tierLabel).toBe('Self-declared');
      expect(badge.credentialCount).toBe(1);
      expect(badge.displayLabel).toBe('Self-declared (Tier 1)');
    });

    it('computes badge for Tier 2 (peer-vouched) credential', async () => {
      const issuer = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createPeerVouchedCredential(issuer.privateKey, subject.publicKey);
      const badge = await computeBadge(subject.publicKey, [cred]);

      expect(badge.isVerified).toBe(true);
      expect(badge.tier).toBe(2);
      expect(badge.tierLabel).toBe('Web-of-trust');
    });

    it('computes badge for Tier 3 (professional) credential', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createProfessionalCredential(
        verifier.privateKey,
        subject.publicKey,
        { profession: 'legal', jurisdiction: 'GB' }
      );
      const badge = await computeBadge(subject.publicKey, [cred]);

      expect(badge.isVerified).toBe(true);
      expect(badge.tier).toBe(3);
      expect(badge.tierLabel).toBe('Verified');
      expect(badge.score).toBeGreaterThan(0);
      expect(badge.displayLabel).toBe('Verified (Tier 3)');
    });

    it('uses highest tier when multiple credentials exist', async () => {
      const kp = generateKeyPair();
      const verifier = generateKeyPair();

      const cred1 = await createSelfDeclaredCredential(kp.privateKey);
      const cred3 = await createProfessionalCredential(
        verifier.privateKey,
        kp.publicKey,
        { profession: 'legal', jurisdiction: 'GB' }
      );

      const badge = await computeBadge(kp.publicKey, [cred1, cred3]);
      expect(badge.tier).toBe(3);
      expect(badge.credentialCount).toBe(2);
    });

    it('counts vouches', async () => {
      const subject = generateKeyPair();
      const voucher1 = generateKeyPair();
      const voucher2 = generateKeyPair();

      const cred = await createSelfDeclaredCredential(subject.privateKey);
      const vouch1 = await createVouch(voucher1.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'in-person',
        voucherTier: 2,
        voucherScore: 50,
      });
      const vouch2 = await createVouch(voucher2.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'online',
        voucherTier: 1,
        voucherScore: 30,
      });

      const badge = await computeBadge(subject.publicKey, [cred, vouch1, vouch2]);
      expect(badge.vouchCount).toBe(2);
      expect(badge.score).toBeGreaterThan(0);
    });

    it('deduplicates vouches from same voucher', async () => {
      const subject = generateKeyPair();
      const voucher = generateKeyPair();

      const vouch1 = await createVouch(voucher.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'in-person',
        voucherTier: 2,
        voucherScore: 50,
      });
      const vouch2 = await createVouch(voucher.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'online',
        voucherTier: 2,
        voucherScore: 50,
      });

      const badge = await computeBadge(subject.publicKey, [vouch1, vouch2]);
      expect(badge.vouchCount).toBe(1);
    });

    it('ignores expired credentials', async () => {
      const kp = generateKeyPair();
      const past = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      const cred = await createSelfDeclaredCredential(kp.privateKey, 'adult', past);
      const badge = await computeBadge(kp.publicKey, [cred]);

      expect(badge.isVerified).toBe(false);
      expect(badge.credentialCount).toBe(0);
    });

    it('ignores events for other pubkeys', async () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp2.privateKey);
      const badge = await computeBadge(kp1.publicKey, [cred]);

      expect(badge.isVerified).toBe(false);
    });
  });

  describe('getTrustLevel', () => {
    it('returns unverified for empty badge', async () => {
      const kp = generateKeyPair();
      const badge = await computeBadge(kp.publicKey, []);
      expect(getTrustLevel(badge)).toBe('unverified');
    });

    it('returns self-declared for Tier 1', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      const badge = await computeBadge(kp.publicKey, [cred]);
      expect(getTrustLevel(badge)).toBe('self-declared');
    });

    it('returns professional for Tier 3', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createProfessionalCredential(
        verifier.privateKey,
        subject.publicKey,
        { profession: 'legal', jurisdiction: 'GB' }
      );
      const badge = await computeBadge(subject.publicKey, [cred]);
      expect(getTrustLevel(badge)).toBe('professional');
    });
  });

  describe('meetsMinimumTier', () => {
    it('returns false for unverified user at any tier', async () => {
      const kp = generateKeyPair();
      const badge = await computeBadge(kp.publicKey, []);
      expect(meetsMinimumTier(badge, 1)).toBe(false);
    });

    it('returns true when tier meets minimum', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createProfessionalCredential(
        verifier.privateKey,
        subject.publicKey,
        { profession: 'legal', jurisdiction: 'GB' }
      );
      const badge = await computeBadge(subject.publicKey, [cred]);
      expect(meetsMinimumTier(badge, 1)).toBe(true);
      expect(meetsMinimumTier(badge, 2)).toBe(true);
      expect(meetsMinimumTier(badge, 3)).toBe(true);
      expect(meetsMinimumTier(badge, 4)).toBe(false);
    });
  });

  describe('filterEventsForPubkey', () => {
    it('filters to only credential and vouch events for the pubkey', async () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();

      const cred1 = await createSelfDeclaredCredential(kp1.privateKey);
      const cred2 = await createSelfDeclaredCredential(kp2.privateKey);

      const filtered = filterEventsForPubkey(kp1.publicKey, [cred1, cred2]);
      expect(filtered).toHaveLength(1);
      expect(filtered[0]).toBe(cred1);
    });
  });

  describe('buildBadgeFilters', () => {
    it('creates filters for one pubkey', () => {
      const kp = generateKeyPair();
      const filters = buildBadgeFilters([kp.publicKey]);

      expect(filters).toHaveLength(1);
      expect(filters[0].kinds).toContain(SIGNET_KINDS.CREDENTIAL);
      expect(filters[0].kinds).toContain(SIGNET_KINDS.VOUCH);
      expect(filters[0]['#d']).toContain(kp.publicKey);
    });

    it('creates filters for multiple pubkeys', () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();
      const filters = buildBadgeFilters([kp1.publicKey, kp2.publicKey]);

      expect(filters[0]['#d']).toContain(kp1.publicKey);
      expect(filters[0]['#d']).toContain(kp2.publicKey);
    });
  });
});
