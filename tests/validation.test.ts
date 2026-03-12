import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createSelfDeclaredCredential,
  createPeerVouchedCredential,
  createChildSafetyCredential,
  createVouch,
  createPolicy,
  createVerifierCredential,
  createChallenge,
  createRevocation,
  validateEvent,
  validateCredential,
  validateVouch,
  SIGNET_KINDS,
} from '../src/index.js';
import { validateFieldSizeBounds } from '../src/validation.js';

describe('validation', () => {
  describe('validateEvent', () => {
    it('validates a Tier 1 credential', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      const result = validateEvent(cred);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('validates a vouch', async () => {
      const voucher = generateKeyPair();
      const subject = generateKeyPair();
      const vouch = await createVouch(voucher.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'in-person',
        voucherTier: 2,
        voucherScore: 50,
      });
      const result = validateEvent(vouch);
      expect(result.valid).toBe(true);
    });

    it('validates a policy', async () => {
      const op = generateKeyPair();
      const policy = await createPolicy(op.privateKey, {
        communityId: 'test',
        adultMinTier: 2,
        childMinTier: 3,
        enforcement: 'client',
      });
      const result = validateEvent(policy);
      expect(result.valid).toBe(true);
    });

    it('validates a verifier credential', async () => {
      const v = generateKeyPair();
      const cred = await createVerifierCredential(v.privateKey, {
        profession: 'solicitor',
        jurisdiction: 'UK',
        licenceHash: 'hash123',
        professionalBody: 'Law Society',
      });
      const result = validateEvent(cred);
      expect(result.valid).toBe(true);
    });

    it('validates a challenge', async () => {
      const reporter = generateKeyPair();
      const verifier = generateKeyPair();
      const challenge = await createChallenge(reporter.privateKey, {
        verifierPubkey: verifier.publicKey,
        reason: 'anomalous-volume',
        evidenceType: 'data',
        reporterTier: 3,
        evidence: 'Evidence here',
      });
      const result = validateEvent(challenge);
      expect(result.valid).toBe(true);
    });

    it('validates a revocation', async () => {
      const auth = generateKeyPair();
      const verifier = generateKeyPair();
      const revocation = await createRevocation(auth.privateKey, {
        verifierPubkey: verifier.publicKey,
        challengeEventId: 'ch1',
        confirmations: 5,
        bondAction: 'slashed',
        scope: 'full',
        effectiveAt: Math.floor(Date.now() / 1000),
        summary: 'Confirmed fraud',
      });
      const result = validateEvent(revocation);
      expect(result.valid).toBe(true);
    });

    it('rejects unknown kinds', () => {
      const result = validateEvent({
        id: 'a'.repeat(64),
        sig: 'b'.repeat(128),
        kind: 99999,
        pubkey: 'c'.repeat(64),
        created_at: 0,
        tags: [],
        content: '',
      });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Unknown');
    });
  });

  describe('credential tier validation', () => {
    it('rejects Tier 1 with wrong type', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      // Tamper: change type to professional
      const tampered = {
        ...cred,
        tags: cred.tags.map((t) =>
          t[0] === 'type' ? ['type', 'professional'] : t
        ),
      };
      const result = validateCredential(tampered);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('Tier 1'))).toBe(true);
    });

    it('rejects Tier 4 without age-range', async () => {
      const verifier = generateKeyPair();
      const parent = generateKeyPair();
      const cred = await createChildSafetyCredential(verifier.privateKey, parent.publicKey, {
        profession: 'notary',
        jurisdiction: 'US',
        ageRange: '8-12',
      });
      // Remove age-range tag
      const tampered = {
        ...cred,
        tags: cred.tags.filter((t) => t[0] !== 'age-range'),
      };
      const result = validateCredential(tampered);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('age-range'))).toBe(true);
    });
  });

  describe('field-size bounds', () => {
    it('rejects tag values beyond index 1 that exceed max length', () => {
      const longValue = 'x'.repeat(1025);
      const errors: string[] = [];
      validateFieldSizeBounds({
        id: 'a'.repeat(64),
        sig: 'b'.repeat(128),
        kind: 30470,
        pubkey: 'c'.repeat(64),
        created_at: 0,
        tags: [['result', 'option-a', longValue]],
        content: '',
      }, errors);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('index 2');
    });

    it('accepts tag values at all indices within bounds', () => {
      const okValue = 'x'.repeat(1024);
      const errors: string[] = [];
      validateFieldSizeBounds({
        id: 'a'.repeat(64),
        sig: 'b'.repeat(128),
        kind: 30470,
        pubkey: 'c'.repeat(64),
        created_at: 0,
        tags: [['result', okValue, okValue, okValue]],
        content: '',
      }, errors);
      expect(errors).toHaveLength(0);
    });
  });

  describe('vouch validation', () => {
    it('rejects self-vouching', async () => {
      const kp = generateKeyPair();
      const vouch = await createVouch(kp.privateKey, {
        subjectPubkey: kp.publicKey, // self-vouch
        method: 'in-person',
        voucherTier: 2,
        voucherScore: 50,
      });
      const result = validateVouch(vouch);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('yourself'))).toBe(true);
    });
  });
});
