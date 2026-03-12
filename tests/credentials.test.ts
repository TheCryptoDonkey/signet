import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createSelfDeclaredCredential,
  createPeerVouchedCredential,
  createProfessionalCredential,
  createChildSafetyCredential,
  verifyCredential,
  isCredentialExpired,
  parseCredential,
  getTagValue,
  SIGNET_KINDS,
} from '../src/index.js';
import { TIER3_OPTS } from './fixtures.js';

describe('credentials', () => {
  describe('Tier 1 — Self-Declared', () => {
    it('creates a valid self-declared credential', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);

      expect(cred.kind).toBe(SIGNET_KINDS.CREDENTIAL);
      expect(cred.pubkey).toBe(kp.publicKey);
      expect(getTagValue(cred, 'tier')).toBe('1');
      expect(getTagValue(cred, 'type')).toBe('self');
      expect(getTagValue(cred, 'scope')).toBe('adult');
      expect(getTagValue(cred, 'd')).toBe(kp.publicKey); // self-issued
    });

    it('passes verification', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      const result = await verifyCredential(cred);

      expect(result.signatureValid).toBe(true);
      expect(result.structureValid).toBe(true);
      expect(result.expired).toBe(false);
    });
  });

  describe('Tier 2 — Peer Vouched', () => {
    it('creates a valid peer vouched credential', async () => {
      const issuer = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createPeerVouchedCredential(issuer.privateKey, subject.publicKey);

      expect(cred.kind).toBe(SIGNET_KINDS.CREDENTIAL);
      expect(getTagValue(cred, 'tier')).toBe('2');
      expect(getTagValue(cred, 'type')).toBe('peer');
      expect(getTagValue(cred, 'd')).toBe(subject.publicKey);
    });

    it('passes verification', async () => {
      const issuer = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createPeerVouchedCredential(issuer.privateKey, subject.publicKey);
      const result = await verifyCredential(cred);

      expect(result.signatureValid).toBe(true);
      expect(result.structureValid).toBe(true);
    });
  });

  describe('Tier 3 — Professional Verified', () => {
    it('creates a valid professional credential', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, TIER3_OPTS);

      expect(getTagValue(cred, 'tier')).toBe('3');
      expect(getTagValue(cred, 'type')).toBe('professional');
      expect(getTagValue(cred, 'scope')).toBe('adult');
      expect(getTagValue(cred, 'profession')).toBe('solicitor');
      expect(getTagValue(cred, 'jurisdiction')).toBe('UK');
      expect(getTagValue(cred, 'method')).toBe('in-person-id');
    });

    it('passes verification', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, TIER3_OPTS);
      const result = await verifyCredential(cred);

      expect(result.signatureValid).toBe(true);
      expect(result.structureValid).toBe(true);
    });
  });

  describe('Tier 4 — Child Safety', () => {
    it('creates a valid child safety credential', async () => {
      const verifier = generateKeyPair();
      const parent = generateKeyPair();
      const cred = await createChildSafetyCredential(verifier.privateKey, parent.publicKey, {
        profession: 'notary',
        jurisdiction: 'US',
        ageRange: '8-12',
      });

      expect(getTagValue(cred, 'tier')).toBe('4');
      expect(getTagValue(cred, 'type')).toBe('professional');
      expect(getTagValue(cred, 'scope')).toBe('adult+child');
      expect(getTagValue(cred, 'age-range')).toBe('8-12');
      expect(getTagValue(cred, 'profession')).toBe('notary');
    });

    it('passes verification', async () => {
      const verifier = generateKeyPair();
      const parent = generateKeyPair();
      const cred = await createChildSafetyCredential(verifier.privateKey, parent.publicKey, {
        profession: 'notary',
        jurisdiction: 'US',
        ageRange: '8-12',
      });
      const result = await verifyCredential(cred);

      expect(result.signatureValid).toBe(true);
      expect(result.structureValid).toBe(true);
    });
  });

  describe('parseCredential', () => {
    it('parses all fields from a Tier 4 credential', async () => {
      const verifier = generateKeyPair();
      const parent = generateKeyPair();
      const cred = await createChildSafetyCredential(verifier.privateKey, parent.publicKey, {
        profession: 'doctor',
        jurisdiction: 'AU',
        ageRange: '5-7',
      });

      const parsed = parseCredential(cred);
      expect(parsed).not.toBeNull();
      expect(parsed!.tier).toBe(4);
      expect(parsed!.type).toBe('professional');
      expect(parsed!.scope).toBe('adult+child');
      expect(parsed!.ageRange).toBe('5-7');
      expect(parsed!.profession).toBe('doctor');
      expect(parsed!.jurisdiction).toBe('AU');
      expect(parsed!.subjectPubkey).toBe(parent.publicKey);
    });
  });

  describe('isCredentialExpired', () => {
    it('returns false for non-expired credentials', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      expect(isCredentialExpired(cred)).toBe(false);
    });

    it('returns true for expired credentials', async () => {
      const kp = generateKeyPair();
      const pastTime = Math.floor(Date.now() / 1000) - 1000;
      const cred = await createSelfDeclaredCredential(kp.privateKey, 'adult', pastTime);
      expect(isCredentialExpired(cred)).toBe(true);
    });

    it('treats NaN expires as expired', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      // Replace the valid expires tag with a NaN value
      cred.tags = cred.tags.filter(t => t[0] !== 'expires');
      cred.tags.push(['expires', 'not-a-number']);
      expect(isCredentialExpired(cred)).toBe(true);
    });
  });

  describe('verifyCredential — expires edge cases', () => {
    it('treats NaN expires as expired', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      cred.tags = cred.tags.filter(t => t[0] !== 'expires');
      cred.tags.push(['expires', 'garbage']);
      const result = await verifyCredential(cred);
      expect(result.expired).toBe(true);
    });
  });
});
