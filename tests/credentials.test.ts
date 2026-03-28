import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createSelfDeclaredCredential,
  createPeerVouchedCredential,
  createProfessionalCredential,
  createChildSafetyCredential,
  createGuardianDelegation,
  verifyCredential,
  isCredentialExpired,
  parseCredential,
  getTagValue,
  ATTESTATION_KIND,
  ATTESTATION_TYPES,
} from '../src/index.js';
import { buildTier3Opts } from './fixtures.js';

describe('credentials', () => {
  describe('Tier 1 — Self-Declared', () => {
    it('creates a valid self-declared credential', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);

      expect(cred.kind).toBe(ATTESTATION_KIND);
      expect(cred.pubkey).toBe(kp.publicKey);
      expect(getTagValue(cred, 'tier')).toBe('1');
      expect(getTagValue(cred, 'type')).toBe(ATTESTATION_TYPES.CREDENTIAL);
      expect(getTagValue(cred, 'verification-type')).toBe('self');
      expect(getTagValue(cred, 'scope')).toBe('adult');
      expect(getTagValue(cred, 'd')).toBe(`credential:${kp.publicKey}`); // direct claim (self-issued)
      // Tier 1 must NOT have an assertion reference
      const eTag = cred.tags.find(t => t[0] === 'e' && t[3] === 'assertion');
      expect(eTag).toBeUndefined();
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
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const cred = await createPeerVouchedCredential(issuer.privateKey, subject.publicKey, { assertionEventId: tier1.id });

      expect(cred.kind).toBe(ATTESTATION_KIND);
      expect(getTagValue(cred, 'tier')).toBe('2');
      expect(getTagValue(cred, 'type')).toBe(ATTESTATION_TYPES.CREDENTIAL);
      expect(getTagValue(cred, 'verification-type')).toBe('peer');
      expect(getTagValue(cred, 'd')).toBe(`assertion:${tier1.id}`);
      expect(getTagValue(cred, 'p')).toBe(subject.publicKey);
    });

    it('passes verification', async () => {
      const issuer = generateKeyPair();
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const cred = await createPeerVouchedCredential(issuer.privateKey, subject.publicKey, { assertionEventId: tier1.id });
      const result = await verifyCredential(cred);

      expect(result.signatureValid).toBe(true);
      expect(result.structureValid).toBe(true);
    });
  });

  describe('Tier 3 — Professional Verified', () => {
    it('creates a valid professional credential', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const tier3Opts = await buildTier3Opts(subject.privateKey);
      const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, tier3Opts);

      expect(getTagValue(cred, 'tier')).toBe('3');
      expect(getTagValue(cred, 'type')).toBe(ATTESTATION_TYPES.CREDENTIAL);
      expect(getTagValue(cred, 'verification-type')).toBe('professional');
      expect(getTagValue(cred, 'scope')).toBe('adult');
      expect(getTagValue(cred, 'profession')).toBe('solicitor');
      expect(getTagValue(cred, 'jurisdiction')).toBe('UK');
      expect(getTagValue(cred, 'method')).toBe('in-person-id');
    });

    it('uses assertion-first hybrid pattern (d-tag + e-tag with assertion marker)', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, {
        assertionEventId: tier1.id,
        profession: 'solicitor',
        jurisdiction: 'GB',
      });

      // d-tag uses assertion: prefix (assertion-first)
      expect(getTagValue(cred, 'd')).toBe(`assertion:${tier1.id}`);
      // e-tag has assertion marker referencing Tier 1
      const eTag = cred.tags.find(t => t[0] === 'e' && t[3] === 'assertion');
      expect(eTag).toBeDefined();
      expect(eTag![1]).toBe(tier1.id);
      // type tag still present (hybrid pattern for relay filtering)
      expect(getTagValue(cred, 'type')).toBe(ATTESTATION_TYPES.CREDENTIAL);
      // p-tag has the subject
      expect(getTagValue(cred, 'p')).toBe(subject.publicKey);
    });

    it('passes verification', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const tier3Opts = await buildTier3Opts(subject.privateKey);
      const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, tier3Opts);
      const result = await verifyCredential(cred);

      expect(result.signatureValid).toBe(true);
      expect(result.structureValid).toBe(true);
    });
  });

  describe('Tier 4 — Child Safety', () => {
    it('creates a valid child safety credential', async () => {
      const verifier = generateKeyPair();
      const parent = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(parent.privateKey);
      const cred = await createChildSafetyCredential(verifier.privateKey, parent.publicKey, {
        assertionEventId: tier1.id,
        profession: 'notary',
        jurisdiction: 'US',
        ageRange: '8-12',
      });

      expect(getTagValue(cred, 'tier')).toBe('4');
      expect(getTagValue(cred, 'type')).toBe(ATTESTATION_TYPES.CREDENTIAL);
      expect(getTagValue(cred, 'verification-type')).toBe('professional');
      expect(getTagValue(cred, 'scope')).toBe('adult+child');
      expect(getTagValue(cred, 'age-range')).toBe('8-12');
      expect(getTagValue(cred, 'profession')).toBe('notary');
    });

    it('passes verification', async () => {
      const verifier = generateKeyPair();
      const parent = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(parent.privateKey);
      const cred = await createChildSafetyCredential(verifier.privateKey, parent.publicKey, {
        assertionEventId: tier1.id,
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
      const tier1 = await createSelfDeclaredCredential(parent.privateKey);
      const cred = await createChildSafetyCredential(verifier.privateKey, parent.publicKey, {
        assertionEventId: tier1.id,
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

    it('treats NaN expiration as expired', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      // Replace the valid expiration tag with a NaN value
      cred.tags = cred.tags.filter(t => t[0] !== 'expiration');
      cred.tags.push(['expiration', 'not-a-number']);
      expect(isCredentialExpired(cred)).toBe(true);
    });
  });

  describe('verifyCredential — expiration edge cases', () => {
    it('treats NaN expiration as expired', async () => {
      const kp = generateKeyPair();
      const cred = await createSelfDeclaredCredential(kp.privateKey);
      cred.tags = cred.tags.filter(t => t[0] !== 'expiration');
      cred.tags.push(['expiration', 'garbage']);
      const result = await verifyCredential(cred);
      expect(result.expired).toBe(true);
    });
  });

  it('has NIP-VA discoverability labels (not manual signet labels)', async () => {
    const verifier = generateKeyPair();
    const subject = generateKeyPair();
    const tier3Opts = await buildTier3Opts(subject.privateKey, { jurisdiction: 'GB' });
    const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, tier3Opts);
    expect(getTagValue(cred, 'L')).toBe('nip-va');
    const lTag = cred.tags.find(t => t[0] === 'l' && t[2] === 'nip-va');
    expect(lTag).toBeDefined();
    expect(lTag![1]).toBe('credential');
    const signetL = cred.tags.find(t => t[0] === 'l' && t[2] === 'signet');
    expect(signetL).toBeUndefined();
  });

  it('guardian delegation includes occurredAt when provided', async () => {
    const guardian = generateKeyPair();
    const delegate = generateKeyPair();
    const child = generateKeyPair();
    const delegationTime = Math.floor(Date.now() / 1000) - 1800;

    const event = await createGuardianDelegation(guardian.privateKey, {
      childPubkey: child.publicKey,
      delegatePubkey: delegate.publicKey,
      scope: 'activity-approval',
      expiresAt: Math.floor(Date.now() / 1000) + 86400,
      occurredAt: delegationTime,
    });

    expect(getTagValue(event, 'occurred_at')).toBe(String(delegationTime));
  });
});
