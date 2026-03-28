import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  getTagValue,
  createSelfDeclaredCredential,
  createPeerVouchedCredential,
  createProfessionalCredential,
  createChildSafetyCredential,
  parseCredential,
  createVouch,
  parseVouch,
  createPolicy,
  parsePolicy,
  createVerifierCredential,
  parseVerifier,
  createChallenge,
  parseChallenge,
  createRevocation,
  parseRevocation,
  createIdentityBridge,
  parseIdentityBridge,
  createGuardianDelegation,
  selectDecoyRing,
  DEFAULT_CRYPTO_ALGORITHM,
  ATTESTATION_KIND,
  ATTESTATION_TYPES,
  APP_DATA_KIND,
} from '../src/index.js';
import type { CryptoAlgorithm, NostrEvent } from '../src/index.js';
import { buildTier3Opts, generateKeypairs } from './fixtures.js';

describe('quantum readiness — algo tag', () => {
  describe('algo tag is present on all event kinds', () => {
    it('Tier 1 credential has algo tag', async () => {
      const kp = generateKeyPair();
      const event = await createSelfDeclaredCredential(kp.privateKey);
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('Tier 2 credential has algo tag', async () => {
      const issuer = generateKeyPair();
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const event = await createPeerVouchedCredential(issuer.privateKey, subject.publicKey, { assertionEventId: tier1.id });
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('Tier 3 credential has algo tag', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const event = await createProfessionalCredential(verifier.privateKey, subject.publicKey, await buildTier3Opts(subject.privateKey));
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('Tier 4 credential has algo tag', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const event = await createChildSafetyCredential(verifier.privateKey, subject.publicKey, {
        assertionEventId: tier1.id,
        profession: 'solicitor',
        jurisdiction: 'UK',
        ageRange: '8-12',
      });
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('vouch has algo tag', async () => {
      const voucher = generateKeyPair();
      const subject = generateKeyPair();
      const event = await createVouch(voucher.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'in-person',
        voucherTier: 3,
        voucherScore: 120,
      });
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('policy has algo tag', async () => {
      const operator = generateKeyPair();
      const event = await createPolicy(operator.privateKey, {
        communityId: 'test-community',
        adultMinTier: 2,
        childMinTier: 4,
        enforcement: 'client',
      });
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('verifier credential has algo tag', async () => {
      const kp = generateKeyPair();
      const event = await createVerifierCredential(kp.privateKey, {
        profession: 'solicitor',
        jurisdiction: 'UK',
        licenceHash: 'abc123',
        professionalBody: 'Law Society',
      });
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('challenge has algo tag', async () => {
      const reporter = generateKeyPair();
      const target = generateKeyPair();
      const event = await createChallenge(reporter.privateKey, {
        verifierPubkey: target.publicKey,
        reason: 'registry-mismatch',
        evidenceType: 'document',
        reporterTier: 3,
        evidence: 'test evidence',
      });
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('revocation has algo tag', async () => {
      const authority = generateKeyPair();
      const target = generateKeyPair();
      const event = await createRevocation(authority.privateKey, {
        verifierPubkey: target.publicKey,
        challengeEventId: 'challenge123',
        confirmations: 5,
        bondAction: 'slashed',
        scope: 'full',
        effectiveAt: Math.floor(Date.now() / 1000),
        summary: 'Revoked for test',
      });
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('identity bridge has algo tag', async () => {
      const anon = generateKeyPair();
      const real = generateKeyPair();
      const decoys = generateKeypairs(4).map(kp => kp.publicKey);
      const { ring, signerIndex } = selectDecoyRing(decoys, real.publicKey, 5);
      const event = await createIdentityBridge(anon.privateKey, real.privateKey, ring, signerIndex, 3);
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });

    it('guardian delegation has algo tag', async () => {
      const guardian = generateKeyPair();
      const child = generateKeyPair();
      const delegate = generateKeyPair();
      const event = await createGuardianDelegation(guardian.privateKey, {
        childPubkey: child.publicKey,
        delegatePubkey: delegate.publicKey,
        scope: 'full',
      });
      expect(getTagValue(event, 'algo')).toBe('secp256k1');
    });
  });

  describe('parsers extract algorithm', () => {
    it('parseCredential returns algorithm', async () => {
      const kp = generateKeyPair();
      const event = await createSelfDeclaredCredential(kp.privateKey);
      const parsed = parseCredential(event);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });

    it('parseVouch returns algorithm', async () => {
      const voucher = generateKeyPair();
      const subject = generateKeyPair();
      const event = await createVouch(voucher.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'in-person',
        voucherTier: 3,
        voucherScore: 120,
      });
      const parsed = parseVouch(event);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });

    it('parsePolicy returns algorithm', async () => {
      const operator = generateKeyPair();
      const event = await createPolicy(operator.privateKey, {
        communityId: 'test-community',
        adultMinTier: 2,
        childMinTier: 4,
        enforcement: 'client',
      });
      const parsed = parsePolicy(event);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });

    it('parseVerifier returns algorithm', async () => {
      const kp = generateKeyPair();
      const event = await createVerifierCredential(kp.privateKey, {
        profession: 'solicitor',
        jurisdiction: 'UK',
        licenceHash: 'abc123',
        professionalBody: 'Law Society',
      });
      const parsed = parseVerifier(event);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });

    it('parseChallenge returns algorithm', async () => {
      const reporter = generateKeyPair();
      const target = generateKeyPair();
      const event = await createChallenge(reporter.privateKey, {
        verifierPubkey: target.publicKey,
        reason: 'registry-mismatch',
        evidenceType: 'document',
        reporterTier: 3,
        evidence: 'test evidence',
      });
      const parsed = parseChallenge(event);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });

    it('parseRevocation returns algorithm', async () => {
      const authority = generateKeyPair();
      const target = generateKeyPair();
      const event = await createRevocation(authority.privateKey, {
        verifierPubkey: target.publicKey,
        challengeEventId: 'challenge123',
        confirmations: 5,
        bondAction: 'slashed',
        scope: 'full',
        effectiveAt: Math.floor(Date.now() / 1000),
        summary: 'Revoked for test',
      });
      const parsed = parseRevocation(event);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });

    it('parseIdentityBridge returns algorithm', async () => {
      const anon = generateKeyPair();
      const real = generateKeyPair();
      const decoys = generateKeypairs(4).map(kp => kp.publicKey);
      const { ring, signerIndex } = selectDecoyRing(decoys, real.publicKey, 5);
      const event = await createIdentityBridge(anon.privateKey, real.privateKey, ring, signerIndex, 3);
      const parsed = parseIdentityBridge(event);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });
  });

  describe('legacy events default to secp256k1', () => {
    it('event without algo tag defaults to secp256k1 in parser', () => {
      // Simulate a legacy event (pre-quantum-readiness) with no algo tag
      const legacyEvent: NostrEvent = {
        id: 'legacy-id',
        sig: 'legacy-sig',
        kind: ATTESTATION_KIND,
        pubkey: 'aabbccdd',
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['d', 'credential:subject-pubkey'],
          ['tier', '1'],
          ['type', 'credential'],
          ['verification-type', 'self'],
          ['scope', 'adult'],
          ['method', 'self-declaration'],
          ['expiration', String(Math.floor(Date.now() / 1000) + 86400)],
          ['L', 'signet'],
          ['l', 'verification', 'signet'],
          // No ['algo', ...] tag — legacy event
        ],
        content: '',
      };

      const parsed = parseCredential(legacyEvent);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });

    it('legacy vouch defaults to secp256k1', () => {
      const legacyVouch: NostrEvent = {
        id: 'legacy-vouch-id',
        sig: 'legacy-sig',
        kind: ATTESTATION_KIND,
        pubkey: 'aabbccdd',
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['d', 'vouch:subject-pubkey'],
          ['p', 'subject-pubkey'],
          ['type', 'vouch'],
          ['method', 'in-person'],
          ['voucher-tier', '3'],
          ['voucher-score', '120'],
          ['L', 'signet'],
          ['l', 'vouch', 'signet'],
        ],
        content: '',
      };

      const parsed = parseVouch(legacyVouch);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('secp256k1');
    });
  });

  describe('future algorithm value is preserved', () => {
    it('parser preserves a non-secp256k1 algorithm tag', () => {
      const futureEvent: NostrEvent = {
        id: 'future-id',
        sig: 'future-sig',
        kind: ATTESTATION_KIND,
        pubkey: 'aabbccdd',
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['d', 'credential:subject-pubkey'],
          ['tier', '3'],
          ['type', 'credential'],
          ['verification-type', 'professional'],
          ['scope', 'adult'],
          ['method', 'in-person-id'],
          ['expiration', String(Math.floor(Date.now() / 1000) + 86400)],
          ['algo', 'ml-kem-768'],
          ['L', 'signet'],
          ['l', 'verification', 'signet'],
        ],
        content: '',
      };

      const parsed = parseCredential(futureEvent);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('ml-kem-768');
    });

    it('future algo is preserved in vouch parser', () => {
      const futureVouch: NostrEvent = {
        id: 'future-vouch-id',
        sig: 'future-sig',
        kind: ATTESTATION_KIND,
        pubkey: 'aabbccdd',
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['d', 'vouch:subject-pubkey'],
          ['p', 'subject-pubkey'],
          ['type', 'vouch'],
          ['method', 'in-person'],
          ['voucher-tier', '3'],
          ['voucher-score', '120'],
          ['algo', 'ml-dsa-65'],
          ['L', 'signet'],
          ['l', 'vouch', 'signet'],
        ],
        content: '',
      };

      const parsed = parseVouch(futureVouch);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('ml-dsa-65');
    });

    it('future algo is preserved in policy parser', () => {
      const futurePolicy: NostrEvent = {
        id: 'future-policy-id',
        sig: 'future-sig',
        kind: APP_DATA_KIND,
        pubkey: 'aabbccdd',
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['d', 'signet:policy:test-community'],
          ['adult-min-tier', '2'],
          ['child-min-tier', '4'],
          ['enforcement', 'client'],
          ['algo', 'slh-dsa-128s'],
        ],
        content: '',
      };

      const parsed = parsePolicy(futurePolicy);
      expect(parsed).not.toBeNull();
      expect(parsed!.algorithm).toBe('slh-dsa-128s');
    });
  });

  describe('DEFAULT_CRYPTO_ALGORITHM constant', () => {
    it('is secp256k1', () => {
      expect(DEFAULT_CRYPTO_ALGORITHM).toBe('secp256k1');
    });

    it('satisfies CryptoAlgorithm type', () => {
      const algo: CryptoAlgorithm = DEFAULT_CRYPTO_ALGORITHM;
      expect(algo).toBe('secp256k1');
    });
  });
});
