import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createChallenge,
  parseChallenge,
  createRevocation,
  parseRevocation,
  hasReachedRevocationThreshold,
  countChallengeConfirmations,
  createProfessionalCredential,
  verifyEvent,
  getTagValue,
  ATTESTATION_KIND,
  ATTESTATION_TYPES,
} from '../src/index.js';
import type { NostrEvent } from '../src/types.js';
import { TIER3_OPTS } from './fixtures.js';

describe('challenges', () => {
  it('creates a valid challenge event', async () => {
    const reporter = generateKeyPair();
    const verifier = generateKeyPair();

    const challenge = await createChallenge(reporter.privateKey, {
      verifierPubkey: verifier.publicKey,
      reason: 'anomalous-volume',
      evidenceType: 'issuance-data',
      reporterTier: 3,
      evidence: 'Issued 200 verifications in one week',
    });

    expect(challenge.kind).toBe(ATTESTATION_KIND);
    expect(challenge.pubkey).toBe(reporter.publicKey);
    expect(getTagValue(challenge, 'type')).toBe(ATTESTATION_TYPES.CHALLENGE);
    expect(getTagValue(challenge, 'd')).toBe(`challenge:${verifier.publicKey}`);
    expect(getTagValue(challenge, 'reason')).toBe('anomalous-volume');
    expect(getTagValue(challenge, 'evidence-type')).toBe('issuance-data');
    expect(getTagValue(challenge, 'reporter-tier')).toBe('3');
    expect(challenge.content).toBe('Issued 200 verifications in one week');

    const valid = await verifyEvent(challenge);
    expect(valid).toBe(true);
  });

  describe('parseChallenge', () => {
    it('parses challenge fields', async () => {
      const reporter = generateKeyPair();
      const verifier = generateKeyPair();

      const challenge = await createChallenge(reporter.privateKey, {
        verifierPubkey: verifier.publicKey,
        reason: 'registry-mismatch',
        evidenceType: 'registry-screenshot',
        reporterTier: 3,
        evidence: 'Licence number not found',
      });

      const parsed = parseChallenge(challenge);
      expect(parsed).not.toBeNull();
      expect(parsed!.verifierPubkey).toBe(verifier.publicKey);
      expect(parsed!.reason).toBe('registry-mismatch');
      expect(parsed!.evidenceType).toBe('registry-screenshot');
      expect(parsed!.reporterTier).toBe(3);
    });
  });
});

describe('revocations', () => {
  it('creates a valid revocation event', async () => {
    const authority = generateKeyPair();
    const verifier = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);

    const revocation = await createRevocation(authority.privateKey, {
      verifierPubkey: verifier.publicKey,
      challengeEventId: 'challenge123',
      confirmations: 7,
      bondAction: 'slashed',
      scope: 'full',
      effectiveAt: now,
      summary: 'Confirmed fraudulent: licence revoked by SRA',
    });

    expect(revocation.kind).toBe(ATTESTATION_KIND);
    expect(getTagValue(revocation, 'type')).toBe(ATTESTATION_TYPES.REVOCATION);
    expect(getTagValue(revocation, 'd')).toBe(`revocation:${verifier.publicKey}`);
    expect(getTagValue(revocation, 'challenge')).toBe('challenge123');
    expect(getTagValue(revocation, 'confirmations')).toBe('7');
    expect(getTagValue(revocation, 'bond-action')).toBe('slashed');
    expect(getTagValue(revocation, 'scope')).toBe('full');
    expect(revocation.content).toBe('Confirmed fraudulent: licence revoked by SRA');

    const valid = await verifyEvent(revocation);
    expect(valid).toBe(true);
  });

  describe('parseRevocation', () => {
    it('parses revocation fields', async () => {
      const authority = generateKeyPair();
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);

      const revocation = await createRevocation(authority.privateKey, {
        verifierPubkey: verifier.publicKey,
        challengeEventId: 'ch456',
        confirmations: 5,
        bondAction: 'held',
        scope: 'partial',
        effectiveAt: now,
        summary: 'Under review',
      });

      const parsed = parseRevocation(revocation);
      expect(parsed).not.toBeNull();
      expect(parsed!.verifierPubkey).toBe(verifier.publicKey);
      expect(parsed!.challengeEventId).toBe('ch456');
      expect(parsed!.confirmations).toBe(5);
      expect(parsed!.bondAction).toBe('held');
      expect(parsed!.scope).toBe('partial');
    });
  });

  describe('hasReachedRevocationThreshold', () => {
    it('returns true at default threshold', () => {
      expect(hasReachedRevocationThreshold(5)).toBe(true);
      expect(hasReachedRevocationThreshold(7)).toBe(true);
    });

    it('returns false below threshold', () => {
      expect(hasReachedRevocationThreshold(4)).toBe(false);
      expect(hasReachedRevocationThreshold(0)).toBe(false);
    });

    it('uses custom threshold', () => {
      expect(hasReachedRevocationThreshold(3, 3)).toBe(true);
      expect(hasReachedRevocationThreshold(2, 3)).toBe(false);
    });
  });

  describe('countChallengeConfirmations', () => {
    function makeConfirmation(pubkey: string, challengeId: string): NostrEvent {
      return {
        id: Math.random().toString(36).slice(2),
        kind: 1,
        pubkey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['challenge', challengeId]],
        content: 'Confirmed',
        sig: 'mock',
      };
    }

    it('returns 0 with no confirmation events', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const cred = await createProfessionalCredential(verifier.privateKey, subject.publicKey, TIER3_OPTS);

      const count = countChallengeConfirmations('challenge-1', [], [cred]);
      expect(count).toBe(0);
    });

    it('counts Tier 3+ confirmations', async () => {
      const verifier = generateKeyPair();
      const confirmer1 = generateKeyPair();
      const confirmer2 = generateKeyPair();

      // Create Tier 3 credentials for both confirmers
      const cred1 = await createProfessionalCredential(verifier.privateKey, confirmer1.publicKey, TIER3_OPTS);
      const cred2 = await createProfessionalCredential(verifier.privateKey, confirmer2.publicKey, {
        profession: 'doctor',
        jurisdiction: 'UK',
      });

      const confirmations = [
        makeConfirmation(confirmer1.publicKey, 'ch-1'),
        makeConfirmation(confirmer2.publicKey, 'ch-1'),
      ];

      const count = countChallengeConfirmations('ch-1', confirmations, [cred1, cred2]);
      expect(count).toBe(2);
    });

    it('ignores confirmations from non-Tier-3 pubkeys', async () => {
      const verifier = generateKeyPair();
      const tier3User = generateKeyPair();
      const tier1User = generateKeyPair();

      const cred = await createProfessionalCredential(verifier.privateKey, tier3User.publicKey, TIER3_OPTS);

      const confirmations = [
        makeConfirmation(tier3User.publicKey, 'ch-2'),
        makeConfirmation(tier1User.publicKey, 'ch-2'), // no Tier 3 credential
      ];

      const count = countChallengeConfirmations('ch-2', confirmations, [cred]);
      expect(count).toBe(1);
    });

    it('deduplicates confirmations from the same pubkey', async () => {
      const verifier = generateKeyPair();
      const confirmer = generateKeyPair();

      const cred = await createProfessionalCredential(verifier.privateKey, confirmer.publicKey, TIER3_OPTS);

      const confirmations = [
        makeConfirmation(confirmer.publicKey, 'ch-3'),
        makeConfirmation(confirmer.publicKey, 'ch-3'), // duplicate
      ];

      const count = countChallengeConfirmations('ch-3', confirmations, [cred]);
      expect(count).toBe(1);
    });

    it('ignores confirmations for a different challenge', async () => {
      const verifier = generateKeyPair();
      const confirmer = generateKeyPair();

      const cred = await createProfessionalCredential(verifier.privateKey, confirmer.publicKey, TIER3_OPTS);

      const confirmations = [
        makeConfirmation(confirmer.publicKey, 'ch-other'),
      ];

      const count = countChallengeConfirmations('ch-4', confirmations, [cred]);
      expect(count).toBe(0);
    });
  });
});
