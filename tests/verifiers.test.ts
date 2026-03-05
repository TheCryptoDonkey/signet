import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createVerifierCredential,
  parseVerifier,
  checkCrossVerification,
  isVerifierRevoked,
  createVouch,
  createRevocation,
  verifyEvent,
  getTagValue,
  SIGNET_KINDS,
} from '../src/index.js';

describe('verifiers', () => {
  it('creates a valid verifier credential', async () => {
    const verifier = generateKeyPair();
    const cred = await createVerifierCredential(verifier.privateKey, {
      profession: 'solicitor',
      jurisdiction: 'UK',
      licenceHash: 'abc123hash',
      professionalBody: 'Law Society of England and Wales',
      statement: 'Available for Signet verification',
    });

    expect(cred.kind).toBe(SIGNET_KINDS.VERIFIER);
    expect(cred.pubkey).toBe(verifier.publicKey);
    expect(getTagValue(cred, 'profession')).toBe('solicitor');
    expect(getTagValue(cred, 'jurisdiction')).toBe('UK');
    expect(getTagValue(cred, 'licence')).toBe('abc123hash');
    expect(getTagValue(cred, 'body')).toBe('Law Society of England and Wales');
    expect(cred.content).toBe('Available for Signet verification');

    const valid = await verifyEvent(cred);
    expect(valid).toBe(true);
  });

  describe('parseVerifier', () => {
    it('parses verifier credential fields', async () => {
      const verifier = generateKeyPair();
      const cred = await createVerifierCredential(verifier.privateKey, {
        profession: 'doctor',
        jurisdiction: 'AU',
        licenceHash: 'med12345',
        professionalBody: 'Medical Board of Australia',
      });

      const parsed = parseVerifier(cred);
      expect(parsed).not.toBeNull();
      expect(parsed!.profession).toBe('doctor');
      expect(parsed!.jurisdiction).toBe('AU');
      expect(parsed!.licenceHash).toBe('med12345');
      expect(parsed!.professionalBody).toBe('Medical Board of Australia');
    });
  });

  describe('checkCrossVerification', () => {
    it('activates verifier with sufficient cross-profession vouches', async () => {
      const newVerifier = generateKeyPair();

      // Two existing verifiers from different professions
      const lawyer = generateKeyPair();
      const doctor = generateKeyPair();

      const lawyerCred = await createVerifierCredential(lawyer.privateKey, {
        profession: 'solicitor',
        jurisdiction: 'UK',
        licenceHash: 'law123',
        professionalBody: 'Law Society',
      });

      const doctorCred = await createVerifierCredential(doctor.privateKey, {
        profession: 'doctor',
        jurisdiction: 'UK',
        licenceHash: 'med456',
        professionalBody: 'GMC',
      });

      // Both vouch for the new verifier
      const lawyerVouch = await createVouch(lawyer.privateKey, {
        subjectPubkey: newVerifier.publicKey,
        method: 'in-person',
        voucherTier: 3,
        voucherScore: 90,
      });

      const doctorVouch = await createVouch(doctor.privateKey, {
        subjectPubkey: newVerifier.publicKey,
        method: 'in-person',
        voucherTier: 3,
        voucherScore: 85,
      });

      const result = checkCrossVerification(
        newVerifier.publicKey,
        [lawyerVouch, doctorVouch],
        [lawyerCred, doctorCred]
      );

      expect(result.activated).toBe(true);
      expect(result.vouchCount).toBe(2);
      expect(result.professions).toContain('solicitor');
      expect(result.professions).toContain('doctor');
      expect(result.errors).toHaveLength(0);
    });

    it('rejects verifier with same-profession vouches only', async () => {
      const newVerifier = generateKeyPair();
      const lawyer1 = generateKeyPair();
      const lawyer2 = generateKeyPair();

      const cred1 = await createVerifierCredential(lawyer1.privateKey, {
        profession: 'solicitor',
        jurisdiction: 'UK',
        licenceHash: 'law1',
        professionalBody: 'Law Society',
      });

      const cred2 = await createVerifierCredential(lawyer2.privateKey, {
        profession: 'solicitor',
        jurisdiction: 'UK',
        licenceHash: 'law2',
        professionalBody: 'Law Society',
      });

      const vouches = await Promise.all([
        createVouch(lawyer1.privateKey, {
          subjectPubkey: newVerifier.publicKey,
          method: 'in-person',
          voucherTier: 3,
          voucherScore: 90,
        }),
        createVouch(lawyer2.privateKey, {
          subjectPubkey: newVerifier.publicKey,
          method: 'in-person',
          voucherTier: 3,
          voucherScore: 85,
        }),
      ]);

      const result = checkCrossVerification(
        newVerifier.publicKey,
        vouches,
        [cred1, cred2]
      );

      expect(result.activated).toBe(false);
      expect(result.vouchCount).toBe(2);
      expect(result.professions).toHaveLength(1);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('rejects verifier with insufficient vouches', async () => {
      const newVerifier = generateKeyPair();
      const lawyer = generateKeyPair();

      const lawyerCred = await createVerifierCredential(lawyer.privateKey, {
        profession: 'solicitor',
        jurisdiction: 'UK',
        licenceHash: 'law1',
        professionalBody: 'Law Society',
      });

      const vouch = await createVouch(lawyer.privateKey, {
        subjectPubkey: newVerifier.publicKey,
        method: 'in-person',
        voucherTier: 3,
        voucherScore: 90,
      });

      const result = checkCrossVerification(
        newVerifier.publicKey,
        [vouch],
        [lawyerCred]
      );

      expect(result.activated).toBe(false);
      expect(result.vouchCount).toBe(1);
    });
  });

  describe('isVerifierRevoked', () => {
    it('returns false when no revocations exist', () => {
      const verifier = generateKeyPair();
      expect(isVerifierRevoked(verifier.publicKey, [])).toBe(false);
    });

    it('returns true when a revocation exists', async () => {
      const verifier = generateKeyPair();
      const authority = generateKeyPair();

      const revocation = await createRevocation(authority.privateKey, {
        verifierPubkey: verifier.publicKey,
        challengeEventId: 'abc123',
        confirmations: 7,
        bondAction: 'slashed',
        scope: 'full',
        effectiveAt: Math.floor(Date.now() / 1000),
        summary: 'Fraudulent attestations confirmed',
      });

      expect(isVerifierRevoked(verifier.publicKey, [revocation])).toBe(true);
    });
  });
});
