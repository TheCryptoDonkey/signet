import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createRingProtectedCredential,
  createRingProtectedChildCredential,
  verifyRingProtectedContent,
  verifyCredential,
  renewCredential,
  needsRenewal,
  createProfessionalCredential,
  getTagValue,
} from '../src/index.js';
import { TIER3_OPTS, generateKeypairs } from './fixtures.js';

describe('ring-protected credentials', () => {
  it('creates a Tier 3 ring-protected credential', async () => {
    const verifiers = generateKeypairs(5);
    const subject = generateKeyPair();
    const signerIdx = 2;

    const cred = await createRingProtectedCredential(
      verifiers[signerIdx].privateKey,
      subject.publicKey,
      verifiers.map((v) => v.publicKey),
      signerIdx,
      TIER3_OPTS
    );

    expect(getTagValue(cred, 'tier')).toBe('3');
    expect(getTagValue(cred, 'type')).toBe('credential');
    expect(getTagValue(cred, 'verification-type')).toBe('professional');

    // Verify the event signature
    const eventResult = await verifyCredential(cred);
    expect(eventResult.signatureValid).toBe(true);
    expect(eventResult.structureValid).toBe(true);

    // Verify the ring signature in content
    const ringResult = verifyRingProtectedContent(cred);
    expect(ringResult.hasRingSignature).toBe(true);
    expect(ringResult.ringValid).toBe(true);
    expect(ringResult.hasRangeProof).toBe(false);
  });

  it('creates a Tier 4 ring-protected credential with age proof', async () => {
    const verifiers = generateKeypairs(5);
    const parent = generateKeyPair();
    const signerIdx = 4;

    const cred = await createRingProtectedChildCredential(
      verifiers[signerIdx].privateKey,
      parent.publicKey,
      verifiers.map((v) => v.publicKey),
      signerIdx,
      {
        profession: 'notary',
        jurisdiction: 'US',
        ageRange: '8-12',
        actualAge: 10,
      }
    );

    expect(getTagValue(cred, 'tier')).toBe('4');
    expect(getTagValue(cred, 'scope')).toBe('adult+child');
    expect(getTagValue(cred, 'age-range')).toBe('8-12');

    const ringResult = verifyRingProtectedContent(cred);
    expect(ringResult.hasRingSignature).toBe(true);
    expect(ringResult.ringValid).toBe(true);
    expect(ringResult.hasRangeProof).toBe(true);
    expect(ringResult.rangeProofValid).toBe(true);
  });

  it('Tier 4 ring-protected credential proves boundary ages', async () => {
    const verifiers = generateKeypairs(3);
    const parent = generateKeyPair();

    // Test lower boundary
    const cred8 = await createRingProtectedChildCredential(
      verifiers[0].privateKey,
      parent.publicKey,
      verifiers.map((v) => v.publicKey),
      0,
      { profession: 'doctor', jurisdiction: 'AU', ageRange: '8-12', actualAge: 8 }
    );
    expect(verifyRingProtectedContent(cred8).rangeProofValid).toBe(true);

    // Test upper boundary
    const cred12 = await createRingProtectedChildCredential(
      verifiers[1].privateKey,
      parent.publicKey,
      verifiers.map((v) => v.publicKey),
      1,
      { profession: 'doctor', jurisdiction: 'AU', ageRange: '8-12', actualAge: 12 }
    );
    expect(verifyRingProtectedContent(cred12).rangeProofValid).toBe(true);
  });
});

describe('credential renewal', () => {
  it('renews an existing credential', async () => {
    const verifier = generateKeyPair();
    const subject = generateKeyPair();

    const original = await createProfessionalCredential(verifier.privateKey, subject.publicKey, TIER3_OPTS);

    const renewed = await renewCredential(verifier.privateKey, original);

    expect(getTagValue(renewed, 'd')).toBe(`credential:${subject.publicKey}`);
    expect(getTagValue(renewed, 'tier')).toBe('3');
    expect(getTagValue(renewed, 'profession')).toBe('solicitor');

    // New expiry should be in the future
    const expiresAt = parseInt(getTagValue(renewed, 'expires')!);
    expect(expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('needsRenewal detects soon-to-expire credentials', async () => {
    const kp = generateKeyPair();
    const subject = generateKeyPair();

    // Create credential expiring in 10 days
    const tenDays = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60;
    const cred = await createProfessionalCredential(kp.privateKey, subject.publicKey, {
      ...TIER3_OPTS,
      expiresAt: tenDays,
    });

    expect(needsRenewal(cred, 30)).toBe(true);  // within 30 days
    expect(needsRenewal(cred, 5)).toBe(false);   // not within 5 days
  });
});
