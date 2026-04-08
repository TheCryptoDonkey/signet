import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../src/crypto.js';
import { createProfessionalCredential, createChildSafetyCredential, createSelfDeclaredCredential } from '../src/credentials.js';
import {
  checkCredentialCompliance,
  checkCrossBorderCompliance,
  checkChildCompliance,
  getConsentRequirements,
  getRetentionGuidance,
  checkMultiJurisdictionCompliance,
  getMostRestrictiveRequirements,
} from '../src/compliance.js';

/** Helper: create a valid Tier 3 professional credential for testing. */
async function createTestCredential(opts?: {
  profession?: string;
  jurisdiction?: string;
  expiresAt?: number;
}) {
  const verifier = generateKeyPair();
  const subject = generateKeyPair();
  const tier1 = await createSelfDeclaredCredential(subject.privateKey);
  return createProfessionalCredential(verifier.privateKey, subject.publicKey, {
    assertionEventId: tier1.id,
    profession: opts?.profession ?? 'solicitor',
    jurisdiction: opts?.jurisdiction ?? 'GB',
    expiresAt: opts?.expiresAt,
    actualAge: 25,
  });
}

describe('compliance', () => {
  describe('checkCredentialCompliance', () => {
    it('returns compliant for a valid UK credential', async () => {
      const cred = await createTestCredential();
      const result = checkCredentialCompliance(cred, 'GB');

      expect(result.compliant).toBe(true);
      expect(result.jurisdiction).toBe('GB');
      expect(result.checkedAt).toBeGreaterThan(0);
      // Should have info-level issues (consent required, breach notification) but no errors
      const errors = result.issues.filter((i) => i.severity === 'error');
      expect(errors).toHaveLength(0);
    });

    it('returns error for unknown jurisdiction', async () => {
      const cred = await createTestCredential();
      const result = checkCredentialCompliance(cred, 'XX');

      expect(result.compliant).toBe(false);
      expect(result.issues).toHaveLength(1);
      expect(result.issues[0].code).toBe('UNKNOWN_JURISDICTION');
      expect(result.issues[0].severity).toBe('error');
    });

    it('flags expired credentials', async () => {
      const pastTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      const cred = await createTestCredential({ expiresAt: pastTime });
      const result = checkCredentialCompliance(cred, 'GB');

      expect(result.compliant).toBe(false);
      const expiredIssue = result.issues.find((i) => i.code === 'CREDENTIAL_EXPIRED');
      expect(expiredIssue).toBeDefined();
      expect(expiredIssue!.severity).toBe('error');
      expect(expiredIssue!.remediation).toContain('Renew');
    });

    it('includes GDPR info for UK credentials', async () => {
      const cred = await createTestCredential();
      const result = checkCredentialCompliance(cred, 'GB');

      // GB requires explicit consent under UK GDPR
      const consentIssue = result.issues.find((i) => i.code === 'CONSENT_REQUIRED');
      expect(consentIssue).toBeDefined();
      expect(consentIssue!.severity).toBe('info');
      expect(consentIssue!.message).toContain('UK GDPR');

      // GB has breach notification requirements
      const breachIssue = result.issues.find((i) => i.code === 'BREACH_NOTIFICATION');
      expect(breachIssue).toBeDefined();
      expect(breachIssue!.severity).toBe('info');
      expect(breachIssue!.message).toContain('72');
    });

    it('does not flag e-signature issues for UK credentials', async () => {
      const cred = await createTestCredential();
      const result = checkCredentialCompliance(cred, 'GB');

      const eSignIssue = result.issues.find((i) => i.code === 'ESIGNATURE_NOT_RECOGNISED');
      expect(eSignIssue).toBeUndefined();
    });
  });

  describe('checkCrossBorderCompliance', () => {
    it('flags safeguards required for GB to FR (post-Brexit)', () => {
      // GB is not in the EU EEA list, but FR has GB in adequacy list,
      // so FR->GB works with adequacy, but GB->FR requires checking
      const result = checkCrossBorderCompliance('GB', 'FR');

      expect(result.fromJurisdiction).toBe('GB');
      expect(result.toJurisdiction).toBe('FR');
      expect(result.allowed).toBe(true);
      // GB has cross-border restrictions and FR is in its mutual recognition list
      // (GB mutualRecognition: ['IE', 'AU', 'NZ', 'CA', 'HK'] — FR is not included)
      // So this should require safeguards
      const safeguards = result.issues.find((i) => i.code === 'SAFEGUARDS_REQUIRED');
      expect(safeguards).toBeDefined();
      expect(safeguards!.severity).toBe('warning');
    });

    it('allows EU internal transfer between FR and DE', () => {
      const result = checkCrossBorderCompliance('FR', 'DE');

      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('eu-internal');
      // No safeguards needed for EU internal transfers
      const safeguards = result.issues.find((i) => i.code === 'SAFEGUARDS_REQUIRED');
      expect(safeguards).toBeUndefined();
    });

    it('flags CN data localization', () => {
      const result = checkCrossBorderCompliance('CN', 'US');

      const cnIssue = result.issues.find((i) => i.code === 'CN_DATA_LOCALIZATION');
      expect(cnIssue).toBeDefined();
      expect(cnIssue!.severity).toBe('warning');
      expect(cnIssue!.message).toContain('PIPL');
      expect(cnIssue!.message).toContain('security assessment');
    });

    it('returns error for unknown jurisdiction', () => {
      const result = checkCrossBorderCompliance('XX', 'GB');

      expect(result.allowed).toBe(false);
      expect(result.issues.some((i) => i.code === 'UNKNOWN_JURISDICTION')).toBe(true);
    });
  });

  describe('checkChildCompliance', () => {
    it('requires parental consent for age 10 in UK (below consent age 13)', () => {
      const result = checkChildCompliance(10, 'GB');

      expect(result.compliant).toBe(false);
      expect(result.requiresParentalConsent).toBe(true);
      expect(result.minConsentAge).toBe(13);
      expect(result.ageOfMajority).toBe(18);

      const parentalIssue = result.issues.find((i) => i.code === 'PARENTAL_CONSENT_REQUIRED');
      expect(parentalIssue).toBeDefined();
      expect(parentalIssue!.severity).toBe('error');
      expect(parentalIssue!.message).toContain('10');
      expect(parentalIssue!.message).toContain('13');
    });

    it('requires parental consent for age 15 in DE (below consent age 16)', () => {
      const result = checkChildCompliance(15, 'DE');

      expect(result.compliant).toBe(false);
      expect(result.requiresParentalConsent).toBe(true);
      expect(result.minConsentAge).toBe(16);

      const parentalIssue = result.issues.find((i) => i.code === 'PARENTAL_CONSENT_REQUIRED');
      expect(parentalIssue).toBeDefined();
      expect(parentalIssue!.severity).toBe('error');
    });

    it('does not require parental consent for age 15 in GB (above consent age 13)', () => {
      const result = checkChildCompliance(15, 'GB');

      expect(result.requiresParentalConsent).toBe(false);
      expect(result.minConsentAge).toBe(13);

      const parentalIssue = result.issues.find((i) => i.code === 'PARENTAL_CONSENT_REQUIRED');
      expect(parentalIssue).toBeUndefined();
    });

    it('includes AADC compliance info for GB', () => {
      const result = checkChildCompliance(10, 'GB');

      const aadcIssue = result.issues.find((i) => i.code === 'AADC_COMPLIANCE');
      expect(aadcIssue).toBeDefined();
      expect(aadcIssue!.severity).toBe('info');
      expect(aadcIssue!.message).toContain('Age Appropriate Design Code');
    });

    it('includes COPPA compliance info for US', () => {
      const result = checkChildCompliance(10, 'US');

      const coppaIssue = result.issues.find((i) => i.code === 'COPPA_COMPLIANCE');
      expect(coppaIssue).toBeDefined();
      expect(coppaIssue!.severity).toBe('warning');
      expect(coppaIssue!.message).toContain('COPPA');
    });

    it('flags enhanced protections where applicable', () => {
      const result = checkChildCompliance(10, 'GB');

      const enhancedIssue = result.issues.find((i) => i.code === 'ENHANCED_CHILD_PROTECTIONS');
      expect(enhancedIssue).toBeDefined();
    });

    it('flags profiling restrictions where applicable', () => {
      const result = checkChildCompliance(10, 'GB');

      const profilingIssue = result.issues.find((i) => i.code === 'PROFILING_RESTRICTED');
      expect(profilingIssue).toBeDefined();
      expect(profilingIssue!.severity).toBe('warning');
    });

    it('returns error for unknown jurisdiction', () => {
      const result = checkChildCompliance(10, 'XX');

      expect(result.compliant).toBe(false);
      expect(result.issues.some((i) => i.code === 'UNKNOWN_JURISDICTION')).toBe(true);
      // Falls back to defaults
      expect(result.minConsentAge).toBe(16);
      expect(result.ageOfMajority).toBe(18);
      expect(result.requiresParentalConsent).toBe(true);
    });
  });

  describe('getConsentRequirements', () => {
    it('returns requirements for UK including explicit consent', () => {
      const req = getConsentRequirements('GB');

      expect(req.jurisdiction).toBe('GB');
      expect(req.requiresExplicitConsent).toBe(true);
      expect(req.consentAge).toBe(13);
      expect(req.parentalConsentRequired).toBe(true);
      expect(req.dataCategories).toContain('identity');
      expect(req.dataCategories).toContain('professional-status');
      // GB is in the GDPR jurisdictions list, so should have biometric-hash
      expect(req.specialCategories).toContain('biometric-hash');
      expect(req.notes).toContain('GDPR');
    });

    it('returns requirements for US', () => {
      const req = getConsentRequirements('US');

      expect(req.jurisdiction).toBe('US');
      expect(req.requiresExplicitConsent).toBe(false);
      expect(req.consentAge).toBe(13);
      expect(req.parentalConsentRequired).toBe(true);
      expect(req.dataCategories).toContain('identity');
    });

    it('includes child-age-range for jurisdictions with enhanced child protections', () => {
      const req = getConsentRequirements('GB');
      expect(req.specialCategories).toContain('child-age-range');
    });

    it('includes biometric-hash for Brazil (LGPD)', () => {
      const req = getConsentRequirements('BR');
      expect(req.specialCategories).toContain('biometric-hash');
      expect(req.notes).toContain('LGPD');
    });

    it('returns conservative defaults for unknown jurisdiction', () => {
      const req = getConsentRequirements('XX');

      expect(req.jurisdiction).toBe('XX');
      expect(req.requiresExplicitConsent).toBe(true);
      expect(req.consentAge).toBe(16);
      expect(req.parentalConsentRequired).toBe(true);
    });
  });

  describe('getRetentionGuidance', () => {
    it('returns GDPR guidance for UK', () => {
      const guidance = getRetentionGuidance('GB');

      expect(guidance.maxDays).toBe(0); // GDPR does not specify fixed period
      expect(guidance.guidance).toContain('GDPR');
      expect(guidance.guidance).toContain('no longer than necessary');
      expect(guidance.regulation).toContain('UK');
    });

    it('returns GDPR guidance for FR', () => {
      const guidance = getRetentionGuidance('FR');

      expect(guidance.maxDays).toBe(0);
      expect(guidance.guidance).toContain('GDPR');
    });

    it('returns GDPR guidance for DE', () => {
      const guidance = getRetentionGuidance('DE');

      expect(guidance.maxDays).toBe(0);
      expect(guidance.guidance).toContain('GDPR');
    });

    it('returns guidance for non-GDPR jurisdictions', () => {
      const guidance = getRetentionGuidance('JP');

      expect(guidance.regulation).toBeTruthy();
      expect(guidance.guidance).toBeTruthy();
    });

    it('returns conservative default for unknown jurisdiction', () => {
      const guidance = getRetentionGuidance('XX');

      expect(guidance.maxDays).toBe(365);
      expect(guidance.guidance).toContain('conservative');
      expect(guidance.regulation).toBe('Best Practice');
    });
  });

  describe('checkMultiJurisdictionCompliance', () => {
    it('returns compliance results for multiple jurisdictions', async () => {
      const cred = await createTestCredential();
      const results = checkMultiJurisdictionCompliance(cred, ['GB', 'US', 'FR', 'DE']);

      expect(results.size).toBe(4);
      expect(results.has('GB')).toBe(true);
      expect(results.has('US')).toBe(true);
      expect(results.has('FR')).toBe(true);
      expect(results.has('DE')).toBe(true);

      // Each result should have the correct jurisdiction field
      for (const [code, result] of results) {
        expect(result.jurisdiction).toBe(code);
        expect(result.checkedAt).toBeGreaterThan(0);
        expect(Array.isArray(result.issues)).toBe(true);
      }
    });

    it('handles unknown jurisdictions in the list', async () => {
      const cred = await createTestCredential();
      const results = checkMultiJurisdictionCompliance(cred, ['GB', 'XX']);

      const gbResult = results.get('GB')!;
      const xxResult = results.get('XX')!;

      expect(gbResult.compliant).toBe(true);
      expect(xxResult.compliant).toBe(false);
      expect(xxResult.issues[0].code).toBe('UNKNOWN_JURISDICTION');
    });
  });

  describe('getMostRestrictiveRequirements', () => {
    it('picks the highest consent age across jurisdictions', () => {
      // GB=13, DE=16, IN=18
      const result = getMostRestrictiveRequirements(['GB', 'DE', 'IN']);

      expect(result.highestConsentAge).toBe(18); // India
      expect(result.highestAgeOfMajority).toBe(18);
      expect(result.requiresExplicitConsent).toBe(true);
      expect(result.jurisdictions).toEqual(['GB', 'DE', 'IN']);
    });

    it('picks highest age of majority', () => {
      // Most are 18, but SG is 21
      const result = getMostRestrictiveRequirements(['GB', 'SG', 'US']);

      expect(result.highestAgeOfMajority).toBe(21); // Singapore
    });

    it('requires explicit consent if any jurisdiction does', () => {
      // US does not require explicit consent, GB does
      const result = getMostRestrictiveRequirements(['US', 'GB']);

      expect(result.requiresExplicitConsent).toBe(true);
    });

    it('picks the shortest breach notification period', () => {
      // GB=72, BR=48, US=0 (no requirement)
      const result = getMostRestrictiveRequirements(['GB', 'BR']);

      expect(result.shortestBreachNotification).toBe(48); // Brazil
    });

    it('returns zero breach notification when no jurisdiction requires it', () => {
      // US has 0 breach notification hours
      const result = getMostRestrictiveRequirements(['US']);

      expect(result.shortestBreachNotification).toBe(0);
    });

    it('checks erasure requirement across jurisdictions', () => {
      const result = getMostRestrictiveRequirements(['GB', 'DE', 'FR']);

      // All GDPR jurisdictions have right to erasure
      expect(result.allRequireErasure).toBe(true);
    });

    it('returns false for allRequireErasure when a jurisdiction lacks it', () => {
      // AU does not have right to erasure
      const result = getMostRestrictiveRequirements(['GB', 'AU']);

      expect(result.allRequireErasure).toBe(false);
    });

    it('handles empty jurisdiction list', () => {
      const result = getMostRestrictiveRequirements([]);

      expect(result.highestConsentAge).toBe(0);
      expect(result.highestAgeOfMajority).toBe(0);
      expect(result.requiresExplicitConsent).toBe(false);
      expect(result.shortestBreachNotification).toBe(0);
    });

    it('ignores unknown jurisdictions gracefully', () => {
      const result = getMostRestrictiveRequirements(['XX', 'GB']);

      // Should still return GB's values, ignoring unknown
      expect(result.highestConsentAge).toBe(13);
      expect(result.requiresExplicitConsent).toBe(true);
    });
  });

  describe('checkChildDataRequirements (via checkCredentialCompliance)', () => {
    it('flags age ranges that include ages below consent age', async () => {
      // GB consent age is 13. Age range "8-12" is entirely below — should flag.
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const cred = await createChildSafetyCredential(verifier.privateKey, subject.publicKey, {
        assertionEventId: tier1.id,
        profession: 'solicitor',
        jurisdiction: 'GB',
        ageRange: '8-12',
        actualAge: 10,
      });
      const result = checkCredentialCompliance(cred, 'GB');
      const consentIssue = result.issues.find((i) => i.code === 'BELOW_CONSENT_AGE');
      expect(consentIssue).toBeDefined();
      expect(consentIssue!.message).toContain('digital consent age');
    });

    it('does not flag age ranges entirely above consent age', async () => {
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const cred = await createChildSafetyCredential(verifier.privateKey, subject.publicKey, {
        assertionEventId: tier1.id,
        profession: 'solicitor',
        jurisdiction: 'GB',
        ageRange: '13-17',
        actualAge: 15,
      });
      const result = checkCredentialCompliance(cred, 'GB');
      const consentIssue = result.issues.find((i) => i.code === 'BELOW_CONSENT_AGE');
      expect(consentIssue).toBeUndefined();
    });
  });
});
