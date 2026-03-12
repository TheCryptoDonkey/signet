import { describe, it, expect } from 'vitest';
import {
  getJurisdiction,
  getJurisdictionCodes,
  getProfessionalBodies,
  getMutualRecognitionPartners,
  isProfessionRegulated,
  findJurisdictionsForProfession,
  getDigitalConsentAge,
  getAgeOfMajority,
  canTransferData,
  getAllLanguages,
  getJurisdictionsByLanguage,
} from '../src/jurisdictions.js';

describe('jurisdictions', () => {
  describe('getJurisdiction', () => {
    it('returns correct data for GB', () => {
      const gb = getJurisdiction('GB');
      expect(gb).toBeDefined();
      expect(gb!.name).toBe('United Kingdom');
      expect(gb!.legalSystem).toBe('common-law');
      expect(gb!.languages).toContain('en');
      expect(gb!.currency).toBe('GBP');
      expect(gb!.eSignatureRecognised).toBe(true);
    });

    it('returns correct data for US', () => {
      const us = getJurisdiction('US');
      expect(us).toBeDefined();
      expect(us!.name).toBe('United States');
      expect(us!.legalSystem).toBe('common-law');
      expect(us!.languages).toContain('en');
      expect(us!.languages).toContain('es');
      expect(us!.currency).toBe('USD');
    });

    it('returns correct data for JP', () => {
      const jp = getJurisdiction('JP');
      expect(jp).toBeDefined();
      expect(jp!.name).toBe('Japan');
      expect(jp!.nameLocal).toBe('日本');
      expect(jp!.legalSystem).toBe('civil-law');
      expect(jp!.languages).toContain('ja');
      expect(jp!.currency).toBe('JPY');
    });

    it('returns correct data for BR', () => {
      const br = getJurisdiction('BR');
      expect(br).toBeDefined();
      expect(br!.name).toBe('Brazil');
      expect(br!.nameLocal).toBe('Brasil');
      expect(br!.legalSystem).toBe('civil-law');
      expect(br!.languages).toContain('pt');
      expect(br!.currency).toBe('BRL');
      expect(br!.dataProtection.name).toBe('LGPD');
    });

    it('returns correct data for DE', () => {
      const de = getJurisdiction('DE');
      expect(de).toBeDefined();
      expect(de!.name).toBe('Germany');
      expect(de!.nameLocal).toBe('Deutschland');
      expect(de!.legalSystem).toBe('civil-law');
      expect(de!.languages).toContain('de');
      expect(de!.currency).toBe('EUR');
    });

    it('returns undefined for unknown jurisdiction', () => {
      expect(getJurisdiction('XX')).toBeUndefined();
    });

    it('is case-insensitive', () => {
      const gb = getJurisdiction('gb');
      expect(gb).toBeDefined();
      expect(gb!.code).toBe('GB');
    });
  });

  describe('getJurisdictionCodes', () => {
    it('returns all codes (28+ jurisdictions)', () => {
      const codes = getJurisdictionCodes();
      expect(codes.length).toBeGreaterThanOrEqual(28);
      expect(codes).toContain('GB');
      expect(codes).toContain('US');
      expect(codes).toContain('FR');
      expect(codes).toContain('DE');
      expect(codes).toContain('JP');
      expect(codes).toContain('BR');
      expect(codes).toContain('AU');
      expect(codes).toContain('CA');
    });
  });

  describe('getProfessionalBodies', () => {
    it('returns professional bodies for UK legal profession', () => {
      const bodies = getProfessionalBodies('GB', 'legal');
      expect(bodies.length).toBeGreaterThanOrEqual(3);
      const names = bodies.map((b) => b.name);
      expect(names).toContain('The Law Society of England and Wales');
      expect(names).toContain('Law Society of Scotland');
      expect(names).toContain('Law Society of Northern Ireland');
    });

    it('returns all professional bodies when no profession filter is given', () => {
      const allBodies = getProfessionalBodies('GB');
      const legalBodies = getProfessionalBodies('GB', 'legal');
      expect(allBodies.length).toBeGreaterThan(legalBodies.length);
    });

    it('filters by profession correctly', () => {
      const medical = getProfessionalBodies('GB', 'medical');
      expect(medical.length).toBeGreaterThanOrEqual(1);
      medical.forEach((b) => {
        expect(b.profession).toBe('medical');
      });
    });

    it('returns empty array for unknown jurisdiction', () => {
      expect(getProfessionalBodies('XX')).toEqual([]);
    });

    it('returns empty array for a profession not present in a jurisdiction', () => {
      const result = getProfessionalBodies('GB', 'financial');
      expect(result).toEqual([]);
    });
  });

  describe('getMutualRecognitionPartners', () => {
    it('returns mutual recognition partners for GB including AU and CA', () => {
      const partners = getMutualRecognitionPartners('GB');
      const codes = partners.map((p) => p.code);
      expect(codes).toContain('AU');
      expect(codes).toContain('CA');
      expect(codes).toContain('IE');
      expect(codes).toContain('NZ');
      expect(codes).toContain('HK');
    });

    it('returns empty array for unknown jurisdiction', () => {
      expect(getMutualRecognitionPartners('XX')).toEqual([]);
    });

    it('returns Jurisdiction objects with valid data', () => {
      const partners = getMutualRecognitionPartners('GB');
      partners.forEach((p) => {
        expect(p.code).toBeDefined();
        expect(p.name).toBeDefined();
        expect(p.legalSystem).toBeDefined();
      });
    });
  });

  describe('isProfessionRegulated', () => {
    it('returns true for UK legal profession', () => {
      expect(isProfessionRegulated('GB', 'legal')).toBe(true);
    });

    it('returns true for UK medical profession', () => {
      expect(isProfessionRegulated('GB', 'medical')).toBe(true);
    });

    it('returns false for a profession not present in a jurisdiction', () => {
      expect(isProfessionRegulated('GB', 'financial')).toBe(false);
    });

    it('returns false for unknown jurisdiction', () => {
      expect(isProfessionRegulated('XX', 'legal')).toBe(false);
    });
  });

  describe('findJurisdictionsForProfession', () => {
    it('returns many jurisdictions for medical profession', () => {
      const jurisdictions = findJurisdictionsForProfession('medical');
      expect(jurisdictions.length).toBeGreaterThanOrEqual(15);
      const codes = jurisdictions.map((j) => j.code);
      expect(codes).toContain('GB');
      expect(codes).toContain('US');
      expect(codes).toContain('FR');
      expect(codes).toContain('DE');
      expect(codes).toContain('JP');
    });

    it('returns jurisdictions for legal profession', () => {
      const jurisdictions = findJurisdictionsForProfession('legal');
      expect(jurisdictions.length).toBeGreaterThanOrEqual(20);
    });

    it('returns fewer jurisdictions for niche professions', () => {
      const legal = findJurisdictionsForProfession('legal');
      const architecture = findJurisdictionsForProfession('architecture');
      // Architecture has fewer registered bodies than legal
      expect(architecture.length).toBeLessThan(legal.length);
    });
  });

  describe('getDigitalConsentAge', () => {
    it('returns 13 for GB', () => {
      expect(getDigitalConsentAge('GB')).toBe(13);
    });

    it('returns 16 for DE', () => {
      expect(getDigitalConsentAge('DE')).toBe(16);
    });

    it('returns 14 for KR', () => {
      expect(getDigitalConsentAge('KR')).toBe(14);
    });

    it('returns 13 for US (COPPA)', () => {
      expect(getDigitalConsentAge('US')).toBe(13);
    });

    it('returns 15 for JP', () => {
      expect(getDigitalConsentAge('JP')).toBe(15);
    });

    it('returns 12 for BR', () => {
      expect(getDigitalConsentAge('BR')).toBe(12);
    });

    it('returns default 16 for unknown jurisdiction', () => {
      expect(getDigitalConsentAge('XX')).toBe(16);
    });
  });

  describe('getAgeOfMajority', () => {
    it('returns 18 for most jurisdictions', () => {
      expect(getAgeOfMajority('GB')).toBe(18);
      expect(getAgeOfMajority('US')).toBe(18);
      expect(getAgeOfMajority('FR')).toBe(18);
      expect(getAgeOfMajority('DE')).toBe(18);
      expect(getAgeOfMajority('JP')).toBe(18);
    });

    it('returns 21 for SG', () => {
      expect(getAgeOfMajority('SG')).toBe(21);
    });

    it('returns 19 for KR', () => {
      expect(getAgeOfMajority('KR')).toBe(19);
    });

    it('returns 21 for AE', () => {
      expect(getAgeOfMajority('AE')).toBe(21);
    });

    it('returns default 18 for unknown jurisdiction', () => {
      expect(getAgeOfMajority('XX')).toBe(18);
    });
  });

  describe('canTransferData', () => {
    it('allows domestic transfer (same jurisdiction)', () => {
      const result = canTransferData('GB', 'GB');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('domestic');
    });

    it('allows EU internal transfer between FR and DE', () => {
      const result = canTransferData('FR', 'DE');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('eu-internal');
    });

    it('allows EU internal transfer between DE and IT', () => {
      const result = canTransferData('DE', 'IT');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('eu-internal');
    });

    it('allows transfer from EU to adequacy countries', () => {
      const result = canTransferData('FR', 'GB');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('adequacy-decision');
    });

    it('allows transfer from EU to JP with adequacy decision', () => {
      const result = canTransferData('DE', 'JP');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('adequacy-decision');
    });

    it('requires safeguards for transfers without adequacy or mutual recognition', () => {
      const result = canTransferData('FR', 'BR');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('safeguards-required');
    });

    it('allows no-restriction transfer from US (no cross-border restrictions)', () => {
      const result = canTransferData('US', 'BR');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('no-restrictions');
    });

    it('allows mutual recognition transfer', () => {
      const result = canTransferData('GB', 'AU');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('mutual-recognition');
    });

    it('returns not allowed for unknown jurisdiction', () => {
      const result = canTransferData('XX', 'GB');
      expect(result.allowed).toBe(false);
    });

    it('handles lowercase jurisdiction codes correctly (case normalisation)', () => {
      // Previously, lowercase codes bypassed EU-internal set membership
      const result = canTransferData('fr', 'de');
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe('eu-internal');
    });

    it('recognises all mapped EU members for eu-internal transfers', () => {
      // All mapped EU members should get eu-internal mechanism
      expect(canTransferData('FR', 'DE').mechanism).toBe('eu-internal');
      expect(canTransferData('ES', 'IT').mechanism).toBe('eu-internal');
      expect(canTransferData('NL', 'IE').mechanism).toBe('eu-internal');
    });

    it('recognises mapped adequacy countries', () => {
      // GB, JP, KR etc. are all in the adequacy list AND the jurisdictions map
      expect(canTransferData('FR', 'GB').mechanism).toBe('adequacy-decision');
      expect(canTransferData('DE', 'JP').mechanism).toBe('adequacy-decision');
      expect(canTransferData('IT', 'IL').mechanism).toBe('adequacy-decision');
    });
  });

  describe('getAllLanguages', () => {
    it('returns a non-empty sorted array', () => {
      const languages = getAllLanguages();
      expect(languages.length).toBeGreaterThan(0);
      // Check sorted order
      const sorted = [...languages].sort();
      expect(languages).toEqual(sorted);
    });

    it('includes common languages', () => {
      const languages = getAllLanguages();
      expect(languages).toContain('en');
      expect(languages).toContain('fr');
      expect(languages).toContain('de');
      expect(languages).toContain('es');
      expect(languages).toContain('ja');
      expect(languages).toContain('ar');
      expect(languages).toContain('zh');
    });
  });

  describe('getJurisdictionsByLanguage', () => {
    it('returns multiple jurisdictions for English', () => {
      const results = getJurisdictionsByLanguage('en');
      expect(results.length).toBeGreaterThanOrEqual(5);
      const codes = results.map((j) => j.code);
      expect(codes).toContain('GB');
      expect(codes).toContain('US');
      expect(codes).toContain('AU');
      expect(codes).toContain('NZ');
      expect(codes).toContain('CA');
    });

    it('returns Spanish-speaking jurisdictions for es', () => {
      const results = getJurisdictionsByLanguage('es');
      expect(results.length).toBeGreaterThanOrEqual(2);
      const codes = results.map((j) => j.code);
      expect(codes).toContain('ES');
      expect(codes).toContain('MX');
    });

    it('returns empty array for unlisted language', () => {
      expect(getJurisdictionsByLanguage('xx')).toEqual([]);
    });
  });

  describe('jurisdiction data integrity', () => {
    it('each jurisdiction has all required fields', () => {
      const codes = getJurisdictionCodes();
      for (const code of codes) {
        const j = getJurisdiction(code);
        expect(j, `Jurisdiction ${code} should exist`).toBeDefined();

        // Core fields
        expect(j!.code, `${code} should have a code`).toBe(code);
        expect(j!.name, `${code} should have a name`).toBeTruthy();
        expect(j!.nameLocal, `${code} should have a nameLocal`).toBeTruthy();
        expect(j!.legalSystem, `${code} should have a legalSystem`).toBeTruthy();
        expect(j!.languages.length, `${code} should have at least one language`).toBeGreaterThanOrEqual(1);
        expect(j!.currency, `${code} should have a currency`).toBeTruthy();
        expect(typeof j!.eSignatureRecognised, `${code} eSignatureRecognised should be boolean`).toBe('boolean');
        expect(Array.isArray(j!.mutualRecognition), `${code} mutualRecognition should be array`).toBe(true);

        // Professional bodies
        expect(Array.isArray(j!.professionalBodies), `${code} professionalBodies should be array`).toBe(true);
        expect(j!.professionalBodies.length, `${code} should have at least one professional body`).toBeGreaterThanOrEqual(1);

        // Data protection
        expect(j!.dataProtection.name, `${code} dataProtection should have name`).toBeTruthy();
        expect(j!.dataProtection.fullName, `${code} dataProtection should have fullName`).toBeTruthy();
        expect(j!.dataProtection.year, `${code} dataProtection should have year`).toBeGreaterThan(1900);
        expect(typeof j!.dataProtection.requiresExplicitConsent, `${code} requiresExplicitConsent should be boolean`).toBe('boolean');
        expect(j!.dataProtection.digitalConsentAge, `${code} digitalConsentAge should be positive`).toBeGreaterThan(0);
        expect(typeof j!.dataProtection.breachNotificationHours, `${code} breachNotificationHours should be number`).toBe('number');
        expect(typeof j!.dataProtection.rightToErasure, `${code} rightToErasure should be boolean`).toBe('boolean');
        expect(typeof j!.dataProtection.rightToPortability, `${code} rightToPortability should be boolean`).toBe('boolean');
        expect(typeof j!.dataProtection.crossBorderRestrictions, `${code} crossBorderRestrictions should be boolean`).toBe('boolean');
        expect(j!.dataProtection.supervisoryAuthority, `${code} supervisoryAuthority should be set`).toBeTruthy();

        // Child protection
        expect(j!.childProtection.name, `${code} childProtection should have name`).toBeTruthy();
        expect(j!.childProtection.minAgeDigitalConsent, `${code} minAgeDigitalConsent should be > 0`).toBeGreaterThan(0);
        expect(j!.childProtection.ageOfMajority, `${code} ageOfMajority should be >= 18`).toBeGreaterThanOrEqual(18);
        expect(typeof j!.childProtection.requiresParentalConsent, `${code} requiresParentalConsent should be boolean`).toBe('boolean');
        expect(typeof j!.childProtection.enhancedProtections, `${code} enhancedProtections should be boolean`).toBe('boolean');
        expect(typeof j!.childProtection.profilingRestrictions, `${code} profilingRestrictions should be boolean`).toBe('boolean');
      }
    });

    it('professional bodies have required fields', () => {
      const codes = getJurisdictionCodes();
      for (const code of codes) {
        const bodies = getProfessionalBodies(code);
        for (const body of bodies) {
          expect(body.id, `Body in ${code} should have id`).toBeTruthy();
          expect(body.name, `Body ${body.id} in ${code} should have name`).toBeTruthy();
          expect(body.profession, `Body ${body.id} in ${code} should have profession`).toBeTruthy();
          expect(body.website, `Body ${body.id} in ${code} should have website`).toBeTruthy();
          expect(typeof body.hasPublicRegister, `Body ${body.id} hasPublicRegister should be boolean`).toBe('boolean');
          expect(typeof body.issuesDigitalCredentials, `Body ${body.id} issuesDigitalCredentials should be boolean`).toBe('boolean');
        }
      }
    });
  });
});
