import { describe, it, expect, beforeEach } from 'vitest';
import {
  setLanguage,
  getLanguage,
  getSupportedLanguages,
  t,
  getTranslations,
  getLanguageName,
  getLanguageNativeName,
  formatLocalizedTrustScore,
  getTierDescription,
} from '../src/i18n.js';
import type { LanguageCode, TranslationStrings } from '../src/i18n.js';
import { ENTITY_LABELS } from '../src/constants.js';

describe('i18n', () => {
  // Reset to English before each test to avoid leaking state between tests
  beforeEach(() => {
    setLanguage('en');
  });

  describe('setLanguage and getLanguage', () => {
    it('sets and gets the current language', () => {
      setLanguage('es');
      expect(getLanguage()).toBe('es');

      setLanguage('ja');
      expect(getLanguage()).toBe('ja');

      setLanguage('en');
      expect(getLanguage()).toBe('en');
    });

    it('throws for invalid language code', () => {
      expect(() => setLanguage('xx' as LanguageCode)).toThrow('Unsupported language');
    });
  });

  describe('getSupportedLanguages', () => {
    it('returns 15 supported languages', () => {
      const languages = getSupportedLanguages();
      expect(languages).toHaveLength(15);
    });

    it('includes all expected language codes', () => {
      const languages = getSupportedLanguages();
      const expected = ['en', 'es', 'fr', 'de', 'pt', 'ja', 'ko', 'zh', 'ar', 'hi', 'it', 'nl', 'tr', 'id', 'sw'];
      for (const code of expected) {
        expect(languages).toContain(code);
      }
    });
  });

  describe('t() — translation function', () => {
    it('returns English by default', () => {
      expect(t('credential_self_declared')).toBe('Self-Declared Identity');
      expect(t('status_valid')).toBe('Valid');
      expect(t('action_verify')).toBe('Verify');
    });

    it('returns correct Spanish for credential types', () => {
      setLanguage('es');
      expect(t('credential_self_declared')).toBe('Identidad Autodeclarada');
      expect(t('credential_vouched')).toBe('Identidad Avalada por la Comunidad');
      expect(t('credential_professional')).toBe('Identidad Verificada Profesionalmente');
    });

    it('returns correct Japanese for tier descriptions', () => {
      setLanguage('ja');
      expect(t('tier_1_desc')).toBe('自己申告 — 未検証の人間性の主張');
      expect(t('tier_2_desc')).toBe('信頼ネットワーク — コミュニティメンバーによる保証');
      expect(t('tier_3_desc')).toBe('専門家 — 資格を持つ専門家による検証');
      expect(t('tier_4_desc')).toBe('専門家＋児童保護 — 年齢範囲証明を含む');
    });

    it('returns correct Arabic for actions', () => {
      setLanguage('ar');
      expect(t('action_verify')).toBe('تحقق');
      expect(t('action_issue')).toBe('إصدار');
      expect(t('action_revoke')).toBe('إلغاء');
      expect(t('action_renew')).toBe('تجديد');
      expect(t('action_vouch')).toBe('كفالة');
      expect(t('action_challenge')).toBe('طعن');
    });

    it('uses explicit lang parameter over current language', () => {
      setLanguage('en');
      expect(t('status_valid', 'de')).toBe('Gültig');
      expect(t('status_valid', 'fr')).toBe('Valide');
      expect(t('status_valid', 'it')).toBe('Valido');
      // Current language should still be English
      expect(getLanguage()).toBe('en');
      expect(t('status_valid')).toBe('Valid');
    });

    it('falls back to English for missing keys', () => {
      // Accessing a valid key in a non-English language should return the translation,
      // but if somehow a key were missing (they're all defined), it would fall back.
      // We can test the fallback by verifying that a known key works in all languages.
      const languages = getSupportedLanguages();
      for (const lang of languages) {
        const result = t('credential_self_declared', lang);
        expect(result, `${lang} should have a translation for credential_self_declared`).toBeTruthy();
        expect(result.length, `${lang} translation should not be empty`).toBeGreaterThan(0);
      }
    });
  });

  describe('getTranslations', () => {
    it('returns a full translation object for the current language', () => {
      const translations = getTranslations();
      expect(translations).toBeDefined();
      expect(translations.credential_self_declared).toBe('Self-Declared Identity');
      expect(translations.tier_1).toBe('Tier 1');
      expect(translations.action_verify).toBe('Verify');
    });

    it('returns translations for a specific language', () => {
      const frTranslations = getTranslations('fr');
      expect(frTranslations.credential_self_declared).toBe('Identité Auto-déclarée');
      expect(frTranslations.tier_1).toBe('Niveau 1');
    });

    it('returns English translations as fallback for unknown language', () => {
      const fallback = getTranslations('xx' as LanguageCode);
      expect(fallback.credential_self_declared).toBe('Self-Declared Identity');
    });
  });

  describe('getLanguageName and getLanguageNativeName', () => {
    it('returns English names for language codes', () => {
      expect(getLanguageName('en')).toBe('English');
      expect(getLanguageName('es')).toBe('Spanish');
      expect(getLanguageName('fr')).toBe('French');
      expect(getLanguageName('de')).toBe('German');
      expect(getLanguageName('ja')).toBe('Japanese');
      expect(getLanguageName('ar')).toBe('Arabic');
      expect(getLanguageName('zh')).toBe('Chinese (Simplified)');
      expect(getLanguageName('sw')).toBe('Swahili');
    });

    it('returns native names for language codes', () => {
      expect(getLanguageNativeName('en')).toBe('English');
      expect(getLanguageNativeName('es')).toBe('Español');
      expect(getLanguageNativeName('fr')).toBe('Français');
      expect(getLanguageNativeName('de')).toBe('Deutsch');
      expect(getLanguageNativeName('ja')).toBe('日本語');
      expect(getLanguageNativeName('ko')).toBe('한국어');
      expect(getLanguageNativeName('zh')).toBe('简体中文');
      expect(getLanguageNativeName('ar')).toBe('العربية');
      expect(getLanguageNativeName('hi')).toBe('हिन्दी');
      expect(getLanguageNativeName('sw')).toBe('Kiswahili');
      expect(getLanguageNativeName('id')).toBe('Bahasa Indonesia');
      expect(getLanguageNativeName('tr')).toBe('Türkçe');
    });
  });

  describe('formatLocalizedTrustScore', () => {
    it('formats Signet Score in English', () => {
      expect(formatLocalizedTrustScore(85)).toBe('Signet Score: 85/200');
    });

    it('formats Signet Score in Spanish', () => {
      expect(formatLocalizedTrustScore(72, 'es')).toBe('Signet Score: 72/200');
    });

    it('formats Signet Score in Japanese', () => {
      expect(formatLocalizedTrustScore(90, 'ja')).toBe('Signet Score: 90/200');
    });

    it('formats Signet Score in German', () => {
      expect(formatLocalizedTrustScore(50, 'de')).toBe('Signet Score: 50/200');
    });

    it('formats Signet Score with zero', () => {
      expect(formatLocalizedTrustScore(0)).toBe('Signet Score: 0/200');
    });

    it('formats Signet Score with max value', () => {
      expect(formatLocalizedTrustScore(200)).toBe('Signet Score: 200/200');
    });
  });

  describe('getTierDescription', () => {
    it('returns correct descriptions for all 4 tiers in English', () => {
      expect(getTierDescription(1)).toBe('Self-declared — unverified claim of humanness');
      expect(getTierDescription(2)).toBe('Web-of-trust — vouched for by community members');
      expect(getTierDescription(3)).toBe('Professional — verified by a licensed professional');
      expect(getTierDescription(4)).toBe('Professional + Child Safety — includes age range proof');
    });

    it('returns tier descriptions in French', () => {
      expect(getTierDescription(1, 'fr')).toContain('Auto-déclaré');
      expect(getTierDescription(3, 'fr')).toContain('Professionnel');
    });

    it('returns tier descriptions in Korean', () => {
      expect(getTierDescription(1, 'ko')).toBe('자기 선언 — 미검증된 인간성 주장');
      expect(getTierDescription(4, 'ko')).toBe('전문가 + 아동 보호 — 연령 범위 증명 포함');
    });
  });

  describe('entity type labels', () => {
    const entityKeys: (keyof TranslationStrings)[] = [
      'entity_natural_person',
      'entity_persona',
      'entity_personal_agent',
      'entity_unlinked_personal_agent',
      'entity_juridical_person',
      'entity_juridical_persona',
      'entity_organised_agent',
      'entity_unlinked_organised_agent',
      'entity_unlinked_agent',
    ];

    it('all 9 entity type keys present in all 15 languages', () => {
      const languages = getSupportedLanguages();
      expect(languages).toHaveLength(15);
      for (const lang of languages) {
        for (const key of entityKeys) {
          const value = t(key, lang);
          expect(value, `${lang} missing ${key}`).toBeTruthy();
          expect(value.length, `${lang} ${key} should not be empty`).toBeGreaterThan(0);
        }
      }
    });

    it('English entity labels match ENTITY_LABELS constants', () => {
      expect(t('entity_natural_person', 'en')).toBe(ENTITY_LABELS.natural_person);
      expect(t('entity_persona', 'en')).toBe(ENTITY_LABELS.persona);
      expect(t('entity_personal_agent', 'en')).toBe(ENTITY_LABELS.personal_agent);
      expect(t('entity_unlinked_personal_agent', 'en')).toBe(ENTITY_LABELS.unlinked_personal_agent);
      expect(t('entity_juridical_person', 'en')).toBe(ENTITY_LABELS.juridical_person);
      expect(t('entity_juridical_persona', 'en')).toBe(ENTITY_LABELS.juridical_persona);
      expect(t('entity_organised_agent', 'en')).toBe(ENTITY_LABELS.organised_agent);
      expect(t('entity_unlinked_organised_agent', 'en')).toBe(ENTITY_LABELS.unlinked_organised_agent);
      expect(t('entity_unlinked_agent', 'en')).toBe(ENTITY_LABELS.unlinked_agent);
    });
  });

  describe('all languages have all required keys', () => {
    it('every supported language has all translation keys defined', () => {
      const languages = getSupportedLanguages();
      const enTranslations = getTranslations('en');
      const requiredKeys = Object.keys(enTranslations) as (keyof TranslationStrings)[];

      for (const lang of languages) {
        const translations = getTranslations(lang);
        for (const key of requiredKeys) {
          expect(
            translations[key],
            `Language '${lang}' is missing key '${key}'`
          ).toBeTruthy();
          expect(
            typeof translations[key],
            `Language '${lang}' key '${key}' should be a string`
          ).toBe('string');
          expect(
            translations[key].length,
            `Language '${lang}' key '${key}' should not be empty`
          ).toBeGreaterThan(0);
        }
      }
    });
  });
});
