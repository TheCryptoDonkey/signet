// Signet Compliance Module
// Jurisdiction-aware compliance checking for credentials, data transfers,
// child protection, and professional regulation.

import {
  getJurisdiction,
  canTransferData,
  isProfessionRegulated,
  type Jurisdiction,
  type ProfessionType,
} from './jurisdictions.js';
import { getTagValue } from './validation.js';
import type { NostrEvent } from './types.js';

// --- Types ---

export type ComplianceSeverity = 'error' | 'warning' | 'info';

export interface ComplianceIssue {
  code: string;
  severity: ComplianceSeverity;
  jurisdiction: string;
  message: string;
  regulation: string;
  remediation?: string;
}

export interface ComplianceResult {
  compliant: boolean;
  issues: ComplianceIssue[];
  jurisdiction: string;
  checkedAt: number;
}

export interface CrossBorderResult {
  allowed: boolean;
  mechanism?: string;
  issues: ComplianceIssue[];
  fromJurisdiction: string;
  toJurisdiction: string;
}

export interface ChildComplianceResult {
  compliant: boolean;
  issues: ComplianceIssue[];
  jurisdiction: string;
  minConsentAge: number;
  ageOfMajority: number;
  requiresParentalConsent: boolean;
}

export interface ConsentRequirement {
  jurisdiction: string;
  requiresExplicitConsent: boolean;
  consentAge: number;
  parentalConsentRequired: boolean;
  dataCategories: string[];
  specialCategories: string[];
  notes?: string;
}

const GDPR_JURISDICTIONS = ['GB', 'FR', 'DE', 'ES', 'IT', 'NL', 'IE'];

// --- Credential Compliance ---

/**
 * Check if a credential complies with a jurisdiction's regulations.
 */
export function checkCredentialCompliance(
  credential: NostrEvent,
  jurisdictionCode: string
): ComplianceResult {
  const issues: ComplianceIssue[] = [];
  const j = getJurisdiction(jurisdictionCode);

  if (!j) {
    return {
      compliant: false,
      issues: [{
        code: 'UNKNOWN_JURISDICTION',
        severity: 'error',
        jurisdiction: jurisdictionCode,
        message: `Jurisdiction '${jurisdictionCode}' is not recognised in the Signet registry.`,
        regulation: 'Signet Protocol',
      }],
      jurisdiction: jurisdictionCode,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  // Check profession regulation
  const profession = getTagValue(credential, 'profession');
  if (profession) {
    const profType = mapProfessionString(profession);
    if (profType && !isProfessionRegulated(jurisdictionCode, profType)) {
      issues.push({
        code: 'PROFESSION_NOT_REGULATED',
        severity: 'warning',
        jurisdiction: jurisdictionCode,
        message: `Profession '${profession}' is not registered as regulated in ${j.name}.`,
        regulation: 'Professional Regulation',
        remediation: 'Verify the profession is regulated in this jurisdiction before issuing credentials.',
      });
    }
  }

  // Check credential expiry
  const expiresStr = getTagValue(credential, 'expires');
  if (expiresStr) {
    const expires = parseInt(expiresStr, 10);
    const now = Math.floor(Date.now() / 1000);
    if (expires < now) {
      issues.push({
        code: 'CREDENTIAL_EXPIRED',
        severity: 'error',
        jurisdiction: jurisdictionCode,
        message: 'Credential has expired.',
        regulation: 'Credential Validity',
        remediation: 'Renew the credential before use.',
      });
    }
  }

  // Check electronic signature recognition
  if (!j.eSignatureRecognised) {
    issues.push({
      code: 'ESIGNATURE_NOT_RECOGNISED',
      severity: 'warning',
      jurisdiction: jurisdictionCode,
      message: `Electronic signatures may not be fully recognised in ${j.name}.`,
      regulation: 'Electronic Signatures',
      remediation: 'Additional attestation or wet signature may be required.',
    });
  }

  // Check scope for child-related credentials
  const scope = getTagValue(credential, 'scope');
  if (scope === 'adult+child') {
    const childIssues = checkChildDataRequirements(credential, j);
    issues.push(...childIssues);
  }

  // Check data protection consent requirements
  if (j.dataProtection.requiresExplicitConsent) {
    issues.push({
      code: 'CONSENT_REQUIRED',
      severity: 'info',
      jurisdiction: jurisdictionCode,
      message: `${j.dataProtection.name} requires explicit consent for processing personal data.`,
      regulation: j.dataProtection.fullName,
      remediation: 'Ensure explicit consent is obtained and recorded before credential issuance.',
    });
  }

  // Check breach notification requirements
  if (j.dataProtection.breachNotificationHours > 0) {
    issues.push({
      code: 'BREACH_NOTIFICATION',
      severity: 'info',
      jurisdiction: jurisdictionCode,
      message: `Data breaches must be reported to ${j.dataProtection.supervisoryAuthority} within ${j.dataProtection.breachNotificationHours} hours.`,
      regulation: j.dataProtection.fullName,
    });
  }

  return {
    compliant: !issues.some((i) => i.severity === 'error'),
    issues,
    jurisdiction: jurisdictionCode,
    checkedAt: Math.floor(Date.now() / 1000),
  };
}

// --- Cross-Border Compliance ---

/**
 * Check if a credential can be used across borders.
 */
export function checkCrossBorderCompliance(
  fromJurisdiction: string,
  toJurisdiction: string
): CrossBorderResult {
  const issues: ComplianceIssue[] = [];
  const transfer = canTransferData(fromJurisdiction, toJurisdiction);

  const fromJ = getJurisdiction(fromJurisdiction);
  const toJ = getJurisdiction(toJurisdiction);

  if (!fromJ || !toJ) {
    return {
      allowed: false,
      issues: [{
        code: 'UNKNOWN_JURISDICTION',
        severity: 'error',
        jurisdiction: fromJurisdiction,
        message: 'One or both jurisdictions are not recognised.',
        regulation: 'Signet Protocol',
      }],
      fromJurisdiction,
      toJurisdiction,
    };
  }

  if (transfer.mechanism === 'safeguards-required') {
    issues.push({
      code: 'SAFEGUARDS_REQUIRED',
      severity: 'warning',
      jurisdiction: fromJurisdiction,
      message: `Transfer from ${fromJ.name} to ${toJ.name} requires Standard Contractual Clauses or equivalent safeguards.`,
      regulation: fromJ.dataProtection.fullName,
      remediation: 'Implement SCCs, BCRs, or obtain an adequacy determination.',
    });
  }

  // Special cases
  if (fromJurisdiction === 'CN') {
    issues.push({
      code: 'CN_DATA_LOCALIZATION',
      severity: 'warning',
      jurisdiction: 'CN',
      message: 'China\'s PIPL requires data localization. Cross-border transfers require security assessment by CAC.',
      regulation: 'Personal Information Protection Law (PIPL)',
      remediation: 'Complete a data export security assessment or obtain PPC certification.',
    });
  }

  if (fromJurisdiction === 'IN') {
    issues.push({
      code: 'IN_DATA_LOCALIZATION',
      severity: 'info',
      jurisdiction: 'IN',
      message: 'India\'s DPDPA 2023 may restrict transfers to certain jurisdictions via government notification.',
      regulation: 'Digital Personal Data Protection Act 2023',
      remediation: 'Check the list of restricted jurisdictions published by the Indian government.',
    });
  }

  if (fromJurisdiction === 'SA') {
    issues.push({
      code: 'SA_CROSS_BORDER',
      severity: 'warning',
      jurisdiction: 'SA',
      message: 'Saudi Arabia requires data to remain within the Kingdom unless specific conditions are met.',
      regulation: 'Personal Data Protection Law (Royal Decree M/19)',
      remediation: 'Ensure the transfer meets SDAIA cross-border transfer requirements.',
    });
  }

  return {
    allowed: transfer.allowed,
    mechanism: transfer.mechanism,
    issues,
    fromJurisdiction,
    toJurisdiction,
  };
}

// --- Child Protection Compliance ---

/**
 * Check child data protection compliance for a jurisdiction.
 */
export function checkChildCompliance(
  childAge: number,
  jurisdictionCode: string
): ChildComplianceResult {
  const issues: ComplianceIssue[] = [];
  const j = getJurisdiction(jurisdictionCode);

  if (!j) {
    return {
      compliant: false,
      issues: [{
        code: 'UNKNOWN_JURISDICTION',
        severity: 'error',
        jurisdiction: jurisdictionCode,
        message: `Jurisdiction '${jurisdictionCode}' is not recognised.`,
        regulation: 'Signet Protocol',
      }],
      jurisdiction: jurisdictionCode,
      minConsentAge: 16,
      ageOfMajority: 18,
      requiresParentalConsent: true,
    };
  }

  const consentAge = j.childProtection.minAgeDigitalConsent;
  const majority = j.childProtection.ageOfMajority;
  const needsParental = childAge < consentAge;

  if (needsParental) {
    issues.push({
      code: 'PARENTAL_CONSENT_REQUIRED',
      severity: 'error',
      jurisdiction: jurisdictionCode,
      message: `Child age ${childAge} is below the digital consent age of ${consentAge} in ${j.name}. Verifiable parental consent is required.`,
      regulation: j.childProtection.name,
      remediation: 'Obtain and record verifiable parental consent before processing child data.',
    });
  }

  if (j.childProtection.enhancedProtections) {
    issues.push({
      code: 'ENHANCED_CHILD_PROTECTIONS',
      severity: 'info',
      jurisdiction: jurisdictionCode,
      message: `${j.name} requires enhanced protections for children's data under ${j.childProtection.name}.`,
      regulation: j.childProtection.name,
      remediation: 'Apply data minimisation, purpose limitation, and enhanced security for child data.',
    });
  }

  if (j.childProtection.profilingRestrictions) {
    issues.push({
      code: 'PROFILING_RESTRICTED',
      severity: 'warning',
      jurisdiction: jurisdictionCode,
      message: `Automated profiling of children is restricted in ${j.name}.`,
      regulation: j.childProtection.name,
      remediation: 'Do not use child data for automated profiling or targeted services.',
    });
  }

  // Jurisdiction-specific child protection rules
  if (jurisdictionCode === 'US') {
    issues.push({
      code: 'COPPA_COMPLIANCE',
      severity: 'warning',
      jurisdiction: 'US',
      message: 'COPPA requires verifiable parental consent before collecting data from children under 13.',
      regulation: "Children's Online Privacy Protection Act (COPPA)",
      remediation: 'Implement COPPA-compliant consent mechanisms (signed form, credit card verification, etc.).',
    });
  }

  if (jurisdictionCode === 'GB') {
    issues.push({
      code: 'AADC_COMPLIANCE',
      severity: 'info',
      jurisdiction: 'GB',
      message: 'The Age Appropriate Design Code (Children\'s Code) applies to services likely to be accessed by children.',
      regulation: 'Age Appropriate Design Code (ICO)',
      remediation: 'Conduct a Data Protection Impact Assessment (DPIA) for child-facing features.',
    });
  }

  return {
    compliant: !issues.some((i) => i.severity === 'error'),
    issues,
    jurisdiction: jurisdictionCode,
    minConsentAge: consentAge,
    ageOfMajority: majority,
    requiresParentalConsent: needsParental,
  };
}

// --- Consent Requirements ---

/**
 * Get consent requirements for a jurisdiction.
 */
export function getConsentRequirements(jurisdictionCode: string): ConsentRequirement {
  const j = getJurisdiction(jurisdictionCode);

  if (!j) {
    return {
      jurisdiction: jurisdictionCode,
      requiresExplicitConsent: true,
      consentAge: 16,
      parentalConsentRequired: true,
      dataCategories: ['identity', 'professional-status'],
      specialCategories: ['biometric-hash', 'child-age-range'],
    };
  }

  const base: ConsentRequirement = {
    jurisdiction: jurisdictionCode,
    requiresExplicitConsent: j.dataProtection.requiresExplicitConsent,
    consentAge: j.childProtection.minAgeDigitalConsent,
    parentalConsentRequired: j.childProtection.requiresParentalConsent,
    dataCategories: ['identity', 'professional-status', 'jurisdiction'],
    specialCategories: [],
  };

  // Add special category data based on credential types
  if (j.childProtection.enhancedProtections) {
    base.specialCategories.push('child-age-range');
  }

  // GDPR special categories
  if (GDPR_JURISDICTIONS.includes(jurisdictionCode)) {
    base.specialCategories.push('biometric-hash');
    base.notes = 'GDPR Article 9 applies — biometric data used for identification is a special category.';
  }

  // Brazil LGPD sensitive data
  if (jurisdictionCode === 'BR') {
    base.specialCategories.push('biometric-hash');
    base.notes = 'LGPD treats biometric data as sensitive personal data requiring specific legal basis.';
  }

  return base;
}

// --- Data Retention ---

/**
 * Get data retention guidance for a jurisdiction.
 */
export function getRetentionGuidance(jurisdictionCode: string): {
  maxDays: number;
  guidance: string;
  regulation: string;
} {
  const j = getJurisdiction(jurisdictionCode);
  if (!j) {
    return {
      maxDays: 365,
      guidance: 'Unknown jurisdiction — apply a conservative 1-year retention period.',
      regulation: 'Best Practice',
    };
  }

  if (j.dataProtection.maxRetentionDays > 0) {
    return {
      maxDays: j.dataProtection.maxRetentionDays,
      guidance: `${j.name} mandates a maximum retention of ${j.dataProtection.maxRetentionDays} days.`,
      regulation: j.dataProtection.fullName,
    };
  }

  // Default guidance based on jurisdiction type
  if (GDPR_JURISDICTIONS.includes(jurisdictionCode)) {
    return {
      maxDays: 0,
      guidance: 'GDPR requires data to be kept no longer than necessary for the purpose. Apply data minimisation. Signet credentials are inherently time-limited via the expires tag.',
      regulation: j.dataProtection.fullName,
    };
  }

  return {
    maxDays: 0,
    guidance: `${j.dataProtection.name} does not specify a fixed retention period. Data should be retained only as long as necessary for the processing purpose.`,
    regulation: j.dataProtection.fullName,
  };
}

// --- Multi-Jurisdiction Compliance ---

/**
 * Check compliance across multiple jurisdictions simultaneously.
 * Useful for credentials that may be used internationally.
 */
export function checkMultiJurisdictionCompliance(
  credential: NostrEvent,
  jurisdictions: string[]
): Map<string, ComplianceResult> {
  const results = new Map<string, ComplianceResult>();
  for (const code of jurisdictions) {
    results.set(code, checkCredentialCompliance(credential, code));
  }
  return results;
}

/**
 * Find the most restrictive requirements across jurisdictions.
 * Useful for setting defaults that satisfy all target jurisdictions.
 */
export function getMostRestrictiveRequirements(jurisdictions: string[]): {
  highestConsentAge: number;
  highestAgeOfMajority: number;
  requiresExplicitConsent: boolean;
  shortestBreachNotification: number;
  allRequireErasure: boolean;
  jurisdictions: string[];
} {
  let highestConsentAge = 0;
  let highestAgeOfMajority = 0;
  let requiresExplicitConsent = false;
  let shortestBreachNotification = Infinity;
  let allRequireErasure = true;

  for (const code of jurisdictions) {
    const j = getJurisdiction(code);
    if (!j) continue;

    highestConsentAge = Math.max(highestConsentAge, j.childProtection.minAgeDigitalConsent);
    highestAgeOfMajority = Math.max(highestAgeOfMajority, j.childProtection.ageOfMajority);
    if (j.dataProtection.requiresExplicitConsent) requiresExplicitConsent = true;
    if (j.dataProtection.breachNotificationHours > 0) {
      shortestBreachNotification = Math.min(shortestBreachNotification, j.dataProtection.breachNotificationHours);
    }
    if (!j.dataProtection.rightToErasure) allRequireErasure = false;
  }

  return {
    highestConsentAge,
    highestAgeOfMajority,
    requiresExplicitConsent,
    shortestBreachNotification: shortestBreachNotification === Infinity ? 0 : shortestBreachNotification,
    allRequireErasure,
    jurisdictions,
  };
}

// --- Internal Helpers ---

function mapProfessionString(profession: string): ProfessionType | undefined {
  const map: Record<string, ProfessionType> = {
    solicitor: 'legal', lawyer: 'legal', attorney: 'legal', advocate: 'legal',
    barrister: 'legal', avocat: 'legal', abogado: 'legal', advogado: 'legal',
    rechtsanwalt: 'legal', avvocato: 'legal', advocaat: 'legal',
    doctor: 'medical', physician: 'medical', surgeon: 'medical',
    médecin: 'medical', arzt: 'medical', medico: 'medical',
    notary: 'notary', notaire: 'notary', notar: 'notary', notaio: 'notary',
    accountant: 'accounting', cpa: 'accounting', 'chartered-accountant': 'accounting',
    'expert-comptable': 'accounting', wirtschaftsprüfer: 'accounting',
    engineer: 'engineering', ingénieur: 'engineering', ingenieur: 'engineering',
    ingeniero: 'engineering', engenheiro: 'engineering',
    teacher: 'teaching', enseignant: 'teaching', lehrer: 'teaching',
    profesor: 'teaching', professor: 'teaching',
    veterinarian: 'veterinary', vet: 'veterinary',
    veterinario: 'veterinary', vétérinaire: 'veterinary', tierarzt: 'veterinary',
    pharmacist: 'pharmacy', 'pharmacy-technician': 'pharmacy',
    farmacéutico: 'pharmacy', pharmacien: 'pharmacy', apotheker: 'pharmacy',
    architect: 'architecture',
    arquitecto: 'architecture', architecte: 'architecture', architekt: 'architecture',
    'social-worker': 'social-work', 'social worker': 'social-work',
    nurse: 'medical', midwife: 'medical',
    dentist: 'medical', 'dental-hygienist': 'medical',
    optometrist: 'medical', optician: 'medical',
    osteopath: 'medical', chiropractor: 'medical',
    paramedic: 'medical', physiotherapist: 'medical',
    radiographer: 'medical', dietitian: 'medical',
    'speech-therapist': 'medical', 'occupational-therapist': 'medical',
  };
  return map[profession.toLowerCase()];
}

function checkChildDataRequirements(
  credential: NostrEvent,
  j: Jurisdiction
): ComplianceIssue[] {
  const issues: ComplianceIssue[] = [];

  // Check age range tag
  const ageRange = getTagValue(credential, 'age-range');
  if (!ageRange) {
    issues.push({
      code: 'MISSING_AGE_RANGE',
      severity: 'error',
      jurisdiction: j.code,
      message: 'Child credential is missing the age-range tag.',
      regulation: j.childProtection.name,
      remediation: 'Include an age-range tag (e.g., "8-12") in the credential.',
    });
    return issues;
  }

  // Handle "18+" format (adults, no upper bound)
  let minAge: number;
  let maxAge: number;
  if (ageRange.endsWith('+')) {
    minAge = parseInt(ageRange.slice(0, -1), 10);
    maxAge = 150;
  } else {
    const [minStr, maxStr] = ageRange.split('-');
    minAge = parseInt(minStr, 10);
    maxAge = parseInt(maxStr, 10);
  }

  // Check if age range falls below digital consent age
  if (maxAge < j.childProtection.minAgeDigitalConsent) {
    issues.push({
      code: 'BELOW_CONSENT_AGE',
      severity: 'warning',
      jurisdiction: j.code,
      message: `Age range ${ageRange} is entirely below the digital consent age of ${j.childProtection.minAgeDigitalConsent} in ${j.name}. Parental consent is required.`,
      regulation: j.childProtection.name,
      remediation: 'Ensure verifiable parental consent has been obtained.',
    });
  }

  // Check that the age range is within expected bounds
  if (minAge < 0 || maxAge > j.childProtection.ageOfMajority) {
    issues.push({
      code: 'INVALID_AGE_RANGE',
      severity: 'warning',
      jurisdiction: j.code,
      message: `Age range ${ageRange} extends beyond expected bounds for ${j.name} (0-${j.childProtection.ageOfMajority}).`,
      regulation: j.childProtection.name,
    });
  }

  return issues;
}
