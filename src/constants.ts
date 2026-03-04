// Signet Protocol Constants

/** Nostr event kind numbers (placeholders pending NIP allocation) */
export const SIGNET_KINDS = {
  CREDENTIAL: 30470,
  VOUCH: 30471,
  POLICY: 30472,
  VERIFIER: 30473,
  CHALLENGE: 30474,
  REVOCATION: 30475,
  IDENTITY_BRIDGE: 30476,
  DELEGATION: 30477,
} as const;

/** Protocol namespace label */
export const SIGNET_LABEL = 'signet';

/** Default number of vouches needed for Tier 2 */
export const DEFAULT_VOUCH_THRESHOLD = 3;

/** Default minimum tier of vouchers for Tier 2 */
export const DEFAULT_VOUCHER_MIN_TIER = 2;

/** Default credential expiry: 2 years in seconds */
export const DEFAULT_CREDENTIAL_EXPIRY_SECONDS = 2 * 365 * 24 * 60 * 60;

/** Default number of Tier 3+ confirmations to revoke a verifier */
export const DEFAULT_REVOCATION_THRESHOLD = 5;

/** Minimum cross-verification requirements for verifier activation */
export const VERIFIER_ACTIVATION = {
  MIN_VOUCHES: 2,
  MIN_PROFESSIONS: 2,
} as const;

/** Trust score weights (default implementation) */
export const TRUST_WEIGHTS = {
  PROFESSIONAL_VERIFICATION: 40,
  IN_PERSON_VOUCH: 8,
  ONLINE_VOUCH: 2,
  ACCOUNT_AGE_PER_YEAR: 5,
  ACCOUNT_AGE_MAX: 15,
  IDENTITY_BRIDGE: 25,
} as const;

/** Minimum ring size for identity bridges (anonymity threshold) */
export const MIN_BRIDGE_RING_SIZE = 5;

/** Maximum trust score */
export const MAX_TRUST_SCORE = 100;

/** Valid entity types */
export const ENTITY_TYPES = [
  'natural_person',
  'persona',
  'personal_agent',
  'free_personal_agent',
  'juridical_person',
  'juridical_persona',
  'organised_agent',
  'free_organised_agent',
  'free_agent',
] as const;

/** Valid delegation owner → agent type mappings */
export const DELEGATION_CONSTRAINTS: Record<string, string> = {
  natural_person: 'personal_agent',
  persona: 'free_personal_agent',
  juridical_person: 'organised_agent',
  juridical_persona: 'free_organised_agent',
};

/** App-friendly labels for entity types */
export const ENTITY_LABELS: Record<string, string> = {
  natural_person: 'Person',
  persona: 'Alias',
  personal_agent: 'Personal Agent',
  free_personal_agent: 'Free Personal Agent',
  juridical_person: 'Organisation',
  juridical_persona: 'Org Alias',
  organised_agent: 'Organised Agent',
  free_organised_agent: 'Free Org Agent',
  free_agent: 'Free Agent',
};

/** Signal ordering (protocol-mandated) */
export const SIGNAL_PRIORITY = [
  'professional-verification',
  'identity-bridge',
  'in-person-vouch',
  'online-vouch',
  'account-age',
] as const;
