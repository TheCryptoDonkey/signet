// Signet Protocol Constants

/** Generic Verifiable Attestation kind (NIP-VA, placeholder pending NIP assignment) */
export const ATTESTATION_KIND = 30999;

/** NIP-78 App-specific Data kind (existing Nostr kind) */
export const APP_DATA_KIND = 30078;

/** Attestation type identifiers */
export const ATTESTATION_TYPES = {
  CREDENTIAL: 'credential',
  VOUCH: 'vouch',
  VERIFIER: 'verifier',
  CHALLENGE: 'challenge',
  REVOCATION: 'revocation',
  IDENTITY_BRIDGE: 'identity-bridge',
  DELEGATION: 'delegation',
} as const;

/** Voting kinds (moved to separate NIP, kept until Plan 4 extracts them) */
export const VOTING_KINDS = {
  ELECTION: 30482,
  BALLOT: 30483,
  ELECTION_RESULT: 30484,
} as const;

/** @deprecated — use ATTESTATION_KIND + ATTESTATION_TYPES instead */
export const SIGNET_KINDS = {
  CREDENTIAL: ATTESTATION_KIND,
  VOUCH: ATTESTATION_KIND,
  POLICY: APP_DATA_KIND,
  VERIFIER: ATTESTATION_KIND,
  CHALLENGE: ATTESTATION_KIND,
  REVOCATION: ATTESTATION_KIND,
  IDENTITY_BRIDGE: ATTESTATION_KIND,
  DELEGATION: ATTESTATION_KIND,
  ...VOTING_KINDS,
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

/** Signet Score weights (default implementation, 0-200 scale) */
export const TRUST_WEIGHTS = {
  PROFESSIONAL_VERIFICATION: 80,
  IN_PERSON_VOUCH: 16,
  ONLINE_VOUCH: 4,
  ACCOUNT_AGE_PER_YEAR: 10,
  ACCOUNT_AGE_MAX: 30,
  IDENTITY_BRIDGE: 50,
} as const;

/** Minimum ring size for identity bridges (anonymity threshold) */
export const MIN_BRIDGE_RING_SIZE = 5;

/** Maximum Signet Score */
export const MAX_TRUST_SCORE = 200;

/** Valid entity types */
export const ENTITY_TYPES = [
  'natural_person',
  'persona',
  'personal_agent',
  'unlinked_personal_agent',
  'juridical_person',
  'juridical_persona',
  'organised_agent',
  'unlinked_organised_agent',
  'unlinked_agent',
] as const;

/** Valid delegation owner → agent type mappings */
export const DELEGATION_CONSTRAINTS: Record<string, string> = {
  natural_person: 'personal_agent',
  persona: 'unlinked_personal_agent',
  juridical_person: 'organised_agent',
  juridical_persona: 'unlinked_organised_agent',
};

/** App-friendly labels for entity types */
export const ENTITY_LABELS: Record<string, string> = {
  natural_person: 'Person',
  persona: 'Alias',
  personal_agent: 'Personal Agent',
  unlinked_personal_agent: 'Unlinked Personal Agent',
  juridical_person: 'Organisation',
  juridical_persona: 'Org Alias',
  organised_agent: 'Organised Agent',
  unlinked_organised_agent: 'Unlinked Org Agent',
  unlinked_agent: 'Unlinked Agent',
};

/** Default asymmetric cryptographic algorithm (Nostr standard secp256k1).
 * Tagged on events so future parsers can distinguish pre- and post-quantum events. */
export const DEFAULT_CRYPTO_ALGORITHM = 'secp256k1' as const;

/** Cold-call verification constants */
export const COLD_CALL_CONTEXT = 'signet:cold-call';
export const COLD_CALL_EPOCH_SECONDS = 30;
export const COLD_CALL_TOLERANCE = 1;           // ±1 epoch
export const WELL_KNOWN_PATH = '/.well-known/signet.json';
export const WELL_KNOWN_MAX_SIZE = 10240;       // 10 KB
export const WELL_KNOWN_MAX_PUBKEYS = 20;
export const WELL_KNOWN_MAX_CACHE_HOURS = 24;
export const SESSION_CODE_EXPIRY_SECONDS = 300; // 5 minutes

/** NATO phonetic alphabet for session codes */
export const NATO_ALPHABET = [
  'ALFA', 'BRAVO', 'CHARLIE', 'DELTA', 'ECHO', 'FOXTROT',
  'GOLF', 'HOTEL', 'INDIA', 'JULIET', 'KILO', 'LIMA',
  'MIKE', 'NOVEMBER', 'OSCAR', 'PAPA', 'QUEBEC', 'ROMEO',
  'SIERRA', 'TANGO', 'UNIFORM', 'VICTOR', 'WHISKEY',
  'XRAY', 'YANKEE', 'ZULU',
] as const;

/** Signal ordering (protocol-mandated) */
export const SIGNAL_PRIORITY = [
  'professional-verification',
  'identity-bridge',
  'in-person-vouch',
  'online-vouch',
  'account-age',
] as const;
