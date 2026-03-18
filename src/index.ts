// Signet Protocol — TypeScript Library
// Decentralised identity verification for Nostr

// Types
export type {
  CryptoAlgorithm,
  SignetTier,
  VerificationType,
  VerificationScope,
  VerificationMethod,
  VouchMethod,
  EnforcementLevel,
  ChallengeReason,
  BondAction,
  RevocationScope,
  EntityType,
  EntityMode,
  UnsignedEvent,
  NostrEvent,
  CredentialParams,
  VouchParams,
  PolicyParams,
  PolicyCheckResult,
  VerifierParams,
  ChallengeParams,
  RevocationParams,
  TrustSignal,
  TrustScoreBreakdown,
  MerkleProof,
  SelectiveDisclosure,
  ParsedCredential,
  ParsedVouch,
  ParsedPolicy,
  ParsedVerifier,
  ParsedChallenge,
  ParsedRevocation,
  ParsedDelegation,
  ParsedIdentityBridge,
  TwoCredentialResult,
  CredentialChain,
  GuardianDelegationParams,
  GuardianDelegationScope,
  SimpleEntityType,
} from './types.js';

// Entity display labels (value export from types)
export { ENTITY_DISPLAY_LABELS } from './types.js';

// Constants
export {
  ATTESTATION_KIND,
  APP_DATA_KIND,
  ATTESTATION_TYPES,
  SIGNET_KINDS,
  SIGNET_LABEL,
  DEFAULT_VOUCH_THRESHOLD,
  DEFAULT_VOUCHER_MIN_TIER,
  DEFAULT_CREDENTIAL_EXPIRY_SECONDS,
  DEFAULT_REVOCATION_THRESHOLD,
  VERIFIER_ACTIVATION,
  TRUST_WEIGHTS,
  MAX_TRUST_SCORE,
  SIGNAL_PRIORITY,
  MIN_BRIDGE_RING_SIZE,
  ENTITY_TYPES,
  DELEGATION_CONSTRAINTS,
  ENTITY_LABELS,
  DEFAULT_CRYPTO_ALGORITHM,
} from './constants.js';

// Crypto
export {
  generateKeyPair,
  getPublicKey,
  signEvent,
  verifyEvent,
  getEventId,
  hash,
  hashString,
} from './crypto.js';

// Credentials (attestation type: credential)
export {
  buildCredentialEvent,
  createSelfDeclaredCredential,
  createPeerVouchedCredential,
  createProfessionalCredential,
  createChildSafetyCredential,
  verifyCredential,
  isCredentialExpired,
  parseCredential,
  // Ring-signature protected credentials
  createRingProtectedCredential,
  createRingProtectedChildCredential,
  verifyRingProtectedContent,
  // Credential renewal
  renewCredential,
  needsRenewal,
  // Two-credential ceremony
  createTwoCredentialCeremony,
  // Credential chains
  supersedeCredential,
  resolveCredentialChain,
  isSuperseded,
  // Nullifier utilities
  computeNullifier,
  checkNullifierDuplicate,
  buildNullifierChainTag,
  // Multi-document nullifier families
  computeNullifierFamily,
  buildNullifierFamilyTags,
  checkNullifierFamilyDuplicate,
  // Guardian delegation
  createGuardianDelegation,
} from './credentials.js';

export type { RingProtectedContent, DocumentDescriptor, NullifierFamily } from './credentials.js';

// Vouches (attestation type: vouch)
export {
  buildVouchEvent,
  createVouch,
  parseVouch,
  countQualifyingVouches,
  hasEnoughVouches,
  getVouchers,
} from './vouches.js';

// Policies (NIP-78 kind 30078)
export {
  buildPolicyEvent,
  createPolicy,
  parsePolicy,
  checkPolicyCompliance,
  PolicyChecker,
} from './policies.js';

// Verifiers (attestation type: verifier)
export {
  buildVerifierEvent,
  createVerifierCredential,
  parseVerifier,
  checkCrossVerification,
  isVerifierRevoked,
} from './verifiers.js';

// Challenges & Revocations (attestation types: challenge, revocation)
export {
  buildChallengeEvent,
  createChallenge,
  parseChallenge,
  buildRevocationEvent,
  createRevocation,
  parseRevocation,
  countChallengeConfirmations,
  hasReachedRevocationThreshold,
} from './challenges.js';

// Signet Score
export {
  computeTrustScore,
  formatTrustDisplay,
  verifySignalOrdering,
} from './trust-score.js';

// Merkle Tree
export {
  MerkleTree,
  verifyMerkleProof,
  verifySelectiveDisclosure,
} from './merkle.js';

// Ring Signatures
export {
  MAX_RING_SIZE,
  ringSign,
  ringVerify,
  signCredentialRing,
  verifyCredentialRing,
} from './ring-signature.js';

export type { RingSignature } from './ring-signature.js';

// LSAG (Linkable Ring Signatures)
export {
  MAX_RING_SIZE as LSAG_MAX_RING_SIZE,
  computeKeyImage,
  lsagSign,
  lsagVerify,
  hasDuplicateKeyImage,
} from './lsag.js';

export type { LsagSignature } from './lsag.js';

// Identity Bridge (attestation type: identity-bridge)
export {
  createIdentityBridge,
  verifyIdentityBridge,
  parseIdentityBridge,
  selectDecoyRing,
  computeBridgeWeight,
} from './identity-bridge.js';

// Range Proofs (Pedersen Commitments)
export {
  commit,
  verifyCommitment,
  createRangeProof,
  verifyRangeProof,
  createAgeRangeProof,
  verifyAgeRangeProof,
  serializeRangeProof,
  deserializeRangeProof,
} from './range-proof.js';

export type { PedersenCommitment, RangeProof } from './range-proof.js';

// Relay Client
export {
  RelayClient,
  publishToRelays,
  fetchFromRelay,
} from './relay.js';

export type {
  RelayMessage,
  NostrFilter,
  SubscriptionCallback,
  RelayState,
  RelayOptions,
} from './relay.js';

// Event Store
export { SignetStore } from './store.js';
export type { StoreQuery } from './store.js';

// Anomaly Detection
export {
  detectAnomalies,
  scanForAnomalies,
} from './anomaly.js';

export type {
  AnomalyType,
  AnomalyFlag,
  AnomalyConfig,
} from './anomaly.js';

// Jurisdictions (re-exported from jurisdiction-kit)
export {
  JURISDICTIONS,
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
  computeJurisdictionConfidence,
  getJurisdictionConfidence,
  rankJurisdictionsByConfidence,
} from 'jurisdiction-kit';

export type {
  LegalSystem,
  ProfessionType,
  ProfessionalBody,
  DataProtectionLaw,
  ChildProtectionLaw,
  Jurisdiction,
  JurisdictionConfidence,
} from 'jurisdiction-kit';

// Internationalization
export {
  setLanguage,
  getLanguage,
  getSupportedLanguages,
  t,
  getTranslations,
  getLanguageName,
  getLanguageNativeName,
  formatLocalizedTrustScore,
  getTierDescription,
} from './i18n.js';

export type { LanguageCode, TranslationStrings } from './i18n.js';

// Compliance
export {
  checkCredentialCompliance,
  checkCrossBorderCompliance,
  checkChildCompliance,
  getConsentRequirements,
  getRetentionGuidance,
  checkMultiJurisdictionCompliance,
  getMostRestrictiveRequirements,
} from './compliance.js';

export type {
  ComplianceSeverity,
  ComplianceIssue,
  ComplianceResult,
  CrossBorderResult,
  ChildComplianceResult,
  ConsentRequirement,
} from './compliance.js';

// Validation
export {
  validateCredential,
  validateVouch,
  validatePolicy,
  validateVerifier,
  validateChallenge,
  validateRevocation,
  validateEvent,
  getTagValue,
  getTagValues,
} from './validation.js';

export type { ValidationResult } from './validation.js';

// Errors
export {
  SignetError,
  SignetValidationError,
  SignetCryptoError,
} from './errors.js';

// BIP-39 Wordlist
export { wordlist as BIP39_WORDLIST } from '@scure/bip39/wordlists/english.js';

// Mnemonic (BIP-39)
export {
  generateMnemonic,
  mnemonicToEntropy,
  entropyToMnemonic,
  validateMnemonic,
} from '@scure/bip39';
export { mnemonicToSeedSync as mnemonicToSeed } from '@scure/bip39';

// Key Derivation (BIP-32 / NIP-06) & nsec/npub encoding (NIP-19)
export {
  NIP06_DERIVATION_PATH,
  parsePath,
  deriveKeyFromSeed,
  deriveNostrKeyPair,
  createIdentityFromMnemonic,
  deriveChildAccount,
  encodeNsec,
  encodeNpub,
  decodeNsec,
} from './key-derivation.js';

// Shamir's Secret Sharing
export {
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
} from './shamir.js';

export type { ShamirShare } from './shamir.js';

// Connections (ECDH / QR Exchange)
export {
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  createConnection,
  ConnectionStore,
} from './connections.js';

export type { ContactInfo, Connection, QRPayload } from './connections.js';

// Badge Display (Level 1 integration)
export {
  computeBadge,
  getTrustLevel,
  meetsMinimumTier,
  filterEventsForPubkey,
  buildBadgeFilters,
} from './badge.js';

export type { BadgeInfo, TrustLevel } from './badge.js';

// Signet Words (Time-Based Verification — powered by spoken-token)
export {
  SIGNET_EPOCH_SECONDS,
  SIGNET_WORD_COUNT,
  SIGNET_TOLERANCE,
  MAX_WORD_COUNT,
  SIGNET_WORDLIST,
  getEpoch,
  deriveWords,
  getSignetWords,
  verifySignetWords,
  formatSignetWords,
  getSignetDisplay,
} from './signet-words.js';

export type { SignetWordsConfig } from './signet-words.js';

// Cold-Call Verification (institutional caller verification via .well-known/signet.json + ephemeral ECDH)
export {
  fetchInstitutionKeys,
  generateSessionCode,
  deriveColdCallWords,
  initiateColdCallVerification,
  completeColdCallVerification,
  type ColdCallSession,
} from './cold-call.js';

export type { InstitutionKeys, InstitutionPubkey } from './types.js';
