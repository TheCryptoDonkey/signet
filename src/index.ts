// Signet Protocol — TypeScript Library
// Decentralised identity verification for Nostr

// Types
export type {
  SignetTier,
  VerificationType,
  VerificationScope,
  VerificationMethod,
  VouchMethod,
  EnforcementLevel,
  ChallengeReason,
  BondAction,
  RevocationScope,
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
  ParsedIdentityBridge,
} from './types.js';

// Constants
export {
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

// Credentials (kind 30470)
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
} from './credentials.js';

export type { RingProtectedContent } from './credentials.js';

// Vouches (kind 30471)
export {
  buildVouchEvent,
  createVouch,
  parseVouch,
  countQualifyingVouches,
  hasEnoughVouches,
  getVouchers,
} from './vouches.js';

// Policies (kind 30472)
export {
  buildPolicyEvent,
  createPolicy,
  parsePolicy,
  checkPolicyCompliance,
  PolicyChecker,
} from './policies.js';

// Verifiers (kind 30473)
export {
  buildVerifierEvent,
  createVerifierCredential,
  parseVerifier,
  checkCrossVerification,
  isVerifierRevoked,
} from './verifiers.js';

// Challenges & Revocations (kind 30474, 30475)
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

// Trust Score
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
  ringSign,
  ringVerify,
  signCredentialRing,
  verifyCredentialRing,
} from './ring-signature.js';

export type { RingSignature } from './ring-signature.js';

// Identity Bridge (kind 30476)
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

// Jurisdictions
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
} from './jurisdictions.js';

export type {
  LegalSystem,
  ProfessionType,
  ProfessionalBody,
  DataProtectionLaw,
  ChildProtectionLaw,
  Jurisdiction,
} from './jurisdictions.js';

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

// BIP-39 Wordlist
export { BIP39_WORDLIST, wordIndex } from './wordlist.js';

// Mnemonic (BIP-39)
export {
  generateEntropy,
  entropyToMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
  mnemonicToSeed,
  generateMnemonic,
} from './mnemonic.js';

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
  gf256Add,
  gf256Mul,
  gf256Inv,
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

// Signet Words (Time-Based Verification)
export {
  SIGNET_EPOCH_SECONDS,
  SIGNET_WORD_COUNT,
  SIGNET_TOLERANCE,
  getEpoch,
  deriveWords,
  getSignetWords,
  verifySignetWords,
  formatSignetWords,
  getSignetDisplay,
} from './signet-words.js';
