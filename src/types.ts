// Signet Protocol Types
// All TypeScript interfaces for the 11 Nostr event kinds (8 core + 3 voting extension) and supporting structures

/** Asymmetric cryptographic algorithm for event signing and key agreement.
 * 'secp256k1' is the current Nostr standard. Additional algorithms
 * (e.g. post-quantum lattice-based schemes) may be added in future versions. */
export type CryptoAlgorithm = 'secp256k1' | (string & {});

/** Verification tier levels */
export type SignetTier = 1 | 2 | 3 | 4;

/** How the verification was performed */
export type VerificationType = 'self' | 'peer' | 'professional';

/** Scope of verification */
export type VerificationScope = 'adult' | 'adult+child';

/** Method of verification */
export type VerificationMethod =
  | 'self-declaration'
  | 'in-person'
  | 'online'
  | 'in-person-id';

/** Vouch method */
export type VouchMethod = 'in-person' | 'online';

/** Policy enforcement level */
export type EnforcementLevel = 'client' | 'relay' | 'both';

/** Challenge reasons */
export type ChallengeReason =
  | 'anomalous-volume'
  | 'registry-mismatch'
  | 'fraudulent-attestation'
  | 'licence-revoked'
  | 'other';

/** Bond action on revocation */
export type BondAction = 'slashed' | 'returned' | 'held';

/** Revocation scope */
export type RevocationScope = 'full' | 'partial';

// --- Base Nostr Event ---

export interface UnsignedEvent {
  kind: number;
  pubkey: string;
  created_at: number;
  tags: string[][];
  content: string;
}

export interface NostrEvent extends UnsignedEvent {
  id: string;
  sig: string;
}

// --- Kind 30470: Verification Credential ---

export interface CredentialParams {
  subjectPubkey: string;
  tier: SignetTier;
  type: VerificationType;
  scope: VerificationScope;
  method: VerificationMethod;
  expiresAt: number;
  profession?: string;
  jurisdiction?: string;
  ageRange?: string; // e.g. "8-12", "18+"
  content?: string;  // ZKP proof blob
  entityType?: EntityType;
  nullifier?: string;
  merkleRoot?: string;
  guardianPubkeys?: string[];
  supersedes?: string; // event ID of superseded credential
}

// --- Kind 30471: Vouch Attestation ---

export interface VouchParams {
  subjectPubkey: string;
  method: VouchMethod;
  context?: string;
  voucherTier: SignetTier;
  voucherScore: number;
}

// --- Kind 30472: Community Verification Policy ---

export interface PolicyParams {
  communityId: string;
  adultMinTier: SignetTier;
  childMinTier: SignetTier;
  enforcement: EnforcementLevel;
  minScore?: number;
  modMinTier?: SignetTier;
  verifierBond?: number;
  revocationThreshold?: number;
  description?: string;
}

export interface PolicyCheckResult {
  allowed: boolean;
  reason?: string;
  requiredTier: SignetTier;
  actualTier: SignetTier;
  requiredScore?: number;
  actualScore?: number;
}

// --- Kind 30473: Verifier Credential ---

export interface VerifierParams {
  profession: string;
  jurisdiction: string;
  licenceHash: string;
  professionalBody: string;
  statement?: string;
}

// --- Kind 30474: Verifier Challenge ---

export interface ChallengeParams {
  verifierPubkey: string;
  reason: ChallengeReason;
  evidenceType: string;
  reporterTier: SignetTier;
  evidence: string;
}

// --- Kind 30475: Verifier Revocation ---

export interface RevocationParams {
  verifierPubkey: string;
  challengeEventId: string;
  confirmations: number;
  bondAction: BondAction;
  scope: RevocationScope;
  effectiveAt: number;
  summary: string;
}

// --- Signet Score ---

export interface TrustSignal {
  type: 'professional-verification' | 'in-person-vouch' | 'online-vouch' | 'account-age' | 'identity-bridge';
  weight: number;
  source?: string; // pubkey of signal source
  score?: number;  // source's own score (for vouch multiplier)
}

export interface TrustScoreBreakdown {
  score: number; // 0-200 (Signet Score)
  tier: SignetTier;
  professionalVerifications: number;
  inPersonVouches: number;
  onlineVouches: number;
  accountAgeDays: number;
  signals: TrustSignal[];
}

// --- Merkle Selective Disclosure ---

export interface MerkleProof {
  leaf: string;
  index: number;
  siblings: string[];
  root: string;
}

export interface SelectiveDisclosure {
  revealedAttributes: Record<string, string>;
  proofs: MerkleProof[];
  merkleRoot: string;
}

// --- Parsed event helpers ---

export interface ParsedCredential {
  subjectPubkey: string;
  tier: SignetTier;
  type: VerificationType;
  scope: VerificationScope;
  method: VerificationMethod;
  profession?: string;
  jurisdiction?: string;
  ageRange?: string;
  expiresAt?: number;
  entityType?: EntityType;
  nullifier?: string;
  merkleRoot?: string;
  guardianPubkeys?: string[];
  supersedes?: string;
  supersededBy?: string;
  algorithm: CryptoAlgorithm;
}

export interface ParsedVouch {
  subjectPubkey: string;
  method: VouchMethod;
  context?: string;
  voucherTier: SignetTier;
  voucherScore: number;
  algorithm: CryptoAlgorithm;
}

export interface ParsedPolicy {
  communityId: string;
  adultMinTier: SignetTier;
  childMinTier: SignetTier;
  enforcement: EnforcementLevel;
  minScore?: number;
  modMinTier?: SignetTier;
  verifierBond?: number;
  revocationThreshold?: number;
  algorithm: CryptoAlgorithm;
}

export interface ParsedVerifier {
  profession: string;
  jurisdiction: string;
  licenceHash: string;
  professionalBody: string;
  algorithm: CryptoAlgorithm;
}

export interface ParsedChallenge {
  verifierPubkey: string;
  reason: ChallengeReason;
  evidenceType: string;
  reporterTier: SignetTier;
  algorithm: CryptoAlgorithm;
}

export interface ParsedRevocation {
  verifierPubkey: string;
  challengeEventId: string;
  confirmations: number;
  bondAction: BondAction;
  scope: RevocationScope;
  effectiveAt: number;
  algorithm: CryptoAlgorithm;
}

// --- Entity Type Classification ---

/** Entity type classification (§17 of spec) */
export type EntityType =
  | 'natural_person'
  | 'persona'
  | 'personal_agent'
  | 'unlinked_personal_agent'
  | 'juridical_person'
  | 'juridical_persona'
  | 'organised_agent'
  | 'unlinked_organised_agent'
  | 'unlinked_agent';

/** Developer-friendly entity type labels */
export type SimpleEntityType = 'person' | 'persona' | 'organisation' | 'agent';

/** Maps full entity types to simplified labels */
export const ENTITY_DISPLAY_LABELS: Record<EntityType, SimpleEntityType> = {
  natural_person: 'person',
  persona: 'persona',
  juridical_person: 'organisation',
  juridical_persona: 'organisation',
  personal_agent: 'agent',
  organised_agent: 'agent',
  unlinked_agent: 'agent',
  unlinked_personal_agent: 'agent',
  unlinked_organised_agent: 'agent',
};

/** Dynamic mode signaling for teleoperated/autonomous entities (§17.9) */
export type EntityMode =
  | 'teleoperated'
  | 'autonomous'
  | 'assisted';

// --- Agent Delegation ---

export interface ParsedDelegation {
  agentPubkey: string;
  entityType: 'personal_agent' | 'unlinked_personal_agent' | 'organised_agent' | 'unlinked_organised_agent';
  ownerPubkey: string;
  expiresAt?: number;
  algorithm: CryptoAlgorithm;
}

// --- Voting Extension (spec/voting.md) ---

/** Election scale */
export type ElectionScale = 'organisational' | 'community' | 'national';

/** Re-vote policy */
export type ReVotePolicy = 'allowed' | 'denied';

/** Kind 30482: Election Definition */
export interface ElectionParams {
  electionId: string;
  title: string;
  description?: string;
  options: string[];
  scale: ElectionScale;
  eligibleEntityTypes: EntityType[];
  eligibleMinTier: SignetTier;
  eligibleCommunity?: string;
  opens: number;
  closes: number;
  reVote: ReVotePolicy;
  tallyPubkeys: string[];
  tallyThreshold?: [m: number, n: number];
  ringSize?: number;
}

export interface ParsedElection {
  electionId: string;
  title: string;
  description?: string;
  options: string[];
  scale: ElectionScale;
  eligibleEntityTypes: EntityType[];
  eligibleMinTier: SignetTier;
  eligibleCommunity?: string;
  opens: number;
  closes: number;
  reVote: ReVotePolicy;
  tallyPubkeys: string[];
  tallyThreshold?: [m: number, n: number];
  ringSize?: number;
  authorityPubkey: string;
  algorithm: CryptoAlgorithm;
}

/** Kind 30483: Ballot */
export interface BallotParams {
  electionId: string;
  electionEventId: string;
  keyImage: string;
  ringSig: string;
  encryptedVote: string;
}

export interface ParsedBallot {
  electionId: string;
  electionEventId: string;
  keyImage: string;
  ringSig: string;
  encryptedVote: string;
  ephemeralPubkey: string;
  timestamp: number;
  algorithm: CryptoAlgorithm;
}

/** Kind 30484: Election Result */
export interface ElectionResultParams {
  electionId: string;
  electionEventId: string;
  results: Array<{ option: string; count: number }>;
  totalBallots: number;
  totalEligible: number;
  totalInvalid?: number;
  tallyProof?: string;
}

export interface ParsedElectionResult {
  electionId: string;
  electionEventId: string;
  results: Array<{ option: string; count: number }>;
  totalBallots: number;
  totalEligible: number;
  totalInvalid: number;
  tallyProof?: string;
  tallierPubkey: string;
  algorithm: CryptoAlgorithm;
}

// --- Two-Credential Ceremony ---

export interface TwoCredentialResult {
  naturalPerson: NostrEvent;
  persona: NostrEvent;
  merkleLeaves: Record<string, string>;
  merkleProofs: MerkleProof[];
}

export interface CredentialChain {
  current: NostrEvent;
  history: NostrEvent[];
}

// --- Guardian Delegation ---

export interface GuardianDelegationParams {
  childPubkey: string;
  delegatePubkey: string;
  scope: GuardianDelegationScope;
  expiresAt?: number;
}

export type GuardianDelegationScope =
  | 'full'
  | 'activity-approval'
  | 'content-management'
  | 'contact-approval';

// --- Cold-Call Verification ---

/** A single institutional verification pubkey */
export interface InstitutionPubkey {
  id: string;
  pubkey: string;         // 64-char hex, secp256k1 x-only
  label: string;
  created: string;        // ISO 8601
}

/** .well-known/signet.json response */
export interface InstitutionKeys {
  version: number;
  name: string;
  pubkeys: InstitutionPubkey[];
  relay?: string;
  policy?: {
    rotation?: string;
    contact?: string;
  };
}

// --- Kind 30476: Identity Bridge ---

export interface ParsedIdentityBridge {
  anonPubkey: string;
  ringMinTier: SignetTier;
  ringSize: number;
  ring: string[];
  timestamp: number;
  algorithm: CryptoAlgorithm;
}
