// Signet Protocol Types
// All TypeScript interfaces for the 11 Nostr event kinds (8 core + 3 voting extension) and supporting structures

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

// --- Signet IQ ---

export interface TrustSignal {
  type: 'professional-verification' | 'in-person-vouch' | 'online-vouch' | 'account-age' | 'identity-bridge';
  weight: number;
  source?: string; // pubkey of signal source
  score?: number;  // source's own score (for vouch multiplier)
}

export interface TrustScoreBreakdown {
  score: number; // 0-200 (Signet IQ)
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
}

export interface ParsedVouch {
  subjectPubkey: string;
  method: VouchMethod;
  context?: string;
  voucherTier: SignetTier;
  voucherScore: number;
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
}

export interface ParsedVerifier {
  profession: string;
  jurisdiction: string;
  licenceHash: string;
  professionalBody: string;
}

export interface ParsedChallenge {
  verifierPubkey: string;
  reason: ChallengeReason;
  evidenceType: string;
  reporterTier: SignetTier;
}

export interface ParsedRevocation {
  verifierPubkey: string;
  challengeEventId: string;
  confirmations: number;
  bondAction: BondAction;
  scope: RevocationScope;
  effectiveAt: number;
}

// --- Entity Type Classification ---

/** Entity type classification (§17 of spec) */
export type EntityType =
  | 'natural_person'
  | 'persona'
  | 'personal_agent'
  | 'free_personal_agent'
  | 'juridical_person'
  | 'juridical_persona'
  | 'organised_agent'
  | 'free_organised_agent'
  | 'free_agent';

/** Dynamic mode signaling for teleoperated/autonomous entities (§17.9) */
export type EntityMode =
  | 'teleoperated'
  | 'autonomous'
  | 'assisted';

// --- Kind 30477: Agent Delegation ---

export interface DelegationParams {
  agentPubkey: string;
  entityType: 'personal_agent' | 'free_personal_agent' | 'organised_agent' | 'free_organised_agent';
  expiresAt?: number;
}

export interface ParsedDelegation {
  agentPubkey: string;
  entityType: 'personal_agent' | 'free_personal_agent' | 'organised_agent' | 'free_organised_agent';
  ownerPubkey: string;
  expiresAt?: number;
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

// --- Kind 30476: Identity Bridge ---

export interface ParsedIdentityBridge {
  anonPubkey: string;
  ringMinTier: SignetTier;
  ringSize: number;
  ring: string[];
  timestamp: number;
}
