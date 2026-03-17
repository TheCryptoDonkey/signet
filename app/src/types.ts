// My Signet App — Types (v2)

export interface SignetIdentity {
  /** Primary keypair pubkey — whichever keypair is currently active */
  id: string;
  mnemonic: string;
  naturalPerson: {
    publicKey: string;
    privateKey: string;
    displayName: string;
  };
  persona: {
    publicKey: string;
    privateKey: string;
    displayName: string;
  };
  primaryKeypair: 'natural-person' | 'persona';
  isChild: boolean;
  guardianPubkey?: string;
  createdAt: number;
  /** Whether private keys and mnemonic are encrypted */
  encrypted?: boolean;
  /** Whether backup words have been saved */
  backedUp?: boolean;
}

/** Self-entered identity document (pre-verification) */
export interface IdentityDocument {
  /** Unique local ID */
  id: string;
  /** Owner's primary pubkey */
  ownerPubkey: string;
  country: string;
  documentType: string;
  fullName: string;
  dateOfBirth: string;
  nationality?: string;
  documentNumber: string;
  documentExpiry?: string;
  /** Additional country-specific fields */
  additionalFields?: Record<string, string>;
  /** Credential event ID if verified */
  credentialId?: string;
  createdAt: number;
  updatedAt: number;
}

/** Stored credential (after verification) */
export interface StoredCredential {
  /** Credential event ID */
  id: string;
  /** Which document this credential verifies */
  documentId: string;
  /** Which keypair (NP or Persona) */
  keypairType: 'natural-person' | 'persona';
  /** The signed Nostr event (Kind 30470) */
  event: string;
  /** Private Merkle leaves */
  merkleLeaves?: Record<string, string>;
  /** Merkle proofs for selective disclosure */
  merkleProofs?: string;
  /** Verifier's pubkey */
  verifierPubkey: string;
  verifiedAt: number;
  /** Whether verifier's Kind 30473 has been confirmed */
  verifierStatus: 'confirmed' | 'pending';
}

export interface FamilyMember {
  /** Their pubkey — primary key */
  pubkey: string;
  /** Which of our accounts owns this connection */
  ownerPubkey: string;
  displayName: string;
  /** ECDH shared secret for Signet Me words */
  sharedSecret: string;
  /** When we verified them */
  verifiedAt: number;
  /** Optional relationship label */
  relationship?: 'parent' | 'child' | 'sibling' | 'grandparent' | 'partner' | 'other';
  isChild?: boolean;
}

export interface ChildSettings {
  /** Child's pubkey — primary key */
  childPubkey: string;
  guardianPubkey: string;
  contactPolicy: 'family-only' | 'approved' | 'open';
  approvedContacts?: string[];
}

/** Verification security tier — controls word count in Signet Me */
export type SecurityTier = 'basic' | 'standard' | 'expert';

/** Maps tier names to word count per side */
export const TIER_WORD_COUNT: Record<SecurityTier, number> = {
  basic: 1,
  standard: 2,
  expert: 3,
};

export interface AppPreferences {
  id: string;
  theme: 'system' | 'light' | 'dark';
  activeAccountId?: string;
  /** Verification security tier (default: basic) */
  securityTier?: SecurityTier;
  /** User's configured relay URL for publishing credentials */
  relayUrl?: string;
  /** Power mode toggle state — reveals advanced settings */
  powerMode?: boolean;
}

export type Page = 'home' | 'family' | 'add' | 'member-detail' | 'settings' | 'child-settings' | 'get-verified' | 'my-documents' | 'add-document' | 'verify-someone' | 'shamir' | 'identity-bridge' | 'import-nsec' | 'credential-detail' | 'approve-verification' | 'approve-connect' | 'approve-auth' | 'web-verify';
