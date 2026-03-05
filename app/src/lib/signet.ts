import {
  generateMnemonic,
  validateMnemonic,
  deriveNostrKeyPair,
  mnemonicToEntropy,
  entropyToMnemonic,
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  getSignetWords,
  verifySignetWords,
  formatSignetWords,
  getSignetDisplay,
  getJurisdictionCodes,
  getJurisdiction,
  decodeNsec,
  encodeNsec,
  encodeNpub,
  // Two-credential ceremony
  createTwoCredentialCeremony,
  // Guardian delegation
  createGuardianDelegation,
  // Nullifier utilities
  computeNullifier,
  checkNullifierDuplicate,
  // Credential chains
  resolveCredentialChain,
  supersedeCredential,
  isSuperseded,
  parseCredential,
  // Entity labels
  ENTITY_LABELS,
  type ContactInfo,
  type QRPayload,
  type ShamirShare,
  type EntityType,
  type TwoCredentialResult,
  type GuardianDelegationParams,
  type GuardianDelegationScope,
  type CredentialChain,
  type NostrEvent,
} from 'signet-protocol';
import type { StoredIdentity } from './db';

export {
  generateMnemonic,
  validateMnemonic,
  deriveNostrKeyPair,
  mnemonicToEntropy,
  entropyToMnemonic,
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  getSignetWords,
  verifySignetWords,
  formatSignetWords,
  getSignetDisplay,
  getJurisdictionCodes,
  getJurisdiction,
  decodeNsec,
  encodeNsec,
  encodeNpub,
  createTwoCredentialCeremony,
  createGuardianDelegation,
  computeNullifier,
  checkNullifierDuplicate,
  resolveCredentialChain,
  supersedeCredential,
  isSuperseded,
  parseCredential,
  ENTITY_LABELS,
};

export type {
  ContactInfo,
  QRPayload,
  ShamirShare,
  EntityType,
  TwoCredentialResult,
  GuardianDelegationParams,
  GuardianDelegationScope,
  CredentialChain,
  NostrEvent,
};

export function createNewIdentity(
  role: StoredIdentity['role'],
  displayName: string,
  opts?: {
    entityType?: StoredIdentity['entityType'];
    guardianPubkey?: string;
    isChild?: boolean;
  },
): StoredIdentity {
  const mnemonic = generateMnemonic();
  const { privateKey, publicKey } = deriveNostrKeyPair(mnemonic);
  return {
    id: publicKey,
    mnemonic,
    publicKey,
    privateKey,
    role,
    displayName,
    createdAt: Math.floor(Date.now() / 1000),
    importMethod: 'mnemonic',
    entityType: opts?.entityType,
    guardianPubkey: opts?.guardianPubkey,
    isChild: opts?.isChild,
  };
}

export function importIdentity(
  mnemonic: string,
  role: StoredIdentity['role'],
  displayName: string,
  opts?: {
    entityType?: StoredIdentity['entityType'];
    guardianPubkey?: string;
    isChild?: boolean;
  },
): StoredIdentity {
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase');
  }
  const { privateKey, publicKey } = deriveNostrKeyPair(mnemonic);
  return {
    id: publicKey,
    mnemonic,
    publicKey,
    privateKey,
    role,
    displayName,
    createdAt: Math.floor(Date.now() / 1000),
    importMethod: 'mnemonic',
    entityType: opts?.entityType,
    guardianPubkey: opts?.guardianPubkey,
    isChild: opts?.isChild,
  };
}

export function importFromNsec(
  nsec: string,
  role: StoredIdentity['role'],
  displayName: string,
  opts?: {
    entityType?: StoredIdentity['entityType'];
    guardianPubkey?: string;
    isChild?: boolean;
  },
): StoredIdentity {
  const { privateKey, publicKey } = decodeNsec(nsec);
  return {
    id: publicKey,
    publicKey,
    privateKey,
    role,
    displayName,
    createdAt: Math.floor(Date.now() / 1000),
    importMethod: 'nsec',
    entityType: opts?.entityType,
    guardianPubkey: opts?.guardianPubkey,
    isChild: opts?.isChild,
  };
}
