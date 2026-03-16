// Simplified protocol library wrapper for My Signet (v2)

import {
  generateMnemonic as _generateMnemonic,
  validateMnemonic as _validateMnemonic,
  BIP39_WORDLIST,
  deriveNostrKeyPair,
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  getSignetDisplay,
  verifySignetWords,
  encodeNpub,
  createVouch,
  computeBadge,
  buildBadgeFilters,
  splitSecret,
  shareToWords,
  mnemonicToEntropy,
  createTwoCredentialCeremony,
} from 'signet-protocol';
import type { SignetIdentity } from '../types';

// Wrap @scure/bip39 functions that require a wordlist parameter
function generateMnemonic(): string {
  return _generateMnemonic(BIP39_WORDLIST);
}

export function validateMnemonic(mnemonic: string): boolean {
  return _validateMnemonic(mnemonic, BIP39_WORDLIST);
}

export {
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  getSignetDisplay,
  verifySignetWords,
  encodeNpub,
  createVouch,
  computeBadge,
  buildBadgeFilters,
  splitSecret,
  shareToWords,
  mnemonicToEntropy,
  createTwoCredentialCeremony,
};

/** Create a new identity with two keypairs from a fresh mnemonic */
export function createNewIdentity(
  displayName: string,
  primaryKeypair: 'natural-person' | 'persona',
  isChild: boolean,
  guardianPubkey?: string
): SignetIdentity {
  const mnemonic = generateMnemonic();
  return buildIdentity(mnemonic, displayName, primaryKeypair, isChild, guardianPubkey);
}

/** Restore an identity from an existing mnemonic */
export function importFromMnemonic(
  mnemonic: string,
  displayName: string,
  primaryKeypair: 'natural-person' | 'persona',
  isChild: boolean,
  guardianPubkey?: string
): SignetIdentity {
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid backup words');
  }
  return buildIdentity(mnemonic, displayName, primaryKeypair, isChild, guardianPubkey);
}

function buildIdentity(
  mnemonic: string,
  displayName: string,
  primaryKeypair: 'natural-person' | 'persona',
  isChild: boolean,
  guardianPubkey?: string
): SignetIdentity {
  // Natural Person keypair at account index 0 (m/44'/1237'/0'/0/0)
  const np = deriveNostrKeyPair(mnemonic, 0);
  // Persona keypair at account index 1 (m/44'/1237'/1'/0/0)
  const persona = deriveNostrKeyPair(mnemonic, 1);

  const primaryPub = primaryKeypair === 'natural-person' ? np.publicKey : persona.publicKey;

  return {
    id: primaryPub,
    mnemonic,
    naturalPerson: {
      publicKey: np.publicKey,
      privateKey: np.privateKey,
      displayName: primaryKeypair === 'natural-person' ? displayName : '',
    },
    persona: {
      publicKey: persona.publicKey,
      privateKey: persona.privateKey,
      displayName: primaryKeypair === 'persona' ? displayName : '',
    },
    primaryKeypair,
    isChild,
    guardianPubkey,
    createdAt: Math.floor(Date.now() / 1000),
    backedUp: false,
  };
}

/** Get the active keypair's public key */
export function getActivePubkey(identity: SignetIdentity): string {
  return identity.primaryKeypair === 'natural-person'
    ? identity.naturalPerson.publicKey
    : identity.persona.publicKey;
}

/** Get the active keypair's private key */
export function getActivePrivateKey(identity: SignetIdentity): string {
  return identity.primaryKeypair === 'natural-person'
    ? identity.naturalPerson.privateKey
    : identity.persona.privateKey;
}

/** Get the active display name */
export function getActiveDisplayName(identity: SignetIdentity): string {
  return identity.primaryKeypair === 'natural-person'
    ? identity.naturalPerson.displayName
    : identity.persona.displayName;
}
