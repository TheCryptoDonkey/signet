// Simplified protocol library wrapper for My Signet (v2)

import {
  generateMnemonic as _generateMnemonic,
  validateMnemonic as _validateMnemonic,
  BIP39_WORDLIST,
  createSignetIdentity,
  createSignetIdentityFromNsec,
  encodeNpub,
  decodeNsec,
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  getSignetDisplay,
  verifySignetWords,
  createVouch,
  computeBadge,
  buildBadgeFilters,
  splitSecret,
  shareToWords,
  mnemonicToEntropy,
  createTwoCredentialCeremony,
  signEvent,
  getPublicKey,
} from 'signet-protocol';
import { bytesToHex } from '@noble/hashes/utils.js';
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
  decodeNsec,
  BIP39_WORDLIST,
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
  const signet = createSignetIdentity(mnemonic);
  const npId = signet.naturalPerson.identity;
  const pId = signet.persona.identity;

  const npPub = bytesToHex(npId.publicKey);
  const npPriv = bytesToHex(npId.privateKey);
  const pPub = bytesToHex(pId.publicKey);
  const pPriv = bytesToHex(pId.privateKey);
  const primaryPub = primaryKeypair === 'natural-person' ? npPub : pPub;

  signet.root.destroy();

  return {
    id: primaryPub,
    mnemonic,
    naturalPerson: {
      publicKey: npPub,
      privateKey: npPriv,
      displayName: primaryKeypair === 'natural-person' ? displayName : '',
    },
    persona: {
      publicKey: pPub,
      privateKey: pPriv,
      displayName: primaryKeypair === 'persona' ? displayName : '',
    },
    primaryKeypair,
    isChild,
    guardianPubkey,
    createdAt: Math.floor(Date.now() / 1000),
    backedUp: false,
  };
}

/** Import an identity from an nsec (derives both personas via nsec-tree) */
export function importFromNsec(
  nsec: string,
  displayName: string,
  primaryKeypair: 'natural-person' | 'persona',
): SignetIdentity {
  const signet = createSignetIdentityFromNsec(nsec);
  const npId = signet.naturalPerson.identity;
  const pId = signet.persona.identity;

  const npPub = bytesToHex(npId.publicKey);
  const npPriv = bytesToHex(npId.privateKey);
  const pPub = bytesToHex(pId.publicKey);
  const pPriv = bytesToHex(pId.privateKey);
  const primaryPub = primaryKeypair === 'natural-person' ? npPub : pPub;

  signet.root.destroy();

  return {
    id: primaryPub,
    mnemonic: '', // nsec import has no mnemonic
    naturalPerson: {
      publicKey: npPub,
      privateKey: npPriv,
      displayName: primaryKeypair === 'natural-person' ? displayName : '',
    },
    persona: {
      publicKey: pPub,
      privateKey: pPriv,
      displayName: primaryKeypair === 'persona' ? displayName : '',
    },
    primaryKeypair,
    isChild: false,
    createdAt: Math.floor(Date.now() / 1000),
    backedUp: true, // no mnemonic to back up — suppress backup nag
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

/**
 * Sign an auth challenge string using the Nostr signEvent convention.
 *
 * The challenge is embedded in a Kind 27235 (NIP-98 style) event so that
 * the signature is a standard Nostr event signature that any verifier can
 * check using `verifyEvent`.
 *
 * Returns { pubkey, signature, eventId } where:
 *   - pubkey    — x-only Schnorr pubkey (hex, 64 chars)
 *   - signature — Schnorr signature over the event ID (hex, 128 chars)
 *   - eventId   — the signed event ID (hex, 64 chars)
 */
export async function signAuthChallenge(
  privateKey: string,
  challenge: string,
  origin: string,
): Promise<{ pubkey: string; signature: string; eventId: string }> {
  const pubkey = getPublicKey(privateKey);
  const event = await signEvent(
    {
      pubkey,
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['challenge', challenge],
        ['origin', origin],
      ],
      content: '',
    },
    privateKey,
  );
  return { pubkey, signature: event.sig, eventId: event.id };
}
