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
  type ContactInfo,
  type QRPayload,
  type ShamirShare,
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
};

export type { ContactInfo, QRPayload, ShamirShare };

export function createNewIdentity(
  role: StoredIdentity['role'],
  displayName: string,
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
  };
}

export function importIdentity(
  mnemonic: string,
  role: StoredIdentity['role'],
  displayName: string,
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
  };
}

export function importFromNsec(
  nsec: string,
  role: StoredIdentity['role'],
  displayName: string,
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
  };
}
