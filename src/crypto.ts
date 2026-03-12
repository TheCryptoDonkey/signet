// Signet Cryptographic Utilities
// Schnorr signatures (BIP-340) on secp256k1, event ID computation

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { zeroBytes } from './utils.js';
import type { UnsignedEvent, NostrEvent } from './types.js';

/** Generate a new secp256k1 keypair. Returns { privateKey, publicKey } as hex strings.
 *  Public key is x-only (32 bytes) per BIP-340 / Nostr convention.
 *
 *  SECURITY NOTE: The Uint8Array is zeroed after conversion, but the returned hex
 *  strings are JS primitives and cannot be wiped from memory. This is a fundamental
 *  limitation of the JavaScript runtime. Callers handling private keys should minimise
 *  their lifetime and avoid logging or serialising them unnecessarily. */
export function generateKeyPair(): { privateKey: string; publicKey: string } {
  const privateKeyRaw = schnorr.utils.randomPrivateKey();
  const publicKey = schnorr.getPublicKey(privateKeyRaw);
  const privateKey = bytesToHex(privateKeyRaw);
  const publicKeyHex = bytesToHex(publicKey);
  zeroBytes(privateKeyRaw);
  return {
    privateKey,
    publicKey: publicKeyHex,
  };
}

/** Get x-only public key (32 bytes hex) from a private key */
export function getPublicKey(privateKey: string): string {
  return bytesToHex(schnorr.getPublicKey(hexToBytes(privateKey)));
}

/** Serialize a Nostr event for hashing (NIP-01) */
export function serializeEvent(event: UnsignedEvent): string {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
}

/** Compute the event ID (SHA-256 of the serialized event) */
export function getEventId(event: UnsignedEvent): string {
  const serialized = serializeEvent(event);
  return bytesToHex(sha256(utf8ToBytes(serialized)));
}

/** Sign an unsigned event, returning a full NostrEvent */
export async function signEvent(
  event: UnsignedEvent,
  privateKey: string
): Promise<NostrEvent> {
  const id = getEventId(event);
  const sig = schnorr.sign(id, privateKey);
  return {
    ...event,
    id,
    sig: bytesToHex(sig),
  };
}

/** Verify a signed Nostr event's signature */
export async function verifyEvent(event: NostrEvent): Promise<boolean> {
  try {
    const expectedId = getEventId(event);
    if (expectedId !== event.id) return false;
    return schnorr.verify(event.sig, event.id, event.pubkey);
  } catch {
    return false;
  }
}

/** SHA-256 hash of arbitrary data, returned as hex */
export function hash(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

/** SHA-256 hash of a UTF-8 string, returned as hex */
export function hashString(data: string): string {
  return hash(utf8ToBytes(data));
}
