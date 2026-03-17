// NIP-04 Encrypted Direct Messages
// ECDH shared secret (raw x-coordinate) + AES-256-CBC
//
// Format: base64(ciphertext) + "?iv=" + base64(iv)
//
// IMPORTANT: NIP-04 uses the RAW ECDH x-coordinate as the AES key.
// This differs from computeSharedSecret() in connections.ts, which applies
// SHA-256 to the x-coordinate for Signet Words / peer connections.
// Do NOT substitute one for the other — they are intentionally different.

import { secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes } from '@noble/hashes/utils';
import { SignetCryptoError } from './errors.js';

/**
 * Compute the NIP-04 shared secret: raw ECDH x-coordinate (NO hashing).
 *
 * WARNING: This is NOT the same as computeSharedSecret() in connections.ts.
 * connections.ts applies SHA-256 to the x-coordinate for Signet Words and
 * peer connection use cases. NIP-04 requires the raw x-coordinate bytes
 * as the AES-256-CBC key. Using the wrong one will silently produce
 * ciphertext that the other party cannot decrypt.
 */
function nip04SharedSecret(privateKey: string, publicKey: string): Uint8Array {
  // Nostr/schnorr public keys are x-only (32 bytes). Prepend 0x02
  // (assume even y-coordinate) to form a valid compressed point.
  const theirPoint = secp256k1.ProjectivePoint.fromHex('02' + publicKey);
  const scalar = BigInt('0x' + privateKey) % secp256k1.CURVE.n;
  if (scalar === 0n) throw new SignetCryptoError('Invalid private key (zero)');
  const shared = theirPoint.multiply(scalar);
  if (shared.equals(secp256k1.ProjectivePoint.ZERO)) {
    throw new SignetCryptoError('ECDH produced identity point');
  }
  // Return the raw x-coordinate — no SHA-256, per NIP-04 spec.
  const xHex = shared.toAffine().x.toString(16).padStart(64, '0');
  return hexToBytes(xHex);
}

/**
 * Encrypt a plaintext string using NIP-04 (AES-256-CBC with ECDH shared secret).
 *
 * @param privateKey  - Our private key (64-char hex)
 * @param theirPubkey - Their x-only public key (64-char hex)
 * @param plaintext   - The message to encrypt
 * @returns NIP-04 formatted ciphertext: base64(ciphertext) + "?iv=" + base64(iv)
 */
export async function nip04Encrypt(
  privateKey: string,
  theirPubkey: string,
  plaintext: string,
): Promise<string> {
  const sharedX = nip04SharedSecret(privateKey, theirPubkey);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    sharedX.buffer as ArrayBuffer,
    { name: 'AES-CBC' },
    false,
    ['encrypt'],
  );
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    key,
    encoded,
  );
  const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  const ivB64 = btoa(String.fromCharCode(...iv));
  return ctB64 + '?iv=' + ivB64;
}

/**
 * Decrypt a NIP-04 ciphertext string.
 *
 * @param privateKey  - Our private key (64-char hex)
 * @param theirPubkey - Their x-only public key (64-char hex)
 * @param ciphertext  - NIP-04 formatted string: base64(ciphertext) + "?iv=" + base64(iv)
 * @returns The decrypted plaintext
 */
export async function nip04Decrypt(
  privateKey: string,
  theirPubkey: string,
  ciphertext: string,
): Promise<string> {
  const [ctB64, ivB64] = ciphertext.split('?iv=');
  if (!ctB64 || !ivB64) throw new SignetCryptoError('Invalid NIP-04 ciphertext format');
  const sharedX = nip04SharedSecret(privateKey, theirPubkey);
  const ct = Uint8Array.from(atob(ctB64), (c) => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    sharedX.buffer as ArrayBuffer,
    { name: 'AES-CBC' },
    false,
    ['decrypt'],
  );
  const plainBuffer = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    key,
    ct,
  );
  return new TextDecoder().decode(plainBuffer);
}
