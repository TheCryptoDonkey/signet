// Cold-Call Verification
// Allows customers to verify unknown institutional callers via:
//   .well-known/signet.json — institution publishes its pubkeys
//   Ephemeral ECDH         — customer generates a one-time keypair
//   Spoken-token words     — both sides derive the same words independently

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { SignetCryptoError, SignetValidationError } from './errors.js';
import type { InstitutionKeys } from './types.js';
import {
  COLD_CALL_CONTEXT,
  COLD_CALL_EPOCH_SECONDS,
  NATO_ALPHABET,
  WELL_KNOWN_MAX_PUBKEYS,
  WELL_KNOWN_MAX_SIZE,
  WELL_KNOWN_PATH,
} from './constants.js';
import { deriveWords } from './signet-words.js';

// ── .well-known/signet.json fetching ─────────────────────────────────────────

/**
 * Fetch and validate an institution's verification keys from `.well-known/signet.json`.
 *
 * Always uses HTTPS. Enforces a 10 KB size limit, version 1, at most 20 pubkeys,
 * and validates that each pubkey is a 64-char lowercase hex string.
 *
 * @param domain - The institution's domain (e.g. `'acmelegal.com'`). Do NOT include scheme.
 * @returns Validated InstitutionKeys object.
 * @throws {SignetValidationError} If the response is invalid, too large, or fails validation.
 */
export async function fetchInstitutionKeys(domain: string): Promise<InstitutionKeys> {
  const url = `https://${domain}${WELL_KNOWN_PATH}`;

  // Fetch (throws on network error — caller decides how to handle)
  const response = await fetch(url);
  const text = await response.text();

  // Enforce size limit
  if (text.length > WELL_KNOWN_MAX_SIZE) {
    throw new SignetValidationError(`.well-known/signet.json exceeds ${WELL_KNOWN_MAX_SIZE} bytes`);
  }

  // Parse with runtime type guard
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new SignetValidationError('.well-known/signet.json is not valid JSON');
  }

  if (typeof data !== 'object' || data === null) {
    throw new SignetValidationError('.well-known/signet.json must be a JSON object');
  }

  const obj = data as Record<string, unknown>;

  if (obj['version'] !== 1) {
    throw new SignetValidationError(`Unsupported signet.json version: ${obj['version']}`);
  }

  if (!obj['name'] || typeof obj['name'] !== 'string') {
    throw new SignetValidationError('Missing or invalid name field');
  }

  if (!Array.isArray(obj['pubkeys']) || (obj['pubkeys'] as unknown[]).length === 0) {
    throw new SignetValidationError('Missing or empty pubkeys array');
  }

  const pubkeys = obj['pubkeys'] as unknown[];

  if (pubkeys.length > WELL_KNOWN_MAX_PUBKEYS) {
    throw new SignetValidationError(`Too many pubkeys (max ${WELL_KNOWN_MAX_PUBKEYS})`);
  }

  for (const pk of pubkeys) {
    if (typeof pk !== 'object' || pk === null) {
      throw new SignetValidationError('Each pubkey entry must be an object');
    }
    const entry = pk as Record<string, unknown>;
    if (typeof entry['pubkey'] !== 'string' || !/^[0-9a-f]{64}$/i.test(entry['pubkey'])) {
      throw new SignetValidationError(`Invalid pubkey format: ${entry['id'] ?? '(unknown)'}`);
    }
  }

  return data as InstitutionKeys;
}

// ── Session code generation ───────────────────────────────────────────────────

/**
 * Generate a human-readable session code from an ephemeral pubkey.
 *
 * Format: `NATOWORD-NNNN` (e.g. `BRAVO-7742`).
 * The code is derived deterministically from the SHA-256 of the pubkey bytes.
 *
 * @param ephemeralPubkey - 64-char hex x-only secp256k1 public key.
 * @returns Session code string.
 * @throws {SignetValidationError} If the pubkey is not 64 hex characters.
 */
export function generateSessionCode(ephemeralPubkey: string): string {
  if (!/^[0-9a-f]{64}$/i.test(ephemeralPubkey)) {
    throw new SignetValidationError('Invalid ephemeral pubkey format — must be 64-char hex');
  }

  const hash = sha256(hexToBytes(ephemeralPubkey));
  const natoIndex = hash[0] % NATO_ALPHABET.length;
  // Use 5 bytes to derive a 0–9999 digit (avoids bias vs single byte % 10000)
  const raw = ((hash[1] << 24) | (hash[2] << 16) | (hash[3] << 8) | hash[4]) >>> 0;
  const digits = raw % 10000;
  return `${NATO_ALPHABET[natoIndex]}-${digits.toString().padStart(4, '0')}`;
}

// ── Word derivation ───────────────────────────────────────────────────────────

/**
 * Derive spoken words from a cold-call ECDH shared secret.
 *
 * Uses context `"signet:cold-call"` (domain-separated from the "Signet me"
 * context `"signet:verify"`), so cold-call and peer-verification words never clash.
 *
 * @param ecdhSecret - 32-byte ECDH shared secret (Uint8Array or 64-char hex).
 * @param counter - Epoch counter (default: current 30-second epoch).
 * @param wordCount - Number of words to derive (1-16, default 3).
 * @returns Array of spoken-clarity words.
 */
export function deriveColdCallWords(
  ecdhSecret: Uint8Array | string,
  counter?: number,
  wordCount: number = 3,
): string[] {
  const currentCounter = counter ?? Math.floor(Date.now() / 1000 / COLD_CALL_EPOCH_SECONDS);
  return deriveWords(ecdhSecret, currentCounter, wordCount, COLD_CALL_CONTEXT);
}

// ── ECDH cold-call flow ───────────────────────────────────────────────────────

/** The result of initiating a cold-call verification session. */
export interface ColdCallSession {
  /** 64-char hex x-only ephemeral public key — share this with the institution. */
  ephemeralPubkey: string;
  /** Human-readable session code derived from the ephemeral pubkey (e.g. `"BRAVO-7742"`). */
  sessionCode: string;
  /** Spoken words the customer expects to hear from the institution. */
  words: string[];
}

/**
 * Customer side: generate a fresh ephemeral keypair, perform ECDH with the
 * institution's pubkey, and derive the expected spoken words.
 *
 * The customer MUST share `ephemeralPubkey` (or `sessionCode`) with the institution
 * so the institution can perform the matching ECDH.
 *
 * The shared secret is SHA-256 of the x-coordinate of the ECDH point.
 *
 * @param institutionPubkey - 64-char hex x-only secp256k1 pubkey from `.well-known/signet.json`.
 * @param wordCount - Number of words to derive (default 3).
 * @returns ColdCallSession with ephemeral pubkey, session code, and expected words.
 * @throws {SignetCryptoError} If ECDH produces an invalid point.
 */
export function initiateColdCallVerification(
  institutionPubkey: string,
  wordCount: number = 3,
): ColdCallSession {
  // Generate ephemeral keypair
  const ephPriv = secp256k1.utils.randomPrivateKey();
  const ephPubCompressed = secp256k1.getPublicKey(ephPriv, true); // 33 bytes, 02-prefix

  // ECDH: customer ephemeral private × institution public
  // getSharedSecret expects a compressed pubkey with 02/03 prefix
  const sharedPoint = secp256k1.getSharedSecret(ephPriv, '02' + institutionPubkey);

  // Shared secret = SHA-256(x-coordinate of the ECDH point)
  // sharedPoint is a 65-byte uncompressed point or 33-byte compressed; take bytes [1..33]
  const xBytes = sharedPoint.slice(1, 33);
  const sharedSecret = sha256(xBytes);

  // Derive words at the current epoch
  const words = deriveColdCallWords(sharedSecret, undefined, wordCount);

  // Session code from the ephemeral pubkey (x-only, strip 02 prefix)
  const ephPubHex = bytesToHex(ephPubCompressed).slice(2);
  const sessionCode = generateSessionCode(ephPubHex);

  // Zero ephemeral private key bytes (defence-in-depth; GC still owns the buffer)
  ephPriv.fill(0);

  return { ephemeralPubkey: ephPubHex, sessionCode, words };
}

/**
 * Institution side: receive the customer's ephemeral pubkey, perform ECDH with
 * the institution's own private key, and derive the same spoken words.
 *
 * If the institution reads out the returned words and they match what the customer
 * sees, the caller is verified as genuine.
 *
 * @param institutionPrivkey - 64-char hex secp256k1 private key.
 * @param ephemeralPubkey - 64-char hex x-only ephemeral pubkey from the customer.
 * @param wordCount - Number of words to derive (must match customer's wordCount, default 3).
 * @returns Array of spoken words — should match the customer's displayed words.
 * @throws {SignetCryptoError} If ECDH produces an invalid point.
 */
export function completeColdCallVerification(
  institutionPrivkey: string,
  ephemeralPubkey: string,
  wordCount: number = 3,
): string[] {
  // ECDH: institution private × customer ephemeral public
  const privBytes = hexToBytes(institutionPrivkey);
  const sharedPoint = secp256k1.getSharedSecret(privBytes, '02' + ephemeralPubkey);

  const xBytes = sharedPoint.slice(1, 33);
  const sharedSecret = sha256(xBytes);

  return deriveColdCallWords(sharedSecret, undefined, wordCount);
}
