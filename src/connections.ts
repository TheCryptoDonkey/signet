// Signet Peer Connection Management
// ECDH-based shared secret derivation and connection lifecycle

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { SignetCryptoError, SignetValidationError } from './errors.js';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ContactInfo {
  name?: string;
  mobile?: string;
  email?: string;
  address?: string;
  childPubkeys?: string[];
}

/** SECURITY NOTE: sharedSecret is stored as a plain hex string in memory.
 *  For production use, secrets should be encrypted at rest (e.g. via OS keychain
 *  or encrypted storage). JS strings cannot be zeroed from memory. */
export interface Connection {
  pubkey: string;           // their public key (hex)
  sharedSecret: string;     // ECDH-derived shared secret (hex, 32 bytes)
  theirInfo: ContactInfo;   // what they shared with us
  ourInfo: ContactInfo;     // what we shared with them
  connectedAt: number;      // unix timestamp
  method: 'qr-in-person' | 'online';
}

export interface QRPayload {
  pubkey: string;           // our public key
  nonce: string;            // random 32-byte hex for uniqueness
  info?: ContactInfo;       // optional pre-selected contact info
}

// ── ECDH ─────────────────────────────────────────────────────────────────────

/** Compute an ECDH shared secret from our private key and their x-only public key.
 *  The result is the SHA-256 of the x-coordinate of the ECDH point, returned as
 *  a 32-byte hex string.  The secret is symmetric: A(priv)+B(pub) === B(priv)+A(pub). */
export function computeSharedSecret(myPrivateKey: string, theirPublicKey: string): string {
  // Nostr/schnorr public keys are x-only (32 bytes).  To perform ECDH we need
  // the full compressed point, so we prepend 0x02 (assume even y-coordinate).
  const theirPoint = secp256k1.ProjectivePoint.fromHex('02' + theirPublicKey);
  const privateKeyBigInt = BigInt('0x' + myPrivateKey) % secp256k1.CURVE.n;
  if (privateKeyBigInt === 0n) throw new SignetCryptoError('Invalid private key (zero after mod N reduction)');
  const sharedPoint = theirPoint.multiply(privateKeyBigInt);
  if (sharedPoint.equals(secp256k1.ProjectivePoint.ZERO)) {
    throw new SignetCryptoError('ECDH produced identity point — invalid public key');
  }

  // Derive shared secret: SHA-256 of the x-coordinate (32 bytes big-endian)
  const xBytes = hexToBytes(sharedPoint.toAffine().x.toString(16).padStart(64, '0'));
  return bytesToHex(sha256(xBytes));
}

// ── QR Payload ───────────────────────────────────────────────────────────────

/**
 * Create a QR payload containing our public key and a random nonce.
 *
 * **SECURITY WARNING — unencrypted payload:** The returned object is serialised
 * as cleartext JSON by `serializeQRPayload`.  Any `ContactInfo` embedded in the
 * payload (name, mobile, email, address, children's public keys) is transmitted
 * without encryption.  Only display this QR code on trusted screens in
 * controlled environments.  Do not transmit it over untrusted channels.
 */
export function createQRPayload(publicKey: string, info?: ContactInfo): QRPayload {
  const nonce = bytesToHex(randomBytes(32));
  const payload: QRPayload = { pubkey: publicKey, nonce };
  if (info !== undefined) {
    payload.info = info;
  }
  return payload;
}

/** Serialize a QR payload to a JSON string. */
export function serializeQRPayload(payload: QRPayload): string {
  return JSON.stringify(payload);
}

const MAX_CONTACT_FIELD_LENGTH = 256;
const MAX_CHILD_PUBKEYS = 20;

/** Validate ContactInfo field sizes to prevent oversized payloads from untrusted sources. */
function validateContactInfo(info: unknown): void {
  if (typeof info !== 'object' || info === null) {
    throw new SignetValidationError('Invalid ContactInfo: must be an object');
  }
  const ci = info as Record<string, unknown>;
  for (const field of ['name', 'mobile', 'email', 'address'] as const) {
    if (ci[field] !== undefined) {
      if (typeof ci[field] !== 'string') throw new SignetValidationError(`Invalid ContactInfo: ${field} must be a string`);
      if ((ci[field] as string).length > MAX_CONTACT_FIELD_LENGTH) {
        throw new SignetValidationError(`Invalid ContactInfo: ${field} exceeds ${MAX_CONTACT_FIELD_LENGTH} characters`);
      }
    }
  }
  if (ci.childPubkeys !== undefined) {
    if (!Array.isArray(ci.childPubkeys)) throw new SignetValidationError('Invalid ContactInfo: childPubkeys must be an array');
    if (ci.childPubkeys.length > MAX_CHILD_PUBKEYS) {
      throw new SignetValidationError(`Invalid ContactInfo: childPubkeys exceeds ${MAX_CHILD_PUBKEYS} entries`);
    }
    for (const pk of ci.childPubkeys) {
      if (typeof pk !== 'string' || !/^[0-9a-f]{64}$/i.test(pk)) {
        throw new SignetValidationError('Invalid ContactInfo: childPubkeys must contain valid 64-char hex pubkeys');
      }
    }
  }
}

/** Parse and validate a QR payload from a JSON string.
 *  Throws if the data is not valid JSON or is missing required fields. */
export function parseQRPayload(data: string): QRPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(data);
  } catch {
    throw new SignetValidationError('Invalid QR payload: malformed JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new SignetValidationError('Invalid QR payload: not an object');
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(obj.pubkey)) {
    throw new SignetValidationError('Invalid QR payload: pubkey must be a 64-character hex string');
  }
  if (typeof obj.nonce !== 'string' || obj.nonce.length < 32 || obj.nonce.length > 128) {
    throw new SignetValidationError('Invalid QR payload: nonce must be 32-128 hex characters');
  }

  // Validate ContactInfo field sizes if present
  if (obj.info !== undefined) {
    validateContactInfo(obj.info);
  }

  return parsed as QRPayload;
}

// ── Connection ───────────────────────────────────────────────────────────────

/** Create a Connection from our private key and a scanned QR payload. */
export function createConnection(
  myPrivateKey: string,
  qrPayload: QRPayload,
  ourInfo: ContactInfo,
): Connection {
  const sharedSecret = computeSharedSecret(myPrivateKey, qrPayload.pubkey);
  return {
    pubkey: qrPayload.pubkey,
    sharedSecret,
    theirInfo: qrPayload.info ?? {},
    ourInfo,
    connectedAt: Math.floor(Date.now() / 1000),
    method: 'qr-in-person',
  };
}

// ── ConnectionStore ──────────────────────────────────────────────────────────

/** Simple in-memory connection manager keyed by remote public key. */
export class ConnectionStore {
  private connections: Map<string, Connection> = new Map();

  /** Add a connection. If a connection with the same pubkey already exists it is replaced. */
  add(connection: Connection): void {
    this.connections.set(connection.pubkey, connection);
  }

  /** Get a connection by remote public key. */
  get(pubkey: string): Connection | undefined {
    return this.connections.get(pubkey);
  }

  /** List all connections. */
  list(): Connection[] {
    return Array.from(this.connections.values());
  }

  /** Remove a connection by remote public key. Returns true if a connection was removed. */
  remove(pubkey: string): boolean {
    return this.connections.delete(pubkey);
  }

  /** Check whether a connection for the given public key exists. */
  has(pubkey: string): boolean {
    return this.connections.has(pubkey);
  }

  /** Export all connections as an array (for serialization). */
  export(): Connection[] {
    return this.list();
  }

  /** Import connections from an array, replacing any existing connections with the same pubkey. */
  import(connections: Connection[]): void {
    for (const conn of connections) {
      if (!conn || typeof conn !== 'object') continue;
      if (typeof conn.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(conn.pubkey)) continue;
      if (typeof conn.sharedSecret !== 'string' || !/^[0-9a-f]{64}$/i.test(conn.sharedSecret)) continue;
      if (typeof conn.connectedAt !== 'number' || conn.connectedAt <= 0) continue;
      if (typeof conn.theirInfo !== 'object' || conn.theirInfo === null) continue;
      if (typeof conn.ourInfo !== 'object' || conn.ourInfo === null) continue;
      if (conn.method !== 'qr-in-person' && conn.method !== 'online') continue;
      this.connections.set(conn.pubkey, conn);
    }
  }
}
