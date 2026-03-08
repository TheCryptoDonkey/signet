// Signet Peer Connection Management
// ECDH-based shared secret derivation and connection lifecycle

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ContactInfo {
  name?: string;
  mobile?: string;
  email?: string;
  address?: string;
  childPubkeys?: string[];
}

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
  if (privateKeyBigInt === 0n) throw new Error('Invalid private key (zero after mod N reduction)');
  const sharedPoint = theirPoint.multiply(privateKeyBigInt);

  // Derive shared secret: SHA-256 of the x-coordinate (32 bytes big-endian)
  const xBytes = hexToBytes(sharedPoint.toAffine().x.toString(16).padStart(64, '0'));
  return bytesToHex(sha256(xBytes));
}

// ── QR Payload ───────────────────────────────────────────────────────────────

/** Create a QR payload containing our public key and a random nonce. */
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

/** Parse and validate a QR payload from a JSON string.
 *  Throws if the data is not valid JSON or is missing required fields. */
export function parseQRPayload(data: string): QRPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(data);
  } catch {
    throw new Error('Invalid QR payload: malformed JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Invalid QR payload: not an object');
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.pubkey !== 'string' || obj.pubkey.length === 0) {
    throw new Error('Invalid QR payload: missing or invalid pubkey');
  }
  if (typeof obj.nonce !== 'string' || obj.nonce.length === 0) {
    throw new Error('Invalid QR payload: missing or invalid nonce');
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
      this.connections.set(conn.pubkey, conn);
    }
  }
}
