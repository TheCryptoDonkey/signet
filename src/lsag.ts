// LSAG (Linkable Spontaneous Anonymous Group) Ring Signatures on secp256k1
// Extends SAG with a key image that links signatures by the same signer
// across multiple uses of the same election, enabling double-vote detection.

import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { SignetValidationError, SignetCryptoError } from './errors.js';
import { constantTimeEqual } from './utils.js';
import {
  Point,
  N,
  type ProjectivePoint,
  mod,
  randomScalar,
  scalarToHex,
  hexToScalar,
  hashToScalar,
  hashToPoint,
  safeMultiply,
  scalarEqual,
  G,
} from './secp256k1-utils.js';

export interface LsagSignature {
  keyImage: string;      // compressed point hex (33 bytes / 66 hex chars)
  c0: string;            // starting challenge scalar hex
  responses: string[];   // one scalar hex per ring member
  ring: string[];        // x-only pubkey hex array (internally converted via '02' prefix)
  message: string;       // the signed message
  electionId: string;    // binds key image to this election
}

/** Maximum number of members in a ring, to prevent denial-of-service via unbounded computation. */
export const MAX_RING_SIZE = 1000;

const LSAG_DOMAIN = utf8ToBytes('signet-lsag-v1');

function validatePubkeyHex(pubkeyHex: string): void {
  if (!/^[0-9a-f]{64}$/i.test(pubkeyHex)) {
    throw new SignetValidationError(`Invalid x-only public key: expected 64 hex chars, got ${pubkeyHex.length} chars`);
  }
}

function pubkeyToPoint(pubkeyHex: string): ProjectivePoint {
  validatePubkeyHex(pubkeyHex);
  return Point.fromHex('02' + pubkeyHex);
}

/**
 * Compute H_p(P || electionId) — the per-member, per-election hash point.
 * P is the compressed (33-byte, 02-prefixed) public key.
 */
function hashPointForMember(pubkeyHex: string, electionId: string): ProjectivePoint {
  const compressedPubkey = hexToBytes('02' + pubkeyHex);
  const electionBytes = utf8ToBytes(electionId);
  const data = new Uint8Array(compressedPubkey.length + electionBytes.length);
  data.set(compressedPubkey);
  data.set(electionBytes, compressedPubkey.length);
  return hashToPoint(data);
}

/**
 * Compute a deterministic key image for a voter in a specific election.
 * I = x * H_p(P || electionId)
 */
export function computeKeyImage(privateKey: string, publicKey: string, electionId: string): string {
  let x = hexToScalar(privateKey);
  // BIP-340 parity fix
  const P = G.multiply(x);
  const pAffine = P.toAffine();
  if (pAffine.y % 2n !== 0n) {
    x = mod(N - x);
  }
  const Hp = hashPointForMember(publicKey, electionId);
  const I = Hp.multiply(x);
  return bytesToHex(I.toRawBytes(true));
}

export function hasDuplicateKeyImage(keyImage: string, existingImages: string[]): boolean {
  const target = hexToBytes(keyImage);
  let found = false;
  for (const img of existingImages) {
    const candidate = hexToBytes(img);
    if (candidate.length === target.length && constantTimeEqual(target, candidate)) {
      found = true;
    }
  }
  return found;
}

function challengeHash(
  msgBytes: Uint8Array,
  ringBytes: Uint8Array,
  L: ProjectivePoint,
  R: ProjectivePoint,
): bigint {
  return hashToScalar(LSAG_DOMAIN, msgBytes, ringBytes, L.toRawBytes(true), R.toRawBytes(true));
}

export function lsagSign(
  message: string,
  ring: string[],
  signerIndex: number,
  privateKey: string,
  electionId: string,
): LsagSignature {
  if (ring.length < 2) throw new SignetValidationError('Ring must have at least 2 members');
  if (ring.length > MAX_RING_SIZE) throw new SignetValidationError(`Ring size ${ring.length} exceeds maximum of ${MAX_RING_SIZE}`);
  if (signerIndex < 0 || signerIndex >= ring.length) throw new SignetValidationError('Signer index out of range');

  const n = ring.length;
  const pi = signerIndex;
  let x = hexToScalar(privateKey);
  const msgBytes = utf8ToBytes(message);
  const ringBytes = utf8ToBytes(ring.join(','));
  const ringPoints = ring.map(pubkeyToPoint);

  // BIP-340 parity fix
  const P = G.multiply(x);
  const pAffine = P.toAffine();
  if (pAffine.y % 2n !== 0n) {
    x = mod(N - x);
  }

  // Key image: I = x * H_p(P_s || electionId)
  const HpSigner = hashPointForMember(ring[pi], electionId);
  const I = HpSigner.multiply(x);
  const keyImage = bytesToHex(I.toRawBytes(true));

  const alpha = randomScalar();
  const L_s = G.multiply(alpha);
  const R_s = HpSigner.multiply(alpha);

  const challenges: bigint[] = new Array(n);
  const responses: bigint[] = new Array(n);

  const nextIdx = (pi + 1) % n;
  challenges[nextIdx] = challengeHash(msgBytes, ringBytes, L_s, R_s);

  for (let j = 1; j < n; j++) {
    const i = (pi + j) % n;
    const iNext = (i + 1) % n;
    responses[i] = randomScalar();
    const L_i = safeMultiply(G, responses[i]).add(safeMultiply(ringPoints[i], challenges[i]));
    const HpI = hashPointForMember(ring[i], electionId);
    const R_i = safeMultiply(HpI, responses[i]).add(safeMultiply(I, challenges[i]));
    if (iNext !== nextIdx || j < n - 1) {
      challenges[iNext] = challengeHash(msgBytes, ringBytes, L_i, R_i);
    }
  }

  responses[pi] = mod(alpha - mod(challenges[pi] * x));

  return {
    keyImage,
    c0: scalarToHex(challenges[0]),
    responses: responses.map(scalarToHex),
    ring,
    message,
    electionId,
  };
}

export function lsagVerify(sig: LsagSignature): boolean {
  try {
    const { keyImage, c0, responses, ring, message, electionId } = sig;
    if (ring.length < 2) return false;
    if (ring.length > MAX_RING_SIZE) return false;
    if (responses.length !== ring.length) return false;

    const I = Point.fromHex(keyImage);
    I.assertValidity();
    if (I.equals(Point.ZERO)) return false;

    const n = ring.length;
    const msgBytes = utf8ToBytes(message);
    const ringBytes = utf8ToBytes(ring.join(','));
    const ringPoints = ring.map(pubkeyToPoint);

    let c = hexToScalar(c0);

    for (let i = 0; i < n; i++) {
      const s = hexToScalar(responses[i]);
      const L_i = safeMultiply(G, s).add(safeMultiply(ringPoints[i], c));
      const HpI = hashPointForMember(ring[i], electionId);
      const R_i = safeMultiply(HpI, s).add(safeMultiply(I, c));
      c = challengeHash(msgBytes, ringBytes, L_i, R_i);
    }

    return scalarEqual(c, hexToScalar(c0));
  } catch {
    return false;
  }
}
