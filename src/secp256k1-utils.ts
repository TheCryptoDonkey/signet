// Shared secp256k1 utilities for ring-signature.ts and range-proof.ts.
// These are internal crypto helpers — not exported from src/index.ts.

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes, concatBytes } from '@noble/hashes/utils';

export const Point = secp256k1.ProjectivePoint;
export const N = secp256k1.CURVE.n;
export type ProjectivePoint = typeof Point.BASE;

/** Modular arithmetic helper — defaults to curve order N */
export function mod(a: bigint, m: bigint = N): bigint {
  const result = a % m;
  return result >= 0n ? result : result + m;
}

/** Generate a random scalar in [1, N-1] (rejection sampling if mod reduces to 0) */
export function randomScalar(): bigint {
  let s: bigint;
  do {
    const bytes = secp256k1.utils.randomPrivateKey();
    s = mod(BigInt('0x' + bytesToHex(bytes)));
  } while (s === 0n);
  return s;
}

/** Convert a scalar bigint to 32-byte hex */
export function scalarToHex(s: bigint): string {
  return s.toString(16).padStart(64, '0');
}

/** Convert hex to bigint scalar */
export function hexToScalar(hex: string): bigint {
  return BigInt('0x' + hex);
}

/** Hash to scalar: SHA-256 of concatenated data, reduced mod N */
export function hashToScalar(...parts: Uint8Array[]): bigint {
  const data = concatBytes(...parts);
  const h = sha256(data);
  return mod(BigInt('0x' + bytesToHex(h)));
}

/** Safe scalar multiplication — handles 0n (which noble/curves rejects) */
export function safeMultiply(point: ProjectivePoint, scalar: bigint): ProjectivePoint {
  const s = mod(scalar);
  if (s === 0n) return Point.ZERO;
  return point.multiply(s);
}

// --- Generator Points ---

/** Generator G: standard secp256k1 base point */
export const G = Point.BASE;

/**
 * Generator H: nothing-up-my-sleeve second generator for Pedersen commitments.
 * Created by hashing to a curve point — nobody knows log_G(H).
 */
function createGeneratorH(): ProjectivePoint {
  const seed = utf8ToBytes('Signet-Pedersen-Generator-H-v1');
  for (let i = 0; i < 256; i++) {
    const buf = new Uint8Array(seed.length + 1);
    buf.set(seed);
    buf[seed.length] = i;
    const h = sha256(buf);
    const hex = '02' + bytesToHex(h);
    try {
      const point = Point.fromHex(hex);
      point.assertValidity();
      return point;
    } catch {
      continue;
    }
  }
  throw new Error('Failed to generate H point');
}

export const H = createGeneratorH();
