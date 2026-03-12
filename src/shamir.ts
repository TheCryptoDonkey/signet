// Shamir's Secret Sharing over GF(256)
// Split secrets into threshold-of-n shares using polynomial interpolation

import { randomBytes } from '@noble/hashes/utils';
import { wordlist as BIP39_WORDLIST } from '@scure/bip39/wordlists/english.js';
import { zeroBytes } from './utils.js';

/**
 * Shamir's Secret Sharing over GF(256).
 *
 * INTENTIONAL DUPLICATION: Dominion Protocol has its own GF(256) Shamir
 * implementation. The low-level maths is identical but the protocols serve
 * different purposes:
 *
 *   - Signet: splits identity keys across PEOPLE (guardian recovery).
 *     Shares are encoded as BIP-39 words for human exchange.
 *   - Dominion: splits content keys across MACHINES (warden relays).
 *     Shares are raw bytes for relay distribution.
 *
 * Coupling the protocols via a shared dependency is worse than ~100 lines
 * of duplicated arithmetic. GF(256) is stable and will never change.
 *
 * See: trott-business/docs/plans/2026-03-12-fathom-alpha-live-design.md
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ShamirShare {
  id: number;       // 1-255 (the x coordinate)
  data: Uint8Array;  // evaluated polynomial bytes
}

// ---------------------------------------------------------------------------
// GF(256) Arithmetic — irreducible polynomial 0x11b (same as AES)
// ---------------------------------------------------------------------------

const IRREDUCIBLE = 0x11b;
const GENERATOR = 0x03;

/** Log table: log_g(i) for i in [0..255]. LOG[0] is unused. */
const LOG = new Uint8Array(256);
/** Exp table: g^i for i in [0..255]. EXP[255] wraps to EXP[0]. */
const EXP = new Uint8Array(256);

/** Carryless multiplication used only during table construction */
function gf256MulSlow(a: number, b: number): number {
  let result = 0;
  let aa = a;
  let bb = b;
  while (bb > 0) {
    if (bb & 1) result ^= aa;
    aa <<= 1;
    if (aa & 0x100) aa ^= IRREDUCIBLE;
    bb >>= 1;
  }
  return result;
}

// Build log/exp tables at module load time using generator 0x03
{
  let val = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = val;
    LOG[val] = i;
    val = gf256MulSlow(val, GENERATOR);
  }
  // Wrap: makes modular indexing simpler
  EXP[255] = EXP[0];
}

/** Addition in GF(256) is XOR */
export function gf256Add(a: number, b: number): number {
  return a ^ b;
}

/** Multiplication in GF(256) using log/exp tables */
export function gf256Mul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a] + LOG[b]) % 255];
}

/** Multiplicative inverse in GF(256) */
export function gf256Inv(a: number): number {
  if (a === 0) throw new Error('No inverse for zero in GF(256)');
  return EXP[(255 - LOG[a]) % 255];
}

// ---------------------------------------------------------------------------
// Shamir's Secret Sharing
// ---------------------------------------------------------------------------

/**
 * Evaluate a polynomial at x in GF(256) using Horner's method.
 * coeffs[0] is the constant term (the secret byte).
 */
function evalPoly(coeffs: Uint8Array, x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gf256Add(gf256Mul(result, x), coeffs[i]);
  }
  return result;
}

/**
 * Split a secret into shares using Shamir's Secret Sharing over GF(256).
 *
 * @param secret    The secret bytes to split
 * @param threshold Minimum shares needed to reconstruct (>= 2)
 * @param shares    Total number of shares to create (>= threshold, <= 255)
 * @returns Array of ShamirShare objects
 */
export function splitSecret(
  secret: Uint8Array,
  threshold: number,
  shares: number,
): ShamirShare[] {
  if (threshold < 2) {
    throw new Error('Threshold must be at least 2');
  }
  if (shares < threshold) {
    throw new Error('Number of shares must be >= threshold');
  }
  if (shares > 255) {
    throw new Error('Number of shares must be <= 255');
  }

  const secretLen = secret.length;
  const result: ShamirShare[] = [];

  // Initialize share data arrays
  for (let i = 0; i < shares; i++) {
    result.push({ id: i + 1, data: new Uint8Array(secretLen) });
  }

  // For each byte of the secret, build a random polynomial and evaluate
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    // coeffs[0] = secret byte, coeffs[1..threshold-1] = random
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[byteIdx];

    const rand = randomBytes(threshold - 1);
    for (let j = 1; j < threshold; j++) {
      coeffs[j] = rand[j - 1];
    }

    // Evaluate at x = 1, 2, ..., shares
    for (let i = 0; i < shares; i++) {
      result[i].data[byteIdx] = evalPoly(coeffs, i + 1);
    }

    zeroBytes(coeffs);
    zeroBytes(rand);
  }

  return result;
}

/**
 * Reconstruct a secret from shares using Lagrange interpolation over GF(256).
 *
 * @param shares    Array of shares (at least `threshold` shares)
 * @param threshold The threshold used during splitting
 * @returns The reconstructed secret bytes
 */
export function reconstructSecret(
  shares: ShamirShare[],
  threshold: number,
): Uint8Array {
  if (shares.length < threshold) {
    throw new Error(`Need at least ${threshold} shares, got ${shares.length}`);
  }

  // Use only the first `threshold` shares
  const used = shares.slice(0, threshold);

  // Validate no duplicate share IDs
  const ids = new Set(used.map(s => s.id));
  if (ids.size !== used.length) {
    throw new Error('Duplicate share IDs detected — each share must have a unique ID');
  }

  // Reject shares with ID 0: x=0 is the secret itself, not a valid share x-coordinate
  for (const share of used) {
    if (share.id === 0) {
      throw new Error('Invalid share ID: 0 is not a valid x-coordinate');
    }
  }
  const secretLen = used[0].data.length;
  for (const share of used) {
    if (share.data.length !== secretLen) {
      throw new Error('Inconsistent share lengths — shares may be from different secrets');
    }
  }
  const result = new Uint8Array(secretLen);

  // Lagrange interpolation at x = 0 for each byte position
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let value = 0;

    for (let i = 0; i < threshold; i++) {
      const xi = used[i].id;
      const yi = used[i].data[byteIdx];

      // Lagrange basis l_i(0) = product of x_j / (x_i ^ x_j) for j != i
      // In GF(256): subtraction = addition = XOR
      let basis = 1;
      for (let j = 0; j < threshold; j++) {
        if (i === j) continue;
        const xj = used[j].id;
        basis = gf256Mul(basis, gf256Mul(xj, gf256Inv(gf256Add(xi, xj))));
      }

      value = gf256Add(value, gf256Mul(yi, basis));
    }

    result[byteIdx] = value;
  }

  return result;
}

// ---------------------------------------------------------------------------
// BIP-39 Word Encoding
// ---------------------------------------------------------------------------

/**
 * Encode a share as BIP-39 words.
 * Prepends the share ID byte to the data, then converts to 11-bit groups.
 */
export function shareToWords(share: ShamirShare): string[] {
  // Prepend ID byte to data
  const bytes = new Uint8Array(1 + share.data.length);
  bytes[0] = share.id;
  bytes.set(share.data, 1);

  // Stream bytes into 11-bit word indices
  const words: string[] = [];
  let bits = 0;
  let accumulator = 0;

  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 11) {
      bits -= 11;
      const index = (accumulator >> bits) & 0x7ff;
      words.push(BIP39_WORDLIST[index]);
    }
  }

  // Pad remaining bits on the right to form a final 11-bit group
  if (bits > 0) {
    const index = (accumulator << (11 - bits)) & 0x7ff;
    words.push(BIP39_WORDLIST[index]);
  }

  return words;
}

/**
 * Decode BIP-39 words back to a share.
 * Reverses the encoding from shareToWords.
 */
export function wordsToShare(words: string[]): ShamirShare {
  // Convert words to 11-bit indices
  const indices: number[] = [];
  for (const word of words) {
    const idx = BIP39_WORDLIST.indexOf(word.toLowerCase());
    if (idx === -1) throw new Error(`Unknown BIP-39 word: "${word}"`);
    indices.push(idx);
  }

  // Total bits encoded, and how many full bytes that represents
  const totalBits = indices.length * 11;
  const totalBytes = Math.floor(totalBits / 8);

  // Stream 11-bit groups into bytes
  let bits = 0;
  let accumulator = 0;
  const byteList: number[] = [];

  for (const index of indices) {
    accumulator = (accumulator << 11) | index;
    bits += 11;
    while (bits >= 8) {
      bits -= 8;
      byteList.push((accumulator >> bits) & 0xff);
    }
  }

  // Only take the expected number of full bytes (discard padding bits)
  const usable = byteList.slice(0, totalBytes);

  // First byte is the share ID, rest is data
  const id = usable[0];
  const data = new Uint8Array(usable.slice(1));

  return { id, data };
}
