// Pedersen Commitments + Range Proofs on secp256k1
// Proves "value is in [min, max]" without revealing the exact value.
// Used for Tier 4 age range proofs: "child aged 8-12" without revealing exact age.

import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import {
  Point,
  type ProjectivePoint,
  mod,
  randomScalar,
  scalarToHex,
  hexToScalar,
  hashToScalar,
  safeMultiply,
  scalarEqual,
  G,
  H,
} from './secp256k1-utils.js';

function pointToBytes(p: ProjectivePoint): Uint8Array {
  return p.toRawBytes(true);
}

const DOMAIN_BIT_PROOF = 'signet-bit-proof';
const DOMAIN_SUM_BINDING = 'signet-sum-binding';

/** Empty context (no binding) */
const EMPTY_CONTEXT = new Uint8Array(0);

// --- Pedersen Commitment ---

export interface PedersenCommitment {
  /** The commitment point C = v*G + r*H (compressed hex) */
  commitment: string;
  /** The blinding factor (hex) — kept secret by the committer */
  blinding: string;
  /** The committed value — kept secret by the committer */
  value: number;
}

/**
 * Create a Pedersen commitment: C = v*G + r*H
 * @param value - The value to commit to
 * @param blinding - Optional blinding factor (random if not provided)
 */
export function commit(value: number, blinding?: bigint): PedersenCommitment {
  const v = BigInt(value);
  const r = blinding ?? randomScalar();

  // C = v*G + r*H
  const vG = safeMultiply(G, v);
  const rH = safeMultiply(H, r);
  const C = vG.add(rH);

  return {
    commitment: C.toHex(true),
    blinding: scalarToHex(r),
    value,
  };
}

/**
 * Open and verify a Pedersen commitment.
 */
export function verifyCommitment(commitment: string, value: number, blinding: string): boolean {
  try {
    const v = BigInt(value);
    const r = hexToScalar(blinding);
    const C = Point.fromHex(commitment);
    const expected = safeMultiply(G, v).add(safeMultiply(H, r));
    return C.equals(expected);
  } catch {
    return false;
  }
}

// --- Bit Proof (OR-proof that a committed bit is 0 or 1) ---

interface BitProof {
  /** Commitment to the bit: C = b*G + r*H */
  commitment: string;
  /** Challenge for the b=0 branch */
  e0: string;
  /** Response for the b=0 branch */
  s0: string;
  /** Challenge for the b=1 branch */
  e1: string;
  /** Response for the b=1 branch */
  s1: string;
}

/**
 * Create an OR-proof that a Pedersen commitment contains 0 or 1.
 * Uses Cramer-Damgård-Schoenmakers OR composition.
 *
 * Statement: "∃r: C = r*H" (bit=0) OR "∃r: C - G = r*H" (bit=1)
 *
 * Schnorr convention: s = k - e*r, verify R = s*H + e*P
 *
 * @param context - Optional binding context included in Fiat-Shamir hash
 *                  (e.g. subject pubkey) to prevent proof transplanting
 */
function proveBit(bit: 0 | 1, blinding: bigint, commitmentPoint: ProjectivePoint, context: Uint8Array = EMPTY_CONTEXT): BitProof {
  const C = commitmentPoint;
  const commitHex = C.toHex(true);

  if (bit === 0) {
    // Real branch: C = r*H, prove knowledge of r (DLog of C w.r.t. H)
    // Fake branch: C - G = r'*H (simulate)
    const k = randomScalar();
    const R0 = safeMultiply(H, k); // real commitment

    // Simulate branch 1
    const fakeE1 = randomScalar();
    const fakeS1 = randomScalar();
    // R1 = s1*H + e1*(C - G)
    const CminusG = C.add(G.negate());
    const R1 = safeMultiply(H, fakeS1).add(safeMultiply(CminusG, fakeE1));

    // Fiat-Shamir challenge (includes context to bind proof to credential)
    const e = hashToScalar(
      utf8ToBytes(DOMAIN_BIT_PROOF),
      context,
      hexToBytes(commitHex),
      pointToBytes(R0),
      pointToBytes(R1)
    );

    const e0 = mod(e - fakeE1);
    // Schnorr: s = k - e*r, verifier checks s*H + e*C = R
    const s0 = mod(k - mod(e0 * blinding));

    return {
      commitment: commitHex,
      e0: scalarToHex(e0),
      s0: scalarToHex(s0),
      e1: scalarToHex(fakeE1),
      s1: scalarToHex(fakeS1),
    };
  } else {
    // bit === 1
    // Real branch: C - G = r*H, prove knowledge of r
    // Fake branch: C = r'*H (simulate)
    const k = randomScalar();
    const R1 = safeMultiply(H, k); // real commitment

    // Simulate branch 0
    const fakeE0 = randomScalar();
    const fakeS0 = randomScalar();
    // For Schnorr DLog proof of C = r*H:
    //   Prover sends R = k*H, gets challenge e, responds s = k - e*r
    //   Verifier checks s*H + e*C = k*H = R
    const R0 = safeMultiply(H, fakeS0).add(safeMultiply(C, fakeE0));

    // Fiat-Shamir challenge (includes context to bind proof to credential)
    const e = hashToScalar(
      utf8ToBytes(DOMAIN_BIT_PROOF),
      context,
      hexToBytes(commitHex),
      pointToBytes(R0),
      pointToBytes(R1)
    );

    const e1 = mod(e - fakeE0);
    // Schnorr: s = k - e*r, verifier checks s*H + e*(C-G) = R
    const s1 = mod(k - mod(e1 * blinding));

    return {
      commitment: commitHex,
      e0: scalarToHex(fakeE0),
      s0: scalarToHex(fakeS0),
      e1: scalarToHex(e1),
      s1: scalarToHex(s1),
    };
  }
}

/**
 * Verify a bit proof: the commitment contains either 0 or 1.
 */
function verifyBitProof(proof: BitProof, context: Uint8Array = EMPTY_CONTEXT): boolean {
  try {
    const C = Point.fromHex(proof.commitment);
    const e0 = hexToScalar(proof.e0);
    const s0 = hexToScalar(proof.s0);
    const e1 = hexToScalar(proof.e1);
    const s1 = hexToScalar(proof.s1);

    // Reconstruct R0: for b=0 branch (C = r*H)
    // R0 = s0*H + e0*C
    const R0 = safeMultiply(H, s0).add(safeMultiply(C, e0));

    // Reconstruct R1: for b=1 branch (C - G = r*H)
    // R1 = s1*H + e1*(C - G)
    const CminusG = C.add(G.negate());
    const R1 = safeMultiply(H, s1).add(safeMultiply(CminusG, e1));

    // Check Fiat-Shamir: e0 + e1 = H(...)
    const e = hashToScalar(
      utf8ToBytes(DOMAIN_BIT_PROOF),
      context,
      hexToBytes(proof.commitment),
      pointToBytes(R0),
      pointToBytes(R1)
    );

    return scalarEqual(mod(e0 + e1), e);
  } catch {
    return false;
  }
}

// --- Range Proof ---

export interface RangeProof {
  /** Overall commitment to the value: C = v*G + r*H */
  commitment: string;
  /** Minimum of the range */
  min: number;
  /** Maximum of the range */
  max: number;
  /** Number of bits used */
  bits: number;
  /** Proof that (value - min) is non-negative and fits in `bits` bits */
  lowerProof: BitProof[];
  /** Proof that (max - value) is non-negative and fits in `bits` bits */
  upperProof: BitProof[];
  /** Commitment to (value - min) */
  lowerCommitment: string;
  /** Commitment to (max - value) */
  upperCommitment: string;
  /** Sum-binding proof: DLog of (lowerC + upperC - range*G) w.r.t. H */
  sumBindingE: string;
  sumBindingS: string;
  /** Optional binding context (e.g. subject pubkey hex) included in Fiat-Shamir
   *  challenges to prevent proof transplanting between credentials. */
  context?: string;
}

/**
 * Number of bits needed to represent a value.
 */
function bitsNeeded(maxVal: number): number {
  if (maxVal <= 0) return 1;
  return Math.ceil(Math.log2(maxVal + 1));
}

/**
 * Prove knowledge of the discrete log of D w.r.t. H.
 * D must equal r*H for the proof to verify.
 * Uses Schnorr convention: s = k - e*r, verify s*H + e*D = R.
 */
function proveSumBinding(
  rTotal: bigint,
  D: ProjectivePoint,
  context: Uint8Array = EMPTY_CONTEXT
): { e: string; s: string } {
  const k = randomScalar();
  const R = safeMultiply(H, k);

  const e = hashToScalar(
    utf8ToBytes(DOMAIN_SUM_BINDING),
    context,
    pointToBytes(D),
    pointToBytes(R)
  );

  const s = mod(k - mod(e * rTotal));

  return { e: scalarToHex(e), s: scalarToHex(s) };
}

function verifySumBinding(
  D: ProjectivePoint,
  eHex: string,
  sHex: string,
  context: Uint8Array = EMPTY_CONTEXT
): boolean {
  try {
    const e = hexToScalar(eHex);
    const s = hexToScalar(sHex);

    // R = s*H + e*D (Schnorr verification)
    const R = safeMultiply(H, s).add(safeMultiply(D, e));
    const eCheck = hashToScalar(
      utf8ToBytes(DOMAIN_SUM_BINDING),
      context,
      pointToBytes(D),
      pointToBytes(R)
    );
    return scalarEqual(eCheck, e);
  } catch {
    return false;
  }
}

/**
 * Create a range proof proving value ∈ [min, max].
 *
 * @param value - The secret value
 * @param min - Minimum of the range (inclusive)
 * @param max - Maximum of the range (inclusive)
 * @param bindingContext - Optional context string (e.g. subject pubkey) included
 *                         in Fiat-Shamir challenges to prevent proof transplanting
 * @returns A range proof and the commitment
 */
export function createRangeProof(value: number, min: number, max: number, bindingContext?: string): RangeProof {
  if (value < min || value > max) throw new Error(`Value ${value} not in range [${min}, ${max}]`);
  if (min < 0) throw new Error('Minimum must be non-negative');

  const context = bindingContext ? utf8ToBytes(bindingContext) : EMPTY_CONTEXT;

  const range = max - min;
  const bits = bitsNeeded(range);

  // Commit to the value
  const blinding = randomScalar();
  const valueBI = BigInt(value);
  const C = safeMultiply(G, valueBI).add(safeMultiply(H, blinding));

  // Prove (value - min) ∈ [0, 2^bits - 1]
  const lowerVal = value - min;
  const lowerBitProofs: BitProof[] = [];

  let lowerBlindingSum = 0n;
  for (let i = 0; i < bits; i++) {
    const bit = ((lowerVal >> i) & 1) as 0 | 1;
    const r_i = randomScalar();
    lowerBlindingSum = mod(lowerBlindingSum + (1n << BigInt(i)) * r_i);

    const bitCommitment = safeMultiply(G, BigInt(bit)).add(safeMultiply(H, r_i));
    lowerBitProofs.push(proveBit(bit, r_i, bitCommitment, context));
  }

  // Commitment to (value - min)
  const lowerC = safeMultiply(G, BigInt(lowerVal)).add(safeMultiply(H, lowerBlindingSum));

  // Prove (max - value) ∈ [0, 2^bits - 1]
  const upperVal = max - value;
  const upperBitProofs: BitProof[] = [];

  let upperBlindingSum = 0n;
  for (let i = 0; i < bits; i++) {
    const bit = ((upperVal >> i) & 1) as 0 | 1;
    const r_i = randomScalar();
    upperBlindingSum = mod(upperBlindingSum + (1n << BigInt(i)) * r_i);

    const bitCommitment = safeMultiply(G, BigInt(bit)).add(safeMultiply(H, r_i));
    upperBitProofs.push(proveBit(bit, r_i, bitCommitment, context));
  }

  const upperC = safeMultiply(G, BigInt(upperVal)).add(safeMultiply(H, upperBlindingSum));

  // Sum-binding proof: prove lowerC + upperC - range*G = r_total * H
  // This ensures the two sub-values sum to (max - min)
  const rTotal = mod(lowerBlindingSum + upperBlindingSum);
  const rangeG = safeMultiply(G, BigInt(range));
  const D = lowerC.add(upperC).add(rangeG.negate());
  const sumBinding = proveSumBinding(rTotal, D, context);

  return {
    commitment: C.toHex(true),
    min,
    max,
    bits,
    lowerProof: lowerBitProofs,
    upperProof: upperBitProofs,
    lowerCommitment: lowerC.toHex(true),
    upperCommitment: upperC.toHex(true),
    sumBindingE: sumBinding.e,
    sumBindingS: sumBinding.s,
    context: bindingContext,
  };
}

/**
 * Verify a range proof.
 *
 * @param proof - The range proof to verify
 * @returns true if the proof is valid
 */
export function verifyRangeProof(proof: RangeProof): boolean {
  try {
    const { min, max, bits, lowerProof, upperProof } = proof;
    const context = proof.context ? utf8ToBytes(proof.context) : EMPTY_CONTEXT;

    if (lowerProof.length !== bits || upperProof.length !== bits) return false;

    // 1. Verify all bit proofs for lower (value - min)
    for (const bp of lowerProof) {
      if (!verifyBitProof(bp, context)) return false;
    }

    // 2. Verify all bit proofs for upper (max - value)
    for (const bp of upperProof) {
      if (!verifyBitProof(bp, context)) return false;
    }

    // 3. Verify bit commitments sum to the aggregate commitment (lower)
    let lowerSum = Point.ZERO;
    for (let i = 0; i < bits; i++) {
      const bitC = Point.fromHex(lowerProof[i].commitment);
      const weight = 1n << BigInt(i);
      lowerSum = lowerSum.add(safeMultiply(bitC, weight));
    }
    const lowerC = Point.fromHex(proof.lowerCommitment);
    if (!lowerSum.equals(lowerC)) return false;

    // 4. Verify bit commitments sum to the aggregate commitment (upper)
    let upperSum = Point.ZERO;
    for (let i = 0; i < bits; i++) {
      const bitC = Point.fromHex(upperProof[i].commitment);
      const weight = 1n << BigInt(i);
      upperSum = upperSum.add(safeMultiply(bitC, weight));
    }
    const upperC = Point.fromHex(proof.upperCommitment);
    if (!upperSum.equals(upperC)) return false;

    // 5. Verify sum-binding: lowerC + upperC - range*G = r_total * H
    // This proves the two sub-values sum to exactly (max - min)
    const rangeG = safeMultiply(G, BigInt(max - min));
    const D = lowerC.add(upperC).add(rangeG.negate());
    if (!verifySumBinding(D, proof.sumBindingE, proof.sumBindingS, context)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Create an age range proof for a Signet Tier 4 credential.
 *
 * @param age - The child's actual age (secret)
 * @param ageRange - The range to prove, e.g. "8-12"
 * @param subjectPubkey - Optional subject pubkey to bind the proof to this credential
 * @returns The range proof (to be placed in event content)
 */
export function createAgeRangeProof(age: number, ageRange: string, subjectPubkey?: string): RangeProof {
  // Handle "18+" format (adults, no upper bound — use 150 as practical max)
  if (ageRange.endsWith('+')) {
    const min = parseInt(ageRange.slice(0, -1), 10);
    if (isNaN(min)) throw new Error(`Invalid age range format: ${ageRange}`);
    return createRangeProof(age, min, 150, subjectPubkey);
  }

  const [minStr, maxStr] = ageRange.split('-');
  const min = parseInt(minStr, 10);
  const max = parseInt(maxStr, 10);

  if (isNaN(min) || isNaN(max)) throw new Error(`Invalid age range format: ${ageRange}`);

  return createRangeProof(age, min, max, subjectPubkey);
}

/**
 * Verify an age range proof.
 */
export function verifyAgeRangeProof(proof: RangeProof): boolean {
  return verifyRangeProof(proof);
}

/**
 * Serialize a range proof to a JSON string for embedding in event content.
 */
export function serializeRangeProof(proof: RangeProof): string {
  return JSON.stringify(proof);
}

/**
 * Deserialize a range proof from a JSON string.
 */
export function deserializeRangeProof(json: string): RangeProof {
  const parsed = JSON.parse(json);
  if (typeof parsed !== 'object' || parsed === null) throw new Error('Invalid range proof: not an object');
  if (typeof parsed.min !== 'number' || typeof parsed.max !== 'number') {
    throw new Error('Invalid range proof: missing min/max');
  }
  if (typeof parsed.bits !== 'number' || typeof parsed.commitment !== 'string') {
    throw new Error('Invalid range proof: missing bits or commitment');
  }
  if (!Array.isArray(parsed.lowerProof) || !Array.isArray(parsed.upperProof)) {
    throw new Error('Invalid range proof: missing lowerProof/upperProof');
  }
  if (typeof parsed.lowerCommitment !== 'string' || typeof parsed.upperCommitment !== 'string') {
    throw new Error('Invalid range proof: missing lowerCommitment/upperCommitment');
  }
  if (typeof parsed.sumBindingE !== 'string' || typeof parsed.sumBindingS !== 'string') {
    throw new Error('Invalid range proof: missing sumBindingE/sumBindingS');
  }
  // Validate bit proof array contents
  for (const bp of [...parsed.lowerProof, ...parsed.upperProof]) {
    if (typeof bp !== 'object' || bp === null) throw new Error('Invalid range proof: bit proof is not an object');
    if (typeof bp.commitment !== 'string' || typeof bp.e0 !== 'string' ||
        typeof bp.s0 !== 'string' || typeof bp.e1 !== 'string' || typeof bp.s1 !== 'string') {
      throw new Error('Invalid range proof: bit proof missing required fields');
    }
  }
  if (parsed.context !== undefined && typeof parsed.context !== 'string') {
    throw new Error('Invalid range proof: context must be a string if present');
  }
  return parsed as RangeProof;
}
