// Pedersen Commitments + Range Proofs — compatibility wrapper over @forgesworn/range-proof
// Proves "value is in [min, max]" without revealing the exact value.
// Used for Tier 4 age range proofs: "child aged 8-12" without revealing exact age.

import {
  commit,
  verifyCommitment,
  createRangeProof,
  createAgeRangeProof,
  serializeRangeProof,
  deserializeRangeProof,
  type PedersenCommitment,
  type RangeProof,
} from '@forgesworn/range-proof';
import {
  verifyRangeProof as verifyRangeProofUpstream,
  verifyAgeRangeProof as verifyAgeRangeProofUpstream,
} from '@forgesworn/range-proof';

function normalizeBindingContext(bindingContext?: string): string | undefined {
  return bindingContext === '' ? undefined : bindingContext;
}

function parseAgeRange(ageRange: string): { min: number; max: number } | null {
  const digitsOnly = /^\d+$/;

  if (ageRange.endsWith('+')) {
    const minStr = ageRange.slice(0, -1);
    if (!digitsOnly.test(minStr)) return null;
    return { min: parseInt(minStr, 10), max: 150 };
  }

  const parts = ageRange.split('-');
  if (parts.length !== 2) return null;
  if (!digitsOnly.test(parts[0]) || !digitsOnly.test(parts[1])) return null;
  return {
    min: parseInt(parts[0], 10),
    max: parseInt(parts[1], 10),
  };
}

export { commit, verifyCommitment, createRangeProof, createAgeRangeProof, serializeRangeProof, deserializeRangeProof };
export type { PedersenCommitment, RangeProof };

export function verifyRangeProof(
  proof: RangeProof,
  expectedMin: number,
  expectedMax: number,
  expectedBindingContext?: string
): boolean {
  if (!Number.isSafeInteger(expectedMin) || !Number.isSafeInteger(expectedMax)) return false;
  if (expectedMin < 0 || expectedMax < 0 || expectedMax < expectedMin) return false;
  if (proof.min !== expectedMin || proof.max !== expectedMax) return false;
  if (normalizeBindingContext(proof.context) !== normalizeBindingContext(expectedBindingContext)) return false;
  return verifyRangeProofUpstream(proof, expectedMin, expectedMax, expectedBindingContext);
}

export function verifyAgeRangeProof(
  proof: RangeProof,
  expectedAgeRange: string,
  expectedSubjectPubkey?: string
): boolean {
  const parsed = parseAgeRange(expectedAgeRange);
  if (!parsed) return false;
  return verifyRangeProof(proof, parsed.min, parsed.max, expectedSubjectPubkey);
}
