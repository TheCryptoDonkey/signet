// Pedersen Commitments + Range Proofs — thin re-export from secp256k1-range-proof
// Proves "value is in [min, max]" without revealing the exact value.
// Used for Tier 4 age range proofs: "child aged 8-12" without revealing exact age.

export {
  type PedersenCommitment,
  type RangeProof,
  commit,
  verifyCommitment,
  createRangeProof,
  verifyRangeProof,
  createAgeRangeProof,
  verifyAgeRangeProof,
  serializeRangeProof,
  deserializeRangeProof,
} from 'secp256k1-range-proof';
