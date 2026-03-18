// LSAG (Linkable Spontaneous Anonymous Group) Ring Signatures
// Thin re-export from secp256k1-ring-sig with Signet domain separator.
// Extends SAG with a key image that links signatures by the same signer
// across multiple uses of the same election, enabling double-vote detection.

import {
  computeKeyImage as _computeKeyImage,
  hasDuplicateKeyImage as _hasDuplicateKeyImage,
  lsagSign as _lsagSign,
  lsagVerify as _lsagVerify,
  type LsagSignature,
  MAX_RING_SIZE,
} from 'secp256k1-ring-sig';

export { type LsagSignature, MAX_RING_SIZE };

// Re-export directly — the package handles domain separation internally.
export const computeKeyImage = _computeKeyImage;
export const hasDuplicateKeyImage = _hasDuplicateKeyImage;
export const lsagSign = _lsagSign;
export const lsagVerify = _lsagVerify;
