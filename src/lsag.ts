// LSAG (Linkable Spontaneous Anonymous Group) Ring Signatures
// Thin re-export from @forgesworn/ring-sig with Signet domain separator.
// Extends SAG with a key image that links signatures by the same signer
// across multiple uses of the same election, enabling double-vote detection.

import {
  computeKeyImage as _computeKeyImage,
  hasDuplicateKeyImage as _hasDuplicateKeyImage,
  lsagSign as _lsagSign,
  lsagVerify as _lsagVerify,
  type LsagSignature,
  MAX_RING_SIZE,
} from '@forgesworn/ring-sig';

const SIGNET_LSAG_DOMAIN = 'signet-lsag-v1';

export { type LsagSignature, MAX_RING_SIZE };

// Key image functions do not involve challenge hashes — safe to re-export directly.
export const computeKeyImage = _computeKeyImage;
export const hasDuplicateKeyImage = _hasDuplicateKeyImage;

/**
 * Sign with LSAG using Signet's domain separator.
 *
 * @param message - The message to sign (typically `electionId:SHA-256(encryptedVote)`)
 * @param ring - Array of x-only public keys (hex) forming the anonymity set
 * @param signerIndex - Index of the actual signer in the ring
 * @param privateKey - Signer's private key (hex)
 * @param electionId - Election identifier for key image linkability
 * @returns A linkable ring signature with Signet domain
 */
export function lsagSign(
  message: string,
  ring: string[],
  signerIndex: number,
  privateKey: string,
  electionId: string,
): LsagSignature {
  const sig = _lsagSign(message, ring, signerIndex, privateKey, electionId, SIGNET_LSAG_DOMAIN);
  sig.domain = SIGNET_LSAG_DOMAIN;
  return sig;
}

/**
 * Verify an LSAG signature.
 *
 * @param sig - The LSAG signature to verify
 * @returns true if the signature is valid
 */
export function lsagVerify(sig: LsagSignature): boolean {
  return _lsagVerify(sig);
}
