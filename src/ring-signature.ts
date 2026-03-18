// SAG Ring Signatures — thin re-export from secp256k1-ring-sig with Signet domain separator
// Proves "one of N public keys signed this message" without revealing which one.
// Used for Tier 3/4 issuer privacy: "a professional verified this" without revealing which professional.

import { ringSign as _ringSign, ringVerify as _ringVerify, type RingSignature, MAX_RING_SIZE } from 'secp256k1-ring-sig';

const SIGNET_SAG_DOMAIN = 'signet-sag-v1';

export { MAX_RING_SIZE, type RingSignature };

/**
 * Sign a message with a ring signature using Signet's domain separator.
 *
 * @param message - The message to sign (will be hashed)
 * @param ring - Array of x-only public keys (hex) forming the anonymity set
 * @param signerIndex - Index of the actual signer in the ring
 * @param privateKey - Signer's private key (hex)
 * @returns A ring signature
 */
export function ringSign(
  message: string,
  ring: string[],
  signerIndex: number,
  privateKey: string
): RingSignature {
  const sig = _ringSign(message, ring, signerIndex, privateKey, SIGNET_SAG_DOMAIN);
  // Ensure the domain is carried in the signature so ringVerify uses the correct domain
  sig.domain = SIGNET_SAG_DOMAIN;
  return sig;
}

/**
 * Verify a ring signature.
 *
 * @param sig - The ring signature to verify
 * @returns true if the signature is valid
 */
export function ringVerify(sig: RingSignature): boolean {
  return _ringVerify(sig);
}

/**
 * Create a ring signature for a Signet credential.
 * Wraps ringSign with credential-specific message construction.
 *
 * @param credentialEventId - The event ID of the credential being signed
 * @param subjectPubkey - The pubkey of the person being verified
 * @param ring - Array of verifier pubkeys forming the anonymity set
 * @param signerIndex - Index of the actual signing verifier
 * @param privateKey - Signing verifier's private key
 */
export function signCredentialRing(
  credentialEventId: string,
  subjectPubkey: string,
  ring: string[],
  signerIndex: number,
  privateKey: string
): RingSignature {
  const message = `signet:credential:${credentialEventId}:${subjectPubkey}`;
  const sig = _ringSign(message, ring, signerIndex, privateKey, SIGNET_SAG_DOMAIN);
  sig.domain = SIGNET_SAG_DOMAIN;
  return sig;
}

/**
 * Verify a ring signature on a Signet credential.
 */
export function verifyCredentialRing(
  sig: RingSignature,
  credentialEventId: string,
  subjectPubkey: string
): boolean {
  const expectedMessage = `signet:credential:${credentialEventId}:${subjectPubkey}`;
  if (sig.message !== expectedMessage) return false;
  return _ringVerify(sig);
}
