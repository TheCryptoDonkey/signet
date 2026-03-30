// Proof-of-Reserve Bond Attestation
// Non-custodial bond system: verifiers prove Bitcoin address control via BIP-322

import { BOND_DOMAIN_SEPARATOR, DEFAULT_BOND_MAX_AGE_SECS, VALID_BOND_ADDRESS_TYPES } from './constants.js';
import { getTagValue } from './validation.js';
import { SignetValidationError } from './errors.js';
import type { BondProof, BondStatus, BondVerificationResult, BIP322Verifier, BitcoinAddressType, NostrEvent } from './types.js';

/** Build the canonical BIP-322 message for a bond proof */
export function buildBondMessage(
  verifierPubkey: string,
  amountSats: number,
  timestamp: number,
): string {
  return `${BOND_DOMAIN_SEPARATOR}:${verifierPubkey}:${amountSats}:${timestamp}`;
}

export interface CreateBondProofParams {
  address: string;
  addressType: BitcoinAddressType;
  amountSats: number;
  signature: string;
  verifierPubkey: string;
  timestamp?: number;
}

/** Create a BondProof object (does not verify the signature) */
export function createBondProof(params: CreateBondProofParams): BondProof {
  const timestamp = params.timestamp ?? Math.floor(Date.now() / 1000);
  const message = buildBondMessage(params.verifierPubkey, params.amountSats, timestamp);

  return {
    address: params.address,
    addressType: params.addressType,
    amountSats: params.amountSats,
    timestamp,
    message,
    signature: params.signature,
  };
}

export interface VerifyBondProofOptions {
  /** External BIP-322 verifier. If omitted, signature is not checked (status becomes 'unverified'). */
  verifier?: BIP322Verifier;
  /** Maximum age in seconds (default: DEFAULT_BOND_MAX_AGE_SECS) */
  maxAgeSecs?: number;
  /** Minimum required amount in satoshis */
  requiredSats?: number;
  /** Override current time (unix seconds, for testing) */
  now?: number;
}

/** Verify a bond proof structurally and optionally cryptographically */
export async function verifyBondProof(
  proof: BondProof,
  verifierPubkey: string,
  opts: VerifyBondProofOptions = {},
): Promise<BondVerificationResult> {
  const errors: string[] = [];
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const maxAgeSecs = opts.maxAgeSecs ?? DEFAULT_BOND_MAX_AGE_SECS;

  // Structural validation
  if (!proof.address) {
    errors.push('Bond proof has empty address');
  }
  if (!proof.signature) {
    errors.push('Bond proof has empty signature');
  }
  if (proof.amountSats <= 0) {
    errors.push('Bond amount must be positive');
  }
  if (proof.timestamp > now) {
    errors.push('Bond proof timestamp is in the future');
  }

  // Verify that the message matches the expected format
  const expectedMessage = buildBondMessage(verifierPubkey, proof.amountSats, proof.timestamp);
  if (proof.message !== expectedMessage) {
    errors.push('Bond proof message does not match expected format for this verifier');
  }

  const ageSecs = now - proof.timestamp;
  const fresh = ageSecs <= maxAgeSecs;

  // Check threshold
  const meetsThreshold = opts.requiredSats != null
    ? proof.amountSats >= opts.requiredSats
    : null;

  // Signature verification
  let signatureValid: boolean | null = null;

  if (opts.verifier && errors.length === 0) {
    try {
      const result = await opts.verifier(proof.address, proof.message, proof.signature);
      signatureValid = result;
      if (!result) {
        errors.push('BIP-322 signature verification failed');
      }
    } catch (err) {
      errors.push(`BIP-322 verifier threw an error: ${err instanceof Error ? err.message : String(err)}`);
      signatureValid = false;
    }
  }

  // Determine overall status
  let status: BondStatus;
  if (errors.length > 0) {
    status = 'invalid';
  } else if (signatureValid === null) {
    status = 'unverified';
  } else if (!fresh) {
    status = 'stale';
  } else {
    status = 'valid';
  }

  // If there are no structural errors but proof is stale, mark as stale (not invalid)
  if (errors.length === 0 && signatureValid !== false && !fresh) {
    status = 'stale';
  }

  return {
    status,
    signatureValid,
    fresh,
    ageSecs,
    meetsThreshold,
    errors,
  };
}

/** Check whether a bond proof is older than the maximum allowed age */
export function isBondStale(
  proof: BondProof,
  maxAgeSecs: number = DEFAULT_BOND_MAX_AGE_SECS,
  now?: number,
): boolean {
  const currentTime = now ?? Math.floor(Date.now() / 1000);
  return currentTime - proof.timestamp > maxAgeSecs;
}

/** Serialise a BondProof into Nostr event tags (6 tags) */
export function bondProofToTags(proof: BondProof): string[][] {
  return [
    ['bond-address', proof.address],
    ['bond-address-type', proof.addressType],
    ['bond-amount', String(proof.amountSats)],
    ['bond-timestamp', String(proof.timestamp)],
    ['bond-message', proof.message],
    ['bond-signature', proof.signature],
  ];
}

/** Parse a BondProof from Nostr event tags, or return null if no bond tags are present */
export function parseBondProof(event: NostrEvent | { tags: string[][] }): BondProof | null {
  const address = getTagValue(event as NostrEvent, 'bond-address');
  if (!address) return null;

  const addressType = getTagValue(event as NostrEvent, 'bond-address-type') as BitcoinAddressType | undefined;
  const amountStr = getTagValue(event as NostrEvent, 'bond-amount');
  const timestampStr = getTagValue(event as NostrEvent, 'bond-timestamp');
  const message = getTagValue(event as NostrEvent, 'bond-message');
  const signature = getTagValue(event as NostrEvent, 'bond-signature');

  if (!addressType || !amountStr || !timestampStr || !message || !signature) {
    return null;
  }

  const amountSats = parseInt(amountStr, 10);
  const timestamp = parseInt(timestampStr, 10);

  if (isNaN(amountSats) || isNaN(timestamp)) {
    return null;
  }

  return {
    address,
    addressType,
    amountSats,
    timestamp,
    message,
    signature,
  };
}

/** Check whether a bond proof meets a required amount threshold */
export function checkBondCompliance(
  proof: BondProof | null,
  requiredSats: number,
): { meets: boolean; reason?: string } {
  if (!proof) {
    return { meets: false, reason: 'No bond proof provided' };
  }
  if (proof.amountSats < requiredSats) {
    return {
      meets: false,
      reason: `Bond amount ${proof.amountSats} sats is below required ${requiredSats} sats`,
    };
  }
  return { meets: true };
}
