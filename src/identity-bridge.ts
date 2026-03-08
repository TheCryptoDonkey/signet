// Identity Bridge (kind 30476)
// Allows an anonymous account to cryptographically prove it is controlled by
// a verified real account, without revealing which one. Uses SAG ring signatures.
//
// Published from the anon account. Content contains a ring signature proving
// one of N verified accounts also controls this anon account.

import { SIGNET_KINDS, SIGNET_LABEL, MIN_BRIDGE_RING_SIZE, TRUST_WEIGHTS } from './constants.js';
import { getPublicKey, signEvent, verifyEvent } from './crypto.js';
import { ringSign, ringVerify } from './ring-signature.js';
import { getTagValue } from './validation.js';
import { randomBytes } from '@noble/hashes/utils';
import type { NostrEvent, UnsignedEvent, SignetTier, ParsedIdentityBridge } from './types.js';
import type { RingSignature } from './ring-signature.js';

/** Generate a cryptographically secure random integer in [0, max) */
function secureRandomInt(max: number): number {
  const bytes = randomBytes(4);
  const val = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return val % max;
}

/**
 * Select decoy ring members from a set of verified pubkeys.
 * Inserts the real pubkey at a random position among the decoys.
 *
 * @param verifiedPubkeys - Pool of verified pubkeys to choose decoys from (must not include realPubkey)
 * @param realPubkey - The real verified account's pubkey
 * @param ringSize - Desired ring size (minimum MIN_BRIDGE_RING_SIZE)
 * @returns { ring, signerIndex } — the ring array and the position of the real signer
 */
export function selectDecoyRing(
  verifiedPubkeys: string[],
  realPubkey: string,
  ringSize: number = MIN_BRIDGE_RING_SIZE
): { ring: string[]; signerIndex: number } {
  if (ringSize < MIN_BRIDGE_RING_SIZE) {
    throw new Error(`Ring size must be at least ${MIN_BRIDGE_RING_SIZE}`);
  }
  // Filter out the real pubkey from candidates
  const candidates = verifiedPubkeys.filter((pk) => pk !== realPubkey);
  const decoyCount = ringSize - 1;
  if (candidates.length < decoyCount) {
    throw new Error(
      `Not enough verified pubkeys for ring: need ${decoyCount} decoys, have ${candidates.length}`
    );
  }

  // Shuffle and pick decoys (Fisher-Yates partial shuffle, CSPRNG)
  const shuffled = [...candidates];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  const decoys = shuffled.slice(0, decoyCount);

  // Insert real pubkey at a random position (CSPRNG)
  const signerIndex = secureRandomInt(ringSize);
  const ring: string[] = [];
  let decoyIdx = 0;
  for (let i = 0; i < ringSize; i++) {
    if (i === signerIndex) {
      ring.push(realPubkey);
    } else {
      ring.push(decoys[decoyIdx++]);
    }
  }

  return { ring, signerIndex };
}

/**
 * Compute the trust weight contribution of an identity bridge based on the
 * minimum tier of ring members.
 */
export function computeBridgeWeight(ringMinTier: SignetTier): number {
  return TRUST_WEIGHTS.IDENTITY_BRIDGE * (ringMinTier / 4);
}

/**
 * Create an identity bridge event (kind 30476).
 * Published from the anonymous account, it proves the anon account owner
 * also controls one of the verified accounts in the ring.
 *
 * @param anonPrivateKey - Private key of the anonymous account (signs the Nostr event)
 * @param realPrivateKey - Private key of the real verified account (signs the ring signature)
 * @param ring - Array of verified pubkeys forming the anonymity set
 * @param signerIndex - Position of the real account in the ring
 * @param ringMinTier - Minimum verification tier among ring members
 * @returns Signed kind 30476 NostrEvent
 */
export async function createIdentityBridge(
  anonPrivateKey: string,
  realPrivateKey: string,
  ring: string[],
  signerIndex: number,
  ringMinTier: SignetTier
): Promise<NostrEvent> {
  if (ring.length < MIN_BRIDGE_RING_SIZE) {
    throw new Error(`Ring must have at least ${MIN_BRIDGE_RING_SIZE} members`);
  }

  const anonPubkey = getPublicKey(anonPrivateKey);
  const timestamp = Math.floor(Date.now() / 1000);

  // The binding message ties the anon pubkey to this timestamp
  const bindingMessage = `signet:identity-bridge:${anonPubkey}:${timestamp}`;

  // Ring signature: real private key signs binding message inside the ring
  const ringSig = ringSign(bindingMessage, ring, signerIndex, realPrivateKey);

  const content = JSON.stringify({
    ringSig: {
      ring: ringSig.ring,
      c0: ringSig.c0,
      responses: ringSig.responses,
      message: ringSig.message,
    },
    timestamp,
  });

  const unsigned: UnsignedEvent = {
    kind: SIGNET_KINDS.IDENTITY_BRIDGE,
    pubkey: anonPubkey,
    created_at: timestamp,
    tags: [
      ['d', 'identity-bridge'],
      ['ring-min-tier', String(ringMinTier)],
      ['ring-size', String(ring.length)],
      ['L', SIGNET_LABEL],
      ['l', 'identity-bridge', SIGNET_LABEL],
    ],
    content,
  };

  return signEvent(unsigned, anonPrivateKey);
}

/**
 * Verify an identity bridge event.
 * Checks: Nostr signature, ring signature validity, ring size >= minimum.
 */
export async function verifyIdentityBridge(event: NostrEvent): Promise<boolean> {
  // Check kind
  if (event.kind !== SIGNET_KINDS.IDENTITY_BRIDGE) return false;

  // Verify Nostr event signature
  const validEvent = await verifyEvent(event);
  if (!validEvent) return false;

  // Parse content
  let parsed: { ringSig: RingSignature; timestamp: number };
  try {
    parsed = JSON.parse(event.content);
  } catch {
    return false;
  }

  // Verify ring size
  const ringSize = parseInt(getTagValue(event, 'ring-size') || '0', 10);
  if (ringSize < MIN_BRIDGE_RING_SIZE) return false;
  if (parsed.ringSig.ring.length !== ringSize) return false;

  // Verify binding message format
  const expectedMessage = `signet:identity-bridge:${event.pubkey}:${parsed.timestamp}`;
  if (parsed.ringSig.message !== expectedMessage) return false;

  // Verify ring signature
  return ringVerify(parsed.ringSig);
}

/**
 * Parse an identity bridge event into a structured form.
 */
export function parseIdentityBridge(event: NostrEvent): ParsedIdentityBridge | null {
  if (event.kind !== SIGNET_KINDS.IDENTITY_BRIDGE) return null;

  try {
    const parsed = JSON.parse(event.content);
    const ringMinTier = parseInt(getTagValue(event, 'ring-min-tier') || '1', 10) as SignetTier;
    const ringSize = parseInt(getTagValue(event, 'ring-size') || '0', 10);

    return {
      anonPubkey: event.pubkey,
      ringMinTier,
      ringSize,
      ring: parsed.ringSig.ring,
      timestamp: parsed.timestamp,
    };
  } catch {
    return null;
  }
}
