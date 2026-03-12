// Level 1 Badge Display Library
// Minimal drop-in module for Nostr clients to display Signet trust badges.
// Requires only 2 event kinds (30470 credential, 30471 vouch) and Schnorr verification.

import { SIGNET_KINDS, TRUST_WEIGHTS, MAX_TRUST_SCORE } from './constants.js';
import { verifyEvent } from './crypto.js';
import { getTagValue } from './validation.js';
import type { NostrEvent, SignetTier } from './types.js';

// --- Types ---

export interface BadgeInfo {
  /** The pubkey this badge describes */
  pubkey: string;
  /** Highest verification tier (1-4) */
  tier: SignetTier;
  /** Human-readable tier label */
  tierLabel: string;
  /** Signet IQ (0-200) */
  score: number;
  /** Whether the user has any valid credentials */
  isVerified: boolean;
  /** Short display string, e.g. "Verified (Tier 3)" */
  displayLabel: string;
  /** Number of valid credentials */
  credentialCount: number;
  /** Number of valid vouches */
  vouchCount: number;
}

export type TrustLevel = 'unverified' | 'self-declared' | 'vouched' | 'professional' | 'professional-child';

const TIER_LABELS: Record<SignetTier, string> = {
  1: 'Self-declared',
  2: 'Web-of-trust',
  3: 'Verified',
  4: 'Verified (Child Safety)',
};

const TIER_TO_TRUST_LEVEL: Record<SignetTier, TrustLevel> = {
  1: 'self-declared',
  2: 'vouched',
  3: 'professional',
  4: 'professional-child',
};

// --- Core Functions ---

/**
 * Compute badge info for a pubkey from their credentials and vouches.
 * This is the main entry point for Level 1 integration.
 *
 * @param pubkey - The Nostr pubkey to compute a badge for
 * @param events - All relevant kind 30470 and 30471 events
 * @param options - Optional configuration
 * @returns Badge info for display
 */
export async function computeBadge(
  pubkey: string,
  events: NostrEvent[],
  options?: { verifySignatures?: boolean; now?: number }
): Promise<BadgeInfo> {
  const now = options?.now ?? Math.floor(Date.now() / 1000);
  const verify = options?.verifySignatures ?? false;

  let highestTier: SignetTier = 1;
  let rawScore = 0;
  let credentialCount = 0;
  let hasAnyCredential = false;

  // Process credentials (kind 30470)
  for (const event of events) {
    if (event.kind !== SIGNET_KINDS.CREDENTIAL) continue;
    const subject = getTagValue(event, 'd');
    if (subject !== pubkey) continue;

    // Check expiry — NaN must be treated as expired (not perpetually valid)
    const expires = getTagValue(event, 'expires');
    if (expires) {
      const exp = parseInt(expires, 10);
      if (isNaN(exp) || exp < now) continue;
    }

    // Optional signature verification
    if (verify && !await verifyEvent(event)) continue;

    hasAnyCredential = true;
    credentialCount++;

    const rawTier = parseInt(getTagValue(event, 'tier') || '1', 10);
    const tier = (rawTier >= 1 && rawTier <= 4 ? rawTier : 1) as SignetTier;
    if (tier > highestTier) highestTier = tier;

    const type = getTagValue(event, 'type');
    if (type === 'professional') {
      rawScore += TRUST_WEIGHTS.PROFESSIONAL_VERIFICATION;
    }
  }

  // Process vouches (kind 30471)
  const vouchersSeen = new Set<string>();
  let vouchCount = 0;

  for (const event of events) {
    if (event.kind !== SIGNET_KINDS.VOUCH) continue;
    const subject = getTagValue(event, 'd');
    if (subject !== pubkey) continue;

    // One vouch per voucher
    if (vouchersSeen.has(event.pubkey)) continue;
    vouchersSeen.add(event.pubkey);

    if (verify && !await verifyEvent(event)) continue;

    vouchCount++;

    const method = getTagValue(event, 'method');
    const rawVoucherScore = parseInt(getTagValue(event, 'voucher-score') || '50', 10);
    const voucherScore = isNaN(rawVoucherScore) ? 50 : Math.max(0, Math.min(rawVoucherScore, MAX_TRUST_SCORE));
    const multiplier = voucherScore / MAX_TRUST_SCORE;

    if (method === 'in-person') {
      rawScore += TRUST_WEIGHTS.IN_PERSON_VOUCH * multiplier;
    } else {
      rawScore += TRUST_WEIGHTS.ONLINE_VOUCH * multiplier;
    }
  }

  const score = Math.min(Math.round(rawScore), MAX_TRUST_SCORE);
  const tierLabel = TIER_LABELS[highestTier];

  let displayLabel: string;
  if (!hasAnyCredential && vouchCount === 0) {
    displayLabel = 'Unverified';
  } else {
    displayLabel = `${tierLabel} (Tier ${highestTier})`;
  }

  return {
    pubkey,
    tier: highestTier,
    tierLabel,
    score,
    isVerified: hasAnyCredential,
    displayLabel,
    credentialCount,
    vouchCount,
  };
}

/**
 * Get the trust level classification for a badge.
 */
export function getTrustLevel(badge: BadgeInfo): TrustLevel {
  if (!badge.isVerified && badge.vouchCount === 0) return 'unverified';
  return TIER_TO_TRUST_LEVEL[badge.tier];
}

/**
 * Check if a pubkey has at least the required tier.
 * Useful for gating access to features or communities.
 */
export function meetsMinimumTier(badge: BadgeInfo, minTier: SignetTier): boolean {
  return badge.isVerified && badge.tier >= minTier;
}

/**
 * Filter a set of events to only those relevant for a given pubkey.
 * Useful when you have a mixed bag of events from a relay query.
 */
export function filterEventsForPubkey(pubkey: string, events: NostrEvent[]): NostrEvent[] {
  return events.filter(event => {
    if (event.kind !== SIGNET_KINDS.CREDENTIAL && event.kind !== SIGNET_KINDS.VOUCH) {
      return false;
    }
    const subject = getTagValue(event, 'd');
    return subject === pubkey;
  });
}

/**
 * Build a Nostr filter for fetching badge-relevant events for one or more pubkeys.
 * Returns filters suitable for use with REQ messages.
 */
export function buildBadgeFilters(pubkeys: string[]): Array<{ kinds: number[]; '#d': string[] }> {
  return [
    {
      kinds: [SIGNET_KINDS.CREDENTIAL, SIGNET_KINDS.VOUCH],
      '#d': pubkeys,
    },
  ];
}
