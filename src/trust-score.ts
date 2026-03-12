// Signet IQ Computation
// Continuous 0-200 Signet IQ score from weighted signals

import { TRUST_WEIGHTS, MAX_TRUST_SCORE, SIGNET_KINDS } from './constants.js';
import { getTagValue } from './validation.js';
import type {
  NostrEvent,
  TrustSignal,
  TrustScoreBreakdown,
  SignetTier,
} from './types.js';

/** Compute Signet IQ for a subject from their credentials, vouches, and bridges */
export function computeTrustScore(
  subjectPubkey: string,
  credentials: NostrEvent[],
  vouches: NostrEvent[],
  accountCreatedAt?: number,
  bridges?: NostrEvent[]
): TrustScoreBreakdown {
  const signals: TrustSignal[] = [];
  let rawScore = 0;
  let highestTier: SignetTier = 1;
  let professionalVerifications = 0;
  let inPersonVouches = 0;
  let onlineVouches = 0;

  // Process credentials (kind 30470)
  for (const cred of credentials) {
    if (cred.kind !== SIGNET_KINDS.CREDENTIAL) continue;
    const subject = getTagValue(cred, 'd');
    if (subject !== subjectPubkey) continue;

    const rawTier = parseInt(getTagValue(cred, 'tier') || '1', 10);
    const tier = (rawTier >= 1 && rawTier <= 4 ? rawTier : 1) as SignetTier;
    if (tier > highestTier) highestTier = tier;

    const type = getTagValue(cred, 'type');
    if (type === 'professional') {
      professionalVerifications++;
      const weight = TRUST_WEIGHTS.PROFESSIONAL_VERIFICATION;
      rawScore += weight;
      signals.push({
        type: 'professional-verification',
        weight,
        source: cred.pubkey,
      });
    }
  }

  // Process vouches (kind 30471)
  const vouchersSeen = new Set<string>();
  for (const vouch of vouches) {
    if (vouch.kind !== SIGNET_KINDS.VOUCH) continue;
    const subject = getTagValue(vouch, 'd');
    if (subject !== subjectPubkey) continue;

    // One vouch per voucher
    if (vouchersSeen.has(vouch.pubkey)) continue;
    vouchersSeen.add(vouch.pubkey);

    const method = getTagValue(vouch, 'method');
    const rawVoucherScore = parseInt(getTagValue(vouch, 'voucher-score') || '50', 10);
    const voucherScore = isNaN(rawVoucherScore) ? 50 : Math.max(0, Math.min(rawVoucherScore, MAX_TRUST_SCORE));
    const scoreMultiplier = voucherScore / MAX_TRUST_SCORE;

    if (method === 'in-person') {
      inPersonVouches++;
      const weight = TRUST_WEIGHTS.IN_PERSON_VOUCH * scoreMultiplier;
      rawScore += weight;
      signals.push({
        type: 'in-person-vouch',
        weight,
        source: vouch.pubkey,
        score: voucherScore,
      });
    } else {
      onlineVouches++;
      const weight = TRUST_WEIGHTS.ONLINE_VOUCH * scoreMultiplier;
      rawScore += weight;
      signals.push({
        type: 'online-vouch',
        weight,
        source: vouch.pubkey,
        score: voucherScore,
      });
    }
  }

  // Process identity bridges (kind 30476)
  if (bridges) {
    for (const bridge of bridges) {
      if (bridge.kind !== SIGNET_KINDS.IDENTITY_BRIDGE) continue;
      if (bridge.pubkey !== subjectPubkey) continue;

      const rawRingMinTier = parseInt(getTagValue(bridge, 'ring-min-tier') || '1', 10);
      const ringMinTier = (rawRingMinTier >= 1 && rawRingMinTier <= 4 ? rawRingMinTier : 1) as SignetTier;
      const weight = TRUST_WEIGHTS.IDENTITY_BRIDGE * (ringMinTier / 4);
      rawScore += weight;
      signals.push({
        type: 'identity-bridge',
        weight,
        source: bridge.pubkey,
      });
      // Only count one bridge per account
      break;
    }
  }

  // Account age
  let accountAgeDays = 0;
  if (accountCreatedAt) {
    const now = Math.floor(Date.now() / 1000);
    accountAgeDays = Math.floor((now - accountCreatedAt) / (24 * 60 * 60));
    const years = accountAgeDays / 365;
    const ageWeight = Math.min(
      years * TRUST_WEIGHTS.ACCOUNT_AGE_PER_YEAR,
      TRUST_WEIGHTS.ACCOUNT_AGE_MAX
    );
    rawScore += ageWeight;
    signals.push({
      type: 'account-age',
      weight: ageWeight,
    });
  }

  // Cap at MAX_TRUST_SCORE
  const score = Math.min(Math.round(rawScore), MAX_TRUST_SCORE);

  return {
    score,
    tier: highestTier,
    professionalVerifications,
    inPersonVouches,
    onlineVouches,
    accountAgeDays,
    signals,
  };
}

/** Get a human-readable Signet IQ display */
export function formatTrustDisplay(breakdown: TrustScoreBreakdown): string {
  const checkmarks = breakdown.tier >= 2 ? '✓'.repeat(breakdown.tier - 1) : '';
  const tierLabel = ['', 'Self-declared', 'Web-of-trust', 'Verified', 'Verified (Child Safety)'][breakdown.tier];

  const lines = [
    `${checkmarks} Tier ${breakdown.tier} (${tierLabel})`,
    `Signet IQ: ${breakdown.score}`,
  ];

  if (breakdown.professionalVerifications > 0) {
    lines.push(`  Prof verified: ${breakdown.professionalVerifications}`);
  }
  if (breakdown.inPersonVouches > 0) {
    lines.push(`  In-person vouches: ${breakdown.inPersonVouches}`);
  }
  if (breakdown.onlineVouches > 0) {
    lines.push(`  Online vouches: ${breakdown.onlineVouches}`);
  }
  if (breakdown.accountAgeDays > 0) {
    const years = (breakdown.accountAgeDays / 365).toFixed(1);
    lines.push(`  Account age: ${years} years`);
  }

  return lines.join('\n');
}

/** Verify the signal ordering invariant:
 *  professional verification > identity bridge > in-person vouch > online vouch > account age */
export function verifySignalOrdering(signals: TrustSignal[]): boolean {
  const maxWeight = (type: TrustSignal['type']): number => {
    const weights = signals.filter((s) => s.type === type).map((s) => s.weight);
    return weights.length > 0 ? Math.max(...weights) : 0;
  };

  const profMax = maxWeight('professional-verification');
  const bridgeMax = maxWeight('identity-bridge');
  const inPersonMax = maxWeight('in-person-vouch');

  // Professional verification must exceed identity bridge
  if (profMax > 0 && bridgeMax > 0 && profMax <= bridgeMax) return false;

  // Identity bridge must exceed in-person vouch
  if (bridgeMax > 0 && inPersonMax > 0 && bridgeMax <= inPersonMax) return false;

  // Professional verification must exceed in-person vouch
  if (profMax > 0 && inPersonMax > 0 && profMax <= inPersonMax) return false;

  return true;
}
