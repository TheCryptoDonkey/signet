// Kind 30474 — Verifier Challenge
// Kind 30475 — Verifier Revocation

import { ATTESTATION_KIND, ATTESTATION_TYPES, SIGNET_LABEL, DEFAULT_REVOCATION_THRESHOLD, DEFAULT_CRYPTO_ALGORITHM } from './constants.js';
import { signEvent, getPublicKey } from './crypto.js';
import { getTagValue } from './validation.js';
import type {
  NostrEvent,
  UnsignedEvent,
  ChallengeParams,
  RevocationParams,
  ParsedChallenge,
  ParsedRevocation,
  ChallengeReason,
  BondAction,
  RevocationScope,
  SignetTier,
  CryptoAlgorithm,
} from './types.js';

// --- Kind 30474: Challenge ---

/** Build an unsigned challenge event */
export function buildChallengeEvent(
  reporterPubkey: string,
  params: ChallengeParams
): UnsignedEvent {
  return {
    kind: ATTESTATION_KIND,
    pubkey: reporterPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['d', `challenge:${params.verifierPubkey}`],
      ['p', params.verifierPubkey],
      ['type', ATTESTATION_TYPES.CHALLENGE],
      ['reason', params.reason],
      ['evidence-type', params.evidenceType],
      ['reporter-tier', String(params.reporterTier)],
      ['summary', `Challenge against verifier ${params.verifierPubkey.slice(0, 8)}... (${params.reason})`],
      ['algo', DEFAULT_CRYPTO_ALGORITHM],
      ['L', SIGNET_LABEL],
      ['l', 'challenge', SIGNET_LABEL],
    ],
    content: params.evidence,
  };
}

/** Create and sign a verifier challenge */
export async function createChallenge(
  reporterPrivateKey: string,
  params: ChallengeParams
): Promise<NostrEvent> {
  const pubkey = getPublicKey(reporterPrivateKey);
  const event = buildChallengeEvent(pubkey, params);
  return signEvent(event, reporterPrivateKey);
}

/** Parse a challenge event */
export function parseChallenge(event: NostrEvent): ParsedChallenge | null {
  if (event.kind !== ATTESTATION_KIND) return null;
  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.CHALLENGE) return null;

  const algorithm = (getTagValue(event, 'algo') || DEFAULT_CRYPTO_ALGORITHM) as CryptoAlgorithm;

  // Strip 'challenge:' prefix from d-tag to get verifier pubkey
  const dTag = getTagValue(event, 'd') || '';
  const verifierPubkey = dTag.startsWith('challenge:') ? dTag.slice('challenge:'.length) : dTag;

  return {
    verifierPubkey,
    reason: (getTagValue(event, 'reason') || 'other') as ChallengeReason,
    evidenceType: getTagValue(event, 'evidence-type') || '',
    reporterTier: (() => { const t = parseInt(getTagValue(event, 'reporter-tier') || '1', 10); return (t >= 1 && t <= 4 ? t : 1) as SignetTier; })(),
    algorithm,
  };
}

// --- Kind 30475: Revocation ---

/** Build an unsigned revocation event */
export function buildRevocationEvent(
  authorityPubkey: string,
  params: RevocationParams
): UnsignedEvent {
  return {
    kind: ATTESTATION_KIND,
    pubkey: authorityPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['d', `revocation:${params.verifierPubkey}`],
      ['p', params.verifierPubkey],
      ['type', ATTESTATION_TYPES.REVOCATION],
      ['challenge', params.challengeEventId],
      ['confirmations', String(params.confirmations)],
      ['bond-action', params.bondAction],
      ['scope', params.scope],
      ['effective', String(params.effectiveAt)],
      ['summary', `Revocation of verifier ${params.verifierPubkey.slice(0, 8)}...`],
      ['algo', DEFAULT_CRYPTO_ALGORITHM],
      ['L', SIGNET_LABEL],
      ['l', 'revocation', SIGNET_LABEL],
    ],
    content: params.summary,
  };
}

/** Create and sign a verifier revocation */
export async function createRevocation(
  authorityPrivateKey: string,
  params: RevocationParams
): Promise<NostrEvent> {
  const pubkey = getPublicKey(authorityPrivateKey);
  const event = buildRevocationEvent(pubkey, params);
  return signEvent(event, authorityPrivateKey);
}

/** Parse a revocation event */
export function parseRevocation(event: NostrEvent): ParsedRevocation | null {
  if (event.kind !== ATTESTATION_KIND) return null;
  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.REVOCATION) return null;

  const algorithm = (getTagValue(event, 'algo') || DEFAULT_CRYPTO_ALGORITHM) as CryptoAlgorithm;

  // Strip 'revocation:' prefix from d-tag to get verifier pubkey
  const dTag = getTagValue(event, 'd') || '';
  const verifierPubkey = dTag.startsWith('revocation:') ? dTag.slice('revocation:'.length) : dTag;

  return {
    verifierPubkey,
    challengeEventId: getTagValue(event, 'challenge') || '',
    confirmations: (() => { const c = parseInt(getTagValue(event, 'confirmations') || '0', 10); return isNaN(c) || c < 0 ? 0 : c; })(),
    bondAction: (getTagValue(event, 'bond-action') || 'held') as BondAction,
    scope: (getTagValue(event, 'scope') || 'full') as RevocationScope,
    effectiveAt: (() => { const e = parseInt(getTagValue(event, 'effective') || '0', 10); return isNaN(e) ? 0 : e; })(),
    algorithm,
  };
}

/** Count Tier 3+ confirmations for a challenge */
export function countChallengeConfirmations(
  challengeEventId: string,
  confirmationEvents: NostrEvent[],
  credentialEvents: NostrEvent[]
): number {
  // Build a set of Tier 3+ pubkeys
  const tier3Plus = new Set<string>();
  for (const cred of credentialEvents) {
    if (cred.kind !== ATTESTATION_KIND) continue;
    if (getTagValue(cred, 'type') !== ATTESTATION_TYPES.CREDENTIAL) continue;
    const tier = getTagValue(cred, 'tier');
    const tierNum = tier ? parseInt(tier, 10) : NaN;
    if (!isNaN(tierNum) && tierNum >= 3) {
      const dTag = getTagValue(cred, 'd') || '';
      const subject = dTag.startsWith('credential:') ? dTag.slice('credential:'.length) : dTag;
      if (subject) tier3Plus.add(subject);
    }
  }

  // Count unique Tier 3+ confirmations
  const confirmedBy = new Set<string>();
  for (const conf of confirmationEvents) {
    // Confirmation events reference the challenge
    const refChallenge = getTagValue(conf, 'challenge');
    if (refChallenge !== challengeEventId) continue;

    if (tier3Plus.has(conf.pubkey) && !confirmedBy.has(conf.pubkey)) {
      confirmedBy.add(conf.pubkey);
    }
  }

  return confirmedBy.size;
}

/** Check if a challenge has reached the revocation threshold */
export function hasReachedRevocationThreshold(
  confirmations: number,
  threshold: number = DEFAULT_REVOCATION_THRESHOLD
): boolean {
  return confirmations >= threshold;
}
