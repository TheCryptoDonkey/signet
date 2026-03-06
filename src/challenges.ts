// Kind 30474 — Verifier Challenge
// Kind 30475 — Verifier Revocation

import { SIGNET_KINDS, SIGNET_LABEL, DEFAULT_REVOCATION_THRESHOLD } from './constants.js';
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
} from './types.js';

// --- Kind 30474: Challenge ---

/** Build an unsigned challenge event */
export function buildChallengeEvent(
  reporterPubkey: string,
  params: ChallengeParams
): UnsignedEvent {
  return {
    kind: SIGNET_KINDS.CHALLENGE,
    pubkey: reporterPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['d', params.verifierPubkey],
      ['p', params.verifierPubkey],
      ['reason', params.reason],
      ['evidence-type', params.evidenceType],
      ['reporter-tier', String(params.reporterTier)],
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
  if (event.kind !== SIGNET_KINDS.CHALLENGE) return null;

  return {
    verifierPubkey: getTagValue(event, 'd') || '',
    reason: (getTagValue(event, 'reason') || 'other') as ChallengeReason,
    evidenceType: getTagValue(event, 'evidence-type') || '',
    reporterTier: (parseInt(getTagValue(event, 'reporter-tier') || '1')) as SignetTier,
  };
}

// --- Kind 30475: Revocation ---

/** Build an unsigned revocation event */
export function buildRevocationEvent(
  authorityPubkey: string,
  params: RevocationParams
): UnsignedEvent {
  return {
    kind: SIGNET_KINDS.REVOCATION,
    pubkey: authorityPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['d', params.verifierPubkey],
      ['p', params.verifierPubkey],
      ['challenge', params.challengeEventId],
      ['confirmations', String(params.confirmations)],
      ['bond-action', params.bondAction],
      ['scope', params.scope],
      ['effective', String(params.effectiveAt)],
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
  if (event.kind !== SIGNET_KINDS.REVOCATION) return null;

  return {
    verifierPubkey: getTagValue(event, 'd') || '',
    challengeEventId: getTagValue(event, 'challenge') || '',
    confirmations: parseInt(getTagValue(event, 'confirmations') || '0'),
    bondAction: (getTagValue(event, 'bond-action') || 'held') as BondAction,
    scope: (getTagValue(event, 'scope') || 'full') as RevocationScope,
    effectiveAt: parseInt(getTagValue(event, 'effective') || '0'),
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
    if (cred.kind !== SIGNET_KINDS.CREDENTIAL) continue;
    const tier = getTagValue(cred, 'tier');
    if (tier && parseInt(tier, 10) >= 3) {
      const subject = getTagValue(cred, 'd');
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
