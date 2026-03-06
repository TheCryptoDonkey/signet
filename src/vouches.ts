// Kind 30471 — Vouch Attestation
// Create and manage peer vouches

import { SIGNET_KINDS, SIGNET_LABEL, DEFAULT_VOUCH_THRESHOLD, DEFAULT_VOUCHER_MIN_TIER } from './constants.js';
import { signEvent, getPublicKey } from './crypto.js';
import { getTagValue } from './validation.js';
import type {
  NostrEvent,
  UnsignedEvent,
  VouchParams,
  ParsedVouch,
  VouchMethod,
  SignetTier,
} from './types.js';

/** Build an unsigned vouch event */
export function buildVouchEvent(
  voucherPubkey: string,
  params: VouchParams
): UnsignedEvent {
  const tags: string[][] = [
    ['d', params.subjectPubkey],
    ['p', params.subjectPubkey],
    ['method', params.method],
    ['voucher-tier', String(params.voucherTier)],
    ['voucher-score', String(params.voucherScore)],
    ['L', SIGNET_LABEL],
    ['l', 'vouch', SIGNET_LABEL],
  ];

  if (params.context) tags.push(['context', params.context]);

  return {
    kind: SIGNET_KINDS.VOUCH,
    pubkey: voucherPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: '', // no personal data
  };
}

/** Create and sign a vouch for another user */
export async function createVouch(
  voucherPrivateKey: string,
  params: VouchParams
): Promise<NostrEvent> {
  const pubkey = getPublicKey(voucherPrivateKey);
  const event = buildVouchEvent(pubkey, params);
  return signEvent(event, voucherPrivateKey);
}

/** Parse a vouch event into a structured object */
export function parseVouch(event: NostrEvent): ParsedVouch | null {
  if (event.kind !== SIGNET_KINDS.VOUCH) return null;

  const tier = getTagValue(event, 'voucher-tier');
  const score = getTagValue(event, 'voucher-score');

  return {
    subjectPubkey: getTagValue(event, 'd') || '',
    method: (getTagValue(event, 'method') || 'online') as VouchMethod,
    context: getTagValue(event, 'context'),
    voucherTier: (tier ? parseInt(tier, 10) : 1) as SignetTier,
    voucherScore: score ? parseInt(score, 10) : 50,
  };
}

/** Count qualifying vouches for a subject from a set of vouch events */
export function countQualifyingVouches(
  vouches: NostrEvent[],
  subjectPubkey: string,
  minVoucherTier: SignetTier = DEFAULT_VOUCHER_MIN_TIER as SignetTier
): number {
  const seen = new Set<string>();
  let count = 0;

  for (const vouch of vouches) {
    if (vouch.kind !== SIGNET_KINDS.VOUCH) continue;

    const subject = getTagValue(vouch, 'd');
    if (subject !== subjectPubkey) continue;

    const tier = getTagValue(vouch, 'voucher-tier');
    if (!tier || parseInt(tier, 10) < minVoucherTier) continue;

    // One vouch per voucher
    if (seen.has(vouch.pubkey)) continue;
    seen.add(vouch.pubkey);

    count++;
  }

  return count;
}

/** Check if a subject has enough qualifying vouches for Tier 2 */
export function hasEnoughVouches(
  vouches: NostrEvent[],
  subjectPubkey: string,
  threshold: number = DEFAULT_VOUCH_THRESHOLD,
  minVoucherTier: SignetTier = DEFAULT_VOUCHER_MIN_TIER as SignetTier
): boolean {
  return countQualifyingVouches(vouches, subjectPubkey, minVoucherTier) >= threshold;
}

/** Get unique voucher pubkeys for a subject */
export function getVouchers(
  vouches: NostrEvent[],
  subjectPubkey: string
): string[] {
  const vouchers = new Set<string>();

  for (const vouch of vouches) {
    if (vouch.kind !== SIGNET_KINDS.VOUCH) continue;
    const subject = getTagValue(vouch, 'd');
    if (subject === subjectPubkey) {
      vouchers.add(vouch.pubkey);
    }
  }

  return Array.from(vouchers);
}
