// Vouch Attestation (kind 30999, type: vouch)
// Create and manage peer vouches

import { ATTESTATION_KIND, ATTESTATION_TYPES, SIGNET_LABEL, DEFAULT_VOUCH_THRESHOLD, DEFAULT_VOUCHER_MIN_TIER, DEFAULT_CRYPTO_ALGORITHM } from './constants.js';
import { signEvent, getPublicKey } from './crypto.js';
import { getTagValue } from './validation.js';
import type {
  NostrEvent,
  UnsignedEvent,
  VouchParams,
  ParsedVouch,
  VouchMethod,
  SignetTier,
  CryptoAlgorithm,
} from './types.js';

/** Build an unsigned vouch event */
export function buildVouchEvent(
  voucherPubkey: string,
  params: VouchParams
): UnsignedEvent {
  const tags: string[][] = [
    ['d', `vouch:${params.subjectPubkey}`],
    ['p', params.subjectPubkey],
    ['type', ATTESTATION_TYPES.VOUCH],
    ['method', params.method],
    ['voucher-tier', String(params.voucherTier)],
    ['voucher-score', String(params.voucherScore)],
    ['summary', `${params.method} vouch for ${params.subjectPubkey.slice(0, 8)}...`],
    ['algo', DEFAULT_CRYPTO_ALGORITHM],
    ['L', SIGNET_LABEL],
    ['l', 'vouch', SIGNET_LABEL],
  ];

  if (params.context) tags.push(['context', params.context]);

  return {
    kind: ATTESTATION_KIND,
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
  if (event.kind !== ATTESTATION_KIND) return null;
  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.VOUCH) return null;

  const tier = getTagValue(event, 'voucher-tier');
  const score = getTagValue(event, 'voucher-score');

  const algorithm = (getTagValue(event, 'algo') || DEFAULT_CRYPTO_ALGORITHM) as CryptoAlgorithm;

  // Strip 'vouch:' prefix from d-tag to get subject pubkey
  const dTag = getTagValue(event, 'd') || '';
  const subjectPubkey = dTag.startsWith('vouch:') ? dTag.slice('vouch:'.length) : dTag;

  return {
    subjectPubkey,
    method: (getTagValue(event, 'method') || 'online') as VouchMethod,
    context: getTagValue(event, 'context'),
    voucherTier: (() => { const t = tier ? parseInt(tier, 10) : NaN; return (!isNaN(t) && t >= 1 && t <= 4 ? t : 1) as SignetTier; })(),
    voucherScore: (() => { const v = score ? parseInt(score, 10) : 50; return isNaN(v) ? 50 : Math.max(0, Math.min(v, 200)); })(),
    algorithm,
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
    if (vouch.kind !== ATTESTATION_KIND) continue;
    if (getTagValue(vouch, 'type') !== ATTESTATION_TYPES.VOUCH) continue;

    const dTag = getTagValue(vouch, 'd') || '';
    const subject = dTag.startsWith('vouch:') ? dTag.slice('vouch:'.length) : dTag;
    if (subject !== subjectPubkey) continue;

    const tier = getTagValue(vouch, 'voucher-tier');
    const tierNum = tier ? parseInt(tier, 10) : 0;
    if (isNaN(tierNum) || tierNum < minVoucherTier) continue;

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
    if (vouch.kind !== ATTESTATION_KIND) continue;
    if (getTagValue(vouch, 'type') !== ATTESTATION_TYPES.VOUCH) continue;
    const dTag = getTagValue(vouch, 'd') || '';
    const subject = dTag.startsWith('vouch:') ? dTag.slice('vouch:'.length) : dTag;
    if (subject === subjectPubkey) {
      vouchers.add(vouch.pubkey);
    }
  }

  return Array.from(vouchers);
}
