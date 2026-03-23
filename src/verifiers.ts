// Verifier Credential (kind 31000, type: verifier)
// Professional verifier registration and cross-verification

import { createAttestation, parseAttestation } from 'nostr-attestations';
import { ATTESTATION_KIND, ATTESTATION_TYPES, SIGNET_LABEL, VERIFIER_ACTIVATION, DEFAULT_CRYPTO_ALGORITHM } from './constants.js';
import { signEvent, getPublicKey } from './crypto.js';
import { getTagValue } from './validation.js';
import type {
  NostrEvent,
  UnsignedEvent,
  VerifierParams,
  ParsedVerifier,
  CryptoAlgorithm,
} from './types.js';

/** Build an unsigned verifier credential event */
export function buildVerifierEvent(
  verifierPubkey: string,
  params: VerifierParams
): UnsignedEvent {
  const signetTags: string[][] = [
    ['profession', params.profession],
    ['jurisdiction', params.jurisdiction],
    ['licence', params.licenceHash],
    ['body', params.professionalBody],
    ['algo', DEFAULT_CRYPTO_ALGORITHM],
    ['L', SIGNET_LABEL],
    ['l', 'verifier', SIGNET_LABEL],
  ];

  const template = createAttestation({
    type: ATTESTATION_TYPES.VERIFIER,
    summary: `${params.profession} verifier in ${params.jurisdiction}`,
    tags: signetTags,
    content: params.statement || '',
  });

  return {
    ...template,
    pubkey: verifierPubkey,
    created_at: Math.floor(Date.now() / 1000),
  };
}

/** Create and sign a verifier credential */
export async function createVerifierCredential(
  privateKey: string,
  params: VerifierParams
): Promise<NostrEvent> {
  const pubkey = getPublicKey(privateKey);
  const event = buildVerifierEvent(pubkey, params);
  return signEvent(event, privateKey);
}

/** Parse a verifier credential event */
export function parseVerifier(event: NostrEvent): ParsedVerifier | null {
  const base = parseAttestation(event);
  if (!base) return null;
  if (base.type !== ATTESTATION_TYPES.VERIFIER) return null;

  const algorithm = (getTagValue(event, 'algo') || DEFAULT_CRYPTO_ALGORITHM) as CryptoAlgorithm;

  return {
    profession: getTagValue(event, 'profession') || '',
    jurisdiction: getTagValue(event, 'jurisdiction') || '',
    licenceHash: getTagValue(event, 'licence') || '',
    professionalBody: getTagValue(event, 'body') || '',
    algorithm,
  };
}

/** Check if a verifier has sufficient cross-verification.
 *  Requires vouches from verified professionals in different fields. */
export function checkCrossVerification(
  verifierPubkey: string,
  vouches: NostrEvent[],
  verifierCredentials: NostrEvent[]
): {
  activated: boolean;
  vouchCount: number;
  professions: string[];
  errors: string[];
} {
  const errors: string[] = [];
  const professionsSet = new Set<string>();
  const vouchersSeen = new Set<string>();
  let vouchCount = 0;

  // Build a map of verifier pubkey -> profession
  const verifierProfessions = new Map<string, string>();
  for (const cred of verifierCredentials) {
    if (cred.kind !== ATTESTATION_KIND) continue;
    if (getTagValue(cred, 'type') !== ATTESTATION_TYPES.VERIFIER) continue;
    const profession = getTagValue(cred, 'profession');
    if (profession) {
      verifierProfessions.set(cred.pubkey, profession);
    }
  }

  // Count qualifying vouches (from other verified professionals)
  for (const vouch of vouches) {
    if (vouch.kind !== ATTESTATION_KIND) continue;
    if (getTagValue(vouch, 'type') !== ATTESTATION_TYPES.VOUCH) continue;

    const dTag = getTagValue(vouch, 'd') || '';
    const subject = dTag.startsWith('vouch:') ? dTag.slice('vouch:'.length) : dTag;
    if (subject !== verifierPubkey) continue;

    // Voucher must themselves be a verified professional
    const voucherProfession = verifierProfessions.get(vouch.pubkey);
    if (!voucherProfession) continue;

    // One vouch per voucher
    if (vouchersSeen.has(vouch.pubkey)) continue;
    vouchersSeen.add(vouch.pubkey);

    professionsSet.add(voucherProfession);
    vouchCount++;
  }

  const professions = Array.from(professionsSet);
  const activated =
    vouchCount >= VERIFIER_ACTIVATION.MIN_VOUCHES &&
    professions.length >= VERIFIER_ACTIVATION.MIN_PROFESSIONS;

  if (vouchCount < VERIFIER_ACTIVATION.MIN_VOUCHES) {
    errors.push(
      `Need ${VERIFIER_ACTIVATION.MIN_VOUCHES} vouches from verified professionals, have ${vouchCount}`
    );
  }
  if (professions.length < VERIFIER_ACTIVATION.MIN_PROFESSIONS) {
    errors.push(
      `Need vouches from ${VERIFIER_ACTIVATION.MIN_PROFESSIONS} different professions, have ${professions.length}`
    );
  }

  return { activated, vouchCount, professions, errors };
}

/** Check if a verifier credential has been revoked */
export function isVerifierRevoked(
  verifierPubkey: string,
  revocations: NostrEvent[]
): boolean {
  return revocations.some((rev) => {
    if (rev.kind !== ATTESTATION_KIND) return false;
    if (getTagValue(rev, 'type') !== ATTESTATION_TYPES.REVOCATION) return false;
    const dTag = getTagValue(rev, 'd') || '';
    const target = dTag.startsWith('revocation:') ? dTag.slice('revocation:'.length) : dTag;
    return target === verifierPubkey;
  });
}
