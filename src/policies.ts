// Kind 30472 — Community Verification Policy
// Create policies and check compliance

import { APP_DATA_KIND, DEFAULT_CRYPTO_ALGORITHM } from './constants.js';
import { signEvent, getPublicKey } from './crypto.js';
import { getTagValue } from './validation.js';
import { SignetValidationError } from './errors.js';
import type {
  NostrEvent,
  UnsignedEvent,
  PolicyParams,
  PolicyCheckResult,
  ParsedPolicy,
  SignetTier,
  EnforcementLevel,
  CryptoAlgorithm,
} from './types.js';

/** Build an unsigned policy event */
export function buildPolicyEvent(
  operatorPubkey: string,
  params: PolicyParams
): UnsignedEvent {
  const tags: string[][] = [
    ['d', `signet:policy:${params.communityId}`],
    ['adult-min-tier', String(params.adultMinTier)],
    ['child-min-tier', String(params.childMinTier)],
    ['enforcement', params.enforcement],
    ['algo', DEFAULT_CRYPTO_ALGORITHM],
  ];

  if (params.minScore !== undefined) tags.push(['min-score', String(params.minScore)]);
  if (params.modMinTier !== undefined) tags.push(['mod-min-tier', String(params.modMinTier)]);
  if (params.verifierBond !== undefined) tags.push(['verifier-bond', String(params.verifierBond)]);
  if (params.revocationThreshold !== undefined) tags.push(['revocation-threshold', String(params.revocationThreshold)]);

  return {
    kind: APP_DATA_KIND,
    pubkey: operatorPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: params.description || '',
  };
}

/** Create and sign a community policy */
export async function createPolicy(
  operatorPrivateKey: string,
  params: PolicyParams
): Promise<NostrEvent> {
  const pubkey = getPublicKey(operatorPrivateKey);
  const event = buildPolicyEvent(pubkey, params);
  return signEvent(event, operatorPrivateKey);
}

/** Parse a policy event into a structured object */
export function parsePolicy(event: NostrEvent): ParsedPolicy | null {
  if (event.kind !== APP_DATA_KIND) return null;
  // NIP-78 policy events are identified by the signet:policy: d-tag prefix
  const dTag = getTagValue(event, 'd') || '';
  if (!dTag.startsWith('signet:policy:')) return null;

  const adultTier = getTagValue(event, 'adult-min-tier');
  const childTier = getTagValue(event, 'child-min-tier');

  const algorithm = (getTagValue(event, 'algo') || DEFAULT_CRYPTO_ALGORITHM) as CryptoAlgorithm;

  // Strip 'signet:policy:' prefix from d-tag to get community ID
  const communityId = dTag.slice('signet:policy:'.length);

  return {
    communityId,
    adultMinTier: (() => { const t = adultTier ? parseInt(adultTier, 10) : 1; return (t >= 1 && t <= 4 ? t : 1) as SignetTier; })(),
    childMinTier: (() => { const t = childTier ? parseInt(childTier, 10) : 1; return (t >= 1 && t <= 4 ? t : 1) as SignetTier; })(),
    enforcement: (getTagValue(event, 'enforcement') || 'client') as EnforcementLevel,
    minScore: (() => { const s = getTagValue(event, 'min-score'); if (!s) return undefined; const v = parseInt(s, 10); return isNaN(v) ? undefined : Math.max(0, Math.min(v, 200)); })(),
    modMinTier: (() => { const s = getTagValue(event, 'mod-min-tier'); if (!s) return undefined; const t = parseInt(s, 10); if (isNaN(t) || t < 1 || t > 4) return undefined; return t as SignetTier; })(),
    verifierBond: (() => { const s = getTagValue(event, 'verifier-bond'); if (!s) return undefined; const v = parseInt(s, 10); return isNaN(v) || v < 0 ? undefined : v; })(),
    revocationThreshold: (() => { const s = getTagValue(event, 'revocation-threshold'); if (!s) return undefined; const v = parseInt(s, 10); return isNaN(v) || v < 1 ? undefined : v; })(),
    algorithm,
  };
}

/** Check if a user meets a policy's requirements */
export function checkPolicyCompliance(
  policy: ParsedPolicy,
  userTier: SignetTier,
  userScore: number,
  opts: {
    isChild?: boolean;
    isModerator?: boolean;
  } = {}
): PolicyCheckResult {
  const requiredTier = opts.isChild
    ? policy.childMinTier
    : opts.isModerator && policy.modMinTier
      ? policy.modMinTier
      : policy.adultMinTier;

  if (userTier < requiredTier) {
    return {
      allowed: false,
      reason: `Tier ${userTier} does not meet minimum tier ${requiredTier}`,
      requiredTier,
      actualTier: userTier,
    };
  }

  if (policy.minScore !== undefined && userScore < policy.minScore) {
    return {
      allowed: false,
      reason: `Score ${userScore} does not meet minimum score ${policy.minScore}`,
      requiredTier,
      actualTier: userTier,
      requiredScore: policy.minScore,
      actualScore: userScore,
    };
  }

  return {
    allowed: true,
    requiredTier,
    actualTier: userTier,
    requiredScore: policy.minScore,
    actualScore: userScore,
  };
}

/** Policy checker that holds a policy and checks multiple users */
export class PolicyChecker {
  private policy: ParsedPolicy;

  constructor(policyEvent: NostrEvent) {
    const parsed = parsePolicy(policyEvent);
    if (!parsed) throw new SignetValidationError('Invalid policy event');
    this.policy = parsed;
  }

  getPolicy(): ParsedPolicy {
    return this.policy;
  }

  checkAdult(tier: SignetTier, score: number): PolicyCheckResult {
    return checkPolicyCompliance(this.policy, tier, score, { isChild: false });
  }

  checkChild(tier: SignetTier, score: number): PolicyCheckResult {
    return checkPolicyCompliance(this.policy, tier, score, { isChild: true });
  }

  checkModerator(tier: SignetTier, score: number): PolicyCheckResult {
    return checkPolicyCompliance(this.policy, tier, score, { isModerator: true });
  }
}
