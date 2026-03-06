// Kind 30472 — Community Verification Policy
// Create policies and check compliance

import { SIGNET_KINDS, SIGNET_LABEL } from './constants.js';
import { signEvent, getPublicKey } from './crypto.js';
import { getTagValue } from './validation.js';
import type {
  NostrEvent,
  UnsignedEvent,
  PolicyParams,
  PolicyCheckResult,
  ParsedPolicy,
  SignetTier,
  EnforcementLevel,
} from './types.js';

/** Build an unsigned policy event */
export function buildPolicyEvent(
  operatorPubkey: string,
  params: PolicyParams
): UnsignedEvent {
  const tags: string[][] = [
    ['d', params.communityId],
    ['adult-min-tier', String(params.adultMinTier)],
    ['child-min-tier', String(params.childMinTier)],
    ['enforcement', params.enforcement],
    ['L', SIGNET_LABEL],
    ['l', 'policy', SIGNET_LABEL],
  ];

  if (params.minScore !== undefined) tags.push(['min-score', String(params.minScore)]);
  if (params.modMinTier !== undefined) tags.push(['mod-min-tier', String(params.modMinTier)]);
  if (params.verifierBond !== undefined) tags.push(['verifier-bond', String(params.verifierBond)]);
  if (params.revocationThreshold !== undefined) tags.push(['revocation-threshold', String(params.revocationThreshold)]);

  return {
    kind: SIGNET_KINDS.POLICY,
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
  if (event.kind !== SIGNET_KINDS.POLICY) return null;

  const adultTier = getTagValue(event, 'adult-min-tier');
  const childTier = getTagValue(event, 'child-min-tier');

  return {
    communityId: getTagValue(event, 'd') || '',
    adultMinTier: (adultTier ? parseInt(adultTier, 10) : 1) as SignetTier,
    childMinTier: (childTier ? parseInt(childTier, 10) : 1) as SignetTier,
    enforcement: (getTagValue(event, 'enforcement') || 'client') as EnforcementLevel,
    minScore: getTagValue(event, 'min-score') ? parseInt(getTagValue(event, 'min-score')!, 10) : undefined,
    modMinTier: getTagValue(event, 'mod-min-tier') ? parseInt(getTagValue(event, 'mod-min-tier')!, 10) as SignetTier : undefined,
    verifierBond: getTagValue(event, 'verifier-bond') ? parseInt(getTagValue(event, 'verifier-bond')!, 10) : undefined,
    revocationThreshold: getTagValue(event, 'revocation-threshold') ? parseInt(getTagValue(event, 'revocation-threshold')!, 10) : undefined,
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
    if (!parsed) throw new Error('Invalid policy event');
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
