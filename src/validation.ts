// Signet Event Validation
// Validates structure and required fields for all 6 event kinds

import { SIGNET_KINDS, SIGNET_LABEL } from './constants.js';
import type { NostrEvent, SignetTier } from './types.js';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

/** Get a tag value by name from a Nostr event */
export function getTagValue(event: NostrEvent | { tags: string[][] }, name: string): string | undefined {
  const tag = event.tags.find((t) => t[0] === name);
  return tag?.[1];
}

/** Get all tag values by name */
export function getTagValues(event: NostrEvent | { tags: string[][] }, name: string): string[] {
  return event.tags.filter((t) => t[0] === name).map((t) => t[1]);
}

/** Check that the event has the signet protocol label */
function hasSignetLabel(event: NostrEvent): boolean {
  return event.tags.some(
    (t) => t[0] === 'L' && t[1] === SIGNET_LABEL
  );
}

/** Validate a kind 30470 Verification Credential */
export function validateCredential(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  if (event.kind !== SIGNET_KINDS.CREDENTIAL) {
    errors.push(`Expected kind ${SIGNET_KINDS.CREDENTIAL}, got ${event.kind}`);
  }

  if (!hasSignetLabel(event)) {
    errors.push('Missing signet protocol label (["L", "signet"])');
  }

  const subject = getTagValue(event, 'd');
  if (!subject) errors.push('Missing "d" tag (subject pubkey)');

  const tier = getTagValue(event, 'tier');
  if (!tier || !['1', '2', '3', '4'].includes(tier)) {
    errors.push('Missing or invalid "tier" tag (must be 1-4)');
  }

  const type = getTagValue(event, 'type');
  if (!type || !['self', 'peer', 'professional'].includes(type)) {
    errors.push('Missing or invalid "type" tag');
  }

  const scope = getTagValue(event, 'scope');
  if (!scope || !['adult', 'adult+child'].includes(scope)) {
    errors.push('Missing or invalid "scope" tag');
  }

  const method = getTagValue(event, 'method');
  if (!method) errors.push('Missing "method" tag');

  // Tier-specific validations
  const tierNum = parseInt(tier || '0', 10) as SignetTier;

  if (tierNum === 1 && type !== 'self') {
    errors.push('Tier 1 must have type "self"');
  }

  if (tierNum === 2 && type !== 'peer') {
    errors.push('Tier 2 must have type "peer"');
  }

  if ((tierNum === 3 || tierNum === 4) && type !== 'professional') {
    errors.push(`Tier ${tierNum} must have type "professional"`);
  }

  if (tierNum === 4) {
    if (scope !== 'adult+child') {
      errors.push('Tier 4 must have scope "adult+child"');
    }
    if (!getTagValue(event, 'age-range')) {
      errors.push('Tier 4 must include "age-range" tag');
    }
  }

  if ((tierNum === 3 || tierNum === 4) && !getTagValue(event, 'profession')) {
    errors.push(`Tier ${tierNum} should include "profession" tag`);
  }

  return { valid: errors.length === 0, errors };
}

/** Validate a kind 30471 Vouch Attestation */
export function validateVouch(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  if (event.kind !== SIGNET_KINDS.VOUCH) {
    errors.push(`Expected kind ${SIGNET_KINDS.VOUCH}, got ${event.kind}`);
  }

  if (!hasSignetLabel(event)) {
    errors.push('Missing signet protocol label');
  }

  const subject = getTagValue(event, 'd');
  if (!subject) errors.push('Missing "d" tag (subject pubkey)');

  const method = getTagValue(event, 'method');
  if (!method || !['in-person', 'online'].includes(method)) {
    errors.push('Missing or invalid "method" tag');
  }

  const voucherTier = getTagValue(event, 'voucher-tier');
  if (!voucherTier || !['1', '2', '3', '4'].includes(voucherTier)) {
    errors.push('Missing or invalid "voucher-tier" tag');
  }

  // Voucher must not vouch for themselves
  if (subject && event.pubkey === subject) {
    errors.push('Cannot vouch for yourself');
  }

  return { valid: errors.length === 0, errors };
}

/** Validate a kind 30472 Community Policy */
export function validatePolicy(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  if (event.kind !== SIGNET_KINDS.POLICY) {
    errors.push(`Expected kind ${SIGNET_KINDS.POLICY}, got ${event.kind}`);
  }

  if (!hasSignetLabel(event)) {
    errors.push('Missing signet protocol label');
  }

  const communityId = getTagValue(event, 'd');
  if (!communityId) errors.push('Missing "d" tag (community identifier)');

  const adultMinTier = getTagValue(event, 'adult-min-tier');
  if (!adultMinTier || !['1', '2', '3', '4'].includes(adultMinTier)) {
    errors.push('Missing or invalid "adult-min-tier" tag');
  }

  const childMinTier = getTagValue(event, 'child-min-tier');
  if (!childMinTier || !['1', '2', '3', '4'].includes(childMinTier)) {
    errors.push('Missing or invalid "child-min-tier" tag');
  }

  const enforcement = getTagValue(event, 'enforcement');
  if (!enforcement || !['client', 'relay', 'both'].includes(enforcement)) {
    errors.push('Missing or invalid "enforcement" tag');
  }

  return { valid: errors.length === 0, errors };
}

/** Validate a kind 30473 Verifier Credential */
export function validateVerifier(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  if (event.kind !== SIGNET_KINDS.VERIFIER) {
    errors.push(`Expected kind ${SIGNET_KINDS.VERIFIER}, got ${event.kind}`);
  }

  if (!hasSignetLabel(event)) {
    errors.push('Missing signet protocol label');
  }

  if (!getTagValue(event, 'profession')) {
    errors.push('Missing "profession" tag');
  }

  if (!getTagValue(event, 'jurisdiction')) {
    errors.push('Missing "jurisdiction" tag');
  }

  if (!getTagValue(event, 'licence')) {
    errors.push('Missing "licence" tag');
  }

  if (!getTagValue(event, 'body')) {
    errors.push('Missing "body" tag (professional body)');
  }

  return { valid: errors.length === 0, errors };
}

/** Validate a kind 30474 Verifier Challenge */
export function validateChallenge(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  if (event.kind !== SIGNET_KINDS.CHALLENGE) {
    errors.push(`Expected kind ${SIGNET_KINDS.CHALLENGE}, got ${event.kind}`);
  }

  if (!hasSignetLabel(event)) {
    errors.push('Missing signet protocol label');
  }

  const verifierPubkey = getTagValue(event, 'd');
  if (!verifierPubkey) errors.push('Missing "d" tag (verifier pubkey)');

  const reason = getTagValue(event, 'reason');
  const validReasons = ['anomalous-volume', 'registry-mismatch', 'fraudulent-attestation', 'licence-revoked', 'other'];
  if (!reason || !validReasons.includes(reason)) {
    errors.push('Missing or invalid "reason" tag');
  }

  if (!getTagValue(event, 'evidence-type')) {
    errors.push('Missing "evidence-type" tag');
  }

  if (!event.content || event.content.length === 0) {
    errors.push('Challenge must include evidence in content');
  }

  return { valid: errors.length === 0, errors };
}

/** Validate a kind 30475 Verifier Revocation */
export function validateRevocation(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  if (event.kind !== SIGNET_KINDS.REVOCATION) {
    errors.push(`Expected kind ${SIGNET_KINDS.REVOCATION}, got ${event.kind}`);
  }

  if (!hasSignetLabel(event)) {
    errors.push('Missing signet protocol label');
  }

  const verifierPubkey = getTagValue(event, 'd');
  if (!verifierPubkey) errors.push('Missing "d" tag (verifier pubkey)');

  if (!getTagValue(event, 'challenge')) {
    errors.push('Missing "challenge" tag (challenge event ID)');
  }

  const confirmations = getTagValue(event, 'confirmations');
  if (!confirmations || parseInt(confirmations, 10) < 1) {
    errors.push('Missing or invalid "confirmations" tag');
  }

  const bondAction = getTagValue(event, 'bond-action');
  if (!bondAction || !['slashed', 'returned', 'held'].includes(bondAction)) {
    errors.push('Missing or invalid "bond-action" tag');
  }

  const scope = getTagValue(event, 'scope');
  if (!scope || !['full', 'partial'].includes(scope)) {
    errors.push('Missing or invalid "scope" tag');
  }

  return { valid: errors.length === 0, errors };
}

/** Validate any Signet event by kind */
export function validateEvent(event: NostrEvent): ValidationResult {
  switch (event.kind) {
    case SIGNET_KINDS.CREDENTIAL:
      return validateCredential(event);
    case SIGNET_KINDS.VOUCH:
      return validateVouch(event);
    case SIGNET_KINDS.POLICY:
      return validatePolicy(event);
    case SIGNET_KINDS.VERIFIER:
      return validateVerifier(event);
    case SIGNET_KINDS.CHALLENGE:
      return validateChallenge(event);
    case SIGNET_KINDS.REVOCATION:
      return validateRevocation(event);
    default:
      return { valid: false, errors: [`Unknown Signet event kind: ${event.kind}`] };
  }
}
