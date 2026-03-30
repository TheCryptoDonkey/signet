// Signet Event Validation
// Validates structure and required fields for all 6 event kinds

import { validateAttestation } from 'nostr-attestations';
import { ATTESTATION_KIND, ATTESTATION_TYPES, APP_DATA_KIND, SIGNET_LABEL, VALID_BOND_ADDRESS_TYPES } from './constants.js';
import type { NostrEvent } from './types.js';

export const MAX_CONTENT_LENGTH = 65536;
export const MAX_TAG_VALUE_LENGTH = 1024;
export const MAX_TAGS_COUNT = 100;

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
  return event.tags.filter((t) => t[0] === name && t[1] !== undefined).map((t) => t[1]);
}

/** Validate field-size bounds on untrusted event data */
export function validateFieldSizeBounds(event: NostrEvent, errors: string[]): void {
  if (event.content.length > MAX_CONTENT_LENGTH) {
    errors.push(`Event content exceeds maximum length of ${MAX_CONTENT_LENGTH} characters`);
  }
  if (event.tags.length > MAX_TAGS_COUNT) {
    errors.push(`Event has too many tags (max ${MAX_TAGS_COUNT})`);
  }
  for (const t of event.tags) {
    for (let i = 1; i < t.length; i++) {
      if (t[i] !== undefined && t[i].length > MAX_TAG_VALUE_LENGTH) {
        errors.push(`Tag value at index ${i} for "${t[0]}" exceeds maximum length of ${MAX_TAG_VALUE_LENGTH} characters`);
      }
    }
  }
}

/** Check that the event has a NIP-VA discoverability label.
 * Accepts both the current 'nip-va' label and the legacy 'signet' label
 * for backwards compatibility with events created before v2.3.0. */
function hasSignetLabel(event: NostrEvent): boolean {
  return event.tags.some(
    (t) => t[0] === 'L' && (t[1] === 'nip-va' || t[1] === SIGNET_LABEL)
  );
}

/** Validate a Verification Credential attestation (kind 31000, type: credential) */
export function validateCredential(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  validateFieldSizeBounds(event, errors);

  const base = validateAttestation(event);
  if (!base.valid) {
    return { valid: false, errors: [...base.errors] };
  }

  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.CREDENTIAL) {
    errors.push(`Expected type tag '${ATTESTATION_TYPES.CREDENTIAL}'`);
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

  const verificationType = getTagValue(event, 'verification-type');
  if (!verificationType || !['self', 'peer', 'professional'].includes(verificationType)) {
    errors.push('Missing or invalid "verification-type" tag');
  }

  const scope = getTagValue(event, 'scope');
  if (!scope || !['adult', 'adult+child'].includes(scope)) {
    errors.push('Missing or invalid "scope" tag');
  }

  const method = getTagValue(event, 'method');
  if (!method) errors.push('Missing "method" tag');

  // V-SIG-07: nullifier, if present, must be a 64-character lowercase hex string (SHA-256)
  const nullifier = getTagValue(event, 'nullifier');
  if (nullifier !== undefined && !/^[0-9a-f]{64}$/.test(nullifier)) {
    errors.push('Invalid "nullifier" tag (must be 64-character lowercase hex SHA-256)');
  }

  // Tier-specific validations — use string comparison (tier is already whitelisted above)
  if (tier === '1' && verificationType !== 'self') {
    errors.push('Tier 1 must have verification-type "self"');
  }

  // V-SIG-03: Tier 1 self-declaration must be self-signed (pubkey === p tag)
  if (tier === '1') {
    const pTag = getTagValue(event, 'p');
    if (pTag && event.pubkey !== pTag) {
      errors.push('Tier 1 credential must be self-signed (pubkey must equal p tag)');
    }
  }

  if (tier === '2' && verificationType !== 'peer') {
    errors.push('Tier 2 must have verification-type "peer"');
  }

  if ((tier === '3' || tier === '4') && verificationType !== 'professional') {
    errors.push(`Tier ${tier} must have verification-type "professional"`);
  }

  if (tier === '4') {
    if (scope !== 'adult+child') {
      errors.push('Tier 4 must have scope "adult+child"');
    }
    if (!getTagValue(event, 'age-range')) {
      errors.push('Tier 4 must include "age-range" tag');
    }
  }

  if ((tier === '3' || tier === '4') && !getTagValue(event, 'profession')) {
    errors.push(`Tier ${tier} should include "profession" tag`);
  }

  return { valid: errors.length === 0, errors };
}

/** Validate a Vouch Attestation (kind 31000, type: vouch) */
export function validateVouch(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  validateFieldSizeBounds(event, errors);

  const base = validateAttestation(event);
  if (!base.valid) {
    return { valid: false, errors: [...base.errors] };
  }

  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.VOUCH) {
    errors.push(`Expected type tag '${ATTESTATION_TYPES.VOUCH}'`);
  }

  if (!hasSignetLabel(event)) {
    errors.push('Missing signet protocol label');
  }

  const dTag = getTagValue(event, 'd');
  if (!dTag) errors.push('Missing "d" tag (subject pubkey)');

  // Strip 'vouch:' prefix from d-tag to get subject pubkey
  const subject = dTag && dTag.startsWith('vouch:') ? dTag.slice('vouch:'.length) : dTag;

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

/** Validate a Community Policy (kind 30078, NIP-78) */
export function validatePolicy(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  validateFieldSizeBounds(event, errors);

  if (event.kind !== APP_DATA_KIND) {
    errors.push(`Expected kind ${APP_DATA_KIND}, got ${event.kind}`);
  }

  const dTag = getTagValue(event, 'd');
  if (!dTag || !dTag.startsWith('signet:policy:')) {
    errors.push('Missing or invalid "d" tag (must start with "signet:policy:")');
  }

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

/** Validate a Verifier Credential attestation (kind 31000, type: verifier) */
export function validateVerifier(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  validateFieldSizeBounds(event, errors);

  const base = validateAttestation(event);
  if (!base.valid) {
    return { valid: false, errors: [...base.errors] };
  }

  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.VERIFIER) {
    errors.push(`Expected type tag '${ATTESTATION_TYPES.VERIFIER}'`);
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

  // Bond tag validation (only when bond-address is present — all 6 tags must be present together)
  const bondAddress = getTagValue(event, 'bond-address');
  if (bondAddress !== undefined) {
    const bondAddressType = getTagValue(event, 'bond-address-type');
    const bondAmount = getTagValue(event, 'bond-amount');
    const bondTimestamp = getTagValue(event, 'bond-timestamp');
    const bondMessage = getTagValue(event, 'bond-message');
    const bondSignature = getTagValue(event, 'bond-signature');

    if (!bondAddressType) errors.push('Missing "bond-address-type" tag (required when bond-address is present)');
    if (!bondAmount) errors.push('Missing "bond-amount" tag (required when bond-address is present)');
    if (!bondTimestamp) errors.push('Missing "bond-timestamp" tag (required when bond-address is present)');
    if (!bondMessage) errors.push('Missing "bond-message" tag (required when bond-address is present)');
    if (!bondSignature) errors.push('Missing "bond-signature" tag (required when bond-address is present)');

    if (bondAddressType && !(VALID_BOND_ADDRESS_TYPES as readonly string[]).includes(bondAddressType)) {
      errors.push(`Invalid "bond-address-type" tag (must be one of: ${VALID_BOND_ADDRESS_TYPES.join(', ')})`);
    }

    if (bondAmount) {
      const amountNum = parseInt(bondAmount, 10);
      if (isNaN(amountNum) || amountNum <= 0) {
        errors.push('Invalid "bond-amount" tag (must be a positive integer)');
      }
    }

    if (bondMessage && !bondMessage.startsWith('signet:bond:')) {
      errors.push('Invalid "bond-message" tag (must start with "signet:bond:")');
    }
  }

  return { valid: errors.length === 0, errors };
}

/** Validate a Verifier Challenge attestation (kind 31000, type: challenge) */
export function validateChallenge(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  validateFieldSizeBounds(event, errors);

  const base = validateAttestation(event);
  if (!base.valid) {
    return { valid: false, errors: [...base.errors] };
  }

  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.CHALLENGE) {
    errors.push(`Expected type tag '${ATTESTATION_TYPES.CHALLENGE}'`);
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

/** Validate a Verifier Revocation attestation (kind 31000, type: revocation) */
export function validateRevocation(event: NostrEvent): ValidationResult {
  const errors: string[] = [];

  validateFieldSizeBounds(event, errors);

  const base = validateAttestation(event);
  if (!base.valid) {
    return { valid: false, errors: [...base.errors] };
  }

  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.REVOCATION) {
    errors.push(`Expected type tag '${ATTESTATION_TYPES.REVOCATION}'`);
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
  const confirmationsNum = confirmations ? parseInt(confirmations, 10) : NaN;
  if (!confirmations || isNaN(confirmationsNum) || confirmationsNum < 1) {
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

/** Validate any Signet event by kind + type tag */
export function validateEvent(event: NostrEvent): ValidationResult {
  if (event.kind === APP_DATA_KIND) {
    return validatePolicy(event);
  }

  if (event.kind === ATTESTATION_KIND) {
    const eventType = getTagValue(event, 'type');
    switch (eventType) {
      case ATTESTATION_TYPES.CREDENTIAL:
        return validateCredential(event);
      case ATTESTATION_TYPES.VOUCH:
        return validateVouch(event);
      case ATTESTATION_TYPES.VERIFIER:
        return validateVerifier(event);
      case ATTESTATION_TYPES.CHALLENGE:
        return validateChallenge(event);
      case ATTESTATION_TYPES.REVOCATION:
        return validateRevocation(event);
      default:
        return { valid: false, errors: [`Unknown attestation type: ${eventType}`] };
    }
  }

  return { valid: false, errors: [`Unknown Signet event kind: ${event.kind}`] };
}
