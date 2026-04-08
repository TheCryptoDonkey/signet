/**
 * Signet Credential Presentation Protocol
 *
 * Types and validation for age verification requests/responses.
 * This module defines the wire protocol — transport (BroadcastChannel,
 * relay publish) is handled by the consuming application.
 */

import { verifyAgeRangeProof } from './range-proof.js';

/** Valid age range values for verification requests. */
export const VALID_AGE_RANGES = ['0-3', '4-7', '8-12', '13-17', '18+'] as const;

export interface VerifyRequest {
  type: 'signet-verify-request';
  requestId: string;
  requiredAgeRange: string;
  callbackUrl?: string;
  relayUrl?: string;
  origin?: string;
  /** Session pubkey (hex) for NIP-17 gift-wrap encryption. If absent, response is cleartext. */
  sessionPubkey?: string;
  timestamp: number;
}

export interface VerifyResponse {
  type: 'signet-verify-response';
  requestId: string;
  credential: {
    id: string;
    kind: number;
    pubkey: string;
    tags: string[][];
    content: string;
    sig: string;
    created_at: number;
  };
  subjectPubkey: string;
}

/**
 * Parse a verification request from a QR code payload or JSON string.
 * Returns null for invalid or expired requests.
 */
export function parseVerifyRequest(data: string): VerifyRequest | null {
  try {
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      // Try base64 decode (from signet:verify: prefix)
      const base64 = data.startsWith('signet:verify:') ? data.slice(14) : data;
      parsed = JSON.parse(atob(base64));
    }

    if (typeof parsed !== 'object' || parsed === null) return null;
    const obj = parsed as Record<string, unknown>;
    if (obj.type !== 'signet-verify-request') return null;
    if (typeof obj.requestId !== 'string') return null;
    if (typeof obj.requiredAgeRange !== 'string') return null;

    const requestId = obj.requestId as string;
    const requiredAgeRange = obj.requiredAgeRange as string;
    if (typeof obj.timestamp !== 'number') return null;
    const timestamp = obj.timestamp;

    // Validate timestamp is within 5 minutes of now
    if (Math.abs(Date.now() / 1000 - timestamp) > 300) return null;

    // Validate requestId is a 32-char hex string
    if (!/^[0-9a-f]{32}$/i.test(requestId)) return null;

    // Validate requiredAgeRange is in the allowed set
    if (!(VALID_AGE_RANGES as readonly string[]).includes(requiredAgeRange)) return null;

    // Cap and validate URL fields
    const callbackUrl = typeof obj.callbackUrl === 'string' ? obj.callbackUrl.slice(0, 1024) : undefined;
    const relayUrl = typeof obj.relayUrl === 'string' ? obj.relayUrl.slice(0, 1024) : undefined;

    // Validate callbackUrl scheme: must be https:// or http://localhost
    if (callbackUrl !== undefined && !/^https:\/\//i.test(callbackUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(callbackUrl)) {
      return null;
    }

    // Validate relayUrl: wss:// or ws://localhost
    if (relayUrl !== undefined && !/^wss:\/\//i.test(relayUrl) && !/^ws:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(relayUrl)) return null;

    const origin = typeof obj.origin === 'string' ? obj.origin.slice(0, 1024) : undefined;

    // Validate origin scheme if present
    if (origin !== undefined) {
      if (!/^https:\/\//i.test(origin) && !/^http:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(origin)) return null;
    }

    // Extract session pubkey for NIP-17 gift wrapping (optional, 64-char hex)
    const sessionPubkey = typeof obj.sessionPubkey === 'string' && /^[0-9a-f]{64}$/i.test(obj.sessionPubkey)
      ? obj.sessionPubkey as string
      : undefined;

    return {
      type: 'signet-verify-request',
      requestId,
      requiredAgeRange,
      callbackUrl,
      relayUrl,
      origin,
      sessionPubkey,
      timestamp,
    };
  } catch {
    return null;
  }
}

/**
 * Build a verification response.
 */
export function buildVerifyResponse(
  requestId: string,
  credential: VerifyResponse['credential'],
  subjectPubkey: string,
): VerifyResponse {
  return {
    type: 'signet-verify-response',
    requestId,
    credential,
    subjectPubkey,
  };
}

/**
 * Check if a credential's tags satisfy a verification request's age range.
 * If the credential has a ZK age proof (zk-age tag), verifies the proof.
 * Legacy credentials without proofs are accepted during migration.
 */
export function credentialSatisfiesRequest(
  credentialTags: string[][],
  requiredAgeRange: string,
  credentialContent?: string,
  subjectPubkey?: string,
): boolean {
  const ageRange = credentialTags.find(t => t[0] === 'age-range')?.[1];
  if (!ageRange) return false;

  // Age range must match
  if (requiredAgeRange === '18+' && ageRange !== '18+') return false;
  if (requiredAgeRange !== '18+' && ageRange !== requiredAgeRange) return false;

  // If ZK proof is present, verify it
  const hasZkAge = credentialTags.some(t => t[0] === 'zk-age' && t[1] === '1');
  if (hasZkAge && credentialContent && subjectPubkey) {
    try {
      const content = JSON.parse(credentialContent);
      if (content.rangeProof) {
        if (!verifyAgeRangeProof(content.rangeProof, ageRange, subjectPubkey)) {
          return false; // Proof invalid — reject even if tag matches
        }
      }
    } catch {
      return false; // Malformed content — reject
    }
  }

  return true;
}
