/**
 * Relay Event Builders for Signet Presentation Protocol
 *
 * Builds unsigned kind 29999 event templates for verification responses,
 * rejections, and auth responses. The consuming application signs these
 * with the user's signing backend and publishes to relays.
 */

import type { UnsignedEvent } from './types.js';
import type { VerifyResponse } from './presentation.js';

/** Auth response payload published via relay (cross-device flow). */
export interface AuthResponse {
  type: 'signet-auth-response';
  requestId: string;
  pubkey: string;
  /** Schnorr signature of the challenge string using the user's active private key */
  signature: string;
  /** Optional credential (included for signet-login-request flows) */
  credential?: {
    id: string;
    kind: number;
    pubkey: string;
    tags: string[][];
    content: string;
    sig: string;
    created_at: number;
  };
}

/**
 * Build an unsigned kind 29999 event carrying a verification response.
 * The caller must sign this event before publishing.
 */
export function buildVerifyEventTemplate(
  response: VerifyResponse,
  pubkey: string,
): UnsignedEvent {
  const credTags = response.credential.tags;
  const ageRange = credTags.find(t => t[0] === 'age-range')?.[1] ?? '';
  const tier = credTags.find(t => t[0] === 'tier')?.[1] ?? '';
  const entityType = credTags.find(t => t[0] === 'entity-type')?.[1] ?? '';

  return {
    kind: 29999,
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['session', response.requestId],
      ['credential', JSON.stringify(response.credential)],
      ['status', 'approved'],
      ['age-range', ageRange],
      ['tier', tier],
      ['entity-type', entityType],
    ],
    content: '',
  };
}

/**
 * Build an unsigned kind 29999 event for a verification rejection.
 * The caller must sign this event before publishing.
 */
export function buildRejectionEventTemplate(
  requestId: string,
  pubkey: string,
): UnsignedEvent {
  return {
    kind: 29999,
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['session', requestId],
      ['status', 'rejected'],
    ],
    content: '',
  };
}

/**
 * Build an unsigned kind 29999 event for an auth response.
 * The caller must sign this event before publishing.
 */
export function buildAuthResponseEventTemplate(
  response: AuthResponse,
  pubkey: string,
): UnsignedEvent {
  return {
    kind: 29999,
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['session', response.requestId],
      ['status', 'approved'],
    ],
    content: JSON.stringify(response),
  };
}
