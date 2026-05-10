/**
 * URL-based authentication for "Sign in with Signet" redirect flow.
 *
 * External websites redirect to the Signet app with URL params containing
 * a challenge, origin, callback, and site name. The app signs the challenge
 * and redirects back with the signature.
 */

import type { LoginRequest } from './qr-router.js';

/** Check if a URL is https:// or http://localhost (dev). */
function isValidAuthUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:') return true;
    if (parsed.protocol === 'http:' && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')) return true;
    return false;
  } catch {
    return false;
  }
}

/** Check if a URL is wss:// or ws://localhost (dev). Used for relay delivery mode. */
function isValidRelayUrl(url: string): boolean {
  return /^wss:\/\//i.test(url) || /^ws:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(url);
}

/**
 * Parse URL auth params from a query string (e.g. window.location.search).
 * Returns a LoginRequest compatible with the approval flow,
 * or null if params are missing/invalid.
 */
export function parseUrlAuthParams(search: string): LoginRequest | null {
  const params = new URLSearchParams(search);
  if (params.get('auth') !== '1') return null;

  const challenge = params.get('challenge');
  const origin = params.get('origin');
  const name = params.get('name');
  const callback = params.get('callback');

  // All four params required
  if (!challenge || !origin || !name || !callback) return null;

  // Challenge must be 64 hex chars (normalize to lowercase)
  if (!/^[0-9a-f]{64}$/i.test(challenge)) return null;
  const normalizedChallenge = challenge.toLowerCase();

  // Name must be non-empty, max 64 chars
  if (name.length === 0 || name.length > 64) return null;

  // Origin must be https:// (or http://localhost for dev)
  if (!isValidAuthUrl(origin)) return null;

  // Callback must be https:// (or http://localhost for dev)
  if (!isValidAuthUrl(callback)) return null;

  // Callback origin must match origin param (prevent open redirect)
  try {
    const callbackOrigin = new URL(callback).origin;
    const requestOrigin = new URL(origin).origin;
    if (callbackOrigin !== requestOrigin) return null;
  } catch {
    return null;
  }

  const timestampParam = params.get('t') || params.get('timestamp');
  if (!timestampParam) return null; // timestamp required for replay protection
  const timestamp = parseInt(timestampParam, 10);
  if (isNaN(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > 300) return null;

  // Optional cross-device relay delivery params.
  // Both must be present together — gift-wrap is non-optional in relay mode,
  // so a relay URL without a session pubkey (or vice versa) is rejected.
  const relayParam = params.get('relay');
  const sessionPubkeyParam = params.get('sessionPubkey');

  let relay: string | undefined;
  let sessionPubkey: string | undefined;

  if (relayParam !== null || sessionPubkeyParam !== null) {
    if (!relayParam || !sessionPubkeyParam) return null;
    if (relayParam.length > 1024) return null;
    if (!isValidRelayUrl(relayParam)) return null;
    if (!/^[0-9a-f]{64}$/i.test(sessionPubkeyParam)) return null;
    relay = relayParam;
    sessionPubkey = sessionPubkeyParam.toLowerCase();
  }

  const result: LoginRequest = {
    type: 'signet-login-request',
    requestId: normalizedChallenge, // use challenge as requestId for URL auth
    challenge: normalizedChallenge,
    origin,
    callbackUrl: callback,
    timestamp,
  };
  if (relay !== undefined) result.relay = relay;
  if (sessionPubkey !== undefined) result.sessionPubkey = sessionPubkey;
  return result;
}

/**
 * Build the callback redirect URL after successful auth.
 * Uses the URL API to safely append params (no string concatenation).
 *
 * `createdAt` is the unix-seconds `created_at` field of the kind-21236 event
 * that produced `signature`. Optional for backward compatibility — older
 * callers that don't supply it get the historical URL shape (no `t` param).
 * When supplied, consumers can reconstruct the exact event (and verify the
 * signature against it) without extra round-trips, since the rest of the
 * event tags are derivable from the request URL params (`challenge`,
 * `origin`, `name`).
 */
export function buildAuthCallbackUrl(
  callbackUrl: string,
  pubkey: string,
  npub: string,
  signature: string,
  eventId: string,
  createdAt?: number,
): string {
  if (!isValidAuthUrl(callbackUrl)) throw new Error('Invalid callback URL scheme');
  const url = new URL(callbackUrl);
  url.searchParams.set('pubkey', pubkey);
  url.searchParams.set('npub', npub);
  url.searchParams.set('signature', signature);
  url.searchParams.set('eventId', eventId);
  if (createdAt !== undefined) {
    if (!Number.isInteger(createdAt) || createdAt < 0) {
      throw new Error('createdAt must be a non-negative integer (unix seconds)');
    }
    url.searchParams.set('t', String(createdAt));
  }
  return url.toString();
}

/**
 * Build the callback redirect URL for a denied auth request.
 */
export function buildAuthDeniedUrl(callbackUrl: string): string {
  if (!isValidAuthUrl(callbackUrl)) throw new Error('Invalid callback URL scheme');
  const url = new URL(callbackUrl);
  url.searchParams.set('error', 'denied');
  return url.toString();
}

/**
 * Extract and sanitise the site name from URL auth params.
 * Strips control characters and bidirectional text markers, caps at 64 chars.
 */
export function getUrlAuthSiteName(search: string): string {
  const params = new URLSearchParams(search);
  const name = params.get('name') ?? '';
  return name.replace(/[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g, '').slice(0, 64);
}
