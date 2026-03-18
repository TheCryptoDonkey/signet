/**
 * Universal QR Router — detects QR type and returns the appropriate action.
 *
 * Supported QR types:
 * 1. signet-verify-request — age/credential verification
 * 2. signet-auth-request — NIP-46 style login (prove pubkey ownership)
 * 3. signet-login-request — combined auth + verification
 * 4. nostr+connect:// — standard NIP-46 connection string
 * 5. npub1... / nprofile1... — Nostr public key (add as contact)
 * 6. Unknown — not recognised
 */

import type { VerifyRequest } from './presentation';

export type QRAction =
  | { type: 'verify'; request: VerifyRequest }
  | { type: 'auth'; request: AuthRequest }
  | { type: 'login'; request: LoginRequest }
  | { type: 'nostr-connect'; uri: string; pubkey: string; relay?: string }
  | { type: 'contact'; npub: string }
  | { type: 'unknown'; raw: string };

export interface AuthRequest {
  type: 'signet-auth-request';
  requestId: string;
  challenge: string;
  origin: string;
  relay?: string;
  callbackUrl?: string;
  timestamp: number;
}

export interface LoginRequest {
  type: 'signet-login-request';
  requestId: string;
  challenge: string;
  requiredAgeRange?: string;
  origin: string;
  relay?: string;
  callbackUrl?: string;
  timestamp: number;
}

const VALID_AGE_RANGES = ['0-3', '4-7', '8-12', '13-17', '18+'];

/** Validate that a parsed object is a well-formed VerifyRequest */
function isValidVerifyRequest(obj: Record<string, unknown>): obj is Record<string, unknown> & VerifyRequest {
  if (typeof obj.requestId !== 'string') return false;
  if (!/^[0-9a-f]{32}$/i.test(obj.requestId)) return false;
  if (typeof obj.requiredAgeRange !== 'string') return false;
  if (!VALID_AGE_RANGES.includes(obj.requiredAgeRange)) return false;
  const ts = typeof obj.timestamp === 'number' ? obj.timestamp : Math.floor(Date.now() / 1000);
  if (Math.abs(Date.now() / 1000 - ts) > 300) return false;
  // Validate optional URL fields (with length bounds)
  if (obj.callbackUrl !== undefined) {
    if (typeof obj.callbackUrl !== 'string' || obj.callbackUrl.length > 1024) return false;
    if (!/^https:\/\//i.test(obj.callbackUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(obj.callbackUrl)) return false;
  }
  if (obj.relayUrl !== undefined) {
    if (typeof obj.relayUrl !== 'string' || obj.relayUrl.length > 1024) return false;
    if (!obj.relayUrl.startsWith('wss://')) return false;
  }
  return true;
}

/** Validate that a parsed object is a well-formed AuthRequest */
function isValidAuthRequest(obj: Record<string, unknown>): obj is Record<string, unknown> & AuthRequest {
  if (typeof obj.requestId !== 'string' || obj.requestId.length > 64) return false;
  if (typeof obj.challenge !== 'string' || obj.challenge.length > 512) return false;
  if (typeof obj.origin !== 'string' || obj.origin.length > 1024) return false;
  if (typeof obj.timestamp !== 'number') return false;
  if (Math.abs(Date.now() / 1000 - obj.timestamp) > 300) return false;
  return true;
}

/** Validate that a parsed object is a well-formed LoginRequest */
function isValidLoginRequest(obj: Record<string, unknown>): obj is Record<string, unknown> & LoginRequest {
  if (typeof obj.requestId !== 'string' || obj.requestId.length > 64) return false;
  if (typeof obj.challenge !== 'string' || obj.challenge.length > 512) return false;
  if (typeof obj.origin !== 'string' || obj.origin.length > 1024) return false;
  if (typeof obj.timestamp !== 'number') return false;
  if (Math.abs(Date.now() / 1000 - obj.timestamp) > 300) return false;
  return true;
}

/**
 * Route a raw QR code string to the appropriate action.
 * All parsing is defensive — unknown or malformed input returns { type: 'unknown' }.
 */
export function routeQR(data: string): QRAction {
  const raw = data.trim();

  // ── JSON-encoded Signet request types ─────────────────────
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === 'object' && parsed !== null) {
      const obj = parsed as Record<string, unknown>;

      if (obj.type === 'signet-verify-request') {
        if (isValidVerifyRequest(obj)) {
          // Normalise timestamp (parseVerifyRequest does this too)
          const ts = typeof obj.timestamp === 'number' ? obj.timestamp : Math.floor(Date.now() / 1000);
          const request: VerifyRequest = {
            type: 'signet-verify-request',
            requestId: obj.requestId as string,
            requiredAgeRange: obj.requiredAgeRange as string,
            callbackUrl: typeof obj.callbackUrl === 'string' ? (obj.callbackUrl as string).slice(0, 1024) : undefined,
            relayUrl: typeof obj.relayUrl === 'string' ? (obj.relayUrl as string).slice(0, 1024) : undefined,
            timestamp: ts,
          };
          return { type: 'verify', request };
        }
        return { type: 'unknown', raw };
      }

      // Compact format: { t: 'sa', r: requestId, c: challenge, o: origin, l: relay, s: timestamp }
      if (obj.t === 'sa') {
        const expanded: Record<string, unknown> = {
          type: 'signet-auth-request',
          requestId: obj.r,
          challenge: obj.c,
          origin: obj.o,
          relay: typeof obj.l === 'string' && obj.l.length > 0 ? obj.l : undefined,
          timestamp: obj.s,
        };
        if (isValidAuthRequest(expanded)) {
          return { type: 'auth', request: expanded as unknown as AuthRequest };
        }
        return { type: 'unknown', raw };
      }

      // Compact format: { t: 'sl', r, c, o, l, s, a: requiredAgeRange }
      if (obj.t === 'sl') {
        const expanded: Record<string, unknown> = {
          type: 'signet-login-request',
          requestId: obj.r,
          challenge: obj.c,
          origin: obj.o,
          relay: typeof obj.l === 'string' && obj.l.length > 0 ? obj.l : undefined,
          requiredAgeRange: obj.a,
          timestamp: obj.s,
        };
        if (isValidLoginRequest(expanded)) {
          return { type: 'login', request: expanded as unknown as LoginRequest };
        }
        return { type: 'unknown', raw };
      }

      if (obj.type === 'signet-auth-request') {
        if (isValidAuthRequest(obj)) {
          return { type: 'auth', request: obj as unknown as AuthRequest };
        }
        return { type: 'unknown', raw };
      }

      if (obj.type === 'signet-login-request') {
        if (isValidLoginRequest(obj)) {
          return { type: 'login', request: obj };
        }
        return { type: 'unknown', raw };
      }
    }
  } catch { /* not JSON */ }

  // ── Base64-encoded signet:verify: prefix ──────────────────
  if (raw.startsWith('signet:verify:')) {
    try {
      const json = atob(raw.slice(14));
      const parsed: unknown = JSON.parse(json);
      if (typeof parsed === 'object' && parsed !== null) {
        const obj = parsed as Record<string, unknown>;
        if (obj.type === 'signet-verify-request' && isValidVerifyRequest(obj)) {
          const ts = typeof obj.timestamp === 'number' ? obj.timestamp : Math.floor(Date.now() / 1000);
          const request: VerifyRequest = {
            type: 'signet-verify-request',
            requestId: obj.requestId as string,
            requiredAgeRange: obj.requiredAgeRange as string,
            callbackUrl: typeof obj.callbackUrl === 'string' ? (obj.callbackUrl as string).slice(0, 1024) : undefined,
            relayUrl: typeof obj.relayUrl === 'string' ? (obj.relayUrl as string).slice(0, 1024) : undefined,
            timestamp: ts,
          };
          return { type: 'verify', request };
        }
      }
    } catch { /* invalid base64 or JSON */ }
    return { type: 'unknown', raw };
  }

  // ── nostr+connect:// URI (NIP-46) ─────────────────────────
  if (raw.startsWith('nostr+connect://')) {
    try {
      const url = new URL(raw);
      // pubkey is the hostname in nostr+connect://pubkey?relay=...
      const pubkey = url.hostname || url.pathname.replace('//', '');
      const relay = url.searchParams.get('relay') ?? undefined;
      if (/^[0-9a-f]{64}$/i.test(pubkey)) {
        return { type: 'nostr-connect', uri: raw, pubkey, relay };
      }
    } catch { /* invalid URI */ }
    return { type: 'unknown', raw };
  }

  // ── nostrconnect:// URI (NIP-46 alternate prefix) ─────────
  if (raw.startsWith('nostrconnect://')) {
    try {
      const url = new URL(raw);
      const pubkey = url.hostname || url.pathname.replace('//', '');
      const relay = url.searchParams.get('relay') ?? undefined;
      if (/^[0-9a-f]{64}$/i.test(pubkey)) {
        return { type: 'nostr-connect', uri: raw, pubkey, relay };
      }
    } catch { /* invalid URI */ }
    return { type: 'unknown', raw };
  }

  // ── Nostr public key bech32 encodings ─────────────────────
  if (raw.startsWith('npub1') && raw.length >= 60) {
    return { type: 'contact', npub: raw };
  }
  if (raw.startsWith('nprofile1')) {
    return { type: 'contact', npub: raw };
  }

  return { type: 'unknown', raw };
}
