/**
 * Signet Credential Presentation Protocol
 *
 * Handles age verification requests from websites.
 * Two modes:
 *   - Same device: BroadcastChannel communication
 *   - Cross device: QR code → relay-based response
 */

export interface VerifyRequest {
  type: 'signet-verify-request';
  requestId: string;
  requiredAgeRange: string;
  callbackUrl?: string;
  relayUrl?: string;
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
 * Parse a verification request from a QR code payload
 */
export function parseVerifyRequest(data: string): VerifyRequest | null {
  try {
    // Try direct JSON first
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
    const timestamp = typeof obj.timestamp === 'number' ? obj.timestamp : Math.floor(Date.now() / 1000);

    // Validate timestamp is within 5 minutes of now
    if (Math.abs(Date.now() / 1000 - timestamp) > 300) return null;

    // Validate requestId is a 32-char hex string
    if (!/^[0-9a-f]{32}$/i.test(requestId)) return null;

    // Validate requiredAgeRange is in the allowed set
    const VALID_AGE_RANGES = ['0-3', '4-7', '8-12', '13-17', '18+'];
    if (!VALID_AGE_RANGES.includes(requiredAgeRange)) return null;

    // Cap and validate URL fields
    const rawCallbackUrl = typeof obj.callbackUrl === 'string' ? obj.callbackUrl : undefined;
    const rawRelayUrl = typeof obj.relayUrl === 'string' ? obj.relayUrl : undefined;

    const callbackUrl = rawCallbackUrl ? rawCallbackUrl.slice(0, 1024) : undefined;
    const relayUrl = rawRelayUrl ? rawRelayUrl.slice(0, 1024) : undefined;

    // Validate callbackUrl scheme: must be https:// or http://localhost
    if (rawCallbackUrl !== undefined && !/^https:\/\//i.test(rawCallbackUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(rawCallbackUrl)) {
      return null;
    }

    // Validate relayUrl starts with wss:// if present
    if (relayUrl !== undefined && !relayUrl.startsWith('wss://')) return null;

    return {
      type: 'signet-verify-request',
      requestId,
      requiredAgeRange,
      callbackUrl,
      relayUrl,
      timestamp,
    };
  } catch {
    return null;
  }
}

/**
 * Build a verification response
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
 * Send response via BroadcastChannel (same-device flow)
 */
export function sendResponseViaBroadcast(response: VerifyResponse): void {
  const channel = new BroadcastChannel('signet-verify-' + response.requestId);
  channel.postMessage(response);
  channel.close();
}

/**
 * Check if the user's credential satisfies the request
 */
export function credentialSatisfiesRequest(
  credentialTags: string[][],
  requiredAgeRange: string,
): boolean {
  const ageRange = credentialTags.find(t => t[0] === 'age-range')?.[1];
  if (!ageRange) return false;

  if (requiredAgeRange === '18+') return ageRange === '18+';
  return ageRange === requiredAgeRange;
}
