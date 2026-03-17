/**
 * Signet Verify — Website Age Verification SDK
 *
 * Usage:
 *   <script src="https://cdn.signet.trotters.cc/signet-verify.js"></script>
 *   <script>
 *     const result = await Signet.verifyAge('18+');
 *     if (result.verified) { // allow access }
 *   </script>
 */

export interface SignetVerifyResult {
  verified: boolean;
  ageRange: string | null;
  tier: number | null;
  entityType: string | null;
  credentialId: string | null;
  verifierPubkey: string | null;
  /** Whether the verifier is confirmed against a public professional register */
  verifierConfirmed: boolean | null;
  /** Verifier's confirmation method: A (NIP-05 on body domain), B (body-issued), C (cross-verified), D (website), null if unknown */
  verifierMethod: 'A' | 'B' | 'C' | 'D' | null;
  issuedAt: number | null;
  expiresAt: number | null;
  error?: string;
}

export interface SignetVerifyOptions {
  /** Required age range to verify (e.g., '18+', '13-17') */
  requiredAgeRange: string;
  /** Relay URL for cross-device communication */
  relayUrl?: string;
  /** Callback URL for same-device flow */
  callbackUrl?: string;
  /** Custom styling for the verification modal */
  theme?: 'light' | 'dark' | 'auto';
  /** Timeout in milliseconds (default: 120000 — 2 minutes) */
  timeout?: number;
  /**
   * URL of the verification bot that checks verifier credentials against public registers.
   * Default: 'https://verify.signet.trotters.cc'
   * Set to null to skip verifier checking (accept any signed credential).
   * Anyone can run their own bot — the URL is configurable, not a central authority.
   */
  verifierCheckUrl?: string | null;
  /**
   * Accept credentials from unconfirmed verifiers.
   * Default: false (safe — only confirmed verifiers pass).
   * Set to true to accept any valid credential regardless of verifier status.
   */
  acceptUnconfirmed?: boolean;
}

/** The presentation request sent to the app */
interface PresentationRequest {
  type: 'signet-verify-request';
  requestId: string;
  requiredAgeRange: string;
  callbackUrl?: string;
  relayUrl?: string;
  timestamp: number;
}

/** The presentation response from the app */
interface PresentationResponse {
  type: 'signet-verify-response';
  requestId: string;
  credential: {
    id: string;
    kind: number;
    pubkey: string; // verifier pubkey
    tags: string[][];
    content: string;
    sig: string;
    created_at: number;
  };
  subjectPubkey: string;
}

// Escape HTML special characters to prevent XSS in innerHTML
function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Generate a random request ID
function generateRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// Extract a tag value from a Nostr event
function getTagValue(tags: string[][], key: string): string | undefined {
  const tag = tags.find(t => t[0] === key);
  return tag ? tag[1] : undefined;
}

// BIP-340 Schnorr signature verification via @noble/curves (bundled by esbuild)
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Verify a Nostr event's Schnorr signature (BIP-340).
 * Checks: structural validity, event ID hash, and cryptographic signature.
 */
async function verifyEventSignature(event: PresentationResponse['credential']): Promise<boolean> {
  // Structural validation: check field formats
  if (!event.id || !event.pubkey || !event.sig || !event.tags || event.kind !== 30470) {
    return false;
  }
  // sig must be exactly 128 hex chars (64-byte Schnorr signature)
  if (!/^[0-9a-f]{128}$/i.test(event.sig)) return false;
  // pubkey must be exactly 64 hex chars (32-byte x-only public key)
  if (!/^[0-9a-f]{64}$/i.test(event.pubkey)) return false;
  // id must be exactly 64 hex chars (32-byte SHA-256 hash)
  if (!/^[0-9a-f]{64}$/i.test(event.id)) return false;

  // Field-size bounds
  if (event.tags.length > 100) return false;
  if (event.content.length > 65536) return false;
  if (event.tags.some(t => t.some(v => v.length > 1024))) return false;

  // Required tags must be present
  const tagKeys = event.tags.map(t => t[0]);
  if (!tagKeys.includes('tier')) return false;
  if (!tagKeys.includes('age-range')) return false;
  if (!tagKeys.includes('entity-type')) return false;

  // Verify event ID matches the SHA-256 hash of the serialized event
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const encoder = new TextEncoder();
  const hashBytes = sha256(encoder.encode(serialized));
  const expectedId = bytesToHex(hashBytes);
  if (expectedId !== event.id.toLowerCase()) return false;

  // BIP-340 Schnorr signature verification
  try {
    const sigBytes = hexToBytes(event.sig);
    const idBytes = hexToBytes(event.id);
    const pubkeyBytes = hexToBytes(event.pubkey);
    return schnorr.verify(sigBytes, idBytes, pubkeyBytes);
  } catch {
    return false;
  }
}

// Check if the credential's age range satisfies the required range
function ageRangeSatisfies(credentialRange: string, requiredRange: string): boolean {
  // Simple range matching
  if (credentialRange === requiredRange) return true;
  // '18+' satisfies any adult requirement
  if (credentialRange === '18+' && requiredRange === '18+') return true;
  // Child ranges: credential must exactly match or be within required
  const ranges = ['0-3', '4-7', '8-12', '13-17', '18+'];
  const credIdx = ranges.indexOf(credentialRange);
  const reqIdx = ranges.indexOf(requiredRange);
  if (credIdx === -1 || reqIdx === -1) return false;
  // For '18+' requirement, credential must be '18+'
  if (requiredRange === '18+') return credentialRange === '18+';
  // For child requirements, credential range must match
  return credentialRange === requiredRange;
}

/** Response from the verification bot */
interface VerifierStatus {
  confirmed: boolean;
  method: 'A' | 'B' | 'C' | 'D' | null;
  profession?: string;
  jurisdiction?: string;
}

/**
 * Check a verifier's status against the verification bot.
 * Returns { confirmed, method } or null if the check fails/is skipped.
 */
async function checkVerifierStatus(
  verifierPubkey: string,
  checkUrl: string | null | undefined,
): Promise<VerifierStatus | null> {
  if (checkUrl === null || checkUrl === undefined) return null;
  if (!/^https:\/\//i.test(checkUrl)) return null;
  if (!/^[0-9a-f]{64}$/i.test(verifierPubkey)) return null;

  try {
    const response = await fetch(`${checkUrl}/status/${verifierPubkey}`, {
      signal: AbortSignal.timeout(5000), // 5 second timeout — don't block the UX
    });
    if (!response.ok) return null;

    const data: unknown = await response.json();
    if (typeof data !== 'object' || data === null) return null;

    const obj = data as Record<string, unknown>;
    return {
      confirmed: obj.confirmed === true,
      method: (['A', 'B', 'C', 'D'].includes(obj.method as string) ? obj.method : null) as VerifierStatus['method'],
      profession: typeof obj.profession === 'string' ? obj.profession : undefined,
      jurisdiction: typeof obj.jurisdiction === 'string' ? obj.jurisdiction : undefined,
    };
  } catch {
    // Bot unreachable — return null (unknown), don't block verification
    return null;
  }
}

/**
 * Main verification function.
 * Shows a modal with QR code, waits for the user's app to respond.
 */
export async function verifyAge(requiredAgeRange: string, options?: Partial<SignetVerifyOptions>): Promise<SignetVerifyResult> {
  const VALID_AGE_RANGES = ['0-3', '4-7', '8-12', '13-17', '18+'];
  if (!VALID_AGE_RANGES.includes(requiredAgeRange)) {
    return { verified: false, ageRange: null, tier: null, entityType: null, credentialId: null, verifierPubkey: null, verifierConfirmed: null, verifierMethod: null, issuedAt: null, expiresAt: null, error: 'invalid-age-range' };
  }

  const opts: SignetVerifyOptions = {
    requiredAgeRange,
    relayUrl: options?.relayUrl || 'wss://relay.damus.io',
    theme: options?.theme || 'auto',
    timeout: options?.timeout || 120000,
    verifierCheckUrl: options?.verifierCheckUrl !== undefined ? options.verifierCheckUrl : 'https://verify.signet.trotters.cc',
    acceptUnconfirmed: options?.acceptUnconfirmed || false,
    ...options,
  };
  opts.timeout = Math.max(5000, Math.min(opts.timeout ?? 120000, 600000));

  const requestId = generateRequestId();

  const request: PresentationRequest = {
    type: 'signet-verify-request',
    requestId,
    requiredAgeRange: opts.requiredAgeRange,
    relayUrl: opts.relayUrl,
    timestamp: Math.floor(Date.now() / 1000),
  };

  // Encode the request as a URL for QR code
  const requestPayload = JSON.stringify(request);
  const requestBase64 = btoa(requestPayload);

  return new Promise<SignetVerifyResult>((resolve) => {
    // Inject ::backdrop style for the native <dialog> element
    const style = document.createElement('style');
    style.textContent = '#signet-verify-dialog::backdrop{background:rgba(0,0,0,0.7)}';
    document.head.appendChild(style);

    const isDark = opts.theme === 'dark' || (opts.theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const bg = isDark ? '#1a1a2e' : '#ffffff';
    const fg = isDark ? '#e0e0e0' : '#1a1a2e';
    const muted = isDark ? '#888' : '#666';

    // Use <dialog> for native focus trap and top-layer placement
    const dialog = document.createElement('dialog');
    dialog.id = 'signet-verify-dialog';
    dialog.style.cssText = `border:none;border-radius:16px;padding:32px;max-width:380px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);background:${bg};color:${fg};font-family:system-ui,-apple-system,sans-serif;`;

    dialog.innerHTML = `
      <h2 style="margin:0 0 8px;font-size:1.3rem;">Verify your age with Signet</h2>
      <p style="margin:0 0 24px;color:${muted};font-size:0.9rem;">Scan this QR code with your Signet app to prove you are ${escapeHtml(requiredAgeRange)}. No personal data is shared.</p>
      <div id="signet-qr" style="display:flex;justify-content:center;margin-bottom:24px;"></div>
      <p style="margin:0 0 16px;color:${muted};font-size:0.8rem;">Waiting for verification...</p>
      <button id="signet-cancel" style="background:none;border:1px solid ${muted};color:${fg};padding:10px 24px;border-radius:8px;cursor:pointer;font-size:0.9rem;">Cancel</button>
    `;

    document.body.appendChild(dialog);
    dialog.showModal();

    // Generate QR code (simple SVG-based, no dependency)
    const qrContainer = dialog.querySelector<HTMLElement>('#signet-qr');
    if (qrContainer) {
      // For MVP: show the request payload as text that can be copied
      // A proper QR library should be bundled for production
      const qrPlaceholder = document.createElement('div');
      qrPlaceholder.style.cssText = `width:200px;height:200px;background:${isDark ? '#2a2a3e' : '#f0f0f0'};border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:0.75rem;color:${muted};word-break:break-all;padding:12px;`;
      qrPlaceholder.textContent = `signet:verify:${requestBase64.slice(0, 40)}...`;
      qrContainer.appendChild(qrPlaceholder);
    }

    // Listen for response via BroadcastChannel (same-device, request-specific channel)
    const channel = new BroadcastChannel('signet-verify-' + requestId);

    // Cancel handler — scoped to the dialog
    dialog.querySelector<HTMLButtonElement>('#signet-cancel')?.addEventListener('click', () => {
      channel.close();
      dialog.close(); dialog.remove(); style.remove();
      resolve({ verified: false, ageRange: null, tier: null, entityType: null, credentialId: null, verifierPubkey: null, verifierConfirmed: null, verifierMethod: null, issuedAt: null, expiresAt: null, error: 'cancelled' });
    });
    channel.onmessage = async (event) => {
      const data: unknown = event.data;
      if (typeof data !== 'object' || data === null) return;
      const response = data as Partial<PresentationResponse>;
      if (response.type !== 'signet-verify-response' || response.requestId !== requestId) return;
      if (!response.credential || typeof response.credential !== 'object' || !Array.isArray(response.credential.tags)) return;
      const credential = response.credential as PresentationResponse['credential'];

      // Verify the credential
      const valid = await verifyEventSignature(credential);
      const ageRange = getTagValue(credential.tags, 'age-range');
      const tier = getTagValue(credential.tags, 'tier');
      const entityType = getTagValue(credential.tags, 'entity-type');
      const expires = getTagValue(credential.tags, 'expires');

      const satisfied = ageRange ? ageRangeSatisfies(ageRange, opts.requiredAgeRange) : false;

      // Check verifier status against the verification bot
      const verifierStatus = await checkVerifierStatus(credential.pubkey, opts.verifierCheckUrl);
      const verifierConfirmed = verifierStatus?.confirmed ?? null;
      const verifierMethod = verifierStatus?.method ?? null;

      // By default, verified is true only when:
      // 1. Credential signature is valid
      // 2. Age range satisfies requirement
      // 3. Verifier is confirmed (unless acceptUnconfirmed is true)
      const verifierOk = opts.acceptUnconfirmed || verifierConfirmed === true;

      dialog.close(); dialog.remove(); style.remove();
      channel.close();

      const tierValue = tier ? parseInt(tier, 10) : null;
      const expiresValue = expires ? parseInt(expires, 10) : null;

      const nowSec = Math.floor(Date.now() / 1000);
      const notExpired = expiresValue === null || !isNaN(expiresValue) && expiresValue > nowSec;

      let error: string | undefined;
      if (!valid) error = 'invalid-credential';
      else if (!notExpired) error = 'credential-expired';
      else if (!satisfied) error = 'age-range-not-met';
      else if (!verifierOk) error = verifierConfirmed === false ? 'verifier-not-confirmed' : 'verifier-check-unavailable';

      resolve({
        verified: valid && notExpired && satisfied && verifierOk,
        ageRange: ageRange || null,
        tier: (tierValue !== null && !isNaN(tierValue)) ? tierValue : null,
        entityType: entityType || null,
        credentialId: credential.id,
        verifierPubkey: credential.pubkey,
        verifierConfirmed,
        verifierMethod,
        issuedAt: credential.created_at,
        expiresAt: (expiresValue !== null && !isNaN(expiresValue)) ? expiresValue : null,
        error,
      });
    };

    // Timeout
    setTimeout(() => {
      dialog.close(); dialog.remove(); style.remove();
      channel.close();
      resolve({ verified: false, ageRange: null, tier: null, entityType: null, credentialId: null, verifierPubkey: null, verifierConfirmed: null, verifierMethod: null, issuedAt: null, expiresAt: null, error: 'timeout' });
    }, opts.timeout);
  });
}

// Auto-attach to window for script-tag usage
if (typeof window !== 'undefined') {
  (window as any).Signet = { verifyAge };
}
