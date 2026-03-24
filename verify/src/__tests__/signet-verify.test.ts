import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

import {
  verifyEventSignature,
  ageRangeSatisfies,
  escapeHtml,
  getTagValue,
  generateRequestId,
  checkVerifierStatus,
} from '../internals';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A minimal valid kind 31000 credential shape used throughout the tests. */
type Credential = {
  id: string;
  kind: number;
  pubkey: string;
  created_at: number;
  tags: string[][];
  content: string;
  sig: string;
};

const VALID_TAGS: string[][] = [
  ['tier', '3'],
  ['age-range', '18+'],
  ['entity-type', 'natural-person'],
];

/**
 * Build and cryptographically sign a kind 31000 credential.
 * Uses real BIP-340 Schnorr signatures via @noble/curves so that
 * verifyEventSignature's cryptographic check is exercised.
 */
function createSignedEvent(
  privateKeyHex: string,
  kind: number,
  tags: string[][],
  content: string,
): Credential {
  const pubkey = bytesToHex(schnorr.getPublicKey(privateKeyHex));
  const created_at = Math.floor(Date.now() / 1000);
  const serialized = JSON.stringify([0, pubkey, created_at, kind, tags, content]);
  const msgBytes = sha256(new TextEncoder().encode(serialized));
  const id = bytesToHex(msgBytes);
  const sig = bytesToHex(schnorr.sign(msgBytes, privateKeyHex));
  return { id, kind, pubkey, created_at, tags, content, sig };
}

// A deterministic 32-byte private key for tests — never use in production.
const TEST_PRIVATE_KEY = 'a'.repeat(64);

// ---------------------------------------------------------------------------
// verifyEventSignature
// ---------------------------------------------------------------------------

describe('verifyEventSignature', () => {
  it('accepts a well-formed event with a valid Schnorr signature', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, '');
    const result = await verifyEventSignature(event);
    expect(result).toBe(true);
  });

  it('rejects an event whose kind is not 31000', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 1, VALID_TAGS, '');
    // Force kind to something other than 31000 without changing the signature
    const tampered = { ...event, kind: 1 };
    const result = await verifyEventSignature(tampered);
    expect(result).toBe(false);
  });

  it('rejects an event with a tampered id', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, '');
    const tampered = { ...event, id: 'b'.repeat(64) };
    const result = await verifyEventSignature(tampered);
    expect(result).toBe(false);
  });

  it('rejects an event with a tampered signature', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, '');
    // Flip the last character of the signature
    const lastChar = event.sig.slice(-1);
    const flipped = lastChar === 'f' ? '0' : 'f';
    const tampered = { ...event, sig: event.sig.slice(0, -1) + flipped };
    const result = await verifyEventSignature(tampered);
    expect(result).toBe(false);
  });

  it('rejects an event missing the tier tag', async () => {
    const tags = [['age-range', '18+'], ['entity-type', 'natural-person']];
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, tags, '');
    const result = await verifyEventSignature(event);
    expect(result).toBe(false);
  });

  it('rejects an event missing the age-range tag', async () => {
    const tags = [['tier', '3'], ['entity-type', 'natural-person']];
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, tags, '');
    const result = await verifyEventSignature(event);
    expect(result).toBe(false);
  });

  it('rejects an event missing the entity-type tag', async () => {
    const tags = [['tier', '3'], ['age-range', '18+']];
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, tags, '');
    const result = await verifyEventSignature(event);
    expect(result).toBe(false);
  });

  it('rejects an event whose content exceeds 64 KB', async () => {
    const oversizedContent = 'x'.repeat(65537);
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, oversizedContent);
    const result = await verifyEventSignature(event);
    expect(result).toBe(false);
  });

  it('rejects an event with more than 100 tags', async () => {
    const manyTags = Array.from({ length: 101 }, (_, i) => ['extra', String(i)]);
    const tags = [...VALID_TAGS, ...manyTags];
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, tags, '');
    const result = await verifyEventSignature(event);
    expect(result).toBe(false);
  });

  it('rejects an event containing a tag value longer than 1024 characters', async () => {
    const longValue = 'v'.repeat(1025);
    const tags = [...VALID_TAGS, ['note', longValue]];
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, tags, '');
    const result = await verifyEventSignature(event);
    expect(result).toBe(false);
  });

  it('rejects an event whose pubkey contains non-hex characters', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, '');
    const tampered = { ...event, pubkey: 'z'.repeat(64) };
    const result = await verifyEventSignature(tampered);
    expect(result).toBe(false);
  });

  it('rejects an event whose id contains non-hex characters', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, '');
    const tampered = { ...event, id: 'z'.repeat(64) };
    const result = await verifyEventSignature(tampered);
    expect(result).toBe(false);
  });

  it('rejects an event whose sig contains non-hex characters', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, '');
    const tampered = { ...event, sig: 'z'.repeat(128) };
    const result = await verifyEventSignature(tampered);
    expect(result).toBe(false);
  });

  it('rejects an event with a pubkey that is the wrong length', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, '');
    const tampered = { ...event, pubkey: event.pubkey.slice(0, 32) };
    const result = await verifyEventSignature(tampered);
    expect(result).toBe(false);
  });

  it('rejects an event with a sig that is the wrong length', async () => {
    const event = createSignedEvent(TEST_PRIVATE_KEY, 31000, VALID_TAGS, '');
    const tampered = { ...event, sig: event.sig.slice(0, 64) };
    const result = await verifyEventSignature(tampered);
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ageRangeSatisfies
// ---------------------------------------------------------------------------

describe('ageRangeSatisfies', () => {
  it("returns true when credential range is '18+' and required range is '18+'", () => {
    expect(ageRangeSatisfies('18+', '18+')).toBe(true);
  });

  it("returns false when credential range '13-17' is presented for '18+' requirement", () => {
    expect(ageRangeSatisfies('13-17', '18+')).toBe(false);
  });

  it("returns false when credential range '8-12' is presented for '18+' requirement", () => {
    expect(ageRangeSatisfies('8-12', '18+')).toBe(false);
  });

  it("returns false when credential range '18+' is presented for '13-17' requirement", () => {
    expect(ageRangeSatisfies('18+', '13-17')).toBe(false);
  });

  it('returns false for an unknown credential range', () => {
    expect(ageRangeSatisfies('21+', '18+')).toBe(false);
  });

  it('returns false for an unknown required range', () => {
    expect(ageRangeSatisfies('18+', '16+')).toBe(false);
  });

  it('returns true when credential range exactly matches required range for each valid range', () => {
    const validRanges = ['0-3', '4-7', '8-12', '13-17', '18+'];
    for (const range of validRanges) {
      expect(ageRangeSatisfies(range, range)).toBe(true);
    }
  });

  it("returns false when credential range '0-3' is presented for '8-12' requirement", () => {
    expect(ageRangeSatisfies('0-3', '8-12')).toBe(false);
  });

  it("returns false when credential range '4-7' is presented for '13-17' requirement", () => {
    expect(ageRangeSatisfies('4-7', '13-17')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// escapeHtml
// ---------------------------------------------------------------------------

describe('escapeHtml', () => {
  it('escapes < to &lt;', () => {
    expect(escapeHtml('<')).toBe('&lt;');
  });

  it('escapes > to &gt;', () => {
    expect(escapeHtml('>')).toBe('&gt;');
  });

  it('escapes & to &amp;', () => {
    expect(escapeHtml('&')).toBe('&amp;');
  });

  it('escapes " to &quot;', () => {
    expect(escapeHtml('"')).toBe('&quot;');
  });

  it('escapes a string containing all four special characters', () => {
    expect(escapeHtml('<div class="a&b">')).toBe('&lt;div class=&quot;a&amp;b&quot;&gt;');
  });

  it('leaves ordinary text unchanged', () => {
    expect(escapeHtml('Hello, world!')).toBe('Hello, world!');
  });

  it('returns an empty string unchanged', () => {
    expect(escapeHtml('')).toBe('');
  });

  it('handles a realistic XSS injection attempt', () => {
    const input = '<script>alert("xss")</script>';
    const output = escapeHtml(input);
    expect(output).not.toContain('<script>');
    expect(output).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
  });
});

// ---------------------------------------------------------------------------
// getTagValue
// ---------------------------------------------------------------------------

describe('getTagValue', () => {
  const tags: string[][] = [
    ['tier', '3'],
    ['age-range', '18+'],
    ['entity-type', 'natural-person'],
    ['note', 'first-note'],
    ['note', 'second-note'],
  ];

  it('returns the value for a tag that exists', () => {
    expect(getTagValue(tags, 'tier')).toBe('3');
  });

  it('returns undefined for a tag that does not exist', () => {
    expect(getTagValue(tags, 'expires')).toBeUndefined();
  });

  it('returns the first match when multiple tags share the same name', () => {
    expect(getTagValue(tags, 'note')).toBe('first-note');
  });

  it('handles an empty tags array', () => {
    expect(getTagValue([], 'tier')).toBeUndefined();
  });

  it('handles a tag with no value element', () => {
    const sparseTag: string[][] = [['tier']];
    expect(getTagValue(sparseTag, 'tier')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// generateRequestId
// ---------------------------------------------------------------------------

describe('generateRequestId', () => {
  it('returns a 32-character hex string', () => {
    const id = generateRequestId();
    expect(id).toHaveLength(32);
    expect(/^[0-9a-f]{32}$/.test(id)).toBe(true);
  });

  it('produces a different value on each call', () => {
    const id1 = generateRequestId();
    const id2 = generateRequestId();
    expect(id1).not.toBe(id2);
  });

  it('produces only lowercase hex digits', () => {
    for (let i = 0; i < 10; i++) {
      const id = generateRequestId();
      expect(/^[0-9a-f]+$/.test(id)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// checkVerifierStatus
// ---------------------------------------------------------------------------

describe('checkVerifierStatus', () => {
  const VALID_PUBKEY = 'a'.repeat(64);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns null when checkUrl is null', async () => {
    const result = await checkVerifierStatus(VALID_PUBKEY, null);
    expect(result).toBeNull();
  });

  it('returns null when checkUrl is undefined', async () => {
    const result = await checkVerifierStatus(VALID_PUBKEY, undefined);
    expect(result).toBeNull();
  });

  it('returns null for a non-https URL', async () => {
    const result = await checkVerifierStatus(VALID_PUBKEY, 'http://verify.example.com');
    expect(result).toBeNull();
  });

  it('returns null for a plain string that is not a URL', async () => {
    const result = await checkVerifierStatus(VALID_PUBKEY, 'not-a-url');
    expect(result).toBeNull();
  });

  it('returns null when the verifier pubkey is not 64 hex characters', async () => {
    const result = await checkVerifierStatus('deadbeef', 'https://verify.signet.forgesworn.dev');
    expect(result).toBeNull();
  });

  it('returns null when the verifier pubkey contains non-hex characters', async () => {
    const result = await checkVerifierStatus('z'.repeat(64), 'https://verify.signet.forgesworn.dev');
    expect(result).toBeNull();
  });

  it('returns null when the bot responds with a non-ok HTTP status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, json: async () => ({}) }));
    const result = await checkVerifierStatus(VALID_PUBKEY, 'https://verify.signet.forgesworn.dev');
    expect(result).toBeNull();
  });

  it('returns null when the bot throws (e.g. network error)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network error')));
    const result = await checkVerifierStatus(VALID_PUBKEY, 'https://verify.signet.forgesworn.dev');
    expect(result).toBeNull();
  });

  it('returns a VerifierStatus with confirmed=true when the bot confirms the verifier', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ confirmed: true, method: 'A', profession: 'Doctor', jurisdiction: 'GB' }),
    }));
    const result = await checkVerifierStatus(VALID_PUBKEY, 'https://verify.signet.forgesworn.dev');
    expect(result).not.toBeNull();
    expect(result!.confirmed).toBe(true);
    expect(result!.method).toBe('A');
    expect(result!.profession).toBe('Doctor');
    expect(result!.jurisdiction).toBe('GB');
  });

  it('returns a VerifierStatus with confirmed=false when the bot denies the verifier', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ confirmed: false, method: null }),
    }));
    const result = await checkVerifierStatus(VALID_PUBKEY, 'https://verify.signet.forgesworn.dev');
    expect(result).not.toBeNull();
    expect(result!.confirmed).toBe(false);
    expect(result!.method).toBeNull();
  });

  it('sets method to null for an unrecognised method value from the bot', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ confirmed: true, method: 'Z' }),
    }));
    const result = await checkVerifierStatus(VALID_PUBKEY, 'https://verify.signet.forgesworn.dev');
    expect(result).not.toBeNull();
    expect(result!.method).toBeNull();
  });

  it('returns null when the bot response body is not an object', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => 'unexpected string',
    }));
    const result = await checkVerifierStatus(VALID_PUBKEY, 'https://verify.signet.forgesworn.dev');
    expect(result).toBeNull();
  });

  it('calls the bot at the correct URL path including the pubkey', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ confirmed: true, method: 'B' }),
    });
    vi.stubGlobal('fetch', mockFetch);
    const checkUrl = 'https://verify.signet.forgesworn.dev';
    await checkVerifierStatus(VALID_PUBKEY, checkUrl);
    expect(mockFetch).toHaveBeenCalledWith(
      `${checkUrl}/status/${VALID_PUBKEY}`,
      expect.objectContaining({ signal: expect.anything() }),
    );
  });

  it('accepts all four valid method values (A, B, C, D) from the bot', async () => {
    for (const method of ['A', 'B', 'C', 'D'] as const) {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ confirmed: true, method }),
      }));
      const result = await checkVerifierStatus(VALID_PUBKEY, 'https://verify.signet.forgesworn.dev');
      expect(result!.method).toBe(method);
    }
  });
});
