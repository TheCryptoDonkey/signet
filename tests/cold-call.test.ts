// Cold-call verification tests
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';

import {
  fetchInstitutionKeys,
  generateSessionCode,
  deriveColdCallWords,
  initiateColdCallVerification,
  completeColdCallVerification,
  type ColdCallSession,
} from '../src/cold-call.js';
import { deriveWords } from '../src/signet-words.js';
import type { InstitutionKeys } from '../src/types.js';
import { SignetValidationError } from '../src/errors.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Generate a random x-only secp256k1 pubkey (64-char hex). */
function randomPubkeyHex(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(priv, true); // compressed, 33 bytes
  return bytesToHex(pub).slice(2); // strip 02 prefix → 64 hex chars
}

/** Generate a random private key (64-char hex). */
function randomPrivkeyHex(): string {
  return bytesToHex(secp256k1.utils.randomPrivateKey());
}

/** Derive the corresponding x-only pubkey from a private key. */
function pubkeyFromPrivkey(privHex: string): string {
  const priv = secp256k1.utils.normPrivateKeyToScalar(BigInt('0x' + privHex));
  const pub = secp256k1.getPublicKey(priv, true);
  return bytesToHex(pub).slice(2);
}

/** Build a minimal valid InstitutionKeys response. */
function validPayload(overrides: Partial<InstitutionKeys> = {}): InstitutionKeys {
  return {
    version: 1,
    name: 'Acme Legal LLP',
    pubkeys: [
      { id: 'key-1', pubkey: 'a'.repeat(64), label: 'Primary', created: '2026-01-01T00:00:00Z' },
    ],
    ...overrides,
  };
}

// ── fetchInstitutionKeys ──────────────────────────────────────────────────────

describe('fetchInstitutionKeys', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function mockFetch(body: string, ok = true, status = 200): void {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok,
      status,
      text: async () => body,
    });
  }

  it('builds an HTTPS URL from the domain', async () => {
    mockFetch(JSON.stringify(validPayload()));
    await fetchInstitutionKeys('example.com');
    expect(globalThis.fetch).toHaveBeenCalledWith('https://example.com/.well-known/signet.json');
  });

  it('rejects responses larger than 10 KB', async () => {
    const big = JSON.stringify(validPayload()) + ' '.repeat(10241);
    mockFetch(big);
    await expect(fetchInstitutionKeys('example.com')).rejects.toThrow(SignetValidationError);
  });

  it('rejects version !== 1', async () => {
    mockFetch(JSON.stringify(validPayload({ version: 2 })));
    await expect(fetchInstitutionKeys('example.com')).rejects.toThrow(SignetValidationError);
  });

  it('rejects more than 20 pubkeys', async () => {
    const manyPubkeys = Array.from({ length: 21 }, (_, i) => ({
      id: `key-${i}`,
      pubkey: 'b'.repeat(64),
      label: `Key ${i}`,
      created: '2026-01-01T00:00:00Z',
    }));
    mockFetch(JSON.stringify(validPayload({ pubkeys: manyPubkeys })));
    await expect(fetchInstitutionKeys('example.com')).rejects.toThrow(SignetValidationError);
  });

  it('rejects pubkeys that are not 64-char hex', async () => {
    const badPubkeys = [
      { id: 'bad', pubkey: 'not-a-hex-key', label: 'Bad', created: '2026-01-01T00:00:00Z' },
    ];
    mockFetch(JSON.stringify(validPayload({ pubkeys: badPubkeys })));
    await expect(fetchInstitutionKeys('example.com')).rejects.toThrow(SignetValidationError);
  });

  it('rejects missing name field', async () => {
    const payload = validPayload();
    // @ts-expect-error intentionally invalid
    delete payload.name;
    mockFetch(JSON.stringify(payload));
    await expect(fetchInstitutionKeys('example.com')).rejects.toThrow(SignetValidationError);
  });

  it('rejects empty pubkeys array', async () => {
    mockFetch(JSON.stringify(validPayload({ pubkeys: [] })));
    await expect(fetchInstitutionKeys('example.com')).rejects.toThrow(SignetValidationError);
  });

  it('accepts a valid response and returns a typed result', async () => {
    const payload = validPayload();
    mockFetch(JSON.stringify(payload));
    const result = await fetchInstitutionKeys('example.com');
    expect(result.version).toBe(1);
    expect(result.name).toBe('Acme Legal LLP');
    expect(result.pubkeys).toHaveLength(1);
  });

  it('propagates network errors', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Network error'));
    await expect(fetchInstitutionKeys('example.com')).rejects.toThrow('Network error');
  });
});

// ── generateSessionCode ───────────────────────────────────────────────────────

describe('generateSessionCode', () => {
  it('returns a string matching WORD-NNNN format', () => {
    const pubkey = randomPubkeyHex();
    const code = generateSessionCode(pubkey);
    expect(code).toMatch(/^[A-Z]+-\d{4}$/);
  });

  it('is deterministic — same pubkey always yields same code', () => {
    const pubkey = randomPubkeyHex();
    expect(generateSessionCode(pubkey)).toBe(generateSessionCode(pubkey));
  });

  it('produces different codes for different pubkeys', () => {
    const a = randomPubkeyHex();
    const b = randomPubkeyHex();
    // Extremely unlikely to collide; if it does, regenerate
    expect(generateSessionCode(a)).not.toBe(generateSessionCode(b));
  });

  it('rejects an invalid pubkey (not 64-char hex)', () => {
    expect(() => generateSessionCode('short')).toThrow(SignetValidationError);
    expect(() => generateSessionCode('z'.repeat(64))).toThrow(SignetValidationError);
  });

  it('pads the digit segment to 4 characters', () => {
    // Run many pubkeys to check that all have exactly 4 digit chars
    for (let i = 0; i < 50; i++) {
      const code = generateSessionCode(randomPubkeyHex());
      const parts = code.split('-');
      const digits = parts[parts.length - 1];
      expect(digits).toHaveLength(4);
      expect(digits).toMatch(/^\d{4}$/);
    }
  });

  it('NATO word is from the official alphabet', () => {
    const natoWords = [
      'ALFA','BRAVO','CHARLIE','DELTA','ECHO','FOXTROT','GOLF','HOTEL',
      'INDIA','JULIET','KILO','LIMA','MIKE','NOVEMBER','OSCAR','PAPA',
      'QUEBEC','ROMEO','SIERRA','TANGO','UNIFORM','VICTOR','WHISKEY',
      'XRAY','YANKEE','ZULU',
    ];
    for (let i = 0; i < 20; i++) {
      const code = generateSessionCode(randomPubkeyHex());
      const parts = code.split('-');
      // Word is everything before the last hyphen
      const word = parts.slice(0, parts.length - 1).join('-');
      expect(natoWords).toContain(word);
    }
  });
});

// ── deriveColdCallWords ───────────────────────────────────────────────────────

describe('deriveColdCallWords', () => {
  const sharedSecret = new Uint8Array(32).fill(0x42);

  it('returns 3 words by default', () => {
    const words = deriveColdCallWords(sharedSecret, 0);
    expect(words).toHaveLength(3);
  });

  it('returns custom word counts', () => {
    expect(deriveColdCallWords(sharedSecret, 0, 1)).toHaveLength(1);
    expect(deriveColdCallWords(sharedSecret, 0, 5)).toHaveLength(5);
    expect(deriveColdCallWords(sharedSecret, 0, 16)).toHaveLength(16);
  });

  it('same secret + same counter → same words', () => {
    const a = deriveColdCallWords(sharedSecret, 100);
    const b = deriveColdCallWords(sharedSecret, 100);
    expect(a).toEqual(b);
  });

  it('different secrets → different words', () => {
    const secretA = new Uint8Array(32).fill(0x01);
    const secretB = new Uint8Array(32).fill(0x02);
    expect(deriveColdCallWords(secretA, 0)).not.toEqual(deriveColdCallWords(secretB, 0));
  });

  it('different counters → different words', () => {
    const a = deriveColdCallWords(sharedSecret, 0);
    const b = deriveColdCallWords(sharedSecret, 1);
    expect(a).not.toEqual(b);
  });

  it('uses context "signet:cold-call" — produces different words from "signet:verify"', () => {
    const coldCallWords = deriveColdCallWords(sharedSecret, 42);
    const verifyWords = deriveWords(sharedSecret, 42, 3, 'signet:verify');
    expect(coldCallWords).not.toEqual(verifyWords);
  });

  it('accepts a hex string secret', () => {
    const hexSecret = 'a'.repeat(64); // 32 bytes as hex
    const words = deriveColdCallWords(hexSecret, 0);
    expect(words).toHaveLength(3);
    expect(words.every(w => typeof w === 'string' && w.length > 0)).toBe(true);
  });
});

// ── initiateColdCallVerification / completeColdCallVerification ───────────────

describe('ECDH cold-call flow', () => {
  let institutionPrivkey: string;
  let institutionPubkey: string;

  beforeEach(() => {
    institutionPrivkey = randomPrivkeyHex();
    institutionPubkey = pubkeyFromPrivkey(institutionPrivkey);
  });

  it('initiateColdCallVerification returns a ColdCallSession object', () => {
    const session = initiateColdCallVerification(institutionPubkey);
    expect(session).toHaveProperty('ephemeralPubkey');
    expect(session).toHaveProperty('sessionCode');
    expect(session).toHaveProperty('words');
    expect(session.ephemeralPubkey).toMatch(/^[0-9a-f]{64}$/i);
    expect(session.sessionCode).toMatch(/^[A-Z]+-\d{4}$/);
    expect(session.words).toHaveLength(3);
  });

  it('institution derives the same words as the customer (round-trip)', () => {
    const session = initiateColdCallVerification(institutionPubkey);
    const institutionWords = completeColdCallVerification(
      institutionPrivkey,
      session.ephemeralPubkey,
    );
    expect(institutionWords).toEqual(session.words);
  });

  it('words do NOT match with wrong institution private key', () => {
    const session = initiateColdCallVerification(institutionPubkey);
    const wrongPrivkey = randomPrivkeyHex();
    const wrongWords = completeColdCallVerification(wrongPrivkey, session.ephemeralPubkey);
    expect(wrongWords).not.toEqual(session.words);
  });

  it('respects custom word count on both sides', () => {
    const session = initiateColdCallVerification(institutionPubkey, 5);
    expect(session.words).toHaveLength(5);
    const institutionWords = completeColdCallVerification(
      institutionPrivkey,
      session.ephemeralPubkey,
      5,
    );
    expect(institutionWords).toHaveLength(5);
    expect(institutionWords).toEqual(session.words);
  });

  it('each call generates a fresh ephemeral keypair (different sessions)', () => {
    const sessionA = initiateColdCallVerification(institutionPubkey);
    const sessionB = initiateColdCallVerification(institutionPubkey);
    // Different ephemeral pubkeys → different session codes → different words
    expect(sessionA.ephemeralPubkey).not.toBe(sessionB.ephemeralPubkey);
    expect(sessionA.sessionCode).not.toBe(sessionB.sessionCode);
    // Words may differ (different ECDH secrets) but are each individually verifiable
    const wordsA = completeColdCallVerification(institutionPrivkey, sessionA.ephemeralPubkey);
    const wordsB = completeColdCallVerification(institutionPrivkey, sessionB.ephemeralPubkey);
    expect(wordsA).toEqual(sessionA.words);
    expect(wordsB).toEqual(sessionB.words);
  });
});
