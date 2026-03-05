// Identity Bridge Tests (kind 30476)

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createIdentityBridge,
  verifyIdentityBridge,
  parseIdentityBridge,
  selectDecoyRing,
  computeBridgeWeight,
  computeTrustScore,
  createProfessionalCredential,
  MIN_BRIDGE_RING_SIZE,
  SIGNET_KINDS,
} from '../src/index.js';

// Generate a set of test keypairs
function generateKeypairs(n: number) {
  return Array.from({ length: n }, () => generateKeyPair());
}

describe('selectDecoyRing', () => {
  it('creates a ring of the correct size', () => {
    const keys = generateKeypairs(10);
    const real = keys[0];
    const candidates = keys.slice(1).map((k) => k.publicKey);

    const { ring, signerIndex } = selectDecoyRing(candidates, real.publicKey, 5);
    expect(ring).toHaveLength(5);
    expect(ring[signerIndex]).toBe(real.publicKey);
  });

  it('includes the real pubkey at signerIndex', () => {
    const keys = generateKeypairs(10);
    const real = keys[0];
    const candidates = keys.slice(1).map((k) => k.publicKey);

    for (let i = 0; i < 5; i++) {
      const { ring, signerIndex } = selectDecoyRing(candidates, real.publicKey, 5);
      expect(ring[signerIndex]).toBe(real.publicKey);
    }
  });

  it('rejects ring size below minimum', () => {
    const keys = generateKeypairs(10);
    const candidates = keys.slice(1).map((k) => k.publicKey);
    expect(() => selectDecoyRing(candidates, keys[0].publicKey, 3)).toThrow(
      'at least'
    );
  });

  it('rejects when not enough decoys', () => {
    const keys = generateKeypairs(3);
    const candidates = keys.slice(1).map((k) => k.publicKey);
    expect(() => selectDecoyRing(candidates, keys[0].publicKey, 5)).toThrow(
      'Not enough'
    );
  });

  it('filters out real pubkey from candidates', () => {
    const keys = generateKeypairs(10);
    const real = keys[0];
    // Include real pubkey in candidates - should be filtered
    const candidates = keys.map((k) => k.publicKey);

    const { ring, signerIndex } = selectDecoyRing(candidates, real.publicKey, 5);
    expect(ring).toHaveLength(5);
    // Real pubkey should appear exactly once
    expect(ring.filter((pk) => pk === real.publicKey)).toHaveLength(1);
    expect(ring[signerIndex]).toBe(real.publicKey);
  });
});

describe('computeBridgeWeight', () => {
  it('scales weight by tier', () => {
    expect(computeBridgeWeight(4)).toBe(50);
    expect(computeBridgeWeight(3)).toBeCloseTo(37.5);
    expect(computeBridgeWeight(2)).toBeCloseTo(25);
    expect(computeBridgeWeight(1)).toBeCloseTo(12.5);
  });
});

describe('createIdentityBridge', () => {
  it('creates and verifies a bridge event', async () => {
    const anon = generateKeyPair();
    const real = generateKeyPair();
    const decoys = generateKeypairs(6);
    const ring = [
      ...decoys.slice(0, 2).map((k) => k.publicKey),
      real.publicKey,
      ...decoys.slice(2).map((k) => k.publicKey),
    ];
    const signerIndex = 2; // real is at index 2

    const event = await createIdentityBridge(
      anon.privateKey,
      real.privateKey,
      ring,
      signerIndex,
      3
    );

    expect(event.kind).toBe(SIGNET_KINDS.IDENTITY_BRIDGE);
    expect(event.pubkey).toBe(anon.publicKey);

    const valid = await verifyIdentityBridge(event);
    expect(valid).toBe(true);
  });

  it('rejects ring below minimum size', async () => {
    const anon = generateKeyPair();
    const real = generateKeyPair();
    const ring = [real.publicKey, generateKeyPair().publicKey];

    await expect(
      createIdentityBridge(anon.privateKey, real.privateKey, ring, 0, 3)
    ).rejects.toThrow('at least');
  });
});

describe('verifyIdentityBridge', () => {
  it('rejects tampered content', async () => {
    const anon = generateKeyPair();
    const real = generateKeyPair();
    const decoys = generateKeypairs(6);
    const ring = [
      real.publicKey,
      ...decoys.map((k) => k.publicKey),
    ].slice(0, MIN_BRIDGE_RING_SIZE);
    // Fill if needed
    while (ring.length < MIN_BRIDGE_RING_SIZE) {
      ring.push(generateKeyPair().publicKey);
    }

    const event = await createIdentityBridge(
      anon.privateKey,
      real.privateKey,
      ring,
      0,
      3
    );

    // Tamper with content
    const tampered = { ...event, content: '{"ringSig":{"ring":[],"c0":"00","responses":[],"message":"fake"},"timestamp":0}' };
    const valid = await verifyIdentityBridge(tampered);
    expect(valid).toBe(false);
  });

  it('rejects wrong event kind', async () => {
    const anon = generateKeyPair();
    const real = generateKeyPair();
    const decoys = generateKeypairs(MIN_BRIDGE_RING_SIZE - 1);
    const ring = [real.publicKey, ...decoys.map((k) => k.publicKey)];

    const event = await createIdentityBridge(
      anon.privateKey,
      real.privateKey,
      ring,
      0,
      3
    );

    const wrongKind = { ...event, kind: 30470 };
    const valid = await verifyIdentityBridge(wrongKind);
    expect(valid).toBe(false);
  });
});

describe('parseIdentityBridge', () => {
  it('parses a valid bridge event', async () => {
    const anon = generateKeyPair();
    const real = generateKeyPair();
    const decoys = generateKeypairs(MIN_BRIDGE_RING_SIZE - 1);
    const ring = [real.publicKey, ...decoys.map((k) => k.publicKey)];

    const event = await createIdentityBridge(
      anon.privateKey,
      real.privateKey,
      ring,
      0,
      3
    );

    const parsed = parseIdentityBridge(event);
    expect(parsed).not.toBeNull();
    expect(parsed!.anonPubkey).toBe(anon.publicKey);
    expect(parsed!.ringMinTier).toBe(3);
    expect(parsed!.ringSize).toBe(MIN_BRIDGE_RING_SIZE);
    expect(parsed!.ring).toHaveLength(MIN_BRIDGE_RING_SIZE);
  });

  it('returns null for wrong kind', () => {
    const fakeEvent = {
      kind: 30470,
      pubkey: 'abc',
      created_at: 0,
      tags: [],
      content: '{}',
      id: 'x',
      sig: 'y',
    };
    expect(parseIdentityBridge(fakeEvent)).toBeNull();
  });
});

describe('trust score integration', () => {
  it('includes bridge weight in trust score', async () => {
    const anon = generateKeyPair();
    const real = generateKeyPair();
    const decoys = generateKeypairs(MIN_BRIDGE_RING_SIZE - 1);
    const ring = [real.publicKey, ...decoys.map((k) => k.publicKey)];

    const bridge = await createIdentityBridge(
      anon.privateKey,
      real.privateKey,
      ring,
      0,
      3
    );

    const breakdown = computeTrustScore(anon.publicKey, [], [], undefined, [bridge]);
    expect(breakdown.score).toBeGreaterThan(0);
    expect(breakdown.signals.some((s) => s.type === 'identity-bridge')).toBe(true);

    const bridgeSignal = breakdown.signals.find((s) => s.type === 'identity-bridge');
    expect(bridgeSignal!.weight).toBeCloseTo(37.5); // 50 * (3/4)
  });

  it('combines bridge with vouches', async () => {
    const anon = generateKeyPair();
    const real = generateKeyPair();
    const decoys = generateKeypairs(MIN_BRIDGE_RING_SIZE - 1);
    const ring = [real.publicKey, ...decoys.map((k) => k.publicKey)];

    const bridge = await createIdentityBridge(
      anon.privateKey,
      real.privateKey,
      ring,
      0,
      4
    );

    // Score with bridge only
    const withBridge = computeTrustScore(anon.publicKey, [], [], undefined, [bridge]);
    expect(withBridge.score).toBe(50); // 50 * (4/4)

    // Score without bridge
    const without = computeTrustScore(anon.publicKey, [], []);
    expect(without.score).toBe(0);
  });
});
