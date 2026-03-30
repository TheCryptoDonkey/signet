import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../src/crypto.js';
import { createVerifierCredential, parseVerifier, buildVerifierEvent } from '../src/verifiers.js';
import {
  buildBondMessage,
  createBondProof,
  verifyBondProof,
  isBondStale,
  bondProofToTags,
  parseBondProof,
  checkBondCompliance,
} from '../src/bonds.js';
import { validateVerifier } from '../src/validation.js';
import {
  BOND_DOMAIN_SEPARATOR,
  DEFAULT_BOND_MAX_AGE_SECS,
} from '../src/constants.js';
import type { BondProof, BIP322Verifier } from '../src/types.js';

const SAMPLE_ADDRESS = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const SAMPLE_SIG = 'AkDummySig==';

function makeBondProof(overrides: Partial<BondProof> = {}): BondProof {
  const verifier = generateKeyPair();
  const timestamp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
  const message = buildBondMessage(verifier.publicKey, 100_000, timestamp);
  return {
    address: SAMPLE_ADDRESS,
    addressType: 'p2wpkh',
    amountSats: 100_000,
    timestamp,
    message,
    signature: SAMPLE_SIG,
    ...overrides,
  };
}

describe('buildBondMessage', () => {
  it('returns the expected format', () => {
    const msg = buildBondMessage('deadbeef', 50_000, 1_700_000_000);
    expect(msg).toBe(`${BOND_DOMAIN_SEPARATOR}:deadbeef:50000:1700000000`);
  });

  it('is deterministic', () => {
    const a = buildBondMessage('aabbcc', 1000, 9999);
    const b = buildBondMessage('aabbcc', 1000, 9999);
    expect(a).toBe(b);
  });

  it('differs when any parameter changes', () => {
    const base = buildBondMessage('pubkey', 1000, 9999);
    expect(buildBondMessage('other', 1000, 9999)).not.toBe(base);
    expect(buildBondMessage('pubkey', 2000, 9999)).not.toBe(base);
    expect(buildBondMessage('pubkey', 1000, 8888)).not.toBe(base);
  });
});

describe('createBondProof', () => {
  it('populates all required fields', () => {
    const verifier = generateKeyPair();
    const timestamp = Math.floor(Date.now() / 1000);
    const proof = createBondProof({
      address: SAMPLE_ADDRESS,
      addressType: 'p2wpkh',
      amountSats: 200_000,
      signature: SAMPLE_SIG,
      verifierPubkey: verifier.publicKey,
      timestamp,
    });

    expect(proof.address).toBe(SAMPLE_ADDRESS);
    expect(proof.addressType).toBe('p2wpkh');
    expect(proof.amountSats).toBe(200_000);
    expect(proof.timestamp).toBe(timestamp);
    expect(proof.signature).toBe(SAMPLE_SIG);
    expect(proof.message).toBe(buildBondMessage(verifier.publicKey, 200_000, timestamp));
  });

  it('defaults timestamp to current time when not provided', () => {
    const verifier = generateKeyPair();
    const before = Math.floor(Date.now() / 1000);
    const proof = createBondProof({
      address: SAMPLE_ADDRESS,
      addressType: 'p2tr',
      amountSats: 50_000,
      signature: SAMPLE_SIG,
      verifierPubkey: verifier.publicKey,
    });
    const after = Math.floor(Date.now() / 1000);
    expect(proof.timestamp).toBeGreaterThanOrEqual(before);
    expect(proof.timestamp).toBeLessThanOrEqual(after);
  });
});

describe('bondProofToTags / parseBondProof round-trip', () => {
  it('produces exactly 6 tags', () => {
    const proof = makeBondProof();
    const tags = bondProofToTags(proof);
    expect(tags).toHaveLength(6);
  });

  it('tag names are correct', () => {
    const proof = makeBondProof();
    const tags = bondProofToTags(proof);
    const names = tags.map((t) => t[0]);
    expect(names).toEqual([
      'bond-address',
      'bond-address-type',
      'bond-amount',
      'bond-timestamp',
      'bond-message',
      'bond-signature',
    ]);
  });

  it('round-trips through parseBondProof', () => {
    const proof = makeBondProof();
    const tags = bondProofToTags(proof);
    const parsed = parseBondProof({ tags });
    expect(parsed).not.toBeNull();
    expect(parsed!.address).toBe(proof.address);
    expect(parsed!.addressType).toBe(proof.addressType);
    expect(parsed!.amountSats).toBe(proof.amountSats);
    expect(parsed!.timestamp).toBe(proof.timestamp);
    expect(parsed!.message).toBe(proof.message);
    expect(parsed!.signature).toBe(proof.signature);
  });

  it('parseBondProof returns null when no bond-address tag present', () => {
    const result = parseBondProof({ tags: [['type', 'verifier']] });
    expect(result).toBeNull();
  });

  it('parseBondProof returns null when bond tags are incomplete', () => {
    const result = parseBondProof({
      tags: [
        ['bond-address', SAMPLE_ADDRESS],
        // missing the other 5 tags
      ],
    });
    expect(result).toBeNull();
  });
});

describe('isBondStale', () => {
  it('fresh proof (1 day old) is not stale', () => {
    const now = Math.floor(Date.now() / 1000);
    const proof = makeBondProof({ timestamp: now - 86_400 });
    expect(isBondStale(proof, DEFAULT_BOND_MAX_AGE_SECS, now)).toBe(false);
  });

  it('old proof (31 days) is stale with default max age', () => {
    const now = Math.floor(Date.now() / 1000);
    const proof = makeBondProof({ timestamp: now - 31 * 86_400 });
    expect(isBondStale(proof, DEFAULT_BOND_MAX_AGE_SECS, now)).toBe(true);
  });

  it('respects custom maxAgeSecs', () => {
    const now = Math.floor(Date.now() / 1000);
    const proof = makeBondProof({ timestamp: now - 3_600 }); // 1 hour ago
    expect(isBondStale(proof, 1_800, now)).toBe(true);   // 30 min max → stale
    expect(isBondStale(proof, 7_200, now)).toBe(false);  // 2 hour max → fresh
  });
});

describe('verifyBondProof', () => {
  describe('structural validation', () => {
    it('rejects mismatched verifier pubkey (wrong message)', async () => {
      const proof = makeBondProof();
      const wrongPubkey = generateKeyPair().publicKey;
      const result = await verifyBondProof(proof, wrongPubkey);
      expect(result.status).toBe('invalid');
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.includes('message does not match'))).toBe(true);
    });

    it('rejects proof with future timestamp', async () => {
      const verifier = generateKeyPair();
      const futureTs = Math.floor(Date.now() / 1000) + 9999;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: futureTs,
        message: buildBondMessage(verifier.publicKey, 100_000, futureTs),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey);
      expect(result.status).toBe('invalid');
      expect(result.errors.some((e) => e.includes('future'))).toBe(true);
    });

    it('rejects zero amount', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 0,
        timestamp: now - 60,
        message: buildBondMessage(verifier.publicKey, 0, now - 60),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey);
      expect(result.status).toBe('invalid');
      expect(result.errors.some((e) => e.includes('positive'))).toBe(true);
    });

    it('rejects empty address', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const proof: BondProof = {
        address: '',
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: now - 60,
        message: buildBondMessage(verifier.publicKey, 100_000, now - 60),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey);
      expect(result.status).toBe('invalid');
      expect(result.errors.some((e) => e.includes('address'))).toBe(true);
    });

    it('rejects empty signature', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: now - 60,
        message: buildBondMessage(verifier.publicKey, 100_000, now - 60),
        signature: '',
      };
      const result = await verifyBondProof(proof, verifier.publicKey);
      expect(result.status).toBe('invalid');
      expect(result.errors.some((e) => e.includes('signature'))).toBe(true);
    });
  });

  describe('freshness', () => {
    it('1-day-old proof is fresh', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 86_400;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey, { now });
      expect(result.fresh).toBe(true);
    });

    it('31-day-old proof is stale', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 31 * 86_400;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey, { now });
      expect(result.fresh).toBe(false);
      expect(result.status).toBe('stale');
    });

    it('respects custom maxAgeSecs', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 3_600; // 1 hour ago
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const staleResult = await verifyBondProof(proof, verifier.publicKey, { maxAgeSecs: 1_800, now });
      expect(staleResult.fresh).toBe(false);

      const freshResult = await verifyBondProof(proof, verifier.publicKey, { maxAgeSecs: 7_200, now });
      expect(freshResult.fresh).toBe(true);
    });
  });

  describe('signature callback', () => {
    it('status is unverified when no verifier provided', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 60;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey, { now });
      expect(result.status).toBe('unverified');
      expect(result.signatureValid).toBeNull();
    });

    it('status is valid when verifier returns true', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 60;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const mockVerifier: BIP322Verifier = () => true;
      const result = await verifyBondProof(proof, verifier.publicKey, { verifier: mockVerifier, now });
      expect(result.status).toBe('valid');
      expect(result.signatureValid).toBe(true);
    });

    it('status is invalid when verifier returns false', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 60;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const mockVerifier: BIP322Verifier = () => false;
      const result = await verifyBondProof(proof, verifier.publicKey, { verifier: mockVerifier, now });
      expect(result.status).toBe('invalid');
      expect(result.signatureValid).toBe(false);
    });

    it('async verifier works correctly', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 60;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const asyncVerifier: BIP322Verifier = async () => {
        await new Promise((r) => setTimeout(r, 1));
        return true;
      };
      const result = await verifyBondProof(proof, verifier.publicKey, { verifier: asyncVerifier, now });
      expect(result.status).toBe('valid');
      expect(result.signatureValid).toBe(true);
    });
  });

  describe('meetsThreshold', () => {
    it('returns null when requiredSats not provided', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 60;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey, { now });
      expect(result.meetsThreshold).toBeNull();
    });

    it('returns true when amount meets threshold', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 60;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 100_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 100_000, ts),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey, { now, requiredSats: 50_000 });
      expect(result.meetsThreshold).toBe(true);
    });

    it('returns false when amount is below threshold', async () => {
      const verifier = generateKeyPair();
      const now = Math.floor(Date.now() / 1000);
      const ts = now - 60;
      const proof: BondProof = {
        address: SAMPLE_ADDRESS,
        addressType: 'p2wpkh',
        amountSats: 10_000,
        timestamp: ts,
        message: buildBondMessage(verifier.publicKey, 10_000, ts),
        signature: SAMPLE_SIG,
      };
      const result = await verifyBondProof(proof, verifier.publicKey, { now, requiredSats: 50_000 });
      expect(result.meetsThreshold).toBe(false);
    });
  });
});

describe('checkBondCompliance', () => {
  it('returns meets: true when amount meets threshold', () => {
    const proof = makeBondProof({ amountSats: 200_000 });
    const result = checkBondCompliance(proof, 100_000);
    expect(result.meets).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('returns meets: false when amount is below threshold', () => {
    const proof = makeBondProof({ amountSats: 50_000 });
    const result = checkBondCompliance(proof, 100_000);
    expect(result.meets).toBe(false);
    expect(result.reason).toBeDefined();
    expect(result.reason).toContain('50000');
    expect(result.reason).toContain('100000');
  });

  it('returns meets: false when proof is null', () => {
    const result = checkBondCompliance(null, 100_000);
    expect(result.meets).toBe(false);
    expect(result.reason).toBeDefined();
  });

  it('meets: true at exact threshold', () => {
    const proof = makeBondProof({ amountSats: 100_000 });
    const result = checkBondCompliance(proof, 100_000);
    expect(result.meets).toBe(true);
  });
});

describe('integration: verifier credentials with bond proof', () => {
  it('buildVerifierEvent includes bond tags when bondProof provided', () => {
    const verifier = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const ts = now - 60;
    const bondProof: BondProof = {
      address: SAMPLE_ADDRESS,
      addressType: 'p2wpkh',
      amountSats: 500_000,
      timestamp: ts,
      message: buildBondMessage(verifier.publicKey, 500_000, ts),
      signature: SAMPLE_SIG,
    };

    const event = buildVerifierEvent(verifier.publicKey, {
      profession: 'solicitor',
      jurisdiction: 'GB',
      licenceHash: 'hash123',
      professionalBody: 'Law Society',
      bondProof,
    });

    const tags = event.tags;
    const getTag = (name: string) => tags.find((t) => t[0] === name)?.[1];

    expect(getTag('bond-address')).toBe(SAMPLE_ADDRESS);
    expect(getTag('bond-address-type')).toBe('p2wpkh');
    expect(getTag('bond-amount')).toBe('500000');
    expect(getTag('bond-timestamp')).toBe(String(ts));
    expect(getTag('bond-message')).toBe(bondProof.message);
    expect(getTag('bond-signature')).toBe(SAMPLE_SIG);
  });

  it('buildVerifierEvent excludes bond tags when no bondProof', () => {
    const verifier = generateKeyPair();
    const event = buildVerifierEvent(verifier.publicKey, {
      profession: 'solicitor',
      jurisdiction: 'GB',
      licenceHash: 'hash123',
      professionalBody: 'Law Society',
    });

    expect(event.tags.find((t) => t[0] === 'bond-address')).toBeUndefined();
  });

  it('parseVerifier extracts bondProof when present', async () => {
    const verifier = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const ts = now - 60;
    const bondProof: BondProof = {
      address: SAMPLE_ADDRESS,
      addressType: 'p2tr',
      amountSats: 1_000_000,
      timestamp: ts,
      message: buildBondMessage(verifier.publicKey, 1_000_000, ts),
      signature: SAMPLE_SIG,
    };

    const cred = await createVerifierCredential(verifier.privateKey, {
      profession: 'doctor',
      jurisdiction: 'GB',
      licenceHash: 'medHash',
      professionalBody: 'GMC',
      bondProof,
    });

    const parsed = parseVerifier(cred);
    expect(parsed).not.toBeNull();
    expect(parsed!.bondProof).toBeDefined();
    expect(parsed!.bondProof!.address).toBe(SAMPLE_ADDRESS);
    expect(parsed!.bondProof!.addressType).toBe('p2tr');
    expect(parsed!.bondProof!.amountSats).toBe(1_000_000);
  });

  it('parseVerifier has undefined bondProof when no bond tags', async () => {
    const verifier = generateKeyPair();
    const cred = await createVerifierCredential(verifier.privateKey, {
      profession: 'doctor',
      jurisdiction: 'GB',
      licenceHash: 'medHash',
      professionalBody: 'GMC',
    });

    const parsed = parseVerifier(cred);
    expect(parsed).not.toBeNull();
    expect(parsed!.bondProof).toBeUndefined();
  });
});

describe('validation: validateVerifier with bond tags', () => {
  it('passes when no bond tags present', async () => {
    const verifier = generateKeyPair();
    const cred = await createVerifierCredential(verifier.privateKey, {
      profession: 'solicitor',
      jurisdiction: 'GB',
      licenceHash: 'hash123',
      professionalBody: 'Law Society',
    });
    const result = validateVerifier(cred);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('passes when all 6 bond tags are present and valid', async () => {
    const verifier = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const ts = now - 60;
    const bondProof: BondProof = {
      address: SAMPLE_ADDRESS,
      addressType: 'p2wpkh',
      amountSats: 100_000,
      timestamp: ts,
      message: buildBondMessage(verifier.publicKey, 100_000, ts),
      signature: SAMPLE_SIG,
    };
    const cred = await createVerifierCredential(verifier.privateKey, {
      profession: 'solicitor',
      jurisdiction: 'GB',
      licenceHash: 'hash123',
      professionalBody: 'Law Society',
      bondProof,
    });
    const result = validateVerifier(cred);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('fails when bond tags are incomplete (bond-address present but others missing)', async () => {
    const verifier = generateKeyPair();
    const cred = await createVerifierCredential(verifier.privateKey, {
      profession: 'solicitor',
      jurisdiction: 'GB',
      licenceHash: 'hash123',
      professionalBody: 'Law Society',
    });

    // Manually inject a lone bond-address tag
    const tamperedEvent = {
      ...cred,
      tags: [...cred.tags, ['bond-address', SAMPLE_ADDRESS]],
    };

    // Re-cast as NostrEvent (signature won't verify but structure is testable)
    const result = validateVerifier(tamperedEvent as typeof cred);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('bond-address-type'))).toBe(true);
  });

  it('fails when bond-address-type is invalid', async () => {
    const verifier = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const ts = now - 60;
    const cred = await createVerifierCredential(verifier.privateKey, {
      profession: 'solicitor',
      jurisdiction: 'GB',
      licenceHash: 'hash123',
      professionalBody: 'Law Society',
    });

    const tamperedEvent = {
      ...cred,
      tags: [
        ...cred.tags,
        ['bond-address', SAMPLE_ADDRESS],
        ['bond-address-type', 'p2invalid'],
        ['bond-amount', '100000'],
        ['bond-timestamp', String(ts)],
        ['bond-message', `signet:bond:${verifier.publicKey}:100000:${ts}`],
        ['bond-signature', SAMPLE_SIG],
      ],
    };

    const result = validateVerifier(tamperedEvent as typeof cred);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('bond-address-type'))).toBe(true);
  });
});
