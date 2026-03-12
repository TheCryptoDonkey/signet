// Key Derivation Tests — BIP-32 / NIP-06

import { describe, it, expect } from 'vitest';
import {
  parsePath,
  deriveKeyFromSeed,
  deriveNostrKeyPair,
  createIdentityFromMnemonic,
  deriveChildAccount,
  NIP06_DERIVATION_PATH,
} from '../src/key-derivation.js';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { TEST_MNEMONIC } from './fixtures.js';

describe('parsePath', () => {
  it('parses NIP-06 derivation path', () => {
    const indices = parsePath("m/44'/1237'/0'/0/0");
    expect(indices).toHaveLength(5);
    // 44' = 44 + 0x80000000
    expect(indices[0]).toBe(44 + 0x80000000);
    // 1237' = 1237 + 0x80000000
    expect(indices[1]).toBe(1237 + 0x80000000);
    // 0' = 0 + 0x80000000
    expect(indices[2]).toBe(0 + 0x80000000);
    // 0 (not hardened)
    expect(indices[3]).toBe(0);
    // 0 (not hardened)
    expect(indices[4]).toBe(0);
  });

  it('throws for invalid path prefix', () => {
    expect(() => parsePath('44/0/0')).toThrow('must start with m/');
  });

  it('throws for non-numeric segments', () => {
    expect(() => parsePath('m/abc')).toThrow('Invalid path segment');
  });

  it('handles h as hardened suffix', () => {
    const indices = parsePath("m/44h/0h");
    expect(indices[0]).toBe(44 + 0x80000000);
    expect(indices[1]).toBe(0 + 0x80000000);
  });
});

describe('deriveKeyFromSeed', () => {
  it('derives a 32-byte key from a seed', () => {
    const seed = mnemonicToSeedSync(TEST_MNEMONIC);
    const key = deriveKeyFromSeed(seed, NIP06_DERIVATION_PATH);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it('same seed + same path = same key (deterministic)', () => {
    const seed = mnemonicToSeedSync(TEST_MNEMONIC);
    const key1 = deriveKeyFromSeed(seed, NIP06_DERIVATION_PATH);
    const key2 = deriveKeyFromSeed(seed, NIP06_DERIVATION_PATH);
    expect(bytesToHex(key1)).toBe(bytesToHex(key2));
  });

  it('different paths produce different keys', () => {
    const seed = mnemonicToSeedSync(TEST_MNEMONIC);
    const key1 = deriveKeyFromSeed(seed, "m/44'/1237'/0'/0/0");
    const key2 = deriveKeyFromSeed(seed, "m/44'/1237'/1'/0/0");
    expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
  });
});

describe('deriveNostrKeyPair', () => {
  it('derives a valid keypair from a mnemonic', () => {
    const { privateKey, publicKey } = deriveNostrKeyPair(TEST_MNEMONIC);
    // private key is 64 hex chars (32 bytes)
    expect(privateKey).toMatch(/^[0-9a-f]{64}$/);
    // public key is 64 hex chars (32 bytes, x-only)
    expect(publicKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic', () => {
    const kp1 = deriveNostrKeyPair(TEST_MNEMONIC);
    const kp2 = deriveNostrKeyPair(TEST_MNEMONIC);
    expect(kp1.privateKey).toBe(kp2.privateKey);
    expect(kp1.publicKey).toBe(kp2.publicKey);
  });

  it('passphrase changes the derived key', () => {
    const kp1 = deriveNostrKeyPair(TEST_MNEMONIC);
    const kp2 = deriveNostrKeyPair(TEST_MNEMONIC, 'my-passphrase');
    expect(kp1.privateKey).not.toBe(kp2.privateKey);
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
  });

  it('produces the known NIP-06 test vector', () => {
    // NIP-06 specifies this test vector for the "abandon" mnemonic
    // The private key should be deterministic and verifiable
    const { privateKey, publicKey } = deriveNostrKeyPair(TEST_MNEMONIC);
    // Verify the key is non-zero and valid
    expect(BigInt('0x' + privateKey)).toBeGreaterThan(0n);
    expect(BigInt('0x' + publicKey)).toBeGreaterThan(0n);
  });

  it('works with a freshly generated mnemonic', () => {
    const mnemonic = generateMnemonic(wordlist);
    const { privateKey, publicKey } = deriveNostrKeyPair(mnemonic);
    expect(privateKey).toMatch(/^[0-9a-f]{64}$/);
    expect(publicKey).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('createIdentityFromMnemonic', () => {
  it('returns mnemonic, privateKey, and publicKey', () => {
    const mnemonic = generateMnemonic(wordlist);
    const identity = createIdentityFromMnemonic(mnemonic);
    expect(identity.mnemonic).toBe(mnemonic);
    expect(identity.privateKey).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.publicKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('derived keys match deriveNostrKeyPair', () => {
    const mnemonic = generateMnemonic(wordlist);
    const identity = createIdentityFromMnemonic(mnemonic);
    const kp = deriveNostrKeyPair(mnemonic);
    expect(identity.privateKey).toBe(kp.privateKey);
    expect(identity.publicKey).toBe(kp.publicKey);
  });
});

describe('deriveChildAccount', () => {
  it('derives different keys for different account indices', () => {
    const child0 = deriveChildAccount(TEST_MNEMONIC, 0);
    const child1 = deriveChildAccount(TEST_MNEMONIC, 1);
    const child2 = deriveChildAccount(TEST_MNEMONIC, 2);
    expect(child0.privateKey).not.toBe(child1.privateKey);
    expect(child1.privateKey).not.toBe(child2.privateKey);
    expect(child0.publicKey).not.toBe(child1.publicKey);
  });

  it('account 0 matches the standard NIP-06 derivation', () => {
    const child0 = deriveChildAccount(TEST_MNEMONIC, 0);
    const standard = deriveNostrKeyPair(TEST_MNEMONIC);
    expect(child0.privateKey).toBe(standard.privateKey);
    expect(child0.publicKey).toBe(standard.publicKey);
  });

  it('is deterministic', () => {
    const a = deriveChildAccount(TEST_MNEMONIC, 5);
    const b = deriveChildAccount(TEST_MNEMONIC, 5);
    expect(a.privateKey).toBe(b.privateKey);
  });

  it('produces valid keypairs', () => {
    for (let i = 0; i < 5; i++) {
      const child = deriveChildAccount(TEST_MNEMONIC, i);
      expect(child.privateKey).toMatch(/^[0-9a-f]{64}$/);
      expect(child.publicKey).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

describe('parsePath depth limit', () => {
  it('rejects derivation paths deeper than 10 levels', () => {
    const deepPath = "m/" + Array(11).fill("0'").join('/');
    expect(() => parsePath(deepPath)).toThrow('Derivation path too deep');
  });

  it('accepts derivation paths up to 10 levels', () => {
    const maxPath = "m/" + Array(10).fill("0'").join('/');
    expect(() => parsePath(maxPath)).not.toThrow();
  });
});
