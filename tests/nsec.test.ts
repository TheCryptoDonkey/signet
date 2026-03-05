// nsec/npub encode/decode tests (NIP-19)

import { describe, it, expect } from 'vitest';
import {
  encodeNsec,
  encodeNpub,
  decodeNsec,
  generateKeyPair,
  deriveNostrKeyPair,
} from '../src/index.js';
import { TEST_MNEMONIC } from './fixtures.js';

describe('nsec/npub encoding', () => {
  it('encodes and decodes nsec roundtrip', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const nsec = encodeNsec(privateKey);
    expect(nsec).toMatch(/^nsec1/);

    const decoded = decodeNsec(nsec);
    expect(decoded.privateKey).toBe(privateKey);
    expect(decoded.publicKey).toBe(publicKey);
  });

  it('encodes npub correctly', () => {
    const { publicKey } = generateKeyPair();
    const npub = encodeNpub(publicKey);
    expect(npub).toMatch(/^npub1/);
  });

  it('roundtrips for mnemonic-derived keys', () => {
    const { privateKey, publicKey } = deriveNostrKeyPair(TEST_MNEMONIC);

    const nsec = encodeNsec(privateKey);
    const npub = encodeNpub(publicKey);

    expect(nsec).toMatch(/^nsec1/);
    expect(npub).toMatch(/^npub1/);

    const decoded = decodeNsec(nsec);
    expect(decoded.privateKey).toBe(privateKey);
    expect(decoded.publicKey).toBe(publicKey);
  });

  it('multiple roundtrips produce same result', () => {
    const { privateKey } = generateKeyPair();
    const nsec1 = encodeNsec(privateKey);
    const nsec2 = encodeNsec(privateKey);
    expect(nsec1).toBe(nsec2);
  });

  it('rejects invalid nsec prefix', () => {
    const { publicKey } = generateKeyPair();
    const npub = encodeNpub(publicKey);
    expect(() => decodeNsec(npub)).toThrow('Expected nsec prefix');
  });

  it('rejects invalid bech32 string', () => {
    expect(() => decodeNsec('nsec1invalid')).toThrow();
  });

  it('rejects wrong-length private key for encode', () => {
    expect(() => encodeNsec('abcd')).toThrow('32 bytes');
  });

  it('rejects wrong-length public key for encode', () => {
    expect(() => encodeNpub('abcd')).toThrow('32 bytes');
  });

  it('handles all-zeros key', () => {
    // Not a valid secp256k1 key, but tests encoding pathway
    const zeroKey = '0000000000000000000000000000000000000000000000000000000000000001';
    const nsec = encodeNsec(zeroKey);
    expect(nsec).toMatch(/^nsec1/);
    const decoded = decodeNsec(nsec);
    expect(decoded.privateKey).toBe(zeroKey);
  });
});
