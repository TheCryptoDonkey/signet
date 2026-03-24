import { describe, it, expect } from 'vitest';
import {
  createNewIdentity,
  importFromMnemonic,
  getActivePubkey,
  getActivePrivateKey,
  validateMnemonic,
} from '../signet';

// A valid BIP-39 mnemonic for deterministic import tests
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('createNewIdentity', () => {
  it('returns an identity with valid hex pubkeys (64 characters each)', () => {
    const identity = createNewIdentity('Alice', 'natural-person', false);
    expect(identity.naturalPerson.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.persona.publicKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('natural person and persona have different public keys', () => {
    const identity = createNewIdentity('Alice', 'natural-person', false);
    expect(identity.naturalPerson.publicKey).not.toBe(identity.persona.publicKey);
  });

  it('natural person and persona have different private keys', () => {
    const identity = createNewIdentity('Alice', 'natural-person', false);
    expect(identity.naturalPerson.privateKey).not.toBe(identity.persona.privateKey);
  });

  it('primaryKeypair flag is set correctly when natural-person', () => {
    const identity = createNewIdentity('Alice', 'natural-person', false);
    expect(identity.primaryKeypair).toBe('natural-person');
  });

  it('primaryKeypair flag is set correctly when persona', () => {
    const identity = createNewIdentity('Alice', 'persona', false);
    expect(identity.primaryKeypair).toBe('persona');
  });

  it('isChild flag is set correctly when false', () => {
    const identity = createNewIdentity('Alice', 'natural-person', false);
    expect(identity.isChild).toBe(false);
  });

  it('isChild flag is set correctly when true', () => {
    const identity = createNewIdentity('Alice', 'natural-person', true);
    expect(identity.isChild).toBe(true);
  });

  it('mnemonic is a valid BIP-39 mnemonic with at least 12 words', () => {
    const identity = createNewIdentity('Alice', 'natural-person', false);
    const words = identity.mnemonic.trim().split(/\s+/);
    expect(words.length).toBeGreaterThanOrEqual(12);
    expect(validateMnemonic(identity.mnemonic)).toBe(true);
  });
});

describe('importFromMnemonic', () => {
  it('same mnemonic produces the same keypairs (deterministic)', () => {
    const first = importFromMnemonic(TEST_MNEMONIC, 'Alice', 'natural-person', false);
    const second = importFromMnemonic(TEST_MNEMONIC, 'Alice', 'natural-person', false);
    expect(first.naturalPerson.publicKey).toBe(second.naturalPerson.publicKey);
    expect(first.naturalPerson.privateKey).toBe(second.naturalPerson.privateKey);
    expect(first.persona.publicKey).toBe(second.persona.publicKey);
    expect(first.persona.privateKey).toBe(second.persona.privateKey);
  });

  it('throws on an invalid mnemonic', () => {
    expect(() =>
      importFromMnemonic('this is not a valid mnemonic at all', 'Alice', 'natural-person', false),
    ).toThrow();
  });
});

describe('getActivePubkey', () => {
  it('returns the natural person public key when primaryKeypair is natural-person', () => {
    const identity = importFromMnemonic(TEST_MNEMONIC, 'Alice', 'natural-person', false);
    expect(getActivePubkey(identity)).toBe(identity.naturalPerson.publicKey);
  });

  it('returns the persona public key when primaryKeypair is persona', () => {
    const identity = importFromMnemonic(TEST_MNEMONIC, 'Alice', 'persona', false);
    expect(getActivePubkey(identity)).toBe(identity.persona.publicKey);
  });
});

describe('getActivePrivateKey', () => {
  it('returns the natural person private key when primaryKeypair is natural-person', () => {
    const identity = importFromMnemonic(TEST_MNEMONIC, 'Alice', 'natural-person', false);
    expect(getActivePrivateKey(identity)).toBe(identity.naturalPerson.privateKey);
  });

  it('returns the persona private key when primaryKeypair is persona', () => {
    const identity = importFromMnemonic(TEST_MNEMONIC, 'Alice', 'persona', false);
    expect(getActivePrivateKey(identity)).toBe(identity.persona.privateKey);
  });
});

describe('validateMnemonic', () => {
  it('returns true for a valid BIP-39 mnemonic', () => {
    expect(validateMnemonic(TEST_MNEMONIC)).toBe(true);
  });

  it('returns false for an invalid mnemonic', () => {
    expect(validateMnemonic('not a valid mnemonic phrase at all here')).toBe(false);
  });

  it('returns false for an empty string', () => {
    expect(validateMnemonic('')).toBe(false);
  });
});
