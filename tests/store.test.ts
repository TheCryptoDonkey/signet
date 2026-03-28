import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  signEvent,
  SignetStore,
  createSelfDeclaredCredential,
  createProfessionalCredential,
  createVouch,
  createPolicy,
  createVerifierCredential,
  ATTESTATION_KIND,
  ATTESTATION_TYPES,
  getTagValue,
} from '../src/index.js';
import { buildTier3Opts } from './fixtures.js';

describe('SignetStore', () => {
  it('adds and retrieves events', async () => {
    const store = new SignetStore();
    const kp = generateKeyPair();
    const cred = await createSelfDeclaredCredential(kp.privateKey);

    expect(store.add(cred)).toBe(true);
    expect(store.size).toBe(1);
    expect(store.get(cred.id)).toEqual(cred);
  });

  it('deduplicates by event ID', async () => {
    const store = new SignetStore();
    const kp = generateKeyPair();
    const cred = await createSelfDeclaredCredential(kp.privateKey);

    expect(store.add(cred)).toBe(true);
    expect(store.add(cred)).toBe(false);
    expect(store.size).toBe(1);
  });

  it('handles replaceable events (newer replaces older)', async () => {
    const store = new SignetStore();
    const kp = generateKeyPair();

    // Create first credential
    const cred1 = await createSelfDeclaredCredential(kp.privateKey);

    // Create second credential with a later timestamp, then re-sign so the ID is correct
    const { id: _id, sig: _sig, ...unsigned } = cred1;
    const cred2 = await signEvent(
      { ...unsigned, created_at: cred1.created_at + 1 },
      kp.privateKey
    );

    store.add(cred1);
    store.add(cred2);

    // Should keep only the newer one
    expect(store.size).toBe(1);
    expect(store.has(cred1.id)).toBe(false);
    expect(store.has(cred2.id)).toBe(true);
  });

  it('queries by kind', async () => {
    const store = new SignetStore();
    const kp = generateKeyPair();
    const subject = generateKeyPair();

    const cred = await createSelfDeclaredCredential(kp.privateKey);
    const vouch = await createVouch(kp.privateKey, {
      subjectPubkey: subject.publicKey,
      method: 'in-person',
      voucherTier: 2,
      voucherScore: 50,
    });

    store.add(cred);
    store.add(vouch);

    // Both credential and vouch share kind ATTESTATION_KIND now — filter by type tag
    const allAttestations = store.query({ kinds: [ATTESTATION_KIND] });
    expect(allAttestations).toHaveLength(2);

    const creds = allAttestations.filter(e => getTagValue(e, 'type') === ATTESTATION_TYPES.CREDENTIAL);
    expect(creds).toHaveLength(1);

    const vouches = allAttestations.filter(e => getTagValue(e, 'type') === ATTESTATION_TYPES.VOUCH);
    expect(vouches).toHaveLength(1);
  });

  it('queries by author', async () => {
    const store = new SignetStore();
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();

    store.add(await createSelfDeclaredCredential(kp1.privateKey));
    store.add(await createSelfDeclaredCredential(kp2.privateKey));

    const results = store.query({ authors: [kp1.publicKey] });
    expect(results).toHaveLength(1);
    expect(results[0].pubkey).toBe(kp1.publicKey);
  });

  it('queries by subject', async () => {
    const store = new SignetStore();
    const verifier = generateKeyPair();
    const subject = generateKeyPair();
    const other = generateKeyPair();

    store.add(await createProfessionalCredential(verifier.privateKey, subject.publicKey, await buildTier3Opts(subject.privateKey)));
    store.add(await createProfessionalCredential(verifier.privateKey, other.publicKey, await buildTier3Opts(other.privateKey)));

    const results = store.query({ subjects: [subject.publicKey] });
    expect(results).toHaveLength(1);
  });

  describe('convenience methods', () => {
    it('getCredentials returns credentials for a subject', async () => {
      const store = new SignetStore();
      const verifier = generateKeyPair();
      const subject = generateKeyPair();

      store.add(await createProfessionalCredential(verifier.privateKey, subject.publicKey, await buildTier3Opts(subject.privateKey)));

      const creds = store.getCredentials(subject.publicKey);
      expect(creds).toHaveLength(1);
    });

    it('getHighestCredential returns the highest tier', async () => {
      const store = new SignetStore();
      const subject = generateKeyPair();
      const verifier = generateKeyPair();

      store.add(await createSelfDeclaredCredential(subject.privateKey));
      store.add(await createProfessionalCredential(verifier.privateKey, subject.publicKey, await buildTier3Opts(subject.privateKey)));

      const highest = store.getHighestCredential(subject.publicKey);
      expect(highest).not.toBeNull();
      expect(highest!.tier).toBe(3);
    });

    it('getVouches returns vouches for a subject', async () => {
      const store = new SignetStore();
      const v1 = generateKeyPair();
      const v2 = generateKeyPair();
      const subject = generateKeyPair();

      store.add(await createVouch(v1.privateKey, {
        subjectPubkey: subject.publicKey, method: 'in-person', voucherTier: 2, voucherScore: 50,
      }));
      store.add(await createVouch(v2.privateKey, {
        subjectPubkey: subject.publicKey, method: 'online', voucherTier: 2, voucherScore: 40,
      }));

      expect(store.getVouches(subject.publicKey)).toHaveLength(2);
    });
  });

  describe('serialization', () => {
    it('exports and imports events', async () => {
      const store = new SignetStore();
      const kp = generateKeyPair();

      store.add(await createSelfDeclaredCredential(kp.privateKey));
      store.add(await createVouch(kp.privateKey, {
        subjectPubkey: generateKeyPair().publicKey,
        method: 'online', voucherTier: 2, voucherScore: 50,
      }));

      const json = store.export();

      const store2 = new SignetStore();
      const imported = store2.import(json);
      expect(imported).toBe(2);
      expect(store2.size).toBe(2);
    });

    it('rejects non-JSON import data', () => {
      const store = new SignetStore();
      expect(() => store.import('not json')).toThrow('not valid JSON');
    });

    it('rejects non-array import data', () => {
      const store = new SignetStore();
      expect(() => store.import('{"foo":1}')).toThrow('must be a JSON array');
    });

    it('rejects oversized import array', () => {
      const store = new SignetStore();
      const huge = JSON.stringify(Array(10_001).fill(null));
      expect(() => store.import(huge)).toThrow('too large');
    });

    it('skips events with invalid hex id', () => {
      const store = new SignetStore();
      const data = JSON.stringify([{
        id: 'ZZZZ' + 'a'.repeat(60),  // uppercase / invalid hex
        pubkey: 'b'.repeat(64),
        kind: 31000,
        created_at: 1000,
        tags: [],
        content: '',
        sig: 'c'.repeat(128),
      }]);
      expect(store.import(data)).toBe(0);
    });

    it('skips events with invalid hex pubkey', () => {
      const store = new SignetStore();
      const data = JSON.stringify([{
        id: 'a'.repeat(64),
        pubkey: 'NOT-HEX!',
        kind: 31000,
        created_at: 1000,
        tags: [],
        content: '',
        sig: 'c'.repeat(128),
      }]);
      expect(store.import(data)).toBe(0);
    });

    it('skips events with invalid hex sig', () => {
      const store = new SignetStore();
      const data = JSON.stringify([{
        id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        kind: 31000,
        created_at: 1000,
        tags: [],
        content: '',
        sig: 'short',
      }]);
      expect(store.import(data)).toBe(0);
    });

    it('skips malformed entries (missing fields)', () => {
      const store = new SignetStore();
      const data = JSON.stringify([
        { id: 'a'.repeat(64) },  // missing most fields
        null,
        42,
      ]);
      expect(store.import(data)).toBe(0);
    });
  });

  it('clears all events', async () => {
    const store = new SignetStore();
    store.add(await createSelfDeclaredCredential(generateKeyPair().privateKey));
    expect(store.size).toBe(1);
    store.clear();
    expect(store.size).toBe(0);
  });
});
