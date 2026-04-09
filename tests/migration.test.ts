import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  getPublicKey,
  getTagValue,
  ATTESTATION_KIND,
} from '../src/index.js';
import {
  createMigrationEvent,
  parseMigrationEvent,
  followMigrationChain,
} from '../src/migration.js';
import type { NostrEvent } from '../src/index.js';

describe('migration', () => {
  // -------------------------------------------------------------------------
  // createMigrationEvent
  // -------------------------------------------------------------------------
  describe('createMigrationEvent', () => {
    it('creates a valid migration event with correct kind', async () => {
      const oldKp = generateKeyPair();
      const newKp = generateKeyPair();

      const event = await createMigrationEvent(oldKp.privateKey, newKp.publicKey);

      expect(event.kind).toBe(ATTESTATION_KIND);
    });

    it('sets the type tag to migration', async () => {
      const oldKp = generateKeyPair();
      const newKp = generateKeyPair();

      const event = await createMigrationEvent(oldKp.privateKey, newKp.publicKey);

      expect(getTagValue(event, 'type')).toBe('migration');
    });

    it('sets the d tag to migration:<old-pubkey>', async () => {
      const oldKp = generateKeyPair();
      const newKp = generateKeyPair();

      const event = await createMigrationEvent(oldKp.privateKey, newKp.publicKey);

      expect(getTagValue(event, 'd')).toBe(`migration:${oldKp.publicKey}`);
    });

    it('includes NIP-VA discoverability labels', async () => {
      const oldKp = generateKeyPair();
      const newKp = generateKeyPair();

      const event = await createMigrationEvent(oldKp.privateKey, newKp.publicKey);

      const lTag = event.tags.find((t) => t[0] === 'L' && t[1] === 'nip-va');
      expect(lTag).toBeDefined();

      const lowerTag = event.tags.find(
        (t) => t[0] === 'l' && t[1] === 'migration' && t[2] === 'nip-va'
      );
      expect(lowerTag).toBeDefined();
    });

    it('old pubkey is the signer (event.pubkey)', async () => {
      const oldKp = generateKeyPair();
      const newKp = generateKeyPair();

      const event = await createMigrationEvent(oldKp.privateKey, newKp.publicKey);

      expect(event.pubkey).toBe(oldKp.publicKey);
    });

    it('new pubkey is in the p tag', async () => {
      const oldKp = generateKeyPair();
      const newKp = generateKeyPair();

      const event = await createMigrationEvent(oldKp.privateKey, newKp.publicKey);

      expect(getTagValue(event, 'p')).toBe(newKp.publicKey);
    });

    it('event is signed by the old private key (has id and sig)', async () => {
      const oldKp = generateKeyPair();
      const newKp = generateKeyPair();

      const event = await createMigrationEvent(oldKp.privateKey, newKp.publicKey);

      expect(typeof event.id).toBe('string');
      expect(event.id.length).toBe(64);
      expect(typeof event.sig).toBe('string');
      expect(event.sig.length).toBe(128);
    });
  });

  // -------------------------------------------------------------------------
  // parseMigrationEvent
  // -------------------------------------------------------------------------
  describe('parseMigrationEvent', () => {
    it('parses a valid migration event', async () => {
      const oldKp = generateKeyPair();
      const newKp = generateKeyPair();

      const event = await createMigrationEvent(oldKp.privateKey, newKp.publicKey);
      const result = parseMigrationEvent(event);

      expect(result).not.toBeNull();
      expect(result!.oldPubkey).toBe(oldKp.publicKey);
      expect(result!.newPubkey).toBe(newKp.publicKey);
    });

    it('returns null for a non-migration event (wrong type tag)', async () => {
      const kp = generateKeyPair();
      // Fabricate a minimal event with wrong type
      const fakeEvent: NostrEvent = {
        kind: ATTESTATION_KIND,
        pubkey: kp.publicKey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['d', `credential:${kp.publicKey}`],
          ['type', 'credential'],
          ['L', 'nip-va'],
          ['l', 'credential', 'nip-va'],
        ],
        content: '',
        id: 'a'.repeat(64),
        sig: 'b'.repeat(128),
      };

      expect(parseMigrationEvent(fakeEvent)).toBeNull();
    });

    it('returns null for wrong kind', async () => {
      const kp = generateKeyPair();
      const fakeEvent: NostrEvent = {
        kind: 1,
        pubkey: kp.publicKey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['type', 'migration']],
        content: '',
        id: 'a'.repeat(64),
        sig: 'b'.repeat(128),
      };

      expect(parseMigrationEvent(fakeEvent)).toBeNull();
    });

    it('returns null when p tag is missing', async () => {
      const kp = generateKeyPair();
      const fakeEvent: NostrEvent = {
        kind: ATTESTATION_KIND,
        pubkey: kp.publicKey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['d', `migration:${kp.publicKey}`],
          ['type', 'migration'],
          ['L', 'nip-va'],
          ['l', 'migration', 'nip-va'],
        ],
        content: '',
        id: 'a'.repeat(64),
        sig: 'b'.repeat(128),
      };

      expect(parseMigrationEvent(fakeEvent)).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // followMigrationChain
  // -------------------------------------------------------------------------
  describe('followMigrationChain', () => {
    it('returns the input pubkey unchanged when no migration exists', async () => {
      const kp = generateKeyPair();
      const result = followMigrationChain(kp.publicKey, []);
      expect(result).toBe(kp.publicKey);
    });

    it('follows a single migration hop', async () => {
      const kpA = generateKeyPair();
      const kpB = generateKeyPair();

      const migration = await createMigrationEvent(kpA.privateKey, kpB.publicKey);
      const result = followMigrationChain(kpA.publicKey, [migration]);

      expect(result).toBe(kpB.publicKey);
    });

    it('follows a multi-hop chain (A → B → C)', async () => {
      const kpA = generateKeyPair();
      const kpB = generateKeyPair();
      const kpC = generateKeyPair();

      const migrationAB = await createMigrationEvent(kpA.privateKey, kpB.publicKey);
      const migrationBC = await createMigrationEvent(kpB.privateKey, kpC.publicKey);

      const result = followMigrationChain(kpA.publicKey, [migrationAB, migrationBC]);

      expect(result).toBe(kpC.publicKey);
    });

    it('returns input pubkey unchanged when events are unrelated', async () => {
      const kpA = generateKeyPair();
      const kpX = generateKeyPair();
      const kpY = generateKeyPair();

      // Migration between X and Y — unrelated to A
      const migration = await createMigrationEvent(kpX.privateKey, kpY.publicKey);
      const result = followMigrationChain(kpA.publicKey, [migration]);

      expect(result).toBe(kpA.publicKey);
    });

    it('detects a direct cycle (A → B → A) and does not loop infinitely', async () => {
      const kpA = generateKeyPair();
      const kpB = generateKeyPair();

      // We cannot sign with kpB.privateKey for a migration back to A because
      // createMigrationEvent derives the signer from the private key.
      // Instead, fabricate events directly to test the cycle-detection logic.
      const now = Math.floor(Date.now() / 1000);
      const fakeAtoB: NostrEvent = {
        kind: ATTESTATION_KIND,
        pubkey: kpA.publicKey,
        created_at: now,
        tags: [
          ['d', `migration:${kpA.publicKey}`],
          ['type', 'migration'],
          ['p', kpB.publicKey],
          ['L', 'nip-va'],
          ['l', 'migration', 'nip-va'],
        ],
        content: '',
        id: 'a'.repeat(64),
        sig: 'b'.repeat(128),
      };
      const fakeBtoA: NostrEvent = {
        kind: ATTESTATION_KIND,
        pubkey: kpB.publicKey,
        created_at: now,
        tags: [
          ['d', `migration:${kpB.publicKey}`],
          ['type', 'migration'],
          ['p', kpA.publicKey],
          ['L', 'nip-va'],
          ['l', 'migration', 'nip-va'],
        ],
        content: '',
        id: 'c'.repeat(64),
        sig: 'd'.repeat(128),
      };

      // Should not throw; should terminate and return one of the pubkeys
      const result = followMigrationChain(kpA.publicKey, [fakeAtoB, fakeBtoA]);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });

    it('respects max depth (chain of 101 hops returns last safely reached key)', async () => {
      // Build a chain of 101 keypairs so that the chain depth exceeds MAX_CHAIN_DEPTH (100)
      const keypairs = Array.from({ length: 102 }, () => generateKeyPair());
      const events: NostrEvent[] = [];
      for (let i = 0; i < 101; i++) {
        events.push(
          await createMigrationEvent(keypairs[i].privateKey, keypairs[i + 1].publicKey)
        );
      }

      const result = followMigrationChain(keypairs[0].publicKey, events);

      // The result must be a pubkey from within our chain (not an error)
      expect(typeof result).toBe('string');
      expect(result.length).toBe(64);

      // Must not return the very first key (at least one hop was followed)
      expect(result).not.toBe(keypairs[0].publicKey);
    });
  });
});
