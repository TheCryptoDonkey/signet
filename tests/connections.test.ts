import { describe, it, expect } from 'vitest';
import {
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  createConnection,
  ConnectionStore,
} from '../src/connections.js';
import type { ContactInfo, Connection } from '../src/connections.js';
import { generateKeyPair } from '../src/crypto.js';

describe('connections', () => {
  // ── computeSharedSecret ──────────────────────────────────────────────────

  describe('computeSharedSecret', () => {
    it('is symmetric — A→B equals B→A', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      const secretAB = computeSharedSecret(alice.privateKey, bob.publicKey);
      const secretBA = computeSharedSecret(bob.privateKey, alice.publicKey);

      expect(secretAB).toBe(secretBA);
    });

    it('different key pairs produce different shared secrets', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const carol = generateKeyPair();

      const secretAB = computeSharedSecret(alice.privateKey, bob.publicKey);
      const secretAC = computeSharedSecret(alice.privateKey, carol.publicKey);

      expect(secretAB).not.toBe(secretAC);
    });

    it('produces a 64-char hex string (32 bytes)', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      const secret = computeSharedSecret(alice.privateKey, bob.publicKey);

      expect(secret).toHaveLength(64);
      expect(secret).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // ── createQRPayload ─────────────────────────────────────────────────────

  describe('createQRPayload', () => {
    it('includes pubkey and a random 32-byte nonce', () => {
      const kp = generateKeyPair();
      const payload = createQRPayload(kp.publicKey);

      expect(payload.pubkey).toBe(kp.publicKey);
      expect(payload.nonce).toHaveLength(64);
      expect(payload.nonce).toMatch(/^[0-9a-f]{64}$/);
    });

    it('generates a different nonce each time', () => {
      const kp = generateKeyPair();
      const p1 = createQRPayload(kp.publicKey);
      const p2 = createQRPayload(kp.publicKey);

      expect(p1.nonce).not.toBe(p2.nonce);
    });

    it('includes info when provided', () => {
      const kp = generateKeyPair();
      const info: ContactInfo = { name: 'Alice' };
      const payload = createQRPayload(kp.publicKey, info);

      expect(payload.info).toEqual(info);
    });

    it('omits info when not provided', () => {
      const kp = generateKeyPair();
      const payload = createQRPayload(kp.publicKey);

      expect(payload.info).toBeUndefined();
    });
  });

  // ── serializeQRPayload / parseQRPayload ──────────────────────────────────

  describe('serializeQRPayload / parseQRPayload', () => {
    it('roundtrips without info', () => {
      const kp = generateKeyPair();
      const original = createQRPayload(kp.publicKey);
      const serialized = serializeQRPayload(original);
      const parsed = parseQRPayload(serialized);

      expect(parsed.pubkey).toBe(original.pubkey);
      expect(parsed.nonce).toBe(original.nonce);
      expect(parsed.info).toBeUndefined();
    });

    it('roundtrips with info', () => {
      const kp = generateKeyPair();
      const info: ContactInfo = { name: 'Bob', email: 'bob@example.com' };
      const original = createQRPayload(kp.publicKey, info);
      const serialized = serializeQRPayload(original);
      const parsed = parseQRPayload(serialized);

      expect(parsed).toEqual(original);
    });

    it('throws on malformed JSON', () => {
      expect(() => parseQRPayload('not json')).toThrow('malformed JSON');
    });

    it('throws on missing pubkey', () => {
      const data = JSON.stringify({ nonce: 'abc' });
      expect(() => parseQRPayload(data)).toThrow('pubkey must be a 64-character hex string');
    });

    it('throws on missing nonce', () => {
      const data = JSON.stringify({ pubkey: 'a'.repeat(64) });
      expect(() => parseQRPayload(data)).toThrow('nonce must be 32-128 hex characters');
    });

    it('throws on nonce shorter than 32 characters', () => {
      const data = JSON.stringify({ pubkey: 'a'.repeat(64), nonce: 'abc123' });
      expect(() => parseQRPayload(data)).toThrow('nonce must be 32-128 hex characters');
    });

    it('rejects a nonce of exactly 16 characters (below 128-bit minimum)', () => {
      const data = JSON.stringify({ pubkey: 'a'.repeat(64), nonce: 'b'.repeat(16) });
      expect(() => parseQRPayload(data)).toThrow('nonce must be 32-128 hex characters');
    });

    it('accepts a nonce of exactly 32 characters', () => {
      const data = JSON.stringify({ pubkey: 'a'.repeat(64), nonce: 'b'.repeat(32) });
      expect(() => parseQRPayload(data)).not.toThrow();
    });

    it('rejects a nonce longer than 128 characters', () => {
      const data = JSON.stringify({ pubkey: 'a'.repeat(64), nonce: 'b'.repeat(200) });
      expect(() => parseQRPayload(data)).toThrow('nonce must be 32-128 hex characters');
    });

    it('rejects oversized ContactInfo fields in QR payload', () => {
      const data = JSON.stringify({
        pubkey: 'a'.repeat(64),
        nonce: 'b'.repeat(32),
        info: { name: 'x'.repeat(300) },
      });
      expect(() => parseQRPayload(data)).toThrow('exceeds');
    });

    it('rejects too many childPubkeys in ContactInfo', () => {
      const data = JSON.stringify({
        pubkey: 'a'.repeat(64),
        nonce: 'b'.repeat(32),
        info: { childPubkeys: Array(25).fill('c'.repeat(64)) },
      });
      expect(() => parseQRPayload(data)).toThrow('exceeds');
    });

    it('throws on invalid pubkey format', () => {
      const data = JSON.stringify({ pubkey: 'abc', nonce: 'abc' });
      expect(() => parseQRPayload(data)).toThrow('pubkey must be a 64-character hex string');
    });

    it('throws when payload is not an object', () => {
      expect(() => parseQRPayload('"just a string"')).toThrow('not an object');
    });
  });

  // ── createConnection ────────────────────────────────────────────────────

  describe('createConnection', () => {
    it('produces a valid Connection with a shared secret', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      const bobPayload = createQRPayload(bob.publicKey, { name: 'Bob' });
      const conn = createConnection(alice.privateKey, bobPayload, { name: 'Alice' });

      expect(conn.pubkey).toBe(bob.publicKey);
      expect(conn.sharedSecret).toHaveLength(64);
      expect(conn.theirInfo).toEqual({ name: 'Bob' });
      expect(conn.ourInfo).toEqual({ name: 'Alice' });
      expect(conn.method).toBe('qr-in-person');
      expect(conn.connectedAt).toBeGreaterThan(0);
    });

    it('two users connecting to each other get the same shared secret', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      const bobPayload = createQRPayload(bob.publicKey);
      const alicePayload = createQRPayload(alice.publicKey);

      const connAlice = createConnection(alice.privateKey, bobPayload, {});
      const connBob = createConnection(bob.privateKey, alicePayload, {});

      expect(connAlice.sharedSecret).toBe(connBob.sharedSecret);
    });

    it('sets theirInfo to empty object when QR has no info', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      const bobPayload = createQRPayload(bob.publicKey); // no info
      const conn = createConnection(alice.privateKey, bobPayload, { name: 'Alice' });

      expect(conn.theirInfo).toEqual({});
    });
  });

  // ── ContactInfo ─────────────────────────────────────────────────────────

  describe('ContactInfo', () => {
    it('supports all fields', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const child = generateKeyPair();

      const fullInfo: ContactInfo = {
        name: 'Alice Smith',
        mobile: '+44 7700 900000',
        email: 'alice@example.com',
        address: '10 Downing Street, London',
        childPubkeys: [child.publicKey],
      };

      const bobPayload = createQRPayload(bob.publicKey, fullInfo);
      const conn = createConnection(alice.privateKey, bobPayload, fullInfo);

      expect(conn.theirInfo.name).toBe('Alice Smith');
      expect(conn.theirInfo.mobile).toBe('+44 7700 900000');
      expect(conn.theirInfo.email).toBe('alice@example.com');
      expect(conn.theirInfo.address).toBe('10 Downing Street, London');
      expect(conn.theirInfo.childPubkeys).toEqual([child.publicKey]);
      expect(conn.ourInfo).toEqual(fullInfo);
    });

    it('supports partial fields (just name)', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      const partialInfo: ContactInfo = { name: 'Bob' };
      const bobPayload = createQRPayload(bob.publicKey, partialInfo);
      const conn = createConnection(alice.privateKey, bobPayload, partialInfo);

      expect(conn.theirInfo).toEqual({ name: 'Bob' });
      expect(conn.theirInfo.email).toBeUndefined();
      expect(conn.theirInfo.mobile).toBeUndefined();
      expect(conn.theirInfo.address).toBeUndefined();
      expect(conn.theirInfo.childPubkeys).toBeUndefined();
    });
  });

  // ── ContactInfo — personas field ─────────────────────────────────────────

  describe('ContactInfo — personas field', () => {
    it('roundtrips a payload with personas', () => {
      const kp = generateKeyPair();
      const p1 = generateKeyPair();
      const p2 = generateKeyPair();
      const info: ContactInfo = {
        name: 'Alice',
        personas: [
          { pubkey: p1.publicKey, label: 'Gaming' },
          { pubkey: p2.publicKey },
        ],
      };
      const payload = createQRPayload(kp.publicKey, info);
      const serialized = serializeQRPayload(payload);
      const parsed = parseQRPayload(serialized);
      expect(parsed.info?.personas).toEqual(info.personas);
    });

    it('accepts personas with no label', () => {
      const kp = generateKeyPair();
      const p1 = generateKeyPair();
      const data = JSON.stringify({
        pubkey: kp.publicKey,
        nonce: 'a'.repeat(64),
        info: { personas: [{ pubkey: p1.publicKey }] },
      });
      expect(() => parseQRPayload(data)).not.toThrow();
    });

    it('rejects personas that is not an array', () => {
      const data = JSON.stringify({
        pubkey: 'a'.repeat(64),
        nonce: 'b'.repeat(32),
        info: { personas: 'not-an-array' },
      });
      expect(() => parseQRPayload(data)).toThrow('personas must be an array');
    });

    it('rejects personas exceeding 20 entries', () => {
      const entries = Array.from({ length: 21 }, () => ({ pubkey: 'c'.repeat(64) }));
      const data = JSON.stringify({
        pubkey: 'a'.repeat(64),
        nonce: 'b'.repeat(32),
        info: { personas: entries },
      });
      expect(() => parseQRPayload(data)).toThrow('exceeds');
    });

    it('rejects persona entry with invalid pubkey', () => {
      const data = JSON.stringify({
        pubkey: 'a'.repeat(64),
        nonce: 'b'.repeat(32),
        info: { personas: [{ pubkey: 'not-hex' }] },
      });
      expect(() => parseQRPayload(data)).toThrow('valid 64-char hex pubkey');
    });

    it('rejects persona entry with non-string label', () => {
      const data = JSON.stringify({
        pubkey: 'a'.repeat(64),
        nonce: 'b'.repeat(32),
        info: { personas: [{ pubkey: 'c'.repeat(64), label: 123 }] },
      });
      expect(() => parseQRPayload(data)).toThrow('label must be a string');
    });

    it('rejects persona entry with oversized label', () => {
      const data = JSON.stringify({
        pubkey: 'a'.repeat(64),
        nonce: 'b'.repeat(32),
        info: { personas: [{ pubkey: 'c'.repeat(64), label: 'x'.repeat(300) }] },
      });
      expect(() => parseQRPayload(data)).toThrow('label exceeds');
    });
  });

  // ── ConnectionStore ─────────────────────────────────────────────────────

  describe('ConnectionStore', () => {
    function makeConnection(theirPubkey: string, sharedSecret: string): Connection {
      return {
        pubkey: theirPubkey,
        sharedSecret,
        theirInfo: { name: 'Peer' },
        ourInfo: { name: 'Self' },
        connectedAt: Math.floor(Date.now() / 1000),
        method: 'qr-in-person',
      };
    }

    it('add, get, and has work', () => {
      const store = new ConnectionStore();
      const kp = generateKeyPair();
      const conn = makeConnection(kp.publicKey, 'a'.repeat(64));

      store.add(conn);

      expect(store.has(kp.publicKey)).toBe(true);
      expect(store.get(kp.publicKey)).toEqual(conn);
    });

    it('get returns undefined for unknown pubkey', () => {
      const store = new ConnectionStore();
      expect(store.get('nonexistent')).toBeUndefined();
    });

    it('has returns false for unknown pubkey', () => {
      const store = new ConnectionStore();
      expect(store.has('nonexistent')).toBe(false);
    });

    it('list returns all connections', () => {
      const store = new ConnectionStore();
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();

      store.add(makeConnection(kp1.publicKey, 'a'.repeat(64)));
      store.add(makeConnection(kp2.publicKey, 'b'.repeat(64)));

      const all = store.list();
      expect(all).toHaveLength(2);

      const pubkeys = all.map((c) => c.pubkey);
      expect(pubkeys).toContain(kp1.publicKey);
      expect(pubkeys).toContain(kp2.publicKey);
    });

    it('remove deletes a connection and returns true', () => {
      const store = new ConnectionStore();
      const kp = generateKeyPair();

      store.add(makeConnection(kp.publicKey, 'a'.repeat(64)));
      expect(store.has(kp.publicKey)).toBe(true);

      const removed = store.remove(kp.publicKey);
      expect(removed).toBe(true);
      expect(store.has(kp.publicKey)).toBe(false);
      expect(store.get(kp.publicKey)).toBeUndefined();
    });

    it('remove returns false for unknown pubkey', () => {
      const store = new ConnectionStore();
      expect(store.remove('nonexistent')).toBe(false);
    });

    it('add replaces existing connection with same pubkey', () => {
      const store = new ConnectionStore();
      const kp = generateKeyPair();

      const conn1 = makeConnection(kp.publicKey, 'a'.repeat(64));
      const conn2 = makeConnection(kp.publicKey, 'b'.repeat(64));

      store.add(conn1);
      store.add(conn2);

      expect(store.list()).toHaveLength(1);
      expect(store.get(kp.publicKey)!.sharedSecret).toBe('b'.repeat(64));
    });

    it('export returns all connections as an array', () => {
      const store = new ConnectionStore();
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();

      const conn1 = makeConnection(kp1.publicKey, 'a'.repeat(64));
      const conn2 = makeConnection(kp2.publicKey, 'b'.repeat(64));

      store.add(conn1);
      store.add(conn2);

      const exported = store.export();
      expect(exported).toHaveLength(2);
      expect(exported).toEqual(expect.arrayContaining([conn1, conn2]));
    });

    it('import loads connections from an array', () => {
      const store = new ConnectionStore();
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();

      const conn1 = makeConnection(kp1.publicKey, 'a'.repeat(64));
      const conn2 = makeConnection(kp2.publicKey, 'b'.repeat(64));

      store.import([conn1, conn2]);

      expect(store.has(kp1.publicKey)).toBe(true);
      expect(store.has(kp2.publicKey)).toBe(true);
      expect(store.list()).toHaveLength(2);
    });

    it('import skips connections with oversized ContactInfo fields', () => {
      const store = new ConnectionStore();
      const kp = generateKeyPair();
      const oversizedConn: Connection = {
        pubkey: kp.publicKey,
        sharedSecret: 'a'.repeat(64),
        theirInfo: { name: 'x'.repeat(10000) }, // exceeds MAX_CONTACT_FIELD_LENGTH
        ourInfo: { name: 'Self' },
        connectedAt: Math.floor(Date.now() / 1000),
        method: 'qr-in-person',
      };
      store.import([oversizedConn]);
      expect(store.has(kp.publicKey)).toBe(false);
    });

    it('export/import roundtrips', () => {
      const store1 = new ConnectionStore();
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      const alicePayload = createQRPayload(alice.publicKey, { name: 'Alice' });
      const bobPayload = createQRPayload(bob.publicKey, { name: 'Bob' });

      store1.add(createConnection(alice.privateKey, bobPayload, { name: 'Alice' }));

      const exported = store1.export();

      const store2 = new ConnectionStore();
      store2.import(exported);

      expect(store2.list()).toEqual(store1.list());
      expect(store2.get(bob.publicKey)!.sharedSecret).toBe(
        store1.get(bob.publicKey)!.sharedSecret,
      );
    });
  });
});
