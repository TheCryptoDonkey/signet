import { describe, it, expect } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { buildSignedVerifyEvent } from '../relay-publish';
import type { VerifyResponse } from '../presentation';

function makeTestPrivateKey(): string {
  return bytesToHex(schnorr.utils.randomSecretKey());
}

function makeTestResponse(requestId: string): VerifyResponse {
  return {
    type: 'signet-verify-response',
    requestId,
    credential: {
      id: 'a'.repeat(64),
      kind: 31000,
      pubkey: 'b'.repeat(64),
      tags: [
        ['age-range', '18+'],
        ['tier', '3'],
        ['entity-type', 'natural-person'],
      ],
      content: '',
      sig: 'c'.repeat(128),
      created_at: 1700000000,
    },
    subjectPubkey: 'd'.repeat(64),
  };
}

describe('buildSignedVerifyEvent', () => {
  it('returns a valid NIP-01 event with id, pubkey, and sig', async () => {
    const privateKey = makeTestPrivateKey();
    const pubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(privateKey)));
    const requestId = bytesToHex(randomBytes(16));
    const response = makeTestResponse(requestId);

    const event = await buildSignedVerifyEvent(response, privateKey);

    // Kind must be 29999
    expect(event.kind).toBe(29999);

    // pubkey must be 64-char hex (32 bytes)
    expect(event.pubkey).toBe(pubkey);
    expect(event.pubkey).toMatch(/^[0-9a-f]{64}$/);

    // id must be 64-char hex
    expect(event.id).toMatch(/^[0-9a-f]{64}$/);

    // sig must be 128-char hex (64 bytes)
    expect(event.sig).toMatch(/^[0-9a-f]{128}$/);
  });

  it('has the correct session tag', async () => {
    const privateKey = makeTestPrivateKey();
    const requestId = bytesToHex(randomBytes(16));
    const response = makeTestResponse(requestId);

    const event = await buildSignedVerifyEvent(response, privateKey);

    const sessionTag = event.tags.find(t => t[0] === 'session');
    expect(sessionTag).toBeDefined();
    expect(sessionTag![1]).toBe(requestId);
  });

  it('has the credential tag with JSON-serialised credential', async () => {
    const privateKey = makeTestPrivateKey();
    const requestId = bytesToHex(randomBytes(16));
    const response = makeTestResponse(requestId);

    const event = await buildSignedVerifyEvent(response, privateKey);

    const credTag = event.tags.find(t => t[0] === 'credential');
    expect(credTag).toBeDefined();
    expect(credTag![1]).toBe(JSON.stringify(response.credential));
  });

  it('has status, age-range, tier, and entity-type tags', async () => {
    const privateKey = makeTestPrivateKey();
    const requestId = bytesToHex(randomBytes(16));
    const response = makeTestResponse(requestId);

    const event = await buildSignedVerifyEvent(response, privateKey);

    const statusTag = event.tags.find(t => t[0] === 'status');
    expect(statusTag).toEqual(['status', 'approved']);

    const ageRangeTag = event.tags.find(t => t[0] === 'age-range');
    expect(ageRangeTag).toBeDefined();
    expect(ageRangeTag![1]).toBe('18+');

    const tierTag = event.tags.find(t => t[0] === 'tier');
    expect(tierTag).toBeDefined();
    expect(tierTag![1]).toBe('3');

    const entityTypeTag = event.tags.find(t => t[0] === 'entity-type');
    expect(entityTypeTag).toBeDefined();
    expect(entityTypeTag![1]).toBe('natural-person');
  });

  it('produces a verifiable Schnorr signature', async () => {
    const privateKey = makeTestPrivateKey();
    const requestId = bytesToHex(randomBytes(16));
    const response = makeTestResponse(requestId);

    const event = await buildSignedVerifyEvent(response, privateKey);

    const valid = schnorr.verify(
      hexToBytes(event.sig),
      hexToBytes(event.id),
      hexToBytes(event.pubkey),
    );
    expect(valid).toBe(true);
  });
});
