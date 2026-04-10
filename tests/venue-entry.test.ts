import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  buildVenueEntryEventTemplate,
  signEvent,
  VENUE_ENTRY_KIND,
  verifyEvent,
} from '../src/index.js';
import { createHash } from 'crypto';

describe('Venue Entry QR', () => {
  describe('buildVenueEntryEventTemplate as first-class primitive', () => {
    it('builds a venue entry event template with just pubkey', () => {
      const pubkey = generateKeyPair().publicKey;

      const template = buildVenueEntryEventTemplate(pubkey);

      expect(template.pubkey).toBe(pubkey);
      expect(template.kind).toBe(VENUE_ENTRY_KIND);
      expect(template.kind).toBe(21235);
      expect(template.created_at).toBeGreaterThan(0);
      expect(template.content).toBe('');
      expect(Array.isArray(template.tags)).toBe(true);
    });

    it('includes signet-venue-entry tag', () => {
      const pubkey = generateKeyPair().publicKey;

      const template = buildVenueEntryEventTemplate(pubkey);

      const signetTag = template.tags.find(t => t[0] === 't' && t[1] === 'signet-venue-entry');
      expect(signetTag).toBeDefined();
    });

    it('includes photo hash when provided', () => {
      const pubkey = generateKeyPair().publicKey;
      const photoHash = 'abc123def456789abc123def456789abc123def456789abc123def456789abc1';

      const template = buildVenueEntryEventTemplate(pubkey, photoHash);

      const xTag = template.tags.find(t => t[0] === 'x' && t[1] === photoHash);
      expect(xTag).toBeDefined();
    });

    it('includes blossom URL when both photoHash and blossomUrl provided', () => {
      const pubkey = generateKeyPair().publicKey;
      const photoHash = 'abc123def456789abc123def456789abc123def456789abc123def456789abc1';
      const blossomUrl = 'https://cdn.blossom.example.com';

      const template = buildVenueEntryEventTemplate(pubkey, photoHash, blossomUrl);

      const blossomTag = template.tags.find(t => t[0] === 'blossom' && t[1] === blossomUrl);
      expect(blossomTag).toBeDefined();
    });

    it('ignores blossom URL if photoHash not provided', () => {
      const pubkey = generateKeyPair().publicKey;
      const blossomUrl = 'https://cdn.blossom.example.com';

      const template = buildVenueEntryEventTemplate(pubkey, undefined, blossomUrl);

      const blossomTag = template.tags.find(t => t[0] === 'blossom');
      expect(blossomTag).toBeUndefined();
    });

    it('ignores invalid blossom URLs', () => {
      const pubkey = generateKeyPair().publicKey;
      const photoHash = 'abc123def456789abc123def456789abc123def456789abc123def456789abc1';
      const badUrl = 'ftp://invalid.example.com'; // Not HTTPS

      const template = buildVenueEntryEventTemplate(pubkey, photoHash, badUrl);

      const blossomTag = template.tags.find(t => t[0] === 'blossom');
      expect(blossomTag).toBeUndefined();
    });

    it('allows localhost blossom URL for development', () => {
      const pubkey = generateKeyPair().publicKey;
      const photoHash = 'abc123def456789abc123def456789abc123def456789abc123def456789abc1';
      const localhostUrl = 'http://localhost:3000/api/upload';

      const template = buildVenueEntryEventTemplate(pubkey, photoHash, localhostUrl);

      const blossomTag = template.tags.find(t => t[0] === 'blossom' && t[1] === localhostUrl);
      expect(blossomTag).toBeDefined();
    });

    it('can be signed by MatchPass without signet-app dependency', async () => {
      const kp = generateKeyPair();
      const photoHash = createHash('sha256').update('example-photo').digest('hex');

      // Build the event template (standalone, no dependency on signet-app)
      const template = buildVenueEntryEventTemplate(kp.publicKey, photoHash, 'https://cdn.example.com');

      // Sign it (using the same signEvent function as other attestations)
      const signed = await signEvent(template, kp.privateKey);

      expect(signed.sig).toBeDefined();
      expect(signed.pubkey).toBe(kp.publicKey);
      expect(signed.kind).toBe(21235);

      // Verify the signature
      const isValid = await verifyEvent(signed);
      expect(isValid).toBe(true);
    });

    it('produces QR-compatible structure', () => {
      const kp = generateKeyPair();
      const template = buildVenueEntryEventTemplate(kp.publicKey);

      // A QR renderer would call JSON.stringify on the signed event
      // Verify the template produces valid JSON structure
      const jsonStr = JSON.stringify(template);
      const parsed = JSON.parse(jsonStr);

      expect(parsed.pubkey).toBe(kp.publicKey);
      expect(parsed.kind).toBe(21235);
      expect(parsed.tags).toBeDefined();
    });

    it('multiple venue entries can be created for same user', async () => {
      const kp = generateKeyPair();

      // Entry 1: without photo
      const entry1 = buildVenueEntryEventTemplate(kp.publicKey);
      const signed1 = await signEvent(entry1, kp.privateKey);

      // Entry 2: with photo
      const photoHash = 'photo2hash';
      const entry2 = buildVenueEntryEventTemplate(kp.publicKey, photoHash, 'https://cdn.example.com');
      const signed2 = await signEvent(entry2, kp.privateKey);

      expect(signed1.sig).not.toBe(signed2.sig);
      expect(signed1.created_at).toBeLessThanOrEqual(signed2.created_at);
    });
  });
});
