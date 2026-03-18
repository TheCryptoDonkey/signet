import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createVouch,
  parseVouch,
  countQualifyingVouches,
  hasEnoughVouches,
  getVouchers,
  verifyEvent,
  getTagValue,
  ATTESTATION_KIND,
  ATTESTATION_TYPES,
} from '../src/index.js';

describe('vouches', () => {
  it('creates a valid in-person vouch', async () => {
    const voucher = generateKeyPair();
    const subject = generateKeyPair();

    const vouch = await createVouch(voucher.privateKey, {
      subjectPubkey: subject.publicKey,
      method: 'in-person',
      context: 'bitcoin-meetup',
      voucherTier: 3,
      voucherScore: 87,
    });

    expect(vouch.kind).toBe(ATTESTATION_KIND);
    expect(vouch.pubkey).toBe(voucher.publicKey);
    expect(getTagValue(vouch, 'type')).toBe(ATTESTATION_TYPES.VOUCH);
    expect(getTagValue(vouch, 'd')).toBe(`vouch:${subject.publicKey}`);
    expect(getTagValue(vouch, 'method')).toBe('in-person');
    expect(getTagValue(vouch, 'context')).toBe('bitcoin-meetup');
    expect(getTagValue(vouch, 'voucher-tier')).toBe('3');
    expect(getTagValue(vouch, 'voucher-score')).toBe('87');
    expect(vouch.content).toBe('');

    const valid = await verifyEvent(vouch);
    expect(valid).toBe(true);
  });

  it('creates a valid online vouch', async () => {
    const voucher = generateKeyPair();
    const subject = generateKeyPair();

    const vouch = await createVouch(voucher.privateKey, {
      subjectPubkey: subject.publicKey,
      method: 'online',
      voucherTier: 2,
      voucherScore: 55,
    });

    expect(getTagValue(vouch, 'method')).toBe('online');
  });

  describe('parseVouch', () => {
    it('parses a vouch event correctly', async () => {
      const voucher = generateKeyPair();
      const subject = generateKeyPair();

      const vouch = await createVouch(voucher.privateKey, {
        subjectPubkey: subject.publicKey,
        method: 'in-person',
        context: 'conference',
        voucherTier: 3,
        voucherScore: 90,
      });

      const parsed = parseVouch(vouch);
      expect(parsed).not.toBeNull();
      expect(parsed!.subjectPubkey).toBe(subject.publicKey);
      expect(parsed!.method).toBe('in-person');
      expect(parsed!.context).toBe('conference');
      expect(parsed!.voucherTier).toBe(3);
      expect(parsed!.voucherScore).toBe(90);
    });
  });

  describe('countQualifyingVouches', () => {
    it('counts only qualifying vouches', async () => {
      const subject = generateKeyPair();
      const vouchers = [generateKeyPair(), generateKeyPair(), generateKeyPair()];

      const vouchEvents = await Promise.all([
        createVouch(vouchers[0].privateKey, {
          subjectPubkey: subject.publicKey,
          method: 'in-person',
          voucherTier: 3,
          voucherScore: 80,
        }),
        createVouch(vouchers[1].privateKey, {
          subjectPubkey: subject.publicKey,
          method: 'in-person',
          voucherTier: 2,
          voucherScore: 60,
        }),
        // This one is Tier 1, below min
        createVouch(vouchers[2].privateKey, {
          subjectPubkey: subject.publicKey,
          method: 'online',
          voucherTier: 1,
          voucherScore: 20,
        }),
      ]);

      // Default min tier is 2
      const count = countQualifyingVouches(vouchEvents, subject.publicKey);
      expect(count).toBe(2); // only tier 2 and 3
    });

    it('deduplicates vouches from the same voucher', async () => {
      const subject = generateKeyPair();
      const voucher = generateKeyPair();

      const vouchEvents = await Promise.all([
        createVouch(voucher.privateKey, {
          subjectPubkey: subject.publicKey,
          method: 'in-person',
          voucherTier: 3,
          voucherScore: 80,
        }),
        createVouch(voucher.privateKey, {
          subjectPubkey: subject.publicKey,
          method: 'online',
          voucherTier: 3,
          voucherScore: 80,
        }),
      ]);

      const count = countQualifyingVouches(vouchEvents, subject.publicKey);
      expect(count).toBe(1);
    });
  });

  describe('hasEnoughVouches', () => {
    it('returns true when threshold is met', async () => {
      const subject = generateKeyPair();
      const vouchEvents = await Promise.all(
        Array.from({ length: 3 }, () => {
          const v = generateKeyPair();
          return createVouch(v.privateKey, {
            subjectPubkey: subject.publicKey,
            method: 'in-person',
            voucherTier: 2,
            voucherScore: 50,
          });
        })
      );

      expect(hasEnoughVouches(vouchEvents, subject.publicKey)).toBe(true);
    });

    it('returns false when threshold is not met', async () => {
      const subject = generateKeyPair();
      const vouchEvents = await Promise.all(
        Array.from({ length: 2 }, () => {
          const v = generateKeyPair();
          return createVouch(v.privateKey, {
            subjectPubkey: subject.publicKey,
            method: 'in-person',
            voucherTier: 2,
            voucherScore: 50,
          });
        })
      );

      expect(hasEnoughVouches(vouchEvents, subject.publicKey)).toBe(false);
    });
  });

  describe('getVouchers', () => {
    it('returns unique voucher pubkeys', async () => {
      const subject = generateKeyPair();
      const v1 = generateKeyPair();
      const v2 = generateKeyPair();

      const vouchEvents = await Promise.all([
        createVouch(v1.privateKey, {
          subjectPubkey: subject.publicKey,
          method: 'in-person',
          voucherTier: 2,
          voucherScore: 50,
        }),
        createVouch(v2.privateKey, {
          subjectPubkey: subject.publicKey,
          method: 'online',
          voucherTier: 3,
          voucherScore: 70,
        }),
      ]);

      const vouchers = getVouchers(vouchEvents, subject.publicKey);
      expect(vouchers).toHaveLength(2);
      expect(vouchers).toContain(v1.publicKey);
      expect(vouchers).toContain(v2.publicKey);
    });
  });
});
