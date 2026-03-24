import { describe, it, expect } from 'vitest';
import { encryptSecret, decryptSecret, isEncrypted } from '../crypto-store';

// Note: crypto.subtle is available globally in Node.js >= 22 via globalThis.crypto.

describe('encryptSecret + decryptSecret', () => {
  it('round-trip: encrypt then decrypt returns the original plaintext', async () => {
    const plaintext = 'my secret key material';
    const passphrase = 'correct-horse-battery-staple';
    const encrypted = await encryptSecret(plaintext, passphrase);
    const decrypted = await decryptSecret(encrypted, passphrase);
    expect(decrypted).toBe(plaintext);
  });

  it('different passphrases produce different ciphertexts', async () => {
    const plaintext = 'same plaintext';
    const first = await encryptSecret(plaintext, 'passphrase-one');
    const second = await encryptSecret(plaintext, 'passphrase-two');
    // Ciphertexts differ because PBKDF2 keys differ
    expect(first).not.toBe(second);
  });

  it('wrong passphrase fails to decrypt and throws', async () => {
    const plaintext = 'sensitive data';
    const encrypted = await encryptSecret(plaintext, 'correct-passphrase');
    await expect(decryptSecret(encrypted, 'wrong-passphrase')).rejects.toThrow();
  });

  it('encrypts and decrypts an empty string', async () => {
    const encrypted = await encryptSecret('', 'any-passphrase');
    const decrypted = await decryptSecret(encrypted, 'any-passphrase');
    expect(decrypted).toBe('');
  });

  it('encrypts and decrypts a long plaintext (1000 characters)', async () => {
    const plaintext = 'x'.repeat(1000);
    const passphrase = 'passphrase-for-long-text';
    const encrypted = await encryptSecret(plaintext, passphrase);
    const decrypted = await decryptSecret(encrypted, passphrase);
    expect(decrypted).toBe(plaintext);
  });

  it('encrypts and decrypts unicode content', async () => {
    const plaintext = 'こんにちは 世界 🌍 café naïve résumé';
    const passphrase = 'unicode-passphrase-βγδ';
    const encrypted = await encryptSecret(plaintext, passphrase);
    const decrypted = await decryptSecret(encrypted, passphrase);
    expect(decrypted).toBe(plaintext);
  });
});

describe('isEncrypted', () => {
  it('returns true for output produced by encryptSecret', async () => {
    const encrypted = await encryptSecret('some secret', 'a-passphrase');
    expect(isEncrypted(encrypted)).toBe(true);
  });

  it('returns false for plain text', () => {
    expect(isEncrypted('hello world')).toBe(false);
  });

  it('returns false for short base64 (below minimum decoded length)', () => {
    // salt(16) + iv(12) + min-ciphertext(16) = 44 bytes minimum
    // 10 bytes of base64 encodes only ~7 bytes — well below the threshold
    const shortBase64 = btoa('tooshort');
    expect(isEncrypted(shortBase64)).toBe(false);
  });

  it('returns false for non-base64 input', () => {
    expect(isEncrypted('not!base64@string#here')).toBe(false);
  });
});
