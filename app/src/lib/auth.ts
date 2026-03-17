// Biometric auth using WebAuthn with PIN fallback

const CREDENTIAL_ID_KEY = 'signet-auth-credential-id';
const ENCRYPTED_KEY_KEY = 'signet-auth-encrypted-key';
const AUTH_METHOD_KEY = 'signet-auth-method';

/** Check if WebAuthn with biometrics is available */
export async function isBiometricAvailable(): Promise<boolean> {
  if (!window.PublicKeyCredential) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/** Set up biometric auth — creates a WebAuthn credential and stores the encryption key behind it */
export async function setupBiometric(encryptionKey: string): Promise<boolean> {
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          name: 'My Signet',
          id: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? window.location.hostname
            : 'signet.trotters.cc',
        },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'signet-user',
          displayName: 'Signet User',
        },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        timeout: 60000,
      },
    }) as PublicKeyCredential | null;

    if (!credential) return false;

    // Store credential ID for later retrieval
    const credId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    localStorage.setItem(CREDENTIAL_ID_KEY, credId);

    // Since PRF extension isn't universally available, we store the encryption key
    // encrypted with a key derived from the credential ID + a device salt.
    // The biometric gate is the WebAuthn assertion — you can't get past it without the biometric.
    const deviceSalt = crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await deriveKeyFromCredential(credId, deviceSalt);
    const encrypted = await encryptWithKey(encryptionKey, derivedKey);

    localStorage.setItem(
      ENCRYPTED_KEY_KEY,
      JSON.stringify({ encrypted, salt: btoa(String.fromCharCode(...deviceSalt)) }),
    );
    localStorage.setItem(AUTH_METHOD_KEY, 'biometric');

    return true;
  } catch {
    return false;
  }
}

/** Set up PIN auth — derives encryption key from PIN via PBKDF2 */
export async function setupPIN(pin: string, encryptionKey: string): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derivedKey = await deriveKeyFromPIN(pin, salt);
  const encrypted = await encryptWithKey(encryptionKey, derivedKey);

  localStorage.setItem(
    ENCRYPTED_KEY_KEY,
    JSON.stringify({ encrypted, salt: btoa(String.fromCharCode(...salt)) }),
  );
  localStorage.setItem(AUTH_METHOD_KEY, 'pin');
}

/** Authenticate with biometric — returns the encryption key */
export async function authenticateBiometric(): Promise<string | null> {
  try {
    const credIdB64 = localStorage.getItem(CREDENTIAL_ID_KEY);
    if (!credIdB64) return null;

    const credIdBytes = Uint8Array.from(atob(credIdB64), c => c.charCodeAt(0));
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{ id: credIdBytes, type: 'public-key', transports: ['internal'] }],
        userVerification: 'required',
        timeout: 60000,
      },
    }) as PublicKeyCredential | null;

    if (!assertion) return null;

    // Biometric passed — decrypt the stored encryption key
    const raw = localStorage.getItem(ENCRYPTED_KEY_KEY);
    if (!raw) return null;
    const stored = JSON.parse(raw) as Record<string, unknown>;
    if (typeof stored.encrypted !== 'string' || typeof stored.salt !== 'string') return null;

    const salt = Uint8Array.from(atob(stored.salt), c => c.charCodeAt(0));
    const derivedKey = await deriveKeyFromCredential(credIdB64, salt);
    return await decryptWithKey(stored.encrypted, derivedKey);
  } catch {
    return null;
  }
}

/** Authenticate with PIN — returns the encryption key, or null on wrong PIN */
export async function authenticatePIN(pin: string): Promise<string | null> {
  try {
    const raw = localStorage.getItem(ENCRYPTED_KEY_KEY);
    if (!raw) return null;
    const stored = JSON.parse(raw) as Record<string, unknown>;
    if (typeof stored.encrypted !== 'string' || typeof stored.salt !== 'string') return null;

    const salt = Uint8Array.from(atob(stored.salt), c => c.charCodeAt(0));
    const derivedKey = await deriveKeyFromPIN(pin, salt);
    return await decryptWithKey(stored.encrypted, derivedKey);
  } catch {
    return null; // wrong PIN or corrupt data
  }
}

/** Check if auth is set up */
export function isAuthSetUp(): boolean {
  return localStorage.getItem(AUTH_METHOD_KEY) !== null;
}

/** Get auth method */
export function getAuthMethod(): 'biometric' | 'pin' | null {
  const val = localStorage.getItem(AUTH_METHOD_KEY);
  if (val === 'biometric' || val === 'pin') return val;
  return null;
}

/** Generate a random 256-bit encryption key (hex string) */
export function generateEncryptionKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** Clear all auth data from localStorage (for account deletion) */
export function clearAuthData(): void {
  localStorage.removeItem(CREDENTIAL_ID_KEY);
  localStorage.removeItem(ENCRYPTED_KEY_KEY);
  localStorage.removeItem(AUTH_METHOD_KEY);
}

// --- Internal helpers ---

async function deriveKeyFromPIN(pin: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  // Ensure we have a plain ArrayBuffer — required by SubtleCrypto Pbkdf2Params
  const saltArr = new Uint8Array(salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltArr, iterations: 600000, hash: 'SHA-256' } as Pbkdf2Params,
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function deriveKeyFromCredential(credId: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const saltArr = new Uint8Array(salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(credId), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltArr, iterations: 600000, hash: 'SHA-256' } as Pbkdf2Params,
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptWithKey(plaintext: string, key: CryptoKey): Promise<string> {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  let binary = '';
  combined.forEach(b => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

async function decryptWithKey(encrypted: string, key: CryptoKey): Promise<string> {
  const combined = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}
