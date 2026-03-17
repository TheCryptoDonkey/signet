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

/** The PRF salt used with WebAuthn PRF extension — app-specific, constant */
const PRF_SALT = new Uint8Array([
  0x73, 0x69, 0x67, 0x6e, 0x65, 0x74, 0x2d, 0x70,  // "signet-p"
  0x72, 0x66, 0x2d, 0x73, 0x61, 0x6c, 0x74, 0x2d,  // "rf-salt-"
  0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // "v1" + padding
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 32 bytes total
]);

/** Get the relying party ID for WebAuthn */
function getRpId(): string {
  return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? window.location.hostname
    : 'signet.trotters.cc';
}

/**
 * Set up biometric auth — creates a WebAuthn credential.
 * Tries PRF extension first (hardware-derived key). Falls back to credential-ID-based
 * key derivation if PRF is unavailable (weaker but still biometric-gated).
 */
export async function setupBiometric(encryptionKey: string): Promise<boolean> {
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    // Request PRF extension during credential creation
    const createOptions: PublicKeyCredentialCreationOptions & { extensions?: Record<string, unknown> } = {
      challenge,
      rp: { name: 'My Signet', id: getRpId() },
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
      extensions: { prf: {} },
      timeout: 60000,
    };

    const credential = await navigator.credentials.create({
      publicKey: createOptions,
    }) as PublicKeyCredential | null;

    if (!credential) return false;

    const credId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    localStorage.setItem(CREDENTIAL_ID_KEY, credId);

    // Check if PRF extension is supported by the authenticator
    const extensions = (credential as PublicKeyCredential & { getClientExtensionResults(): Record<string, unknown> }).getClientExtensionResults();
    const prfSupported = !!(extensions?.prf && (extensions.prf as Record<string, unknown>)?.enabled);

    if (prfSupported) {
      // PRF available: get hardware-derived key material via assertion
      const prfKey = await getPRFKey(credId);
      if (prfKey) {
        const derivedKey = await deriveKeyFromPRF(prfKey);
        const encrypted = await encryptWithKey(encryptionKey, derivedKey);
        localStorage.setItem(ENCRYPTED_KEY_KEY, JSON.stringify({ encrypted, prf: true }));
        localStorage.setItem(AUTH_METHOD_KEY, 'biometric');
        return true;
      }
    }

    // PRF not available: fall back to credential-ID-based derivation (weaker)
    // The biometric assertion still gates access, but the key material is derived from
    // the credential ID which is stored in localStorage. This is secure against live
    // attacks (need biometric) but not against offline extraction of localStorage.
    const deviceSalt = crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await deriveKeyFromCredential(credId, deviceSalt);
    const encrypted = await encryptWithKey(encryptionKey, derivedKey);

    localStorage.setItem(
      ENCRYPTED_KEY_KEY,
      JSON.stringify({ encrypted, salt: btoa(String.fromCharCode(...deviceSalt)), prf: false }),
    );
    localStorage.setItem(AUTH_METHOD_KEY, 'biometric');

    return true;
  } catch {
    return false;
  }
}

/** Get PRF output from the authenticator via assertion */
async function getPRFKey(credIdB64: string): Promise<ArrayBuffer | null> {
  try {
    const credIdBytes = Uint8Array.from(atob(credIdB64), c => c.charCodeAt(0));
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{ id: credIdBytes, type: 'public-key', transports: ['internal'] }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: PRF_SALT } } } as Record<string, unknown>,
        timeout: 60000,
      },
    }) as PublicKeyCredential | null;

    if (!assertion) return null;

    const extensions = (assertion as PublicKeyCredential & { getClientExtensionResults(): Record<string, unknown> }).getClientExtensionResults();
    const prfResults = extensions?.prf as Record<string, unknown> | undefined;
    const results = prfResults?.results as Record<string, ArrayBuffer> | undefined;

    return results?.first ?? null;
  } catch {
    return null;
  }
}

/** Derive an AES-256-GCM key from PRF output (hardware-derived, high entropy) */
async function deriveKeyFromPRF(prfOutput: ArrayBuffer): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: PRF_SALT, info: new TextEncoder().encode('signet-encryption-key') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
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

    const raw = localStorage.getItem(ENCRYPTED_KEY_KEY);
    if (!raw) return null;
    const stored = JSON.parse(raw) as Record<string, unknown>;
    if (typeof stored.encrypted !== 'string') return null;

    const usesPRF = stored.prf === true;

    if (usesPRF) {
      // PRF path: get hardware-derived key from authenticator
      const prfKey = await getPRFKey(credIdB64);
      if (!prfKey) return null;
      const derivedKey = await deriveKeyFromPRF(prfKey);
      return await decryptWithKey(stored.encrypted, derivedKey);
    } else {
      // Fallback path: biometric assertion + credential-ID-based key
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

      if (typeof stored.salt !== 'string') return null;
      const salt = Uint8Array.from(atob(stored.salt), c => c.charCodeAt(0));
      const derivedKey = await deriveKeyFromCredential(credIdB64, salt);
      return await decryptWithKey(stored.encrypted, derivedKey);
    }
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
  localStorage.removeItem('signet-pin-attempts');
  localStorage.removeItem('signet-pin-locked');
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
