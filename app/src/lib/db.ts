// IndexedDB storage for My Signet family app

import { openDB, type IDBPDatabase } from 'idb';
import type { SignetIdentity, FamilyMember, ChildSettings, AppPreferences, IdentityDocument, StoredCredential } from '../types';
import { encryptSecret, decryptSecret } from './crypto-store';

export { encryptSecret, decryptSecret } from './crypto-store';

const DB_NAME = 'my-signet';
const DB_VERSION = 2;

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDB(): Promise<IDBPDatabase> {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db, oldVersion) {
        // Version 1 stores
        if (oldVersion < 1) {
          if (!db.objectStoreNames.contains('identity')) {
            db.createObjectStore('identity', { keyPath: 'id' });
          }
          if (!db.objectStoreNames.contains('family')) {
            const family = db.createObjectStore('family', { keyPath: 'pubkey' });
            family.createIndex('ownerPubkey', 'ownerPubkey');
          }
          if (!db.objectStoreNames.contains('child-settings')) {
            db.createObjectStore('child-settings', { keyPath: 'childPubkey' });
          }
          if (!db.objectStoreNames.contains('preferences')) {
            db.createObjectStore('preferences', { keyPath: 'id' });
          }
        }
        // Version 2 stores
        if (oldVersion < 2) {
          if (!db.objectStoreNames.contains('documents')) {
            const documents = db.createObjectStore('documents', { keyPath: 'id' });
            documents.createIndex('ownerPubkey', 'ownerPubkey');
          }
          if (!db.objectStoreNames.contains('credentials')) {
            const credentials = db.createObjectStore('credentials', { keyPath: 'id' });
            credentials.createIndex('documentId', 'documentId');
          }
        }
      },
    });
  }
  return dbPromise;
}

// --- Identity ---

export async function getIdentity(pubkey: string): Promise<SignetIdentity | undefined> {
  const db = await getDB();
  return db.get('identity', pubkey);
}

export async function getAllIdentities(): Promise<SignetIdentity[]> {
  const db = await getDB();
  return db.getAll('identity');
}

/**
 * @deprecated Stores privateKey and mnemonic in plaintext.
 * Use saveIdentityEncrypted instead to protect private key material at rest.
 */
export async function saveIdentity(identity: SignetIdentity): Promise<void> {
  const db = await getDB();
  await db.put('identity', identity);
}

/**
 * Encrypt private keys and mnemonic with a passphrase-derived AES-256-GCM key before storing.
 * The stored record has encrypted: true so callers know to decrypt on load.
 */
export async function saveIdentityEncrypted(identity: SignetIdentity, passphrase: string): Promise<void> {
  const encryptedNpPrivateKey = await encryptSecret(identity.naturalPerson.privateKey, passphrase);
  const encryptedPersonaPrivateKey = await encryptSecret(identity.persona.privateKey, passphrase);
  const encryptedMnemonic = await encryptSecret(identity.mnemonic, passphrase);

  const encryptedIdentity: SignetIdentity = {
    ...identity,
    naturalPerson: {
      ...identity.naturalPerson,
      privateKey: encryptedNpPrivateKey,
    },
    persona: {
      ...identity.persona,
      privateKey: encryptedPersonaPrivateKey,
    },
    mnemonic: encryptedMnemonic,
    encrypted: true,
  };

  const db = await getDB();
  await db.put('identity', encryptedIdentity);
}

/**
 * Load an identity and decrypt private keys and mnemonic if they were stored encrypted.
 * Returns undefined if no identity exists for the given pubkey.
 * Throws if decryption fails (wrong passphrase).
 */
export async function loadIdentityDecrypted(pubkey: string, passphrase: string): Promise<SignetIdentity | undefined> {
  const db = await getDB();
  const stored: SignetIdentity | undefined = await db.get('identity', pubkey);
  if (!stored) return undefined;

  if (!stored.encrypted) return stored;

  const npPrivateKey = await decryptSecret(stored.naturalPerson.privateKey, passphrase);
  const personaPrivateKey = await decryptSecret(stored.persona.privateKey, passphrase);
  const mnemonic = await decryptSecret(stored.mnemonic, passphrase);

  return {
    ...stored,
    naturalPerson: { ...stored.naturalPerson, privateKey: npPrivateKey },
    persona: { ...stored.persona, privateKey: personaPrivateKey },
    mnemonic,
    encrypted: false,
  };
}

export async function deleteIdentityRecord(pubkey: string): Promise<void> {
  const db = await getDB();
  await db.delete('identity', pubkey);
}

// --- Family Members ---

export async function getFamilyMembers(ownerPubkey: string): Promise<FamilyMember[]> {
  const db = await getDB();
  return db.getAllFromIndex('family', 'ownerPubkey', ownerPubkey);
}

export async function getFamilyMember(pubkey: string): Promise<FamilyMember | undefined> {
  const db = await getDB();
  return db.get('family', pubkey);
}

export async function saveFamilyMember(member: FamilyMember): Promise<void> {
  const db = await getDB();
  await db.put('family', member);
}

export async function deleteFamilyMember(pubkey: string): Promise<void> {
  const db = await getDB();
  await db.delete('family', pubkey);
}

// --- Child Settings ---

export async function getChildSettings(childPubkey: string): Promise<ChildSettings | undefined> {
  const db = await getDB();
  return db.get('child-settings', childPubkey);
}

export async function saveChildSettings(settings: ChildSettings): Promise<void> {
  const db = await getDB();
  await db.put('child-settings', settings);
}

// --- Preferences ---

export async function getPreferences(): Promise<AppPreferences> {
  const db = await getDB();
  const prefs = await db.get('preferences', 'current');
  return prefs || { id: 'current', theme: 'system' };
}

export async function savePreferences(prefs: AppPreferences): Promise<void> {
  const db = await getDB();
  await db.put('preferences', prefs);
}

// --- Identity Documents ---

export async function getDocument(id: string): Promise<IdentityDocument | undefined> {
  const db = await getDB();
  return db.get('documents', id);
}

export async function getDocumentsByOwner(ownerPubkey: string): Promise<IdentityDocument[]> {
  const db = await getDB();
  return db.getAllFromIndex('documents', 'ownerPubkey', ownerPubkey);
}

export async function saveDocument(document: IdentityDocument): Promise<void> {
  const db = await getDB();
  await db.put('documents', document);
}

export async function deleteDocument(id: string): Promise<void> {
  const db = await getDB();
  await db.delete('documents', id);
}

// --- Stored Credentials ---

export async function getCredential(id: string): Promise<StoredCredential | undefined> {
  const db = await getDB();
  return db.get('credentials', id);
}

export async function getCredentialsByDocument(documentId: string): Promise<StoredCredential[]> {
  const db = await getDB();
  return db.getAllFromIndex('credentials', 'documentId', documentId);
}

export async function getAllCredentials(): Promise<StoredCredential[]> {
  const db = await getDB();
  return db.getAll('credentials');
}

export async function saveCredential(credential: StoredCredential): Promise<void> {
  const db = await getDB();
  await db.put('credentials', credential);
}

export async function deleteCredential(id: string): Promise<void> {
  const db = await getDB();
  await db.delete('credentials', id);
}
