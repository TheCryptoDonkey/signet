import { openDB, type IDBPDatabase } from 'idb';

const DB_NAME = 'signet';
const DB_VERSION = 2;

export type EntityType =
  | 'natural_person'
  | 'persona'
  | 'personal_agent'
  | 'free_personal_agent'
  | 'juridical_person'
  | 'juridical_persona'
  | 'organised_agent'
  | 'free_organised_agent'
  | 'free_agent';

export interface StoredIdentity {
  id: string; // pubkey (was 'current' in v1)
  mnemonic?: string; // optional — nsec imports have none
  publicKey: string;
  privateKey: string;
  role: 'adult' | 'child' | 'verifier';
  displayName: string;
  createdAt: number;
  importMethod: 'mnemonic' | 'nsec';
  entityType?: EntityType;
  guardianPubkey?: string; // for child accounts
  linkedPersonaPubkey?: string; // link between Natural Person and Persona
  ageRange?: string;
  isChild?: boolean;
}

export interface StoredConnection {
  pubkey: string;
  sharedSecret: string;
  ownerPubkey: string; // which account owns this connection
  theirInfo: {
    name?: string;
    mobile?: string;
    email?: string;
    address?: string;
    childPubkeys?: string[];
  };
  ourInfo: {
    name?: string;
    mobile?: string;
    email?: string;
    address?: string;
    childPubkeys?: string[];
  };
  connectedAt: number;
  method: string;
}

export interface StoredPreferences {
  id: 'current';
  theme: 'system' | 'light' | 'dark';
  activeAccountId?: string; // pubkey of active account
  relayUrl?: string;
}

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDB() {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db, oldVersion, _newVersion, transaction) {
        // v1: create stores
        if (oldVersion < 1) {
          db.createObjectStore('identity', { keyPath: 'id' });
          db.createObjectStore('connections', { keyPath: 'pubkey' });
          db.createObjectStore('preferences', { keyPath: 'id' });
        }

        // v1 → v2: migrate identity id from 'current' to pubkey, add ownerPubkey to connections
        if (oldVersion < 2) {
          const identityStore = transaction.objectStore('identity');
          const connectionsStore = transaction.objectStore('connections');
          const prefsStore = transaction.objectStore('preferences');

          // Migrate existing identity (idb wraps stores — .get()/.getAll() return Promises)
          identityStore.get('current').then((old: Record<string, unknown> | undefined) => {
            if (old && old.publicKey) {
              const pubkey = old.publicKey as string;
              identityStore.delete('current');
              identityStore.put({
                ...old,
                id: pubkey,
                importMethod: (old.importMethod as string) || 'mnemonic',
              });

              prefsStore.get('current').then((prefs: Record<string, unknown> | undefined) => {
                const p = prefs || { id: 'current', theme: 'system' };
                prefsStore.put({ ...p, activeAccountId: pubkey });
              });

              connectionsStore.getAll().then((conns: Record<string, unknown>[]) => {
                for (const conn of conns) {
                  if (!conn.ownerPubkey) {
                    connectionsStore.put({ ...conn, ownerPubkey: pubkey });
                  }
                }
              });
            }
          });
        }
      },
    });
  }
  return dbPromise;
}

// Identity — multi-account
export async function getIdentity(pubkey: string): Promise<StoredIdentity | undefined> {
  const db = await getDB();
  return db.get('identity', pubkey);
}

export async function getAllIdentities(): Promise<StoredIdentity[]> {
  const db = await getDB();
  return db.getAll('identity');
}

export async function getActiveIdentity(): Promise<StoredIdentity | undefined> {
  const prefs = await getPreferences();
  if (!prefs.activeAccountId) {
    // Fallback: return first identity
    const all = await getAllIdentities();
    return all[0];
  }
  return getIdentity(prefs.activeAccountId);
}

export async function saveIdentity(identity: StoredIdentity): Promise<void> {
  const db = await getDB();
  await db.put('identity', identity);
}

export async function deleteIdentity(pubkey: string): Promise<void> {
  const db = await getDB();
  await db.delete('identity', pubkey);
}

export async function setActiveAccount(pubkey: string): Promise<void> {
  const prefs = await getPreferences();
  prefs.activeAccountId = pubkey;
  await savePreferences(prefs);
}

// Connections — scoped by owner
export async function getConnections(): Promise<StoredConnection[]> {
  const db = await getDB();
  return db.getAll('connections');
}

export async function getConnectionsForAccount(ownerPubkey: string): Promise<StoredConnection[]> {
  const all = await getConnections();
  return all.filter((c) => c.ownerPubkey === ownerPubkey);
}

export async function getConnection(pubkey: string): Promise<StoredConnection | undefined> {
  const db = await getDB();
  return db.get('connections', pubkey);
}

export async function saveConnection(connection: StoredConnection): Promise<void> {
  const db = await getDB();
  await db.put('connections', connection);
}

export async function deleteConnection(pubkey: string): Promise<void> {
  const db = await getDB();
  await db.delete('connections', pubkey);
}

export async function clearConnections(): Promise<void> {
  const db = await getDB();
  await db.clear('connections');
}

// Preferences
export async function getPreferences(): Promise<StoredPreferences> {
  const db = await getDB();
  const prefs = await db.get('preferences', 'current');
  return prefs ?? { id: 'current', theme: 'system' };
}

export async function savePreferences(prefs: StoredPreferences): Promise<void> {
  const db = await getDB();
  await db.put('preferences', prefs);
}
