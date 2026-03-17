import { useState, useEffect, useCallback } from 'react';
import type { SignetIdentity } from '../types';
import * as db from '../lib/db';
import { createNewIdentity, importFromMnemonic, importFromNsec } from '../lib/signet';

export function useIdentity(encryptionKey?: string | null) {
  const [identities, setIdentities] = useState<SignetIdentity[]>([]);
  const [activeIdentity, setActiveIdentity] = useState<SignetIdentity | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAll = useCallback(async () => {
    const raw = await db.getAllIdentities();
    let all = raw;
    if (encryptionKey) {
      all = await Promise.all(raw.map(async (identity) => {
        if (!identity.encrypted) return identity;
        try {
          const decrypted = await db.loadIdentityDecrypted(identity.id, encryptionKey);
          return decrypted || identity;
        } catch {
          return identity; // fallback if decryption fails
        }
      }));
    }
    setIdentities(all);
    const prefs = await db.getPreferences();
    const active = prefs.activeAccountId
      ? all.find(i => i.id === prefs.activeAccountId) || all[0]
      : all[0];
    setActiveIdentity(active || null);
    setLoading(false);
  }, [encryptionKey]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const create = useCallback(async (
    displayName: string,
    primaryKeypair: 'natural-person' | 'persona',
    isChild: boolean,
    guardianPubkey?: string,
    overrideEncryptionKey?: string,
  ) => {
    const identity = createNewIdentity(displayName, primaryKeypair, isChild, guardianPubkey);
    const key = overrideEncryptionKey || encryptionKey;
    if (key) {
      await db.saveIdentityEncrypted(identity, key);
    } else {
      await db.saveIdentity(identity); // fallback for pre-auth state
    }
    await db.savePreferences({ ...(await db.getPreferences()), activeAccountId: identity.id });
    await loadAll();
    return identity;
  }, [loadAll, encryptionKey]);

  const restore = useCallback(async (
    mnemonic: string,
    displayName: string,
    primaryKeypair: 'natural-person' | 'persona',
    isChild: boolean,
    guardianPubkey?: string,
    overrideEncryptionKey?: string,
  ) => {
    const identity = importFromMnemonic(mnemonic, displayName, primaryKeypair, isChild, guardianPubkey);
    const key = overrideEncryptionKey || encryptionKey;
    if (key) {
      await db.saveIdentityEncrypted(identity, key);
    } else {
      await db.saveIdentity(identity); // fallback for pre-auth state
    }
    await db.savePreferences({ ...(await db.getPreferences()), activeAccountId: identity.id });
    await loadAll();
    return identity;
  }, [loadAll, encryptionKey]);

  const remove = useCallback(async (pubkey?: string) => {
    const target = pubkey || activeIdentity?.id;
    if (!target) return;
    await db.deleteIdentityRecord(target);
    const prefs = await db.getPreferences();
    if (prefs.activeAccountId === target) {
      await db.savePreferences({ ...prefs, activeAccountId: undefined });
    }
    await loadAll();
  }, [activeIdentity, loadAll]);

  const importNsec = useCallback(async (
    nsec: string,
    displayName: string,
    primaryKeypair: 'natural-person' | 'persona',
    overrideEncryptionKey?: string,
  ) => {
    const identity = importFromNsec(nsec, displayName, primaryKeypair);
    const key = overrideEncryptionKey || encryptionKey;
    if (key) {
      await db.saveIdentityEncrypted(identity, key);
    } else {
      await db.saveIdentity(identity); // fallback for pre-auth state
    }
    await db.savePreferences({ ...(await db.getPreferences()), activeAccountId: identity.id });
    await loadAll();
    return identity;
  }, [loadAll, encryptionKey]);

  const markBackedUp = useCallback(async (pubkey?: string) => {
    const target = pubkey || activeIdentity?.id;
    if (!target) return;
    const identity = encryptionKey
      ? await db.loadIdentityDecrypted(target, encryptionKey)
      : await db.getIdentity(target);
    if (!identity) return;
    const updated = { ...identity, backedUp: true };
    if (encryptionKey) {
      await db.saveIdentityEncrypted(updated, encryptionKey);
    } else {
      await db.saveIdentity(updated); // fallback for pre-auth state
    }
    await loadAll();
  }, [activeIdentity, loadAll, encryptionKey]);

  const switchPrimary = useCallback(async (keypair: 'natural-person' | 'persona') => {
    if (!activeIdentity) return;
    const updated = { ...activeIdentity, primaryKeypair: keypair, id: keypair === 'natural-person' ? activeIdentity.naturalPerson.publicKey : activeIdentity.persona.publicKey };
    if (encryptionKey) {
      await db.saveIdentityEncrypted(updated, encryptionKey);
    } else {
      await db.saveIdentity(updated); // fallback for pre-auth state
    }
    await db.savePreferences({ ...(await db.getPreferences()), activeAccountId: updated.id });
    await loadAll();
  }, [activeIdentity, loadAll, encryptionKey]);

  return { identity: activeIdentity, identities, loading, create, restore, importNsec, remove, markBackedUp, switchPrimary };
}
