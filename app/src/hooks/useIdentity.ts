import { useState, useEffect, useCallback } from 'react';
import {
  getAllIdentities,
  getActiveIdentity,
  saveIdentity,
  deleteIdentity as dbDeleteIdentity,
  setActiveAccount,
  type StoredIdentity,
} from '../lib/db';
import { createNewIdentity, importIdentity, importFromNsec } from '../lib/signet';

export function useIdentity() {
  const [identities, setIdentities] = useState<StoredIdentity[]>([]);
  const [activeIdentity, setActiveIdentity] = useState<StoredIdentity | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAll = useCallback(async () => {
    const all = await getAllIdentities();
    setIdentities(all);
    const active = await getActiveIdentity();
    setActiveIdentity(active ?? null);
  }, []);

  useEffect(() => {
    loadAll().then(() => setLoading(false));
  }, [loadAll]);

  const create = useCallback(async (role: StoredIdentity['role'], displayName: string) => {
    const newIdentity = createNewIdentity(role, displayName);
    await saveIdentity(newIdentity);
    await setActiveAccount(newIdentity.publicKey);
    await loadAll();
    return newIdentity;
  }, [loadAll]);

  const importMnemonic = useCallback(async (mnemonic: string, role: StoredIdentity['role'], displayName: string) => {
    const imported = importIdentity(mnemonic, role, displayName);
    await saveIdentity(imported);
    await setActiveAccount(imported.publicKey);
    await loadAll();
    return imported;
  }, [loadAll]);

  const importNsec = useCallback(async (nsec: string, role: StoredIdentity['role'], displayName: string) => {
    const imported = importFromNsec(nsec, role, displayName);
    await saveIdentity(imported);
    await setActiveAccount(imported.publicKey);
    await loadAll();
    return imported;
  }, [loadAll]);

  const switchAccount = useCallback(async (pubkey: string) => {
    await setActiveAccount(pubkey);
    await loadAll();
  }, [loadAll]);

  const remove = useCallback(async (pubkey?: string) => {
    const target = pubkey ?? activeIdentity?.publicKey;
    if (!target) return;
    await dbDeleteIdentity(target);
    // Switch to another account if available
    const remaining = identities.filter((i) => i.publicKey !== target);
    if (remaining.length > 0) {
      await setActiveAccount(remaining[0].publicKey);
    }
    await loadAll();
  }, [activeIdentity, identities, loadAll]);

  // Backward compat: expose identity as activeIdentity alias
  return {
    identity: activeIdentity,
    identities,
    activeIdentity,
    loading,
    create,
    importMnemonic,
    importNsec,
    switchAccount,
    deleteIdentity: remove,
  };
}
