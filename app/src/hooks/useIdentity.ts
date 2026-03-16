import { useState, useEffect, useCallback } from 'react';
import type { SignetIdentity } from '../types';
import * as db from '../lib/db';
import { createNewIdentity, importFromMnemonic } from '../lib/signet';

export function useIdentity() {
  const [identities, setIdentities] = useState<SignetIdentity[]>([]);
  const [activeIdentity, setActiveIdentity] = useState<SignetIdentity | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAll = useCallback(async () => {
    const all = await db.getAllIdentities();
    setIdentities(all);
    const prefs = await db.getPreferences();
    const active = prefs.activeAccountId
      ? all.find(i => i.id === prefs.activeAccountId) || all[0]
      : all[0];
    setActiveIdentity(active || null);
    setLoading(false);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const create = useCallback(async (
    displayName: string,
    primaryKeypair: 'natural-person' | 'persona',
    isChild: boolean,
    guardianPubkey?: string
  ) => {
    const identity = createNewIdentity(displayName, primaryKeypair, isChild, guardianPubkey);
    await db.saveIdentity(identity);
    await db.savePreferences({ ...(await db.getPreferences()), activeAccountId: identity.id });
    await loadAll();
    return identity;
  }, [loadAll]);

  const restore = useCallback(async (
    mnemonic: string,
    displayName: string,
    primaryKeypair: 'natural-person' | 'persona',
    isChild: boolean,
    guardianPubkey?: string
  ) => {
    const identity = importFromMnemonic(mnemonic, displayName, primaryKeypair, isChild, guardianPubkey);
    await db.saveIdentity(identity);
    await db.savePreferences({ ...(await db.getPreferences()), activeAccountId: identity.id });
    await loadAll();
    return identity;
  }, [loadAll]);

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

  const markBackedUp = useCallback(async (pubkey?: string) => {
    const target = pubkey || activeIdentity?.id;
    if (!target) return;
    const identity = await db.getIdentity(target);
    if (!identity) return;
    await db.saveIdentity({ ...identity, backedUp: true });
    await loadAll();
  }, [activeIdentity, loadAll]);

  return { identity: activeIdentity, identities, loading, create, restore, remove, markBackedUp };
}
