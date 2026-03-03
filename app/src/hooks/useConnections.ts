import { useState, useEffect, useCallback } from 'react';
import {
  getConnectionsForAccount,
  saveConnection,
  deleteConnection as dbDeleteConnection,
  type StoredConnection,
} from '../lib/db';

export function useConnections(ownerPubkey: string | undefined) {
  const [connections, setConnections] = useState<StoredConnection[]>([]);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    if (!ownerPubkey) {
      setConnections([]);
      return;
    }
    const conns = await getConnectionsForAccount(ownerPubkey);
    setConnections(conns);
  }, [ownerPubkey]);

  useEffect(() => {
    reload().then(() => setLoading(false));
  }, [reload]);

  const addConnection = useCallback(async (connection: Omit<StoredConnection, 'ownerPubkey'>) => {
    if (!ownerPubkey) return;
    await saveConnection({ ...connection, ownerPubkey });
    await reload();
  }, [ownerPubkey, reload]);

  const removeConnection = useCallback(async (pubkey: string) => {
    await dbDeleteConnection(pubkey);
    await reload();
  }, [reload]);

  return { connections, loading, addConnection, removeConnection, reload };
}
