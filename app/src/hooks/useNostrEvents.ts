import { useState, useEffect, useCallback } from 'react';
import { SIGNET_KINDS, type NostrEvent } from 'signet-protocol';
import { getRelayClient, getRelayState } from '../lib/relay-service';

interface NostrEvents {
  credentials: NostrEvent[];
  vouches: NostrEvent[];
  bridges: NostrEvent[];
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

export function useNostrEvents(pubkey: string | undefined): NostrEvents {
  const [credentials, setCredentials] = useState<NostrEvent[]>([]);
  const [vouches, setVouches] = useState<NostrEvent[]>([]);
  const [bridges, setBridges] = useState<NostrEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    if (!pubkey) return;
    if (getRelayState() !== 'connected') return;

    setLoading(true);
    setError(null);

    try {
      const client = getRelayClient();

      // Fetch credentials (kind 30470) where this pubkey is the subject
      const creds = await client.fetch([
        { kinds: [SIGNET_KINDS.CREDENTIAL], '#d': [pubkey] },
      ]);
      setCredentials(creds);

      // Fetch vouches (kind 30471) for this pubkey
      const vs = await client.fetch([
        { kinds: [SIGNET_KINDS.VOUCH], '#d': [pubkey] },
      ]);
      setVouches(vs);

      // Fetch identity bridges (kind 30476) published by this pubkey
      const br = await client.fetch([
        { kinds: [SIGNET_KINDS.IDENTITY_BRIDGE], authors: [pubkey] },
      ]);
      setBridges(br);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch events');
    } finally {
      setLoading(false);
    }
  }, [pubkey]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  return { credentials, vouches, bridges, loading, error, refresh: fetchAll };
}
