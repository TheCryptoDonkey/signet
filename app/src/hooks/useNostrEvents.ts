import { useState, useEffect, useCallback } from 'react';
import { ATTESTATION_KIND, type NostrEvent } from 'signet-protocol';
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

      // Fetch credentials (kind 31000, type: credential) where this pubkey is the subject
      const creds = await client.fetch([
        { kinds: [ATTESTATION_KIND], '#d': [pubkey] },
      ]);
      setCredentials(creds);

      // Fetch vouches (kind 31000, type: vouch) for this pubkey
      const vs = await client.fetch([
        { kinds: [ATTESTATION_KIND], '#d': [pubkey] },
      ]);
      setVouches(vs);

      // Fetch identity bridges (kind 31000, type: identity-bridge) published by this pubkey
      const br = await client.fetch([
        { kinds: [ATTESTATION_KIND], authors: [pubkey] },
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
