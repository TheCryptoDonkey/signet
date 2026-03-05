import { useCallback } from 'react';
import { fetchBadge } from '../lib/badge-fetch';
import { getConnection, saveConnection } from '../lib/db';

const STALE_THRESHOLD = 3600; // 1 hour in seconds

/** Refresh badge data for a contact if stale. Returns updated badge or null. */
export function useBadgeRefresh(relayUrl?: string) {
  const refreshBadge = useCallback(async (pubkey: string) => {
    if (!relayUrl) return null;

    const connection = await getConnection(pubkey);
    if (!connection) return null;

    // Skip if fresh
    const now = Math.floor(Date.now() / 1000);
    if (connection.badge && (now - connection.badge.fetchedAt) < STALE_THRESHOLD) {
      return connection.badge;
    }

    const badge = await fetchBadge(pubkey, relayUrl);
    if (badge) {
      await saveConnection({ ...connection, badge });
    }
    return badge;
  }, [relayUrl]);

  return { refreshBadge };
}
