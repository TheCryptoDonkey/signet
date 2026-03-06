import { buildBadgeFilters, computeBadge, RelayClient } from 'signet-protocol';
import type { EntityType } from 'signet-protocol';
import type { CachedBadge } from './db';

/** Fetch badge data for a pubkey from a relay. Returns null if relay is unreachable. */
export async function fetchBadge(
  pubkey: string,
  relayUrl: string,
  timeoutMs = 10000
): Promise<CachedBadge | null> {
  const relay = new RelayClient(relayUrl, { connectTimeout: timeoutMs });
  try {
    await relay.connect();
    const filters = buildBadgeFilters([pubkey]);
    const events = await relay.fetch(filters);
    const badge = await computeBadge(pubkey, events);

    // Extract entity type from credential events
    let entityType: EntityType | undefined;
    for (const event of events) {
      if (event.kind !== 30470) continue;
      const d = event.tags.find(t => t[0] === 'd')?.[1];
      if (d !== pubkey) continue;
      const et = event.tags.find(t => t[0] === 'entity-type')?.[1];
      if (et) { entityType = et as EntityType; break; }
    }

    return {
      tier: badge.tier,
      tierLabel: badge.tierLabel,
      score: badge.score,
      entityType,
      isVerified: badge.isVerified,
      credentialCount: badge.credentialCount,
      vouchCount: badge.vouchCount,
      fetchedAt: Math.floor(Date.now() / 1000),
    };
  } catch {
    return null;
  } finally {
    relay.disconnect();
  }
}

/** Fetch badges for multiple pubkeys in a single relay query. */
export async function fetchBadges(
  pubkeys: string[],
  relayUrl: string,
  timeoutMs = 10000
): Promise<Map<string, CachedBadge>> {
  const results = new Map<string, CachedBadge>();
  if (pubkeys.length === 0) return results;

  const relay = new RelayClient(relayUrl, { connectTimeout: timeoutMs });
  try {
    await relay.connect();
    const filters = buildBadgeFilters(pubkeys);
    const events = await relay.fetch(filters);

    for (const pubkey of pubkeys) {
      const badge = await computeBadge(pubkey, events);

      let entityType: EntityType | undefined;
      for (const event of events) {
        if (event.kind !== 30470) continue;
        const d = event.tags.find(t => t[0] === 'd')?.[1];
        if (d !== pubkey) continue;
        const et = event.tags.find(t => t[0] === 'entity-type')?.[1];
        if (et) { entityType = et as EntityType; break; }
      }

      results.set(pubkey, {
        tier: badge.tier,
        tierLabel: badge.tierLabel,
        score: badge.score,
        entityType,
        isVerified: badge.isVerified,
        credentialCount: badge.credentialCount,
        vouchCount: badge.vouchCount,
        fetchedAt: Math.floor(Date.now() / 1000),
      });
    }
  } catch {
    // Relay unreachable — return empty map
  } finally {
    relay.disconnect();
  }
  return results;
}
