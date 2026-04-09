// Migration Event (kind 31000, type: migration)
// Allows an identity to publish a signed record linking an old pubkey to a new pubkey.
// The event is signed by the OLD private key, proving the old identity authorised the migration.
// See spec/protocol.md §21.4.3 for the full migration lifecycle.

import { createAttestation } from 'nostr-attestations';
import { ATTESTATION_KIND } from './constants.js';
import { signEvent, getPublicKey } from './crypto.js';
import { getTagValue } from './validation.js';
import type { NostrEvent } from './types.js';

/** Maximum number of hops followed when resolving a migration chain (matches credential chain depth) */
const MAX_CHAIN_DEPTH = 100;

/** The attestation type identifier for migration events */
const MIGRATION_TYPE = 'migration';

/**
 * Create and sign a migration event (kind 31000, type: migration).
 *
 * The event is signed by the old private key, proving the old identity
 * authorised the migration to the new pubkey.
 *
 * @param oldPrivateKey - Private key of the old (migrating-away) identity
 * @param newPubkey     - x-only hex pubkey of the new (receiving) identity
 * @returns Signed kind 31000 migration event
 */
export async function createMigrationEvent(
  oldPrivateKey: string,
  newPubkey: string
): Promise<NostrEvent> {
  const oldPubkey = getPublicKey(oldPrivateKey);

  const template = createAttestation({
    type: MIGRATION_TYPE,
    identifier: oldPubkey,
    subject: newPubkey,
    content: '',
  });

  const unsigned = {
    ...template,
    pubkey: oldPubkey,
    created_at: Math.floor(Date.now() / 1000),
  };

  return signEvent(unsigned, oldPrivateKey);
}

/**
 * Parse a migration event, returning the old and new pubkeys.
 *
 * @param event - The event to parse
 * @returns `{ oldPubkey, newPubkey }` or `null` if the event is not a valid migration event
 */
export function parseMigrationEvent(
  event: NostrEvent
): { oldPubkey: string; newPubkey: string } | null {
  if (event.kind !== ATTESTATION_KIND) return null;
  if (getTagValue(event, 'type') !== MIGRATION_TYPE) return null;

  const newPubkey = getTagValue(event, 'p');
  if (!newPubkey) return null;

  // The signer of the migration event is the old identity
  const oldPubkey = event.pubkey;

  return { oldPubkey, newPubkey };
}

/**
 * Follow a chain of migration events to find the current active pubkey.
 *
 * Given a starting pubkey and a set of events, this function follows migration
 * events to their conclusion. If pubkey A migrated to B, and B migrated to C,
 * the function returns C.
 *
 * Cycle detection is enforced via a visited set. If a cycle is detected or the
 * chain exceeds MAX_CHAIN_DEPTH hops, the last successfully reached pubkey is
 * returned rather than throwing.
 *
 * @param pubkey - Starting pubkey to follow
 * @param events - Pool of events to search for migration records
 * @returns The current (final) active pubkey after following all migrations
 */
export function followMigrationChain(pubkey: string, events: NostrEvent[]): string {
  // Build a map from old pubkey → new pubkey using valid migration events
  const migrations = new Map<string, string>();
  for (const event of events) {
    const parsed = parseMigrationEvent(event);
    if (parsed) {
      // Only record the first migration found for each old pubkey
      if (!migrations.has(parsed.oldPubkey)) {
        migrations.set(parsed.oldPubkey, parsed.newPubkey);
      }
    }
  }

  const visited = new Set<string>();
  let current = pubkey;

  while (migrations.has(current)) {
    if (visited.has(current)) break;          // cycle detected
    if (visited.size >= MAX_CHAIN_DEPTH) break; // depth limit reached
    visited.add(current);
    current = migrations.get(current)!;
  }

  return current;
}
