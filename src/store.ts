// Signet Event Store
// In-memory event storage with query support and JSON serialization

import { SIGNET_KINDS } from './constants.js';
import { getTagValue, validateFieldSizeBounds } from './validation.js';
import { SignetValidationError } from './errors.js';
import type {
  NostrEvent,
  ParsedCredential,
} from './types.js';
import { parseCredential } from './credentials.js';

/** Query options for filtering events */
export interface StoreQuery {
  kinds?: number[];
  authors?: string[];
  subjects?: string[];  // query by 'd' tag
  since?: number;
  until?: number;
  limit?: number;
}

/**
 * In-memory Signet event store.
 * Stores events indexed by kind, author, and subject for fast queries.
 * Handles replaceable event semantics (kind 30xxx: newer replaces older for same d-tag).
 */
export class SignetStore {
  private events = new Map<string, NostrEvent>();

  // Indexes for fast queries
  private byKind = new Map<number, Set<string>>();
  private byAuthor = new Map<string, Set<string>>();
  private bySubject = new Map<string, Set<string>>();

  /** Add an event to the store. Returns true if added (not a duplicate/older). */
  add(event: NostrEvent): boolean {
    // Check if this is a replaceable event (kind 30000-39999)
    if (event.kind >= 30000 && event.kind < 40000) {
      const dTag = getTagValue(event, 'd');

      // Find existing event with same replace key
      for (const [id, existing] of this.events) {
        if (existing.kind === event.kind && existing.pubkey === event.pubkey) {
          const existingD = getTagValue(existing, 'd');
          if (existingD === dTag) {
            if (existing.created_at >= event.created_at) {
              return false; // existing is newer or same
            }
            // Remove older event
            this.remove(id);
            break;
          }
        }
      }
    }

    // Deduplicate by event ID
    if (this.events.has(event.id)) return false;

    this.events.set(event.id, event);
    this.indexEvent(event);
    return true;
  }

  /** Remove an event by ID */
  remove(id: string): boolean {
    const event = this.events.get(id);
    if (!event) return false;

    this.events.delete(id);
    this.deindexEvent(event);
    return true;
  }

  /** Get an event by ID */
  get(id: string): NostrEvent | undefined {
    return this.events.get(id);
  }

  /** Check if an event exists */
  has(id: string): boolean {
    return this.events.has(id);
  }

  /** Total number of events */
  get size(): number {
    return this.events.size;
  }

  /** Query events with filters */
  query(q: StoreQuery = {}): NostrEvent[] {
    let candidateIds: Set<string> | null = null;

    // Narrow by kind
    if (q.kinds?.length) {
      const kindIds = new Set<string>();
      for (const kind of q.kinds) {
        const ids = this.byKind.get(kind);
        if (ids) ids.forEach((id) => kindIds.add(id));
      }
      candidateIds = kindIds;
    }

    // Narrow by author
    if (q.authors?.length) {
      const authorIds = new Set<string>();
      for (const author of q.authors) {
        const ids = this.byAuthor.get(author);
        if (ids) ids.forEach((id) => authorIds.add(id));
      }
      candidateIds = candidateIds
        ? intersect(candidateIds, authorIds)
        : authorIds;
    }

    // Narrow by subject
    if (q.subjects?.length) {
      const subjectIds = new Set<string>();
      for (const subject of q.subjects) {
        const ids = this.bySubject.get(subject);
        if (ids) ids.forEach((id) => subjectIds.add(id));
      }
      candidateIds = candidateIds
        ? intersect(candidateIds, subjectIds)
        : subjectIds;
    }

    // Collect events
    const ids = candidateIds ?? new Set(this.events.keys());
    let results: NostrEvent[] = [];
    for (const id of ids) {
      const event = this.events.get(id);
      if (!event) continue;

      if (q.since && event.created_at < q.since) continue;
      if (q.until && event.created_at > q.until) continue;

      results.push(event);
    }

    // Sort by created_at descending (newest first)
    results.sort((a, b) => b.created_at - a.created_at);

    if (q.limit && results.length > q.limit) {
      results = results.slice(0, q.limit);
    }

    return results;
  }

  // --- Convenience query methods ---

  /** Get all credentials for a subject */
  getCredentials(subjectPubkey: string): NostrEvent[] {
    return this.query({ kinds: [SIGNET_KINDS.CREDENTIAL], subjects: [subjectPubkey] });
  }

  /** Get the highest-tier credential for a subject */
  getHighestCredential(subjectPubkey: string): ParsedCredential | null {
    const creds = this.getCredentials(subjectPubkey);
    let highest: ParsedCredential | null = null;

    for (const cred of creds) {
      const parsed = parseCredential(cred);
      if (parsed && (!highest || parsed.tier > highest.tier)) {
        highest = parsed;
      }
    }

    return highest;
  }

  /** Get all vouches for a subject */
  getVouches(subjectPubkey: string): NostrEvent[] {
    return this.query({ kinds: [SIGNET_KINDS.VOUCH], subjects: [subjectPubkey] });
  }

  /** Get the community policy for a community */
  getPolicy(communityId: string): NostrEvent | undefined {
    const policies = this.query({ kinds: [SIGNET_KINDS.POLICY] });
    return policies.find((p) => getTagValue(p, 'd') === communityId);
  }

  /** Get a verifier credential */
  getVerifierCredential(verifierPubkey: string): NostrEvent | undefined {
    const creds = this.query({ kinds: [SIGNET_KINDS.VERIFIER], authors: [verifierPubkey] });
    return creds[0];
  }

  /** Get all challenges against a verifier */
  getChallenges(verifierPubkey: string): NostrEvent[] {
    return this.query({ kinds: [SIGNET_KINDS.CHALLENGE], subjects: [verifierPubkey] });
  }

  /** Get all revocations for a verifier */
  getRevocations(verifierPubkey: string): NostrEvent[] {
    return this.query({ kinds: [SIGNET_KINDS.REVOCATION], subjects: [verifierPubkey] });
  }

  /** Check if a verifier is revoked */
  isRevoked(verifierPubkey: string): boolean {
    return this.getRevocations(verifierPubkey).length > 0;
  }

  /** Get all credentials issued by a verifier */
  getCredentialsByIssuer(issuerPubkey: string): NostrEvent[] {
    return this.query({ kinds: [SIGNET_KINDS.CREDENTIAL], authors: [issuerPubkey] });
  }

  // --- Serialization ---

  /** Export all events as JSON */
  export(): string {
    return JSON.stringify(Array.from(this.events.values()));
  }

  /** Import events from JSON */
  import(json: string): number {
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new SignetValidationError('Import data is not valid JSON');
    }
    if (!Array.isArray(parsed)) {
      throw new SignetValidationError('Import data must be a JSON array');
    }
    const events: NostrEvent[] = [];
    for (const item of parsed) {
      if (
        typeof item !== 'object' || item === null ||
        typeof item.id !== 'string' ||
        typeof item.pubkey !== 'string' ||
        typeof item.kind !== 'number' ||
        typeof item.created_at !== 'number' ||
        !Array.isArray(item.tags) ||
        typeof item.content !== 'string' ||
        typeof item.sig !== 'string' ||
        !item.tags.every((t: unknown) => Array.isArray(t) && t.every((v: unknown) => typeof v === 'string'))
      ) {
        continue; // skip malformed entries
      }
      // Validate field-size bounds on imported events
      const boundsErrors: string[] = [];
      validateFieldSizeBounds(item as NostrEvent, boundsErrors);
      if (boundsErrors.length > 0) continue;

      events.push(item as NostrEvent);
    }
    let added = 0;
    for (const event of events) {
      if (this.add(event)) added++;
    }
    return added;
  }

  /** Clear all events */
  clear(): void {
    this.events.clear();
    this.byKind.clear();
    this.byAuthor.clear();
    this.bySubject.clear();
  }

  // --- Index management ---

  private indexEvent(event: NostrEvent): void {
    // Index by kind
    if (!this.byKind.has(event.kind)) this.byKind.set(event.kind, new Set());
    this.byKind.get(event.kind)!.add(event.id);

    // Index by author
    if (!this.byAuthor.has(event.pubkey)) this.byAuthor.set(event.pubkey, new Set());
    this.byAuthor.get(event.pubkey)!.add(event.id);

    // Index by subject (d tag)
    const subject = getTagValue(event, 'd');
    if (subject) {
      if (!this.bySubject.has(subject)) this.bySubject.set(subject, new Set());
      this.bySubject.get(subject)!.add(event.id);
    }

    // Also index by p tag (many events reference subjects via p tag)
    const pTags = event.tags.filter((t) => t[0] === 'p').map((t) => t[1]);
    for (const p of pTags) {
      if (!this.bySubject.has(p)) this.bySubject.set(p, new Set());
      this.bySubject.get(p)!.add(event.id);
    }
  }

  private deindexEvent(event: NostrEvent): void {
    this.byKind.get(event.kind)?.delete(event.id);
    this.byAuthor.get(event.pubkey)?.delete(event.id);

    const subject = getTagValue(event, 'd');
    if (subject) this.bySubject.get(subject)?.delete(event.id);

    const pTags = event.tags.filter((t) => t[0] === 'p').map((t) => t[1]);
    for (const p of pTags) {
      this.bySubject.get(p)?.delete(event.id);
    }
  }
}

/** Set intersection */
function intersect(a: Set<string>, b: Set<string>): Set<string> {
  const result = new Set<string>();
  const [smaller, larger] = a.size <= b.size ? [a, b] : [b, a];
  for (const item of smaller) {
    if (larger.has(item)) result.add(item);
  }
  return result;
}
