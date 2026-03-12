// Nostr Relay Client
// WebSocket-based publish/subscribe with NIP-42 AUTH support

import { signEvent, getPublicKey, verifyEvent } from './crypto.js';
import type { NostrEvent, UnsignedEvent } from './types.js';
import { SignetValidationError } from './errors.js';

/** NIP-42 client authentication event kind */
const NIP42_AUTH_KIND = 22242;

/** Nostr relay message types (relay → client) */
export type RelayMessage =
  | ['EVENT', string, NostrEvent]
  | ['OK', string, boolean, string]
  | ['EOSE', string]
  | ['NOTICE', string]
  | ['AUTH', string];

/** Nostr subscription filter */
export interface NostrFilter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  '#d'?: string[];
  '#p'?: string[];
  '#L'?: string[];
  '#l'?: string[];
  since?: number;
  until?: number;
  limit?: number;
}

/** Subscription callback */
export type SubscriptionCallback = (event: NostrEvent) => void;

/** Relay connection state */
export type RelayState = 'connecting' | 'connected' | 'disconnected' | 'error';

/** Options for the relay client */
export interface RelayOptions {
  /** Private key for NIP-42 AUTH (hex) */
  authPrivateKey?: string;
  /** Connection timeout in ms (default: 5000) */
  connectTimeout?: number;
  /** Auto-reconnect on disconnect (default: true) */
  autoReconnect?: boolean;
  /** Reconnect delay in ms (default: 3000) */
  reconnectDelay?: number;
  /** Max reconnect attempts (default: 5) */
  maxReconnectAttempts?: number;
  /** Verify event signatures before delivering to callbacks (default: true).
   *  Events that fail verification are silently dropped. */
  verifyEvents?: boolean;
  /** Callback for rejected events (signature or ID verification failed) */
  onEventRejected?: (event: NostrEvent, reason: string) => void;
}

interface PendingSubscription {
  filters: NostrFilter[];
  callback: SubscriptionCallback;
  eoseCallback?: () => void;
}

interface PendingPublish {
  resolve: (result: { ok: boolean; message: string }) => void;
  timeout: ReturnType<typeof setTimeout>;
}

/**
 * Nostr relay client with NIP-42 AUTH support.
 * Handles publishing events, subscribing to filters, and authentication.
 */
export class RelayClient {
  private ws: WebSocket | null = null;
  private state: RelayState = 'disconnected';
  private subscriptions = new Map<string, PendingSubscription>();
  private pendingPublishes = new Map<string, PendingPublish>();
  private subCounter = 0;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private disconnectRequested = false;
  private onStateChange?: (state: RelayState) => void;

  constructor(
    private url: string,
    private options: RelayOptions = {}
  ) {
    if (!/^wss?:\/\//i.test(this.url)) {
      throw new SignetValidationError('Relay URL must use ws:// or wss:// scheme');
    }
    // Enforce TLS for non-localhost connections — identity data must not travel in cleartext
    if (/^ws:\/\//i.test(this.url) && !/^ws:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(this.url)) {
      throw new SignetValidationError('Relay URL must use wss:// for non-localhost connections');
    }
    this.options = {
      connectTimeout: 5000,
      autoReconnect: true,
      reconnectDelay: 3000,
      maxReconnectAttempts: 5,
      verifyEvents: true,
      ...options,
    };
  }

  /** Get current connection state */
  getState(): RelayState {
    return this.state;
  }

  /** Set a state change listener */
  onStateChanged(callback: (state: RelayState) => void): void {
    this.onStateChange = callback;
  }

  private setState(state: RelayState): void {
    this.state = state;
    this.onStateChange?.(state);
  }

  /** Connect to the relay */
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.state === 'connected') {
        resolve();
        return;
      }

      this.setState('connecting');

      const timeout = setTimeout(() => {
        this.ws?.close();
        reject(new SignetValidationError(`Connection timeout after ${this.options.connectTimeout}ms`));
      }, this.options.connectTimeout);

      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        clearTimeout(timeout);
        this.setState('connected');
        this.reconnectAttempts = 0;
        // Re-subscribe existing subscriptions
        for (const [id, sub] of this.subscriptions) {
          this.sendSubscription(id, sub.filters);
        }
        resolve();
      };

      this.ws.onclose = () => {
        clearTimeout(timeout);
        this.setState('disconnected');
        this.handleReconnect();
      };

      this.ws.onerror = () => {
        clearTimeout(timeout);
        this.setState('error');
        reject(new SignetValidationError('WebSocket connection failed'));
      };

      this.ws.onmessage = (msg) => {
        if (typeof msg.data !== 'string') return; // ignore binary frames
        this.handleMessage(msg.data);
      };
    });
  }

  /** Disconnect from the relay */
  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.disconnectRequested = true;
    this.ws?.close();
    this.ws = null;
    this.setState('disconnected');

    // Clean up pending publishes
    for (const [, pending] of this.pendingPublishes) {
      clearTimeout(pending.timeout);
      pending.resolve({ ok: false, message: 'Disconnected' });
    }
    this.pendingPublishes.clear();
  }

  /** Publish an event to the relay */
  async publish(event: NostrEvent): Promise<{ ok: boolean; message: string }> {
    if (this.state !== 'connected' || !this.ws) {
      throw new SignetValidationError('Not connected to relay');
    }

    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this.pendingPublishes.delete(event.id);
        resolve({ ok: false, message: 'Publish timeout' });
      }, 10000);

      this.pendingPublishes.set(event.id, { resolve, timeout });
      this.ws!.send(JSON.stringify(['EVENT', event]));
    });
  }

  /**
   * Subscribe to events matching the given filters.
   * @returns Subscription ID (use to close the subscription)
   */
  subscribe(
    filters: NostrFilter[],
    onEvent: SubscriptionCallback,
    onEose?: () => void
  ): string {
    const subId = `signet-sub-${++this.subCounter}`;

    this.subscriptions.set(subId, {
      filters,
      callback: onEvent,
      eoseCallback: onEose,
    });

    if (this.state === 'connected') {
      this.sendSubscription(subId, filters);
    }

    return subId;
  }

  /** Close a subscription */
  closeSubscription(subId: string): void {
    this.subscriptions.delete(subId);
    if (this.state === 'connected' && this.ws) {
      this.ws.send(JSON.stringify(['CLOSE', subId]));
    }
  }

  /**
   * Fetch events matching filters (returns after EOSE).
   * Convenience method that subscribes, collects events, and closes.
   */
  fetch(filters: NostrFilter[], timeoutMs: number = 30000): Promise<NostrEvent[]> {
    return new Promise((resolve) => {
      const events: NostrEvent[] = [];
      let resolved = false;

      const done = () => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timer);
        this.closeSubscription(subId);
        resolve(events);
      };

      const maxEvents = 10_000;
      const subId = this.subscribe(
        filters,
        (event) => { events.push(event); if (events.length >= maxEvents) done(); },
        () => done(),
      );

      // Timeout guard: resolve with events collected so far if EOSE never arrives
      const timer = setTimeout(() => done(), timeoutMs);
    });
  }

  private sendSubscription(subId: string, filters: NostrFilter[]): void {
    if (this.ws) {
      this.ws.send(JSON.stringify(['REQ', subId, ...filters]));
    }
  }

  private handleMessage(data: string): void {
    try {
      const msg: unknown = JSON.parse(data);
      if (!Array.isArray(msg) || msg.length < 2 || typeof msg[0] !== 'string') return;

      switch (msg[0]) {
        case 'EVENT': {
          if (msg.length < 3 || typeof msg[1] !== 'string' || typeof msg[2] !== 'object' || msg[2] === null) break;
          const raw = msg[2] as Record<string, unknown>;
          // Validate required NostrEvent fields before casting
          if (typeof raw.id !== 'string' || typeof raw.pubkey !== 'string' ||
              typeof raw.kind !== 'number' || typeof raw.created_at !== 'number' ||
              !Array.isArray(raw.tags) || typeof raw.content !== 'string' ||
              typeof raw.sig !== 'string') break;
          const subId = msg[1] as string;
          const event = raw as unknown as NostrEvent;
          const sub = this.subscriptions.get(subId);
          if (sub) {
            if (this.options.verifyEvents !== false) {
              verifyEvent(event).then((valid) => {
                if (valid) {
                  sub.callback(event);
                } else {
                  this.options.onEventRejected?.(event, 'invalid signature or event ID');
                }
              });
            } else {
              sub.callback(event);
            }
          }
          break;
        }

        case 'OK': {
          if (msg.length < 4 || typeof msg[1] !== 'string' || typeof msg[2] !== 'boolean' || typeof msg[3] !== 'string') break;
          const eventId = msg[1] as string;
          const pending = this.pendingPublishes.get(eventId);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingPublishes.delete(eventId);
            pending.resolve({ ok: msg[2] as boolean, message: msg[3] as string });
          }
          break;
        }

        case 'EOSE': {
          if (typeof msg[1] !== 'string') break;
          const sub = this.subscriptions.get(msg[1]);
          sub?.eoseCallback?.();
          break;
        }

        case 'AUTH': {
          if (typeof msg[1] !== 'string') break;
          this.handleAuth(msg[1]);
          break;
        }

        case 'NOTICE': {
          // Relay notices are informational — log but don't act
          break;
        }
      }
    } catch {
      // Malformed message — ignore
    }
  }

  /** Handle NIP-42 AUTH challenge */
  private async handleAuth(challenge: string): Promise<void> {
    if (!this.options.authPrivateKey) return;

    const pubkey = getPublicKey(this.options.authPrivateKey);
    const authEvent: UnsignedEvent = {
      kind: NIP42_AUTH_KIND,
      pubkey,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['relay', this.url],
        ['challenge', challenge],
      ],
      content: '',
    };

    const signed = await signEvent(authEvent, this.options.authPrivateKey);
    this.ws?.send(JSON.stringify(['AUTH', signed]));
  }

  private handleReconnect(): void {
    if (this.disconnectRequested || !this.options.autoReconnect) return;
    if (this.reconnectAttempts >= (this.options.maxReconnectAttempts ?? 5)) return;

    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      this.connect().catch(() => {
        // Will retry via onclose handler
      });
    }, this.options.reconnectDelay);
  }
}

/**
 * Publish a Signet event to multiple relays.
 */
export async function publishToRelays(
  event: NostrEvent,
  relayUrls: string[]
): Promise<Map<string, { ok: boolean; message: string }>> {
  const results = new Map<string, { ok: boolean; message: string }>();

  const promises = relayUrls.map(async (url) => {
    const relay = new RelayClient(url);
    try {
      await relay.connect();
      const result = await relay.publish(event);
      results.set(url, result);
    } catch (err) {
      results.set(url, { ok: false, message: err instanceof Error ? err.message : 'Connection failed' });
    } finally {
      relay.disconnect();
    }
  });

  await Promise.allSettled(promises);
  return results;
}

/**
 * Fetch Signet events from a relay by kind and optional filters.
 */
export async function fetchFromRelay(
  relayUrl: string,
  filters: NostrFilter[]
): Promise<NostrEvent[]> {
  const relay = new RelayClient(relayUrl);
  try {
    await relay.connect();
    return await relay.fetch(filters);
  } finally {
    relay.disconnect();
  }
}
