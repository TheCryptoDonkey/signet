import { RelayClient, type NostrFilter, type RelayState, type NostrEvent } from 'signet-protocol';

const DEFAULT_RELAY_URL = 'ws://localhost:7777';

let client: RelayClient | null = null;
let currentUrl: string = DEFAULT_RELAY_URL;

export function getRelayClient(): RelayClient {
  if (!client) {
    client = new RelayClient(currentUrl);
  }
  return client;
}

export function getRelayUrl(): string {
  return currentUrl;
}

export function setRelayUrl(url: string): void {
  if (url !== currentUrl) {
    if (client) {
      client.disconnect();
      client = null;
    }
    currentUrl = url;
  }
}

export async function connectRelay(): Promise<void> {
  const c = getRelayClient();
  await c.connect();
}

export function disconnectRelay(): void {
  if (client) {
    client.disconnect();
    client = null;
  }
}

export function getRelayState(): RelayState {
  if (!client) return 'disconnected';
  return client.getState();
}

export async function publishEvent(event: NostrEvent): Promise<{ ok: boolean; message: string }> {
  const c = getRelayClient();
  if (c.getState() !== 'connected') {
    await c.connect();
  }
  return c.publish(event);
}

export async function fetchEvents(filters: NostrFilter[]): Promise<NostrEvent[]> {
  const c = getRelayClient();
  if (c.getState() !== 'connected') {
    await c.connect();
  }
  return c.fetch(filters);
}

export { DEFAULT_RELAY_URL };
