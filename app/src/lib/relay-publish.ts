import type { VerifyResponse } from './presentation';

/**
 * Publish a verification response to a Nostr relay (cross-device flow).
 * The SDK running on the website is listening for this event.
 * Returns true if the message was sent, false on error or invalid relay URL.
 */
export async function publishVerifyResponseToRelay(
  response: VerifyResponse,
  relayUrl: string,
): Promise<boolean> {
  if (!relayUrl) return false;
  // Validate relay URL: must be wss:// for production or ws://localhost for dev
  if (!/^wss:\/\//i.test(relayUrl) && !/^ws:\/\/(localhost|127\.0\.0\.1)/i.test(relayUrl)) {
    return false;
  }

  return new Promise((resolve) => {
    try {
      const ws = new WebSocket(relayUrl);
      const timeout = setTimeout(() => { ws.close(); resolve(false); }, 10000);

      ws.onopen = () => {
        // Send as a wrapped event — ephemeral (kind 29999), not stored
        ws.send(JSON.stringify(['EVENT', {
          kind: 29999,
          content: JSON.stringify(response),
          tags: [['r', response.requestId]],
          created_at: Math.floor(Date.now() / 1000),
        }]));
        clearTimeout(timeout);
        // Give the relay a moment to receive the message before closing
        setTimeout(() => { ws.close(); resolve(true); }, 1000);
      };

      ws.onerror = () => { clearTimeout(timeout); resolve(false); };
    } catch {
      resolve(false);
    }
  });
}
