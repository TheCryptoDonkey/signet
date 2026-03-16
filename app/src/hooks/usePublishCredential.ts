import { useCallback, useState } from 'react';

/**
 * Hook for publishing credential events to a relay.
 * Opt-in only — called explicitly after verification.
 */
export function usePublishCredential(relayUrl?: string) {
  const [publishing, setPublishing] = useState(false);
  const [published, setPublished] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const publish = useCallback(async (eventJson: string) => {
    if (!relayUrl) {
      setError('No relay configured. Go to Settings → Power Mode to add one.');
      return false;
    }
    setPublishing(true);
    setError(null);
    try {
      // publishToRelay should accept a relay URL and a signed event JSON string
      // If the function doesn't exist yet, create a simple WebSocket publish
      const ws = new WebSocket(relayUrl);
      await new Promise<void>((resolve, reject) => {
        ws.onopen = () => {
          let event: unknown;
          try {
            event = JSON.parse(eventJson);
            if (typeof event !== 'object' || event === null) {
              reject(new Error('Invalid event JSON'));
              ws.close();
              return;
            }
          } catch {
            reject(new Error('Invalid event JSON'));
            ws.close();
            return;
          }
          ws.send(JSON.stringify(['EVENT', event]));
          // Wait briefly for OK response
          ws.onmessage = (msg) => {
            try {
              const data: unknown = JSON.parse(msg.data as string);
              if (Array.isArray(data) && data[0] === 'OK') {
                resolve();
              }
            } catch {
              // Malformed relay message — keep waiting for timeout
            }
          };
          // Timeout after 5 seconds
          setTimeout(() => resolve(), 5000);
        };
        ws.onerror = () => reject(new Error('Failed to connect to relay'));
        setTimeout(() => reject(new Error('Connection timeout')), 10000);
      });
      ws.close();
      setPublished(true);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to publish');
      return false;
    } finally {
      setPublishing(false);
    }
  }, [relayUrl]);

  return { publish, publishing, published, error };
}
