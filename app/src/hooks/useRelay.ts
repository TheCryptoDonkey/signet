import { useState, useEffect, useCallback } from 'react';
import type { RelayState, NostrEvent, NostrFilter } from 'signet-protocol';
import {
  connectRelay,
  disconnectRelay,
  getRelayState,
  getRelayClient,
  publishEvent,
  fetchEvents,
  setRelayUrl,
  getRelayUrl,
} from '../lib/relay-service';

export type RelayHook = ReturnType<typeof useRelay>;

export function useRelay() {
  const [state, setState] = useState<RelayState>(getRelayState());
  const [url, setUrl] = useState(getRelayUrl());

  useEffect(() => {
    const client = getRelayClient();
    client.onStateChanged((newState) => setState(newState));
    setState(client.getState());
    return () => {
      client.onStateChanged(() => {});
    };
  }, [url]);

  const connect = useCallback(async () => {
    await connectRelay();
    setState(getRelayState());
  }, []);

  const disconnect = useCallback(() => {
    disconnectRelay();
    setState('disconnected');
  }, []);

  const publish = useCallback(async (event: NostrEvent) => {
    return publishEvent(event);
  }, []);

  const fetch = useCallback(async (filters: NostrFilter[]) => {
    return fetchEvents(filters);
  }, []);

  const changeUrl = useCallback((newUrl: string) => {
    setRelayUrl(newUrl);
    setUrl(newUrl);
  }, []);

  return { state, url, connect, disconnect, publish, fetch, changeUrl };
}
