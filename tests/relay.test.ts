import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { RelayClient } from '../src/relay.js';
import { generateKeyPair, signEvent } from '../src/crypto.js';
import type { NostrEvent, UnsignedEvent } from '../src/types.js';

// --- Mock WebSocket ---

type WSListener = (evt: { data: string }) => void;

class MockWebSocket {
  static instances: MockWebSocket[] = [];

  url: string;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: WSListener | null = null;
  sent: string[] = [];
  closed = false;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.closed = true;
    // Don't auto-trigger onclose — let tests control it
  }

  // Test helpers
  simulateOpen() {
    this.onopen?.();
  }

  simulateMessage(msg: unknown) {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }

  simulateClose() {
    this.onclose?.();
  }

  simulateError() {
    this.onerror?.();
  }
}

// Stub WebSocket globally
vi.stubGlobal('WebSocket', MockWebSocket);

function lastWS(): MockWebSocket {
  return MockWebSocket.instances[MockWebSocket.instances.length - 1];
}

const dummyEvent: NostrEvent = {
  id: 'abc123',
  kind: 30470,
  pubkey: 'pub1',
  created_at: 1700000000,
  tags: [['d', 'subject1']],
  content: '',
  sig: 'sig1',
};

describe('RelayClient', () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('constructor and state', () => {
    it('starts in disconnected state', () => {
      const client = new RelayClient('wss://relay.example.com');
      expect(client.getState()).toBe('disconnected');
    });

    it('throws for non-websocket URL schemes', () => {
      expect(() => new RelayClient('https://relay.example.com')).toThrow('ws:// or wss://');
      expect(() => new RelayClient('http://relay.example.com')).toThrow('ws:// or wss://');
      expect(() => new RelayClient('relay.example.com')).toThrow('ws:// or wss://');
    });

    it('accepts ws:// and wss:// URLs', () => {
      expect(() => new RelayClient('wss://relay.example.com')).not.toThrow();
      expect(() => new RelayClient('ws://relay.example.com')).not.toThrow();
    });

    it('notifies state changes via callback', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const states: string[] = [];
      client.onStateChanged((s) => states.push(s));

      const connectPromise = client.connect();
      lastWS().simulateOpen();
      await connectPromise;

      expect(states).toContain('connecting');
      expect(states).toContain('connected');
    });
  });

  describe('connect', () => {
    it('resolves on successful connection', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const connectPromise = client.connect();

      lastWS().simulateOpen();
      await connectPromise;

      expect(client.getState()).toBe('connected');
    });

    it('resolves immediately if already connected', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p1 = client.connect();
      lastWS().simulateOpen();
      await p1;

      // Second connect should resolve immediately
      await client.connect();
      expect(client.getState()).toBe('connected');
    });

    it('rejects on error', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const connectPromise = client.connect();

      lastWS().simulateError();

      await expect(connectPromise).rejects.toThrow('WebSocket connection failed');
    });

    it('rejects on timeout', async () => {
      const client = new RelayClient('wss://relay.example.com', {
        connectTimeout: 1000,
      });
      const connectPromise = client.connect();

      vi.advanceTimersByTime(1001);

      await expect(connectPromise).rejects.toThrow('Connection timeout');
    });
  });

  describe('disconnect', () => {
    it('closes websocket and sets state', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      client.disconnect();

      expect(client.getState()).toBe('disconnected');
      expect(lastWS().closed).toBe(true);
    });

    it('resolves pending publishes with failure', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const publishPromise = client.publish(dummyEvent);
      client.disconnect();

      const result = await publishPromise;
      expect(result.ok).toBe(false);
      expect(result.message).toBe('Disconnected');
    });
  });

  describe('publish', () => {
    it('throws if not connected', async () => {
      const client = new RelayClient('wss://relay.example.com');
      await expect(client.publish(dummyEvent)).rejects.toThrow('Not connected');
    });

    it('sends EVENT message and resolves on OK', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const publishPromise = client.publish(dummyEvent);

      // Check the sent message
      const sent = JSON.parse(lastWS().sent[0]);
      expect(sent[0]).toBe('EVENT');
      expect(sent[1].id).toBe('abc123');

      // Simulate OK response
      lastWS().simulateMessage(['OK', 'abc123', true, '']);

      const result = await publishPromise;
      expect(result.ok).toBe(true);
    });

    it('resolves with failure on publish timeout', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const publishPromise = client.publish(dummyEvent);
      vi.advanceTimersByTime(10001);

      const result = await publishPromise;
      expect(result.ok).toBe(false);
      expect(result.message).toBe('Publish timeout');
    });
  });

  describe('subscribe', () => {
    it('sends REQ and returns subscription ID', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const events: NostrEvent[] = [];
      const subId = client.subscribe(
        [{ kinds: [30470] }],
        (event) => events.push(event)
      );

      expect(subId).toMatch(/^signet-sub-/);

      const sent = JSON.parse(lastWS().sent[0]);
      expect(sent[0]).toBe('REQ');
      expect(sent[1]).toBe(subId);
      expect(sent[2]).toEqual({ kinds: [30470] });
    });

    it('delivers events to the callback (verification disabled)', async () => {
      const client = new RelayClient('wss://relay.example.com', { verifyEvents: false });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const events: NostrEvent[] = [];
      const subId = client.subscribe(
        [{ kinds: [30470] }],
        (event) => events.push(event)
      );

      lastWS().simulateMessage(['EVENT', subId, dummyEvent]);

      expect(events).toHaveLength(1);
      expect(events[0].id).toBe('abc123');
    });

    it('calls EOSE callback', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      let eoseCalled = false;
      const subId = client.subscribe(
        [{ kinds: [30470] }],
        () => {},
        () => { eoseCalled = true; }
      );

      lastWS().simulateMessage(['EOSE', subId]);

      expect(eoseCalled).toBe(true);
    });
  });

  describe('closeSubscription', () => {
    it('sends CLOSE and removes subscription', async () => {
      const client = new RelayClient('wss://relay.example.com', { verifyEvents: false });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const events: NostrEvent[] = [];
      const subId = client.subscribe(
        [{ kinds: [30470] }],
        (event) => events.push(event)
      );

      client.closeSubscription(subId);

      const closeSent = JSON.parse(lastWS().sent[1]); // [0] was REQ
      expect(closeSent[0]).toBe('CLOSE');
      expect(closeSent[1]).toBe(subId);

      // Events after close should not be delivered
      lastWS().simulateMessage(['EVENT', subId, dummyEvent]);
      expect(events).toHaveLength(0);
    });
  });

  describe('fetch', () => {
    it('collects events until EOSE then resolves', async () => {
      const client = new RelayClient('wss://relay.example.com', { verifyEvents: false });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const fetchPromise = client.fetch([{ kinds: [30470] }]);

      // Find the subscription ID from the REQ message
      const req = JSON.parse(lastWS().sent[0]);
      const subId = req[1];

      // Send events
      lastWS().simulateMessage(['EVENT', subId, dummyEvent]);
      lastWS().simulateMessage(['EVENT', subId, { ...dummyEvent, id: 'def456' }]);

      // Send EOSE to complete
      lastWS().simulateMessage(['EOSE', subId]);

      const events = await fetchPromise;
      expect(events).toHaveLength(2);
      expect(events[0].id).toBe('abc123');
      expect(events[1].id).toBe('def456');
    });
  });

  describe('reconnect', () => {
    it('attempts reconnect on disconnect', async () => {
      const client = new RelayClient('wss://relay.example.com', {
        autoReconnect: true,
        reconnectDelay: 1000,
        maxReconnectAttempts: 3,
      });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const wsBefore = MockWebSocket.instances.length;

      // Simulate disconnect
      lastWS().simulateClose();

      // Advance timer past reconnect delay
      vi.advanceTimersByTime(1001);

      // A new WebSocket should have been created
      expect(MockWebSocket.instances.length).toBe(wsBefore + 1);
    });

    it('stops reconnecting after max attempts', async () => {
      const client = new RelayClient('wss://relay.example.com', {
        autoReconnect: true,
        reconnectDelay: 100,
        maxReconnectAttempts: 2,
      });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      // Disconnect → reconnect attempt 1
      lastWS().simulateClose();
      vi.advanceTimersByTime(101);
      lastWS().simulateClose(); // attempt 1 fails

      // reconnect attempt 2
      vi.advanceTimersByTime(101);
      lastWS().simulateClose(); // attempt 2 fails

      const wsCount = MockWebSocket.instances.length;
      // Attempt 3 should NOT happen
      vi.advanceTimersByTime(101);
      expect(MockWebSocket.instances.length).toBe(wsCount);
    });

    it('does not reconnect after explicit disconnect', async () => {
      const client = new RelayClient('wss://relay.example.com', {
        autoReconnect: true,
        reconnectDelay: 100,
      });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const wsCount = MockWebSocket.instances.length;
      client.disconnect();

      vi.advanceTimersByTime(200);
      expect(MockWebSocket.instances.length).toBe(wsCount);
    });

    it('re-subscribes existing subscriptions on reconnect', async () => {
      const client = new RelayClient('wss://relay.example.com', {
        autoReconnect: true,
        reconnectDelay: 100,
      });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      // Create a subscription
      client.subscribe([{ kinds: [30470] }], () => {});

      // Disconnect and reconnect
      lastWS().simulateClose();
      vi.advanceTimersByTime(101);
      lastWS().simulateOpen();

      // The new WS should have a REQ for the existing subscription
      const reqMessages = lastWS().sent.filter(s => {
        const parsed = JSON.parse(s);
        return parsed[0] === 'REQ';
      });
      expect(reqMessages.length).toBe(1);
    });
  });

  describe('message handling', () => {
    it('ignores malformed JSON', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      // Should not throw
      lastWS().onmessage?.({ data: 'not json' });
      expect(client.getState()).toBe('connected');
    });

    it('handles NOTICE without error', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      // Should not throw
      lastWS().simulateMessage(['NOTICE', 'relay message']);
      expect(client.getState()).toBe('connected');
    });
  });

  describe('event verification', () => {
    // These tests need real timers for async crypto verification
    beforeEach(() => {
      vi.useRealTimers();
    });

    afterEach(() => {
      vi.useFakeTimers();
    });

    it('delivers valid signed events when verification is enabled', async () => {
      const client = new RelayClient('wss://relay.example.com', { verifyEvents: true });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      // Create a properly signed event
      const kp = generateKeyPair();
      const unsigned: UnsignedEvent = {
        kind: 30470,
        pubkey: kp.publicKey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['d', 'test']],
        content: '',
      };
      const validEvent = await signEvent(unsigned, kp.privateKey);

      const events: NostrEvent[] = [];
      const subId = client.subscribe(
        [{ kinds: [30470] }],
        (event) => events.push(event)
      );

      lastWS().simulateMessage(['EVENT', subId, validEvent]);

      // Verification is async; wait for it
      await new Promise((r) => setTimeout(r, 50));

      expect(events).toHaveLength(1);
      expect(events[0].id).toBe(validEvent.id);
    });

    it('drops events with invalid signatures', async () => {
      const rejected: Array<{ event: NostrEvent; reason: string }> = [];
      const client = new RelayClient('wss://relay.example.com', {
        verifyEvents: true,
        onEventRejected: (event, reason) => rejected.push({ event, reason }),
      });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const events: NostrEvent[] = [];
      const subId = client.subscribe(
        [{ kinds: [30470] }],
        (event) => events.push(event)
      );

      // Send the dummy event (invalid signature)
      lastWS().simulateMessage(['EVENT', subId, dummyEvent]);

      // Verification is async; wait for it
      await new Promise((r) => setTimeout(r, 50));

      expect(events).toHaveLength(0);
      expect(rejected).toHaveLength(1);
      expect(rejected[0].reason).toContain('invalid signature');
    });

    it('drops events with tampered content', async () => {
      const client = new RelayClient('wss://relay.example.com', { verifyEvents: true });
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      // Create a valid event then tamper with it
      const kp = generateKeyPair();
      const unsigned: UnsignedEvent = {
        kind: 30470,
        pubkey: kp.publicKey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['d', 'test']],
        content: 'original',
      };
      const validEvent = await signEvent(unsigned, kp.privateKey);
      const tampered = { ...validEvent, content: 'tampered' };

      const events: NostrEvent[] = [];
      const subId = client.subscribe(
        [{ kinds: [30470] }],
        (event) => events.push(event)
      );

      lastWS().simulateMessage(['EVENT', subId, tampered]);

      await new Promise((r) => setTimeout(r, 50));

      expect(events).toHaveLength(0);
    });

    it('verification is enabled by default', async () => {
      const client = new RelayClient('wss://relay.example.com');
      const p = client.connect();
      lastWS().simulateOpen();
      await p;

      const events: NostrEvent[] = [];
      const subId = client.subscribe(
        [{ kinds: [30470] }],
        (event) => events.push(event)
      );

      // Fake event should be rejected by default
      lastWS().simulateMessage(['EVENT', subId, dummyEvent]);

      await new Promise((r) => setTimeout(r, 50));

      expect(events).toHaveLength(0);
    });
  });
});
