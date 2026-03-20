import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { signEvent } from 'signet-protocol';
import type { NostrEvent, UnsignedEvent } from 'signet-protocol';
import type { VerifyResponse } from './presentation';

export interface AuthResponse {
  type: 'signet-auth-response';
  requestId: string;
  pubkey: string;
  /** Schnorr signature of the challenge string using the user's active private key */
  signature: string;
  /** Optional credential (included for signet-login-request flows) */
  credential?: {
    id: string;
    kind: number;
    pubkey: string;
    tags: string[][];
    content: string;
    sig: string;
    created_at: number;
  };
}

/**
 * Build a signed NIP-01 event (kind 29999) carrying a verify response.
 * The event is signed with the subject's private key so any relay will accept it.
 */
export async function buildSignedVerifyEvent(
  response: VerifyResponse,
  privateKey: string,
): Promise<NostrEvent> {
  const pubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(privateKey)));

  // Extract claim tags from the credential
  const credTags = response.credential.tags;
  const ageRange = credTags.find(t => t[0] === 'age-range')?.[1] ?? '';
  const tier = credTags.find(t => t[0] === 'tier')?.[1] ?? '';
  const entityType = credTags.find(t => t[0] === 'entity-type')?.[1] ?? '';

  const unsigned: UnsignedEvent = {
    kind: 29999,
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['session', response.requestId],
      ['credential', JSON.stringify(response.credential)],
      ['status', 'approved'],
      ['age-range', ageRange],
      ['tier', tier],
      ['entity-type', entityType],
    ],
    content: '',
  };

  return signEvent(unsigned, privateKey);
}

/**
 * Publish a verification response to a Nostr relay (cross-device flow).
 * The SDK running on the website is listening for this event.
 * Returns true if the message was sent, false on error or invalid relay URL.
 */
export async function publishVerifyResponseToRelay(
  response: VerifyResponse,
  relayUrl: string,
  privateKey: string,
): Promise<boolean> {
  if (!relayUrl) return false;
  // Validate relay URL: must be wss:// for production or ws://localhost for dev
  if (!/^wss:\/\//i.test(relayUrl) && !/^ws:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(relayUrl)) {
    return false;
  }

  let signedEvent: NostrEvent;
  try {
    signedEvent = await buildSignedVerifyEvent(response, privateKey);
  } catch {
    return false;
  }

  return new Promise((resolve) => {
    try {
      const ws = new WebSocket(relayUrl);
      const timeout = setTimeout(() => { ws.close(); resolve(false); }, 10000);

      ws.onopen = () => {
        ws.send(JSON.stringify(['EVENT', signedEvent]));
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

/**
 * Publish a verification rejection to a Nostr relay (cross-device flow).
 * The SDK running on the website is listening for this event and will
 * immediately resolve with error: 'cancelled' instead of waiting for timeout.
 * Returns true if the message was sent, false on error or invalid relay URL.
 */
export async function publishVerifyRejectionToRelay(
  requestId: string,
  relayUrl: string,
  privateKey: string,
): Promise<boolean> {
  if (!relayUrl) return false;
  // Validate relay URL: must be wss:// for production or ws://localhost for dev
  if (!/^wss:\/\//i.test(relayUrl) && !/^ws:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(relayUrl)) {
    return false;
  }

  const pubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(privateKey)));

  const unsigned: UnsignedEvent = {
    kind: 29999,
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['session', requestId],
      ['status', 'rejected'],
    ],
    content: '',
  };

  let signedEvent: NostrEvent;
  try {
    signedEvent = await signEvent(unsigned, privateKey);
  } catch {
    return false;
  }

  return new Promise((resolve) => {
    try {
      const ws = new WebSocket(relayUrl);
      const timeout = setTimeout(() => { ws.close(); resolve(false); }, 10000);

      ws.onopen = () => {
        ws.send(JSON.stringify(['EVENT', signedEvent]));
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

/**
 * Publish an auth response to a Nostr relay (cross-device flow).
 * The website is listening for this event.
 * Returns true if the message was sent, false on error or invalid relay URL.
 */
export async function publishAuthResponseToRelay(
  response: AuthResponse,
  relayUrl: string,
  privateKey: string,
): Promise<boolean> {
  if (!relayUrl) return false;
  // Validate relay URL: must be wss:// for production or ws://localhost for dev
  if (!/^wss:\/\//i.test(relayUrl) && !/^ws:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(relayUrl)) {
    return false;
  }

  const pubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(privateKey)));

  const unsigned: UnsignedEvent = {
    kind: 29999,
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['session', response.requestId],
      ['status', 'approved'],
    ],
    content: JSON.stringify(response),
  };

  let signedEvent: NostrEvent;
  try {
    signedEvent = await signEvent(unsigned, privateKey);
  } catch {
    return false;
  }

  return new Promise((resolve) => {
    try {
      const ws = new WebSocket(relayUrl);
      const timeout = setTimeout(() => { ws.close(); resolve(false); }, 10000);

      ws.onopen = () => {
        ws.send(JSON.stringify(['EVENT', signedEvent]));
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
