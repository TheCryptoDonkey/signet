/**
 * NIP-46 Remote Signer for My Signet
 *
 * Handles signing requests from websites via Nostr relay.
 * The app listens for requests, prompts the user, signs with their key.
 */

import { signEvent, RelayClient } from 'signet-protocol';
import type { UnsignedEvent } from 'signet-protocol';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes } from '@noble/hashes/utils';

/**
 * NIP-04 encrypt — local copy for NIP-46 compatibility.
 * TODO: Replace with NIP-44 when NIP-46 spec finalises NIP-44 support.
 */
async function nip04Encrypt(privateKey: string, theirPubkey: string, plaintext: string): Promise<string> {
  const theirPoint = secp256k1.ProjectivePoint.fromHex('02' + theirPubkey);
  const scalar = BigInt('0x' + privateKey) % secp256k1.CURVE.n;
  const shared = theirPoint.multiply(scalar);
  const xHex = shared.toAffine().x.toString(16).padStart(64, '0');
  const sharedX = hexToBytes(xHex);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const key = await globalThis.crypto.subtle.importKey('raw',
    sharedX.buffer.slice(sharedX.byteOffset, sharedX.byteOffset + sharedX.byteLength) as ArrayBuffer,
    { name: 'AES-CBC' }, false, ['encrypt']);
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await globalThis.crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, encoded);
  const ctBytes = new Uint8Array(ciphertext);
  let ctBinary = '';
  for (let i = 0; i < ctBytes.length; i++) ctBinary += String.fromCharCode(ctBytes[i]);
  return btoa(ctBinary) + '?iv=' + btoa(String.fromCharCode(...iv));
}

export interface NIP46Request {
  id: string;
  method: string;
  params: string[];
}

export interface NIP46Response {
  id: string;
  result?: string;
  error?: string;
}

export interface SigningRequest {
  id: string;
  method: string;
  origin: string;
  params: string[];
  timestamp: number;
}

export interface NostrConnectRequest {
  clientPubkey: string;    // ephemeral pubkey from the website (64-char hex)
  relayUrl: string;        // relay to respond through
  appName: string;         // from metadata.name
  appUrl?: string;         // from metadata.url
}

/**
 * Parse a NIP-46 request from an encrypted event content
 */
export function parseNIP46Request(content: string): NIP46Request | null {
  try {
    const parsed: unknown = JSON.parse(content);
    if (typeof parsed !== 'object' || parsed === null) return null;
    const obj = parsed as Record<string, unknown>;
    if (typeof obj.id !== 'string' || typeof obj.method !== 'string' || !Array.isArray(obj.params)) return null;
    if (!obj.params.every((p: unknown) => typeof p === 'string')) return null;
    return { id: obj.id, method: obj.method, params: obj.params as string[] };
  } catch {
    return null;
  }
}

/**
 * Build a NIP-46 response
 */
export function buildNIP46Response(id: string, result?: string, error?: string): string {
  const response: NIP46Response = { id };
  if (result !== undefined) response.result = result;
  if (error !== undefined) response.error = error;
  return JSON.stringify(response);
}

/**
 * Supported NIP-46 methods
 */
export const SUPPORTED_METHODS = [
  'connect',
  'get_public_key',
  'sign_event',
  'get_relays',
  'nip04_encrypt',
  'nip04_decrypt',
] as const;

export type SupportedMethod = typeof SUPPORTED_METHODS[number];

export function isSupportedMethod(method: string): method is SupportedMethod {
  return (SUPPORTED_METHODS as readonly string[]).includes(method);
}

/** Parse a nostrconnect:// URI into a structured request */
export function parseNostrConnectURI(uri: string): NostrConnectRequest | null {
  if (!uri.startsWith('nostrconnect://')) return null;
  try {
    // Replace scheme so URL parser can handle it
    const url = new URL(uri.replace('nostrconnect://', 'https://'));
    const clientPubkey = url.hostname;
    const relayUrl = url.searchParams.get('relay');
    const metadataStr = url.searchParams.get('metadata');
    if (!clientPubkey || !relayUrl) return null;
    if (!/^[0-9a-f]{64}$/i.test(clientPubkey)) return null;
    let appName = 'Unknown App';
    let appUrl: string | undefined;
    if (metadataStr) {
      try {
        const meta: unknown = JSON.parse(metadataStr);
        if (typeof meta === 'object' && meta !== null) {
          const m = meta as Record<string, unknown>;
          if (typeof m.name === 'string') appName = m.name.slice(0, 100);
          if (typeof m.url === 'string') appUrl = m.url.slice(0, 200);
        }
      } catch {
        // Invalid metadata JSON — use defaults
      }
    }
    return { clientPubkey, relayUrl, appName, appUrl };
  } catch {
    return null;
  }
}

/** Send NIP-46 connect response — publishes kind 24133 event with encrypted pubkey */
export async function sendConnectResponse(
  request: NostrConnectRequest,
  signerPrivateKey: string,
  signerPubkey: string
): Promise<boolean> {
  // Build response JSON
  const responseId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const responseJson = JSON.stringify({ id: responseId, result: signerPubkey });

  // NIP-04 encrypt the response for the client's ephemeral pubkey
  const encrypted = await nip04Encrypt(signerPrivateKey, request.clientPubkey, responseJson);

  // Build and sign the kind 24133 event
  const event: UnsignedEvent = {
    kind: 24133,
    pubkey: signerPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['p', request.clientPubkey]],
    content: encrypted,
  };
  const signed = await signEvent(event, signerPrivateKey);

  // Publish to the relay specified in the connect request
  const relay = new RelayClient(request.relayUrl);
  try {
    await relay.connect();
    const result = await relay.publish(signed);
    return result.ok;
  } finally {
    relay.disconnect();
  }
}
