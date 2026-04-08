/**
 * Venue Entry Event Builder (kind 21235)
 *
 * Builds unsigned venue entry events for physical venue scanning.
 * The event is a self-contained, signed QR payload verifiable via
 * standard NIP-01 signature verification.
 *
 * Kind 21235 is in the ephemeral range. The consuming application
 * signs the event and renders it as a QR code.
 */

import type { UnsignedEvent } from './types.js';

/** Venue entry event kind (ephemeral range). */
export const VENUE_ENTRY_KIND = 21235;

/**
 * Build an unsigned venue entry event template.
 * The caller must sign this before rendering as a QR code.
 *
 * @param pubkey - The natural person's hex public key.
 * @param photoHash - Optional SHA-256 hash of the uploaded photo.
 * @param blossomUrl - Optional Blossom server URL where the photo is hosted.
 */
export function buildVenueEntryEventTemplate(
  pubkey: string,
  photoHash?: string,
  blossomUrl?: string,
): UnsignedEvent {
  const tags: string[][] = [['t', 'signet-venue-entry']];

  if (photoHash) {
    tags.push(['x', photoHash]);
  }

  if (blossomUrl && photoHash) {
    if (/^https:\/\//i.test(blossomUrl) || /^http:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(blossomUrl)) {
      tags.push(['blossom', blossomUrl]);
    }
  }

  return {
    pubkey,
    kind: VENUE_ENTRY_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: '',
  };
}
