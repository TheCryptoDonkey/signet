// Signet Words — Time-based word verification ("signet me")
// Uses HMAC-SHA256 to derive rotating word sequences from a shared secret

import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { BIP39_WORDLIST } from './wordlist.js';

/** Default: words rotate every 30 seconds */
export const SIGNET_EPOCH_SECONDS = 30;

/** Default: 3 words per signet */
export const SIGNET_WORD_COUNT = 3;

/** Default: accept +/-1 epoch window for clock skew tolerance */
export const SIGNET_TOLERANCE = 1;

/** Maximum supported word count (limited by HMAC output bytes) */
export const MAX_WORD_COUNT = 23; // 23 × 11 = 253 bits, fits in 32 bytes of SHA-256 output

/** Configuration options for signet words */
export interface SignetWordsConfig {
  /** Number of words to derive (1-23, default: 3) */
  wordCount?: number;
  /** Epoch interval in seconds (default: 30) */
  epochSeconds?: number;
  /** Tolerance in epochs, +/- (default: 1) */
  tolerance?: number;
}

/** Return the current epoch index for a given interval. */
export function getEpoch(timestampMs?: number, epochSeconds: number = SIGNET_EPOCH_SECONDS): number {
  return Math.floor((timestampMs ?? Date.now()) / (epochSeconds * 1000));
}

/** Derive N BIP-39 words from a shared secret and epoch number.
 *  Uses HMAC-SHA256 and extracts N x 11-bit indices. */
export function deriveWords(sharedSecret: string, epoch: number, wordCount: number = SIGNET_WORD_COUNT): string[] {
  if (wordCount < 1 || wordCount > MAX_WORD_COUNT) {
    throw new Error(`wordCount must be between 1 and ${MAX_WORD_COUNT}`);
  }

  const key = hexToBytes(sharedSecret);
  const message = utf8ToBytes(epoch.toString());
  const mac = hmac(sha256, key, message);

  // Extract wordCount x 11-bit indices from the HMAC output
  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    const bitOffset = i * 11;
    const byteIndex = Math.floor(bitOffset / 8);
    const bitShift = bitOffset % 8;

    // Read 3 bytes to cover the 11-bit window that may span byte boundaries
    const threeBytes = ((mac[byteIndex] ?? 0) << 16) | ((mac[byteIndex + 1] ?? 0) << 8) | (mac[byteIndex + 2] ?? 0);
    const index = (threeBytes >> (13 - bitShift)) & 0x7FF;

    words.push(BIP39_WORDLIST[index]);
  }

  return words;
}

/** Get the current word sequence for a shared secret. */
export function getSignetWords(sharedSecret: string, timestampMs?: number, config?: SignetWordsConfig): string[] {
  const epochSeconds = config?.epochSeconds ?? SIGNET_EPOCH_SECONDS;
  const wordCount = config?.wordCount ?? SIGNET_WORD_COUNT;
  return deriveWords(sharedSecret, getEpoch(timestampMs, epochSeconds), wordCount);
}

/** Verify that the given words match the current epoch (+/- tolerance).
 *  Returns true if the words match any epoch within the tolerance window. */
export function verifySignetWords(
  sharedSecret: string,
  words: string[],
  timestampMs?: number,
  config?: SignetWordsConfig,
): boolean {
  const epochSeconds = config?.epochSeconds ?? SIGNET_EPOCH_SECONDS;
  const wordCount = config?.wordCount ?? SIGNET_WORD_COUNT;
  const tolerance = config?.tolerance ?? SIGNET_TOLERANCE;
  const currentEpoch = getEpoch(timestampMs, epochSeconds);

  for (let offset = -tolerance; offset <= tolerance; offset++) {
    const candidate = deriveWords(sharedSecret, currentEpoch + offset, wordCount);
    if (candidate.length === words.length && candidate.every((w, i) => w === words[i])) {
      return true;
    }
  }

  return false;
}

/** Format words with middle-dot separator: "ocean · tiger · marble" */
export function formatSignetWords(words: string[]): string {
  return words.join(' \u00b7 ');
}

/** Get everything needed for UI display: words, formatted string, and countdown. */
export function getSignetDisplay(
  sharedSecret: string,
  timestampMs?: number,
  config?: SignetWordsConfig,
): { words: string[]; formatted: string; expiresIn: number } {
  const epochSeconds = config?.epochSeconds ?? SIGNET_EPOCH_SECONDS;
  const now = timestampMs ?? Date.now();
  const words = getSignetWords(sharedSecret, now, config);
  const formatted = formatSignetWords(words);

  // Seconds until the next epoch boundary
  const epochMs = epochSeconds * 1000;
  const msIntoEpoch = now % epochMs;
  const expiresIn = (epochMs - msIntoEpoch) / 1000;

  return { words, formatted, expiresIn };
}
