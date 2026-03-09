// Signet Words — Time-based word verification ("signet me")
// Delegates word derivation to canary-kit for protocol alignment.
// Signet handles identity (who you are). Canary handles verification (prove it's you).

import { deriveTokenBytes } from 'canary-kit/token';
import { encodeAsWords, type TokenEncoding } from 'canary-kit/encoding';
import { WORDLIST } from 'canary-kit/wordlist';

/** The Canary spoken-clarity wordlist used for Signet word verification. */
export { WORDLIST as SIGNET_WORDLIST } from 'canary-kit/wordlist';

/** Default: words rotate every 30 seconds */
export const SIGNET_EPOCH_SECONDS = 30;

/** Default: 3 words per signet */
export const SIGNET_WORD_COUNT = 3;

/** Default: accept +/-1 epoch window for clock skew tolerance */
export const SIGNET_TOLERANCE = 1;

/** Maximum supported word count (limited by HMAC output bytes: 32 bytes / 2 bytes per word = 16) */
export const MAX_WORD_COUNT = 16;

/** Context string for Signet word derivation via CANARY-DERIVE */
const SIGNET_CONTEXT = 'signet:verify';

/** Configuration options for signet words */
export interface SignetWordsConfig {
  /** Number of words to derive (1-16, default: 3) */
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

/** Derive N words from a shared secret and epoch number.
 *  Uses canary-kit's CANARY-DERIVE (HMAC-SHA256) and encodes as spoken-clarity words. */
export function deriveWords(sharedSecret: string, epoch: number, wordCount: number = SIGNET_WORD_COUNT): string[] {
  if (wordCount < 1 || wordCount > MAX_WORD_COUNT) {
    throw new Error(`wordCount must be between 1 and ${MAX_WORD_COUNT}`);
  }

  const bytes = deriveTokenBytes(sharedSecret, SIGNET_CONTEXT, epoch);
  return encodeAsWords(bytes, wordCount, WORDLIST);
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
