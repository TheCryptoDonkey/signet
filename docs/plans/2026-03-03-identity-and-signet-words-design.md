# Identity Management & "Signet Me" Verification — Design

**Date:** 2026-03-03
**Status:** Approved

## Problem

Signet verifies who you are to the network. But how do you prove who you are to another person directly — over a phone call, at a bank, in any real-time interaction?

And before any of that: how does a user create their identity in the first place, and how do they back it up safely?

## Features

### 1. Profile Creation (BIP-39 / NIP-06)

- Generate 128 bits entropy → 12 BIP-39 English mnemonic words
- Derive seed via PBKDF2 (mnemonic + optional passphrase)
- Derive Nostr private key via BIP-32 HD derivation at `m/44'/1237'/0'/0/0` (NIP-06)
- Zero new dependencies — `@noble/hashes` provides HMAC-SHA512 and PBKDF2

### 2. Shared Backup (Shamir's Secret Sharing)

- Split 128-bit seed entropy into N shares, any M reconstruct
- GF(256) arithmetic, pure math, no dependencies
- Default: 2-of-3 (keep one, give two to trusted people)
- Configurable up to 255-of-255 (practical limit ~5-of-N)
- Shares encoded as 12 BIP-39 words for familiarity

### 3. Connections (QR Exchange)

- QR contains: pubkey + connection nonce
- Both parties compute `ECDH(my_priv, their_pub)` → identical shared secret
- During exchange, each user selects what to share (name, mobile, address, kids' pubkeys)
- Contact info stored locally only — never published to relays
- Optionally auto-creates mutual in-person vouches (kind 30471)

### 4. "Signet Me" — Time-Based Verification Words (powered by canary-kit)

- Delegates word derivation to canary-kit's CANARY-DERIVE primitive
- `deriveTokenBytes(sharedSecret, "signet:verify", epoch)` → HMAC-SHA256 → 32 bytes
- `encodeAsWords(bytes, 3, CANARY_WORDLIST)` → 3 spoken-clarity words
- 30-second epoch, accept current ± 1 window (90s tolerance)
- Both parties compute independently → same words
- Works offline, no server needed
- Works for personal contacts and organisations (banks, etc.)
- Same wordlist as Canary protocol — consistent vocabulary across identity and verification

## Modules

| Module | File | Tests |
|--------|------|-------|
| BIP-39 Wordlist | `src/wordlist.ts` | N/A (data) |
| Mnemonic | `src/mnemonic.ts` | `tests/mnemonic.test.ts` |
| Key Derivation | `src/key-derivation.ts` | `tests/key-derivation.test.ts` |
| Shamir's SSS | `src/shamir.ts` | `tests/shamir.test.ts` |
| Connections | `src/connections.ts` | `tests/connections.test.ts` |
| Signet Words | `src/signet-words.ts` | `tests/signet-words.test.ts` |

## Spec Addition

Add Section 15 to `spec/protocol.md` covering all four features.

## Example

Add `examples/signet-me.ts` demonstrating: profile creation → backup → connection → verification words.
