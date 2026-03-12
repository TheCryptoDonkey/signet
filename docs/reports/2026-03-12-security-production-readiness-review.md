# Signet Protocol - Security & Production Readiness Review

**Date:** 2026-03-12
**Version reviewed:** 0.1.0 (commit on main, pre-publish)
**Reviewer:** Claude Code (automated)

## Status

- Typecheck: Clean
- Tests: 538/538 passing (32 test files)
- Security fixes applied: 9 files, see "Addressed" section

## Outstanding Items

### 1. CRITICAL - Voting extension needs LSAG implementation

The voting types (`BallotParams`, `ParsedBallot`) include `keyImage` fields, confirming linkable ring signatures are the intended design. However, **no LSAG implementation exists**. The current `ringSign`/`ringVerify` in `ring-signature.ts` implements unlinkable SAG.

If SAG is used for voting, the same voter can cast multiple ballots that cannot be linked - **double-voting is undetectable**.

**Required:**
- Implement `lsagSign` / `lsagVerify` with key image generation
- Key image: `I = x * H_p(P)` where `H_p` is hash-to-point
- Verification must check key image uniqueness per election
- Must NOT reuse the existing SAG functions for voting

**Location:** New file `src/lsag.ts` or extend `src/ring-signature.ts`
**Spec:** `spec/voting.md` describes the protocol; implementation is missing

### 2. BLOCKER - `canary-kit` is a `file:` dependency

`package.json` contains:
```json
"canary-kit": "file:../canary-kit"
```

This prevents npm publish. The `signet-words.ts` module depends on canary-kit for wordlist generation and CANARY-DERIVE.

**Required:**
- Publish canary-kit to npm (it's already live per the Fathom architecture doc)
- Update `package.json` to use a versioned npm dependency: `"canary-kit": "^x.y.z"`

### 3. BLOCKER - No `dist/` output

TypeScript is not compiled. The package exports `dist/index.js` but no build artefact exists. Consumers cannot import the package.

**Required:**
- Run `tsc` to produce `dist/`
- Ensure `dist/` is included in npm package (check `files` field or `.npmignore`)
- Consider adding `prepublishOnly` script: `"prepublishOnly": "npm run build"`

## Addressed (2026-03-12)

All code changes applied directly to source. Typecheck and tests pass.

### Range proof binding (MEDIUM)

Range proofs now accept an optional `bindingContext` parameter included in all Fiat-Shamir challenges. When a subject pubkey is provided, the proof is cryptographically bound to that credential and cannot be transplanted to another.

- `createRangeProof()` and `createAgeRangeProof()` accept optional context
- `RangeProof` interface includes optional `context` field
- `verifyRangeProof()` uses stored context for verification
- `createRingProtectedChildCredential()` passes `subjectPubkey` as context
- `verifyRingProtectedContent()` checks context matches credential subject
- Backwards-compatible: omitting context preserves previous behaviour

### Timestamp consistency (MEDIUM)

`createRingProtectedCredential()` and `createRingProtectedChildCredential()` now use a single timestamp for both the Nostr event's `created_at` and the ring signature binding message. Previously these were computed independently, allowing clock skew between them.

### Identity bridge replay resistance (MEDIUM)

`verifyIdentityBridge()` now includes:
- **Freshness check:** Rejects bridges older than `maxAgeSeconds` (default 24h, configurable, set to 0 to disable)
- **Timestamp consistency:** Verifies `parsed.timestamp === event.created_at`

### Pubkey format validation (MEDIUM)

`ring-signature.ts` now validates public keys are exactly 64 hex characters before attempting curve point construction. Previously, malformed keys would produce opaque errors from `@noble/curves`.

### `deserializeRangeProof` validation (LOW)

Now validates all required fields including `lowerCommitment`, `upperCommitment`, `sumBindingE`, `sumBindingS`, all `BitProof` array contents, and `context` type.

### Documentation additions (INFO)

- `crypto.ts` / `key-derivation.ts`: Documented that JS strings cannot be zeroed from memory; `Uint8Array` intermediates are cleared but hex string private keys persist until GC
- `secp256k1-utils.ts`: Documented ~2^-128 modular bias in `hashToScalar` (negligible for Fiat-Shamir; wider hash per RFC 9380 would eliminate)
- `utils.ts`: Documented that `constantTimeEqual` length check is not constant-time (all callers use fixed 32-byte buffers)
- `connections.ts`: Documented that `sharedSecret` is stored plaintext; production needs encrypted-at-rest storage

## Recommendations

1. **Formal security audit** before production deployment with real identity data. Custom ring signatures, range proofs, and Shamir implementations are hand-rolled and should be independently reviewed.
2. **LSAG for voting** must be implemented before the voting extension ships.
3. **Resolve npm publish blockers** (canary-kit dep + dist/ build) before any downstream consumer can use the package.
