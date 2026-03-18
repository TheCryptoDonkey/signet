# Signet in 5 Minutes

Signet is an open-source, decentralised identity verification protocol for Nostr. It lets users prove claims
about who they are — human, professional, adult, organisation — without exposing personal data. Verification
is anchored to professional bodies (law societies, medical boards, notary commissions) rather than any central
authority. Trust accumulates as a continuous Signet Score score (0–200, where 100 represents the current government standard) assembled from weighted signals, and is expressed as a tier badge any Nostr client can display.


## How Trust Flows

```
  Person
    |
    | signs a kind 30470 self-declaration
    v
  Tier 1 — Self-declared
    |
    | three or more peers sign kind 30471 vouches
    v
  Tier 2 — Web-of-trust
    |
    | licensed professional issues kind 30470 credential
    | with zero-knowledge age proof and document nullifier
    v
  Tier 3 — Professionally verified (adult)
    |
    | same ceremony, scope extended to child supervision
    v
  Tier 4 — Professionally verified (adult + child)
    |
    v
  Trust signals accumulated (professional verif, vouches, account age, identity bridges)
    |
    v
  Signet Score computed (0-200, where 100 = government standard)
    |
    v
  Badge displayed by client  e.g. "Verified (Tier 3) — Signet Score 106"
```


## The Four Tiers

| Tier | Name                        | Who issues                              | What it proves                                      | Score contribution |
|------|-----------------------------|-----------------------------------------|-----------------------------------------------------|--------------------|
| 1    | Self-declared               | Subject themselves                      | "I exist and I own this key"                        | —                  |
| 2    | Web-of-trust                | Peers (kind 30471 vouches)              | Enough known people can vouch for this identity     | +2–8 per vouch     |
| 3    | Professionally verified     | Licensed professional (kind 30470)      | Government document seen; adult age confirmed       | +40               |
| 4    | Professional + child safety | Licensed professional (kind 30470)      | Tier 3 plus authorisation to interact with minors   | +40               |

Tier 2 requires at least 3 vouches from Tier 2+ peers (configurable per community via kind 30472 policy).
Tiers 3 and 4 are issued in a two-credential ceremony: one Natural Person credential (carries document
nullifier and Merkle root) and one anonymous Persona credential (carries age range only, no identifying data).


## Three Implementation Levels

### Level 1 — Display badges (a weekend)

Read kinds 30470 and 30471 from relays, call `computeBadge`, show a label.
No cryptography required beyond Schnorr signature verification (optional).

### Level 2 — Issue vouches (a few days)

Add kind 30471 vouch issuance. Requires Schnorr signing, relay write access, and basic
kind 30472 policy parsing so your client respects community verification thresholds.

### Level 3 — Full protocol (weeks)

Issue professional credentials, manage verifier lifecycle (kinds 30473–30475), build
guardian delegation (kind 30477), support credential chains (supersedes / superseded-by),
and integrate the voting extension (kinds 30478–30480).


## How Verification Works (Tier 3 / 4)

```
  Subject                 Verifier
    |                        |
    |--- presents document -->|
    |                        |
    |        Verifier computes nullifier:
    |        SHA-256(docType || country || docNumber || salt)
    |        (prevents duplicate identity; document never stored)
    |                        |
    |        Verifier builds Merkle tree:
    |        leaves = verified attributes (name, DOB, address, ...)
    |        only root is published on-chain
    |                        |
    |        Verifier creates zero-knowledge age range proof
    |        (proves "subject is 18+" without revealing birth date)
    |                        |
    |        Two credentials signed and published:
    |          kind 30470 Natural Person  (nullifier + Merkle root)
    |          kind 30470 Persona         (age range only, anonymous)
    |                        |
    v                        v
               Both events published to Nostr relays
```

Professional verifiers are themselves credentialed (kind 30473) and require cross-verification
by two other licensed professionals before becoming active. A challenge / revocation mechanism
(kinds 30474–30475) allows the community to remove a fraudulent verifier.


## Event Kinds Reference

| Kind  | Name              | Purpose                                            |
|-------|-------------------|----------------------------------------------------|
| 30470 | Credential        | Verification credential for any tier               |
| 30471 | Vouch             | Peer attestation (Tier 2 building block)           |
| 30472 | Policy            | Community verification requirements                |
| 30473 | Verifier          | Professional verifier credential                   |
| 30474 | Challenge         | Report a suspected fraudulent verifier             |
| 30475 | Revocation        | Remove a verifier after threshold confirmations    |
| 30476 | Identity bridge   | Link two keypairs via ring signature               |
| 30477 | Delegation        | Guardian / agent delegation with scoped permission |
| 30478 | Election          | Voting extension: define an election               |
| 30479 | Ballot            | Voting extension: cast an anonymous ballot         |
| 30480 | Election result   | Voting extension: publish tallied result           |


## Integrating at Level 1

Install the library:

```
npm install signet-protocol
```

Fetch events from a relay, then call `computeBadge`:

```typescript
import { computeBadge, buildBadgeFilters, meetsMinimumTier } from 'signet-protocol';
import type { NostrEvent } from 'signet-protocol';

// 1. Build relay filters for one or more pubkeys
const pubkeys = ['<hex-pubkey>'];
const filters = buildBadgeFilters(pubkeys);
// filters = [{ kinds: [30470, 30471], '#d': ['<hex-pubkey>'] }]

// 2. Fetch events from your relay (using whatever WebSocket client you prefer)
const events: NostrEvent[] = await fetchFromRelay(filters);

// 3. Compute the badge
const badge = computeBadge(pubkeys[0], events, { verifySignatures: true });

// badge.displayLabel  => "Verified (Tier 3)"
// badge.score         => 106
// badge.tier          => 3
// badge.vouchCount    => 5

// 4. Gate a feature on minimum tier
if (meetsMinimumTier(badge, 2)) {
  // allow posting in a verified-only community
}
```

`computeBadge` accepts any mix of kind 30470 and 30471 events. It handles expiry, deduplication
(one vouch counted per voucher pubkey), and optional Schnorr signature verification. The result is
a plain object — no rendering assumptions are made.

The `buildBadgeFilters` helper returns a standard Nostr REQ filter array ready for use with any
relay client library.


## Further Reading

- Full protocol specification: `spec/protocol.md`
- Voting extension: `spec/voting.md`
- Level 1 badge library: `src/badge.ts`
- Signet Score details: `src/trust-score.ts`
- Full working example: `examples/full-flow.ts`
- Jurisdiction-specific examples: `examples/jurisdictions/`
- "Signet me" peer verification: `examples/signet-me.ts`
