# Signet

**Decentralised identity verification for Nostr.**

Signet is an open protocol that enables users to prove claims about their identity — age, parenthood, professional status — using zero-knowledge proofs, without revealing personal data or relying on a central authority.

## What It Does

- **4 verification tiers**: self-declared → web-of-trust → professional adult → professional adult+child
- **Signet IQ** (0-200, where 100 = government standard): weighted by professional verification > in-person vouches > online vouches > account age
- **Verifier anti-corruption**: 6 layers of accountability for professional verifiers
- **ZKP age proofs**: prove "child aged 8-12" without revealing exact date of birth
- **Blue checkmarks for Nostr**: decentralised, cryptographic social proof for everyone
- **Community policies**: any relay, client, or community sets their own minimum verification requirements

## Why

Nostr has no identity layer. Anyone can claim to be anyone. This matters for child safety (a predator can create a fake child account), for trust (no way to prove "I met this person"), and for regulation (age verification laws are coming worldwide).

Signet solves this without centralised data collection. A professional verifies your identity in person. A ZKP credential attests to the result. No personal data is stored. No database to breach.

## Quick Start

```bash
npm install signet-protocol
```

Display a verification badge for any Nostr user (Level 1 — a weekend to integrate):

```typescript
import { computeBadge, buildBadgeFilters, meetsMinimumTier } from 'signet-protocol';

const filters = buildBadgeFilters(['<hex-pubkey>']);
const events = await fetchFromRelay(filters);
const badge = computeBadge('<hex-pubkey>', events, { verifySignatures: true });

// badge.tier => 3, badge.score => 106, badge.displayLabel => "Verified (Tier 3)"
if (meetsMinimumTier(badge, 2)) {
  // allow posting in verified-only community
}
```

See [Signet in 5 Minutes](docs/signet-in-5-minutes.md) for a full developer overview, or the [full flow example](examples/full-flow.ts) for all 4 tiers, trust scoring, policies, and verifier lifecycle.

## Protocol

The full specification is at [`spec/protocol.md`](spec/protocol.md).

### Event Kinds

| Kind | Name | Purpose |
|------|------|---------|
| 30470 | Verification Credential | Attests to a subject's verification tier |
| 30471 | Vouch Attestation | Peer vouch for another user |
| 30472 | Community Verification Policy | Minimum verification requirements |
| 30473 | Verifier Credential | Professional declares verifier status |
| 30474 | Verifier Challenge | Challenge a verifier's legitimacy |
| 30475 | Verifier Revocation | Community confirms challenge, revokes verifier |
| 30476 | Identity Bridge | Link two keypairs via ring signature |
| 30477 | Delegation | Guardian or agent delegation with scoped permission |
| 30482 | Election | Voting extension: define an election |
| 30483 | Ballot | Voting extension: cast an anonymous ballot |
| 30484 | Election Result | Voting extension: publish tallied result |

### Crypto Stack

```
Layer 1: Schnorr (secp256k1) — zero new dependencies
         Credential signing, Merkle selective disclosure,
         ring signatures for issuer privacy, MuSig2

Layer 2: Bulletproofs (secp256k1) — age range proofs
         ~700 byte proofs, no trusted setup

Layer 3: General-purpose ZK (future, if needed)
         Complex threshold proofs, recursive composition
```

## Status

**v0.1.0** — spec complete, TypeScript library implemented, reference apps functional. Seeking community feedback.

Kind numbers are placeholders pending NIP allocation.

## Implementation

This repo includes:
- `src/` — TypeScript protocol library (`signet-protocol` on npm)

[Fathom](https://github.com/decented/decented) is the first external reference implementation, a sovereign learning and family management app on Nostr.

## Regulatory Compatibility

Signet is designed to satisfy identity verification requirements across jurisdictions:

| Regulation | Position |
|------------|----------|
| **UK Online Safety Act** | Tier 4 exceeds Ofcom's "highly effective age assurance" standard |
| **US COPPA** | No PII collected — exceeds FTC's March 2026 flexibility policy |
| **EU eIDAS 2.0** | Compatible with selective disclosure direction |
| **ISO/IEC 27566-1:2025** | Compatible with outcomes-based age assurance framework |
| **Australia under-16 ban** | Proves age range without central verification |

## Contributing

Feedback, NIP discussion, and contributions are welcome. Open an issue or submit a PR.

## Licence

MIT
