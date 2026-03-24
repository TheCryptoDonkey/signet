# Signet Implementation Levels

A guide for Nostr client developers integrating the Signet identity protocol. There are three progressive integration levels. Start at Level 1 and add depth as your use case demands.

## Summary

| Level | Effort | Event Kinds | New Crypto | What Users Get |
|-------|--------|-------------|------------|----------------|
| 1 — Read Trust Badges | ~1 weekend | 31000 (credential, vouch) | None | Tier badges and Signet Score on profiles |
| 2 — Issue Vouches | A few days | 31000, 30078 | None | Peer vouching, Tier 2 networks, policy checks |
| 3 — Full Protocol | Weeks to months | 31000, 30078, 30482-30484 | Merkle, Pedersen range proofs, ring signatures | Professional verification, ZK proofs, elections |

---

## Level 1 — Read Trust Badges

**Effort:** A weekend
**Event kinds:** 31000 (attestation — filter by `type` tag: `credential`, `vouch`)
**New crypto required:** None — Nostr already verifies Schnorr signatures

This is the NIP-05 equivalent of Signet integration. You read one event kind (filtered by type tag), call one function, and display a badge. No cryptographic work on your part beyond what your Nostr client already does.

### What to build

1. Subscribe to kind `31000` events with `type` tags `credential` and `vouch` for the pubkeys you want to display.
2. Pass the events to `computeBadge()`.
3. Show the result on the user's profile.

### Installation

```bash
npm install signet-protocol
```

### Code example

```typescript
import { computeBadge, buildBadgeFilters } from 'signet-protocol';

// 1. Fetch events from relay
const filters = buildBadgeFilters([pubkey]);
// Send a REQ message to your relay with these filters.
// The filters request kind 31000 with credential and vouch type tags.

// 2. Compute badge from the events you receive
const badge = computeBadge(pubkey, events);

// 3. Display
if (badge.isVerified) {
  showBadge(badge.tierLabel, badge.score);
}
```

The `badge` object includes:

- `badge.isVerified` — boolean, true if the pubkey has any Signet verification
- `badge.tier` — number 1–4, the highest verified tier
- `badge.tierLabel` — human-readable string (e.g. `"Vouched"`, `"Verified"`, `"Verified (Child Safety)"`)
- `badge.score` — integer 0–200 Signet Score derived from weighted trust signals (100 = government standard)

### Trust tiers at a glance

| Tier | Meaning |
|------|---------|
| 1 | Self-declared — the user has made identity claims |
| 2 | Web-of-trust — other users have vouched for this identity |
| 3 | Professional adult — verified by a recognised professional body |
| 4 | Professional adult + child safeguarding — extended professional verification |

### What you do NOT need to handle at this level

- Generating or validating zero-knowledge proofs
- Nullifier computation
- Merkle trees
- Any cryptographic primitives beyond standard Nostr signature verification

---

## Level 2 — Issue Vouches

**Effort:** A few days
**Event kinds:** 31000 (attestation — credential, vouch types), 30078 (policy)
**New crypto required:** None

Level 2 adds the ability for your users to vouch for each other and for your client to respect community policies. This is the viral layer of the protocol — peer vouching is what builds Tier 2 trust networks and creates network effects across clients.

### What to build

Everything from Level 1, plus:

1. UI for a user to select a contact and publish a kind `31000` vouch attestation (with `['type', 'vouch']` tag).
2. Read kind `30078` (NIP-78 app-specific data) policies from community relays and check whether a pubkey meets the policy threshold before allowing sensitive actions.

### Creating a vouch

```typescript
import { createVouch } from 'signet-protocol';

// createVouch takes the voucher's private key and a VouchParams object.
// It returns a signed Nostr event ready to publish.
const vouchEvent = await createVouch(myPrivkey, {
  subjectPubkey: theirPubkey,
  method: 'in-person',
  context: 'I have met this person in person and verified their identity.',
  voucherTier: 2,
  voucherScore: 106,
});

// Publish to your relay as a standard Nostr event.
await publishEvent(vouchEvent);
```

### Parsing incoming vouches

```typescript
import { parseVouch, countQualifyingVouches, hasEnoughVouches } from 'signet-protocol';

// Parse a raw Nostr event into a structured vouch object
const vouch = parseVouch(rawEvent);

// Count how many qualifying vouches a pubkey has received
const count = countQualifyingVouches(allVouchEvents, pubkey);

// Check whether a pubkey clears the threshold required for Tier 2
const qualifies = hasEnoughVouches(allVouchEvents, pubkey, 3);
```

Reference: `src/vouches.ts`

### Checking policy compliance

Policies (kind `30078`, NIP-78) let community operators define trust thresholds for specific actions — for example, requiring a minimum score of 40 before a user can post to a paid relay, or requiring Tier 2 before joining a group.

```typescript
import { parsePolicy, checkPolicyCompliance, PolicyChecker } from 'signet-protocol';

// Parse a policy event
const policy = parsePolicy(policyEvent);

// One-shot check: does this user meet the policy?
const result = checkPolicyCompliance(policy, userTier, userScore);
if (!result.allowed) {
  showError(`This action requires Tier ${result.requiredTier} or higher.`);
}

// For repeated checks across many pubkeys, use PolicyChecker (more efficient)
const checker = new PolicyChecker(policyEvent);
const adultResult = checker.checkAdult(userTier, userScore);
```

Reference: `src/policies.ts`

### What you do NOT need to handle at this level

- Zero-knowledge proofs of any kind
- Professional body verification flows
- Two-credential ceremonies
- Nullifiers or document hashing

---

## Level 3 — Full Protocol

**Effort:** Weeks to months
**Event kinds:** 31000 (all attestation types), 30078 (policies), 30482-30484 (voting)
**New crypto required:** Merkle trees, Pedersen range proofs (age range proofs), linkable ring signatures

Level 3 is full reference implementation. This is appropriate for clients that want to act as professional verifiers, run elections, or issue and receive Tier 3/4 credentials with zero-knowledge proofs.

### What to build (beyond Level 2)

- **Two-credential ceremony:** Professional verifiers issue a Natural Person credential (kind `31000` with `type: credential`, nullifier and Merkle root) and an anonymous Persona credential simultaneously. The Natural Person credential binds to a document-based nullifier (`SHA-256(docType || country || docNumber || salt)`) to prevent duplicate identity claims. The Persona credential reveals only an age range, not the full identity.
- **Merkle selective disclosure:** Verified attributes are stored as private leaves of a Merkle tree. Only the root is published on-chain. Users disclose individual leaves with inclusion proofs when required.
- **Age range proofs:** Pedersen range proofs prove that a user is within an age range without revealing their exact date of birth.
- **Professional verifier onboarding:** Verifier accounts (kind `31000` with `type: verifier`) are backed by recognised professional bodies (law societies, medical boards, notary commissions). The protocol has no central authority — trust anchors are these external bodies.
- **Ring signatures and elections:** The voting extension (kinds `30482`–`30484`) uses linkable ring signatures for anonymous voting with double-spend prevention.
- **Guardian delegation:** Delegation attestations (kind `31000` with `type: delegation`) with scopes (`full`, `activity-approval`, `content-management`, `contact-approval`) support family structures and guardian-linked sub-accounts.
- **Revocation and lifecycle:** Revocation attestations (kind `31000` with `type: revocation`) and credential chains using `supersedes`/`superseded-by` tags handle name changes, document renewal, and tier upgrades.
- **Identity bridging:** Identity bridge attestations (kind `31000` with `type: identity-bridge`) link verified identities across protocols or jurisdictions.
- **Anomaly detection:** The library includes heuristics for detecting suspicious vouching patterns (e.g. vouch rings, rapid bulk vouching).

### Key modules in signet-protocol

All modules are re-exported from the package root. You can also import them directly for tree-shaking.

| Module | Source | Responsibility |
|--------|--------|----------------|
| Credentials | `src/credentials.ts` | Issue, parse, verify credentials including Merkle roots and nullifiers |
| Ring signatures | `src/ring-signature.ts` | Ring signature generation and verification (via `@forgesworn/ring-sig`) |
| Range proofs | `src/range-proof.ts` | Pedersen range proofs for age verification (via `@forgesworn/range-proof`) |
| Merkle trees | `src/merkle.ts` | Build attribute trees, generate and verify inclusion proofs |
| Signet Score | `src/trust-score.ts` | Weighted signal aggregation, 0–200 Signet Score computation |
| Anomaly detection | `src/anomaly.ts` | Detect vouch ring attacks and other manipulation patterns |
| Jurisdictions | `jurisdiction-kit` | Jurisdiction-specific rules for document types and professional bodies |

All modules are re-exported from the package root (`signet-protocol`). Import from the root entry point:

### Event kind reference

All Signet identity attestations use a single generic kind, differentiated by `type` tag:

| Kind | Type Tag | Name | Description |
|------|----------|------|-------------|
| 31000 | `credential` | Credential | Identity claim with optional Merkle root and nullifier |
| 31000 | `vouch` | Vouch | Peer attestation of another pubkey's identity |
| 31000 | `verifier` | Verifier | Professional verifier registration |
| 31000 | `challenge` | Challenge | Challenge against a verifier's legitimacy |
| 31000 | `revocation` | Revocation | Credential or vouch revocation |
| 31000 | `identity-bridge` | Identity Bridge | Cross-protocol or cross-jurisdiction identity link |
| 31000 | `delegation` | Delegation | Guardian or organisational delegation with scopes |
| 30078 | — | Policy | Community trust threshold definitions (NIP-78) |
| 30482 | — | Election | Voting election definition (separate NIP) |
| 30483 | — | Ballot | Anonymous signed ballot |
| 30484 | — | Election Result | Tallied election result |

**Note:** Kind 31000 is the NIP-VA (Verifiable Attestations) kind. The `type` tag differentiates attestation types within the single kind.

### Where to start

The `signet-protocol` npm package contains everything. The protocol specification at `spec/protocol.md` is the authoritative source of truth for all behaviour.

---

## Choosing your level

Start at Level 1 unless you have a specific reason to go further. Most social clients only need Level 1 — displaying trust context on profiles. Level 2 is appropriate if your community has a peer moderation culture. Level 3 is for infrastructure builders: relay operators, professional verification portals, and election platforms.

You can ship Level 1 in a weekend and upgrade later. The three levels are strictly additive — nothing you build at Level 1 needs to be undone to reach Level 2 or 3.
