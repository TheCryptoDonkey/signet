# Signet Implementation Levels

A guide for Nostr client developers integrating the Signet identity protocol. There are three progressive integration levels. Start at Level 1 and add depth as your use case demands.

## Summary

| Level | Effort | Event Kinds | New Crypto | What Users Get |
|-------|--------|-------------|------------|----------------|
| 1 — Read Trust Badges | ~1 weekend | 30999 (credential, vouch) | None | Tier badges and Signet Score on profiles |
| 2 — Issue Vouches | A few days | 30999, 30078 | None | Peer vouching, Tier 2 networks, policy checks |
| 3 — Full Protocol | Weeks to months | 30999, 30078, 30482-30484 | Merkle, Pedersen range proofs, ring signatures | Professional verification, ZK proofs, elections |

---

## Level 1 — Read Trust Badges

**Effort:** A weekend
**Event kinds:** 30470 (credential), 30471 (vouch)
**New crypto required:** None — Nostr already verifies Schnorr signatures

This is the NIP-05 equivalent of Signet integration. You read two event kinds, call one function, and display a badge. No cryptographic work on your part beyond what your Nostr client already does.

### What to build

1. Subscribe to kind `30470` (credentials) and kind `30471` (vouches) for the pubkeys you want to display.
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
// The filters include both 30470 and 30471 kinds automatically.

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
**Event kinds:** 30470 (credential), 30471 (vouch), 30472 (policy)
**New crypto required:** None

Level 2 adds the ability for your users to vouch for each other and for your client to respect community policies. This is the viral layer of the protocol — peer vouching is what builds Tier 2 trust networks and creates network effects across clients.

### What to build

Everything from Level 1, plus:

1. UI for a user to select a contact and publish a kind `30471` vouch event.
2. Read kind `30472` (policies) from community relays and check whether a pubkey meets the policy threshold before allowing sensitive actions.

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

Policies (kind `30472`) let community operators define trust thresholds for specific actions — for example, requiring a minimum score of 40 before a user can post to a paid relay, or requiring Tier 2 before joining a group.

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
**Event kinds:** 30470–30480 (all 11 kinds)
**New crypto required:** Merkle trees, Pedersen range proofs (age range proofs), linkable ring signatures

Level 3 is full reference implementation. This is appropriate for clients that want to act as professional verifiers, run elections, or issue and receive Tier 3/4 credentials with zero-knowledge proofs.

### What to build (beyond Level 2)

- **Two-credential ceremony:** Professional verifiers issue a Natural Person credential (kind `30470`, with nullifier and Merkle root) and an anonymous Persona credential simultaneously. The Natural Person credential binds to a document-based nullifier (`SHA-256(docType || country || docNumber || salt)`) to prevent duplicate identity claims. The Persona credential reveals only an age range, not the full identity.
- **Merkle selective disclosure:** Verified attributes are stored as private leaves of a Merkle tree. Only the root is published on-chain. Users disclose individual leaves with inclusion proofs when required.
- **Age range proofs:** Pedersen range proofs prove that a user is within an age range without revealing their exact date of birth.
- **Professional verifier onboarding:** Verifier accounts (kind `30473`) are backed by recognised professional bodies (law societies, medical boards, notary commissions). The protocol has no central authority — trust anchors are these external bodies.
- **Ring signatures and elections:** The voting extension (kinds `30478`–`30480`) uses linkable ring signatures for anonymous voting with double-spend prevention.
- **Guardian delegation:** Kind `30477` delegation events with scopes (`full`, `activity-approval`, `content-management`, `contact-approval`) support family structures and guardian-linked sub-accounts.
- **Revocation and lifecycle:** Kind `30475` revocation events and credential chains using `supersedes`/`superseded-by` tags handle name changes, document renewal, and tier upgrades.
- **Identity bridging:** Kind `30476` identity bridge events link verified identities across protocols or jurisdictions.
- **Anomaly detection:** The library includes heuristics for detecting suspicious vouching patterns (e.g. vouch rings, rapid bulk vouching).

### Key modules in signet-protocol

All modules are re-exported from the package root. You can also import them directly for tree-shaking.

| Module | Source | Responsibility |
|--------|--------|----------------|
| Credentials | `src/credentials.ts` | Issue, parse, verify kind 30470 credentials including Merkle roots and nullifiers |
| Ring signatures | `src/ring-signature.ts` | Linkable ring signature generation and verification for voting |
| Range proofs | `src/range-proof.ts` | Bulletproof-based age range proofs |
| Merkle trees | `src/merkle.ts` | Build attribute trees, generate and verify inclusion proofs |
| Signet Score | `src/trust-score.ts` | Weighted signal aggregation, 0–200 Signet Score computation |
| Anomaly detection | `src/anomaly.ts` | Detect vouch ring attacks and other manipulation patterns |
| Jurisdictions | `src/jurisdictions.ts` | Jurisdiction-specific rules for document types and professional bodies |

All modules are re-exported from the package root (`signet-protocol`). Import from the root entry point:

### Full event kind reference

| Kind | Name | Description |
|------|------|-------------|
| 30470 | Credential | Identity claim with optional Merkle root and nullifier |
| 30471 | Vouch | Peer attestation of another pubkey's identity |
| 30472 | Policy | Community trust threshold definitions |
| 30473 | Verifier | Professional verifier registration |
| 30474 | Challenge | Verifier-issued identity challenge |
| 30475 | Revocation | Credential or vouch revocation |
| 30476 | Identity bridge | Cross-protocol or cross-jurisdiction identity link |
| 30477 | Delegation | Guardian or organisational delegation with scopes |
| 30478 | Election | Voting election definition (ring signature voting) |
| 30479 | Ballot | Anonymous signed ballot |
| 30480 | Election result | Tallied election result |

### Where to start

The `signet-protocol` npm package contains everything. The reference web app in the `app/` directory of this repository is a working Level 3 implementation and is the recommended starting point for understanding the full flow. The protocol specification at `spec/protocol.md` is the authoritative source of truth for all behaviour.

---

## Choosing your level

Start at Level 1 unless you have a specific reason to go further. Most social clients only need Level 1 — displaying trust context on profiles. Level 2 is appropriate if your community has a peer moderation culture. Level 3 is for infrastructure builders: relay operators, professional verification portals, and election platforms.

You can ship Level 1 in a weekend and upgrade later. The three levels are strictly additive — nothing you build at Level 1 needs to be undone to reach Level 2 or 3.
