# The Signet Protocol

**Decentralised Identity Verification for Nostr**

**Version:** 0.1.0 (Draft)
**Date:** 2026-03-02
**Status:** Draft specification — seeking community feedback
**Licence:** MIT

---

## Abstract

Signet is an open protocol for decentralised identity verification on Nostr. It enables users to prove claims about their identity — age, parenthood, professional status — using zero-knowledge proofs, without revealing personal data or relying on a central authority.

The protocol defines four verification tiers, nine entity types, a continuous trust score, a verifier accountability framework, and seven Nostr event kinds. Any Nostr client can implement Signet. Any community can set verification policies. Any licensed professional can become a verifier.

**Child safety is the killer app. Social proof (blue checkmarks) drives adoption across all of Nostr.**

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Design Principles](#2-design-principles)
3. [Credential Tiers](#3-credential-tiers)
4. [Trust Score](#4-trust-score)
5. [Service Policies](#5-service-policies)
6. [Verifier Network](#6-verifier-network)
7. [Anti-Corruption Framework](#7-anti-corruption-framework)
8. [Event Kinds](#8-event-kinds)
9. [Cryptographic Stack](#9-cryptographic-stack)
10. [Social Proof — The Blue Checkmark](#10-social-proof--the-blue-checkmark)
11. [Alignment with Existing Standards](#11-alignment-with-existing-standards)
12. [Regulatory Compatibility](#12-regulatory-compatibility)
13. [Limitations](#13-limitations)
14. [Reference Implementation](#14-reference-implementation)
15. [Identity Management & Peer Verification](#15-identity-management--peer-verification)
16. [Identity Bridge](#16-identity-bridge)
17. [Entity Type Classification](#17-entity-type-classification)

---

## 1. Motivation

### The Identity Gap on Nostr

Nostr has no identity verification. Anyone can claim to be anyone. There is no blue checkmark, no web-of-trust scoring, no way to prove "I met this person" or "a professional verified this person's identity." The result: spam, impersonation, and zero basis for trust beyond "I recognise this pubkey."

### For Children

Every kids' social platform that failed (Club Penguin, Messenger Kids, Wizz, Yubo) collapsed because safety was policy-based, not cryptographic. Adults could create child accounts to impersonate children. Age verification was self-declaration or nonexistent. No platform could prove:

- This parent is a real person
- This child is a real child
- This parent actually has this child

### For Everyone

Nostr needs a trust layer that:

- Proves claims without revealing personal data
- Works without a central authority
- Starts with nothing (any account can get verified retroactively)
- Scales from casual peer vouching to professional identity verification
- Lets communities set their own policies

### The Regulatory Landscape

The world is moving to mandatory age verification:

- **EU eIDAS 2.0** (December 2026): Every Member State must offer a digital identity wallet with selective disclosure
- **France SREN law** (April 2025): Adult sites must implement ZKP-based age verification
- **UK Online Safety Act** (2023): Platforms liable for children's exposure; Ofcom requires "highly effective age assurance"
- **US COPPA 2.0** (pending): Extends protections to under-17
- **US FTC COPPA flexibility** (March 2026): FTC will not enforce against data collected solely for age verification — but requires robust deletion and clear notice. Signet exceeds this: no personal data is collected at all.
- **Australia under-16 ban** (2024): $50M AUD fines on platforms
- **ISO/IEC 27566-1:2025**: New global age assurance standard

Nobody has built this for the decentralised world. Signet fills that gap.

---

## 2. Design Principles

1. **The credential states facts, the service sets policy.** Credentials say "here's what was verified and how." Communities decide "here's what we require." Separation of attestation and enforcement.

2. **Privacy by default.** ZKP means proving a claim without revealing the underlying data. "This parent has a child aged 8-12" without revealing which parent, which child, or the exact age.

3. **No central authority.** Professional bodies (Law Society, Medical Board, notary commissions) are the trust anchors. No single entity approves verifiers. No DAO. No token.

4. **Progressive — more than nothing is better than nothing.** Users who refuse to show documents can still accumulate peer vouches. Less trust weight, but more than zero, which is what everyone has today.

5. **Retroactive.** Verification attaches to existing accounts. Any active Nostr identity — adult or child — can get verified at any time. Not tied to account creation.

6. **Composable.** Discrete tiers for policy gates + continuous score for reputation. Simple for end users, nuanced for power users.

7. **Nostr-native.** Built on secp256k1. Uses existing Nostr event infrastructure. Zero new dependencies for basic functionality.

---

## 3. Credential Tiers

Four tiers of verification, each declaring what was proven and by whom.

### Tier 1 — Self-Declared

| Aspect | Detail |
|--------|--------|
| **What's proven** | Nothing — a signed claim: "I say I'm X" |
| **Issuer** | Self |
| **ZKP hides** | N/A |
| **Use case** | Baseline. What every Nostr account has today. |
| **Trust weight** | Minimal |

### Tier 2 — Web-of-Trust Vouched

| Aspect | Detail |
|--------|--------|
| **What's proven** | N verified people (Tier 2+) attest: "I know this person/family" |
| **Issuer** | Peers |
| **ZKP hides** | Who vouched (proves count and minimum tier of vouchers without revealing identities) |
| **Use case** | Local communities, meetup groups, conferences. People who know each other. |
| **Trust weight** | Moderate. In-person vouches carry more weight than online vouches. |
| **Threshold** | Configurable per community. Default: 3 vouches from Tier 2+ accounts. |

### Tier 3 — Professional Verified (Adult)

| Aspect | Detail |
|--------|--------|
| **What's proven** | A licensed professional verified this adult's government-issued ID in person |
| **Issuer** | Professional (lawyer, doctor, notary) |
| **ZKP hides** | Which professional, the adult's real name, ID number, address — everything except "a professional verified this person" |
| **Use case** | High-trust communities. Adults who want strong verification without publishing their identity. |
| **Trust weight** | High |

### Tier 4 — Professional Verified (Adult + Child)

| Aspect | Detail |
|--------|--------|
| **What's proven** | A licensed professional verified the adult's ID AND confirmed a child exists in a specific age range |
| **Issuer** | Professional |
| **ZKP hides** | Everything in Tier 3 + child's identity, exact age, which documents were shown |
| **Evidence the professional sees** | Parent's ID (passport, driving licence) + child evidence (birth certificate, passport, school record) |
| **Use case** | Maximum safety spaces. Proves the child is real and the parent is real. |
| **Trust weight** | Maximum |

### Why Tier 4 Stops Predators

A predator who is a verified real adult (Tier 3) could still create a fake child account. Tier 4 prevents this because:

- A professional independently confirms the child exists
- The professional sees evidence of the child (birth cert, passport)
- The professional's licence is on the line — fraudulent attestation = professional misconduct
- The ZKP cryptographically binds the parent's identity to the child's verified age range
- An adult pretending to have a child cannot produce a child's birth certificate to a lawyer

---

## 4. Trust Score

On top of discrete tiers, a continuous trust score (0-100%) provides nuanced reputation.

### Score Components

| Signal | Weight | Notes |
|--------|--------|-------|
| Professional verification (Tier 3/4) | Heavy | Single event, large impact |
| Identity bridge (kind 30476) | Medium | Ring-sig proof linking anon account to verified identity, scaled by ring min tier |
| In-person peer signature | Strong | Met in person, signed keys face-to-face |
| Online vouch from verified user | Light | Accumulates — many light vouches add up |
| Account age | Passive | Time on the network adds weight gradually |
| Voucher's own score | Multiplier | A vouch from someone at 90% carries more than from someone at 30% |

### Score Algorithm

The exact algorithm is implementation-defined (clients can weight signals differently), but the protocol specifies the **signal types and their relative ordering**:

```
professional verification > identity bridge > in-person vouch > online vouch > account age
```

Clients MUST respect this ordering. A single professional verification always outweighs any number of online vouches. This prevents gaming through vouch farms.

### Display

```
┌───────────────────────────────────┐
│  Alice ✓✓✓              Tier 3   │
│  Trust: 87%                       │
│                                   │
│  ● Prof verified (lawyer)         │
│  ● 4 in-person vouches            │
│  ● 12 online vouches              │
│  ● Account age: 2 years           │
└───────────────────────────────────┘
```

- **Tier** = the gate (can you enter this space?)
- **Score** = the reputation (how much should I trust this person?)
- End users see a simple tier badge. Power users can drill into the score breakdown.

---

## 5. Service Policies

Each community, circle, relay, or client sets a minimum verification requirement.

### Policy Matrix

| Community Type | Adult Minimum | Child Minimum | Example |
|----------------|---------------|---------------|---------|
| Open | Tier 1 | Tier 1 | Public Nostr feed |
| Casual group | Tier 2 | Tier 2 | Local meetup group |
| Curated circle | Tier 3 | Tier 3 | Trusted community |
| Max safety | Tier 3 | Tier 4 | Children's learning space |

### Policy Options

Services can also set:

- **Minimum score**: "Tier 2 AND score > 50%"
- **Per-role requirements**: "moderators need Tier 3, members need Tier 2"
- **Child-specific overrides**: "adults can be Tier 2, child accounts must be Tier 4"

### Policy Enforcement

Policy is enforced at the **client level** and optionally at the **relay level**:

- **Client-side**: Clients check Signet credentials before displaying content or allowing interaction.
- **Relay-side** (optional): AUTH-gated relays can require minimum verification tier before accepting events. This prevents unverified accounts from even publishing to protected spaces.

---

## 6. Verifier Network

### Open With Credentials — No Central Authority

Anyone can become a verifier if they meet the criteria. No single entity approves verifiers. No DAO. No token.

### Professional Verifiers (Issue Tier 3/4)

**Becoming a professional verifier:**

1. Publish a verifier credential (kind 30473) containing your professional licence information (bar number, medical licence number, notary commission ID)
2. Get cross-verified by other professional verifiers (prevents fraudulent licence claims)
3. You can now issue Tier 3 and Tier 4 attestations
4. Your professional body is your accountability — fraudulent attestations = professional misconduct, loss of licence, potential criminal liability

**Professional bodies as trust anchors:**

The system doesn't create a new trust hierarchy. It uses the ones that already exist: the Law Society, medical licensing boards, notary commissions. These bodies already:

- Verify practitioners' identities
- Hold them to ethical standards
- Have disciplinary procedures
- Can revoke licences

Signet gives these existing trust relationships a cryptographic expression.

**Cross-verification prevents gaming:**

A fake lawyer can't just publish a credential claiming to be a lawyer. Other verified lawyers in the network must vouch for the credential. This creates a self-policing professional network — the same professionals who risk their licences have every incentive to call out fakes.

### Peer Verifiers (Contribute to Tier 2 and Score)

**Becoming a peer verifier:**

1. Reach Tier 2+ yourself
2. You can vouch for others you know
3. In-person vouches (key signing at meetups, conferences) carry more weight than online vouches
4. Your vouches' weight scales with your own trust score

**The already-doxed advantage:**

People who are already public figures (conference speakers, known community members) can vouch freely for people they meet in person. Their public identity IS their credential. When they sign someone's key at a meetup, that signature carries real weight because the voucher is already publicly accountable.

### Verification Flow

```
Professional Verification (Tier 3/4):

  User ──── meets in person ────► Lawyer/Doctor/Notary
                                       │
                                  sees passport
                                  (+ child evidence for Tier 4)
                                       │
                                  issues Signet credential
                                       │
                                  publishes to Nostr relay
                                       │
  User's account ◄──── credential attached ────┘


Peer Verification (Tier 2 / score):

  User A ──── meets User B in person ────► key signing
                                              │
                                         mutual vouch events
                                         published to relay
                                              │
  Both users' scores increase ◄───────────────┘


Online Vouching (score only):

  Verified User ──── "I vouch for this person" ────► vouch event
                                                        │
  Target user's score increases ◄───────────────────────┘
  (weight depends on voucher's own score)
```

---

## 7. Anti-Corruption Framework

A registered professional can still be corrupt — doctors sell black market prescriptions, lawyers take bribes. No single measure prevents this. The defence is layered: make corruption expensive, detectable, and permanently traceable.

### Layer 1 — Public Registry Verification

Every verifier credential (kind 30473) includes a licence number and jurisdiction. Any client can link directly to the relevant public register for users to verify:

| Jurisdiction | Register | URL |
|-------------|----------|-----|
| UK solicitors | SRA | sra.org.uk/consumers/register |
| UK doctors | GMC | gmc-uk.org/registration-and-licensing |
| US lawyers | State bar (per state) | Varies by state |
| Notaries | State/county register | Varies by jurisdiction |

A fake professional is caught immediately — anyone can look up whether the licence number corresponds to a real, active practitioner. Clients can automate this check where registers expose APIs.

### Layer 2 — Cross-Professional Verification

A new verifier needs vouches from verified professionals in **other** fields. A corrupt doctor needs corrupt friends who are lawyers, notaries, or accountants. Cross-profession collusion rings are exponentially harder to build than single-profession ones.

Minimum requirement for verifier activation:

- At least 2 vouches from verified professionals
- At least 2 different professions represented
- Vouchers must themselves be active, non-revoked verifiers

### Layer 3 — Rate Limiting / Anomaly Detection

All credentials are public Nostr events. Issuance volume is visible to the entire network.

Clients perform statistical anomaly detection:

- **Volume flags:** A doctor issuing 200 verifications/week vs. the network average of 5/week is automatically flagged.
- **Geographic flags:** A solicitor in Manchester verifying 50 families in Tokyo is suspicious.
- **Temporal flags:** 30 verifications in one hour suggests rubber-stamping, not in-person ID checks.
- **Display:** Clients show a warning badge on credentials from flagged verifiers: "This verifier's issuance pattern is unusual."

This is purely client-side — no central authority decides what's suspicious. Each client applies its own heuristics. The transparency of Nostr events makes this possible without surveillance.

### Layer 4 — Lightning Bond (Skin in the Game)

Professional verifiers stake sats via Lightning when registering as a verifier. The bond is:

- **Locked** when the verifier credential (kind 30473) is published
- **Slashed** (burned or redistributed to reporters) if the verifier is found fraudulent and revoked
- **Returned** if the verifier deactivates cleanly (retires, leaves the network)

Bond amount is configurable per community policy. A casual group might require 100,000 sats. A high-security community might require 1,000,000 sats. The bond makes corruption financially costly — a corrupt verifier doesn't just lose their reputation, they lose money.

Implementation: NWC (Nostr Wallet Connect) for bond locking. The bond mechanism is optional — communities that don't require it simply don't set a bond threshold in their policy (kind 30472).

### Layer 5 — Community Reporting and Revocation

Anyone can publish a **challenge event** (kind 30474) against a verifier, presenting evidence of fraudulent behaviour.

Challenge flow:

```
Reporter ──── publishes kind 30474 ────► challenge event
                                            │
                                        includes evidence
                                        (screenshots, registry status,
                                         anomaly data, testimony)
                                            │
              ◄──── community reviews ──────┘
                                            │
              If N trusted accounts (Tier 3+) confirm:
                │
                ├─ Verifier's kind 30473 is superseded
                │  by a revocation event (kind 30475)
                │
                ├─ Lightning bond is slashed
                │
                └─ All credentials issued by this verifier
                   are flagged in clients
```

The threshold for revocation (how many confirmations needed) is set per community policy. Default: 5 confirmations from Tier 3+ accounts.

### Layer 6 — Credential Provenance Trail

Every credential (kind 30470) traces back to its issuer via the `pubkey` field. This is an immutable, public audit trail on Nostr relays.

If a verifier is revoked:

- Clients display a warning on all credentials they issued: "This verification was issued by a now-revoked verifier. Re-verification recommended."
- The credentials are not automatically invalidated — the community policy decides whether to require re-verification or grandfather existing credentials.
- The subject can get re-verified by a different professional. The old credential remains as a historical record.

### The Cumulative Cost of Corruption

A corrupt professional in this system must:

1. Be genuinely registered with a professional body (or be caught instantly by registry check)
2. Convince professionals in *other* fields to vouch for them (cross-profession requirement)
3. Keep issuance volume low enough to avoid anomaly detection (limits the profit from corruption)
4. Risk losing their Lightning bond (direct financial cost)
5. Risk community reporting, public revocation, and permanent reputation damage on Nostr
6. Accept that every fake credential they ever issued is permanently traceable back to them

Compare this to centralised identity verification: a company scans your ID, stores it in a database that gets breached, and has no accountability when it fails. Signet doesn't prevent all corruption — nothing does — but it makes corruption more expensive and more detectable than any centralised alternative.

---

## 8. Event Kinds

**Note:** Kind numbers are placeholders pending NIP allocation.

### Kind 30470 — Verification Credential

A replaceable event published by a verifier attesting to a subject's verification status.

```jsonc
{
  "kind": 30470,
  "pubkey": "<verifier_pubkey>",
  "tags": [
    ["d", "<subject_pubkey>"],           // who is being verified
    ["p", "<subject_pubkey>"],           // for queryability
    ["tier", "3"],                        // 1, 2, 3, or 4
    ["type", "professional"],            // "self", "peer", "professional"
    ["scope", "adult"],                  // "adult" or "adult+child"
    ["age-range", "8-12"],              // only for tier 4 (child age range)
    ["method", "in-person-id"],          // verification method
    ["profession", "solicitor"],         // verifier's profession
    ["jurisdiction", "UK"],              // legal jurisdiction
    ["expires", "<unix_timestamp>"],     // credential expiry
    ["L", "signet"],                     // protocol namespace label
    ["l", "verification", "signet"]      // protocol label
  ],
  "content": "<zkp_proof_blob>"          // the actual zero-knowledge proof
}
```

### Kind 30471 — Vouch Attestation

A replaceable event published by a peer vouching for another user.

```jsonc
{
  "kind": 30471,
  "pubkey": "<voucher_pubkey>",
  "tags": [
    ["d", "<subject_pubkey>"],           // who is being vouched for
    ["p", "<subject_pubkey>"],
    ["method", "in-person"],             // "in-person" or "online"
    ["context", "bitcoin-meetup"],       // optional: where/how they met
    ["voucher-tier", "3"],               // voucher's own tier at time of vouch
    ["voucher-score", "87"],             // voucher's own score at time of vouch
    ["L", "signet"],
    ["l", "vouch", "signet"]
  ],
  "content": ""                          // no personal data
}
```

### Kind 30472 — Community Verification Policy

A replaceable event published by a community operator defining minimum verification requirements.

```jsonc
{
  "kind": 30472,
  "pubkey": "<community_operator_pubkey>",
  "tags": [
    ["d", "<community_identifier>"],
    ["adult-min-tier", "2"],
    ["child-min-tier", "3"],
    ["min-score", "50"],                 // optional minimum score
    ["mod-min-tier", "3"],               // optional moderator requirement
    ["enforcement", "client"],           // "client", "relay", or "both"
    ["verifier-bond", "100000"],         // optional: min sats bond for verifiers
    ["revocation-threshold", "5"],       // optional: confirmations needed to revoke
    ["L", "signet"],
    ["l", "policy", "signet"]
  ],
  "content": "<human-readable policy description>"
}
```

### Kind 30473 — Verifier Credential

A replaceable event published by a professional declaring their verifier status.

```jsonc
{
  "kind": 30473,
  "pubkey": "<verifier_pubkey>",
  "tags": [
    ["d", "verifier-credential"],
    ["profession", "solicitor"],
    ["jurisdiction", "UK"],
    ["licence", "<encrypted_or_hashed_licence_number>"],
    ["body", "Law Society of England and Wales"],
    ["L", "signet"],
    ["l", "verifier", "signet"]
    // Cross-verification vouches from other professionals
    // are separate kind 30471 events pointing at this pubkey
  ],
  "content": "<optional: public statement about verification services>"
}
```

### Kind 30474 — Verifier Challenge

A regular event published by anyone challenging a verifier's legitimacy. Triggers community review.

```jsonc
{
  "kind": 30474,
  "pubkey": "<reporter_pubkey>",
  "tags": [
    ["d", "<verifier_pubkey>"],            // who is being challenged
    ["p", "<verifier_pubkey>"],
    ["reason", "anomalous-volume"],        // "anomalous-volume", "registry-mismatch",
                                           // "fraudulent-attestation", "licence-revoked",
                                           // "other"
    ["evidence-type", "registry-screenshot"], // type of evidence provided
    ["reporter-tier", "3"],                // reporter's own tier
    ["L", "signet"],
    ["l", "challenge", "signet"]
  ],
  "content": "<detailed evidence and explanation>"
}
```

### Kind 30475 — Verifier Revocation

A replaceable event published when a community confirms a challenge. Supersedes the verifier's kind 30473 credential.

```jsonc
{
  "kind": 30475,
  "pubkey": "<revoking_authority_pubkey>",  // community operator or threshold of Tier 3+ accounts
  "tags": [
    ["d", "<verifier_pubkey>"],             // whose credential is revoked
    ["p", "<verifier_pubkey>"],
    ["challenge", "<kind_30474_event_id>"], // the challenge that triggered this
    ["confirmations", "7"],                 // number of Tier 3+ accounts that confirmed
    ["bond-action", "slashed"],             // "slashed", "returned", "held"
    ["scope", "full"],                      // "full" = all credentials flagged,
                                            // "partial" = specific credentials flagged
    ["effective", "<unix_timestamp>"],      // when revocation takes effect
    ["L", "signet"],
    ["l", "revocation", "signet"]
  ],
  "content": "<summary of findings>"
}
```

**Client behaviour on kind 30475:**

1. Display a warning on all kind 30470 credentials issued by the revoked verifier
2. Reduce the trust score contribution of those credentials to zero
3. Notify affected users that re-verification is recommended
4. Do not automatically invalidate credentials — the community policy decides whether to require re-verification or grandfather existing ones

### Kind 30476 — Identity Bridge

A replaceable event published by an anonymous account to prove it is controlled by a verified identity, without revealing which one. Uses SAG ring signatures over secp256k1.

**Use case:** A user has a real-name account (verified at Tier 3 by a professional) and an anonymous account. The identity bridge lets the anonymous account prove "I am a real verified person" without revealing which verified person. This enables anonymous participation with trust.

```jsonc
{
  "kind": 30476,
  "pubkey": "<anon_pubkey>",              // the anonymous account publishing this
  "tags": [
    ["d", "identity-bridge"],
    ["ring-min-tier", "3"],                // minimum verification tier of ring members
    ["ring-size", "10"],                   // number of pubkeys in the ring
    ["L", "signet"],
    ["l", "identity-bridge", "signet"]
  ],
  "content": "{\"ringSig\":{\"ring\":[...],\"c0\":\"...\",\"responses\":[...],\"message\":\"signet:identity-bridge:<anon_pubkey>:<timestamp>\"},\"timestamp\":...}"
}
```

**Ring signature construction:**

1. The real verified account's pubkey is placed at a random position in a ring of N verified pubkeys (minimum N=5).
2. The binding message is `signet:identity-bridge:<anon_pubkey>:<timestamp>`.
3. The real account's private key signs this message using a SAG ring signature, proving one of the N ring members also controls the anon account.
4. The Nostr event itself is signed by the anonymous account's private key.

**Verification:**

1. Verify the Nostr event signature (anon account signed the event).
2. Parse the ring signature from content.
3. Verify the binding message format matches `signet:identity-bridge:<event.pubkey>:<timestamp>`.
4. Verify the ring signature (one of the ring members signed the binding message).
5. Verify ring size >= 5 (anonymity threshold).

**Trust score contribution:**

- Base weight: 25 points (between professional verification and in-person vouch).
- Scaled by ring minimum tier: `weight = 25 × (ringMinTier / 4)`.
- Tier 3 ring → 18.75 points. Tier 4 ring → 25 points.
- Only one bridge per account is counted.

**Trust compounding:** When bridged anonymous accounts vouch for each other, each vouch is weighted by the voucher's score (which includes bridge points). This creates natural trust compounding without a special mechanism.

**Privacy guarantees:**

- The ring signature reveals only that *one of N* verified accounts controls the anon account, not which one.
- Minimum ring size of 5 provides meaningful anonymity (1-in-5 or better).
- Larger rings provide stronger anonymity at no additional cost to the verifier.
- The binding message prevents ring signature reuse across different anon accounts.

---

## 9. Cryptographic Stack

The protocol design (tiers, scores, event kinds, policies) is specified independently of the ZKP implementation. The credential format works regardless of which cryptographic library backs the proofs. This section specifies the recommended architecture.

### Recommended Architecture: Hybrid Layers

```
Layer 1: Schnorr — the base (zero new dependencies)
│
├─ Credential issuance & verification
│   Verifier signs kind 30470 event with their Nostr key.
│   Any client verifies with schnorr.verify().
│
├─ Selective disclosure via Merkle trees
│   Credential attributes as Merkle leaves, sign root.
│   Holder reveals chosen attributes + sibling paths.
│   @noble/secp256k1 + @noble/hashes (already in every Nostr client).
│
├─ Ring signatures for issuer privacy (Tier 3/4)
│   SAG: "one of these N professionals verified this"
│   without revealing which one.
│   Stays on secp256k1.
│
├─ MuSig2 for multi-verifier co-signing
│   Multiple professionals co-sign → single aggregated Schnorr sig.
│
└─ Trust score computation
    Pure client-side math. Count vouches, weight by voucher score.
    No crypto needed.

Layer 2: Bulletproofs — targeted addition (for Tier 4 age proofs)
│
└─ Age range proofs
    "This child is in age range [8, 12]" without revealing exact age.
    Pedersen commitment + Bulletproof range proof on secp256k1.
    ~700 byte proofs. No trusted setup. No new curve.

Layer 3: General-purpose ZK (future, if needed)
│
├─ Complex threshold proofs
│   "I have N vouches from tier 2+ accounts" via recursive composition.
│
├─ Credential binding proofs
│   Prove credential ownership + attribute predicate in one proof.
│
└─ Unlinkable presentations (if required)
    Re-randomisable proofs. For when threat model evolves.
```

### What Each Tier Needs

| Tier | Crypto Required | New Dependencies |
|------|----------------|------------------|
| **Tier 1** (self-declared) | Standard Nostr event signing | None (already present) |
| **Tier 2** (web-of-trust) | Vouch events + score calculation | None |
| **Tier 3** (professional, adult) | Ring signature on credential | Ring signature library (secp256k1-based) |
| **Tier 4** (professional, adult+child) | Ring sig + age range proof | Ring sig + Bulletproofs library |
| **Blue checkmark / score** | Read existing events, compute score | None |

### The Credential Signing Decision

Verifiers sign credentials with their **Nostr key** (secp256k1 Schnorr). No second keypair required.

| Approach | Pro | Con | Decision |
|----------|-----|-----|----------|
| **Nostr key only** | One identity, Nostr-native, no extra keys | Expensive to prove inside ZK circuits if needed later | **Use this.** |
| ZK-friendly curve (Baby Jubjub) | Cheap to prove in ZK circuits | Verifiers need a second keypair | Defer unless ZK circuit proofs become essential. |

Ring signatures handle issuer privacy without ZK circuits. Bulletproofs handle age range proofs without leaving secp256k1. The ZK-friendly signature question only arises if the protocol needs to prove "this Nostr key signed this credential" inside a zero-knowledge circuit — and the current design avoids that need.

### Reference Libraries

| Library | Purpose | Notes |
|---------|---------|-------|
| `@noble/secp256k1` | Core Schnorr sign/verify | Stable, audited, 4.94KB gzipped |
| `@noble/hashes` | SHA-256 for Merkle trees | Stable, audited |
| Ring signature lib (e.g. Nostringer) | SAG on Nostr pubkeys | Experimental — needs audit before production |
| MuSig2 lib | Multi-party signing | Functional, BIP-327 |
| Bulletproofs lib | Range proofs on secp256k1 | Needs audit before production |

### Open Implementation Questions

1. **Ring signature audit.** Ring signatures are critical for Tier 3/4 issuer privacy. The SAG math is sound (used by Monero for years) but JS implementations need audit.
2. **Bulletproofs library choice.** Pure JS (slower, easier to audit) vs WASM (faster, harder to audit the C layer).
3. **Ring size.** How many professional verifiers form the anonymity set? Target: 20-50 verifiers per profession per jurisdiction.
4. **Credential expiry.** Verification credentials should expire (recommended: 1-2 years) and be renewable.
5. **Revocation propagation.** NIP-09 deletion requests are advisory only. The kind 30474/30475 challenge-revocation mechanism handles this at the protocol level.

---

## 10. Social Proof — The Blue Checkmark

The verification system is not limited to child safety. It is a general-purpose Nostr identity layer.

### For Users Who Won't Show Documents

They can still build trust through:

- Peer vouches from verified users
- In-person key signings at meetups and conferences
- Account age and consistent behaviour
- Online vouches from high-score accounts

This gives them a visible trust score and a checkmark — weaker than professional verification, but more than nothing. And nothing is what everyone on Nostr has today.

### For Public Figures

Already-doxed individuals (podcasters, conference speakers, known community members) can leverage their public identity. Their checkmark is backed by the fact that hundreds of people have met them and can vouch. They become trust anchors for their communities.

### For Creators

A verified creator can prove they're real without revealing their legal name. Content gated by verification tiers becomes more valuable when the creator has a verified identity backing it.

### Checkmark Display

| Display | Meaning |
|---------|---------|
| No mark | Unverified (Tier 1) |
| ✓ | Web-of-trust vouched (Tier 2) |
| ✓✓ | Professional verified, adult (Tier 3) |
| ✓✓✓ | Professional verified, adult + child (Tier 4) |
| Score % | Continuous reputation visible on drill-down |

---

## 11. Alignment with Existing Standards

| Standard | Relevance |
|----------|-----------|
| **NIP-58** (Badges, kind 30009/8) | Existing attestation system on Nostr. Signet credentials extend this pattern with cryptographic proofs. |
| **NIP-101** (proposed) | Decentralised trust system integrating W3C VC format with Nostr. Signet is complementary — simpler, Nostr-native, focused on progressive tiers. |
| **Nostr DID method** (`did:nostr:<hex_pubkey>`) | Enables Nostr keys to participate in W3C DID/VC ecosystem. Signet credentials could be wrapped as W3C VCs for interop. |
| **SchnorrSecp256k1Signature2019** (DIF) | Proposed proof type for W3C VCs using Schnorr over secp256k1. Would let Signet events be treated as standards-compliant W3C VCs. |
| **ISO/IEC 27566-1:2025** | Age assurance standard. Signet's architecture is compatible with the outcomes-based framework (effectiveness, privacy, security, acceptability). |
| **UK DIATF** | Digital Identity and Attributes Trust Framework. Signet's Tier 3/4 architecture aligns. Not yet certified. Certification path exists. |
| **EU eIDAS 2.0** | European digital identity framework. Signet's selective disclosure via Merkle trees and ZKP proofs aligns with eIDAS requirements for minimal disclosure. |

---

## 12. Regulatory Compatibility

Signet is designed to satisfy identity verification requirements across multiple jurisdictions without centralised data collection.

| Regulation | How Signet Addresses It |
|------------|------------------------|
| **UK Online Safety Act** (ss.9, 11, 12) | Tier 4 provides "highly effective age assurance" via professional in-person verification. Exceeds Ofcom's accepted methods. No centralised ID scanning. |
| **COPPA / COPPA 2.0** (US) | Cryptographic proof of parental consent via Tier 3/4 credential. Exceeds current parental consent mechanisms. The FTC's March 2026 policy statement permits data collection solely for age verification with robust deletion — Signet goes further by collecting no personal data at all. The ZKP proof contains zero PII. |
| **EU eIDAS 2.0** | Credential format compatible with eIDAS selective disclosure direction. Could accept EU digital identity wallet credentials as Tier 3 input. |
| **France SREN law** | ZKP-based age verification is explicitly what the law requires. |
| **Australia under-16 ban** | Tier 4 proves child's age range without central verification. |
| **ISO/IEC 27566-1:2025** | Protocol design is compatible with the outcomes-based framework. |

### The FTC's New Position and Signet

In March 2026, the FTC issued a policy statement signalling flexibility on COPPA age checks: it will not take enforcement action where personal data is collected solely for age verification purposes, provided the data is robustly deleted and clear notice is given to parents and children.

This is significant because it removes a major blocker — platforms were previously reluctant to implement age verification for fear of COPPA liability for collecting the verification data itself. The FTC is now saying: verify ages, just delete the data.

Signet leapfrogs this entirely:

| FTC Requirement | Signet's Position |
|----------------|-------------------|
| Data collected solely for age verification | No data collected — ZKP proves age range without transmitting personal data |
| Robust data deletion | Nothing to delete — no PII ever enters any system |
| Clear notice to parents/children | Parent initiates the entire verification process and holds all keys |
| Don't use data for other purposes | Cryptographically impossible — the proof contains no personal data to repurpose |

The FTC lowered the bar. Signet doesn't need the bar — it flies over it.

### The Privacy Argument

Every other approach to age verification involves a trade-off: privacy vs safety, user experience vs verification rigour, centralised control vs accountability. Signet is designed to avoid that trade-off:

- Professional verifies in person → ZKP credential
- Credential proves age range without revealing personal data
- No personal data stored centrally — no database to breach
- Anti-corruption layers on verifier network
- Audit trail on Nostr relays

---

## 13. Limitations

| Limitation | Why It's Acceptable |
|------------|---------------------|
| **A verified parent can still be a bad parent** | True of all systems. The protocol proves identity, not character. But it creates accountability — the parent's verified identity is cryptographically linked. |
| **Professional verifiers could collude** | Possible but career-ending. Cross-verification and professional body oversight mitigate this. Same risk exists in the existing notary/legal system. |
| **Doesn't prevent all predators** | A determined predator with a real child could still misuse the system. But they can no longer be anonymous — their Tier 4 credential links back to a professional who verified them in person. |
| **ZKP crypto is complex** | Implementation risk. Mitigated by using proven libraries and by designing the protocol independently of the crypto stack. |
| **Adoption requires verifiers** | Chicken-and-egg: users need verifiers, verifiers need users. Mitigated by the web-of-trust tier (no professionals needed) and by starting with existing professional networks. |

---

## 14. Reference Implementation

The first reference implementation of Signet is being built within [Fathom](https://github.com/decented/decented), a sovereign learning and family management app built on Nostr. Fathom's implementation integrates Signet credentials with:

- Parent-controlled vault tiers (cryptographic access control)
- Child account protection (NIP-26 delegation)
- Community verification policies for home-education groups
- Age-based permission defaults

Signet is designed as a standalone NIP. Any Nostr client can implement it independently. The protocol does not depend on Fathom or any specific client.

### Contributing

Signet is open source. Contributions, feedback, and NIP discussion are welcome.

- Protocol specification: this document
- Reference implementation: [Fathom](https://github.com/decented/decented)
- NIP proposal: pending (kind numbers are placeholders)

---

## 15. Identity Management & Peer Verification

### 15.1 Profile Creation (BIP-39 / NIP-06)

Signet identities are derived from a 12-word BIP-39 mnemonic phrase. This is the industry standard used across Bitcoin and Nostr — the same 12 words can recover the identity on any compatible app.

**Creation flow:**

```
1. Generate 128 bits of cryptographic entropy
2. SHA-256 hash → take first 4 bits as checksum
3. 132 bits → 12 groups of 11 bits → 12 BIP-39 English words
4. PBKDF2-SHA512(mnemonic, "mnemonic" + passphrase, 2048 iterations) → 64-byte seed
5. BIP-32 HD derivation at path m/44'/1237'/0'/0/0 (NIP-06) → Nostr private key
6. Schnorr x-only public key derived from private key → Nostr identity
```

The 12 words **are** the identity. The user writes them down and stores them securely. An optional passphrase adds a second factor (the "25th word").

**Child accounts** can be derived at different account indices on the same HD path: `m/44'/1237'/{index}'/0/0`. A parent's mnemonic can deterministically generate keys for all their children's accounts, keeping the family's key management under one recovery phrase.

### 15.2 Shared Backup (Shamir's Secret Sharing)

Writing down 12 words creates a single point of failure. Shamir's Secret Sharing solves this by splitting the entropy into N shares where any M can reconstruct it.

**Scheme:** GF(256) polynomial interpolation (same field used by AES).

**Default:** 2-of-3 — keep one share, give two to trusted people. Any two of the three shares reconstruct the original entropy. No individual share reveals anything about the secret.

**Share encoding:** Each share is encoded as BIP-39 words (same wordlist, same format) so they look and feel familiar. A share holder sees 12 words that look like a normal mnemonic — but they are mathematically useless without a second share.

```
Original:  [12-word mnemonic] ← derives the Nostr private key
                │
        Shamir's 2-of-3 split
                │
    ┌───────────┼───────────┐
    │           │           │
Share 1     Share 2     Share 3
(12 words)  (12 words)  (12 words)
Keep this   Give to     Give to
yourself    friend A    friend B

Any 2 shares → reconstruct → original mnemonic → private key
```

**Parameters:**
- Threshold (M): minimum 2, configurable
- Shares (N): minimum M, maximum 255, configurable
- Practical recommendation: 2-of-3 for personal use, 3-of-5 for high-value keys

### 15.3 Peer Connections

When two Signet users meet in person, they establish a cryptographic connection by exchanging QR codes.

**Connection flow:**

```
Alice's phone                          Bob's phone
─────────────                          ──────────
1. Shows QR code containing:           1. Shows QR code containing:
   - Alice's public key                   - Bob's public key
   - Random nonce                         - Random nonce
   - Selected contact info                - Selected contact info
     (name, mobile, etc.)                   (name, mobile, etc.)

2. Scans Bob's QR                      2. Scans Alice's QR

3. Computes:                           3. Computes:
   ECDH(alice_priv, bob_pub)              ECDH(bob_priv, alice_pub)
        │                                      │
        └──── Same shared secret S ────────────┘

4. Stores:                             4. Stores:
   - Bob's pubkey                         - Alice's pubkey
   - Shared secret S                      - Shared secret S
   - Bob's shared info                    - Alice's shared info
   - What Alice shared                    - What Bob shared
```

**ECDH shared secret derivation:**
- Nostr public keys are x-only (32 bytes). Prepend `02` to assume even y-coordinate.
- Multiply the full point by the other party's private key scalar.
- SHA-256 hash the x-coordinate of the resulting point → 32-byte shared secret.
- The result is symmetric: `ECDH(A_priv, B_pub) === ECDH(B_priv, A_pub)`.

**Contact info selection:** During the QR exchange, each user selects what to share:
- Name
- Mobile number
- Email
- Home address
- Children's public keys (for families whose kids play together)

This data is stored **locally only** — never published to relays. The QR exchange happens entirely in person.

**Automatic vouch:** The connection optionally triggers a mutual in-person vouch (kind 30471), contributing to both users' Tier 2 web-of-trust and trust scores.

### 15.4 Signet Verification Words ("Signet Me")

The core peer-to-peer identity verification feature. Given a connection with a shared secret, both parties can independently compute the same 3 words at any time — proving they hold the keys that established the connection.

**The problem:** Your friend calls, panicked, asking you to send money to a new bank account. It sounds like him — social cues are right, he drops the kids' names. But is it really him?

**The solution:** "Signet me." Both users open each other's profiles. Both see the same 3 words. The caller reads them out. Match → it's really them.

**Algorithm:**

```
Inputs:
  S  = shared secret (32 bytes, from ECDH at connection time)
  t  = current Unix timestamp in milliseconds

Epoch:
  E = floor(t / 30000)           // words rotate every 30 seconds

Derivation:
  H = HMAC-SHA256(S, E.toString())   // 32-byte MAC

Word extraction (33 bits → 3 × 11-bit indices):
  word1 = ((H[0] << 3) | (H[1] >> 5)) & 0x7FF   // bits 0-10
  word2 = ((H[1] << 6) | (H[2] >> 2)) & 0x7FF   // bits 11-21
  word3 = ((H[2] << 9) | (H[3] << 1) | (H[4] >> 7)) & 0x7FF  // bits 22-32

Output:
  [BIP39_WORDLIST[word1], BIP39_WORDLIST[word2], BIP39_WORDLIST[word3]]
```

**Properties:**
- **Symmetric:** Both parties compute the same words from the same shared secret.
- **Rotating:** Words change every 30 seconds. Stale words cannot be replayed.
- **Tolerant:** Verification accepts current epoch ±1 (90-second window) to accommodate phone call lag.
- **Offline:** No server, no relay, no network needed. Pure local computation.
- **Strong:** 3 words from a 2048-word list = 2048³ ≈ 8.6 billion combinations. With a 30-second window, an attacker gets exactly one guess at 0.000000012% odds.

**Use cases:**

| Scenario | Flow |
|----------|------|
| **Friend asks for money** | "Signet me." Both open the app. Words match → send it. |
| **Bank calls about suspicious activity** | "Read me my signet." Agent checks your profile → reads the 3 words. |
| **You call the bank** | "What's my signet?" You verify they have access to the bank's private key. |
| **Family emergency contact** | Relative calls claiming to be with your child. "Signet me first." |
| **Business verification** | Supplier calls to change payment details. "Signet me before I update anything." |

**Display:**

```
┌──────────────────────────────────────┐
│  Bob's Profile                       │
│                                      │
│  My Signet:                          │
│                                      │
│     ocean · tiger · marble           │
│                                      │
│  ████████████░░░░  18s               │
│                                      │
│  Tap to verify words read to you     │
└──────────────────────────────────────┘
```

The progress bar shows time until the next word rotation. The user sees the words update in real time.

### 15.5 Security Considerations

**Key management:**
- The 12-word mnemonic must be stored offline (paper, metal backup). It is the master secret.
- The optional passphrase adds plausible deniability (different passphrase → different identity).
- Shamir shares should be distributed to people in different locations.

**Shared secrets:**
- ECDH shared secrets are derived from the connection and stored locally. They never leave the device.
- If a device is compromised, all shared secrets on that device are compromised. Users should re-establish connections from a new device.

**Signet words:**
- The 30-second epoch prevents replay beyond the tolerance window.
- An attacker who compromises one party's device gains their shared secrets and can generate words. This is equivalent to compromising their private key — the defence is device security, not protocol design.
- For high-value transactions, combine signet words with other verification (video call, previously agreed code phrase).

---

---

## 16. Identity Bridge

### 16.1 Overview

The identity bridge allows users to maintain separate anonymous and real-name accounts while cryptographically proving their anonymous account is backed by a verified identity. This is essential for privacy-respecting participation in communities that require trust.

**Example flow:**

1. Alice has a real-name account verified at Tier 3 by her solicitor.
2. Alice creates an anonymous account for participating in communities where she wants privacy.
3. Alice creates an identity bridge: her real account signs a ring signature (among 10 other verified accounts) proving "one of these 11 people also controls this anon account."
4. The bridge event (kind 30476) is published from Alice's anon account.
5. Community members see Alice's anon account has a trust score of ~19 (from the bridge alone), indicating a verified person is behind it.
6. When other bridged anonymous accounts vouch for Alice's anon account, trust compounds naturally.

### 16.2 Ring Construction

The ring must contain at least 5 verified pubkeys (the `MIN_BRIDGE_RING_SIZE` constant). The user's real pubkey is placed at a random position among decoys selected from the pool of verified accounts on the relay.

Decoy selection:
- Query the relay for pubkeys with kind 30470 credentials at or above the desired minimum tier.
- Exclude the user's real pubkey from the candidate pool.
- Randomly select `ringSize - 1` decoys.
- Insert the real pubkey at a random index.

### 16.3 nsec Import

Users may import existing Nostr accounts via nsec (NIP-19 bech32-encoded private keys). nsec-imported accounts:
- Have no mnemonic (cannot use Shamir backup).
- Can fully participate in the protocol (vouch, receive credentials, create bridges).
- Are clearly indicated in the UI as nsec-imported.

### 16.4 Multi-Account Management

A device may hold multiple accounts (real-name + anonymous, or multiple identities). Each account:
- Is identified by its pubkey (not a singleton key).
- Has its own connections, credentials, and trust score.
- Can be switched between in the app UI.

Connections are scoped to the owning account. Credentials and vouches are naturally scoped by pubkey in the Nostr protocol.

---

## 17. Entity Type Classification

### 17.1 Overview

The protocol classifies accounts along two orthogonal axes:

- **Verification tier** (1–4): How deeply an account is verified.
- **Entity type** (9 types): What kind of entity the account represents.

These axes are independent. A Natural Person could be Tier 3 or Tier 4. A Free Agent is always Tier 1. Entity type is determined by the cryptographic mechanism that links the account to the chain of trust.

### 17.2 Entity Types

The protocol defines nine entity types in three root categories.

**Root categories:**

| Protocol Term | Code | Description |
|---|---|---|
| Natural Person | `natural_person` | A living human, professionally verified (Tier 3+) |
| Juridical Person | `juridical_person` | A legal entity, verified by professional + multi-sig from Natural Persons |
| Free Agent | `free_agent` | An unverified account with no chain of trust (the default) |

**Alias subtypes (anonymous identities):**

| Protocol Term | Code | Description |
|---|---|---|
| Persona | `persona` | Anonymous alias of a Natural Person, linked via identity bridge (ring signature) |
| Juridical Persona | `juridical_persona` | Anonymous alias of a Juridical Person, linked via identity bridge |

**Agent subtypes (delegated bots):**

| Protocol Term | Code | Description |
|---|---|---|
| Personal Agent | `personal_agent` | Bot delegated by a Natural Person |
| Free Personal Agent | `free_personal_agent` | Bot delegated by a Persona |
| Organised Agent | `organised_agent` | Bot delegated by a Juridical Person |
| Free Organised Agent | `free_organised_agent` | Bot delegated by a Juridical Persona |

**Naming convention:** The protocol uses legal terminology (Natural Person, Juridical Person, Persona) for precision. Client applications SHOULD use friendly labels (Person, Organisation, Alias) in user interfaces. See §17.8 for the recommended label mapping.

### 17.3 Ownership and Delegation Tree

```
Natural Person ──► Personal Agent
  │
  └──► Persona ──► Free Personal Agent

Juridical Person ──► Organised Agent
  │
  └──► Juridical Persona ──► Free Organised Agent

Free Agent (standalone, no chain of trust)
```

Every account starts as a Free Agent. Entity type is earned through the appropriate verification mechanism.

### 17.4 Mechanism-Based Type Determination

Entity type is defined by the cryptographic linkage that connects an account to the chain of trust:

| Entity Type | Linkage Mechanism | Event Kind |
|---|---|---|
| Natural Person | Professional credential | 30470 (Tier 3/4) |
| Persona | Identity bridge (ring signature) from a Natural Person | 30476 |
| Personal Agent | Delegation event from a Natural Person | 30477 |
| Free Personal Agent | Delegation event from a Persona | 30477 |
| Juridical Person | Professional credential + multi-sig attestation | 30470 |
| Juridical Persona | Identity bridge (ring signature) from a Juridical Person | 30476 |
| Organised Agent | Delegation event from a Juridical Person | 30477 |
| Free Organised Agent | Delegation event from a Juridical Persona | 30477 |
| Free Agent | None | — |

### 17.5 Credential Tag

The existing credential event (kind 30470) gains a new tag:

```jsonc
["entity_type", "<type_code>"]
```

Where `<type_code>` is one of: `natural_person`, `persona`, `personal_agent`, `free_personal_agent`, `juridical_person`, `juridical_persona`, `organised_agent`, `free_organised_agent`, `free_agent`.

This tag is derived from the verification mechanism used but is included explicitly for relay and client queryability.

### 17.6 Agent Delegation Event (Kind 30477)

A replaceable event published by an account owner to delegate authority to an agent (bot).

```jsonc
{
  "kind": 30477,
  "pubkey": "<owner_pubkey>",
  "tags": [
    ["d", "<unique_delegation_id>"],
    ["p", "<agent_pubkey>"],              // the bot/agent being delegated
    ["entity_type", "<agent_type>"],      // personal_agent, free_personal_agent,
                                          // organised_agent, free_organised_agent
    ["expires", "<unix_timestamp>"],      // optional: delegation expiry
    ["L", "signet"],
    ["l", "delegation", "signet"]
  ],
  "content": ""
}
```

**Delegation constraints:**

- A Natural Person may delegate → `personal_agent`
- A Persona may delegate → `free_personal_agent`
- A Juridical Person may delegate → `organised_agent`
- A Juridical Persona may delegate → `free_organised_agent`

Any other owner→agent type combination is invalid and MUST be rejected by clients and relays.

**Revocation:** Delegations are revoked using the existing kind 30475 revocation event, with the `["d", "<agent_pubkey>"]` tag pointing to the agent being revoked.

### 17.7 Juridical Person Verification

A Juridical Person (organisation) requires dual verification:

1. **Professional verification:** A Tier 3+ professional verifies the organisation's legal registration documents (articles of incorporation, registration certificate, etc.) and issues a kind 30470 credential.
2. **Multi-sig attestation:** N-of-M verified Natural Persons co-sign a credential attesting they represent the organisation (e.g., 3 of 5 board members). Each co-signer must themselves be a verified Natural Person.

Both proofs must be present for an account to achieve Juridical Person status.

### 17.8 Application Label Mapping

Client applications SHOULD map protocol entity types to user-friendly labels:

| Protocol Term | Recommended App Label |
|---|---|
| Natural Person | Person |
| Persona | Alias |
| Personal Agent | Personal Agent |
| Free Personal Agent | Free Personal Agent |
| Juridical Person | Organisation |
| Juridical Persona | Org Alias |
| Organised Agent | Organised Agent |
| Free Organised Agent | Free Org Agent |
| Free Agent | Free Agent |

### 17.9 Dynamic Mode Signaling

A single account (particularly a physical device such as a humanoid robot or telepresence system) may switch between entity types depending on who or what is in control at a given moment. Events published by such accounts SHOULD include a mode tag:

```jsonc
["mode", "<mode>"]
```

Where `<mode>` is one of:

| Mode | Meaning |
|---|---|
| `teleoperated` | A verified person is in direct real-time control (entity acts as Persona) |
| `autonomous` | AI/software is acting on behalf of the owner (entity acts as Agent) |
| `assisted` | A verified person is in control with AI assistance (entity acts as Persona) |

**Example:** A paraplegic Natural Person controls a humanoid robot via a brain-computer interface. When the person is directly controlling the robot, it publishes events with `["mode", "teleoperated"]` and operates as a Persona. When the person steps away and onboard AI takes over, it publishes with `["mode", "autonomous"]` and operates as a Personal Agent. This allows others interacting with the robot to know whether they are communicating with the person or their AI.

This pattern applies to any remote-operated system: telepresence robots, drone operators, remote surgery rigs, VR avatars — any case where a verified person may or may not be in direct control at a given moment.

### 17.10 Relay Policy Extensions

Community verification policies (kind 30472) may include entity type requirements:

```jsonc
["allowed-entity-types", "natural_person,persona,juridical_person"]
```

Relays MAY filter events by entity type. For example, a child-safety relay might only accept events from Natural Persons and Personas (verified humans and their aliases), rejecting Free Agents and unverified bots.

### 17.11 Future Extension: Synthetic Person

The current taxonomy covers entities that are human, human-controlled, human-organised, or unverified. It does not cover fully autonomous beings (e.g., a sentient AI or truly independent robot) that act on their own behalf rather than on behalf of a human or organisation.

If such entities require their own legal or social standing, a new root category — **Synthetic Person** — may be added alongside Natural Person and Juridical Person, with its own alias and agent subtypes. The taxonomy is designed to accommodate this without breaking changes.

*This specification is a living document. It will evolve through community feedback and implementation experience.*
