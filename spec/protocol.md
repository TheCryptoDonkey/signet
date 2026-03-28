# The Signet Protocol

**Decentralised Identity Verification for Nostr**

**Version:** 0.1.0 (Draft)
**Date:** 2026-03-02
**Status:** Draft specification — seeking community feedback
**Licence:** MIT

---

## Abstract

Signet is an open protocol for decentralised identity verification on Nostr. It enables users to prove claims about their identity — age, parenthood, professional status — using zero-knowledge proofs, without revealing personal data or relying on a central authority.

The protocol defines four verification tiers, nine entity types, a continuous Signet Score, a verifier accountability framework, and uses a single generic Verifiable Attestation kind (31000, NIP-VA Verifiable Attestations) for all identity attestations, plus NIP-78 (kind 30078) for policies. A separate voting extension uses kinds 30482-30484. Every professionally verified person receives two credentials — a Natural Person (real identity with Merkle-bound attributes and document nullifier) and a Persona (anonymous alias with age-range proof only). This two-credential model makes privacy a first-class design goal.

Any Nostr client can implement Signet. Any community can set verification policies. Any licensed professional can become a verifier.

**Child safety is the killer app. Social proof (blue checkmarks) drives adoption across all of Nostr.**

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Design Principles](#2-design-principles)
3. [Credential Tiers](#3-credential-tiers)
4. [Signet IQ](#4-signet-iq)
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
18. [Adversarial Resilience](#18-adversarial-resilience)
19. [Civic Identity](#19-civic-identity)
20. [Two-Credential Verification](#20-two-credential-verification)
21. [Credential Lifecycle](#21-credential-lifecycle)
22. [Child Online Safety](#22-child-online-safety)
23. [Inclusivity](#23-inclusivity)
24. [Jurisdiction Confidence](#24-jurisdiction-confidence)
25. [Implementation Levels](#25-implementation-levels)

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

## 4. Signet IQ (Identification Quotient)

On top of discrete tiers, a continuous Signet IQ (0-200) measures identity quality — the statistical confidence that an identity is real, not fabricated. It is not a reputation score. A high IQ means independent, verifiable sources confirm this entity exists. What the entity does with that identity is a separate concern.

A score of 100 represents the confidence level equivalent to a human checking a passport face-to-face — the standard that governments deem acceptable. Scores above 100 indicate that the identity is harder to fabricate than a government-issued passport, because more independent sources confirm it.

### Score Components

| Signal | Weight | Notes |
|--------|--------|-------|
| Professional verification (Tier 3/4) | Heavy | Single event, large impact |
| Identity bridge (kind 31000, `type: identity-bridge`) | Medium | Ring-sig proof linking anon account to verified identity, scaled by ring min tier |
| In-person peer signature | Strong | Met in person, signed keys face-to-face |
| Online vouch from verified user | Light | Accumulates — many light vouches add up |
| Account age | Passive | Time on the network adds weight gradually |
| Voucher's own Signet Score | Multiplier | A vouch from someone at IQ 150 carries more than from someone at IQ 40 |

### Score Algorithm

The exact algorithm is implementation-defined (clients can weight signals differently), but the protocol specifies the **signal types and their relative ordering**:

```
professional verification > identity bridge > in-person vouch > online vouch > account age
```

Clients MUST respect this ordering. A single professional verification always outweighs any number of online vouches. This prevents gaming through vouch farms.

### Display

```
┌───────────────────────────────────┐
│  Alice ✓✓               Tier 3   │
│  Signet IQ: 106                      │
│                                   │
│  ● Prof verified (lawyer)         │
│  ● 4 in-person vouches            │
│  ● 12 online vouches              │
│  ● Account age: 2 years           │
└───────────────────────────────────┘
```

- **Tier** = the gate (can you enter this space?)
- **Signet IQ** = the identity quality (how confident are we that this identity is real?)
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

- **Minimum Signet Score**: "Tier 2 AND iq > 100"
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

1. Publish a verifier attestation (kind 31000 with `type: verifier`) containing your professional licence information (bar number, medical licence number, notary commission ID)
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
4. Your vouches' weight scales with your own Signet Score

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

Every verifier attestation (kind 31000 with `type: verifier`) includes a licence number and jurisdiction. Any client can link directly to the relevant public register for users to verify:

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

- **Locked** when the verifier attestation (kind 31000 with `type: verifier`) is published
- **Slashed** (burned or redistributed to reporters) if the verifier is found fraudulent and revoked
- **Returned** if the verifier deactivates cleanly (retires, leaves the network)

Bond amount is configurable per community policy. A casual group might require 100,000 sats. A high-security community might require 1,000,000 sats. The bond makes corruption financially costly — a corrupt verifier doesn't just lose their reputation, they lose money.

Implementation: NWC (Nostr Wallet Connect) for bond locking. The bond mechanism is optional — communities that don't require it simply don't set a bond threshold in their policy (kind 30078).

### Layer 5 — Community Reporting and Revocation

Anyone can publish a **challenge attestation** (kind 31000 with `type: challenge`) against a verifier, presenting evidence of fraudulent behaviour.

Challenge flow:

```
Reporter ──── publishes kind 31000 (type: challenge) ────► challenge attestation
                                            │
                                        includes evidence
                                        (screenshots, registry status,
                                         anomaly data, testimony)
                                            │
              ◄──── community reviews ──────┘
                                            │
              If N trusted accounts (Tier 3+) confirm:
                │
                ├─ Verifier's kind 31000 verifier attestation is superseded
                │  by a revocation attestation (kind 31000, type: revocation)
                │
                ├─ Lightning bond is slashed
                │
                └─ All credentials issued by this verifier
                   are flagged in clients
```

The threshold for revocation (how many confirmations needed) is set per community policy. Default: 5 confirmations from Tier 3+ accounts.

### Layer 6 — Credential Provenance Trail

Every credential attestation (kind 31000 with `type: credential`) traces back to its issuer via the `pubkey` field. This is an immutable, public audit trail on Nostr relays.

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

Signet uses two Nostr event kinds for all identity attestations:

1. **Kind 31000** — Generic Verifiable Attestation (NIP-VA, NIP-VA Verifiable Attestations). All 7 identity attestation types share this kind, differentiated by the `type` tag.
2. **Kind 30078** — NIP-78 App-specific Data. Used for community verification policies.

Voting kinds (30482-30484) are documented in `spec/voting.md`.

### Attestation Event Structure

All attestation events use kind 31000 with the following common tags:

- `["type", "<attestation_type>"]` — one of: `credential`, `vouch`, `verifier`, `challenge`, `revocation`, `identity-bridge`, `delegation`
- `["d", "..."]` — d-tag format depends on the attestation pattern (see below)
- `["summary", "<human-readable description>"]` — brief description of the attestation
- `["algo", "secp256k1"]` — cryptographic algorithm
- `["L", "signet"]` — protocol namespace label

### Attestation Patterns

Each attestation type uses the NIP-VA pattern that matches its speech act:

- **Assertion-first (Tier 2-4 credentials):** The subject publishes a Tier 1 self-declaration. The verifier references it via `e` tag with `"assertion"` marker. d-tag: `assertion:<tier-1-event-id>`. The `type: credential` tag is included as a hybrid override for relay filtering and resilience.
- **Direct claim (vouches, challenges):** The attestor originates the claim. d-tag: `<type>:<subject-pubkey>`.
- **Self-attestation (Tier 1, verifier registration):** The publisher is also the subject. d-tag: `<type>:<own-pubkey>`.

### Attestation Type: Credential

Tier 1 is a self-declaration (direct claim, `pubkey` equals `p` tag):

```jsonc
{
  "kind": 31000,
  "pubkey": "<subject_pubkey>",
  "tags": [
    ["d", "credential:<subject_pubkey>"],  // direct claim (self-issued)
    ["p", "<subject_pubkey>"],
    ["type", "credential"],
    ["tier", "1"],
    ["verification-type", "self"],
    ["scope", "adult"],
    ["method", "self-declaration"],
    ["algo", "secp256k1"],
    ["L", "signet"]
  ],
  "content": ""
}
```

Tier 3 uses the assertion-first hybrid pattern, referencing the subject's Tier 1 self-declaration:

```jsonc
{
  "kind": 31000,
  "pubkey": "<verifier_pubkey>",
  "tags": [
    ["d", "assertion:<tier-1-event-id>"],  // assertion-first d-tag
    ["e", "<tier-1-event-id>", "wss://relay.example.com", "assertion"],  // references Tier 1
    ["type", "credential"],                // hybrid: explicit type for filtering
    ["p", "<subject_pubkey>"],
    ["tier", "3"],
    ["verification-type", "professional"],
    ["scope", "adult"],
    ["method", "in-person-id"],
    ["profession", "solicitor"],
    ["jurisdiction", "GB"],
    ["expiration", "<unix_timestamp>"],
    ["summary", "professional verification (tier 3) for abc123..."],
    ["algo", "secp256k1"],
    ["L", "signet"]
  ],
  "content": "<zkp_proof_blob>"
}
```

### Attestation Type: Vouch

A replaceable event published by a peer vouching for another user.

```jsonc
{
  "kind": 31000,
  "pubkey": "<voucher_pubkey>",
  "tags": [
    ["d", "vouch:<subject_pubkey>"],       // type-prefixed d-tag
    ["p", "<subject_pubkey>"],
    ["type", "vouch"],                     // attestation type
    ["method", "in-person"],               // "in-person" or "online"
    ["context", "bitcoin-meetup"],         // optional: where/how they met
    ["voucher-tier", "3"],                 // voucher's own tier at time of vouch
    ["voucher-score", "87"],               // voucher's own score at time of vouch
    ["summary", "in-person vouch for abc123..."],
    ["algo", "secp256k1"],                 // cryptographic algorithm (§9.5)
    ["L", "signet"],
    ["l", "vouch", "signet"]
  ],
  "content": ""                            // no personal data
}
```

### Community Verification Policy (NIP-78)

A NIP-78 app-specific data event published by a community operator defining minimum verification requirements. Uses kind 30078 with a `signet:policy:` d-tag prefix.

```jsonc
{
  "kind": 30078,
  "pubkey": "<community_operator_pubkey>",
  "tags": [
    ["d", "signet:policy:<community_identifier>"],
    ["adult-min-tier", "2"],
    ["child-min-tier", "3"],
    ["min-score", "50"],                   // optional minimum score
    ["mod-min-tier", "3"],                 // optional moderator requirement
    ["enforcement", "client"],             // "client", "relay", or "both"
    ["verifier-bond", "100000"],           // optional: min sats bond for verifiers
    ["revocation-threshold", "5"],         // optional: confirmations needed to revoke
    ["algo", "secp256k1"]                  // cryptographic algorithm (§9.5)
  ],
  "content": "<human-readable policy description>"
}
```

### Attestation Type: Verifier

A replaceable event published by a professional declaring their verifier status.

```jsonc
{
  "kind": 31000,
  "pubkey": "<verifier_pubkey>",
  "tags": [
    ["d", "verifier"],
    ["type", "verifier"],                  // attestation type
    ["profession", "solicitor"],
    ["jurisdiction", "UK"],
    ["licence", "<encrypted_or_hashed_licence_number>"],
    ["body", "Law Society of England and Wales"],
    ["summary", "solicitor verifier in UK"],
    ["algo", "secp256k1"],                 // cryptographic algorithm (§9.5)
    ["L", "signet"],
    ["l", "verifier", "signet"]
    // Cross-verification vouches from other professionals
    // are separate vouch attestation events pointing at this pubkey
  ],
  "content": "<optional: public statement about verification services>"
}
```

### Attestation Type: Challenge

An event published by anyone challenging a verifier's legitimacy. Triggers community review.

```jsonc
{
  "kind": 31000,
  "pubkey": "<reporter_pubkey>",
  "tags": [
    ["d", "challenge:<verifier_pubkey>"],   // type-prefixed d-tag
    ["p", "<verifier_pubkey>"],
    ["type", "challenge"],                 // attestation type
    ["reason", "anomalous-volume"],        // "anomalous-volume", "registry-mismatch",
                                           // "fraudulent-attestation", "licence-revoked",
                                           // "other"
    ["evidence-type", "registry-screenshot"], // type of evidence provided
    ["reporter-tier", "3"],                // reporter's own tier
    ["summary", "Challenge against verifier abc123... (anomalous-volume)"],
    ["algo", "secp256k1"],                 // cryptographic algorithm (§9.5)
    ["L", "signet"],
    ["l", "challenge", "signet"]
  ],
  "content": "<detailed evidence and explanation>"
}
```

### Attestation Type: Revocation

A replaceable event published when a community confirms a challenge.

```jsonc
{
  "kind": 31000,
  "pubkey": "<revoking_authority_pubkey>",  // community operator or threshold of Tier 3+ accounts
  "tags": [
    ["d", "revocation:<verifier_pubkey>"],  // type-prefixed d-tag
    ["p", "<verifier_pubkey>"],
    ["type", "revocation"],                // attestation type
    ["challenge", "<challenge_event_id>"], // the challenge that triggered this
    ["confirmations", "7"],                 // number of Tier 3+ accounts that confirmed
    ["bond-action", "slashed"],             // "slashed", "returned", "held"
    ["scope", "full"],                      // "full" = all credentials flagged,
                                            // "partial" = specific credentials flagged
    ["effective", "<unix_timestamp>"],      // when revocation takes effect
    ["summary", "Revocation of verifier abc123..."],
    ["algo", "secp256k1"],                 // cryptographic algorithm (§9.5)
    ["L", "signet"],
    ["l", "revocation", "signet"]
  ],
  "content": "<summary of findings>"
}
```

**Client behaviour on revocation:**

1. Display a warning on all credentials issued by the revoked verifier
2. Reduce the Signet Score contribution of those credentials to zero
3. Notify affected users that re-verification is recommended
4. Do not automatically invalidate credentials — the community policy decides whether to require re-verification or grandfather existing ones

### Attestation Type: Identity Bridge

A replaceable event published by an anonymous account to prove it is controlled by a verified identity, without revealing which one. Uses SAG ring signatures over secp256k1.

**Use case:** A user has a real-name account (verified at Tier 3 by a professional) and an anonymous account. The identity bridge lets the anonymous account prove "I am a real verified person" without revealing which verified person. This enables anonymous participation with trust.

```jsonc
{
  "kind": 31000,
  "pubkey": "<anon_pubkey>",              // the anonymous account publishing this
  "tags": [
    ["d", "identity-bridge"],
    ["type", "identity-bridge"],           // attestation type
    ["ring-min-tier", "3"],                // minimum verification tier of ring members
    ["ring-size", "10"],                   // number of pubkeys in the ring
    ["algo", "secp256k1"],               // cryptographic algorithm (§9.5)
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

**Signet Score contribution:**

- Base weight: 50 points (between professional verification and in-person vouch).
- Scaled by ring minimum tier: `weight = 50 × (ringMinTier / 4)`.
- Tier 3 ring → 37.5 points. Tier 4 ring → 50 points.
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
│   Verifier signs kind 31000 credential attestation with their Nostr key.
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
└─ Signet Score computation
    Pure client-side math. Count vouches, weight by voucher score.
    No crypto needed.

Layer 2: Pedersen range proofs — targeted addition (for Tier 4 age proofs)
│
└─ Age range proofs
    "This child is in age range [8, 12]" without revealing exact age.
    Pedersen commitment + Pedersen range proof range proof on secp256k1.
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
| **Tier 4** (professional, adult+child) | Ring sig + age range proof | Ring sig + Pedersen range proofs library |
| **Blue checkmark / score** | Read existing events, compute score | None |

### The Credential Signing Decision

Verifiers sign credentials with their **Nostr key** (secp256k1 Schnorr). No second keypair required.

| Approach | Pro | Con | Decision |
|----------|-----|-----|----------|
| **Nostr key only** | One identity, Nostr-native, no extra keys | Expensive to prove inside ZK circuits if needed later | **Use this.** |
| ZK-friendly curve (Baby Jubjub) | Cheap to prove in ZK circuits | Verifiers need a second keypair | Defer unless ZK circuit proofs become essential. |

Ring signatures handle issuer privacy without ZK circuits. Pedersen range proofs handle age range proofs without leaving secp256k1. The ZK-friendly signature question only arises if the protocol needs to prove "this Nostr key signed this credential" inside a zero-knowledge circuit — and the current design avoids that need.

### Reference Libraries

| Library | Purpose | Notes |
|---------|---------|-------|
| `@noble/secp256k1` | Core Schnorr sign/verify | Stable, audited, 4.94KB gzipped |
| `@noble/hashes` | SHA-256 for Merkle trees | Stable, audited |
| Ring signature lib (e.g. Nostringer) | SAG on Nostr pubkeys | Experimental — needs audit before production |
| MuSig2 lib | Multi-party signing | Functional, BIP-327 |
| Pedersen range proofs lib | Range proofs on secp256k1 | Needs audit before production |

### Quantum Readiness

Every Signet event carries an `["algo", "secp256k1"]` tag identifying the asymmetric cryptographic algorithm used for event signing and key agreement. This tag serves two purposes:

1. **Forward compatibility.** When post-quantum algorithms (e.g. ML-DSA, SLH-DSA, ML-KEM) are standardised for Nostr, new events will carry a different `algo` value. Parsers can distinguish pre- and post-quantum events without heuristics.
2. **Graceful migration.** During a transition period, clients can accept both `secp256k1` and post-quantum algorithm values, enabling a rolling upgrade across the network.

**Rules for the `algo` tag:**

| Rule | Detail |
|------|--------|
| **MUST be present** on all Signet attestation events (kind 31000) | Builders set it to `DEFAULT_CRYPTO_ALGORITHM` (`secp256k1`) |
| **Parsers MUST default** to `secp256k1` if absent | Ensures backward compatibility with legacy events created before this tag was introduced |
| **Value is a free-form string** | Allows future algorithms without a protocol revision — just publish events with the new value |
| **One algorithm per event** | An event is signed under a single algorithm; hybrid constructions would use two separate events |

**Current status:** All Signet events use secp256k1 (Schnorr signatures via BIP-340). No post-quantum migration is currently planned, but the tagging ensures the protocol is ready when one becomes necessary.

### Open Implementation Questions

1. **Ring signature audit.** Ring signatures are critical for Tier 3/4 issuer privacy. The SAG math is sound (used by Monero for years) but JS implementations need audit.
2. **Pedersen range proofs library choice.** Pure JS (slower, easier to audit) vs WASM (faster, harder to audit the C layer).
3. **Ring size.** How many professional verifiers form the anonymity set? Target: 20-50 verifiers per profession per jurisdiction.
4. **Credential expiry.** Verification credentials should expire (recommended: 1-2 years) and be renewable.
5. **Revocation propagation.** NIP-09 deletion requests are advisory only. The kind 31000 challenge/revocation attestation mechanism handles this at the protocol level.

---

## 10. Social Proof — The Blue Checkmark

The verification system is not limited to child safety. It is a general-purpose Nostr identity layer.

### For Users Who Won't Show Documents

They can still build trust through:

- Peer vouches from verified users
- In-person key signings at meetups and conferences
- Account age and consistent behaviour
- Online vouches from high-IQ accounts

This gives them a visible Signet IQ and a checkmark — weaker than professional verification, but more than nothing. And nothing is what everyone on Nostr has today.

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
| Signet IQ | Continuous identity quality (0–200) visible on drill-down |

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

### 15.1 Profile Creation (nsec-tree Identity Model)

Signet identities are derived using [nsec-tree](https://www.npmjs.com/package/nsec-tree), a hierarchical key derivation library for Nostr. A master secret is established from one of two sources, then child personas are derived deterministically from it.

**Establishing the master secret:**

Two entry points are supported:

1. **From a BIP-39 mnemonic** (`fromMnemonic()`): Generate a 12-word BIP-39 mnemonic (128 bits of entropy + 4-bit checksum, encoded as 12 English words). The mnemonic is converted to a 64-byte seed via PBKDF2-SHA512, then BIP-32 HD derivation at path `m/44'/1237'/727'/0'/0'` produces the master private key. The 12 words remain the human-readable backup for this flow.

2. **From an existing nsec** (`fromNsec()`): Users with an existing Nostr private key may import it as the master secret. An HMAC-SHA256 separation layer is applied so that the master material differs from the raw private key before any child keys are derived.

```
Option A (new identity):
  BIP-39 mnemonic (12 words)
    → PBKDF2-SHA512 seed
    → BIP-32 HD path m/44'/1237'/727'/0'/0'
    → master secret

Option B (existing nsec):
  nsec (NIP-19 bech32-encoded private key)
    → HMAC-SHA256 separation layer
    → master secret
```

**Required personas:**

Every Signet identity MUST derive two personas from the master secret:

| Persona | Purpose string | Role |
|---------|---------------|------|
| `natural-person` | `nostr:persona:natural-person` | Real-identity credentials; receives professionally verified attestations |
| `persona` | `nostr:persona:persona` | Anonymous alias; receives age-range-only credentials from the two-credential ceremony |

Clients MAY derive additional personas using the purpose pattern `nostr:persona:{name}` for application-specific contexts.

**Child derivation:**

Each persona is derived from the master secret using HMAC-SHA256 with the following construction:

```
HMAC-SHA256(
  key   = master_secret,
  data  = "nsec-tree\0" || purpose_string || "\0" || index_be32
)
```

Where `index_be32` is the derivation index encoded as a big-endian uint32. If the HMAC output is not a valid secp256k1 scalar (i.e. it is zero or ≥ the curve order), the index is incremented and the derivation is retried. The maximum index is `MAX_INDEX = 0xFFFFFFFF`.

The derived scalar becomes the child private key; the corresponding Schnorr x-only public key is the child's Nostr identity.

**Optional passphrase:** When deriving from a mnemonic, an optional passphrase adds a second factor (the "25th word") — a different passphrase produces an entirely different master secret and identity tree.

### 15.1a Linkage Proofs

Because all personas are derived from a single master secret, the master owner can prove cryptographic ownership of any child identity without revealing the derivation relationship to observers.

Two proof types are defined:

| Proof type | What it contains | Privacy |
|------------|-----------------|---------|
| **Blind proof** | BIP-340 Schnorr signature by the master key over the child pubkey | No derivation metadata — only proves master owns child |
| **Full proof** | Same Schnorr signature + purpose string + derivation index | Reveals the purpose and index to the verifying party |

**Construction:**

```
blind_proof:
  message = SHA-256("signet-linkage-v1\0" || child_pubkey_bytes)
  signature = schnorr_sign(master_private_key, message)
  proof = { masterPubkey, childPubkey, signature }

full_proof:
  message = SHA-256("signet-linkage-v1\0" || child_pubkey_bytes)
  signature = schnorr_sign(master_private_key, message)
  proof = { masterPubkey, childPubkey, purpose, index, signature }
```

**Where proofs are used:**

Linkage proofs are application-layer data. They are exchanged within bilateral flows — for example, inside the challenge (`["payload", ...]` tag of a kind 31000 challenge attestation) and response (kind 31000 revocation attestation) events of a challenge-response flow. They are **not** published as standalone Nostr events, ensuring privacy by default. A relying party who receives a proof can verify it locally without any relay interaction.

**Verification:**

Reconstruct the message from `child_pubkey_bytes`, then verify the Schnorr signature against `master_pubkey`. A valid signature proves the holder of the master private key authorised the child identity.

### 15.2 Shared Backup (Shamir's Secret Sharing)

Writing down a master secret (mnemonic or private key bytes) creates a single point of failure. Shamir's Secret Sharing solves this by splitting the master secret into N shares where any M can reconstruct it.

**Scheme:** GF(256) polynomial interpolation (same field used by AES).

**Default:** 2-of-3 — keep one share, give two to trusted people. Any two of the three shares reconstruct the original master secret. No individual share reveals anything about the secret.

**Share encoding:** Each share is encoded as BIP-39 words (same wordlist, same format) so they look and feel familiar. A share holder sees 12 words that look like a normal mnemonic — but they are mathematically useless without a second share.

**What is backed up:** The master secret — either the mnemonic entropy (for `fromMnemonic()` users) or the private key bytes (for `fromNsec()` users). The backup mechanism is identical in both cases; only the source material differs.

```
Option A (mnemonic user):
  [12-word mnemonic entropy] ← master secret
          │
  Shamir's 2-of-3 split
          │
┌─────────┼─────────┐
│         │         │
Share 1  Share 2  Share 3
Keep     Give to  Give to
this     friend A friend B

Any 2 shares → reconstruct → mnemonic entropy → master secret → all personas

Option B (nsec user):
  [private key bytes] ← master secret
          │
  Shamir's 2-of-3 split
          │
┌─────────┼─────────┐
│         │         │
Share 1  Share 2  Share 3

Any 2 shares → reconstruct → private key bytes → master secret → all personas
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

**Automatic vouch:** The connection optionally triggers a mutual in-person vouch attestation (kind 31000 with `type: vouch`), contributing to both users' Tier 2 web-of-trust and Signet Score.

### 15.4 Signet Verification Words ("Signet Me")

The core peer-to-peer identity verification feature. Given a connection with a shared secret, both parties can independently compute the same words at any time — proving they hold the keys that established the connection.

**The problem:** Your friend calls, panicked, asking you to send money to a new bank account. It sounds like him — social cues are right, he drops the kids' names. But is it really him?

**The solution:** "Signet me." Both users open each other's profiles. Both see the same words. The caller reads them out. Match → it's really them.

**Algorithm (powered by canary-kit):**

Signet delegates word derivation to the [CANARY protocol](https://www.npmjs.com/package/canary-kit) for protocol alignment. Canary handles real-time spoken verification; Signet handles identity and trust.

```
Inputs:
  S  = shared secret (32 bytes, from ECDH at connection time)
  t  = current Unix timestamp in milliseconds
  N  = word count (1-16, default: 3)
  I  = epoch interval in seconds (default: 30)
  T  = tolerance in epochs (default: 1)

Epoch:
  E = floor(t / (I × 1000))

Derivation (CANARY-DERIVE):
  H = HMAC-SHA256(S, utf8("signet:verify") || E_be32)   // 32-byte MAC

Word extraction (N × 16-bit indices from H):
  For i = 0 to N-1:
    index   = readUint16BE(H, i × 2) mod 2048
    word[i] = CANARY_WORDLIST[index]
```

**Wordlist:** The Canary spoken-clarity wordlist (2048 words, curated from BIP-39 with homophones and phonetic near-collisions removed). Optimised for verbal exchange.

**Defaults:** 3 words, 30-second epoch, ±1 tolerance. These are the recommended settings for in-person and phone verification. Implementations MAY allow configuration of all three parameters for different use cases.

**Configuration guidelines:**

| Use Case | Words | Epoch | Tolerance | Effective Window |
|----------|-------|-------|-----------|-----------------|
| In-person verification | 3 | 30s | ±1 | 90 seconds |
| Phone call | 3 | 30s | ±1 | 90 seconds |
| Quick in-room check | 1 | 30s | ±1 | 90 seconds |
| Async/text channel | 3 | 300s | ±1 | 15 minutes |
| High-security | 4 | 30s | 0 | 30 seconds |

**Entropy by word count:**

| Words | Entropy | Combinations |
|-------|---------|-------------|
| 1 | 11 bits | 2,048 |
| 2 | 22 bits | ~4 million |
| 3 | 33 bits | ~8.6 billion |
| 4 | 44 bits | ~17.6 trillion |

**Maximum word count:** 16 (32 bytes of HMAC output / 2 bytes per word index).

**Properties:**
- **Symmetric:** Both parties compute the same words from the same shared secret.
- **Rotating:** Words change every epoch. Stale words cannot be replayed.
- **Tolerant:** Verification accepts current epoch ±T (default: ±1, giving a 3× epoch window) to accommodate lag.
- **Offline:** No server, no relay, no network needed. Pure local computation.
- **Configurable:** Word count, epoch interval, and tolerance are adjustable for different security/usability trade-offs.
- **Consistent prefix:** The first N words are always the same regardless of the total word count requested. Asking for 4 words gives the same first 3 as asking for 3.
- **Protocol aligned:** Uses canary-kit's CANARY-DERIVE primitive and spoken-clarity wordlist, ensuring consistent vocabulary across Signet (identity establishment) and Canary (ongoing verification, duress signalling).

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
- The master secret (mnemonic entropy for `fromMnemonic()` users, private key bytes for `fromNsec()` users) must be stored offline (paper, metal backup). It is the root of the entire identity tree.
- The optional passphrase (mnemonic flow) adds plausible deniability — a different passphrase produces an entirely different master secret and identity tree.
- Shamir shares should be distributed to people in different locations.

**Shared secrets:**
- ECDH shared secrets are derived from the connection and stored locally. They never leave the device.
- If a device is compromised, all shared secrets on that device are compromised. Users should re-establish connections from a new device.

**Signet words:**
- The epoch interval prevents replay beyond the tolerance window.
- An attacker who compromises one party's device gains their shared secrets and can generate words. This is equivalent to compromising their private key — the defence is device security, not protocol design.
- For high-value transactions, use 4+ words with tight tolerance (0), and combine with other verification (video call, previously agreed code phrase).
- Using 1 word (1-in-2,048) is acceptable only for low-stakes, physical-proximity scenarios where the threat model is impersonation, not brute force.
- Both parties MUST agree on the same configuration (word count, epoch, tolerance) for verification to succeed. Mismatched config will always fail.

**nsec-tree derivation constraints:**
- `MAX_INDEX = 0xFFFFFFFF` — implementations MUST NOT attempt derivation beyond this index.
- **Curve-order skip:** if the HMAC-SHA256 output for a given index is not a valid secp256k1 scalar (i.e. zero, or ≥ the curve order `n`), increment the index by one and retry. This is equivalent to BIP-32 hardened child key derivation behaviour and avoids biased keys.
- **Memory cleanup:** implementations MUST call `zeroise()` on the `Uint8Array` `privateKey` and `publicKey` fields of `Identity` objects when they are no longer needed. `TreeRoot.destroy()` MUST be called to zeroise the root secret held in memory.
- **JS string limitation:** `nsec` and `npub` string fields on `Identity` objects cannot be wiped from memory — JavaScript string primitives are immutable and GC-managed. Only `Uint8Array` fields (`privateKey`, `publicKey`) can be actively zeroed. Implementations should avoid materialising `nsec`/`npub` strings unless required by the application layer.

---

---

## 16. Identity Bridge

### 16.1 Overview

The identity bridge allows users to maintain separate anonymous and real-name accounts while cryptographically proving their anonymous account is backed by a verified identity. This is essential for privacy-respecting participation in communities that require trust.

**Example flow:**

1. Alice has a real-name account verified at Tier 3 by her solicitor.
2. Alice creates an anonymous account for participating in communities where she wants privacy.
3. Alice creates an identity bridge: her real account signs a ring signature (among 10 other verified accounts) proving "one of these 11 people also controls this anon account."
4. The identity bridge attestation (kind 31000 with `type: identity-bridge`) is published from Alice's anon account.
5. Community members see Alice's anon account has a Signet Score of ~38 (from the bridge alone), indicating a verified person is behind it.
6. When other bridged anonymous accounts vouch for Alice's anon account, trust compounds naturally.

### 16.2 Ring Construction

The ring must contain at least 5 verified pubkeys (the `MIN_BRIDGE_RING_SIZE` constant). The user's real pubkey is placed at a random position among decoys selected from the pool of verified accounts on the relay.

Decoy selection:
- Query the relay for pubkeys with kind 31000 credential attestations at or above the desired minimum tier.
- Exclude the user's real pubkey from the candidate pool.
- Randomly select `ringSize - 1` decoys.
- Insert the real pubkey at a random index.

### 16.3 nsec Import

Users may import existing Nostr accounts via nsec (NIP-19 bech32-encoded private keys). When imported via `fromNsec()`, the private key bytes become the master secret after an HMAC-SHA256 separation layer is applied. nsec-imported accounts:
- Have no BIP-39 mnemonic, but CAN use Shamir backup (the private key bytes are the material that is split).
- Can fully participate in the protocol (vouch, receive credentials, create bridges).
- Can derive additional personas from the imported key as the master secret.
- Are clearly indicated in the UI as nsec-imported.

### 16.4 Multi-Account Management

A device may hold multiple accounts (real-name + anonymous, or multiple identities). Each account:
- Is identified by its pubkey (not a singleton key).
- Has its own connections, credentials, and Signet Score.
- Can be switched between in the app UI.

Connections are scoped to the owning account. Credentials and vouches are naturally scoped by pubkey in the Nostr protocol.

---

## 17. Entity Type Classification

### 17.1 Overview

The protocol classifies accounts along two orthogonal axes:

- **Verification tier** (1–4): How deeply an account is verified.
- **Entity type** (9 types): What kind of entity the account represents.

These axes are independent. A Natural Person could be Tier 3 or Tier 4. An Unlinked Agent is always Tier 1. Entity type is determined by the cryptographic mechanism that links the account to the chain of trust.

### 17.2 Entity Types

The protocol defines nine entity types in three root categories.

**Root categories:**

| Protocol Term | Code | Description |
|---|---|---|
| Natural Person | `natural_person` | A living human, professionally verified (Tier 3+) |
| Juridical Person | `juridical_person` | A legal entity, verified by professional + multi-sig from Natural Persons |
| Unlinked Agent | `unlinked_agent` | An unverified account with no chain of trust (the default) |

**Alias subtypes (anonymous identities):**

| Protocol Term | Code | Description |
|---|---|---|
| Persona | `persona` | Anonymous alias of a Natural Person, linked via identity bridge (ring signature) |
| Juridical Persona | `juridical_persona` | Anonymous alias of a Juridical Person, linked via identity bridge |

**Agent subtypes (delegated bots):**

| Protocol Term | Code | Description |
|---|---|---|
| Personal Agent | `personal_agent` | Bot delegated by a Natural Person |
| Unlinked Personal Agent | `unlinked_personal_agent` | Bot delegated by a Persona |
| Organised Agent | `organised_agent` | Bot delegated by a Juridical Person |
| Unlinked Organised Agent | `unlinked_organised_agent` | Bot delegated by a Juridical Persona |

**Naming convention:** The protocol uses legal terminology (Natural Person, Juridical Person, Persona) for precision. Client applications SHOULD use friendly labels (Person, Organisation, Alias) in user interfaces. See §17.8 for the recommended label mapping.

### 17.3 Ownership and Delegation Tree

```
Natural Person ──► Personal Agent
  │
  └──► Persona ──► Unlinked Personal Agent

Juridical Person ──► Organised Agent
  │
  └──► Juridical Persona ──► Unlinked Organised Agent

Unlinked Agent (standalone, no chain of trust)
```

Every account starts as an Unlinked Agent. Entity type is earned through the appropriate verification mechanism.

### 17.4 Mechanism-Based Type Determination

Entity type is defined by the cryptographic linkage that connects an account to the chain of trust:

| Entity Type | Linkage Mechanism | Event Kind |
|---|---|---|
| Natural Person | Professional credential | 31000 (`type: credential`, Tier 3/4) |
| Persona | Identity bridge (ring signature) from a Natural Person | 31000 (`type: identity-bridge`) |
| Personal Agent | Delegation event from a Natural Person | 31000 (`type: delegation`) |
| Unlinked Personal Agent | Delegation event from a Persona | 31000 (`type: delegation`) |
| Juridical Person | Professional credential + multi-sig attestation | 31000 (`type: credential`) |
| Juridical Persona | Identity bridge (ring signature) from a Juridical Person | 31000 (`type: identity-bridge`) |
| Organised Agent | Delegation event from a Juridical Person | 31000 (`type: delegation`) |
| Unlinked Organised Agent | Delegation event from a Juridical Persona | 31000 (`type: delegation`) |
| Unlinked Agent | None | — |

### 17.5 Credential Tag

The existing credential attestation (kind 31000) gains a new tag:

```jsonc
["entity-type", "<type_code>"]
```

Where `<type_code>` is one of: `natural_person`, `persona`, `personal_agent`, `unlinked_personal_agent`, `juridical_person`, `juridical_persona`, `organised_agent`, `unlinked_organised_agent`, `unlinked_agent`.

This tag is derived from the verification mechanism used but is included explicitly for relay and client queryability.

### 17.6 Agent Delegation Event (Kind 31000, `type: delegation`)

A replaceable event published by an account owner to delegate authority to an agent (bot).

```jsonc
{
  "kind": 31000,
  "pubkey": "<owner_pubkey>",
  "tags": [
    ["d", "<unique_delegation_id>"],
    ["type", "delegation"],               // attestation type
    ["p", "<agent_pubkey>"],              // the bot/agent being delegated
    ["entity-type", "<agent_type>"],      // personal_agent, unlinked_personal_agent,
                                          // organised_agent, unlinked_organised_agent
    ["agent-type", "<type>"],             // optional: "ai", "human", or "device"
    ["expires", "<unix_timestamp>"],      // optional: delegation expiry
    ["algo", "secp256k1"],               // cryptographic algorithm (§9.5)
    ["L", "signet"],
    ["l", "delegation", "signet"]
  ],
  "content": ""
}
```

**Delegation constraints:**

- A Natural Person may delegate → `personal_agent`
- A Persona may delegate → `unlinked_personal_agent`
- A Juridical Person may delegate → `organised_agent`
- A Juridical Persona may delegate → `unlinked_organised_agent`

Any other owner→agent type combination is invalid and MUST be rejected by clients and relays.

**Agent type tag (optional):**

The `["agent-type", "<type>"]` tag distinguishes what kind of agent is being delegated:

| Value | Meaning | Example |
|---|---|---|
| `ai` | An AI/software agent acting on behalf of the owner | Personal AI assistant, DVM operator, moderation bot |
| `human` | A human delegate (not an AI) | Guardian, employee, temporary access |
| `device` | A physical device (robot, IoT, telepresence) | Humanoid robot, smart lock, drone |

If omitted, clients SHOULD assume `human` for backwards compatibility. The tag is informational — it helps clients display appropriate trust context (e.g., "This is an AI agent operated by a verified person" vs "This is a human delegate").

**Revocation:** Delegations are revoked using a kind 31000 revocation attestation (with `type: revocation`), with the `["d", "<agent_pubkey>"]` tag pointing to the agent being revoked.

### 17.7 Juridical Person Verification

A Juridical Person (organisation) requires dual verification:

1. **Professional verification:** A Tier 3+ professional verifies the organisation's legal registration documents (articles of incorporation, registration certificate, etc.) and issues a credential attestation (kind 31000 with `type: credential`).
2. **Multi-sig attestation:** N-of-M verified Natural Persons co-sign a credential attesting they represent the organisation (e.g., 3 of 5 board members). Each co-signer must themselves be a verified Natural Person.

Both proofs must be present for an account to achieve Juridical Person status.

#### 17.7.1 Domain Proof via `.well-known/signet.json`

An institution MAY publish its Signet identity and staff roster via `https://<domain>/.well-known/signet.json`. This extends the schema defined in §27.1 (Cold-Call Verification) with fields for entity type, registry cross-referencing, and staff pubkeys.

```json
{
  "version": 2,
  "name": "Baker & Co Solicitors",
  "entity": "juridical_person",
  "registry": {
    "authority": "sra",
    "id": "654321",
    "url": "https://www.sra.org.uk/consumers/register/organisation/?sraNumber=654321"
  },
  "pubkeys": [
    {
      "id": "firm-key-2026",
      "pubkey": "<64-char hex secp256k1 x-only pubkey>",
      "label": "Firm Verification Key",
      "created": "2026-01-15T00:00:00Z"
    }
  ],
  "staff": [
    {
      "pubkey": "<64-char hex>",
      "name": "Jane Smith",
      "role": "solicitor",
      "registry": { "authority": "sra", "id": "123456" }
    },
    {
      "pubkey": "<64-char hex>",
      "name": "John Davies",
      "role": "solicitor",
      "registry": { "authority": "sra", "id": "789012" }
    }
  ],
  "relay": "wss://relay.example.com",
  "policy": {
    "rotation": "annual",
    "contact": "compliance@bakerco.co.uk"
  }
}
```

**Version 2 fields (all optional — version 1 documents remain valid):**

| Field | Type | Description |
|---|---|---|
| `entity` | string | Entity type code: `juridical_person` or `juridical_persona` |
| `registry` | object | Regulatory body and registration ID for the institution |
| `registry.authority` | string | Registry identifier: `sra`, `gmc`, `gdc`, `arb`, `ofsted`, `companies-house`, etc. |
| `registry.id` | string | The institution's registration ID on that registry |
| `registry.url` | string | Optional: direct URL to the institution's public registry entry |
| `staff` | array | Array of verified individuals at this institution |
| `staff[].pubkey` | string | 64-char hex secp256k1 x-only pubkey of the staff member |
| `staff[].name` | string | Display name (for human cross-referencing) |
| `staff[].role` | string | Role at the institution (e.g., `solicitor`, `gp`, `head-teacher`) |
| `staff[].registry` | object | Optional: the individual's own registry entry (e.g., their personal SRA ID) |

**Validation rules (extending §27.1 rules):**

- `version` MUST be `1` or `2`. Clients MUST accept version 1 documents (which lack `entity`, `registry`, `staff`).
- `entity`, if present, MUST be `juridical_person` or `juridical_persona`.
- `staff`, if present, MUST be an array with at most 500 entries.
- Each `staff[].pubkey` MUST be a 64-character lowercase hexadecimal string.
- `registry.authority` values SHOULD use the lowercase identifiers defined in the Signet registry authority table (see §17.7.4).
- The document MUST NOT exceed 102,400 bytes (100 KB) to accommodate large staff rosters.

#### 17.7.2 Juridical Person Onboarding Flow

The recommended onboarding flow for an institution (e.g., a law firm):

**Step 1: Create the institution's Signet identity.**

The managing partner (or designated compliance officer) generates a BIP-39 mnemonic for the institution. This mnemonic is the institution's master key. It SHOULD be:
- Generated on a secure device (hardware wallet or air-gapped machine)
- Backed up via Shamir Secret Sharing (e.g., 2-of-3 split across partners) using `@forgesworn/shamir-words`
- Never stored on a general-purpose computer or cloud service

The mnemonic derives the institution's `juridical_person` identity via `createSignetIdentity()`.

**Step 2: Professional verification of the institution.**

A Tier 3+ verified professional (who is NOT an employee of the institution) verifies:
- The institution's legal registration documents (e.g., Companies House certificate, SRA firm registration)
- That the persons claiming to represent the institution match their registry records

The professional issues a credential attestation (kind 31000, `type: credential`, `entity-type: juridical_person`) against the institution's pubkey.

**Step 3: Multi-sig attestation by directors/partners.**

N-of-M verified Natural Persons at the institution co-sign a credential attesting they represent the organisation. For example, for a law firm with 5 equity partners, a 3-of-5 attestation. Each co-signer must themselves be a verified Natural Person (Tier 3+).

**Step 4: Publish `.well-known/signet.json`.**

The institution publishes the domain proof file on its website. This anchors the institution's pubkey to its domain. For institutions on restricted domains (`.sch.uk`, `.nhs.uk`, `.ac.uk`, `.gov.uk`), the domain itself provides infrastructure-level anti-Sybil — the domain registrar has already verified the institution's legitimacy.

**Step 5: Staff verification.**

The institution (via its `juridical_person` identity) issues credentials to individual staff members. Each staff credential:
- Is issued by the institution's pubkey (not by the individual professional's own verification chain)
- Includes the `entity-type: natural_person` tag on the staff member's pubkey
- Includes a `["delegator", "<institution_pubkey>"]` tag linking the credential to the institution
- Can be cross-referenced against the staff member's individual registry entry (e.g., their personal SRA ID)

This means a solicitor at the firm has TWO credential paths:
1. **Via the institution:** SRA register → firm's domain → `.well-known/signet.json` → firm credential → individual
2. **Via personal verification:** Another verified professional vouches for them in person

Either path is valid. Both together are stronger.

**Step 6: Staff are listed in `.well-known/signet.json`.**

The institution adds each verified staff member's pubkey to the `staff` array. This creates a single machine-readable file that lists every verified person at the institution, cross-referenceable against the relevant professional register.

#### 17.7.3 Staff Verification by the Institution

When an institution issues a credential to a staff member, the credential event includes tags linking it to the institution:

```jsonc
{
  "kind": 31000,
  "pubkey": "<institution_pubkey>",
  "tags": [
    ["d", "<unique_credential_id>"],
    ["type", "credential"],
    ["p", "<staff_member_pubkey>"],
    ["entity-type", "natural_person"],
    ["delegator", "<institution_pubkey>"],
    ["delegator-entity", "juridical_person"],
    ["registry", "sra", "<staff_member_sra_id>"],
    ["algo", "secp256k1"],
    ["L", "signet"],
    ["l", "credential", "signet"]
  ],
  "content": ""
}
```

The `["registry", "<authority>", "<id>"]` tag enables automated cross-referencing. A verifying client can:

1. Find the credential issued by `<institution_pubkey>`
2. Fetch `https://<institution-domain>/.well-known/signet.json`
3. Confirm `<institution_pubkey>` matches a pubkey in the file
4. Confirm `<staff_member_pubkey>` appears in the `staff` array
5. Look up the `registry` tag value against the relevant professional register (e.g., SRA API)
6. Confirm the named person at the named registry ID works at the named firm

All six checks must pass for full verification. Steps 1–4 are automatable. Step 5 requires registry integration (API or web scrape). Step 6 is a human-readable cross-check.

#### 17.7.4 Registry Authority Identifiers

The protocol defines the following registry authority identifiers for use in `registry.authority` fields and `["registry"]` tags:

| Identifier | Registry | Country | Profession |
|---|---|---|---|
| `sra` | Solicitors Regulation Authority | UK | Solicitors |
| `bsb` | Bar Standards Board | UK | Barristers |
| `gmc` | General Medical Council | UK | Doctors/GPs |
| `gdc` | General Dental Council | UK | Dentists |
| `gphc` | General Pharmaceutical Council | UK | Pharmacists |
| `nmc` | Nursing and Midwifery Council | UK | Nurses, midwives |
| `goc` | General Optical Council | UK | Opticians, optometrists |
| `hcpc` | Health and Care Professions Council | UK | Physios, paramedics, psychologists, etc. |
| `swe` | Social Work England | UK (England) | Social workers |
| `arb` | Architects Registration Board | UK | Architects |
| `rcvs` | Royal College of Veterinary Surgeons | UK | Veterinarians |
| `icaew` | Institute of Chartered Accountants | UK | Chartered accountants |
| `acca` | Assoc. of Chartered Certified Accountants | UK | Chartered certified accountants |
| `rics` | Royal Institution of Chartered Surveyors | UK | Chartered surveyors |
| `engc` | Engineering Council | UK | Chartered engineers |
| `gtcs` | General Teaching Council for Scotland | UK (Scotland) | Teachers |
| `ofsted` | Office for Standards in Education | UK (England) | Schools, childminders, nurseries |
| `companies-house` | Companies House | UK | Companies, LLPs |
| `faculty-office` | Faculty Office of the Archbishop of Canterbury | UK | Notaries public |

This table is non-exhaustive. Implementations SHOULD accept any `registry.authority` value — unknown authorities are not invalid, merely unverifiable by that particular client. International registries may be added by any implementation.

### 17.8 Application Label Mapping

Client applications SHOULD map protocol entity types to user-friendly labels:

| Protocol Term | Recommended App Label |
|---|---|
| Natural Person | Person |
| Persona | Alias |
| Personal Agent | Personal Agent |
| Unlinked Personal Agent | Unlinked Personal Agent |
| Juridical Person | Organisation |
| Juridical Persona | Org Alias |
| Organised Agent | Organised Agent |
| Unlinked Organised Agent | Unlinked Org Agent |
| Unlinked Agent | Unlinked Agent |

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

Community verification policies (kind 30078) may include entity type requirements:

```jsonc
["allowed-entity-types", "natural_person,persona,juridical_person"]
```

Relays MAY filter events by entity type. For example, a child-safety relay might only accept events from Natural Persons and Personas (verified humans and their aliases), rejecting Unlinked Agents and unverified bots.

### 17.11 Future Extension: Synthetic Person

The current taxonomy covers entities that are human, human-controlled, human-organised, or unverified. It does not cover fully autonomous beings (e.g., a sentient AI or truly independent robot) that act on their own behalf rather than on behalf of a human or organisation.

If such entities require their own legal or social standing, a new root category — **Synthetic Person** — may be added alongside Natural Person and Juridical Person, with its own alias and agent subtypes. The taxonomy is designed to accommodate this without breaking changes.

---

## 18. Adversarial Resilience

### 18.1 Overview

Any identity protocol that achieves meaningful adoption will be evaluated — and potentially co-opted — by adversarial actors, including nation-states. A protocol that works only under cooperative assumptions is not a protocol; it is an invitation to abuse. Signet MUST be designed, evaluated, and maintained under adversarial assumptions, including the scenario where a government mandates Signet ID and then attempts to weaponise it.

This section defines the threat model, compares Signet's position to the current state and its trajectory, and establishes formal requirements that the protocol must satisfy.

### 18.2 Threat Scenarios

The following table compares ten adversarial scenarios across three contexts: the current state (2026), the trajectory if centralised digital identity continues unchecked, and the position with Signet.

| Scenario | Current State (2026) | Trajectory Without Decentralised Alternative | With Signet |
|---|---|---|---|
| **Identity revocation** | Multiple ID forms exist. Losing one doesn't kill identity. | Centralised digital ID (EU eIDAS, UK DIATF) creates single points of failure. One revocation = locked out. India's Aadhaar locks people out of food rations. | Multiple independent credential issuers. No single revocation kills identity. Government revokes their attestation, not identity itself. |
| **Anonymous participation** | Possible via cash, physical post, in-person. Diminishing with CCTV, card-only payments, phone tracking. | Cash elimination. Real-name platform verification (EU DSA, UK OSA). Anonymous speech criminalised or de-platformed. Trajectory: zero anonymity. | Ring signatures provide mathematical anonymity. Persona accounts unlinkable to Natural Person. Anonymous but verified participation is a protocol feature, not a loophole. |
| **Backdoored identity** | Government holds biometrics. Centralised databases. Citizen doesn't control infrastructure. | Mandatory government wallet apps. Closed-source, government-audited. Apple/Google as gatekeepers. Must use their app to have identity. | Open-source clients. Keys generated offline. Open spec anyone can implement. No mandated app. |
| **Retrospective de-anonymisation** | ISP logging (UK IPA). CCTV retained. Much activity still unrecorded. | AI retroactive analysis of CCTV, social media, location, payments. "Reconstruct your 2025" becomes routine. Facial recognition on stored footage. | Risk exists (quantum). Post-quantum crypto migration is plannable. Analogue world has NO defence against retrospective AI analysis. |
| **Mass surveillance** | GCHQ/NSA bulk collection. Smart city sensors. Mobile tracking. Mostly passive. | Real-time AI monitoring. IoT everywhere. China-model normalised as "public safety." Active, not passive. | Relay diversity across jurisdictions. Encrypted connections. Signet words work offline. Can't surveil what doesn't touch your infrastructure. |
| **Statistical de-anonymisation** | Browser fingerprinting, ad IDs, metadata analysis already de-anonymise routinely. | AI correlation attacks improve exponentially. Pseudonymity provides zero real protection. | Ring signatures stronger than pseudonymity — provable unlinkability. Larger rings = stronger guarantees. |
| **Social graph mapping** | Social media, phone contacts, email, payments reveal relationships. Government can request with warrants. | AI real-time social graph analysis. Cross-platform graph merging. No relationship private. | Persona-based connections unlinkable to Natural Person. Government key and social key cryptographically separated. |
| **Family structure exploitation** | Birth certs, school records, tax returns link families. Government knows family structure. | Centralised child identity systems. Family graphs cross-linked across all services. | ZKP proves "parent has child aged 8-12" without revealing which child, which school, any detail. |
| **Verifier coercion** | Government can pressure professionals via licensing. Professionals have some legal protections. | Professional independence eroded. Licensing bodies politicised. "Comply or lose licence" routine. | Multiple verifiers across jurisdictions and professions. No single jurisdiction's coercion captures entire verification chain. |
| **Election manipulation** | Paper ballots work reasonably for secrecy. Postal voting vulnerable. No crypto guarantees. | Digital voting without proper crypto. Centralised "trust us" counting. Convenience over security. | Linkable ring signatures for ballot secrecy. Re-voting for coercion resistance. Verifiable tallying anyone can audit. |

### 18.3 Defence Principles

Every defence follows the same meta-principle: **decentralisation prevents single-entity control.**

1. **Multiple credential issuers** — no single entity's revocation kills your identity
2. **Open-source clients** — no mandated app can be secretly backdoored
3. **Relay diversity** — no single jurisdiction controls the communication layer
4. **Large ring signatures** — statistical de-anonymisation requires infeasible computation
5. **Post-quantum migration path** — build crypto agility into the spec now
6. **Multiple election authorities** — no single signer controls ballot issuance
7. **Cross-jurisdiction verifiers** — professionals in different countries provide independent trust paths
8. **Voluntary credential presentation** — the protocol MUST NOT enable compulsory ID through the back door

### 18.4 Formal Adversarial Requirement

The protocol MUST ensure that no single entity — including a nation-state — can unilaterally:

- **Revoke a person's identity** — only their own attestation, not the keypair or credentials from other issuers
- **De-anonymise a Persona** — without possession of the private key
- **Coerce a vote** — without detection by the voter or audit trail
- **Surveil all activity** — relay diversity defeats centralised monitoring
- **Weaponise credentials as social credit** — multiple independent issuers prevent any single issuer from gatekeeping participation

These properties are non-negotiable. Any proposed protocol change that weakens any of these guarantees MUST be rejected unless it provides an equivalent or stronger guarantee through a different mechanism.

---

## 19. Civic Identity

### 19.1 Government as Verifier

Governments are simply another class of verifier in the Signet model. A government issues kind 31000 credential attestations to citizens, just as a professional verifier issues credentials to individuals. The critical difference from traditional national ID:

| Aspect | Traditional National ID | Signet ID |
|---|---|---|
| Who generates the identity | Government issues it | Citizen generates keypair |
| Who holds the master record | Government database | Citizen holds private key |
| What government stores | Name, DOB, address, photo, biometrics | Public key + attestation |
| Single point of failure | Government database breach = mass identity theft | No central database to breach |
| Revocation power | Government can cancel your identity | Government can revoke their attestation; your key still works with other verifiers |
| Surveillance capability | Full — they hold all your data | Limited — they hold a public key |

No new event kinds are required. Governments use kind 31000 for credential issuance (`type: credential`), revocation (`type: revocation`), and identity bridges (`type: identity-bridge`) where applicable, plus kind 30078 for policies.

### 19.2 Verification Flow

Citizen verification follows a six-step process using existing protocol mechanisms:

1. **Key generation** — Citizen generates a Nostr keypair using a 12-word BIP-39 mnemonic (via the nsec-tree `fromMnemonic()` derivation path)
2. **In-person appearance** — Citizen visits a government office (analogous to passport issuance)
3. **Document verification** — Government official verifies identity documents in person
4. **Credential issuance** — Government issues a credential attestation (kind 31000 with `type: credential`) to the citizen's pubkey: "This pubkey belongs to a verified citizen"
5. **Connection establishment** — Citizen and government official establish a verified connection (QR exchange, shared secret, or Signet words)
6. **Ongoing verification** — For future interactions, either party can verify the other using "Signet me" time-based word verification

### 19.3 Good Standing Credentials

A government may issue a "good standing" credential — a kind 31000 credential attestation (with `type: credential`) that indicates the citizen has no outstanding warrants or court orders requiring action.

**Revocation as warrant mechanism:**
- When a court issues a warrant, the good standing credential is revoked via a kind 31000 revocation attestation (with `type: revocation`)
- The citizen's ZKP can prove non-membership in the revocation set (i.e., "I am not on any warrant list")
- Ring signatures anonymise which specific credential is being proven
- The credential can be re-issued when the warrant is resolved

**Privacy guarantee:** The revocation set is public (as all kind 31000 revocation attestations are), but ring signatures prevent observers from linking a specific proof of good standing to a specific citizen.

### 19.4 Privacy-Preserving Police Interaction

**Current process:**
1. Police stop a person
2. Ask for name
3. Run name through Police National Computer / NCIC
4. Check for warrants
5. If clear, person goes — but name, location, and time are all logged

**Signet process:**
1. Police stop a person
2. Ask to verify status
3. Person's device presents a ZKP: "I hold a valid, non-revoked citizen credential"
4. Officer's device verifies the proof and checks revocation status
5. If clear, person goes — **no identity revealed**

The officer learns exactly one fact: this person holds a valid, non-revoked citizen credential.

**Critical constraint:** Presentation of a Signet credential MUST be voluntary. Refusal to present a credential MUST NOT be grounds for detention, search, or further action. Without this constraint, Signet becomes compulsory ID through the back door. This requirement MUST be enshrined in enabling legislation (see §19.6).

### 19.5 Separation of Official and Private Identity

Citizens maintain strict separation between their government-registered identity and their private life:

```
Citizen's registered pubkey (Natural Person)
  │  Used ONLY for government interactions:
  │  taxes, official correspondence, warrant checks
  │
  └──► Persona accounts (anonymous aliases)
       │  Used for private life:
       │  social media, communities, personal expression
       │  Ring signature proves "I am a real citizen"
       │  without revealing which one
       │
       └──► Unlinked Personal Agents
            Bots/services under anonymous identity
```

The government knows the citizen's registered pubkey. They cannot link it to any Persona account without breaking the ring signature — which is computationally infeasible. This separation is enforced by cryptography, not by policy.

### 19.6 Legal Framework Requirements

For civic identity to function as described, enabling legislation MUST ensure:

1. **Voluntary presentation** — no person may be compelled to present a Signet credential outside of contexts where identification is already legally required (e.g., border control, court proceedings)
2. **Refusal without consequence** — refusal to present a credential in a voluntary context must not be treated as grounds for suspicion, detention, or any adverse action
3. **Keypair sovereignty** — the citizen's private key is their property; government may not demand access to it
4. **Credential plurality** — citizens may hold credentials from multiple issuers; no single government credential may be made a prerequisite for participation in civil society
5. **Algorithmic audit** — any government systems that process Signet credentials must be subject to independent audit
6. **Sunset and review** — civic identity legislation must include mandatory review periods to assess whether the system is being used as intended

---

## 20. Two-Credential Verification

### 20.1 Design Principle

Anonymity is a first-class design goal, not an afterthought. Every person verified through Signet receives **two** credentials on **two** separate keypairs:

- **Keypair A (Natural Person):** Real identity — name, nationality, document hash, nullifier
- **Keypair B (Persona):** Anonymous identity — inherits only the age-range proof and guardian tags (if child)

The professional verifier sees both keypairs and issues both credentials in a single ceremony. The link between keypairs is known only to the subject and the verifier (protected by professional confidentiality — solicitor-client privilege, notary secrecy, medical confidentiality).

### 20.2 The Ceremony

The two-credential ceremony follows these steps:

1. Subject presents two Nostr pubkeys (keypair A and keypair B) to the verifier
2. Subject presents identity documents (passport, national ID, birth certificate)
3. Verifier examines documents and confirms identity of the person present
4. A Merkle tree is built from verified attributes (name, nationality, document type, DOB, nullifier)
5. Verifier computes nullifier using length-prefixed encoding (see §20.7)
6. Verifier generates Pedersen range proof age-range proof from date of birth
7. Verifier issues Natural Person credential (keypair A) with: entity-type, merkle-root, nullifier, age-range, guardian tags (if child)
8. Verifier issues Persona credential (keypair B) with: entity-type=persona, age-range (same proof), guardian tags (if child), NO nullifier, NO merkle-root

### 20.3 On-Chain vs Private Data

| Data | On-chain (public) | Private (Merkle leaf only) |
|------|-------------------|---------------------------|
| Entity type | Yes | — |
| Age range (e.g., "18+") | Yes (ZKP) | — |
| Merkle root | Yes (NP only) | — |
| Nullifier hash | Yes (NP only) | — |
| Guardian pubkey(s) | Yes (if child) | — |
| Full name | — | Yes |
| Nationality | — | Yes |
| Date of birth | — | Yes |
| Document type | — | Yes |
| Document number | — | Yes (Merkle leaf, for selective disclosure) |
| Document expiry | — | Yes (Merkle leaf, for consumer-side validity checks) |
| Photo hash | — | Yes (Merkle leaf, SHA-256 of verified photo) |

**Credential expiry vs document expiry:** The `expires` tag on the credential attestation (kind 31000 with `type: credential`) is the credential's validity period — when the credential itself stops being accepted. The `documentExpiry` Merkle leaf is the underlying document's expiry date — when the passport or licence expires. These are different: a credential might expire in 2 years but the passport doesn't expire for 10. Clients should check both.

### 20.4 Date of Birth and Age-Range Proofs

All tiers carry age-range proofs when issued by a professional:

- **Tier 1 (self-declared):** No age-range proof (self-declaration is not verification)
- **Tier 2 (peer-vouched):** No age-range proof (peers cannot verify DOB)
- **Tier 3 (professional, adult):** Age-range proof "18+" from verified DOB
- **Tier 4 (professional, adult+child):** Age-range proof with specific range (e.g., "8-12", "13-17")

Age ranges for children:

| Age | Range tag | Tier | Scope |
|-----|-----------|------|-------|
| 0-3 | `0-3` | 4 | adult+child |
| 4-7 | `4-7` | 4 | adult+child |
| 8-12 | `8-12` | 4 | adult+child |
| 13-17 | `13-17` | 4 | adult+child |
| 18+ | `18+` | 3 | adult |

The DOB is NEVER published on-chain. Only the zero-knowledge age-range proof appears. The Pedersen range proof proves "this person's age falls within [min, max]" without revealing the exact age or DOB.

### 20.5 Merkle-Bound Name Verification

The Natural Person credential includes a `merkle-root` tag. The Merkle tree contains verified attributes as leaves:

```
Merkle Root
├── H("dateOfBirth:1990-05-15")
├── H("documentExpiry:2030-05-15")
├── H("documentNumber:123456789")
├── H("documentType:passport")
├── H("name:Alice Smith")
├── H("nationality:GB")
├── H("nullifier:<hash>")
└── H("photoHash:<sha256>")
```

**Note:** The leaves shown above are an example. The leaf set is variable per credential — different document types may include different attributes. The tree construction (RFC 6962 domain separation) and proof format are identical regardless of the number of leaves.

Selective disclosure: The subject can reveal any attribute by providing the leaf value and its Merkle proof (sibling hashes). The verifier (or any party) can verify the proof against the published Merkle root without seeing the other attributes.

Use cases for selective disclosure:
- Prove name to a bank without revealing nationality
- Prove nationality for a community policy without revealing name
- Prove document type for a regulatory check without revealing anything else

### 20.6 Entity Type as Immutable Differentiator

The `entity-type` tag is set at credential issuance and cannot be changed without a new credential:

| Entity type | Display | Can hold nullifier? | Can hold merkle-root? |
|-------------|---------|--------------------|-----------------------|
| natural_person | Person | Yes | Yes |
| persona | Alias | No | No |

Clients MUST display the entity type. A Persona MUST NOT be displayed as a verified person. The entity type is the primary signal for "is this a real identity or an alias?"

### 20.7 Document-Based Nullifiers

Nullifiers prevent duplicate identity creation. The nullifier is computed using length-prefixed encoding to prevent field-boundary collisions:

```
nullifier = SHA-256(
  uint16be(len(document_type)) || document_type ||
  uint16be(len(country_code))  || country_code  ||
  uint16be(len(document_number)) || document_number ||
  uint16be(len(domain_tag))    || domain_tag
)

where domain_tag = "signet-nullifier-v2"
```

Each field is prefixed with its UTF-8 byte length as a 2-byte big-endian unsigned integer. This prevents ambiguity where field values containing delimiters could produce colliding nullifiers (e.g., docType="A||B" + country="C" must not collide with docType="A" + country="B||C").

Properties:
- **Deterministic:** Same document always produces the same nullifier
- **One-way:** Cannot recover document details from the nullifier
- **Collision-resistant:** Different documents produce different nullifiers; length-prefixed encoding prevents field-boundary ambiguity
- **Cross-verifier consistent:** Any verifier with the same document computes the same nullifier

When a verifier encounters a nullifier that already exists on a relay, this indicates either:
1. The same person is getting re-verified (legitimate — supersede the old credential)
2. Two different people presented the same document (fraud — flag for investigation)

### 20.8 Multi-Document Nullifier Families

When a subject presents multiple identity documents during a verification ceremony (e.g., passport AND driving licence AND national ID), the verifier SHOULD compute nullifiers for ALL documents, not just the primary. These form a **nullifier family** — a set of nullifiers that all belong to the same person.

```
nullifier_passport    = SHA-256(LP("passport") || LP("GB") || LP("123456789") || LP("signet-nullifier-v2"))
nullifier_licence     = SHA-256(LP("driving_licence") || LP("GB") || LP("SMITH901150J99XX") || LP("signet-nullifier-v2"))
nullifier_national_id = SHA-256(LP("national_id") || LP("GB") || LP("AB123456C") || LP("signet-nullifier-v2"))

where LP(s) = uint16be(len(s)) || s
```

The credential event includes:
- `["nullifier", "<primary_nullifier>"]` — the primary nullifier (backwards compatible)
- `["nullifier-family", "<nullifier>", "<document_type>"]` — one tag per document in the family

**Collision detection:** When checking for duplicates, clients and relays MUST check ALL nullifiers in the incoming family against ALL nullifiers (both `nullifier` and `nullifier-family` tags) in existing credentials. A collision with ANY nullifier in ANY family indicates the same person has been verified before.

This significantly strengthens duplicate prevention: a person cannot circumvent the system by presenting a different document to a different verifier, because both documents' nullifiers are recorded and cross-checked.

### 20.9 Nullifier Weaknesses and Mitigations

| Weakness | Mitigation |
|----------|------------|
| Document shared between family members | Nullifier collision detected; professional investigates |
| Document number guessable (sequential) | Hash includes document type + country; brute-force requires knowing all three components |
| Multiple documents (passport + national ID) | Multi-document nullifier families (§20.8) — each document produces a nullifier, all are cross-checked |
| Country changes document format | Domain tag version ("signet-nullifier-v2") allows migration to new formula |
| Verifier collusion (issue without real document) | Anti-corruption framework (§7) applies; nullifier without document is detectable via anomaly patterns |
| eIDAS wallet credentials | When available, the eIDAS unique person identifier can serve as an additional nullifier source for EU citizens (§20.10) |

### 20.10 eIDAS 2.0 Bridge (Future)

EU eIDAS 2.0 mandates unique person identifiers for ~450M EU citizens by December 2026. When a subject presents an eIDAS wallet credential during a Signet verification ceremony, the verifier MAY use the eIDAS unique person identifier as an additional nullifier source:

```
nullifier_eidas = SHA-256(LP("eidas") || LP(eidas_unique_id) || LP("signet-nullifier-v2"))

where LP(s) = uint16be(len(s)) || s
```

Note: The eIDAS nullifier uses only two data fields (type + identifier) since there is no country code or document number; the length-prefixed encoding ensures this cannot collide with document-based nullifiers which always have three data fields.

This provides a de facto perfect nullifier for EU citizens, as the eIDAS identifier is government-issued, unique, and machine-verifiable. The eIDAS nullifier is included in the nullifier family alongside document-based nullifiers.

### 20.11 Cross-Verification

When a subject presents the same document to a different verifier, the same nullifier is produced (because the nullifier is derived from the document details). The protocol distinguishes cross-verification from fraud by checking the subject's pubkey:

| Scenario | Nullifier | Subject pubkey | Interpretation |
|---|---|---|---|
| First verification | New | User's | New identity — record it |
| Cross-verification (same doc, new verifier) | Same | Same | Independent confirmation — higher IQ contribution |
| Document renewal (new number) | New | Same | New document — supersedes old credential |
| Document renewal (same number) | Same | Same | Re-verification — supersedes old credential |
| Fraud (someone else uses the document) | Same | Different | Duplicate detected — flag for investigation |

Cross-verification is the most valuable IQ signal because it represents independent professional confirmation of the same identity.

---

## 21. Credential Lifecycle

### 21.1 Credential Chains

When a credential needs updating (name change, document renewal, tier upgrade), a new credential is issued with a `["supersedes", "<old_event_id>"]` tag. The old credential receives a `["superseded-by", "<new_event_id>"]` tag.

```
Credential v1 (original)
  ├── superseded-by: <v2_id>
  └── [still on relay, but clients show as superseded]

Credential v2 (current)
  ├── supersedes: <v1_id>
  └── [active, displayed by clients]
```

Rules:
- Only a professional verifier can issue a superseding credential
- The superseding credential MUST reference the old credential's event ID
- Clients MUST follow the chain and display only the current (non-superseded) credential
- The chain is append-only — superseded credentials cannot be un-superseded

### 21.2 Name Changes

When a subject's legal name changes (marriage, divorce, deed poll, court order):

1. Subject presents new legal documents to a professional verifier
2. Verifier builds new Merkle tree with updated name
3. Verifier issues new Natural Person credential with `["supersedes", "<old_id>"]`
4. Persona credential is UNAFFECTED (it carries no name)

### 21.3 Titles and Qualifications

Professional titles (PhD, Dr., KC/QC, Prof.) are NOT name changes. They are separate credentials issued by awarding bodies or verified by professionals, linked to the same pubkey. The Natural Person credential reflects the legal name only.

### 21.4 Children

#### 21.4.1 Child Credential Requirements

Foundational rule: child credentials MUST be sub-accounts of a verified parent or guardian.

The ceremony requires:
- Parent/guardian with Tier 3+ Signet credential (mandatory)
- Child's birth certificate or passport (DOB mandatory)
- Professional verifies parental authority (birth certificate name match, court order if applicable)
- Professional generates Pedersen range proof age-range proof from DOB
- Issues Natural Person + Persona credentials, both with age-range proof and `["guardian", "<parent_pubkey>"]` tag
- Child's real name NEVER published — only in private Merkle leaves

#### 21.4.2 Guardian Link

The `["guardian", "<parent_pubkey>"]` tag is:
- Set by the professional verifier at issuance
- Immutable — cannot be changed without a new credential issued by a professional
- Multiple guardians supported (joint custody): multiple `["guardian", ...]` tags
- Present on BOTH Natural Person and Persona credentials

#### 21.4.3 Child to Adult Transition

When a child turns 18:
1. Subject visits a professional verifier with current identity documents
2. Verifier issues new Tier 3 credential with `["age-range", "18+"]` and `["supersedes", "<child_credential_id>"]`
3. New credential has NO guardian tag
4. Same keypair preserved — all history and connections maintained
5. Persona credential also superseded with updated age-range and no guardian tag

#### 21.4.4 Age-Appropriate Tiers

| Age range | Tier | Guardian required? | Typical capabilities |
|-----------|------|--------------------|---------------------|
| 0-7 | 4 | Yes (mandatory) | Guardian-managed account, no direct messaging |
| 8-12 | 4 | Yes (mandatory) | Limited messaging with guardian approval |
| 13-17 | 4 | Yes (mandatory) | More autonomy, guardian notification |
| 18+ | 3 | No | Full adult account |

#### 21.4.5 Family Structures

Three distinct layers handle the complexity of real families:

**Layer 1 — Credential level (immutable, set by professional):**
Guardian tags reflect legal parental responsibility. Only changeable via court order + new credential from a professional.

**Layer 2 — Delegation level (flexible, set by guardian):**
Guardians delegate specific permissions to step-parents, grandparents, teachers, or other trusted adults via kind 31000 delegation attestations (with `type: delegation`). Delegations are:
- Time-limited (expiry tag)
- Scope-limited: `full`, `activity-approval`, `content-management`, `contact-approval`
- Revocable by the guardian at any time

**Layer 3 — Client level (app-specific, enforced locally):**
Applications enforce permissions based on Layer 1 and Layer 2 data: screen time limits, content filtering, activity approval workflows, contact restrictions.

### 21.5 Document Renewal

When a document expires and is renewed (new passport number):
1. New nullifier computed from new document details
2. `["nullifier-chain", "<old_nullifier>"]` tag links old and new
3. New credential supersedes old
4. Continuity of identity maintained despite new document

### 21.6 Death, Key Compromise, Incapacitation

**Death:** A professional issues a kind 31000 revocation attestation (with `type: revocation`) with reason "death." All credentials for the pubkey are considered revoked.

**Key compromise:** Subject visits a professional with identity documents. Professional revokes all old credentials and issues new ones on a new keypair. Existing vouches are lost (deliberate security measure — prevents an attacker who compromised the key from retaining social trust).

**Incapacitation:** Court-appointed guardian added via guardian tag on a superseding credential, issued by a professional with the court order.

### 21.7 Nostr Early Adopter Migration

Existing Nostr users can integrate with Signet without losing their established identity:

**Path 1 — Sign existing keypair:**
The user's existing npub becomes their Natural Person identity. They visit a professional for verification. All followers, NIP-05, zaps, and reputation are preserved.

**Path 2 — Existing npub becomes Persona:**
The user creates a new keypair for their Natural Person identity and uses their existing npub as their Persona. An identity bridge attestation (kind 31000 with `type: identity-bridge`) links them with ring-signature privacy.

Both paths use existing mechanisms (NIP-05, identity bridges, credential chains). No automatic trust transfer between keypairs (prevents impersonation).

---

## 22. Child Online Safety

### 22.1 Grooming Prevention

The primary defence against grooming is the combination of age-range proofs and in-person professional verification:

1. **Unverified accounts cannot enter child spaces.** Communities require Tier 4 + age-range proof. An unverified account is rejected.
2. **Peer vouching cannot produce age-range proofs.** Only professionals who see the person and their documents can issue age-range proofs. A Tier 2 vouch carries no age verification.
3. **Professionals see the actual person.** AI can generate convincing documents, but a 40-year-old cannot present as a 14-year-old in person. Professionals verify documents daily as part of their existing practice.
4. **Guardian notifications.** When a child's account receives contact from an unknown adult, the guardian is notified. Contact requires guardian approval in strict mode.
5. **"Signet me" challenges.** Time-based word verification proves the current device holder matches the credential. Detects proxy use and reveals age gaps.

### 22.2 Age Bypass Prevention

Preventing children from accessing adult-only spaces:

1. **Adult spaces require Tier 3+ with "18+" age-range proof.** Self-declaration ("I am 18") is not sufficient.
2. **Nullifiers prevent second keypairs.** A child cannot create an additional keypair without age-range proof — the deterministic nullifier from their document will match their existing child credential.
3. **Persona credentials carry age-range.** The Persona issued during the two-credential ceremony MUST carry the same age-range proof as the Natural Person credential. A child's Persona is still identifiable as a child's Persona.
4. **Identity bridges inherit age-range.** Any identity bridge created from a child credential carries the source credential's age-range constraint.

### 22.3 Client Display Requirements

Clients implementing Signet MUST display:

| Element | Display |
|---------|---------|
| Unverified account | "Unverified" label, no trust indicators |
| Tier 4 child (0-12) | "Verified Child" + age range badge |
| Tier 4 teen (13-17) | "Verified Teen" + age range badge |
| Tier 3 adult (18+) | "Verified Adult" badge |
| Guardian link | "Guardian: [name/pubkey]" on child profiles |
| Age-gap contact | Warning to child + guardian notification |
| Missing age proof | "Age not verified" warning |

### 22.4 Guardian Controls

Guardian accounts (pubkeys listed in a child's guardian tags) have access to:

- **DM policy:** Block all / approve-only / notify / allow
- **Content filtering:** Strict / moderate / off
- **Contact restrictions:** Whitelist / blacklist / open with notifications
- **Meeting detection:** "Signet me" required for first real-world contact
- **Delegation:** Grant specific permissions to trusted adults (step-parent, grandparent, teacher)

These controls are enforced at the client level (Layer 3 of the family structure model, §21.4.5).

### 22.5 Community Policy Templates

Communities can adopt pre-defined safety policies:

| Template | Min tier | Age range | Guardian required? | DM policy |
|----------|----------|-----------|-------------------|-----------|
| Child-safe (under-13) | 4 | 0-12 | Yes | Guardian-approved only |
| Teen (13-17) | 4 | 13-17 | Yes (notify) | Open with logging |
| Adult-only (18+) | 3 | 18+ | No | Open |
| Mixed-age | 3 (adults) / 4 (children) | All | Per age group | Age-appropriate |

---

## 23. Inclusivity

### 23.1 Tier System as Safety Net

The four-tier system ensures that lack of documents does not mean exclusion:

- **Tier 1 (self-declared):** Anyone can create an account. No documents required. Zero barrier to entry.
- **Tier 2 (peer-vouched):** Real-world connections can vouch. No professional or document needed.
- **Tier 3 (professional, adult):** Requires documents and professional verification.
- **Tier 4 (professional, adult+child):** Requires documents, professional, and guardian.

Every person starts at Tier 1. The system provides *degrees of confidence*, not binary access.

### 23.2 Expanded Document Types

Professional verifiers can accept a range of identity documents beyond passports and national IDs:

- UNHCR refugee travel documents
- Stateless person travel documents (1954 Convention)
- Temporary residence permits
- Birth certificates (for children)
- Court-issued identity documents
- Religious community attestations (with professional co-signing)
- Employer attestations (for jurisdiction-specific contexts)

The verifier's professional judgement determines which documents are sufficient. The credential records the document type used, allowing communities to set their own acceptance thresholds.

### 23.3 The "Down and Out" Path

For people with no documents at all (homeless, displaced, stateless):

1. **Tier 1** — immediate access. Create a keypair, start participating.
2. **Tier 2** — community vouching. Local people who know the person can vouch.
3. **Support pathway** — NGOs, shelters, legal aid organisations can help obtain documents over time
4. **Tier 3** — when documents are eventually obtained, professional verification upgrades the credential

The system never requires documents as a prerequisite for basic participation. Documents unlock higher tiers, which unlock access to communities with stricter policies — but Tier 1 and Tier 2 are always available.

### 23.4 Degrees of Confidence, Not Binary Access

Communities choose their own verification thresholds. A community for casual conversation might accept Tier 1. A community for financial advice might require Tier 3. A community for children requires Tier 4.

This is not gatekeeping — it is informed choice. Each community publishes its policy (kind 30078). Users can see what is required before joining. No central authority decides who can participate where.

The goal is that every person, regardless of documentation status, has a path to meaningful participation — while communities retain the right to set appropriate safety standards for their members.

---

## 24. Jurisdiction Confidence

### 24.1 Overview

Not all jurisdictions provide equal assurance for professional verification. A credential issued by a verifier in a jurisdiction with strong professional regulation, public registries, and digital credential infrastructure carries more weight than one from a jurisdiction with weaker oversight.

### 24.2 Confidence Scoring

The jurisdiction confidence score (0-100) is computed from:

| Factor | Max Points | Description |
|--------|-----------|-------------|
| Corruption Perception Index | 20 | Transparency International CPI (updated annually, publicly available). Score = CPI / 5, capped at 20. A jurisdiction with CPI 90 (Denmark) scores 18. A jurisdiction with CPI 20 scores 4. |
| Professional body coverage | 15 | Number of regulated professions (1pt per body, capped at 15) |
| Public register availability | 15 | Proportion of bodies with queryable public registers |
| Digital credential issuance | 15 | Proportion of bodies issuing machine-verifiable credentials |
| Data protection maturity | 15 | Explicit consent, erasure rights, portability, breach notification, cross-border restrictions |
| Mutual recognition | 10 | Number of mutual recognition partners (1pt per partner, capped at 10) |
| E-signature recognition | 5 | Whether electronic signatures are legally recognised |
| Legal system compatibility | 5 | Common-law and civil-law score highest (well-established professional regulation) |

The CPI factor is the single most important signal. In jurisdictions where bribery is common, the confidence that a professional genuinely verified documents (rather than rubber-stamping for a fee) is lower. This is not discrimination — it is statistical confidence based on publicly available data.

### 24.3 Client Behaviour

Clients MAY use jurisdiction confidence scores to:
- Weight Signet Score contributions from different jurisdictions (a Tier 3 credential from a high-confidence jurisdiction contributes more to the Signet Score)
- Display jurisdiction confidence alongside credentials
- Set minimum jurisdiction confidence in community policies

Clients MUST NOT use jurisdiction confidence to deny Tier 1 or Tier 2 credentials, which are jurisdiction-independent.

### 24.4 Three Failure Modes

| Mode | Example | Solution |
|------|---------|----------|
| **Captured/corrupt bodies** | State-controlled professional bodies | Cross-jurisdiction verification: subject verified by professional in a free-body jurisdiction |
| **Nonexistent bodies** | No formal professional regulation | Embassy model: international NGOs and law firms with globally-licensed professionals serve as remote trust anchors |
| **Non-digital bodies** | Paper-based registries, no APIs | Manual registry cross-checks (weighted lower); eIDAS 2.0 mandates machine-readable interfaces by December 2026 |

For jurisdictions where Tier 3/4 is not achievable, Tier 1 + Tier 2 (self-declared + peer vouches) are always available. "Some trust" is infinitely better than "no trust."

### 24.5 Bribery as Self-Documenting Evidence

In jurisdictions with high corruption, bribery in document issuance is currently invisible — cash changes hands, fake documents appear, nobody knows. Signet inverts this: every credential is public, permanently traceable to a specific verifier, and subject to anomaly detection.

A corrupt official who rubber-stamps verifications creates a permanent, public audit trail:
- **Volume anomalies** — issuing 200 verifications/week when the norm is 5 (§7 Layer 3)
- **Geographic impossibilities** — verifying people in locations they couldn't plausibly reach
- **Nullifier collisions** — multiple people presenting the same document
- **Cross-verification failures** — credentials that don't survive independent confirmation by a second verifier

The corruption that was invisible becomes the evidence that catches itself. The more a corrupt official does it, the more obvious the pattern. This has the potential to reduce bribery in document issuance — not by preventing it, but by making it permanently traceable.

Cross-jurisdiction verification (§24.4) provides the escape valve: a person in a corrupt jurisdiction can get verified by a professional in a less corrupt one. The credential from the independent jurisdiction carries higher confidence, and the discrepancy (if any) between the two credentials surfaces the problem.

#### The game theory inversion

Currently, bribery is a Nash equilibrium in many developing countries — everyone does it because the cost of not doing it (waiting months, being denied) exceeds the cost of doing it (a small fee, no consequences). Signet breaks the equilibrium from both sides:

- **The corrupt official** carries every bribed verification as a permanent liability. One anomaly detection flag and their entire history unravels — taking down every credential they ever signed. Their career, their professional registration, and their reputation are on the line forever.
- **The person paying the bribe** has their entire identity infrastructure linked to that official. If the official falls, their credential's IQ contribution drops to near zero. Everything built on top — service access, family trust chains, children's verifications — crumbles. The bribe isn't a one-time transaction; it's a permanent bond to a ticking time bomb.

The honest route becomes the rational economic choice, even in a corrupt environment. A slow, honest credential lasts forever. A fast, corrupt credential is a house of cards. Both sides of the bribe are incentivised to go straight — not through enforcement, but through structural incentives. The system doesn't need to catch everyone — it just needs to shift the equilibrium.

#### Scale of the problem

The UN estimates $1 trillion is paid in bribes annually and $2.6 trillion stolen through corruption — roughly 5% of global GDP (~$5.75 trillion in 2025). Even reducing document-related bribery by a fraction of a percent moves billions. Anti-corruption as a structural byproduct of transparent identity verification, at zero additional cost.

Sources: [UN Secretary-General, Security Council (2018)](https://press.un.org/en/2018/sc13493.doc.htm), [World Economic Forum (2018)](https://www.weforum.org/stories/2018/12/the-global-economy-loses-3-6-trillion-to-corruption-each-year-says-u-n/), [World Bank](https://blogs.worldbank.org/en/governance/what-are-costs-corruption).

### 24.6 Document Type Registry

The Merkle tree leaf keys and the document type strings used in nullifier computation are defined by the **Signet Document Registry**, which is maintained separately from this specification.

The registry lists, per country:
- Available document types (passport, national ID, driving licence, etc.)
- Required and optional fields for each document type
- Which fields contribute to the nullifier computation
- Whether the document number changes on renewal
- Country-specific attributes (e.g., `gb:nationalInsurance`, `in:aadhaar`, `us:ssn`)

The registry is an open-source community resource hosted alongside the protocol. Adding a new country or document type is a registry update — it does not require a protocol revision. The protocol is document-agnostic by design: it defines the Merkle tree format and nullifier computation, not the contents.

---

## 25. Implementation Levels

### 25.1 Overview

Protocol complexity should not prevent partial adoption. Signet defines three progressive implementation levels so that client developers can integrate incrementally.

### 25.2 Level 1 — Read Trust Badges

**Effort:** A weekend. **Event kinds:** 31000 (`type: credential`), 31000 (`type: vouch`).

Read credentials and vouches for a pubkey, compute a basic trust tier and score, display a badge. No new cryptography beyond Schnorr signature verification (which Nostr clients already implement). This is the NIP-05 equivalent — minimal effort, immediate value.

The reference implementation provides `src/badge.ts` with `computeBadge()`, `buildBadgeFilters()`, and related helpers.

### 25.3 Level 2 — Issue Vouches

**Effort:** A few days. **Event kinds:** 31000 (credential, vouch), 30078 (policy).

Level 1 + users can vouch for each other (create kind 31000 vouch attestations) and communities can set policies (kind 30078). This is the viral layer — peer vouching creates Tier 2 network effects without requiring professional verifiers.

### 25.4 Level 3 — Full Protocol

**Effort:** Weeks to months. **Event kinds:** 31000 (all attestation types), 30078 (policy), 30482-30484 (voting).

All event kinds, full cryptographic stack: Merkle trees for selective disclosure, Pedersen range proofs for age range proofs, ring signatures for issuer privacy, two-credential ceremony, nullifier computation, guardian delegation, anomaly detection, and the voting extension.

### 25.5 Strategic Guidance

The recommended adoption path is:
1. Get Level 1 into 10+ Nostr clients (badges create visibility and demand)
2. Enable Level 2 for viral peer vouching
3. Level 3 for clients that want full verification capability

## 26. Security Considerations — Privacy Design Trade-offs

This section documents known privacy trade-offs in the Signet protocol design, the mitigations available to users and implementers, and the accepted trade-offs where transparency or continuity was deliberately chosen over maximum privacy.

### 26.1 Credential Chain Privacy

Credential chains (`supersedes`/`superseded-by` tags) create a publicly observable timeline of credential lifecycle events. An observer can follow the full history of a Natural Person's credential renewals, name changes, and tier upgrades through these links.

**Mitigation options for privacy-sensitive users:**
- Issue new credentials without `supersedes` tags, sacrificing continuity proof for privacy
- Use a fresh keypair when replacing credentials (requires re-establishing trust)
- Clients SHOULD warn users that supersedes chains are publicly visible

**Accepted trade-off:** Credential chains provide important auditability and credential lifecycle management. For most users, the transparency is a feature (proving continuous identity). Users who need stronger privacy should avoid credential chains.

### 26.2 Guardian Tag Privacy

Guardian delegation tags (`["guardian", "<parent_pubkey>"]`) on child Persona credentials publicly link the child's anonymous account to their parent's verified Natural Person identity. This reveals:
- That the account belongs to a child
- Which specific adult is their guardian
- The child's age range

**Mitigation (future):** Guardian tags on Persona credentials SHOULD reference the parent's Persona pubkey rather than their Natural Person pubkey. This preserves the guardian relationship while maintaining the parent's anonymity. Implementations MUST validate that the referenced guardian holds a valid credential regardless of which pubkey is used.

**Current status:** Implementations currently use the Natural Person pubkey for simplicity. A migration path will be defined in a future spec revision.

### 26.3 Ring Intersection Attacks on Identity Bridges

Identity bridge attestations (kind 31000 with `type: identity-bridge`) embed the full ring of public keys used for the ring signature. If a Persona issues multiple identity bridges over time with different randomly selected decoy members, an observer can intersect the ring sets to identify the common member — the actual signer.

With a ring of size `n` and `k` independent bridge events, the expected intersection size is approximately `1 + (n-1) * (1/pool_size)^(k-1)`, which rapidly approaches 1 (the signer) as `k` increases.

**Mitigations:**
- Identity bridges SHOULD be issued at most once per Persona. Re-issuance MUST reuse the same ring members
- Larger rings (50+ members) require more samples for intersection attacks to succeed
- Clients MUST NOT automatically refresh identity bridges — manual re-issuance only, with a warning about ring intersection risks
- Future: consider using zero-knowledge proofs of set membership instead of explicit rings

---

## 27. Cold-Call Verification

Cold-call verification solves a common trust problem: a customer receives a call claiming to be from their bank, law firm, or other institution. How can the customer verify the caller is genuine, without installing a new app, without sharing personal data, and without depending on a central authority?

Signet provides a mechanism for institutions to publish their verification pubkeys via `.well-known/signet.json`, and for both parties to independently derive the same spoken words from an ephemeral ECDH shared secret.

### 27.1 Institution Key Publication

Institutions publish a JSON document at `https://<domain>/.well-known/signet.json`:

```json
{
  "version": 1,
  "name": "Acme Legal LLP",
  "pubkeys": [
    {
      "id": "key-2026-01",
      "pubkey": "<64-char hex secp256k1 x-only pubkey>",
      "label": "Primary Verification Key",
      "created": "2026-01-01T00:00:00Z"
    }
  ],
  "relay": "wss://relay.example.com",
  "policy": {
    "rotation": "annual",
    "contact": "security@acmelegal.com"
  }
}
```

**Validation rules for clients fetching this document:**

- MUST use HTTPS — HTTP is rejected.
- Response body MUST NOT exceed 10,240 bytes (10 KB) for version 1 documents, or 102,400 bytes (100 KB) for version 2 documents (see §17.7.1 for the extended schema).
- `version` MUST be `1` or `2`. Version 2 documents may include `entity`, `registry`, and `staff` fields as defined in §17.7.1.
- `name` MUST be a non-empty string.
- `pubkeys` MUST be a non-empty array with at most 20 entries.
- Each `pubkey` value MUST be a 64-character lowercase hexadecimal string (x-only secp256k1).
- Clients MAY cache the response for up to 24 hours.

### 27.2 Session Code Format

To let the customer and institution find each other (e.g. when the customer initiates the check in an app and reads a code over the phone), a human-friendly session code is derived from the ephemeral pubkey:

```
NATOWORD-NNNN
```

Examples: `BRAVO-7742`, `NOVEMBER-0053`, `XRAY-1991`

Derivation:

1. Compute `hash = SHA-256(ephemeralPubkey_bytes)`.
2. `natoIndex = hash[0] mod 26` → select from the NATO phonetic alphabet.
3. `digits = ((hash[1] << 24) | (hash[2] << 16) | (hash[3] << 8) | hash[4]) mod 10000` → zero-padded to 4 digits.
4. Code = `NATO[natoIndex] + "-" + digits.padStart(4, "0")`.

The session code is a human-readable fingerprint of the ephemeral pubkey, not a secret. It allows the institution to look up the associated ephemeral pubkey from a relay (Phase 2 feature) without the customer needing to read out 64 hex characters.

**NATO phonetic alphabet (Signet uses the ICAO standard):**

`ALFA BRAVO CHARLIE DELTA ECHO FOXTROT GOLF HOTEL INDIA JULIET KILO LIMA MIKE NOVEMBER OSCAR PAPA QUEBEC ROMEO SIERRA TANGO UNIFORM VICTOR WHISKEY XRAY YANKEE ZULU`

### 27.3 Ephemeral ECDH Flow

The verification flow uses a one-time ECDH exchange to derive a shared secret that neither party possessed before the call:

**Customer side (initiate):**

1. Fetch `https://<institution-domain>/.well-known/signet.json` and select a pubkey.
2. Generate an ephemeral secp256k1 keypair `(ephPriv, ephPub)`.
3. Compute `sharedPoint = secp256k1.ECDH(ephPriv, institutionPubkey)`.
4. Derive `sharedSecret = SHA-256(x-coordinate of sharedPoint)` (32 bytes).
5. Derive words: `words = SPOKEN-DERIVE(sharedSecret, "signet:cold-call", currentEpoch, wordCount=3)`.
6. Generate `sessionCode = NATO-WORD + "-" + 4-digits` from ephemeral pubkey.
7. Display `words` on screen — the customer expects to hear these words from the caller.
8. Share `ephemeralPubkey` (or `sessionCode`) with the institution (read it out, or relay lookup).
9. Zero the ephemeral private key immediately after use.

**Institution side (complete):**

1. Receive the customer's `ephemeralPubkey` (via relay lookup by session code, or spoken by customer).
2. Compute `sharedPoint = secp256k1.ECDH(institutionPrivkey, ephemeralPubkey)`.
3. Derive `sharedSecret = SHA-256(x-coordinate of sharedPoint)`.
4. Derive `words = SPOKEN-DERIVE(sharedSecret, "signet:cold-call", currentEpoch, wordCount=3)`.
5. Read the words out to the customer.

If the words match, the caller holds the private key corresponding to a pubkey published in the institution's `.well-known/signet.json` at the time the customer fetched it.

### 27.4 Word Derivation Specification

Cold-call words use the same SPOKEN-DERIVE function as "Signet me" (§15), with a different context string for domain separation:

- **Algorithm:** `HMAC-SHA256(sharedSecret, utf8("signet:cold-call") || counter_be32)`
- **Context:** `"signet:cold-call"` (distinct from `"signet:verify"` used by "Signet me")
- **Counter:** `Math.floor(unixSeconds / 30)` — 30-second epoch, same as "Signet me"
- **Tolerance:** ±1 epoch (accounts for up to 30 seconds of clock skew between parties)
- **Default word count:** 3
- **Wordlist:** spoken-clarity wordlist (same as "Signet me")

The context separation ensures that cold-call words and peer-verification words are always different, even if the same shared secret were somehow reused.

### 27.5 Security Properties

**What cold-call verification provides:**

- **Institution authenticity:** The caller knows the institution's private key — they are who they claim to be (or the key has been compromised).
- **Freshness:** The ephemeral keypair is generated per-call. Replaying an old session code produces different words in the next epoch.
- **No data disclosure:** The customer's personal data is never transmitted. The ECDH produces a shared secret without either party revealing their private key.
- **No central authority:** Verification relies only on DNS (to reach the `.well-known` endpoint) and the HTTPS PKI.

**Limitations:**

- **DNS/TLS trust:** If the institution's domain is compromised, an attacker could substitute their own pubkeys in `.well-known/signet.json`. Clients SHOULD cache the pubkeys and warn if they change unexpectedly.
- **Key compromise:** If the institution's private key is leaked, an attacker can impersonate the institution. Institutions SHOULD rotate keys annually and support multiple simultaneous pubkeys for transition periods.
- **Epoch synchronisation:** Both parties must be within ±30 seconds. Network time attacks could desynchronise them, but ±1 epoch tolerance mitigates minor skew.
- **No relay integration yet (Phase 1):** In the current implementation, the customer must share the `ephemeralPubkey` or `sessionCode` verbally. Phase 2 will add relay-based session code resolution so the institution can look up the ephemeral pubkey automatically.

### 27.6 Phase 2: Relay-Based Session Code Resolution

*Not yet implemented. Described here for future implementers.*

The institution publishes a relay URL in `.well-known/signet.json` (`relay` field). The customer's app publishes the ephemeral pubkey to this relay, tagged with the session code. The institution's system subscribes and automatically retrieves the ephemeral pubkey without requiring the customer to read it out.

This eliminates the need for the customer to verbally communicate anything except confirming that the words match.

---

*This specification is a living document. It will evolve through community feedback and implementation experience.*
