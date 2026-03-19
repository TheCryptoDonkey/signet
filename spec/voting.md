# Signet Voting Extension

**Cryptographically Secure Elections for Nostr**

**Version:** 0.1.0 (Draft)
**Date:** 2026-03-04
**Status:** Draft specification — seeking community feedback
**Licence:** MIT
**Depends on:** [Signet Protocol Specification](protocol.md) v0.1.0+

---

## Abstract

This specification defines a voting extension for the Signet protocol. It enables cryptographically secure elections at organisational, community, and national scale, using linkable ring signatures for ballot secrecy and one-person-one-vote enforcement.

The extension depends on the Signet protocol for identity verification (credential tiers, entity types, Signet Score) and adds three new Nostr event kinds: Election Definition (30482), Ballot (30483), and Election Result (30484).

Ballot secrecy is achieved through linkable ring signatures — voters prove membership in an eligible set without revealing which member they are, while key images prevent double voting. Encrypted ballots ensure vote content remains secret until tallying.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Three Scales](#2-three-scales)
3. [Architecture](#3-architecture)
4. [Event Kinds](#4-event-kinds)
5. [Linkable Ring Signature Scheme](#5-linkable-ring-signature-scheme)
6. [Encrypted Ballots](#6-encrypted-ballots)
7. [Re-Voting Protocol](#7-re-voting-protocol)
8. [Use Cases](#8-use-cases)
9. [Global Legal Context](#9-global-legal-context)
10. [Security Considerations](#10-security-considerations)
11. [Future: National-Scale Elections](#11-future-national-scale-elections)

---

## 1. Motivation

Every voting fraud vector traces back to identity:

| Problem | Root Cause | Category |
|---|---|---|
| Impersonation fraud | Can't prove who you are | Identity |
| Multiple voting | Can't prove uniqueness | Identity |
| Ballot harvesting | Third parties submit ballots on behalf of voters | Chain of custody |
| Vote buying / bribery | Voter can prove how they voted to a buyer | Ballot secrecy |
| Coercion / undue influence | Voter can be forced to reveal or prove their vote | Ballot secrecy |
| Treating | Votes linkable to identity, enabling reward/punishment | Ballot secrecy |

The Signet protocol solves the identity problems (top rows) through its credential tier system and entity type classification. The ballot secrecy problems (bottom rows) require additional cryptography — specifically, a mechanism that proves "I am eligible to vote" without revealing "I am this specific person."

This extension provides that mechanism using linkable ring signatures and encrypted ballots.

---

## 2. Three Scales

Elections operate at different scales with different requirements:

| Scale | Stakeholders | Secrecy Needs | Coercion Risk | Complexity |
|---|---|---|---|---|
| **Organisational** | Board members, committees, DAO governance | Often non-secret or low stakes | Low | Simple |
| **Community** | Relay governance, meetups, party policy votes | Ballot secrecy needed | Moderate | Moderate |
| **National** | Citizens of a country | Full secrecy + coercion resistance | High | Very high |

**Pragmatic scope:** This specification covers organisational and community-scale elections. These are sufficient for most Nostr use cases and can be made robust with linkable ring signatures and re-voting. National-scale elections require additional mechanisms (see §11) and are a future goal, not a launch requirement.

### 2.1 Scale Requirements

**Organisational elections** require:
- Proof of membership (existing Signet credentials)
- One-member-one-vote enforcement
- Optional ballot secrecy (some organisational votes are open)
- Verifiable tally

**Community elections** require all of the above plus:
- Mandatory ballot secrecy
- Re-voting capability for coercion resistance
- Multiple tally authorities to prevent single-authority manipulation

**National elections** require all of the above plus:
- Full coercion resistance (fake credentials, deniable encryption)
- Threshold tally authorities with no single point of failure
- Legal framework integration (see §9)
- Accessibility for non-technical citizens

---

## 3. Architecture

### 3.1 Design Choice: Linkable Ring Signatures

This extension uses **linkable ring signatures** rather than blind signatures for ballot secrecy. The rationale:

| Property | Blind Signatures | Linkable Ring Signatures |
|---|---|---|
| Authority interaction | Voter must interact with signing authority | No authority interaction needed |
| Single point of failure | Signing authority can deny ballot tokens | No authority can deny participation |
| Anonymity model | Authority knows who requested a token (but not the vote) | No one learns who voted |
| Double-vote prevention | Authority tracks token issuance | Key images are deterministic per election |
| Alignment with Signet principles | Requires trusted authority | Fully decentralised |

Linkable ring signatures align with Signet's core principle of decentralisation (see protocol spec §18.3). No single entity can deny a voter's participation or learn who voted.

### 3.2 How It Works

1. **Eligibility** — An election definition specifies which entity types, credential tiers, and (optionally) community memberships are required. Eligibility is determined by existing Signet credentials — no new credential type is needed.

2. **Eligible set** — The set of public keys that hold qualifying credentials forms the ring. All eligible voters are members of this ring.

3. **Key images** — Each voter computes a deterministic key image for the election:

   ```
   I = x * H_p(P || election_id)
   ```

   Where `x` is the voter's private key, `P` is their public key, `H_p` is a hash-to-point function, and `election_id` uniquely identifies the election. The key image is the same every time this voter signs for this election, but different across elections. This prevents double voting without revealing the voter's identity.

4. **Encrypted ballots** — The voter encrypts their vote content to the tally authority's public key(s). The encrypted vote is included in the ballot event. No one can read the vote until the tally phase.

5. **Ring signature** — The voter produces a linkable ring signature over a commitment to the encrypted ballot (`electionId:SHA-256(encryptedVote)`), proving they are a member of the eligible set without revealing which member or how they voted. The signed message MUST NOT contain the plaintext vote.

6. **Submission** — The voter publishes the ballot as a kind 30483 event on Nostr relays.

7. **Re-voting** — If the election allows re-voting, a voter may submit a new ballot with the same key image. The latest ballot (by event timestamp) replaces all previous ballots with that key image.

8. **Tally** — After the election closes, tally authorities decrypt the ballots, deduplicate by key image (keeping the latest), count the votes, and publish the result as a kind 30484 event.

9. **Verification** — Anyone can verify: each ballot has a valid ring signature from the eligible set, each key image appears at most once in the final tally, and the published totals match the decrypted ballots.

---

## 4. Event Kinds

> **Note:** Kinds 30480-30481 are reserved for the Dominion Protocol (vault share, vault config).

### Kind 30482 — Election Definition

A replaceable event published by an election authority defining an election.

```jsonc
{
  "kind": 30482,
  "pubkey": "<election_authority_pubkey>",
  "tags": [
    ["d", "<election_id>"],
    ["title", "<election title>"],
    ["description", "<human-readable description>"],
    ["options", "<option_1>", "<option_2>", "..."],     // candidates or choices
    ["scale", "<organisational|community|national>"],
    ["eligible-entity-types", "<type1>,<type2>,..."],    // e.g. "natural_person,persona"
    ["eligible-min-tier", "<1-4>"],                      // minimum verification tier
    ["eligible-community", "<community_id>"],            // optional: restrict to community
    ["opens", "<unix_timestamp>"],
    ["closes", "<unix_timestamp>"],
    ["re-vote", "<allowed|denied>"],                     // re-voting policy
    ["tally-pubkeys", "<pubkey1>", "<pubkey2>", "..."],  // keys that can decrypt ballots
    ["tally-threshold", "<m>", "<n>"],                   // m-of-n threshold for decryption
    ["ring-size", "<minimum_ring_size>"],                 // minimum eligible set size
    ["algo", "secp256k1"],                                  // cryptographic algorithm
    ["L", "signet"],
    ["l", "election", "signet"]
  ],
  "content": "<optional: extended description, rules, or context>"
}
```

**Field requirements:**
- `election_id` MUST be unique across all elections by this authority
- `options` MUST contain at least 2 values
- `opens` MUST be a future Unix timestamp at time of publication
- `closes` MUST be after `opens`
- `tally-pubkeys` MUST contain at least one public key
- `tally-threshold` is OPTIONAL; defaults to all tally pubkeys required (n-of-n)
- `ring-size` is OPTIONAL; defaults to the full eligible set. Elections with fewer eligible voters than `ring-size` MUST NOT proceed
- `scale` MUST be one of: `organisational`, `community`, `national`

### Kind 30483 — Ballot

A replaceable event published by a voter. The voter's actual pubkey is NOT used — ballots are published from an ephemeral key to prevent linking.

```jsonc
{
  "kind": 30483,
  "pubkey": "<ephemeral_ballot_pubkey>",
  "tags": [
    ["d", "<election_id>:<random_16_bytes_hex>"],
    ["election", "<kind_30482_event_id>"],
    ["key-image", "<hex_encoded_key_image>"],
    ["ring-sig", "<hex_encoded_linkable_ring_signature>"],
    ["encrypted-vote", "<encrypted_vote_content>"],
    ["algo", "secp256k1"],                                  // cryptographic algorithm
    ["L", "signet"],
    ["l", "ballot", "signet"]
  ],
  "content": ""
}
```

**Field requirements:**
- `d` tag MUST be `<election_id>:<random_16_bytes_hex>` where the 16 bytes are generated fresh for each ballot submission. The random suffix prevents relays and observers from correlating ballot submissions via the `d` tag (which would expose re-voting patterns). Key image deduplication is performed at tally time using the `key-image` tag, not via relay-level replaceable event semantics.
- `election_id` MUST match a published kind 30482 election
- `key-image` MUST be deterministically derived as `I = x * H_p(P || election_id)` where `x` is the voter's private key and `P` is their public key in the eligible set
- `ring-sig` MUST be a valid linkable ring signature over the message `<election_id>:SHA-256(<encrypted-vote>)`, verifiable against the eligible set. The signed message MUST be a commitment to the ciphertext, never the plaintext vote — this ensures ballot secrecy even if the ring signature is inspected
- `encrypted-vote` MUST be the vote content encrypted to the tally authority pubkey(s) specified in the election definition
- `content` MUST be empty (vote content is in the encrypted tag)
- The ephemeral pubkey MUST NOT be reused across elections

**Validation rules:**
- Relays and clients MUST verify the ring signature before accepting
- If the key image matches a previously seen ballot for this election and re-voting is allowed, the new ballot replaces the old one
- If re-voting is denied and a matching key image exists, the ballot MUST be rejected

### Kind 30484 — Election Result

A replaceable event published after an election closes with the verified tally.

```jsonc
{
  "kind": 30484,
  "pubkey": "<tallier_pubkey>",
  "tags": [
    ["d", "<election_id>"],
    ["election", "<kind_30482_event_id>"],
    ["result", "<option_1>", "<count>"],
    ["result", "<option_2>", "<count>"],
    ["total-ballots", "<count>"],
    ["total-eligible", "<count>"],
    ["total-invalid", "<count>"],
    ["tally-proof", "<proof_data>"],
    ["algo", "secp256k1"],                                  // cryptographic algorithm
    ["L", "signet"],
    ["l", "election-result", "signet"]
  ],
  "content": "<optional: detailed breakdown, notes, or methodology>"
}
```

**Field requirements:**
- `tallier_pubkey` SHOULD be one of the `tally-pubkeys` from the election definition
- The sum of all `result` counts plus `total-invalid` MUST equal `total-ballots`
- `tally-proof` SHOULD contain sufficient data for independent verification (e.g., the decrypted ballots and their ring signatures)
- Anyone MAY publish a kind 30484 for any election — independent tallies increase confidence

---

## 5. Linkable Ring Signature Scheme

### 5.1 Overview

The linkable ring signature scheme extends the Spontaneous Anonymous Group (SAG) signature scheme already used in `src/ring-signature.ts` in the Signet reference implementation. Linkability is achieved through key images — deterministic values that are the same for a given signer in a given election, but reveal nothing about which ring member produced them.

### 5.2 Definitions

- **Ring** `R = {P_0, P_1, ..., P_{n-1}}`: the set of public keys of all eligible voters
- **Signer index** `s`: the position of the actual signer in the ring
- **Private key** `x_s`: the signer's private key, where `P_s = x_s * G`
- **Election ID** `e`: a unique identifier for the election
- **Hash-to-point** `H_p`: a function that maps arbitrary data to a point on secp256k1
- **Key image** `I = x_s * H_p(P_s || e)`: deterministic per signer per election

### 5.3 Signing

Given a message `m` (the commitment `<election_id>:SHA-256(<encrypted_vote>)` — never the plaintext vote), ring `R`, signer index `s`, private key `x_s`, and election ID `e`:

1. Compute key image: `I = x_s * H_p(P_s || e)`
2. Generate random scalar `α`
3. For each non-signer index i (wrapping from s+1 back to s), generate a random response r_i. Compute the challenge c_{i+1} sequentially from the hash chain: c_{i+1} = H(m || L_i || R_i).
4. Compute initial commitment: `L_s = α * G`, `R_s = α * H_p(P_s || e)`
5. For each `i` from `s+1` to `s-1` (wrapping):
   - `L_i = r_i * G + c_i * P_i`
   - `R_i = r_i * H_p(P_i || e) + c_i * I`
   - `c_{i+1} = H(m || L_i || R_i)`
6. Close the ring: `c_s = H(m || L_{s-1} || R_{s-1})`
7. Compute `r_s = α - c_s * x_s`
8. Output signature: `σ = (I, c_0, r_0, r_1, ..., r_{n-1})`

### 5.4 Verification

Given message `m`, ring `R`, election ID `e`, and signature `σ = (I, c_0, r_0, ..., r_{n-1})`:

1. For each `i` from `0` to `n-1`:
   - `L_i = r_i * G + c_i * P_i`
   - `R_i = r_i * H_p(P_i || e) + c_i * I`
   - `c_{i+1} = H(m || L_i || R_i)`
2. Verify: `c_n == c_0` (the ring closes)
3. Verify: `I` is a valid point on secp256k1

### 5.5 Linkability

Two signatures with the same key image `I` were produced by the same signer for the same election. This is because `I = x_s * H_p(P_s || e)` is deterministic — the signer cannot produce a different key image without using a different private key (which wouldn't be in the ring).

**Cross-election unlinkability:** Different election IDs produce different key images for the same signer, because `H_p(P_s || e_1) ≠ H_p(P_s || e_2)`. A voter's participation in one election cannot be linked to their participation in another.

---

## 6. Encrypted Ballots

### 6.1 Encryption

The voter encrypts their vote content to the tally authority's public key(s) before including it in the ballot event:

1. Voter selects their choice from the election's `options`
2. Vote content is serialised as a JSON string: `{"option": "<selected_option>"}`
3. Content is encrypted using ECDH with the tally authority's public key:
   - Generate ephemeral keypair `(k, K = k * G)`
   - Compute shared secret `S = k * T` where `T` is the tally authority's public key
   - Derive encryption key from `S` using HKDF
   - Encrypt vote content using AEAD cipher (AES-256-GCM recommended; available in Web Crypto API across all target runtimes)
   - Output: `K || nonce || ciphertext || tag`

### 6.2 Multi-Authority Threshold Decryption

When multiple tally authorities are specified with an m-of-n threshold:

1. Each authority holds a share of the decryption key (generated via Shamir's Secret Sharing or a DKG protocol)
2. After the election closes, at least `m` authorities must cooperate to decrypt each ballot
3. No single authority (or fewer than `m`) can decrypt any ballot
4. The decryption process produces the plaintext votes, which are then tallied

This prevents a single compromised or coerced authority from reading votes before the close, or from selectively revealing individual votes.

### 6.3 Post-Close Transparency

After decryption and tallying:
- All decrypted votes are published (without linking to specific voters)
- The ring signatures remain verifiable
- Anyone can independently verify that the tally matches the decrypted ballots
- The election result event (kind 30484) references the verification data

---

## 7. Re-Voting Protocol

### 7.1 Motivation

Re-voting is the primary coercion resistance mechanism for organisational and community-scale elections. If a voter is coerced ("vote X while I watch"), they comply, then later re-vote from a safe context. The coercer cannot determine whether the voter re-voted.

### 7.2 Mechanics

1. Election definition specifies `["re-vote", "allowed"]`
2. Voter submits initial ballot with key image `I` and timestamp `t_1`
3. Later, voter submits a new ballot with the same key image `I` and timestamp `t_2 > t_1`
4. At tally time, only the ballot with the latest timestamp for each key image is counted
5. The coercer sees the first ballot was published but cannot determine whether a replacement exists (all ballots are encrypted and signed with ephemeral keys)

### 7.3 Why Re-Voting Is Sufficient at Community Scale

At community scale, the coercer typically cannot:
- Monitor the voter's network traffic continuously
- Distinguish a re-vote from any other Nostr event
- Determine which ephemeral pubkey belongs to the voter

The coercer can see that a ballot was cast (they watched), but cannot see that it was replaced. This provides practical coercion resistance without the complexity of full JCJ coercion resistance.

### 7.4 Limitations

Re-voting does NOT protect against:
- A coercer who controls the voter's device or key material
- A coercer who can monitor all relay traffic and correlate timing
- State-level adversaries with mass surveillance capability

These threats require national-scale mechanisms (see §11).

---

## 8. Use Cases

### 8.1 Party Policy Votes

A political party (e.g., Restore Britain) wants members to vote on policy positions:

1. Party establishes itself as a Juridical Person (verified organisation) with Signet credentials
2. Members are verified Natural Persons who hold party membership credentials (kind 30999, `type: credential`)
3. Party leadership publishes a kind 30482 election: "Should the party support policy X?"
   - `eligible-entity-types`: `natural_person`
   - `eligible-min-tier`: `2` (web-of-trust verified)
   - `eligible-community`: `<party_community_id>`
   - `re-vote`: `allowed`
4. Each eligible member computes their key image and submits an encrypted ballot (kind 30483)
5. After close, tally authorities decrypt and count
6. Result published as kind 30484 — anyone can verify
7. If a member was coerced by party leadership, they re-vote privately — last ballot counts

### 8.2 Relay / Community Governance

A Nostr relay community votes on moderation policy:

1. Relay operator publishes community verification policy (kind 30078, NIP-78) requiring Tier 2+
2. Operator publishes a kind 30482 election for policy change
   - `scale`: `community`
   - `eligible-entity-types`: `natural_person,persona`
   - `eligible-min-tier`: `2`
   - `ring-size`: `20` (minimum anonymity set)
3. Community members vote via kind 30483
4. If fewer than 20 eligible members exist, election cannot proceed (ring too small for meaningful anonymity)

### 8.3 Organisational Board Votes

A company board votes on a resolution:

1. Board members hold Juridical Person delegation credentials
2. Chair publishes kind 30482 election
   - `scale`: `organisational`
   - `eligible-entity-types`: `natural_person`
   - `eligible-min-tier`: `3` (professionally verified)
   - `re-vote`: `denied` (board votes are typically final)
3. Board members vote; ring size equals the full board
4. Small ring size means limited anonymity — acceptable for organisational votes where participants are known but vote content should be private

### 8.4 Citizenship Verification for Voting Eligibility

Using civic identity from the Signet protocol spec (§19):

1. Government issues citizen credentials (kind 30999, `type: credential`) as described in protocol spec §19.2
2. Election authority publishes kind 30482 referencing citizenship credentials
   - `eligible-entity-types`: `natural_person`
   - `eligible-min-tier`: `3` (government-verified)
3. Citizens vote using their government-attested public keys as ring members
4. Ring signature proves "I am a verified citizen" without revealing which one
5. Key image prevents any citizen from voting twice

This use case requires the civic identity framework described in the core protocol spec §19 and appropriate legal frameworks (see §9).

---

## 9. Global Legal Context

### 9.1 Election Law Survey

Cryptographic voting must operate within existing legal frameworks. The following survey identifies key legal considerations by jurisdiction.

**Estonia — i-Voting:**
Estonia has operated internet voting since 2005. Key precedent: voters can re-vote during the advance voting period, with only the last vote counted. This establishes legal precedent for re-voting as a coercion resistance mechanism. The Estonian system uses a different cryptographic approach (server-side identity verification) but the re-voting principle maps directly to this specification's re-voting protocol.

**European Union — eIDAS:**
The EU's eIDAS regulation establishes a framework for electronic identification and trust services. eIDAS-compliant electronic identities could serve as the basis for voting eligibility credentials. Signet's credential tier system could map to eIDAS assurance levels: Tier 2 ≈ Substantial, Tier 3 ≈ High. The EU does not mandate a specific voting protocol, so member states could adopt Signet-based voting independently.

**United States — State-Level Variation:**
US election law varies by state. No federal standard exists for electronic voting. Some states permit electronic ballot delivery (for overseas/military voters under UOCAVA). Blockchain-based voting has been piloted in limited contexts (e.g., West Virginia, Utah County). Legal challenges focus on auditability, accessibility, and the Help America Vote Act (HAVA) requirements. Signet voting's verifiable tally and public auditability address several HAVA concerns.

**Switzerland — E-Voting Trials:**
Switzerland has conducted multiple e-voting trials, with mixed results. The Swiss Federal Chancellery requires individual verifiability (voters can verify their vote was recorded) and universal verifiability (anyone can verify the tally). Post Office's e-voting system was withdrawn in 2019 after security researchers found critical flaws. Swiss requirements align well with Signet's verifiable tally approach, but the Swiss experience underscores the importance of independent security audits.

**United Kingdom — Representation of the People Act 1983:**
UK election law defines specific offences relevant to coercion resistance:
- **Treating** (s.114): providing food, drink, or entertainment to influence votes
- **Undue influence** (s.115): using force, threats, or fraud to influence votes
- **Bribery** (s.113): giving money or procuring office to influence votes
- **Personation** (s.60): voting as another person

Signet voting addresses personation (ring signature proves eligibility), and re-voting provides practical defence against treating, undue influence, and bribery (the coerced vote can be replaced). The Ballot Secrecy Act 1872 and subsequent legislation require that votes cannot be traced to individual voters — ring signatures provide this mathematically.

**Ballot Secrecy Requirements:**
Most democratic jurisdictions require ballot secrecy as a fundamental principle. Requirements vary:
- Some require secrecy of the act of voting (who voted)
- All require secrecy of the vote content (how they voted)
- Some explicitly permit the voter to voluntarily disclose their own vote

Signet voting provides both forms of secrecy through ring signatures (who) and encrypted ballots (how), while allowing voluntary self-disclosure (a voter can reveal their own key image and vote content if they choose).

### 9.2 Mapping to Legal Frameworks

| Legal Requirement | Signet Voting Mechanism |
|---|---|
| Voter eligibility verification | Signet credential tiers + entity types |
| One-person-one-vote | Key images (deterministic, unique per voter per election) |
| Ballot secrecy | Ring signatures + encrypted ballots |
| Coercion resistance | Re-voting protocol (last vote counts) |
| Auditability / verifiable tally | Public ring signatures + published decrypted ballots |
| Accessibility | Client implementation concern (not protocol-level) |
| Independent oversight | Anyone can verify; multiple tally authorities |

---

## 10. Security Considerations

### 10.1 Sybil Attacks

**Threat:** An attacker creates multiple fake identities to cast multiple votes.

**Mitigation:** Signet's credential tier system. Elections that require Tier 2+ credentials require web-of-trust verification or professional attestation. Creating fake Tier 3 identities requires corrupting a licensed professional verifier — a real-world attack with legal consequences. The anti-corruption framework (protocol spec §7) provides detection and accountability mechanisms.

### 10.2 Key Image Collision Resistance

**Threat:** Two different voters produce the same key image, causing one ballot to overwrite the other.

**Mitigation:** Key images are points on secp256k1, derived via `I = x * H_p(P || e)`. Collision requires finding two distinct private keys that produce the same key image for a given election — equivalent to finding a collision in the hash-to-point function composed with scalar multiplication. This is computationally infeasible under standard cryptographic assumptions.

### 10.3 Encrypted Ballot Timing

**Threat:** An observer correlates the timing of ballot submission with voter activity to de-anonymise votes.

**Mitigation:** Voters SHOULD submit ballots at random times during the voting period, not immediately after the election opens. Clients SHOULD implement random delay. Additionally, the use of ephemeral pubkeys for ballot submission prevents linking a ballot to a voter's known Nostr identity.

### 10.4 Tally Authority Collusion

**Threat:** All tally authorities collude to decrypt ballots before the election closes, or selectively reveal individual votes.

**Mitigation:** Threshold decryption (m-of-n) ensures that fewer than `m` authorities cannot decrypt. The threshold should be set high enough that collusion is impractical. For community elections, a 3-of-5 threshold is recommended. Tally authorities SHOULD be from different organisations or jurisdictions.

### 10.5 Ring Size and Anonymity

**Threat:** Small ring sizes provide weak anonymity. In a ring of 5, each voter has a 20% chance of being the signer.

**Mitigation:** Elections SHOULD enforce a minimum ring size. The recommended minimums:
- Organisational: 5 (acceptable given participants are known)
- Community: 20
- National: 1000+

Elections with fewer eligible voters than the minimum ring size MUST NOT proceed, or MUST clearly disclose the reduced anonymity.

### 10.6 Quantum Threats

**Threat:** A quantum computer could break the discrete logarithm problem underlying secp256k1, allowing recovery of private keys from public keys and breaking ring signature anonymity.

**Mitigation:** This is a long-term threat shared with all secp256k1-based systems (including Nostr itself and Bitcoin). The Signet protocol spec §18.3 mandates a post-quantum migration path. When post-quantum ring signature schemes mature (e.g., lattice-based), the voting extension will migrate. In the interim, the practical risk is low — quantum computers capable of breaking secp256k1 do not yet exist.

### 10.7 Relay Censorship

**Threat:** A relay refuses to accept or relay ballot events, effectively disenfranchising voters.

**Mitigation:** Voters can submit ballots to multiple relays. Election definitions SHOULD specify multiple recommended relays across different jurisdictions. The Nostr protocol's relay diversity is a natural defence.

---

## 11. Future: National-Scale Elections

This section describes mechanisms that are NOT part of v0.1.0 but are planned for future versions to support national-scale elections with full coercion resistance.

### 11.1 JCJ Coercion Resistance

The Juels-Catalano-Jakobsson (JCJ) protocol provides full coercion resistance through:

- **Fake credentials:** Voters can generate fake voting credentials that are indistinguishable from real ones. Under coercion, the voter provides a fake credential. The coercer cannot tell whether the credential is real.
- **Credential validation at tally time:** Only real credentials produce valid votes. Fake credentials produce ballots that pass verification but are silently excluded during tallying.

This requires a more complex credential infrastructure than the current ring signature approach.

### 11.2 Deniable Encryption

A voter can encrypt their ballot such that, under coercion, they can produce a plausible decryption to a different vote. The real vote is only recoverable by the tally authority.

### 11.3 Scale Challenges

National-scale elections introduce challenges not present at community scale:

- **Ring size:** Millions of eligible voters. Ring signature computation scales with ring size. Efficient constructions (sub-linear proofs) are required.
- **Tally time:** Decrypting and verifying millions of ballots. Parallelisable tally protocols are needed.
- **Accessibility:** Non-technical citizens must be able to participate. Hardware security modules, polling station terminals, and mobile apps must all be supported.
- **Legal integration:** National elections are governed by detailed legislation. Protocol compliance must be formally verified.

### 11.4 Roadmap

1. **v0.1.0** (this specification): Organisational and community elections with linkable ring signatures and re-voting
2. **v0.2.0**: Improved ring signature efficiency for larger rings, multi-authority key generation protocols
3. **v1.0.0**: National-scale with JCJ coercion resistance, deniable encryption, formal security proofs

---

*This specification is an extension to the Signet protocol. It will evolve through community feedback and implementation experience.*