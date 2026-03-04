# Verifier Bootstrapping & Trust Anchor Design

**Date:** 2026-03-04
**Status:** Draft — for review

## 1. The Problem

The Signet spec says professional bodies are trust anchors, but there is no mechanism binding a Nostr pubkey to a real professional. The current system has a fundamental vulnerability:

**Attack: Impersonation with public data**
1. Attacker looks up "Jane Smith, Solicitor, SRA #12345" on the public SRA register
2. Creates a Nostr account claiming to be Jane Smith with licence hash matching #12345
3. The licence hash proves nothing — anyone who knows the public licence number can compute it

**Attack: Sybil mesh**
1. Attacker creates N fake accounts across M professions (all using real licence numbers from public registries)
2. Fake accounts cross-verify each other, satisfying the 2-profession / 2-vouch activation requirement
3. Attacker now has "activated" verifiers that can issue Tier 3 credentials at scale
4. The entire anti-corruption framework (§7) is bypassed because the verifiers were never real

**Attack: Slow-burn infiltration**
1. Attacker creates one convincing fake professional, invests time building reputation
2. Attends events, meets real professionals, gets legitimate cross-verifications
3. Uses that one real-looking verifier to anchor a wider fraud chain

The root cause: **a licence hash is not a proof of licence possession.** Public registry data is public — using it as a credential is like using someone's address as their password.

## 2. Research Findings

### 2.1 How Existing Systems Solve This

**EU eIDAS 2.0 (QEAA model):**
Professional bodies are "authentic sources." Qualified Trust Service Providers (QTSPs) verify attributes against these authentic sources and issue cryptographically sealed attestations. The three-party model: authentic source --> trust service --> holder. eIDAS 2.0 *requires* authentic sources to provide machine-readable interfaces by December 2026.

**UK DIATF:**
Similar structure via Attribute Service Providers, but voluntary adoption. Currently focused on employment eligibility, not professional licensure.

**EV SSL Certificates:**
The most rigorous web-based organisational identity system. Multi-factor: legal existence + physical address + domain control + telephone callback to organisation's listed number. Human-in-the-loop verification. Time-limited validity with mandatory re-verification.

**Keybase.io (now defunct, but the proof system was excellent):**
- User signs a structured proof with their private key
- Posts the signed proof publicly on the external platform (tweet, GitHub gist, DNS TXT record, or `.well-known/keybase.txt` file on their website)
- Creates a corresponding entry in their public signature chain
- Anyone can verify: fetch sigchain, follow link to external platform, verify signatures match
- Merkle tree + Bitcoin anchoring prevented the server from presenting different views to different users

**Nostr NIP-05:**
Simple DNS-based identification: `alice@example.com` resolves via `https://example.com/.well-known/nostr.json`. Provides identification (human-readable name) but not verification (proof of identity). Trust derives entirely from trust in the domain. No cryptographic binding — the domain operator can reassign mappings at will.

**did:web / did:webs:**
`did:web:example.com` resolves to a DID Document at `https://example.com/.well-known/did.json`. Inherits all DNS security flaws. The improved `did:webs` variant adds a self-certifying identifier (cryptographic fingerprint in the DID itself), so even if the web server is compromised, a fake document won't verify.

### 2.2 Professional Registry API Availability

| Registry | Jurisdiction | API? | Cost |
|---|---|---|---|
| SRA (Solicitors Regulation Authority) | UK | **Yes — free REST API** | Free (account required) |
| GMC (General Medical Council) | UK | **Bulk download only** | GBP 815/year |
| NPPES (NPI Registry) | US healthcare | **Yes — free, open, no auth** | Free |
| State Bar Associations | US (50 states) | **No APIs** — web forms only | N/A |
| Nursys | US nursing | **Yes** | Via agreement |

**Key insight:** Registry API availability is patchy. Signet cannot rely on automated registry checks as a universal mechanism. But where APIs exist, they add a valuable signal.

### 2.3 Sybil Resistance Research

**PGP Web of Trust failures (instructive):**
- Network never grew beyond ~60,000 keys in the "strong set"
- Certificate flooding attack (2019) crashed GnuPG by attaching millions of bogus signatures
- Signature semantics were undefined (what does a signature actually mean?)
- No enforceable revocation
- Lesson: *precisely defined verification levels* and *spam resistance* are critical

**Academic Sybil detection (SybilGuard, SybilLimit, SybilInfer):**

Core insight: real social networks have a structural bottleneck between honest nodes and Sybil nodes. An attacker can create many fake identities but can only establish a *limited number of trust edges* with real users.

- SybilLimit achieves O(log n) accepted Sybils per attack edge — near-optimal
- All approaches assume "fast mixing" (random walks reach uniform distribution quickly)
- **Problem: many real social networks are NOT fast mixing.** Users form tightly-knit communities that trap random walks.

**Graph-theoretic Sybil indicators:**

| Property | Honest Network | Sybil Cluster |
|---|---|---|
| Cluster age spread | Accounts created over months/years | Accounts created within days |
| External corroboration | Multiple independent signals per node | Only internal vouches |
| Vouch reciprocity | Asymmetric — not everyone vouches for everyone | Often fully connected (everyone vouched for everyone) |
| Network reach | Many independent paths to trust anchors | Few paths, all through same attack edges |
| Degree distribution | Power-law / heavy-tailed | Often more uniform |

## 3. Analysis: Why No Single Fix Works

| Approach | Strengths | Fatal weakness if used alone |
|---|---|---|
| Professional body attestation | Gold standard, eliminates impersonation | Requires institutional adoption — may take years, government influence risk |
| Domain-based proof (website) | Available now, hard to fake | Websites can be hacked; not all professionals have websites |
| Registry API cross-check | Automated, objective | Most registries have no API; proves registry entry exists, not that *this pubkey* owns it |
| Cross-professional vouches | Existing mechanism, real-world cost | Sybil mesh defeats it entirely |
| Graph analysis / anomaly detection | Catches patterns humans miss | Reactive, not preventive; sophisticated attackers adapt |

**No single mechanism is sufficient. The defence must be layered.**

## 4. Proposed Design: Multi-Signal Verifier Authentication

### 4.1 Core Principle

Instead of binary verifier activation (activated/not), verifiers accumulate independent *authentication signals*. Each signal raises the cost of attack. Clients compute a *verifier confidence score* from these signals and display it alongside any credentials the verifier has issued.

### 4.2 The Five Signals

**Signal 1: Cross-Professional Vouches (existing)**
- 2+ vouches from 2+ different professions
- Keeps the current mechanism as one signal among several
- Alone insufficient (Sybil mesh), but contributes to the score

**Signal 2: Domain Proof (new — Keybase model)**
The professional publishes a cryptographic proof on their professional website.

File at `https://example-law.com/.well-known/signet.json`:
```json
{
  "pubkey": "<hex_nostr_pubkey>",
  "licence": "SRA/12345",
  "jurisdiction": "GB",
  "profession": "legal",
  "statement": "I am Jane Smith, solicitor at Smith & Partners. This is my Signet verifier identity.",
  "sig": "<nostr_schnorr_signature_of_above_fields>"
}
```

The `sig` field is a Schnorr signature by the claimed pubkey over the canonical JSON of the other fields. This creates a *bidirectional link*:
- The website points to the pubkey (domain --> identity)
- The signature proves the pubkey holder created the file (identity --> domain)
- The kind 30473 event includes a `["website-proof", "https://example-law.com"]` tag

**What this proves:** The person who controls the private key also controls this professional website. This is NOT proof of being a licensed professional, but it dramatically raises the attack cost from "look up a public licence number" to "hack a professional's website."

**Why websites are currently safe:** Professional firm websites (solicitor practices, medical clinics, accounting firms) are low-value targets for hackers. Their value as phishing targets is marginal compared to banks or crypto exchanges. As Signet grows and these websites become higher-value targets, professional body attestation (Signal 4) should have caught up as the primary trust anchor.

**Signal 3: Registry Cross-Check (new — where available)**
Automated or manual verification against public professional registries.

- Client fetches registry data via API where available (SRA, NPPES, etc.)
- Cross-references: does the licence number correspond to a real, active practitioner?
- Does the name on the registry plausibly match the name claimed on the Nostr profile?
- Result: `confirmed`, `unconfirmed` (no API available), or `mismatch`

This is a *supporting signal*, not a proof of identity. A match confirms the licence number is real and active. A mismatch is a strong red flag. "Unconfirmed" is neutral.

**Signal 4: Professional Body Attestation (new — aspirational)**
A professional body publishes its own Nostr pubkey and issues kind 30470 credentials to its members.

Flow:
1. Professional body (e.g., SRA) creates a Nostr account
2. Establishes its identity via NIP-05 on its official domain (`_@sra.org.uk`) and/or `.well-known/signet.json`
3. Issues kind 30470 credentials to verified members: "This pubkey is SRA-registered solicitor #12345"
4. The credential is signed by the professional body's key — unforgeable

**This is the gold standard.** It eliminates impersonation entirely because the professional body itself attests to the binding. But it requires institutional adoption, which takes time and may face government resistance.

**Adoption strategy:** Signet should be designed so that professional body attestation is the *strongest* signal but not the *only* path. Early adopters use domain proof + registry cross-check. As Signet demonstrates value, professional bodies have an incentive to participate (their attestation becomes the gold standard, reinforcing their relevance).

**Signal 5: Network Position Analysis (new — algorithmic)**
Graph-theoretic analysis of the verifier's position in the trust network.

Computed signals:
- **Cluster age spread:** Time between oldest and newest account in the verifier's cross-verification cluster. Real clusters develop over months/years. Sybil clusters appear simultaneously.
- **Connectivity to trust anchors:** Number of independent paths from this verifier to well-established trust anchors (founding verifiers, body-attested verifiers). Sybil clusters connect through very few edges.
- **Vouch graph structure:** Fully-connected clusters (everyone vouched for everyone) are suspicious. Real professional networks have asymmetric, sparse relationships.
- **Geographic plausibility:** A London solicitor cross-verified by a Tokyo notary is unusual (not impossible, but flags for review).
- **Issuance patterns:** A newly activated verifier immediately issuing many credentials is suspicious (existing anomaly detection from §7 feeds into this).

### 4.3 Verifier Confidence Score

Each signal contributes to a composite score:

| Signal | Weight | Max contribution |
|---|---|---|
| Cross-professional vouches | 20 | 20 (2+ vouches, 2+ professions) |
| Domain proof | 25 | 25 (valid, fresh, HTTPS, matching) |
| Registry cross-check | 15 | 15 (confirmed active practitioner) |
| Professional body attestation | 30 | 30 (kind 30470 from verified body) |
| Network position analysis | 10 | 10 (well-connected, plausible graph) |

**Score interpretation:**
- 0-20: **Unverified** — do not trust credentials from this verifier
- 21-40: **Weak** — use with caution, display warnings
- 41-60: **Moderate** — domain-proven, some corroboration
- 61-80: **Strong** — multiple independent signals
- 81-100: **Authoritative** — professional body attested + strong network position

**Critical rule:** The score is *informational*, not gatekeeping. Clients display it. Communities set thresholds in their policies. No single entity decides what score is "enough."

### 4.4 Minimum Activation Threshold

To prevent the current vulnerability where cross-verification alone is sufficient, the minimum for verifier activation should be:

**Cross-professional vouches (Signal 1) PLUS at least one of:**
- Domain proof (Signal 2)
- Registry cross-check confirmed (Signal 3)
- Professional body attestation (Signal 4)

This means an attacker must, at minimum, either hack a professional's website OR have their fake identity pass a registry cross-check OR get a professional body attestation. The Sybil mesh attack alone no longer works.

## 5. The Bootstrap Problem

### 5.1 The Chicken-and-Egg

The current spec requires 2+ vouches from 2+ professions. But who verifies the *first* verifiers in a new jurisdiction?

### 5.2 Founding Verifier Ceremony

For the first verifiers in a jurisdiction:

1. **Recruitment:** 4+ professionals from 3+ different professions agree to bootstrap Signet in their jurisdiction. They should be publicly identifiable professionals — people whose real-world identity is already widely known (published authors, firm partners, hospital consultants). Impersonating a well-known professional is far riskier than impersonating an obscure one.

2. **In-person ceremony:** The founding verifiers meet physically. Each presents:
   - Government-issued photo ID
   - Professional licence documentation
   - Their Nostr pubkey (via QR code)
   They verify each other's documents and perform "Signet me" word verification.

3. **Domain proof:** Each founding verifier publishes their `.well-known/signet.json` proof on their professional website *before* the ceremony.

4. **Simultaneous activation:** After the ceremony, they simultaneously publish kind 30473 events and cross-verify each other. This creates the initial trust nucleus.

5. **Public record:** The ceremony is documented (photographs, video, signed attendance list). This creates an auditable record of the genesis event.

6. **Cross-jurisdiction bootstrap:** Once one jurisdiction has active verifiers, they can help bootstrap adjacent jurisdictions by travelling to verify founding verifiers there. This creates a growing web of trust across borders.

### 5.3 Why Founding Verifiers Are Hard to Fake

An attacker trying to fake a founding verifier ceremony must:
- Impersonate a publicly known professional (high risk of detection)
- Maintain a professional website with domain proof (requires hacking or creating a convincing fake site)
- Meet other real professionals in person and present convincing fake documents
- Sustain the deception over time as the network grows

This is not impossible, but it is *expensive and risky* — exactly the properties we want.

## 6. Sybil Detection Algorithm

### 6.1 Overview

Beyond prevention (multi-signal authentication), the protocol needs detection (identifying suspicious patterns after the fact). This is the "good algo to spot fake web of trust" component.

### 6.2 Trust Anchor Propagation

Start from known-good nodes (founding verifiers, body-attested verifiers) and propagate trust through the vouch graph using personalised PageRank:

1. Assign each trust anchor a seed trust of 1.0
2. At each step, each node distributes its trust equally to nodes it has vouched for, with a damping factor (0.85)
3. After convergence, nodes reachable only through very few edges from the honest network will have low propagated trust

This is similar to Google's PageRank but personalised to the trust anchors. Sybil clusters that connect to the honest network through few attack edges will have low trust scores regardless of their internal structure.

### 6.3 Anomaly Signals

In addition to trust propagation, flag specific anomalies:

| Signal | Detection Method | Severity |
|---|---|---|
| Cluster simultaneity | All accounts in a cross-verification group created within 7 days | High |
| Full connectivity | Every member of a group has vouched for every other member | Medium |
| Isolated cluster | Group has fewer than 2 independent paths to nearest trust anchor | High |
| Geographic implausibility | Cross-verifiers claim jurisdictions >5000km apart with no shared professional context | Medium |
| Issuance spike | Verifier issues >10 credentials in first 30 days after activation | Medium |
| Registry mismatch | Licence number doesn't match any active practitioner in claimed jurisdiction | Critical |

### 6.4 Implementation

This could be implemented as:
- A library function `computeVerifierConfidence(verifierPubkey, vouchGraph, trustAnchors)` in `src/verifiers.ts`
- A client-side component that periodically scans the vouch graph
- An optional relay-side filter that flags suspicious verifiers

The algorithm is *informational* — it produces warnings, not bans. The community decides how to act on the warnings.

## 7. Comparison of Approaches Considered

### Approach A: Multi-Signal (Recommended — described above)
- Multiple independent signals, no single point of failure
- Graceful degradation: works with domain proof alone, gets better with body attestation
- Matches real-world reality: adoption is gradual
- **Chosen because:** Most resilient, most practical, best adoption path

### Approach B: Mandatory Body Attestation
- Require professional body attestation for all verifiers
- Pro: Eliminates impersonation entirely
- Con: Blocks adoption until bodies participate; government-influenced bodies could gatekeep
- **Rejected because:** Creates a hard dependency on institutional adoption and a government veto point — exactly what Signet is designed to avoid

### Approach C: Mandatory Domain Proof Only
- Require domain proof as the minimum for activation
- Pro: Simple, available now
- Con: Not all professionals have websites; website hacking becomes the attack vector
- **Rejected as sole mechanism because:** Too narrow, but included as one signal in Approach A

## 8. Protocol Changes Required

### 8.1 New Tag on Kind 30473 (Verifier Credential)

```jsonc
["website-proof", "<url_to_well_known_signet_json>"]
```

Optional. When present, clients SHOULD fetch and verify the proof.

### 8.2 New Well-Known URL

`/.well-known/signet.json` — format specified in §4.2 above.

### 8.3 Spec Updates

- §6 (Verifier Network): Add multi-signal authentication description
- §7 (Anti-Corruption Framework): Add Sybil detection algorithm description
- New subsection: Founding Verifier Ceremony protocol
- Update verifier activation requirements: cross-verification + at least one additional signal

### 8.4 Code Changes

- New: `src/verifier-auth.ts` — domain proof verification, registry cross-check, confidence score computation
- Modify: `src/verifiers.ts` — update `checkCrossVerification` to return confidence score
- New: `tests/verifier-auth.test.ts`
- Modify: `src/i18n.ts` — add verifier confidence level labels

### 8.5 No New Event Kinds

All changes use existing event kinds. The domain proof is off-chain (HTTP). The confidence score is computed client-side. Professional body attestation uses existing kind 30470.

## 9. Two-Credential Verification: Real Identity + Anonymous Identity

### 9.1 Design Principle

Governments already have passport and DVLA databases. Signet cannot prevent governments from knowing who their citizens are — that ship has sailed. What Signet *can* do is give every person a **verified anonymous identity** alongside their real one, so that daily digital life does not require exposing your real name.

Professionals (doctors, lawyers, notaries) are the only tier that needs to be publicly identified — they already have this obligation in law. They sign and witness legal documents as part of their profession. Everyone else gets anonymity by default.

### 9.2 The Two-Credential Verification Ceremony

When a person visits a professional for verification, the ceremony produces **two credentials**:

1. **Person generates two keypairs:**
   - Keypair A — Natural Person (real identity)
   - Keypair B — Persona (anonymous identity)

2. **Person visits a professional** with passport + both pubkeys (e.g. as QR codes)

3. **Professional verifies the passport** (same process as witnessing any legal document)

4. **Professional builds a Merkle tree** of verified attributes:
   - Leaf 0: `name` = "John Smith"
   - Leaf 1: `nationality` = "GB"
   - Leaf 2: `document_type` = "passport"
   - Leaf 3: `nullifier` = `H("passport" || "GB" || "123456789" || "signet-uniqueness-v1")`

5. **Professional issues two kind 30470 credentials:**

   **Credential 1 — Natural Person (keypair A):**
   ```jsonc
   {
     "kind": 30470,
     "tags": [
       ["p", "<keypair_A_pubkey>"],
       ["entity-type", "natural_person"],
       ["merkle-root", "<root_of_verified_attributes>"],
       ["nullifier", "<hex_encoded_nullifier>"],
       ["tier", "3"],
       // ... other standard tags
     ]
   }
   ```

   **Credential 2 — Persona (keypair B):**
   ```jsonc
   {
     "kind": 30470,
     "tags": [
       ["p", "<keypair_B_pubkey>"],
       ["entity-type", "persona"],
       ["tier", "3"],
       // ... other standard tags
       // NO nullifier — Persona is anonymous
       // NO merkle-root — no verified attributes to bind
     ]
   }
   ```

6. **Professional gives the subject** the Merkle leaves and proofs privately (for selective disclosure later)

7. **Professional records both pubkeys** in their client file (same record-keeping obligation they already have for witnessing documents)

### 9.3 What Goes On-Chain vs What Stays Private

| Data | On-chain? | Who knows it? |
|---|---|---|
| Keypair A pubkey | Yes | Public |
| Keypair B pubkey | Yes | Public |
| Entity type (`natural_person` / `persona`) | Yes (in credential, signed by professional) | Public |
| Nullifier hash | Yes (on Natural Person credential only) | Public, but not reversible |
| Merkle root of verified attributes | Yes (on Natural Person credential only) | Public, but reveals nothing without leaves |
| Verified name, nationality, document details | **No** — private Merkle leaves | Subject + professional only |
| Passport number | **No** — consumed to compute nullifier, then discarded | Professional's private records |
| Link between keypair A and keypair B | **No** | Subject + professional only |

### 9.4 Merkle-Bound Name Verification

The Natural Person credential contains a Merkle root of verified attributes, signed by the professional. This root is **immutable** — the subject cannot change it.

The subject's Nostr kind 0 profile (display name, avatar, bio) is a separate event that the subject controls. They CAN change their display name — but the Merkle root in the credential doesn't change with it.

**Selective disclosure:** When someone needs to verify that a Natural Person's display name matches their verified name, the subject reveals the `name` Merkle leaf + proof. The verifier checks it against the root in the credential.

**Name-change attack defence:**

If "John Smith" changes his kind 0 profile name to "Dr. James Wilson":
- The credential's Merkle root still contains the hash of "John Smith"
- Any client that requests name disclosure will see the mismatch
- If the subject refuses disclosure, the client flags: "verified identity, name unconfirmed"

### 9.5 Entity Type as Immutable Differentiator

The `entity-type` tag is in the credential, signed by the professional. **The subject cannot change it.** This is the primary defence against a Persona impersonating a Natural Person.

**Attack: Persona name change**
1. Get a Persona credential under display name "SuperDad"
2. Build web-of-trust, accumulate vouches
3. Change kind 0 display name to "Dr. James Wilson"
4. Hope people think you're a verified doctor

**Defence:** The credential still says `entity-type: "persona"`. Clients MUST display this prominently.

**Required client display behaviour:**

| Profile name | Entity type in credential | Merkle name match | Client displays |
|---|---|---|---|
| John Smith | `natural_person` | Match | **John Smith — Verified Person** |
| Dr. James Wilson | `natural_person` | Mismatch | **Dr. James Wilson — Warning: verified name differs** |
| Dr. James Wilson | `natural_person` | Not disclosed | **Dr. James Wilson — Verified Person, name unconfirmed** |
| SuperDad | `persona` | N/A | **SuperDad — Verified Alias** |
| Dr. James Wilson | `persona` | N/A | **Dr. James Wilson — Verified Alias** |
| Dr. James Wilson | (none) | N/A | **Dr. James Wilson — Unverified** |

The visual distinction between "Verified Person" and "Verified Alias" must be unmistakable — different colours, different icons, different badge shapes. Think of it as a cryptographically enforced version of Twitter's verification, except the badge can't be bought and the type can't be faked.

### 9.6 Document-Based Nullifiers

The nullifier prevents one person from obtaining multiple Natural Person credentials:

```
nullifier = H(document_type || country_code || document_number || "signet-uniqueness-v1")
```

**Properties:**
- **Deterministic:** Same passport → same nullifier, regardless of which professional computes it
- **Privacy-preserving:** The nullifier is a hash — it reveals nothing unless you already know the document number
- **Decentralised detection:** Anyone can scan for duplicate nullifiers — no central registry needed
- **Persona-safe:** Nullifiers only appear on Natural Person credentials, never on Persona credentials

**Detection:** If two Natural Person credentials on different pubkeys share a nullifier, the duplicate is visible to the entire network. The later credential is suspect.

**Government mass computation:** Yes, a government with a database of all passport numbers could compute all nullifiers and match them to Natural Person pubkeys. But governments already have this information — the nullifier doesn't give them anything new about your real identity. What matters is that your *Persona* has no nullifier and cannot be linked to your Natural Person credential by anyone except you and the issuing professional.

### 9.7 Nullifier Weaknesses and Mitigations

| Attack | Mitigation |
|---|---|
| Different document types (passport for one, licence for another) | Require passport as primary; compute nullifiers for ALL documents presented |
| Dual citizenship, two passports | Rarer and expensive; cross-reference nationality nullifiers |
| Professional doesn't compute nullifier | Clients flag credentials without nullifiers as lower confidence |
| Government computes nullifiers for all citizens | Only links to Natural Person pubkey — Persona remains unlinkable |

### 9.8 The Link Between Keypair A and Keypair B

The professional knows both pubkeys (from the verification ceremony). This is the same trust model as solicitor-client confidentiality or doctor-patient privilege. Breaking it is professional misconduct and potentially criminal.

**Stronger variant (optional):** The professional signs only keypair A. The subject then creates an **identity bridge** (kind 30476) from keypair A to keypair B using a ring signature. This way the professional never learns keypair B — they only verified keypair A. The Persona proves "I am backed by a Tier 3 Natural Person credential" without revealing which one.

This is already supported by the existing identity bridge mechanism in the spec.

### 9.9 Social Constraints (Defence in Depth)

Nullifiers and Merkle-bound names catch the primary attacks. Social constraints make residual attacks economically unattractive:

1. **Empty social graph:** A sold identity has no organic vouches. Clients display "0 vouches, 0 connections" alongside the Tier 3 badge.

2. **"Signet me" fails:** Time-based word verification requires real-time presence. The buyer can't pass this test with anyone who knows the original person.

3. **Trust score is low:** A fresh Tier 3 with no vouches, no identity bridges, no account age scores low (professional verification weight is 40/100, but all other signals are zero).

4. **Professional liability:** Verifying the same passport for two different Natural Person pubkeys is professional misconduct. Professionals keep records. If caught, they face disciplinary action and licence revocation.

5. **Credential provenance:** Every credential traces to its issuer. Fraud → investigation → issuing professional → their records.

### 9.10 Why This Is Better Than Government Digital ID

| | Government Digital ID | Signet |
|---|---|---|
| **Issuer** | Government monopoly | Any licensed professional |
| **Anonymity** | None — traceability is the point | Built in by default (Persona key) |
| **What you reveal** | Your full identity, every time | You choose: real name OR anonymous proof |
| **Revocation** | Government revokes unilaterally | Requires threshold of peer professionals |
| **Portability** | Tied to one country's system | Works across jurisdictions |
| **Key custody** | Government holds or controls keys | You hold your own keys |
| **Duplicate prevention** | Central database | Nullifier hash (decentralised) |
| **Name binding** | Government-issued, government-controlled | Merkle-bound, professionally verified, you control disclosure |
| **Anonymous but verified** | Not possible | Default — every person gets a Persona |

### 9.11 Honest Assessment

This won't prevent a determined, well-funded attacker from creating duplicate identities. No decentralised system can guarantee one-person-one-identity without biometrics or a central registry.

But Signet doesn't need to be perfect — it needs to be *better than the status quo*:
- Fake IDs cost $50-500 on the dark web; with Signet, duplicates require visiting a real professional, paying real fees, and risking a nullifier collision
- Currently there is no duplicate detection across services; with Signet, nullifiers catch the common case
- Currently there is no anonymous-but-verified identity; with Signet, everyone gets one by default
- A sold identity is worth much less: no social graph, fails "Signet me", low trust score
- The audit trail is permanent and public

The goal is economic deterrence, not cryptographic impossibility. And the real win is the Persona layer — verified anonymity that governments cannot provide and cannot easily surveil.

## 10. Credential Lifecycle: Changes After Verification

### 10.1 Core Mechanism — Credential Chains

When real-world attributes change, a professional issues a NEW credential that **supersedes** the old one. The pubkey stays the same — all vouches, trust score, and social graph carry forward. Only the attestation changes.

```jsonc
// New credential includes:
["supersedes", "<old_credential_event_id>"]

// Issuer updates old credential with:
["superseded-by", "<new_credential_event_id>"]
```

Clients resolve the chain: follow `superseded-by` links to find the current credential. Old credentials in the chain remain visible for audit history.

**Critical rule:** Only the ORIGINAL ISSUER (or another professional who independently re-verifies the subject) can issue a superseding credential. The subject cannot self-supersede.

### 10.2 Name Changes

**Triggers:** Marriage, divorce, deed poll, gender transition, religious conversion, cultural adoption.

**Mechanism:**
1. Subject visits a professional (can be the original verifier or a new one) with updated documents (e.g. marriage certificate + updated passport, deed poll + updated passport)
2. Professional verifies the new documents against the subject (same person, new name)
3. Professional issues a new kind 30470 credential with:
   - Updated Merkle tree (new name in leaf 0)
   - Same pubkey (keypair A unchanged)
   - New nullifier if passport number changed, plus a `["nullifier-chain", "<old_nullifier>"]` tag linking old and new nullifiers
   - `["supersedes", "<old_credential_id>"]` tag
4. Old credential gets `["superseded-by", "<new_credential_id>"]`

**Persona impact:** None. The Persona (keypair B) has no verified name. A name change in real life does not affect the Persona at all. If someone built a great Persona reputation as "SuperDad" and then changed their real name from John Smith to Jane Smith after marriage, "SuperDad" continues uninterrupted.

**The key insight:** The Persona layer makes name changes painless. Your real-world identity changes; your digital pseudonym does not. This is one of the strongest arguments for the two-credential model.

### 10.3 Titles and Qualifications

**Titles earned after verification:** Dr. (PhD, MD), Prof., KC/QC, Lord, Dame, Sir, OBE, etc.

**Design decision: titles are SEPARATE credentials, not name changes.**

A title is an attribute, not a name. "Dr. John Smith" is "John Smith" (name, in the Natural Person credential) + "Dr." (qualification, in a separate attestation). Conflating them creates problems:
- You'd need a new credential every time you earn a qualification
- Multiple qualifications (Dr. Prof. Sir John Smith KC) would require constant reissuance
- The name credential would become fragile

**Mechanism:**
1. The awarding body (university, professional body, Crown, etc.) issues a **separate kind 30470 credential** attesting to the qualification:
   ```jsonc
   ["qualification", "PhD"],
   ["awarding-body", "University of Oxford"],
   ["field", "Physics"]
   ```
2. Or a professional who can verify the qualification (e.g. a notary who has seen the degree certificate) issues the attestation
3. The qualification credential is linked to the same pubkey
4. Clients compose the display: name from the Natural Person credential + titles from qualification credentials

**Title lost (struck off):**
When a professional is struck off the register, the professional body (if they're on Signet) or another professional issues a kind 30475 revocation against the qualification credential. The base identity credential remains valid — you're still a person, you're just no longer a doctor.

### 10.4 Children

**The challenge:** Children are Natural Persons but cannot independently consent to verification. The existing Tier 4 (Professional + Child Safety) with Bulletproof age range proofs handles the crypto. The questions are about ceremony, guardianship, and transition to adulthood.

#### 10.4.1 Child Verification Ceremony

1. **Parent/guardian brings the child** to a professional (typically a doctor or social worker — the same professionals who already certify children's identities for passport applications)
2. **Professional verifies:**
   - Child's birth certificate or passport
   - Parent/guardian's identity (their own Signet Natural Person credential, or passport)
   - Parental authority (birth certificate, court order, adoption certificate)
3. **Professional issues credentials to the child's keypair:**

   **Natural Person credential:**
   ```jsonc
   ["entity-type", "natural_person"],
   ["tier", "4"],
   ["age-range", "8-12"],  // Bulletproof range proof, not exact age
   ["guardian", "<parent_pubkey>"],
   ["nullifier", "<child_document_nullifier>"]
   ```

   **Persona credential (for the child's online identity):**
   ```jsonc
   ["entity-type", "persona"],
   ["tier", "4"],
   ["age-range", "8-12"],
   // NO nullifier, NO verified name — child protection
   ```

4. **The child's real name is NEVER published on-chain.** It exists only in the Merkle tree leaves, held by the child (or parent on their behalf) and the professional. Child protection takes priority.

#### 10.4.2 Guardian Link

The `["guardian", "<parent_pubkey>"]` tag on the child's credential:
- Is signed by the professional (immutable)
- Identifies who has parental authority
- Can be updated via a superseding credential if custody changes (divorce, adoption, fostering)
- Clients can enforce parental controls: "this account is a child with guardian X"

**Multiple guardians:** Multiple `["guardian", "..."]` tags for joint custody.

**Foster children / looked-after children:** The local authority's pubkey can appear as guardian instead of (or alongside) a parent's.

#### 10.4.3 Child → Adult Transition

When the child turns 18 (or the age of majority in their jurisdiction):

1. The age range proof in the existing credential expires naturally — the Bulletproof proof that "age is in range 8-12" is no longer valid when they're 18
2. The young adult visits a professional **independently** (no parent required)
3. Professional issues a new credential:
   - `["tier", "3"]` (adult, no longer child safety tier)
   - No `["guardian", "..."]` tag
   - No `["age-range", "..."]` tag
   - `["supersedes", "<child_credential_id>"]`
4. The young adult now has a standard adult Natural Person credential
5. They keep the same keypair — all trust, vouches, and connections built during childhood carry forward

**The Persona carries through seamlessly.** A teenager's Persona identity — their online reputation, their connections, their creative work — survives the transition to adulthood without interruption.

#### 10.4.4 Age-Appropriate Tiers

| Age | Tier | Guardian Required | Age Range Proof | Notes |
|---|---|---|---|---|
| 0-12 | 4 | Yes | Required | Full child protection |
| 13-15 | 4 | Yes (but child can consent to some things depending on jurisdiction) | Required | Digital consent age varies: 13 (US COPPA), 16 (UK GDPR) |
| 16-17 | 4 or 3 | Jurisdiction-dependent | Optional | Some jurisdictions treat 16+ as near-adult |
| 18+ | 3 | No | No | Standard adult credential |

### 10.5 Document Renewal

**The problem:** Passport expires → new passport number → new nullifier → old and new credentials look like different people.

**Mechanism:**
1. Subject visits a professional with both old (expired) and new passport
2. Professional verifies: same person, same photo, old passport → new passport
3. Professional issues a new credential with:
   - New nullifier (from new passport number)
   - `["nullifier-chain", "<old_nullifier>"]` — links old and new nullifiers
   - `["supersedes", "<old_credential_id>"]`
4. Old credential is superseded

**The `nullifier-chain` tag** creates a verifiable link between old and new nullifiers. Anyone scanning for duplicates can follow the chain: "these two nullifiers belong to the same person because a professional attested to the continuity."

**This is distinct from the duplicate attack** (§9.6) because:
- The old credential is superseded (inactive)
- Only one active credential exists at any time
- The chain is attested by a professional, not self-declared

### 10.6 Death

1. A professional with access to death records (doctor who certified death, registrar, solicitor handling probate) issues a kind 30475 revocation against the deceased's credential
2. The revocation includes `["reason", "death"]`
3. Clients mark the identity as deceased
4. The Persona credential can optionally be left active (for memorial purposes) or revoked

### 10.7 Key Compromise / Identity Theft Recovery

If someone's private key is stolen:

1. Subject visits a professional with their passport (proving they're the real person)
2. Professional issues a revocation (kind 30475) against ALL credentials on the compromised pubkey
3. Subject generates a NEW keypair
4. Professional issues fresh credentials on the new keypair
5. New credential includes `["replaces-compromised", "<old_pubkey>"]`
6. Nullifier stays the same (same passport) — ensuring the new credential is recognised as the same person

**Vouches and trust score are lost** — this is a deliberate security property. If the attacker could transfer trust to a new key, they could steal someone's reputation. The subject must rebuild their web of trust. This is painful but safe.

### 10.8 Incapacitation / Guardianship

When a court appoints a guardian for an incapacitated adult:

1. The guardian (or their solicitor) presents the court order to a professional
2. Professional issues a superseding credential on the incapacitated person's pubkey with `["guardian", "<guardian_pubkey>"]`
3. The guardian can act on behalf of the incapacitated person (using the delegation system, kind 30477)
4. If capacity is restored, a professional issues a new credential removing the guardian tag

### 10.9 Emigration / Jurisdiction Change

1. Subject obtains residency/citizenship documents in new jurisdiction
2. A professional in the new jurisdiction verifies the documents
3. Professional issues a new credential with updated jurisdiction
4. Old credential can be superseded or left active (dual nationality = dual credentials)
5. Nullifier from the new country's documents is added; old nullifier linked via `nullifier-chain`

### 10.10 Tier Upgrade

When someone gains a professional qualification and moves from Tier 2 (web-of-trust) to Tier 3 (professionally verified):

1. The newly qualified professional gets verified by a peer professional (as per the standard ceremony)
2. New Tier 3 credential supersedes the old Tier 2 credential
3. Same pubkey — all existing trust carries forward
4. The old Tier 2 vouches remain valid and continue contributing to trust score

### 10.11 Key Rotation (Without Compromise)

Security best practice is periodic key rotation. This is harder than compromise recovery because we want to PRESERVE trust:

1. Subject generates a new keypair
2. Subject signs a **key rotation declaration** with BOTH the old and new keys: "old pubkey X is being replaced by new pubkey Y"
3. A professional verifies the subject's identity and co-signs the rotation
4. New credentials are issued on the new pubkey
5. Vouches: existing vouchers are notified and can re-vouch for the new key (or clients can accept the professionally-attested rotation as sufficient)

**This is an open design question.** Automatic trust transfer during key rotation is convenient but creates an attack surface (compromise old key → rotate to attacker's key). Requiring professional attestation for rotation is safer but adds friction. The right balance may depend on the tier: Tier 1-2 could self-rotate, Tier 3-4 should require professional attestation.

### 10.12 Persona Migration

Occasionally someone may want to retire one Persona and create a new one while carrying forward their verified status:

1. Subject creates a new keypair C (new Persona)
2. Subject creates a NEW identity bridge (kind 30476) from their Natural Person credential to keypair C
3. The old Persona (keypair B) is left active, deprecated, or revoked — subject's choice
4. Trust and vouches on the old Persona do NOT transfer (they're tied to keypair B)
5. The new Persona starts fresh but with "Verified Alias" status from day one

**Trust does not transfer between Personas** — this is deliberate. If it did, de-anonymisation would be trivial (follow the trust transfer to link old and new Personas). The cost of Persona migration is rebuilding social trust. This incentivises identity stability.

### 10.13 Nostr Early Adopter Migration

**The scenario:** Someone has been on Nostr for years. Their npub is widely known — they have followers, NIP-05 verification, relay subscriptions, zaps, a social graph, published notes, long-form content. Signet launches. They want professional verification without losing any of that.

#### 10.13.1 The Simple Case: Sign the Existing Keypair

The two-credential ceremony (§9) does NOT require a new keypair. The subject brings their **existing** Nostr keypair to the professional:

1. Early adopter generates no new keys — they present their existing pubkey (keypair A)
2. Professional verifies identity against documents
3. Professional issues a kind 30470 credential on the **existing pubkey**
4. Optionally, the subject generates a separate keypair B for a Persona
5. Result: all followers, relay subscriptions, NIP-05, published content, zaps, reputation — completely untouched. They just gained a Signet credential on top.

**This is the expected path for most early adopters.** Nothing migrates because nothing moves.

#### 10.13.2 The Reverse Case: Existing npub Becomes the Persona

Some early adopters may have built their Nostr presence pseudonymously — they don't use their real name, and they want to keep it that way. Their existing npub IS their Persona. They want a new keypair for their real-name identity.

1. Subject generates a NEW keypair A (for their real-name Natural Person)
2. Subject brings keypair A + their existing npub (keypair B, the Persona) to the professional
3. Professional verifies identity and issues:
   - Natural Person credential on keypair A (new, real-name)
   - Persona credential on keypair B (existing, pseudonymous)
4. Subject optionally creates an identity bridge (kind 30476) linking keypair A to keypair B with ring signature privacy
5. Result: existing Nostr identity continues as a verified Persona. New real-name identity exists separately.

#### 10.13.3 Forwarding and Linking

What about web-style forwarding — "this old identity points to this new one"?

**Within Nostr, this is already handled:**
- **NIP-05 redirect:** Update `_@domain/.well-known/nostr.json` to point to the new pubkey
- **Kind 0 metadata:** Update the old account's profile to reference the new one
- **Relay list:** Publish the same relay list on both keys

**Within Signet, the mechanisms already exist:**
- **Identity bridge (kind 30476):** Cryptographically links two keypairs with ring signature privacy — proves they're controlled by the same verified person without revealing which person
- **Credential chain:** If migrating from one keypair to another, a professional can issue a new credential that references the old one via `["supersedes", "<old_credential_id>"]`

**What Signet does NOT do (deliberately):**
- Automatic trust transfer between keypairs. If someone's Tier 2 vouches are on keypair A and they want to move to keypair B, those vouches stay on A. People who vouched for A would need to re-vouch for B. This prevents impersonation attacks where someone claims "my new key is X, transfer everything."
- Follower migration. Nostr followers follow a specific pubkey. Signet doesn't and shouldn't try to redirect followers — that's a social layer concern, not an identity layer concern.

#### 10.13.4 The NIP-05 to Signet Upgrade Path

Many early adopters have NIP-05 verification (`alice@example.com`). This is identification, not verification — it proves domain ownership, not identity. But it's a useful stepping stone:

1. **NIP-05 gives a human-readable name** — Signet credentials add cryptographic identity proof behind that name
2. **No conflict** — NIP-05 and Signet credentials coexist on the same pubkey
3. **Additive trust signal** — Clients can show both: "alice@example.com (NIP-05) + Verified Person (Signet Tier 3)"
4. **Long-standing NIP-05** — an account that has had the same NIP-05 for years is itself a trust signal (account age contributes to trust score)

#### 10.13.5 What Early Adopters Keep vs What They Gain

| Already have (Nostr) | Gain (Signet) | Lose |
|---|---|---|
| Pubkey + followers | Professional verification credential | Nothing |
| NIP-05 identification | Cryptographic identity proof | Nothing |
| Social graph (follows/followers) | Trust score based on verification tier | Nothing |
| Published content (notes, articles) | Merkle-bound verified name (optional disclosure) | Nothing |
| Relay subscriptions | Selective disclosure of attributes | Nothing |
| Zap history | Persona credential (anonymous verified identity) | Nothing |
| Existing reputation | Nullifier-based duplicate prevention | Nothing |

**The answer is: they lose nothing.** Signet is purely additive for existing Nostr users.

### 10.14 Summary: What Changes, What Stays

| Event | Pubkey changes? | Credential changes? | Nullifier changes? | Vouches preserved? | Persona affected? |
|---|---|---|---|---|---|
| Name change | No | Yes (superseded) | Maybe (if passport number changed) | Yes | No |
| Title gained | No | No (separate credential) | No | Yes | No |
| Title lost | No | No (title credential revoked) | No | Yes | No |
| Child → adult | No | Yes (superseded) | No | Yes | No |
| Document renewal | No | Yes (superseded) | Yes (nullifier-chain) | Yes | No |
| Death | No | Revoked | N/A | N/A | Optional |
| Key compromise | Yes (new keypair) | Yes (fresh issuance) | No | **Lost** | **Lost** |
| Incapacitation | No | Yes (guardian added) | No | Yes | Yes (guardian controls) |
| Emigration | No | Yes (new jurisdiction) | Maybe (new country docs) | Yes | No |
| Tier upgrade | No | Yes (superseded) | No | Yes | No |
| Key rotation | Yes (new keypair) | Yes (rotated) | No | Partial (re-vouch) | No (new bridge) |
| Persona migration | Yes (new Persona key) | New bridge | No | **Lost** (on Persona) | Yes (new Persona) |
| Nostr early adopter (sign existing key) | No | Yes (new credential on existing key) | No | Yes (all preserved) | N/A (new Persona optional) |
| Nostr early adopter (existing key becomes Persona) | New keypair A created | Yes (new Natural Person + Persona on existing) | No | Yes (on Persona key) | No (existing key becomes verified Persona) |

## 11. Inclusivity: Entry Without Standard Documents

The system described so far assumes the subject has a passport (or equivalent government-issued document) for Tier 3+ verification. But many people don't. Signet must work for everyone — not just people with their paperwork in order.

### 11.1 The Tier System Is Already a Safety Net

The existing tier system provides entry points that require **zero documents**:

| Tier | Requirement | Documents needed | Who this serves |
|---|---|---|---|
| 1 | Self-declaration | None | Anyone with a device |
| 2 | Community vouches | None — peers vouch for you | Anyone with social connections |
| 3 | Professional verification | Government-issued photo ID | People with standard documents |
| 4 | Professional + child safety | Government-issued photo ID + birth certificate | Children with documented guardians |

**The key insight:** Nobody is locked out. A person with nothing — no passport, no driving licence, no fixed address — can still enter the system at Tier 1 (self-declared) and work their way up to Tier 2 (community-vouched). These tiers are not "lesser" — they're appropriate trust levels for someone whose identity hasn't been formally verified. They can still participate in communities, build reputation, and access services that accept Tier 1-2 credentials.

### 11.2 Who Doesn't Have Standard Documents?

| Situation | Estimated population | Documents available |
|---|---|---|
| **Homeless / rough sleepers** | ~650K (US), ~300K (UK) | Often have expired ID, birth certificate, or NHS number. May have **none**. |
| **Refugees / asylum seekers** | ~36M globally (UNHCR) | UNHCR refugee travel document, asylum registration card, or nothing |
| **Undocumented migrants** | ~11M (US), ~1.2M (UK est.) | May have home country ID, consular documents, or nothing |
| **Domestic abuse survivors** | Fleeing without documents | May have been denied access to their own documents by an abuser |
| **Recently released prisoners** | ~600K/year (US) | Prison release documents, expired pre-imprisonment ID |
| **Elderly without photo ID** | Significant in UK (no mandatory ID) | Birth certificate, pension letter, utility bills |
| **Young people (just turned 18)** | N/A | May never have applied for passport or driving licence |
| **Trans people mid-transition** | N/A | Documents may not match current presentation |
| **People in crisis** | Variable | House fire, theft, natural disaster — all documents lost |

### 11.3 Expanded Document Types for Nullifiers

The current design uses `H(document_type || country_code || document_number || "signet-uniqueness-v1")` with passports as the primary document. But the nullifier system can accept ANY document with a unique, persistent identifier:

| Document type | Unique identifier | Jurisdictions | Nullifier strength |
|---|---|---|---|
| **Passport** | Passport number | Global | Strong — unique, government-issued, photo |
| **National ID card** | ID number | EU, many countries | Strong — equivalent to passport in issuing countries |
| **Driving licence** | Licence number | UK, US, EU, etc. | Moderate — widely held, photo, but not universal |
| **Birth certificate** | Certificate number + district | UK, US, etc. | Moderate — universal at birth, but no photo, easily lost |
| **NHS number** | 10-digit NHS number | UK | Moderate — unique, persistent, no photo |
| **Social Security number** | SSN | US | Moderate — unique, persistent, no photo, but privacy-sensitive |
| **UNHCR travel document** | Document number | Global (for refugees) | Moderate — issued by UNHCR, internationally recognised |
| **Asylum registration card** | Registration number | Per country | Weak-moderate — valid during claim process |
| **Consular ID** | ID number | Per issuing country (e.g. Mexican Matrícula Consular) | Moderate — recognised by some but not all institutions |
| **Prison release document** | Prisoner number | Per jurisdiction | Weak — short-lived, but verifiable |

**Design decision:** The professional verifier decides which document type to accept. The `document_type` field in the nullifier captures what was used. Clients and communities can set minimum document standards via their policies (kind 30472), but the protocol itself is document-agnostic.

### 11.4 The "Down and Out" Path — Re-entry With Nothing

**Scenario:** Someone has lost everything — no ID, no phone, no fixed address, no social connections in the area. How do they enter Signet?

**Step 1: Tier 1 — Self-declaration (immediate)**
- Borrow or access any device (library computer, shelter phone, donated handset)
- Create a keypair — you now have a Tier 1 identity
- This is enough to read content, join public communities, and start building presence

**Step 2: Tier 2 — Community vouching (days to weeks)**
- Shelter staff, charity workers, social workers, food bank volunteers, religious leaders — anyone with a Tier 2+ identity can vouch for you
- "I see this person regularly at the shelter, they are who they say they are"
- Three vouches from Tier 2+ people → you now have a Tier 2 identity
- This is enough for most community participation

**Step 3: Tier 3 — Professional verification (when documents are available)**
- Apply for replacement documents:
  - UK: Emergency passport (£75.50, 1-day), provisional driving licence (£34, weeks), birth certificate copy (£11, 1-2 weeks)
  - US: Replacement Social Security card (free), state ID (varies, $0-$30)
- When replacement documents arrive, visit a professional for standard Tier 3 verification
- The professional can accept whichever document is available (see §11.3)

**The crucial point:** At no stage is the person locked out of the system. They have a usable identity from minute one (Tier 1), a community-validated identity within days (Tier 2), and can work toward full professional verification when they're ready.

### 11.5 Social Worker and Shelter Attestation

Social workers and shelter staff occupy a unique position: they work with undocumented people daily and can attest to identity even without formal documents. Within Signet:

1. **Social workers ARE professionals** — they're registered (e.g. Social Work England, NASW in the US) and can be verified as Signet verifiers through the standard bootstrapping process
2. A social worker can issue a Tier 3 credential based on their professional assessment, even if the subject only has limited documentation
3. The credential includes the document type used (or `["document-type", "professional-assessment"]` if no document was available)
4. The trust score reflects this: a credential backed by professional assessment alone scores lower than one backed by a passport, but it's still professionally verified

**Shelter attestation** (non-professional):
- Shelter managers who are not registered social workers can still provide **Tier 2 vouches**
- A vouch from a shelter manager carries more weight than a random online vouch (in-person, repeated contact)
- Combined with other shelter staff vouches, this gets someone to Tier 2 quickly

### 11.6 Non-Standard Document Acceptance

**The problem:** A refugee presents a UNHCR travel document that doesn't appear on the professional's usual list of accepted documents. What happens?

**Design decision: Accept and record, don't reject.**

1. The professional verifies the document to the best of their ability (UNHCR documents have security features, registration numbers, photos)
2. The credential includes:
   ```jsonc
   ["document-type", "unhcr_travel_document"],
   ["document-country", "UNHCR"],  // issuing authority
   ["nullifier", "<hash_of_unhcr_doc_number>"]
   ```
3. The nullifier still works — UNHCR document numbers are unique and persistent
4. Communities can set their own policies:
   - A refugee support community might accept any UNHCR credential
   - A financial services community might require passport-grade documents
   - Neither policy is wrong — they reflect different risk appetites

### 11.7 Key Recovery for People Without Backups

Standard key backup uses Shamir secret sharing across trusted contacts. But what if someone loses their device and has no backup?

**Recovery paths:**

| Path | Requires | Result |
|---|---|---|
| **Shamir reconstruction** | K-of-N trusted contacts still have their shares | Full key recovery — all credentials, trust, history preserved |
| **Mnemonic recovery** | Written-down 12-word mnemonic | Full key recovery |
| **Professional re-verification** | Visit a professional with documents | New keypair, fresh credentials. Old trust score lost. Nullifier links old and new identities. |
| **Community re-vouching** | Existing contacts vouch for new keypair | Tier 2 on new keypair quickly, with same social connections |

**For the "down and out" scenario:** If they never set up Shamir backup and lost their mnemonic, the path is: new keypair → Tier 1 → community vouches → Tier 2 → professional verification when documents available → Tier 3. Their old identity exists as an orphan (no one can sign with it), and the nullifier prevents someone else from claiming their documents.

### 11.8 The Principle: Degrees of Confidence, Not Binary Access

Traditional identity systems are binary: you have ID or you don't. You're in the database or you're not. This creates a cliff edge that disproportionately harms vulnerable people.

Signet's tiered model creates a **gradient of confidence**:
- Tier 1: "Someone claims to be human" (0.1% confidence)
- Tier 2: "Multiple people who know this person confirm they're real" (moderate confidence)
- Tier 3: "A professional verified their documents" (high confidence)
- Tier 4: "A professional verified their documents and confirmed age range" (high confidence + child safety)

**No tier is "wrong" or "lesser" for its purpose.** A Tier 2 identity is perfectly appropriate for joining a community forum, participating in discussions, or building a reputation. Tier 3 is needed when the stakes are higher: financial services, professional attestation, legal proceedings.

The system meets people where they are and provides a path upward as their circumstances improve. A homeless person today can be a fully verified Tier 3 identity holder tomorrow, without starting over — the same keypair, the same social connections, just a new credential from a professional.

## 12. Child Online Safety — Adversarial Analysis

This is the most immediate problem Signet must solve. Two attack vectors, examined from the attacker's perspective, then defended.

### 12.1 Attack Vector 1: Adult Pretending to Be a Child (Grooming)

**The attack today (no Signet):** Trivially easy. Create an account, put "14" in your bio, use a stolen or AI-generated photo of a teenager, join teen spaces, start building trust. There is literally nothing stopping this. Every social platform relies on self-declaration.

**The attack with Signet — how an attacker would try:**

#### 12.1.1 Attempt: Create an unverified account claiming to be a child

1. Attacker creates a Tier 1 keypair
2. Sets bio to "14 year old, loves gaming"
3. Tries to enter a child-safe community

**Defence:** Any properly configured child-safe community sets a kind 30472 policy requiring:
```jsonc
["child-min-tier", "4"],
["require-age-range", "true"]
```
A Tier 1 account has NO age-range proof. Rejected at the door. The attacker can't even enter the space.

#### 12.1.2 Attempt: Get a Tier 2 (community-vouched) child identity

1. Attacker builds a fake child persona at Tier 1
2. Gets vouched by other Tier 2+ users who believe they're a child

**Defence:** Tier 2 vouches do NOT include age-range proofs. A vouch says "this person is real" — it doesn't say "this person is 14." The community policy requiring `["require-age-range", "true"]` still blocks them because age-range proofs can ONLY be issued by a professional who has verified identity documents. No amount of social engineering gets past this — the Bulletproof proof requires a professional's signature on a document-verified age.

#### 12.1.3 Attempt: Get a fake Tier 4 child credential from a professional

1. Attacker walks into a professional's office
2. Presents forged birth certificate claiming to be 14

**Defence: The professional has eyes.** This is the single strongest defence and it's beautifully simple — a 35-year-old cannot walk into a doctor's office and convince them they're 14. The in-person physical verification that Signet requires for Tier 3-4 makes this attack absurd in a way that no purely digital system can.

Even in edge cases (physically young-looking adult): the professional checks a government-issued photo ID document. If the attacker presents someone else's birth certificate, the photo won't match. If they present a forged document, the professional is trained to detect forgeries (this is literally what notaries, doctors, and solicitors do daily).

#### 12.1.4 Attempt: Use a real child as a proxy

1. Attacker recruits or coerces a real child to create an account
2. Child gets legitimately verified at Tier 4
3. Attacker takes over the account (gets the child's private key)

**Defence (multiple layers):**
- **Guardian notifications:** The child's credential has a `["guardian", "<parent_pubkey>"]` tag. Clients can notify the guardian of unusual activity patterns (sudden change in messaging behaviour, new adult contacts)
- **"Signet me" challenge:** If the attacker-as-child contacts another child and suggests meeting, the other child's client can prompt a "Signet me" real-time verification — the attacker can't produce the time-based words because they don't have the child's live presence
- **Key custody:** The child's key should be on the child's device, protected by biometrics. The attacker would need physical access to the device
- **Revocation on detection:** If the proxy use is discovered, the credential is revoked via kind 30475. The nullifier ensures the real child can get re-verified, but the attacker's access is burned

#### 12.1.5 Attempt: Operate in public/mixed-age spaces

1. Attacker has a valid adult Persona credential (Tier 3, no age range)
2. Enters a public Nostr community where children also participate
3. Identifies children by their Tier 4 credentials
4. Initiates contact, builds trust over weeks, eventually grooms

**This is the hardest attack to prevent at the protocol level.** But Signet provides tools that don't exist today:

**Defence — Age-aware client behaviour:**
- When an adult-credentialed user initiates a DM to a child-credentialed user, the client can:
  - **Warn the child:** "This person is a verified adult. Do you know them?"
  - **Notify the guardian:** "An adult has messaged your child"
  - **Require guardian approval** before the DM is delivered (configurable)
  - **Block entirely:** Guardian can set "no adult DMs" policy on the child's account

**Defence — Contact restrictions on child accounts:**
- Client-enforced policy (configurable by guardian):
  - `allow-adult-dms: none` — no adults can DM this child
  - `allow-adult-dms: approved-only` — guardian pre-approves specific adults (teachers, family)
  - `allow-adult-dms: notify` — adults can DM but guardian gets notified
- These policies are enforceable because Signet credentials contain the age data

**Defence — Meeting safety protocol:**
When conversation includes meeting-related language (client-level heuristic, not protocol-level):
1. Client prompts: "Someone has suggested meeting in person. Would you like to verify them?"
2. Initiates a "Signet me" challenge — both parties prove they match their credential in real-time
3. If age gap detected: client alerts the child and the guardian
4. If the person refuses the "Signet me" challenge: that refusal is itself a warning signal
5. Guardian can be automatically notified with location data if a meetup is planned

**Defence — The absence of age proof is itself a signal:**
- An adult with a Persona credential but NO age-range proof contacting a child in a mixed space → client can flag: "This person has not verified their age"
- A verified adult contacting a child → client can flag: "This is a verified adult"
- In both cases, **today's systems show nothing** — everyone is an anonymous avatar

#### 12.1.6 Attempt: Use AI-generated documents

1. Use AI to generate a convincing birth certificate or child passport
2. Present it to a professional for Tier 4 verification

**Defence:**
- The professional sees the actual person. AI can generate documents but not a 14-year-old human body.
- Professionals are trained in document verification (watermarks, holograms, UV features, paper stock)
- Where registry APIs exist, the professional cross-checks the document number against official records
- Anomaly detection: a professional who issues an unusual number of child credentials gets flagged

#### 12.1.7 Summary: Why Grooming Is Harder With Signet

| Step in grooming process | Today | With Signet |
|---|---|---|
| Create fake child identity | Trivial (set bio) | Impossible without professional verification |
| Enter child-safe spaces | Self-declare age | Requires Tier 4 + Bulletproof age range proof |
| Build trust with real children | No verification barrier | Credential shows entity type and verified age range |
| Initiate private contact | No restrictions | Guardian-gated DMs, age-gap warnings |
| Suggest meeting | No safeguards | "Signet me" challenge, guardian notification, age verification |
| Ongoing deception | Indefinite | Anomaly detection, guardian oversight, re-verification prompts |

**The fundamental shift:** Today, an adult must be CAUGHT pretending to be a child. With Signet, an adult must PROVE they are a child — and that proof requires fooling a professional in person, which is near-impossible for the age-gap scenario.

### 12.2 Attack Vector 2: Child Pretending to Be an Adult

**The attack today (no Signet):** Click "I am 18+." Done. Every age gate on the internet is a checkbox. Children access pornography, gambling, alcohol sales, and other age-restricted services with zero friction.

**The attack with Signet — how a child would try:**

#### 12.2.1 Attempt: Create a Tier 1 account claiming to be adult

1. Child creates a new keypair
2. No age-range proof exists on this credential
3. Tries to access an adult-only community

**Defence:** An adult-only community policy requires:
```jsonc
["adult-min-tier", "3"],
["require-adult-proof", "true"]
```
This means: you need a Tier 3+ credential AND a proof that you are NOT a child (either no age-range tag — meaning adult verification — or an age-range proof showing 18+). A Tier 1 account has neither. Rejected.

**But wait — what if the adult community only requires Tier 1?** Then yes, a child could enter. But this is the community's choice. Communities that don't care about age verification will exist, just as websites without age gates exist today. Signet provides the mechanism; communities choose whether to enforce it.

#### 12.2.2 Attempt: Get vouched as an adult at Tier 2

1. Child gets friends/strangers to vouch for them
2. Claims to be 18+ in vouching context

**Defence:** Same as grooming defence — Tier 2 vouches don't include age proofs. A community requiring adult age verification needs professional-signed age data. Social vouching doesn't provide it.

#### 12.2.3 Attempt: Use a parent's or older sibling's credentials

1. Child borrows parent's phone
2. Uses parent's Signet-verified keypair to access adult content

**Defence (partial — same as any auth system):**
- Biometric lock on device and on Signet key access (fingerprint, face ID)
- Key stored in secure enclave, not exportable
- Client can require re-authentication for age-restricted access
- **Honest limitation:** If a child knows their parent's unlock credentials, this attack works — same as a child using a parent's Netflix login or finding their parent's ID card. No system fully prevents physical access sharing within a household.

#### 12.2.4 Attempt: Use a fake or stolen adult document

1. Physically mature 16-year-old uses older sibling's passport
2. Visits a professional for adult Tier 3 verification

**Defence:**
- Professional compares photo to person — older sibling's passport photo should differ
- **Nullifier collision:** When the real sibling later tries to get verified, the nullifier matches → duplicate detected. One credential must be revoked. Investigation reveals the fraud.
- **Honest limitation:** A 17-year-old who closely resembles their 19-year-old sibling might fool the photo check. This is the same attack that works against bartenders, bouncers, and passport control. Signet is not worse than existing systems here — it's roughly equivalent.

#### 12.2.5 Attempt: Create a second keypair without age range

1. Child already has a Tier 4 credential with age-range "13-17" on keypair A
2. Creates a new keypair B
3. Gets keypair B verified at Tier 3 (adult, no age range) using the same documents

**Defence: The nullifier.** Both credentials would use the same government document (passport, birth certificate). The nullifier `H(document_type || country_code || document_number || "signet-uniqueness-v1")` is deterministic. When the second credential is issued, the nullifier already exists on-chain attached to a Tier 4 child credential. The system detects the duplicate and rejects it.

The child would need a DIFFERENT document to generate a different nullifier — but:
- Their passport says their date of birth (professional checks this)
- Their birth certificate says their date of birth
- Any document that truthfully identifies them reveals they're a minor
- A forged document with a fake DOB is the only remaining attack (see §12.2.4)

#### 12.2.6 Attempt: Wait and re-verify at 18

1. Child waits until they're 18
2. Gets legitimately verified as an adult

**Defence: This isn't an attack — it's the intended flow.** When someone turns 18, they SHOULD be able to access adult content. The child → adult transition (§10.4.3) handles this cleanly. The age-range proof in the old Tier 4 credential expires naturally, and a professional issues a new Tier 3 adult credential.

#### 12.2.7 Attempt: Exploit the Persona layer

1. Child has Tier 4 child credential on keypair A
2. Creates a Persona on keypair B
3. The Persona has no age-range tag (because Personas don't carry demographic data by default)
4. Tries to use the age-range-free Persona to access adult content

**Defence — critical design decision:**

**A Persona credential issued from a child verification ceremony MUST carry the age-range proof.** This is already specified in §10.4.1:
```jsonc
// Child's Persona credential:
["entity-type", "persona"],
["tier", "4"],
["age-range", "8-12"]
```

The age-range is mandatory on the Persona for precisely this reason. If the Persona lacked age data, it would be a clean bypass. The professional signs the age range onto BOTH credentials (Natural Person and Persona) during the child verification ceremony.

**What about creating a NEW Persona later (not through the ceremony)?**
- Creating a Persona requires an identity bridge (kind 30476) from an existing credential
- The identity bridge inherits the tier and age-range from the source credential
- A child's identity bridge carries the age restriction forward
- The ring signature proves the Persona is linked to a verified identity — and that identity includes age data

#### 12.2.8 Summary: Why Age Bypass Is Harder With Signet

| Method children use today | Works? | Signet equivalent | Works? |
|---|---|---|---|
| Click "I am 18+" | Yes (always) | Create Tier 1, claim adult | No — community requires Tier 3+ |
| Use parent's account | Yes (common) | Use parent's key | Partially — biometrics help but not foolproof |
| Lie about DOB on signup | Yes (always) | Get vouched as adult | No — vouches don't include age proofs |
| Use fake ID at a shop | Sometimes | Use fake documents with professional | Harder — nullifier + in-person + professional training |
| Use older sibling's ID | Sometimes | Use sibling's passport for verification | Harder — nullifier detects when sibling verifies |
| No enforcement exists | Most platforms | No age verification policy set | Yes — but community's explicit choice |

**The fundamental shift:** Today, children must be CAUGHT accessing adult content (which essentially never happens). With Signet, children must PROVE they are adults — and that proof requires either a genuinely verifying professional to make an error, or a forged document to go undetected. The barrier goes from zero to substantial.

### 12.3 Design Requirements for Child-Safe Clients

Signet provides the data. Clients must use it. The following are RECOMMENDED client behaviours for any Nostr client that implements Signet:

#### 12.3.1 Mandatory Displays

| Credential state | Client MUST show |
|---|---|
| Tier 4 + age-range 0-12 | "Verified Child" + guardian info |
| Tier 4 + age-range 13-17 | "Verified Teen" + guardian info |
| Tier 3 + no age-range | "Verified Adult" |
| Tier 1-2 + no age-range | "Unverified Age" |

#### 12.3.2 Guardian Controls

Clients SHOULD provide guardian configuration:

| Setting | Options | Default |
|---|---|---|
| Adult DM policy | `block` / `approve-only` / `notify` / `allow` | `notify` |
| Adult group chat policy | `block` / `notify` / `allow` | `notify` |
| Meeting detection | `on` / `off` | `on` |
| Content filter level | `strict` / `moderate` / `off` | `strict` for under-13, `moderate` for 13-17 |
| "Signet me" on first contact | `required` / `suggested` / `off` | `suggested` |
| Location sharing to guardian | `on-meetup` / `always` / `off` | `on-meetup` |

#### 12.3.3 Age-Gap Contact Warnings

When an adult-credentialed user initiates private contact with a child-credentialed user, clients SHOULD:

1. **Warn the child:** "This person is verified as an adult. Be cautious about sharing personal information."
2. **Notify the guardian** (per guardian settings)
3. **Log the contact initiation** for potential review (client-local, not on-chain)
4. **Offer "Signet me"** as a verification step

#### 12.3.4 Community Policy Templates

Pre-built policy templates for common scenarios:

**Child-Safe Community (under-13):**
```jsonc
{
  "child-min-tier": 4,
  "require-age-range": true,
  "max-age": 12,
  "adult-roles": ["moderator", "guardian"],
  "adult-dm-policy": "guardian-approved-only"
}
```

**Teen Community (13-17):**
```jsonc
{
  "child-min-tier": 4,
  "require-age-range": true,
  "min-age": 13,
  "max-age": 17,
  "adult-roles": ["moderator", "guardian", "mentor"],
  "adult-dm-policy": "notify-guardian"
}
```

**Adult-Only Community (18+):**
```jsonc
{
  "adult-min-tier": 3,
  "require-adult-proof": true,
  "min-age": 18
}
```

**Mixed-Age Community (family-friendly):**
```jsonc
{
  "min-tier": 2,
  "age-gap-dm-warning": true,
  "guardian-notify-on-adult-contact": true
}
```

### 12.4 The "Signet Me" Defence for Child Safety

The time-based word verification system gains specific value in child safety:

**Scenario: Online contact suggests meeting up**

1. Either child or client initiates "Signet me" challenge
2. Both parties must produce the correct time-based words for their keypair
3. The words prove the person currently holding the device matches the credential
4. If the adult's words verify against an adult credential → age gap revealed
5. If the person cannot produce words → they may not be who they claim

**Scenario: Ongoing contact verification**

A child's client can periodically prompt "Signet me" challenges for contacts, especially:
- New contacts (first week)
- Before any meetup
- When conversation patterns change (detected client-side)
- When a guardian requests verification

This doesn't prevent all attacks, but it raises the cost of impersonation. An attacker using a stolen child credential must have continuous access to the child's device. An attacker using a proxy child must have the child present for every challenge.

### 12.5 What Signet Cannot Prevent (Honest Assessment)

| Attack | Can Signet prevent it? | Why not |
|---|---|---|
| Adult using child's unlocked device | No | Same as any auth system — physical access defeats digital controls |
| Adult grooming child in public (physical world) | No | Signet is digital — it can't prevent physical-world approaches |
| Adult grooming through platforms that don't implement Signet | No | Signet is opt-in — platforms must choose to implement it |
| Determined attacker with forged documents who fools a professional | Unlikely but not impossible | Professionals are human — multi-signal verification reduces but doesn't eliminate this |
| Child who convinces an adult to share credentials | No | Social engineering within trusted relationships is always possible |
| Grooming via voice/video call where no credential check occurs | No | Real-time communication doesn't inherently involve credential presentation |

**The honest framing:** Signet does not eliminate child safety risks. It makes the two most common attacks — adult pretending to be a child, and child bypassing age gates — dramatically harder by replacing self-declaration with professional verification and zero-knowledge age proofs. It provides guardians with tools that don't exist today. It gives child-safe communities enforceable policies instead of trust-based-on-nothing. It shifts the baseline from "everyone lies about age and nothing prevents it" to "age claims are cryptographically backed and verifiable."

### 12.6 The Comparison: Today vs Signet

| Dimension | Today | With Signet |
|---|---|---|
| Age verification | "Click if you're 18+" (useless) | Bulletproof age-range proof from professional verification |
| Adult in child space | Self-declare age, enter freely | Requires Tier 4 + age proof — professional must verify |
| Child in adult space | Click checkbox, enter freely | Requires Tier 3+ adult proof — child's age-range proof blocks entry |
| Guardian awareness | None — parents don't know who contacts their child | Guardian tags, DM notifications, contact approval, meeting alerts |
| Predator detection | Reactive — caught after harm | Proactive — age-gap warnings, contact patterns, "Signet me" |
| Identity of contacts | Completely unknown | Entity type + tier + age range visible to clients |
| Meeting safety | Nothing | "Signet me" challenge, guardian notification, age verification |
| Accountability | Anonymous, disposable accounts | Nullifier prevents unlimited new identities, professional vouches for verifier |

## 13. Open Questions

1. **Should domain proof be REQUIRED or just weighted?** If required, it blocks professionals without websites. If optional, the Sybil mesh attack still works for the cross-verification-only path.

   **Tentative answer:** Required for verifier activation (as a minimum second signal beyond cross-verification). Professionals without websites can use registry cross-check or body attestation instead. At least ONE additional signal beyond cross-verification must be present.

2. **How do we handle professional body key distribution?** A professional body's Nostr pubkey needs to be discoverable and verifiable. NIP-05 on their official domain is a good start, but what if someone registers a lookalike domain?

   **Tentative answer:** Professional body pubkeys should be published via multiple channels: NIP-05 on official domain, their official website, press releases. Clients can hardcode known body pubkeys (like browser root certificates). A curated list of verified body pubkeys could be maintained as a community resource.

3. **What happens when a professional changes firms (and domains)?** The domain proof points to a specific website. If the professional leaves that firm, the proof breaks.

   **Tentative answer:** Domain proofs have implicit freshness — clients should re-verify periodically (e.g., every 90 days). When a proof goes stale, the verifier's confidence score drops but their credentials remain valid. They re-establish the proof on their new firm's domain.

4. **How aggressive should Sybil detection be?** False positives (flagging legitimate verifiers) damage trust in the system. False negatives (missing Sybil clusters) enable fraud.

   **Tentative answer:** Conservative. Flag for human review, don't auto-block. The anomaly signals produce warnings that communities and clients can act on. Better to let a few suspicious verifiers through (with low confidence scores) than to block legitimate professionals.

## 14. Original Adoption Roadmap

**Phase 1 (Now — launch):**
- Domain proof mechanism implemented
- Cross-verification + domain proof required for activation
- Registry cross-check where APIs exist (SRA, NPPES)
- Founding verifier ceremony protocol documented
- Basic Sybil detection (cluster simultaneity, full connectivity)

**Phase 2 (6-12 months):**
- Outreach to professional bodies for attestation adoption
- Enhanced Sybil detection (trust propagation, geographic analysis)
- Community-maintained list of verified professional body pubkeys
- Cross-jurisdiction bootstrap events

**Phase 3 (12-24 months):**
- eIDAS 2.0 QEAA integration (professional bodies required to expose APIs by December 2026)
- Professional body attestation becomes the primary signal for new jurisdictions
- Domain proof remains as supplementary signal
- Advanced graph analysis with historical pattern detection

## 15. Why This Works (Threat Model Revisited)

**Against simple impersonation:**
Domain proof raises the cost from "look up a public licence number" to "hack a professional's website." Registry cross-check catches non-existent licence numbers. Body attestation eliminates impersonation entirely.

**Against Sybil mesh:**
Cross-verification alone is no longer sufficient. Each fake verifier also needs a domain proof (requires hacking multiple professional websites) or registry confirmation or body attestation. A mesh of 10 fake verifiers now requires compromising 10 professional websites.

**Against slow-burn infiltration:**
Network position analysis detects isolated clusters. Trust anchor propagation assigns low scores to nodes connected through few edges. Anomaly detection flags suspicious issuance patterns.

**Against government coercion of professional bodies:**
Domain proof works without body participation. Cross-jurisdiction verifiers provide independent trust paths. Multiple signals mean no single institution can gatekeep. This directly supports the adversarial resilience principles in §18.

**The key insight:** Each layer doesn't need to be perfect. It needs to make the attack *more expensive* than the alternative (impersonating someone in the physical world, which has its own costs and risks). The goal is not cryptographic certainty — it's economic deterrence through layered defence.

## 16. Professional Directory Verification (Additional Signal)

### 16.1 The Opportunity

Professionals are already listed in directories that publish their credentials, websites, and affiliations. Many of these directories have editable profile fields where a Nostr pubkey or Signet verification URL could be added. This creates an additional corroboration signal: if a professional's pubkey appears on their listing in an established directory, it's harder to impersonate them.

This is similar to the domain proof (Signal 2) but doesn't require the professional to own a website — just a profile on an existing directory.

### 16.2 Directories With Self-Editable URL Fields

**High suitability (free, self-editable, custom URLs confirmed):**

| Directory | Profession | Editable Field | Coverage |
|---|---|---|---|
| **Avvo** | Lawyers (US) | 4-5 custom URLs with labels | Major US directory |
| **Justia** | Lawyers (US) | Websites and social media | Free, fully editable |
| **Doximity** | Physicians (US) | "Links" section — arbitrary URLs | ~50% of US physicians |
| **LinkedIn** | All professions | Up to 3 website URLs with "Other" label | Global, cross-profession |

**Moderate suitability (paid or limited):**

| Directory | Profession | Notes |
|---|---|---|
| Martindale-Hubbell | Lawyers (US/intl) | Full edit at ~$399/mo; free tier is request-based |
| Healthgrades | Physicians (US) | Website link is paid tier; free-text description exists |
| Zocdoc | Physicians (US) | Website URL field; primarily a booking platform |
| FindLaw | Lawyers (US) | Website link in listing; depth of customization unclear |

**Not suitable (regulatory registers, no editable URL):**

SRA Register, GMC Register, Bar Standards Board Register, AICPA Directory, AMA Profiles — these are compliance records, not marketing profiles. No individual-level URL fields.

### 16.3 The UK Gap

UK regulatory bodies (SRA, GMC, ICAEW) maintain compliance registers with no individual-level URL or social media fields. UK professionals would need to rely on:
- LinkedIn (universally available, cross-profession)
- Their firm's website (domain proof)
- Consumer-facing directories with UK coverage (limited)

This reinforces why domain proof and LinkedIn-style directory proof should both be supported as verification signals.

### 16.4 Directory Proof Mechanism

A professional adds a URL to their directory profile:
```
https://signet.example/verify/npub1abc...
```
or simply includes their npub in a free-text bio/description field.

**Automated audit:** A Signet client or auditing service can:
1. Fetch the verifier's kind 30473 event
2. Check the `["directory-proof", "<directory_url>"]` tag
3. Fetch the directory profile page
4. Verify the pubkey or verification URL appears on the page
5. Record the result as a verification signal

This is weaker than domain proof (the professional doesn't control the directory infrastructure) but stronger than nothing (the directory has its own verification of who can edit a profile).

### 16.5 Tag Addition

Kind 30473 gains an optional tag:
```jsonc
["directory-proof", "<url_to_directory_profile>"]
```

Multiple directory-proof tags may be present (a lawyer on both Avvo and LinkedIn).

## 17. Political and Public Official Adoption

### 17.1 We Don't Need 100% — Just Seeds

The entire web-of-trust model works by seeding trust and letting it propagate. A single MP who publishes their Nostr pubkey on their official parliament page becomes a trust anchor that can verify (or be verified by) professionals in their constituency. A few early adopters create the nucleus.

### 17.2 UK Parliament — Technical Feasibility

The UK Parliament Members API (`members-api.parliament.uk`) uses a flexible type-based contact system. Social media platforms are stored as contact entries with distinct `typeId` values (e.g., Website = 6, X/Twitter = 7). The system is generic — adding a "Nostr" typeId is architecturally straightforward.

**Current fields available per MP:**
- Parliamentary office (address, phone, email)
- Website URL
- X (formerly Twitter)
- Additional social media (Instagram, Facebook, YouTube — typeId values vary by member)
- `notes` field per contact entry

**What would be needed:** A new `typeId` for Nostr (or a generic "Cryptographic Identity" type). This is an administrative change, not a technical one. An MP could also use their existing Website field to link to a page containing their pubkey.

**No MP has published a Nostr pubkey on parliament.uk** (or any official government page anywhere in the world, as of our research). The precedent closest to this is Mastodon handles appearing in the `unitedstates/congress-legislators` community dataset — several US House members have Mastodon accounts listed.

### 17.3 US Congress

**Congress.gov API** — provides `officialUrl` only, no social media fields.

**`unitedstates/congress-legislators`** (community-maintained GitHub dataset) — tracks Twitter, Facebook, YouTube, Instagram, and **Mastodon** for current legislators. No `nostr` field exists yet. Adding one would be a simple PR to the repository (YAML schema change + population as members adopt).

**Individual member pages** (house.gov, senate.gov) are self-managed by each office. An MP/representative could add a Nostr pubkey to their own page at their discretion.

### 17.4 UK Local Councils

Local councils overwhelmingly use **ModernGov** (by GOSS Interactive) for councillor directories. The platform is rigid: name, party, ward, email, phone. No social media, no website, no custom fields. **Not currently viable** for Nostr pubkey publication without platform changes.

### 17.5 Politicians Already on Nostr

No politicians are confirmed on Nostr with official pubkeys. Notable non-politician public figures on Nostr include Edward Snowden and Jack Dorsey. The platform's user base is concentrated in the Bitcoin/cypherpunk community.

**The Mastodon precedent is instructive:** Several US House members adopted Mastodon, the community dataset added a field for it, and it became a normal part of the political social media landscape. The same path is available for Nostr — it just needs the first adopters.

### 17.6 Strategy: Target Crypto-Friendly Politicians

Rather than seeking broad political adoption, target politicians who are already aligned:
- UK: Members of APPG on Blockchain, crypto-friendly MPs
- US: Sen. Cynthia Lummis (WY), Rep. Tom Emmer (MN), members of the Congressional Blockchain Caucus
- El Salvador: Government officials involved in Bitcoin legal tender implementation
- EU: MEPs involved in MiCA regulation who understand digital identity

A single crypto-friendly MP publishing their Nostr pubkey on parliament.uk creates:
1. A trust anchor for their constituency
2. A precedent for other MPs
3. Media coverage for Signet/Nostr adoption
4. A proof point that the parliament.uk system can accommodate cryptographic identity

## 18. Professional Identity Theft — The Advocacy Angle

### 18.1 Overview

Professional identity theft is a growing and underreported problem. Fraudsters impersonate licensed professionals to commit fraud, provide unlicensed services, or establish false credentials. This is the *exact attack* that Signet's verifier bootstrapping must defend against — and it's already happening in the physical world.

### 18.2 Why This Matters for Adoption

Positioning Signet as a solution to professional identity theft serves two purposes:
1. **Technical:** It motivates the multi-signal authentication design — the problem is real, not theoretical
2. **Political:** It gives professional bodies and regulators a reason to adopt Signet — they're already looking for solutions to this problem

### 18.3 Deep Dive Report

**Completed:** See `docs/reports/2026-03-04-professional-identity-fraud-deep-dive.md`

The report covers statistics, case studies ($47B US identity fraud losses, £11.7M UK conveyancing fraud, 22-year fake NHS doctor), economic losses, regulatory gaps, and how Signet's multi-signal verifier authentication directly addresses the identified threats. Intended as advocacy material for engaging professional bodies and regulators.

## 19. Updated Adoption Roadmap (Revised)

**Phase 1 (Now — launch):**
- Domain proof mechanism (`.well-known/signet.json`)
- Directory proof mechanism (Avvo, LinkedIn, Doximity, Justia)
- Cross-verification + at least one additional signal for activation
- Registry cross-check where APIs exist (SRA, NPPES)
- Founding verifier ceremony protocol
- Basic Sybil detection

**Phase 2 (3-6 months):**
- Target crypto-friendly politicians for early pubkey publication
- Produce professional identity theft report for advocacy
- PR to `unitedstates/congress-legislators` to add `nostr` field
- Outreach to Avvo/Justia/Doximity for potential Signet integration
- Enhanced Sybil detection (trust propagation, geographic analysis)

**Phase 3 (6-12 months):**
- Professional body outreach with identity theft report as ammunition
- Community-maintained list of verified body pubkeys
- Cross-jurisdiction bootstrap ceremonies
- Parliament.uk engagement for Nostr typeId addition

**Phase 4 (12-24 months):**
- eIDAS 2.0 QEAA integration (authentic source APIs mandatory by December 2026)
- Professional body attestation as primary signal
- National-scale verifier network with graph analysis
- Political adoption creating trust anchors across jurisdictions
