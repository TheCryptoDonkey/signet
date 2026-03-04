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

## 10. Open Questions (Revised)

1. **Should domain proof be REQUIRED or just weighted?** If required, it blocks professionals without websites. If optional, the Sybil mesh attack still works for the cross-verification-only path.

   **Tentative answer:** Required for verifier activation (as a minimum second signal beyond cross-verification). Professionals without websites can use registry cross-check or body attestation instead. At least ONE additional signal beyond cross-verification must be present.

2. **How do we handle professional body key distribution?** A professional body's Nostr pubkey needs to be discoverable and verifiable. NIP-05 on their official domain is a good start, but what if someone registers a lookalike domain?

   **Tentative answer:** Professional body pubkeys should be published via multiple channels: NIP-05 on official domain, their official website, press releases. Clients can hardcode known body pubkeys (like browser root certificates). A curated list of verified body pubkeys could be maintained as a community resource.

3. **What happens when a professional changes firms (and domains)?** The domain proof points to a specific website. If the professional leaves that firm, the proof breaks.

   **Tentative answer:** Domain proofs have implicit freshness — clients should re-verify periodically (e.g., every 90 days). When a proof goes stale, the verifier's confidence score drops but their credentials remain valid. They re-establish the proof on their new firm's domain.

4. **How aggressive should Sybil detection be?** False positives (flagging legitimate verifiers) damage trust in the system. False negatives (missing Sybil clusters) enable fraud.

   **Tentative answer:** Conservative. Flag for human review, don't auto-block. The anomaly signals produce warnings that communities and clients can act on. Better to let a few suspicious verifiers through (with low confidence scores) than to block legitimate professionals.

## 11. Original Adoption Roadmap

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

## 12. Why This Works (Threat Model Revisited)

**Against simple impersonation:**
Domain proof raises the cost from "look up a public licence number" to "hack a professional's website." Registry cross-check catches non-existent licence numbers. Body attestation eliminates impersonation entirely.

**Against Sybil mesh:**
Cross-verification alone is no longer sufficient. Each fake verifier also needs a domain proof (requires hacking multiple professional websites) or registry confirmation or body attestation. A mesh of 10 fake verifiers now requires compromising 10 professional websites.

**Against slow-burn infiltration:**
Network position analysis detects isolated clusters. Trust anchor propagation assigns low scores to nodes connected through few edges. Anomaly detection flags suspicious issuance patterns.

**Against government coercion of professional bodies:**
Domain proof works without body participation. Cross-jurisdiction verifiers provide independent trust paths. Multiple signals mean no single institution can gatekeep. This directly supports the adversarial resilience principles in §18.

**The key insight:** Each layer doesn't need to be perfect. It needs to make the attack *more expensive* than the alternative (impersonating someone in the physical world, which has its own costs and risks). The goal is not cryptographic certainty — it's economic deterrence through layered defence.

## 13. Professional Directory Verification (Additional Signal)

### 13.1 The Opportunity

Professionals are already listed in directories that publish their credentials, websites, and affiliations. Many of these directories have editable profile fields where a Nostr pubkey or Signet verification URL could be added. This creates an additional corroboration signal: if a professional's pubkey appears on their listing in an established directory, it's harder to impersonate them.

This is similar to the domain proof (Signal 2) but doesn't require the professional to own a website — just a profile on an existing directory.

### 13.2 Directories With Self-Editable URL Fields

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

### 13.3 The UK Gap

UK regulatory bodies (SRA, GMC, ICAEW) maintain compliance registers with no individual-level URL or social media fields. UK professionals would need to rely on:
- LinkedIn (universally available, cross-profession)
- Their firm's website (domain proof)
- Consumer-facing directories with UK coverage (limited)

This reinforces why domain proof and LinkedIn-style directory proof should both be supported as verification signals.

### 13.4 Directory Proof Mechanism

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

### 13.5 Tag Addition

Kind 30473 gains an optional tag:
```jsonc
["directory-proof", "<url_to_directory_profile>"]
```

Multiple directory-proof tags may be present (a lawyer on both Avvo and LinkedIn).

## 14. Political and Public Official Adoption

### 14.1 We Don't Need 100% — Just Seeds

The entire web-of-trust model works by seeding trust and letting it propagate. A single MP who publishes their Nostr pubkey on their official parliament page becomes a trust anchor that can verify (or be verified by) professionals in their constituency. A few early adopters create the nucleus.

### 14.2 UK Parliament — Technical Feasibility

The UK Parliament Members API (`members-api.parliament.uk`) uses a flexible type-based contact system. Social media platforms are stored as contact entries with distinct `typeId` values (e.g., Website = 6, X/Twitter = 7). The system is generic — adding a "Nostr" typeId is architecturally straightforward.

**Current fields available per MP:**
- Parliamentary office (address, phone, email)
- Website URL
- X (formerly Twitter)
- Additional social media (Instagram, Facebook, YouTube — typeId values vary by member)
- `notes` field per contact entry

**What would be needed:** A new `typeId` for Nostr (or a generic "Cryptographic Identity" type). This is an administrative change, not a technical one. An MP could also use their existing Website field to link to a page containing their pubkey.

**No MP has published a Nostr pubkey on parliament.uk** (or any official government page anywhere in the world, as of our research). The precedent closest to this is Mastodon handles appearing in the `unitedstates/congress-legislators` community dataset — several US House members have Mastodon accounts listed.

### 14.3 US Congress

**Congress.gov API** — provides `officialUrl` only, no social media fields.

**`unitedstates/congress-legislators`** (community-maintained GitHub dataset) — tracks Twitter, Facebook, YouTube, Instagram, and **Mastodon** for current legislators. No `nostr` field exists yet. Adding one would be a simple PR to the repository (YAML schema change + population as members adopt).

**Individual member pages** (house.gov, senate.gov) are self-managed by each office. An MP/representative could add a Nostr pubkey to their own page at their discretion.

### 14.4 UK Local Councils

Local councils overwhelmingly use **ModernGov** (by GOSS Interactive) for councillor directories. The platform is rigid: name, party, ward, email, phone. No social media, no website, no custom fields. **Not currently viable** for Nostr pubkey publication without platform changes.

### 14.5 Politicians Already on Nostr

No politicians are confirmed on Nostr with official pubkeys. Notable non-politician public figures on Nostr include Edward Snowden and Jack Dorsey. The platform's user base is concentrated in the Bitcoin/cypherpunk community.

**The Mastodon precedent is instructive:** Several US House members adopted Mastodon, the community dataset added a field for it, and it became a normal part of the political social media landscape. The same path is available for Nostr — it just needs the first adopters.

### 14.6 Strategy: Target Crypto-Friendly Politicians

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

## 15. Professional Identity Theft — The Advocacy Angle

### 15.1 Overview

Professional identity theft is a growing and underreported problem. Fraudsters impersonate licensed professionals to commit fraud, provide unlicensed services, or establish false credentials. This is the *exact attack* that Signet's verifier bootstrapping must defend against — and it's already happening in the physical world.

### 15.2 Why This Matters for Adoption

Positioning Signet as a solution to professional identity theft serves two purposes:
1. **Technical:** It motivates the multi-signal authentication design — the problem is real, not theoretical
2. **Political:** It gives professional bodies and regulators a reason to adopt Signet — they're already looking for solutions to this problem

### 15.3 Deep Dive Report

**Completed:** See `docs/reports/2026-03-04-professional-identity-fraud-deep-dive.md`

The report covers statistics, case studies ($47B US identity fraud losses, £11.7M UK conveyancing fraud, 22-year fake NHS doctor), economic losses, regulatory gaps, and how Signet's multi-signal verifier authentication directly addresses the identified threats. Intended as advocacy material for engaging professional bodies and regulators.

## 16. Updated Adoption Roadmap (Revised)

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
