# My Signet App — v2 Specification

> Status: Ready to build
> Date: 2026-03-16 (updated after Holodeck session)
> Changelog: Holodeck session resolved onboarding friction, ceremony flow, verifier model, IQ benchmarking, infrastructure funding
> This document is self-contained. No other files are needed for full context.

---

## 0. Protocol Context

This section summarises the Signet protocol — enough for anyone reading this spec to understand every decision below. The full protocol spec is at `spec/protocol.md` but is not required reading.

### 0.1 What Signet is

Signet is an open protocol for decentralised identity verification on Nostr (a decentralised social protocol). It lets people prove claims about their identity — age, parenthood, professional status — using zero-knowledge proofs, without revealing personal data or relying on a central authority. Any Nostr client can implement Signet. Any community can set verification policies. Any licensed professional can become a verifier.

**Child safety is the killer app.** A child can prove they're 8-12 years old to a game without revealing their name. A parent can prove they are the legal guardian. A deepfake caller can be detected in real time with time-based spoken words.

### 0.2 Verification tiers

| Tier | Name | How you get it | What it proves |
|------|------|---------------|----------------|
| 0 | Unverified | Create an account | Nothing — just a keypair |
| 1 | Self-declared | Sign a statement "I am an adult" | Self-attestation only (weak) |
| 2 | Peer-vouched | 3+ verified people vouch for you | Community trust (medium) |
| 3 | Professional (adult) | A solicitor/doctor/notary checks your passport | Government-grade identity |
| 4 | Professional (child) | Same + birth certificate + guardian confirmation | Child identity + legal guardian binding |

Tiers 3 and 4 are the focus of this app. They produce the two-credential ceremony (see §0.5).

### 0.3 Nostr event kinds

Signet defines 11 event kinds on the Nostr network. The ones relevant to this app:

| Kind | Name | What it is |
|------|------|-----------|
| 30470 | Credential | A signed statement about someone's identity (tier, age range, entity type). This is the core event — issued by a verifier during the ceremony. |
| 30471 | Vouch | "I've met this person" — peer endorsement. Creates Tier 2 trust. |
| 30473 | Verifier | A professional body (Law Society, medical board) confirming someone is a registered professional. Without this, credentials they issue show as "pending." |
| 30475 | Revocation | Cancel a previously issued credential. |
| 30477 | Delegation | A guardian granting scoped, time-limited permissions to another adult (e.g., grandma can approve contacts this weekend). |

All events are signed with Schnorr signatures (secp256k1). Events are published to Nostr relays but the ceremony itself is local computation — no network required.

### 0.4 Entity types

Every credential has an `entity-type` tag:

| Entity type | What it means | Key property |
|-------------|--------------|--------------|
| `natural_person` | A real, identified human | Has nullifier + Merkle root — provable, unique identity |
| `persona` | An anonymous alias | Has age range only — no name, no nullifier, no Merkle root |

A single person has BOTH — their Natural Person credential (real identity) and their Persona credential (anonymous). These are issued together in the two-credential ceremony. Clients MUST display the entity type: "Person" vs "Alias."

### 0.5 The two-credential ceremony

When a professional verifies someone, they issue TWO credentials simultaneously:

**Natural Person credential (Keypair A):**
- `entity-type`: `natural_person`
- `nullifier`: SHA-256 hash of document details (prevents same passport verifying twice)
- `merkle-root`: Root of a Merkle tree containing name, nationality, DOB, document type, nullifier
- `age-range`: e.g., `18+`, `8-12`
- `guardian` tags: parent pubkeys (if child)
- Tier: 3 (adult) or 4 (child)

**Persona credential (Keypair B):**
- `entity-type`: `persona`
- `age-range`: same as above
- `guardian` tags: same (if child)
- NO nullifier, NO merkle-root, NO name
- Tier: 3 or 4

The link between keypairs A and B is known only to the subject and the verifier, protected by professional confidentiality (solicitor-client privilege, notary secrecy, medical confidentiality).

**Nullifier computation:**
```
SHA-256(
  uint16be(len(documentType))  || documentType  ||
  uint16be(len(countryCode))   || countryCode   ||
  uint16be(len(documentNumber))|| documentNumber ||
  uint16be(len("signet-nullifier-v2")) || "signet-nullifier-v2"
)
```
The document number is NEVER stored or published. Only the one-way hash appears in the credential.

**Merkle tree (dynamic key-value leaves):**
- Core leaves: name, nationality, documentType, dateOfBirth, documentNumber, documentExpiry, nullifier
- Additional leaves vary by document type and country (see §0.8 attribute namespacing)
- Uses RFC 6962 domain separation (0x00 leaf prefix, 0x01 internal prefix)
- Only the root is published. The subject keeps the leaves and proofs privately.
- Selective disclosure: the subject can prove any single attribute (e.g., passport number to an airline, nationality to a bank) by providing the leaf + Merkle proof, without revealing the other leaves.

**Document number as a leaf:** Unlike the previous spec (which discarded the document number after nullifier computation), the document number is now stored as a Merkle leaf. This enables selective disclosure for use cases like booking flights or banking KYC. Note: revealing the document number via selective disclosure confirms the nullifier (since the nullifier is derived from the document number), but the nullifier is already public — so this creates no additional linkability.

**Document expiry as a leaf:** The document's expiry date is stored as a Merkle leaf (`signet:documentExpiry`). This enables:
- IQ scoring to apply accelerated decay after expiry (see §0.12)
- Consumers (airlines, banks) to enforce their own hard cliffs via selective disclosure
- The app to prompt renewal before expiry

**Age ranges:** `0-3 | 4-7 | 8-12 | 13-17 | 18+`

### 0.6 Guardian delegation (Kind 30477)

A guardian (parent with Tier 4 credential) can grant scoped, time-limited permissions to another verified adult:

| Scope | What it allows |
|-------|---------------|
| `full` | Everything — co-parent or trusted step-parent |
| `activity-approval` | Approve/deny child's participation in activities |
| `content-management` | Set or override content filters |
| `contact-approval` | Approve/reject new contact requests for the child |

Delegations can have an expiry timestamp. They are revocable at any time.

### 0.7 Signet IQ (trust score)

A continuous 0-200 score called the Identification Quotient. Like IQ, the distribution is non-linear — getting to 100 is straightforward, getting to 200 requires sustained effort from multiple independent sources. The score incentivizes progressive verification: each new document, each new verifier, each new connection pushes you higher, but with diminishing returns.

**Score ranges:**

| Range | Meaning | What it typically takes |
|-------|---------|----------------------|
| 0-40 | Unverified | New account, maybe some peer connections |
| 40-80 | Emerging | One professional verification |
| 80-120 | Solid | First verification + second document or peer vouches |
| 120-160 | Strong | Multiple verifiers + social proof + diverse attributes |
| 160-200 | Exceptional | Cross-verification + longevity + strong web of trust |

100 = government-acceptable standard. Most people will sit at 80-120. 200 is aspirational.

**Signal categories:**

*Professional verification (core identity):*

| Signal | First time | Diminishing returns |
|--------|-----------|-------------------|
| Professional verification (passport/ID) | 80 | — (one-time) |
| Additional document, same verifier | 15, then 8, then 4 | Same trust source |
| Additional document, different verifier | 25, then 15, then 8 | Independent confirmation — worth more |
| New attribute type (address, NI, etc.) | 10, then 8, then 5 | Supplementary attributes |
| Cross-verification (same attribute, different verifier) | 10, then 5, then 3 | Redundancy bonus |

*Web of trust (social proof):*

| Signal | Points | Cap | Notes |
|--------|--------|-----|-------|
| Connected to verified person (passive) | 2 × (their IQ / 200) each | Max 20 total | In your contacts |
| Mutual Signet Me verification | 3 × (their IQ / 200) each | Max 30 total | Both confirmed each other in real time |
| In-person vouch (Kind 30471) | 16 × (voucher's IQ / 200) each | No cap per-vouch | They put their reputation on the line |
| Online vouch | 4 × (voucher's IQ / 200) each | No cap per-vouch | Weaker than in-person |

*Longevity and bridges:*

| Signal | Points |
|--------|--------|
| Account age | 10 per year, max 30 |
| Identity bridge (cross-platform proof) | Up to 50 |

**Key scoring properties:**
- **Independence is rewarded.** Two different verifiers confirming the same identity is worth more than the same verifier confirming two documents.
- **Recursive trust.** The voucher's own IQ scales what their vouch is worth to you. A vouch from someone at IQ 160 is worth 4x more than from someone at IQ 40. Trust flows through the network.
- **Diminishing returns.** The same type of evidence contributes less each time. This prevents gaming (verifying the same passport at 10 different solicitors).
- **Self-reinforcing.** As your connections improve their IQ, your score improves too. A family that all gets verified together lifts each other.

**Example — a family getting verified together:**

Gran starts at IQ 0. She visits a solicitor with her passport → IQ jumps to 80. Her daughter (IQ 95) and son-in-law (IQ 90) both vouch for her → adds ~15. She verifies her address with a bank statement at a different solicitor → adds 25 (different verifier). After 2 years of account age → adds 20. Total: ~140. Strong.

The app shows this as a progress bar with a "next step" prompt:
```
IQ: 140 ██████████████░░
Next: Ask 2 more verified friends to vouch (+12)
```

The app does NOT show a fake score. It either shows the real computed score (when credentials and vouches are available) or shows "Unverified" with no number.

### 0.8 Progressive verification and dynamic attributes

The current protocol has a fixed 5-leaf Merkle tree (name, nationality, documentType, dateOfBirth, nullifier). The v2 model extends this to support **progressive verification** — attributes accumulated over time from different documents and different verifiers.

**Core principles:**
1. **The Merkle tree is dynamic** — arbitrary key-value pairs, not fixed leaves. A credential can have 1 leaf or 50 leaves, depending on what the verifier can confirm.
2. **Credentials are scoped** — each credential covers the attributes one verifier can confirm from one document. A passport credential has name/DOB/nationality. An address credential has address/postcode.
3. **Credentials stack** — the app accumulates verified attributes over time. A user might have 3-4 credentials from different visits, each covering different attributes.
4. **The self-declared profile is the starting point** — users enter their own details first (unverified). When they visit a professional, the verifier confirms what's already entered. Much faster than starting from scratch.
5. **Form auto-fill is the killer UX** — websites can request verified attributes. The user approves, the app shares specific Merkle proofs. No typing, no mistakes, cryptographically verified.

**Attribute namespacing (country-specific):**

| Namespace | Examples |
|-----------|---------|
| `signet:` (universal) | `signet:name`, `signet:dateOfBirth`, `signet:nationality`, `signet:address` |
| `gb:` (UK) | `gb:nationalInsurance`, `gb:nhsNumber` |
| `us:` (USA) | `us:ssn`, `us:driversLicense` |
| `in:` (India) | `in:aadhaar`, `in:pan` |
| `de:` (Germany) | `de:steuerID` |

Different countries have different ID systems. The attribute vocabulary is extensible — any verifier can add country-specific attributes.

**Dual passports / multiple documents:**

A person with British and US passports has two document nullifiers (one per passport). Each can be verified in a separate credential. Both contribute to the same identity. The protocol's `computeNullifierFamily` handles multi-document cases — one nullifier per document type + number + country.

**Example — progressive verification over time:**

| Visit | Document | Credential attributes | IQ contribution |
|-------|----------|----------------------|-----------------|
| Solicitor, March | UK passport | name, DOB, nationality, nullifier | +80 (first verification) |
| Same solicitor, March | Child's birth cert | child: age, guardian relationship | +15 (second document, same verifier) |
| Bank, June | Bank statement | address, postcode | +25 (different verifier) + 10 (new attribute type) |
| HMRC, September | Tax letter | NI number | +10 (new attribute type) |
| GP, November | Medical records | NHS number | +8 (new attribute type, diminishing) |

Total after all visits: ~148. Each visit is 3-5 minutes. The identity gets stronger over time without a single "big bang" ceremony.

### 0.9 Canary-kit

Canary-kit is a separate library (published on npm as `canary-kit`) that provides deepfake-proof spoken verification. It is the engine behind "Signet Me." Key features used by this app:

**Directional pairs:** `deriveDirectionalPair(secret, namespace, [roleA, roleB], counter, encoding)` — derives TWO different words from the same shared secret. Person A gets one word, person B gets a different word. Neither can be derived from the other without the secret. Prevents the echo attack (parroting back what you just heard).

**Spoken-clarity wordlist:** 2048 words filtered for spoken clarity — no homophones, no phonetic near-collisions, all 3-8 characters.

**Encoding options:**
- Words (1-16 words, default 1) — 11 bits per word
- PIN (1-10 digits) — for kids who find words hard
- Hex (1-64 chars) — for developer interfaces

**Features proposed but pending security review:**
- Duress tokens — a personal "safe word" that looks normal but silently signals distress
- Liveness tokens — dead man's switch heartbeats ("I'm safe")
- Encrypted location beacons — AES-256-GCM, precision-controllable
- Duress alerts — emergency location broadcast at full precision

### 0.10 Cryptographic primitives

| Primitive | Used for |
|-----------|---------|
| HMAC-SHA256 | Word derivation (canary-kit CANARY-DERIVE) |
| ECDH (secp256k1) | Shared secrets between family members |
| SHA-256 | Nullifier computation, Merkle tree |
| Schnorr signatures (secp256k1) | Event signing (Nostr standard) |
| AES-256-GCM | Encryption at rest (PBKDF2 key derivation) |
| BIP-39 | Mnemonic generation (12 words) |
| BIP-32 | HD key derivation (NIP-06 path) |

### 0.11 Verified photos

During the verification ceremony, the verifier captures or confirms a photo of the subject. This photo becomes a verified attribute — it proves the person holding the phone matches the credential.

**How it works:**
1. The person takes a selfie in the app (with guidance — face forward, good lighting, no sunglasses)
2. The verifier confirms the photo matches the person in front of them — or takes the photo themselves
3. A fresh photo is preferred over a passport photo (which may be years old and low quality)
4. The verifier uses their professional discretion on photo quality

**Storage — two layers:**

The photo always exists locally. Blossom is optional but required for some scenarios.

| Layer | What | When | Required? |
|-------|------|------|-----------|
| **Local** | Photo stored on device (IndexedDB, encrypted). Hash in the Merkle tree: `signet:photo → SHA-256(photo_bytes)` | Always — created during verification ceremony | Yes — this is the base layer |
| **Blossom** | Photo uploaded to a Blossom server (Nostr blob storage), referenced by hash. URL optionally included in credential metadata. | When the user chooses, or when a scenario requires remote access | No — user's choice |

**When Blossom is needed:**
- Integrated venue systems that fetch your photo remotely (e.g., gate scanner at a stadium)
- Any scenario where a third party needs to see your photo without you showing your phone
- Services that verify credentials server-side

**When local is enough:**
- Showing your phone at a bar or gate (person looks at your screen)
- Any in-person visual check where you're present with your device
- Offline scenarios with no connectivity

**Photo per credential (user's choice):**

| Choice | Privacy | Use case |
|--------|---------|----------|
| Photo on Natural Person only | Persona stays fully anonymous | Bank, airport — where name is required anyway |
| Photo on Persona only | Anonymous but visually verifiable | Pub, football match — age check with face match |
| Photo on both (different photos) | Unlinkable if photos differ | Maximum flexibility |
| Photo on both (same photo) | **Linkable — the app warns against this** | Convenience, but breaks persona privacy |
| No photo | Maximum privacy, no visual check | Online-only use cases |

**Pairing warning:** If the user puts the same photo on both credentials, anyone who sees both can match the hashes and link the identities. The app must warn: "Using the same photo on both identities will link them."

**Venue presentation — two modes:**

*Mode 1: Local (no infrastructure needed)*
1. Fan opens app, shows credential screen with photo + age badge
2. Steward compares face on phone screen to person in front of them
3. Works offline, works at any venue, zero infrastructure
4. Photo comes from the device's local storage

*Mode 2: Remote/Blossom (integrated venues)*
1. Ticket QR contains the fan's Persona pubkey
2. Steward/system scans the ticket QR
3. System fetches credential from relay + photo from Blossom (by hash)
4. Photo appears on the steward's screen — independent of the fan's device
5. Steward compares face to person

```
┌─────────────────────────────┐
│  GATE VERIFICATION          │
│                             │
│  ┌──────────┐               │
│  │  [Photo] │  Age: 18+ ✓   │
│  │          │  IQ: 95       │
│  └──────────┘  Tier 3       │
│                             │
│  Name: [not disclosed]      │
│  Persona credential         │
│                             │
│  [ADMIT]  [DENY]            │
└─────────────────────────────┘
```

Mode 2 is stronger because the venue system fetches the photo independently — it doesn't trust what the fan's phone displays. A fake app can't change what Blossom serves. But Mode 2 requires:
- The Persona credential published to a relay
- The photo uploaded to Blossom
- Connectivity at the venue

Most venues will start with Mode 1 (just eyeballs) and move to Mode 2 as adoption grows.

For offline venues: the person's app could show the photo + credential locally (the current flow). The steward compares visually. No Blossom fetch needed — the photo is on the person's device.

**Biometric unlock (additional protection):** The app should require FaceID / fingerprint to show credentials. Even if someone borrows the phone, they can't open the Signet app. Two layers: biometric lock (prevents casual borrowing) + verified photo (visual check by a human).

### 0.12 IQ erosion (time-based decay)

Instead of credentials having a hard 2-year expiry (verified one day, expired the next), the IQ contribution gradually decays over time. This creates a gentle incentive to renew without breaking anything overnight.

**Half-life model:**
```
contribution = basePoints × 2^(-age_years / halfLife)
```

Different signals decay at different rates because real-world confidence changes differently:

| Signal | Half-life | Rationale |
|--------|-----------|-----------|
| Document verification (passport) | 3 years | Documents valid ~10 years, but circumstances change |
| Photo | 2 years | Appearance changes faster than documents |
| Vouches | 2 years | Relationships change, people move on |
| Address verification | 1.5 years | People move frequently |
| Account age | Never decays | Factual — the account has existed since X |
| Identity bridge | 3 years | Key ownership is stable |

**Example — IQ erosion without renewal:**

| Time | Document (80) | Vouches (15) | Account age | Total IQ |
|------|:---:|:---:|:---:|:---:|
| Year 0 (fresh) | 80 | 15 | 20 | **115** |
| Year 1 | 63 | 12 | 20 | **95** |
| Year 2 | 50 | 8 | 20 | **78** |
| Year 3 | 40 | 5 | 20 | **65** |
| Year 4 | 32 | 3 | 20 | **55** |
| Year 5 | 25 | 2 | 20 | **47** |

The app nudges before the score drops too far:
```
Your IQ has dropped to 78.
Your verification is 2 years old.
Renew at your next appointment to restore your score.
```

**Why this fits the confidence model:** Over time, the probability that a verification is still accurate decreases. People change names, move countries, documents can be compromised. A 5-year-old verification is genuinely less trustworthy than a fresh one. The decay represents real-world confidence erosion.

**Accelerated decay for expired documents:** When a document's expiry date passes (available from the `signet:documentExpiry` Merkle leaf), the half-life shortens dramatically:

| Document state | Half-life |
|---|---|
| In-date | 3 years (standard) |
| Expired | 6 months (accelerated) |

An expired passport still contributes to IQ — you're still a real person. But confidence erodes faster. An out-of-date passport alongside an in-date driving licence gives a combined score where the valid document holds strong and the expired one fades gradually. This is the right model because:
- An expired document is still better than no document (the person was verified)
- Renewal takes time (6+ weeks for a passport) — a hard cliff punishes people for bureaucratic delays
- Homeless or disadvantaged users may not be able to renew immediately
- Consumers who need current document validity (airlines, banks) can enforce their own hard cliffs via selective disclosure of the expiry date — that's their business logic, not Signet's

**Signet's position: we attest to reality, we don't enforce policy.** The document expired — that's a fact in the Merkle tree. What anyone does with that fact is their decision.

**Renewal:** Same ceremony as the first time. Visit a verifier, check documents, new photo, issue new credentials. The new credential supersedes the old one. IQ jumps back up. Takes 5 minutes.

**Photo decay specifically:** A photo decays faster (2-year half-life) because appearance changes. The app could nudge: "Your verified photo is 18 months old. Update it at your next appointment." This keeps the visual check useful for venue scenarios.

### 0.13 Key design decisions already made

- **Offline-first.** The app works without a server or relay. All core features (Signet Me, QR pairing, key management) are local.
- **No central authority.** Professional bodies (Law Society, medical boards) are the trust anchors — not Signet, not any company.
- **Privacy by default.** The Persona credential proves age without revealing name. The Natural Person credential uses a Merkle tree so attributes can be selectively disclosed.
- **The protocol is audited.** The `signet-protocol` TypeScript library has been through security review. New features that touch the protocol require security team approval before merging. The app can use canary-kit directly (via Vite alias) to avoid modifying audited code.

---

## 1. What This App Is

My Signet is **the** Signet app. One app for everyone — grandparents, parents, teenagers, solicitors, doctors. It is not a "family app" or a "developer tool." It is the single interface through which people interact with the Signet identity protocol.

A separate **Signet Developer** app exists for protocol exploration, event inspection, and testing. That is not this app.

### 1.1 Design principles

- **Basic should feel complete.** A user who never opens settings should never feel like they're missing something.
- **No crypto jargon.** No "mnemonic," "pubkey," "keypair," "hex," or "relay" in any user-facing text. These concepts exist but are expressed in human terms.
- **Capabilities expand based on who you are.** The app is the same download for everyone. Features surface based on your credentials and registrations — not which SKU you installed.
- **The physical presence moment is sacred.** When someone is in the room with a professional, passport in hand — capture the verification. Don't waste it on bureaucracy that can happen later.

---

## 2. Identity Model

### 2.1 Two keypairs, always

Every user has two keypairs, derived from a single 12-word mnemonic using BIP-32 HD derivation (NIP-06):

| Keypair | Derivation path | Purpose |
|---------|----------------|---------|
| Natural Person | `m/44'/1237'/0'/0/0` | Real identity — name, verified attributes |
| Persona | `m/44'/1237'/1'/0/0` | Anonymous identity — age range only, no name |

Both keypairs are **always generated during onboarding**. The user chooses which one is their primary (day-to-day) identity. The other exists silently, ready for when it's needed.

The link between the two keypairs is known only to the user and (after verification) their verifier. It is protected by professional confidentiality.

### 2.2 Choosing a primary identity

During onboarding, the user is asked:

> "Do you want to use your real name, or a nickname?"

- **Real name** → Natural Person keypair is the primary. The Persona keypair exists but is dormant. This is the path for gran, for parents, for most people.
- **Nickname** → Persona keypair is the primary. The Natural Person keypair exists but is dormant. This is the path for teenagers, privacy-conscious users, or anyone who already has an online handle.

The user can switch their primary identity later in settings. Both keypairs share the same mnemonic backup — recovering one recovers both.

### 2.3 Data model

```typescript
interface SignetIdentity {
  id: string;                          // Primary keypair pubkey
  mnemonic: string;                    // Shared 12-word seed (encrypted at rest)
  naturalPerson: {
    publicKey: string;
    privateKey: string;                // Encrypted at rest
    displayName: string;               // Real name (e.g., "Margaret Smith")
  };
  persona: {
    publicKey: string;
    privateKey: string;                // Encrypted at rest
    displayName: string;               // Nickname (e.g., "DarkWolf99")
  };
  primaryKeypair: 'natural-person' | 'persona';
  isChild: boolean;
  guardianPubkey?: string;             // Parent's pubkey (if child)
  createdAt: number;                   // Unix timestamp
}
```

The `id` field is the pubkey of whichever keypair is currently primary.

---

## 3. Onboarding

### 3.1 Create flow

**Design principle: minimise friction to get in, maximise gravity when it matters.** Backup words are NOT shown during onboarding. They appear later, before the irreversible step of professional verification (see §6).

**Step 1 — Welcome**
```
Signet
Verified. Not identified.

[Create My Signet]
[I have my 12 backup words]
```

**Step 2 — Name choice**
```
Do you want to use your real name, or a nickname?

[Use my real name]    → goes to Step 3a
[Use a nickname]      → goes to Step 3b
```

**Step 3a — Real name (Natural Person primary)**
```
What should we call you?
Your name, a nickname, whatever you like.
You can change it anytime.

e.g. "Margaret Smith" or "DarkWolf99"

[_____________]
[Continue]
```

**Step 3b — Nickname (Persona primary)**
```
Pick a nickname.
This is how people will see you.
Your real name stays private.

[_____________]
[Continue]
```

The display name is NOT a username. It is not unique, not permanent, and not tied to any credential. It is a local label that can be changed freely at any time. The persona vs natural person distinction only matters at professional verification.

**Step 4 — Child check**
```
Is this account for a child?
Child accounts are linked to a parent for safety.

[No, this is for me]
[Yes, for a child]
```

If child → **Step 4a: Link to parent**
```
Ask the parent to open their Signet app and tap "Copy" under their Signet ID. Then paste it here.

[_____________]
[Continue]
```

**Step 5 — Done**
App detects identity exists, shows home screen. No backup words shown. The user is in.

### 3.1.1 Backup word reminders (stake-based escalation)

Backup words are never shown during onboarding. Instead, reminders escalate based on what's at stake — not on a timer:

| Trigger | Reminder |
|---|---|
| Account created, no connections | No reminder. Nothing to lose yet. |
| First family member added | Gentle first mention: "You've got connections now. If you lose this phone, you'll lose them." |
| Multiple members / regular Signet Me use | Slightly more prominent, still dismissable. |
| User taps "How verification works" | Hard gate: backup ceremony must be completed before the verification QR is generated (see §6). |

The reminder is always a small, non-blocking indicator on the home screen: "Not backed up." Tapping it opens the backup ceremony whenever they're ready. No nag, no countdown, just always visible until they act. The escalation follows the stakes, so the nudge always makes sense in context.

**The danger of over-nagging:** If we badger them too much, they'll write the words on a Post-it note just to make it go away. That's worse than not backing up at all. The reminder must feel like helpful information, not a chore.

### 3.2 Import flow

1. "Enter your 12 backup words" → validates with BIP-39
2. "Do you want to use your real name, or a nickname?" → same as create flow
3. Name input
4. Done — both keypairs derived from the imported mnemonic

### 3.3 What happens behind the scenes

On account creation:
1. Generate BIP-39 mnemonic (12 words, English wordlist)
2. Derive Natural Person keypair at `m/44'/1237'/0'/0/0`
3. Derive Persona keypair at `m/44'/1237'/1'/0/0`
4. Set primary based on user's name choice
5. Store encrypted in IndexedDB (PBKDF2 + AES-256-GCM)

No credentials are issued. No events are published. The user is Tier 0 (unverified) until they visit a professional. This is fine — Signet Me verification works without any tier.

---

## 4. Home Screen

The home screen adapts based on who you are.

### 4.1 Regular user (everyone)

```
┌─────────────────────────────┐
│ Margaret              [gear]│
│ ○ Unverified                │
│                             │
│ MY FAMILY                   │
│ ┌─────────────────────────┐ │
│ │ Tom           Verified  │ │
│ │ Tap to verify           │ │
│ ├─────────────────────────┤ │
│ │ Sophie     Child Account│ │
│ │ Tap to verify           │ │
│ └─────────────────────────┘ │
│                             │
│ YOUR SIGNET ID              │
│ npub1abc...xyz              │
│ [Copy]  [Share]             │
│                             │
│ ┌─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐  │
│   Get verified at your      │
│   next appointment →        │
│ └─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘  │
│                             │
│ [My Signet]  [+]  [Family] │
└─────────────────────────────┘
```

The "Get verified" prompt is a subtle, dashed-border card. Not a nag. Not a gate. A gentle suggestion.

### 4.2 Verified user

Same layout, but:
- Badge changes from "Unverified" to "Verified (Tier 3)" or similar
- "Get verified" card disappears
- Family members show their real tier badges

### 4.3 Registered verifier

Same layout as verified user, **plus one card**:

```
┌─────────────────────────────┐
│  Verify Someone             │
│  Tap when a patient or      │
│  client needs verifying     │
└─────────────────────────────┘
```

This card only appears after verifier activation (see §8). It is never visible to regular users.

### 4.4 Empty state (no family members)

```
Add your first family member
Once connected, you can verify each other
with Signet Me.

[Add someone]
```

---

## 5. Signet Me — Directional Verification

### 5.1 How it works

When two people are connected (via QR exchange), each person sees **different words** derived from their shared secret. This prevents the echo attack where someone parrots back what they just heard.

Uses canary-kit's `deriveDirectionalPair(secret, namespace, [myPubkey, theirPubkey], counter, encoding)`.

- Namespace: `signet:me`
- Counter: `floor(unix_seconds / 30)` — words rotate every 30 seconds
- Tolerance: ±1 counter (accepts previous/next 30-second window for clock skew)
- Roles: the two parties' pubkeys (deterministic, unique)

### 5.2 Security tiers

The number of words per side is controlled by a global setting:

| Tier | Words per side | Entropy | Use case |
|------|---------------|---------|----------|
| Basic | 1 | 11 bits (1 in 2,048) | "Is it really you?" |
| Standard | 2 | 22 bits (1 in 4.2M) | Approving something |
| Expert | 3 | 33 bits (1 in 8.6B) | High-security actions |

Default: **Basic** (1 word each). Changed in Settings → Verification Security.

### 5.3 UI — Display mode

```
┌─────────────────────────────┐
│  Signet Me                  │
│                             │
│  YOU SAY                    │
│  ┌─────────┐                │
│  │ marble  │                │
│  └─────────┘                │
│                             │
│  THEY SAY                   │
│  ┌─────────┐                │
│  │ falcon  │  (green)       │
│  └─────────┘                │
│                             │
│  Refreshes in 24s           │
│                             │
│  [Verify what they said]    │
└─────────────────────────────┘
```

Standard tier (2 words):
```
  YOU SAY
  ┌─────────┐ ┌─────────┐
  │ marble  │ │ ocean   │
  └─────────┘ └─────────┘

  THEY SAY
  ┌─────────┐ ┌─────────┐
  │ falcon  │ │ river   │
  └─────────┘ └─────────┘
```

### 5.4 UI — Verify mode

Tapping "Verify what they said" shows input fields matching the word count:

```
┌─────────────────────────────┐
│  What did they say?         │
│  ┌─────────────────────┐    │
│  │ [their word]        │    │
│  └─────────────────────┘    │
│  [Check]  [Cancel]          │
└─────────────────────────────┘
```

Results:
- **Match** → "Confirmed — it's really them." (green, auto-dismisses after 2s)
- **No match** → "Doesn't match. This might not be who they claim to be." (red, stays until dismissed)

### 5.5 Where Signet Me appears

- **Family member detail page** — prominently, at the top
- **After adding a new member** — in the success step
- **Home screen** — each family member row shows "Tap to verify" which navigates to their detail page

---

## 6. Getting Verified (Subject Side)

This is the flow for a regular user who wants to get their identity professionally verified. The flow has three phases: **education** (at home), **backup ceremony** (hard gate), and **action** (in the room with the verifier).

### 6.1 Entry point

A subtle card on the home screen (dashed border, muted text):
```
How verification works →
```

Tapping it opens the education screen. This is NOT an action — it's information. The user can read it sitting on the sofa, days before any appointment.

### 6.2 How verification works (education screen)

```
┌─────────────────────────────┐
│  How verification works     │
│                             │
│  1. Enter your details      │
│     Add your name, date of  │
│     birth, and document     │
│     info in the app.        │
│                             │
│  2. Visit a verifier        │
│     Your GP, solicitor,     │
│     teacher, accountant, or │
│     any registered          │
│     professional.           │
│                             │
│  3. They check your ID      │
│     Show your passport or   │
│     driving licence. They   │
│     confirm your details    │
│     on their phone.         │
│                             │
│  4. Done                    │
│     Takes about 3 minutes.  │
│                             │
│  [Enter my details]         │
│  [Find a verifier near me]  │
│  (future — not MVP)         │
└─────────────────────────────┘
```

### 6.2.1 Self-entry of details

The user enters their own identity details at home, at their own pace:

```
┌─────────────────────────────┐
│  My Details                 │
│                             │
│  Full name (as on document) │
│  [Margaret Anne Smith     ] │
│                             │
│  Date of birth              │
│  [22/03/1965             ]  │
│                             │
│  Nationality                │
│  [British                ]  │
│                             │
│  Document type              │
│  [Passport / ID Card / ..] │
│                             │
│  Document number             │
│  [123456789              ]  │
│                             │
│  Issuing country            │
│  [GB                     ]  │
│                             │
│  Document expiry date       │
│  [22/03/2035             ]  │
│                             │
│  [Save]                     │
└─────────────────────────────┘
```

This data is stored locally (encrypted in IndexedDB). It is NOT published, NOT sent anywhere. It will be transferred to the verifier's app during the ceremony for confirmation.

The user can add multiple documents (passport, driving licence, etc.) over time. Each becomes a separate credential after verification.

### 6.2.2 Backup ceremony (hard gate)

When the user taps **"I'm with my verifier"** (see §6.3), the app checks whether backup words have been saved. If not, the backup ceremony is triggered:

```
┌─────────────────────────────┐
│  Before you verify          │
│                             │
│  You're about to tie your   │
│  real identity to this      │
│  account. Before you do,    │
│  let's secure it properly.  │
│                             │
│  Your 12 backup words       │
│  Write these down on paper  │
│  and keep them somewhere    │
│  safe — a drawer, a safe,   │
│  NOT a Post-it note.        │
│                             │
│  If you lose your phone,    │
│  these words are the only   │
│  way to get your Signet     │
│  back.                      │
│                             │
│  1. apple     7. garden     │
│  2. river     8. marble     │
│  3. ocean     9. falcon     │
│  4. tiger    10. beacon     │
│  5. cloud    11. silver     │
│  6. brave    12. puzzle     │
│                             │
│  [ ] I've written these     │
│      down somewhere safe    │
│  [Continue]                 │
│  [Copy to clipboard]        │
└─────────────────────────────┘
```

This is the ONE moment the backup words are shown with gravity. The user understands why it matters because they're about to do something irreversible. The ceremony feels significant, not bureaucratic.

A brief screen during the flow is also shown to both parties: "Have you stored your backup words somewhere safe?" This may prompt a natural conversation with the verifier — but the verifier does not enforce it. Their role is confirmation only.

### 6.3 "I'm with my verifier" (action screen)

```
┌─────────────────────────────┐
│  I'm with my verifier       │
│                             │
│  Ask them to show you       │
│  their verifier QR code     │
│  on their phone.            │
│                             │
│  [Scan verifier's QR]       │
│                             │
│  This will send your        │
│  details to their app for   │
│  confirmation. No data      │
│  leaves your phone until    │
│  you scan.                  │
└─────────────────────────────┘
```

After scanning the verifier's QR, the user's self-entered details are transferred to the verifier's app. The verifier then confirms or rejects (see §7).

### 6.4 QR payload

The QR code contains both pubkeys:

```typescript
interface VerificationQRPayload {
  type: 'signet-verify-request';
  naturalPersonPubkey: string;   // Keypair A
  personaPubkey: string;         // Keypair B
  displayName: string;           // Current primary display name
  isChild: boolean;
  guardianPubkey?: string;       // If child, the parent's pubkey
}
```

Serialised as JSON, same pattern as the existing `createQRPayload`.

### 6.4 Receiving credentials

After the verifier runs the ceremony, credentials are delivered back to the user's app. Transport options (in priority order):

1. **QR exchange** — verifier's app shows a QR containing the two signed credential events. Subject's app scans and stores them. Works offline.
2. **Local network** — if both devices are on the same WiFi, direct transfer. Future enhancement.
3. **Nostr relay** — verifier publishes the credentials to a relay. Subject's app subscribes and receives them. Requires connectivity.

For MVP: **QR exchange only**. The verifier's app renders the two credential events as a QR code (or sequence of QR codes if too large). The subject scans and stores.

### 6.5 Pending credentials

If the verifier is not yet registered (their Kind 30473 hasn't been issued by their professional body), the credentials are still cryptographically valid — they're signed by the verifier's key. They just lack the trust chain.

The subject's app shows:

```
Verified by Dr. Patel
Registration pending — your verification will be
confirmed when Dr. Patel's professional registration
is processed. No action needed from you.
```

When the Kind 30473 appears (checked via relay or manual refresh), the status updates to:

```
Verified by Dr. Patel ✓
General Medical Council
```

The subject never needs to revisit the verifier.

### 6.6 Credential storage

Both credentials (Natural Person and Persona) are stored in IndexedDB alongside the identity:

```typescript
interface StoredCredentials {
  naturalPersonCredential?: NostrEvent;   // Kind 30470, entity-type: natural_person
  personaCredential?: NostrEvent;         // Kind 30470, entity-type: persona
  merkleLeaves?: Record<string, string>;  // Private — name, nationality, DOB, docType, nullifier
  merkleProofs?: MerkleProof[];           // For selective disclosure
  verifierPubkey?: string;               // Who issued the credentials
  verifiedAt?: number;                    // Unix timestamp
  verifierStatus: 'confirmed' | 'pending'; // Whether verifier's 30473 has been seen
}
```

The `merkleLeaves` and `merkleProofs` are private — they never leave the device unless the user explicitly chooses to disclose an attribute.

---

## 7. Verifying Someone (Professional Side)

### 7.1 Activation — hidden by design

The verifier capability is **never visible** to regular users. It is activated through a deliberate, hidden gesture — similar to Android developer mode.

**Activation method:**

1. Go to Settings
2. Scroll to "About" section at the bottom
3. Tap the version number ("My Signet v1.0.0") **5 times**
4. A prompt appears: "Enter your professional registration number"
5. User enters their GMC / SRA / notary commission number
6. A second prompt: "Select your professional body" (dropdown or search)
7. App stores the registration locally and sends a verification request to the professional body (or provides instructions for the body's website)
8. Verifier mode is now active — "Verify Someone" card appears on home screen

**Deactivation:** Settings → Verifier Settings → "Deactivate verifier mode"

The professional body's confirmation (Kind 30473 event) may arrive later. The verifier can issue credentials immediately — they will show as "pending" on recipients' apps until the 30473 is confirmed.

### 7.2 Verifier registration data

```typescript
interface VerifierRegistration {
  registrationNumber: string;        // GMC number, SRA ID, notary commission, etc.
  professionalBody: string;          // "General Medical Council", "Solicitors Regulation Authority", etc.
  profession: string;                // "doctor", "solicitor", "notary", etc.
  jurisdiction: string;              // "GB", "US-CA", "DE", etc.
  activatedAt: number;               // Unix timestamp
  verifierCredential?: NostrEvent;   // Kind 30473, when received from professional body
  status: 'pending' | 'confirmed';
}
```

### 7.3 Verify Someone flow

**Key design change:** The verifier does NOT enter any data. The subject enters their own details at home (see §6.2.1). The verifier only **confirms or rejects** what the subject entered, by comparing it to the physical documents in their hand. This eliminates fat-finger errors and keeps the verifier's role pure: "I confirm this person is real."

**Step 1 — Show verifier QR**

The verifier taps "Verify Someone" on the home screen. Their app shows a QR code identifying them as a verifier:

```
┌─────────────────────────────┐
│  Verify Someone             │
│                             │
│  Show this QR code to the   │
│  person you're verifying.   │
│  They'll scan it with       │
│  their Signet app.          │
│                             │
│  ┌───────────────┐          │
│  │               │          │
│  │   [QR CODE]   │          │
│  │               │          │
│  └───────────────┘          │
│                             │
│  Once they scan, their      │
│  details will appear here   │
│  for you to confirm.        │
└─────────────────────────────┘
```

**Step 2 — Receive subject's details**

After the subject scans the verifier's QR (from their "I'm with my verifier" screen, §6.3), the subject's self-entered details are transferred to the verifier's app. The verifier now sees:

```
┌─────────────────────────────┐
│  Verify: Margaret Smith     │
│                             │
│  Name: Margaret Anne Smith  │
│  DOB: 22 March 1965        │
│  Nationality: British       │
│  Document: Passport (GB)    │
│  Number: 123456789          │
│  Expiry: 22 March 2035      │
│                             │
│  ○ Adult account            │
│                             │
│  Compare these details to   │
│  the physical document.     │
│                             │
│  [Confirm — details correct]│
│  [Reject — details wrong]   │
│  [Cancel]                   │
└─────────────────────────────┘
```

For child accounts, additional fields are shown:
- Guardian pubkey (pre-filled from subject's app)
- The verifier confirms: "I confirm this person is the legal guardian"
- For teachers: school enrollment records serve as evidence of the parent-child relationship — a birth certificate may not be needed if the school already verified it at enrollment

**Step 3a — Rejection (no penalty)**

If the verifier taps "Reject," the details bounce back to the subject's app with an optional note:

```
┌─────────────────────────────┐
│  Details rejected           │
│                             │
│  Note from verifier:        │
│  "Passport number has a     │
│   typo — check digit 9"    │
│                             │
│  The person can fix their   │
│  details and resubmit.      │
│                             │
│  [Wait for resubmission]    │
│  [Cancel verification]      │
└─────────────────────────────┘
```

The subject fixes the error on their phone and resubmits. This loop has no penalty — it's just a correction cycle. The verifier waits.

**Step 3b — Confirmation**

If the verifier taps "Confirm," a summary is shown:

```
┌─────────────────────────────┐
│  Confirm & Issue            │
│                             │
│  Name: Margaret Anne Smith  │
│  DOB: 22 March 1965        │
│  Age range: 18+            │
│  Document: Passport (GB)   │
│  Tier: 3 (Professional)    │
│                             │
│  Two credentials will be    │
│  issued:                    │
│  • Person credential        │
│    (verified identity)      │
│  • Persona credential       │
│    (anonymous, age only)    │
│                             │
│  [Confirm & Issue]          │
│  [Back]                     │
└─────────────────────────────┘
```

**Step 4 — Credential delivery**

The ceremony runs locally on the verifier's device (`createTwoCredentialCeremony`). The credentials are transferred back to the subject's app (via the existing connection or QR):

```
┌─────────────────────────────┐
│  Credentials Issued ✓       │
│                             │
│  Margaret's credentials     │
│  have been sent to their    │
│  app.                       │
│                             │
│  [Done]                     │
└─────────────────────────────┘
```

**Step 5 — Done**

Both parties return to their home screens. The subject's credentials are stored in their app. The verifier's home screen is unchanged.

### 7.4 What happens during the ceremony

All local computation — no network required:

1. Receive subject's two pubkeys and self-entered details from the data transfer
2. Compute nullifier: `SHA-256(len||docType || len||country || len||docNumber || len||"signet-nullifier-v2")`
3. Compute age range from DOB: `0-3 | 4-7 | 8-12 | 13-17 | 18+`
4. Determine tier: `18+` → Tier 3 (adult), child range → Tier 4 (adult+child)
5. Build dynamic Merkle tree from verified attributes: name, nationality, documentType, dateOfBirth, documentNumber, documentExpiry, nullifier (plus any additional attributes the document supports)
6. Sign Natural Person credential (Kind 30470): entity-type, merkle-root, nullifier, age-range, guardian tags
7. Sign Persona credential (Kind 30470): entity-type=persona, age-range, guardian tags — NO nullifier, NO merkle-root
8. Transfer both signed events + Merkle proofs back to the subject's app

The document number is now stored as a Merkle leaf (for selective disclosure) AND used to compute the nullifier. Both appear in the credential.

### 7.5 Batch verification (family scenario)

A common scenario: a family of four visits a solicitor. The verifier flow supports rapid sequential verification:

1. Verify parent A → receive details, check passport, confirm, issue credentials
2. Verify parent B → scan QR, check passport, issue credentials
3. Verify child 1 → scan QR, check birth certificate, confirm guardian, issue credentials
4. Verify child 2 → same

Each takes 3-5 minutes. Total: ~15-20 minutes for the whole family.

The app does not have an explicit "batch mode." Each verification is independent. The speed comes from the flow being short (scan → fill form → confirm → deliver).

---

## 8. Settings

### 8.1 Structure

```
Settings
├── My Name
│   └── Display name (editable)
├── My Identity
│   ├── Primary: Real name / Nickname (switchable)
│   ├── Natural Person ID: npub1abc... [Copy]
│   └── Persona ID: npub1xyz... [Copy]
├── Verification Security
│   ├── ○ Basic — 1 word each (quick check)
│   ├── ● Standard — 2 words each (approvals)
│   └── ○ Expert — 3 words each (high security)
├── Backup Words
│   └── [View my 12 words] (hidden by default)
├── Appearance
│   └── System / Light / Dark
├── Child Accounts (if applicable)
│   └── [Manage linked children]
├── Verifier Settings (only if activated)
│   ├── Registration: GMC 1234567
│   ├── Status: Confirmed ✓ / Pending
│   └── [Deactivate verifier mode]
├── Delete My Signet
└── About
    └── My Signet v1.0.0  ← tap 5 times to activate verifier
```

### 8.2 Switching primary identity

In "My Identity," the user can switch between Natural Person and Persona as their primary. This changes:
- Which pubkey is shown as "Your Signet ID" on the home screen
- Which keypair is used for new family connections
- Which display name appears in the app header

Existing family connections are **not affected** — they are bound to the specific keypair used when the connection was made.

---

## 9. Credential Display

### 9.1 Badge on home screen

| State | Badge | Colour |
|-------|-------|--------|
| No credentials | "Unverified" | Grey |
| Credentials from pending verifier | "Pending" | Amber |
| Credentials from confirmed verifier | "Verified (Tier 3)" or "Verified (Tier 4)" | Green |
| Child with verified guardian | "Child Account ✓" | Blue |

### 9.2 Credential detail (tappable badge)

Tapping the badge shows:

```
┌─────────────────────────────┐
│  Your Verification          │
│                             │
│  Tier: 3 — Professional     │
│  Verified by: Dr. A. Patel  │
│  Issued: 14 March 2026      │
│  Expires: 14 March 2028     │
│                             │
│  Age range: 18+             │
│  Entity: Person             │
│                             │
│  Your Persona credential    │
│  proves your age without    │
│  revealing your name.       │
│                             │
│  [Share age proof]          │
│  (future — not MVP)         │
└─────────────────────────────┘
```

---

## 10. Proposed Features (Pending Security Review)

These features use canary-kit capabilities not yet integrated. They require review by the security team before implementation.

### 10.1 Duress detection (safe words)

Each person has personal "safe words" — time-based words derived from `deriveDuressTokenBytes(secret, context + ":duress", identity, counter)`. If spoken during a Signet Me verification instead of the real words, the other party's app silently shows a safety alert.

**Protocol change required:** Add `verifySignetWordsEnhanced()` to signet-protocol that returns `'valid' | 'duress' | 'invalid'`. See separate proposal: [Duress Detection Proposal](#appendix-a).

**UI:** A "Your safe words" section on the family member detail page (hidden by default, expandable).

### 10.2 Liveness check-in

One-tap "I'm safe" using canary-kit's `deriveLivenessToken`. Family members see when each person last checked in. Uses HMAC with `:alive` domain separator.

### 10.3 Shamir backup split

Split the 12-word mnemonic into 2-of-3 shares using `splitSecret`. Each share is encoded as BIP-39 words. Give one share to your partner, one to a grandparent. Any two can recover the account.

### 10.4 Location beacons (Expert tier)

Encrypted location sharing using canary-kit's `encryptBeacon`. Precision controllable: 1.2km (neighbourhood) to 3m (full precision for emergencies). AES-256-GCM encryption — only family members can decrypt.

### 10.5 Duress alerts with location (Expert tier)

If a safe word is detected, broadcast the distressed person's location at full precision to all family members. Silent, encrypted, automatic.

---

## 11. Technical Architecture

### 11.1 Data storage

All data is stored in IndexedDB with the following object stores:

| Store | Key | Contents |
|-------|-----|----------|
| `identity` | pubkey | SignetIdentity (encrypted private keys) |
| `credentials` | pubkey | StoredCredentials (signed events + Merkle proofs) |
| `family` | pubkey + index:ownerPubkey | FamilyMember (shared secrets) |
| `child-settings` | childPubkey | ChildSettings (contact policies) |
| `preferences` | `'current'` | AppPreferences (theme, tier, active account) |
| `verifier` | `'registration'` | VerifierRegistration (if activated) |

### 11.2 Canary-kit integration

The app imports canary-kit directly via Vite alias — NOT through signet-protocol. This keeps the audited protocol library untouched.

```typescript
// vite.config.ts
resolve: {
  alias: {
    'signet-protocol': path.resolve(__dirname, '../src'),
    'canary-kit': path.resolve(__dirname, '../../canary-kit/src'),
  },
}
```

Features using canary-kit:
- `deriveDirectionalPair` — directional Signet Me words
- `WORDLIST` — spoken-clarity wordlist (2048 words)

Features proposed (pending security review):
- `deriveDuressTokenBytes` — duress/safe words
- `deriveLivenessToken` — check-in heartbeats
- `encryptBeacon` / `encryptDuressAlert` — location features

### 11.3 Protocol library usage

The app uses signet-protocol for:
- `generateMnemonic` / `validateMnemonic` — BIP-39 mnemonic management
- `deriveNostrKeyPair` / `deriveChildAccount` — key derivation
- `computeSharedSecret` — ECDH for family connections
- `createQRPayload` / `parseQRPayload` — QR exchange
- `encodeNpub` — npub display
- `createTwoCredentialCeremony` — professional verification (verifier side)
- `computeNullifier` — duplicate detection

### 11.4 What requires a relay (future)

The MVP is fully offline. These features require Nostr relay connectivity:

| Feature | Why it needs a relay |
|---------|---------------------|
| Checking verifier status (Kind 30473) | To confirm pending → confirmed |
| Duplicate nullifier detection | To check if a document was already verified |
| Publishing credentials for other apps | So Fathom and other clients can see your tier |
| Receiving guardian delegation events | For cross-app delegation enforcement |
| "Find a verifier near me" | Verifier directory lookup |

---

## 12. File Structure

```
app/                                — My Signet (renamed from family-app/ on 2026-03-16)
├── src/
│   ├── main.tsx
│   ├── App.tsx                     — Router, state orchestrator
│   ├── types.ts                    — All data types
│   ├── styles/
│   │   └── global.css              — Design system
│   ├── pages/
│   │   ├── Home.tsx                — Family-first home screen
│   │   ├── Onboarding.tsx          — Two-keypair creation
│   │   ├── Family.tsx              — Family member list
│   │   ├── FamilyMember.tsx        — Member detail + Signet Me
│   │   ├── AddMember.tsx           — QR scan / enter ID
│   │   ├── GetVerified.tsx         — Subject: show QR for verifier   (NEW)
│   │   ├── VerifySomeone.tsx       — Verifier: scan, form, issue     (NEW)
│   │   ├── CredentialDetail.tsx    — View your credential             (NEW)
│   │   ├── Settings.tsx            — All settings
│   │   └── ChildSettings.tsx       — Guardian controls
│   ├── components/
│   │   ├── Layout.tsx
│   │   ├── BottomNav.tsx
│   │   ├── SignetWords.tsx         — Directional "You say / They say"
│   │   ├── WordInput.tsx           — Variable word count input
│   │   ├── QRCode.tsx
│   │   ├── QRScanner.tsx
│   │   ├── StatusBadge.tsx         — Tier-aware badge
│   │   └── TrustBar.tsx            — (unused until relay integration)
│   ├── hooks/
│   │   ├── useIdentity.ts          — Two-keypair identity management  (UPDATED)
│   │   ├── useFamily.ts
│   │   ├── useSignetMe.ts          — Directional word display
│   │   ├── usePreferences.ts       — Theme + security tier
│   │   ├── useCamera.ts
│   │   └── useCredentials.ts       — Load/store credentials           (NEW)
│   └── lib/
│       ├── db.ts                   — IndexedDB (updated schema)
│       ├── signet.ts               — Protocol library wrapper
│       ├── signet-me.ts            — Canary-kit directional pairs
│       └── crypto-store.ts         — PBKDF2 + AES-256-GCM
```

---

## 13. Backup and Recovery

### 13.1 What the mnemonic recovers

The 12-word mnemonic recovers both keypairs (Natural Person + Persona). That's the cryptographic identity. But locally-stored data — credentials, family connections, photos, Merkle proofs — needs its own backup strategy.

### 13.2 Optional Blossom/relay backup

The user can opt to back up credential data:

| Data | Backup destination | How |
|------|-------------------|-----|
| Credentials (signed events) | Nostr relay | Publish Kind 30470 events — they're already designed for relay storage |
| Merkle proofs | Blossom | Encrypted blob, referenced by hash |
| Verified photos | Blossom | Encrypted blob (already there if user opted for Blossom photo) |
| Family connections (shared secrets) | NOT backed up remotely | Re-establish via QR scan after recovery — shared secrets should never leave the device |

### 13.3 Recovery flow

1. Install app on new device
2. Import 12 backup words → keypairs recovered
3. App checks relays for any published credentials → restored automatically
4. App checks Blossom for any backed-up proofs/photos → restored if found
5. Family connections must be re-established in person (QR scan) — this is a feature, not a bug. It confirms the recovered identity is still held by the same person.

### 13.4 Shamir recovery

If the user has split their mnemonic (2-of-3 Shamir), two share holders can reconstruct the mnemonic and perform the recovery. Shares go to **people you trust** — not automatically to legal next-of-kin. This is about trust and connection, not legal succession.

### 13.5 Death / succession

When someone dies, the Shamir share holders can reconstruct the mnemonic and access the account. This is a deliberate choice made by the user when they split their backup — they chose who to trust. The app does not have an automatic inheritance mechanism. The trust graph IS the succession plan.

---

## 14. Child Aging and Credential Lifecycle

### 14.1 Date of birth, not age range

The app stores the child's **date of birth** (as entered during the verification ceremony), not a computed age range. The credential may publish an age range (`8-12`, `13-17`, `18+`) but the source of truth is the DOB, stored privately in the Merkle tree.

This matters because:
- Platforms typically require DOB (stored on their servers) — the Merkle proof for DOB can be shared selectively
- Sharing only the birth year (not full date) is significantly more private than sharing the full DOB, while still allowing age calculation
- The age range in the credential tag is a convenience — the DOB in the Merkle leaf is the authoritative attribute

### 14.2 Age boundary transitions

Age ranges in credentials are snapshots — they reflect the age at verification time. They do NOT auto-update.

When a child crosses an age boundary (e.g., turns 13, turns 18), the credential's age range becomes stale. The app can detect this (it knows the DOB) and prompt:

```
Sophie turned 13 last month.
Her credential still shows "8-12."
Visit a verifier to update her age range.
```

**No automatic ceremonies.** The user must visit a verifier to get a new credential with the updated age range. This is a deliberate design choice — age transitions are significant events (especially 18) and should involve professional confirmation, not automated updates.

### 14.3 Turning 18

When a child turns 18:
- Their Tier 4 credential (`adult+child` scope) should be superseded by a Tier 3 credential (`adult` scope)
- The `guardian` tags are removed — they are now an independent adult
- They visit a verifier with their own documents (no parent needed)
- The old credential is superseded, the new one stands alone
- Their IQ score transitions — guardian-based signals drop off, adult signals take over

The app prompts at the right time:
```
Sophie is now 18.
She can get her own adult verification.
Her child credential will be replaced
with an independent adult credential.
```

---

## 15. Document Renewal and Cross-Verification

### 15.1 Cross-verification UX (same document, new verifier)

When a user already has a verified credential and wants a second professional to confirm it (for a higher IQ score), they do NOT re-enter their details. The existing credential is reused:

1. Open app, go to documents
2. Tap the existing verified credential (e.g., passport)
3. Tap "Get additional verification"
4. Scan the new verifier's QR
5. Existing details transfer to the verifier's phone — **read-only, no editing**
6. Verifier compares to the physical document in their hand
7. Confirm — a second credential is issued with the **same nullifier**

The protocol recognises cross-verification via the nullifier: same nullifier + same pubkey + different verifier = independent confirmation of the same document. This is the most valuable IQ signal (25 points first time from a different verifier vs 15 from the same verifier for a new document).

The data is frozen from the first verification. No risk of typos or formatting differences producing a different nullifier.

### 15.2 Document renewal — new number (e.g., UK passport)

UK passport numbers **change on every renewal.** A new passport = new document number = new nullifier. The protocol treats this as a new document:

1. User receives new passport from HMPO (new number, new expiry, same name/nationality/DOB)
2. User enters the new passport as a new document in the app
3. Gets it verified by any professional
4. New credential issued with new nullifier
5. New credential **supersedes** the old one (`["supersedes", "<old_credential_id>"]`)
6. Old credential's accelerated decay becomes irrelevant — the new one has replaced it
7. IQ refreshes to full strength for that document

The nullifier family links old and new passports because both are passport-type nullifiers bound to the same pubkey. The credential chain tells the full history.

**Overlap period:** There is typically a period where both old and new passports exist (the old one is physically invalidated — corner cut off — before the new one arrives). This is a non-issue: the old credential is superseded as soon as the new one is verified. If the user hasn't renewed yet, accelerated decay on the expired credential nudges them.

### 15.3 Document renewal — same number (e.g., UK driving licence)

UK driving licence numbers **do not change on renewal.** The DVLA number is derived from name and DOB, so it stays the same for life (unless name changes). Same number = same nullifier:

1. User receives renewed photocard from DVLA (same number, new expiry)
2. In the app, tap existing driving licence credential
3. Tap "Update expiry" — change the one field
4. Get it re-verified (any professional, even the same one)
5. New credential issued, **same nullifier**, new expiry in Merkle tree
6. Old credential superseded, IQ refreshes

The protocol recognises this as re-verification: same nullifier + same pubkey = legitimate renewal. The verifier glances at the new photocard, confirms the expiry matches, signs it. Thirty seconds.

The document number is the **stable anchor** across renewals. The nullifier stays the same, the number stays the same, only the expiry rotates. Pre-filling everything except expiry makes this near-frictionless.

### 15.4 Name change (marriage, deed poll)

When a legal name changes:
- Documents are reissued with new name (passport, driving licence)
- New passport = new number = new nullifier (see §15.2)
- New driving licence = same number = same nullifier, but Merkle tree has updated name
- The supersedes chain tracks the name change: old credential (maiden name) → new credential (married name)
- The Persona credential is **unaffected** — it carries no name

### 15.5 Summary: nullifier behaviour by scenario

| Scenario | Nullifier | Pubkey | Protocol interpretation |
|---|---|---|---|
| First verification | New | User's | New identity — record it |
| Cross-verification (same doc, new verifier) | Same | Same | Independent confirmation — reward it |
| Document renewal (new number, e.g., passport) | New | Same | New document — supersedes old credential |
| Document renewal (same number, e.g., driving licence) | Same | Same | Re-verification — supersedes old credential |
| Fraud (someone else uses your document) | Same | Different | Duplicate detected — flag for investigation |
| Name change | New or Same (depends on doc type) | Same | Supersedes — name updated in Merkle tree |

---

## 16. Corrupt Verifier Handling

### 15.1 The problem

A verifier (doctor, solicitor) issues fraudulent credentials. Their professional body discovers this and revokes their Kind 30473 verifier registration.

### 15.2 Impact on issued credentials

When a verifier's registration is revoked, **all credentials they've signed become suspect.** This affects every person they verified.

**The IQ impact uses decay, not an instant cliff:**

| Time after revocation | Effect on IQ contribution |
|----------------------|--------------------------|
| Day 0 (revocation announced) | Credential contribution drops to 50% |
| Week 1 | Drops to 30% |
| Month 1 | Drops to 10% |
| Month 3 | Drops to 0% |

This 3-month decay window gives affected users time to get re-verified by a different (trustworthy) verifier. Their IQ drops gradually rather than crashing to zero overnight — they can still attend their football match tomorrow while they sort out a new verification appointment.

### 15.3 User notification

The app notifies affected users immediately:

```
Your verifier Dr. Patel has been deregistered
by the General Medical Council.

Your credentials are still valid for 3 months,
but your IQ will gradually decrease.

Get re-verified by a different professional
to maintain your score.

[Find a verifier]
```

### 15.4 Prevention through multiple verifiers

This risk is **mitigated by having credentials from multiple independent verifiers.** If one verifier is compromised:
- Credentials from other verifiers are unaffected
- The user's IQ only partially drops (the compromised portion decays, the rest holds)
- The statistical confidence model handles this naturally — removing one independent source reduces confidence but doesn't eliminate it

This is another incentive for progressive verification with different professionals. Two verifiers = resilience against one going bad.

---

## 17. PIN Mode for Kids

### 17.1 The problem

Young children can't read words like "nebula" or "falcon." The spoken-clarity wordlist is designed for adults.

### 17.2 PIN encoding

Canary-kit supports `encodeAsPin(bytes, digits)` — converting the same HMAC output into a numeric code instead of words. Same cryptography, different presentation.

### 17.3 How it works

In Settings → Verification Security, alongside the word count tiers, there's a format toggle:

```
Verification format:
  ● Words (marble, falcon)
  ○ PIN (4821)
```

When PIN mode is selected:

```
┌─────────────────────────────┐
│  Signet Me                  │
│                             │
│  YOU SAY                    │
│  ┌──────────────┐           │
│  │     4821     │           │
│  └──────────────┘           │
│                             │
│  THEY SAY                   │
│  ┌──────────────┐           │
│  │     7390     │  (green)  │
│  └──────────────┘           │
│                             │
│  Refreshes in 24s           │
└─────────────────────────────┘
```

Still directional (different PINs for each side). Still rotates every 30 seconds. Same security properties — just numbers instead of words.

### 17.4 PIN digit count follows security tier

| Tier | Words | PIN equivalent |
|------|-------|---------------|
| Basic | 1 word (11 bits) | 4 digits (~13 bits) |
| Standard | 2 words (22 bits) | 7 digits (~23 bits) |
| Expert | 3 words (33 bits) | 10 digits (~33 bits) |

### 17.5 When to use PIN mode

- Children under ~8 who can read numbers but not complex words
- Users with reading difficulties
- Any situation where numeric entry is easier (e.g., phone keypad)

The parent can set PIN mode on a per-child-account basis, or the child's account can default to PIN mode based on age range.

---

## 18. Offline Verification Trust

### 18.1 The problem

At a venue with no connectivity, the steward scans your credential QR. They can verify the Schnorr signature locally (pure maths, no network). But how do they know the verifier who signed it is legitimate, without checking the Kind 30473 on a relay?

### 18.2 Solution: local trust cache + mutual QR verification

**For venue scenarios (e.g., Belper FC):**

The venue's app/device maintains a local cache of known verifier pubkeys (downloaded when connectivity was available). When scanning a fan's credential offline, the app:

1. Verifies the credential's Schnorr signature (local, no network)
2. Checks the signing pubkey against the cached verifier list
3. If found → trusted. If not found → "unrecognised verifier" warning (not rejected — just flagged)

The cache is updated whenever the device has connectivity. For a small club, this might be "steward connects to WiFi at the clubhouse before the match."

**For person-to-person scenarios (e.g., two fans meeting):**

If both parties have the Signet app, they can verify each other through a mutual QR scan. Each person's app verifies the other's credential signature locally. If both apps have the verifier's Kind 30473 cached (from when they last had connectivity), the verification is fully trusted offline.

---

## 19. Notifications

### 19.1 When the app notifies

| Event | Notification | Priority |
|-------|-------------|----------|
| IQ score has dropped (erosion) | "Your IQ dropped to 78. Renew at your next appointment." | Low — shown on next app open |
| Incoming vouch | "Dave vouched for you. Your IQ increased." | Medium — push if enabled |
| Verifier confirmed | "Dr. Patel's registration is confirmed. Your credentials are now fully verified." | High — push if enabled |
| Verifier deregistered | "Your verifier has been deregistered. Get re-verified within 3 months." | High — push |
| Signet Me request | "Tom wants to verify you. Tap to respond." | High — push if enabled |
| Child age boundary | "Sophie turned 13. Update her credential at your next appointment." | Low — shown on next app open |
| Photo getting stale | "Your verified photo is 18 months old. Consider updating." | Low — shown on next app open |

### 19.2 Signet Me via notification

When someone wants to verify you, they don't both need to have the app open simultaneously. The flow:

1. Alice taps "Verify Tom" on her app
2. Tom gets a push notification: "Alice wants to Signet Me. Tap to respond."
3. Tom taps the notification → app opens directly to the Signet Me screen for Alice
4. Both apps now show their directional words
5. They verify over the phone as normal

**Only one person needs to launch the app first.** The other person is pulled in by the notification. This reduces friction — no "hey, open your app" coordination needed.

### 19.3 User control

Notifications are opt-in. The app works without them — events are shown on the home screen when you next open the app. Push notifications just reduce friction for time-sensitive events (Signet Me requests, verifier deregistration).

---

## 20. Accessibility

### 20.1 Design philosophy

The app defaults to an emphasis on design — clean, minimal, beautiful. Accessibility features are available within 1-2 taps from Settings, not buried deep. The accessible version should feel like a first-class experience, not an afterthought bolted on.

**The principle: design-first by default, accessible in two taps.**

```
Settings → Accessibility
  ├── Text size: Default / Large / Extra Large
  ├── High contrast: Off / On
  ├── Reduce motion: Off / On
  ├── Screen reader optimised: Off / On
  └── Verification format: Words / PIN / Audio
```

### 20.2 Screen reader support

The app must work fully with VoiceOver (iOS) and TalkBack (Android).

**Requirements:**
- Every interactive element has an accessible label (not just visual text)
- The Signet Me words are announced clearly: "Your word is marble. Their word is falcon. Refreshes in 24 seconds."
- QR codes have a text alternative: "QR code containing your Signet ID. Tap to copy as text."
- The photo verification result is announced: "Match confirmed" or "Mismatch warning"
- Navigation follows a logical reading order (top to bottom, not visually positioned)
- Focus management on page transitions — screen reader focus moves to the new page title

**Implementation:** Use semantic HTML elements (`button`, `heading`, `img` with alt text), ARIA labels where semantics are insufficient, and `aria-live` regions for dynamic content (word countdown, verification results).

### 20.3 Visual accessibility

**Colour and contrast:**
- All text meets WCAG 2.1 AA contrast ratios (4.5:1 for body text, 3:1 for large text)
- Status indicators never rely on colour alone — always paired with text or icons (e.g., "Verified ✓" not just a green dot)
- High contrast mode increases all contrast ratios to AAA (7:1)
- The design system's CSS custom properties make this a single `data-theme` toggle

**Text size:**
- Default, Large (+25%), Extra Large (+50%)
- Layout must reflow — no horizontal scrolling, no truncated content
- The Signet Me word display scales proportionally

**Motion:**
- `prefers-reduced-motion` media query is respected by default
- The "Reduce motion" toggle in Settings forces this regardless of system setting
- Affected: fade-in animations, checkmark animation, countdown transitions
- Reduced motion replaces animations with instant state changes

### 20.4 Motor accessibility

**Touch targets:**
- Minimum 48×48px for all interactive elements (Apple/Google standard)
- Buttons have generous padding — the existing design system already uses 12px padding, increase to 16px in accessible mode
- No drag gestures, no swipe-to-dismiss, no pinch-to-zoom required for any core flow
- All actions achievable via single tap

**One-tap credential display:**
- From the home screen, tapping your badge opens a full-screen credential view
- Large photo, large age badge, large "Verified" text
- Designed to be shown to another person (bouncer, steward) with no further interaction needed
- Auto-locks after 30 seconds (returns to home screen)

```
┌─────────────────────────────┐
│                             │
│                             │
│       ┌──────────┐          │
│       │          │          │
│       │  [PHOTO] │          │
│       │          │          │
│       └──────────┘          │
│                             │
│         18+  ✓              │
│       Verified              │
│                             │
│                             │
│    Tap anywhere to close    │
└─────────────────────────────┘
```

### 20.5 Cognitive and literacy accessibility

**PIN mode (§16):**
- Numeric codes instead of words
- Already specced — this is the primary accessibility feature for non-readers

**Minimal steps:**
- Core flows use the fewest possible steps
- Show credential: 1 tap from home
- Signet Me verification: 2 taps from home (tap person → words appear)
- No multi-step wizards for daily use — wizards are only for onboarding and verification ceremonies

**Clear visual feedback:**
- Green checkmark = confirmed
- Red cross = mismatch
- Amber warning = attention needed
- These icons are always paired with text labels (for colour blindness and screen readers)

**Simple language:**
- All user-facing text aims for reading age 11 (year 7 / 6th grade)
- No jargon, no technical terms, no acronyms without explanation
- Error messages explain what to do, not what went wrong

### 20.6 Audio verification mode

For users who can't see the screen well enough to read words or PINs:

```
Settings → Accessibility → Verification format → Audio
```

In audio mode, the Signet Me words are spoken aloud by the device:
- "Your word is marble"
- "Their word should be falcon"

The user can tap a "Speak" button to repeat at any time. This works with the phone's text-to-speech engine — no custom audio needed.

The verification input can also be voice: "Say the word they told you" → speech-to-text → matched against expected word.

**Note:** Audio mode in a noisy environment (pub, football ground) may not work well. PIN mode displayed at large size may be more practical in those contexts.

### 20.7 What's NOT covered here (needs further work)

These accessibility concerns require additional design work beyond the app's UI:

- **Non-smartphone users** — see §19.2 (Open Questions): printed QR card
- **Users who cannot take selfies** — alternative photo capture (verifier takes photo, family member assists)
- **Users who cannot attend a verification ceremony in person** — remote verification, home visits, or proxy verification through a trusted person
- **Users with no fixed address** — address verification alternatives

---

## 21. Verifier IQ (Verifier Trust Scoring)

Not all verifiers are equal. A verifier confirmed by their professional body is worth more than one who's only cross-verified by peers. The **Verifier IQ** determines how much IQ their credentials contribute to users.

### 21.1 Verifier confirmation methods (ranked by strength)

| Method | Code | Verifier IQ | Effect on user's IQ | Description |
|---|---|---|---|---|
| Professional body issues Kind 30473 directly | B | 100% | Full (80 pts) | The GMC, SRA, TRA etc. has a Signet keypair and signs the verifier's credential directly. Strongest proof. |
| NIP-05 on professional body's domain | A | 90% | Near-full (72 pts) | The body's website hosts a `.well-known/nostr.json` mapping registration numbers to pubkeys. Trivial technical ask for the body. |
| Pubkey on the verifier's own professional website | D | 50% | Half strength (40 pts) | Their law firm or GP surgery website publishes their Signet pubkey. Weaker — the website could be faked, but domain age and reputation are checkable. |
| Cross-verification by other professionals only | C | 25% | Quarter strength (20 pts) | Other verified professionals vouch for the new verifier. Weakest — vulnerable to coordinated fakes, but works for bootstrapping. |

**Trust flows backwards:** When a verifier upgrades (e.g., from C to A), ALL credentials they've previously issued automatically gain the higher IQ contribution. No second visit needed. The credential was always cryptographically valid — what changed is our confidence in the verifier.

**Bootstrap strategy:** Start with C (cross-verification) to get the network moving. Everyone has an incentive to upgrade to A or B because it makes their credentials worth more.

### 21.2 Separate professional keypair

Verifiers MUST use a **dedicated professional keypair** for signing credentials, separate from their personal Nostr identity. This keypair:
- Only signs Kind 30470 credentials and Kind 30473 verifier events
- Does NOT receive DMs, does NOT post notes, does NOT participate in social Nostr
- Has no inbox to spam
- Is the keypair registered with their professional body

This keeps professional and personal identities separate and prevents the verifier's personal Nostr account from being discoverable through their professional role.

### 21.3 Verifier registration checks (verification bot)

A reference verification bot checks verifier claims against public professional registers:

| Check | What it does | Automated? |
|---|---|---|
| Registration number lookup | Queries GMC, SRA, TRA, NMC etc. public registers | Yes — HTTP scraping or API |
| NIP-05 verification | Checks `.well-known/nostr.json` on professional body domains | Yes — HTTP request |
| Website pubkey verification | Checks the verifier's professional website for their published pubkey | Yes — HTTP crawl |
| Domain age and reputation | Checks domain registration date, backlinks, Companies House | Yes — WHOIS + crawl |
| Volume anomaly detection | Flags verifiers issuing credentials at unusual rates | Yes — event analysis |
| Cross-profession requirement | Ensures cross-verification vouches come from 2+ different professions | Yes — event analysis |

The bot publishes its findings as Nostr events. Multiple independent bots checking the same verifier = consensus. The bot does not decide who's verified — it checks public registers and publishes what it finds.

**Funding:** Initially run at own cost as a reference server. Target model: community-funded via Lightning micropayments (see §22).

### 21.4 Priority checks via L402

Users can trigger an immediate check of their verifier's status by paying a small Lightning invoice via the L402 protocol:

1. User's app calls: `POST /check?verifier=<pubkey>`
2. Bot returns 402 Payment Required with a Lightning invoice (a few sats)
3. User pays (automatically if the app has a wallet, or via QR scan)
4. Bot runs the specific check immediately, publishes result
5. User's IQ updates

Users who don't want to pay wait for the next scheduled free run (e.g., every 24 hours). Priority checks are self-funding — each payment covers its own compute cost and contributes surplus to the meter.

---

## 21.5 Jurisdiction Confidence and Anti-Bribery

The Verifier IQ (§21.1) is further weighted by the **jurisdiction confidence score** defined in the protocol (spec §24). This means a verification from a high-integrity jurisdiction carries more IQ than one from a jurisdiction with high corruption.

The jurisdiction confidence score (0-100) factors in the Transparency International Corruption Perceptions Index (CPI), professional body coverage, public register availability, and digital credential maturity. A credential from a Danish solicitor (CPI: 90) carries near-full weight. A credential from a jurisdiction with CPI 20 carries significantly less.

**The anti-bribery flip:** In jurisdictions where bribery in document issuance is common, Signet makes that bribery self-documenting. Every corrupt verification creates a permanent, public, traceable record — volume anomalies, geographic impossibilities, nullifier collisions. The corruption that was invisible becomes the evidence that catches itself. This has the potential to reduce bribery in document issuance, not by preventing it, but by making it permanently traceable.

**IQ formula with jurisdiction confidence:**
```
credential_iq = base_points × verifier_iq_percentage × (jurisdiction_confidence / 100)
```

Example: A passport verified by a cross-verified-only verifier (25%) in a jurisdiction with confidence 60:
```
80 × 0.25 × 0.60 = 12 IQ points
```

Same passport, NIP-05 confirmed verifier (90%), jurisdiction confidence 95:
```
80 × 0.90 × 0.95 = 68 IQ points
```

### 21.6 Document Type Registry

The app pulls document types, field definitions, and country-specific attributes from the **Signet Document Registry** — a separate open-source resource maintained alongside the protocol. The registry defines:

- Available document types per country (passport, national ID, driving licence, etc.)
- Required and optional fields for each document type
- Which fields contribute to nullifier computation
- Whether the document number changes on renewal
- Country-specific attributes (`gb:nationalInsurance`, `in:aadhaar`, `us:ssn`, etc.)
- Human-readable labels (for the app UI)

The UX flow is:
1. User taps "Add document"
2. Select country (dropdown, searchable)
3. Select document type (filtered by country)
4. App shows the right fields — auto-generated from the registry
5. User fills in their details

Adding a new country or document type is a registry update — no protocol revision, no library change, no app release needed. The app fetches the latest registry periodically.

The registry starts comprehensive — covering the top 50 countries by population (~90% of the world) with universal document types (passport, driving licence, national ID, birth certificate) plus country-specific documents for major jurisdictions. Community contributors add the rest.

---

## 22. Acceptable Verifiers (UK Countersigning Standard)

The spec previously named only "solicitors, doctors, notaries" as acceptable verifiers. This is far too narrow. The acceptable verifier list aligns with the **UK passport countersigning standard** — 40+ professions, each with a registered professional body.

### 22.1 Acceptable professions

| Category | Professions |
|---|---|
| **Legal** | Solicitor, barrister, legal executive, commissioner for oaths, notary public, Justice of the Peace |
| **Medical** | Doctor (GP/consultant), dentist, optician, pharmacist, nurse (RGN/RMN), chiropodist, veterinary surgeon |
| **Financial** | Accountant (chartered), bank/building society official, insurance agent, financial adviser, valuer/auctioneer |
| **Education** | Head teacher, teacher, lecturer |
| **Public service** | Police officer, fire service official, civil servant (permanent), local government officer, councillor, MP, social worker |
| **Religious** | Minister of religion, Salvation Army officer |
| **Engineering** | Chartered engineer, chartered surveyor |
| **Other regulated** | Airline pilot, Merchant Navy officer, funeral director, photographer (professional), trade union officer, company director |

Everyone already knows someone on this list. Your GP. Your kids' teacher. Your accountant. The solicitor who did your house purchase. Verification should be bundled with existing appointments — zero additional cost.

### 22.2 Teachers as the primary child verification channel

Teachers are the most efficient verifier for children:

- They **know the child** — they see them every day
- They **know the parents** — parents' evenings, school pick-ups, emergency contacts
- The **school already verified the birth certificate** at enrollment
- They have the **child's DOB** on file
- They have the **parent-guardian relationship** documented

A parent at parents' evening shows their passport, teacher confirms the child — 3 minutes, zero cost. One teacher could verify an entire class in a single parents' evening session.

**Professional knowledge counts as evidence.** A teacher doesn't need to re-verify what the school already verified at enrollment. Their professional standing (regulated by the Teaching Regulation Agency) and daily knowledge of the child is the evidence. If the TRA can strike them off for misconduct, they have skin in the game.

### 22.3 Verifier role clarity

The verifier's role is exactly one thing: **"I confirm this person is real."**

Not "I endorse Signet." Not "I understand the protocol." Not "I advocate for how this person uses their identity." Just: "I checked their documents, this person is who they say they are." The same thing they already do when they countersign a passport photo.

**Don't be Bitcoin.** Nobody needs to understand Merkle trees, nullifiers, or secp256k1. The pitch to a professional: "This is the best system for protecting kids online. All you do is confirm the person is real, like countersigning a passport. Your professional registration means you're accountable. That's it."

---

## 23. Infrastructure and Funding

### 23.1 Verification bot

A reference verification bot runs the checks described in §20.3. Initially self-funded by the project. Open source — anyone can fork and run their own.

### 23.2 Lightning meter model

Target funding model: community-funded via Lightning micropayments using toll-booth (L402 middleware).

**How it works:**
- A public "meter" shows the balance, cost per check, and estimated runway
- Anyone can top up the meter with Lightning sats
- Like putting 50p in a parking meter — the infrastructure runs as long as there's balance

**Critical constraint:** Lightning payments go **directly from the contributor to the hosting provider's Lightning node.** There is no Signet wallet, no intermediary, no custody. The invoice is generated by the hosting provider's node, not ours. This means:
- No money transmission (no FCA registration)
- No taxable event for the project (no HMRC liability)
- No entity needed (no accounts, no books)
- The hosting provider receives payment for services — that's their tax event

If there is ANY wallet in between — even an auto-forwarding one — the model breaks. The no-custody constraint is non-negotiable.

### 23.3 Bootstrap phase

Run a reference verification bot at own cost. The Lightning meter is the target but isn't blocking. Get the bot running first, figure out direct-to-provider Lightning payment later.

---

## 24. Market Positioning (IQ Benchmarking)

The global identity verification market is $14-16 billion (2025-2026). The age verification sub-sector is $2.5 billion, projected to reach $7.1 billion by 2033. Key players: Onfido (acquired by Entrust for $650M), Yoti ($39M revenue in 2025, 62% YoY growth), Jumio, Veriff, Sumsub.

Every player in this market sits between IQ 5 and IQ 75 on our scale. None achieve what a single Signet professional verification does.

### 24.1 Every verification method scored on Signet IQ

**IQ 0-5: Proves nothing**

| Method | IQ | What it actually proves |
|---|---|---|
| Self-declaration checkbox ("I am 18") | 2 | The user clicked a button. 22-47% of children fake their age this way. |
| Device-level age signal (Apple/Google) | 3 | Someone declared an age at device setup. A child can lie. |
| Social media behavioural inference | 5 | An AI guesses your age from behaviour. A child who mimics adults passes. |

**IQ 5-15: Proves access to something**

| Method | IQ | What it actually proves |
|---|---|---|
| Debit card ownership | 5 | Access to a card. UK children can have debit cards from age 11. |
| Credit card ownership | 10 | Access to a credit card. Children use parents' cards routinely. |
| MNO (mobile number) check | 12 | The SIM is registered to an adult. Many children on parent contracts. |
| Email-based age estimation | 12 | The email has a history with age-gated services. Parent's email bypasses it. |

**IQ 15-35: Database match, no person present**

| Method | IQ | What it actually proves |
|---|---|---|
| Parental consent (COPPA) | 15 | Someone claiming to be a parent consented. Child can impersonate. |
| Credit reference / electoral roll | 20 | A person with that name/DOB exists in a database. Not who's at the keyboard. |
| AI facial age estimation (Yoti etc.) | 25 | AI estimates the face is probably adult. Deepfakes and age filters defeat it. |
| Challenge 25 (in-person retail) | 30 | A shop worker thinks you look old enough. Subjective. |
| Open banking | 35 | A verified bank account holder is 18+. Strong database but not who's using it. |

**IQ 35-65: Document seen, some biometric**

| Method | IQ | What it actually proves |
|---|---|---|
| Government ID photo upload (OCR) | 45 | Someone uploaded a photo of a document. No liveness. |
| Video selfie + ID + liveness | 55 | Face matches document, person is live. Deepfake attacks documented but harder. |
| Digital identity wallet (eIDAS) | 60-75 | A trusted provider previously verified this person. Depends on initial proofing. |

**IQ 70-85: Cryptographic or professional**

| Method | IQ | What it actually proves |
|---|---|---|
| NFC chip reading + liveness | 75 | Government-signed cryptographic data from document chip matches a live person. |
| **Signet Tier 3 (single verification)** | **80** | A licensed professional inspected physical documents and confirmed the person is real. Their career is on the line. |

**IQ 80-200: Signet progressive verification (no market equivalent)**

| Level | IQ | What it adds |
|---|---|---|
| Single professional verification | 80 | One document, one verifier. Already exceeds everything above. |
| + second document, different verifier | 105 | Independent confirmation from a different professional. |
| + peer vouches from verified people | 120 | Social proof from people who've staked their reputation. |
| + multiple document types + longevity | 140 | Passport + driving licence + NI card + years of account history. |
| + cross-verification + identity bridges | 160-200 | Maximum possible confidence. |

### 24.2 Contextual IQ prompting (no gamification)

The app NEVER tells users their score isn't good enough. External demand drives upgrades:

| User | Scenario | What the app says |
|---|---|---|
| Gran (IQ 0) | Just uses Signet Me with family | Nothing. She's happy. App never nags. |
| Parent (IQ 0) | Kid needs age verification for Steam | "Steam needs a verified age range. Here's how to get verified." |
| Security enthusiast (IQ 120) | Wants to max out | Discovers IQ details in Settings. Chases 200 on their own. |

The IQ score is visible if you look for it, but the app never pushes. Motivation is always external — a platform requirement, a specific use case, a real need. If nothing requires a higher score, the app stays silent.

---

## 25. Protocol Changes Required

These changes to `spec/protocol.md` are required to support the v2 app:

| Change | Type | Complexity | Description |
|---|---|---|---|
| Dynamic Merkle tree | **Breaking** | High | Arbitrary key-value leaves instead of fixed 5. New leaf format: `key:value` pairs. Proof format unchanged (RFC 6962). |
| `signet:documentNumber` leaf | Additive | Low | Document number stored as a Merkle leaf for selective disclosure. |
| `signet:documentExpiry` leaf | Additive | Low | Document expiry date as a Merkle leaf. Enables accelerated IQ decay and consumer-side hard cliffs. |
| Attribute namespacing | Additive | Medium | `signet:` (universal), `gb:` (UK), `us:` (USA) etc. Extensible vocabulary for country-specific attributes. |
| Scoped credentials | **Breaking** | High | One credential per document per verifier, rather than one credential covering everything. Credentials stack. |
| Verifier IQ model | Additive | Medium | New scoring layer for verifier trust. Affects how credential IQ contributions are weighted. |
| Accelerated decay for expired documents | Additive | Low | Half-life shortens from 3 years to 6 months when document expiry passes. |
| Ceremony flow (user enters data) | App-level | None | Not a protocol change — the ceremony cryptography is identical. Only the UX changes. |

---

## 26. Open Questions (Pre-Production)

These items require further thought before production. They are acknowledged gaps, not oversights.

### 26.1 Credential portability

Users may switch from My Signet to another Signet-compatible app (e.g., Fathom). Credentials are standard Nostr events and can be exported. Merkle proofs could be transferred via QR or recovered from Blossom (if the user opted for Blossom backup).

**Vulnerability concern:** The transfer of Merkle proofs is a sensitive operation — the proofs contain private attribute data (name, DOB, etc.). The transfer mechanism must be end-to-end encrypted and authenticated. QR exchange (in person) is safe. Remote transfer via relay needs encryption. **This needs careful design before production — it is a potential vulnerability point.**

### 26.2 Printed QR card (non-smartphone users)

A downstream app concern, not a protocol issue. The protocol provides everything needed: a published credential with a QR-encodable pubkey, a photo hash in the Merkle tree, and optional Blossom storage for remote photo retrieval. Any app or third-party service can produce a physical card from this data.

Two tiers envisioned:
- **Print at home** — app generates a PDF with photo, age badge, QR code. Free, instant, low physical security. The QR is the real trust — scanning it verifies the credential cryptographically.
- **Professional print** — ordered via API from a card printing service (e.g., The Card Network, Cardaxis). PVC, hologram, tamper-evident. For non-smartphone users who need a standalone physical ID.

**This is an app-level feature, not a protocol change.** To be designed as part of the app's settings/ordering flow.

### 26.3 Physical ID fallback principle

Signet is an enhancement, never a gate. Any venue, service, or platform that accepts Signet SHOULD also accept traditional physical ID (passport, driving licence). Signet provides better privacy and stronger verification, but must never exclude someone who only has a passport.

---

## Appendix A: Duress Detection Proposal

**For security team review.**

Three new functions added to `src/signet-words.ts` (additive, no existing changes):

| Function | Purpose |
|----------|---------|
| `deriveSignetDuressWords(secret, identity, epoch)` | Derive safe words for a specific person |
| `getSignetDuressDisplay(secret, identity)` | UI bundle for safe words (with countdown) |
| `verifySignetWordsEnhanced(secret, words, identities)` | Returns `'valid'` / `'duress'` / `'invalid'` |

New type: `SignetVerifyResult = { status: 'valid' | 'duress' | 'invalid', identity?: string }`

Security considerations:
1. All branches computed before returning (prevents timing side-channels)
2. Uses `constantTimeEqual` for all comparisons
3. HMAC domain separator (`:duress` suffix) prevents collision with normal words
4. `deriveDuressTokenBytes` from canary-kit — same HMAC-SHA256 primitive already in use

Questions for review:
1. Is `deriveDuressTokenBytes` from canary-kit trustworthy for this use case?
2. Is the all-branches-before-return pattern sufficient to prevent timing attacks?
3. Should collision avoidance be added (checking duress words don't match normal words in the tolerance window)?

---

## Appendix B: Migration from Current Family App

The current `app/` codebase (formerly `family-app/`, renamed 2026-03-16) can be incrementally migrated:

| Current | v2 | Migration |
|---------|-----|-----------|
| Single keypair (`FamilyIdentity`) | Two keypairs (`SignetIdentity`) | Add second keypair, migrate existing as Natural Person |
| `verifySignetWords` (symmetric) | `verifySignetMe` (directional) | Already implemented — uses canary-kit directly |
| 3 hardcoded words | Configurable 1/2/3 via tier | Already implemented — `wordCount` prop |
| "Recovery phrase" language | "Backup words" language | Already implemented |
| Plaintext JSON export | Removed | Already implemented |
| Certificate download | Removed | Already implemented |
| Fake trust score | Removed | Already implemented |
| QR code on home screen | Family-first home | Already implemented |
| No credential storage | IndexedDB credential store | New — `useCredentials` hook + DB schema |
| No verification flow | Get Verified + Verify Someone | New — two new pages |
| No verifier activation | Hidden 5-tap activation | New — Settings enhancement |
