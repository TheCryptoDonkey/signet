# Signet ecosystem — which lib do I want?

Signet is split into focused libraries, each with one job. This page is the orientation map: tell us what you're building, and we'll tell you which packages to install.

## "I want to…"

| Goal | Install | Reach for |
|---|---|---|
| **Let users sign in with Signet** (one click, QR or same-device) | [`signet-login`](https://www.npmjs.com/package/signet-login) | `Signet.login()` returns a verified kind-21236 event |
| **Show a user's display name** in my app | [`signet-credentials`](https://www.npmjs.com/package/signet-credentials) | `fetchPersonaHandle(pubkey)` returns the current handle |
| **Verify a sign-in event server-side** | [`signet-protocol`](https://www.npmjs.com/package/signet-protocol) | `verifyAuthEvent(event, challenge, origin)` |
| **Display a verification badge** (tier 1–4 + Signet IQ) | [`signet-protocol`](https://www.npmjs.com/package/signet-protocol) | `computeBadge(pubkey, events)` |
| **Build a credential** (display-name today; age scope, profession planned) | [`signet-credentials`](https://www.npmjs.com/package/signet-credentials) | `buildPersonaNameCredential(...)` (caller publishes) |
| **Enforce a community verification policy** (min tier to post) | [`signet-protocol`](https://www.npmjs.com/package/signet-protocol) | `PolicyChecker` |
| **Build a parent-controlled child account** | [`nsec-tree`](https://www.npmjs.com/package/nsec-tree) + [`charter`](https://www.npmjs.com/package/charter) | `derivePersona` + Charter clause subscription |
| **Issue blinded reputation scores** (privacy-preserving WoT) | [`nostr-veil`](https://www.npmjs.com/package/nostr-veil) | Ring-signature group scoring |
| **Implement NIP-VA** (kind-31000 attestations) in your own protocol | [`nostr-attestations`](https://www.npmjs.com/package/nostr-attestations) | Reference impl, profile-agnostic |
| **Time-grant signing approvals to an app** (NIP-46 with policy) | [`charter`](https://www.npmjs.com/package/charter) | Clause evaluator + pairing storage |

## The libraries

### Identity & sign-in

**[`signet-login`](https://www.npmjs.com/package/signet-login)** — Sign in with Signet SDK. QR + same-device redirect. The one-script-tag integration. Most consumer apps need only this.

**[`signet-protocol`](https://www.npmjs.com/package/signet-protocol)** — Core protocol library. Types, crypto primitives, builders for credentials, vouches, policies, badges, verifier lifecycle. The full Signet protocol surface; consume when you need more than sign-in.

**[`signet-verify`](https://www.npmjs.com/package/signet-verify)** — Age verification service / SDK. Drop-in age gate for websites; one script tag, one function call.

### Credentials & attestations

**[`signet-credentials`](https://www.npmjs.com/package/signet-credentials)** — Consumer SDK for the Signet credential profile. Publish, fetch, parse, validate display-name credentials (the `persona-name` profile shipped first; `age-scope`, `professional`, `supersession` planned). Bring-your-own transport. See [`docs/integrations/axenstax-migration.md`](https://github.com/forgesworn/signet-credentials/blob/main/docs/integrations/axenstax-migration.md) for a worked example of porting a hand-rolled consumer.

**[`nostr-attestations`](https://www.npmjs.com/package/nostr-attestations)** — Reference implementation of NIP-VA (kind-31000 verifiable attestations). Profile-agnostic — for the Signet credential profile, prefer `signet-credentials`, which composes on top.

### Identity derivation & privacy

**[`nsec-tree`](https://www.npmjs.com/package/nsec-tree)** — Deterministic Nostr identity hierarchies. One master secret, unlimited personas. The derivation primitive behind parent/child accounts in Signet.

**[`nostr-veil`](https://www.npmjs.com/package/nostr-veil)** — Privacy layer for Nostr reputation. Groups collectively score trustworthiness using ring signatures — scores are verifiable but contributors are unidentifiable. Used for tier-2+ Signet WoT without doxxing voters.

### Sub-protocols

**[`charter`](https://www.npmjs.com/package/charter)** — Parent-led, libre game account management. Consumer SDK exports `evaluateSchedule` (pure clause evaluation), `createPairingStore` (IDB-backed NIP-46 bunker pairings), and `createCharterEvaluator` (live subscribe → decrypt → cache → sync gate). Phase 1α shipped at v0.1.0; budget/spend/content clauses planned. See [`docs/integrations/axenstax-migration.md`](https://github.com/forgesworn/charter/blob/main/docs/integrations/axenstax-migration.md) for a worked example.

**[`attestation-bridge`](https://github.com/forgesworn/attestation-bridge)** — Neutral adapter boundary for Nostr attestation formats used by Signet, Trott, and nostr-veil. Internal tooling — consumers shouldn't normally need it.

### Reference apps & tooling

**[`signet-app`](https://github.com/forgesworn/signet-app)** ("My Signet" at [mysignet.app](https://mysignet.app)) — User-facing identity wallet. React PWA, all client-side, no backend. The reference consumer of every lib above. Read the source when you want to see how it all fits together.

**[`signet-verification-bot`](https://github.com/forgesworn/signet-verification-bot)** — Automated verification bot for trusted verifiers.

## Composition patterns

### Minimum sign-in site (most consumers)

```
signet-login          # sign-in SDK
signet-credentials    # fetch + display the user's handle
```

That's it. Two installs cover the 80% case.

### Sign-in + credential verification (server-side)

```
signet-login          # browser SDK
signet-protocol       # server: verify kind-21236 + compute badge
signet-credentials    # server: validate inbound credential presentations
```

### Family-account site (with parental controls)

```
signet-login          # parent + child sign-in
signet-credentials    # display-name + age-scope credentials
nsec-tree             # parent-derived child personas
charter               # parent grants time / spend / content scope
```

### Reputation site (blinded WoT)

```
signet-protocol       # core types + badges
nostr-veil            # ring-signature scoring
nostr-attestations    # generic NIP-VA tooling for non-Signet kind-31000
```

## Naming & versioning

- All libs are **published unscoped on npm** (`signet-protocol`, not `@forgesworn/signet-protocol`).
- Each lib has a focused scope and its own version. They compose via peer dependencies on `signet-protocol`.
- Sub-protocol libs (`charter`, `nostr-veil`, `nsec-tree`) own their own kinds and tags — they don't depend on `signet-protocol`.
- `signet-credentials`, `signet-verify`, and friends sit on top of `signet-protocol` as consumer SDKs.

## Rust crates (planned)

The TypeScript libs above cover browser + Node consumers. Rust-side Signet support is on the roadmap as **`signet-rs`** — Schnorr verification, kind-21236 challenge handling, credential parse/build — with a thin `signet-credentials-rs` companion for the credential profile. Engine and embedded consumers (axenstax, heartwood, bark) currently hand-roll these primitives; the crate consolidates that work.

## Audit finding (2026-05-25)

Live audit of `wss://relay.trotters.cc` showed 23 kind-31000 events: 13 vouches, 8 ownership-claims, 1 authorship, 1 endorsement. **Zero display-name credentials**, confirming that no Signet consumer is currently publishing them in production. Consumer wire formats also revealed at least one hand-rolled implementation reading `expires` instead of `expiration` (NIP-40 standard) — silently fail-open. `signet-credentials` fixes both: a canonical publisher, and a canonical fetcher with correct tag reads.

## Contributing

Want to add a new sub-protocol lib? The pattern:
- Pick a focused scope (one Nostr kind family OR one credential profile OR one sub-protocol).
- Unscoped npm name, MIT licence, ESM-only, target ES2022.
- Peer-depend on `signet-protocol` when you need core types/crypto.
- Add yourself to this page.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full guide.
