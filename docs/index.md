# Signet Documentation

Signet is a decentralised identity verification protocol for Nostr. It lets users prove claims about their identity using zero-knowledge proofs, without revealing personal data or relying on a central authority.

## Architecture

### Trust Flow

```mermaid
flowchart TD
    T1["Tier 1: Self-Declared\n(any Nostr account)"]
    T2["Tier 2: Web-of-Trust\n(3+ peer vouches)"]
    T3["Tier 3: Professional Adult\n(lawyer/doctor/notary verifies ID)"]
    T4["Tier 4: Adult + Child Safety\n(professional verifies parent + child)"]
    IQ["Signet IQ (0–200)\nWeighted trust score"]
    Badge["Badge Display\nTier label + score"]

    T1 -->|"peers vouch\n(kind 30471)"| T2
    T2 -->|"professional issues\ncredential (kind 30470)"| T3
    T3 -->|"extended ceremony\nwith child evidence"| T4

    T1 --> IQ
    T2 --> IQ
    T3 --> IQ
    T4 --> IQ
    IQ --> Badge
```

### Event Kinds

```mermaid
flowchart LR
    subgraph Core["Core Protocol (30470–30477)"]
        Cred["30470\nCredential"]
        Vouch["30471\nVouch"]
        Policy["30472\nPolicy"]
        Verifier["30473\nVerifier"]
        Challenge["30474\nChallenge"]
        Revocation["30475\nRevocation"]
        Bridge["30476\nIdentity Bridge"]
        Delegation["30477\nDelegation"]
    end

    subgraph Voting["Voting Extension (30482–30484)"]
        Election["30482\nElection"]
        Ballot["30483\nBallot"]
        Result["30484\nResult"]
    end

    Vouch -->|"builds"| Cred
    Verifier -->|"issues"| Cred
    Challenge -->|"targets"| Verifier
    Challenge -->|"leads to"| Revocation
    Policy -->|"gates on"| Cred
    Bridge -->|"links to"| Cred
    Delegation -->|"scopes from"| Cred

    Election --> Ballot --> Result
```

### Verification Ceremony (Tier 3/4)

```mermaid
sequenceDiagram
    participant S as Subject
    participant V as Professional Verifier
    participant R as Nostr Relays

    S->>V: Presents government ID (in person)
    Note over V: Verifies document authenticity
    V->>V: Computes nullifier SHA-256(docType‖country‖docNumber‖salt)
    V->>V: Builds Merkle tree of verified attributes
    V->>V: Creates Bulletproof age range proof
    V->>R: Publishes Natural Person credential (nullifier + Merkle root)
    V->>R: Publishes Persona credential (age range only, anonymous)
    Note over S,R: Subject now has Tier 3/4 — no personal data stored
```

### Crypto Stack

```mermaid
flowchart TB
    subgraph L1["Layer 1: Schnorr (secp256k1)"]
        Signing["Event signing"]
        Merkle["Merkle selective disclosure"]
        Ring["SAG ring signatures\n(issuer privacy)"]
    end

    subgraph L2["Layer 2: Bulletproofs (secp256k1)"]
        Age["Age range proofs\n(~700 byte, no trusted setup)"]
    end

    subgraph L3["Layer 3: LSAG"]
        Vote["Linkable ring signatures\n(anonymous voting)"]
    end

    L1 --- L2
    L2 --- L3
```

### Verifier Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Registered: Publish kind 30473\n(profession + licence hash)
    Registered --> Active: Cross-verified by\n2+ professionals
    Active --> Challenged: kind 30474 filed\n(evidence of fraud)
    Challenged --> Active: Challenge dismissed
    Challenged --> Revoked: Threshold confirmations\nreached (kind 30475)
    Active --> [*]: Voluntary retirement
    Revoked --> [*]: Bond slashed,\ncredentials invalidated
```

## Guides

| Document | Description |
|----------|-------------|
| [Signet in 5 Minutes](signet-in-5-minutes.md) | One-page developer overview with code examples |
| [Implementation Levels](implementation-levels.md) | Three-level integration guide (weekend → weeks) |
| [Local Development](spinup.md) | Relay setup, app spinup, certificates |
| [Origin Story](origin-story.md) | How and why Signet was created |

## Specifications

| Document | Description |
|----------|-------------|
| [Protocol Specification](../spec/protocol.md) | Full protocol spec — 25 sections, source of truth |
| [Voting Extension](../spec/voting.md) | Anonymous voting via linkable ring signatures |

## Examples

| Example | Description |
|---------|-------------|
| [Full Flow](../examples/full-flow.ts) | All 4 tiers, trust scoring, policies, verifier lifecycle, Merkle disclosure |
| [Signet Me](../examples/signet-me.ts) | Time-based word verification for peer identity proofs |
| [UK Solicitor](../examples/jurisdictions/uk-solicitor.ts) | Jurisdiction-specific: UK solicitor verification |
| [US Attorney](../examples/jurisdictions/us-attorney.ts) | Jurisdiction-specific: US attorney verification |
| [EU Doctor](../examples/jurisdictions/eu-doctor.ts) | Jurisdiction-specific: EU doctor verification |
| [Brazil Lawyer](../examples/jurisdictions/brazil-lawyer.ts) | Jurisdiction-specific: Brazil lawyer verification |
| [India Doctor](../examples/jurisdictions/india-doctor.ts) | Jurisdiction-specific: India doctor verification |
| [Japan Notary](../examples/jurisdictions/japan-notary.ts) | Jurisdiction-specific: Japan notary verification |
| [UAE Professional](../examples/jurisdictions/uae-professional.ts) | Jurisdiction-specific: UAE professional verification |
| [Multi-Jurisdiction](../examples/jurisdictions/multi-jurisdiction.ts) | Cross-border compliance across multiple jurisdictions |

## Reports

| Document | Description |
|----------|-------------|
| [Security & Production Readiness Review](reports/2026-03-12-security-production-readiness-review.md) | Comprehensive security review findings |
| [Professional Identity Fraud Deep Dive](reports/2026-03-04-professional-identity-fraud-deep-dive.md) | Analysis of professional identity fraud vectors |

## For LLMs

| File | Description |
|------|-------------|
| [llms.txt](../llms.txt) | Concise LLM-optimised overview (~100 lines) |
| [llms-full.txt](../llms-full.txt) | Full context: llms.txt + protocol spec + voting spec + developer guides |
