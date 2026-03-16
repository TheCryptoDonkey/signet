# Signet for AI Agents

**Date:** 2026-03-16
**Status:** Draft

---

## 1. The Problem

AI agents on Nostr are anonymous by default. Anyone can deploy a bot. There is no way to know who operates it, whether it acts with anyone's authorisation, or whether the operator has any accountability.

This was tolerable when bots posted memes. It stops being tolerable as agents gain capabilities:

- **Money.** Data Vending Machines (NIP-90) pay agents sats for computation. Fraudulent DVMs can extract payment, manipulate outputs, or launder funds. There is currently no way to distinguish a legitimate DVM operator from a scammer.
- **Moderation.** Agents that ban, shadowban, or curate community content can cause real harm. An anonymous moderator-bot has no accountability.
- **Children.** An agent interacting with a child in a family-safe community should be traceable to a verified adult. An anonymous bot has no such requirement today.
- **Deepfake voice and video.** Real-time voice agents and video agents are arriving. A user on a voice call cannot tell whether they are talking to a human, an AI teleoperated by a human, or a fully autonomous agent. The mode signal matters as much as the identity.

The competitive landscape is moving fast. NIP-XX (#2226) defines AI Agent Messages. NIP-AC (#2253) defines DVM Agent Coordination. pablof7z is building AI SDK infrastructure at pace. Nobody has shipped agent identity verification on Nostr. The DIF's Trusted AI Agents working group is circling the problem from the SSI side. The window for Signet to define this space is open, but not indefinitely.

---

## 2. How Signet Solves It

Signet already has the primitives. No new cryptography is required. The solution is a clear mapping and a single optional new tag.

The core mechanic is **operator delegation**:

1. An operator gets verified (Tier 3 or 4 — professionally verified Natural Person, or Tier 1/2 for lower-trust use cases).
2. The operator publishes a Kind 30477 delegation event assigning a Nostr pubkey to their agent.
3. The agent inherits trust from its operator. The delegation is scoped and optionally time-limited.
4. If the operator's credential is revoked (Kind 30475), all their agents lose trust instantly — no separate revocation needed per agent.

**Trust is not created for the agent. It is inherited from the operator through a verifiable chain.**

The chain is short and auditable:

```
Professional verifier
  └─► Kind 30470 credential → Natural Person (Tier 3)
        └─► Kind 30477 delegation → Personal Agent
```

A client verifying an agent walks this chain in two relay queries. No ZK proofs required at the agent layer. The proof work was already done when the operator was verified.

---

## 3. Entity Types for AI Agents

The protocol's nine entity types (§17) already cover every AI agent scenario. The four agent types map directly to deployment contexts.

### 3.1 Agent Type Taxonomy

| Entity Type | Code | Operator | Trust Level | AI Use Case |
|---|---|---|---|---|
| Personal Agent | `personal_agent` | Natural Person (Tier 3/4) | Professionally verified individual | Personal AI assistant, DVM run by a verified person |
| Free Personal Agent | `free_personal_agent` | Persona (identity bridge) | Anonymous but bridged to a verified person | Agent for a privacy-preserving personal workflow |
| Organised Agent | `organised_agent` | Juridical Person (verified org) | Professionally verified organisation | Company AI, verified business DVM |
| Free Organised Agent | `free_organised_agent` | Juridical Persona (org alias) | Anonymous but bridged to a verified org | Anonymised corporate workflow agent |

The unverified default — a bot with no delegation chain — is a **Free Agent** (`free_agent`). Clients can treat this as the baseline of zero operator accountability. This is the current state of all Nostr bots.

### 3.2 Delegation Tree

```
Natural Person (Tier 3/4) ──► personal_agent
  │
  └──► Persona ──► free_personal_agent

Juridical Person ──► organised_agent
  │
  └──► Juridical Persona ──► free_organised_agent

Free Agent (no chain, anonymous operator)
```

The delegation constraints are enforced at the protocol level (§17.6). A Persona cannot delegate an `organised_agent`. A `free_agent` cannot delegate anything. The type encoding is what it is — no spoofing.

### 3.3 Scoped Delegation

Kind 30477 supports an optional `["scope", ...]` tag. For AI agents this enables fine-grained authorisation:

```jsonc
{
  "kind": 30477,
  "pubkey": "<operator_pubkey>",
  "tags": [
    ["d", "<delegation_id>"],
    ["p", "<agent_pubkey>"],
    ["entity-type", "personal_agent"],
    ["scope", "content-management"],     // what the agent is authorised to do
    ["expires", "1798761600"],           // auto-expires; operator must renew
    ["agent-type", "ai"],               // proposed new tag — see §7
    ["algo", "secp256k1"],
    ["L", "signet"],
    ["l", "delegation", "signet"]
  ],
  "content": ""
}
```

Scope values already defined in the guardian delegation context (§21) apply naturally here: `full`, `activity-approval`, `content-management`, `contact-approval`. For AI-specific contexts, new scope values can be added without breaking the event structure.

---

## 4. Dynamic Mode Signaling

The mode tag (§17.7 of the entity type design) is especially important for AI agents. A single agent pubkey may operate in different modes at different times:

```
["mode", "teleoperated"]   // Human operator is in direct real-time control
["mode", "autonomous"]     // AI is acting on behalf of the operator
["mode", "assisted"]       // Human in control with AI assistance
```

This tag appears on events published by the agent, not on the delegation event. It is a per-message signal.

**Why this matters for AI agents specifically:**

- A DVM might process a job autonomously (`autonomous`) but escalate a sensitive request to its human operator (`teleoperated`) before responding.
- A moderation agent running in `assisted` mode signals that a human is reviewing AI decisions before they are applied. Communities requiring human moderation can filter for this.
- A customer service agent switching to `teleoperated` signals that a human has taken over — important for consent, legal liability, and user trust.

Clients that display agent identity SHOULD surface the current mode alongside the operator trust badge. A user interacting with an agent in `autonomous` mode is interacting with software. A user interacting in `teleoperated` mode is interacting with the operator, mediated through software.

**Voice agents.** The deepfake threat makes mode signaling critical. A Nostr voice agent that publishes `["mode", "autonomous"]` on its messages provides a cryptographic commitment to being AI. A client can verify the operator's credential and surface: "You are speaking with an AI agent operated by [Name], verified professional." This is not a perfect defence against deepfake audio, but it creates an auditable trail and a clear protocol for verified AI communication.

---

## 5. DVM Integration

Data Vending Machines (NIP-90) are Nostr's compute marketplace. DVMs receive job requests (kind 5000-5999), do work, and return results (kind 6000-6999). They are paid in sats. The operator identity problem is directly relevant.

### 5.1 The Trust Signal

A DVM operator verified at Tier 3 has their career on the line. A solicitor, doctor, or accountant who runs a fraudulent DVM faces professional consequences in the real world. Their Signet credential is a skin-in-the-game signal, not just a checkbox.

A DVM that can present:

1. A Kind 30477 delegation from a verified operator
2. The operator's Kind 30470 Tier 3 credential

...is a qualitatively different proposition from an anonymous DVM. Clients can surface this to users before they submit a job and pay.

### 5.2 Client Integration Pattern

A DVM marketplace client could filter and rank DVMs by operator tier:

```
Tier 3 operator   → "Verified professional"    (high trust)
Tier 2 operator   → "Vouched person"            (medium trust)
Tier 1 operator   → "Self-declared"             (low trust)
No delegation     → "Anonymous"                 (no trust)
```

This does not require any changes to NIP-90. It is a display-layer enrichment. The client queries for the DVM's delegation event, walks the chain, and computes a trust badge. The DVM operator publishes nothing extra — they just have a Signet credential and a delegation event.

### 5.3 Fee Escrow and Accountability

A natural extension (not in scope for this document, but worth noting): escrow services for DVM payments could require Tier 3 operator verification before releasing funds above a threshold. A verified operator creates a real-world accountability hook. This is composable with existing Lightning/Cashu payment flows in DVMs.

---

## 6. Competitive Landscape

### What exists today

| Project | Approach | Status |
|---|---|---|
| NIP-XX Agent Messages (#2226) | Defines message format for AI agents on Nostr | Active proposal |
| NIP-AC DVM Agent Coordination (#2253) | Defines coordination protocol for DVM agents | Active proposal |
| DIF Trusted AI Agents WG | SSI-based agent identity from the W3C/DIF side | Early working group |
| pablof7z AI SDK | Practical tooling for Nostr agents | Actively shipping |

### What nobody has shipped

Agent identity verification on Nostr. NIP-XX and NIP-AC define how agents communicate. Neither defines how to verify who operates them, or who is accountable when something goes wrong.

### Signet's position

Signet has:
- Entity types that explicitly cover agents (`personal_agent`, `organised_agent`, etc.) — already in the spec (§17)
- A delegation event (Kind 30477) with scoped, time-limited authority — already implemented
- A trust scoring system (Signet IQ) that propagates through delegation chains — already in `src/`
- A revocation mechanism (Kind 30475) that cascades to agents instantly — already in the spec
- Dynamic mode signaling (`["mode", ...]` tag) — already in the spec (§17.7)

The gap is not in the protocol. It is in documentation, examples, and client display. This document is the start of closing that gap.

---

## 7. What Needs Building

The protocol already supports AI agent verification. The work is shallow.

### 7.1 Proposed New Tag: `["agent-type", "ai"]`

Kind 30477 currently does not distinguish between an AI agent and a human delegate. For the family app's guardian delegation (§21), a human delegate (e.g., a grandparent) and an AI agent are very different things. Adding a tag to mark the distinction is low cost and high value:

```
["agent-type", "ai"]         // an AI/software agent
["agent-type", "human"]      // a human acting as delegate
["agent-type", "device"]     // a hardware device (robot, IoT)
```

This tag is optional and additive. No breaking change. Clients that don't know about it ignore it.

Proposed addition to Kind 30477 spec in §17.6.

### 7.2 Example Flows

Three flows should be documented as worked examples (additions to `examples/`):

1. **Personal AI assistant** — a Tier 3 Natural Person delegates to their AI assistant with `content-management` scope, auto-expiring in 90 days. The assistant publishes messages with `["mode", "autonomous"]`.

2. **Verified DVM** — a Tier 3 professional deploys a code-review DVM. The delegation event is publicly queryable. A DVM marketplace client shows "Verified professional operator" on the DVM listing.

3. **Teleoperated voice agent** — a support organisation runs a voice bot. When a human takes over, the agent switches from `["mode", "autonomous"]` to `["mode", "teleoperated"]`, cryptographically signaling the handover.

### 7.3 Client Display Guidance

Clients implementing Level 1 Signet (§3 of `docs/implementation-levels.md`) should treat agent trust display as a natural extension of operator trust display:

```
[Agent badge] Operated by: [Operator badge]
  "personal_agent — operated by Maria S. (Tier 3, solicitor, UK)"
  "organised_agent — operated by Acme Corp (Verified Organisation)"
  "free_agent — anonymous operator"
```

The operator badge is the trust signal. The agent badge is context. Clients need:
- One relay query for the agent's Kind 30477 delegation event
- One relay query for the operator's Kind 30470 credential
- Badge computation already provided by `computeBadge()` in `src/badge.ts`

### 7.4 NIP Engagement

Once Signet has real-world agent delegations deployed (even a handful), the entity type system and `["agent-type", ...]` tag should be proposed as an additive extension to NIP-XX and NIP-AC. Signet does not need to own the NIP — it needs to be compatible with whatever agent coordination layer wins. The credential chain is orthogonal to message format.

The engagement path is the same as for the core protocol: code and adoption first, NIP proposal second. One verified DVM with a delegation chain visible in a client is more persuasive than a specification alone.

---

## 8. Summary

| Problem | Signet Solution | Status |
|---|---|---|
| Who operates this agent? | Kind 30477 delegation from verified operator | Spec complete, needs examples |
| Is the operator accountable? | Tier 3 operator has professional skin in the game | Protocol supports this |
| What can the agent do? | Scoped delegation (content-management, etc.) | Kind 30477 supports scope tags |
| Can I revoke a rogue agent? | Kind 30475 revocation cascades immediately | Implemented |
| Is a human or AI currently in control? | `["mode", ...]` tag on each event | Spec complete |
| How do I distinguish AI from human delegates? | Proposed `["agent-type", "ai"]` tag | New — needs spec addition |
| How do DVMs signal operator trust? | Tier 3 operator + delegation chain = trust badge | Display layer only, no NIP change |

The protocol is ready. The documentation and examples are not. This document is step one.
