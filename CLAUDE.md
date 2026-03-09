# CLAUDE.md — Signet Protocol

## What This Is

Signet is an open-source identity verification protocol for Nostr. It uses zero-knowledge proofs to let users prove claims about their identity without revealing personal data.

This repo contains:
- `spec/protocol.md` — the full protocol specification
- `spec/voting.md` — voting extension specification (linkable ring signatures, elections)
- `src/` — TypeScript protocol library (npm publishable)
- `app/` — Reference web app (React + Vite, imports the protocol library)
- `family-app/` — My Signet family app (React + Vite, production-ready, normie-friendly)
- `examples/` — example event payloads and flows
- `legal/` — legal documents in multiple languages
- `docs/plans/` — design and implementation plans
- `docs/signet-in-5-minutes.md` — one-page developer overview
- `docs/implementation-levels.md` — three-level integration guide for client developers

## Key Concepts

- **4 verification tiers**: Tier 1 (self-declared) → Tier 2 (web-of-trust) → Tier 3 (professional adult) → Tier 4 (professional adult+child)
- **8 core event kinds** (30470-30477): credential, vouch, policy, verifier, challenge, revocation, identity bridge, delegation
- **3 voting extension event kinds** (30478-30480): election, ballot, election result
- **9 entity types**: Natural Person, Persona, Personal Agent, Free Personal Agent, Juridical Person, Juridical Persona, Organised Agent, Free Organised Agent, Free Agent
- **Two-credential ceremony**: Professional verification issues Natural Person credential (with nullifier, Merkle root) + Persona credential (anonymous, age-range only) simultaneously
- **Document-based nullifiers**: SHA-256(docType||country||docNumber||"signet-uniqueness-v1") prevents duplicate identity without revealing documents
- **Multi-document nullifier families**: All documents presented during verification produce nullifiers; collision with ANY nullifier detects duplicates
- **Jurisdiction confidence**: Scored 0-100 based on professional body coverage, public registers, digital credentials, data protection maturity, mutual recognition
- **3 implementation levels**: Level 1 (read badges, a weekend) → Level 2 (issue vouches, days) → Level 3 (full protocol, weeks+)
- **Badge display library**: `src/badge.ts` — drop-in Level 1 integration for any Nostr client
- **Credential chains**: `supersedes`/`superseded-by` tags for lifecycle events (name change, document renewal, tier upgrade)
- **Guardian delegation**: Kind 30477 events with scopes (full, activity-approval, content-management, contact-approval) for family structures
- **Merkle selective disclosure**: Verified attributes as private leaves, only root published on-chain
- **Crypto stack**: Schnorr (secp256k1 base) + Bulletproofs (age range proofs) + future ZK layer
- **No central authority**: professional bodies (Law Society, medical boards, notary commissions) are the trust anchors
- **"Signet me"**: Time-based word verification (configurable 1-16 words, default 3) powered by canary-kit's CANARY-DERIVE and spoken-clarity wordlist
- **BIP-39 / NIP-06**: Identity derived from 12-word mnemonic, Shamir backup supported
- **canary-kit dependency**: Word derivation and encoding delegated to canary-kit/token and canary-kit/encoding for protocol alignment
- **Child safety**: Age-range proofs on all tiers, guardian-linked sub-accounts, client display requirements for age-gap warnings

## Relationship to Fathom

Fathom (https://github.com/decented/decented) is the first reference implementation. Signet is protocol-level — it doesn't depend on Fathom or any specific client.

## Development Workflow

### After ANY code change, you MUST:

1. **Run the full test suite** — `node node_modules/vitest/vitest.mjs run` (protocol) and app tests if applicable
2. **Run typecheck** — `node node_modules/typescript/bin/tsc --noEmit`
3. **If a bug is found and fixed**, update `spec/protocol.md` with any clarifications needed so the spec is sufficient to rebuild from scratch without hitting the same bug
4. **Commit** the code changes, test fixes, and any spec updates together
5. **Push** to remote

Never claim work is complete without fresh test output confirming it passes. Evidence before assertions.

### Pacing and Accuracy

This is a protocol that others will build on. Correctness matters more than speed. Follow these rules:

1. **Verify before presenting.** When building analysis tables, mappings, or logical arguments, re-read each row/cell and confirm it's correct before showing it to the user. Don't rush tables — wrong analysis is worse than slow analysis.
2. **Re-read the user's words.** When the user proposes options (A, B, C), re-read their exact descriptions before summarising or mapping them. Don't paraphrase from memory — go back to what they actually said.
3. **Check assumptions in tests.** When writing tests with hardcoded values, verify the arithmetic (e.g., does this timestamp actually fall where I think it does in the epoch?).
4. **Say "I'm not sure" when you're not sure.** This is a protocol with legal, cryptographic, and social implications. Confident-sounding wrong answers are dangerous. If a claim needs verification, say so.
5. **Slow down during brainstorming.** Design discussions set the foundation for everything built on top. Take time to reason carefully about edge cases, naming, and category boundaries. Getting the model right matters more than getting it fast.

### Spec-First Development

The spec (`spec/protocol.md`) is the source of truth. If implementation reveals ambiguity, underspecification, or an error in the spec, **update the spec first**, then fix the code. The spec must always be complete enough that a new implementer could rebuild the system from the spec alone.

## Project Structure

```
Signet/
├── src/          — Protocol library (TypeScript, no framework dependencies)
├── tests/        — Protocol tests (vitest)
├── app/          — Reference web app (React + Vite + TypeScript)
├── family-app/   — My Signet family app (React + Vite + TypeScript)
├── spec/         — Protocol specification
├── examples/     — Example flows
├── legal/        — Legal documents (multi-language)
├── docs/plans/   — Design and implementation plans
├── dist/         — Compiled protocol library output
└── .github/      — CI workflows
```

## Commands

```bash
# Protocol
node node_modules/vitest/vitest.mjs run       # run protocol tests
node node_modules/typescript/bin/tsc --noEmit  # typecheck protocol

# App (from app/ directory)
npm run dev                                     # start dev server
npm run build                                   # production build
npm run typecheck                               # typecheck app

# Family App (from family-app/ directory)
npm run dev                                     # start dev server (port 5175)
npm run build                                   # production build
npm run typecheck                               # typecheck family app
```

## Port Allocation

- **5174** — Signet reference app (HTTPS, self-signed cert)
- **5175** — My Signet family app (HTTPS, self-signed cert)
- Avoid: 3000, 5173, 7777, 7778, 8787 (in use by other services)

## Subagent Model Selection

When dispatching subagents via the Agent tool, choose the model based on task complexity:

- **Haiku** — file searches, codebase exploration, simple lookups, summarising content, simple questions
- **Sonnet** — well-defined implementation tasks with clear instructions, straightforward code changes, find-and-replace edits, running tests, code reviews
- **Opus** — complex multi-step reasoning, architectural decisions, ambiguous requirements, large refactors with many interdependent changes, brainstorming and design work

Default to **Sonnet** unless the task genuinely needs Opus-level reasoning. Prefer the cheapest model that can reliably complete the task.

### Guidance by agent type

| Agent type | Default model | Rationale |
|------------|---------------|-----------|
| `Explore` | Haiku | Read-only, no Edit/Write tools — fast search is all that's needed |
| `general-purpose` | Sonnet | Most implementation work is well-scoped by the time it's dispatched |
| `Plan` | Opus | Planning benefits from deeper reasoning about trade-offs |
| `superpowers:code-reviewer` | Sonnet | Review against known criteria is systematic, not creative |

### Guidance by skill

| Skill | Recommended model | Rationale |
|-------|-------------------|-----------|
| `brainstorming` | Opus | Exploring intent, requirements, and design needs strong reasoning |
| `writing-plans` | Opus | Multi-step planning with architectural trade-offs |
| `executing-plans` | Sonnet | Following an already-written plan with clear steps |
| `subagent-driven-development` | Sonnet (per subagent) | Each subagent gets a well-scoped task from the plan |
| `test-driven-development` | Sonnet | Writing tests and implementation from clear requirements |
| `systematic-debugging` | Sonnet | Structured process; escalate to Opus if root cause is elusive |
| `requesting-code-review` | Sonnet | Checking work against known requirements |
| `verification-before-completion` | Haiku | Running commands and confirming output — minimal reasoning needed |
| `finishing-a-development-branch` | Sonnet | Straightforward merge/PR workflow |
