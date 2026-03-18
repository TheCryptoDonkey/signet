# Contributing to Signet

Feedback, NIP discussion, and contributions are welcome. Open an issue or submit a PR.

## Setup

```bash
git clone https://github.com/forgesworn/signet-protocol.git
cd signet
npm install
```

## Development

```bash
# Run all tests
npm test

# Typecheck
npm run typecheck

# Build
npm run build
```

## Project Structure

```
src/          — Protocol library (TypeScript, no framework dependencies)
tests/        — Protocol tests (vitest)
spec/         — Protocol specification (source of truth)
examples/     — Example flows
docs/         — Developer documentation
```

## Conventions

- **British English** — colour, initialise, behaviour, licence
- **Spec-first** — if you find a gap in the spec, update `spec/protocol.md` first, then fix the code
- **Commit messages** — `type: description` (e.g. `feat:`, `fix:`, `docs:`, `refactor:`)
- **Security** — see the Security Conventions section in `CLAUDE.md` for crypto and validation patterns
- **Tests** — all changes must pass `npm test` and `npm run typecheck`

## Licence

MIT
