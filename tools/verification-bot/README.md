# Signet Verification Bot

A reference implementation of a Signet verifier-credential checker. It
periodically fetches Kind 30473 (verifier credential) events from a Nostr
relay, looks up the stated licence numbers against public professional
registers, caches results in SQLite, and publishes findings back to the relay
as Kind 1 notes.

Anyone can run their own instance — the bot is intentionally self-contained
and has no central authority.

## How to run

```bash
npm install
npm start        # production
npm run dev      # auto-restart on file changes (Node --watch)
```

The server starts on **port 3847** by default.

## Environment variables

| Variable    | Default                 | Description                        |
|-------------|-------------------------|------------------------------------|
| `PORT`      | `3847`                  | HTTP port to listen on             |
| `RELAY_URL` | `ws://localhost:7777`   | Nostr relay WebSocket URL          |

Example:

```bash
RELAY_URL=wss://relay.example.com PORT=4000 npm start
```

## Endpoints

| Method | Path               | Description                                               |
|--------|--------------------|-----------------------------------------------------------|
| GET    | `/`                | Health check — returns bot status and total tracked count |
| GET    | `/status/:pubkey`  | Returns the cached check result for a verifier pubkey     |
| POST   | `/check/:pubkey`   | Triggers an immediate check for the given pubkey          |
| GET    | `/stats`           | Returns totals: confirmed, unconfirmed, flagged, errored  |

### Example

```bash
# Trigger a check
curl -X POST http://localhost:3847/check/<64-char-pubkey>

# Read the cached result
curl http://localhost:3847/status/<64-char-pubkey>

# Overall stats
curl http://localhost:3847/stats
```

## Supported registers

| Jurisdiction | Profession          | Registry                         |
|--------------|---------------------|----------------------------------|
| GB / UK      | Doctor / Physician  | GMC (General Medical Council)    |
| GB / UK      | Solicitor / Lawyer  | SRA (Solicitors Regulation Auth) |
| Others       | —                   | Marked `unconfirmed` (add more)  |

To add a new jurisdiction, add a checker function to the `REGISTRY_CHECKERS`
object in `index.js` and extend the `resolveChecker` function.

## Check results

| Value         | Meaning                                                         |
|---------------|-----------------------------------------------------------------|
| `confirmed`   | Licence number found in the public register                     |
| `unconfirmed` | No checker implemented for this jurisdiction, or not found      |
| `flagged`     | Anomaly detected (volume / geographic / temporal mismatch)      |
| `error`       | Network failure or no credential event found on relay           |

## SQLite database

Results are stored in `verification-bot.db` in the working directory. The
database is created automatically on first run.

## Notes

- The bot generates a keypair on first run and stores it in SQLite. Event
  signing in this reference implementation uses a SHA-256 stub — a production
  deployment should replace this with a proper secp256k1 Schnorr signature
  (e.g. using `@noble/secp256k1`).
- Registry HTML checks are inherently fragile. If a register changes its
  markup, update the checker or switch to an official API.
- This is a reference implementation. No warranties; use at your own risk.
