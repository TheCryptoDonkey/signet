# Signet Verify — Age Verification SDK

Add privacy-preserving age verification to any website. One script tag, one function call. No personal data collected.

## Quick Start

```html
<script src="https://cdn.signet.trotters.cc/signet-verify.js"></script>
<script>
  document.getElementById('verify-btn').addEventListener('click', async () => {
    const result = await Signet.verifyAge('18+');
    if (result.verified) {
      // User is verified as 18+ by a confirmed professional
      console.log('Verified! Tier:', result.tier);
    } else {
      console.log('Not verified:', result.error);
    }
  });
</script>
<button id="verify-btn">Verify your age</button>
```

## How It Works

1. Website calls `Signet.verifyAge('18+')`
2. A modal appears with a QR code
3. User scans with their Signet app and approves
4. The app sends a cryptographic proof (no PII)
5. The SDK verifies the proof AND checks the verifier's professional registration
6. Returns the result — the user's app can be closed

## Verifier Trust

By default, the SDK checks the verifier's professional registration against public registers (GMC, SRA, TRA, etc.) via the Signet verification bot. This prevents fake professional rings from issuing accepted credentials.

- **Default:** `verified: true` only when the verifier is confirmed against a public register
- **Configurable:** websites can accept unconfirmed verifiers or point to their own verification bot
- **Decentralised:** the verification bot is open source — anyone can run their own

```javascript
// Default: safe — only confirmed verifiers pass
const result = await Signet.verifyAge('18+');

// Accept unconfirmed verifiers (less safe, more permissive)
const result = await Signet.verifyAge('18+', { acceptUnconfirmed: true });

// Use your own verification bot
const result = await Signet.verifyAge('18+', { verifierCheckUrl: 'https://my-bot.example.com' });

// Skip verifier checking entirely
const result = await Signet.verifyAge('18+', { verifierCheckUrl: null });
```

## API

### `Signet.verifyAge(requiredAgeRange, options?)`

Returns `Promise<SignetVerifyResult>`

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `relayUrl` | `string` | `wss://relay.damus.io` | Relay URL for cross-device communication |
| `theme` | `'light' \| 'dark' \| 'auto'` | `'auto'` | Modal colour scheme |
| `timeout` | `number` | `120000` | Timeout in milliseconds |
| `verifierCheckUrl` | `string \| null` | `'https://verify.signet.trotters.cc'` | Verification bot URL. Set to `null` to skip. |
| `acceptUnconfirmed` | `boolean` | `false` | Accept credentials from unconfirmed verifiers |

**Result:**

| Field | Type | Description |
|-------|------|-------------|
| `verified` | `boolean` | `true` if credential valid, age range met, AND verifier confirmed (or `acceptUnconfirmed` is true) |
| `ageRange` | `string \| null` | Age range from the credential (e.g. `'18+'`) |
| `tier` | `number \| null` | Verification tier (1–4) |
| `entityType` | `string \| null` | `'natural_person'`, `'persona'`, etc. |
| `verifierPubkey` | `string \| null` | Professional keypair of the issuing verifier |
| `verifierConfirmed` | `boolean \| null` | Whether the verifier is confirmed against a public register. `null` if check unavailable. |
| `verifierMethod` | `'A' \| 'B' \| 'C' \| 'D' \| null` | How the verifier was confirmed: A=NIP-05 on body domain, B=body-issued, C=cross-verified, D=website |
| `issuedAt` | `number \| null` | Unix timestamp of credential issuance |
| `expiresAt` | `number \| null` | Unix timestamp of credential expiry |
| `error` | `string \| undefined` | Error code (see below) |

**Error codes:**

| Error | Meaning |
|-------|---------|
| `'cancelled'` | User cancelled the verification |
| `'timeout'` | Verification timed out (default: 2 minutes) |
| `'invalid-credential'` | Credential signature failed verification |
| `'age-range-not-met'` | Credential age range doesn't satisfy the requirement |
| `'verifier-not-confirmed'` | Verifier is not confirmed against a public register |
| `'verifier-check-unavailable'` | Verification bot unreachable (credential valid but verifier status unknown) |

## Age Range Values

| Value | Meaning |
|-------|---------|
| `'0-3'` | Ages 0–3 |
| `'4-7'` | Ages 4–7 |
| `'8-12'` | Ages 8–12 |
| `'13-17'` | Ages 13–17 |
| `'18+'` | Adult (18 and over) |

## Privacy

- No personal data is transmitted — only a cryptographic proof of age range
- No account creation required on the website
- No cookies beyond session management
- The proof is verified entirely in the browser — no server-side API calls needed
- Verifier check is a single GET request returning confirmed/not — no user data sent
- Compliant with GDPR, COPPA, UK Online Safety Act, France SREN law
