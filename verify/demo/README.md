# Signet Verify — Demo Site

A minimal age-gated page demonstrating the `signet-verify` SDK.

## Setup

### 1. Build the SDK

```bash
cd ..
npm run build
```

This produces `dist/signet-verify.js`, which the demo page loads directly.

### 2. Serve the demo

```bash
npx serve .
```

Then open `http://localhost:3000` in your browser.

## Known Verifier

The demo is pre-configured to accept attestations from a single known verifier keypair
(generated for this MVP demo).

**Verifier public key (hex):**

```
02a1aa16af3f355ada9bd6e20baad6927e0ea5e9a02e06e5808045309c4a8511
```

## Importing the Verifier into My Signet

To act as the verifier and issue attestations:

1. Open the My Signet app (`signet-app/`)
2. Navigate to **Settings → Import Key**
3. Paste the verifier `nsec` (stored separately — do not commit it)
4. The app will load the verifier identity, allowing you to issue age attestations

Once an attestation is published to `wss://nos.lol` with a user's pubkey and `ageRange: "18+"`,
clicking **Verify My Age** in the demo page will resolve successfully.
