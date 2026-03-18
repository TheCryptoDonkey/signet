# Signet W3C Verifiable Credential Bridge

## What This Is

A JSON-LD context definition and mapping specification for expressing Signet Kind
30470 credentials as W3C Verifiable Credentials (VCDM v2.0) using the `did:nostr`
DID method.

The JSON-LD context is located at `docs/signet-vc-context.jsonld` and is intended
to be hosted at `https://signet.forgesworn.dev/ns/v1` when the protocol goes live.

---

## Why

Signet credentials are Nostr-native events. The W3C Verifiable Credentials
ecosystem (DIF, academic institutions, US state digital wallets, enterprise SSI
deployments) expects a different wire format with JSON-LD context, a `did:` issuer
URI, and a Data Integrity proof block.

This bridge is an **additive interoperability layer**. The original Nostr event is
preserved inside the `proof.nostrEvent` field. The W3C VC envelope is generated on
top and can be passed to any W3C VC-compatible verifier without requiring that
verifier to understand Nostr.

The `did:nostr` method specification (published by the W3C Nostr Community Group at
https://nostrcg.github.io/did-nostr/) derives a DID directly from a Nostr public
key. This means no separate DID registration is required — every Signet pubkey is
already a valid `did:nostr` identifier.

The proof type used is `SchnorrSecp256k1Signature2019` (DIF specification:
https://identity.foundation/SchnorrSecp256k1Signature2019/), which wraps a
Schnorr/secp256k1 signature as a detached JWS. This is structurally compatible
with the BIP-340 signatures Nostr already produces.

---

## How It Works

### Field Mapping

The table below shows how each Signet Kind 30470 tag maps to the W3C Verifiable
Credential Data Model v2.0.

| Signet Field | W3C VC Field | Notes |
|---|---|---|
| `pubkey` (event) | `issuer` | `did:nostr:<verifier_pubkey>` |
| `["d", <subject>]` tag | `credentialSubject.id` | `did:nostr:<subject_pubkey>` |
| `["tier", "3"]` tag | `credentialSubject.signetTier` | Integer 1–4 |
| `["type", "professional"]` tag | `credentialSubject.verificationMethod` | `self`, `peer`, or `professional` |
| `["scope", "adult"]` tag | `credentialSubject.signetScope` | `adult` or `adult+child` |
| `["age-range", "8-12"]` tag | `credentialSubject.ageRange` | e.g. `18+`, `8-12` |
| `["entity-type", <t>]` tag | `credentialSubject.entityType` | `natural_person`, `persona`, `juridical_person`, etc. |
| `["profession", "solicitor"]` tag | `credentialSubject.profession` | Verifier's licensed profession |
| `["jurisdiction", "GB"]` tag | `credentialSubject.jurisdiction` | ISO 3166-1 alpha-2 country code |
| `["nullifier", <h>]` tag | `credentialSubject.nullifier` | Hex-encoded SHA-256, length-prefixed encoding (§20.7) |
| `["merkle-root", <r>]` tag | `credentialSubject.merkleRoot` | Hex-encoded root of verified-attributes Merkle tree |
| `["expires", <unix_ts>]` tag | `expirationDate` | Unix timestamp converted to ISO 8601 |
| `created_at` (event) | `validFrom` | Unix timestamp converted to ISO 8601 |
| `sig` (Schnorr/BIP-340) | `proof.proofValue` | SchnorrSecp256k1Signature2019 detached JWS |

Notes on fields not present in the Kind 30470 tag list:
- `signetIQ` (Signet IQ score) is a computed value derived from vouches, account
  age, and tier. It is NOT a tag on the credential event. If included in a VC, it
  must be computed by the wrapping library at the time of VC generation and treated
  as informational rather than cryptographically attested.
- `documentExpiry` is a Merkle tree leaf value (not a top-level tag). It can only
  be disclosed selectively via Merkle proof — it is not included in the base VC
  envelope unless the subject consents to selective disclosure.
- `photoHash` is likewise a Merkle tree leaf. Same selective-disclosure rules apply.
- `guardianPubkey` appears as `["guardian", "<parent_pubkey>"]` tags on child
  credentials (Tier 4). Multiple guardian tags are supported (joint custody).
- `agentType` appears as `["agent-type", <type>]` on delegation events (Kind 30477),
  not on credential events directly.

### Resolution Strategy

A W3C VC verifier receiving a Signet VC resolves the issuer DID as follows:

1. Parse `issuer` as `did:nostr:<pubkey>`.
2. Attempt HTTP resolution: check `/.well-known/did.json` at the verifier's domain
   (if the verifier has published one).
3. Fall back to offline resolution: construct a minimal DID document directly from
   the 32-byte pubkey.
4. Optionally enhance via Nostr relay query (NIP-65 / profile metadata).

A live HTTP resolver is available at `nostr.rocks`. A TypeScript library
`nostr-did-resolver` is available for programmatic resolution.

---

## Example

A complete Signet Kind 30470 event wrapped as a W3C Verifiable Credential
(VCDM v2.0 with Data Integrity proof):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://signet.forgesworn.dev/ns/v1"
  ],
  "type": ["VerifiableCredential", "SignetCredential"],
  "issuer": "did:nostr:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
  "validFrom": "2026-03-16T12:00:00Z",
  "expirationDate": "2028-03-16T12:00:00Z",
  "credentialSubject": {
    "id": "did:nostr:def456abc123def456abc123def456abc123def456abc123def456abc123def4",
    "signetTier": 3,
    "entityType": "natural_person",
    "verificationMethod": "professional",
    "signetScope": "adult",
    "ageRange": "18+",
    "profession": "solicitor",
    "jurisdiction": "GB",
    "nullifier": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "merkleRoot": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
  },
  "proof": {
    "type": "SchnorrSecp256k1Signature2019",
    "created": "2026-03-16T12:00:00Z",
    "verificationMethod": "did:nostr:abc123def456abc123def456abc123def456abc123def456abc123def456abc1#key-0",
    "proofPurpose": "assertionMethod",
    "jws": "eyJhbGciOiJTUzI1NksifQ...<detached-jws>",
    "nostrEvent": {
      "kind": 30470,
      "pubkey": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      "created_at": 1773403200,
      "tags": [
        ["d", "def456abc123def456abc123def456abc123def456abc123def456abc123def4"],
        ["p", "def456abc123def456abc123def456abc123def456abc123def456abc123def4"],
        ["tier", "3"],
        ["type", "professional"],
        ["scope", "adult"],
        ["profession", "solicitor"],
        ["jurisdiction", "GB"],
        ["expires", "1836475200"],
        ["entity-type", "natural_person"],
        ["nullifier", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"],
        ["merkle-root", "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"],
        ["algo", "secp256k1"],
        ["L", "signet"],
        ["l", "verification", "signet"]
      ],
      "content": "<base64url-encoded-bulletproof-blob>",
      "id": "deadbeef...",
      "sig": "abcdef01..."
    }
  }
}
```

Key points about this structure:

- The `nostrEvent` inside `proof` preserves the original Nostr event verbatim.
  This allows a Nostr-native verifier to re-validate using standard Nostr tooling
  without any VC-layer knowledge.
- The `content` field (Bulletproof age-range proof blob) is preserved as an opaque
  base64url-encoded value. It cannot be expressed in plain JSON-LD and is not
  semantically typed in the context. A VC verifier that does not understand
  Bulletproofs can ignore this field; a Nostr-native verifier can verify it.
- The VCDM v2.0 `validFrom` field replaces the v1.0 `issuanceDate`. Any library
  targeting v1.1 contexts should use `issuanceDate` instead for backwards
  compatibility.

---

## What This Does NOT Do

This context and bridge specification does NOT:

- **Make Signet credentials valid ISO mDocs.** ISO 18013-5 mDoc requires credentials
  to be issued under an IACA (Issuing Authority Certificate Authority) government-
  rooted PKI chain. Signet's trust anchor is licensed professionals, not government
  certificate authorities. These are structurally different trust models.
- **Make Signet credentials compatible with EUDI Wallet.** The EU Digital Identity
  Wallet Architecture Reference Framework mandates ISO mDoc and SD-JWT VC as the
  credential formats, issued via OID4VCI. This bridge produces W3C VC format, which
  is referenced but not mandated by EUDI. A separate mDoc issuance pathway would be
  required for EUDI compatibility.
- **Validate the Bulletproof.** The `proof` block carries the Nostr event's BIP-340
  Schnorr signature as the Data Integrity proof. The Bulletproof age-range proof
  stored in `content` is included as an opaque field — W3C VC tooling cannot
  evaluate it.
- **Replace the Nostr event.** The original Kind 30470 event is the authoritative
  source of truth. The W3C VC envelope is a view over that event for interoperability
  purposes.

This bridge is suitable for: DIF ecosystem interoperability, academic and standards
discussions, US state digital wallet integrations, and enterprise SSI deployments
that require W3C VC format. It is not a substitute for mDoc/SD-JWT work targeting
EU eIDAS 2.0 compliance.

---

## Status

Draft. The context URL `https://signet.forgesworn.dev/ns/v1` is a placeholder.
It must be hosted at a stable URL before this bridge can be used in production.
The JSON-LD context file is `docs/signet-vc-context.jsonld` in this repository.

The `SchnorrSecp256k1Signature2019` suite is a DIF experimental specification
(https://identity.foundation/SchnorrSecp256k1Signature2019/), not a W3C Standard.
It is the closest existing proof type to what Nostr uses, but implementers should
monitor the W3C Data Integrity working group for a standardised Schnorr/secp256k1
cryptosuite.

---

## References

- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Verifiable Credential Data Integrity 1.1](https://w3c.github.io/vc-data-integrity/)
- [Nostr DID Method Specification](https://nostrcg.github.io/did-nostr/)
- [SchnorrSecp256k1Signature2019 — DIF](https://identity.foundation/SchnorrSecp256k1Signature2019/)
- [Signet Protocol Specification](../spec/protocol.md) — Kind 30470, §20.7 nullifiers, §20.3 Merkle trees

