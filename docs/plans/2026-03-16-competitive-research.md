# Competitive Research Note — 2026-03-16

Three topics relevant to Signet's roadmap: the did:nostr → W3C VC bridge, Google's
longfellow-zk library, and the EU age verification technical specification.

---

## Topic 1: Nostr DID Method → W3C Verifiable Credential Bridge

### What is did:nostr?

The W3C Nostr Community Group (nostrcg) publishes an unofficial draft DID method
specification at https://nostrcg.github.io/did-nostr/. It is not a W3C Standard and
is not on the Standards Track, but it is actively maintained and has real
implementations.

**How did:nostr works:**

A `did:nostr` identifier is derived directly from a Nostr public key (32-byte
x-only BIP-340 format):

```
did:nostr:npub1<bech32-encoded-pubkey>
```

Resolution supports three strategies:

| Strategy | Mechanism | Speed |
|---|---|---|
| HTTP resolution | Check `/.well-known/did.json` at a domain | Fastest |
| Offline-first | Generate minimal DID document from pubkey alone | Instant, no network |
| Enhanced resolution | Query Nostr relays for NIP-65 / profile metadata | Richest metadata |

The resulting DID document uses JSON-LD context
`["https://w3id.org/did", "https://w3id.org/nostr/context"]` and encodes the
secp256k1 Schnorr public key using the W3C Data Integrity **Multikey**
verification method. The x-only 32-byte key is extended to a 33-byte compressed
form (parity byte prepended) then Multibase base16-lower encoded.

A live HTTP resolver exists at `nostr.rocks` and a TypeScript library
`nostr-did-resolver` is available.

### W3C VC Data Model v2.0 (Recommendation, May 2025) Requirements

The W3C Verifiable Credentials Data Model v2.0 became a full Recommendation in
May 2025. The essential fields a conforming Verifiable Credential must have:

| Field | Requirement | Notes |
|---|---|---|
| `@context` | MUST include `https://www.w3.org/ns/credentials/v2` | JSON-LD context |
| `type` | MUST include `VerifiableCredential` | Plus credential-specific type |
| `issuer` | MUST be a URI (DID) | The credential issuer |
| `validFrom` | MUST be an ISO 8601 datetime | Replaces `issuanceDate` from v1 |
| `credentialSubject` | MUST be present | Subject claims |
| `proof` | RECOMMENDED (securing mechanism) | One of Data Integrity or JWT |

The **securing mechanism** for a Nostr-native VC would use the W3C Data Integrity
1.1 spec, which went to Recommendation alongside VCDM v2.0. The relevant
cryptosuite for Nostr keys is either:

- **`ecdsa-sd-2023`** — but this uses ECDSA, not Schnorr
- **`SchnorrSecp256k1Signature2019`** — DIF spec, uses Schnorr over secp256k1 with
  detached JWS (`SS256K` algorithm), an unregistered experimental suite

The DIF's SchnorrSecp256k1Signature2019 suite (https://identity.foundation/SchnorrSecp256k1Signature2019/)
is the closest existing proof type to what Nostr uses. It wraps a Schnorr/secp256k1
signature as a detached JWS, which is structurally compatible with the BIP-340
signatures that Nostr (and therefore Signet) already produces.

### What the Bridge Would Look Like for Signet Kind 30470

A Signet Kind 30470 credential is a Nostr event. The raw fields map to W3C VC
concepts as follows:

| Nostr / Signet field | W3C VC field | Notes |
|---|---|---|
| `pubkey` (issuer) | `issuer` | Encoded as `did:nostr:<pubkey>` |
| `created_at` | `validFrom` | Unix timestamp → ISO 8601 |
| tag `["p", <subject>]` | `credentialSubject.id` | Subject's `did:nostr` |
| tag `["tier", "3"]` | `credentialSubject.signetTier` | Signet-specific claim |
| tag `["scope", "adult"]` | `credentialSubject.verificationScope` | Signet-specific claim |
| tag `["expires", <t>]` | `expirationDate` | |
| tag `["nullifier", <h>]` | `credentialSubject.nullifier` | Privacy-preserving |
| tag `["merkle_root", <r>]` | `credentialSubject.merkleRoot` | Selective disclosure root |
| `content` (ZKP blob) | `credentialSubject.ageRangeProof` | Bulletproof bytes |
| `sig` (Schnorr/BIP-340) | `proof.proofValue` | SchnorrSecp256k1Signature2019 |

The wrapping would be additive: the original Nostr event is preserved inside a
`proof.nostrEvent` field, and the W3C VC envelope is generated on top. This is
the same pattern used by the ATProto/Bluesky DID bridge work.

**Concrete steps needed:**

1. Publish a JSON-LD context at a stable URL defining Signet-specific credential
   terms (`signetTier`, `verificationScope`, `nullifier`, `merkleRoot`,
   `ageRangeProof`).
2. Implement a `SignetCredential2026` cryptosuite (or reuse
   `SchnorrSecp256k1Signature2019`) that maps `sig` + `id` fields to a
   Data Integrity `proof` block.
3. Implement a resolver plugin for `did:nostr` so that VC verifiers can look up
   the issuer's public key.
4. The Bulletproof blob in `content` cannot be expressed in plain JSON-LD — it
   would be base64url-encoded as an opaque proof value, referencing a
   `proofType: BulletproofAgeRange` claim type.

### Is this Worth Pursuing for EU eIDAS 2.0?

eIDAS 2.0 (Regulation (EU) 2024/1183, in force May 2024, full rollout by end of
2026) does NOT require W3C VCs. The EUDI Wallet Architecture Reference Framework
specifies ISO mDoc and SD-JWT VC as the mandatory credential formats. W3C VCs
with Data Integrity proofs are referenced but not mandated for the EUDI wallet
itself.

**Assessment:** The did:nostr → W3C VC bridge is worth a limited investment as an
interoperability layer for non-EU ecosystems (e.g., US state digital wallets, Web5
ecosystems, enterprise SSI deployments using W3C VCs). For EU eIDAS 2.0
compliance specifically, the bridge alone is insufficient — Signet would also need
to support ISO mDoc issuance via OID4VCI. The bridge is a 3-6 month independent
work item that could run in parallel with, but does not substitute for, mDoc/SD-JWT
work.

**Sources:**
- [Nostr DID Method Specification](https://nostrcg.github.io/did-nostr/)
- [GitHub: nostrcg/did-nostr](https://github.com/nostrcg/did-nostr)
- [SchnorrSecp256k1Signature2019 — DIF](https://identity.foundation/SchnorrSecp256k1Signature2019/)
- [GitHub: decentralized-identity/SchnorrSecp256k1Signature2019](https://github.com/decentralized-identity/SchnorrSecp256k1Signature2019)
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Verifiable Credential Data Integrity 1.1](https://w3c.github.io/vc-data-integrity/)
- [Nostr ↔ W3C Interoperability (Medium)](https://medium.com/@itsliran/working-towards-interoperability-decentralized-identifiers-decentralized-web-nodes-verifiable-91839cb98f16)

---

## Topic 2: Google longfellow-zk

### What Google Built

**Repository:** https://github.com/google/longfellow-zk
**Docs site:** https://google.github.io/longfellow-zk/
**IETF draft:** https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/
**Blog post:** https://blog.google/technology/safety-security/opening-up-zero-knowledge-proof-technology-to-promote-privacy-in-age-assurance/

Google open-sourced longfellow-zk in mid-2025. It is named after the bridge near
their Cambridge office. The library implements ZK protocols designed specifically
for legacy identity document formats (ISO mDoc/mDL, JWT, W3C VCs). It was
developed in partnership with Sparkasse and is the ZK engine powering age
assurance in Google Wallet.

### Cryptographic Approach

Longfellow-zk is **not** Bulletproofs and **not** a standard SNARK. It is a novel
combination:

| Component | What it does |
|---|---|
| **Ligero** | MPC-in-the-head argument system, no trusted setup, symmetric-key operations only |
| **Sum-Check protocol** | Verifiable computation protocol; combined with Ligero for efficient circuit evaluation |
| **Reed-Solomon encoding** | Efficient field operations over required extension fields |
| **Specialised ECDSA circuit** | Optimised for P-256 ECDSA + SHA-256 as found in ISO mDocs |

The algorithm was developed by Ligero Inc. (a startup founded in 2018 as a Yale
spinout) and licensed to Google. Google refers to the deployed version as
"Google-zk."

**Proof system properties:**

| Property | Longfellow-zk | Bulletproofs | Groth16 (SNARK) |
|---|---|---|---|
| Trusted setup | None (transparent) | None (transparent) | Required |
| Prover time (ECDSA) | ~60 ms (native) | N/A (different circuit type) | Fast but setup-dependent |
| Full mDoc flow (mobile) | ~1.2 s | Not designed for this | Not designed for this |
| Proof size | Moderate (sublinear in circuit size) | Logarithmic in statement size | Very small (constant) |
| Primitive basis | Symmetric crypto (hash-based) | Elliptic curve (inner product) | Pairing-based ECC |
| WASM support | Yes (SIMD128 routines) | Varies | Varies |

### What Longfellow-zk Proves

The two core circuits:
1. **ECDSA P-256 signature verification** — proves "I know a document signed by
   the issuer's P-256 key" without revealing the document
2. **SHA-256 hash chain** — proves "this document contains attribute X satisfying
   predicate P" (e.g. `age_over_18 == true`)

These circuits target the specific cryptographic primitives in ISO 18013-5 mDocs
and the `com.google.wallet.idcard.1` Google IDPass format. They are NOT
general-purpose ZK systems for arbitrary circuits.

### Licence

Apache 2.0 (confirmed by multiple secondary sources; the GitHub repository is a
Google open-source project). Two independent academic/industry security reviews
are in progress as of release, with reports to be published in project documentation.

### Integration with Google Wallet

Google Wallet now issues age attestations using this ZK system:
1. User scans a government mDL or ID card into Google Wallet.
2. When a website requests age verification via the W3C Digital Credentials API,
   Wallet generates a ZK proof using longfellow-zk.
3. The proof proves `age_over_18 = true` (or other age predicates) derived from
   the ECDSA-signed mDoc, without releasing any other identity data.
4. The verifier receives only the proof + the issuer's IACA certificate chain.

This is the same flow the EU age verification blueprint uses (see Topic 3).

### How It Compares to Signet's Bulletproofs Age-Range Proofs

Signet currently uses Bulletproofs for age-range proofs. The differences are
fundamental:

| Dimension | Signet (Bulletproofs) | Google (longfellow-zk) |
|---|---|---|
| **Input credential format** | Signet-native (Nostr event, Kind 30470) | ISO mDoc / mDL (government document) |
| **What is being proved** | Age range ("18+" or "8-12") asserted by a human verifier | Age range derived directly from a government-issued document |
| **Trust anchor** | Licensed professional (verifier network) | Government document issuer (IACA cert chain) |
| **ZK scheme** | Bulletproofs (inner product argument, secp256k1) | Ligero + Sum-Check (symmetric, P-256 ECDSA) |
| **Proof size** | Logarithmic (compact) | Moderate (sublinear) |
| **Setup** | No trusted setup | No trusted setup |
| **Document linkage** | Document-based nullifier (SHA-256 hash), no direct doc reference | Proves signature over actual document data |
| **Privacy model** | Verifier-to-subject linkage via nullifier only | Single-use proof, no persistent identity |

### Could Signet Use longfellow-zk?

Partially. Longfellow-zk is purpose-built for ISO mDoc/ECDSA P-256 circuits. Its
circuits would be irrelevant to Signet's current Bulletproofs use case, which
proves range claims over verifier-asserted attributes (not government-document
fields). However, if Signet adds a Tier 3+ pathway that accepts government mDL/mDoc
as a source document, longfellow-zk could serve as the ZK engine for generating
age proofs from those documents — complementing rather than replacing Bulletproofs.

### Signet's Differentiator

Longfellow-zk requires the subject to already have a government-issued digital
credential (mDL/mDoc). Signet's value proposition covers the gap where no such
document exists or cannot be used:

- Countries without digital mDLs (most of the world in 2026)
- Minors who do not have government identity documents
- Scenarios requiring professional verification (e.g. a notary witnesses an
  elderly person without an mDL)
- Nostr-native identity without government-issued credentials
- Web-of-trust Tier 2 (peer vouching), which has no mDoc analogue

Signet and longfellow-zk are **complementary**, not competing. A future Signet
integration could use longfellow-zk to bootstrap Tier 3 credentials from mDocs
in jurisdictions where those exist.

**Sources:**
- [Google longfellow-zk blog post](https://blog.google/technology/safety-security/opening-up-zero-knowledge-proof-technology-to-promote-privacy-in-age-assurance/)
- [GitHub: google/longfellow-zk](https://github.com/google/longfellow-zk)
- [Longfellow ZK docs site](https://google.github.io/longfellow-zk/)
- [IETF draft-google-cfrg-libzk-01](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)
- [Google Wallet integrates ZK-proofs — The Block](https://www.theblock.co/post/352865/google-wallet-integrates-zk-proofs-a-tech-incubated-by-crypto-industry)
- [Google adopts Ligero — Ligero Inc.](https://ligero-inc.com/google)
- [Longfellow ZK overview — Dyne.org](https://news.dyne.org/longfellow-zero-knowledge-google-zk/)
- [Google open-sources privacy tech — Help Net Security](https://www.helpnetsecurity.com/2025/07/03/google-zero-knowledge-proofs-zkp/)
- [Google researchers build ZK scheme with mDocs — Biometric Update](https://www.biometricupdate.com/202412/google-researchers-build-zero-knowledge-proof-scheme-with-mdocs/)

---

## Topic 3: EU Age Verification Technical Specification

### Overview and Policy Context

**Repository:** https://github.com/eu-digital-identity-wallet/av-doc-technical-specification
**Developer site:** https://ageverification.dev/
**Architecture spec:** https://ageverification.dev/av-doc-technical-specification/docs/architecture-and-technical-specifications/

The EU Age Verification Solution is a Commission-led initiative intended as a
bridge until EUDI Wallets become available (end of 2026). It is grounded in:

- **Digital Services Act, Article 28** — requires Very Large Online Platforms
  (VLOPs) and Very Large Online Search Engines (VLOSEs) accessible to minors to
  implement measures ensuring a high level of safety and privacy for minors.
- **Louvain-la-Neuve Declaration** — EU commitment to a safer, more trusted online
  environment for children.
- The solution is being built by the T-Scy consortium (Scytales AB + T-Systems
  International GmbH) under a two-year European Commission contract (2025–2027).

The five-country (now six-country) pilot launched in 2025 with: **Cyprus, Denmark,
France, Greece, Italy, and Spain**.

### Technical Architecture

The solution has three components:

| Component | Description |
|---|---|
| **Mini Wallet (AVI App)** | A lightweight user-facing wallet app ("Age Verification Instrument") that holds proof-of-age attestations |
| **Issuer services** | Issue age attestations from official eID, passport/ID card scan, bank KYC, or other recognised sources |
| **Verifier interface** | Web-based integration for online services to request age proofs |

**Credential format:** ISO mDoc (ISO/IEC 18013-5), the same as an mDL.
**Credential identifier:** `proof_of_age` (the `credential_configuration_ids` value)
**Issuance protocol:** OID4VCI (OpenID for Verifiable Credential Issuance 1.0)
**Presentation protocol:** OID4VP (OpenID for Verifiable Presentations) + W3C Digital Credentials API
**Interoperability profile:** OpenID4VC High Assurance Interoperability Profile (HAIP)
**Client authentication:** `redirect_uri` scheme (HAIP x509_san_dns and verifier_attestation were evaluated but not adopted due to trust-list dependency)

The key attribute disclosed during a verification:

- `age_over_18: true` (boolean, from ISO 18013-5 `age_over_nn` attribute family)
- No name, date of birth, address, or document number is transmitted

### Privacy Model: Batch Issuance (Current Approach)

The v1 implementation does not use ZKPs. Instead, it achieves unlinkability
through **batch issuance**:

- 30 single-use credentials are issued at once.
- Each credential is discarded after a single presentation to a verifier.
- The issuer (proof provider) never learns which website the credential was
  presented to.
- When all 30 are exhausted, the user must re-scan their passport or ID card.

This is explicitly called out in the spec as a **temporary measure** — weaker
privacy than ZKPs but adopted to reduce complexity and enable rapid deployment.

### ZKP Roadmap (Annex B)

Annex B of the technical specification documents the planned ZKP integration.
Key choices from the evaluation:

| ZKP approach evaluated | Status | Notes |
|---|---|---|
| **ECDSA Anonymous Credentials (Ligero-based)** | Selected as most promising | No trusted setup; compatible with existing mDoc issuance flows |
| Bulletproofs | Not selected | Designed for range proofs over Pedersen commitments, not ECDSA-signed mDoc attributes |
| Standard SNARKs (Groth16 etc.) | Not selected | Require trusted setup |
| BBS+ / BBS credentials | Under consideration | Good for selective disclosure but not directly compatible with mDoc ECDSA sigs |

The ZKP circuit to be deployed mirrors longfellow-zk's approach: it proves
"the Proof of Age attestation includes `age_over_18` and its value is `true`"
without revealing the underlying credential to the verifier. The EU spec
explicitly references Annex C of ISO/IEC TS 18013-7 for ZKP presentation flows.

The ZKP layer was planned for integration by end of 2025; as of March 2026 it
remains "upcoming" in the production deployment.

### What the Spec Requires: A Compliance Checklist

| Requirement | Detail |
|---|---|
| Credential format | ISO mDoc (ISO/IEC 18013-5) |
| Issuance protocol | OID4VCI 1.0 with HAIP profile |
| Presentation protocol | OID4VP 1.0 + W3C Digital Credentials API |
| Age attribute | `age_over_18` (boolean) from ISO 18013-5 attribute namespace |
| Issuer authentication | IACA certificate chain (ISO 18013-5 trust framework) |
| Unlinkability | Batch issuance (current) → ZKP (roadmap) |
| Device binding | Yes — credential bound to device key |
| Onboarding sources | eID, passport/ID card scan, bank KYC |
| User app | "Mini wallet" (white-label Android/iOS app provided) |
| ZKP (future) | ECDSA Anonymous Credentials, Ligero-based, no trusted setup |

### How Signet Aligns (and Doesn't)

**Alignment:**

- Both systems share the core privacy design goal: only `age_over_18` is
  transmitted, nothing else.
- Both systems are building toward ZKPs with no trusted setup.
- Signet's document-based nullifier (SHA-256 of docType + country + docNumber +
  domain separator) is analogous in purpose to the EU system's use of single-use
  credentials — both prevent duplicate registration.
- Signet's Tier 3/4 professional verification can accept government documents as
  input, making Signet an upstream issuer compatible with feeding into the EU
  system's issuance pipeline.

**Gaps / Incompatibilities:**

| Gap | Description |
|---|---|
| **Credential format** | The EU spec mandates ISO mDoc. Signet issues Nostr events (Kind 30470). These are different formats with different parsers, schemas, and trust frameworks. |
| **Proof system** | The EU roadmap targets Ligero-based ECDSA proofs. Signet uses Bulletproofs over secp256k1. These are not interoperable at the proof layer. |
| **Trust anchor** | The EU system uses IACA certificate chains (government PKI). Signet uses licensed professionals (Law Society, medical boards, notary commissions). |
| **Issuance protocol** | The EU system requires OID4VCI. Signet does not currently implement OID4VCI. |
| **Presentation protocol** | The EU system uses the W3C Digital Credentials API + OID4VP. Signet uses Nostr relay distribution. |
| **Device binding** | The EU mini-wallet binds credentials to device keys. Signet credentials are portable Nostr events, not device-bound. |

### What Changes Would Be Needed for Compatibility

A Signet-to-EU-AV compatibility layer would require:

1. **OID4VCI issuer endpoint** — Signet's professional verifiers would need to
   issue mDoc-format `proof_of_age` credentials (not just Nostr events) via an
   OID4VCI-compliant endpoint.
2. **IACA-equivalent trust anchor** — Signet's verifier credentials (Kind 30473)
   would need to be recognised as an issuer authority, either by joining a trust
   list or by a professional body issuing a root certificate.
3. **Age attribute translation** — Signet's age-range claims (`ageRange: "18+"`)
   would need to map to the ISO 18013-5 `age_over_18` boolean attribute.
4. **Bulletproofs → Ligero migration (optional)** — Not strictly required if
   mDoc issuance produces standard ECDSA-signed mDocs that longfellow-zk can then
   prove against. Bulletproofs remain valid for Signet's internal ZK layer;
   the output credential can be ECDSA-signed for external consumers.

The most practical path is: Signet verifiers issue standard ISO mDocs as a
secondary output format alongside the existing Nostr event, using the Signet
verification as the KYC step that authorises mDoc issuance. This keeps Signet's
Nostr-native credential system intact while adding an EU-compatible output.

### Security Analysis Note

A credible security analysis (Yivi project, 2025) noted that the v1 EU AV
solution's batch-issuance approach has weaknesses: if an adversary can correlate
credential delivery timing with presentation timing, cross-service tracking may
still be feasible even with single-use credentials. This reinforces the importance
of the ZKP roadmap. Signet's nullifier approach, where the nullifier is derived
from document fields and not from credential delivery, does not share this
particular weakness.

**Sources:**
- [GitHub: eu-digital-identity-wallet/av-doc-technical-specification](https://github.com/eu-digital-identity-wallet/av-doc-technical-specification)
- [European Age Verification Solution — ageverification.dev](https://ageverification.dev/)
- [Architecture and Technical Specifications](https://ageverification.dev/av-doc-technical-specification/docs/architecture-and-technical-specifications/)
- [Annex A — Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile/)
- [Annex B — Zero Knowledge Proofs](https://ageverification.dev/Technical%20Specification/annexes/annex-B/annex-B-zkp/)
- [EU launches age verification app pilot (eunews.it)](https://www.eunews.it/en/2025/07/14/the-eu-launches-an-online-age-verification-app-pilot-project-in-five-member-states-including-italy/)
- [Commission second version blueprint](https://digital-strategy.ec.europa.eu/en/news/commission-releases-enhanced-second-version-age-verification-blueprint)
- [Blueprint factpage (European Commission)](https://digital-strategy.ec.europa.eu/en/factpages/blueprint-age-verification-solution-help-protect-minors-online)
- [Yivi security analysis of EU AV app](https://docs.yivi.app/blog/eu-age-verification-security-analysis/)
- [EFF: Age Verification in the EU](https://www.eff.org/deeplinks/2025/04/age-verification-european-union-mini-id-wallet)
- [OpenID4VC HAIP spec](https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html)

---

## Cross-Cutting Observations

**Convergence on Ligero.** Two of the three topics independently converge on the
Ligero ZK scheme: Google chose Ligero for longfellow-zk, and the EU AV spec's
Annex B identifies Ligero-based ECDSA Anonymous Credentials as the most promising
ZKP approach. This is a strong signal that Ligero is becoming the industry default
for ZK proofs over document-format credentials. Signet's Bulletproofs layer, which
proves range claims over verifier-asserted data rather than over ECDSA-signed
document fields, occupies a different niche and is not in direct competition.

**ISO mDoc as the common carrier.** The EU AV spec, Google Wallet, and eIDAS 2.0
all converge on ISO mDoc as the credential wire format. Any Signet roadmap item
targeting EU compliance or Google Wallet integration must plan for mDoc issuance
as an output format. This does not require replacing the Nostr event layer —
mDoc can be a secondary output from the same verification ceremony.

**did:nostr is live but lightly adopted.** The DID method spec is real and has
working implementations (nostr.rocks resolver, TypeScript library). The main
obstacle to Signet VC compatibility is the absence of a stable JSON-LD context
for Signet-specific credential terms, not any fundamental cryptographic barrier.
The SchnorrSecp256k1Signature2019 DIF suite already handles the signature layer.
A Signet JSON-LD context + a credential wrapper library is a bounded, achievable
work item.

**ZKP is not yet deployed in EU production.** The EU AV system running in the
five/six country pilot today uses batch issuance, not ZKPs. Signet's Bulletproofs
ZK layer is already implemented. In the short term (2026), Signet's cryptographic
posture is actually ahead of the EU deployment in terms of ZK maturity, even if
its credential format is not yet EU-compatible.
