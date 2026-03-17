# Privacy Policy

**Signet Protocol — v0.1.0**

**Effective Date:** March 2026
**Last Updated:** March 2026

---

## 1. Introduction

This Privacy Policy describes how the Signet Protocol ("Signet," "we," "us," or "our") collects, uses, discloses, and protects information in connection with the Signet Protocol (the "Protocol") and the My Signet application (the "App"). Signet is an open-source, decentralised identity verification protocol for the Nostr network that uses zero-knowledge proofs, ring signatures, and cryptographic credentials.

Signet is designed with privacy at its core. It enables users to prove claims about their identity — such as age range, professional status, or geographic jurisdiction — without revealing the underlying personal data. This Privacy Policy explains what limited data interactions occur, where data stays, and how it is handled.

This Policy applies to all users, verifiers, relying parties, and other participants who interact with the Signet Protocol or the My Signet application, regardless of location.

The canonical protocol description is `spec/protocol.md` in the open-source Signet repository.

---

## 2. Data Controller

**Data Controller:** The Signet Protocol
**Contact Email:** privacy@signet.id
**Data Protection Officer (DPO):** dpo@signet.id

For jurisdictions requiring a local representative, contact the DPO at the address above. Formal representative appointments for EU (GDPR Art. 27) and UK (UK GDPR Art. 27) purposes will be published at signet.id/legal.

---

## 3. Data We Collect and Process

The Signet Protocol is architected to minimise data collection. Because the Protocol uses zero-knowledge proofs, ring signatures, and decentralised credential verification, the vast majority of information remains solely under the user's control and is never transmitted to or accessible by Signet.

### 3.1 Data Categories

| Category | Description | Source | Storage Location |
|----------|-------------|--------|-----------------|
| **Nostr Public Keys** | secp256k1 public keys (npub) used for Protocol interactions | User-generated | Nostr relays (decentralised) |
| **Credential Metadata** | Nostr event kinds 30470–30477 containing verification tier, issuance timestamps, expiry dates, age range, and entity type identifiers | Generated during credential issuance | Nostr relays (decentralised) |
| **Zero-Knowledge Proofs** | Bulletproofs for age range verification | Generated locally by user | Embedded in credential events on Nostr relays |
| **Ring Signatures** | Cryptographic signatures that prove membership in a group without revealing which member signed | Generated locally by user | Nostr relays (decentralised) |
| **Nullifier Hashes** | SHA-256 hash of length-prefixed document type, country code, document number, and domain tag "signet-nullifier-v2" — prevents duplicate identity creation; cannot be reversed to recover document details | Computed locally during two-credential ceremony | Embedded in Natural Person credential events |
| **Merkle Roots** | Hash commitment to verified attributes enabling selective disclosure. Leaves include name, nationality, documentType, dateOfBirth, documentNumber, documentExpiry, photoHash, and nullifier. Only the root hash is published — individual leaf values are never published | Computed locally during two-credential ceremony | Embedded in Natural Person credential events |
| **Vouch Records** | Kind 30471 events representing web-of-trust endorsements | Created by vouching parties | Nostr relays (decentralised) |
| **Policy Events** | Kind 30472 events specifying relying party requirements | Created by relying parties | Nostr relays (decentralised) |
| **Verifier Registration** | Kind 30473 events identifying professional verifiers, including professional signing pubkey and jurisdictional information | Created by verifiers | Nostr relays (decentralised) |
| **Challenge/Response Data** | Kind 30474 events for verifier legitimacy challenges | Generated during verification | Nostr relays (decentralised) |
| **Revocation Records** | Kind 30475 events for credential revocation | Created when credentials are revoked | Nostr relays (decentralised) |
| **Identity Bridge Events** | Kind 30476 events linking Natural Person and Persona keypairs via ring signatures | Created by the user | Nostr relays (decentralised) |
| **Delegation Events** | Kind 30477 events for agent or guardian delegation with scoped permissions | Created by the delegator | Nostr relays (decentralised) |
| **Encrypted Key Material** | Private keys encrypted with AES-256-GCM (key derived via PBKDF2, 600,000 iterations, SHA-256) | Stored locally on device | Device local storage only — never transmitted |

### 3.2 What Stays on Your Device

The following information is processed on your device and never transmitted to or stored by Signet:

- **Private keys and mnemonic phrase** — Your 12-word BIP-39 mnemonic and the private keys derived from it (both Natural Person and Persona keypairs, derived via BIP-32 HD derivation at NIP-06 paths) remain on your device at all times, encrypted at rest.
- **Document details entered during the ceremony** — Your document number, document expiry date, date of birth, name, nationality, and any photograph you present. These are entered by you into the app, used to compute the Merkle tree and nullifier, and then discarded. The individual leaf values are retained by you in your local credential record for future selective disclosure. They are not transmitted to Signet and are not sent to the verifier electronically — the verifier inspects your physical documents in person and confirms the data you have entered.
- **Merkle leaf values** — Individual attribute values (name, date of birth, document number, document expiry, photo hash, nationality, document type, nullifier) are stored as Merkle leaves in your local credential record, enabling you to prove individual attributes via selective disclosure proofs. Only the Merkle root hash is published on-chain.
- **Biometric data** — See Section 3.3.
- **Exact dates of birth** — Age range proofs reveal only that you fall within a range (e.g., "18+"), not your exact date of birth.

### 3.3 Biometric Authentication (Special Category Data)

The My Signet app supports biometric authentication via the **WebAuthn API with the PRF (Pseudo-Random Function) extension**, with PIN as a fallback.

**How it works:**
- When you enrol biometrics, your device's platform authenticator (fingerprint sensor, Face ID, or equivalent) creates a WebAuthn credential. The credential stays on your device's secure enclave or TPM.
- The WebAuthn PRF extension derives cryptographic key material from your biometric assertion. This key material is used to decrypt your encrypted private keys during an authenticated session.
- **No biometric template is ever transmitted to Signet.** No biometric data leaves your device. Signet never receives, stores, or processes any biometric information.
- The WebAuthn credential ID is stored in your device's local storage to identify which credential to assert during authentication. This is a random identifier, not a biometric template.

Under GDPR Article 9 and UK GDPR, biometric data used for the purpose of uniquely identifying a natural person is special category data. Because biometric processing occurs entirely on your local device using the platform's built-in secure hardware, and no biometric data is transmitted to or processed by Signet's systems, Signet does not act as a data controller or processor of biometric data. Processing is under your sole control.

If your device does not support WebAuthn PRF, the app falls back to a PIN, derived via PBKDF2-SHA-256 (600,000 iterations) to produce an AES-256-GCM decryption key.

### 3.4 Data We Do NOT Collect

By design, the Signet Protocol does **not** collect, process, or store:

- Real names, addresses, or government identification numbers
- Exact dates of birth (age range proofs reveal only a range)
- Document numbers or document expiry dates (processed locally to compute Merkle leaves; individual values are not transmitted to Signet or to the verifier electronically)
- Biometric data (processed locally on device via WebAuthn; never transmitted)
- Financial information or payment data
- Location data or IP addresses (Protocol-level; relay operators may independently collect IP addresses)
- Browsing history or device fingerprints
- Email addresses (unless voluntarily provided for support)
- Photographs or images (a photo hash may be included as a Merkle leaf, but the image itself stays on your device)
- The underlying data behind any zero-knowledge proof

### 3.5 Data Processed by Third Parties

Nostr relay operators independently process data transmitted through their relays. Their data practices are governed by their own privacy policies. Signet does not control relay operators.

---

## 4. The Two-Credential Ceremony

This section explains the professional verification process in detail, because it is the most data-intensive interaction in the Protocol.

### 4.1 How the Ceremony Works

1. **You enter your own data.** In the My Signet app, you enter your name, date of birth, nationality, document type, document number, document expiry date, and optionally provide or photograph your document. The app computes the Merkle tree and nullifier locally.

2. **The verifier inspects your physical documents.** A Tier 3 or Tier 4 verifier (a licensed professional such as a solicitor, notary, or medical professional) examines your physical identity documents in person. The verifier confirms that the data you have entered matches your documents. The verifier does not independently enter your data into the system.

3. **The verifier signs the credential.** The verifier signs two credential events: a Natural Person credential (kind 30470, signed by the verifier's professional Nostr keypair) and a Persona credential (anonymous, age-range only, also signed by the verifier). Both are published to Nostr relays.

4. **What is published.** The published credential events contain: the verifier's public key, your Persona public key (subject pubkey), credential metadata (tier, dates, entity type, age range), the zero-knowledge age range proof, the nullifier hash (a one-way hash; cannot be reversed), and the Merkle root (a hash commitment; individual leaf values are not published). No name, date of birth, document number, or other identifying information is published.

5. **What you retain locally.** Your local credential record contains the individual Merkle leaf values (name, nationality, date of birth, document type, document number, document expiry, nullifier, and optionally photo hash). You use these to generate selective disclosure proofs when you later wish to prove specific attributes (e.g., proving your passport number when checking in for a flight).

### 4.2 Document Number and Expiry as Merkle Leaves

Unlike earlier versions of the Protocol, document number and document expiry are **not** discarded after the ceremony. They are retained as Merkle leaves in your local credential record. This enables you to:

- Prove your passport number to a relying party that requires it (e.g., an airline) via a Merkle inclusion proof, without revealing other attributes.
- Support accelerated Signet IQ decay when your document expiry approaches, providing relying parties with a signal about the freshness of your underlying identity evidence.

Only you control which attributes you disclose and to whom. Individual leaf values are never transmitted to or accessible by Signet.

### 4.3 Nullifier Format

The nullifier is computed as:

```
SHA-256(len16(docType) || docType || len16(countryCode) || countryCode || len16(docNumber) || docNumber || len16("signet-nullifier-v2") || "signet-nullifier-v2")
```

where `len16(x)` is the UTF-8 byte length of `x` encoded as a 2-byte big-endian uint16. The domain tag `signet-nullifier-v2` distinguishes this scheme from any earlier version. The nullifier hash allows the Protocol to detect duplicate identity registrations without revealing which document was used.

---

## 5. Two-Keypair Model

Each Signet user has two keypairs derived from a single 12-word BIP-39 mnemonic:

- **Natural Person keypair** — derived via NIP-06 path `m/44'/1237'/0'/0/0`. Used for the Natural Person credential (kind 30470). This keypair is associated with your verified real-world identity via the credential, but the keypair itself carries no inherent linkage to your documents.
- **Persona keypair** — derived via BIP-32 HD path at a separate account index. Used for the Persona credential (anonymous, age-range only). This keypair carries no direct link to your real-world identity. Your online social activity uses this keypair.

**Privacy implication:** Because both keypairs derive from the same mnemonic, you can prove linkage between them (via kind 30476 identity bridge events) or keep them entirely separate. An identity bridge event, once published, creates a public cryptographic link. You should only publish a bridge event if you wish to associate your anonymous Persona with your verified Natural Person status.

**Key management and data subject rights:** Your private keys are derived deterministically from your mnemonic. Signet never possesses or transmits your private keys. If you delete the app and lose your mnemonic (and any Shamir backup), your keys are unrecoverable. Signet cannot assist with key recovery because we do not hold copies.

---

## 6. The signet-verify.js SDK

The My Signet ecosystem includes `signet-verify.js`, a JavaScript SDK that websites embed to request age or identity verification from their visitors.

### 6.1 How the SDK Works

1. A website embeds `signet-verify.js` and calls `Signet.verifyAge('18+')` (or similar).
2. The SDK opens a verification modal on the website.
3. The user approves the request in the My Signet app. The credential proof is transmitted back to the website via a BroadcastChannel (same-device communication; no server involved).
4. The SDK verifies the Schnorr signature on the credential event and checks that the verifier's pubkey is registered and confirmed.
5. The SDK returns a result to the website.

### 6.2 What Data the Website Receives

A website using `signet-verify.js` receives:

| Field | Description |
|-------|-------------|
| `verified` | Boolean: does the credential meet the stated requirement? |
| `ageRange` | Age range string (e.g., "18+") — never exact date of birth |
| `tier` | Verification tier (1–4) |
| `entityType` | Account classification (Natural Person, Persona, etc.) |
| `credentialId` | Credential event ID (a public Nostr event identifier) |
| `verifierPubkey` | The verifier's Nostr public key |
| `verifierConfirmed` | Whether the verifier has been confirmed against a public professional register |
| `issuedAt` / `expiresAt` | Credential validity timestamps |

**No personally identifiable information is transmitted to the website.** The website does not receive your name, date of birth, document number, or any Merkle leaf values. The BroadcastChannel communication is local to the device — the verification exchange does not pass through any Signet server.

### 6.3 Verification Bot

Signet operates an open-source verification bot that checks verifier registrations against public professional registers (e.g., the General Medical Council register, the Solicitors Regulation Authority roll, Teaching Regulation Agency records). The bot publishes its findings as Nostr events.

The verifier's professional Nostr pubkey is a purpose-built signing key used only for Signet verifications. It has no inherent social identity. The bot receives this pubkey to query public registers. Submission of a professional pubkey to the bot for register-checking is not a transfer of personal data under GDPR, because the pubkey is a pseudonymous cryptographic identifier purpose-built for this function. However, out of an abundance of caution, verifiers consent to this process as part of the Verifier Agreement.

---

## 7. NIP-46 Remote Signing

The My Signet app can act as a NIP-46 remote signer. In this mode:

- Signing requests arrive from a connected Nostr client application via a Nostr relay.
- The app displays each signing request and asks the user to approve or reject it.
- The private key never leaves the app. Remote signing does not transmit the private key to the requesting application or the relay.
- Approved signatures are transmitted back to the requesting application via the relay.

The relay operator can observe that a signing request and response occurred (as encrypted Nostr events), but cannot read the content of the signing request or the private key.

---

## 8. Legal Bases for Processing

We process data under the following legal bases, depending on your jurisdiction.

### 8.1 European Union / European Economic Area (GDPR)

| Purpose | Legal Basis | GDPR Article |
|---------|-------------|--------------|
| Protocol operation and credential verification | Legitimate interest | Art. 6(1)(f) |
| Compliance with legal obligations | Legal obligation | Art. 6(1)(c) |
| User-initiated credential issuance | Performance of a contract | Art. 6(1)(b) |
| Child safety and age verification | Legitimate interest / Legal obligation | Art. 6(1)(f) / Art. 6(1)(c) |

Note: Biometric data is processed exclusively on-device via WebAuthn. Signet does not process biometric data under Article 9(1). If any biometric processing by Signet were later established, the legal basis would be explicit consent under Art. 9(2)(a).

**eIDAS 2.0:** The EU Digital Identity Wallet Regulation (eIDAS 2.0) mandates that member states issue digital identity wallets to citizens by December 2026. Signet's architecture is designed to be compatible with eIDAS 2.0-issued credentials via the kind 30476 identity bridge mechanism.

### 8.2 United Kingdom (UK GDPR / Data Protection Act 2018)

The same legal bases as the EU GDPR apply, as supplemented by the Data Protection Act 2018.

**Online Safety Act 2023:** Signet's age verification capabilities support compliance with the age assurance requirements of the Online Safety Act 2023 and associated Ofcom guidance. Signet's zero-knowledge architecture is designed to enable age verification without creating centralised age-verification databases.

**Age Appropriate Design Code (AADC / Children's Code):** Signet is committed to the 15 standards of the AADC, including best interests of the child assessment, data minimisation, default high-privacy settings for children, and age-appropriate transparency.

**ICO as Supervisory Authority:** The Information Commissioner's Office (ICO) is Signet's lead supervisory authority in the UK. Contact: [https://ico.org.uk](https://ico.org.uk).

### 8.3 United States

**COPPA (Children's Online Privacy Protection Act):** Signet collects zero personal information from any user, including children under 13. The Protocol's zero-knowledge architecture means that no name, date of birth, address, photograph, or any other personal information defined under COPPA is collected, stored, or transmitted by Signet. The FTC's March 2026 guidance confirms that platforms collecting no covered personal information are outside COPPA's collection restrictions. Signet's approach of enabling age verification without collecting personal information is consistent with the FTC's stated flexibility for privacy-preserving age verification methods.

**CCPA / CPRA (California):** We do not sell personal information. We do not share personal information for cross-context behavioural advertising. California residents have the right to know, delete, correct, and opt out. Because Signet collects no personal information in the traditional sense, most CCPA rights are satisfied by the architecture itself.

**State privacy laws:** We comply with applicable state privacy laws including those of Virginia (VCDPA), Colorado (CPA), Connecticut (CTDPA), Utah (UCPA), Texas (TDPSA), and other states with enacted privacy legislation.

**State age verification laws:** A number of US states have enacted laws requiring age verification for access to certain online services. Signet's age range proofs are designed to satisfy these requirements without creating centralised databases of users' dates of birth or identity documents.

### 8.4 Brazil (LGPD — Lei Geral de Proteção de Dados)

Processing is based on:
- Legitimate interest (Art. 7, X)
- Compliance with legal or regulatory obligations (Art. 7, II)
- Execution of a contract or preliminary procedures (Art. 7, V)

### 8.5 South Korea (PIPA — Personal Information Protection Act)

Processing complies with PIPA requirements including collection limited to the minimum necessary, specific purpose limitation, notification of processing purposes, and compliance with consent requirements.

### 8.6 Japan (APPI — Act on the Protection of Personal Information)

Processing complies with the APPI as amended, including specification of utilisation purpose, proper acquisition of personal information, and compliance with cross-border transfer requirements.

### 8.7 China (PIPL — Personal Information Protection Law)

Where the Protocol is accessed from the People's Republic of China, processing is based on individual consent or contract performance, data localisation requirements are respected, and cross-border transfers comply with PIPL Art. 38–43.

### 8.8 India (DPDP — Digital Personal Data Protection Act)

Processing complies with the DPDP Act, including processing based on consent or legitimate uses, obligations as a data fiduciary, and rights of data principals.

---

## 9. How We Use Data

Data processed through the Signet Protocol is used exclusively for:

1. **Credential Issuance and Verification** — Enabling users to create, present, and verify credentials across the four verification tiers.
2. **Signet IQ Computation** — Calculating Signet IQ scores based on web-of-trust vouches, credential tiers, credential freshness, and document expiry signals.
3. **Age Range Verification** — Using Bulletproofs to prove a user falls within an age range without revealing their exact age.
4. **Professional Verification** — Enabling licensed professionals (lawyers, notaries, medical professionals) to act as verifiers.
5. **Credential Revocation** — Processing revocation events when credentials are invalidated.
6. **Protocol Integrity** — Maintaining the cryptographic integrity and security of the Protocol.
7. **Legal Compliance** — Complying with applicable laws and regulations.
8. **Two-Credential Ceremony** — Issuing paired Natural Person and Persona credentials during professional verification, including computation of Merkle trees, nullifiers, and age-range proofs.
9. **Guardian Management** — Processing guardian delegation events (kind 30477) for child account management.
10. **Selective Disclosure** — Enabling users to prove individual Merkle leaf attributes (including document number and document expiry) to relying parties that require them, without revealing unrelated attributes.
11. **Credential Lifecycle** — Processing credential chains (supersedes/superseded-by tags) for name changes, document renewal, and tier upgrades.

---

## 10. Data Sharing and Disclosure

### 10.1 Protocol-Level Sharing

The Signet Protocol operates on the Nostr network, which is decentralised. When you publish a credential event, vouch, or other Protocol event, it is broadcast to Nostr relays. This is inherent to the Protocol's design and is initiated by you.

### 10.2 We Do Not Share Data With

- Advertisers or marketing companies
- Data brokers
- Social media platforms (beyond Nostr relay publication)
- Government agencies (except as required by law or valid legal process)

### 10.3 Disclosure Required by Law

We may disclose information if required by a valid court order, subpoena, or legal process, applicable law or regulation, or a request from a law enforcement or regulatory authority with valid jurisdiction. We will notify affected users of such requests where legally permitted. Because Signet does not hold personal data about users in centralised systems, the scope of any compellable disclosure is extremely limited.

### 10.4 Verifier Data Sharing

Professional verifiers (Tier 3 and Tier 4) publish verifier registration events (kind 30473) on the Nostr network. These events include the verifier's professional Nostr pubkey and jurisdictional information. Verifiers consent to this publication as part of the Verifier Agreement.

The only data shared between the verifier and the Protocol via published events is the credential event (kind 30470), which contains the verifier's public key, the subject's Persona public key, credential metadata (tier, dates, entity type, age range), the zero-knowledge age-range proof, the nullifier hash, and the Merkle root.

No personal identification data (name, date of birth, document numbers, nationality) appears in any published event.

---

## 11. International Data Transfers

### 11.1 Decentralised Architecture

The Nostr network operates globally. When you publish events to Nostr relays, those events may be replicated to relays located anywhere in the world. This is a fundamental characteristic of the decentralised protocol.

### 11.2 Transfer Mechanisms

For any centralised processing Signet conducts, international data transfers are protected by:

- **EU/EEA:** Standard Contractual Clauses (SCCs) as approved by the European Commission (Decision 2021/914), supplemented by transfer impact assessments where required.
- **UK:** International Data Transfer Agreement (IDTA) or the UK Addendum to EU SCCs.
- **South Korea:** Compliance with PIPA cross-border transfer provisions.
- **Japan:** Transfers to countries with an adequate level of protection as recognised by the PPC, or with user consent.
- **China:** Security assessments, standard contracts, or certifications as required by PIPL.
- **Brazil:** Transfers compliant with LGPD Art. 33, including to countries with an adequate level of protection or with specific guarantees.

### 11.3 Adequacy Decisions

We rely on adequacy decisions where available, including the EU-US Data Privacy Framework, the UK Extension to the EU-US Data Privacy Framework, and Japan's adequacy finding by the European Commission.

---

## 12. Data Retention

### 12.1 Nostr Events

Events published to the Nostr network are retained by relay operators according to their own policies. Because the Nostr network is decentralised, Signet cannot guarantee the deletion of events from all relays.

### 12.2 Credential Lifecycle

| Data Type | Retention Period |
|-----------|-----------------|
| Active credentials | Until expiry or revocation |
| Revoked credentials | Revocation events are retained indefinitely for verification integrity |
| Expired credentials | Retained on relays per relay operator policies |
| Vouch records | Until revoked by the vouching party |
| Challenge/response data | Persistent; published to Nostr relays as standard events, retained for protocol integrity |
| Local encrypted key material | On your device until you delete the app or clear app data |

### 12.3 Centralised Records

Any records Signet maintains centrally (e.g., support correspondence, legal compliance records) are retained for:
- Support records: 2 years from last interaction
- Legal compliance records: As required by applicable law (typically 5–7 years)
- Audit logs: 3 years

---

## 13. Your Rights

### 13.1 Universal Rights

Regardless of your jurisdiction, you may:
- Request information about what data we process about you
- Request correction of inaccurate data
- Withdraw consent where processing is based on consent
- Lodge a complaint with us or a supervisory authority

### 13.2 A Note on Architecture and Rights

Because Signet's architecture is decentralised and privacy-first, many rights are satisfied structurally:

- **Access and portability:** Your credential data is stored in public Nostr events that you published, and in your local app storage. You already have full access to it.
- **Erasure:** Signet holds no centralised copy of your personal data. We cannot delete Nostr events from relay operators' infrastructure on your behalf, but we can issue a revocation event. You can request deletion from individual relay operators.
- **Rectification:** Incorrect credentials can be superseded by issuing a new credential event referencing the old one.

### 13.3 European Union / EEA (GDPR)

Under the GDPR, you have the right to:
- **Access** (Art. 15) — Obtain a copy of your personal data
- **Rectification** (Art. 16) — Correct inaccurate data
- **Erasure** (Art. 17) — Request deletion ("right to be forgotten") where applicable
- **Restriction** (Art. 18) — Restrict processing in certain circumstances
- **Data Portability** (Art. 20) — Receive your data in a structured, machine-readable format
- **Object** (Art. 21) — Object to processing based on legitimate interest
- **Automated Decision-Making** (Art. 22) — Not be subject to solely automated decisions with legal effects

**Supervisory Authority:** You may lodge a complaint with your local data protection authority. A list of EU/EEA DPAs is available at [https://edpb.europa.eu/about-edpb/about-edpb/members_en](https://edpb.europa.eu/about-edpb/about-edpb/members_en).

### 13.4 United Kingdom (UK GDPR)

You have equivalent rights as under the EU GDPR. You may lodge a complaint with the Information Commissioner's Office (ICO) at [https://ico.org.uk](https://ico.org.uk).

### 13.5 United States (CCPA / CPRA)

California residents have the right to:
- **Know** — What personal information is collected, used, and disclosed
- **Delete** — Request deletion of personal information
- **Correct** — Request correction of inaccurate personal information
- **Opt-Out** — Opt out of the sale or sharing of personal information (we do not sell or share)
- **Non-Discrimination** — Not be discriminated against for exercising privacy rights

To exercise these rights, contact us at privacy@signet.id.

Residents of Virginia, Colorado, Connecticut, Utah, Texas, and other states with privacy legislation have comparable rights under their respective laws.

### 13.6 Brazil (LGPD)

Data subjects have the right to confirmation of the existence of processing, access to data, correction of incomplete, inaccurate, or outdated data, anonymisation, blocking, or deletion of unnecessary or excessive data, data portability, deletion of data processed with consent, information about shared data, information about the possibility of denying consent and its consequences, and revocation of consent.

Contact the ANPD (Autoridade Nacional de Proteção de Dados) for complaints: [https://www.gov.br/anpd](https://www.gov.br/anpd).

### 13.7 South Korea (PIPA)

Data subjects have the right to request access to personal information, request correction or deletion, request suspension of processing, and file a complaint with the Personal Information Protection Commission (PIPC).

### 13.8 Japan (APPI)

Data subjects have the right to request disclosure of retained personal data, request correction, addition, or deletion, request cessation of use or provision to third parties, and file a complaint with the Personal Information Protection Commission (PPC).

### 13.9 China (PIPL)

Data subjects have the right to know and decide on processing of personal information, restrict or refuse processing, access and copy personal information, request portability, request correction and deletion, and request explanation of processing rules.

### 13.10 India (DPDP Act)

Data principals have the right to access information about processing, correction and erasure of personal data, grievance redressal, and to nominate another person to exercise rights.

### 13.11 Exercising Your Rights

To exercise any of the above rights, contact us at:
- **Email:** privacy@signet.id
- **DPO Email:** dpo@signet.id

We will respond within the time frames required by applicable law:
- GDPR/UK GDPR: 30 days (extendable by 60 days for complex requests)
- CCPA/CPRA: 45 days (extendable by 45 days)
- LGPD: 15 days
- PIPA: 10 days
- APPI: Without delay
- PIPL: Promptly

---

## 14. Children's Data

### 14.1 General Policy

The Signet Protocol includes Tier 4 (Professional Verification — Adult + Child), which is specifically designed for child safety. We take the protection of children's data extremely seriously. Children under 18 may only be verified under Tier 4 with the active participation of a verified adult guardian, who is issued a Tier 4 credential linking their pubkey to the child's credential via a guardian tag.

### 14.2 Age Verification

The Protocol uses Bulletproofs-based zero-knowledge proofs for age range verification. These proofs demonstrate that a user is within a given age range (e.g., "0-3", "4-7", "8-12", "13-17", "18+") without revealing their exact date of birth.

### 14.3 Jurisdiction-Specific Age Requirements

| Jurisdiction | Minimum Age for Digital Consent | Governing Law |
|-------------|-------------------------------|---------------|
| EU (default) | 16 years | GDPR Art. 8 |
| EU (member state option) | 13–16 years (varies by member state) | GDPR Art. 8(1) |
| United Kingdom | 13 years | UK GDPR / Children's Code |
| United States | 13 years | COPPA |
| Brazil | 12 years (parental consent required under 18) | LGPD Art. 14 |
| South Korea | 14 years | PIPA |
| Japan | 15 years (guidelines) | APPI |
| China | 14 years | PIPL Art. 28 |
| India | 18 years (with exceptions) | DPDP Act |

### 14.4 Parental Consent

Where parental consent is required, the Protocol supports:
- Verifiable parental consent through Tier 3 or Tier 4 verified parent/guardian credentials
- Age-gating through ZK proof verification at the relying party level
- Guardian delegation events (kind 30477) enabling parents to manage their children's Signet activity
- Mechanisms for parents to revoke delegation and consent

### 14.5 COPPA Compliance (United States)

Signet collects zero personal information from any user, including children under 13. The Protocol's zero-knowledge architecture means there is no name, date of birth, address, or other COPPA-covered personal information collected, stored, or transmitted by Signet. The FTC's March 2026 guidance acknowledges flexibility for platforms that implement privacy-preserving verification without collecting covered personal information.

### 14.6 Age Appropriate Design Code (United Kingdom)

Signet is committed to the principles of the UK Age Appropriate Design Code (Children's Code), including best interests of the child assessment, age-appropriate application, data minimisation, default settings protective of children, and transparency appropriate to the child's age.

---

## 15. Security

### 15.1 Cryptographic Security

The Signet Protocol employs:
- **Schnorr signatures** on the secp256k1 curve for all credential signing
- **Bulletproofs** for zero-knowledge age range proofs
- **Ring signatures** (SAG and LSAG) for anonymous group membership proofs, with domain separation tags and ring size limits (maximum 1,000 members)
- **RFC 6962 Merkle trees** with domain separation (`0x00` leaf prefix, `0x01` internal node prefix) for tamper-evident attribute commitments
- **ECDH** with identity-point rejection for shared secret derivation
- **Future ZK layer** planned for additional proof types (ZK-SNARKs/ZK-STARKs)

### 15.2 Key Storage Security

Private keys in the My Signet app are:
- Encrypted at rest using AES-256-GCM
- The encryption key is derived via PBKDF2 with SHA-256 and 600,000 iterations (OWASP 2023 recommendation), using a random salt
- Keys are held in memory only during an authenticated session
- Mnemonic phrases and private keys are never transmitted to Signet or any third party
- Never stored in plaintext in IndexedDB, localStorage, or any other storage mechanism

### 15.3 Input Validation

All event validators enforce maximum content length (64 KB), maximum tag count (100 tags), maximum tag value length (1,024 characters), and integer bounds checking to prevent silent security bypasses.

### 15.4 Decentralised Security Model

The Protocol's decentralised architecture provides inherent security benefits: no single point of failure, no centralised database to breach, user-controlled key management, and cryptographic verification without trusted intermediaries.

### 15.5 Breach Notification

In the event of a personal data breach affecting any centralised Signet systems, we will:
- Notify the relevant supervisory authority within 72 hours (GDPR) or as required by applicable law
- Notify affected individuals without undue delay where the breach is likely to result in a high risk to their rights and freedoms
- Document the breach, its effects, and remedial actions

---

## 16. Cookies and Tracking Technologies

The Signet Protocol does **not** use:
- Cookies
- Web beacons or tracking pixels
- Browser fingerprinting
- Local storage for tracking purposes
- Any third-party analytics or tracking services

If ancillary services (such as a documentation website) use cookies, a separate cookie notice will be provided with appropriate consent mechanisms.

---

## 17. Automated Decision-Making and Profiling

### 17.1 Signet IQ Computation

The Protocol computes Signet IQ scores (0–200, where 100 represents the current government identity standard) based on verification tier level, number and quality of vouches, verifier credentials and standing, credential age, and document expiry signals. These scores are computed algorithmically and are visible to relying parties. They do not constitute automated decision-making with legal effects under GDPR Art. 22, as they are one input among many that relying parties may consider.

### 17.2 No Profiling for Marketing

We do not engage in profiling for marketing, advertising, or behavioural analysis purposes.

---

## 18. Third-Party Links and Services

The Signet Protocol interoperates with:
- Nostr relays (operated independently)
- Nostr clients (such as Fathom, the reference implementation client)
- Professional bodies and regulatory registries (via the open-source verification bot)
- The document type registry (an external YAML file defining document field definitions per country — contains no personal data)

These third parties have their own privacy policies. Signet is not responsible for their data practices.

---

## 19. Changes to This Privacy Policy

We may update this Privacy Policy from time to time. Changes will be indicated by updating the "Last Updated" date at the top of this document. For material changes, we will provide notice through a Nostr event announcement and an update to the Protocol specification repository. Your continued use of the Protocol after changes constitutes acceptance of the updated Privacy Policy.

---

## 20. Jurisdiction-Specific Provisions

### 20.1 European Union — Additional Provisions

Where we process personal data under the GDPR, the provisions of the GDPR take precedence over any conflicting provisions in this Privacy Policy. Regarding eIDAS 2.0: Signet's Protocol is designed to accept identity bridge events from EU Digital Identity Wallets when those wallets are deployed by member states, anticipated by December 2026.

### 20.2 United Kingdom — Additional Provisions

**ICO Registration:** Signet will register with the ICO as required. Registration details will be published at signet.id/legal.

**Do Not Sell or Share My Personal Information:** We do not sell or share personal information.

**Online Safety Act:** Signet's age verification capabilities are designed to be compatible with the age assurance requirements of the Online Safety Act 2023.

### 20.3 California — Additional Provisions

**Do Not Sell or Share My Personal Information:** We do not sell or share personal information as defined under the CCPA/CPRA.

**Financial Incentives:** We do not offer financial incentives related to the collection of personal information.

**Shine the Light (Cal. Civ. Code Section 1798.83):** California residents may request information about disclosures of personal information to third parties for direct marketing. We do not make such disclosures.

### 20.4 Brazil — Additional Provisions

The DPO (Encarregado) may be contacted at dpo@signet.id for all LGPD-related inquiries.

### 20.5 Australia — Additional Provisions

We comply with the Australian Privacy Principles (APPs) under the Privacy Act 1988 (Cth). You may lodge a complaint with the Office of the Australian Information Commissioner (OAIC).

### 20.6 New Zealand — Additional Provisions

We comply with the Privacy Act 2020 (NZ). You may lodge a complaint with the Office of the Privacy Commissioner.

### 20.7 Singapore — Additional Provisions

We comply with the Personal Data Protection Act 2012 (PDPA). You may contact the Personal Data Protection Commission (PDPC) for complaints.

### 20.8 South Africa — Additional Provisions

We comply with the Protection of Personal Information Act 2013 (POPIA). You may lodge a complaint with the Information Regulator.

---

## 21. Contact Us

For any questions, concerns, or requests related to this Privacy Policy or our data practices:

**General Inquiries:**
The Signet Protocol
Email: privacy@signet.id

**Data Protection Officer:**
Email: dpo@signet.id

---

## 22. Regulatory Filings

Depending on jurisdiction, Signet maintains or will maintain registrations or filings with:
- The Information Commissioner's Office (UK) — registration to be completed; details published at signet.id/legal
- Applicable EU/EEA data protection authorities
- Other regulatory bodies as required by law

---

*This Privacy Policy describes the data practices of the Signet Protocol as of March 2026. The Signet Protocol is open-source software. This document does not constitute legal advice. Users and operators should seek qualified legal counsel familiar with the applicable data protection laws in their jurisdiction.*

*Signet Protocol — v0.1.0*
*Document Version: 2.0*
