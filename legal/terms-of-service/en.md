# Terms of Service

**The Signet Protocol — v0.1.0**
**Effective Date:** 17 March 2026
**Last Updated:** 17 March 2026

*This document covers your use of My Signet (the reference app) and the Signet Protocol libraries, including the signet-verify.js SDK. It is not legal advice. Seek qualified counsel for your jurisdiction before relying on it in a production deployment.*

---

## Contents

1. [Acceptance of Terms](#1-acceptance-of-terms)
2. [Eligibility](#2-eligibility)
3. [Description of the Protocol and App](#3-description-of-the-protocol-and-app)
4. [Key Management and Account Security](#4-key-management-and-account-security)
5. [The Verification Ceremony](#5-the-verification-ceremony)
6. [Credential Lifecycle](#6-credential-lifecycle)
7. [User Obligations](#7-user-obligations)
8. [Verifier Obligations](#8-verifier-obligations)
9. [Website Operators and the signet-verify.js SDK](#9-website-operators-and-the-signet-verifyjs-sdk)
10. [The Verification Bot](#10-the-verification-bot)
11. [Signet IQ Scores](#11-signet-iq-scores)
12. [Data Protection](#12-data-protection)
13. [Intellectual Property](#13-intellectual-property)
14. [Disclaimers](#14-disclaimers)
15. [Limitation of Liability](#15-limitation-of-liability)
16. [Indemnification](#16-indemnification)
17. [Governing Law and Dispute Resolution](#17-governing-law-and-dispute-resolution)
18. [Termination](#18-termination)
19. [Amendments](#19-amendments)
20. [General Provisions](#20-general-provisions)
21. [Contact](#21-contact)
22. [Jurisdiction-Specific Annexes](#22-jurisdiction-specific-annexes)

---

## 1. Acceptance of Terms

By accessing, downloading, or using My Signet (the "App"), the Signet Protocol libraries, or the signet-verify.js SDK (together, "the Protocol"), or by acting as a verifier, you ("you" or "User") agree to be bound by these Terms of Service ("Terms").

If you do not agree to these Terms, you must not use the Protocol.

If you use the Protocol on behalf of an organisation, you represent that you have authority to bind that organisation, and "you" includes that organisation.

**Verifiers:** By publishing a kind 30473 verifier credential event on the Nostr network, or by performing a Signet verification ceremony, you accept Section 8 (Verifier Obligations) as a legally binding condition of your participation. You do not need to sign a separate document. The act of performing a verification is your acceptance.

---

## 2. Eligibility

### 2.1 General Eligibility

To use the Protocol, you must:

- Have the legal capacity to enter a binding agreement in your jurisdiction
- Not be prohibited from using the Protocol under any applicable law
- Not have been removed from the Protocol for a material breach of these Terms

### 2.2 Age Requirements

| Jurisdiction | Minimum age — own account | With verified parental consent |
|---|---|---|
| European Union (default) | 16 | 13 (varies by member state) |
| United Kingdom | 13 | N/A |
| United States | 13 | Under 13 with COPPA-compliant parental consent |
| Brazil | 18 | 12 with parental consent |
| South Korea | 14 | Under 14 with parental consent |
| Japan | 15 | Under 15 with parental consent |
| India | 18 | As per DPDP Act |
| Other | Age of digital consent | As per local law |

Children under the digital consent age for their jurisdiction may only have a Signet account as a sub-account of a verified parent or guardian (see Section 6.7).

### 2.3 Verifier Eligibility

To act as a professional verifier and issue Tier 3 or Tier 4 credentials, you must:

- Hold a current, valid professional registration in good standing with the relevant regulatory body
- Be authorised to practise in the jurisdiction where you perform verifications
- Not be subject to any suspension, restriction, or disciplinary proceedings that would impair your ability to verify identity
- Maintain professional indemnity insurance adequate to cover your verification activities

The full list of eligible professions is in Section 8.2.

---

## 3. Description of the Protocol and App

### 3.1 Overview

The Signet Protocol is a decentralised identity verification protocol for the Nostr network. It enables users to prove claims about their identity — including age, parenthood, and professional status — using zero-knowledge proofs and ring signatures, without revealing underlying personal data. There is no central database, no central authority, and no single organisation that controls the network.

**My Signet** is the reference app. It is a progressive web app (PWA) that runs in your browser. It is one application used by everyone: individuals, verifiers, and communities.

### 3.2 Verification Tiers

| Tier | Name | What it means |
|---|---|---|
| 1 | Self-Declared | You created an account and declared some attributes. No external check. Lowest trust. |
| 2 | Web-of-Trust | Other users who know you have vouched for you. Trust is derived from the network. |
| 3 | Professional Verification (Adult) | A licensed professional verified your government-issued identity document in person and issued two credentials via the two-credential ceremony. |
| 4 | Professional Verification (Adult + Child) | Tier 3 extended to include a child account, with the child's relationship to a verified parent/guardian confirmed by a professional. |

### 3.3 Nostr Event Kinds

The Protocol uses the following Nostr event kinds:

| Kind | Purpose |
|---|---|
| 30470 | Credential events |
| 30471 | Vouch attestations |
| 30472 | Community verification policies |
| 30473 | Verifier registration credentials |
| 30474 | Challenge events |
| 30475 | Revocation events |
| 30476 | Identity bridge events |
| 30477 | Delegation events (guardian and agent) |
| 30482–30484 | Voting extension (election, ballot, result) |

Event kind numbers are pending final NIP allocation.

### 3.4 Cryptographic Stack

The Protocol uses:

- Schnorr signatures on the secp256k1 curve (base layer)
- Bulletproofs for age-range zero-knowledge proofs
- Spontaneous Anonymous Group (SAG) and Linkable SAG (LSAG) ring signatures for issuer privacy
- PBKDF2 (600,000 iterations, SHA-256) with AES-256-GCM for local credential storage
- A future ZK layer (ZK-SNARKs or ZK-STARKs) is planned for Level 3 cryptographic completeness

### 3.5 Decentralised Nature

The Signet Protocol operates on the Nostr network. We develop and maintain the Protocol specification but do not control the network, relay operators, or individual participants. Events published to Nostr are public, persistent, and replicated by relay operators we do not control.

---

## 4. Key Management and Account Security

### 4.1 Two-Keypair Model

My Signet derives two independent keypairs from a single 12-word BIP-39 mnemonic:

- **Natural Person keypair:** Used for your real-identity credential (name, document, nullifier, Merkle root). This keypair is only used when you explicitly choose to present your verified real identity.
- **Persona keypair:** An anonymous alias. It carries an age-range proof inherited from the verification ceremony but no name, document reference, or nullifier. All your day-to-day Nostr activity can use this keypair.

During onboarding, you choose which keypair is your primary account for that device. You may switch at any time. The link between your two keypairs is known only to you and your verifier (protected by their professional confidentiality obligations).

### 4.2 Single-Keypair Mode (nsec Import)

If you are an existing Nostr user, you may import your existing private key (nsec). In single-keypair mode, your existing npub becomes your Natural Person identity, and you can create an identity bridge (kind 30476 event) to link it to a Persona account. All your existing followers, NIP-05, zaps, and reputation are preserved.

### 4.3 Key Generation and Backup

- Your mnemonic is generated locally in the App using cryptographically secure randomness. It is never transmitted to any server.
- You are solely responsible for backing up your mnemonic. We cannot recover it. If you lose your mnemonic and your device, your account cannot be recovered without a fresh professional verification.
- Child accounts can be derived at different BIP-44 account indices from the same parent mnemonic, keeping family key management under one recovery phrase.
- Shamir's Secret Sharing backup (via `@scure/bip39`) is supported for splitting the mnemonic across trusted custodians.

### 4.4 Biometric and PIN Authentication

My Signet requires authentication to access your private key:

- **Biometric (preferred):** Uses WebAuthn with the PRF extension, where available. Your biometric never leaves your device. Where PRF is supported, key material is hardware-derived and cannot be extracted from localStorage even by code running on the same device.
- **PIN fallback:** Where biometric authentication is unavailable, a PIN is required. The PIN is used with PBKDF2 (600,000 iterations) to derive an AES-256-GCM encryption key.
- **Session management:** After a period of inactivity, the App locks itself. You must re-authenticate to continue. The inactivity timeout can be configured in settings.

Your private key is never stored in plaintext. It is always encrypted at rest using AES-256-GCM.

### 4.5 Key Compromise

If you believe your private key has been compromised, you must visit a professional verifier with your original identity documents. The verifier will revoke all credentials issued to your old keypair and issue fresh credentials to a new keypair. Vouches associated with the compromised key are not transferred (this is a deliberate security measure — an attacker who compromised your key cannot retain your social trust).

### 4.6 NIP-46 Remote Signing

My Signet supports NIP-46 remote signing. This allows other applications or services to request that the App sign Nostr events on their behalf. Every signing request requires your explicit approval. The App will display the request details before you approve or reject it. You must not approve requests you do not recognise or understand.

---

## 5. The Verification Ceremony

### 5.1 How Professional Verification Works

Tier 3 and Tier 4 credentials are issued through the two-credential ceremony:

1. **You enter your data.** Before visiting a verifier, you enter your own identity attributes (name, date of birth, nationality, document type and number) into the App. The App pre-computes your Merkle tree and your document nullifier.

2. **You present your documents.** You attend an in-person appointment with a professional verifier and show your original government-issued identity document(s).

3. **The verifier confirms or rejects.** The verifier inspects your documents, verifies that you are the person described in them, and confirms or rejects the data you entered. The verifier does not type your personal data — they only confirm what you have entered.

4. **Two credentials are issued.** If the verifier confirms the data, they publish two kind 30470 credential events — one for your Natural Person keypair (with your Merkle root and nullifier) and one for your Persona keypair (with only your age-range proof). Both credentials are signed with the verifier's professional Nostr key.

5. **The document number is discarded.** After the nullifier is computed, the document number is not retained by the Protocol, the App, or (unless required by their professional obligations) the verifier.

### 5.2 Who Is Responsible for Data Accuracy

Because you enter your own identity data, you bear primary responsibility for its accuracy. Entering false data (wrong name, someone else's document number) is fraudulent and may constitute a criminal offence in your jurisdiction.

The verifier's role is to confirm that the person standing before them matches the documents presented. The verifier does not warrant the completeness or accuracy of the data you entered beyond what can be visually confirmed from the documents.

### 5.3 Document Nullifiers

The Protocol uses document-based nullifiers to prevent the same person from obtaining multiple Tier 3 credentials. The nullifier is computed as:

```
SHA-256(LP(docType) || LP(country) || LP(docNumber) || LP("signet-nullifier-v2"))
```

where `LP(x)` is the UTF-8 byte length of `x` encoded as a 2-byte big-endian integer, followed by the bytes of `x`. This length-prefixed encoding prevents field-boundary collisions.

The nullifier:
- Is deterministic: the same document always produces the same nullifier
- Is one-way: the document number cannot be recovered from the nullifier
- Is collision-resistant: different documents produce different nullifiers
- Is cross-verifier consistent: any verifier with the same document produces the same nullifier

If you present multiple identity documents (e.g., passport and driving licence), the verifier may compute nullifiers for all documents, forming a nullifier family. All nullifiers in the family are published in the credential and cross-checked against existing credentials on relays.

### 5.4 The Merkle Tree

Your personal attributes (name, date of birth, nationality, document type, document expiry, nullifier) are stored as leaves in a Merkle tree. Only the Merkle root is published on-chain. You can prove individual attributes by providing a Merkle path, without revealing all attributes. The Merkle tree uses RFC 6962 domain separation (0x00 prefix for leaf hashes, 0x01 for internal nodes).

### 5.5 Age-Range Proofs

Your date of birth is never published. Instead, the verifier computes a Bulletproof zero-knowledge proof that your age falls within a specified range (e.g., "18+", "13–17", "8–12"). The proof is mathematically verifiable without revealing your exact age or date of birth.

### 5.6 Cross-Verification

You may seek verification from a second (or further) verifier presenting the same documents. Because the nullifier is derived from your documents, the same nullifier is produced. The Protocol distinguishes cross-verification from duplicate fraud by checking whether the subject's public key matches the existing credential:

- Same nullifier + same pubkey = independent confirmation (higher Signet IQ contribution)
- Same nullifier + different pubkey = possible duplicate identity (flagged for investigation)

Cross-verification is the strongest IQ signal, representing independent professional confirmation of the same identity.

---

## 6. Credential Lifecycle

### 6.1 Credential Expiry and Decay

Professional credentials include an `expires` tag (the credential's validity period) and a `documentExpiry` Merkle leaf (when the underlying document expires). These are different: a credential might expire after two years while the passport it was based on does not expire for ten.

Credentials do not hard-cliff at expiry. Instead, the IQ contribution of an expiring credential decays gradually as the expiry date approaches, rather than dropping to zero on the expiry date. Clients are expected to display this decay visually (a slowly dimming indicator) rather than a binary valid/invalid state.

If the document underlying a credential expires before the credential itself, the IQ contribution decays faster — reflecting the reduced confidence in the underlying identity document.

### 6.2 Credential Revocation

Credentials may be revoked by publishing a kind 30475 event. Revocation may be initiated by:

- You (self-revocation — e.g., on key compromise or name change)
- The issuing verifier (for cause, such as discovered fraud)
- Community consensus (for systemic fraud or security compromise)

### 6.3 Credential Chains and Document Renewal

When your real-world attributes change (name change, document renewal, tier upgrade), a superseding credential is issued with a `["supersedes", "<old_event_id>"]` tag. Clients follow the chain to display only the current active credential. Superseded credentials remain on relays as historical records.

**Document renewal and nullifiers:**
- **Passport renewal:** A new passport number produces a new nullifier. The old and new nullifiers are linked by a `["nullifier-chain", "<old_nullifier>"]` tag in the new credential.
- **Driving licence renewal (UK):** The licence number typically does not change on renewal. The new credential references the same nullifier.

### 6.4 Two-Credential Model Detail

| Credential | Contains | Does not contain |
|---|---|---|
| Natural Person | Merkle root, primary nullifier, nullifier family, age-range proof, entity-type, guardian tags (if child) | Real name, date of birth, document number |
| Persona | Age-range proof, entity-type=persona, guardian tags (if child) | Nullifier, Merkle root, any personal attributes |

### 6.5 Guardian Delegation

A guardian (verified parent or legal guardian) may delegate specific permissions to trusted adults via kind 30477 delegation events. Delegation scopes include:

- `full` — full delegation (e.g., co-parent)
- `activity-approval` — approve activities requiring parental consent
- `content-management` — manage the child's content and connections
- `contact-approval` — approve new contacts

Delegation events include an `agent-type` tag identifying the relationship (e.g., `teacher`, `grandparent`, `step-parent`). Guardian tags in credentials are immutable — they can only be changed by a new credential issued by a professional with appropriate legal documentation.

### 6.6 Child Sub-Accounts

A child credential is a sub-account of a verified parent or guardian:

- The child credential must include guardian tags linking to a Tier 3+ verified parent or guardian
- The child must be present during the Tier 4 verification ceremony (in person or through a legally equivalent process)
- When the child turns 18, they receive a new Tier 3 credential with no guardian tags, superseding the child credential
- A child cannot hold a Persona credential that carries a higher age-range assertion than their verified age range

### 6.7 Persona Accounts

A Persona is an anonymous alias:

- A Persona carries no personally identifying information — no name, no nullifier, no Merkle root
- A Persona inherits the age-range proof from the two-credential ceremony
- A Persona may be linked to a Natural Person via an identity bridge (kind 30476) using ring signatures, allowing the Persona to prove "I am a real, verified person" without revealing which person
- You are responsible for all activity conducted through your Persona accounts

### 6.8 No Guarantee of Acceptance

We do not guarantee that any credential will be accepted by any relying party. Communities set their own acceptance policies through kind 30472 policy events.

### 6.9 Document Wallet

My Signet supports a document wallet containing multiple identity documents. Each document produces its own credential and its own nullifier. This enables progressive verification: you may add documents over time, with each additional document strengthening your nullifier family and contributing to your Signet IQ.

---

## 7. User Obligations

### 7.1 General Obligations

All users must:

1. **Accuracy.** Enter truthful information when creating credentials. Fraudulent credentials undermine the trust model and may constitute criminal fraud.
2. **Key security.** Protect your mnemonic and private key. You are solely responsible for their security.
3. **Compliance.** Comply with all applicable laws and regulations.
4. **Responsible use.** Use the Protocol in good faith and not for any unlawful, fraudulent, or harmful purpose.
5. **Reporting.** Promptly report security vulnerabilities, credential fraud, or Protocol misuse to the contact address in Section 21.

### 7.2 Prohibited Uses

You must not:

1. Create false, misleading, or fraudulent credentials
2. Impersonate another person or entity
3. Attempt to reverse-engineer zero-knowledge proofs to extract personal data
4. Use the Protocol to facilitate illegal activities, including identity theft, fraud, money laundering, terrorist financing, or child exploitation
5. Attack the Protocol's cryptographic infrastructure or attempt to break ring signature anonymity sets
6. Spam the network with illegitimate credential, vouch, or challenge events
7. Collude with verifiers to obtain unwarranted Tier 3 or Tier 4 credentials
8. Use automated systems to mass-generate credentials or vouches without genuine verification
9. Interfere with or disrupt the Protocol or the Nostr network
10. Exploit the Protocol to circumvent age restrictions or child safety measures

### 7.3 Vouching Obligations (Tier 2)

When vouching for another user (kind 30471 event):

- You must have a genuine, personal basis for the vouch
- You must not accept payment or other consideration for providing vouches
- You may revoke a vouch at any time by publishing a revocation event
- Your vouching behaviour affects your own Signet IQ

---

## 8. Verifier Obligations

### 8.1 Why There Is No Separate Agreement

We have absorbed the verifier agreement into these Terms because the people most likely to verify children — teachers at parents' evenings, GPs, social workers — should not need to navigate a second legal document. By acting as a Signet verifier (publishing a kind 30473 event or performing a ceremony), you accept the obligations in this section. These obligations are in addition to, and do not replace, your existing professional duties.

### 8.2 Eligible Professions

You may act as a Signet verifier if you hold a current, valid registration with a recognised regulatory body in one of the following categories. This list follows the UK passport countersigning standard and its international equivalents.

**Legal professionals:** Solicitor, barrister, advocate, attorney-at-law, legal executive, notary public, commissaire de justice, Notar, licensed conveyancer, chartered legal executive.

**Medical and health professionals:** Physician, surgeon, general practitioner, dentist, pharmacist, optician/optometrist, registered nurse (where nationally permitted), physiotherapist, clinical psychologist, community or hospital-based healthcare professional registered with a national body (GMC, NMC, GDC, GPhC, HCPC, or equivalent).

**Education professionals:** Qualified teacher (registered with the Teaching Regulation Agency or national equivalent), headteacher or deputy headteacher, further or higher education lecturer registered with a professional body, school inspector.

**Financial professionals:** Chartered accountant (ICAEW, ICAS, ACCA, CIMA, CPA, or equivalent), chartered certified accountant, licensed auditor, independent financial adviser authorised by a national financial regulator, bank or building society official of officer grade.

**Public service and emergency professionals:** Police officer, fire officer, member of HM Armed Forces (officer), judge, magistrate, justice of the peace, Crown Prosecution Service officer, probation officer, social worker registered with a national regulatory body.

**Faith and community professionals:** Minister of religion, faith leader recognised as such by a registered denomination, civil registrar.

**Engineering, science, and technical professionals:** Chartered engineer (registered with a national engineering institution), chartered scientist, architect (registered with the Architects Registration Board or equivalent), chartered surveyor.

**Other regulated professionals:** Any professional regulated by a statutory body whose register is publicly searchable and whose members are subject to fitness-to-practise proceedings. If in doubt, contact us before performing verifications.

In all cases, you must be in good standing (not subject to suspension, restriction, or ongoing disciplinary proceedings that affect your fitness to verify identity).

### 8.3 Registration

To register as a verifier:

1. Publish a kind 30473 verifier credential event on Nostr containing your professional category, jurisdiction, licensing body, and licence reference.
2. Obtain at least two vouches from other verified Signet professionals from at least two different professions (cross-profession vouching prevents single-profession collusion rings).
3. Registration does not imply endorsement by us.

### 8.4 Performing Tier 3 Verifications (Adult)

When performing a Tier 3 (Adult) verification, you must:

1. Verify identity in person, or through a legally equivalent remote process expressly permitted by law in the relevant jurisdiction. Remote verification is the exception, not the default.
2. Inspect at least one original, government-issued photo identification document (passport, national ID card, or driving licence). Digital document inspection (including eIDAS wallet credentials where available) is permitted where national law treats it as equivalent to physical inspection.
3. Confirm that the person before you matches the document.
4. Confirm (or reject) the data the subject has pre-entered in the App. You are confirming what you see; you are not entering data on behalf of the subject.
5. Compute the document nullifier and, where multiple documents are presented, the nullifier family.
6. Issue the Natural Person credential (kind 30470) and the Persona credential (kind 30470) via the two-credential ceremony.
7. Discard the document number after nullifier computation. Do not store it unless your professional obligations independently require you to.
8. Maintain records of the verification (date, location, identity of the subject, documents inspected, nullifier hash, both pubkeys) for the period required by your professional obligations — typically at least six years.

**Confirmation methods and IQ weight:**

| Method | Description | IQ contribution weight |
|---|---|---|
| A — In-person, physical document | You physically inspect an original document and the person together, face-to-face | Full weight |
| B — In-person, digital document | In-person meeting; subject presents an eIDAS wallet or equivalent government-verified digital identity | Full weight (where law treats as equivalent) |
| C — Remote, regulated | Video call with regulatory approval and liveness check; original documents couriered or shown at high resolution | Reduced weight |
| D — Remote, unregulated | Any remote process not covered by C | Not permitted for Tier 3 or Tier 4 |

The verification method is recorded in the credential (`["method", "in-person-id"]` or equivalent tag). Clients and relying parties may restrict acceptance to certain methods.

### 8.5 Performing Tier 4 Verifications (Adult + Child)

When performing a Tier 4 (Adult + Child) verification, you must comply with all Tier 3 obligations and additionally:

1. **Verify the child's identity** using appropriate documents (birth certificate, passport, or other documents adequate in your professional judgement).
2. **Verify the parent-guardian relationship** through documentation: birth certificate (biological parent), court-issued guardianship order (legal guardian), adoption papers (adoptive parent), or step-parent responsibility order.
3. **Teachers and school-based verifiers:** You may use your professional knowledge and the school's enrollment records (which already incorporate birth certificate verification) as evidence in lieu of, or in addition to, original documents. The child's date of birth is already on the school's records. A parent presenting their passport at a parents' evening is sufficient for a Tier 4 verification in the same session.
4. **Obtain parental consent** for the child's credential, documented in accordance with applicable child protection law.
5. **Conduct the verification with the child present** where at all possible.
6. **Assess the child's welfare.** Exercise your professional judgement to identify any indicators of coercion, exploitation, or safeguarding concern. If any such concerns arise, do not proceed, and follow your mandatory reporting obligations under applicable law.
7. Issue two credentials for the child (Natural Person + Persona), both carrying the child's age-range proof and guardian tags linking the child to their verified parent or guardian.

### 8.6 Prohibited Verifier Actions

You must not:

1. Issue credentials for anyone whose identity you have not genuinely confirmed
2. Accept payment, gifts, or other consideration in exchange for issuing unwarranted verifications
3. Allow any other person to perform verifications using your credentials or Nostr key
4. Perform verifications for family members or close personal associates without prior disclosure and approval
5. Self-verify — issue Tier 3 or Tier 4 credentials for yourself
6. Retain copies of identity documents beyond what your professional obligations require
7. Use data obtained during verifications for any purpose other than the verification itself and required record-keeping
8. Disclose details of verifications to any third party, except as required by law

### 8.7 Verifier Reporting Obligations

You must promptly report to us:

- Any compromise or suspected compromise of your Nostr private key
- Any discovery that you have previously issued a fraudulent or erroneous verification
- Any change in your professional registration status (suspension, restriction, revocation, disciplinary proceedings)
- Any data breach affecting your verification records
- Any legal process, investigation, or regulatory action relating to your verification activities
- Any conflict of interest arising in connection with a verification

### 8.8 Verifier Liability

You are independently liable for the accuracy and integrity of your verifications. Because you are confirming data entered by the subject, your liability is specifically for:

- Confirming data you did not in fact verify, or that you knew or had reason to know was incorrect
- Failure to identify document forgery that a reasonably competent professional in your field would have identified
- Failure to identify safeguarding concerns in Tier 4 verifications
- Violation of your professional obligations and applicable law

We do not supervise, endorse, or guarantee the quality of any individual verifier's work. We are not jointly or vicariously liable for your acts or omissions. You are an independent professional, not our employee, agent, or partner.

### 8.9 Insurance

You should maintain professional indemnity insurance adequate for your verification activities. The appropriate level depends on your profession's existing requirements. If your profession already mandates professional indemnity insurance (as most of the professions in Section 8.2 do), that coverage should extend to your Signet verification activities provided they fall within the scope of your general professional practice.

### 8.10 Verifier Termination

Your verifier status may be terminated:

**Immediately and without notice if:** your professional licence is suspended or revoked; you have issued fraudulent verifications; your Nostr private key is compromised; you have breached child safety obligations; or you have committed a criminal offence related to your verification activities.

**With 30 days' notice if:** you materially breach these Terms and fail to cure within 14 days; you no longer meet eligibility requirements; or the Protocol is discontinued.

Upon termination, your kind 30473 verifier credential is revoked. Previously issued credentials remain valid unless individually revoked. You must retain verification records for the required retention period.

---

## 9. Website Operators and the signet-verify.js SDK

### 9.1 Who This Section Applies To

This section applies to any person or organisation that integrates the signet-verify.js SDK or otherwise calls Signet Protocol APIs from a website or application to verify the identity or age of their users ("Website Operators").

### 9.2 What the SDK Provides

When a user presents a Signet credential to your website through the SDK, you receive:

- An age-range proof (e.g., "18+", "13–17") — mathematically verified
- The user's Signet IQ score
- The credential tier
- A verification timestamp

You do not receive:

- The user's real name
- The user's date of birth or age
- The user's document type or number
- The user's address or any other personally identifying information
- The identity of the verifier

The SDK is designed so that you receive the minimum information necessary to make an age or identity gate decision.

### 9.3 Website Operator Obligations

By integrating the SDK, you agree to:

1. **No storage beyond session.** You must not store proof data, age-range assertions, or Signet IQ scores beyond the duration of the user's session, unless you have a specific legal basis for doing so under applicable data protection law and you have disclosed this to your users.
2. **No re-identification.** You must not attempt to re-identify users from the proof data, or combine proof data with other data to identify users.
3. **No profiling.** You must not use proof data to build profiles of users' verification history or credential states.
4. **Accurate reliance only.** You must only rely on the proof for the purpose it provides — confirming that a user meets an age or identity threshold. You must not represent to third parties that you have verified the user's real identity.
5. **Privacy notice.** You must disclose in your privacy notice that you use Signet credential verification and describe what data you receive and how you use it.
6. **No manipulation.** You must not use the SDK in a way designed to circumvent its privacy protections or manipulate users into presenting credentials they would not otherwise present.
7. **Compliance.** You must comply with all applicable laws, including data protection laws (GDPR, UK GDPR, CCPA/CPRA, and equivalents), in your use of the SDK.

### 9.4 SDK Licence

The signet-verify.js SDK is made available under the same open-source licence as the Protocol specification (see the Protocol repository). You must comply with the licence terms.

### 9.5 No Endorsement

Integration of the SDK does not imply endorsement of your website or service by us. You must not represent that Signet endorses or certifies your service.

---

## 10. The Verification Bot

### 10.1 What It Is

The Signet verification bot ("the Bot") is an automated service that monitors the Nostr network for kind 30470 credential events and provides credential verification summaries on request. The Bot may post replies to queries, publish periodic digests, or respond to mentions.

### 10.2 What It Processes

The Bot processes public Nostr events only. It reads kind 30470, 30471, 30472, 30473, 30475, 30476, and 30477 events from public relays. It does not access your private key, your mnemonic, or any data stored locally in the App.

The Bot computes Signet IQ scores from public on-chain data. It does not collect or store personal data beyond what is published in public Nostr events.

### 10.3 Who Runs It

The Bot is operated by the Protocol team. Its Nostr public key is published in the Protocol repository. Third parties may run compatible verification bots using the open-source Protocol specification; third-party bots are not operated by us and are not our responsibility.

### 10.4 Bot Limitations

The Bot provides a best-effort service. It may lag behind real-time relay state. It does not guarantee that its output reflects every current credential or revocation event on every relay. Relying parties making access control decisions should query relays directly, not rely solely on Bot output.

---

## 11. Signet IQ Scores

### 11.1 What Signet IQ Is

The Signet IQ score (0–200) is a continuous reputation score derived from on-chain data. A score of 100 represents a baseline equivalent to the current UK/US government identity standard. Scores above 100 reflect multiple verifications, strong peer trust, identity bridges, and account longevity.

### 11.2 How It Is Computed

The score is computed from weighted contributions including:

- Tier 3 or Tier 4 professional verification (highest weight)
- Cross-verification by additional independent professionals
- In-person peer vouches from high-IQ users
- Identity bridges (kind 30476)
- Account age and activity
- Verifier trust score (see Section 11.3)

Vouch weight scales with the voucher's own Signet IQ. A vouch from someone at IQ 150 carries more weight than a vouch from someone at IQ 40.

### 11.3 Verifier Trust Scores

Every professional verifier has a trust score that feeds into the IQ contribution of credentials they have issued. The trust score is derived from:

- Confirmation method (Method A carries full weight; Method C carries reduced weight — see Section 8.4)
- Number of independent cross-verifications of their subjects by other verifiers
- The jurisdiction's Corruption Perceptions Index (CPI) — credentials from jurisdictions with lower CPI scores carry less weight, not because of discrimination, but because objective statistical confidence in the verification process is lower
- Anomaly detection (e.g., 30 verifications in one hour, rapid temporal clustering, suspicious nullifier patterns)

### 11.4 Decay

The IQ contribution of a credential decays as:

- The credential expiry date approaches
- The underlying document expiry date approaches (faster decay)
- The verifier's trust score falls (e.g., due to discovered fraud)

Decay is gradual. There is no hard cliff.

### 11.5 Disclaimer

The Signet IQ score is a computed metric based on publicly available on-chain data. It does not constitute a definitive assessment of trustworthiness, identity, or character. We make no warranty that any Signet IQ score accurately reflects the trustworthiness of any user.

---

## 12. Data Protection

### 12.1 Personal Data the Protocol Does Not Collect

The Signet Protocol is designed not to collect or publish your personal data. Your name, date of birth, nationality, and document number are:

- Never published on the Nostr network
- Never transmitted to our servers
- Stored locally on your device in encrypted form (AES-256-GCM, key derived via PBKDF2 600,000 iterations)
- Accessible only after successful biometric or PIN authentication

### 12.2 What Is Published On-Chain

The following data is published to the Nostr network (public by design):

- Your Nostr public key (npub)
- Your credential tier and type
- Your Merkle root (a cryptographic hash — does not reveal personal attributes)
- Your document nullifier (a one-way hash — does not reveal document details)
- Your age-range proof (e.g., "18+" — does not reveal your age)
- Verifier credential metadata (profession, jurisdiction, licensing body reference)
- Vouch attestations
- Delegation events

Once published to Nostr, these events are public and may be replicated by relay operators. We cannot delete or modify published events.

### 12.3 Local Data Storage

Data stored locally in the App (mnemonic, private keys, document details used to compute the Merkle tree) is stored in IndexedDB in encrypted form. It is never stored in plaintext. The encryption key is protected by your biometric or PIN.

### 12.4 Verifiers as Independent Data Controllers

When a professional verifier inspects your identity documents and maintains verification records, they do so as an independent data controller. Their processing is governed by their professional obligations and applicable data protection law (UK GDPR, GDPR, CCPA/CPRA, or equivalent), not by us.

### 12.5 Jurisdiction-Specific Data Protection

| Jurisdiction | Applicable law |
|---|---|
| United Kingdom | UK GDPR, Data Protection Act 2018 |
| European Union | GDPR (Regulation 2016/679) |
| United States | CCPA/CPRA (California), state privacy laws |
| Brazil | LGPD |
| India | DPDP Act 2023 |
| Australia | Privacy Act 1988 |
| Japan | APPI |
| South Korea | PIPA |
| UAE | Federal Decree-Law No. 45 of 2021 |
| Other | Applicable national or regional data protection law |

### 12.6 EU/UK Data Subject Rights

If you are in the EU or UK, you have the right to access, rectify, erase, restrict processing of, and port your personal data. Because the Protocol is designed to minimise data collection, the data we hold about you is limited. Contact us at the address in Section 21 to exercise your rights.

### 12.7 EU Online Dispute Resolution

If you are a consumer in the EU, you may lodge a complaint through the EU Online Dispute Resolution platform: [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

---

## 13. Intellectual Property

### 13.1 Protocol Specification

The Signet Protocol specification is released under an open-source licence as specified in the Protocol repository. You are granted a licence to use, implement, and build upon the Protocol in accordance with that licence.

### 13.2 Trademarks

"The Signet Protocol", "Signet", and "My Signet" and associated logos are trademarks. You may not use these marks in a manner that implies endorsement or affiliation without prior written consent, except for accurate descriptive reference to the Protocol or the App.

### 13.3 User Content

You retain ownership of any content you create using the Protocol (credentials, vouches, delegation events). By publishing events to the Nostr network, you acknowledge that these events are public and may be stored and replicated by relay operators.

### 13.4 SDK

The signet-verify.js SDK is made available under the open-source licence specified in the Protocol repository. Commercial use is permitted in accordance with that licence.

### 13.5 Contributions

Contributions to the Protocol specification or implementation code are subject to the contributor licence agreement in the Protocol repository.

---

## 14. Disclaimers

### 14.1 Protocol Provided "As Is"

THE PROTOCOL, THE APP, AND THE SDK ARE PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.

### 14.2 No Warranty of Accuracy

WE DO NOT WARRANT THAT:

- ANY CREDENTIAL IS ACCURATE, COMPLETE, OR RELIABLE
- ANY VERIFIER IS COMPETENT, HONEST, OR PROPERLY LICENSED
- THE PROTOCOL WILL OPERATE WITHOUT INTERRUPTION OR ERROR
- THE CRYPTOGRAPHIC COMPONENTS WILL REMAIN SECURE INDEFINITELY
- ANY SIGNET IQ SCORE ACCURATELY REFLECTS THE TRUSTWORTHINESS OF ANY USER
- THE SDK WILL MEET ANY PARTICULAR RELYING PARTY'S LEGAL COMPLIANCE REQUIREMENTS

### 14.3 Decentralisation Disclaimer

Because the Protocol operates on a decentralised network, we:

- Cannot control, monitor, or censor Protocol activity
- Cannot reverse or modify published events
- Cannot guarantee the availability or performance of any relay
- Cannot enforce these Terms against all participants globally
- Cannot be responsible for the conduct of independent relay operators

### 14.4 Cryptographic Disclaimer

No cryptographic system is provably secure against all future attacks. Advances in computing (including quantum computing) may affect the security of the Protocol's cryptographic components. We intend to support post-quantum migration, but cannot guarantee specific timelines.

### 14.5 Regulatory Disclaimer

The regulatory landscape for decentralised identity and zero-knowledge proofs is evolving. Compliance obligations may change. Features of the Protocol may become subject to new regulations.

---

## 15. Limitation of Liability

### 15.1 General Limitation

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, WE, OUR DIRECTORS, OFFICERS, EMPLOYEES, AGENTS, AND AFFILIATES SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, PUNITIVE, OR EXEMPLARY DAMAGES, INCLUDING LOSS OF PROFITS, GOODWILL, DATA, OR OTHER INTANGIBLE LOSSES, WHETHER OR NOT WE WERE ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

### 15.2 Cap on Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, OUR TOTAL AGGREGATE LIABILITY FOR ALL CLAIMS ARISING OUT OF OR RELATED TO THESE TERMS OR THE PROTOCOL SHALL NOT EXCEED THE GREATER OF: (A) THE AMOUNT YOU PAID TO US IN THE 12 MONTHS PRECEDING THE CLAIM, OR (B) £100.

### 15.3 Exceptions

The limitations above do not apply to:

- Liability that cannot be excluded or limited under applicable law
- Liability arising from wilful misconduct or fraud
- Liability for death or personal injury caused by negligence (in jurisdictions where limitation is prohibited)
- Consumer statutory rights that cannot be waived by contract

### 15.4 Consumer Protection

Nothing in these Terms affects your statutory rights as a consumer under applicable consumer protection laws.

---

## 16. Indemnification

### 16.1 Your Indemnification Obligations

You agree to indemnify, defend, and hold us harmless from and against any claims, damages, losses, liabilities, costs, and expenses (including reasonable legal fees) arising out of or related to:

1. Your use of the Protocol
2. Your breach of these Terms
3. Your violation of any applicable law
4. Your infringement of any third-party rights
5. Credentials you create, including false or misleading credentials
6. Vouches you issue
7. Verifications you perform (if you are a verifier)
8. Your use of the SDK and any claims brought by your users in connection with it

### 16.2 Indemnification Procedure

We will notify you promptly of any claim, provide reasonable cooperation, and allow you to control the defence and settlement of the claim, provided you do not settle any claim that imposes obligations on us without our prior written consent.

---

## 17. Governing Law and Dispute Resolution

### 17.1 Governing Law

These Terms are governed by and construed in accordance with the laws of England and Wales, without regard to conflict of law provisions.

### 17.2 Dispute Resolution

**Step 1 — Negotiation:** The parties shall first attempt to resolve any dispute through good-faith negotiation for 30 days.

**Step 2 — Mediation:** If negotiation fails, the parties shall submit to mediation administered by the Centre for Effective Dispute Resolution (CEDR) in accordance with its rules.

**Step 3 — Arbitration:** If mediation fails, the dispute shall be finally resolved by binding arbitration administered by the London Court of International Arbitration (LCIA) under its rules. The seat of arbitration is London. The language is English. The award is final and binding.

### 17.3 Class Action Waiver

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, YOU AGREE TO RESOLVE DISPUTES ONLY ON AN INDIVIDUAL BASIS AND NOT IN A CLASS, CONSOLIDATED, OR REPRESENTATIVE ACTION. IF THIS WAIVER IS UNENFORCEABLE, THE ARBITRATION PROVISION IS NULL AND VOID.

### 17.4 Exceptions

Either party may seek injunctive relief in any court of competent jurisdiction to protect intellectual property or prevent irreparable harm.

### 17.5 EU Consumer Rights

If you are a consumer in the EU, you may also use your national courts and the EU ODR platform: [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

### 17.6 Verifier Professional Regulatory Matters

Nothing in these Terms restricts the jurisdiction of any professional regulatory body over a verifier, a verifier's right to seek guidance from their regulatory body, or our right to report concerns to a verifier's regulatory body.

---

## 18. Termination

### 18.1 Your Right to Terminate

You may stop using the Protocol at any time. Due to the decentralised nature of the Protocol, previously published events may remain on Nostr relays indefinitely.

### 18.2 Our Rights

We reserve the right to:

- Revoke verifier credentials for cause (as described in Section 8.10)
- Publish community advisories about fraudulent credentials or actors
- Modify or discontinue the Protocol specification

### 18.3 Effect of Termination

Upon termination:

- Your right to use any proprietary App components ceases
- Sections 8 (verifier obligations — record-keeping survives), 12, 13, 14, 15, 16, 17, and 20 survive
- Previously published Nostr events are not affected

---

## 19. Amendments

### 19.1 Right to Amend

We may modify these Terms at any time. Modifications are effective upon:

- Publication of updated Terms in the Protocol repository
- A Nostr event announcement referencing the updated Terms
- 30 days' notice for material changes

### 19.2 Acceptance of Amendments

Your continued use of the Protocol after the effective date constitutes acceptance. If you do not agree, you must stop using the Protocol.

### 19.3 Material Changes

For material changes, we will provide:

- Clear notice of the nature of the changes
- A plain-English summary of key changes
- At least 30 days before the changes take effect

---

## 20. General Provisions

### 20.1 Entire Agreement

These Terms constitute the entire agreement between you and us regarding the Protocol. They supersede the separately published Verifier Agreement (which is now incorporated herein as Section 8). If you previously executed a standalone Verifier Agreement, these Terms replace it from the Effective Date.

### 20.2 Severability

If any provision is found invalid or unenforceable, it shall be enforced to the maximum extent permissible. The remaining provisions remain in full force.

### 20.3 Waiver

Failure to enforce any provision does not constitute a waiver.

### 20.4 Assignment

You may not assign these Terms without our prior written consent. We may assign these Terms without your consent.

### 20.5 Force Majeure

Neither party is liable for failure or delay due to causes beyond their reasonable control, including natural disasters, war, terrorism, pandemics, government action, network failures, cryptographic algorithm compromises, or Nostr relay outages.

### 20.6 Notices

Notices to us: see Section 21. Notices to you: any contact information you have provided, or via Nostr event or the Protocol repository.

### 20.7 Third-Party Beneficiaries

These Terms do not create third-party beneficiary rights, except that the Nostr network relay operators and Protocol users who rely on credentials issued by verifiers are intended beneficiaries of Section 8.

### 20.8 Export Compliance

You must comply with all applicable export and sanctions laws. The Protocol's cryptographic components may be subject to export controls in certain jurisdictions.

### 20.9 Headings

Section headings are for convenience only and do not affect interpretation.

---

## 21. Contact

For questions about these Terms, to exercise data protection rights, or to report security issues:

**The Signet Protocol**
Email: legal@signet.trotters.cc
Security disclosures: security@signet.trotters.cc
Repository: https://github.com/decented/signet

---

## 22. Jurisdiction-Specific Annexes

### Annex A — United Kingdom

**Licensing bodies:** Law Society of England and Wales, Law Society of Scotland, Law Society of Northern Ireland, Bar Council of England and Wales, Faculty of Advocates, General Medical Council (GMC), Nursing and Midwifery Council (NMC), General Dental Council (GDC), General Pharmaceutical Council (GPhC), Health and Care Professions Council (HCPC), Teaching Regulation Agency (TRA), General Teaching Council for Scotland (GTCS), Architects Registration Board (ARB), Institute of Chartered Accountants in England and Wales (ICAEW), Institute of Chartered Accountants of Scotland (ICAS), Association of Chartered Certified Accountants (ACCA), Financial Conduct Authority (FCA) — authorised persons, Faculty Office of the Archbishop of Canterbury (notaries public).

**Professional indemnity:** As required by the SRA, FCA, GMC, TRA, or the relevant regulatory body.

**Child safety:** Children Act 1989 and 2004; Safeguarding Vulnerable Groups Act 2006; DBS Enhanced Check required for teachers and other regulated activity roles performing Tier 4 verifications; mandatory reporting under Working Together to Safeguard Children (2023).

**Data protection:** UK GDPR; Data Protection Act 2018; ICO guidance; DSIT guidance on biometric data.

**Age verification:** Online Safety Act 2022 (Ofcom-approved age assurance). Tier 4 in-person professional verification exceeds Ofcom's accepted methods.

### Annex B — United States

**Licensing bodies:** State bar associations; state medical boards; state notary commissions; state departments of education (teachers); relevant state financial regulators.

**Note:** Eligibility and obligations vary significantly by state. You must comply with the law of the state(s) where you perform verifications.

**Child safety:** COPPA (Children's Online Privacy Protection Act); FERPA (for school-based verifiers); state mandatory reporter obligations; state child protection statutes. School enrollment records held by a teacher may serve as documentary evidence for Tier 4 verifications where state law permits.

**Data protection:** CCPA/CPRA (California); Virginia CDPA; other state privacy laws; FERPA (school records). A separate Data Processing Agreement may be required for California-resident users.

### Annex C — European Union

**Licensing bodies:** National bar associations, medical councils, notarial chambers, and their equivalents in each member state.

**Note:** Specific requirements vary by member state. Verifiers must comply with the law of the member state where they are established and where they perform verifications.

**eIDAS 2.0:** The eIDAS unique person identifier, when presented via a government-issued eIDAS wallet, may serve as an additional nullifier source. The nullifier formula is `SHA-256(LP("eidas") || LP(eidas_unique_id) || LP("signet-nullifier-v2"))`.

**Child safety:** GDPR Article 8; national implementing legislation; Regulation (EU) 2022/2065 (DSA) age verification obligations.

**Data protection:** GDPR (Regulation 2016/679); national implementing legislation; national DPA guidance.

### Annex D — Australia

**Licensing bodies:** State and territory law societies; Australian Health Practitioner Regulation Agency (AHPRA) for medical and allied health; state/territory justice departments (notaries); relevant state teacher registration bodies.

**Child safety:** Working With Children Check as applicable to role; Online Safety Act 2021; state child protection statutes.

**Data protection:** Privacy Act 1988; Australian Privacy Principles; Consumer Data Right (CDR) where applicable.

### Annex E — Japan

**Licensing bodies:** Japan Federation of Bar Associations (JFBA); Ministry of Justice (notaries); Japan Medical Association; relevant teaching registration authorities.

**Child safety:** APPI guidelines; national child protection legislation; Working with Young People obligations.

**Data protection:** Act on the Protection of Personal Information (APPI) and its amendments.

### Annex F — South Korea

**Licensing bodies:** Korean Bar Association; Korean Medical Association; relevant government ministries for other regulated professions.

**Child safety:** Personal Information Protection Act (PIPA); Youth Protection Act; mandatory reporting obligations.

**Data protection:** PIPA.

### Annex G — Brazil

**Licensing bodies:** Ordem dos Advogados do Brasil (OAB); Conselho Federal de Medicina (CFM); notarial chambers; relevant federal and state professional councils.

**Child safety:** LGPD Article 14 (child data — parental consent required); Estatuto da Criança e do Adolescente (ECA); mandatory reporting obligations.

**Data protection:** Lei Geral de Proteção de Dados (LGPD); ANPD guidance.

### Annex H — India

**Licensing bodies:** Bar Council of India and state bar councils; National Medical Commission (NMC); relevant state authorities for other regulated professions.

**Child safety:** Digital Personal Data Protection Act 2023 (DPDP); Protection of Children from Sexual Offences Act (POCSO); mandatory reporting obligations.

**Data protection:** DPDP Act 2023; rules issued thereunder.

### Annex I — United Arab Emirates

**Licensing bodies:** Ministry of Justice; Dubai Health Authority (DHA) or Health Authority Abu Dhabi (HAAD); relevant emirate professional authorities.

**Child safety:** Federal Law No. 3 of 2016 (Wadeema's Law — Child Rights Law); mandatory reporting obligations.

**Data protection:** Federal Decree-Law No. 45 of 2021 on Personal Data Protection; UAE Data Office guidance.

---

*The Signet Protocol — v0.1.0 — March 2026*
*This document is provided for informational purposes. It does not constitute legal advice. Seek qualified legal counsel for your jurisdiction before relying on it.*
