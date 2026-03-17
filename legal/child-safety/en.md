# Child Safety Policy

**The Signet Protocol — v0.1.0**

*Template — Seek qualified legal counsel for your jurisdiction before deployment.*

**Effective Date:** March 2026
**Last Updated:** March 2026

---

## 1. Purpose

This Child Safety Policy ("Policy") sets out the commitment of the Signet Protocol ("we," "us," or "our") to protecting children who interact with or are affected by the Signet Protocol (the "Protocol"). The Protocol's Tier 4 verification (Professional Verification — Adult + Child) specifically addresses child identity verification, and this Policy governs how that capability — and all child-related data — is handled.

The safety and privacy of children is our paramount concern. This Policy is designed to comply with all applicable child protection laws globally and to exceed minimum requirements where practicable.

---

## 2. Scope

This Policy applies to:

- All interactions with the Signet Protocol involving individuals under the age of 18 (or the age of majority in the relevant jurisdiction, whichever is higher)
- Tier 4 credential issuance and verification processes
- Age verification processes using zero-knowledge proofs
- All personnel, verifiers, relying parties, and third parties who interact with children's data through the Protocol
- All jurisdictions where the Protocol is used

---

## 3. Definitions

**"Child"** means any individual under the age of 18, or under the age of majority in the relevant jurisdiction, whichever is higher.

**"Digital Consent Age"** means the minimum age at which a child can independently consent to the processing of their personal data for digital services, as defined by the applicable jurisdiction.

**"Parent/Guardian"** means a parent, legal guardian, or other person with legal authority to act on behalf of a child.

**"Tier 4 Verification"** means the Protocol's Professional Verification (Adult + Child) tier, in which a licensed professional verifier confirms the identity of a child with the involvement and consent of a parent/guardian.

**"Age Range Proof"** means a zero-knowledge proof (using Bulletproofs) that demonstrates a user's age falls within a specified range without revealing the exact date of birth.

**"Signet IQ"** means the Protocol's continuous Identification Quotient score (0–200) reflecting the cumulative strength of a user's verification signals. For children, Signet IQ is computed from the guardian's own verification tier and Signet IQ, the child's own Tier 4 credential, and any peer vouches from verified accounts.

---

## 4. Regulatory Framework

### 4.1 International Compliance

This Policy is designed to comply with the following laws and frameworks:

| Jurisdiction | Law / Framework | Key Requirements |
|-------------|----------------|-----------------|
| **United States** | Children's Online Privacy Protection Act (COPPA) | Verifiable parental consent for children under 13; data minimisation; parental access rights |
| **European Union** | GDPR Article 8 | Digital consent age of 16 (member states may lower to 13); parental consent required below digital consent age |
| **United Kingdom** | UK GDPR + Age Appropriate Design Code (AADC) | Best interests of the child; age-appropriate design; 15 standards of AADC |
| **Australia** | Privacy Act 1988 + Online Safety Act 2021 | Reasonable steps to verify age; basic online safety expectations |
| **South Korea** | PIPA + Act on Promotion of Information and Communications Network | Consent of legal representative for children under 14 |
| **Brazil** | LGPD Article 14 | Best interests of the child; specific parental consent for children under 12; dual consent for 12–17 |
| **India** | DPDP Act 2023 | Verifiable consent of parent/guardian for children (under 18); prohibition on tracking, behavioural monitoring, and targeted advertising for children |
| **China** | PIPL Article 28 + Provisions on Protecting Minors Online | Specific consent for under-14; heightened protections for all minors |
| **Japan** | APPI + Basic Act on Cyber Security | Industry guidelines for children's data protection |
| **Canada** | PIPEDA + provincial laws | Meaningful consent based on child's capacity |

### 4.2 UN Convention on the Rights of the Child

This Policy is guided by the principles of the UN Convention on the Rights of the Child, including:
- The best interests of the child (Article 3)
- The right to privacy (Article 16)
- The right to protection from exploitation (Article 36)

---

## 5. Age Verification via Zero-Knowledge Proofs

### 5.1 How Age Verification Works

The Signet Protocol uses Bulletproofs-based zero-knowledge proofs for age verification. This approach:

1. **Proves without revealing:** A user can prove they are within a specified age range (e.g., "over 13," "over 16," "over 18," "13–17") without revealing their exact date of birth.
2. **Cannot be reverse-engineered:** The zero-knowledge proof is mathematically constructed so that the underlying date of birth cannot be extracted from the proof.
3. **Is verified cryptographically:** Relying parties can verify the proof's validity without learning anything beyond the age range claim.
4. **Is issued once, used many times:** A single age range proof can be presented to multiple relying parties without re-verification.

### 5.2 Age Range Categories

The Protocol supports the following standard age range proofs:

| Range | Description | Use Case |
|-------|-------------|----------|
| Under 13 | Below COPPA threshold | Requires full parental consent and supervision |
| 13–15 | Above COPPA, below some GDPR thresholds | May require parental consent depending on jurisdiction |
| 16–17 | Above most digital consent ages, below majority | Independent consent in most jurisdictions; some parental oversight |
| 18+ | Age of majority in most jurisdictions | Full independent consent |
| Custom | Jurisdiction-specific age ranges | Compliance with specific local requirements |

### 5.3 Proof Issuance for Children

For children (under 18), the verification ceremony follows a user-led flow with professional confirmation:

1. The parent/guardian and child attend a Tier 4 verification with a licensed professional (solicitor, notary, doctor, or equivalent).
2. **The user (parent/guardian) enters all document details** in the My Signet app: document type, country of issue, document number, and the child's date of birth. The verifier inspects the physical documents to confirm the data entered is accurate — they do not type on behalf of the user.
3. The Protocol computes the document-based nullifier locally on the user's device using the `signet-nullifier-v2` formula (SHA-256 of length-prefixed: docType, country, docNumber, "signet-nullifier-v2"). The nullifier is transmitted to the verifier; the raw document details are not.
4. The verifier generates the Bulletproof age-range proof and issues two credentials simultaneously: a Natural Person credential (keypair A) and a Persona credential (keypair B). Both carry the age-range proof and guardian tags (`["guardian", "<parent_pubkey>"]`). The child's real name is stored only as a private Merkle leaf — never published on-chain.
5. The Merkle tree for the child's Natural Person credential contains: date of birth (for the age-range proof), guardian relationship, document type, document number, and document expiry. The child's name is included as a private Merkle leaf and is **not** published to any relay. Nationality may be included for jurisdictional compliance.
6. The document-based nullifier (hash of document type, country, and number using `signet-nullifier-v2`) is included only on the Natural Person credential, preventing duplicate identity creation.
7. **Biometric account protection:** On the child's device, the My Signet app uses WebAuthn biometric unlock (face recognition or fingerprint) to protect access to the child's account. The biometric data never leaves the device — it is handled entirely by the device's secure enclave via the WebAuthn standard. No biometric templates are transmitted to any server or stored outside the device.

### 5.4 Teachers as a Primary Child Verification Channel

Teachers and school administrators are a recognised channel for Tier 4 child verification. School enrollment records — which establish the parent-child relationship and provide date of birth evidence — are accepted as supporting documentation alongside parental ID.

A teacher who is a licensed professional (e.g., a qualified teacher in a jurisdiction that treats teaching as a regulated profession, or a school-affiliated notary) may perform Tier 4 verification using:
- The parent/guardian's government-issued ID
- The school enrollment record as child evidence (in addition to or in lieu of a birth certificate or passport)

This pathway is especially important for home education communities and regions where access to solicitors or notaries is limited. The educator's professional body and their employing institution are the trust anchor. Fraudulent attestation by a teacher constitutes professional misconduct under applicable education law.

### 5.5 SDK-Based Age Verification for Websites

The Signet SDK allows websites and applications to verify a child's age range without receiving any personally identifiable information. The data flow is:

```
Website → SDK → My Signet app → ZK age-range proof → Website
```

The website requests proof of a specific age claim (e.g., "user is under 18" or "user is between 13 and 17"). The Signet SDK routes this request to the My Signet app on the user's device. The app generates the proof locally and returns only the cryptographic proof — no name, no date of birth, no document details, no nullifier. The website verifies the proof mathematically and learns only the age range claim.

This means websites can comply with age verification requirements (COPPA, UK Online Safety Act, Australian under-16 regulations) without collecting or storing any personal data about children.

---

## 6. Parental Consent Mechanisms

### 6.1 Consent Requirements by Jurisdiction

| Jurisdiction | Digital Consent Age | Consent Mechanism Required |
|-------------|--------------------|-----------------------------|
| United States (COPPA) | 13 | Verifiable parental consent (e.g., signed form, credit card verification, video call, government ID check) |
| EU (GDPR default) | 16 | Reasonable efforts to verify parental consent |
| EU (member state minimum) | 13 | As per member state implementation |
| United Kingdom | 13 | Age-appropriate verification of parental consent |
| Australia | No specific digital age | Reasonable steps based on maturity and risk |
| South Korea | 14 | Consent of legal representative |
| Brazil | 12 (with parental consent to 18) | Specific and prominent consent by parent/guardian |
| India | 18 | Verifiable consent of parent/guardian |
| China | 14 | Separate consent of parent/guardian |
| Japan | 15 (guideline) | Parental involvement recommended |

### 6.2 Protocol Consent Mechanisms

The Protocol supports the following parental consent mechanisms:

1. **Tier 3/4 Verified Parent Credential:**
   The parent/guardian obtains a Tier 3 or Tier 4 credential verifying their own identity via the two-credential ceremony (Natural Person + Persona). They then cryptographically sign a consent event authorising the child's credential. This creates a verifiable chain:
   - Parent's identity verified by professional verifier (two-credential ceremony)
   - Parent's consent cryptographically signed with their Nostr key
   - Child's credential linked to parent via immutable guardian tags on both Natural Person and Persona credentials
   - Guardian delegation events (kind 30477) allow the parent to delegate specific permissions to other trusted adults

2. **Co-Verification:**
   The parent/guardian and child attend a Tier 4 verification session together. The professional verifier:
   - Verifies both the parent/guardian's and child's identities
   - Confirms the parent-child or guardian-child relationship
   - Records the parent/guardian's consent as part of the verification event

3. **Delegated Consent:**
   For jurisdictions requiring specific consent mechanisms (e.g., COPPA's verifiable parental consent), additional verification steps may be required:
   - Signed consent form (digital or physical)
   - Video verification session
   - Government-issued ID verification of the consenting parent/guardian

### 6.3 Consent Withdrawal

Parents/guardians may withdraw consent at any time by:
1. Publishing a revocation event (kind 30475) from the parent/guardian's Nostr key, revoking the consent event.
2. Contacting the Signet Protocol support team to request revocation assistance.
3. Through any Nostr client implementing the Protocol's consent management features.

Upon consent withdrawal:
- The child's credential is immediately revoked.
- Relying parties are notified via the revocation event.
- All centrally held data related to the child is deleted within 30 days, except where retention is required by law.

---

## 7. Data Minimisation for Children

### 7.1 Principle

The Protocol applies the strictest data minimisation principles for children's data. No more data is collected or processed than is strictly necessary for the credential verification.

### 7.2 What Is Collected

| Data | Collected | Rationale |
|------|-----------|-----------|
| Child's Nostr public key | Yes | Required for credential binding |
| Age range proof (ZK proof) | Yes | Required for age verification |
| Parental consent record | Yes | Required for legal compliance |
| Credential metadata (tier, dates) | Yes | Required for credential functionality |
| Child's name | **No (not on-chain)** | Stored only as a private Merkle leaf; never published |
| Child's date of birth | **No (not on-chain)** | Replaced by ZK age range proof; stored only as a private Merkle leaf |
| Child's photograph | **No** | Not required |
| Child's government ID number | **No (not on-chain)** | Stored only as a private Merkle leaf for selective disclosure; not stored by verifier after ceremony |
| Nullifier hash (`signet-nullifier-v2`) | Yes (NP credential only) | Required for duplicate prevention; cannot be reversed to document details |
| Guardian pubkey(s) | Yes (both credentials) | Required for guardian-child link |
| Guardian relationship | Yes (private Merkle leaf, NP credential) | Establishes legal basis for guardian link |
| Merkle root | Yes (NP credential only) | Commits to verified attributes without publishing them |
| Entity type tag | Yes (both credentials) | Required to distinguish Natural Person from Persona |
| Child's location | **No** | Not required |
| Child's school or institution | **No (not on-chain)** | May be referenced as supporting evidence but not published |
| Behavioural data | **No** | Prohibited |
| Usage tracking | **No** | Prohibited for children |
| Biometric data | **No** | Device-local only via WebAuthn; no templates transmitted |

### 7.3 Merkle Tree Attributes for Children

The Natural Person credential for a child commits to a Merkle tree with the following leaves:

| Leaf | Purpose | Disclosed on-chain? |
|------|---------|---------------------|
| `dateOfBirth:<ISO date>` | Source for ZK age-range proof | No — private |
| `guardianRelationship:<type>` | Legal basis (e.g., "parent", "legal_guardian") | No — private |
| `documentType:<type>` | Type of evidence presented | No — private |
| `documentNumber:<number>` | For selective disclosure if required | No — private |
| `documentExpiry:<date>` | Document validity check | No — private |
| `name:<name>` | For selective disclosure if required | No — private |
| `nationality:<code>` | Jurisdictional compliance | No — private |
| `nullifier:<hash>` | Duplicate prevention | Yes (as top-level tag) |

Only the Merkle root and the nullifier hash appear on-chain. Individual leaves are revealed only when the child's guardian explicitly exercises selective disclosure (e.g., to prove the child's nationality to a regulatory authority).

### 7.4 Signet IQ for Children

Children have Signet IQ scores computed from:
- The Tier 4 credential itself (major contribution)
- The guardian's own verification tier and Signet IQ (weighted contribution, reflecting the strength of the guardian relationship)
- Peer vouches from other Tier 2+ accounts who know the family

A child's Signet IQ is displayed to relying parties as an aggregate trust signal. It does not reveal the guardian's identity, the child's name, or any other personal attribute — it is computed from public credential events only. Social scoring of children based on their Signet IQ for purposes beyond age verification and access control is prohibited (see Section 8).

### 7.5 Retention Limits

Children's data is subject to the shortest permissible retention periods:
- Active credentials: Until expiry, revocation, or the child reaching majority (whichever is earliest)
- Consent records: Duration of credential validity plus any legally required retention period
- Verification records: As required by verifier's professional obligations (typically 1–3 years)
- Challenge/response data: Deleted immediately after verification

---

## 8. Prohibited Uses

### 8.1 Absolute Prohibitions

The following uses of the Protocol in relation to children are **strictly prohibited**:

1. **Profiling:** Using the Protocol to profile children for any purpose, including marketing, advertising, or behavioural analysis.
2. **Tracking:** Using credentials or verification data to track children's online or offline activities.
3. **Targeted Advertising:** Using age range proofs or credential data to target advertising at children.
4. **Data Monetisation:** Selling, licensing, or otherwise monetising children's credential data or age verification data.
5. **Automated Decision-Making:** Using children's credential data for automated decisions that produce legal or similarly significant effects.
6. **Surveillance:** Using the Protocol for ongoing surveillance of children's activities.
7. **Social Scoring:** Using credential or Signet IQ data to create social scoring systems for children beyond age-appropriate access control.
8. **Nudging:** Using design patterns that exploit children's vulnerabilities or manipulate their behaviour.
9. **Unnecessary Data Collection:** Collecting more data from children than is strictly necessary for the credential verification.
10. **Sharing Without Consent:** Sharing children's data with third parties without verifiable parental consent.

### 8.2 Relying Party Restrictions

Relying parties that receive age range proofs or credential verifications for children:
- Must not use the data beyond the specific purpose for which verification was sought
- Must not retain the verification data beyond the immediate need
- Must implement their own child safety measures appropriate to their service
- Must comply with all applicable child protection laws in their jurisdiction

---

## 9. Incident Reporting and Response

### 9.1 Types of Reportable Incidents

The following incidents involving children must be reported:

| Incident Type | Reporting Threshold | Priority |
|--------------|---------------------|----------|
| Breach of child's credential data | Any unauthorised access | Critical — Immediate |
| Fraudulent Tier 4 credential for a child | Discovery of any instance | Critical — Immediate |
| Compromise of parental consent mechanism | Any indication of compromise | Critical — Immediate |
| Exploitation of age verification | Discovery of any bypass | High — Within 4 hours |
| Misuse of child's credential by relying party | Any reported misuse | High — Within 4 hours |
| Suspected child exploitation facilitated by Protocol | Any indication | Critical — Immediate + Law enforcement |
| Deanonymisation of a child's identity | Any instance | Critical — Immediate |

### 9.2 Reporting Procedures

**Internal Reporting:**
- All incidents are reported immediately to the designated Child Safety Officer.
- The Child Safety Officer escalates to the DPO and to senior management.

**Regulatory Reporting:**
- Relevant supervisory authorities are notified within the time frames required by applicable law (e.g., 72 hours under GDPR).
- Country-specific notification requirements are followed (see Section 10).

**Law Enforcement Reporting:**
- Incidents involving suspected child exploitation are reported immediately to:
  - Local law enforcement
  - National Centre for Missing & Exploited Children (NCMEC) (US)
  - Internet Watch Foundation (IWF) (UK)
  - Equivalent bodies in the relevant jurisdiction

**Parental Notification:**
- Parents/guardians are notified without undue delay of any incident affecting their child's data or credential.
- Notification includes a description of the incident, its potential impact, and steps being taken.

### 9.3 Remediation

Following a child safety incident:
1. Immediate containment of the incident
2. Revocation of affected credentials
3. Forensic investigation
4. Root cause analysis
5. Implementation of preventive measures
6. Follow-up notification to affected parties
7. Post-incident review and Policy update if needed

---

## 10. Jurisdiction-Specific Requirements

### 10.1 United Kingdom

**Age Appropriate Design Code (AADC) — 15 Standards:**

| Standard | Implementation |
|----------|---------------|
| Best interests of the child | Child safety impact assessments for all Protocol features affecting children |
| Data protection impact assessments | DPIA conducted for Tier 4 and all child-related processing |
| Age appropriate application | Protocol interfaces designed for different age groups |
| Transparency | Privacy information provided in age-appropriate language |
| Detrimental use of data | Prohibition on using children's data in ways detrimental to their wellbeing |
| Policies and community standards | Clear standards for how children's credentials may be used |
| Default settings | Privacy-protective defaults for all child credentials |
| Data minimisation | Strictest minimisation applied (see Section 7) |
| Data sharing | Children's data not shared beyond verified necessity |
| Geolocation | No geolocation data collected or processed for children |
| Parental controls | Consent and oversight mechanisms as described in Section 6 |
| Profiling | Prohibited for children (see Section 8) |
| Nudge techniques | Prohibited for children (see Section 8) |
| Connected toys and devices | N/A to Protocol, but relying parties advised |
| Online tools | Protocol tools designed with child safety in mind |

**Reporting:** To the Information Commissioner's Office (ICO) within 72 hours.

### 10.2 United States

**COPPA Compliance:**
- Verifiable parental consent obtained before collecting any information from children under 13
- Clear, comprehensive online privacy notice describing children's data practices
- Parental access to review and delete child's data
- No conditioning of a child's participation on unnecessary disclosure of information
- Reasonable security measures for children's data

**FTC March 2026 Position:** The FTC will not take enforcement action where personal data is collected solely for age verification purposes, provided the data is robustly deleted and clear notice is given. Signet exceeds this: no personal data is collected, stored, or transmitted during age verification — the ZKP proof contains zero PII.

**State Laws:**
- California Consumer Privacy Act (CCPA) — opt-in consent required for sale of data of consumers under 16
- California Age-Appropriate Design Code Act (AB 2273) — data protection impact assessments for services likely to be accessed by children
- Other state laws as applicable

**Reporting:** To the FTC and applicable state attorneys general.

### 10.3 European Union

**GDPR Article 8 Compliance:**
- Parental consent required below digital consent age (13–16, per member state)
- Reasonable efforts to verify consent given by the holder of parental responsibility
- Directly offered to a child: privacy notice in clear, plain language suitable for the child

**Member State Variations:**

| Country | Digital Consent Age |
|---------|--------------------|
| Austria | 14 |
| Belgium | 13 |
| Croatia | 16 |
| Czech Republic | 15 |
| Denmark | 13 |
| Estonia | 13 |
| Finland | 13 |
| France | 15 |
| Germany | 16 |
| Greece | 15 |
| Hungary | 16 |
| Ireland | 16 |
| Italy | 14 |
| Latvia | 13 |
| Lithuania | 14 |
| Luxembourg | 16 |
| Malta | 13 |
| Netherlands | 16 |
| Poland | 16 |
| Portugal | 13 |
| Romania | 16 |
| Slovakia | 16 |
| Slovenia | 16 |
| Spain | 14 |
| Sweden | 13 |

**Reporting:** To the lead supervisory authority within 72 hours.

### 10.4 Australia

**Privacy Act 1988 + Online Safety Act 2021:**
- Reasonable steps to ensure child's capacity to consent
- Age-appropriate privacy information
- Compliance with Online Safety (Basic Online Safety Expectations) Determination 2022

**Reporting:** To the Office of the Australian Information Commissioner (OAIC) and the eSafety Commissioner.

### 10.5 South Korea

**PIPA + Act on Promotion of Information and Communications Network:**
- Consent of legal representative required for children under 14
- Minimum necessary information only
- No collection without legal representative consent

**Reporting:** To the Personal Information Protection Commission (PIPC).

### 10.6 Brazil

**LGPD Article 14:**
- Best interests of the child
- Specific, prominent parental consent for children under 12
- Children aged 12–17: dual consent (child + parent)
- Information practices communicated in a simple, clear, and accessible manner appropriate for the child

**Reporting:** To the ANPD (Autoridade Nacional de Proteção de Dados).

### 10.7 India

**DPDP Act 2023:**
- Verifiable consent of parent/guardian for all children (under 18)
- Prohibition on tracking, behavioural monitoring, and targeted advertising directed at children
- Data fiduciary obligations regarding children's data

**Reporting:** To the Data Protection Board of India.

---

## 11. Design Principles for Child Safety

### 11.1 Privacy by Design

All Protocol features affecting children incorporate:
- Data minimisation at the architectural level
- Zero-knowledge proofs to avoid exposing personal data
- Cryptographic protections built into the credential structure
- Default privacy-protective settings
- User-enters-verifier-confirms ceremony flow — document data is entered by the user on their own device; the verifier confirms accuracy but never holds raw document details

### 11.2 Safety by Design

Protocol interfaces and implementations should:
- Clearly distinguish between child and adult credential workflows
- Prevent accidental exposure of child identity information
- Include safeguards against credential misuse
- Provide clear, age-appropriate guidance
- Use biometric device unlock (WebAuthn) to protect child accounts on device

### 11.3 Regular Review

This Policy and all child safety measures are reviewed:
- At least annually
- Upon any change in applicable law
- Following any child safety incident
- Upon significant changes to the Protocol

### 11.4 Guardian Delegation Model

The Protocol implements a three-layer family structure model:

**Layer 1 — Credential level (immutable):**
Guardian tags (`["guardian", "<parent_pubkey>"]`) are set by the professional verifier and reflect legal parental responsibility. They can only be changed by a new credential issued by a professional with appropriate legal documentation (e.g., court order).

**Layer 2 — Delegation level (flexible):**
Guardians may delegate specific permissions to trusted adults (step-parents, grandparents, teachers) via kind 30477 guardian delegation events. Delegations are:
- Time-limited (with expiry)
- Scope-limited: `full`, `activity-approval`, `content-management`, `contact-approval`
- Revocable by the guardian at any time
- Signed by the guardian's Nostr key
- Tagged with `["agent-type", "guardian"]` to distinguish from other delegation event types

**Layer 3 — Client level (app-specific):**
Applications enforce permissions based on Layer 1 and Layer 2 data, including screen time limits, content filtering, activity approval workflows, and contact restrictions.

---

## 12. Training and Awareness

### 12.1 Verifier Training

All professional verifiers authorised to perform Tier 4 (child) verifications must:
- Complete child safety training before performing child verifications
- Understand the child protection laws in their jurisdiction
- Be aware of safeguarding indicators and reporting obligations
- Understand the user-enters-verifier-confirms ceremony flow and not attempt to enter data on behalf of users
- Refresh training annually

### 12.2 Personnel Training

All personnel involved in Protocol development, operations, or support must:
- Complete child safety awareness training
- Understand this Policy and their obligations under it
- Know how to report child safety concerns

---

## 13. Accountability

### 13.1 Designated Child Safety Officer

The Signet Protocol designates a Child Safety Officer responsible for:
- Overseeing implementation of this Policy
- Coordinating with the DPO on children's data protection matters
- Managing child safety incident response
- Engaging with child safety regulators and organisations

### 13.2 Record-Keeping

The Signet Protocol maintains records of:
- Child safety impact assessments
- Parental consent records
- Child safety incidents and responses
- Training records
- Policy reviews and updates

### 13.3 External Oversight

The Signet Protocol is committed to transparency and welcomes oversight from:
- Relevant regulatory authorities
- Child safety organisations
- Independent auditors
- The open-source community

---

## 14. Contact

For questions, concerns, or reports related to child safety:

**Child Safety Officer:** signet-safety@signetprotocol.org *(placeholder — update before deployment)*
**Data Protection Officer:** signet-dpo@signetprotocol.org *(placeholder — update before deployment)*

**Emergency Reporting (suspected child exploitation):**
- UK: Internet Watch Foundation — [https://www.iwf.org.uk](https://www.iwf.org.uk)
- US: NCMEC CyberTipline — [https://www.missingkids.org](https://www.missingkids.org)
- EU: INHOPE — [https://www.inhope.org](https://www.inhope.org)
- AU: eSafety Commissioner — [https://www.esafety.gov.au](https://www.esafety.gov.au)

---

*This Child Safety Policy is provided as a template for the Signet Protocol. It does not constitute legal advice. The Signet Protocol recommends seeking qualified legal counsel familiar with the applicable child protection laws in your jurisdiction before deployment.*

*The Signet Protocol — v0.1.0*
*Document Version: 1.0*
*March 2026*
