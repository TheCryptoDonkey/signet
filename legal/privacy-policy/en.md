# Privacy Policy

**Signet Protocol — Draft v0.1.0**

*Template — Seek qualified legal counsel for your jurisdiction before deployment.*

**Effective Date:** [DATE]
**Last Updated:** [DATE]

---

## 1. Introduction

This Privacy Policy describes how [ORGANIZATION NAME] ("we," "us," or "our") collects, uses, discloses, and protects information in connection with the Signet Protocol (the "Protocol"), a decentralised identity verification protocol for the Nostr network that utilises zero-knowledge proofs, ring signatures, and cryptographic credentials.

The Signet Protocol is designed with privacy at its core. It enables users to prove claims about their identity — such as age range, professional status, or geographic jurisdiction — without revealing the underlying personal data. This Privacy Policy explains what limited data interactions occur and how they are handled.

This Policy applies to all users, verifiers, relying parties, and other participants who interact with the Signet Protocol, regardless of location.

---

## 2. Data Controller

**Data Controller:** [ORGANIZATION NAME]
**Registered Address:** [ADDRESS]
**Contact Email:** [CONTACT EMAIL]
**Data Protection Officer (DPO):** [DPO EMAIL]

For jurisdictions requiring a local representative:

- **EU Representative (GDPR Art. 27):** [EU REPRESENTATIVE NAME AND ADDRESS]
- **UK Representative (UK GDPR Art. 27):** [UK REPRESENTATIVE NAME AND ADDRESS]
- **Brazil (LGPD):** [BRAZIL REPRESENTATIVE]
- **South Korea (PIPA):** [SOUTH KOREA REPRESENTATIVE]

---

## 3. Data We Collect and Process

The Signet Protocol is architected to minimise data collection. Because the Protocol uses zero-knowledge proofs, ring signatures, and decentralised credential verification, much of the information remains solely under the user's control and is never transmitted to or accessible by us.

### 3.1 Data Categories

| Category | Description | Source | Storage Location |
|----------|-------------|--------|-----------------|
| **Nostr Public Keys** | secp256k1 public keys (npub) used for Protocol interactions | User-generated | Nostr relays (decentralised) |
| **Credential Metadata** | Nostr event kinds 30470–30475 containing verification tier, issuance timestamps, expiry dates, and credential type identifiers | Generated during credential issuance | Nostr relays (decentralised) |
| **Zero-Knowledge Proofs** | Bulletproofs for age range verification; future ZK-SNARK/ZK-STARK proofs for other claims | Generated locally by user | Nostr relays (decentralised) |
| **Ring Signatures** | Cryptographic signatures that prove membership in a group without revealing which member signed | Generated locally by user | Nostr relays (decentralised) |
| **Verification Tier Data** | Tier level (1–4) indicating the strength of identity verification | Assigned during verification | Embedded in credential events |
| **Vouch Records** | Kind 30471 events representing web-of-trust endorsements | Created by vouching parties | Nostr relays (decentralised) |
| **Policy Events** | Kind 30472 events specifying relying party requirements | Created by relying parties | Nostr relays (decentralised) |
| **Verifier Registration** | Kind 30473 events identifying professional verifiers | Created by verifiers | Nostr relays (decentralised) |
| **Challenge/Response Data** | Kind 30474 events for interactive verification | Generated during verification | Nostr relays (decentralised) |
| **Revocation Records** | Kind 30475 events for credential revocation | Created when credentials are revoked | Nostr relays (decentralised) |
| **Nullifier Hashes** | SHA-256 hash of document type, country code, and document number — used to prevent duplicate identity creation | Computed during two-credential ceremony | Embedded in Natural Person credential events |
| **Merkle Roots** | Hash commitment to verified attributes (name, nationality, DOB) enabling selective disclosure | Computed during two-credential ceremony | Embedded in Natural Person credential events |
| **Entity Type Tags** | Classification of account type (Natural Person, Persona, etc.) | Set during credential issuance | Embedded in credential events |
| **Guardian Tags** | Parent/guardian public keys linked to child credentials | Set during child verification ceremony | Embedded in child credential events |
| **Identity Bridge Events** | Kind 30476 events linking Natural Person and Persona via ring signatures | Created by the user | Nostr relays (decentralised) |
| **Delegation Events** | Kind 30477 events for agent or guardian delegation | Created by the delegator | Nostr relays (decentralised) |

### 3.2 Data We Do NOT Collect

By design, the Signet Protocol does **not** collect, process, or store:

- Real names, addresses, or government identification numbers
- Biometric data
- Exact dates of birth (age range proofs reveal only that a user falls within a range)
- Document numbers or details (document details are used only to compute a one-way nullifier hash during the two-credential ceremony, then discarded by the verifier; only the hash is published)
- Merkle tree leaf values (the verified name, nationality, and DOB are stored as Merkle leaves known only to the subject and verifier; only the Merkle root hash is published on-chain)
- Financial information or payment data
- Location data or IP addresses (Protocol-level; relay operators may collect IP addresses independently)
- Browsing history or device fingerprints
- Email addresses (unless voluntarily provided for support)
- Photographs or images
- The underlying data behind any zero-knowledge proof

### 3.3 Data Processed by Third Parties

Nostr relay operators independently process data transmitted through their relays. Their data practices are governed by their own privacy policies. The Signet Protocol does not control relay operators.

---

## 4. Legal Bases for Processing

We process data under the following legal bases, depending on your jurisdiction:

### 4.1 European Union / European Economic Area (GDPR)

| Purpose | Legal Basis | GDPR Article |
|---------|-------------|--------------|
| Protocol operation and credential verification | Legitimate interest | Art. 6(1)(f) |
| Compliance with legal obligations | Legal obligation | Art. 6(1)(c) |
| User-initiated credential issuance | Performance of a contract | Art. 6(1)(b) |
| Child safety and age verification | Legitimate interest / Legal obligation | Art. 6(1)(f) / Art. 6(1)(c) |

### 4.2 United Kingdom (UK GDPR / Data Protection Act 2018)

The same legal bases as the EU GDPR apply, as supplemented by the Data Protection Act 2018 and the Age Appropriate Design Code (AADC).

### 4.3 United States (CCPA / CPRA / State Laws)

Under the California Consumer Privacy Act (CCPA) and California Privacy Rights Act (CPRA):

- We do **not** sell personal information.
- We do **not** share personal information for cross-context behavioural advertising.
- California residents have the right to know, delete, correct, and opt out.
- We comply with applicable state privacy laws including those of Virginia (VCDPA), Colorado (CPA), Connecticut (CTDPA), Utah (UCPA), and other states with enacted privacy legislation.

### 4.4 Brazil (LGPD — Lei Geral de Proteção de Dados)

Processing is based on:
- Legitimate interest (Art. 7, X)
- Compliance with legal or regulatory obligations (Art. 7, II)
- Execution of a contract or preliminary procedures (Art. 7, V)

### 4.5 South Korea (PIPA — Personal Information Protection Act)

Processing complies with PIPA requirements including:
- Collection limited to the minimum necessary
- Specific purpose limitation
- Notification of processing purposes
- Compliance with consent requirements

### 4.6 Japan (APPI — Act on the Protection of Personal Information)

Processing complies with the APPI as amended, including:
- Specification of utilisation purpose
- Proper acquisition of personal information
- Compliance with cross-border transfer requirements

### 4.7 China (PIPL — Personal Information Protection Law)

Where the Protocol is accessed from the People's Republic of China:
- Processing is based on individual consent or contract performance
- Data localisation requirements are respected
- Cross-border transfers comply with PIPL Art. 38–43

### 4.8 India (DPDP — Digital Personal Data Protection Act)

Processing complies with the DPDP Act, including:
- Processing based on consent or legitimate uses
- Obligations as a data fiduciary
- Rights of data principals

---

## 5. How We Use Data

Data processed through the Signet Protocol is used exclusively for:

1. **Credential Issuance and Verification** — Enabling users to create, present, and verify credentials across the four verification tiers.
2. **Trust Score Computation** — Calculating trust scores based on web-of-trust vouches, credential tiers, and verification history.
3. **Age Range Verification** — Using Bulletproofs to prove a user falls within an age range without revealing their exact age.
4. **Professional Verification** — Enabling licensed professionals (lawyers, notaries, medical professionals) to act as verifiers.
5. **Credential Revocation** — Processing revocation events when credentials are invalidated.
6. **Protocol Integrity** — Maintaining the cryptographic integrity and security of the Protocol.
7. **Legal Compliance** — Complying with applicable laws and regulations.
8. **Two-Credential Ceremony** — Issuing paired Natural Person and Persona credentials during professional verification, including computation of Merkle trees, nullifiers, and age-range proofs.
9. **Guardian Management** — Processing guardian delegation events (kind 30477) for child account management.
10. **Credential Lifecycle** — Processing credential chains (supersedes/superseded-by tags) for name changes, document renewal, and tier upgrades.

---

## 6. Data Sharing and Disclosure

### 6.1 Protocol-Level Sharing

The Signet Protocol operates on the Nostr network, which is decentralised. When you publish a credential event, vouch, or other Protocol event, it is broadcast to Nostr relays. This is inherent to the Protocol's design and is initiated by you.

### 6.2 We Do Not Share Data With

- Advertisers or marketing companies
- Data brokers
- Social media platforms (beyond Nostr relay publication)
- Government agencies (except as required by law or valid legal process)

### 6.3 Disclosure Required by Law

We may disclose information if required by:
- A valid court order, subpoena, or legal process
- Applicable law or regulation
- A request from a law enforcement or regulatory authority with valid jurisdiction

We will notify affected users of such requests where legally permitted.

### 6.4 Verifier Data Sharing

Professional verifiers (Tier 3 and Tier 4) publish verifier registration events (kind 30473) on the Nostr network. These events include the verifier's public key, professional credentials, and jurisdictional information. Verifiers consent to this publication as part of the Verifier Agreement.

The only data shared between the Verifier and the Protocol is the published credential event (kind 30470), which contains:
- The Verifier's public key (as the signing key)
- The subject's public key
- Credential metadata (tier, dates, type, entity type)
- The zero-knowledge age-range proof
- Nullifier hash (Natural Person credentials only — a one-way hash that cannot be reversed to document details)
- Merkle root (Natural Person credentials only — a hash commitment enabling selective attribute disclosure)
- Guardian pubkey tags (child credentials only)

No personal identification data (name, DOB, document numbers, nationality) is shared with or through the Protocol. These details remain private between the subject and the verifier, accessible only through Merkle proof selective disclosure initiated by the subject.

---

## 7. International Data Transfers

### 7.1 Decentralised Architecture

The Nostr network operates globally. When you publish events to Nostr relays, those events may be replicated to relays located anywhere in the world. This is a fundamental characteristic of the decentralised protocol.

### 7.2 Transfer Mechanisms

For any centralised processing we conduct, international data transfers are protected by:

- **EU/EEA:** Standard Contractual Clauses (SCCs) as approved by the European Commission (Decision 2021/914), supplemented by transfer impact assessments where required.
- **UK:** International Data Transfer Agreement (IDTA) or the UK Addendum to EU SCCs.
- **South Korea:** Compliance with PIPA cross-border transfer provisions.
- **Japan:** Transfers to countries with an adequate level of protection as recognised by the PPC, or with user consent.
- **China:** Security assessments, standard contracts, or certifications as required by PIPL.
- **Brazil:** Transfers compliant with LGPD Art. 33, including to countries with an adequate level of protection or with specific guarantees.

### 7.3 Adequacy Decisions

We rely on adequacy decisions where available, including the EU-US Data Privacy Framework, the UK Extension to the EU-US Data Privacy Framework, and Japan's adequacy finding by the European Commission.

---

## 8. Data Retention

### 8.1 Nostr Events

Events published to the Nostr network are retained by relay operators according to their own policies. Because the Nostr network is decentralised, we cannot guarantee the deletion of events from all relays.

### 8.2 Credential Lifecycle

| Data Type | Retention Period |
|-----------|-----------------|
| Active credentials | Until expiry or revocation |
| Revoked credentials | Revocation events are retained indefinitely for verification integrity |
| Expired credentials | Retained on relays per relay operator policies |
| Vouch records | Until revoked by the vouching party |
| Challenge/response data | Ephemeral; not retained after verification completes |

### 8.3 Centralised Records

Any records we maintain centrally (e.g., support correspondence, legal compliance records) are retained for:
- Support records: 2 years from last interaction
- Legal compliance records: As required by applicable law (typically 5–7 years)
- Audit logs: 3 years

---

## 9. Your Rights

### 9.1 Universal Rights

Regardless of your jurisdiction, you may:
- Request information about what data we process about you
- Request correction of inaccurate data
- Withdraw consent where processing is based on consent
- Lodge a complaint with us or a supervisory authority

### 9.2 European Union / EEA (GDPR)

Under the GDPR, you have the right to:
- **Access** (Art. 15) — Obtain a copy of your personal data
- **Rectification** (Art. 16) — Correct inaccurate data
- **Erasure** (Art. 17) — Request deletion ("right to be forgotten") where applicable
- **Restriction** (Art. 18) — Restrict processing in certain circumstances
- **Data Portability** (Art. 20) — Receive your data in a structured, machine-readable format
- **Object** (Art. 21) — Object to processing based on legitimate interest
- **Automated Decision-Making** (Art. 22) — Not be subject to solely automated decisions with legal effects

**Supervisory Authority:** You may lodge a complaint with your local data protection authority. A list of EU/EEA DPAs is available at [https://edpb.europa.eu/about-edpb/about-edpb/members_en](https://edpb.europa.eu/about-edpb/about-edpb/members_en).

### 9.3 United Kingdom (UK GDPR)

You have equivalent rights as under the EU GDPR. You may lodge a complaint with the Information Commissioner's Office (ICO) at [https://ico.org.uk](https://ico.org.uk).

### 9.4 United States (CCPA / CPRA)

California residents have the right to:
- **Know** — What personal information is collected, used, and disclosed
- **Delete** — Request deletion of personal information
- **Correct** — Request correction of inaccurate personal information
- **Opt-Out** — Opt out of the sale or sharing of personal information (we do not sell or share)
- **Non-Discrimination** — Not be discriminated against for exercising privacy rights

To exercise these rights, contact [CONTACT EMAIL] or submit a request through [PRIVACY RIGHTS URL].

Residents of Virginia, Colorado, Connecticut, Utah, and other states with privacy legislation have comparable rights under their respective laws.

### 9.5 Brazil (LGPD)

Data subjects have the right to:
- Confirmation of the existence of processing
- Access to data
- Correction of incomplete, inaccurate, or outdated data
- Anonymisation, blocking, or deletion of unnecessary or excessive data
- Data portability
- Deletion of data processed with consent
- Information about shared data
- Information about the possibility of denying consent and its consequences
- Revocation of consent

Contact the ANPD (Autoridade Nacional de Proteção de Dados) for complaints: [https://www.gov.br/anpd](https://www.gov.br/anpd).

### 9.6 South Korea (PIPA)

Data subjects have the right to:
- Request access to personal information
- Request correction or deletion
- Request suspension of processing
- File a complaint with the Personal Information Protection Commission (PIPC)

### 9.7 Japan (APPI)

Data subjects have the right to:
- Request disclosure of retained personal data
- Request correction, addition, or deletion
- Request cessation of use or provision to third parties
- File a complaint with the Personal Information Protection Commission (PPC)

### 9.8 China (PIPL)

Data subjects have the right to:
- Know and decide on processing of personal information
- Restrict or refuse processing
- Access and copy personal information
- Request portability
- Request correction and deletion
- Request explanation of processing rules

### 9.9 India (DPDP Act)

Data principals have the right to:
- Access information about processing
- Correction and erasure of personal data
- Grievance redressal
- Nominate another person to exercise rights

### 9.10 Exercising Your Rights

To exercise any of the above rights, contact us at:
- **Email:** [CONTACT EMAIL]
- **DPO Email:** [DPO EMAIL]

We will respond within the time frames required by applicable law:
- GDPR/UK GDPR: 30 days (extendable by 60 days for complex requests)
- CCPA/CPRA: 45 days (extendable by 45 days)
- LGPD: 15 days
- PIPA: 10 days
- APPI: Without delay
- PIPL: Promptly

---

## 10. Children's Data

### 10.1 General Policy

The Signet Protocol includes Tier 4 (Professional Verification — Adult + Child), which is specifically designed for child safety. We take the protection of children's data extremely seriously.

### 10.2 Age Verification

The Protocol uses Bulletproofs-based zero-knowledge proofs for age range verification. These proofs demonstrate that a user is within a given age range (e.g., over 13, over 16, over 18) without revealing their exact date of birth.

### 10.3 Jurisdiction-Specific Age Requirements

| Jurisdiction | Minimum Age for Digital Consent | Governing Law |
|-------------|-------------------------------|---------------|
| EU (default) | 16 years | GDPR Art. 8 |
| EU (member state option) | 13–16 years (varies) | GDPR Art. 8(1) |
| United Kingdom | 13 years | UK GDPR / AADC |
| United States | 13 years | COPPA |
| Brazil | 12 years (with parental consent below 18) | LGPD Art. 14 |
| South Korea | 14 years | PIPA |
| Japan | 15 years (guidelines) | APPI |
| China | 14 years | PIPL Art. 28 |
| India | 18 years (with exceptions) | DPDP Act |

### 10.4 Parental Consent

Where parental consent is required, the Protocol supports:
- Verifiable parental consent through Tier 3 or Tier 4 verified parent/guardian credentials
- Age-gating through ZK proof verification at the relying party level
- Mechanisms for parents to review, modify, or revoke consent

### 10.5 COPPA Compliance (United States)

We comply with the Children's Online Privacy Protection Act (COPPA). We do not knowingly collect personal information from children under 13 without verifiable parental consent.

### 10.6 Age Appropriate Design Code (United Kingdom)

We are committed to the principles of the UK Age Appropriate Design Code (AADC), including:
- Best interests of the child assessment
- Age-appropriate application
- Data minimisation
- Default settings protective of children
- Transparency appropriate to the child's age

For our full Child Safety Policy, see [LINK TO CHILD SAFETY POLICY].

---

## 11. Security

### 11.1 Cryptographic Security

The Signet Protocol employs:
- **Schnorr signatures** on the secp256k1 curve for all credential signing
- **Bulletproofs** for zero-knowledge age range proofs
- **Ring signatures** for anonymous group membership proofs
- **Future ZK layer** planned for additional proof types (ZK-SNARKs/ZK-STARKs)

### 11.2 Organisational Security

We implement:
- Access controls and least-privilege principles
- Encryption in transit (TLS 1.2+) for any centralised services
- Regular security assessments and penetration testing
- Incident response procedures
- Staff training on data protection
- Secure development practices

### 11.3 Decentralised Security Model

The Protocol's decentralised architecture provides inherent security benefits:
- No single point of failure
- No centralised database to breach
- User-controlled key management
- Cryptographic verification without trusted intermediaries

### 11.4 Breach Notification

In the event of a personal data breach affecting our centralised systems, we will:
- Notify the relevant supervisory authority within 72 hours (GDPR) or as required by applicable law
- Notify affected individuals without undue delay where the breach is likely to result in a high risk to their rights and freedoms
- Document the breach, its effects, and remedial actions

---

## 12. Cookies and Tracking Technologies

The Signet Protocol does **not** use:
- Cookies
- Web beacons or tracking pixels
- Browser fingerprinting
- Local storage for tracking purposes
- Any third-party analytics or tracking services

If ancillary services (such as a documentation website) use cookies, a separate cookie notice will be provided with appropriate consent mechanisms.

---

## 13. Automated Decision-Making and Profiling

### 13.1 Trust Score Computation

The Protocol computes trust scores based on:
- Verification tier level (1–4)
- Number and quality of vouches
- Verifier credentials and standing
- Credential age and history

These trust scores are computed algorithmically and are visible to relying parties. They do not constitute automated decision-making with legal effects under GDPR Art. 22, as they are one input among many that relying parties may consider.

### 13.2 No Profiling for Marketing

We do not engage in profiling for marketing, advertising, or behavioural analysis purposes.

---

## 14. Third-Party Links and Services

The Signet Protocol may interoperate with:
- Nostr relays (operated independently)
- Nostr clients (such as Fathom, the reference implementation)
- Professional bodies and regulatory registries

These third parties have their own privacy policies. We are not responsible for their data practices.

---

## 15. Changes to This Privacy Policy

We may update this Privacy Policy from time to time. Changes will be indicated by updating the "Last Updated" date at the top of this document. For material changes, we will provide notice through:
- A Nostr event announcement
- An update to the Protocol specification repository
- Direct notification where feasible

Your continued use of the Protocol after changes constitutes acceptance of the updated Privacy Policy.

---

## 16. Jurisdiction-Specific Provisions

### 16.1 European Union — Additional Provisions

Where we process personal data under the GDPR, the provisions of the GDPR take precedence over any conflicting provisions in this Privacy Policy.

### 16.2 California — Additional Provisions

**Do Not Sell or Share My Personal Information:** We do not sell or share personal information as defined under the CCPA/CPRA.

**Financial Incentives:** We do not offer financial incentives related to the collection of personal information.

**Shine the Light (Cal. Civ. Code Section 1798.83):** California residents may request information about disclosures of personal information to third parties for direct marketing. We do not make such disclosures.

### 16.3 Brazil — Additional Provisions

The DPO (Encarregado) may be contacted at [DPO EMAIL] for all LGPD-related inquiries.

### 16.4 Australia — Additional Provisions

We comply with the Australian Privacy Principles (APPs) under the Privacy Act 1988 (Cth). You may lodge a complaint with the Office of the Australian Information Commissioner (OAIC).

### 16.5 New Zealand — Additional Provisions

We comply with the Privacy Act 2020 (NZ). You may lodge a complaint with the Office of the Privacy Commissioner.

### 16.6 Singapore — Additional Provisions

We comply with the Personal Data Protection Act 2012 (PDPA). You may contact the Personal Data Protection Commission (PDPC) for complaints.

### 16.7 South Africa — Additional Provisions

We comply with the Protection of Personal Information Act 2013 (POPIA). You may lodge a complaint with the Information Regulator.

---

## 17. Contact Us

For any questions, concerns, or requests related to this Privacy Policy or our data practices:

**General Inquiries:**
[ORGANIZATION NAME]
Email: [CONTACT EMAIL]

**Data Protection Officer:**
Email: [DPO EMAIL]

**Mailing Address:**
[ORGANIZATION NAME]
[ADDRESS]

---

## 18. Regulatory Filings

Depending on jurisdiction, we maintain registrations or filings with:
- The Information Commissioner's Office (UK) — Registration No. [ICO REGISTRATION NUMBER]
- Applicable EU/EEA data protection authorities
- Other regulatory bodies as required by law

---

*This Privacy Policy is provided as a template for the Signet Protocol. It does not constitute legal advice. [ORGANIZATION NAME] recommends seeking qualified legal counsel familiar with the applicable data protection laws in your jurisdiction before deployment.*

*Signet Protocol — Draft v0.1.0*
*Document Version: 1.0*
