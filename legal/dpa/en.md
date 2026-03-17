# Data Processing Agreement

**The Signet Protocol — v0.1.0**

*Template — Seek qualified legal counsel for your jurisdiction before deployment.*

**Effective Date:** March 2026
**Last Updated:** March 2026

---

## Preamble

This Data Processing Agreement ("DPA") is entered into between:

**Data Controller:**
[CONTROLLER ORGANIZATION NAME] ("Controller")
Address: [CONTROLLER ADDRESS]
Contact: [CONTROLLER CONTACT EMAIL]

**Data Processor:**
The Signet Protocol ("Processor")
Contact: signet-dpo@signetprotocol.org *(placeholder — update before deployment)*
DPO: signet-dpo@signetprotocol.org *(placeholder — update before deployment)*

(each a "Party" and together the "Parties")

This DPA supplements and forms part of the underlying service agreement or terms of service (the "Principal Agreement") between the Parties relating to the Signet Protocol (the "Protocol").

This DPA is entered into in compliance with Article 28 of the General Data Protection Regulation (EU) 2016/679 ("GDPR"), the UK General Data Protection Regulation ("UK GDPR"), and other applicable data protection legislation.

---

## 1. Definitions

**1.1** "Applicable Data Protection Law" means all laws and regulations relating to the processing of personal data that apply to the processing activities under this DPA, including but not limited to: the GDPR, UK GDPR, LGPD (Brazil), PIPA (South Korea), APPI (Japan), PIPL (China), DPDP Act (India), and their implementing regulations.

**1.2** "Data Subject" means an identified or identifiable natural person whose personal data is processed under this DPA.

**1.3** "Personal Data" means any information relating to a Data Subject, as defined in the Applicable Data Protection Law. In the context of the Protocol, this includes Nostr public keys, credential metadata, verification tier data, and any other data that can be attributed to an identifiable individual.

**1.4** "Processing" means any operation or set of operations performed on Personal Data, whether or not by automated means, including collection, recording, organisation, structuring, storage, adaptation, alteration, retrieval, consultation, use, disclosure by transmission, dissemination, alignment, combination, restriction, erasure, or destruction.

**1.5** "Sub-processor" means any third party engaged by the Processor to process Personal Data on behalf of the Controller.

**1.6** "Security Incident" or "Personal Data Breach" means a breach of security leading to the accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, Personal Data.

**1.7** "Standard Contractual Clauses" or "SCCs" means the standard contractual clauses for the transfer of personal data to processors established in third countries, as adopted by the European Commission (Decision 2021/914).

**1.8** "Technical and Organisational Measures" means the security measures described in Annex II to this DPA.

---

## 2. Scope of Processing

### 2.1 Subject Matter

The Processor processes Personal Data on behalf of the Controller in connection with the provision of services related to the Signet Protocol, as further described in Annex I.

### 2.2 Nature and Purpose of Processing

| Processing Activity | Purpose |
|---------------------|---------|
| Credential issuance support | Facilitating the creation and signing of Signet credentials (kind 30470) |
| Verification processing | Supporting identity verification processes across Tiers 1–4 |
| Signet IQ computation | Computing and updating Signet IQ scores based on vouches and credentials |
| Revocation processing | Processing and propagating credential revocations (kind 30475) |
| Challenge/response facilitation | Processing verifier legitimacy challenges (kind 30474) |
| Professional register checking | Automated verification bot checks that professional verifiers appear on applicable public registers (bar associations, medical boards, notary commissions) |
| Biometric unlock facilitation | Device-local WebAuthn biometric authentication to protect user accounts; no biometric data transmitted or stored by the Processor |
| SDK verification flow | Routing age-range proof requests from relying party websites through the My Signet app; only ZK proofs are transmitted — no PII |
| Audit and compliance | Maintaining logs and records for regulatory compliance |

### 2.3 Categories of Data Subjects

- Protocol users (individuals holding or seeking credentials)
- Professional verifiers (licensed professionals performing verifications)
- Vouching parties (individuals providing Tier 2 vouches)
- Relying parties (organisations or individuals consuming credentials)

### 2.4 Types of Personal Data

- Nostr public keys (npub / secp256k1 public keys)
- Credential metadata (tier level, issuance date, expiry date, credential type)
- Zero-knowledge proof outputs (Bulletproofs, ring signatures)
- Verification event data (kinds 30470–30477)
- Verifier registration data (professional credentials, jurisdiction)
- Signet IQ scores and vouch records
- Nullifier hashes (computed using `signet-nullifier-v2` formula; one-way hash of document details; cannot be reversed)
- Merkle roots (cryptographic commitments to credential attributes; leaves are private and not transmitted to the Processor)
- Timestamps and event identifiers

**Personal data not processed by the Processor:** Full names, dates of birth, document numbers, document types, nationalities, photographs, and other raw identity document details are entered by the user on their own device. These details are used locally to compute nullifier hashes and Merkle trees. The raw details are not transmitted to the Processor and are not stored in any system under the Processor's control.

### 2.5 Duration of Processing

Processing shall continue for the duration of the Principal Agreement, plus any retention period specified in Annex I or required by Applicable Data Protection Law.

---

## 3. Processor Obligations

### 3.1 Lawful Processing

The Processor shall:
1. Process Personal Data only on documented instructions from the Controller, including with regard to transfers to a third country or international organisation, unless required to do so by applicable law — in which case, the Processor shall inform the Controller of that legal requirement before processing, unless the law prohibits such information on important grounds of public interest.
2. Immediately inform the Controller if, in the Processor's opinion, an instruction infringes Applicable Data Protection Law.

### 3.2 Confidentiality

The Processor shall ensure that persons authorised to process Personal Data:
1. Have committed themselves to confidentiality or are under an appropriate statutory obligation of confidentiality.
2. Process Personal Data only on instructions from the Controller, unless required by applicable law.

### 3.3 Purpose Limitation

The Processor shall process Personal Data solely for the purposes specified in this DPA and shall not process Personal Data for any other purpose, including for the Processor's own purposes.

### 3.4 Data Minimisation

The Processor shall ensure that Personal Data processed is adequate, relevant, and limited to what is necessary in relation to the purposes for which it is processed.

### 3.5 Accuracy

The Processor shall take reasonable steps to ensure that Personal Data is accurate and, where necessary, kept up to date, having regard to the purposes of processing.

### 3.6 Cooperation

The Processor shall:
1. Assist the Controller in responding to Data Subject requests (see Section 8).
2. Assist the Controller in ensuring compliance with its obligations regarding security, breach notification, data protection impact assessments, and prior consultation with supervisory authorities.
3. Make available to the Controller all information necessary to demonstrate compliance with this DPA and Applicable Data Protection Law.

---

## 4. Security Measures

### 4.1 General Obligation

The Processor shall implement and maintain appropriate technical and organisational measures to ensure a level of security appropriate to the risk, as described in Annex II. These measures shall include, as appropriate:

1. **Encryption:**
   - All data in transit encrypted using TLS 1.2 or higher
   - All credential data and private keys stored at rest using AES-256-GCM authenticated encryption
   - Key derivation for stored secrets uses PBKDF2-SHA512 with 600,000 iterations (OWASP 2023 recommended minimum)
   - Cryptographic key management in accordance with industry best practices

2. **Pseudonymisation:**
   - Use of Nostr public keys as pseudonymous identifiers
   - Separation of identifier data from credential content
   - Zero-knowledge proofs to avoid processing underlying personal data

3. **Confidentiality:**
   - Role-based access controls with least-privilege principles
   - Multi-factor authentication for administrative access
   - Background checks for personnel with access to Personal Data

4. **Integrity:**
   - Cryptographic verification of all credential events using Schnorr signatures (secp256k1)
   - Merkle tree integrity via RFC 6962 domain separation (0x00 leaf prefix, 0x01 internal node prefix)
   - Tamper-evident audit logs
   - Input validation and data integrity checks including field-size bounds (64KB content limit, 100 tags limit, 1024 character tag value limit)

5. **Availability:**
   - Redundant systems and failover capabilities
   - Regular backups with tested restoration procedures
   - Disaster recovery plan with documented Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)

6. **Resilience:**
   - Regular security assessments and penetration testing (at least annually)
   - Vulnerability management programme
   - Incident response plan with defined roles and procedures

### 4.2 Signet-Specific Security Measures

Given the Protocol's cryptographic nature, the Processor additionally implements:

1. **Cryptographic Security:**
   - Secure implementation of Schnorr signatures (secp256k1)
   - Secure implementation of Bulletproofs for age range proofs
   - Secure implementation of ring signatures (SAG and LSAG) with domain separators (`signet-sag-v1`, `signet-lsag-v1`) and ring size cap of 1,000
   - ECDH identity point rejection (shared point checked against the curve identity element before use)
   - Regular review of cryptographic library dependencies
   - Monitoring of cryptographic vulnerability disclosures

2. **Protocol-Level Security:**
   - Validation of all Nostr event signatures before processing
   - Verification of credential chain integrity with cycle detection and depth cap (100 hops)
   - Detection of anomalous credential or vouch patterns
   - Protection against replay attacks
   - `parseInt` safety: all tag values parsed as integers are checked with `isNaN()` before security comparisons

3. **Key Management:**
   - Hardware Security Modules (HSMs) for critical signing keys
   - Key rotation policies
   - Secure key generation procedures
   - Emergency key revocation procedures
   - Private keys and mnemonics stored in encrypted IndexedDB using `crypto-store.ts` (PBKDF2 + AES-256-GCM); never stored in plaintext

4. **Biometric Processing:**
   - Device biometric authentication (face recognition, fingerprint) is handled exclusively by the device's secure enclave via the WebAuthn standard
   - The WebAuthn PRF extension is used for key derivation where supported; no biometric templates are created, transmitted, or stored outside the user's device
   - The Processor receives no biometric data whatsoever — the entire biometric flow is device-local

### 4.3 Review and Update

The Processor shall regularly review and update its security measures to address evolving threats and vulnerabilities. The Processor shall not reduce the overall level of security without the Controller's prior written consent.

---

## 5. Sub-processors

### 5.1 General Authorisation

The Controller grants the Processor general written authorisation to engage Sub-processors, subject to the requirements of this Section 5.

### 5.2 Current Sub-processors

The current list of Sub-processors is set out in Annex III. The Processor shall maintain an up-to-date list and make it available to the Controller upon request.

### 5.3 Notification of Changes

The Processor shall:
1. Notify the Controller in writing at least 30 days before engaging a new Sub-processor or replacing an existing Sub-processor.
2. Provide sufficient information about the new Sub-processor to enable the Controller to exercise its right to object.

### 5.4 Right to Object

The Controller may object to a new Sub-processor on reasonable grounds relating to data protection within 14 days of notification. If the Controller objects:
1. The Processor shall work with the Controller to find a mutually acceptable solution.
2. If no solution is found within 30 days, the Controller may terminate the affected processing activities.

### 5.5 Sub-processor Obligations

The Processor shall:
1. Impose the same data protection obligations on each Sub-processor as set out in this DPA through a written contract.
2. Remain fully liable to the Controller for the performance of each Sub-processor's obligations.
3. Conduct due diligence on each Sub-processor's ability to meet its obligations.

---

## 6. International Data Transfers

### 6.1 General Restriction

The Processor shall not transfer Personal Data to a country outside the European Economic Area (EEA), the United Kingdom, or any other jurisdiction with applicable data transfer restrictions, unless one of the following safeguards is in place:

1. The European Commission (or relevant authority) has issued an adequacy decision for the recipient country.
2. Standard Contractual Clauses (SCCs) have been executed between the relevant parties.
3. Binding Corporate Rules approved by the competent supervisory authority apply.
4. An appropriate derogation under Article 49 GDPR (or equivalent) applies.

### 6.2 Standard Contractual Clauses

Where SCCs are required, the Parties agree that:
- Module Two (Controller to Processor) SCCs, as adopted by Commission Implementing Decision (EU) 2021/914, shall apply.
- The optional clauses in Clause 7 (docking clause) are included.
- Under Clause 9, Option 2 (general written authorisation) applies, with a notice period of 30 days.
- Under Clause 11, the optional language is not included.
- Under Clause 17, Option 1 applies, with the governing law being that of [SCC GOVERNING LAW JURISDICTION].
- Under Clause 18(b), disputes shall be resolved before the courts of [SCC FORUM JURISDICTION].

The SCCs are incorporated by reference and form part of this DPA. In the event of a conflict between this DPA and the SCCs, the SCCs shall prevail.

### 6.3 UK International Data Transfer Agreement

For transfers subject to UK GDPR, the Parties shall enter into the UK International Data Transfer Agreement (IDTA) or the UK Addendum to the EU SCCs, as appropriate.

### 6.4 Transfer Impact Assessments

The Processor shall:
1. Conduct and document a transfer impact assessment for each international transfer.
2. Implement supplementary measures where necessary to ensure an essentially equivalent level of protection.
3. Suspend the transfer if supplementary measures cannot ensure adequate protection.

### 6.5 Nostr Network Transfers and Relay Operators

The Parties acknowledge that the Nostr network is decentralised and operates globally. Events published to Nostr relays may be replicated to relays located in any jurisdiction.

**Nature of data on Nostr relays:** Signet credentials published to Nostr relays contain no personal data in the ordinary meaning of the term. Credentials consist of:
- Nostr public keys (pseudonymous identifiers)
- ZK proof outputs (mathematical proofs that reveal no underlying personal data)
- Nullifier hashes (one-way hashes computed using `signet-nullifier-v2`; cannot be reversed to document details)
- Merkle roots (cryptographic commitments; leaves are private and never published)
- Metadata (tier, dates, entity type)

Relay operators store and transmit public events. They do not store personal data as defined under GDPR because the published credential events contain no information from which an individual can be identified without access to private Merkle leaves (which are never published). Relay operators are therefore processors of pseudonymous public protocol data rather than processors of personal data in the GDPR sense.

**Notwithstanding the above**, the Processor shall implement appropriate measures to minimise any residual data exposure, including:
- Using zero-knowledge proofs to avoid publishing underlying personal data
- Encrypting sensitive metadata where possible
- Limiting the personal data content of published events to the minimum necessary

---

## 7. Audit Rights

### 7.1 Audit and Inspection

The Controller has the right to:
1. Audit the Processor's compliance with this DPA.
2. Inspect the Processor's facilities, systems, and records related to the processing of Personal Data.
3. Request and receive reports on the Processor's data protection compliance.

### 7.2 Audit Procedure

Audits shall be conducted:
1. Upon reasonable notice (at least 30 days, except in case of a suspected breach).
2. During normal business hours.
3. In a manner that minimises disruption to the Processor's operations.
4. Subject to reasonable confidentiality obligations.

### 7.3 Third-Party Audits

The Controller may:
1. Appoint a qualified, independent third-party auditor to conduct audits.
2. Accept the Processor's existing third-party audit reports (e.g., SOC 2 Type II, ISO 27001) as evidence of compliance, provided they are sufficiently current and comprehensive.

### 7.4 Remediation

If an audit reveals non-compliance:
1. The Processor shall promptly address the identified issues.
2. The Processor shall provide a remediation plan within 14 days.
3. The Controller may conduct a follow-up audit to verify remediation.

### 7.5 Costs

Each Party shall bear its own costs related to audits, unless the audit reveals material non-compliance by the Processor, in which case the Processor shall bear the reasonable costs of the audit.

---

## 8. Data Subject Rights

### 8.1 Assistance Obligation

The Processor shall assist the Controller in fulfilling its obligations to respond to Data Subject requests exercising their rights under Applicable Data Protection Law, including:

- Right of access
- Right to rectification
- Right to erasure ("right to be forgotten")
- Right to restriction of processing
- Right to data portability
- Right to object
- Rights related to automated decision-making and profiling
- Right to withdraw consent
- Right to lodge a complaint with a supervisory authority

### 8.2 Notification of Requests

The Processor shall:
1. Promptly (and in any event within 2 business days) notify the Controller of any Data Subject request received directly.
2. Not respond to Data Subject requests directly unless authorised by the Controller.
3. Provide the Controller with all information necessary to respond to the request.

### 8.3 Signet-Specific Considerations

The decentralised nature of the Protocol presents unique considerations for Data Subject rights:

1. **Right to Erasure:** The Processor can delete data from systems under its control but cannot delete events published to Nostr relays. The Processor shall assist the Controller in publishing revocation events (kind 30475) and requesting deletion from known relay operators. Because published credential events contain no raw personal data (only hashes and ZK proofs), the practical privacy impact of relay retention is minimal — but revocation ensures credentials are no longer accepted by the Protocol.

2. **Right to Portability:** Credential data is inherently portable through the Nostr protocol. The Processor shall provide data in a structured, commonly used, machine-readable format upon request.

3. **Right to Rectification:** Credentials cannot be modified once published. Rectification is achieved by revoking the incorrect credential and issuing a new, corrected credential.

---

## 9. Personal Data Breach Notification

### 9.1 Notification to Controller

The Processor shall:
1. Notify the Controller of any Personal Data Breach without undue delay, and in any event within **24 hours** of becoming aware of the breach.
2. Provide the following information (to the extent known at the time of notification):
   - Description of the nature of the breach, including categories and approximate number of Data Subjects and records affected
   - Name and contact details of the Processor's DPO or other contact point
   - Description of the likely consequences of the breach
   - Description of measures taken or proposed to address the breach, including measures to mitigate its possible adverse effects

### 9.2 Ongoing Updates

The Processor shall:
1. Provide supplementary information as it becomes available.
2. Provide updates at intervals agreed with the Controller.
3. Maintain a complete record of the breach, its effects, and remedial actions.

### 9.3 Assistance

The Processor shall assist the Controller in:
1. Notifying the competent supervisory authority (within 72 hours under GDPR).
2. Notifying affected Data Subjects where required.
3. Conducting any investigation or risk assessment related to the breach.
4. Implementing measures to prevent recurrence.

### 9.4 Signet-Specific Breach Scenarios

The following events constitute breaches requiring notification:

| Scenario | Severity | Notification Priority |
|----------|----------|----------------------|
| Compromise of verifier signing keys | Critical | Immediate |
| Unauthorised issuance of Tier 3/4 credentials | Critical | Immediate |
| Breach of ring signature anonymity | High | Within 24 hours |
| Unauthorised access to credential processing systems | High | Within 24 hours |
| Disclosure of mapping between public keys and real identities | Critical | Immediate |
| Compromise of Bulletproof age range proofs | High | Within 24 hours |
| Mass credential revocation due to security incident | Medium | Within 24 hours |
| Compromise of professional register verification bot | High | Within 24 hours |

---

## 10. Return and Deletion of Data

### 10.1 Upon Termination

Upon termination or expiry of the Principal Agreement, the Processor shall, at the Controller's choice:

**Option A — Return:**
- Return all Personal Data to the Controller in a structured, commonly used, machine-readable format.
- Certify in writing that all copies have been returned.

**Option B — Deletion:**
- Securely delete all Personal Data from the Processor's systems.
- Certify in writing that all copies have been deleted.

### 10.2 Retention Exceptions

The Processor may retain Personal Data only to the extent required by Applicable Data Protection Law, and only for the period and purposes required by such law. The Processor shall:
1. Inform the Controller of any such retention requirement.
2. Ensure the retained data remains subject to this DPA.
3. Delete the retained data when the retention requirement expires.

### 10.3 Deletion Standard

Deletion shall be performed using methods that render the data irrecoverable, including:
- Cryptographic erasure (destruction of encryption keys) — particularly appropriate given the AES-256-GCM encrypted storage model
- Secure overwriting in accordance with NIST SP 800-88 or equivalent
- Physical destruction of storage media where applicable

### 10.4 Nostr Network Data

The Parties acknowledge that events published to the Nostr network cannot be deleted by the Processor. The Processor shall:
1. Publish revocation events (kind 30475) for any credentials that should be invalidated.
2. Request deletion from known relay operators where feasible.
3. Ensure that published events contain the minimum Personal Data necessary.

### 10.5 Timeline

Return or deletion shall be completed within 30 days of the termination or expiry of the Principal Agreement, unless a longer period is agreed in writing or required by law.

---

## 11. Liability

### 11.1 Allocation of Liability

Each Party's liability under this DPA is subject to the limitations and exclusions of liability set out in the Principal Agreement, except that:
1. Neither Party's liability for breaches of Applicable Data Protection Law shall be limited where such limitation is prohibited by law.
2. The Processor's liability for breaches caused by its Sub-processors is not limited by this DPA.

### 11.2 Indemnification

The Processor shall indemnify the Controller against all claims, damages, losses, costs, and expenses (including reasonable legal fees) arising from the Processor's breach of this DPA or Applicable Data Protection Law.

---

## 12. Term and Termination

### 12.1 Term

This DPA shall remain in effect for the duration of the Principal Agreement and for as long as the Processor processes Personal Data on behalf of the Controller.

### 12.2 Termination for Breach

Either Party may terminate this DPA if the other Party materially breaches this DPA and fails to remedy the breach within 30 days of written notice.

### 12.3 Survival

Sections 4, 7, 8, 9, 10, and 11 shall survive the termination or expiry of this DPA.

---

## 13. Miscellaneous

### 13.1 Governing Law

This DPA shall be governed by the laws of [GOVERNING LAW JURISDICTION], without regard to its conflict of law provisions.

### 13.2 Order of Precedence

In the event of a conflict between this DPA and the Principal Agreement:
1. Applicable Data Protection Law takes precedence.
2. The Standard Contractual Clauses (if applicable) take precedence.
3. This DPA takes precedence.
4. The Principal Agreement applies to all other matters.

### 13.3 Amendments

This DPA may only be amended in writing signed by both Parties.

### 13.4 Severability

If any provision of this DPA is found to be invalid or unenforceable, the remaining provisions shall remain in full force and effect.

---

## Annex I — Details of Processing

| Item | Description |
|------|-------------|
| **Subject matter of processing** | Processing of Personal Data in connection with the Signet Protocol for identity verification on the Nostr network |
| **Duration of processing** | Duration of the Principal Agreement plus any legally required retention periods |
| **Nature of processing** | Credential issuance, verification, trust computation, revocation processing, professional register checking, SDK proof routing, audit logging |
| **Purpose of processing** | Enabling decentralised identity verification using zero-knowledge proofs and tiered trust |
| **Categories of Data Subjects** | Protocol users, professional verifiers, vouching parties, relying parties |
| **Types of Personal Data** | Nostr public keys, credential metadata, ZK proof outputs, verification events, nullifier hashes, Merkle roots, Signet IQ scores, timestamps |
| **Sensitive data (if any)** | Age range data (processed via ZK proofs only; no raw DOB transmitted); professional credentials of verifiers |
| **Ceremony data flow** | User enters document details on their own device; verifier confirms accuracy of physical documents; raw document details are not transmitted to or stored by the Processor |
| **SDK data flow** | Website → Signet SDK → My Signet app → ZK age-range proof → Website; no PII transmitted at any stage |
| **Biometric data** | Device-local only (WebAuthn); not transmitted to or stored by the Processor |
| **Frequency of transfers** | Continuous, as Protocol events are published |
| **Retention period** | Active credentials until expiry/revocation; audit logs for 3 years; legal compliance records as required by law |

---

## Annex II — Technical and Organisational Measures

### A. Encryption and Pseudonymisation

| Measure | Implementation |
|---------|---------------|
| Encryption in transit | TLS 1.2+ for all communications |
| Encryption at rest | AES-256-GCM authenticated encryption for all stored credential data and private keys |
| Key derivation | PBKDF2-SHA512 with 600,000 iterations for password-derived keys |
| WebAuthn PRF extension | Used for key derivation from biometric unlock where the device supports it |
| Key management | HSM-backed key storage; regular key rotation |
| Pseudonymisation | Nostr public keys as primary identifiers; ZK proofs to prevent data exposure |
| Nullifier format | `signet-nullifier-v2` — SHA-256 of length-prefixed fields; one-way, cannot be reversed |
| Merkle trees | RFC 6962 domain separation (0x00 leaf, 0x01 internal node); private leaves never published |

### B. Access Controls

| Measure | Implementation |
|---------|---------------|
| Authentication | Multi-factor authentication for all administrative access |
| Biometric device unlock | WebAuthn (device-local only); no biometric templates transmitted |
| Authorisation | Role-based access control with least-privilege principles |
| Logging | Comprehensive audit logging of all access and modifications |
| Review | Quarterly access reviews; prompt revocation upon role change |

### C. Physical Security

| Measure | Implementation |
|---------|---------------|
| Data centre security | Tier III+ facilities with 24/7 monitoring |
| Access control | Biometric and badge-based access to server areas |
| Environmental controls | Fire suppression, climate control, redundant power |

### D. Availability and Resilience

| Measure | Implementation |
|---------|---------------|
| Redundancy | Geographic redundancy across multiple availability zones |
| Backups | Daily encrypted backups; tested monthly |
| Disaster recovery | RTO: [RTO HOURS] hours; RPO: [RPO HOURS] hours |
| Business continuity | Documented BCP; tested annually |

### E. Incident Response

| Measure | Implementation |
|---------|---------------|
| Incident response plan | Documented; roles assigned; tested quarterly |
| Breach notification | Automated alerting; 24-hour SLA for Controller notification |
| Forensics | Forensic investigation capability; evidence preservation procedures |
| Post-incident review | Root cause analysis within 14 days of incident resolution |

### F. Organisational Measures

| Measure | Implementation |
|---------|---------------|
| Staff training | Annual data protection training; role-specific training |
| Confidentiality | Confidentiality agreements for all staff |
| DPO | Designated DPO at signet-dpo@signetprotocol.org *(placeholder)* |
| DPIA | Data Protection Impact Assessments for high-risk processing |
| Vendor management | Due diligence and contractual obligations for all Sub-processors |

---

## Annex III — List of Sub-processors

| Sub-processor | Processing Activity | Location | Safeguard |
|---------------|---------------------|----------|-----------|
| Signet Verification Bot | Automated open-source bot that checks professional verifiers against public professional registers (bar associations, medical boards, notary commissions). Processes verifier licence numbers and public register data only. No credential holder personal data is processed. Source code is publicly auditable. | [HOSTING JURISDICTION] | [SCCs / Adequacy / Other] |
| Nostr Relay Operators | Store and transmit public Nostr events (kinds 30470–30477). Published events contain only ZK proofs, nullifier hashes, Merkle roots, and public keys — no raw personal data. Relay operators are processors of pseudonymous public protocol data. | Various (global, decentralised) | Relay operators are selected from jurisdictions with adequate protections where feasible; events minimise personal data per §6.5 |
| [INFRASTRUCTURE PROVIDER] | Hosting, compute, and storage for Protocol services | [COUNTRY] | [SCCs / Adequacy / Other] |

*Update this annex as Sub-processors are added or removed.*

---

## Annex IV — International Transfer Mechanisms

| Transfer | From | To | Mechanism |
|----------|------|-----|-----------|
| [TRANSFER 1] | [ORIGIN] | [DESTINATION] | SCCs (Module 2) |
| [TRANSFER 2] | [ORIGIN] | [DESTINATION] | Adequacy Decision |
| [TRANSFER 3] | [ORIGIN] | [DESTINATION] | [MECHANISM] |

---

## Signatures

**Data Controller:**

Name: ____________________________
Title: ____________________________
Date: ____________________________
Signature: ________________________

**Data Processor:**

Name: ____________________________
Title: ____________________________
Date: ____________________________
Signature: ________________________

---

*This Data Processing Agreement is provided as a template for the Signet Protocol. It does not constitute legal advice. The Signet Protocol recommends seeking qualified legal counsel familiar with the applicable data protection laws in your jurisdiction before deployment.*

*The Signet Protocol — v0.1.0*
*Document Version: 1.0*
*March 2026*
