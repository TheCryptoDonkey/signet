# Professional Verifier Agreement

**Signet Protocol — Draft v0.1.0**

*Template — Seek qualified legal counsel for your jurisdiction before deployment.*

**Effective Date:** [DATE]
**Last Updated:** [DATE]

---

## Parties

This Professional Verifier Agreement ("Agreement") is entered into between:

**Protocol Operator:**
[ORGANIZATION NAME] ("Operator")
Address: [ADDRESS]
Contact: [CONTACT EMAIL]

**Professional Verifier:**
Name: ____________________________
Professional Title: ____________________________
Licence Number: ____________________________
Licensing Body: ____________________________
Jurisdiction: ____________________________
Nostr Public Key (npub): ____________________________
Contact Email: ____________________________

(each a "Party" and together the "Parties")

---

## Recitals

**WHEREAS:**

A. The Operator develops and maintains the Signet Protocol (the "Protocol"), a decentralised identity verification protocol for the Nostr network that uses zero-knowledge proofs, ring signatures, and a tiered trust system.

B. The Protocol includes Tier 3 (Professional Verification — Adult) and Tier 4 (Professional Verification — Adult + Child) verification tiers that require verifications to be performed by licensed professionals.

C. The Verifier is a licensed professional in good standing who wishes to act as a professional verifier under the Protocol.

D. The Parties wish to set out the terms and conditions under which the Verifier will perform verifications.

**NOW, THEREFORE,** in consideration of the mutual covenants and agreements set forth herein, the Parties agree as follows:

---

## 1. Eligibility

### 1.1 Professional Qualifications

To be eligible to act as a Verifier under this Agreement, the Verifier must:

1. **Hold a current, valid professional licence** in one of the following categories (or equivalent in the relevant jurisdiction):

   | Category | Examples |
   |----------|---------|
   | **Legal Professionals** | Solicitor, barrister, attorney, advocate, notary public, legal executive |
   | **Medical Professionals** | Physician, surgeon, dentist, pharmacist, registered nurse (in jurisdictions where permitted) |
   | **Notarial Professionals** | Notary public, notary, commissaire de justice, Notar |
   | **Accounting Professionals** | Chartered accountant, CPA, auditor (in jurisdictions where permitted) |
   | **Other Regulated Professionals** | As approved by the Operator on a jurisdiction-by-jurisdiction basis |

2. **Be in good standing** with the relevant professional regulatory body (e.g., Law Society, Bar Association, Medical Board, Notary Commission).

3. **Not be subject to** any disciplinary proceedings, sanctions, suspensions, or restrictions on practice that would affect the ability to perform verifications.

4. **Have practised** for a minimum of [MINIMUM YEARS] years in the relevant profession.

5. **Maintain current professional indemnity insurance** as specified in Section 8.

### 1.2 Eligibility Verification

The Verifier agrees to:
1. Provide documentary evidence of all qualifications at the time of registration.
2. Submit to verification of professional status through public registries.
3. Notify the Operator immediately of any change in eligibility status.
4. Re-verify eligibility annually or as requested by the Operator.

### 1.3 Registration

Upon acceptance, the Verifier will:
1. Publish a verifier registration event (kind 30473) on the Nostr network.
2. The registration event will include: the Verifier's public key, professional category, jurisdiction, licensing body, and licence verification reference.
3. Registration does not imply endorsement by the Operator.

---

## 2. Verifier Obligations

### 2.1 General Obligations

The Verifier shall:

1. **Perform verifications honestly, diligently, and in accordance with this Agreement and all applicable professional standards.**
2. **Comply with all applicable laws and regulations** in the jurisdiction(s) where verifications are performed.
3. **Maintain the highest standards of professional conduct** in all verification activities.
4. **Act independently and impartially** — verifications must be based solely on the presented evidence and the Verifier's professional judgement.

### 2.2 Tier 3 Verification (Adult) Obligations

When performing Tier 3 (Adult) verifications, the Verifier shall:

1. **Verify identity in person** or through a legally equivalent process (e.g., regulated remote verification where permitted by law in the relevant jurisdiction).
2. **Examine original identity documents** — the Verifier must inspect at least one government-issued photo identification document (e.g., passport, national ID card, driving licence).
3. **Confirm the identity of the person** — the Verifier must satisfy themselves that the person presenting the documents is the person described in the documents.
4. **Verify age** — confirm the individual's date of birth from the identity documents and generate a Bulletproof age-range proof (e.g., "18+" for adults). The date of birth is NEVER published on-chain.
5. **Perform the two-credential ceremony** — the subject presents two Nostr pubkeys (Natural Person and Persona). The Verifier:
   - Builds a Merkle tree from verified attributes (name, nationality, document type, DOB, nullifier)
   - Computes a document-based nullifier: `SHA-256(document_type || country_code || document_number || "signet-uniqueness-v1")`
   - Issues a Natural Person credential (kind 30470) with entity-type, merkle-root, nullifier, and age-range tags
   - Issues a Persona credential (kind 30470) with entity-type=persona and age-range tags only (NO nullifier, NO merkle-root)
   - Discards document number after nullifier computation — it is NOT stored or published
6. **Maintain records** — keep records of the verification as required by the Verifier's professional obligations (see Section 2.5), including both pubkeys and document details (but NOT the document number after nullifier computation, unless required by professional regulations).

### 2.3 Tier 4 Verification (Adult + Child) Obligations

When performing Tier 4 (Adult + Child) verifications, the Verifier shall comply with all Tier 3 obligations and additionally:

1. **Verify the child's identity** — inspect the child's identity documents (birth certificate, passport, or other appropriate documents).
2. **Verify the parent/guardian relationship** — confirm the relationship between the adult and the child through appropriate documentation (birth certificate, legal guardianship order, adoption papers, or equivalent). The parent/guardian MUST hold a Tier 3+ Signet credential.
3. **Obtain parental consent** — obtain and document verifiable parental consent for the child's credential, in compliance with the applicable child protection laws (see Child Safety Policy).
4. **Conduct the verification with the child present** — the child must be present during the verification (in person or through legally equivalent means).
5. **Assess the child's welfare** — exercise professional judgement to identify any indicators of coercion, exploitation, or safeguarding concerns. If concerns arise, the Verifier must not proceed and must follow applicable reporting procedures (see Section 2.8).
6. **Perform the child two-credential ceremony** — issue two credentials for the child (Natural Person + Persona), both carrying:
   - Age-range proof appropriate to the child's age (e.g., "8-12", "13-17")
   - Guardian tags (`["guardian", "<parent_pubkey>"]`) linking the child to their verified parent/guardian
   - Multiple guardian tags if applicable (joint custody)
   - The child's real name is stored only as a private Merkle leaf — never published on-chain
7. **Verify guardian documentation** — for non-standard family structures, verify appropriate legal documentation:
   - Birth certificate (biological parent)
   - Court-issued guardianship order (legal guardian)
   - Adoption papers (adoptive parent)
   - Step-parent responsibility order (where applicable)

### 2.4 Verification Standards

All verifications must meet the following minimum standards:

| Standard | Requirement |
|----------|-------------|
| **Document inspection** | Physical or high-resolution digital inspection of original documents |
| **Identity confirmation** | Face-to-face comparison of the individual to photo identification |
| **Liveness check** | Confirmation that the individual is physically present (not a photograph or recording) |
| **Document authenticity** | Reasonable professional inspection for signs of forgery or alteration |
| **Record keeping** | Contemporaneous notes of the verification process |
| **Independence** | No personal, financial, or other relationship with the subject that could compromise impartiality |

### 2.5 Record Keeping

The Verifier shall:
1. Maintain records of all verifications performed, including:
   - Date and location of verification
   - Identity of the verified individual (sufficient for professional record-keeping obligations)
   - Both pubkeys (Natural Person and Persona) issued during the two-credential ceremony
   - Documents inspected and document type used
   - Nullifier hash computed (but NOT the document number, unless required by professional regulations)
   - Outcome of verification
   - For Tier 4: parental consent documentation and guardian pubkey(s)
2. Retain records for the period required by the Verifier's professional obligations (typically 6–7 years, or longer as required by law).
3. Store records securely and in compliance with applicable data protection laws.
4. **Not retain** copies of identity documents beyond what is required by professional obligations.

### 2.6 Continuing Obligations

The Verifier shall:
1. Maintain their professional licence in good standing throughout the term of this Agreement.
2. Maintain required insurance throughout the term of this Agreement.
3. Complete Protocol-specific training as required by the Operator.
4. Stay current with changes to the Protocol, this Agreement, and applicable laws.
5. Cooperate with audits and reviews conducted by the Operator.

### 2.7 Reporting Obligations

The Verifier shall promptly report to the Operator:
1. Any compromise or suspected compromise of their Nostr private key.
2. Any discovery of a fraudulent verification previously issued.
3. Any change in professional licence status (suspension, restriction, revocation, or disciplinary proceedings).
4. Any data breach affecting verification records.
5. Any legal process, investigation, or regulatory action relating to their verification activities.
6. Any conflict of interest arising in connection with a verification.

### 2.8 Safeguarding Obligations

The Verifier shall:
1. Be trained in recognising indicators of exploitation, coercion, or safeguarding concerns.
2. Refuse to perform a verification if they have any concern about the welfare of the individual (especially children).
3. Report safeguarding concerns to the appropriate authorities in accordance with local law.
4. Follow the Protocol's Child Safety Policy for all Tier 4 verifications.

---

## 3. Prohibited Actions

The Verifier shall NOT:

1. **Issue fraudulent credentials** — verify the identity of anyone whose identity has not been genuinely confirmed.
2. **Accept bribes or improper inducements** — accept payment, gifts, or other consideration in exchange for issuing unwarranted or false verifications.
3. **Verify remotely where not permitted** — perform remote verifications in jurisdictions that require in-person verification.
4. **Delegate verifications** — allow any other person to perform verifications using the Verifier's credentials or Nostr key.
5. **Bulk verify** — perform verifications without genuine individual assessment (i.e., no rubber-stamping).
6. **Verify family members or associates** — verify individuals with whom the Verifier has a personal, familial, or close business relationship, unless disclosed and approved by the Operator.
7. **Retain unnecessary data** — keep copies of identity documents or personal data beyond what is required by professional obligations.
8. **Misrepresent qualifications** — falsely represent their professional status, qualifications, or scope of practice.
9. **Charge excessive fees** — charge fees for verification that are unreasonably excessive compared to prevailing rates for comparable professional services in the jurisdiction.
10. **Use verification data for unrelated purposes** — use data obtained during verifications for any purpose other than the verification itself and required record-keeping.
11. **Share verification details** — disclose details of verifications to any third party, except as required by law or this Agreement.
12. **Verify their own identity** — self-verify or create Tier 3/4 credentials for themselves.

---

## 4. Operator Obligations

The Operator shall:

1. **Provide Protocol documentation** — maintain clear, current documentation of the Protocol and verification procedures.
2. **Provide training** — offer or arrange training on Protocol procedures, cryptographic tools, and legal requirements.
3. **Maintain the Protocol** — maintain the Protocol specification and reference implementations.
4. **Support Verifiers** — provide reasonable technical support for verification-related issues.
5. **Investigate complaints** — investigate complaints about Verifier conduct and take appropriate action.
6. **Publish Verifier directory** — maintain a registry of active, verified Verifiers through kind 30473 events.
7. **Notify of changes** — provide reasonable notice of changes to the Protocol, this Agreement, or verification requirements.

---

## 5. Liability

### 5.1 Verifier Liability

The Verifier is independently liable for:
1. The accuracy and integrity of verifications they perform.
2. Compliance with their professional obligations and ethical rules.
3. Compliance with applicable laws, including data protection laws and child safety laws.
4. Any damages arising from negligent or fraudulent verifications.
5. Safeguarding failures in Tier 4 (child) verifications.

### 5.2 Operator Liability

The Operator is liable for:
1. The integrity and security of the Protocol specification.
2. Accurate documentation and training materials.
3. Timely notification of known Protocol vulnerabilities.

### 5.3 Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW:
- The Operator's total aggregate liability under this Agreement shall not exceed [LIABILITY CAP AMOUNT].
- Neither Party shall be liable for indirect, consequential, special, or punitive damages.
- These limitations do not apply to liability arising from wilful misconduct, fraud, or gross negligence.

### 5.4 No Joint Liability

The Verifier is an independent professional, not an employee, agent, or partner of the Operator. The Operator is not jointly or vicariously liable for the Verifier's acts or omissions.

---

## 6. Intellectual Property

### 6.1 Protocol IP

The Protocol specification and associated trademarks remain the property of the Operator (subject to the open-source licence under which the Protocol is published).

### 6.2 Verifier Use

The Verifier is granted a non-exclusive, non-transferable, revocable licence to:
- Use the Protocol for verification purposes.
- Reference the Signet Protocol in connection with their verification services, provided such reference is accurate and not misleading.

### 6.3 Restrictions

The Verifier shall not:
- Modify the Protocol in a way that compromises its integrity.
- Use the Signet Protocol trademarks in a manner that implies endorsement by the Operator, beyond accurate factual reference to their Verifier status.

---

## 7. Data Protection

### 7.1 Role Allocation

In the context of Tier 3 and Tier 4 verifications:
- The Verifier acts as an **independent data controller** for personal data processed during the verification process (document inspection, identity confirmation, record-keeping).
- The Operator acts as a **data controller** for verifier registration data and Protocol-level processing.
- Where the Verifier processes data on behalf of the Operator, a separate Data Processing Agreement applies.

### 7.2 Verifier Data Protection Obligations

The Verifier shall:
1. Comply with all applicable data protection laws.
2. Implement appropriate technical and organisational security measures.
3. Maintain a record of processing activities.
4. Respond to data subject requests within the required time frames.
5. Report data breaches to the relevant supervisory authority within the required time frames.
6. Conduct data protection impact assessments for high-risk processing (including Tier 4 child verifications).

### 7.3 Data Sharing

The only data shared between the Verifier and the Protocol is the published credential event (kind 30470), which contains:
- The Verifier's public key (as the signing key)
- The subject's public key
- Credential metadata (tier, dates, type)
- The zero-knowledge proof(s)

No personal identification data is shared with or through the Protocol.

---

## 8. Insurance Requirements

### 8.1 Required Insurance

The Verifier shall maintain the following insurance throughout the term of this Agreement:

| Insurance Type | Minimum Coverage |
|---------------|-----------------|
| **Professional Indemnity / Errors & Omissions** | [MINIMUM COVERAGE AMOUNT] per claim; [MINIMUM COVERAGE AMOUNT] aggregate |
| **General / Public Liability** | [MINIMUM COVERAGE AMOUNT] per occurrence |
| **Cyber Liability** (recommended) | [MINIMUM COVERAGE AMOUNT] per claim |

### 8.2 Insurance Requirements

The insurance must:
1. Be issued by a reputable insurer rated A- or higher by AM Best (or equivalent).
2. Cover verification activities performed under this Agreement.
3. Include run-off cover of at least [RUN-OFF YEARS] years after termination of this Agreement.
4. Not contain exclusions that would void coverage for Protocol-related verification activities.

### 8.3 Evidence of Insurance

The Verifier shall:
1. Provide certificates of insurance upon request.
2. Notify the Operator immediately if insurance coverage lapses or is cancelled.
3. Not perform verifications during any period of lapsed insurance.

---

## 9. Fees and Compensation

### 9.1 Verification Fees

The Verifier may charge reasonable fees to individuals seeking verification, subject to:
1. Fees being transparent and disclosed before the verification.
2. Fees being comparable to prevailing rates for similar professional services in the jurisdiction.
3. Compliance with any fee guidelines published by the Operator.
4. Compliance with applicable professional fee regulations.

### 9.2 No Operator Fees

As of the Effective Date, the Operator does not charge Verifiers a fee for participation in the Protocol. The Operator reserves the right to introduce fees with at least 90 days' notice.

### 9.3 No Revenue Sharing

The Verifier is not entitled to any share of revenue from the Protocol or the Operator.

---

## 10. Termination

### 10.1 Termination by the Verifier

The Verifier may terminate this Agreement at any time by:
1. Providing 30 days' written notice to the Operator.
2. Publishing a revocation of their verifier registration event (kind 30473).

### 10.2 Termination by the Operator

The Operator may terminate this Agreement:

**Immediately, without notice, if:**
1. The Verifier's professional licence is suspended or revoked.
2. The Verifier is found to have issued fraudulent verifications.
3. The Verifier's Nostr private key is compromised.
4. The Verifier breaches child safety obligations.
5. The Verifier commits a criminal offence related to their verification activities.
6. The Verifier's insurance lapses and is not reinstated within 14 days.

**With 30 days' notice, if:**
1. The Verifier materially breaches this Agreement and fails to cure within 14 days of notice.
2. The Verifier fails to meet continuing eligibility requirements.
3. The Protocol is discontinued.

### 10.3 Effect of Termination

Upon termination:
1. The Verifier's registration event (kind 30473) is revoked.
2. The Verifier must cease performing verifications under the Protocol.
3. Previously issued credentials remain valid unless individually revoked.
4. The Verifier must retain verification records for the required retention period.
5. Sections 5, 7, 8 (run-off cover), 10.3, 11, and 12 survive termination.

---

## 11. Dispute Resolution

### 11.1 Governing Law

This Agreement is governed by the laws of [GOVERNING LAW JURISDICTION].

### 11.2 Dispute Resolution Procedure

Disputes shall be resolved as follows:
1. **Negotiation:** Good-faith negotiation for 30 days.
2. **Mediation:** If negotiation fails, mediation administered by [MEDIATION BODY].
3. **Arbitration:** If mediation fails, binding arbitration administered by [ARBITRATION BODY] in [ARBITRATION SEAT].

### 11.3 Professional Regulatory Matters

Nothing in this Agreement restricts:
- The jurisdiction of any professional regulatory body over the Verifier.
- The Verifier's right to seek guidance from their professional regulatory body.
- The Operator's right to report concerns to the Verifier's professional regulatory body.

---

## 12. General Provisions

### 12.1 Entire Agreement

This Agreement, together with the Terms of Service, Privacy Policy, Data Processing Agreement (if applicable), and Child Safety Policy, constitutes the entire agreement between the Parties regarding the Verifier's participation in the Protocol.

### 12.2 Amendments

The Operator may amend this Agreement with 30 days' written notice. If the Verifier does not agree to the amendments, the Verifier may terminate this Agreement in accordance with Section 10.1.

### 12.3 Severability

If any provision is found invalid or unenforceable, the remaining provisions remain in full force.

### 12.4 Waiver

No waiver of any provision shall constitute a waiver of any other provision or a continuing waiver.

### 12.5 Assignment

The Verifier may not assign this Agreement. The Operator may assign this Agreement upon notice.

### 12.6 Notices

Notices to the Operator: [CONTACT EMAIL]
Notices to the Verifier: the email address provided above.

### 12.7 Independent Professional Status

The Verifier is an independent professional. Nothing in this Agreement creates an employment, agency, partnership, or joint venture relationship.

---

## Jurisdiction-Specific Annexes

### Annex A — United Kingdom

- Licensing bodies: Law Society of England and Wales, Law Society of Scotland, Law Society of Northern Ireland, General Medical Council, Faculty Office of the Archbishop of Canterbury (notaries), relevant dental/pharmacy/nursing bodies
- Insurance: Professional indemnity insurance as required by SRA / relevant regulator
- Child safety: Compliance with Children Act 1989/2004, DBS checks as appropriate
- Data protection: UK GDPR, Data Protection Act 2018, ICO guidance

### Annex B — United States

- Licensing bodies: State bar associations, state medical boards, state notary commissions
- Insurance: Malpractice insurance as per state requirements
- Child safety: COPPA compliance, state-specific child protection laws, mandatory reporter obligations
- Data protection: CCPA/CPRA (California), state privacy laws
- Note: Requirements vary significantly by state; Verifiers must comply with the laws of the state(s) where they perform verifications

### Annex C — European Union

- Licensing bodies: National bar associations, medical councils, notarial chambers (varies by member state)
- Insurance: As per national professional regulations
- Child safety: GDPR Article 8, national implementing legislation
- Data protection: GDPR, national implementing legislation
- Note: Specific requirements vary by member state

### Annex D — Australia

- Licensing bodies: State/territory law societies, AHPRA (medical), justice departments (notaries)
- Insurance: Professional indemnity as per state/territory requirements
- Child safety: Working With Children Check as applicable, Online Safety Act 2021
- Data protection: Privacy Act 1988, Australian Privacy Principles

### Annex E — Japan

- Licensing bodies: Japan Federation of Bar Associations, Ministry of Justice (notaries), Japan Medical Association
- Insurance: As per professional body requirements
- Child safety: APPI guidelines, national child protection laws
- Data protection: APPI

### Annex F — South Korea

- Licensing bodies: Korean Bar Association, Korean Medical Association, relevant government ministries
- Insurance: As per professional body requirements
- Child safety: PIPA, Youth Protection Act
- Data protection: PIPA

### Annex G — Brazil

- Licensing bodies: OAB (lawyers), CRM (medical), notarial chambers
- Insurance: As per professional body requirements
- Child safety: LGPD Article 14, Statute of the Child and Adolescent (ECA)
- Data protection: LGPD

### Annex H — India

- Licensing bodies: Bar Council of India / state bar councils, Medical Council of India / NMC, relevant state authorities
- Insurance: As available and per professional body guidance
- Child safety: DPDP Act 2023, Protection of Children from Sexual Offences Act (POCSO)
- Data protection: DPDP Act 2023

### Annex I — United Arab Emirates

- Licensing bodies: Ministry of Justice, DHA/HAAD (medical), relevant emirate authorities
- Insurance: As per UAE / emirate requirements
- Child safety: Federal Child Rights Law (Wadeema's Law)
- Data protection: Federal Decree-Law No. 45 of 2021

---

## Signatures

**Protocol Operator:**

Name: ____________________________
Title: ____________________________
Date: ____________________________
Signature: ________________________

**Professional Verifier:**

Name: ____________________________
Professional Title: ____________________________
Licence Number: ____________________________
Date: ____________________________
Signature: ________________________

---

*This Professional Verifier Agreement is provided as a template for the Signet Protocol. It does not constitute legal advice. [ORGANIZATION NAME] recommends seeking qualified legal counsel familiar with the applicable laws in your jurisdiction before deployment.*

*Signet Protocol — Draft v0.1.0*
*Document Version: 1.0*
