# Terms of Service

**Signet Protocol — Draft v0.1.0**

*Template — Seek qualified legal counsel for your jurisdiction before deployment.*

**Effective Date:** [DATE]
**Last Updated:** [DATE]

---

## 1. Acceptance of Terms

By accessing, using, or participating in the Signet Protocol (the "Protocol"), including but not limited to creating credentials, issuing or receiving vouches, acting as a verifier, or relying on Protocol credentials, you ("User," "you," or "your") agree to be bound by these Terms of Service ("Terms"). If you do not agree to these Terms, you must not use the Protocol.

These Terms constitute a legally binding agreement between you and [ORGANIZATION NAME] ("we," "us," or "our").

If you are using the Protocol on behalf of an organisation, you represent and warrant that you have the authority to bind that organisation to these Terms, and "you" refers to both you individually and the organisation.

---

## 2. Eligibility

### 2.1 General Eligibility

To use the Protocol, you must:
- Be at least the age of digital consent in your jurisdiction (see Section 2.2)
- Have the legal capacity to enter into a binding agreement
- Not be prohibited from using the Protocol under any applicable law or regulation
- Not have been previously suspended or removed from the Protocol for violation of these Terms

### 2.2 Age Requirements

| Jurisdiction | Minimum Age | With Parental Consent |
|-------------|-------------|----------------------|
| European Union (default) | 16 | 13 (varies by member state) |
| United Kingdom | 13 | N/A |
| United States | 13 | Under 13 with COPPA-compliant parental consent |
| Brazil | 18 | 12 with parental consent |
| South Korea | 14 | Under 14 with parental consent |
| Japan | 15 | Under 15 with parental consent |
| China | 14 | Under 14 with parental consent |
| India | 18 | As per DPDP Act |
| Other | Age of majority or digital consent age | As per local law |

### 2.3 Verifier Eligibility

To act as a professional verifier (Tier 3 or Tier 4), you must additionally:
- Hold a current, valid professional licence in good standing (e.g., legal, medical, notarial)
- Be authorised to practise in the relevant jurisdiction
- Execute the separate Verifier Agreement
- Maintain professional indemnity insurance as specified in the Verifier Agreement

---

## 3. Description of the Protocol

### 3.1 Overview

The Signet Protocol is a decentralised identity verification protocol for the Nostr network. It enables users to create and verify identity credentials using zero-knowledge proofs, ring signatures, and a tiered trust system, without revealing underlying personal data.

### 3.2 Verification Tiers

The Protocol implements four verification tiers:

- **Tier 1 — Self-Declared:** User-generated credentials with no external verification. Lowest trust level.
- **Tier 2 — Web-of-Trust:** Credentials strengthened by vouches from other Protocol participants. Trust derived from network endorsements.
- **Tier 3 — Professional Verification (Adult):** Credentials verified by a licensed professional verifier through the two-credential ceremony. The subject receives a Natural Person credential (real identity with Merkle-bound attributes and document nullifier) and a Persona credential (anonymous alias with age-range proof only).
- **Tier 4 — Professional Verification (Adult + Child):** Two-credential ceremony extended to include child identity verification with parental/guardian oversight. Both credentials carry age-range proofs and guardian tags linking the child to their verified parent/guardian.

### 3.3 Event Kinds

The Protocol uses the following Nostr event kinds (numbers are placeholders pending NIP allocation):
- **30470** — Credential events
- **30471** — Vouch events
- **30472** — Policy events
- **30473** — Verifier registration events
- **30474** — Challenge events
- **30475** — Revocation events
- **30476** — Identity bridge events
- **30477** — Delegation events (agent and guardian delegation)
- **30478–30480** — Voting extension events (election, ballot, result)

### 3.4 Cryptographic Components

The Protocol uses:
- Schnorr signatures on the secp256k1 curve
- Bulletproofs for age range zero-knowledge proofs
- Ring signatures for anonymous group membership proofs
- Future planned ZK layer (ZK-SNARKs/ZK-STARKs)

### 3.5 Decentralised Nature

The Protocol operates on the Nostr network and has no central server, database, or authority. [ORGANIZATION NAME] develops and maintains the Protocol specification but does not control the network, relay operators, or individual participants.

---

## 4. User Obligations

### 4.1 General Obligations

All users of the Protocol must:

1. **Accuracy:** Provide truthful information when creating credentials. Fraudulent credentials undermine the trust model and may constitute criminal fraud.
2. **Key Security:** Safeguard your Nostr private key (nsec). You are solely responsible for the security of your private key. Lost or compromised keys cannot be recovered by us.
3. **Compliance:** Comply with all applicable laws and regulations in your jurisdiction.
4. **Responsible Use:** Use the Protocol in good faith and not for any unlawful, fraudulent, or harmful purpose.
5. **Reporting:** Promptly report any security vulnerabilities, credential fraud, or Protocol misuse to [CONTACT EMAIL].

### 4.2 Prohibited Uses

You must NOT:

1. Create false, misleading, or fraudulent credentials
2. Impersonate another person or entity
3. Attempt to reverse-engineer zero-knowledge proofs to extract underlying data
4. Use the Protocol to facilitate illegal activities, including but not limited to identity theft, fraud, money laundering, or terrorist financing
5. Attack the Protocol's cryptographic infrastructure, including attempting to break ring signature anonymity sets
6. Spam the network with illegitimate credential or vouch events
7. Collude with verifiers to issue unwarranted Tier 3 or Tier 4 credentials
8. Exploit the Protocol to circumvent age restrictions or child safety measures
9. Use automated systems to mass-generate credentials or vouches without genuine verification
10. Interfere with or disrupt the Protocol's operation or the Nostr network

### 4.3 Vouching Obligations (Tier 2)

When vouching for another user:
- You must have a genuine basis for the vouch
- You must not accept payment or other consideration for providing vouches (pay-for-vouch schemes)
- You may revoke a vouch at any time by publishing a revocation event
- You understand that your vouching behaviour affects your own trust score

---

## 5. Verifier Obligations

### 5.1 Professional Standards

Verifiers must:
1. Hold and maintain valid professional credentials in their jurisdiction
2. Perform verifications in accordance with the Verifier Agreement and applicable professional standards
3. Verify identity in person or through a legally equivalent process (e.g., regulated remote verification where permitted by law)
4. Maintain accurate records of verifications as required by their professional obligations
5. Report any compromises to their credentials or verification processes immediately

### 5.2 Verifier Liability

Verifiers are independently liable for the accuracy and integrity of their verifications. [ORGANIZATION NAME] does not supervise, endorse, or guarantee the quality of any individual verifier's work.

### 5.3 Verifier Termination

Verifier status may be revoked if:
- The verifier's professional licence is suspended or revoked
- The verifier is found to have issued fraudulent verifications
- The verifier breaches the Verifier Agreement
- The verifier fails to maintain required insurance

---

## 6. Credential Issuance and Lifecycle

### 6.1 Credential Creation

Credentials are created by publishing kind 30470 events to the Nostr network. The credential's trust level corresponds to its verification tier.

### 6.2 Credential Validity

Credentials may include an expiry date. Relying parties should check:
- The credential has not been revoked (kind 30475)
- The credential has not expired
- The credential's verification tier meets their requirements (kind 30472 policy)
- The credential's trust score is acceptable

### 6.3 Credential Revocation

Credentials may be revoked by:
- The credential holder (self-revocation)
- The issuing verifier (for cause, such as discovered fraud)
- The Protocol (in cases of systemic fraud or security compromise, through community consensus)

Revocation is accomplished by publishing a kind 30475 event.

### 6.4 No Guarantee of Acceptance

[ORGANIZATION NAME] does not guarantee that any credential will be accepted by any relying party. Relying parties set their own acceptance policies through kind 30472 events.

### 6.5 Two-Credential Model

Professional verification (Tier 3 and Tier 4) uses a two-credential ceremony:
- **Natural Person credential:** Bound to the subject's real identity, includes Merkle root (for selective attribute disclosure), document-based nullifier (for duplicate prevention), and age-range proof. Personal details (name, DOB, nationality) are never published on-chain.
- **Persona credential:** An anonymous alias carrying only the age-range proof and guardian tags (if child). No nullifier or Merkle root. The link between Natural Person and Persona is known only to the subject and the verifier.

### 6.6 Credential Chains

Credentials may be superseded when real-world attributes change (name change, document renewal, tier upgrade). A superseding credential includes a `["supersedes", "<old_event_id>"]` tag. Clients follow the chain to display only the current active credential. Superseded credentials remain on relays but are marked as historical.

### 6.7 Child Sub-Accounts

Child credentials are sub-accounts of a verified parent/guardian:
- A child credential MUST include guardian tags linking to a Tier 3+ verified parent/guardian
- Guardian tags are immutable — they can only be changed by a new credential issued by a professional with appropriate legal documentation
- Guardians may delegate specific permissions to trusted adults via kind 30477 delegation events
- When a child turns 18, they receive a new Tier 3 credential with no guardian tags, superseding their child credential

### 6.8 Persona Usage

Persona accounts are anonymous aliases:
- A Persona carries no personally identifying information (no name, no nullifier, no Merkle root)
- A Persona inherits the age-range proof from the two-credential ceremony
- A Persona may be linked to a Natural Person via an identity bridge (kind 30476) using ring signatures, preserving anonymity
- Users are responsible for the conduct of all their Persona accounts

---

## 7. Intellectual Property

### 7.1 Protocol Specification

The Signet Protocol specification is released under an open-source licence as specified in the Protocol repository. You are granted a licence to use, implement, and build upon the Protocol in accordance with that licence.

### 7.2 Trademarks

"Signet Protocol" and associated logos are trademarks of [ORGANIZATION NAME]. You may not use these marks in a manner that implies endorsement or affiliation without prior written consent, except for accurate descriptive reference to the Protocol.

### 7.3 User Content

You retain ownership of any content you create using the Protocol (e.g., credentials, vouches). By publishing events to the Nostr network, you acknowledge that these events are publicly visible and may be stored and replicated by relay operators.

### 7.4 Contributions

Contributions to the Protocol specification or implementation code are subject to the contributor licence agreement specified in the Protocol repository.

---

## 8. Disclaimers

### 8.1 Protocol Provided "As Is"

THE PROTOCOL IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.

### 8.2 No Warranty of Accuracy

[ORGANIZATION NAME] DOES NOT WARRANT THAT:
- ANY CREDENTIAL IS ACCURATE, COMPLETE, OR RELIABLE
- ANY VERIFIER IS COMPETENT, HONEST, OR PROPERLY LICENSED
- THE PROTOCOL WILL OPERATE WITHOUT INTERRUPTION OR ERROR
- THE CRYPTOGRAPHIC COMPONENTS WILL REMAIN SECURE INDEFINITELY
- THE PROTOCOL WILL MEET YOUR SPECIFIC REQUIREMENTS
- ANY TRUST SCORE ACCURATELY REFLECTS THE TRUSTWORTHINESS OF A USER

### 8.3 Decentralisation Disclaimer

Because the Protocol operates on a decentralised network, [ORGANIZATION NAME]:
- Cannot control, monitor, or censor Protocol activity
- Cannot reverse or modify published events
- Cannot guarantee the availability or performance of any relay
- Cannot enforce these Terms against all participants globally

### 8.4 Cryptographic Disclaimer

While the Protocol uses state-of-the-art cryptographic techniques, no cryptographic system is provably secure against all future attacks. Advances in computing (including quantum computing) may affect the security of the Protocol's cryptographic components.

### 8.5 Regulatory Disclaimer

The regulatory landscape for decentralised identity and zero-knowledge proofs is evolving. Compliance obligations may change, and features of the Protocol may become subject to new regulations.

---

## 9. Limitation of Liability

### 9.1 General Limitation

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, [ORGANIZATION NAME], ITS DIRECTORS, OFFICERS, EMPLOYEES, AGENTS, AND AFFILIATES SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, PUNITIVE, OR EXEMPLARY DAMAGES, INCLUDING BUT NOT LIMITED TO DAMAGES FOR LOSS OF PROFITS, GOODWILL, USE, DATA, OR OTHER INTANGIBLE LOSSES, REGARDLESS OF WHETHER SUCH DAMAGES WERE FORESEEABLE AND WHETHER [ORGANIZATION NAME] WAS ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

### 9.2 Cap on Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, [ORGANIZATION NAME]'S TOTAL AGGREGATE LIABILITY FOR ALL CLAIMS ARISING OUT OF OR RELATED TO THESE TERMS OR THE PROTOCOL SHALL NOT EXCEED THE GREATER OF: (A) THE AMOUNT YOU PAID TO [ORGANIZATION NAME] IN THE 12 MONTHS PRECEDING THE CLAIM, OR (B) [LIABILITY CAP AMOUNT].

### 9.3 Exceptions

The limitations in Sections 9.1 and 9.2 do not apply to:
- Liability that cannot be excluded or limited under applicable law
- Liability arising from wilful misconduct or gross negligence
- Liability for death or personal injury caused by negligence (in jurisdictions where such limitation is prohibited)

### 9.4 Consumer Protection

Nothing in these Terms affects your statutory rights as a consumer under applicable consumer protection laws that cannot be waived or limited by contract.

---

## 10. Indemnification

### 10.1 Your Indemnification Obligations

You agree to indemnify, defend, and hold harmless [ORGANIZATION NAME], its directors, officers, employees, agents, and affiliates from and against any and all claims, damages, losses, liabilities, costs, and expenses (including reasonable attorneys' fees) arising out of or related to:

1. Your use of the Protocol
2. Your breach of these Terms
3. Your violation of any applicable law or regulation
4. Your infringement of any third-party rights
5. Credentials you create, including false or misleading credentials
6. Vouches you issue
7. Verifications you perform (if you are a verifier)

### 10.2 Indemnification Procedure

We will:
- Notify you promptly of any claim subject to indemnification
- Provide you with reasonable cooperation in the defence of such claim
- Allow you to control the defence and settlement of such claim, provided that you do not settle any claim without our prior written consent if the settlement imposes obligations on us

---

## 11. Governing Law and Dispute Resolution

### 11.1 Governing Law

These Terms are governed by and construed in accordance with the laws of [GOVERNING LAW JURISDICTION], without regard to its conflict of law provisions.

### 11.2 Dispute Resolution

Any dispute, controversy, or claim arising out of or relating to these Terms or the Protocol shall be resolved as follows:

**Step 1 — Negotiation:** The parties shall first attempt to resolve the dispute through good-faith negotiation for a period of 30 days.

**Step 2 — Mediation:** If negotiation fails, the parties shall submit the dispute to mediation administered by [MEDIATION BODY] in accordance with its rules.

**Step 3 — Arbitration:** If mediation fails, the dispute shall be finally resolved by binding arbitration administered by [ARBITRATION BODY] in accordance with its rules. The arbitration shall be conducted in [ARBITRATION SEAT] in the English language. The arbitral award shall be final and binding.

### 11.3 Class Action Waiver

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, YOU AGREE THAT ANY DISPUTE RESOLUTION PROCEEDINGS WILL BE CONDUCTED ONLY ON AN INDIVIDUAL BASIS AND NOT IN A CLASS, CONSOLIDATED, OR REPRESENTATIVE ACTION. IF THIS CLASS ACTION WAIVER IS FOUND TO BE UNENFORCEABLE, THEN THE ENTIRETY OF THIS ARBITRATION PROVISION SHALL BE NULL AND VOID.

### 11.4 Exceptions

Notwithstanding the above, either party may seek injunctive or other equitable relief in any court of competent jurisdiction to protect its intellectual property rights or to prevent irreparable harm.

### 11.5 EU Consumer Rights

If you are a consumer in the European Union, you may also lodge a complaint through the EU Online Dispute Resolution platform at [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

---

## 12. Termination

### 12.1 Your Right to Terminate

You may stop using the Protocol at any time. Due to the decentralised nature of the Protocol, previously published events may remain on Nostr relays.

### 12.2 Our Right to Terminate

We reserve the right to:
- Revoke verifier credentials for cause
- Publish community advisories about fraudulent credentials or actors
- Modify or discontinue the Protocol specification

### 12.3 Effect of Termination

Upon termination:
- Your right to use any proprietary components of the Protocol ceases
- Sections 7, 8, 9, 10, 11, and 14 survive termination
- Previously published Nostr events are not affected (they remain on relays)

---

## 13. Amendments

### 13.1 Right to Amend

We reserve the right to modify these Terms at any time. Modifications will be effective upon:
- Publication of updated Terms in the Protocol repository
- A Nostr event announcement referencing the updated Terms
- 30 days' notice for material changes

### 13.2 Acceptance of Amendments

Your continued use of the Protocol after the effective date of any amendment constitutes acceptance of the amended Terms. If you do not agree to the amendments, you must discontinue use of the Protocol.

### 13.3 Material Changes

For material changes that significantly affect your rights or obligations, we will provide:
- Clear notice of the changes
- A comparison or summary of key changes
- A reasonable period (at least 30 days) before the changes take effect

---

## 14. General Provisions

### 14.1 Entire Agreement

These Terms, together with the Privacy Policy, any applicable Verifier Agreement, and any Data Processing Agreement, constitute the entire agreement between you and [ORGANIZATION NAME] regarding the Protocol.

### 14.2 Severability

If any provision of these Terms is found to be invalid or unenforceable, that provision shall be enforced to the maximum extent permissible, and the remaining provisions shall remain in full force and effect.

### 14.3 Waiver

The failure of [ORGANIZATION NAME] to enforce any provision of these Terms shall not constitute a waiver of that provision or any other provision.

### 14.4 Assignment

You may not assign or transfer these Terms or any rights or obligations hereunder without our prior written consent. We may assign these Terms without your consent.

### 14.5 Force Majeure

Neither party shall be liable for any failure or delay in performance due to causes beyond its reasonable control, including but not limited to natural disasters, war, terrorism, riots, pandemics, government action, network failures, or cryptographic algorithm compromises.

### 14.6 Notices

Notices to [ORGANIZATION NAME] should be sent to [CONTACT EMAIL]. Notices to you will be sent to any contact information you have provided, or published via Nostr event or the Protocol repository.

### 14.7 Third-Party Beneficiaries

These Terms do not create any third-party beneficiary rights except as expressly stated herein.

### 14.8 Export Compliance

You agree to comply with all applicable export and sanctions laws and regulations. The Protocol's cryptographic components may be subject to export controls in certain jurisdictions.

---

## 15. Contact

For questions about these Terms:

**[ORGANIZATION NAME]**
Email: [CONTACT EMAIL]
Address: [ADDRESS]

---

*These Terms of Service are provided as a template for the Signet Protocol. They do not constitute legal advice. [ORGANIZATION NAME] recommends seeking qualified legal counsel familiar with the applicable laws in your jurisdiction before deployment.*

*Signet Protocol — Draft v0.1.0*
*Document Version: 1.0*
