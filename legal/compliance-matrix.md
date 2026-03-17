# Compliance Matrix — Jurisdiction Requirements

**Signet Protocol — v0.1.0**

*Reference guide — Seek qualified legal counsel for your jurisdiction before deployment.*

**Last Updated:** March 2026

---

## Overview

This compliance matrix provides a jurisdiction-by-jurisdiction summary of the legal and regulatory requirements relevant to the Signet Protocol. It covers data protection, consent ages, breach notification, cross-border transfer rules, child protection, electronic signature frameworks, age verification mandates, digital identity wallet status, biometric data classification, and key professional bodies that serve as trust anchors for Tier 3 and Tier 4 verifications.

Three new columns were added in this revision:

- **Age Verification Requirements** — whether the jurisdiction mandates age verification for online services
- **Digital Identity Wallet Status** — whether a national digital identity wallet is being implemented
- **Biometric Data Classification** — how the jurisdiction treats biometric data under its data protection framework

Where Signet's architecture directly satisfies or exceeds a local legal standard, a **Signet Architecture Note** is included.

**Important:** This matrix is a reference guide, not legal advice. Laws and regulations change frequently. Always verify current requirements with qualified legal counsel in the relevant jurisdiction.

---

## Compliance Matrix

### United Kingdom (GB)

| Category | Details |
|----------|---------|
| **Data Protection Law** | UK GDPR (retained EU law) + Data Protection Act 2018 |
| **Supervisory Authority** | Information Commissioner's Office (ICO) |
| **Consent Age (Digital)** | 13 years |
| **Age of Majority** | 18 years |
| **Breach Notification** | 72 hours to ICO; without undue delay to data subjects (if high risk) |
| **Right to Erasure** | Yes (UK GDPR Art. 17) |
| **Cross-Border Rules** | UK International Data Transfer Agreement (IDTA) or UK Addendum to EU SCCs; adequacy decisions; appropriate safeguards |
| **Child Protection** | Age Appropriate Design Code (AADC — Children's Code); Children Act 1989/2004; DBS checks for child-facing roles |
| **eSignature Status** | Electronic Communications Act 2000; eIDAS retained; qualified electronic signatures recognised |
| **Age Verification Requirements** | Yes — Online Safety Act 2023 (in force from 2025). Ofcom Code of Practice requires "highly effective age assurance" (HEAA) for platforms hosting pornography and other age-restricted content. Ofcom published HEAA guidance in 2024; platforms must demonstrate >99.9% effectiveness for the highest-risk services. Age assurance standards include facial age estimation, credit card verification, digital identity, and professional body certification. |
| **Digital Identity Wallet Status** | Active — GOV.UK Wallet (beta, 2025). DSIT One Login digital identity scheme being expanded. Digital Identity and Attributes Trust Framework (DIATF) published; secondary legislation under the Data (Use and Access) Act 2025 underpins cross-sector use. |
| **Biometric Data Classification** | Special category data under UK GDPR Art. 9 — biometric data processed for the purpose of uniquely identifying a natural person requires explicit consent or another Art. 9(2) condition and a Schedule 1 DPA 2018 condition. |
| **Key Professional Bodies** | Law Society of England and Wales; Law Society of Scotland; Law Society of Northern Ireland; General Medical Council (GMC); Faculty Office (notaries); General Dental Council; Nursing and Midwifery Council |

**Signet Architecture Note — UK:** Ofcom's HEAA standard requires age assurance that is "accurate, reliable, and robust." Signet's Tier 3/4 professional verification — where a regulated professional (GMC, Law Society) countersigns a credential — exceeds the Ofcom standard in two respects: (1) verification is performed by a human professional with legal accountability, analogous to the UK's standard of a countersignatory for passport applications; (2) the resulting Persona credential discloses only an age range, not a date of birth, satisfying both the HEAA accuracy requirement and the Privacy and Electronic Communications Regulations (PECR) minimisation principle. Signet's zero-knowledge proof infrastructure provides a cryptographic audit trail that would satisfy ICO's accountability principle under UK GDPR Art. 5(2).

---

### United States (US)

| Category | Details |
|----------|---------|
| **Data Protection Law** | No federal comprehensive law; CCPA/CPRA (California); VCDPA (Virginia); CPA (Colorado); CTDPA (Connecticut); UCPA (Utah); additional state laws enacted through 2025; HIPAA (health); GLBA (financial); FERPA (education) |
| **Supervisory Authority** | FTC (federal); state attorneys general; state privacy agencies (e.g., California Privacy Protection Agency — CPPA) |
| **Consent Age (Digital)** | 13 years (COPPA). FTC finalised COPPA 2.0 updates in January 2025 expanding verifiable parental consent requirements to ages 13–15 for some contexts; rule effective 60 days after publication. |
| **Age of Majority** | 18 years (19 in Alabama and Nebraska) |
| **Breach Notification** | All 50 states have breach notification laws; time frames vary (typically 30–60 days; some require "most expedient time possible"); proposed federal legislation (ADPPA) remains pending as of March 2026 |
| **Right to Erasure** | Yes under CCPA/CPRA and most comprehensive state privacy laws enacted by 2025; no federal right |
| **Cross-Border Rules** | No general restrictions; sector-specific rules (e.g., HIPAA, ITAR); CCPA/CPRA requires contractual protections for service providers; EU-US Data Privacy Framework (DPF, 2023) provides adequacy mechanism for US recipients certified under DPF |
| **Child Protection** | COPPA (under 13, FTC enforcement); Children's Online Privacy Protection Rule amended 2025; California Age-Appropriate Design Code Act (AB 2273, challenged in courts); state child protection laws; mandatory reporter laws |
| **eSignature Status** | ESIGN Act (federal); UETA (adopted by most states); electronic signatures generally valid |
| **Age Verification Requirements** | Varies by state. Louisiana, Utah, Arkansas (HB 1627 — blocked in courts), Texas (HB 18), Virginia, and others enacted age verification requirements for adult content sites between 2023–2025. Federal Kids Online Safety Act (KOSA) signed into law 2024, imposing duty of care on platforms likely to be accessed by minors. No single federal age verification mandate for all online services. |
| **Digital Identity Wallet Status** | No federal digital identity wallet. TSA's mobile driver's licence (mDL) acceptance programme expanding at airports. Several states (Arizona, Colorado, Georgia, Maryland, Utah, California) have issued mDLs (ISO 18013-5). No federal cross-state interoperability framework as of March 2026. |
| **Biometric Data Classification** | Varies by state. Illinois Biometric Information Privacy Act (BIPA, 740 ILCS 14) is the most stringent — prior written consent required; private right of action with $1,000–$5,000 per violation. Texas CUBI, Washington MBPA, and several other state laws also regulate biometric data. Federal baseline: no general biometric law; FTC Act Section 5 unfairness doctrine applies. |
| **Key Professional Bodies** | American Bar Association + state bar associations; state medical boards; National Notary Association + state notary commissions; AICPA + state CPA boards |

**Signet Architecture Note — US:** The FTC's January 2025 COPPA updates emphasise "data minimisation" and restrict the collection of personal information from children. Signet's architecture collects zero personally identifiable information (PII) at the protocol level — the Persona credential contains only an age range and a Nostr public key. There is no name, date of birth, document number, or government identifier stored or transmitted. This design satisfies the FTC's stated COPPA flexibility objectives more comprehensively than any age-verification-by-data-collection approach. For BIPA-jurisdictional deployments, Signet does not use biometric processing; professional countersigning via regulated practitioners provides age assurance without facial recognition or fingerprinting.

---

### France (FR)

| Category | Details |
|----------|---------|
| **Data Protection Law** | GDPR + Loi Informatique et Libertés (amended by Loi no. 2018-493) |
| **Supervisory Authority** | Commission Nationale de l'Informatique et des Libertés (CNIL) |
| **Consent Age (Digital)** | 15 years |
| **Age of Majority** | 18 years |
| **Breach Notification** | 72 hours to CNIL; without undue delay to data subjects (if high risk) |
| **Right to Erasure** | Yes (GDPR Art. 17) + Loi pour une République numérique (digital estate) |
| **Cross-Border Rules** | GDPR Chapter V; SCCs; adequacy decisions; BCRs |
| **Child Protection** | GDPR Art. 8 (15 years per French implementation); Code de l'action sociale et des familles; Loi relative à la protection des mineurs |
| **eSignature Status** | eIDAS Regulation; Code civil Art. 1366–1367; qualified electronic signatures have equivalent effect to handwritten |
| **Age Verification Requirements** | Yes — Loi visant à sécuriser et réguler l'espace numérique (SREN, Law no. 2024-449). Arcom (Autorité de régulation de la communication audiovisuelle et numérique) is the enforcement body. SREN mandates double-anonymity technical standard for age verification on adult content platforms — systems must verify age without disclosing identity to the platform. Arcom published the technical reference system in 2024; platforms must comply by 2025. Non-compliance: Arcom may order app stores to remove the application. |
| **Digital Identity Wallet Status** | Active — France Identité (beta/rollout from 2023). EU eIDAS 2.0 EUDIW reference implementation; France is one of the Large Scale Pilot (LSP) member states in the POTENTIAL consortium. France Identité issues digital versions of national identity cards and driver's licences; cross-sector use cases expanding. |
| **Biometric Data Classification** | Special category data under GDPR Art. 9 — biometric data processed for unique identification requires explicit consent or another Art. 9(2) condition. CNIL has published specific guidelines on facial recognition and biometric access control systems; prior CNIL authorisation may be required for novel biometric processing. |
| **Key Professional Bodies** | Conseil National des Barreaux (CNB); Ordre des Avocats; Conseil Supérieur du Notariat; Ordre National des Médecins; Ordre des Pharmaciens |

**Signet Architecture Note — France:** Arcom's double-anonymity standard for online age verification requires that the verifying party (the platform) cannot learn the user's identity, and the identity provider cannot learn which platform the user is accessing. Signet's Persona credential satisfies the Arcom standard by design: the Persona credential is issued once during the two-credential ceremony and presented to any platform via Nostr without revealing the holder's identity. The platform learns only that the credential holder is above a specified age range — no name, no document number, no identity provider metadata. The Merkle proof structure ensures the credential cannot be linked across sessions unless the holder chooses to use the same Nostr keypair. This satisfies both the anti-tracking and the anonymity-preservation requirements of the Arcom technical reference system.

---

### Germany (DE)

| Category | Details |
|----------|---------|
| **Data Protection Law** | GDPR + Bundesdatenschutzgesetz (BDSG) + Landesdatenschutzgesetze (state laws) |
| **Supervisory Authority** | BfDI (federal); Landesdatenschutzbeauftragte (state DPAs, 16 states) |
| **Consent Age (Digital)** | 16 years |
| **Age of Majority** | 18 years |
| **Breach Notification** | 72 hours to supervisory authority; without undue delay to data subjects (if high risk) |
| **Right to Erasure** | Yes (GDPR Art. 17) |
| **Cross-Border Rules** | GDPR Chapter V; SCCs; adequacy decisions; BCRs; BDSG Section 78 |
| **Child Protection** | GDPR Art. 8 (16 years); Jugendschutzgesetz (Youth Protection Act); Jugendmedienschutz-Staatsvertrag (JMStV, amended 2021) |
| **eSignature Status** | eIDAS Regulation; Vertrauensdienstegesetz (VDG); qualified electronic signatures equivalent to handwritten (BGB §126a) |
| **Age Verification Requirements** | Yes — Jugendmedienschutz-Staatsvertrag (JMStV) requires effective age verification for age-restricted online content accessible from Germany. Kommission für Jugendmedienschutz (KJM) is the enforcement body; KJM maintains a list of approved age verification solutions. German Telecommunications Telemedia Data Protection Act (TTDSG, 2021) applies additional consent requirements. |
| **Digital Identity Wallet Status** | Active — EU EUDIW reference wallet (Germany participating in all four Large Scale Pilots). Bundesnetzagentur is national contact point for eIDAS 2.0. Germany's eID (Personalausweis online function) is one of the most mature national eID systems in the EU with millions of active users. |
| **Biometric Data Classification** | Special category data under GDPR Art. 9. BfDI and state DPAs have issued opinions on facial recognition and workplace biometrics. BDSG §26 governs employee biometric data (explicit consent or collective agreement required). |
| **Key Professional Bodies** | Bundesrechtsanwaltskammer (BRAK); Bundesnotarkammer (BNotK); Bundesärztekammer; Landesärztekammern; Wirtschaftsprüferkammer (WPK) |

---

### Spain (ES)

| Category | Details |
|----------|---------|
| **Data Protection Law** | GDPR + Ley Orgánica 3/2018 de Protección de Datos (LOPDGDD) |
| **Supervisory Authority** | Agencia Española de Protección de Datos (AEPD); regional authorities in Catalonia (APDCAT), Basque Country (AVPD), Andalusia (DPOA) |
| **Consent Age (Digital)** | 14 years |
| **Age of Majority** | 18 years |
| **Breach Notification** | 72 hours to AEPD; without undue delay to data subjects (if high risk) |
| **Right to Erasure** | Yes (GDPR Art. 17) + LOPDGDD Art. 93 (right to be forgotten in internet searches) |
| **Cross-Border Rules** | GDPR Chapter V; SCCs; adequacy decisions; BCRs |
| **Child Protection** | GDPR Art. 8 (14 years per LOPDGDD); Ley Orgánica de Protección Jurídica del Menor |
| **eSignature Status** | eIDAS Regulation; Ley 6/2020 de servicios electrónicos de confianza; qualified electronic signatures fully recognised |
| **Age Verification Requirements** | EU DSA (Digital Services Act) applies. Spain has adopted DSA enforcement powers in the Ley de Servicios Digitales (Circular 1/2023 of CNMC). Platforms hosting pornography face age verification requirements under the Spanish Ley de Protección de la Infancia (2021, amendment pending). AEPD has issued guidance on GDPR-compliant age verification techniques. |
| **Digital Identity Wallet Status** | Active — EU EUDIW participant (POTENTIAL Large Scale Pilot consortium); Spain's DNIe digital identity expanding. Ministerio para la Transformación Digital leading national EUDIW implementation. |
| **Biometric Data Classification** | Special category data under GDPR Art. 9; LOPDGDD does not modify GDPR Art. 9 conditions. AEPD has published specific opinions on facial recognition as special category processing. |
| **Key Professional Bodies** | Consejo General de la Abogacía Española; Consejo General del Notariado; Consejo General de Colegios de Médicos; Colegios de Abogados (regional) |

---

### Italy (IT)

| Category | Details |
|----------|---------|
| **Data Protection Law** | GDPR + Codice in materia di protezione dei dati personali (D.Lgs. 196/2003, amended by D.Lgs. 101/2018) |
| **Supervisory Authority** | Garante per la protezione dei dati personali |
| **Consent Age (Digital)** | 14 years |
| **Age of Majority** | 18 years |
| **Breach Notification** | 72 hours to Garante; without undue delay to data subjects (if high risk) |
| **Right to Erasure** | Yes (GDPR Art. 17) |
| **Cross-Border Rules** | GDPR Chapter V; SCCs; adequacy decisions; BCRs |
| **Child Protection** | GDPR Art. 8 (14 years); Codice civile (parental authority); D.Lgs. 196/2003 Art. 2-quinquies |
| **eSignature Status** | eIDAS Regulation; Codice dell'Amministrazione Digitale (CAD); qualified electronic signatures fully recognised |
| **Age Verification Requirements** | EU DSA applies. Agcom (Autorità per le Garanzie nelle Comunicazioni) is the DSA national coordinator. Italy's Legge n. 71/2024 (child protection in digital environments, "Legge Zampa bis") imposes age verification obligations on platforms accessible to minors; AGCOM implementing regulations in progress as of March 2026. |
| **Digital Identity Wallet Status** | Active — SPID/CIE digital identity system operational since 2016; one of the highest eID adoption rates in the EU. Italy participating in EU EUDIW Large Scale Pilots (EWC wallet consortium). IT Wallet (national mobile digital identity wallet) launched in pilot in 2024 via the IT Wallet Act (D.Lgs. 138/2024). |
| **Biometric Data Classification** | Special category data under GDPR Art. 9. Garante has issued specific guidance on biometric recognition systems; processing generally requires Garante authorisation or explicit consent with DPIA. |
| **Key Professional Bodies** | Consiglio Nazionale Forense (CNF); Consiglio Nazionale del Notariato; Federazione Nazionale degli Ordini dei Medici (FNOMCeO); Consiglio Nazionale dei Dottori Commercialisti (CNDCEC) |

---

### Netherlands (NL)

| Category | Details |
|----------|---------|
| **Data Protection Law** | GDPR + Uitvoeringswet Algemene verordening gegevensbescherming (UAVG) |
| **Supervisory Authority** | Autoriteit Persoonsgegevens (AP) |
| **Consent Age (Digital)** | 16 years |
| **Age of Majority** | 18 years |
| **Breach Notification** | 72 hours to AP; without undue delay to data subjects (if high risk) |
| **Right to Erasure** | Yes (GDPR Art. 17) |
| **Cross-Border Rules** | GDPR Chapter V; SCCs; adequacy decisions; BCRs |
| **Child Protection** | GDPR Art. 8 (16 years); Jeugdwet (Youth Act) |
| **eSignature Status** | eIDAS Regulation; Burgerlijk Wetboek (Civil Code); qualified electronic signatures fully recognised |
| **Age Verification Requirements** | EU DSA applies. ACM (Autoriteit Consument en Markt) and AP are joint DSA enforcement bodies. AP issued opinion in 2023 that age estimation is not GDPR-compliant as a standalone mechanism — identity-linked age verification via DigiD preferred. Kijkwijzer (media classification) and Kansspelautoriteit (gambling authority) impose sector-specific age verification requirements. |
| **Digital Identity Wallet Status** | Active — DigiD (national eID system) has over 13 million active users. NL participating in EU EUDIW (EWC consortium). NLDIW (NL Digital Identity Wallet) being developed under coordination of Rijksdienst voor Identiteitsgegevens (RvIG); pilot in 2025, nationwide rollout planned 2026. |
| **Biometric Data Classification** | Special category data under GDPR Art. 9. AP has taken enforcement action on biometric workplace access systems (2020 enforcement notice against Dutch supermarket chain). UAVG does not provide additional Art. 9 conditions beyond GDPR. |
| **Key Professional Bodies** | Nederlandse Orde van Advocaten (NOvA); Koninklijke Notariële Beroepsorganisatie (KNB); Koninklijke Nederlandsche Maatschappij tot bevordering der Geneeskunst (KNMG); NBA (accountants) |

---

### Canada (CA)

| Category | Details |
|----------|---------|
| **Data Protection Law** | PIPEDA (federal, to be replaced by Bill C-27 — Consumer Privacy Protection Act, CPPA — pending royal assent as of March 2026); provincial laws: PIPA Alberta, PIPA BC, Loi 25 Quebec (in force 2022–2023) |
| **Supervisory Authority** | Office of the Privacy Commissioner of Canada (OPC); provincial commissioners (Alberta, BC, Quebec) |
| **Consent Age (Digital)** | No specific statutory age; meaningful consent based on capacity. OPC guidance suggests meaningful consent typically available from age 13; Quebec Loi 25 requires parental consent for children under 14 for commercial services. |
| **Age of Majority** | 18 or 19 (varies by province/territory) |
| **Breach Notification** | "As soon as feasible" to OPC and affected individuals (PIPEDA); within 72 hours in Quebec (Loi 25 Art. 3.7) |
| **Right to Erasure** | Limited under PIPEDA; broader under Quebec Loi 25 (Art. 28 — right to de-indexing); CPPA (when enacted) will introduce stronger deletion right |
| **Cross-Border Rules** | No general prohibition; accountability principle; consent-based; Quebec Loi 25 requires privacy impact assessment before transfer |
| **Child Protection** | PIPEDA (meaningful consent); Quebec Loi 25 (parental consent under 14); provincial child welfare laws; Criminal Code provisions |
| **eSignature Status** | UECA (Uniform Electronic Commerce Act) adopted by most provinces; PIPEDA recognises electronic documents; Quebec Civil Code provisions (Act respecting the legal framework for information technology) |
| **Age Verification Requirements** | No federal mandate as of March 2026. Bill C-63 (Online Harms Act) introduced in 2024 includes age-appropriate design requirements and graduated duties of care for platforms accessed by minors; parliamentary progress ongoing. British Columbia and Alberta considering provincial age assurance frameworks. |
| **Digital Identity Wallet Status** | Active development — Pan-Canadian Trust Framework (PCTF) being implemented by Digital ID and Authentication Council of Canada (DIACC). Several provinces have digital identity pilots: BC Services Card (operational), Ontario Digital ID (pilot), Quebec SIN digital integration. No federal wallet as of March 2026. |
| **Biometric Data Classification** | "Sensitive personal information" under PIPEDA requiring heightened consent and security; Quebec Loi 25 classifies biometrics as sensitive; no federal special category regime equivalent to GDPR. OPC has published guidance on facial recognition and biometric surveillance. |
| **Key Professional Bodies** | Provincial/territorial law societies (e.g., Law Society of Ontario, Barreau du Québec); provincial medical regulatory authorities (e.g., CPSO, CPSBC); provincial notary bodies (e.g., Chambre des notaires du Québec) |

---

### Australia (AU)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Privacy Act 1988 (Cth) + Australian Privacy Principles (APPs); Privacy and Other Legislation Amendment Act 2024 (in force December 2024) introducing statutory tort for serious privacy invasions |
| **Supervisory Authority** | Office of the Australian Information Commissioner (OAIC); eSafety Commissioner (online safety); ACMA (communications and media authority) |
| **Consent Age (Digital)** | No specific statutory digital consent age; capacity-based assessment; Privacy Act 1988 does not set a digital consent age |
| **Age of Majority** | 18 years |
| **Breach Notification** | "As soon as practicable" and within 30 days of awareness of eligible data breach, to OAIC and affected individuals (NDB scheme) |
| **Right to Erasure** | Limited (APP 13 — correction); Privacy and Other Legislation Amendment Act 2024 proposed enhanced deletion right under reform process; not yet full erasure right as of March 2026 |
| **Cross-Border Rules** | APP 8 — reasonable steps to ensure overseas recipient complies with APPs; list of prescribed countries; consent exception |
| **Child Protection** | Online Safety Act 2021; Basic Online Safety Expectations; eSafety Commissioner enforcement; Online Safety (Social Media Minimum Age) Amendment Bill 2024 — under-16 social media ban (passed November 2024, in force from March 2025) |
| **eSignature Status** | Electronic Transactions Act 1999 (Cth) + state/territory equivalents; electronic signatures generally valid (with specific exclusions) |
| **Age Verification Requirements** | Yes — among the world's most stringent. Online Safety (Social Media Minimum Age) Amendment Bill 2024 bans children under 16 from social media platforms effective March 2025; platforms must use "reasonable steps" age assurance. eSafety Commissioner developing mandatory age assurance standards. Online Safety Act 2021 (s. 49A) — eSafety Commissioner may require age verification systems for class 1 content. Australian Classification Board classification requirements for adult content |
| **Digital Identity Wallet Status** | Active — myGov digital identity wallet (myID, formerly myGovID) operational; Trusted Digital Identity Framework (TDIF) governs accredited identity providers; Digital ID Act 2024 passed, establishing the Australian Government Digital ID System (AGDIS); myID expansion across government services. |
| **Biometric Data Classification** | "Sensitive information" under Privacy Act 1988 APP 3 (including "biometric information" and "biometric templates") requiring consent or another authorised exception. Privacy and Other Legislation Amendment Act 2024 strengthens protections. Attorney-General's Department reviewing biometric surveillance. |
| **Key Professional Bodies** | State/territory law societies and bar associations; AHPRA + National Boards (medical, nursing, pharmacy, etc.); state attorneys general / justice departments (notaries) |

**Signet Architecture Note — Australia:** The Online Safety (Social Media Minimum Age) Amendment Bill 2024 requires platforms to take "reasonable steps" to ensure users are 16 or older, but expressly does not require platforms to collect identity documents or retain verification data. Signet's architecture satisfies the "reasonable steps" standard without central data collection: the Persona credential (containing only an age-range assertion) is verified by a regulated Australian professional (e.g., a solicitor, medical practitioner, or AHPRA-registered health professional), and the credential is presented to the platform via a Nostr event. The platform verifies the cryptographic proof without receiving any identity information. This is more privacy-preserving than any document-upload approach and satisfies both the eSafety Commissioner's likely technical standards and the Privacy Act 1988 data minimisation requirements.

---

### New Zealand (NZ)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Privacy Act 2020 |
| **Supervisory Authority** | Office of the Privacy Commissioner |
| **Consent Age (Digital)** | No specific statutory age; capacity-based assessment |
| **Age of Majority** | 18 years |
| **Breach Notification** | "As soon as practicable" to Privacy Commissioner and affected individuals for notifiable privacy breaches |
| **Right to Erasure** | Correction right under IPP 7; no general erasure right |
| **Cross-Border Rules** | IPP 12 — reasonable belief that recipient is subject to comparable safeguards; prescribed countries; individual authorisation |
| **Child Protection** | Privacy Act 2020 (capacity-based); Oranga Tamariki Act 1989; Harmful Digital Communications Act 2015 |
| **eSignature Status** | Electronic Transactions Act 2002; Contract and Commercial Law Act 2017; electronic signatures generally valid |
| **Age Verification Requirements** | Yes — Harmful Digital Communications Act 2015 enforcement; Classification (Publications, Films, Computer Games and Labelling) Act 1989 as amended; Gambling Act 2003 (age verification for online gambling); proposed Digital Safety Act reform under discussion. New Zealand following Australian under-16 developments closely; no equivalent law as of March 2026. |
| **Digital Identity Wallet Status** | Early development — RealMe+ digital identity service operated by New Zealand Post (NZ Post) under contract with Department of Internal Affairs. Digital Identity Services Trust Framework Act 2023 (in force July 2024) establishing accreditation framework; national wallet implementation expected 2025–2027. |
| **Biometric Data Classification** | "Sensitive information" under Privacy Act 2020 (Schedule 2); processing requires explicit consent or authorised exception; no separate biometric special category equivalent to GDPR Art. 9. |
| **Key Professional Bodies** | New Zealand Law Society; Medical Council of New Zealand; New Zealand Society of Notaries |

---

### Japan (JP)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Act on the Protection of Personal Information (APPI, amended 2022, further amendment anticipated 2025 review cycle) |
| **Supervisory Authority** | Personal Information Protection Commission (PPC) |
| **Consent Age (Digital)** | No specific statutory age; industry guidelines suggest 15+ for most online services |
| **Age of Majority** | 18 years (lowered from 20 in 2022) |
| **Breach Notification** | Required for breaches involving sensitive data, >1,000 records, or resulting from unlawful access; "promptly" (within 3–5 days guidance) to PPC and affected individuals |
| **Right to Erasure** | Right to request cessation of use and deletion (APPI Art. 30) |
| **Cross-Border Rules** | APPI Art. 28 — consent, adequacy (PPC whitelist), or APPC-approved binding rules; enhanced information disclosure requirements for transfers to third parties abroad |
| **Child Protection** | APPI (general provisions); Act on Development of an Environment that Provides Safe and Secure Internet Use for Young People (2008, amended); Act on Punishing Activities Relating to Child Prostitution and Child Pornography; industry self-regulation under Safe Internet Association of Japan |
| **eSignature Status** | Act on Electronic Signatures and Certification Business (2000); qualified electronic signatures recognised; specific accreditation framework (JIPDEC, etc.) |
| **Age Verification Requirements** | Yes — Act on Regulations of Transmission of Specified Electronic Mail (against unsolicited communications to minors); Act on Development of an Environment for Safe and Secure Internet Use for Young People imposes duties on ISPs and mobile carriers to provide filtering services for under-18 users. Specific age verification requirements apply to online gaming (self-regulation), adult content, and gambling. Digital Agency proposing broader online age verification framework in 2025 policy consultations. |
| **Digital Identity Wallet Status** | Active — My Number Card (Juki-net / Individual Number Card system) issued by J-LIS; My Number Act amended 2023 to expand digital use cases. Digital Agency's Digital Identity Wallet (Mynaportal wallet) integrating more services. Japan participating in international digital identity standardisation (ISO mDL); interoperability with EU EUDIW under discussion. |
| **Biometric Data Classification** | "Sensitive personal information" (youhairyo kojinjouhou) under APPI Art. 2(3) — includes fingerprints, vein patterns, facial recognition data; acquisition and use restrictions; explicit consent required. PPC guidelines on biometric data published 2022. |
| **Key Professional Bodies** | Japan Federation of Bar Associations (JFBA); Ministry of Justice (notaries — koshi system); Japan Medical Association; Japan Certified Public Accountants Association (JICPA) |

---

### South Korea (KR)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Personal Information Protection Act (PIPA, amended 2023 — significant restructuring, in force September 2023) + Act on Promotion of Information and Communications Network Utilization and Information Protection (Network Act — reduced in scope after PIPA 2023 amendments) |
| **Supervisory Authority** | Personal Information Protection Commission (PIPC) |
| **Consent Age (Digital)** | 14 years |
| **Age of Majority** | 19 years |
| **Breach Notification** | Within 72 hours to PIPC and affected individuals (PIPA Art. 34) |
| **Right to Erasure** | Yes — right to request deletion (PIPA Art. 36) |
| **Cross-Border Rules** | PIPA Art. 28-8 — consent, adequacy (PIPC decision), certification, or standard contract; data localisation for certain data categories |
| **Child Protection** | PIPA (legal representative consent under 14); Youth Protection Act; Act on the Protection of Children and Juveniles Against Sexual Abuse; Game Industry Promotion Act (online gaming shutdown rule for under-16, though modified) |
| **eSignature Status** | Digital Signature Act; Electronic Documents and Transactions Act; accredited certification system (Korea Internet and Security Agency — KISA) |
| **Age Verification Requirements** | Yes — Act on the Promotion of Youth Protection requires age verification for adult content and online games (via national ID or accredited identity verification service). KISA-accredited identity verification providers (KMC, NICE, etc.) are the standard mechanism. Mobile carrier identity verification widely used for age assurance. Significant data collection historically associated with Korean age verification (now under reform following PIPA 2023 amendments reducing mandatory real-name registration). |
| **Digital Identity Wallet Status** | Active — PASS (mobile identity verification) operated by mobile carriers; Ministry of Interior digital ID card (Resident Registration Card mobile version) launched 2024. Digital Government Act 2024 expanding digital credential use. |
| **Biometric Data Classification** | "Sensitive information" under PIPA Art. 23 — processing requires explicit consent or legal basis; biometric data used for identification subject to same restrictions as other sensitive categories. PIPC guidance published on facial recognition in commercial settings. |
| **Key Professional Bodies** | Korean Bar Association; Korean Medical Association; Korean Certified Public Accountant Association; Ministry of Justice (notaries) |

---

### Brazil (BR)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Lei Geral de Proteção de Dados (LGPD, Law No. 13,709/2018; administrative sanctions in force from 2021) |
| **Supervisory Authority** | Autoridade Nacional de Proteção de Dados (ANPD) |
| **Consent Age (Digital)** | 12 years (LGPD Art. 14 — children under 12 require specific parental/guardian consent; ages 12–17 may consent with parental/guardian consent for most processing) |
| **Age of Majority** | 18 years |
| **Breach Notification** | Within 3 business days to ANPD (ANPD Resolution CD/ANPD No. 2/2022); data subjects notified as determined by ANPD |
| **Right to Erasure** | Yes (LGPD Art. 18, V) |
| **Cross-Border Rules** | LGPD Art. 33 — adequacy decision by ANPD, SCCs, BCRs, consent, or other legal bases; ANPD published adequacy evaluation criteria in 2023 |
| **Child Protection** | LGPD Art. 14 — best interests of child; Statute of the Child and Adolescent (ECA, Law No. 8,069/1990); Marco Civil da Internet (parental consent for minors for data collection by apps) |
| **eSignature Status** | Medida Provisória 2,200-2/2001 (ICP-Brasil PKI); LGPD compatible electronic transactions; qualified digital certificates issued by ICP-Brasil certification authorities |
| **Age Verification Requirements** | No general online age verification mandate as of March 2026. Sector-specific: online gambling (age 18+, verification required by gaming regulation); social media — ANPD Nota Técnica 5/2023 recommending age verification for minors. Brazilian Congress debating child online safety legislation expanding on ECA requirements. |
| **Digital Identity Wallet Status** | Active — Gov.br digital identity (CONFIA/Identidade Gov.br); Identity Nacional (new national ID card, RG unification, expanding digital version). Banco Central's PIX open finance infrastructure being extended to digital identity. Full national digital identity wallet roadmap under Secretaria de Governo Digital (SGD). |
| **Biometric Data Classification** | "Sensitive personal data" under LGPD Art. 5, II — biometric data is listed as sensitive personal data; processing requires express consent or another specific LGPD Art. 11 basis; ANPD issuing implementing regulations. |
| **Key Professional Bodies** | Ordem dos Advogados do Brasil (OAB); Conselho Federal de Medicina (CFM); Colégio Notarial do Brasil |

---

### Mexico (MX)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP, 2010) + Reglamento (2011); reform initiative pending in Congress as of March 2026 |
| **Supervisory Authority** | Instituto Nacional de Transparencia, Acceso a la Información y Protección de Datos Personales (INAI) |
| **Consent Age (Digital)** | No specific digital consent age; parental consent for minors (under 18) |
| **Age of Majority** | 18 years |
| **Breach Notification** | "Immediately" to affected data subjects when the breach significantly affects economic or moral rights (LFPDPPP Art. 20); no INAI notification requirement in current law (reform pending) |
| **Right to Erasure** | Yes — ARCO rights (Access, Rectification, Cancellation, Opposition) including cancellation/deletion right |
| **Cross-Border Rules** | LFPDPPP Art. 36-37 — data recipient must assume LFPDPPP obligations; consent exception; contractual necessity |
| **Child Protection** | Ley General de los Derechos de Niñas, Niños y Adolescentes (LGDNNA); LFPDPPP (parental consent for minors); Código Penal Federal (child exploitation provisions) |
| **eSignature Status** | Código de Comercio (Art. 89–114); Ley de Firma Electrónica Avanzada (LFEA); advanced electronic signature recognised as equivalent to handwritten for most commercial acts |
| **Age Verification Requirements** | No general national mandate. Sector-specific: Ley Federal de Juegos y Sorteos (gambling, age 18+); SAT/SAT digital identity for financial services. Digital economy reform proposals under discussion in Congress include age verification for social media for minors. |
| **Digital Identity Wallet Status** | Early development — CURP digital (Clave Única de Registro de Población digital) via Gob.mx platform; SAT electronic signature (e.firma) for tax/legal matters. No integrated national digital identity wallet as of March 2026; infrastructure development ongoing under Secretaría de Hacienda y SEGOB. |
| **Biometric Data Classification** | "Sensitive personal data" under LFPDPPP Art. 3, VI — includes biometric data; heightened protections apply; explicit consent required except in specific cases; INAI has issued guidance on biometric data processing. |
| **Key Professional Bodies** | Barra Mexicana de Abogados (BMA); Asociación Nacional del Notariado Mexicano; Academia Nacional de Medicina |

---

### Argentina (AR)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Ley de Protección de Datos Personales (Law No. 25,326, 2000) + Decree 1558/2001; significant reform bill (Proyecto de Ley de Protección de Datos Personales 2023) pending in Congress, aimed at GDPR alignment |
| **Supervisory Authority** | Agencia de Acceso a la Información Pública (AAIP) |
| **Consent Age (Digital)** | No specific digital consent age; progressive autonomy principle (Código Civil y Comercial, Art. 26); AAIP recommends parental consent for under 13 |
| **Age of Majority** | 18 years |
| **Breach Notification** | No specific statutory timeline in current law (reform bill introduces 72-hour requirement); AAIP recommends prompt notification in current guidance |
| **Right to Erasure** | Yes (Law 25,326 Art. 16 — suppression; constitutional habeas data action) |
| **Cross-Border Rules** | Transfer to countries with adequate protection (AAIP adequacy list, aligned with EU standards); consent exception; other conditions under law |
| **Child Protection** | Law 26,061 (Comprehensive Protection of Children and Adolescents); Código Civil y Comercial (progressive autonomy, Art. 26); Ley 27,590 (Mica's Law — child sexual abuse in digital environments) |
| **eSignature Status** | Ley de Firma Digital (Law 25,506, 2001); digital signature with public key infrastructure (issued by licensed certification authorities under SIGEN) has full legal equivalence to handwritten signature |
| **Age Verification Requirements** | No general national mandate. Sector-specific: Ley 27,153 (national gambling, age 18+). Digital economy bill under development. AAIP has issued guidance on age-appropriate design for digital services targeting children. |
| **Digital Identity Wallet Status** | Moderate development — DNI digital (digital national identity document via Mi Argentina app, operated by Ministerio del Interior); RENAPER-issued digital identity widely used. National Digital Transformation Programme includes digital identity roadmap; interoperability with MERCOSUR partners being explored. |
| **Biometric Data Classification** | "Sensitive data" under Law 25,326 Art. 2 (includes biometric data used for identification); processing requires explicit consent or legal basis; AAIP supervision; reform bill aligns with GDPR Art. 9 structure. |
| **Key Professional Bodies** | Colegio Público de Abogados de la Capital Federal; Colegio de Escribanos (notaries); Confederación Médica de la República Argentina (COMRA) |

---

### India (IN)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Digital Personal Data Protection Act 2023 (DPDP Act); implementing rules (DPDP Rules) published for public consultation in January 2025 |
| **Supervisory Authority** | Data Protection Board of India (DPBI) — not yet constituted as of March 2026; MeitY exercising oversight |
| **Consent Age (Digital)** | 18 years (children defined as under 18); verifiable parental consent required for all children |
| **Age of Majority** | 18 years |
| **Breach Notification** | "Without delay" to DPBI and affected data principals; DPDP Rules to specify time frame (draft rules propose 72 hours for significant breaches) |
| **Right to Erasure** | Yes — right to erasure of personal data (DPDP Act Section 12) |
| **Cross-Border Rules** | DPDP Act Section 16 — transfer permitted except to countries notified by Central Government as restricted; whitelist/blacklist approach; implementing rules pending |
| **Child Protection** | DPDP Act — verifiable parental consent for all processing of children's data; prohibition on tracking, behavioural monitoring, and targeted advertising for children; significant data fiduciary obligations for child-focused services; Protection of Children from Sexual Offences (POCSO) Act |
| **eSignature Status** | Information Technology Act 2000 (s. 3A) — electronic signatures valid; Aadhaar-based e-sign widely used for government and commercial services |
| **Age Verification Requirements** | Yes — DPDP Act requires verifiable parental consent for processing data of users under 18, effectively mandating age verification for services targeting or likely to be accessed by children. Ministry of Electronics and Information Technology (MeitY) and Telecom Regulatory Authority of India (TRAI) developing age verification technical standards. |
| **Digital Identity Wallet Status** | Active — Aadhaar (1.4 billion enrolments) is the world's largest digital identity system; Aadhaar-based authentication, e-KYC, and face authentication widely used. DigiLocker (national digital document wallet, over 200 million users) issues digitally signed documents. ABHA (Ayushman Bharat Health Account) for health credentials. National Digital Identity architecture being expanded. |
| **Biometric Data Classification** | "Sensitive personal data" under IT (Reasonable Security Practices and Procedures and Sensitive Personal Data or Information) Rules 2011 — includes biometric data; processing requires explicit consent. Aadhaar biometrics governed separately by Aadhaar Act 2016; strict purpose limitation and authentication framework. DPDP Act 2023 treatment of biometrics to be addressed in implementing rules. |
| **Key Professional Bodies** | Bar Council of India + state bar councils; National Medical Commission (NMC); Indian Notary system (under Notaries Act 1952, appointed by state governments) |

---

### Singapore (SG)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Personal Data Protection Act 2012 (PDPA, amended 2020 — stronger breach notification, expanded consent framework, new legitimate interests basis) |
| **Supervisory Authority** | Personal Data Protection Commission (PDPC) |
| **Consent Age (Digital)** | No specific statutory digital consent age; capacity-based assessment; PDPC guidance applies |
| **Age of Majority** | 21 years (18 for some purposes including criminal responsibility) |
| **Breach Notification** | 3 calendar days to PDPC for notifiable breaches (PDPA s. 26C); "as soon as practicable" to affected individuals |
| **Right to Erasure** | Correction right (s. 22); no general erasure right; retention limitation obligation — organisations must cease retaining personal data when no longer necessary (s. 25) |
| **Cross-Border Rules** | PDPA s. 26 — comparable standard of protection; contractual arrangements; PDPC-approved binding corporate rules; listed countries under third schedule |
| **Child Protection** | PDPA (consent through parent/guardian for minors without capacity); Children and Young Persons Act 1993; Protection from Harassment Act 2014; POHA as amended 2019 |
| **eSignature Status** | Electronic Transactions Act (ETA, Cap. 88, revised 2010); electronic signatures generally valid; secure electronic signatures (complying with s. 18 ETA) have presumption of reliability |
| **Age Verification Requirements** | Yes — Broadcasting (Class Licence) Notification and IMDA Content Code for Online Safety (in force from 2024) require social media services with significant Singapore user base to implement age assurance measures for users under 18. Online safety directions may require specific platforms to prevent minors from accessing harmful content. |
| **Digital Identity Wallet Status** | Active — Singpass (national digital identity platform, operated by GovTech) has 4+ million users. SGFinDex enables cross-institution financial data sharing via Singpass. MyInfo (government-verified personal data) available to private sector through approved NDI (National Digital Identity) APIs. Singapore Verifiable Credentials framework under development aligned with W3C VCs. |
| **Biometric Data Classification** | No special category equivalent to GDPR Art. 9; biometric data treated as "personal data" under PDPA with same protections. However, PDPC advisory guidelines note heightened sensitivity of biometric data and recommend additional safeguards. |
| **Key Professional Bodies** | Law Society of Singapore; Singapore Medical Council (SMC); Singapore Academy of Law (commissioners for oaths / notaries public); ISCA (accountants) |

---

### United Arab Emirates (AE)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Federal Decree-Law No. 45 of 2021 on Personal Data Protection; DIFC Data Protection Law No. 5 of 2020; ADGM Data Protection Regulations 2021 |
| **Supervisory Authority** | UAE Data Office (federal — Abu Dhabi Government's UAE Data Office); DIFC Commissioner of Data Protection; ADGM Office of Data Protection |
| **Consent Age (Digital)** | No specific digital consent age in federal law; parental consent for minors; free zone laws do not specify age |
| **Age of Majority** | 21 years (civil transactions); 18 for some purposes |
| **Breach Notification** | "Without delay" to UAE Data Office (federal DL 45/2021 Art. 34); 72 hours in DIFC; "without undue delay" in ADGM |
| **Right to Erasure** | Yes (federal law Art. 10; DIFC Art. 22; ADGM Reg. 20) |
| **Cross-Border Rules** | Federal: adequate level of protection or contractual/consent-based mechanisms; DIFC: SCCs, adequacy, BCRs (GDPR-aligned); ADGM: similar to GDPR framework; Saudi-UAE Cross-Border Digital Economy Framework in development |
| **Child Protection** | Federal Child Rights Law (Wadeema's Law — Law No. 3 of 2016); Cybercrime Law No. 34 of 2021; Telecom Regulatory Authority (TRA) guidance on child safety online |
| **eSignature Status** | Federal Law No. 46 of 2021 on Electronic Transactions and Trust Services; electronic signatures valid; digital signatures from accredited trust service providers recognised |
| **Age Verification Requirements** | Yes — TRA Child Safety Standards (2020, updated 2023) require platforms to implement age verification for services not suitable for children. TDRA (Telecommunications and Digital Government Regulatory Authority, formerly TRA) issued Digital Age Verification Framework guidance in 2024. Online gaming and adult content platforms must verify user age. |
| **Digital Identity Wallet Status** | Active — UAE Pass (national digital identity and e-signature service) has over 7 million users; UAE Pass enables digital identity, document signing, and government service access. Abu Dhabi Digital Authority (ADDA) and Smart Dubai Office operating parallel digital identity infrastructure. UAE National Digital ID strategy being consolidated. |
| **Biometric Data Classification** | "Sensitive data" under federal DL 45/2021 (Art. 1) — biometric data for unique identification is sensitive; processing requires explicit consent or legal authorisation; UAE Data Office developing implementing guidance. DIFC and ADGM align with GDPR Art. 9 biometric classification. |
| **Key Professional Bodies** | Ministry of Justice (advocates and licensed notaries); DHA (Dubai Health Authority — medical); DoH (Department of Health Abu Dhabi — medical); MOHAP (Ministry of Health and Prevention — federal medical) |

---

### Saudi Arabia (SA)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Personal Data Protection Law (PDPL, Royal Decree M/19, 2021; Implementing Regulations published 2023, in force since September 2023) |
| **Supervisory Authority** | Saudi Data and Artificial Intelligence Authority (SDAIA); National Data Management Office (NDMO) |
| **Consent Age (Digital)** | No specific digital consent age; parental consent for minors |
| **Age of Majority** | 18 years |
| **Breach Notification** | Within 72 hours of awareness to SDAIA; notification to data subjects where high risk (PDPL Implementing Regulations Art. 19) |
| **Right to Erasure** | Yes (PDPL Art. 14 — right to request deletion; conditions apply) |
| **Cross-Border Rules** | PDPL Art. 29 — transfer with adequate protection; SDAIA adequacy framework being developed; sector-specific localisation requirements for government data; certain financial data localisation (SAMA, CITC rules) |
| **Child Protection** | Child Protection Act (Royal Decree M/14, 2014); PDPL (parental consent for minors); Communications, Space and Technology Commission (CST) child safety online regulations |
| **eSignature Status** | Electronic Transactions Law (Royal Decree M/18, 2007, updated); electronic signatures valid; accredited certification service providers under SDAIA/NCDC |
| **Age Verification Requirements** | Yes — Communications, Space and Technology Commission (CST) requirements for digital platforms; Saudi National Cybersecurity Authority (NCA) guidelines; gaming regulation (Games and Esports Commission, established 2021) requires age verification for in-game purchases for minors. Saudi Content Policy for online platforms requires restricted content to be age-gated. |
| **Digital Identity Wallet Status** | Active — Absher (national digital identity and government services platform, 24+ million users); Saudi National Digital Identity (NID) system; Nafath authentication service for government services. Digital Government Authority (DGA) developing national digital identity wallet aligned with SDAIA's National Data and AI Strategy. |
| **Biometric Data Classification** | "Sensitive personal data" under PDPL Art. 2 — includes biometric data; processing requires explicit consent or legal basis; Implementing Regulations require heightened security measures and DPIA for sensitive data. |
| **Key Professional Bodies** | Saudi Bar Association (est. 2022, licensed since 2023); Saudi Commission for Health Specialties (SCFHS — medical); Ministry of Justice (notary services through court system) |

---

### South Africa (ZA)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Protection of Personal Information Act 2013 (POPIA, fully in force from 1 July 2021) |
| **Supervisory Authority** | Information Regulator (South Africa) |
| **Consent Age (Digital)** | No specific digital consent age; POPIA s. 35 — "competent person" may consent; person under 18 requires parent/guardian consent for processing of personal information |
| **Age of Majority** | 18 years |
| **Breach Notification** | "As soon as reasonably possible" to Information Regulator and data subjects (POPIA s. 22) |
| **Right to Erasure** | Yes — right to deletion or destruction (POPIA s. 24) |
| **Cross-Border Rules** | POPIA s. 72 — adequate level of protection; data subject consent; contractual necessity; BCRs; Information Regulator binding agreements |
| **Child Protection** | POPIA s. 35 — restrictions on processing children's personal information (under 18); must be necessary, done with consent of competent person; Children's Act 2005; Film and Publications Act (age classification for online content) |
| **eSignature Status** | Electronic Communications and Transactions Act 2002 (ECTA); electronic signatures valid; advanced electronic signatures (meeting specific technical standards) required for certain documents |
| **Age Verification Requirements** | Yes — Film and Publications Act (FPA) as amended by Film and Publications Amendment Act 2019 (in force 2022): age verification required for online distribution of adult content (classified 18+); Film and Publications Board (FPB) oversight; social media platforms subject to registration and content moderation obligations. |
| **Digital Identity Wallet Status** | Moderate development — Home Affairs National Identification System (HANIS) with Smart ID card. Department of Home Affairs Digital Identity Wallet pilot announced in 2024 as part of Digital Transformation Strategy. SARS eFiling and other government services use digital identity. National digital identity wallet roadmap under development. |
| **Biometric Data Classification** | No special category equivalent to GDPR Art. 9 in POPIA; biometric data treated as "personal information" (POPIA s. 1 — "biometric information"). However, Information Regulator guidance classifies biometric data as highly sensitive requiring stringent Condition 7 (security safeguards) measures. |
| **Key Professional Bodies** | Law Society of South Africa (LSSA); Legal Practice Council (LPC); Health Professions Council of South Africa (HPCSA); South African Institute of Chartered Accountants (SAICA) |

---

### China (CN)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Personal Information Protection Law (PIPL, 2021) + Cybersecurity Law (CSL, 2017) + Data Security Law (DSL, 2021) + Regulations on the Management of Network Data Security (in force January 2025) |
| **Supervisory Authority** | Cyberspace Administration of China (CAC); MIIT (telecoms sector); SAMR (market regulation); sector-specific regulators |
| **Consent Age (Digital)** | 14 years (separate parental consent required for under-14; separate rules under minor users' protection provisions apply to under-18) |
| **Age of Majority** | 18 years |
| **Breach Notification** | "Immediately" to relevant authorities; notification to individuals if rights/interests may be affected (PIPL Art. 57); Regulations on Network Data Security specify enhanced obligations for critical data processors |
| **Right to Erasure** | Yes (PIPL Art. 47) |
| **Cross-Border Rules** | PIPL Art. 38–43 — CAC security assessment for transfers above thresholds, standard contracts (SCC filing with CAC from 2023), PIPC certification, or other conditions; data localisation for critical information infrastructure operators (CSL Art. 37) and large-scale personal information processors; CAC Measures on Standard Contracts for Personal Information Transfers Abroad (in force June 2023) |
| **Child Protection** | PIPL Art. 28 (minors under 14 as sensitive personal information); Provisions on the Protection of Minors in Cyberspace (2023); Minors Protection Law (2021 revision); Regulations on the Administration of Online Games restricting minors' gaming time; Provisions on the Treatment of Minors' Data mandating age verification |
| **eSignature Status** | Electronic Signature Law (2004, amended 2019); reliable electronic signatures have same legal effect as handwritten |
| **Age Verification Requirements** | Yes — one of the world's most comprehensive systems. Real-name registration requirement for internet services (CSL Art. 24); CAC Provisions on Online Minor Protection (2023) mandate age classification systems, minor mode (restrictions on minors), and parental consent/control tools for platforms; gaming platforms must verify age via National ID system; short-video platforms must detect minors via device identification and real-name binding. |
| **Digital Identity Wallet Status** | Active — Second Generation Resident Identity Card (eID) with embedded chip widely used. Ministry of Public Security's Online Identity Verification system used by major platforms for real-name registration. Alipay/WeChat digital ID integration. National Internet Identity (NII) system under development by MIIT and MPS; legislative framework for digital identity wallets under consultation. |
| **Biometric Data Classification** | "Sensitive personal information" (mingan gerenshinxi) under PIPL Art. 28(1) — explicitly includes biometric data; processing requires separate consent, necessity demonstration, and DPIA (PIPL Art. 29–30); additional restrictions in Provisions on the Management of Personal Information in Facial Recognition Technology (CAC, effective November 2024). |
| **Key Professional Bodies** | All China Lawyers Association (ACLA); Chinese Medical Association (CMA); Ministry of Justice notary system (gongzheng); Chinese Institute of Certified Public Accountants (CICPA) |

---

### Hong Kong (HK)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Personal Data (Privacy) Ordinance (PDPO, Cap. 486, amended 2021 — anti-doxxing provisions) |
| **Supervisory Authority** | Office of the Privacy Commissioner for Personal Data (PCPD) |
| **Consent Age (Digital)** | No specific statutory age; capacity-based assessment |
| **Age of Majority** | 18 years |
| **Breach Notification** | No mandatory statutory requirement; PCPD Guidance Note on Data Breach Handling and Notifications (2023) strongly recommends notification within 2 business days for serious breaches; voluntary code gaining practical status |
| **Right to Erasure** | Correction right (DPP 6); no general erasure right; retention limitation under DPP 2(2) |
| **Cross-Border Rules** | PDPO s. 33 (not yet commenced); PCPD recommends applying s. 33 adequacy standard on a voluntary basis; contractual safeguards; PCPD Guidance Note on Data Transfer (2022) |
| **Child Protection** | PDPO (general provisions); Protection of Children and Juveniles Ordinance; Crimes Ordinance; Film Censorship Ordinance |
| **eSignature Status** | Electronic Transactions Ordinance (ETO, Cap. 553, amended 2004); electronic signatures generally valid |
| **Age Verification Requirements** | Limited formal mandate. Film Censorship Ordinance (Category III films, 18+) imposes age verification for physical distribution; online distribution regulations being reviewed. Communications Authority (CA) co-regulator with OFCA for online content; no mandatory online age verification law as of March 2026. Hong Kong monitoring developments in mainland China and UK closely. |
| **Digital Identity Wallet Status** | Active — iAM Smart (national digital identity app for Hong Kong residents, operated by OGCIO — Office of the Government Chief Information Officer, launched 2020) has over 4 million registered users; enables e-form filling, e-payment, and identity verification for government and private sector services. e-Cert (digital certificates issued by Hongkong Post) for professional use. |
| **Biometric Data Classification** | No special category equivalent to GDPR; biometric data is "personal data" under PDPO with standard protections. PCPD has issued specific guidance on facial recognition as particularly sensitive personal data and recommended enhanced safeguards. |
| **Key Professional Bodies** | Law Society of Hong Kong (solicitors); Hong Kong Bar Association (barristers); Hong Kong Medical Council; Hong Kong Society of Notaries |

---

### Ireland (IE)

| Category | Details |
|----------|---------|
| **Data Protection Law** | GDPR + Data Protection Act 2018 |
| **Supervisory Authority** | Data Protection Commission (DPC) — lead supervisory authority for Meta, Google, Twitter/X, Apple, Microsoft, and most other major tech companies under GDPR one-stop-shop |
| **Consent Age (Digital)** | 16 years |
| **Age of Majority** | 18 years |
| **Breach Notification** | 72 hours to DPC; without undue delay to data subjects (if high risk) |
| **Right to Erasure** | Yes (GDPR Art. 17) |
| **Cross-Border Rules** | GDPR Chapter V; SCCs; adequacy decisions; BCRs |
| **Child Protection** | GDPR Art. 8 (16 years); Children First Act 2015; Child Care Act 1991 (amended); Online Safety and Media Regulation Act 2022 (OSMRA) — Coimisiún na Meán is the online safety regulator |
| **eSignature Status** | eIDAS Regulation; Electronic Commerce Act 2000; qualified electronic signatures fully recognised |
| **Age Verification Requirements** | Yes — Online Safety and Media Regulation Act 2022 (OSMRA) in force from March 2023. Coimisiún na Meán (Online Safety Commissioner) has powers to issue online safety codes requiring age verification for platforms hosting adult content or posing significant risks to children. Online Safety Code published 2024 with age verification obligations for designated online services. Ireland also hosting many platforms' EU headquarters means Irish enforcement has pan-EU significance. |
| **Digital Identity Wallet Status** | Active — EU EUDIW participant (EWC wallet consortium). Department of Social Protection operates MyGovID; Public Services Card (PSC) system being modernised. Revenue and DEASP digital identity programmes expanding. National Digital Identity Framework for Ireland under development as part of Programme for Government 2025 commitments. |
| **Biometric Data Classification** | Special category data under GDPR Art. 9; Data Protection Act 2018 Schedule 1 conditions for Art. 9(2) processing. DPC has issued enforcement decisions and guidance on biometric processing; CCTV and facial recognition guidance published. |
| **Key Professional Bodies** | Law Society of Ireland (solicitors); Bar of Ireland (barristers); Medical Council of Ireland; Faculty of Notaries Public in Ireland |

---

### Turkey (TR)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Kişisel Verilerin Korunması Kanunu (KVKK, Law No. 6698, 2016); significant amendment enacted June 2024 (Law No. 7524) — adds breach notification, updates transfer rules, aligns closer to GDPR |
| **Supervisory Authority** | Kişisel Verileri Koruma Kurumu (KVKK Authority — KVKK) |
| **Consent Age (Digital)** | No specific digital consent age; legal capacity rules apply (generally parental consent for under 18) |
| **Age of Majority** | 18 years |
| **Breach Notification** | Amendment (Law 7524, 2024): within 72 hours to KVKK; data subjects notified as soon as possible (aligned with GDPR) |
| **Right to Erasure** | Yes (KVKK Art. 7; Art. 11 — right to request deletion) |
| **Cross-Border Rules** | KVKK Art. 9 — amendment (2024): adequate protection (KVKK Board adequacy list); standard contracts (SCCs, Turkish version); binding corporate rules; consent (limited); KVKK Board developing adequacy country list |
| **Child Protection** | KVKK (parental consent for minors without legal capacity); Law on Protection of the Family and Prevention of Violence Against Women; Turkish Penal Code (child-specific provisions); Radio and Television Supreme Council (RTÜK) regulations on online broadcasting and child protection |
| **eSignature Status** | Electronic Signature Law (Law No. 5070, 2004); qualified electronic signatures have same legal effect as handwritten; BİLGEM (TÜBİTAK) accreditation system |
| **Age Verification Requirements** | Yes — RTÜK (Radio and Television Supreme Council) extended its jurisdiction to on-demand video streaming and certain online platforms in 2019–2020; age verification required for 18+ content on licensed platforms. Information Technologies and Communication Authority (BTK) enforces age verification for access to social media platforms under Law No. 7253 (2020). |
| **Digital Identity Wallet Status** | Active — e-Devlet Kapısı (e-Government portal, 70+ million users with TR ID); e-Devlet mobile app enables digital identity and document sharing. eID based on national ID number (TC Kimlik No). Turkey developing National Digital Wallet aligned with EU EUDIW principles as part of EU accession digital harmonisation programme. |
| **Biometric Data Classification** | "Special category of personal data" (özel nitelikli kişisel veri) under KVKK Art. 6 — explicitly includes biometric and genetic data; processing prohibited without explicit consent or legal authorisation; KVKK Board must issue regulations for certain biometric processing. |
| **Key Professional Bodies** | Union of Turkish Bar Associations (TBB); Turkish Medical Association (TTB); Turkish Notaries Union (TNB); Union of Chambers of Turkish Engineers and Architects (TMMOB) for specific engineering professions |

---

### Indonesia (ID)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Personal Data Protection Law (Undang-Undang Perlindungan Data Pribadi — UU PDP, Law No. 27 of 2022; 2-year transition period ends October 2024) |
| **Supervisory Authority** | Data Protection Authority (DPA) — to be established under President's regulations; currently Ministry of Communication and Digital (formerly Kominfo, renamed Komdigi 2024) |
| **Consent Age (Digital)** | 17 years or married under UU PDP Art. 4 (parental/guardian consent required for those under 17); civil majority varies (21 or married) |
| **Age of Majority** | 21 years (civil) or 17 years (various statutes); 18 years under Constitutional Court decision for political participation |
| **Breach Notification** | Within 3 × 24 hours (3 days) to supervisory authority and affected data subjects (UU PDP Art. 46) |
| **Right to Erasure** | Yes (UU PDP Art. 8 — right to delete or destroy personal data) |
| **Cross-Border Rules** | UU PDP Art. 56 — transfer to countries with equivalent level of protection; or appropriate safeguards; Presidential Regulation to specify conditions pending |
| **Child Protection** | UU PDP (parental/guardian consent for children under 17); Law on Child Protection (Law No. 23 of 2002, amended by Law No. 35 of 2014 and Government Regulation 2021); Electronic Information and Transactions Law (UU ITE, amended 2024) |
| **eSignature Status** | Government Regulation No. 71 of 2019 on Electronic Systems and Transactions; electronic signatures valid; certified electronic signatures through BSSN (National Cyber and Crypto Agency) registered providers |
| **Age Verification Requirements** | Yes — Government Regulation on Private Scope Electronic Systems and Transactions (PP 71/2019) and Ministry of Communication regulations require age verification for age-restricted content. Kominfo (now Komdigi) issued Circular requiring age verification for social media accounts. |
| **Digital Identity Wallet Status** | Active — Sistem Informasi Administrasi Kependudukan (SIAK) national ID system; e-KTP (electronic national ID card, Kartu Tanda Penduduk elektronik) issued by Ministry of Home Affairs (Dukcapil); GovTech Indonesia developing Satu Data Indonesia and national digital identity portal. INA Digital (digital identity integration programme) launched 2024. |
| **Biometric Data Classification** | "Specific personal data" (data pribadi yang bersifat spesifik) under UU PDP Art. 4(2) — includes biometric data; processing requires explicit consent and additional security; DPA oversight required for large-scale biometric processing. |
| **Key Professional Bodies** | PERADI (Perhimpunan Advokat Indonesia — Indonesian Advocates Association); Indonesian Medical Association (IDI — Ikatan Dokter Indonesia); Ministry of Law and Human Rights (notaries — appointed under Notary Law No. 30 of 2004) |

---

### Nigeria (NG)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Nigeria Data Protection Act 2023 (NDPA) — replaced NDPR; signed by President June 2023 |
| **Supervisory Authority** | Nigeria Data Protection Commission (NDPC) — established under NDPA |
| **Consent Age (Digital)** | No specific digital consent age; parental consent for minors |
| **Age of Majority** | 18 years (Child Rights Act); some states maintain 21 for certain purposes |
| **Breach Notification** | Within 72 hours to NDPC; "as soon as practicable" to affected data subjects (NDPA s. 40) |
| **Right to Erasure** | Yes (NDPA s. 34 — right to erasure/deletion) |
| **Cross-Border Rules** | NDPA s. 43 — adequate level of protection; contractual safeguards; consent; NDPC approved mechanisms; data localisation for "critical national information infrastructure" data |
| **Child Protection** | NDPA (parental consent for children); Child Rights Act 2003 (not adopted uniformly across all states); National Agency for the Prohibition of Trafficking in Persons (NAPTIP); NCC Consumer Code of Practice for online platforms |
| **eSignature Status** | Cybercrimes (Prohibition, Prevention, Etc.) Act 2015; Companies and Allied Matters Act 2020 (CAMA) — electronic documents and signatures recognised in commercial transactions |
| **Age Verification Requirements** | Emerging — National Information Technology Development Agency (NITDA) Draft Code of Practice for Interactive Computer Service Platforms (2022) includes age verification provisions; National Broadcasting Commission (NBC) and Nigerian Communications Commission (NCC) age restriction requirements for certain content; no comprehensive law as of March 2026. |
| **Digital Identity Wallet Status** | Active development — National Identity Management Commission (NIMC) National Identity Number (NIN) system with over 100 million enrolments; BVN (Bank Verification Number) biometric banking identity. NIMC Digital ID application (digital NIN slip). Federal Government's Digital Economy Policy includes national digital identity wallet. |
| **Biometric Data Classification** | NDPA does not explicitly list biometric data as a special category but treats it as sensitive personal data warranting heightened protection; NDPC issuing guidance in 2024–2025 sector regulations. NIN system itself is biometric-based. |
| **Key Professional Bodies** | Nigerian Bar Association (NBA); Nigerian Medical and Dental Council (NMDC); Supreme Court (notaries public — appointed by the Chief Justice) |

---

### Kenya (KE)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Data Protection Act 2019 (implemented in stages; Data Protection (General) Regulations 2021 in force) |
| **Supervisory Authority** | Office of the Data Protection Commissioner (ODPC) |
| **Consent Age (Digital)** | No specific digital consent age; parental consent for children (defined as under 18) |
| **Age of Majority** | 18 years |
| **Breach Notification** | Within 72 hours to ODPC; "as soon as practicable" to affected data subjects (Data Protection Act s. 43) |
| **Right to Erasure** | Yes (Data Protection Act s. 40 — right to erasure) |
| **Cross-Border Rules** | Data Protection Act s. 48-49 — adequate safeguards; appropriate legal mechanisms; consent; ODPC-approved binding corporate rules |
| **Child Protection** | Data Protection Act (parental consent for children under 18); Children Act 2022 (revised); Constitution of Kenya 2010 Art. 53 (children's rights); Film and Stage Plays Act (content classification) |
| **eSignature Status** | Kenya Information and Communications Act (KICA); electronic signatures recognised; ICT Authority developing qualified electronic signature framework |
| **Age Verification Requirements** | Limited formal mandate. Kenya Film Classification Board (KFCB) enforces content classification including online content; Gambling Control Act 2023 requires age verification for online gambling (18+); Communications Authority of Kenya developing child online safety guidelines including age verification. |
| **Digital Identity Wallet Status** | Active — Huduma Namba (National Integrated Identity Management System — NIIMS) being consolidated under Unique Personal Identifier; eCitizen government services portal. National Digital Identity (NDI) Programme under Ministry of ICT developing Maisha Namba (new National ID, replacing old National ID card); biometric-based, with digital wallet component. Kenya participating in AU digital identity interoperability discussions. |
| **Biometric Data Classification** | No explicit biometric special category under Data Protection Act 2019; biometric data treated as personal data with heightened sensitivity per ODPC guidance; NIIMS biometric database governed separately by the NIIMS Act and Constitutional Court scrutiny. |
| **Key Professional Bodies** | Law Society of Kenya (LSK); Kenya Medical Practitioners and Dentists Council (KMPDC); Kenya Notaries (appointed by High Court under the Notaries Public Act) |

---

### Israel (IL)

| Category | Details |
|----------|---------|
| **Data Protection Law** | Protection of Privacy Law 1981 (PPL) + Protection of Privacy Regulations (Data Security) 2017; new Protection of Privacy Law reform (2023 Knesset readings — significantly modernising framework towards GDPR alignment) pending final passage |
| **Supervisory Authority** | Privacy Protection Authority (PPA) — formerly Registrar of Databases, renamed and expanded powers |
| **Consent Age (Digital)** | No specific digital consent age; general capacity rules apply; parental consent for minors (under 18) |
| **Age of Majority** | 18 years |
| **Breach Notification** | "Immediately" to PPA for severe security incidents (Regulation 14 of Data Security Regulations 2017); notification to data subjects where required; reform law expected to introduce formal 72-hour timeline |
| **Right to Erasure** | Right to request deletion and correction under PPL (s. 14); limited compared to GDPR; reform law introduces stronger erasure right |
| **Cross-Border Rules** | PPA whitelist of countries with adequate protection (based substantially on EU adequacy decisions); consent; contractual safeguards; reform law introduces SCCs-style mechanism |
| **Child Protection** | PPL (parental consent for minors); Youth (Care and Supervision) Law 1960; Student Rights Law 2000; Prohibition of Child Pornography and Restriction of Sexual Material to Minors Law 1991; Communications Ministry child safety online regulations |
| **eSignature Status** | Electronic Signature Law 2001; electronic signatures valid; certified electronic signature from accredited certifying authority has higher evidentiary weight |
| **Age Verification Requirements** | Yes — Communications Ministry and Israel Internet Association (ISOC-IL) coordination on online safety; Prohibition of Child Pornography Law and related regulations require age verification for adult content; proposed Digital Services Act-like legislation under Ministry of Communications deliberation. |
| **Digital Identity Wallet Status** | Active — eGov digital identity services via Gov.il; Ministry of Interior digital ID (Teudat Zehut digital) expansion ongoing. Ramot digital identity project. Tel Aviv Digital Twin and Start-Up Nation innovation in digital identity space; national digital identity wallet roadmap under reform law development. |
| **Biometric Data Classification** | No GDPR-equivalent special category; biometric data treated as sensitive personal data under PPL requiring heightened security and specific database registration; PPA guidance on facial recognition published 2023. Reform law expected to introduce special category designation for biometrics aligned with GDPR Art. 9. |
| **Key Professional Bodies** | Israel Bar Association (IBA); Israel Medical Association (IMA); Ministry of Justice (notaries — restricted appointment system, approximately 150 notaries nationwide) |

---

## Summary Table

| Jurisdiction | Code | Data Protection Law | Digital Consent Age | Age of Majority | Breach Notification | Right to Erasure | Cross-Border Mechanism | Age Verification Mandate | Digital Identity Wallet | Biometric Classification |
|-------------|------|--------------------|--------------------|-----------------|---------------------|------------------|----------------------|--------------------------|------------------------|--------------------------|
| United Kingdom | GB | UK GDPR + DPA 2018 | 13 | 18 | 72 hours | Yes | IDTA / UK SCCs | Yes (Online Safety Act — Ofcom HEAA) | Active (GOV.UK Wallet) | Special category (UK GDPR Art. 9) |
| United States | US | CCPA/CPRA + state laws | 13 (COPPA) | 18 | Varies by state | Yes (state) | Limited / DPF | Partial (state laws, KOSA) | State mDLs (no federal wallet) | Varies by state (BIPA in IL; no federal) |
| France | FR | GDPR + Loi IL | 15 | 18 | 72 hours | Yes | GDPR SCCs | Yes (SREN — Arcom double-anonymity) | Active (France Identité / EUDIW) | Special category (GDPR Art. 9) |
| Germany | DE | GDPR + BDSG | 16 | 18 | 72 hours | Yes | GDPR SCCs | Yes (JMStV — KJM approved systems) | Active (eID / EUDIW) | Special category (GDPR Art. 9) |
| Spain | ES | GDPR + LOPDGDD | 14 | 18 | 72 hours | Yes | GDPR SCCs | Partial (DSA + proposed national) | Active (EUDIW / DNIe) | Special category (GDPR Art. 9) |
| Italy | IT | GDPR + D.Lgs 196/2003 | 14 | 18 | 72 hours | Yes | GDPR SCCs | Partial (DSA + Legge 71/2024) | Active (IT Wallet / EUDIW) | Special category (GDPR Art. 9) |
| Netherlands | NL | GDPR + UAVG | 16 | 18 | 72 hours | Yes | GDPR SCCs | Partial (DSA + sector-specific) | Active (DigiD / NLDIW) | Special category (GDPR Art. 9) |
| Canada | CA | PIPEDA + provincial | ~13/14 (guidance/QC) | 18/19 | ASAP / 72h (QC) | Limited | Accountability | Partial (C-63 pending) | Active (provincial schemes / PCTF) | Sensitive (no special category) |
| Australia | AU | Privacy Act 1988 | N/A (capacity) | 18 | 30 days | Limited | APP 8 | Yes (OSA under-16 ban — March 2025) | Active (myID / Digital ID Act 2024) | Sensitive (APP 3) |
| New Zealand | NZ | Privacy Act 2020 | N/A (capacity) | 18 | ASAP | Limited | IPP 12 | Partial (sector-specific) | Development (DISTF Act 2023) | Sensitive (Schedule 2) |
| Japan | JP | APPI | ~15 (guideline) | 18 | Promptly | Yes | APPI Art. 28 | Partial (sector-specific) | Active (My Number / Mynaportal) | Sensitive (APPI Art. 2(3)) |
| South Korea | KR | PIPA | 14 | 19 | 72 hours | Yes | PIPA Art. 28-8 | Yes (National ID verification for adult content) | Active (PASS / digital ID card) | Sensitive (PIPA Art. 23) |
| Brazil | BR | LGPD | 12 (with consent) | 18 | 3 business days | Yes | LGPD Art. 33 | Partial (sector-specific) | Active (Gov.br / DigiLocker equivalent) | Sensitive (LGPD Art. 5, II) |
| Mexico | MX | LFPDPPP | N/A (under 18 minor) | 18 | Immediately | Yes (ARCO) | Contractual | Partial (sector-specific) | Development (CURP digital) | Sensitive (LFPDPPP Art. 3, VI) |
| Argentina | AR | Law 25,326 | ~13 (guidance) | 18 | N/A (pending) | Yes | Adequacy list | Partial (sector-specific) | Moderate (DNI digital / Mi Argentina) | Sensitive (reform pending) |
| India | IN | DPDP Act 2023 | 18 | 18 | Without delay | Yes | Blacklist model | Yes (DPDP — verifiable parental consent) | Active (Aadhaar / DigiLocker) | Sensitive (IT Rules 2011; DPDP rules pending) |
| Singapore | SG | PDPA | N/A (capacity) | 21 | 3 days | Limited | PDPA s. 26 | Partial (IMDA Online Safety Code) | Active (Singpass / MyInfo) | Personal data (heightened guidance) |
| UAE | AE | Federal DL 45/2021 | N/A (minor) | 21 | Without delay | Yes | Adequacy / consent | Yes (TRA child safety / TDRA framework) | Active (UAE Pass) | Sensitive (DL 45/2021 Art. 1) |
| Saudi Arabia | SA | PDPL | N/A (minor) | 18 | 72 hours | Yes | Adequacy + rules | Partial (CST / gaming / content policy) | Active (Absher / Nafath) | Sensitive (PDPL Art. 2) |
| South Africa | ZA | POPIA | N/A (competency) | 18 | ASAP | Yes | POPIA s. 72 | Partial (FPB online / Film Act 2022) | Moderate (Home Affairs / Smart ID) | Personal info (heightened guidance) |
| China | CN | PIPL + CSL + DSL | 14 (under-14 separate) | 18 | Immediately | Yes | CAC security assessment | Yes (real-name + minor mode mandatory) | Active (eID / NII developing) | Sensitive (PIPL Art. 28; facial rec rules 2024) |
| Hong Kong | HK | PDPO | N/A (capacity) | 18 | Recommended (PCPD guidance) | Limited | S. 33 (not in force) | Limited (sector-specific review) | Active (iAM Smart) | Personal data (heightened PCPD guidance) |
| Ireland | IE | GDPR + DPA 2018 | 16 | 18 | 72 hours | Yes | GDPR SCCs | Yes (OSMRA — Coimisiún na Meán) | Active (MyGovID / EUDIW) | Special category (GDPR Art. 9) |
| Turkey | TR | KVKK | N/A (18 civil) | 18 | 72 hours (2024 amendment) | Yes | Board adequacy / SCCs | Partial (RTÜK / BTK) | Active (e-Devlet / developing wallet) | Special category (KVKK Art. 6) |
| Indonesia | ID | UU PDP | 17 (or married) | 21/17 | 72 hours | Yes | Equivalence | Partial (Komdigi / sector) | Active (e-KTP / INA Digital) | Specific (UU PDP Art. 4(2)) |
| Nigeria | NG | NDPA 2023 | N/A (minor) | 18 | 72 hours | Yes | Adequacy | Partial (NITDA draft) | Active development (NIMC NIN) | Sensitive (NDPC guidance) |
| Kenya | KE | DPA 2019 | N/A (minor) | 18 | 72 hours | Yes | Safeguards | Partial (KFCB / sector) | Active (Maisha Namba developing) | Personal data (ODPC guidance) |
| Israel | IL | Privacy Law 1981 | N/A (minor) | 18 | Immediately | Limited | Adequacy list | Partial (Communications Ministry) | Active (Gov.il / developing) | Sensitive (PPA guidance; reform pending) |

---

## Notes

1. **"N/A" in Consent Age** indicates the jurisdiction does not have a specific statutory digital consent age. In these cases, general capacity and parental authority rules apply.
2. **Professional bodies** listed are the primary national-level bodies. Many jurisdictions have additional state/provincial/regional bodies that may serve as Signet verifiers.
3. **eSignature status** summaries are simplified. Specific document types (wills, real estate, notarial acts) may have additional requirements in many jurisdictions.
4. **Cross-border rules** are subject to ongoing regulatory development. Check current guidance from the relevant supervisory authority.
5. **Age verification requirements** are evolving rapidly, particularly following Australia's under-16 social media ban (November 2024) and the UK Online Safety Act (Ofcom HEAA guidance 2024). Many jurisdictions are enacting or drafting similar measures.
6. **Digital identity wallets** are being implemented across most major jurisdictions as part of digital government strategies. EU member states are bound by the eIDAS 2.0 EUDIW timeline (wallet availability required by 2026). Non-EU countries are implementing national programmes on varying timescales.
7. **Biometric data classification** affects whether Signet implementations that use biometric elements (such as facial recognition for age assurance) would require special category processing consent. Signet's protocol-level architecture does not itself process biometrics; however, professional verifiers who use biometric ID verification tools during the countersigning process should be aware of their local biometric data obligations.
8. **This matrix does not cover** sector-specific regulations (e.g., financial services, healthcare, telecommunications, gaming) that may impose additional requirements beyond the general framework.

---

## EU eIDAS 2.0 Alignment Note

The EU's eIDAS 2.0 Regulation (EU 2024/1183, in force May 2024) requires all EU member states to offer a European Digital Identity Wallet (EUDIW) to citizens by 2026. The EUDIW architecture is based on selective disclosure credentials — the wallet holder can prove specific attributes (e.g., age above 18, professional qualification) without revealing the full underlying document.

**Signet Architecture Note — EU eIDAS 2.0:** Signet's Merkle proof architecture achieves the same selective disclosure property as eIDAS 2.0's PID (Person Identification Data) and attestation model. A Signet Persona credential discloses only the age range, while the Merkle root in the Natural Person credential allows any individual attribute to be proven independently. This is structurally equivalent to the ISO 18013-5 (mDL) and W3C Verifiable Credentials selective disclosure approaches that underpin EUDIW. Signet credentials could serve as a compliant additional layer atop a national EUDIW for Nostr-native identity assertions, without duplicating the wallet's data collection.

---

*This Compliance Matrix is provided as a reference guide for the Signet Protocol. It does not constitute legal advice. Signet Protocol recommends seeking qualified legal counsel familiar with the applicable laws in each jurisdiction before deployment.*

*Signet Protocol — v0.1.0*
*Document Version: 2.0*
*Last Updated: March 2026*
