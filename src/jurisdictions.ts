// Global Jurisdiction Registry for Signet Protocol
// Defines professional bodies, legal systems, data protection laws,
// and regulatory frameworks for 30+ jurisdictions worldwide.

// --- Types ---

export type LegalSystem = 'common-law' | 'civil-law' | 'mixed' | 'religious' | 'customary';

export type ProfessionType =
  | 'legal'
  | 'medical'
  | 'notary'
  | 'accounting'
  | 'engineering'
  | 'teaching'
  | 'financial'
  | 'veterinary'
  | 'pharmacy'
  | 'architecture'
  | 'social-work';

export interface ProfessionalBody {
  /** Short identifier, e.g. "law-society-ew" */
  id: string;
  /** Full name in original language */
  name: string;
  /** Full name in English (if different) */
  nameEn?: string;
  /** Profession type */
  profession: ProfessionType;
  /** Website URL */
  website: string;
  /** Whether the body maintains a public register that can be checked */
  hasPublicRegister: boolean;
  /** URL of the public register, if available */
  registerUrl?: string;
  /** Whether the body issues digital credentials */
  issuesDigitalCredentials: boolean;
  /** Notes about the body */
  notes?: string;
}

export interface DataProtectionLaw {
  /** Short name, e.g. "GDPR" */
  name: string;
  /** Full name */
  fullName: string;
  /** Year enacted */
  year: number;
  /** Whether explicit consent is required for data processing */
  requiresExplicitConsent: boolean;
  /** Minimum age for digital consent without parental approval */
  digitalConsentAge: number;
  /** Data breach notification deadline in hours (0 = no requirement) */
  breachNotificationHours: number;
  /** Right to erasure / right to be forgotten */
  rightToErasure: boolean;
  /** Data portability right */
  rightToPortability: boolean;
  /** Whether cross-border transfers are restricted */
  crossBorderRestrictions: boolean;
  /** Maximum data retention period in days (0 = no specific limit) */
  maxRetentionDays: number;
  /** Supervisory authority name */
  supervisoryAuthority: string;
  /** Notes about the law */
  notes?: string;
}

export interface ChildProtectionLaw {
  /** Law name */
  name: string;
  /** Minimum age for digital services without parental consent */
  minAgeDigitalConsent: number;
  /** Age of majority */
  ageOfMajority: number;
  /** Whether parental verifiable consent is required */
  requiresParentalConsent: boolean;
  /** Whether child data requires enhanced protections */
  enhancedProtections: boolean;
  /** Whether there are specific rules about profiling children */
  profilingRestrictions: boolean;
}

export interface Jurisdiction {
  /** ISO 3166-1 alpha-2 code */
  code: string;
  /** Country/region name in English */
  name: string;
  /** Country/region name in original language */
  nameLocal: string;
  /** Legal system type */
  legalSystem: LegalSystem;
  /** Primary language codes (ISO 639-1) */
  languages: string[];
  /** Currency code (ISO 4217) */
  currency: string;
  /** Professional bodies operating in this jurisdiction */
  professionalBodies: ProfessionalBody[];
  /** Data protection law */
  dataProtection: DataProtectionLaw;
  /** Child protection rules */
  childProtection: ChildProtectionLaw;
  /** Whether electronic signatures are legally recognized */
  eSignatureRecognised: boolean;
  /** Whether the jurisdiction has mutual recognition agreements */
  mutualRecognition: string[];
  /** Signet-specific notes */
  notes?: string;
}

// --- Professional Body Definitions ---

const UK_BODIES: ProfessionalBody[] = [
  {
    id: 'law-society-ew',
    name: 'The Law Society of England and Wales',
    profession: 'legal',
    website: 'https://www.lawsociety.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://solicitors.lawsociety.org.uk',
    issuesDigitalCredentials: false,
  },
  {
    id: 'law-society-scotland',
    name: 'Law Society of Scotland',
    profession: 'legal',
    website: 'https://www.lawscot.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.lawscot.org.uk/find-a-solicitor',
    issuesDigitalCredentials: false,
  },
  {
    id: 'law-society-ni',
    name: 'Law Society of Northern Ireland',
    profession: 'legal',
    website: 'https://www.lawsoc-ni.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'gmc-uk',
    name: 'General Medical Council',
    profession: 'medical',
    website: 'https://www.gmc-uk.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.gmc-uk.org/registration-and-licensing/the-medical-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'faculty-office-uk',
    name: 'Faculty Office of the Archbishop of Canterbury',
    profession: 'notary',
    website: 'https://www.facultyoffice.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.thenotariessociety.org.uk/find-a-notary',
    issuesDigitalCredentials: false,
  },
  {
    id: 'icaew',
    name: 'Institute of Chartered Accountants in England and Wales',
    profession: 'accounting',
    website: 'https://www.icaew.com',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'acca-uk',
    name: 'Association of Chartered Certified Accountants',
    profession: 'accounting',
    website: 'https://www.accaglobal.com',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'bsb-uk',
    name: 'Bar Standards Board',
    profession: 'legal',
    website: 'https://www.barstandardsboard.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.barstandardsboard.org.uk/barristers-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'nmc-uk',
    name: 'Nursing and Midwifery Council',
    profession: 'medical',
    website: 'https://www.nmc.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.nmc.org.uk/registration/search-the-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'gdc-uk',
    name: 'General Dental Council',
    profession: 'medical',
    website: 'https://www.gdc-uk.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.gdc-uk.org/registration/the-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'gphc-uk',
    name: 'General Pharmaceutical Council',
    profession: 'pharmacy',
    website: 'https://www.pharmacyregulation.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.pharmacyregulation.org/registers',
    issuesDigitalCredentials: false,
  },
  {
    id: 'hcpc-uk',
    name: 'Health and Care Professions Council',
    profession: 'medical',
    website: 'https://www.hcpc-uk.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.hcpc-uk.org/check-the-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'goc-uk',
    name: 'General Optical Council',
    profession: 'medical',
    website: 'https://www.optical.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.optical.org/check-the-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'gosc-uk',
    name: 'General Osteopathic Council',
    profession: 'medical',
    website: 'https://www.osteopathy.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.osteopathy.org.uk/visiting-an-osteopath/search-the-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'gcc-uk',
    name: 'General Chiropractic Council',
    profession: 'medical',
    website: 'https://www.gcc-uk.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.gcc-uk.org/find-a-chiropractor',
    issuesDigitalCredentials: false,
  },
  {
    id: 'rcvs-uk',
    name: 'Royal College of Veterinary Surgeons',
    profession: 'veterinary',
    website: 'https://www.rcvs.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://findavet.rcvs.org.uk',
    issuesDigitalCredentials: false,
  },
  {
    id: 'arb-uk',
    name: 'Architects Registration Board',
    profession: 'architecture',
    website: 'https://www.arb.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.arb.org.uk/architect-search',
    issuesDigitalCredentials: false,
  },
  {
    id: 'social-work-england',
    name: 'Social Work England',
    profession: 'social-work',
    website: 'https://www.socialworkengland.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.socialworkengland.org.uk/registration/search-the-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'eng-council-uk',
    name: 'Engineering Council',
    profession: 'engineering',
    website: 'https://www.engc.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.engc.org.uk/registrants',
    issuesDigitalCredentials: false,
  },
  {
    id: 'tra-uk',
    name: 'Teaching Regulation Agency',
    profession: 'teaching',
    website: 'https://www.gov.uk/government/organisations/teaching-regulation-agency',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'gtcs-uk',
    name: 'General Teaching Council for Scotland',
    profession: 'teaching',
    website: 'https://www.gtcs.org.uk',
    hasPublicRegister: true,
    registerUrl: 'https://www.gtcs.org.uk/registration/check-the-register',
    issuesDigitalCredentials: false,
  },
];

const US_BODIES: ProfessionalBody[] = [
  {
    id: 'aba-us',
    name: 'American Bar Association',
    profession: 'legal',
    website: 'https://www.americanbar.org',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'Voluntary membership organisation, NOT a statutory regulator. State bars (regulated by state supreme courts) are the actual licensing bodies. ABA accredits law schools.',
  },
  {
    id: 'ama-us',
    name: 'American Medical Association',
    profession: 'medical',
    website: 'https://www.ama-assn.org',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'Voluntary membership organisation, NOT a statutory regulator. State medical boards are the actual licensing bodies.',
  },
  {
    id: 'nna-us',
    name: 'National Notary Association',
    profession: 'notary',
    website: 'https://www.nationalnotary.org',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'Trade association, NOT a statutory regulator. Secretary of State offices in each state issue notary commissions.',
  },
  {
    id: 'aicpa-us',
    name: 'American Institute of Certified Public Accountants',
    profession: 'accounting',
    website: 'https://www.aicpa.org',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'Voluntary membership organisation, NOT a statutory regulator. State boards of accountancy are the actual licensing bodies.',
  },
  {
    id: 'ncees-us',
    name: 'National Council of Examiners for Engineering and Surveying',
    profession: 'engineering',
    website: 'https://ncees.org',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'PE licensing is state-level via state boards.',
  },
  {
    id: 'fsmb-us',
    name: 'Federation of State Medical Boards',
    profession: 'medical',
    website: 'https://www.fsmb.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.docinfo.org',
    issuesDigitalCredentials: false,
    notes: 'Coordinates state medical boards; maintains DocInfo physician verification database.',
  },
  {
    id: 'ncsbn-us',
    name: 'National Council of State Boards of Nursing',
    profession: 'medical',
    website: 'https://www.ncsbn.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.nursys.com',
    issuesDigitalCredentials: false,
    notes: 'Coordinates state nursing boards; maintains Nursys nurse verification database.',
  },
  {
    id: 'nabp-us',
    name: 'National Association of Boards of Pharmacy',
    profession: 'pharmacy',
    website: 'https://nabp.pharmacy',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Coordinates state pharmacy boards; administers NAPLEX licensing exam.',
  },
  {
    id: 'ncarb-us',
    name: 'National Council of Architectural Registration Boards',
    profession: 'architecture',
    website: 'https://www.ncarb.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.ncarb.org/verify',
    issuesDigitalCredentials: true,
    notes: 'Coordinates state architecture boards; issues NCARB Certificate for license reciprocity.',
  },
];

const EU_FRANCE_BODIES: ProfessionalBody[] = [
  {
    id: 'cnb-fr',
    name: 'Conseil National des Barreaux',
    nameEn: 'National Bar Council of France',
    profession: 'legal',
    website: 'https://www.cnb.avocat.fr',
    hasPublicRegister: true,
    registerUrl: 'https://www.cnb.avocat.fr/annuaire-des-avocats',
    issuesDigitalCredentials: false,
  },
  {
    id: 'cnom-fr',
    name: 'Conseil National de l\'Ordre des Médecins',
    nameEn: 'National Council of the Order of Physicians',
    profession: 'medical',
    website: 'https://www.conseil-national.medecin.fr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'csn-fr',
    name: 'Conseil Supérieur du Notariat',
    nameEn: 'Superior Council of Notaries',
    profession: 'notary',
    website: 'https://www.notaires.fr',
    hasPublicRegister: true,
    registerUrl: 'https://www.notaires.fr/fr/annuaire-notaire',
    issuesDigitalCredentials: false,
  },
  {
    id: 'oec-fr',
    name: 'Ordre des Experts-Comptables',
    nameEn: 'Order of Chartered Accountants',
    profession: 'accounting',
    website: 'https://www.experts-comptables.fr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'oni-fr',
    name: 'Ordre National des Infirmiers',
    nameEn: 'National Order of Nurses',
    profession: 'medical',
    website: 'https://www.ordre-infirmiers.fr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body established by Law 2006-1668. Maintains national register of nurses.',
  },
  {
    id: 'oncd-fr',
    name: 'Ordre National des Chirurgiens-Dentistes',
    nameEn: 'National Order of Dental Surgeons',
    profession: 'medical',
    website: 'https://www.ordre-chirurgiens-dentistes.fr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Code de la santé publique.',
  },
  {
    id: 'cnop-fr',
    name: 'Conseil National de l\'Ordre des Pharmaciens',
    nameEn: 'National Council of the Order of Pharmacists',
    profession: 'pharmacy',
    website: 'https://www.ordre.pharmacien.fr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Code de la santé publique.',
  },
  {
    id: 'cnoa-fr',
    name: 'Conseil National de l\'Ordre des Architectes',
    nameEn: 'National Council of the Order of Architects',
    profession: 'architecture',
    website: 'https://www.architectes.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.architectes.org/annuaire-des-architectes',
    issuesDigitalCredentials: false,
    notes: 'Statutory body established by Law 77-2 of 3 January 1977.',
  },
  {
    id: 'onpp-fr',
    name: 'Ordre National des Pédicures-Podologues',
    nameEn: 'National Order of Podiatrists',
    profession: 'medical',
    website: 'https://www.onpp.fr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Code de la santé publique.',
  },
];

const EU_GERMANY_BODIES: ProfessionalBody[] = [
  {
    id: 'brak-de',
    name: 'Bundesrechtsanwaltskammer',
    nameEn: 'German Federal Bar Association',
    profession: 'legal',
    website: 'https://www.brak.de',
    hasPublicRegister: true,
    registerUrl: 'https://www.rechtsanwaltsregister.org',
    issuesDigitalCredentials: false,
  },
  {
    id: 'baek-de',
    name: 'Bundesärztekammer',
    nameEn: 'German Medical Association',
    profession: 'medical',
    website: 'https://www.bundesaerztekammer.de',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'bnotk-de',
    name: 'Bundesnotarkammer',
    nameEn: 'German Federal Chamber of Notaries',
    profession: 'notary',
    website: 'https://www.bnotk.de',
    hasPublicRegister: true,
    registerUrl: 'https://www.notar.de',
    issuesDigitalCredentials: true,
    notes: 'Issues beA (besonderes elektronisches Anwaltspostfach) digital identities.',
  },
  {
    id: 'wpk-de',
    name: 'Wirtschaftsprüferkammer',
    nameEn: 'Chamber of Public Auditors',
    profession: 'accounting',
    website: 'https://www.wpk.de',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'bzaek-de',
    name: 'Bundeszahnärztekammer',
    nameEn: 'German Federal Dental Chamber',
    profession: 'medical',
    website: 'https://www.bzaek.de',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Federal umbrella for 17 state dental chambers (Landeszahnärztekammern).',
  },
  {
    id: 'abda-de',
    name: 'Bundesvereinigung Deutscher Apothekerverbände',
    nameEn: 'Federal Union of German Associations of Pharmacists',
    profession: 'pharmacy',
    website: 'https://www.abda.de',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Coordinates state pharmacy chambers (Landesapothekerkammern). Pharmacist registration is at state level.',
  },
  {
    id: 'bak-de',
    name: 'Bundesarchitektenkammer',
    nameEn: 'Federal Chamber of German Architects',
    profession: 'architecture',
    website: 'https://www.bak.de',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Federal umbrella for 16 state chambers of architects (Architektenkammern).',
  },
  {
    id: 'bingk-de',
    name: 'Bundesingenieurkammer',
    nameEn: 'Federal Chamber of German Engineers',
    profession: 'engineering',
    website: 'https://bingk.de',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Federal umbrella for 16 state chambers of engineers (Ingenieurkammern).',
  },
];

const EU_SPAIN_BODIES: ProfessionalBody[] = [
  {
    id: 'cgae-es',
    name: 'Consejo General de la Abogacía Española',
    nameEn: 'General Council of Spanish Lawyers',
    profession: 'legal',
    website: 'https://www.abogacia.es',
    hasPublicRegister: true,
    registerUrl: 'https://www.abogacia.es/servicios/censo-de-letrados',
    issuesDigitalCredentials: false,
  },
  {
    id: 'cgcom-es',
    name: 'Consejo General de Colegios Oficiales de Médicos',
    nameEn: 'General Council of Official Colleges of Physicians',
    profession: 'medical',
    website: 'https://www.cgcom.es',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'cgn-es',
    name: 'Consejo General del Notariado',
    nameEn: 'General Council of Notaries',
    profession: 'notary',
    website: 'https://www.notariado.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'cgcof-es',
    name: 'Consejo General de Colegios Oficiales de Farmacéuticos',
    nameEn: 'General Council of Official Colleges of Pharmacists',
    profession: 'pharmacy',
    website: 'https://www.portalfarma.com',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under Spanish law coordinating 52 provincial pharmacy colleges.',
  },
  {
    id: 'cgode-es',
    name: 'Consejo General de Dentistas de España',
    nameEn: 'General Council of Dentists of Spain',
    profession: 'medical',
    website: 'https://www.consejodentistas.es',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body coordinating provincial dental colleges.',
  },
  {
    id: 'cscae-es',
    name: 'Consejo Superior de los Colegios de Arquitectos de España',
    nameEn: 'Superior Council of Colleges of Architects of Spain',
    profession: 'architecture',
    website: 'https://www.cscae.com',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body coordinating regional colleges of architects.',
  },
  {
    id: 'cge-es',
    name: 'Consejo General de Enfermería de España',
    nameEn: 'General Council of Nursing of Spain',
    profession: 'medical',
    website: 'https://www.consejogeneralenfermeria.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body coordinating 52 provincial nursing colleges.',
  },
  {
    id: 'cgcii-es',
    name: 'Consejo General de Colegios de Ingeniería Industrial',
    nameEn: 'General Council of Colleges of Industrial Engineering',
    profession: 'engineering',
    website: 'https://www.cgcoii.es',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body coordinating provincial industrial engineering colleges. Multiple engineering branches have separate Colegios.',
  },
];

const EU_ITALY_BODIES: ProfessionalBody[] = [
  {
    id: 'cnf-it',
    name: 'Consiglio Nazionale Forense',
    nameEn: 'National Bar Council',
    profession: 'legal',
    website: 'https://www.consiglionazionaleforense.it',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'fnomceo-it',
    name: 'Federazione Nazionale degli Ordini dei Medici Chirurghi e degli Odontoiatri',
    nameEn: 'National Federation of Orders of Surgeons and Dentists',
    profession: 'medical',
    website: 'https://www.fnomceo.it',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'cnn-it',
    name: 'Consiglio Nazionale del Notariato',
    nameEn: 'National Council of Notaries',
    profession: 'notary',
    website: 'https://www.notariato.it',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'fnopi-it',
    name: 'Federazione Nazionale Ordini Professioni Infermieristiche',
    nameEn: 'National Federation of Nursing Professional Orders',
    profession: 'medical',
    website: 'https://www.fnopi.it',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body established by Law 3/2018. Coordinates 102 provincial nursing orders.',
  },
  {
    id: 'cnappc-it',
    name: 'Consiglio Nazionale degli Architetti, Pianificatori, Paesaggisti e Conservatori',
    nameEn: 'National Council of Architects, Planners, Landscape Architects and Conservators',
    profession: 'architecture',
    website: 'https://www.awn.it',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body coordinating 105 provincial Orders of Architects.',
  },
  {
    id: 'cndcec-it',
    name: 'Consiglio Nazionale dei Dottori Commercialisti e degli Esperti Contabili',
    nameEn: 'National Council of Chartered Accountants and Accounting Experts',
    profession: 'accounting',
    website: 'https://www.commercialisti.it',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under D.Lgs. 139/2005.',
  },
  {
    id: 'fofi-it',
    name: 'Federazione Ordini Farmacisti Italiani',
    nameEn: 'Federation of Italian Pharmacists Orders',
    profession: 'pharmacy',
    website: 'https://www.fofi.it',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body coordinating provincial pharmacy orders.',
  },
  {
    id: 'cni-it',
    name: 'Consiglio Nazionale degli Ingegneri',
    nameEn: 'National Council of Engineers',
    profession: 'engineering',
    website: 'https://www.tuttoingegnere.it',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body coordinating 106 provincial Orders of Engineers.',
  },
];

const EU_NETHERLANDS_BODIES: ProfessionalBody[] = [
  {
    id: 'nova-nl',
    name: 'Nederlandse Orde van Advocaten',
    nameEn: 'Netherlands Bar Association',
    profession: 'legal',
    website: 'https://www.advocatenorde.nl',
    hasPublicRegister: true,
    registerUrl: 'https://www.advocatenorde.nl/zoek-een-advocaat',
    issuesDigitalCredentials: false,
  },
  {
    id: 'knmg-nl',
    name: 'Koninklijke Nederlandsche Maatschappij tot bevordering der Geneeskunst',
    nameEn: 'Royal Dutch Medical Association',
    profession: 'medical',
    website: 'https://www.knmg.nl',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'knb-nl',
    name: 'Koninklijke Notariële Beroepsorganisatie',
    nameEn: 'Royal Dutch Notarial Organisation',
    profession: 'notary',
    website: 'https://www.knb.nl',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'big-nl',
    name: 'BIG-register',
    nameEn: 'Individual Healthcare Professions Register',
    profession: 'medical',
    website: 'https://www.bigregister.nl',
    hasPublicRegister: true,
    registerUrl: 'https://www.bigregister.nl/zoek-zorgverlener',
    issuesDigitalCredentials: false,
    notes: 'Central register under the Wet BIG (Individual Healthcare Professions Act). Covers physicians, dentists, pharmacists, nurses, midwives, physiotherapists, psychologists, and psychotherapists.',
  },
  {
    id: 'knmp-nl',
    name: 'Koninklijke Nederlandse Maatschappij ter bevordering der Pharmacie',
    nameEn: 'Royal Dutch Pharmacists Association',
    profession: 'pharmacy',
    website: 'https://www.knmp.nl',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Professional body for pharmacists. Registration is via the BIG-register.',
  },
  {
    id: 'architectenregister-nl',
    name: 'Bureau Architectenregister',
    nameEn: 'Bureau of the Architects Register',
    profession: 'architecture',
    website: 'https://www.architectenregister.nl',
    hasPublicRegister: true,
    registerUrl: 'https://www.architectenregister.nl/zoeken',
    issuesDigitalCredentials: false,
    notes: 'Statutory register under the Architects Title Act (Wet op de architectentitel).',
  },
  {
    id: 'nba-nl',
    name: 'Nederlandse Beroepsorganisatie van Accountants',
    nameEn: 'Netherlands Institute of Chartered Accountants',
    profession: 'accounting',
    website: 'https://www.nba.nl',
    hasPublicRegister: true,
    registerUrl: 'https://www.nba.nl/zoek-een-accountant',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Wet op het accountantsberoep (Accountants Profession Act).',
  },
];

const CANADA_BODIES: ProfessionalBody[] = [
  {
    id: 'lso-ca',
    name: 'Law Society of Ontario',
    profession: 'legal',
    website: 'https://lso.ca',
    hasPublicRegister: true,
    registerUrl: 'https://lso.ca/public-resources/finding-a-lawyer-or-paralegal',
    issuesDigitalCredentials: false,
    notes: 'Each province has its own law society.',
  },
  {
    id: 'cma-ca',
    name: 'Canadian Medical Association',
    profession: 'medical',
    website: 'https://www.cma.ca',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'Voluntary advocacy body, NOT a statutory regulator. Provincial Colleges of Physicians and Surgeons are the actual licensing bodies.',
  },
  {
    id: 'cpa-canada',
    name: 'Chartered Professional Accountants of Canada',
    profession: 'accounting',
    website: 'https://www.cpacanada.ca',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'engineers-ca',
    name: 'Engineers Canada',
    profession: 'engineering',
    website: 'https://engineerscanada.ca',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'National coordination body. Licensing is provincial via PEOs.',
  },
  {
    id: 'cpso-ca',
    name: 'College of Physicians and Surgeons of Ontario',
    profession: 'medical',
    website: 'https://www.cpso.on.ca',
    hasPublicRegister: true,
    registerUrl: 'https://doctors.cpso.on.ca',
    issuesDigitalCredentials: false,
    notes: 'Statutory regulator for physicians in Ontario. Each province has its own College.',
  },
  {
    id: 'cno-ca',
    name: 'College of Nurses of Ontario',
    profession: 'medical',
    website: 'https://www.cno.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.cno.org/en/find-a-nurse',
    issuesDigitalCredentials: false,
    notes: 'Statutory regulator for nurses in Ontario. Each province has its own nursing college.',
  },
  {
    id: 'chambre-notaires-qc',
    name: 'Chambre des notaires du Québec',
    nameEn: 'Chamber of Notaries of Quebec',
    profession: 'notary',
    website: 'https://www.cnq.org',
    hasPublicRegister: true,
    registerUrl: 'https://www.cnq.org/en/find-a-notary.html',
    issuesDigitalCredentials: false,
    notes: 'Statutory regulator for notaries in Quebec under the Professional Code.',
  },
  {
    id: 'oaq-ca',
    name: 'Ordre des architectes du Québec',
    nameEn: 'Order of Architects of Quebec',
    profession: 'architecture',
    website: 'https://www.oaq.com',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory regulator for architects in Quebec. Other provinces have similar bodies.',
  },
  {
    id: 'peo-ca',
    name: 'Professional Engineers Ontario',
    profession: 'engineering',
    website: 'https://www.peo.on.ca',
    hasPublicRegister: true,
    registerUrl: 'https://www.peo.on.ca/public-register',
    issuesDigitalCredentials: false,
    notes: 'Statutory regulator for engineers in Ontario under the Professional Engineers Act.',
  },
];

const AUSTRALIA_BODIES: ProfessionalBody[] = [
  {
    id: 'lca-au',
    name: 'Law Council of Australia',
    profession: 'legal',
    website: 'https://www.lawcouncil.asn.au',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'Each state/territory has its own law society.',
  },
  {
    id: 'ahpra-au',
    name: 'Australian Health Practitioner Regulation Agency',
    profession: 'medical',
    website: 'https://www.ahpra.gov.au',
    hasPublicRegister: true,
    registerUrl: 'https://www.ahpra.gov.au/Registration/Registers-of-Practitioners.aspx',
    issuesDigitalCredentials: false,
  },
  {
    id: 'cpa-au',
    name: 'CPA Australia',
    profession: 'accounting',
    website: 'https://www.cpaaustralia.com.au',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'ca-anz',
    name: 'Chartered Accountants Australia and New Zealand',
    profession: 'accounting',
    website: 'https://www.charteredaccountantsanz.com',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'ea-au',
    name: 'Engineers Australia',
    profession: 'engineering',
    website: 'https://www.engineersaustralia.org.au',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'aaca-au',
    name: 'Architects Accreditation Council of Australia',
    profession: 'architecture',
    website: 'https://www.aaca.org.au',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'National standards body; state/territory boards handle registration.',
  },
  {
    id: 'avbc-au',
    name: 'Australasian Veterinary Boards Council',
    profession: 'veterinary',
    website: 'https://avbc.asn.au',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Coordinates state/territory veterinary boards.',
  },
  {
    id: 'asic-au',
    name: 'Australian Securities and Investments Commission',
    profession: 'accounting',
    website: 'https://www.asic.gov.au',
    hasPublicRegister: true,
    registerUrl: 'https://www.asic.gov.au/online-services/search-asic-registers',
    issuesDigitalCredentials: false,
    notes: 'Registers company auditors and liquidators under the Corporations Act 2001.',
  },
];

const NEW_ZEALAND_BODIES: ProfessionalBody[] = [
  {
    id: 'nzls',
    name: 'New Zealand Law Society',
    profession: 'legal',
    website: 'https://www.lawsociety.org.nz',
    hasPublicRegister: true,
    registerUrl: 'https://www.lawsociety.org.nz/for-the-community/find-a-lawyer',
    issuesDigitalCredentials: false,
  },
  {
    id: 'mcnz',
    name: 'Medical Council of New Zealand',
    profession: 'medical',
    website: 'https://www.mcnz.org.nz',
    hasPublicRegister: true,
    registerUrl: 'https://www.mcnz.org.nz/registration/register-of-doctors',
    issuesDigitalCredentials: false,
  },
  {
    id: 'ncnz',
    name: 'Nursing Council of New Zealand',
    profession: 'medical',
    website: 'https://www.nursingcouncil.org.nz',
    hasPublicRegister: true,
    registerUrl: 'https://www.nursingcouncil.org.nz/public/Find-a-nurse',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Health Practitioners Competence Assurance Act 2003.',
  },
  {
    id: 'dcnz',
    name: 'Dental Council of New Zealand',
    profession: 'medical',
    website: 'https://www.dcnz.org.nz',
    hasPublicRegister: true,
    registerUrl: 'https://www.dcnz.org.nz/practitioners/search-the-register',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the HPCA Act 2003.',
  },
  {
    id: 'pcnz',
    name: 'Pharmacy Council of New Zealand',
    profession: 'pharmacy',
    website: 'https://www.pharmacycouncil.org.nz',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the HPCA Act 2003.',
  },
  {
    id: 'vcnz',
    name: 'Veterinary Council of New Zealand',
    profession: 'veterinary',
    website: 'https://www.vetcouncil.org.nz',
    hasPublicRegister: true,
    registerUrl: 'https://www.vetcouncil.org.nz/public-register',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Veterinarians Act 2005.',
  },
  {
    id: 'nzrab',
    name: 'New Zealand Registered Architects Board',
    profession: 'architecture',
    website: 'https://www.nzrab.nz',
    hasPublicRegister: true,
    registerUrl: 'https://www.nzrab.nz/architect-search',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Registered Architects Act 2005.',
  },
];

const JAPAN_BODIES: ProfessionalBody[] = [
  {
    id: 'jfba-jp',
    name: '日本弁護士連合会',
    nameEn: 'Japan Federation of Bar Associations',
    profession: 'legal',
    website: 'https://www.nichibenren.or.jp',
    hasPublicRegister: true,
    registerUrl: 'https://www.nichibenren.or.jp/bar_search',
    issuesDigitalCredentials: false,
  },
  {
    id: 'jma-jp',
    name: '日本医師会',
    nameEn: 'Japan Medical Association',
    profession: 'medical',
    website: 'https://www.med.or.jp',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
  },
  {
    id: 'jnna-jp',
    name: '日本公証人連合会',
    nameEn: 'Japan National Notaries Association',
    profession: 'notary',
    website: 'https://www.koshonin.gr.jp',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'jicpa-jp',
    name: '日本公認会計士協会',
    nameEn: 'Japanese Institute of Certified Public Accountants',
    profession: 'accounting',
    website: 'https://jicpa.or.jp',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'mhlw-nurse-jp',
    name: '厚生労働省 看護師免許',
    nameEn: 'Ministry of Health, Labour and Welfare — Nursing Licence',
    profession: 'medical',
    website: 'https://www.mhlw.go.jp',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Nursing licences issued directly by MHLW under the Act on Public Health Nurses, Midwives and Nurses.',
  },
  {
    id: 'mhlw-dental-jp',
    name: '厚生労働省 歯科医師免許',
    nameEn: 'Ministry of Health, Labour and Welfare — Dental Licence',
    profession: 'medical',
    website: 'https://www.mhlw.go.jp',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Dental licences issued by MHLW under the Dentist Act.',
  },
  {
    id: 'mhlw-pharma-jp',
    name: '厚生労働省 薬剤師免許',
    nameEn: 'Ministry of Health, Labour and Welfare — Pharmacist Licence',
    profession: 'pharmacy',
    website: 'https://www.mhlw.go.jp',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Pharmacist licences issued by MHLW under the Pharmacists Act.',
  },
  {
    id: 'mlit-arch-jp',
    name: '国土交通省 建築士免許',
    nameEn: 'Ministry of Land, Infrastructure, Transport and Tourism — Architect Licence',
    profession: 'architecture',
    website: 'https://www.mlit.go.jp',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Architect licences issued under the Architects Act. Administered via prefectural governors and MLIT.',
  },
];

const SOUTH_KOREA_BODIES: ProfessionalBody[] = [
  {
    id: 'kba-kr',
    name: '대한변호사협회',
    nameEn: 'Korean Bar Association',
    profession: 'legal',
    website: 'https://www.koreanbar.or.kr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'kma-kr',
    name: '대한의사협회',
    nameEn: 'Korean Medical Association',
    profession: 'medical',
    website: 'https://www.kma.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'kicpa-kr',
    name: '한국공인회계사회',
    nameEn: 'Korean Institute of Certified Public Accountants',
    profession: 'accounting',
    website: 'https://www.kicpa.or.kr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'kona-kr',
    name: '대한간호협회',
    nameEn: 'Korean Nurses Association',
    profession: 'medical',
    website: 'https://www.koreanurse.or.kr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Nursing licences issued by Ministry of Health and Welfare under the Medical Service Act.',
  },
  {
    id: 'kda-kr',
    name: '대한치과의사협회',
    nameEn: 'Korean Dental Association',
    profession: 'medical',
    website: 'https://www.kda.or.kr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Dental licences issued by Ministry of Health and Welfare under the Medical Service Act.',
  },
  {
    id: 'kpa-kr',
    name: '대한약사회',
    nameEn: 'Korean Pharmaceutical Association',
    profession: 'pharmacy',
    website: 'https://www.kpanet.or.kr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Pharmacist licences issued by Ministry of Health and Welfare under the Pharmaceutical Affairs Act.',
  },
  {
    id: 'kira-kr',
    name: '대한건축사협회',
    nameEn: 'Korean Institute of Registered Architects',
    profession: 'architecture',
    website: 'https://www.kira.or.kr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Architects Act. Registration administered by MOLIT.',
  },
];

const BRAZIL_BODIES: ProfessionalBody[] = [
  {
    id: 'oab-br',
    name: 'Ordem dos Advogados do Brasil',
    nameEn: 'Brazilian Bar Association',
    profession: 'legal',
    website: 'https://www.oab.org.br',
    hasPublicRegister: true,
    registerUrl: 'https://cna.oab.org.br',
    issuesDigitalCredentials: true,
    notes: 'Issues OAB digital certificate via ICP-Brasil.',
  },
  {
    id: 'cfm-br',
    name: 'Conselho Federal de Medicina',
    nameEn: 'Federal Council of Medicine',
    profession: 'medical',
    website: 'https://portal.cfm.org.br',
    hasPublicRegister: true,
    registerUrl: 'https://portal.cfm.org.br/busca-medicos',
    issuesDigitalCredentials: true,
  },
  {
    id: 'cnb-br',
    name: 'Colégio Notarial do Brasil',
    nameEn: 'Notarial College of Brazil',
    profession: 'notary',
    website: 'https://www.notariado.org.br',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
  },
  {
    id: 'cfc-br',
    name: 'Conselho Federal de Contabilidade',
    nameEn: 'Federal Council of Accounting',
    profession: 'accounting',
    website: 'https://cfc.org.br',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'cofen-br',
    name: 'Conselho Federal de Enfermagem',
    nameEn: 'Federal Council of Nursing',
    profession: 'medical',
    website: 'https://www.cofen.gov.br',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory federal council under Law 5.905/1973. Coordinates 27 regional nursing councils (CORENs).',
  },
  {
    id: 'cfo-br',
    name: 'Conselho Federal de Odontologia',
    nameEn: 'Federal Council of Dentistry',
    profession: 'medical',
    website: 'https://website.cfo.org.br',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory federal council under Law 4.324/1964. Coordinates regional dental councils (CROs).',
  },
  {
    id: 'cff-br',
    name: 'Conselho Federal de Farmácia',
    nameEn: 'Federal Council of Pharmacy',
    profession: 'pharmacy',
    website: 'https://www.cff.org.br',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory federal council under Law 3.820/1960. Coordinates regional pharmacy councils (CRFs).',
  },
  {
    id: 'cfmv-br',
    name: 'Conselho Federal de Medicina Veterinária',
    nameEn: 'Federal Council of Veterinary Medicine',
    profession: 'veterinary',
    website: 'https://www.cfmv.gov.br',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory federal council under Law 5.517/1968. Coordinates regional veterinary councils (CRMVs).',
  },
  {
    id: 'cau-br',
    name: 'Conselho de Arquitetura e Urbanismo do Brasil',
    nameEn: 'Council of Architecture and Urbanism of Brazil',
    profession: 'architecture',
    website: 'https://www.caubr.gov.br',
    hasPublicRegister: true,
    registerUrl: 'https://transparencia.caubr.gov.br/consulta-profissional',
    issuesDigitalCredentials: true,
    notes: 'Statutory federal council under Law 12.378/2010.',
  },
];

const MEXICO_BODIES: ProfessionalBody[] = [
  {
    id: 'bma-mx',
    name: 'Barra Mexicana, Colegio de Abogados',
    nameEn: 'Mexican Bar Association',
    profession: 'legal',
    website: 'https://www.bma.org.mx',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
  },
  {
    id: 'anm-mx',
    name: 'Academia Nacional de Medicina de México',
    nameEn: 'National Academy of Medicine of Mexico',
    profession: 'medical',
    website: 'https://www.anmm.org.mx',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'Professional license (cédula profesional) issued by SEP.',
  },
  {
    id: 'colegio-notarios-mx',
    name: 'Colegio de Notarios',
    nameEn: 'College of Notaries',
    profession: 'notary',
    website: 'https://www.notariadomexicano.org.mx',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Notary commissions are state-level.',
  },
  {
    id: 'sep-cedula-mx',
    name: 'Secretaría de Educación Pública — Cédula Profesional',
    nameEn: 'Ministry of Public Education — Professional Licence',
    profession: 'teaching',
    website: 'https://www.gob.mx/sep',
    hasPublicRegister: true,
    registerUrl: 'https://www.cedulaprofesional.sep.gob.mx/cedula/presidencia/indexAvanzada.action',
    issuesDigitalCredentials: true,
    notes: 'SEP issues the cédula profesional, a mandatory professional licence for all regulated professions in Mexico under the General Law of Professions.',
  },
  {
    id: 'cofepris-mx',
    name: 'Comisión Federal para la Protección contra Riesgos Sanitarios',
    nameEn: 'Federal Commission for Protection against Sanitary Risks',
    profession: 'medical',
    website: 'https://www.gob.mx/cofepris',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Federal health regulator. Oversees licensing of health professionals and pharmaceutical products.',
  },
  {
    id: 'cnbv-mx',
    name: 'Comisión Nacional Bancaria y de Valores',
    nameEn: 'National Banking and Securities Commission',
    profession: 'financial',
    website: 'https://www.gob.mx/cnbv',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Regulates and supervises financial institutions. Certifies external auditors.',
  },
  {
    id: 'comaem-mx',
    name: 'Consejo Mexicano para la Acreditación de la Educación Médica',
    nameEn: 'Mexican Council for Accreditation of Medical Education',
    profession: 'medical',
    website: 'https://www.comaem.org.mx',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Accredits medical schools; recognised by the Mexican government under the General Health Law.',
  },
];

const ARGENTINA_BODIES: ProfessionalBody[] = [
  {
    id: 'faca-ar',
    name: 'Federación Argentina de Colegios de Abogados',
    nameEn: 'Argentine Federation of Bar Associations',
    profession: 'legal',
    website: 'https://www.faca.org.ar',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
  },
  {
    id: 'ama-ar',
    name: 'Asociación Médica Argentina',
    nameEn: 'Argentine Medical Association',
    profession: 'medical',
    website: 'https://www.ama-med.org.ar',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
  },
  {
    id: 'cpacf-ar',
    name: 'Colegio Público de Abogados de la Capital Federal',
    nameEn: 'Public Bar Association of Buenos Aires',
    profession: 'legal',
    website: 'https://www.cpacf.org.ar',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body for lawyers in Buenos Aires. Mandatory registration required to practise law.',
  },
  {
    id: 'confemed-ar',
    name: 'Confederación Médica de la República Argentina',
    nameEn: 'Medical Confederation of the Argentine Republic',
    profession: 'medical',
    website: 'https://www.comra.org.ar',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Coordinates provincial medical colleges. Each province maintains its own physician register.',
  },
  {
    id: 'cpce-ar',
    name: 'Consejo Profesional de Ciencias Económicas de la Ciudad Autónoma de Buenos Aires',
    nameEn: 'Professional Council of Economic Sciences of Buenos Aires',
    profession: 'accounting',
    website: 'https://www.cpcecaba.org.ar',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under Law 20.488. Mandatory registration for accountants. Each province has its own council.',
  },
  {
    id: 'cpau-ar',
    name: 'Consejo Profesional de Arquitectura y Urbanismo',
    nameEn: 'Professional Council of Architecture and Urbanism',
    profession: 'architecture',
    website: 'https://www.cpau.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body for architects in Buenos Aires under Law 23.068.',
  },
];

const INDIA_BODIES: ProfessionalBody[] = [
  {
    id: 'bci-in',
    name: 'Bar Council of India',
    profession: 'legal',
    website: 'https://www.barcouncilofindia.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'nmc-in',
    name: 'National Medical Commission',
    profession: 'medical',
    website: 'https://www.nmc.org.in',
    hasPublicRegister: true,
    registerUrl: 'https://www.nmc.org.in/information-desk/indian-medical-register',
    issuesDigitalCredentials: false,
    notes: 'Replaced the Medical Council of India in 2020.',
  },
  {
    id: 'icai-in',
    name: 'Institute of Chartered Accountants of India',
    profession: 'accounting',
    website: 'https://www.icai.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Issues digital membership certificates.',
  },
  {
    id: 'ie-in',
    name: 'Institution of Engineers (India)',
    profession: 'engineering',
    website: 'https://www.ieindia.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'dci-in',
    name: 'Dental Council of India',
    profession: 'medical',
    website: 'https://www.dciindia.gov.in',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Dentists Act 1948.',
  },
  {
    id: 'pci-in',
    name: 'Pharmacy Council of India',
    profession: 'pharmacy',
    website: 'https://www.pci.nic.in',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Pharmacy Act 1948.',
  },
  {
    id: 'vci-in',
    name: 'Veterinary Council of India',
    profession: 'veterinary',
    website: 'https://www.vci.nic.in',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Indian Veterinary Council Act 1984.',
  },
  {
    id: 'coa-in',
    name: 'Council of Architecture',
    profession: 'architecture',
    website: 'https://www.coa.gov.in',
    hasPublicRegister: true,
    registerUrl: 'https://www.coa.gov.in/architect_search.php',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Architects Act 1972.',
  },
  {
    id: 'ncte-in',
    name: 'National Council for Teacher Education',
    profession: 'teaching',
    website: 'https://www.ncte.gov.in',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the NCTE Act 1993.',
  },
];

const SINGAPORE_BODIES: ProfessionalBody[] = [
  {
    id: 'lawsoc-sg',
    name: 'Law Society of Singapore',
    profession: 'legal',
    website: 'https://www.lawsociety.org.sg',
    hasPublicRegister: true,
    registerUrl: 'https://www.lawsociety.org.sg/for-public/find-a-lawyer',
    issuesDigitalCredentials: false,
  },
  {
    id: 'smc-sg',
    name: 'Singapore Medical Council',
    profession: 'medical',
    website: 'https://www.healthprofessionals.gov.sg/smc',
    hasPublicRegister: true,
    registerUrl: 'https://prs.moh.gov.sg',
    issuesDigitalCredentials: false,
  },
  {
    id: 'isca-sg',
    name: 'Institute of Singapore Chartered Accountants',
    profession: 'accounting',
    website: 'https://isca.org.sg',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'sdc-sg',
    name: 'Singapore Dental Council',
    profession: 'medical',
    website: 'https://www.healthprofessionals.gov.sg/sdc',
    hasPublicRegister: true,
    registerUrl: 'https://prs.moh.gov.sg',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Dental Registration Act.',
  },
  {
    id: 'spc-sg',
    name: 'Singapore Pharmacy Council',
    profession: 'pharmacy',
    website: 'https://www.healthprofessionals.gov.sg/spc',
    hasPublicRegister: true,
    registerUrl: 'https://prs.moh.gov.sg',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Pharmacists Registration Act.',
  },
  {
    id: 'snb-sg',
    name: 'Singapore Nursing Board',
    profession: 'medical',
    website: 'https://www.healthprofessionals.gov.sg/snb',
    hasPublicRegister: true,
    registerUrl: 'https://prs.moh.gov.sg',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Nurses and Midwives Act.',
  },
  {
    id: 'boa-sg',
    name: 'Board of Architects Singapore',
    profession: 'architecture',
    website: 'https://www.boa.gov.sg',
    hasPublicRegister: true,
    registerUrl: 'https://www.boa.gov.sg/registered-architects',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Architects Act.',
  },
  {
    id: 'peb-sg',
    name: 'Professional Engineers Board Singapore',
    profession: 'engineering',
    website: 'https://www.peb.gov.sg',
    hasPublicRegister: true,
    registerUrl: 'https://www.peb.gov.sg/registered-professional-engineers',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Professional Engineers Act.',
  },
];

const UAE_BODIES: ProfessionalBody[] = [
  {
    id: 'moj-ae',
    name: 'وزارة العدل',
    nameEn: 'Ministry of Justice',
    profession: 'legal',
    website: 'https://www.moj.gov.ae',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Advocates must be licensed by the Ministry of Justice.',
  },
  {
    id: 'dha-ae',
    name: 'هيئة الصحة بدبي',
    nameEn: 'Dubai Health Authority',
    profession: 'medical',
    website: 'https://www.dha.gov.ae',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
  },
  {
    id: 'haad-ae',
    name: 'دائرة الصحة أبوظبي',
    nameEn: 'Department of Health Abu Dhabi',
    profession: 'medical',
    website: 'https://www.doh.gov.ae',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
  },
  {
    id: 'mohap-ae',
    name: 'وزارة الصحة ووقاية المجتمع',
    nameEn: 'Ministry of Health and Prevention',
    profession: 'pharmacy',
    website: 'https://www.mohap.gov.ae',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Federal health regulator. Licenses pharmacists and other healthcare professionals outside Dubai and Abu Dhabi.',
  },
  {
    id: 'sha-ae',
    name: 'هيئة الشارقة الصحية',
    nameEn: 'Sharjah Health Authority',
    profession: 'medical',
    website: 'https://www.sha.gov.ae',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Health regulator for the Emirate of Sharjah.',
  },
  {
    id: 'sea-ae',
    name: 'جمعية مهندسي الإمارات',
    nameEn: 'Society of Engineers UAE',
    profession: 'engineering',
    website: 'https://www.soe.ae',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Established by Federal Law No. 4 of 1994. Registration is mandatory for practising engineers.',
  },
  {
    id: 'sca-ae',
    name: 'هيئة الأوراق المالية والسلع',
    nameEn: 'Securities and Commodities Authority',
    profession: 'financial',
    website: 'https://www.sca.gov.ae',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Regulates and licenses financial auditors and market professionals under Federal Law.',
  },
];

const SAUDI_ARABIA_BODIES: ProfessionalBody[] = [
  {
    id: 'sba-sa',
    name: 'الهيئة السعودية للمحامين',
    nameEn: 'Saudi Bar Association',
    profession: 'legal',
    website: 'https://sba.gov.sa',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
  },
  {
    id: 'scfhs-sa',
    name: 'الهيئة السعودية للتخصصات الصحية',
    nameEn: 'Saudi Commission for Health Specialties',
    profession: 'medical',
    website: 'https://www.scfhs.org.sa',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Statutory body covering physicians, dentists, pharmacists, nurses, and allied health professionals. Maintains the Mumaris+ practitioner register.',
  },
  {
    id: 'socpa-sa',
    name: 'الهيئة السعودية للمراجعين والمحاسبين',
    nameEn: 'Saudi Organization for Chartered and Professional Accountants',
    profession: 'accounting',
    website: 'https://socpa.org.sa',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Statutory body under Royal Decree M/12 (1992). Licenses and regulates accountants and auditors.',
  },
  {
    id: 'scfhs-nursing-sa',
    name: 'الهيئة السعودية للتخصصات الصحية — التمريض',
    nameEn: 'SCFHS — Nursing Division',
    profession: 'medical',
    website: 'https://www.scfhs.org.sa',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Nursing registration managed under SCFHS. All nurses must register in the Mumaris+ system.',
  },
  {
    id: 'scfhs-dental-sa',
    name: 'الهيئة السعودية للتخصصات الصحية — طب الأسنان',
    nameEn: 'SCFHS — Dental Division',
    profession: 'medical',
    website: 'https://www.scfhs.org.sa',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Dental registration managed under SCFHS. All dentists must register in the Mumaris+ system.',
  },
  {
    id: 'scfhs-pharmacy-sa',
    name: 'الهيئة السعودية للتخصصات الصحية — الصيدلة',
    nameEn: 'SCFHS — Pharmacy Division',
    profession: 'pharmacy',
    website: 'https://www.scfhs.org.sa',
    hasPublicRegister: true,
    issuesDigitalCredentials: true,
    notes: 'Pharmacy registration managed under SCFHS. All pharmacists must register in the Mumaris+ system.',
  },
];

const SOUTH_AFRICA_BODIES: ProfessionalBody[] = [
  {
    id: 'lssa-za',
    name: 'Law Society of South Africa',
    profession: 'legal',
    website: 'https://www.lssa.org.za',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'hpcsa-za',
    name: 'Health Professions Council of South Africa',
    profession: 'medical',
    website: 'https://www.hpcsa.co.za',
    hasPublicRegister: true,
    registerUrl: 'https://isystems.hpcsa.co.za/iregister',
    issuesDigitalCredentials: false,
  },
  {
    id: 'saica-za',
    name: 'South African Institute of Chartered Accountants',
    profession: 'accounting',
    website: 'https://www.saica.co.za',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'sanc-za',
    name: 'South African Nursing Council',
    profession: 'medical',
    website: 'https://www.sanc.co.za',
    hasPublicRegister: true,
    registerUrl: 'https://www.sanc.co.za/verify-registration',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Nursing Act 33 of 2005.',
  },
  {
    id: 'sacap-za',
    name: 'South African Council for the Architectural Profession',
    profession: 'architecture',
    website: 'https://www.sacapsa.com',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Architectural Profession Act 44 of 2000.',
  },
  {
    id: 'ecsa-za',
    name: 'Engineering Council of South Africa',
    profession: 'engineering',
    website: 'https://www.ecsa.co.za',
    hasPublicRegister: true,
    registerUrl: 'https://www.ecsa.co.za/register/SitePages/Search.aspx',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Engineering Profession Act 46 of 2000.',
  },
  {
    id: 'sapc-za',
    name: 'South African Pharmacy Council',
    profession: 'pharmacy',
    website: 'https://www.sapc.za.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Pharmacy Act 53 of 1974.',
  },
  {
    id: 'savc-za',
    name: 'South African Veterinary Council',
    profession: 'veterinary',
    website: 'https://www.savc.org.za',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Veterinary and Para-Veterinary Professions Act 19 of 1982.',
  },
];

const CHINA_BODIES: ProfessionalBody[] = [
  {
    id: 'acla-cn',
    name: '中华全国律师协会',
    nameEn: 'All China Lawyers Association',
    profession: 'legal',
    website: 'https://www.acla.org.cn',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'cma-cn',
    name: '中华医学会',
    nameEn: 'Chinese Medical Association',
    profession: 'medical',
    website: 'https://www.cma.org.cn',
    hasPublicRegister: false,
    issuesDigitalCredentials: false,
    notes: 'Licensing is via National Health Commission.',
  },
  {
    id: 'cna-cn',
    name: '中国公证协会',
    nameEn: 'China Notary Association',
    profession: 'notary',
    website: 'https://www.chinanotary.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'cicpa-cn',
    name: '中国注册会计师协会',
    nameEn: 'Chinese Institute of Certified Public Accountants',
    profession: 'accounting',
    website: 'https://www.cicpa.org.cn',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'nhc-cn',
    name: '国家卫生健康委员会',
    nameEn: 'National Health Commission — Physician Register',
    profession: 'medical',
    website: 'https://www.nhc.gov.cn',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Physician licensing and registration administered by NHC under the Physicians Law of the PRC.',
  },
  {
    id: 'mohurd-arch-cn',
    name: '住房和城乡建设部 注册建筑师',
    nameEn: 'Ministry of Housing and Urban-Rural Development — Registered Architects',
    profession: 'architecture',
    website: 'https://www.mohurd.gov.cn',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Architect registration administered by MOHURD under the Regulations on Registered Architects.',
  },
  {
    id: 'moe-teacher-cn',
    name: '教育部 教师资格',
    nameEn: 'Ministry of Education — Teacher Qualification',
    profession: 'teaching',
    website: 'https://www.moe.gov.cn',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Teacher qualification administered by MOE under the Teachers Law of the PRC.',
  },
];

const HONG_KONG_BODIES: ProfessionalBody[] = [
  {
    id: 'hklawsoc-hk',
    name: 'The Law Society of Hong Kong',
    profession: 'legal',
    website: 'https://www.hklawsoc.org.hk',
    hasPublicRegister: true,
    registerUrl: 'https://www.hklawsoc.org.hk/pub_e/memberlawlist',
    issuesDigitalCredentials: false,
  },
  {
    id: 'mchk',
    name: 'Medical Council of Hong Kong',
    profession: 'medical',
    website: 'https://www.mchk.org.hk',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'dchk',
    name: 'Dental Council of Hong Kong',
    profession: 'medical',
    website: 'https://www.dchk.org.hk',
    hasPublicRegister: true,
    registerUrl: 'https://www.dchk.org.hk/en/registered_dentist.php',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Dentists Registration Ordinance (Cap. 156).',
  },
  {
    id: 'ppbhk',
    name: 'Pharmacy and Poisons Board of Hong Kong',
    profession: 'pharmacy',
    website: 'https://www.ppb.gov.hk',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Pharmacy and Poisons Ordinance (Cap. 138).',
  },
  {
    id: 'nchk',
    name: 'Nursing Council of Hong Kong',
    profession: 'medical',
    website: 'https://www.nchk.org.hk',
    hasPublicRegister: true,
    registerUrl: 'https://www.nchk.org.hk/en/registrations/search_the_register',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Nurses Registration Ordinance (Cap. 164).',
  },
  {
    id: 'arb-hk',
    name: 'Architects Registration Board of Hong Kong',
    profession: 'architecture',
    website: 'https://www.arb.org.hk',
    hasPublicRegister: true,
    registerUrl: 'https://www.arb.org.hk/registered_architect.php',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Architects Registration Ordinance (Cap. 408).',
  },
  {
    id: 'erb-hk',
    name: 'Engineers Registration Board of Hong Kong',
    profession: 'engineering',
    website: 'https://www.erb.org.hk',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Engineers Registration Ordinance (Cap. 409).',
  },
];

const IRELAND_BODIES: ProfessionalBody[] = [
  {
    id: 'lawsoc-ie',
    name: 'Law Society of Ireland',
    profession: 'legal',
    website: 'https://www.lawsociety.ie',
    hasPublicRegister: true,
    registerUrl: 'https://www.lawsociety.ie/Find-a-Solicitor',
    issuesDigitalCredentials: false,
  },
  {
    id: 'imc-ie',
    name: 'Irish Medical Council',
    profession: 'medical',
    website: 'https://www.medicalcouncil.ie',
    hasPublicRegister: true,
    registerUrl: 'https://www.medicalcouncil.ie/public-information/check-the-register',
    issuesDigitalCredentials: false,
  },
  {
    id: 'nmbi-ie',
    name: 'Nursing and Midwifery Board of Ireland',
    profession: 'medical',
    website: 'https://www.nmbi.ie',
    hasPublicRegister: true,
    registerUrl: 'https://www.nmbi.ie/Check-the-Register',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Nurses and Midwives Act 2011.',
  },
  {
    id: 'dci-ie',
    name: 'Dental Council of Ireland',
    profession: 'medical',
    website: 'https://www.dentalcouncil.ie',
    hasPublicRegister: true,
    registerUrl: 'https://www.dentalcouncil.ie/public/search-the-register',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Dentists Act 1985.',
  },
  {
    id: 'psi-ie',
    name: 'Pharmaceutical Society of Ireland',
    profession: 'pharmacy',
    website: 'https://www.psi.ie',
    hasPublicRegister: true,
    registerUrl: 'https://www.psi.ie/en/public/search-the-register',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Pharmacy Act 2007.',
  },
  {
    id: 'vci-ie',
    name: 'Veterinary Council of Ireland',
    profession: 'veterinary',
    website: 'https://www.vci.ie',
    hasPublicRegister: true,
    registerUrl: 'https://www.vci.ie/Registered-Veterinary-Practitioners/Search-the-Register',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Veterinary Practice Act 2005.',
  },
  {
    id: 'riai-ie',
    name: 'Royal Institute of the Architects of Ireland',
    profession: 'architecture',
    website: 'https://www.riai.ie',
    hasPublicRegister: true,
    registerUrl: 'https://www.riai.ie/architect-register',
    issuesDigitalCredentials: false,
    notes: 'Statutory registration under the Building Control Act 2007.',
  },
  {
    id: 'coru-ie',
    name: 'CORU - Health and Social Care Professionals Council',
    profession: 'social-work',
    website: 'https://www.coru.ie',
    hasPublicRegister: true,
    registerUrl: 'https://www.coru.ie/health-and-social-care-professionals/check-the-register',
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Health and Social Care Professionals Act 2005. Registers social workers, dietitians, occupational therapists, physiotherapists, radiographers, and others.',
  },
];

const TURKEY_BODIES: ProfessionalBody[] = [
  {
    id: 'tbb-tr',
    name: 'Türkiye Barolar Birliği',
    nameEn: 'Union of Turkish Bar Associations',
    profession: 'legal',
    website: 'https://www.barobirlik.org.tr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'ttb-tr',
    name: 'Türk Tabipleri Birliği',
    nameEn: 'Turkish Medical Association',
    profession: 'medical',
    website: 'https://www.ttb.org.tr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'tdb-tr',
    name: 'Türk Diş Hekimleri Birliği',
    nameEn: 'Turkish Dental Association',
    profession: 'medical',
    website: 'https://www.tdb.org.tr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under Law 3224. Coordinates provincial dental chambers.',
  },
  {
    id: 'teb-tr',
    name: 'Türk Eczacıları Birliği',
    nameEn: 'Turkish Pharmacists Association',
    profession: 'pharmacy',
    website: 'https://www.teb.org.tr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under Law 6643. Coordinates provincial pharmacy chambers.',
  },
  {
    id: 'tmmob-tr',
    name: 'Türk Mühendis ve Mimar Odaları Birliği',
    nameEn: 'Union of Chambers of Turkish Engineers and Architects',
    profession: 'engineering',
    website: 'https://www.tmmob.org.tr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under Law 6235. Umbrella for 24 professional chambers covering engineers and architects.',
  },
  {
    id: 'thd-tr',
    name: 'Türk Hemşireler Derneği',
    nameEn: 'Turkish Nurses Association',
    profession: 'medical',
    website: 'https://www.turkhemsirelerdernegi.org.tr',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Nursing registration administered by the Ministry of Health under the Nursing Law 6283.',
  },
];

const INDONESIA_BODIES: ProfessionalBody[] = [
  {
    id: 'peradi-id',
    name: 'Perhimpunan Advokat Indonesia',
    nameEn: 'Indonesian Advocates Association',
    profession: 'legal',
    website: 'https://www.peradi.or.id',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'idi-id',
    name: 'Ikatan Dokter Indonesia',
    nameEn: 'Indonesian Medical Association',
    profession: 'medical',
    website: 'https://www.idionline.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'kki-id',
    name: 'Konsil Kedokteran Indonesia',
    nameEn: 'Indonesian Medical Council',
    profession: 'medical',
    website: 'https://www.kki.go.id',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under Law 29/2004 on Medical Practice. Issues physician registration certificates (STR).',
  },
  {
    id: 'ppni-id',
    name: 'Persatuan Perawat Nasional Indonesia',
    nameEn: 'Indonesian National Nurses Association',
    profession: 'medical',
    website: 'https://www.ppni-inna.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Nursing regulation under Law 38/2014 on Nursing. PPNI coordinates nursing registration.',
  },
  {
    id: 'ibi-id',
    name: 'Ikatan Bidan Indonesia',
    nameEn: 'Indonesian Midwives Association',
    profession: 'medical',
    website: 'https://www.ibi.or.id',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Midwifery regulation under Law 4/2019 on Midwifery.',
  },
  {
    id: 'iai-id',
    name: 'Ikatan Arsitek Indonesia',
    nameEn: 'Indonesian Institute of Architects',
    profession: 'architecture',
    website: 'https://www.iai.or.id',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Architect registration under Law 6/2017 on Architects.',
  },
];

const NIGERIA_BODIES: ProfessionalBody[] = [
  {
    id: 'nba-ng',
    name: 'Nigerian Bar Association',
    profession: 'legal',
    website: 'https://nigerianbar.org.ng',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'mdcn-ng',
    name: 'Medical and Dental Council of Nigeria',
    profession: 'medical',
    website: 'https://www.mdcn.gov.ng',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'nmcn-ng',
    name: 'Nursing and Midwifery Council of Nigeria',
    profession: 'medical',
    website: 'https://www.nmcn.gov.ng',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Nursing and Midwifery (Registration, etc.) Act Cap N143 LFN 2004.',
  },
  {
    id: 'pcn-ng',
    name: 'Pharmacists Council of Nigeria',
    profession: 'pharmacy',
    website: 'https://www.pcn.gov.ng',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Pharmacists Council of Nigeria Act Cap P17 LFN 2004.',
  },
  {
    id: 'vcn-ng',
    name: 'Veterinary Council of Nigeria',
    profession: 'veterinary',
    website: 'https://www.vcn.gov.ng',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Veterinary Surgeons Act Cap V3 LFN 2004.',
  },
  {
    id: 'arcon-ng',
    name: 'Architects Registration Council of Nigeria',
    profession: 'architecture',
    website: 'https://www.arcon.gov.ng',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Architects (Registration, etc.) Act Cap A19 LFN 2004.',
  },
  {
    id: 'coren-ng',
    name: 'Council for the Regulation of Engineering in Nigeria',
    profession: 'engineering',
    website: 'https://www.coren.gov.ng',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Engineers (Registration, etc.) Act Cap E11 LFN 2004.',
  },
];

const KENYA_BODIES: ProfessionalBody[] = [
  {
    id: 'lsk-ke',
    name: 'Law Society of Kenya',
    profession: 'legal',
    website: 'https://lsk.or.ke',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'kmpdc-ke',
    name: 'Kenya Medical Practitioners and Dentists Council',
    profession: 'medical',
    website: 'https://kmpdc.go.ke',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'nck-ke',
    name: 'Nursing Council of Kenya',
    profession: 'medical',
    website: 'https://nckenya.com',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Nurses Act Cap 257.',
  },
  {
    id: 'ppb-ke',
    name: 'Pharmacy and Poisons Board',
    profession: 'pharmacy',
    website: 'https://www.pharmacyboardkenya.org',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Pharmacy and Poisons Act Cap 244.',
  },
  {
    id: 'kvb-ke',
    name: 'Kenya Veterinary Board',
    profession: 'veterinary',
    website: 'https://www.kenyavetboard.or.ke',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Veterinary Surgeons and Veterinary Para-professionals Act 2011.',
  },
  {
    id: 'boraqs-ke',
    name: 'Board of Registration of Architects and Quantity Surveyors',
    profession: 'architecture',
    website: 'https://www.boraqs.or.ke',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Architects and Quantity Surveyors Act Cap 525.',
  },
];

const ISRAEL_BODIES: ProfessionalBody[] = [
  {
    id: 'israelbar-il',
    name: 'לשכת עורכי הדין בישראל',
    nameEn: 'Israel Bar Association',
    profession: 'legal',
    website: 'https://www.israelbar.org.il',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'ima-il',
    name: 'הסתדרות הרפואית בישראל',
    nameEn: 'Israel Medical Association',
    profession: 'medical',
    website: 'https://www.ima.org.il',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
  },
  {
    id: 'moh-nursing-il',
    name: 'משרד הבריאות — אגף הסיעוד',
    nameEn: 'Ministry of Health — Nursing Division',
    profession: 'medical',
    website: 'https://www.health.gov.il',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Nursing licences issued by the Ministry of Health under the Public Health Ordinance.',
  },
  {
    id: 'moh-dental-il',
    name: 'משרד הבריאות — רפואת שיניים',
    nameEn: 'Ministry of Health — Dental Division',
    profession: 'medical',
    website: 'https://www.health.gov.il',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Dental licences issued by the Ministry of Health under the Dentists Ordinance.',
  },
  {
    id: 'moh-pharma-il',
    name: 'משרד הבריאות — רוקחות',
    nameEn: 'Ministry of Health — Pharmacy Division',
    profession: 'pharmacy',
    website: 'https://www.health.gov.il',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Pharmacist licences issued by the Ministry of Health under the Pharmacists Ordinance.',
  },
  {
    id: 'icpas-il',
    name: 'לשכת רואי חשבון בישראל',
    nameEn: 'Institute of Certified Public Accountants in Israel',
    profession: 'accounting',
    website: 'https://www.icpas.org.il',
    hasPublicRegister: true,
    issuesDigitalCredentials: false,
    notes: 'Statutory body under the Auditors Act 1955. CPA licensing regulated by the Auditors Council.',
  },
];

// --- Jurisdiction Definitions ---

const GDPR_BASE: DataProtectionLaw = {
  name: 'GDPR',
  fullName: 'General Data Protection Regulation (EU) 2016/679',
  year: 2016,
  requiresExplicitConsent: true,
  digitalConsentAge: 16,
  breachNotificationHours: 72,
  rightToErasure: true,
  rightToPortability: true,
  crossBorderRestrictions: true,
  maxRetentionDays: 0,
  supervisoryAuthority: '',
  notes: 'Member states may lower digital consent age to 13.',
};

export const JURISDICTIONS: Record<string, Jurisdiction> = {
  GB: {
    code: 'GB',
    name: 'United Kingdom',
    nameLocal: 'United Kingdom',
    legalSystem: 'common-law',
    languages: ['en'],
    currency: 'GBP',
    professionalBodies: UK_BODIES,
    dataProtection: {
      name: 'UK GDPR + DPA 2018',
      fullName: 'UK General Data Protection Regulation & Data Protection Act 2018',
      year: 2018,
      requiresExplicitConsent: true,
      digitalConsentAge: 13,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Information Commissioner\'s Office (ICO)',
    },
    childProtection: {
      name: 'Age Appropriate Design Code',
      minAgeDigitalConsent: 13,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['IE', 'AU', 'NZ', 'CA', 'HK'],
    notes: 'Online Safety Act 2023 mandates age verification for certain services.',
  },
  US: {
    code: 'US',
    name: 'United States',
    nameLocal: 'United States',
    legalSystem: 'common-law',
    languages: ['en', 'es'],
    currency: 'USD',
    professionalBodies: US_BODIES,
    dataProtection: {
      name: 'CCPA/CPRA + State Laws',
      fullName: 'California Consumer Privacy Act / California Privacy Rights Act + State Laws',
      year: 2018,
      requiresExplicitConsent: false,
      digitalConsentAge: 13,
      breachNotificationHours: 0,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: false,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Federal Trade Commission (FTC) + State AGs',
      notes: 'No federal privacy law; patchwork of state laws. CCPA/CPRA applies to CA residents.',
    },
    childProtection: {
      name: 'COPPA',
      minAgeDigitalConsent: 13,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['CA', 'GB', 'AU'],
    notes: 'Professional licensing is state-level. COPPA strictly enforced by FTC.',
  },
  FR: {
    code: 'FR',
    name: 'France',
    nameLocal: 'France',
    legalSystem: 'civil-law',
    languages: ['fr'],
    currency: 'EUR',
    professionalBodies: EU_FRANCE_BODIES,
    dataProtection: {
      ...GDPR_BASE,
      digitalConsentAge: 15,
      supervisoryAuthority: 'Commission Nationale de l\'Informatique et des Libertés (CNIL)',
    },
    childProtection: {
      name: 'GDPR Art. 8 + French Data Protection Act',
      minAgeDigitalConsent: 15,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['DE', 'ES', 'IT', 'NL', 'BE', 'LU'],
    notes: 'eIDAS regulation applies. Notaries have strong legal powers.',
  },
  DE: {
    code: 'DE',
    name: 'Germany',
    nameLocal: 'Deutschland',
    legalSystem: 'civil-law',
    languages: ['de'],
    currency: 'EUR',
    professionalBodies: EU_GERMANY_BODIES,
    dataProtection: {
      ...GDPR_BASE,
      digitalConsentAge: 16,
      supervisoryAuthority: 'Bundesbeauftragter für den Datenschutz (BfDI) + State DPAs',
      notes: 'Federal + 16 state DPAs. Strongest GDPR enforcement in EU.',
    },
    childProtection: {
      name: 'GDPR Art. 8 + BDSG',
      minAgeDigitalConsent: 16,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['FR', 'AT', 'CH', 'NL', 'BE'],
    notes: 'beA (besonderes elektronisches Anwaltspostfach) is mandatory for lawyers.',
  },
  ES: {
    code: 'ES',
    name: 'Spain',
    nameLocal: 'España',
    legalSystem: 'civil-law',
    languages: ['es', 'ca', 'eu', 'gl'],
    currency: 'EUR',
    professionalBodies: EU_SPAIN_BODIES,
    dataProtection: {
      ...GDPR_BASE,
      digitalConsentAge: 14,
      supervisoryAuthority: 'Agencia Española de Protección de Datos (AEPD)',
    },
    childProtection: {
      name: 'GDPR Art. 8 + LOPDGDD',
      minAgeDigitalConsent: 14,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['FR', 'PT', 'IT', 'MX', 'AR'],
  },
  IT: {
    code: 'IT',
    name: 'Italy',
    nameLocal: 'Italia',
    legalSystem: 'civil-law',
    languages: ['it'],
    currency: 'EUR',
    professionalBodies: EU_ITALY_BODIES,
    dataProtection: {
      ...GDPR_BASE,
      digitalConsentAge: 14,
      supervisoryAuthority: 'Garante per la protezione dei dati personali',
    },
    childProtection: {
      name: 'GDPR Art. 8 + Italian Privacy Code',
      minAgeDigitalConsent: 14,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['FR', 'ES', 'DE', 'CH'],
  },
  NL: {
    code: 'NL',
    name: 'Netherlands',
    nameLocal: 'Nederland',
    legalSystem: 'civil-law',
    languages: ['nl'],
    currency: 'EUR',
    professionalBodies: EU_NETHERLANDS_BODIES,
    dataProtection: {
      ...GDPR_BASE,
      digitalConsentAge: 16,
      supervisoryAuthority: 'Autoriteit Persoonsgegevens (AP)',
    },
    childProtection: {
      name: 'GDPR Art. 8 + UAVG',
      minAgeDigitalConsent: 16,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['DE', 'BE', 'LU', 'FR'],
  },
  CA: {
    code: 'CA',
    name: 'Canada',
    nameLocal: 'Canada',
    legalSystem: 'common-law',
    languages: ['en', 'fr'],
    currency: 'CAD',
    professionalBodies: CANADA_BODIES,
    dataProtection: {
      name: 'PIPEDA + Provincial Laws',
      fullName: 'Personal Information Protection and Electronic Documents Act',
      year: 2000,
      requiresExplicitConsent: true,
      digitalConsentAge: 13,
      breachNotificationHours: 0,
      rightToErasure: false,
      rightToPortability: false,
      crossBorderRestrictions: false,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Office of the Privacy Commissioner of Canada (OPC)',
      notes: 'Quebec, BC, and Alberta have equivalent provincial laws.',
    },
    childProtection: {
      name: 'PIPEDA + Provincial Laws',
      minAgeDigitalConsent: 13,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['US', 'GB', 'AU', 'NZ'],
  },
  AU: {
    code: 'AU',
    name: 'Australia',
    nameLocal: 'Australia',
    legalSystem: 'common-law',
    languages: ['en'],
    currency: 'AUD',
    professionalBodies: AUSTRALIA_BODIES,
    dataProtection: {
      name: 'Privacy Act 1988',
      fullName: 'Privacy Act 1988 (Australian Privacy Principles)',
      year: 1988,
      requiresExplicitConsent: true,
      digitalConsentAge: 15,
      breachNotificationHours: 720,
      rightToErasure: false,
      rightToPortability: false,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Office of the Australian Information Commissioner (OAIC)',
      notes: 'Notifiable Data Breaches scheme mandatory since 2018.',
    },
    childProtection: {
      name: 'Privacy Act + Online Safety Act',
      minAgeDigitalConsent: 15,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['NZ', 'GB', 'CA', 'SG', 'HK'],
  },
  NZ: {
    code: 'NZ',
    name: 'New Zealand',
    nameLocal: 'Aotearoa New Zealand',
    legalSystem: 'common-law',
    languages: ['en', 'mi'],
    currency: 'NZD',
    professionalBodies: NEW_ZEALAND_BODIES,
    dataProtection: {
      name: 'Privacy Act 2020',
      fullName: 'Privacy Act 2020',
      year: 2020,
      requiresExplicitConsent: true,
      digitalConsentAge: 16,
      breachNotificationHours: 72,
      rightToErasure: false,
      rightToPortability: false,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Office of the Privacy Commissioner',
    },
    childProtection: {
      name: 'Privacy Act 2020',
      minAgeDigitalConsent: 16,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['AU', 'GB', 'CA'],
  },
  JP: {
    code: 'JP',
    name: 'Japan',
    nameLocal: '日本',
    legalSystem: 'civil-law',
    languages: ['ja'],
    currency: 'JPY',
    professionalBodies: JAPAN_BODIES,
    dataProtection: {
      name: 'APPI',
      fullName: 'Act on the Protection of Personal Information',
      year: 2003,
      requiresExplicitConsent: true,
      digitalConsentAge: 15,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: false,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Personal Information Protection Commission (PPC)',
      notes: 'Amended 2022 with stricter cross-border transfer rules. EU adequacy decision.',
    },
    childProtection: {
      name: 'APPI + Child Welfare Act',
      minAgeDigitalConsent: 15,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['KR', 'SG'],
  },
  KR: {
    code: 'KR',
    name: 'South Korea',
    nameLocal: '대한민국',
    legalSystem: 'civil-law',
    languages: ['ko'],
    currency: 'KRW',
    professionalBodies: SOUTH_KOREA_BODIES,
    dataProtection: {
      name: 'PIPA',
      fullName: 'Personal Information Protection Act',
      year: 2011,
      requiresExplicitConsent: true,
      digitalConsentAge: 14,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Personal Information Protection Commission (PIPC)',
      notes: 'One of the strictest data protection regimes globally. EU adequacy decision.',
    },
    childProtection: {
      name: 'PIPA + Juvenile Protection Act',
      minAgeDigitalConsent: 14,
      ageOfMajority: 19,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['JP', 'SG'],
  },
  BR: {
    code: 'BR',
    name: 'Brazil',
    nameLocal: 'Brasil',
    legalSystem: 'civil-law',
    languages: ['pt'],
    currency: 'BRL',
    professionalBodies: BRAZIL_BODIES,
    dataProtection: {
      name: 'LGPD',
      fullName: 'Lei Geral de Proteção de Dados Pessoais',
      year: 2018,
      requiresExplicitConsent: true,
      digitalConsentAge: 12,
      breachNotificationHours: 48,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Autoridade Nacional de Proteção de Dados (ANPD)',
      notes: 'Modelled on GDPR. ICP-Brasil provides PKI infrastructure.',
    },
    childProtection: {
      name: 'LGPD Art. 14 + ECA',
      minAgeDigitalConsent: 12,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['PT', 'AR', 'MX'],
  },
  MX: {
    code: 'MX',
    name: 'Mexico',
    nameLocal: 'México',
    legalSystem: 'civil-law',
    languages: ['es'],
    currency: 'MXN',
    professionalBodies: MEXICO_BODIES,
    dataProtection: {
      name: 'LFPDPPP',
      fullName: 'Ley Federal de Protección de Datos Personales en Posesión de los Particulares',
      year: 2010,
      requiresExplicitConsent: true,
      digitalConsentAge: 16,
      breachNotificationHours: 0,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Instituto Nacional de Transparencia (INAI)',
    },
    childProtection: {
      name: 'LFPDPPP + LGDNNA',
      minAgeDigitalConsent: 16,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['US', 'CA', 'ES', 'BR'],
    notes: 'Professional license (cédula profesional) issued by Secretaría de Educación Pública.',
  },
  AR: {
    code: 'AR',
    name: 'Argentina',
    nameLocal: 'Argentina',
    legalSystem: 'civil-law',
    languages: ['es'],
    currency: 'ARS',
    professionalBodies: ARGENTINA_BODIES,
    dataProtection: {
      name: 'PDPL',
      fullName: 'Personal Data Protection Law No. 25.326',
      year: 2000,
      requiresExplicitConsent: true,
      digitalConsentAge: 13,
      breachNotificationHours: 0,
      rightToErasure: true,
      rightToPortability: false,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Agencia de Acceso a la Información Pública (AAIP)',
      notes: 'EU adequacy decision for data transfers.',
    },
    childProtection: {
      name: 'PDPL + Civil Code',
      minAgeDigitalConsent: 13,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['BR', 'ES', 'UY'],
  },
  IN: {
    code: 'IN',
    name: 'India',
    nameLocal: 'भारत',
    legalSystem: 'common-law',
    languages: ['hi', 'en'],
    currency: 'INR',
    professionalBodies: INDIA_BODIES,
    dataProtection: {
      name: 'DPDPA 2023',
      fullName: 'Digital Personal Data Protection Act 2023',
      year: 2023,
      requiresExplicitConsent: true,
      digitalConsentAge: 18,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: false,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Data Protection Board of India',
      notes: 'Replaces the IT Act 2000 data protection provisions. Full enforcement pending.',
    },
    childProtection: {
      name: 'DPDPA 2023 + POCSO',
      minAgeDigitalConsent: 18,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['SG', 'GB'],
    notes: 'Aadhaar provides national digital identity infrastructure.',
  },
  SG: {
    code: 'SG',
    name: 'Singapore',
    nameLocal: 'Singapore / 新加坡',
    legalSystem: 'common-law',
    languages: ['en', 'zh', 'ms', 'ta'],
    currency: 'SGD',
    professionalBodies: SINGAPORE_BODIES,
    dataProtection: {
      name: 'PDPA',
      fullName: 'Personal Data Protection Act 2012',
      year: 2012,
      requiresExplicitConsent: true,
      digitalConsentAge: 13,
      breachNotificationHours: 72,
      rightToErasure: false,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Personal Data Protection Commission (PDPC)',
    },
    childProtection: {
      name: 'PDPA + Children and Young Persons Act',
      minAgeDigitalConsent: 13,
      ageOfMajority: 21,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['AU', 'NZ', 'HK', 'JP', 'KR'],
  },
  AE: {
    code: 'AE',
    name: 'United Arab Emirates',
    nameLocal: 'الإمارات العربية المتحدة',
    legalSystem: 'mixed',
    languages: ['ar', 'en'],
    currency: 'AED',
    professionalBodies: UAE_BODIES,
    dataProtection: {
      name: 'PDPL',
      fullName: 'Federal Decree-Law No. 45/2021 on Personal Data Protection',
      year: 2021,
      requiresExplicitConsent: true,
      digitalConsentAge: 18,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'UAE Data Office',
      notes: 'DIFC and ADGM have separate data protection regimes.',
    },
    childProtection: {
      name: 'PDPL + Wadeema\'s Law',
      minAgeDigitalConsent: 18,
      ageOfMajority: 21,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['SA', 'BH', 'QA', 'KW', 'OM'],
  },
  SA: {
    code: 'SA',
    name: 'Saudi Arabia',
    nameLocal: 'المملكة العربية السعودية',
    legalSystem: 'religious',
    languages: ['ar'],
    currency: 'SAR',
    professionalBodies: SAUDI_ARABIA_BODIES,
    dataProtection: {
      name: 'PDPL',
      fullName: 'Personal Data Protection Law (Royal Decree M/19)',
      year: 2021,
      requiresExplicitConsent: true,
      digitalConsentAge: 18,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Saudi Data & Artificial Intelligence Authority (SDAIA)',
    },
    childProtection: {
      name: 'PDPL + Child Protection System',
      minAgeDigitalConsent: 18,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['AE', 'BH', 'QA', 'KW', 'OM'],
  },
  ZA: {
    code: 'ZA',
    name: 'South Africa',
    nameLocal: 'South Africa',
    legalSystem: 'mixed',
    languages: ['en', 'af', 'zu', 'xh'],
    currency: 'ZAR',
    professionalBodies: SOUTH_AFRICA_BODIES,
    dataProtection: {
      name: 'POPIA',
      fullName: 'Protection of Personal Information Act 4 of 2013',
      year: 2013,
      requiresExplicitConsent: true,
      digitalConsentAge: 18,
      breachNotificationHours: 0,
      rightToErasure: true,
      rightToPortability: false,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Information Regulator',
    },
    childProtection: {
      name: 'POPIA + Children\'s Act',
      minAgeDigitalConsent: 18,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['KE', 'NG'],
  },
  CN: {
    code: 'CN',
    name: 'China',
    nameLocal: '中华人民共和国',
    legalSystem: 'civil-law',
    languages: ['zh'],
    currency: 'CNY',
    professionalBodies: CHINA_BODIES,
    dataProtection: {
      name: 'PIPL',
      fullName: 'Personal Information Protection Law',
      year: 2021,
      requiresExplicitConsent: true,
      digitalConsentAge: 14,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Cyberspace Administration of China (CAC)',
      notes: 'Strict data localization requirements. Cross-border transfers require security assessment.',
    },
    childProtection: {
      name: 'PIPL + Minor Protection Law',
      minAgeDigitalConsent: 14,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['HK'],
    notes: 'Data localization may impact Nostr relay operations.',
  },
  HK: {
    code: 'HK',
    name: 'Hong Kong',
    nameLocal: '香港',
    legalSystem: 'common-law',
    languages: ['zh', 'en'],
    currency: 'HKD',
    professionalBodies: HONG_KONG_BODIES,
    dataProtection: {
      name: 'PDPO',
      fullName: 'Personal Data (Privacy) Ordinance',
      year: 1996,
      requiresExplicitConsent: true,
      digitalConsentAge: 16,
      breachNotificationHours: 0,
      rightToErasure: true,
      rightToPortability: false,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Office of the Privacy Commissioner for Personal Data',
    },
    childProtection: {
      name: 'PDPO + Protection of Children Ordinance',
      minAgeDigitalConsent: 16,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['GB', 'SG', 'AU'],
  },
  IE: {
    code: 'IE',
    name: 'Ireland',
    nameLocal: 'Éire',
    legalSystem: 'common-law',
    languages: ['en', 'ga'],
    currency: 'EUR',
    professionalBodies: IRELAND_BODIES,
    dataProtection: {
      ...GDPR_BASE,
      digitalConsentAge: 16,
      supervisoryAuthority: 'Data Protection Commission (DPC)',
      notes: 'Lead supervisory authority for many US tech companies under GDPR.',
    },
    childProtection: {
      name: 'GDPR Art. 8 + Data Protection Act 2018',
      minAgeDigitalConsent: 16,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['GB', 'FR', 'DE'],
  },
  TR: {
    code: 'TR',
    name: 'Turkey',
    nameLocal: 'Türkiye',
    legalSystem: 'civil-law',
    languages: ['tr'],
    currency: 'TRY',
    professionalBodies: TURKEY_BODIES,
    dataProtection: {
      name: 'KVKK',
      fullName: 'Kişisel Verilerin Korunması Kanunu',
      year: 2016,
      requiresExplicitConsent: true,
      digitalConsentAge: 18,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Kişisel Verileri Koruma Kurumu (KVKK)',
    },
    childProtection: {
      name: 'KVKK + Child Protection Law',
      minAgeDigitalConsent: 18,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: true,
    },
    eSignatureRecognised: true,
    mutualRecognition: [],
  },
  ID: {
    code: 'ID',
    name: 'Indonesia',
    nameLocal: 'Indonesia',
    legalSystem: 'civil-law',
    languages: ['id'],
    currency: 'IDR',
    professionalBodies: INDONESIA_BODIES,
    dataProtection: {
      name: 'PDP Law',
      fullName: 'Personal Data Protection Law No. 27/2022',
      year: 2022,
      requiresExplicitConsent: true,
      digitalConsentAge: 17,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Ministry of Communication and Informatics (Kominfo)',
    },
    childProtection: {
      name: 'PDP Law + Child Protection Law',
      minAgeDigitalConsent: 17,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['SG', 'MY'],
  },
  NG: {
    code: 'NG',
    name: 'Nigeria',
    nameLocal: 'Nigeria',
    legalSystem: 'mixed',
    languages: ['en'],
    currency: 'NGN',
    professionalBodies: NIGERIA_BODIES,
    dataProtection: {
      name: 'NDPA 2023',
      fullName: 'Nigeria Data Protection Act 2023',
      year: 2023,
      requiresExplicitConsent: true,
      digitalConsentAge: 13,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Nigeria Data Protection Commission (NDPC)',
    },
    childProtection: {
      name: 'NDPA 2023 + Child Rights Act',
      minAgeDigitalConsent: 13,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['KE', 'ZA', 'GH'],
  },
  KE: {
    code: 'KE',
    name: 'Kenya',
    nameLocal: 'Kenya',
    legalSystem: 'mixed',
    languages: ['en', 'sw'],
    currency: 'KES',
    professionalBodies: KENYA_BODIES,
    dataProtection: {
      name: 'DPA 2019',
      fullName: 'Data Protection Act 2019',
      year: 2019,
      requiresExplicitConsent: true,
      digitalConsentAge: 18,
      breachNotificationHours: 72,
      rightToErasure: true,
      rightToPortability: true,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Office of the Data Protection Commissioner',
    },
    childProtection: {
      name: 'DPA 2019 + Children Act',
      minAgeDigitalConsent: 18,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: ['NG', 'ZA', 'TZ', 'UG'],
  },
  IL: {
    code: 'IL',
    name: 'Israel',
    nameLocal: 'ישראל',
    legalSystem: 'mixed',
    languages: ['he', 'ar'],
    currency: 'ILS',
    professionalBodies: ISRAEL_BODIES,
    dataProtection: {
      name: 'PPL',
      fullName: 'Protection of Privacy Law 5741-1981',
      year: 1981,
      requiresExplicitConsent: true,
      digitalConsentAge: 14,
      breachNotificationHours: 0,
      rightToErasure: true,
      rightToPortability: false,
      crossBorderRestrictions: true,
      maxRetentionDays: 0,
      supervisoryAuthority: 'Privacy Protection Authority (PPA)',
      notes: 'EU adequacy decision. New comprehensive privacy bill pending.',
    },
    childProtection: {
      name: 'PPL + Youth Law',
      minAgeDigitalConsent: 14,
      ageOfMajority: 18,
      requiresParentalConsent: true,
      enhancedProtections: true,
      profilingRestrictions: false,
    },
    eSignatureRecognised: true,
    mutualRecognition: [],
  },
};

// --- Helper Functions ---

/** Get a jurisdiction by ISO code */
export function getJurisdiction(code: string): Jurisdiction | undefined {
  return JURISDICTIONS[code.toUpperCase()];
}

/** Get all jurisdiction codes */
export function getJurisdictionCodes(): string[] {
  return Object.keys(JURISDICTIONS);
}

/** Get professional bodies for a jurisdiction */
export function getProfessionalBodies(
  jurisdictionCode: string,
  profession?: ProfessionType
): ProfessionalBody[] {
  const j = getJurisdiction(jurisdictionCode);
  if (!j) return [];
  if (profession) return j.professionalBodies.filter((b) => b.profession === profession);
  return j.professionalBodies;
}

/** Find jurisdictions that have mutual recognition with a given jurisdiction */
export function getMutualRecognitionPartners(jurisdictionCode: string): Jurisdiction[] {
  const j = getJurisdiction(jurisdictionCode);
  if (!j) return [];
  return j.mutualRecognition
    .map((code) => getJurisdiction(code))
    .filter((j): j is Jurisdiction => j !== undefined);
}

/** Check if a profession is regulated in a jurisdiction */
export function isProfessionRegulated(
  jurisdictionCode: string,
  profession: ProfessionType
): boolean {
  return getProfessionalBodies(jurisdictionCode, profession).length > 0;
}

/** Find jurisdictions where a profession is regulated */
export function findJurisdictionsForProfession(profession: ProfessionType): Jurisdiction[] {
  return Object.values(JURISDICTIONS).filter((j) =>
    j.professionalBodies.some((b) => b.profession === profession)
  );
}

/** Get the digital consent age for a jurisdiction */
export function getDigitalConsentAge(jurisdictionCode: string): number {
  const j = getJurisdiction(jurisdictionCode);
  return j?.childProtection.minAgeDigitalConsent ?? 16;
}

/** Get the age of majority for a jurisdiction */
export function getAgeOfMajority(jurisdictionCode: string): number {
  const j = getJurisdiction(jurisdictionCode);
  return j?.childProtection.ageOfMajority ?? 18;
}

/** Check if two jurisdictions can transfer data to each other */
export function canTransferData(fromCode: string, toCode: string): {
  allowed: boolean;
  mechanism?: string;
  notes?: string;
} {
  const from = getJurisdiction(fromCode);
  const to = getJurisdiction(toCode);
  if (!from || !to) return { allowed: false, notes: 'Unknown jurisdiction' };

  // Normalise to uppercase for set lookups (getJurisdiction already uppercases internally)
  const fromUpper = fromCode.toUpperCase();
  const toUpper = toCode.toUpperCase();

  // Same jurisdiction — always allowed
  if (fromUpper === toUpper) return { allowed: true, mechanism: 'domestic' };

  // No cross-border restrictions — allowed
  if (!from.dataProtection.crossBorderRestrictions) {
    return { allowed: true, mechanism: 'no-restrictions' };
  }

  // EU/EEA internal — allowed (GDPR free flow) — check before mutual recognition
  // Full EU (27) + EEA (NO, IS, LI) membership list
  const euEea = new Set([
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
    'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
    'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
    // EEA non-EU
    'NO', 'IS', 'LI',
  ]);
  if (euEea.has(fromUpper) && euEea.has(toUpper)) {
    return { allowed: true, mechanism: 'eu-internal' };
  }

  // EU adequacy decisions (as of 2024 — subject to periodic review)
  const euAdequacy = new Set([
    'GB', 'JP', 'KR', 'AR', 'NZ', 'IL', 'CA', 'CH', 'UY', 'AD',
    'FO', 'GG', 'IM', 'JE',
  ]);
  if (euEea.has(fromUpper) && euAdequacy.has(toUpper)) {
    return { allowed: true, mechanism: 'adequacy-decision' };
  }

  // Mutual recognition — allowed with standard protections
  if (from.mutualRecognition.includes(toUpper)) {
    return { allowed: true, mechanism: 'mutual-recognition' };
  }

  // Default: requires additional safeguards
  return {
    allowed: true,
    mechanism: 'safeguards-required',
    notes: 'Requires Standard Contractual Clauses (SCCs) or equivalent safeguards.',
  };
}

/** Get all unique languages across all jurisdictions */
export function getAllLanguages(): string[] {
  const langs = new Set<string>();
  for (const j of Object.values(JURISDICTIONS)) {
    for (const l of j.languages) langs.add(l);
  }
  return [...langs].sort();
}

/** Get jurisdictions by language */
export function getJurisdictionsByLanguage(languageCode: string): Jurisdiction[] {
  return Object.values(JURISDICTIONS).filter((j) => j.languages.includes(languageCode));
}

// --- Jurisdiction Confidence ---

export interface JurisdictionConfidence {
  /** ISO 3166-1 alpha-2 code */
  code: string;
  /** Overall confidence score (0-100) */
  score: number;
  /** Breakdown of contributing factors */
  breakdown: {
    /** Number of professional bodies (0-20 points, 1pt per body, capped at 20) */
    professionalBodyCoverage: number;
    /** Proportion of bodies with public registers (0-20 points) */
    publicRegisterAvailability: number;
    /** Proportion of bodies issuing digital credentials (0-15 points) */
    digitalCredentialIssuance: number;
    /** Data protection law maturity (0-15 points) */
    dataProtectionMaturity: number;
    /** Number of mutual recognition partners (0-10 points, 1pt per partner, capped at 10) */
    mutualRecognition: number;
    /** E-signature legal recognition (0 or 10 points) */
    eSignatureRecognition: number;
    /** Legal system compatibility bonus (0-10 points) */
    legalSystemScore: number;
  };
}

/**
 * Compute a confidence score for a jurisdiction based on how well its
 * professional bodies and legal framework support Signet verification.
 * Higher scores mean credentials from this jurisdiction carry more weight.
 */
export function computeJurisdictionConfidence(jurisdictionCode: string): JurisdictionConfidence | undefined {
  const j = getJurisdiction(jurisdictionCode);
  if (!j) return undefined;

  const bodies = j.professionalBodies;

  // Professional body coverage: 1pt per body, max 20
  const professionalBodyCoverage = Math.min(bodies.length, 20);

  // Public register availability: proportion of bodies with public registers * 20
  const publicRegisterAvailability = bodies.length > 0
    ? Math.round((bodies.filter(b => b.hasPublicRegister).length / bodies.length) * 20)
    : 0;

  // Digital credential issuance: proportion of bodies issuing digital credentials * 15
  const digitalCredentialIssuance = bodies.length > 0
    ? Math.round((bodies.filter(b => b.issuesDigitalCredentials).length / bodies.length) * 15)
    : 0;

  // Data protection maturity: composite of key data protection features
  let dataProtectionMaturity = 0;
  const dp = j.dataProtection;
  if (dp.requiresExplicitConsent) dataProtectionMaturity += 3;
  if (dp.rightToErasure) dataProtectionMaturity += 3;
  if (dp.rightToPortability) dataProtectionMaturity += 3;
  if (dp.breachNotificationHours > 0) dataProtectionMaturity += 3;
  if (dp.crossBorderRestrictions) dataProtectionMaturity += 3;
  dataProtectionMaturity = Math.min(dataProtectionMaturity, 15);

  // Mutual recognition: 1pt per partner, max 10
  const mutualRecognition = Math.min(j.mutualRecognition.length, 10);

  // E-signature recognition: binary
  const eSignatureRecognition = j.eSignatureRecognised ? 10 : 0;

  // Legal system: common-law and civil-law score highest (well-established professional regulation)
  const legalSystemScores: Record<LegalSystem, number> = {
    'common-law': 10,
    'civil-law': 10,
    'mixed': 7,
    'religious': 4,
    'customary': 3,
  };
  const legalSystemScore = legalSystemScores[j.legalSystem] ?? 5;

  const score = Math.min(
    professionalBodyCoverage +
    publicRegisterAvailability +
    digitalCredentialIssuance +
    dataProtectionMaturity +
    mutualRecognition +
    eSignatureRecognition +
    legalSystemScore,
    100
  );

  return {
    code: j.code,
    score,
    breakdown: {
      professionalBodyCoverage,
      publicRegisterAvailability,
      digitalCredentialIssuance,
      dataProtectionMaturity,
      mutualRecognition,
      eSignatureRecognition,
      legalSystemScore,
    },
  };
}

/**
 * Get the jurisdiction confidence score (0-100) for a jurisdiction.
 * Returns 0 for unknown jurisdictions.
 */
export function getJurisdictionConfidence(jurisdictionCode: string): number {
  const confidence = computeJurisdictionConfidence(jurisdictionCode);
  return confidence?.score ?? 0;
}

/**
 * Get all jurisdictions ranked by confidence score (highest first).
 */
export function rankJurisdictionsByConfidence(): JurisdictionConfidence[] {
  return getJurisdictionCodes()
    .map(code => computeJurisdictionConfidence(code))
    .filter((c): c is JurisdictionConfidence => c !== undefined)
    .sort((a, b) => b.score - a.score);
}
