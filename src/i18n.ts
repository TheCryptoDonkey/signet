// Signet Internationalization Module
// Supports 15 languages for credential types, verification messages, legal terms,
// professional titles, and UI strings.

import { SignetValidationError } from './errors.js';

export type LanguageCode =
  | 'en' | 'es' | 'fr' | 'de' | 'pt' | 'ja' | 'ko'
  | 'zh' | 'ar' | 'hi' | 'it' | 'nl' | 'tr' | 'id' | 'sw';

export interface TranslationStrings {
  // --- Credential Types ---
  credential_self_declared: string;
  credential_vouched: string;
  credential_professional: string;
  credential_professional_child: string;
  credential_verifier: string;

  // --- Tiers ---
  tier_1: string;
  tier_2: string;
  tier_3: string;
  tier_4: string;
  tier_1_desc: string;
  tier_2_desc: string;
  tier_3_desc: string;
  tier_4_desc: string;

  // --- Professions ---
  profession_legal: string;
  profession_medical: string;
  profession_notary: string;
  profession_accounting: string;
  profession_engineering: string;
  profession_teaching: string;
  profession_financial: string;
  profession_veterinary: string;
  profession_pharmacy: string;
  profession_architecture: string;
  profession_social_work: string;

  // --- Verification Status ---
  status_valid: string;
  status_invalid: string;
  status_expired: string;
  status_revoked: string;
  status_pending: string;
  status_challenged: string;

  // --- Actions ---
  action_verify: string;
  action_issue: string;
  action_revoke: string;
  action_renew: string;
  action_vouch: string;
  action_challenge: string;

  // --- Verification Messages ---
  msg_credential_valid: string;
  msg_credential_invalid: string;
  msg_credential_expired: string;
  msg_signature_valid: string;
  msg_signature_invalid: string;
  msg_ring_signature_valid: string;
  msg_ring_signature_invalid: string;
  msg_age_proof_valid: string;
  msg_age_proof_invalid: string;
  msg_signet_score: string;

  // --- Legal Terms ---
  legal_privacy_policy: string;
  legal_terms_of_service: string;
  legal_data_processing: string;
  legal_consent: string;
  legal_right_to_erasure: string;
  legal_data_portability: string;
  legal_parental_consent: string;
  legal_child_protection: string;
  legal_cross_border_transfer: string;
  legal_data_retention: string;
  legal_breach_notification: string;

  // --- Scope ---
  scope_adult: string;
  scope_child: string;
  scope_adult_child: string;

  // --- Entity Types ---
  entity_natural_person: string;
  entity_persona: string;
  entity_personal_agent: string;
  entity_unlinked_personal_agent: string;
  entity_juridical_person: string;
  entity_juridical_persona: string;
  entity_organised_agent: string;
  entity_unlinked_organised_agent: string;
  entity_unlinked_agent: string;

  // --- Error Messages ---
  error_invalid_jurisdiction: string;
  error_profession_not_regulated: string;
  error_age_below_minimum: string;
  error_consent_required: string;
  error_cross_border_denied: string;
  error_credential_expired: string;
  error_verification_failed: string;
}

const en: TranslationStrings = {
  credential_self_declared: 'Self-Declared Identity',
  credential_vouched: 'Community Vouched Identity',
  credential_professional: 'Professionally Verified Identity',
  credential_professional_child: 'Professional Verification with Child Safety',
  credential_verifier: 'Verifier Credential',

  tier_1: 'Tier 1',
  tier_2: 'Tier 2',
  tier_3: 'Tier 3',
  tier_4: 'Tier 4',
  tier_1_desc: 'Self-declared — unverified claim of humanness',
  tier_2_desc: 'Web-of-trust — vouched for by community members',
  tier_3_desc: 'Professional — verified by a licensed professional',
  tier_4_desc: 'Professional + Child Safety — includes age range proof',

  profession_legal: 'Legal Professional',
  profession_medical: 'Medical Professional',
  profession_notary: 'Notary Public',
  profession_accounting: 'Chartered Accountant',
  profession_engineering: 'Professional Engineer',
  profession_teaching: 'Licensed Teacher',
  profession_financial: 'Financial Adviser',
  profession_veterinary: 'Veterinary Surgeon',
  profession_pharmacy: 'Pharmacist',
  profession_architecture: 'Architect',
  profession_social_work: 'Social Worker',

  status_valid: 'Valid',
  status_invalid: 'Invalid',
  status_expired: 'Expired',
  status_revoked: 'Revoked',
  status_pending: 'Pending',
  status_challenged: 'Under Challenge',

  action_verify: 'Verify',
  action_issue: 'Issue',
  action_revoke: 'Revoke',
  action_renew: 'Renew',
  action_vouch: 'Vouch',
  action_challenge: 'Challenge',

  msg_credential_valid: 'This credential is valid and has not expired.',
  msg_credential_invalid: 'This credential could not be verified.',
  msg_credential_expired: 'This credential has expired and should be renewed.',
  msg_signature_valid: 'Cryptographic signature verified successfully.',
  msg_signature_invalid: 'Cryptographic signature verification failed.',
  msg_ring_signature_valid: 'Ring signature verified — issuer is one of the authorised verifiers.',
  msg_ring_signature_invalid: 'Ring signature verification failed.',
  msg_age_proof_valid: 'Age range proof verified — age is within the declared range.',
  msg_age_proof_invalid: 'Age range proof verification failed.',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: 'Privacy Policy',
  legal_terms_of_service: 'Terms of Service',
  legal_data_processing: 'Data Processing Agreement',
  legal_consent: 'Consent',
  legal_right_to_erasure: 'Right to Erasure',
  legal_data_portability: 'Data Portability',
  legal_parental_consent: 'Parental Consent',
  legal_child_protection: 'Child Protection',
  legal_cross_border_transfer: 'Cross-Border Data Transfer',
  legal_data_retention: 'Data Retention',
  legal_breach_notification: 'Breach Notification',

  scope_adult: 'Adult Verification',
  scope_child: 'Child Verification',
  scope_adult_child: 'Adult + Child Verification',

  entity_natural_person: 'Person',
  entity_persona: 'Alias',
  entity_personal_agent: 'Personal Agent',
  entity_unlinked_personal_agent: 'Unlinked Personal Agent',
  entity_juridical_person: 'Organisation',
  entity_juridical_persona: 'Org Alias',
  entity_organised_agent: 'Organised Agent',
  entity_unlinked_organised_agent: 'Unlinked Org Agent',
  entity_unlinked_agent: 'Unlinked Agent',

  error_invalid_jurisdiction: 'The specified jurisdiction is not recognised.',
  error_profession_not_regulated: 'This profession is not regulated in the specified jurisdiction.',
  error_age_below_minimum: 'The subject does not meet the minimum age requirement.',
  error_consent_required: 'Explicit consent is required before processing.',
  error_cross_border_denied: 'Cross-border data transfer is not permitted without safeguards.',
  error_credential_expired: 'This credential has expired.',
  error_verification_failed: 'Verification could not be completed.',
};

const es: TranslationStrings = {
  credential_self_declared: 'Identidad Autodeclarada',
  credential_vouched: 'Identidad Avalada por la Comunidad',
  credential_professional: 'Identidad Verificada Profesionalmente',
  credential_professional_child: 'Verificación Profesional con Protección Infantil',
  credential_verifier: 'Credencial de Verificador',

  tier_1: 'Nivel 1',
  tier_2: 'Nivel 2',
  tier_3: 'Nivel 3',
  tier_4: 'Nivel 4',
  tier_1_desc: 'Autodeclarado — afirmación no verificada de humanidad',
  tier_2_desc: 'Red de confianza — avalado por miembros de la comunidad',
  tier_3_desc: 'Profesional — verificado por un profesional con licencia',
  tier_4_desc: 'Profesional + Protección Infantil — incluye prueba de rango de edad',

  profession_legal: 'Profesional del Derecho',
  profession_medical: 'Profesional Médico',
  profession_notary: 'Notario Público',
  profession_accounting: 'Contador Público',
  profession_engineering: 'Ingeniero Profesional',
  profession_teaching: 'Docente Certificado',
  profession_financial: 'Asesor Financiero',
  profession_veterinary: 'Médico Veterinario',
  profession_pharmacy: 'Farmacéutico',
  profession_architecture: 'Arquitecto',
  profession_social_work: 'Trabajador Social',

  status_valid: 'Válido',
  status_invalid: 'Inválido',
  status_expired: 'Expirado',
  status_revoked: 'Revocado',
  status_pending: 'Pendiente',
  status_challenged: 'Bajo Impugnación',

  action_verify: 'Verificar',
  action_issue: 'Emitir',
  action_revoke: 'Revocar',
  action_renew: 'Renovar',
  action_vouch: 'Avalar',
  action_challenge: 'Impugnar',

  msg_credential_valid: 'Esta credencial es válida y no ha expirado.',
  msg_credential_invalid: 'No se pudo verificar esta credencial.',
  msg_credential_expired: 'Esta credencial ha expirado y debe ser renovada.',
  msg_signature_valid: 'Firma criptográfica verificada correctamente.',
  msg_signature_invalid: 'La verificación de la firma criptográfica falló.',
  msg_ring_signature_valid: 'Firma de anillo verificada — el emisor es uno de los verificadores autorizados.',
  msg_ring_signature_invalid: 'La verificación de la firma de anillo falló.',
  msg_age_proof_valid: 'Prueba de rango de edad verificada — la edad está dentro del rango declarado.',
  msg_age_proof_invalid: 'La verificación de la prueba de rango de edad falló.',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: 'Política de Privacidad',
  legal_terms_of_service: 'Términos de Servicio',
  legal_data_processing: 'Acuerdo de Procesamiento de Datos',
  legal_consent: 'Consentimiento',
  legal_right_to_erasure: 'Derecho de Supresión',
  legal_data_portability: 'Portabilidad de Datos',
  legal_parental_consent: 'Consentimiento Parental',
  legal_child_protection: 'Protección Infantil',
  legal_cross_border_transfer: 'Transferencia Transfronteriza de Datos',
  legal_data_retention: 'Retención de Datos',
  legal_breach_notification: 'Notificación de Violación',

  scope_adult: 'Verificación de Adulto',
  scope_child: 'Verificación de Menor',
  scope_adult_child: 'Verificación de Adulto + Menor',

  entity_natural_person: 'Persona',
  entity_persona: 'Alias',
  entity_personal_agent: 'Agente Personal',
  entity_unlinked_personal_agent: 'Agente Personal Libre',
  entity_juridical_person: 'Organización',
  entity_juridical_persona: 'Alias de Organización',
  entity_organised_agent: 'Agente Organizado',
  entity_unlinked_organised_agent: 'Agente de Org Libre',
  entity_unlinked_agent: 'Agente Libre',

  error_invalid_jurisdiction: 'La jurisdicción especificada no es reconocida.',
  error_profession_not_regulated: 'Esta profesión no está regulada en la jurisdicción especificada.',
  error_age_below_minimum: 'El sujeto no cumple con el requisito mínimo de edad.',
  error_consent_required: 'Se requiere consentimiento explícito antes del procesamiento.',
  error_cross_border_denied: 'La transferencia transfronteriza de datos no está permitida sin salvaguardas.',
  error_credential_expired: 'Esta credencial ha expirado.',
  error_verification_failed: 'No se pudo completar la verificación.',
};

const fr: TranslationStrings = {
  credential_self_declared: 'Identité Auto-déclarée',
  credential_vouched: 'Identité Cautionnée par la Communauté',
  credential_professional: 'Identité Vérifiée Professionnellement',
  credential_professional_child: 'Vérification Professionnelle avec Protection de l\'Enfance',
  credential_verifier: 'Accréditation de Vérificateur',

  tier_1: 'Niveau 1',
  tier_2: 'Niveau 2',
  tier_3: 'Niveau 3',
  tier_4: 'Niveau 4',
  tier_1_desc: 'Auto-déclaré — affirmation non vérifiée d\'humanité',
  tier_2_desc: 'Réseau de confiance — cautionné par des membres de la communauté',
  tier_3_desc: 'Professionnel — vérifié par un professionnel agréé',
  tier_4_desc: 'Professionnel + Protection de l\'enfance — inclut une preuve de tranche d\'âge',

  profession_legal: 'Professionnel du Droit',
  profession_medical: 'Professionnel de la Santé',
  profession_notary: 'Notaire',
  profession_accounting: 'Expert-Comptable',
  profession_engineering: 'Ingénieur Professionnel',
  profession_teaching: 'Enseignant Certifié',
  profession_financial: 'Conseiller Financier',
  profession_veterinary: 'Vétérinaire',
  profession_pharmacy: 'Pharmacien',
  profession_architecture: 'Architecte',
  profession_social_work: 'Travailleur Social',

  status_valid: 'Valide',
  status_invalid: 'Invalide',
  status_expired: 'Expiré',
  status_revoked: 'Révoqué',
  status_pending: 'En attente',
  status_challenged: 'Contesté',

  action_verify: 'Vérifier',
  action_issue: 'Émettre',
  action_revoke: 'Révoquer',
  action_renew: 'Renouveler',
  action_vouch: 'Cautionner',
  action_challenge: 'Contester',

  msg_credential_valid: 'Cette accréditation est valide et n\'a pas expiré.',
  msg_credential_invalid: 'Cette accréditation n\'a pas pu être vérifiée.',
  msg_credential_expired: 'Cette accréditation a expiré et doit être renouvelée.',
  msg_signature_valid: 'Signature cryptographique vérifiée avec succès.',
  msg_signature_invalid: 'La vérification de la signature cryptographique a échoué.',
  msg_ring_signature_valid: 'Signature en anneau vérifiée — l\'émetteur est l\'un des vérificateurs autorisés.',
  msg_ring_signature_invalid: 'La vérification de la signature en anneau a échoué.',
  msg_age_proof_valid: 'Preuve de tranche d\'âge vérifiée — l\'âge est dans la tranche déclarée.',
  msg_age_proof_invalid: 'La vérification de la preuve de tranche d\'âge a échoué.',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: 'Politique de Confidentialité',
  legal_terms_of_service: 'Conditions d\'Utilisation',
  legal_data_processing: 'Accord de Traitement des Données',
  legal_consent: 'Consentement',
  legal_right_to_erasure: 'Droit à l\'Effacement',
  legal_data_portability: 'Portabilité des Données',
  legal_parental_consent: 'Consentement Parental',
  legal_child_protection: 'Protection de l\'Enfance',
  legal_cross_border_transfer: 'Transfert Transfrontalier de Données',
  legal_data_retention: 'Conservation des Données',
  legal_breach_notification: 'Notification de Violation',

  scope_adult: 'Vérification Adulte',
  scope_child: 'Vérification Enfant',
  scope_adult_child: 'Vérification Adulte + Enfant',

  entity_natural_person: 'Personne',
  entity_persona: 'Alias',
  entity_personal_agent: 'Agent Personnel',
  entity_unlinked_personal_agent: 'Agent Personnel Libre',
  entity_juridical_person: 'Organisation',
  entity_juridical_persona: 'Alias d\'Organisation',
  entity_organised_agent: 'Agent Organisé',
  entity_unlinked_organised_agent: 'Agent d\'Org Libre',
  entity_unlinked_agent: 'Agent Libre',

  error_invalid_jurisdiction: 'La juridiction spécifiée n\'est pas reconnue.',
  error_profession_not_regulated: 'Cette profession n\'est pas réglementée dans la juridiction spécifiée.',
  error_age_below_minimum: 'Le sujet ne satisfait pas l\'exigence d\'âge minimum.',
  error_consent_required: 'Le consentement explicite est requis avant le traitement.',
  error_cross_border_denied: 'Le transfert transfrontalier de données n\'est pas autorisé sans garanties.',
  error_credential_expired: 'Cette accréditation a expiré.',
  error_verification_failed: 'La vérification n\'a pas pu être effectuée.',
};

const de: TranslationStrings = {
  credential_self_declared: 'Selbsterklärte Identität',
  credential_vouched: 'Gemeinschaftlich Bestätigte Identität',
  credential_professional: 'Beruflich Verifizierte Identität',
  credential_professional_child: 'Berufliche Verifizierung mit Kinderschutz',
  credential_verifier: 'Prüfernachweis',

  tier_1: 'Stufe 1',
  tier_2: 'Stufe 2',
  tier_3: 'Stufe 3',
  tier_4: 'Stufe 4',
  tier_1_desc: 'Selbsterklärung — nicht verifizierte Behauptung der Menschlichkeit',
  tier_2_desc: 'Vertrauensnetzwerk — von Gemeinschaftsmitgliedern bestätigt',
  tier_3_desc: 'Professionell — von einem lizenzierten Fachmann verifiziert',
  tier_4_desc: 'Professionell + Kinderschutz — beinhaltet Altersbereichsnachweis',

  profession_legal: 'Rechtsanwalt',
  profession_medical: 'Arzt',
  profession_notary: 'Notar',
  profession_accounting: 'Wirtschaftsprüfer',
  profession_engineering: 'Ingenieur',
  profession_teaching: 'Lehrer',
  profession_financial: 'Finanzberater',
  profession_veterinary: 'Tierarzt',
  profession_pharmacy: 'Apotheker',
  profession_architecture: 'Architekt',
  profession_social_work: 'Sozialarbeiter',

  status_valid: 'Gültig',
  status_invalid: 'Ungültig',
  status_expired: 'Abgelaufen',
  status_revoked: 'Widerrufen',
  status_pending: 'Ausstehend',
  status_challenged: 'Angefochten',

  action_verify: 'Verifizieren',
  action_issue: 'Ausstellen',
  action_revoke: 'Widerrufen',
  action_renew: 'Erneuern',
  action_vouch: 'Bürgen',
  action_challenge: 'Anfechten',

  msg_credential_valid: 'Dieser Nachweis ist gültig und nicht abgelaufen.',
  msg_credential_invalid: 'Dieser Nachweis konnte nicht verifiziert werden.',
  msg_credential_expired: 'Dieser Nachweis ist abgelaufen und sollte erneuert werden.',
  msg_signature_valid: 'Kryptographische Signatur erfolgreich verifiziert.',
  msg_signature_invalid: 'Verifizierung der kryptographischen Signatur fehlgeschlagen.',
  msg_ring_signature_valid: 'Ringsignatur verifiziert — der Aussteller ist einer der autorisierten Prüfer.',
  msg_ring_signature_invalid: 'Verifizierung der Ringsignatur fehlgeschlagen.',
  msg_age_proof_valid: 'Altersbereichsnachweis verifiziert — das Alter liegt im angegebenen Bereich.',
  msg_age_proof_invalid: 'Verifizierung des Altersbereichsnachweises fehlgeschlagen.',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: 'Datenschutzerklärung',
  legal_terms_of_service: 'Nutzungsbedingungen',
  legal_data_processing: 'Auftragsverarbeitungsvertrag',
  legal_consent: 'Einwilligung',
  legal_right_to_erasure: 'Recht auf Löschung',
  legal_data_portability: 'Datenübertragbarkeit',
  legal_parental_consent: 'Elterliche Einwilligung',
  legal_child_protection: 'Kinderschutz',
  legal_cross_border_transfer: 'Grenzüberschreitende Datenübermittlung',
  legal_data_retention: 'Datenaufbewahrung',
  legal_breach_notification: 'Meldung von Datenschutzverletzungen',

  scope_adult: 'Erwachsenenverifizierung',
  scope_child: 'Kinderverifizierung',
  scope_adult_child: 'Erwachsenen- + Kinderverifizierung',

  entity_natural_person: 'Person',
  entity_persona: 'Alias',
  entity_personal_agent: 'Persönlicher Agent',
  entity_unlinked_personal_agent: 'Freier Persönlicher Agent',
  entity_juridical_person: 'Organisation',
  entity_juridical_persona: 'Org-Alias',
  entity_organised_agent: 'Organisierter Agent',
  entity_unlinked_organised_agent: 'Freier Org-Agent',
  entity_unlinked_agent: 'Freier Agent',

  error_invalid_jurisdiction: 'Die angegebene Gerichtsbarkeit wird nicht anerkannt.',
  error_profession_not_regulated: 'Dieser Beruf ist in der angegebenen Gerichtsbarkeit nicht reguliert.',
  error_age_below_minimum: 'Die Person erfüllt nicht die Mindestaltersanforderung.',
  error_consent_required: 'Vor der Verarbeitung ist eine ausdrückliche Einwilligung erforderlich.',
  error_cross_border_denied: 'Grenzüberschreitende Datenübermittlung ist ohne Schutzmaßnahmen nicht gestattet.',
  error_credential_expired: 'Dieser Nachweis ist abgelaufen.',
  error_verification_failed: 'Die Verifizierung konnte nicht abgeschlossen werden.',
};

const pt: TranslationStrings = {
  credential_self_declared: 'Identidade Autodeclarada',
  credential_vouched: 'Identidade Atestada pela Comunidade',
  credential_professional: 'Identidade Verificada Profissionalmente',
  credential_professional_child: 'Verificação Profissional com Proteção Infantil',
  credential_verifier: 'Credencial de Verificador',

  tier_1: 'Nível 1',
  tier_2: 'Nível 2',
  tier_3: 'Nível 3',
  tier_4: 'Nível 4',
  tier_1_desc: 'Autodeclarado — afirmação não verificada de humanidade',
  tier_2_desc: 'Rede de confiança — atestado por membros da comunidade',
  tier_3_desc: 'Profissional — verificado por um profissional licenciado',
  tier_4_desc: 'Profissional + Proteção Infantil — inclui prova de faixa etária',

  profession_legal: 'Advogado',
  profession_medical: 'Médico',
  profession_notary: 'Notário',
  profession_accounting: 'Contador',
  profession_engineering: 'Engenheiro',
  profession_teaching: 'Professor',
  profession_financial: 'Consultor Financeiro',
  profession_veterinary: 'Veterinário',
  profession_pharmacy: 'Farmacêutico',
  profession_architecture: 'Arquiteto',
  profession_social_work: 'Assistente Social',

  status_valid: 'Válido',
  status_invalid: 'Inválido',
  status_expired: 'Expirado',
  status_revoked: 'Revogado',
  status_pending: 'Pendente',
  status_challenged: 'Sob Contestação',

  action_verify: 'Verificar',
  action_issue: 'Emitir',
  action_revoke: 'Revogar',
  action_renew: 'Renovar',
  action_vouch: 'Atestar',
  action_challenge: 'Contestar',

  msg_credential_valid: 'Esta credencial é válida e não expirou.',
  msg_credential_invalid: 'Não foi possível verificar esta credencial.',
  msg_credential_expired: 'Esta credencial expirou e deve ser renovada.',
  msg_signature_valid: 'Assinatura criptográfica verificada com sucesso.',
  msg_signature_invalid: 'Falha na verificação da assinatura criptográfica.',
  msg_ring_signature_valid: 'Assinatura em anel verificada — o emissor é um dos verificadores autorizados.',
  msg_ring_signature_invalid: 'Falha na verificação da assinatura em anel.',
  msg_age_proof_valid: 'Prova de faixa etária verificada — a idade está dentro da faixa declarada.',
  msg_age_proof_invalid: 'Falha na verificação da prova de faixa etária.',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: 'Política de Privacidade',
  legal_terms_of_service: 'Termos de Serviço',
  legal_data_processing: 'Acordo de Processamento de Dados',
  legal_consent: 'Consentimento',
  legal_right_to_erasure: 'Direito ao Apagamento',
  legal_data_portability: 'Portabilidade de Dados',
  legal_parental_consent: 'Consentimento Parental',
  legal_child_protection: 'Proteção Infantil',
  legal_cross_border_transfer: 'Transferência Transfronteiriça de Dados',
  legal_data_retention: 'Retenção de Dados',
  legal_breach_notification: 'Notificação de Violação',

  scope_adult: 'Verificação de Adulto',
  scope_child: 'Verificação de Criança',
  scope_adult_child: 'Verificação de Adulto + Criança',

  entity_natural_person: 'Pessoa',
  entity_persona: 'Alias',
  entity_personal_agent: 'Agente Pessoal',
  entity_unlinked_personal_agent: 'Agente Pessoal Livre',
  entity_juridical_person: 'Organização',
  entity_juridical_persona: 'Alias de Organização',
  entity_organised_agent: 'Agente Organizado',
  entity_unlinked_organised_agent: 'Agente de Org Livre',
  entity_unlinked_agent: 'Agente Livre',

  error_invalid_jurisdiction: 'A jurisdição especificada não é reconhecida.',
  error_profession_not_regulated: 'Esta profissão não é regulamentada na jurisdição especificada.',
  error_age_below_minimum: 'O sujeito não atende ao requisito mínimo de idade.',
  error_consent_required: 'O consentimento explícito é necessário antes do processamento.',
  error_cross_border_denied: 'A transferência transfronteiriça de dados não é permitida sem salvaguardas.',
  error_credential_expired: 'Esta credencial expirou.',
  error_verification_failed: 'A verificação não pôde ser concluída.',
};

const ja: TranslationStrings = {
  credential_self_declared: '自己申告型アイデンティティ',
  credential_vouched: 'コミュニティ保証型アイデンティティ',
  credential_professional: '専門家検証済みアイデンティティ',
  credential_professional_child: '専門家検証＋児童保護付きアイデンティティ',
  credential_verifier: '検証者資格証明',

  tier_1: 'ティア1',
  tier_2: 'ティア2',
  tier_3: 'ティア3',
  tier_4: 'ティア4',
  tier_1_desc: '自己申告 — 未検証の人間性の主張',
  tier_2_desc: '信頼ネットワーク — コミュニティメンバーによる保証',
  tier_3_desc: '専門家 — 資格を持つ専門家による検証',
  tier_4_desc: '専門家＋児童保護 — 年齢範囲証明を含む',

  profession_legal: '法律専門家',
  profession_medical: '医療専門家',
  profession_notary: '公証人',
  profession_accounting: '公認会計士',
  profession_engineering: '技術士',
  profession_teaching: '教員',
  profession_financial: 'ファイナンシャルアドバイザー',
  profession_veterinary: '獣医師',
  profession_pharmacy: '薬剤師',
  profession_architecture: '建築士',
  profession_social_work: '社会福祉士',

  status_valid: '有効',
  status_invalid: '無効',
  status_expired: '期限切れ',
  status_revoked: '取消済み',
  status_pending: '保留中',
  status_challenged: '異議申立中',

  action_verify: '検証する',
  action_issue: '発行する',
  action_revoke: '取り消す',
  action_renew: '更新する',
  action_vouch: '保証する',
  action_challenge: '異議を申し立てる',

  msg_credential_valid: 'この資格証明は有効であり、期限切れではありません。',
  msg_credential_invalid: 'この資格証明を検証できませんでした。',
  msg_credential_expired: 'この資格証明は期限切れです。更新が必要です。',
  msg_signature_valid: '暗号署名が正常に検証されました。',
  msg_signature_invalid: '暗号署名の検証に失敗しました。',
  msg_ring_signature_valid: 'リング署名が検証されました — 発行者は承認された検証者の一人です。',
  msg_ring_signature_invalid: 'リング署名の検証に失敗しました。',
  msg_age_proof_valid: '年齢範囲証明が検証されました — 年齢は申告された範囲内です。',
  msg_age_proof_invalid: '年齢範囲証明の検証に失敗しました。',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: 'プライバシーポリシー',
  legal_terms_of_service: '利用規約',
  legal_data_processing: 'データ処理契約',
  legal_consent: '同意',
  legal_right_to_erasure: '消去権',
  legal_data_portability: 'データポータビリティ',
  legal_parental_consent: '保護者の同意',
  legal_child_protection: '児童保護',
  legal_cross_border_transfer: '越境データ移転',
  legal_data_retention: 'データ保持',
  legal_breach_notification: '違反通知',

  scope_adult: '成人検証',
  scope_child: '児童検証',
  scope_adult_child: '成人＋児童検証',

  entity_natural_person: '個人',
  entity_persona: 'エイリアス',
  entity_personal_agent: '個人エージェント',
  entity_unlinked_personal_agent: 'フリー個人エージェント',
  entity_juridical_person: '組織',
  entity_juridical_persona: '組織エイリアス',
  entity_organised_agent: '組織エージェント',
  entity_unlinked_organised_agent: 'フリー組織エージェント',
  entity_unlinked_agent: 'フリーエージェント',

  error_invalid_jurisdiction: '指定された管轄区域は認識されていません。',
  error_profession_not_regulated: 'この職業は指定された管轄区域で規制されていません。',
  error_age_below_minimum: '対象者は最低年齢要件を満たしていません。',
  error_consent_required: '処理前に明示的な同意が必要です。',
  error_cross_border_denied: '安全措置なしでの越境データ移転は許可されていません。',
  error_credential_expired: 'この資格証明は期限切れです。',
  error_verification_failed: '検証を完了できませんでした。',
};

const ko: TranslationStrings = {
  credential_self_declared: '자기 선언 신원',
  credential_vouched: '커뮤니티 보증 신원',
  credential_professional: '전문가 검증 신원',
  credential_professional_child: '전문가 검증 + 아동 보호',
  credential_verifier: '검증자 자격증명',

  tier_1: '1단계',
  tier_2: '2단계',
  tier_3: '3단계',
  tier_4: '4단계',
  tier_1_desc: '자기 선언 — 미검증된 인간성 주장',
  tier_2_desc: '신뢰 네트워크 — 커뮤니티 구성원의 보증',
  tier_3_desc: '전문가 — 면허를 가진 전문가의 검증',
  tier_4_desc: '전문가 + 아동 보호 — 연령 범위 증명 포함',

  profession_legal: '법률 전문가',
  profession_medical: '의료 전문가',
  profession_notary: '공증인',
  profession_accounting: '공인회계사',
  profession_engineering: '기술사',
  profession_teaching: '교사',
  profession_financial: '재정 고문',
  profession_veterinary: '수의사',
  profession_pharmacy: '약사',
  profession_architecture: '건축사',
  profession_social_work: '사회복지사',

  status_valid: '유효',
  status_invalid: '무효',
  status_expired: '만료',
  status_revoked: '취소됨',
  status_pending: '보류 중',
  status_challenged: '이의 제기 중',

  action_verify: '검증',
  action_issue: '발급',
  action_revoke: '취소',
  action_renew: '갱신',
  action_vouch: '보증',
  action_challenge: '이의 제기',

  msg_credential_valid: '이 자격증명은 유효하며 만료되지 않았습니다.',
  msg_credential_invalid: '이 자격증명을 검증할 수 없습니다.',
  msg_credential_expired: '이 자격증명이 만료되었으며 갱신이 필요합니다.',
  msg_signature_valid: '암호화 서명이 성공적으로 검증되었습니다.',
  msg_signature_invalid: '암호화 서명 검증에 실패했습니다.',
  msg_ring_signature_valid: '링 서명이 검증되었습니다 — 발급자는 승인된 검증자 중 한 명입니다.',
  msg_ring_signature_invalid: '링 서명 검증에 실패했습니다.',
  msg_age_proof_valid: '연령 범위 증명이 검증되었습니다 — 연령이 선언된 범위 내에 있습니다.',
  msg_age_proof_invalid: '연령 범위 증명 검증에 실패했습니다.',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: '개인정보 보호정책',
  legal_terms_of_service: '이용약관',
  legal_data_processing: '데이터 처리 계약',
  legal_consent: '동의',
  legal_right_to_erasure: '삭제권',
  legal_data_portability: '데이터 이동권',
  legal_parental_consent: '부모 동의',
  legal_child_protection: '아동 보호',
  legal_cross_border_transfer: '국경 간 데이터 전송',
  legal_data_retention: '데이터 보유',
  legal_breach_notification: '침해 통지',

  scope_adult: '성인 검증',
  scope_child: '아동 검증',
  scope_adult_child: '성인 + 아동 검증',

  entity_natural_person: '개인',
  entity_persona: '별칭',
  entity_personal_agent: '개인 에이전트',
  entity_unlinked_personal_agent: '자유 개인 에이전트',
  entity_juridical_person: '조직',
  entity_juridical_persona: '조직 별칭',
  entity_organised_agent: '조직 에이전트',
  entity_unlinked_organised_agent: '자유 조직 에이전트',
  entity_unlinked_agent: '자유 에이전트',

  error_invalid_jurisdiction: '지정된 관할권이 인식되지 않습니다.',
  error_profession_not_regulated: '이 직업은 지정된 관할권에서 규제되지 않습니다.',
  error_age_below_minimum: '대상자가 최소 연령 요건을 충족하지 않습니다.',
  error_consent_required: '처리 전에 명시적 동의가 필요합니다.',
  error_cross_border_denied: '보호 조치 없이 국경 간 데이터 전송이 허용되지 않습니다.',
  error_credential_expired: '이 자격증명이 만료되었습니다.',
  error_verification_failed: '검증을 완료할 수 없습니다.',
};

const zh: TranslationStrings = {
  credential_self_declared: '自我声明身份',
  credential_vouched: '社区担保身份',
  credential_professional: '专业验证身份',
  credential_professional_child: '专业验证+儿童保护',
  credential_verifier: '验证者凭证',

  tier_1: '第一级',
  tier_2: '第二级',
  tier_3: '第三级',
  tier_4: '第四级',
  tier_1_desc: '自我声明 — 未经验证的人类身份声明',
  tier_2_desc: '信任网络 — 由社区成员担保',
  tier_3_desc: '专业 — 由持证专业人士验证',
  tier_4_desc: '专业+儿童保护 — 包含年龄范围证明',

  profession_legal: '法律专业人士',
  profession_medical: '医疗专业人士',
  profession_notary: '公证人',
  profession_accounting: '注册会计师',
  profession_engineering: '注册工程师',
  profession_teaching: '持证教师',
  profession_financial: '理财顾问',
  profession_veterinary: '兽医',
  profession_pharmacy: '药剂师',
  profession_architecture: '建筑师',
  profession_social_work: '社会工作者',

  status_valid: '有效',
  status_invalid: '无效',
  status_expired: '已过期',
  status_revoked: '已撤销',
  status_pending: '待处理',
  status_challenged: '被质疑',

  action_verify: '验证',
  action_issue: '签发',
  action_revoke: '撤销',
  action_renew: '续期',
  action_vouch: '担保',
  action_challenge: '质疑',

  msg_credential_valid: '此凭证有效且未过期。',
  msg_credential_invalid: '无法验证此凭证。',
  msg_credential_expired: '此凭证已过期，需要续期。',
  msg_signature_valid: '密码学签名验证成功。',
  msg_signature_invalid: '密码学签名验证失败。',
  msg_ring_signature_valid: '环签名已验证 — 签发者是授权验证者之一。',
  msg_ring_signature_invalid: '环签名验证失败。',
  msg_age_proof_valid: '年龄范围证明已验证 — 年龄在声明的范围内。',
  msg_age_proof_invalid: '年龄范围证明验证失败。',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: '隐私政策',
  legal_terms_of_service: '服务条款',
  legal_data_processing: '数据处理协议',
  legal_consent: '同意',
  legal_right_to_erasure: '删除权',
  legal_data_portability: '数据可携带性',
  legal_parental_consent: '家长同意',
  legal_child_protection: '儿童保护',
  legal_cross_border_transfer: '跨境数据传输',
  legal_data_retention: '数据保留',
  legal_breach_notification: '违规通知',

  scope_adult: '成人验证',
  scope_child: '儿童验证',
  scope_adult_child: '成人+儿童验证',

  entity_natural_person: '个人',
  entity_persona: '别名',
  entity_personal_agent: '个人代理',
  entity_unlinked_personal_agent: '自由个人代理',
  entity_juridical_person: '组织',
  entity_juridical_persona: '组织别名',
  entity_organised_agent: '组织代理',
  entity_unlinked_organised_agent: '自由组织代理',
  entity_unlinked_agent: '自由代理',

  error_invalid_jurisdiction: '指定的司法管辖区未被识别。',
  error_profession_not_regulated: '该职业在指定的司法管辖区不受监管。',
  error_age_below_minimum: '对象不符合最低年龄要求。',
  error_consent_required: '处理前需要明确同意。',
  error_cross_border_denied: '没有保障措施不允许跨境数据传输。',
  error_credential_expired: '此凭证已过期。',
  error_verification_failed: '无法完成验证。',
};

const ar: TranslationStrings = {
  credential_self_declared: 'هوية معلنة ذاتياً',
  credential_vouched: 'هوية مكفولة من المجتمع',
  credential_professional: 'هوية موثقة مهنياً',
  credential_professional_child: 'توثيق مهني مع حماية الطفل',
  credential_verifier: 'شهادة المحقق',

  tier_1: 'المستوى 1',
  tier_2: 'المستوى 2',
  tier_3: 'المستوى 3',
  tier_4: 'المستوى 4',
  tier_1_desc: 'إعلان ذاتي — ادعاء غير موثق بالإنسانية',
  tier_2_desc: 'شبكة ثقة — مكفول من أعضاء المجتمع',
  tier_3_desc: 'مهني — تم التحقق منه بواسطة متخصص مرخص',
  tier_4_desc: 'مهني + حماية الطفل — يتضمن إثبات نطاق العمر',

  profession_legal: 'محامي',
  profession_medical: 'طبيب',
  profession_notary: 'كاتب عدل',
  profession_accounting: 'محاسب قانوني',
  profession_engineering: 'مهندس معتمد',
  profession_teaching: 'معلم مرخص',
  profession_financial: 'مستشار مالي',
  profession_veterinary: 'طبيب بيطري',
  profession_pharmacy: 'صيدلي',
  profession_architecture: 'مهندس معماري',
  profession_social_work: 'أخصائي اجتماعي',

  status_valid: 'صالح',
  status_invalid: 'غير صالح',
  status_expired: 'منتهي الصلاحية',
  status_revoked: 'ملغى',
  status_pending: 'قيد الانتظار',
  status_challenged: 'قيد الطعن',

  action_verify: 'تحقق',
  action_issue: 'إصدار',
  action_revoke: 'إلغاء',
  action_renew: 'تجديد',
  action_vouch: 'كفالة',
  action_challenge: 'طعن',

  msg_credential_valid: 'هذه الشهادة صالحة ولم تنتهِ صلاحيتها.',
  msg_credential_invalid: 'لم يتم التحقق من هذه الشهادة.',
  msg_credential_expired: 'انتهت صلاحية هذه الشهادة ويجب تجديدها.',
  msg_signature_valid: 'تم التحقق من التوقيع المشفر بنجاح.',
  msg_signature_invalid: 'فشل التحقق من التوقيع المشفر.',
  msg_ring_signature_valid: 'تم التحقق من توقيع الحلقة — المُصدر هو أحد المحققين المعتمدين.',
  msg_ring_signature_invalid: 'فشل التحقق من توقيع الحلقة.',
  msg_age_proof_valid: 'تم التحقق من إثبات نطاق العمر — العمر ضمن النطاق المعلن.',
  msg_age_proof_invalid: 'فشل التحقق من إثبات نطاق العمر.',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: 'سياسة الخصوصية',
  legal_terms_of_service: 'شروط الخدمة',
  legal_data_processing: 'اتفاقية معالجة البيانات',
  legal_consent: 'الموافقة',
  legal_right_to_erasure: 'حق المحو',
  legal_data_portability: 'قابلية نقل البيانات',
  legal_parental_consent: 'موافقة الوالدين',
  legal_child_protection: 'حماية الطفل',
  legal_cross_border_transfer: 'نقل البيانات عبر الحدود',
  legal_data_retention: 'الاحتفاظ بالبيانات',
  legal_breach_notification: 'إشعار الاختراق',

  scope_adult: 'التحقق من البالغين',
  scope_child: 'التحقق من الأطفال',
  scope_adult_child: 'التحقق من البالغين + الأطفال',

  entity_natural_person: 'شخص',
  entity_persona: 'اسم مستعار',
  entity_personal_agent: 'وكيل شخصي',
  entity_unlinked_personal_agent: 'وكيل شخصي حر',
  entity_juridical_person: 'مؤسسة',
  entity_juridical_persona: 'اسم مستعار للمؤسسة',
  entity_organised_agent: 'وكيل منظم',
  entity_unlinked_organised_agent: 'وكيل مؤسسة حر',
  entity_unlinked_agent: 'وكيل حر',

  error_invalid_jurisdiction: 'الولاية القضائية المحددة غير معترف بها.',
  error_profession_not_regulated: 'هذه المهنة غير منظمة في الولاية القضائية المحددة.',
  error_age_below_minimum: 'الشخص لا يستوفي الحد الأدنى لمتطلبات العمر.',
  error_consent_required: 'الموافقة الصريحة مطلوبة قبل المعالجة.',
  error_cross_border_denied: 'نقل البيانات عبر الحدود غير مسموح به بدون ضمانات.',
  error_credential_expired: 'انتهت صلاحية هذه الشهادة.',
  error_verification_failed: 'لم يتم إتمام التحقق.',
};

const hi: TranslationStrings = {
  credential_self_declared: 'स्व-घोषित पहचान',
  credential_vouched: 'समुदाय प्रमाणित पहचान',
  credential_professional: 'पेशेवर सत्यापित पहचान',
  credential_professional_child: 'पेशेवर सत्यापन + बाल सुरक्षा',
  credential_verifier: 'सत्यापनकर्ता प्रमाणपत्र',

  tier_1: 'स्तर 1',
  tier_2: 'स्तर 2',
  tier_3: 'स्तर 3',
  tier_4: 'स्तर 4',
  tier_1_desc: 'स्व-घोषित — मानवता का असत्यापित दावा',
  tier_2_desc: 'विश्वास नेटवर्क — समुदाय के सदस्यों द्वारा प्रमाणित',
  tier_3_desc: 'पेशेवर — लाइसेंस प्राप्त पेशेवर द्वारा सत्यापित',
  tier_4_desc: 'पेशेवर + बाल सुरक्षा — आयु सीमा प्रमाण सहित',

  profession_legal: 'कानूनी पेशेवर',
  profession_medical: 'चिकित्सा पेशेवर',
  profession_notary: 'नोटरी',
  profession_accounting: 'चार्टर्ड एकाउंटेंट',
  profession_engineering: 'पेशेवर इंजीनियर',
  profession_teaching: 'लाइसेंस प्राप्त शिक्षक',
  profession_financial: 'वित्तीय सलाहकार',
  profession_veterinary: 'पशु चिकित्सक',
  profession_pharmacy: 'फार्मासिस्ट',
  profession_architecture: 'वास्तुकार',
  profession_social_work: 'सामाजिक कार्यकर्ता',

  status_valid: 'वैध',
  status_invalid: 'अमान्य',
  status_expired: 'समाप्त',
  status_revoked: 'निरस्त',
  status_pending: 'लंबित',
  status_challenged: 'चुनौती के अधीन',

  action_verify: 'सत्यापित करें',
  action_issue: 'जारी करें',
  action_revoke: 'निरस्त करें',
  action_renew: 'नवीनीकरण करें',
  action_vouch: 'प्रमाणित करें',
  action_challenge: 'चुनौती दें',

  msg_credential_valid: 'यह प्रमाणपत्र वैध है और समाप्त नहीं हुआ है।',
  msg_credential_invalid: 'इस प्रमाणपत्र को सत्यापित नहीं किया जा सका।',
  msg_credential_expired: 'यह प्रमाणपत्र समाप्त हो गया है और इसे नवीनीकृत किया जाना चाहिए।',
  msg_signature_valid: 'क्रिप्टोग्राफिक हस्ताक्षर सफलतापूर्वक सत्यापित।',
  msg_signature_invalid: 'क्रिप्टोग्राफिक हस्ताक्षर सत्यापन विफल।',
  msg_ring_signature_valid: 'रिंग हस्ताक्षर सत्यापित — जारीकर्ता अधिकृत सत्यापनकर्ताओं में से एक है।',
  msg_ring_signature_invalid: 'रिंग हस्ताक्षर सत्यापन विफल।',
  msg_age_proof_valid: 'आयु सीमा प्रमाण सत्यापित — आयु घोषित सीमा के भीतर है।',
  msg_age_proof_invalid: 'आयु सीमा प्रमाण सत्यापन विफल।',
  msg_signet_score: 'Signet Score',

  legal_privacy_policy: 'गोपनीयता नीति',
  legal_terms_of_service: 'सेवा की शर्तें',
  legal_data_processing: 'डेटा प्रोसेसिंग समझौता',
  legal_consent: 'सहमति',
  legal_right_to_erasure: 'मिटाने का अधिकार',
  legal_data_portability: 'डेटा पोर्टेबिलिटी',
  legal_parental_consent: 'माता-पिता की सहमति',
  legal_child_protection: 'बाल सुरक्षा',
  legal_cross_border_transfer: 'सीमा पार डेटा हस्तांतरण',
  legal_data_retention: 'डेटा प्रतिधारण',
  legal_breach_notification: 'उल्लंघन अधिसूचना',

  scope_adult: 'वयस्क सत्यापन',
  scope_child: 'बाल सत्यापन',
  scope_adult_child: 'वयस्क + बाल सत्यापन',

  entity_natural_person: 'व्यक्ति',
  entity_persona: 'उपनाम',
  entity_personal_agent: 'व्यक्तिगत एजेंट',
  entity_unlinked_personal_agent: 'मुक्त व्यक्तिगत एजेंट',
  entity_juridical_person: 'संगठन',
  entity_juridical_persona: 'संगठन उपनाम',
  entity_organised_agent: 'संगठित एजेंट',
  entity_unlinked_organised_agent: 'मुक्त संगठन एजेंट',
  entity_unlinked_agent: 'मुक्त एजेंट',

  error_invalid_jurisdiction: 'निर्दिष्ट अधिकार क्षेत्र मान्यता प्राप्त नहीं है।',
  error_profession_not_regulated: 'यह पेशा निर्दिष्ट अधिकार क्षेत्र में विनियमित नहीं है।',
  error_age_below_minimum: 'विषय न्यूनतम आयु आवश्यकता को पूरा नहीं करता।',
  error_consent_required: 'प्रसंस्करण से पहले स्पष्ट सहमति आवश्यक है।',
  error_cross_border_denied: 'सुरक्षा उपायों के बिना सीमा पार डेटा हस्तांतरण की अनुमति नहीं है।',
  error_credential_expired: 'यह प्रमाणपत्र समाप्त हो गया है।',
  error_verification_failed: 'सत्यापन पूरा नहीं हो सका।',
};

const it: TranslationStrings = {
  credential_self_declared: 'Identità Autodichiarata',
  credential_vouched: 'Identità Garantita dalla Comunità',
  credential_professional: 'Identità Verificata Professionalmente',
  credential_professional_child: 'Verifica Professionale con Protezione dei Minori',
  credential_verifier: 'Credenziale del Verificatore',
  tier_1: 'Livello 1', tier_2: 'Livello 2', tier_3: 'Livello 3', tier_4: 'Livello 4',
  tier_1_desc: 'Autodichiarato — affermazione non verificata di umanità',
  tier_2_desc: 'Rete di fiducia — garantito da membri della comunità',
  tier_3_desc: 'Professionale — verificato da un professionista abilitato',
  tier_4_desc: 'Professionale + Protezione Minori — include prova della fascia d\'età',
  profession_legal: 'Avvocato', profession_medical: 'Medico', profession_notary: 'Notaio',
  profession_accounting: 'Commercialista', profession_engineering: 'Ingegnere',
  profession_teaching: 'Insegnante', profession_financial: 'Consulente Finanziario',
  profession_veterinary: 'Veterinario', profession_pharmacy: 'Farmacista',
  profession_architecture: 'Architetto', profession_social_work: 'Assistente Sociale',
  status_valid: 'Valido', status_invalid: 'Non Valido', status_expired: 'Scaduto',
  status_revoked: 'Revocato', status_pending: 'In Attesa', status_challenged: 'Contestato',
  action_verify: 'Verificare', action_issue: 'Emettere', action_revoke: 'Revocare',
  action_renew: 'Rinnovare', action_vouch: 'Garantire', action_challenge: 'Contestare',
  msg_credential_valid: 'Questa credenziale è valida e non è scaduta.',
  msg_credential_invalid: 'Non è stato possibile verificare questa credenziale.',
  msg_credential_expired: 'Questa credenziale è scaduta e deve essere rinnovata.',
  msg_signature_valid: 'Firma crittografica verificata con successo.',
  msg_signature_invalid: 'Verifica della firma crittografica fallita.',
  msg_ring_signature_valid: 'Firma ad anello verificata — l\'emittente è uno dei verificatori autorizzati.',
  msg_ring_signature_invalid: 'Verifica della firma ad anello fallita.',
  msg_age_proof_valid: 'Prova della fascia d\'età verificata — l\'età rientra nell\'intervallo dichiarato.',
  msg_age_proof_invalid: 'Verifica della prova della fascia d\'età fallita.',
  msg_signet_score: 'Signet Score',
  legal_privacy_policy: 'Informativa sulla Privacy', legal_terms_of_service: 'Termini di Servizio',
  legal_data_processing: 'Accordo sul Trattamento dei Dati', legal_consent: 'Consenso',
  legal_right_to_erasure: 'Diritto alla Cancellazione', legal_data_portability: 'Portabilità dei Dati',
  legal_parental_consent: 'Consenso dei Genitori', legal_child_protection: 'Protezione dei Minori',
  legal_cross_border_transfer: 'Trasferimento Transfrontaliero dei Dati',
  legal_data_retention: 'Conservazione dei Dati', legal_breach_notification: 'Notifica di Violazione',
  scope_adult: 'Verifica Adulto', scope_child: 'Verifica Minore', scope_adult_child: 'Verifica Adulto + Minore',

  entity_natural_person: 'Persona',
  entity_persona: 'Alias',
  entity_personal_agent: 'Agente Personale',
  entity_unlinked_personal_agent: 'Agente Personale Libero',
  entity_juridical_person: 'Organizzazione',
  entity_juridical_persona: 'Alias di Organizzazione',
  entity_organised_agent: 'Agente Organizzato',
  entity_unlinked_organised_agent: 'Agente di Org Libero',
  entity_unlinked_agent: 'Agente Libero',

  error_invalid_jurisdiction: 'La giurisdizione specificata non è riconosciuta.',
  error_profession_not_regulated: 'Questa professione non è regolamentata nella giurisdizione specificata.',
  error_age_below_minimum: 'Il soggetto non soddisfa il requisito di età minima.',
  error_consent_required: 'Il consenso esplicito è richiesto prima del trattamento.',
  error_cross_border_denied: 'Il trasferimento transfrontaliero dei dati non è consentito senza garanzie.',
  error_credential_expired: 'Questa credenziale è scaduta.',
  error_verification_failed: 'La verifica non è stata completata.',
};

const nl: TranslationStrings = {
  credential_self_declared: 'Zelfverklaarde Identiteit',
  credential_vouched: 'Gemeenschapsgegarandeerde Identiteit',
  credential_professional: 'Professioneel Geverifieerde Identiteit',
  credential_professional_child: 'Professionele Verificatie met Kinderbescherming',
  credential_verifier: 'Verificateur Credential',
  tier_1: 'Niveau 1', tier_2: 'Niveau 2', tier_3: 'Niveau 3', tier_4: 'Niveau 4',
  tier_1_desc: 'Zelfverklaard — niet-geverifieerde claim van menselijkheid',
  tier_2_desc: 'Vertrouwensnetwerk — gegarandeerd door gemeenschapsleden',
  tier_3_desc: 'Professioneel — geverifieerd door een gelicentieerde professional',
  tier_4_desc: 'Professioneel + Kinderbescherming — inclusief leeftijdsbereikbewijs',
  profession_legal: 'Advocaat', profession_medical: 'Arts', profession_notary: 'Notaris',
  profession_accounting: 'Accountant', profession_engineering: 'Ingenieur',
  profession_teaching: 'Docent', profession_financial: 'Financieel Adviseur',
  profession_veterinary: 'Dierenarts', profession_pharmacy: 'Apotheker',
  profession_architecture: 'Architect', profession_social_work: 'Maatschappelijk Werker',
  status_valid: 'Geldig', status_invalid: 'Ongeldig', status_expired: 'Verlopen',
  status_revoked: 'Ingetrokken', status_pending: 'In Behandeling', status_challenged: 'Aangevochten',
  action_verify: 'Verifiëren', action_issue: 'Uitgeven', action_revoke: 'Intrekken',
  action_renew: 'Vernieuwen', action_vouch: 'Garanderen', action_challenge: 'Aanvechten',
  msg_credential_valid: 'Deze credential is geldig en niet verlopen.',
  msg_credential_invalid: 'Deze credential kon niet worden geverifieerd.',
  msg_credential_expired: 'Deze credential is verlopen en moet worden vernieuwd.',
  msg_signature_valid: 'Cryptografische handtekening succesvol geverifieerd.',
  msg_signature_invalid: 'Verificatie van cryptografische handtekening mislukt.',
  msg_ring_signature_valid: 'Ringhandtekening geverifieerd — de uitgever is een van de geautoriseerde verificateurs.',
  msg_ring_signature_invalid: 'Verificatie van ringhandtekening mislukt.',
  msg_age_proof_valid: 'Leeftijdsbereikbewijs geverifieerd — leeftijd valt binnen het aangegeven bereik.',
  msg_age_proof_invalid: 'Verificatie van leeftijdsbereikbewijs mislukt.',
  msg_signet_score: 'Signet Score',
  legal_privacy_policy: 'Privacybeleid', legal_terms_of_service: 'Servicevoorwaarden',
  legal_data_processing: 'Verwerkersovereenkomst', legal_consent: 'Toestemming',
  legal_right_to_erasure: 'Recht op Wissing', legal_data_portability: 'Gegevensoverdraagbaarheid',
  legal_parental_consent: 'Ouderlijke Toestemming', legal_child_protection: 'Kinderbescherming',
  legal_cross_border_transfer: 'Grensoverschrijdende Gegevensoverdracht',
  legal_data_retention: 'Gegevensbewaring', legal_breach_notification: 'Inbreukmeldingsplicht',
  scope_adult: 'Volwassenenverificatie', scope_child: 'Kinderverificatie',
  scope_adult_child: 'Volwassenen- + Kinderverificatie',

  entity_natural_person: 'Persoon',
  entity_persona: 'Alias',
  entity_personal_agent: 'Persoonlijke Agent',
  entity_unlinked_personal_agent: 'Vrije Persoonlijke Agent',
  entity_juridical_person: 'Organisatie',
  entity_juridical_persona: 'Org Alias',
  entity_organised_agent: 'Georganiseerde Agent',
  entity_unlinked_organised_agent: 'Vrije Org Agent',
  entity_unlinked_agent: 'Vrije Agent',

  error_invalid_jurisdiction: 'Het opgegeven rechtsgebied wordt niet herkend.',
  error_profession_not_regulated: 'Dit beroep is niet gereguleerd in het opgegeven rechtsgebied.',
  error_age_below_minimum: 'Het onderwerp voldoet niet aan de minimale leeftijdseis.',
  error_consent_required: 'Uitdrukkelijke toestemming is vereist vóór verwerking.',
  error_cross_border_denied: 'Grensoverschrijdende gegevensoverdracht is niet toegestaan zonder waarborgen.',
  error_credential_expired: 'Deze credential is verlopen.',
  error_verification_failed: 'Verificatie kon niet worden voltooid.',
};

const tr: TranslationStrings = {
  credential_self_declared: 'Kendi Beyanına Dayalı Kimlik',
  credential_vouched: 'Topluluk Tarafından Onaylanmış Kimlik',
  credential_professional: 'Profesyonel Olarak Doğrulanmış Kimlik',
  credential_professional_child: 'Çocuk Korumalı Profesyonel Doğrulama',
  credential_verifier: 'Doğrulayıcı Belgesi',
  tier_1: 'Seviye 1', tier_2: 'Seviye 2', tier_3: 'Seviye 3', tier_4: 'Seviye 4',
  tier_1_desc: 'Öz beyan — doğrulanmamış insanlık iddiası',
  tier_2_desc: 'Güven ağı — topluluk üyeleri tarafından onaylanmış',
  tier_3_desc: 'Profesyonel — lisanslı bir profesyonel tarafından doğrulanmış',
  tier_4_desc: 'Profesyonel + Çocuk Koruma — yaş aralığı kanıtı dahil',
  profession_legal: 'Avukat', profession_medical: 'Doktor', profession_notary: 'Noter',
  profession_accounting: 'Mali Müşavir', profession_engineering: 'Mühendis',
  profession_teaching: 'Öğretmen', profession_financial: 'Mali Danışman',
  profession_veterinary: 'Veteriner', profession_pharmacy: 'Eczacı',
  profession_architecture: 'Mimar', profession_social_work: 'Sosyal Hizmet Uzmanı',
  status_valid: 'Geçerli', status_invalid: 'Geçersiz', status_expired: 'Süresi Dolmuş',
  status_revoked: 'İptal Edilmiş', status_pending: 'Beklemede', status_challenged: 'İtiraz Altında',
  action_verify: 'Doğrula', action_issue: 'Düzenle', action_revoke: 'İptal Et',
  action_renew: 'Yenile', action_vouch: 'Onayla', action_challenge: 'İtiraz Et',
  msg_credential_valid: 'Bu belge geçerlidir ve süresi dolmamıştır.',
  msg_credential_invalid: 'Bu belge doğrulanamadı.',
  msg_credential_expired: 'Bu belgenin süresi dolmuştur ve yenilenmesi gerekmektedir.',
  msg_signature_valid: 'Kriptografik imza başarıyla doğrulandı.',
  msg_signature_invalid: 'Kriptografik imza doğrulaması başarısız oldu.',
  msg_ring_signature_valid: 'Halka imzası doğrulandı — düzenleyen yetkili doğrulayıcılardan biridir.',
  msg_ring_signature_invalid: 'Halka imzası doğrulaması başarısız oldu.',
  msg_age_proof_valid: 'Yaş aralığı kanıtı doğrulandı — yaş beyan edilen aralık içindedir.',
  msg_age_proof_invalid: 'Yaş aralığı kanıtı doğrulaması başarısız oldu.',
  msg_signet_score: 'Signet Score',
  legal_privacy_policy: 'Gizlilik Politikası', legal_terms_of_service: 'Hizmet Şartları',
  legal_data_processing: 'Veri İşleme Sözleşmesi', legal_consent: 'Onay',
  legal_right_to_erasure: 'Silme Hakkı', legal_data_portability: 'Veri Taşınabilirliği',
  legal_parental_consent: 'Ebeveyn Onayı', legal_child_protection: 'Çocuk Koruma',
  legal_cross_border_transfer: 'Sınır Ötesi Veri Aktarımı',
  legal_data_retention: 'Veri Saklama', legal_breach_notification: 'İhlal Bildirimi',
  scope_adult: 'Yetişkin Doğrulaması', scope_child: 'Çocuk Doğrulaması',
  scope_adult_child: 'Yetişkin + Çocuk Doğrulaması',

  entity_natural_person: 'Kişi',
  entity_persona: 'Takma Ad',
  entity_personal_agent: 'Kişisel Ajan',
  entity_unlinked_personal_agent: 'Serbest Kişisel Ajan',
  entity_juridical_person: 'Kuruluş',
  entity_juridical_persona: 'Kuruluş Takma Adı',
  entity_organised_agent: 'Organize Ajan',
  entity_unlinked_organised_agent: 'Serbest Org Ajanı',
  entity_unlinked_agent: 'Serbest Ajan',

  error_invalid_jurisdiction: 'Belirtilen yargı alanı tanınmamaktadır.',
  error_profession_not_regulated: 'Bu meslek belirtilen yargı alanında düzenlenmemiştir.',
  error_age_below_minimum: 'Kişi asgari yaş şartını karşılamamaktadır.',
  error_consent_required: 'İşleme öncesinde açık onay gereklidir.',
  error_cross_border_denied: 'Güvenceler olmadan sınır ötesi veri aktarımına izin verilmez.',
  error_credential_expired: 'Bu belgenin süresi dolmuştur.',
  error_verification_failed: 'Doğrulama tamamlanamadı.',
};

const id_lang: TranslationStrings = {
  credential_self_declared: 'Identitas Dideklarasikan Sendiri',
  credential_vouched: 'Identitas Dijamin Komunitas',
  credential_professional: 'Identitas Diverifikasi Profesional',
  credential_professional_child: 'Verifikasi Profesional dengan Perlindungan Anak',
  credential_verifier: 'Kredensial Verifikator',
  tier_1: 'Tingkat 1', tier_2: 'Tingkat 2', tier_3: 'Tingkat 3', tier_4: 'Tingkat 4',
  tier_1_desc: 'Deklarasi sendiri — klaim kemanusiaan yang belum diverifikasi',
  tier_2_desc: 'Jaringan kepercayaan — dijamin oleh anggota komunitas',
  tier_3_desc: 'Profesional — diverifikasi oleh profesional berlisensi',
  tier_4_desc: 'Profesional + Perlindungan Anak — termasuk bukti rentang usia',
  profession_legal: 'Advokat', profession_medical: 'Dokter', profession_notary: 'Notaris',
  profession_accounting: 'Akuntan Publik', profession_engineering: 'Insinyur',
  profession_teaching: 'Guru', profession_financial: 'Penasihat Keuangan',
  profession_veterinary: 'Dokter Hewan', profession_pharmacy: 'Apoteker',
  profession_architecture: 'Arsitek', profession_social_work: 'Pekerja Sosial',
  status_valid: 'Valid', status_invalid: 'Tidak Valid', status_expired: 'Kedaluwarsa',
  status_revoked: 'Dicabut', status_pending: 'Tertunda', status_challenged: 'Ditantang',
  action_verify: 'Verifikasi', action_issue: 'Terbitkan', action_revoke: 'Cabut',
  action_renew: 'Perbarui', action_vouch: 'Jaminkan', action_challenge: 'Tantang',
  msg_credential_valid: 'Kredensial ini valid dan belum kedaluwarsa.',
  msg_credential_invalid: 'Kredensial ini tidak dapat diverifikasi.',
  msg_credential_expired: 'Kredensial ini telah kedaluwarsa dan perlu diperbarui.',
  msg_signature_valid: 'Tanda tangan kriptografi berhasil diverifikasi.',
  msg_signature_invalid: 'Verifikasi tanda tangan kriptografi gagal.',
  msg_ring_signature_valid: 'Tanda tangan cincin terverifikasi — penerbit adalah salah satu verifikator yang diotorisasi.',
  msg_ring_signature_invalid: 'Verifikasi tanda tangan cincin gagal.',
  msg_age_proof_valid: 'Bukti rentang usia terverifikasi — usia berada dalam rentang yang dinyatakan.',
  msg_age_proof_invalid: 'Verifikasi bukti rentang usia gagal.',
  msg_signet_score: 'Signet Score',
  legal_privacy_policy: 'Kebijakan Privasi', legal_terms_of_service: 'Ketentuan Layanan',
  legal_data_processing: 'Perjanjian Pemrosesan Data', legal_consent: 'Persetujuan',
  legal_right_to_erasure: 'Hak Penghapusan', legal_data_portability: 'Portabilitas Data',
  legal_parental_consent: 'Persetujuan Orang Tua', legal_child_protection: 'Perlindungan Anak',
  legal_cross_border_transfer: 'Transfer Data Lintas Batas',
  legal_data_retention: 'Retensi Data', legal_breach_notification: 'Pemberitahuan Pelanggaran',
  scope_adult: 'Verifikasi Dewasa', scope_child: 'Verifikasi Anak',
  scope_adult_child: 'Verifikasi Dewasa + Anak',

  entity_natural_person: 'Orang',
  entity_persona: 'Alias',
  entity_personal_agent: 'Agen Pribadi',
  entity_unlinked_personal_agent: 'Agen Pribadi Bebas',
  entity_juridical_person: 'Organisasi',
  entity_juridical_persona: 'Alias Organisasi',
  entity_organised_agent: 'Agen Terorganisir',
  entity_unlinked_organised_agent: 'Agen Org Bebas',
  entity_unlinked_agent: 'Agen Bebas',

  error_invalid_jurisdiction: 'Yurisdiksi yang ditentukan tidak diakui.',
  error_profession_not_regulated: 'Profesi ini tidak diatur dalam yurisdiksi yang ditentukan.',
  error_age_below_minimum: 'Subjek tidak memenuhi persyaratan usia minimum.',
  error_consent_required: 'Persetujuan eksplisit diperlukan sebelum pemrosesan.',
  error_cross_border_denied: 'Transfer data lintas batas tidak diizinkan tanpa perlindungan.',
  error_credential_expired: 'Kredensial ini telah kedaluwarsa.',
  error_verification_failed: 'Verifikasi tidak dapat diselesaikan.',
};

const sw: TranslationStrings = {
  credential_self_declared: 'Utambulisho wa Kujitangazia',
  credential_vouched: 'Utambulisho Uliothibitishwa na Jumuiya',
  credential_professional: 'Utambulisho Uliothibitishwa Kitaaluma',
  credential_professional_child: 'Uthibitisho wa Kitaaluma na Ulinzi wa Watoto',
  credential_verifier: 'Hati za Mthibitishaji',
  tier_1: 'Ngazi ya 1', tier_2: 'Ngazi ya 2', tier_3: 'Ngazi ya 3', tier_4: 'Ngazi ya 4',
  tier_1_desc: 'Kujitangazia — madai yasiyothibitishwa ya ubinadamu',
  tier_2_desc: 'Mtandao wa kuaminiana — uliothibitishwa na wanajumuiya',
  tier_3_desc: 'Kitaaluma — uliothibitishwa na mtaalamu aliye na leseni',
  tier_4_desc: 'Kitaaluma + Ulinzi wa Watoto — ikiwa na uthibitisho wa umri',
  profession_legal: 'Wakili', profession_medical: 'Daktari', profession_notary: 'Notari',
  profession_accounting: 'Mhasibu', profession_engineering: 'Mhandisi',
  profession_teaching: 'Mwalimu', profession_financial: 'Mshauri wa Fedha',
  profession_veterinary: 'Daktari wa Wanyama', profession_pharmacy: 'Mfamasia',
  profession_architecture: 'Mbunifu', profession_social_work: 'Mfanyakazi wa Jamii',
  status_valid: 'Halali', status_invalid: 'Si Halali', status_expired: 'Imeisha Muda',
  status_revoked: 'Imefutwa', status_pending: 'Inasubiri', status_challenged: 'Imepingwa',
  action_verify: 'Thibitisha', action_issue: 'Toa', action_revoke: 'Futa',
  action_renew: 'Onyesha Upya', action_vouch: 'Dhamini', action_challenge: 'Pinga',
  msg_credential_valid: 'Hati hii ni halali na haijaisha muda.',
  msg_credential_invalid: 'Hati hii haikuweza kuthibitishwa.',
  msg_credential_expired: 'Muda wa hati hii umeisha na inapaswa kuonyeshwa upya.',
  msg_signature_valid: 'Saini ya kriptografia imethibitishwa kwa mafanikio.',
  msg_signature_invalid: 'Uthibitishaji wa saini ya kriptografia umeshindwa.',
  msg_ring_signature_valid: 'Saini ya pete imethibitishwa — mtaji ni mmoja wa wathibitishaji walioruhusiwa.',
  msg_ring_signature_invalid: 'Uthibitishaji wa saini ya pete umeshindwa.',
  msg_age_proof_valid: 'Uthibitisho wa umri umethibitishwa — umri uko ndani ya masafa yaliyotangazwa.',
  msg_age_proof_invalid: 'Uthibitishaji wa uthibitisho wa umri umeshindwa.',
  msg_signet_score: 'Signet Score',
  legal_privacy_policy: 'Sera ya Faragha', legal_terms_of_service: 'Masharti ya Huduma',
  legal_data_processing: 'Mkataba wa Usindikaji wa Data', legal_consent: 'Ridhaa',
  legal_right_to_erasure: 'Haki ya Kufutwa', legal_data_portability: 'Ubebaji wa Data',
  legal_parental_consent: 'Ridhaa ya Mzazi', legal_child_protection: 'Ulinzi wa Watoto',
  legal_cross_border_transfer: 'Uhamishaji wa Data Kuvuka Mipaka',
  legal_data_retention: 'Uhifadhi wa Data', legal_breach_notification: 'Arifa ya Ukiukaji',
  scope_adult: 'Uthibitishaji wa Mtu Mzima', scope_child: 'Uthibitishaji wa Mtoto',
  scope_adult_child: 'Uthibitishaji wa Mtu Mzima + Mtoto',

  entity_natural_person: 'Mtu',
  entity_persona: 'Jina Bandia',
  entity_personal_agent: 'Wakala Binafsi',
  entity_unlinked_personal_agent: 'Wakala Binafsi Huru',
  entity_juridical_person: 'Shirika',
  entity_juridical_persona: 'Jina Bandia la Shirika',
  entity_organised_agent: 'Wakala Rasmi',
  entity_unlinked_organised_agent: 'Wakala wa Shirika Huru',
  entity_unlinked_agent: 'Wakala Huru',

  error_invalid_jurisdiction: 'Mamlaka iliyoainishwa haitambuliwi.',
  error_profession_not_regulated: 'Taaluma hii haidhibitiwi katika mamlaka iliyoainishwa.',
  error_age_below_minimum: 'Mtu huyu hakidhi mahitaji ya umri wa chini.',
  error_consent_required: 'Ridhaa ya wazi inahitajika kabla ya usindikaji.',
  error_cross_border_denied: 'Uhamishaji wa data kuvuka mipaka hauruhusiwi bila ulinzi.',
  error_credential_expired: 'Muda wa hati hii umeisha.',
  error_verification_failed: 'Uthibitishaji haukuweza kukamilika.',
};

// --- Translation Registry ---

const TRANSLATIONS: Record<LanguageCode, TranslationStrings> = {
  en, es, fr, de, pt, ja, ko, zh, ar, hi, it, nl, tr, id: id_lang, sw,
};

// --- Public API ---

let currentLanguage: LanguageCode = 'en';

/** Set the current language */
export function setLanguage(lang: LanguageCode): void {
  if (!TRANSLATIONS[lang]) throw new SignetValidationError(`Unsupported language: ${lang}`);
  currentLanguage = lang;
}

/** Get the current language */
export function getLanguage(): LanguageCode {
  return currentLanguage;
}

/** Get all supported language codes */
export function getSupportedLanguages(): LanguageCode[] {
  return Object.keys(TRANSLATIONS) as LanguageCode[];
}

/** Get a translation string by key */
export function t(key: keyof TranslationStrings, lang?: LanguageCode): string {
  const translations = TRANSLATIONS[lang ?? currentLanguage];
  return translations[key] ?? TRANSLATIONS.en[key] ?? key;
}

/** Get all translations for a language */
export function getTranslations(lang?: LanguageCode): TranslationStrings {
  return TRANSLATIONS[lang ?? currentLanguage] ?? TRANSLATIONS.en;
}

/** Get a language name in English */
export function getLanguageName(code: LanguageCode): string {
  const names: Record<LanguageCode, string> = {
    en: 'English', es: 'Spanish', fr: 'French', de: 'German',
    pt: 'Portuguese', ja: 'Japanese', ko: 'Korean', zh: 'Chinese (Simplified)',
    ar: 'Arabic', hi: 'Hindi', it: 'Italian', nl: 'Dutch',
    tr: 'Turkish', id: 'Indonesian', sw: 'Swahili',
  };
  return names[code] ?? code;
}

/** Get a language name in its own script */
export function getLanguageNativeName(code: LanguageCode): string {
  const names: Record<LanguageCode, string> = {
    en: 'English', es: 'Español', fr: 'Français', de: 'Deutsch',
    pt: 'Português', ja: '日本語', ko: '한국어', zh: '简体中文',
    ar: 'العربية', hi: 'हिन्दी', it: 'Italiano', nl: 'Nederlands',
    tr: 'Türkçe', id: 'Bahasa Indonesia', sw: 'Kiswahili',
  };
  return names[code] ?? code;
}

/** Format a Signet Score display in the current language */
export function formatLocalizedTrustScore(score: number, lang?: LanguageCode): string {
  const label = t('msg_signet_score', lang);
  return `${label}: ${score}/200`;
}

/** Get the tier description in the current language */
export function getTierDescription(tier: 1 | 2 | 3 | 4, lang?: LanguageCode): string {
  const key = `tier_${tier}_desc` as keyof TranslationStrings;
  return t(key, lang);
}
