---
**Avis de traduction générée par IA**

Ce document a été traduit de l'anglais à l'aide de l'IA (Claude, Anthropic). Il est fourni à titre de référence uniquement. La version anglaise disponible à `en.md` est le seul document juridiquement contraignant. Cette traduction n'a pas été révisée par un traducteur juridique qualifié. En cas de divergence entre cette traduction et l'original anglais, la version anglaise prévaut.

---

# Politique de confidentialité

**Protocole Signet — v0.1.0**

**Date d'entrée en vigueur :** Mars 2026
**Dernière mise à jour :** Mars 2026

---

## 1. Introduction

La présente Politique de confidentialité décrit la manière dont le Protocole Signet (« Signet », « nous » ou « notre ») collecte, utilise, divulgue et protège les informations en lien avec le Protocole Signet (le « Protocole ») et l'application My Signet (l'« Application »). Signet est un protocole de vérification d'identité décentralisé et open source pour le réseau Nostr qui utilise des preuves à divulgation nulle de connaissance, des signatures en anneau et des attestations cryptographiques.

Signet est conçu avec la confidentialité comme principe central. Il permet aux utilisateurs de prouver des revendications concernant leur identité — telles que la tranche d'âge, le statut professionnel ou la juridiction géographique — sans révéler les données personnelles sous-jacentes. La présente Politique de confidentialité explique les interactions de données limitées qui se produisent, où les données restent et comment elles sont traitées.

La présente Politique s'applique à tous les utilisateurs, vérificateurs, parties utilisatrices et autres participants qui interagissent avec le Protocole Signet ou l'application My Signet, quel que soit leur lieu de résidence.

La description canonique du protocole est `spec/protocol.md` dans le dépôt open source de Signet.

---

## 2. Responsable du traitement

**Responsable du traitement :** Le Protocole Signet
**Adresse e-mail de contact :** privacy@signet.id
**Délégué à la protection des données (DPD) :** dpo@signet.id

Pour les juridictions nécessitant un représentant local, contactez le DPD à l'adresse ci-dessus. Les nominations formelles de représentants pour l'UE (RGPD Art. 27) et le Royaume-Uni (UK RGPD Art. 27) seront publiées sur signet.id/legal.

---

## 3. Données que nous collectons et traitons

Le Protocole Signet est conçu pour minimiser la collecte de données. Étant donné que le Protocole utilise des preuves à divulgation nulle de connaissance, des signatures en anneau et la vérification décentralisée des attestations, la grande majorité des informations reste exclusivement sous le contrôle de l'utilisateur et n'est jamais transmise à Signet ni accessible par Signet.

### 3.1 Catégories de données

| Catégorie | Description | Source | Lieu de stockage |
|----------|-------------|--------|-----------------|
| **Clés publiques Nostr** | Clés publiques secp256k1 (npub) utilisées pour les interactions avec le Protocole | Générées par l'utilisateur | Relais Nostr (décentralisés) |
| **Métadonnées des attestations** | Types d'événements Nostr 31000–31000 contenant le niveau de vérification, les horodatages d'émission, les dates d'expiration, la tranche d'âge et les identifiants de type d'entité | Générées lors de l'émission de l'attestation | Relais Nostr (décentralisés) |
| **Preuves à divulgation nulle de connaissance** | Bulletproofs pour la vérification de la tranche d'âge | Générées localement par l'utilisateur | Intégrées dans les événements d'attestation sur les relais Nostr |
| **Signatures en anneau** | Signatures cryptographiques prouvant l'appartenance à un groupe sans révéler quel membre a signé | Générées localement par l'utilisateur | Relais Nostr (décentralisés) |
| **Hashes nullificateurs** | Hash SHA-256 du type de document préfixé par la longueur, du code pays, du numéro de document et de la balise de domaine « signet-nullifier-v2 » — prévient la création d'identités dupliquées ; ne peut pas être inversé pour récupérer les détails du document | Calculés localement lors de la cérémonie à deux attestations | Intégrés dans les événements d'attestation de Personne Physique |
| **Racines Merkle** | Engagement de hash sur les attributs vérifiés permettant la divulgation sélective. Les feuilles incluent le nom, la nationalité, le documentType, la dateOfBirth, le documentNumber, le documentExpiry, le photoHash et le nullificateur. Seul le hash de la racine est publié — les valeurs individuelles des feuilles ne sont jamais publiées | Calculées localement lors de la cérémonie à deux attestations | Intégrées dans les événements d'attestation de Personne Physique |
| **Enregistrements de caution** | Événements de type 31000 représentant des recommandations de réseau de confiance | Créés par les parties cautionnant | Relais Nostr (décentralisés) |
| **Événements de politique** | Événements de type 30078 spécifiant les exigences des parties utilisatrices | Créés par les parties utilisatrices | Relais Nostr (décentralisés) |
| **Enregistrement du vérificateur** | Événements de type 31000 identifiant les vérificateurs professionnels, incluant la clé publique de signature professionnelle et les informations juridictionnelles | Créés par les vérificateurs | Relais Nostr (décentralisés) |
| **Données de défi/réponse** | Événements de type 31000 pour les défis de légitimité des vérificateurs | Générés lors de la vérification | Relais Nostr (décentralisés) |
| **Enregistrements de révocation** | Événements de type 31000 pour la révocation des attestations | Créés lors de la révocation des attestations | Relais Nostr (décentralisés) |
| **Événements de pont d'identité** | Événements de type 31000 liant les paires de clés Personne Physique et Persona via des signatures en anneau | Créés par l'utilisateur | Relais Nostr (décentralisés) |
| **Événements de délégation** | Événements de type 31000 pour la délégation d'agent ou de tuteur avec des autorisations délimitées | Créés par le délégant | Relais Nostr (décentralisés) |
| **Matériel de clé chiffré** | Clés privées chiffrées avec AES-256-GCM (clé dérivée via PBKDF2, 600 000 itérations, SHA-256) | Stockées localement sur l'appareil | Stockage local de l'appareil uniquement — jamais transmis |

### 3.2 Ce qui reste sur votre appareil

Les informations suivantes sont traitées sur votre appareil et ne sont jamais transmises à Signet ni stockées par Signet :

- **Clés privées et phrase mnémonique** — Votre mnémonique BIP-39 de 12 mots et les clés privées dérivées (les deux paires de clés Personne Physique et Persona, dérivées via la dérivation HD BIP-32 aux chemins NIP-06) restent sur votre appareil en permanence, chiffrées au repos.
- **Détails du document saisis lors de la cérémonie** — Votre numéro de document, date d'expiration du document, date de naissance, nom, nationalité et toute photographie que vous présentez. Ceux-ci sont saisis par vous dans l'application, utilisés pour calculer l'arbre Merkle et le nullificateur, puis supprimés. Les valeurs individuelles des feuilles sont conservées par vous dans votre dossier d'attestation local pour une divulgation sélective future. Elles ne sont pas transmises à Signet et ne sont pas envoyées électroniquement au vérificateur — le vérificateur inspecte vos documents physiques en personne et confirme les données que vous avez saisies.
- **Valeurs des feuilles Merkle** — Les valeurs d'attribut individuelles (nom, date de naissance, numéro de document, date d'expiration du document, hash de photo, nationalité, type de document, nullificateur) sont stockées comme feuilles Merkle dans votre dossier d'attestation local, vous permettant de prouver des attributs individuels via des preuves de divulgation sélective. Seul le hash de la racine Merkle est publié en chaîne.
- **Données biométriques** — Voir Section 3.3.
- **Dates de naissance exactes** — Les preuves de tranche d'âge révèlent uniquement que vous vous situez dans une tranche (p. ex. « 18+ »), et non votre date de naissance exacte.

### 3.3 Authentification biométrique (données de catégorie spéciale)

L'application My Signet prend en charge l'authentification biométrique via l'**API WebAuthn avec l'extension PRF (Pseudo-Random Function)**, avec un code PIN comme solution de repli.

**Fonctionnement :**
- Lorsque vous enrôlez la biométrie, l'authentificateur de plateforme de votre appareil (capteur d'empreinte digitale, Face ID ou équivalent) crée une attestation WebAuthn. L'attestation reste dans l'enclave sécurisée ou le TPM de votre appareil.
- L'extension PRF WebAuthn dérive du matériel de clé cryptographique de votre assertion biométrique. Ce matériel de clé est utilisé pour déchiffrer vos clés privées chiffrées lors d'une session authentifiée.
- **Aucun modèle biométrique n'est jamais transmis à Signet.** Aucune donnée biométrique ne quitte votre appareil. Signet ne reçoit, ne stocke ni ne traite aucune information biométrique.
- L'ID d'attestation WebAuthn est stocké dans le stockage local de votre appareil pour identifier quelle attestation affirmer lors de l'authentification. Il s'agit d'un identifiant aléatoire, et non d'un modèle biométrique.

En vertu de l'Article 9 du RGPD et de l'UK RGPD, les données biométriques utilisées à des fins d'identification unique d'une personne physique constituent des données de catégorie spéciale. Étant donné que le traitement biométrique se déroule entièrement sur votre appareil local à l'aide du matériel sécurisé intégré de la plateforme, et qu'aucune donnée biométrique n'est transmise aux systèmes de Signet ni traitée par ceux-ci, Signet n'agit pas comme responsable du traitement ou sous-traitant de données biométriques. Le traitement est sous votre seul contrôle.

Si votre appareil ne prend pas en charge WebAuthn PRF, l'application se rabat sur un code PIN, dérivé via PBKDF2-SHA-256 (600 000 itérations) pour produire une clé de déchiffrement AES-256-GCM.

### 3.4 Données que nous ne collectons PAS

Par conception, le Protocole Signet ne collecte, ne traite ni ne stocke **pas** :

- Les noms réels, adresses ou numéros d'identification gouvernementaux
- Les dates de naissance exactes (les preuves de tranche d'âge ne révèlent qu'une tranche)
- Les numéros de document ou les dates d'expiration des documents (traités localement pour calculer les feuilles Merkle ; les valeurs individuelles ne sont pas transmises à Signet ni électroniquement au vérificateur)
- Les données biométriques (traitées localement sur l'appareil via WebAuthn ; jamais transmises)
- Les informations financières ou les données de paiement
- Les données de localisation ou les adresses IP (au niveau du Protocole ; les opérateurs de relais peuvent collecter indépendamment des adresses IP)
- L'historique de navigation ou les empreintes digitales des appareils
- Les adresses e-mail (sauf si fournies volontairement pour le support)
- Les photographies ou images (un hash de photo peut être inclus comme feuille Merkle, mais l'image elle-même reste sur votre appareil)
- Les données sous-jacentes à toute preuve à divulgation nulle de connaissance

### 3.5 Données traitées par des tiers

Les opérateurs de relais Nostr traitent indépendamment les données transmises via leurs relais. Leurs pratiques en matière de données sont régies par leurs propres politiques de confidentialité. Signet ne contrôle pas les opérateurs de relais.

---

## 4. La cérémonie à deux attestations

Cette section explique le processus de vérification professionnelle en détail, car il constitue l'interaction la plus gourmande en données dans le Protocole.

### 4.1 Fonctionnement de la cérémonie

1. **Vous saisissez vos propres données.** Dans l'application My Signet, vous saisissez votre nom, votre date de naissance, votre nationalité, votre type de document, votre numéro de document, la date d'expiration de votre document, et fournissez ou photographiez éventuellement votre document. L'application calcule l'arbre Merkle et le nullificateur localement.

2. **Le vérificateur inspecte vos documents physiques.** Un vérificateur de niveau 3 ou 4 (un professionnel agréé tel qu'un solicitor, notaire ou médecin) examine vos documents d'identité physiques en personne. Le vérificateur confirme que les données que vous avez saisies correspondent à vos documents. Le vérificateur ne saisit pas vos données de manière indépendante dans le système.

3. **Le vérificateur signe l'attestation.** Le vérificateur signe deux événements d'attestation : une attestation de Personne Physique (type 31000, signée par la paire de clés Nostr professionnelle du vérificateur) et une attestation de Persona (anonyme, tranche d'âge uniquement, également signée par le vérificateur). Les deux sont publiés sur les relais Nostr.

4. **Ce qui est publié.** Les événements d'attestation publiés contiennent : la clé publique du vérificateur, votre clé publique de Persona (clé publique du sujet), les métadonnées de l'attestation (niveau, dates, type d'entité, tranche d'âge), la preuve de tranche d'âge à divulgation nulle de connaissance, le hash nullificateur (un hash à sens unique ; ne peut pas être inversé) et la racine Merkle (un engagement de hash ; les valeurs individuelles des feuilles ne sont pas publiées). Aucun nom, date de naissance, numéro de document ou autre information d'identification n'est publié.

5. **Ce que vous conservez localement.** Votre dossier d'attestation local contient les valeurs individuelles des feuilles Merkle (nom, nationalité, date de naissance, type de document, numéro de document, date d'expiration du document, nullificateur et optionnellement hash de photo). Vous les utilisez pour générer des preuves de divulgation sélective lorsque vous souhaitez ultérieurement prouver des attributs spécifiques (p. ex. prouver votre numéro de passeport lors de l'enregistrement pour un vol).

### 4.2 Numéro de document et date d'expiration comme feuilles Merkle

Contrairement aux versions antérieures du Protocole, le numéro de document et la date d'expiration du document ne sont **pas** supprimés après la cérémonie. Ils sont conservés comme feuilles Merkle dans votre dossier d'attestation local. Cela vous permet de :

- Prouver votre numéro de passeport à une partie utilisatrice qui en a besoin (p. ex. une compagnie aérienne) via une preuve d'inclusion Merkle, sans révéler d'autres attributs.
- Prendre en charge une décroissance accélérée du Signet IQ lorsque la date d'expiration de votre document approche, fournissant aux parties utilisatrices un signal sur la fraîcheur de votre preuve d'identité sous-jacente.

Vous seul contrôlez quels attributs vous divulguez et à qui. Les valeurs individuelles des feuilles ne sont jamais transmises à Signet ni accessibles par Signet.

### 4.3 Format du nullificateur

Le nullificateur est calculé comme suit :

```
SHA-256(len16(docType) || docType || len16(countryCode) || countryCode || len16(docNumber) || docNumber || len16("signet-nullifier-v2") || "signet-nullifier-v2")
```

où `len16(x)` est la longueur en octets UTF-8 de `x` encodée comme un uint16 big-endian sur 2 octets. La balise de domaine `signet-nullifier-v2` distingue ce schéma de toute version antérieure. Le hash nullificateur permet au Protocole de détecter les enregistrements d'identité dupliqués sans révéler quel document a été utilisé.

---

## 5. Modèle à deux paires de clés

Chaque utilisateur Signet possède deux paires de clés dérivées d'une seule mnémonique BIP-39 de 12 mots :

- **Paire de clés Personne Physique** — dérivée via le chemin NIP-06 `m/44'/1237'/0'/0/0`. Utilisée pour l'attestation de Personne Physique (type 31000). Cette paire de clés est associée à votre identité réelle vérifiée via l'attestation, mais la paire de clés elle-même ne comporte aucun lien inhérent à vos documents.
- **Paire de clés Persona** — dérivée via le chemin HD BIP-32 à un index de compte séparé. Utilisée pour l'attestation de Persona (anonyme, tranche d'âge uniquement). Cette paire de clés ne comporte aucun lien direct avec votre identité réelle. Votre activité sociale en ligne utilise cette paire de clés.

**Implication pour la vie privée :** Étant donné que les deux paires de clés dérivent de la même mnémonique, vous pouvez prouver le lien entre elles (via des événements de pont d'identité de type 31000) ou les garder entièrement séparées. Un événement de pont d'identité, une fois publié, crée un lien cryptographique public. Vous ne devriez publier un événement de pont que si vous souhaitez associer votre Persona anonyme à votre statut de Personne Physique vérifiée.

**Gestion des clés et droits des personnes concernées :** Vos clés privées sont dérivées de manière déterministe à partir de votre mnémonique. Signet ne possède ni ne transmet jamais vos clés privées. Si vous supprimez l'application et perdez votre mnémonique (et tout backup Shamir), vos clés sont irrécupérables. Signet ne peut pas aider à la récupération des clés car nous ne détenons pas de copies.

---

## 6. Le SDK signet-verify.js

L'écosystème My Signet comprend `signet-verify.js`, un SDK JavaScript que les sites web intègrent pour demander la vérification de l'âge ou de l'identité de leurs visiteurs.

### 6.1 Fonctionnement du SDK

1. Un site web intègre `signet-verify.js` et appelle `Signet.verifyAge('18+')` (ou similaire).
2. Le SDK ouvre un modal de vérification sur le site web.
3. L'utilisateur approuve la demande dans l'application My Signet. La preuve d'attestation est transmise au site web via un BroadcastChannel (communication sur le même appareil ; pas de serveur impliqué).
4. Le SDK vérifie la signature Schnorr sur l'événement d'attestation et vérifie que la clé publique du vérificateur est enregistrée et confirmée.
5. Le SDK renvoie un résultat au site web.

### 6.2 Données reçues par le site web

Un site web utilisant `signet-verify.js` reçoit :

| Champ | Description |
|-------|-------------|
| `verified` | Booléen : l'attestation satisfait-elle à l'exigence énoncée ? |
| `ageRange` | Chaîne de tranche d'âge (p. ex. « 18+ ») — jamais la date de naissance exacte |
| `tier` | Niveau de vérification (1–4) |
| `entityType` | Classification du type de compte (Personne Physique, Persona, etc.) |
| `credentialId` | ID d'événement d'attestation (un identifiant d'événement Nostr public) |
| `verifierPubkey` | La clé publique Nostr du vérificateur |
| `verifierConfirmed` | Si le vérificateur a été confirmé par rapport à un registre professionnel public |
| `issuedAt` / `expiresAt` | Horodatages de validité de l'attestation |

**Aucune information personnellement identifiable n'est transmise au site web.** Le site web ne reçoit pas votre nom, votre date de naissance, votre numéro de document ni aucune valeur de feuille Merkle. La communication via BroadcastChannel est locale à l'appareil — l'échange de vérification ne passe pas par un serveur Signet.

### 6.3 Bot de vérification

Signet gère un bot de vérification open source qui vérifie les enregistrements des vérificateurs par rapport aux registres professionnels publics (p. ex. le registre du General Medical Council, la liste de la Solicitors Regulation Authority, les dossiers de la Teaching Regulation Agency). Le bot publie ses conclusions sous forme d'événements Nostr.

La clé publique Nostr professionnelle du vérificateur est une clé de signature dédiée utilisée uniquement pour les vérifications Signet. Elle n'a pas d'identité sociale inhérente. Le bot reçoit cette clé publique pour interroger les registres publics. La soumission d'une clé publique professionnelle au bot pour la vérification du registre ne constitue pas un transfert de données personnelles au sens du RGPD, car la clé publique est un identifiant cryptographique pseudonyme conçu spécifiquement pour cette fonction. Cependant, par excès de prudence, les vérificateurs consentent à ce processus dans le cadre de l'Accord du vérificateur.

---

## 7. Signature à distance NIP-46

L'application My Signet peut agir comme signataire à distance NIP-46. Dans ce mode :

- Les demandes de signature arrivent d'une application cliente Nostr connectée via un relais Nostr.
- L'application affiche chaque demande de signature et demande à l'utilisateur de l'approuver ou de la rejeter.
- La clé privée ne quitte jamais l'application. La signature à distance ne transmet pas la clé privée à l'application demandeuse ni au relais.
- Les signatures approuvées sont transmises à l'application demandeuse via le relais.

L'opérateur du relais peut observer qu'une demande de signature et une réponse ont eu lieu (en tant qu'événements Nostr chiffrés), mais ne peut pas lire le contenu de la demande de signature ni la clé privée.

---

## 8. Bases juridiques du traitement

Nous traitons les données sur les bases juridiques suivantes, selon votre juridiction.

### 8.1 Union européenne / Espace économique européen (RGPD)

| Finalité | Base juridique | Article du RGPD |
|---------|-------------|--------------|
| Opération du Protocole et vérification des attestations | Intérêt légitime | Art. 6(1)(f) |
| Respect des obligations légales | Obligation légale | Art. 6(1)(c) |
| Émission d'attestations à l'initiative de l'utilisateur | Exécution d'un contrat | Art. 6(1)(b) |
| Protection de l'enfance et vérification de l'âge | Intérêt légitime / Obligation légale | Art. 6(1)(f) / Art. 6(1)(c) |

Note : Les données biométriques sont traitées exclusivement sur l'appareil via WebAuthn. Signet ne traite pas de données biométriques en vertu de l'Article 9(1). Si un traitement biométrique par Signet était ultérieurement établi, la base juridique serait le consentement explicite en vertu de l'Art. 9(2)(a).

**eIDAS 2.0 :** Le Règlement sur le portefeuille d'identité numérique de l'UE (eIDAS 2.0) impose aux États membres d'émettre des portefeuilles d'identité numérique aux citoyens d'ici décembre 2026. L'architecture de Signet est conçue pour être compatible avec les attestations émises par eIDAS 2.0 via le mécanisme de pont d'identité de type 31000.

### 8.2 Royaume-Uni (UK RGPD / Data Protection Act 2018)

Les mêmes bases juridiques que pour le RGPD de l'UE s'appliquent, complétées par le Data Protection Act 2018.

**Online Safety Act 2023 :** Les capacités de vérification de l'âge de Signet soutiennent la conformité aux exigences de garantie de l'âge de l'Online Safety Act 2023 et aux orientations Ofcom associées. L'architecture à divulgation nulle de connaissance de Signet est conçue pour permettre la vérification de l'âge sans créer de bases de données centralisées de vérification de l'âge.

**Age Appropriate Design Code (AADC / Children's Code) :** Signet s'engage à respecter les 15 normes de l'AADC, notamment l'évaluation de l'intérêt supérieur de l'enfant, la minimisation des données, les paramètres par défaut hautement protecteurs de la vie privée pour les enfants et la transparence adaptée à l'âge.

**ICO en tant qu'autorité de contrôle :** L'Information Commissioner's Office (ICO) est l'autorité de contrôle principale de Signet au Royaume-Uni. Contact : [https://ico.org.uk](https://ico.org.uk).

### 8.3 États-Unis

**COPPA (Children's Online Privacy Protection Act) :** Signet ne collecte aucune information personnelle auprès d'aucun utilisateur, y compris les enfants de moins de 13 ans. L'architecture à divulgation nulle de connaissance du Protocole signifie qu'aucun nom, date de naissance, adresse, photographie ou toute autre information personnelle définie dans le cadre de COPPA n'est collectée, stockée ou transmise par Signet. Les orientations de la FTC de mars 2026 confirment que les plateformes ne collectant aucune information personnelle couverte se situent en dehors des restrictions de collecte de COPPA. L'approche de Signet consistant à permettre la vérification de l'âge sans collecter d'informations personnelles est cohérente avec la flexibilité déclarée de la FTC pour les méthodes de vérification de l'âge préservant la vie privée.

**CCPA / CPRA (Californie) :** Nous ne vendons pas d'informations personnelles. Nous ne partageons pas d'informations personnelles pour la publicité comportementale intercontextuelle. Les résidents californiens ont le droit de savoir, de supprimer, de corriger et de se désinscrire. Étant donné que Signet ne collecte pas d'informations personnelles au sens traditionnel, la plupart des droits CCPA sont satisfaits par l'architecture elle-même.

**Lois étatiques sur la vie privée :** Nous nous conformons aux lois étatiques applicables sur la vie privée, notamment celles de Virginie (VCDPA), du Colorado (CPA), du Connecticut (CTDPA), de l'Utah (UCPA), du Texas (TDPSA) et d'autres États ayant adopté une législation sur la vie privée.

**Lois étatiques sur la vérification de l'âge :** Un certain nombre d'États américains ont adopté des lois exigeant la vérification de l'âge pour l'accès à certains services en ligne. Les preuves de tranche d'âge de Signet sont conçues pour satisfaire à ces exigences sans créer de bases de données centralisées des dates de naissance ou des documents d'identité des utilisateurs.

### 8.4 Brésil (LGPD — Lei Geral de Proteção de Dados)

Le traitement est basé sur :
- L'intérêt légitime (Art. 7, X)
- Le respect des obligations légales ou réglementaires (Art. 7, II)
- L'exécution d'un contrat ou de mesures préliminaires (Art. 7, V)

### 8.5 Corée du Sud (PIPA — Personal Information Protection Act)

Le traitement est conforme aux exigences de la PIPA, notamment la collecte limitée au strict minimum nécessaire, la limitation spécifique de la finalité, la notification des finalités de traitement et la conformité aux exigences de consentement.

### 8.6 Japon (APPI — Act on the Protection of Personal Information)

Le traitement est conforme à l'APPI tel qu'amendé, notamment la spécification de la finalité d'utilisation, l'acquisition appropriée d'informations personnelles et la conformité aux exigences de transfert transfrontalier.

### 8.7 Chine (PIPL — Personal Information Protection Law)

Lorsque le Protocole est accessible depuis la République populaire de Chine, le traitement est basé sur le consentement individuel ou l'exécution du contrat, les exigences de localisation des données sont respectées et les transferts transfrontaliers sont conformes aux Art. 38–43 de la PIPL.

### 8.8 Inde (DPDP — Digital Personal Data Protection Act)

Le traitement est conforme à la Loi DPDP, notamment le traitement basé sur le consentement ou des utilisations légitimes, les obligations en tant que fiduciaire de données et les droits des responsables des données.

---

## 9. Comment nous utilisons les données

Les données traitées via le Protocole Signet sont utilisées exclusivement pour :

1. **Émission et vérification d'attestations** — Permettre aux utilisateurs de créer, présenter et vérifier des attestations à travers les quatre niveaux de vérification.
2. **Calcul du Signet IQ** — Calculer les scores Signet IQ basés sur les cautions de réseau de confiance, les niveaux d'attestation, la fraîcheur des attestations et les signaux d'expiration des documents.
3. **Vérification de la tranche d'âge** — Utiliser les Bulletproofs pour prouver qu'un utilisateur se situe dans une tranche d'âge sans révéler son âge exact.
4. **Vérification professionnelle** — Permettre aux professionnels agréés (avocats, notaires, médecins) d'agir comme vérificateurs.
5. **Révocation d'attestations** — Traiter les événements de révocation lorsque des attestations sont invalidées.
6. **Intégrité du Protocole** — Maintenir l'intégrité cryptographique et la sécurité du Protocole.
7. **Conformité légale** — Se conformer aux lois et réglementations applicables.
8. **Cérémonie à deux attestations** — Émettre des paires d'attestations de Personne Physique et de Persona lors de la vérification professionnelle, notamment le calcul des arbres Merkle, des nullificateurs et des preuves de tranche d'âge.
9. **Gestion de la tutelle** — Traiter les événements de délégation de tuteur (type 31000) pour la gestion des comptes d'enfants.
10. **Divulgation sélective** — Permettre aux utilisateurs de prouver des attributs de feuilles Merkle individuels (notamment le numéro de document et la date d'expiration du document) aux parties utilisatrices qui en ont besoin, sans révéler les attributs non liés.
11. **Cycle de vie de l'attestation** — Traiter les chaînes d'attestations (balises remplace/remplacé-par) pour les changements de nom, le renouvellement des documents et les mises à niveau de niveau.

---

## 10. Partage et divulgation des données

### 10.1 Partage au niveau du Protocole

Le Protocole Signet fonctionne sur le réseau Nostr, qui est décentralisé. Lorsque vous publiez un événement d'attestation, une caution ou tout autre événement du Protocole, il est diffusé sur les relais Nostr. Cela est inhérent à la conception du Protocole et est initié par vous.

### 10.2 Nous ne partageons pas les données avec

- Les annonceurs ou les sociétés de marketing
- Les courtiers en données
- Les plateformes de médias sociaux (au-delà de la publication sur les relais Nostr)
- Les agences gouvernementales (sauf lorsque requis par la loi ou une procédure judiciaire valide)

### 10.3 Divulgation requise par la loi

Nous pouvons divulguer des informations si requis par une ordonnance judiciaire valide, une citation à comparaître ou une procédure judiciaire, une loi ou réglementation applicable, ou une demande d'une autorité d'application de la loi ou réglementaire avec une juridiction valide. Nous informerons les utilisateurs concernés de telles demandes dans la mesure légalement autorisée. Étant donné que Signet ne détient pas de données personnelles sur les utilisateurs dans des systèmes centralisés, la portée de toute divulgation contraignable est extrêmement limitée.

### 10.4 Partage de données des vérificateurs

Les vérificateurs professionnels (niveaux 3 et 4) publient des événements d'enregistrement de vérificateur (type 31000) sur le réseau Nostr. Ces événements incluent la clé publique Nostr professionnelle du vérificateur et les informations juridictionnelles. Les vérificateurs consentent à cette publication dans le cadre de l'Accord du vérificateur.

Les seules données partagées entre le vérificateur et le Protocole via les événements publiés sont l'événement d'attestation (type 31000), qui contient la clé publique du vérificateur, la clé publique de Persona du sujet, les métadonnées de l'attestation (niveau, dates, type d'entité, tranche d'âge), la preuve de tranche d'âge à divulgation nulle de connaissance, le hash nullificateur et la racine Merkle.

Aucune donnée d'identification personnelle (nom, date de naissance, numéros de document, nationalité) n'apparaît dans les événements publiés.

---

## 11. Transferts internationaux de données

### 11.1 Architecture décentralisée

Le réseau Nostr fonctionne à l'échelle mondiale. Lorsque vous publiez des événements sur les relais Nostr, ces événements peuvent être répliqués sur des relais situés partout dans le monde. C'est une caractéristique fondamentale du protocole décentralisé.

### 11.2 Mécanismes de transfert

Pour tout traitement centralisé que Signet effectue, les transferts internationaux de données sont protégés par :

- **UE/EEE :** Clauses contractuelles types (CCT) approuvées par la Commission européenne (Décision 2021/914), complétées par des évaluations d'impact des transferts lorsque requis.
- **Royaume-Uni :** International Data Transfer Agreement (IDTA) ou l'Addendum UK aux CCT de l'UE.
- **Corée du Sud :** Conformité aux dispositions de transfert transfrontalier de la PIPA.
- **Japon :** Transferts vers des pays ayant un niveau de protection adéquat reconnu par la PPC, ou avec le consentement de l'utilisateur.
- **Chine :** Évaluations de sécurité, contrats standard ou certifications conformément aux exigences de la PIPL.
- **Brésil :** Transferts conformes à l'Art. 33 de la LGPD, notamment vers des pays ayant un niveau de protection adéquat ou avec des garanties spécifiques.

### 11.3 Décisions d'adéquation

Nous nous appuyons sur les décisions d'adéquation lorsqu'elles sont disponibles, notamment le Cadre de protection des données UE-États-Unis, l'Extension UK au Cadre de protection des données UE-États-Unis et la décision d'adéquation de la Commission européenne pour le Japon.

---

## 12. Conservation des données

### 12.1 Événements Nostr

Les événements publiés sur le réseau Nostr sont conservés par les opérateurs de relais conformément à leurs propres politiques. Le réseau Nostr étant décentralisé, Signet ne peut pas garantir la suppression des événements de tous les relais.

### 12.2 Cycle de vie des attestations

| Type de données | Période de conservation |
|-----------|-----------------|
| Attestations actives | Jusqu'à expiration ou révocation |
| Attestations révoquées | Les événements de révocation sont conservés indéfiniment pour l'intégrité de la vérification |
| Attestations expirées | Conservées sur les relais selon les politiques des opérateurs de relais |
| Enregistrements de caution | Jusqu'à révocation par la partie cautionnant |
| Données de défi/réponse | Persistantes ; publiées sur les relais Nostr comme événements standard, conservées pour l'intégrité du protocole |
| Matériel de clé chiffré local | Sur votre appareil jusqu'à ce que vous supprimiez l'application ou effaciez les données de l'application |

### 12.3 Registres centralisés

Tous les registres que Signet conserve de manière centralisée (p. ex. correspondance de support, registres de conformité légale) sont conservés pendant :
- Registres de support : 2 ans à partir de la dernière interaction
- Registres de conformité légale : Comme requis par la loi applicable (généralement 5 à 7 ans)
- Journaux d'audit : 3 ans

---

## 13. Vos droits

### 13.1 Droits universels

Quelle que soit votre juridiction, vous pouvez :
- Demander des informations sur les données que nous traitons vous concernant
- Demander la correction de données inexactes
- Retirer votre consentement lorsque le traitement est basé sur le consentement
- Déposer une plainte auprès de nous ou d'une autorité de contrôle

### 13.2 Note sur l'architecture et les droits

L'architecture de Signet étant décentralisée et axée sur la confidentialité, de nombreux droits sont satisfaits de manière structurelle :

- **Accès et portabilité :** Vos données d'attestation sont stockées dans des événements Nostr publics que vous avez publiés, et dans votre stockage local d'application. Vous y avez déjà un accès complet.
- **Effacement :** Signet ne détient aucune copie centralisée de vos données personnelles. Nous ne pouvons pas supprimer les événements Nostr de l'infrastructure des opérateurs de relais en votre nom, mais nous pouvons émettre un événement de révocation. Vous pouvez demander la suppression auprès des opérateurs de relais individuels.
- **Rectification :** Les attestations incorrectes peuvent être remplacées en émettant un nouvel événement d'attestation faisant référence à l'ancien.

### 13.3 Union européenne / EEE (RGPD)

En vertu du RGPD, vous avez le droit :
- **D'accès** (Art. 15) — Obtenir une copie de vos données personnelles
- **De rectification** (Art. 16) — Corriger les données inexactes
- **D'effacement** (Art. 17) — Demander la suppression (« droit à l'oubli ») lorsque applicable
- **De limitation du traitement** (Art. 18) — Limiter le traitement dans certaines circonstances
- **À la portabilité des données** (Art. 20) — Recevoir vos données dans un format structuré et lisible par machine
- **D'opposition** (Art. 21) — S'opposer au traitement basé sur l'intérêt légitime
- **Relatif à la prise de décision automatisée** (Art. 22) — Ne pas faire l'objet de décisions uniquement automatisées ayant des effets juridiques

**Autorité de contrôle :** Vous pouvez déposer une plainte auprès de votre autorité locale de protection des données. Une liste des APD de l'UE/EEE est disponible sur [https://edpb.europa.eu/about-edpb/about-edpb/members_en](https://edpb.europa.eu/about-edpb/about-edpb/members_en).

### 13.4 Royaume-Uni (UK RGPD)

Vous disposez de droits équivalents à ceux du RGPD de l'UE. Vous pouvez déposer une plainte auprès de l'Information Commissioner's Office (ICO) sur [https://ico.org.uk](https://ico.org.uk).

### 13.5 États-Unis (CCPA / CPRA)

Les résidents californiens ont le droit de :
- **Savoir** — Quelles informations personnelles sont collectées, utilisées et divulguées
- **Supprimer** — Demander la suppression d'informations personnelles
- **Corriger** — Demander la correction d'informations personnelles inexactes
- **Se désinscrire** — Se désinscrire de la vente ou du partage d'informations personnelles (nous ne vendons ni ne partageons)
- **Non-discrimination** — Ne pas faire l'objet de discrimination pour l'exercice des droits à la vie privée

Pour exercer ces droits, contactez-nous à privacy@signet.id.

Les résidents de Virginie, du Colorado, du Connecticut, de l'Utah, du Texas et d'autres États ayant adopté une législation sur la vie privée disposent de droits comparables en vertu de leurs lois respectives.

### 13.6 Brésil (LGPD)

Les personnes concernées ont le droit à la confirmation de l'existence du traitement, à l'accès aux données, à la correction des données incomplètes, inexactes ou obsolètes, à l'anonymisation, au blocage ou à la suppression des données inutiles ou excessives, à la portabilité des données, à la suppression des données traitées avec consentement, aux informations sur les données partagées, aux informations sur la possibilité de refuser le consentement et ses conséquences, et à la révocation du consentement.

Contactez l'ANPD (Autoridade Nacional de Proteção de Dados) pour les plaintes : [https://www.gov.br/anpd](https://www.gov.br/anpd).

### 13.7 Corée du Sud (PIPA)

Les personnes concernées ont le droit de demander l'accès aux informations personnelles, de demander la correction ou la suppression, de demander la suspension du traitement et de déposer une plainte auprès de la Personal Information Protection Commission (PIPC).

### 13.8 Japon (APPI)

Les personnes concernées ont le droit de demander la divulgation des données personnelles conservées, de demander la correction, l'ajout ou la suppression, de demander la cessation de l'utilisation ou de la fourniture à des tiers, et de déposer une plainte auprès de la Personal Information Protection Commission (PPC).

### 13.9 Chine (PIPL)

Les personnes concernées ont le droit de savoir et de décider du traitement des informations personnelles, de limiter ou de refuser le traitement, d'accéder aux informations personnelles et de les copier, de demander la portabilité, de demander la correction et la suppression, et de demander une explication des règles de traitement.

### 13.10 Inde (Loi DPDP)

Les responsables des données ont le droit d'accéder aux informations sur le traitement, à la correction et à l'effacement des données personnelles, au recours en cas de réclamation et à la désignation d'une autre personne pour exercer les droits.

### 13.11 Exercice de vos droits

Pour exercer l'un des droits ci-dessus, contactez-nous à :
- **E-mail :** privacy@signet.id
- **E-mail DPD :** dpo@signet.id

Nous répondrons dans les délais requis par la loi applicable :
- RGPD/UK RGPD : 30 jours (extensibles de 60 jours pour les demandes complexes)
- CCPA/CPRA : 45 jours (extensibles de 45 jours)
- LGPD : 15 jours
- PIPA : 10 jours
- APPI : Sans délai
- PIPL : Rapidement

---

## 14. Données des enfants

### 14.1 Politique générale

Le Protocole Signet comprend le niveau 4 (Vérification professionnelle — Adulte + Enfant), spécifiquement conçu pour la sécurité des enfants. Nous prenons la protection des données des enfants très au sérieux. Les enfants de moins de 18 ans ne peuvent être vérifiés qu'au niveau 4 avec la participation active d'un tuteur adulte vérifié, auquel est émise une attestation de niveau 4 liant sa clé publique à l'attestation de l'enfant via une balise de tuteur.

### 14.2 Vérification de l'âge

Le Protocole utilise des preuves à divulgation nulle de connaissance basées sur les Bulletproofs pour la vérification de la tranche d'âge. Ces preuves démontrent qu'un utilisateur se situe dans une tranche d'âge donnée (p. ex. « 0–3 », « 4–7 », « 8–12 », « 13–17 », « 18+ ») sans révéler sa date de naissance exacte.

### 14.3 Exigences d'âge spécifiques aux juridictions

| Juridiction | Âge minimum pour le consentement numérique | Loi applicable |
|-------------|-------------------------------|---------------|
| UE (par défaut) | 16 ans | RGPD Art. 8 |
| UE (option État membre) | 13–16 ans (varie selon l'État membre) | RGPD Art. 8(1) |
| Royaume-Uni | 13 ans | UK RGPD / Children's Code |
| États-Unis | 13 ans | COPPA |
| Brésil | 12 ans (consentement parental requis jusqu'à 18 ans) | LGPD Art. 14 |
| Corée du Sud | 14 ans | PIPA |
| Japon | 15 ans (directives) | APPI |
| Chine | 14 ans | PIPL Art. 28 |
| Inde | 18 ans (avec exceptions) | Loi DPDP |

### 14.4 Consentement parental

Lorsque le consentement parental est requis, le Protocole prend en charge :
- Le consentement parental vérifiable via les attestations vérifiées de niveau 3 ou 4 du parent/tuteur
- La limitation par l'âge via la vérification des preuves ZK au niveau des parties utilisatrices
- Les événements de délégation de tuteur (type 31000) permettant aux parents de gérer l'activité Signet de leurs enfants
- Les mécanismes permettant aux parents de révoquer la délégation et le consentement

### 14.5 Conformité COPPA (États-Unis)

Signet ne collecte aucune information personnelle auprès d'aucun utilisateur, y compris les enfants de moins de 13 ans. L'architecture à divulgation nulle de connaissance du Protocole signifie qu'aucun nom, date de naissance, adresse ou autre information personnelle couverte par COPPA n'est collectée, stockée ou transmise par Signet. Les orientations de la FTC de mars 2026 reconnaissent la flexibilité pour les plateformes qui mettent en œuvre une vérification préservant la vie privée sans collecter d'informations personnelles couvertes.

### 14.6 Age Appropriate Design Code (Royaume-Uni)

Signet s'engage à respecter les principes du UK Age Appropriate Design Code (Children's Code), notamment l'évaluation de l'intérêt supérieur de l'enfant, l'application adaptée à l'âge, la minimisation des données, les paramètres par défaut protecteurs des enfants et la transparence adaptée à l'âge de l'enfant.

---

## 15. Sécurité

### 15.1 Sécurité cryptographique

Le Protocole Signet emploie :
- **Signatures Schnorr** sur la courbe secp256k1 pour toutes les signatures d'attestation
- **Bulletproofs** pour les preuves de tranche d'âge à divulgation nulle de connaissance
- **Signatures en anneau** (SAG et LSAG) pour les preuves d'appartenance à des groupes anonymes, avec des balises de séparation de domaine et des limites de taille d'anneau (maximum 1 000 membres)
- **Arbres Merkle RFC 6962** avec séparation de domaine (préfixe `0x00` pour les feuilles, préfixe `0x01` pour les nœuds internes) pour des engagements d'attributs inviolables
- **ECDH** avec rejet du point d'identité pour la dérivation du secret partagé
- **Future couche ZK** prévue pour des types de preuves supplémentaires (ZK-SNARKs/ZK-STARKs)

### 15.2 Sécurité du stockage des clés

Les clés privées dans l'application My Signet sont :
- Chiffrées au repos avec AES-256-GCM
- La clé de chiffrement est dérivée via PBKDF2 avec SHA-256 et 600 000 itérations (recommandation OWASP 2023), en utilisant un sel aléatoire
- Les clés sont conservées en mémoire uniquement pendant une session authentifiée
- Les phrases mnémoniques et les clés privées ne sont jamais transmises à Signet ni à un tiers
- Jamais stockées en clair dans IndexedDB, localStorage ou tout autre mécanisme de stockage

### 15.3 Validation des entrées

Tous les validateurs d'événements appliquent une longueur de contenu maximale (64 Ko), un nombre maximal de balises (100 balises), une longueur maximale de valeur de balise (1 024 caractères) et des vérifications de bornes d'entiers pour prévenir les contournements de sécurité silencieux.

### 15.4 Modèle de sécurité décentralisé

L'architecture décentralisée du Protocole offre des avantages de sécurité inhérents : pas de point de défaillance unique, pas de base de données centralisée à pirater, gestion des clés contrôlée par l'utilisateur et vérification cryptographique sans intermédiaires de confiance.

### 15.5 Notification de violation

En cas de violation de données personnelles affectant les systèmes centralisés de Signet, nous :
- Notifierons l'autorité de contrôle compétente dans les 72 heures (RGPD) ou comme requis par la loi applicable
- Notifierons les personnes concernées sans délai excessif lorsque la violation est susceptible de présenter un risque élevé pour leurs droits et libertés
- Documenterons la violation, ses effets et les mesures correctives

---

## 16. Cookies et technologies de suivi

Le Protocole Signet n'utilise **pas** :
- De cookies
- De balises web ou pixels de suivi
- D'empreinte digitale du navigateur
- De stockage local à des fins de suivi
- De services d'analyse ou de suivi tiers

Si des services auxiliaires (tels qu'un site web de documentation) utilisent des cookies, un avis de cookie distinct sera fourni avec des mécanismes de consentement appropriés.

---

## 17. Prise de décision automatisée et profilage

### 17.1 Calcul du Signet IQ

Le Protocole calcule les scores Signet IQ (0–200, où 100 représente la norme d'identité gouvernementale actuelle) basés sur le niveau de vérification, le nombre et la qualité des cautions, les attestations et la situation des vérificateurs, l'ancienneté de l'attestation et les signaux d'expiration des documents. Ces scores sont calculés algorithmiquement et sont visibles par les parties utilisatrices. Ils ne constituent pas une prise de décision automatisée ayant des effets juridiques en vertu de l'Art. 22 du RGPD, car ils sont l'une des nombreuses données que les parties utilisatrices peuvent prendre en compte.

### 17.2 Pas de profilage à des fins de marketing

Nous ne nous livrons pas au profilage à des fins de marketing, de publicité ou d'analyse comportementale.

---

## 18. Liens et services tiers

Le Protocole Signet interopère avec :
- Les relais Nostr (exploités indépendamment)
- Les clients Nostr (tels que Fathom, le client d'implémentation de référence)
- Les organismes professionnels et les registres réglementaires (via le bot de vérification open source)
- Le registre des types de documents (un fichier YAML externe définissant les définitions de champs de documents par pays — ne contient aucune donnée personnelle)

Ces tiers ont leurs propres politiques de confidentialité. Signet n'est pas responsable de leurs pratiques en matière de données.

---

## 19. Modifications de la présente Politique de confidentialité

Nous pouvons mettre à jour la présente Politique de confidentialité de temps en temps. Les modifications seront indiquées par la mise à jour de la date « Dernière mise à jour » en haut de ce document. Pour les modifications significatives, nous fournirons un avis via une annonce d'événement Nostr et une mise à jour du dépôt des spécifications du Protocole. Votre utilisation continue du Protocole après les modifications constitue l'acceptation de la Politique de confidentialité mise à jour.

---

## 20. Dispositions spécifiques aux juridictions

### 20.1 Union européenne — Dispositions complémentaires

Lorsque nous traitons des données personnelles en vertu du RGPD, les dispositions du RGPD prévalent sur toute disposition contradictoire de la présente Politique de confidentialité. Concernant eIDAS 2.0 : le Protocole de Signet est conçu pour accepter des événements de pont d'identité provenant des portefeuilles d'identité numérique de l'UE lorsque ces portefeuilles seront déployés par les États membres, prévus d'ici décembre 2026.

### 20.2 Royaume-Uni — Dispositions complémentaires

**Enregistrement auprès de l'ICO :** Signet s'enregistrera auprès de l'ICO comme requis. Les détails d'enregistrement seront publiés sur signet.id/legal.

**Ne pas vendre ni partager mes informations personnelles :** Nous ne vendons ni ne partageons des informations personnelles.

**Online Safety Act :** Les capacités de vérification de l'âge de Signet sont conçues pour être compatibles avec les exigences de garantie de l'âge de l'Online Safety Act 2023.

### 20.3 Californie — Dispositions complémentaires

**Ne pas vendre ni partager mes informations personnelles :** Nous ne vendons ni ne partageons des informations personnelles telles que définies dans le cadre du CCPA/CPRA.

**Incitations financières :** Nous n'offrons pas d'incitations financières liées à la collecte d'informations personnelles.

**Shine the Light (Cal. Civ. Code Section 1798.83) :** Les résidents californiens peuvent demander des informations sur les divulgations d'informations personnelles à des tiers à des fins de marketing direct. Nous ne procédons pas à de telles divulgations.

### 20.4 Brésil — Dispositions complémentaires

Le DPD (Encarregado) peut être contacté à dpo@signet.id pour toutes les demandes liées à la LGPD.

### 20.5 Australie — Dispositions complémentaires

Nous nous conformons aux Principes australiens de protection de la vie privée (APPs) en vertu du Privacy Act 1988 (Cth). Vous pouvez déposer une plainte auprès de l'Office of the Australian Information Commissioner (OAIC).

### 20.6 Nouvelle-Zélande — Dispositions complémentaires

Nous nous conformons au Privacy Act 2020 (NZ). Vous pouvez déposer une plainte auprès de l'Office of the Privacy Commissioner.

### 20.7 Singapour — Dispositions complémentaires

Nous nous conformons au Personal Data Protection Act 2012 (PDPA). Vous pouvez contacter la Personal Data Protection Commission (PDPC) pour les plaintes.

### 20.8 Afrique du Sud — Dispositions complémentaires

Nous nous conformons au Protection of Personal Information Act 2013 (POPIA). Vous pouvez déposer une plainte auprès du Régulateur de l'information.

---

## 21. Nous contacter

Pour toute question, préoccupation ou demande relative à la présente Politique de confidentialité ou à nos pratiques en matière de données :

**Demandes générales :**
Le Protocole Signet
E-mail : privacy@signet.id

**Délégué à la protection des données :**
E-mail : dpo@signet.id

---

## 22. Dépôts réglementaires

Selon la juridiction, Signet maintient ou maintiendra des enregistrements ou dépôts auprès de :
- L'Information Commissioner's Office (Royaume-Uni) — enregistrement à compléter ; détails publiés sur signet.id/legal
- Les autorités de protection des données de l'UE/EEE applicables
- Les autres organismes réglementaires comme requis par la loi

---

*La présente Politique de confidentialité décrit les pratiques en matière de données du Protocole Signet en date de mars 2026. Le Protocole Signet est un logiciel open source. Ce document ne constitue pas un avis juridique. Les utilisateurs et les opérateurs doivent consulter un conseiller juridique qualifié familier avec les lois applicables de protection des données dans leur juridiction.*

*Protocole Signet — v0.1.0*
*Version du document : 2.0*
