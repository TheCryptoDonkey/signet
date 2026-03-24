---
**Avis de traduction générée par IA**

Ce document a été traduit de l'anglais à l'aide de l'IA (Claude, Anthropic). Il est fourni à titre de référence uniquement. La version anglaise disponible à `en.md` est le seul document juridiquement contraignant. Cette traduction n'a pas été révisée par un traducteur juridique qualifié. En cas de divergence entre cette traduction et l'original anglais, la version anglaise prévaut.

---

# Politique de protection de l'enfance

**Le Protocole Signet — v0.1.0**

*Modèle — Consultez un conseiller juridique qualifié dans votre juridiction avant tout déploiement.*

**Date d'entrée en vigueur :** Mars 2026
**Dernière mise à jour :** Mars 2026

---

## 1. Objectif

La présente Politique de protection de l'enfance (la « Politique ») énonce l'engagement du Protocole Signet (« nous » ou « notre ») en faveur de la protection des enfants qui interagissent avec le Protocole Signet (le « Protocole ») ou qui en sont affectés. Le niveau de vérification 4 du Protocole (Vérification professionnelle — Adulte + Enfant) traite spécifiquement de la vérification d'identité des enfants, et la présente Politique régit la manière dont cette capacité — et toutes les données relatives aux enfants — est gérée.

La sécurité et la vie privée des enfants constituent notre préoccupation primordiale. La présente Politique est conçue pour se conformer à toutes les lois applicables de protection de l'enfance dans le monde entier et pour dépasser les exigences minimales dans la mesure du possible.

---

## 2. Champ d'application

La présente Politique s'applique à :

- Toutes les interactions avec le Protocole Signet impliquant des personnes de moins de 18 ans (ou de l'âge de la majorité dans la juridiction concernée, selon ce qui est le plus élevé)
- Les processus d'émission et de vérification des attestations de niveau 4
- Les processus de vérification de l'âge utilisant des preuves à divulgation nulle de connaissance
- Tout le personnel, les vérificateurs, les parties utilisatrices et les tiers qui interagissent avec les données d'enfants via le Protocole
- Toutes les juridictions dans lesquelles le Protocole est utilisé

---

## 3. Définitions

**« Enfant »** désigne toute personne de moins de 18 ans, ou de moins de l'âge de la majorité dans la juridiction concernée, selon ce qui est le plus élevé.

**« Âge de consentement numérique »** désigne l'âge minimal auquel un enfant peut consentir de manière indépendante au traitement de ses données personnelles pour les services numériques, tel que défini par la juridiction applicable.

**« Parent/Tuteur »** désigne un parent, un tuteur légal ou toute autre personne ayant l'autorité légale d'agir au nom d'un enfant.

**« Vérification de niveau 4 »** désigne le niveau Vérification professionnelle (Adulte + Enfant) du Protocole, dans lequel un vérificateur professionnel agréé confirme l'identité d'un enfant avec la participation et le consentement d'un parent/tuteur.

**« Preuve de tranche d'âge »** désigne une preuve à divulgation nulle de connaissance (utilisant des Bulletproofs) qui démontre que l'âge d'un utilisateur se situe dans une tranche spécifiée sans révéler la date de naissance exacte.

**« Signet IQ »** désigne le score continu de Quotient d'Identification du Protocole (0–200) reflétant la force cumulée des signaux de vérification d'un utilisateur. Pour les enfants, le Signet IQ est calculé à partir du niveau de vérification propre du tuteur et de son Signet IQ, de l'attestation de niveau 4 propre à l'enfant, et de toute caution entre pairs provenant de comptes vérifiés.

---

## 4. Cadre réglementaire

### 4.1 Conformité internationale

La présente Politique est conçue pour se conformer aux lois et cadres suivants :

| Juridiction | Loi / Cadre | Exigences principales |
|-------------|----------------|-----------------|
| **États-Unis** | Children's Online Privacy Protection Act (COPPA) | Consentement parental vérifiable pour les enfants de moins de 13 ans ; minimisation des données ; droits d'accès des parents |
| **Union européenne** | RGPD Article 8 | Âge de consentement numérique de 16 ans (les États membres peuvent l'abaisser à 13 ans) ; consentement parental requis en dessous de l'âge de consentement numérique |
| **Royaume-Uni** | UK RGPD + Age Appropriate Design Code (AADC) | Intérêt supérieur de l'enfant ; conception adaptée à l'âge ; 15 normes de l'AADC |
| **Australie** | Privacy Act 1988 + Online Safety Act 2021 | Mesures raisonnables pour vérifier l'âge ; attentes de base en matière de sécurité en ligne |
| **Corée du Sud** | PIPA + Loi sur la promotion de l'utilisation des réseaux d'information et de communication | Consentement du représentant légal pour les enfants de moins de 14 ans |
| **Brésil** | LGPD Article 14 | Intérêt supérieur de l'enfant ; consentement parental spécifique pour les enfants de moins de 12 ans ; double consentement pour 12–17 |
| **Inde** | Loi DPDP 2023 | Consentement vérifiable du parent/tuteur pour les enfants (moins de 18 ans) ; interdiction du suivi, de la surveillance comportementale et de la publicité ciblée pour les enfants |
| **Chine** | PIPL Article 28 + Dispositions sur la protection des mineurs en ligne | Consentement spécifique pour les moins de 14 ans ; protections renforcées pour tous les mineurs |
| **Japon** | APPI + Loi fondamentale sur la cybersécurité | Lignes directrices sectorielles pour la protection des données des enfants |
| **Canada** | PIPEDA + lois provinciales | Consentement significatif basé sur la capacité de l'enfant |

### 4.2 Convention des Nations Unies relative aux droits de l'enfant

La présente Politique s'inspire des principes de la Convention des Nations Unies relative aux droits de l'enfant, notamment :
- L'intérêt supérieur de l'enfant (Article 3)
- Le droit à la vie privée (Article 16)
- Le droit à la protection contre l'exploitation (Article 36)

---

## 5. Vérification de l'âge via des preuves à divulgation nulle de connaissance

### 5.1 Fonctionnement de la vérification de l'âge

Le Protocole Signet utilise des preuves à divulgation nulle de connaissance basées sur les Bulletproofs pour la vérification de l'âge. Cette approche :

1. **Prouve sans révéler :** Un utilisateur peut prouver qu'il se situe dans une tranche d'âge spécifiée (p. ex. « plus de 13 ans », « plus de 16 ans », « plus de 18 ans », « 13–17 ans ») sans révéler sa date de naissance exacte.
2. **Ne peut pas être rétro-ingénié :** La preuve à divulgation nulle de connaissance est construite mathématiquement de sorte que la date de naissance sous-jacente ne peut pas être extraite de la preuve.
3. **Est vérifiée cryptographiquement :** Les parties utilisatrices peuvent vérifier la validité de la preuve sans rien apprendre au-delà de la revendication de tranche d'âge.
4. **Est émise une fois, utilisée plusieurs fois :** Une seule preuve de tranche d'âge peut être présentée à plusieurs parties utilisatrices sans nouvelle vérification.

### 5.2 Catégories de tranches d'âge

Le Protocole prend en charge les preuves de tranches d'âge standard suivantes :

| Tranche | Description | Cas d'usage |
|-------|-------------|----------|
| Moins de 13 ans | En dessous du seuil COPPA | Requiert le consentement parental complet et la supervision |
| 13–15 ans | Au-dessus de COPPA, en dessous de certains seuils RGPD | Peut nécessiter un consentement parental selon la juridiction |
| 16–17 ans | Au-dessus de la plupart des âges de consentement numérique, en dessous de la majorité | Consentement indépendant dans la plupart des juridictions ; supervision parentale partielle |
| 18+ ans | Âge de la majorité dans la plupart des juridictions | Consentement indépendant complet |
| Personnalisé | Tranches d'âge spécifiques à la juridiction | Conformité avec les exigences locales spécifiques |

### 5.3 Émission de preuves pour les enfants

Pour les enfants (moins de 18 ans), la cérémonie de vérification suit un flux dirigé par l'utilisateur avec confirmation professionnelle :

1. Le parent/tuteur et l'enfant se présentent ensemble à une vérification de niveau 4 avec un professionnel agréé (solicitor, notaire, médecin ou équivalent).
2. **L'utilisateur (parent/tuteur) saisit toutes les informations du document** dans l'application My Signet : type de document, pays d'émission, numéro de document et date de naissance de l'enfant. Le vérificateur inspecte les documents physiques pour confirmer l'exactitude des données saisies — il ne saisit pas au nom de l'utilisateur.
3. Le Protocole calcule le nullificateur basé sur le document localement sur l'appareil de l'utilisateur en utilisant la formule `signet-nullifier-v2` (SHA-256 des champs préfixés par la longueur : docType, country, docNumber, « signet-nullifier-v2 »). Le nullificateur est transmis au vérificateur ; les détails bruts du document ne le sont pas.
4. Le vérificateur génère la preuve Bulletproof de tranche d'âge et émet simultanément deux attestations : une attestation de Personne Physique (paire de clés A) et une attestation de Persona (paire de clés B). Les deux portent la preuve de tranche d'âge et les balises de tuteur (`["guardian", "<parent_pubkey>"]`). Le vrai nom de l'enfant n'est stocké que comme feuille Merkle privée — jamais publié en chaîne.
5. L'arbre Merkle pour l'attestation de Personne Physique de l'enfant contient : la date de naissance (pour la preuve de tranche d'âge), la relation de tutelle, le type de document, le numéro de document et la date d'expiration du document. Le nom de l'enfant est inclus comme feuille Merkle privée et n'est **pas** publié sur un relais. La nationalité peut être incluse pour la conformité jurisdictionnelle.
6. Le nullificateur basé sur le document (hash du type de document, du pays et du numéro utilisant `signet-nullifier-v2`) est inclus uniquement dans l'attestation de Personne Physique, empêchant la création d'identités dupliquées.
7. **Protection biométrique du compte :** Sur l'appareil de l'enfant, l'application My Signet utilise le déverrouillage biométrique WebAuthn (reconnaissance faciale ou empreinte digitale) pour protéger l'accès au compte de l'enfant. Les données biométriques ne quittent jamais l'appareil — elles sont entièrement gérées par l'enclave sécurisée de l'appareil via la norme WebAuthn. Aucun modèle biométrique n'est transmis à un serveur ni stocké en dehors de l'appareil.

### 5.4 Les enseignants comme principal canal de vérification des enfants

Les enseignants et les administrateurs scolaires constituent un canal reconnu pour la vérification des enfants de niveau 4. Les dossiers d'inscription scolaire — qui établissent la relation parent-enfant et fournissent des preuves de la date de naissance — sont acceptés comme documentation complémentaire en accompagnement de la pièce d'identité parentale.

Un enseignant qui est un professionnel agréé (p. ex. un enseignant qualifié dans une juridiction qui traite l'enseignement comme une profession réglementée, ou un notaire affilié à une école) peut effectuer la vérification de niveau 4 en utilisant :
- La pièce d'identité officielle délivrée par le gouvernement du parent/tuteur
- Le dossier d'inscription scolaire comme preuve de l'enfant (en complément ou en remplacement d'un acte de naissance ou d'un passeport)

Ce parcours est particulièrement important pour les communautés d'enseignement à domicile et les régions où l'accès à des solicitors ou des notaires est limité. L'ordre professionnel de l'éducateur et son établissement employeur sont les ancres de confiance. L'attestation frauduleuse par un enseignant constitue une faute professionnelle en vertu du droit de l'éducation applicable.

### 5.5 Vérification de l'âge basée sur le SDK pour les sites web

Le SDK Signet permet aux sites web et aux applications de vérifier la tranche d'âge d'un enfant sans recevoir d'informations personnellement identifiables. Le flux de données est :

```
Site web → SDK → Application My Signet → Preuve d'âge ZK → Site web
```

Le site web demande la preuve d'une revendication d'âge spécifique (p. ex. « l'utilisateur a moins de 18 ans » ou « l'utilisateur a entre 13 et 17 ans »). Le SDK Signet achemine cette demande vers l'application My Signet sur l'appareil de l'utilisateur. L'application génère la preuve localement et ne renvoie que la preuve cryptographique — pas de nom, pas de date de naissance, pas de détails du document, pas de nullificateur. Le site web vérifie la preuve mathématiquement et n'apprend que la revendication de tranche d'âge.

Cela signifie que les sites web peuvent se conformer aux exigences de vérification de l'âge (COPPA, UK Online Safety Act, réglementations australiennes pour les moins de 16 ans) sans collecter ni stocker de données personnelles sur les enfants.

---

## 6. Mécanismes de consentement parental

### 6.1 Exigences de consentement par juridiction

| Juridiction | Âge de consentement numérique | Mécanisme de consentement requis |
|-------------|--------------------|-----------------------------|
| États-Unis (COPPA) | 13 | Consentement parental vérifiable (p. ex. formulaire signé, vérification par carte de crédit, appel vidéo, vérification de pièce d'identité officielle) |
| UE (RGPD par défaut) | 16 | Efforts raisonnables pour vérifier le consentement parental |
| UE (minimum des États membres) | 13 | Selon la mise en œuvre de l'État membre |
| Royaume-Uni | 13 | Vérification adaptée à l'âge du consentement parental |
| Australie | Pas d'âge numérique spécifique | Mesures raisonnables basées sur la maturité et le risque |
| Corée du Sud | 14 | Consentement du représentant légal |
| Brésil | 12 (avec consentement parental jusqu'à 18 ans) | Consentement spécifique et explicite du parent/tuteur |
| Inde | 18 | Consentement vérifiable du parent/tuteur |
| Chine | 14 | Consentement distinct du parent/tuteur |
| Japon | 15 (directive) | Participation parentale recommandée |

### 6.2 Mécanismes de consentement du Protocole

Le Protocole prend en charge les mécanismes de consentement parental suivants :

1. **Attestation parentale vérifiée (Niveau 3/4) :**
   Le parent/tuteur obtient une attestation de niveau 3 ou 4 vérifiant sa propre identité via la cérémonie à deux attestations (Personne Physique + Persona). Il signe ensuite cryptographiquement un événement de consentement autorisant l'attestation de l'enfant. Cela crée une chaîne vérifiable :
   - Identité du parent vérifiée par un vérificateur professionnel (cérémonie à deux attestations)
   - Consentement du parent signé cryptographiquement avec sa clé Nostr
   - Attestation de l'enfant liée au parent via des balises de tuteur immuables sur les deux attestations (Personne Physique et Persona)
   - Les événements de délégation de tuteur (type 31000) permettent au parent de déléguer des autorisations spécifiques à d'autres adultes de confiance

2. **Co-vérification :**
   Le parent/tuteur et l'enfant participent ensemble à une session de vérification de niveau 4. Le vérificateur professionnel :
   - Vérifie les identités du parent/tuteur et de l'enfant
   - Confirme la relation parent-enfant ou tuteur-enfant
   - Enregistre le consentement du parent/tuteur dans le cadre de l'événement de vérification

3. **Consentement délégué :**
   Pour les juridictions nécessitant des mécanismes de consentement spécifiques (p. ex. le consentement parental vérifiable de COPPA), des étapes de vérification supplémentaires peuvent être requises :
   - Formulaire de consentement signé (numérique ou physique)
   - Session de vérification vidéo
   - Vérification de la pièce d'identité officielle délivrée par le gouvernement du parent/tuteur consentant

### 6.3 Retrait du consentement

Les parents/tuteurs peuvent retirer leur consentement à tout moment en :
1. Publiant un événement de révocation (type 31000) depuis la clé Nostr du parent/tuteur, révoquant l'événement de consentement.
2. Contactant l'équipe de support du Protocole Signet pour demander une assistance à la révocation.
3. Via tout client Nostr implémentant les fonctionnalités de gestion du consentement du Protocole.

Suite au retrait du consentement :
- L'attestation de l'enfant est immédiatement révoquée.
- Les parties utilisatrices sont notifiées via l'événement de révocation.
- Toutes les données relatives à l'enfant détenues de manière centralisée sont supprimées dans les 30 jours, sauf lorsque la conservation est requise par la loi.

---

## 7. Minimisation des données pour les enfants

### 7.1 Principe

Le Protocole applique les principes de minimisation des données les plus stricts pour les données des enfants. Seules les données strictement nécessaires à la vérification de l'attestation sont collectées ou traitées.

### 7.2 Ce qui est collecté

| Données | Collectées | Justification |
|------|-----------|-----------|
| Clé publique Nostr de l'enfant | Oui | Requise pour la liaison de l'attestation |
| Preuve de tranche d'âge (preuve ZK) | Oui | Requise pour la vérification de l'âge |
| Enregistrement du consentement parental | Oui | Requis pour la conformité légale |
| Métadonnées de l'attestation (niveau, dates) | Oui | Requises pour la fonctionnalité de l'attestation |
| Nom de l'enfant | **Non (pas en chaîne)** | Stocké uniquement comme feuille Merkle privée ; jamais publié |
| Date de naissance de l'enfant | **Non (pas en chaîne)** | Remplacée par la preuve d'âge ZK ; stockée uniquement comme feuille Merkle privée |
| Photo de l'enfant | **Non** | Non requise |
| Numéro de pièce d'identité officielle de l'enfant | **Non (pas en chaîne)** | Stocké uniquement comme feuille Merkle privée pour la divulgation sélective ; non stocké par le vérificateur après la cérémonie |
| Hash nullificateur (`signet-nullifier-v2`) | Oui (attestation NP uniquement) | Requis pour la prévention des doublons ; ne peut pas être inversé pour obtenir les détails du document |
| Clé(s) publique(s) du tuteur | Oui (les deux attestations) | Requises pour le lien tuteur-enfant |
| Relation de tutelle | Oui (feuille Merkle privée, attestation NP) | Établit la base légale du lien de tutelle |
| Racine Merkle | Oui (attestation NP uniquement) | S'engage sur les attributs vérifiés sans les publier |
| Balise de type d'entité | Oui (les deux attestations) | Requise pour distinguer la Personne Physique de la Persona |
| Localisation de l'enfant | **Non** | Non requise |
| École ou institution de l'enfant | **Non (pas en chaîne)** | Peut être référencée comme preuve complémentaire mais pas publiée |
| Données comportementales | **Non** | Interdites |
| Suivi de l'utilisation | **Non** | Interdit pour les enfants |
| Données biométriques | **Non** | Locales à l'appareil uniquement via WebAuthn ; aucun modèle transmis |

### 7.3 Attributs de l'arbre Merkle pour les enfants

L'attestation de Personne Physique d'un enfant s'engage sur un arbre Merkle avec les feuilles suivantes :

| Feuille | Objectif | Divulguée en chaîne ? |
|------|---------|---------------------|
| `dateOfBirth:<date ISO>` | Source pour la preuve d'âge ZK | Non — privée |
| `guardianRelationship:<type>` | Base légale (p. ex. « parent », « legal_guardian ») | Non — privée |
| `documentType:<type>` | Type de preuve présentée | Non — privée |
| `documentNumber:<numéro>` | Pour divulgation sélective si requis | Non — privée |
| `documentExpiry:<date>` | Vérification de la validité du document | Non — privée |
| `name:<nom>` | Pour divulgation sélective si requis | Non — privée |
| `nationality:<code>` | Conformité jurisdictionnelle | Non — privée |
| `nullifier:<hash>` | Prévention des doublons | Oui (en tant que balise de premier niveau) |

Seules la racine Merkle et le hash nullificateur apparaissent en chaîne. Les feuilles individuelles ne sont révélées que lorsque le tuteur de l'enfant exerce explicitement la divulgation sélective (p. ex. pour prouver la nationalité de l'enfant à une autorité réglementaire).

### 7.4 Signet IQ pour les enfants

Les enfants ont des scores Signet IQ calculés à partir de :
- L'attestation de niveau 4 elle-même (contribution majeure)
- Le niveau de vérification propre du tuteur et son Signet IQ (contribution pondérée, reflétant la force de la relation de tutelle)
- Les cautions entre pairs d'autres comptes de niveau 2+ qui connaissent la famille

Le Signet IQ d'un enfant est affiché aux parties utilisatrices comme signal de confiance agrégé. Il ne révèle pas l'identité du tuteur, le nom de l'enfant, ni aucun autre attribut personnel — il est calculé uniquement à partir d'événements d'attestation publics. L'évaluation sociale des enfants basée sur leur Signet IQ à des fins autres que la vérification de l'âge et le contrôle d'accès est interdite (voir Section 8).

### 7.5 Durées de conservation

Les données des enfants sont soumises aux périodes de conservation les plus courtes autorisées :
- Attestations actives : Jusqu'à expiration, révocation ou jusqu'à ce que l'enfant atteigne la majorité (selon ce qui survient en premier)
- Enregistrements de consentement : Durée de validité de l'attestation plus toute période de conservation légalement requise
- Enregistrements de vérification : Selon les obligations professionnelles du vérificateur (généralement 1 à 3 ans)
- Données de défi/réponse : Supprimées immédiatement après la vérification

---

## 8. Utilisations interdites

### 8.1 Interdictions absolues

Les utilisations suivantes du Protocole en relation avec des enfants sont **strictement interdites** :

1. **Profilage :** Utilisation du Protocole pour établir le profil d'enfants à quelque fin que ce soit, y compris le marketing, la publicité ou l'analyse comportementale.
2. **Suivi :** Utilisation des attestations ou des données de vérification pour suivre les activités en ligne ou hors ligne des enfants.
3. **Publicité ciblée :** Utilisation de preuves de tranche d'âge ou de données d'attestation pour cibler la publicité sur les enfants.
4. **Monétisation des données :** Vente, concession sous licence ou autre monétisation des données d'attestation des enfants ou des données de vérification de l'âge.
5. **Prise de décision automatisée :** Utilisation des données d'attestation des enfants pour des décisions automatisées qui ont des effets juridiques ou similairement significatifs.
6. **Surveillance :** Utilisation du Protocole pour la surveillance continue des activités des enfants.
7. **Notation sociale :** Utilisation des données d'attestation ou de Signet IQ pour créer des systèmes de notation sociale pour les enfants au-delà du contrôle d'accès adapté à l'âge.
8. **Manipulation :** Utilisation de schémas de conception qui exploitent les vulnérabilités des enfants ou manipulent leur comportement.
9. **Collecte de données inutile :** Collecte auprès des enfants de plus de données que ce qui est strictement nécessaire pour la vérification de l'attestation.
10. **Partage sans consentement :** Partage des données des enfants avec des tiers sans consentement parental vérifiable.

### 8.2 Restrictions applicables aux parties utilisatrices

Les parties utilisatrices qui reçoivent des preuves de tranche d'âge ou des vérifications d'attestation pour les enfants :
- Ne doivent pas utiliser les données au-delà de l'objectif spécifique pour lequel la vérification a été demandée
- Ne doivent pas conserver les données de vérification au-delà du besoin immédiat
- Doivent mettre en œuvre leurs propres mesures de protection de l'enfance adaptées à leur service
- Doivent se conformer à toutes les lois applicables de protection de l'enfance dans leur juridiction

---

## 9. Signalement et réponse aux incidents

### 9.1 Types d'incidents à signaler

Les incidents suivants impliquant des enfants doivent être signalés :

| Type d'incident | Seuil de signalement | Priorité |
|--------------|---------------------|----------|
| Violation des données d'attestation d'un enfant | Tout accès non autorisé | Critique — Immédiat |
| Attestation de niveau 4 frauduleuse pour un enfant | Découverte de tout cas | Critique — Immédiat |
| Compromission du mécanisme de consentement parental | Tout indice de compromission | Critique — Immédiat |
| Exploitation de la vérification de l'âge | Découverte de tout contournement | Élevée — Dans les 4 heures |
| Utilisation abusive de l'attestation d'un enfant par une partie utilisatrice | Tout abus signalé | Élevée — Dans les 4 heures |
| Exploitation présumée d'enfants facilitée par le Protocole | Tout indice | Critique — Immédiat + Forces de l'ordre |
| Désanonymisation de l'identité d'un enfant | Tout cas | Critique — Immédiat |

### 9.2 Procédures de signalement

**Signalement interne :**
- Tous les incidents sont signalés immédiatement au Responsable désigné de la protection de l'enfance.
- Le Responsable de la protection de l'enfance escalade au DPO et à la direction générale.

**Signalement réglementaire :**
- Les autorités de contrôle compétentes sont notifiées dans les délais requis par la loi applicable (p. ex. 72 heures en vertu du RGPD).
- Les exigences de notification spécifiques à chaque pays sont respectées (voir Section 10).

**Signalement aux forces de l'ordre :**
- Les incidents impliquant une exploitation présumée d'enfants sont immédiatement signalés à :
  - Les forces de l'ordre locales
  - National Centre for Missing & Exploited Children (NCMEC) (États-Unis)
  - Internet Watch Foundation (IWF) (Royaume-Uni)
  - Les organismes équivalents dans la juridiction concernée

**Notification aux parents :**
- Les parents/tuteurs sont notifiés sans délai de tout incident affectant les données ou l'attestation de leur enfant.
- La notification comprend une description de l'incident, son impact potentiel et les mesures prises.

### 9.3 Remédiation

Suite à un incident de protection de l'enfance :
1. Confinement immédiat de l'incident
2. Révocation des attestations affectées
3. Enquête judiciaire
4. Analyse des causes profondes
5. Mise en œuvre de mesures préventives
6. Notification de suivi aux parties affectées
7. Examen post-incident et mise à jour de la Politique si nécessaire

---

## 10. Exigences spécifiques aux juridictions

### 10.1 Royaume-Uni

**Age Appropriate Design Code (AADC) — 15 normes :**

| Norme | Mise en œuvre |
|----------|---------------|
| Intérêt supérieur de l'enfant | Évaluations d'impact sur la protection de l'enfance pour toutes les fonctionnalités du Protocole affectant les enfants |
| Évaluations d'impact sur la protection des données | AIPD réalisée pour le niveau 4 et tout traitement lié aux enfants |
| Application adaptée à l'âge | Interfaces du Protocole conçues pour différentes tranches d'âge |
| Transparence | Informations sur la vie privée fournies dans un langage adapté à l'âge |
| Utilisation préjudiciable des données | Interdiction d'utiliser les données des enfants de manière préjudiciable à leur bien-être |
| Politiques et normes communautaires | Normes claires sur la façon dont les attestations des enfants peuvent être utilisées |
| Paramètres par défaut | Paramètres protecteurs de la vie privée par défaut pour toutes les attestations d'enfants |
| Minimisation des données | Minimisation la plus stricte appliquée (voir Section 7) |
| Partage des données | Données des enfants non partagées au-delà de la nécessité vérifiée |
| Géolocalisation | Aucune donnée de géolocalisation collectée ou traitée pour les enfants |
| Contrôles parentaux | Mécanismes de consentement et de supervision tels que décrits à la Section 6 |
| Profilage | Interdit pour les enfants (voir Section 8) |
| Techniques de manipulation | Interdites pour les enfants (voir Section 8) |
| Jouets et appareils connectés | Non applicable au Protocole, mais les parties utilisatrices sont informées |
| Outils en ligne | Outils du Protocole conçus avec la protection de l'enfance à l'esprit |

**Signalement :** À l'Information Commissioner's Office (ICO) dans les 72 heures.

### 10.2 États-Unis

**Conformité COPPA :**
- Consentement parental vérifiable obtenu avant de collecter toute information auprès des enfants de moins de 13 ans
- Avis de confidentialité en ligne clair et complet décrivant les pratiques en matière de données des enfants
- Accès parental pour examiner et supprimer les données de l'enfant
- Pas de conditionnement de la participation d'un enfant à la divulgation inutile d'informations
- Mesures de sécurité raisonnables pour les données des enfants

**Position de la FTC en mars 2026 :** La FTC n'engagera pas de mesures d'exécution lorsque des données personnelles sont collectées uniquement à des fins de vérification de l'âge, à condition que les données soient robustement supprimées et qu'un avis clair soit donné. Signet dépasse cela : aucune donnée personnelle n'est collectée, stockée ou transmise lors de la vérification de l'âge — la preuve ZKP ne contient aucune PII.

**Lois étatiques :**
- California Consumer Privacy Act (CCPA) — consentement opt-in requis pour la vente de données de consommateurs de moins de 16 ans
- California Age-Appropriate Design Code Act (AB 2273) — évaluations d'impact sur la protection des données pour les services susceptibles d'être consultés par des enfants
- Autres lois étatiques applicables

**Signalement :** À la FTC et aux procureurs généraux des États applicables.

### 10.3 Union européenne

**Conformité à l'Article 8 du RGPD :**
- Consentement parental requis en dessous de l'âge de consentement numérique (13–16, selon l'État membre)
- Efforts raisonnables pour vérifier que le consentement est donné par le titulaire de la responsabilité parentale
- Directement adressé à un enfant : avis de confidentialité en langage clair et simple adapté à l'enfant

**Variations des États membres :**

| Pays | Âge de consentement numérique |
|---------|--------------------|
| Autriche | 14 |
| Belgique | 13 |
| Croatie | 16 |
| République tchèque | 15 |
| Danemark | 13 |
| Estonie | 13 |
| Finlande | 13 |
| France | 15 |
| Allemagne | 16 |
| Grèce | 15 |
| Hongrie | 16 |
| Irlande | 16 |
| Italie | 14 |
| Lettonie | 13 |
| Lituanie | 14 |
| Luxembourg | 16 |
| Malte | 13 |
| Pays-Bas | 16 |
| Pologne | 16 |
| Portugal | 13 |
| Roumanie | 16 |
| Slovaquie | 16 |
| Slovénie | 16 |
| Espagne | 14 |
| Suède | 13 |

**Signalement :** À l'autorité de contrôle principale dans les 72 heures.

### 10.4 Australie

**Privacy Act 1988 + Online Safety Act 2021 :**
- Mesures raisonnables pour assurer la capacité de consentement de l'enfant
- Informations sur la vie privée adaptées à l'âge
- Conformité au Online Safety (Basic Online Safety Expectations) Determination 2022

**Signalement :** À l'Office of the Australian Information Commissioner (OAIC) et au Commissaire à la sécurité en ligne (eSafety Commissioner).

### 10.5 Corée du Sud

**PIPA + Loi sur la promotion de l'utilisation des réseaux d'information et de communication :**
- Consentement du représentant légal requis pour les enfants de moins de 14 ans
- Informations strictement nécessaires uniquement
- Pas de collecte sans consentement du représentant légal

**Signalement :** À la Personal Information Protection Commission (PIPC).

### 10.6 Brésil

**LGPD Article 14 :**
- Intérêt supérieur de l'enfant
- Consentement parental spécifique et explicite pour les enfants de moins de 12 ans
- Enfants de 12–17 ans : double consentement (enfant + parent)
- Pratiques d'information communiquées d'une manière simple, claire et accessible adaptée à l'enfant

**Signalement :** À l'ANPD (Autoridade Nacional de Proteção de Dados).

### 10.7 Inde

**Loi DPDP 2023 :**
- Consentement vérifiable du parent/tuteur pour tous les enfants (moins de 18 ans)
- Interdiction du suivi, de la surveillance comportementale et de la publicité ciblée destinés aux enfants
- Obligations du fiduciaire de données concernant les données des enfants

**Signalement :** Au Data Protection Board of India.

---

## 11. Principes de conception pour la protection de l'enfance

### 11.1 Protection de la vie privée dès la conception

Toutes les fonctionnalités du Protocole affectant les enfants incorporent :
- La minimisation des données au niveau architectural
- Des preuves à divulgation nulle de connaissance pour éviter d'exposer des données personnelles
- Des protections cryptographiques intégrées dans la structure de l'attestation
- Des paramètres protecteurs de la vie privée par défaut
- Un flux de cérémonie où l'utilisateur saisit et le vérificateur confirme — les données du document sont saisies par l'utilisateur sur son propre appareil ; le vérificateur confirme l'exactitude mais ne détient jamais les détails bruts du document

### 11.2 Sécurité dès la conception

Les interfaces et implémentations du Protocole doivent :
- Distinguer clairement les flux de travail d'attestation des enfants et des adultes
- Prévenir l'exposition accidentelle des informations d'identité des enfants
- Inclure des garanties contre l'utilisation abusive des attestations
- Fournir des directives claires et adaptées à l'âge
- Utiliser le déverrouillage biométrique de l'appareil (WebAuthn) pour protéger les comptes des enfants sur l'appareil

### 11.3 Révision régulière

La présente Politique et toutes les mesures de protection de l'enfance sont révisées :
- Au moins annuellement
- Lors de tout changement dans la loi applicable
- Suite à tout incident de protection de l'enfance
- Lors de modifications significatives du Protocole

### 11.4 Modèle de délégation de tutelle

Le Protocole met en œuvre un modèle de structure familiale à trois couches :

**Couche 1 — Niveau de l'attestation (immuable) :**
Les balises de tuteur (`["guardian", "<parent_pubkey>"]`) sont définies par le vérificateur professionnel et reflètent la responsabilité parentale légale. Elles ne peuvent être modifiées que par une nouvelle attestation émise par un professionnel avec la documentation légale appropriée (p. ex. ordonnance du tribunal).

**Couche 2 — Niveau de délégation (flexible) :**
Les tuteurs peuvent déléguer des autorisations spécifiques à des adultes de confiance (beaux-parents, grands-parents, enseignants) via des événements de délégation de tuteur de type 31000. Les délégations sont :
- Limitées dans le temps (avec expiration)
- Limitées en portée : `full`, `activity-approval`, `content-management`, `contact-approval`
- Révocables par le tuteur à tout moment
- Signées par la clé Nostr du tuteur
- Marquées avec `["agent-type", "guardian"]` pour les distinguer des autres types d'événements de délégation

**Couche 3 — Niveau client (spécifique à l'application) :**
Les applications appliquent les autorisations basées sur les données des couches 1 et 2, notamment les limites de temps d'écran, le filtrage du contenu, les flux d'approbation d'activités et les restrictions de contacts.

---

## 12. Formation et sensibilisation

### 12.1 Formation des vérificateurs

Tous les vérificateurs professionnels autorisés à effectuer des vérifications de niveau 4 (enfants) doivent :
- Suivre une formation à la protection de l'enfance avant d'effectuer des vérifications d'enfants
- Comprendre les lois de protection de l'enfance dans leur juridiction
- Être conscients des indicateurs de protection et des obligations de signalement
- Comprendre le flux de cérémonie où l'utilisateur saisit et le vérificateur confirme, et ne pas tenter de saisir des données au nom des utilisateurs
- Actualiser leur formation annuellement

### 12.2 Formation du personnel

Tout le personnel impliqué dans le développement, les opérations ou le support du Protocole doit :
- Suivre une formation de sensibilisation à la protection de l'enfance
- Comprendre la présente Politique et ses obligations
- Savoir comment signaler les préoccupations en matière de protection de l'enfance

---

## 13. Responsabilité

### 13.1 Responsable désigné de la protection de l'enfance

Le Protocole Signet désigne un Responsable de la protection de l'enfance chargé de :
- Superviser la mise en œuvre de la présente Politique
- Coordonner avec le DPO sur les questions de protection des données des enfants
- Gérer la réponse aux incidents de protection de l'enfance
- S'engager avec les régulateurs et organisations de protection de l'enfance

### 13.2 Tenue des registres

Le Protocole Signet tient des registres de :
- Évaluations d'impact sur la protection de l'enfance
- Enregistrements du consentement parental
- Incidents de protection de l'enfance et réponses
- Registres de formation
- Révisions et mises à jour de la Politique

### 13.3 Supervision externe

Le Protocole Signet s'engage à la transparence et accueille favorablement la supervision de :
- Les autorités réglementaires compétentes
- Les organisations de protection de l'enfance
- Les auditeurs indépendants
- La communauté open source

---

## 14. Contact

Pour toute question, préoccupation ou signalement lié à la protection de l'enfance :

**Responsable de la protection de l'enfance :** signet-safety@signetprotocol.org *(espace réservé — à mettre à jour avant déploiement)*
**Délégué à la protection des données :** signet-dpo@signetprotocol.org *(espace réservé — à mettre à jour avant déploiement)*

**Signalement d'urgence (exploitation présumée d'enfants) :**
- Royaume-Uni : Internet Watch Foundation — [https://www.iwf.org.uk](https://www.iwf.org.uk)
- États-Unis : NCMEC CyberTipline — [https://www.missingkids.org](https://www.missingkids.org)
- UE : INHOPE — [https://www.inhope.org](https://www.inhope.org)
- Australie : eSafety Commissioner — [https://www.esafety.gov.au](https://www.esafety.gov.au)

---

*La présente Politique de protection de l'enfance est fournie comme modèle pour le Protocole Signet. Elle ne constitue pas un avis juridique. Le Protocole Signet recommande de consulter un conseiller juridique qualifié familier avec les lois applicables de protection de l'enfance dans votre juridiction avant tout déploiement.*

*Le Protocole Signet — v0.1.0*
*Version du document : 1.0*
*Mars 2026*
