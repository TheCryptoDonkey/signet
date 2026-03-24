---
**Avis de traduction générée par IA**

Ce document a été traduit de l'anglais à l'aide de l'IA (Claude, Anthropic). Il est fourni à titre de référence uniquement. La version anglaise disponible à `en.md` est le seul document juridiquement contraignant. Cette traduction n'a pas été révisée par un traducteur juridique qualifié. En cas de divergence entre cette traduction et l'original anglais, la version anglaise prévaut.

---

# Conditions d'utilisation

**Le Protocole Signet — v0.1.0**
**Date d'entrée en vigueur :** 17 mars 2026
**Dernière mise à jour :** 17 mars 2026

*Ce document couvre votre utilisation de My Signet (l'application de référence) et des bibliothèques du Protocole Signet, incluant le SDK signet-verify.js. Il ne constitue pas un avis juridique. Consultez un conseiller qualifié pour votre juridiction avant de vous y fier dans un déploiement en production.*

---

## Table des matières

1. [Acceptation des conditions](#1-acceptation-des-conditions)
2. [Éligibilité](#2-eligibilite)
3. [Description du Protocole et de l'Application](#3-description-du-protocole-et-de-lapplication)
4. [Gestion des clés et sécurité du compte](#4-gestion-des-cles-et-securite-du-compte)
5. [La cérémonie de vérification](#5-la-ceremonie-de-verification)
6. [Cycle de vie des attestations](#6-cycle-de-vie-des-attestations)
7. [Obligations des utilisateurs](#7-obligations-des-utilisateurs)
8. [Obligations des vérificateurs](#8-obligations-des-verificateurs)
9. [Opérateurs de sites web et le SDK signet-verify.js](#9-operateurs-de-sites-web-et-le-sdk-signet-verifyjs)
10. [Le bot de vérification](#10-le-bot-de-verification)
11. [Scores Signet IQ](#11-scores-signet-iq)
12. [Protection des données](#12-protection-des-donnees)
13. [Propriété intellectuelle](#13-propriete-intellectuelle)
14. [Exclusions de responsabilité](#14-exclusions-de-responsabilite)
15. [Limitation de responsabilité](#15-limitation-de-responsabilite)
16. [Indemnisation](#16-indemnisation)
17. [Droit applicable et règlement des litiges](#17-droit-applicable-et-reglement-des-litiges)
18. [Résiliation](#18-resiliation)
19. [Modifications](#19-modifications)
20. [Dispositions générales](#20-dispositions-generales)
21. [Contact](#21-contact)
22. [Annexes spécifiques aux juridictions](#22-annexes-specifiques-aux-juridictions)

---

## 1. Acceptation des conditions

En accédant, en téléchargeant ou en utilisant My Signet (l'« Application »), les bibliothèques du Protocole Signet ou le SDK signet-verify.js (ensemble, « le Protocole »), ou en agissant en tant que vérificateur, vous (« vous » ou « Utilisateur ») acceptez d'être lié par les présentes Conditions d'utilisation (les « Conditions »).

Si vous n'acceptez pas les présentes Conditions, vous ne devez pas utiliser le Protocole.

Si vous utilisez le Protocole au nom d'une organisation, vous déclarez avoir l'autorité pour lier cette organisation, et « vous » inclut cette organisation.

**Vérificateurs :** En publiant un événement d'attestation de vérificateur de type 31000 sur le réseau Nostr, ou en effectuant une cérémonie de vérification Signet, vous acceptez la Section 8 (Obligations des vérificateurs) comme condition juridiquement contraignante de votre participation. Vous n'avez pas besoin de signer un document séparé. L'acte d'effectuer une vérification constitue votre acceptation.

---

## 2. Éligibilité

### 2.1 Éligibilité générale

Pour utiliser le Protocole, vous devez :

- Avoir la capacité juridique de conclure un accord contraignant dans votre juridiction
- Ne pas être interdit d'utiliser le Protocole par une loi applicable
- Ne pas avoir été exclu du Protocole pour violation substantielle des présentes Conditions

### 2.2 Exigences d'âge

| Juridiction | Âge minimum — compte propre | Avec consentement parental vérifié |
|---|---|---|
| Union européenne (par défaut) | 16 | 13 (varie selon l'État membre) |
| Royaume-Uni | 13 | S/O |
| États-Unis | 13 | Moins de 13 ans avec consentement parental conforme à COPPA |
| Brésil | 18 | 12 avec consentement parental |
| Corée du Sud | 14 | Moins de 14 avec consentement parental |
| Japon | 15 | Moins de 15 avec consentement parental |
| Inde | 18 | Selon la Loi DPDP |
| Autre | Âge de consentement numérique | Selon la loi locale |

Les enfants en dessous de l'âge de consentement numérique de leur juridiction ne peuvent avoir un compte Signet qu'en tant que sous-compte d'un parent ou tuteur vérifié (voir Section 6.7).

### 2.3 Éligibilité des vérificateurs

Pour agir en tant que vérificateur professionnel et émettre des attestations de niveau 3 ou 4, vous devez :

- Détenir une inscription professionnelle actuelle, valide et en règle auprès de l'organisme de réglementation compétent
- Être autorisé à exercer dans la juridiction où vous effectuez des vérifications
- Ne pas faire l'objet d'une suspension, restriction ou procédure disciplinaire susceptible d'affecter votre capacité à vérifier l'identité
- Maintenir une assurance responsabilité professionnelle adéquate pour couvrir vos activités de vérification

La liste complète des professions éligibles figure à la Section 8.2.

---

## 3. Description du Protocole et de l'Application

### 3.1 Vue d'ensemble

Le Protocole Signet est un protocole de vérification d'identité décentralisé pour le réseau Nostr. Il permet aux utilisateurs de prouver des revendications concernant leur identité — notamment l'âge, la parentalité et le statut professionnel — en utilisant des preuves à divulgation nulle de connaissance et des signatures en anneau, sans révéler les données personnelles sous-jacentes. Il n'existe pas de base de données centrale, pas d'autorité centrale et pas d'organisation unique qui contrôle le réseau.

**My Signet** est l'application de référence. C'est une application web progressive (PWA) qui s'exécute dans votre navigateur. C'est une seule application utilisée par tous : les particuliers, les vérificateurs et les communautés.

### 3.2 Niveaux de vérification

| Niveau | Nom | Ce que cela signifie |
|---|---|---|
| 1 | Auto-déclaré | Vous avez créé un compte et déclaré certains attributs. Pas de vérification externe. Confiance la plus faible. |
| 2 | Réseau de confiance | D'autres utilisateurs qui vous connaissent ont répondu de vous. La confiance est dérivée du réseau. |
| 3 | Vérification professionnelle (Adulte) | Un professionnel agréé a vérifié en personne votre document d'identité officiel et a émis deux attestations via la cérémonie à deux attestations. |
| 4 | Vérification professionnelle (Adulte + Enfant) | Niveau 3 étendu pour inclure un compte enfant, avec la relation de l'enfant à un parent/tuteur vérifié confirmée par un professionnel. |

### 3.3 Types d'événements Nostr

Le Protocole utilise les types d'événements Nostr suivants :

| Type | Objectif |
|---|---|
| 31000 | Événements d'attestation |
| 31000 | Attestations de caution |
| 30078 | Politiques de vérification communautaire |
| 31000 | Attestations d'enregistrement de vérificateur |
| 31000 | Événements de défi |
| 31000 | Événements de révocation |
| 31000 | Événements de pont d'identité |
| 31000 | Événements de délégation (tuteur et agent) |
| 30482–30484 | Extension de vote (élection, scrutin, résultat) |

Les numéros de type d'événement sont en attente d'attribution NIP finale.

### 3.4 Pile cryptographique

Le Protocole utilise :

- Les signatures Schnorr sur la courbe secp256k1 (couche de base)
- Les Bulletproofs pour les preuves à divulgation nulle de connaissance de tranche d'âge
- Les signatures en anneau Spontaneous Anonymous Group (SAG) et Linkable SAG (LSAG) pour la confidentialité de l'émetteur
- PBKDF2 (600 000 itérations, SHA-256) avec AES-256-GCM pour le stockage local des attestations
- Une future couche ZK (ZK-SNARKs ou ZK-STARKs) est prévue pour la complétude cryptographique de niveau 3

### 3.5 Nature décentralisée

Le Protocole Signet fonctionne sur le réseau Nostr. Nous développons et maintenons la spécification du Protocole mais ne contrôlons pas le réseau, les opérateurs de relais ou les participants individuels. Les événements publiés sur Nostr sont publics, persistants et répliqués par des opérateurs de relais que nous ne contrôlons pas.

---

## 4. Gestion des clés et sécurité du compte

### 4.1 Modèle à deux paires de clés

My Signet dérive deux paires de clés indépendantes à partir d'une seule mnémonique BIP-39 de 12 mots :

- **Paire de clés Personne Physique :** Utilisée pour votre attestation d'identité réelle (nom, document, nullificateur, racine Merkle). Cette paire de clés n'est utilisée que lorsque vous choisissez explicitement de présenter votre identité réelle vérifiée.
- **Paire de clés Persona :** Un alias anonyme. Elle porte une preuve de tranche d'âge héritée de la cérémonie de vérification mais pas de nom, de référence de document ni de nullificateur. Toute votre activité Nostr quotidienne peut utiliser cette paire de clés.

Lors de l'intégration, vous choisissez quelle paire de clés est votre compte principal pour cet appareil. Vous pouvez changer à tout moment. Le lien entre vos deux paires de clés n'est connu que de vous et de votre vérificateur (protégé par leurs obligations de confidentialité professionnelle).

### 4.2 Mode à paire de clés unique (import nsec)

Si vous êtes un utilisateur Nostr existant, vous pouvez importer votre clé privée existante (nsec). En mode à paire de clés unique, votre npub existant devient votre identité Personne Physique, et vous pouvez créer un pont d'identité (événement de type 31000) pour le lier à un compte Persona. Tous vos abonnés existants, NIP-05, zaps et réputation sont préservés.

### 4.3 Génération et sauvegarde des clés

- Votre mnémonique est générée localement dans l'Application en utilisant un aléa cryptographiquement sûr. Elle n'est jamais transmise à un serveur.
- Vous êtes seul responsable de la sauvegarde de votre mnémonique. Nous ne pouvons pas la récupérer. Si vous perdez votre mnémonique et votre appareil, votre compte ne peut pas être récupéré sans une nouvelle vérification professionnelle.
- Les comptes enfants peuvent être dérivés à différents index de compte BIP-44 à partir de la même mnémonique parentale, gardant la gestion des clés familiales sous une seule phrase de récupération.
- La sauvegarde par partage secret de Shamir (via `@scure/bip39`) est prise en charge pour la division de la mnémonique entre des dépositaires de confiance.

### 4.4 Authentification biométrique et par code PIN

My Signet requiert une authentification pour accéder à votre clé privée :

- **Biométrique (préféré) :** Utilise WebAuthn avec l'extension PRF, lorsque disponible. Votre biométrie ne quitte jamais votre appareil. Là où PRF est pris en charge, le matériel de clé est dérivé par le matériel et ne peut pas être extrait de localStorage même par du code s'exécutant sur le même appareil.
- **Solution de repli PIN :** Lorsque l'authentification biométrique n'est pas disponible, un code PIN est requis. Le code PIN est utilisé avec PBKDF2 (600 000 itérations) pour dériver une clé de chiffrement AES-256-GCM.
- **Gestion des sessions :** Après une période d'inactivité, l'Application se verrouille. Vous devez vous réauthentifier pour continuer. Le délai d'inactivité peut être configuré dans les paramètres.

Votre clé privée n'est jamais stockée en clair. Elle est toujours chiffrée au repos avec AES-256-GCM.

### 4.5 Compromission de clé

Si vous pensez que votre clé privée a été compromise, vous devez vous rendre chez un vérificateur professionnel avec vos documents d'identité originaux. Le vérificateur révoquera toutes les attestations émises pour votre ancienne paire de clés et émettra de nouvelles attestations pour une nouvelle paire de clés. Les cautions associées à la clé compromise ne sont pas transférées (c'est une mesure de sécurité délibérée — un attaquant qui a compromis votre clé ne peut pas conserver votre confiance sociale).

### 4.6 Signature à distance NIP-46

My Signet prend en charge la signature à distance NIP-46. Cela permet à d'autres applications ou services de demander à l'Application de signer des événements Nostr en leur nom. Chaque demande de signature requiert votre approbation explicite. L'Application affichera les détails de la demande avant que vous ne l'approuviez ou la rejetiez. Vous ne devez pas approuver des demandes que vous ne reconnaissez pas ou ne comprenez pas.

---

## 5. La cérémonie de vérification

### 5.1 Fonctionnement de la vérification professionnelle

Les attestations de niveau 3 et 4 sont émises via la cérémonie à deux attestations :

1. **Vous saisissez vos données.** Avant de vous rendre chez un vérificateur, vous saisissez vos propres attributs d'identité (nom, date de naissance, nationalité, type et numéro de document) dans l'Application. L'Application précalcule votre arbre Merkle et votre nullificateur de document.

2. **Vous présentez vos documents.** Vous vous rendez en personne à un rendez-vous avec un vérificateur professionnel et présentez votre (vos) document(s) d'identité officiel(s) original(aux).

3. **Le vérificateur confirme ou rejette.** Le vérificateur inspecte vos documents, vérifie que vous êtes la personne qui y est décrite, et confirme ou rejette les données que vous avez saisies. Le vérificateur ne saisit pas vos données personnelles — il confirme seulement ce que vous avez saisi.

4. **Deux attestations sont émises.** Si le vérificateur confirme les données, il publie deux événements d'attestation de type 31000 — un pour votre paire de clés Personne Physique (avec votre racine Merkle et votre nullificateur) et un pour votre paire de clés Persona (avec uniquement votre preuve de tranche d'âge). Les deux attestations sont signées avec la clé Nostr professionnelle du vérificateur.

5. **Le numéro de document est supprimé.** Après le calcul du nullificateur, le numéro de document n'est pas conservé par le Protocole, l'Application, ni (sauf si requis par leurs obligations professionnelles) le vérificateur.

### 5.2 Qui est responsable de l'exactitude des données

Étant donné que vous saisissez vos propres données d'identité, vous portez la responsabilité principale de leur exactitude. La saisie de fausses données (mauvais nom, numéro de document d'une autre personne) est frauduleuse et peut constituer une infraction pénale dans votre juridiction.

Le rôle du vérificateur est de confirmer que la personne qui se présente devant lui correspond aux documents présentés. Le vérificateur ne garantit pas l'exhaustivité ou l'exactitude des données que vous avez saisies au-delà de ce qui peut être visuellement confirmé à partir des documents.

### 5.3 Nullificateurs de documents

Le Protocole utilise des nullificateurs basés sur les documents pour empêcher la même personne d'obtenir plusieurs attestations de niveau 3. Le nullificateur est calculé comme suit :

```
SHA-256(LP(docType) || LP(country) || LP(docNumber) || LP("signet-nullifier-v2"))
```

où `LP(x)` est la longueur en octets UTF-8 de `x` encodée comme un entier big-endian sur 2 octets, suivi des octets de `x`. Cet encodage préfixé par la longueur prévient les collisions aux frontières des champs.

Le nullificateur :
- Est déterministe : le même document produit toujours le même nullificateur
- Est à sens unique : le numéro de document ne peut pas être récupéré à partir du nullificateur
- Est résistant aux collisions : des documents différents produisent des nullificateurs différents
- Est cohérent entre les vérificateurs : tout vérificateur avec le même document produit le même nullificateur

Si vous présentez plusieurs documents d'identité (p. ex. passeport et permis de conduire), le vérificateur peut calculer des nullificateurs pour tous les documents, formant une famille de nullificateurs. Tous les nullificateurs de la famille sont publiés dans l'attestation et vérifiés par rapport aux attestations existantes sur les relais.

### 5.4 L'arbre Merkle

Vos attributs personnels (nom, date de naissance, nationalité, type de document, date d'expiration du document, nullificateur) sont stockés comme feuilles dans un arbre Merkle. Seule la racine Merkle est publiée en chaîne. Vous pouvez prouver des attributs individuels en fournissant un chemin Merkle, sans révéler tous les attributs. L'arbre Merkle utilise la séparation de domaine RFC 6962 (préfixe 0x00 pour les hashes de feuilles, 0x01 pour les nœuds internes).

### 5.5 Preuves de tranche d'âge

Votre date de naissance n'est jamais publiée. Au lieu de cela, le vérificateur calcule une preuve à divulgation nulle de connaissance Bulletproof que votre âge se situe dans une tranche spécifiée (p. ex. « 18+ », « 13–17 », « 8–12 »). La preuve est mathématiquement vérifiable sans révéler votre âge exact ni votre date de naissance.

### 5.6 Vérification croisée

Vous pouvez demander une vérification auprès d'un deuxième (ou d'autres) vérificateur(s) en présentant les mêmes documents. Le nullificateur étant dérivé de vos documents, le même nullificateur est produit. Le Protocole distingue la vérification croisée de la fraude par dédoublement en vérifiant si la clé publique du sujet correspond à l'attestation existante :

- Même nullificateur + même clé publique = confirmation indépendante (contribution plus élevée au Signet IQ)
- Même nullificateur + clé publique différente = possible identité dupliquée (signalé pour investigation)

La vérification croisée est le signal IQ le plus fort, représentant une confirmation professionnelle indépendante de la même identité.

---

## 6. Cycle de vie des attestations

### 6.1 Expiration et décroissance des attestations

Les attestations professionnelles incluent une balise `expires` (la période de validité de l'attestation) et une feuille Merkle `documentExpiry` (quand le document sous-jacent expire). Celles-ci sont différentes : une attestation peut expirer après deux ans tandis que le passeport sur lequel elle est basée n'expire pas avant dix ans.

Les attestations ne subissent pas d'arrêt brusque à l'expiration. Au lieu de cela, la contribution IQ d'une attestation expirant se dégrade progressivement à mesure que la date d'expiration approche, plutôt que de tomber à zéro à la date d'expiration. Les clients sont censés afficher cette dégradation visuellement (un indicateur qui s'estompe lentement) plutôt qu'un état binaire valide/invalide.

Si le document sous-jacent à une attestation expire avant l'attestation elle-même, la contribution IQ se dégrade plus rapidement — reflétant la confiance réduite dans le document d'identité sous-jacent.

### 6.2 Révocation des attestations

Les attestations peuvent être révoquées en publiant un événement de type 31000. La révocation peut être initiée par :

- Vous (auto-révocation — p. ex. en cas de compromission de clé ou de changement de nom)
- Le vérificateur émetteur (pour cause, comme une fraude découverte)
- Le consensus communautaire (pour une fraude systémique ou une compromission de sécurité)

### 6.3 Chaînes d'attestations et renouvellement de documents

Lorsque vos attributs réels changent (changement de nom, renouvellement de document, mise à niveau de niveau), une attestation de remplacement est émise avec une balise `["supersedes", "<old_event_id>"]`. Les clients suivent la chaîne pour n'afficher que l'attestation active actuelle. Les attestations remplacées restent sur les relais comme archives historiques.

**Renouvellement de documents et nullificateurs :**
- **Renouvellement de passeport :** Un nouveau numéro de passeport produit un nouveau nullificateur. Les anciens et nouveaux nullificateurs sont liés par une balise `["nullifier-chain", "<old_nullifier>"]` dans la nouvelle attestation.
- **Renouvellement de permis de conduire (Royaume-Uni) :** Le numéro de permis ne change généralement pas lors du renouvellement. La nouvelle attestation référence le même nullificateur.

### 6.4 Détail du modèle à deux attestations

| Attestation | Contient | Ne contient pas |
|---|---|---|
| Personne Physique | Racine Merkle, nullificateur principal, famille de nullificateurs, preuve de tranche d'âge, type d'entité, balises de tuteur (si enfant) | Nom réel, date de naissance, numéro de document |
| Persona | Preuve de tranche d'âge, type d'entité=persona, balises de tuteur (si enfant) | Nullificateur, racine Merkle, attributs personnels |

### 6.5 Délégation de tutelle

Un tuteur (parent vérifié ou tuteur légal) peut déléguer des autorisations spécifiques à des adultes de confiance via des événements de délégation de type 31000. Les portées de délégation incluent :

- `full` — délégation complète (p. ex. co-parent)
- `activity-approval` — approuver des activités nécessitant le consentement parental
- `content-management` — gérer le contenu et les connexions de l'enfant
- `contact-approval` — approuver de nouveaux contacts

Les événements de délégation incluent une balise `agent-type` identifiant la relation (p. ex. `teacher`, `grandparent`, `step-parent`). Les balises de tuteur dans les attestations sont immuables — elles ne peuvent être modifiées que par une nouvelle attestation émise par un professionnel avec la documentation légale appropriée.

### 6.6 Sous-comptes enfants

Une attestation enfant est un sous-compte d'un parent ou tuteur vérifié :

- L'attestation enfant doit inclure des balises de tuteur liant à un parent ou tuteur vérifié de niveau 3+
- L'enfant doit être présent lors de la cérémonie de vérification de niveau 4 (en personne ou via un processus légalement équivalent)
- Lorsque l'enfant atteint 18 ans, il reçoit une nouvelle attestation de niveau 3 sans balises de tuteur, remplaçant l'attestation enfant
- Un enfant ne peut pas détenir une attestation Persona portant une revendication de tranche d'âge supérieure à sa tranche d'âge vérifiée

### 6.7 Comptes Persona

Une Persona est un alias anonyme :

- Une Persona ne comporte aucune information personnellement identifiable — pas de nom, pas de nullificateur, pas de racine Merkle
- Une Persona hérite de la preuve de tranche d'âge de la cérémonie à deux attestations
- Une Persona peut être liée à une Personne Physique via un pont d'identité (type 31000) utilisant des signatures en anneau, permettant à la Persona de prouver « Je suis une vraie personne vérifiée » sans révéler laquelle
- Vous êtes responsable de toute activité menée via vos comptes Persona

### 6.8 Pas de garantie d'acceptation

Nous ne garantissons pas qu'une attestation sera acceptée par une partie utilisatrice quelconque. Les communautés définissent leurs propres politiques d'acceptation via des événements de politique de type 30078.

### 6.9 Portefeuille de documents

My Signet prend en charge un portefeuille de documents contenant plusieurs documents d'identité. Chaque document produit sa propre attestation et son propre nullificateur. Cela permet une vérification progressive : vous pouvez ajouter des documents au fil du temps, chaque document supplémentaire renforçant votre famille de nullificateurs et contribuant à votre Signet IQ.

---

## 7. Obligations des utilisateurs

### 7.1 Obligations générales

Tous les utilisateurs doivent :

1. **Exactitude.** Saisir des informations véridiques lors de la création d'attestations. Les attestations frauduleuses compromettent le modèle de confiance et peuvent constituer une fraude pénale.
2. **Sécurité des clés.** Protéger votre mnémonique et votre clé privée. Vous êtes seul responsable de leur sécurité.
3. **Conformité.** Se conformer à toutes les lois et réglementations applicables.
4. **Utilisation responsable.** Utiliser le Protocole de bonne foi et non à des fins illégales, frauduleuses ou préjudiciables.
5. **Signalement.** Signaler rapidement les vulnérabilités de sécurité, les fraudes d'attestation ou les abus du Protocole à l'adresse de contact de la Section 21.

### 7.2 Utilisations interdites

Vous ne devez pas :

1. Créer des attestations fausses, trompeuses ou frauduleuses
2. Usurper l'identité d'une autre personne ou entité
3. Tenter de rétro-ingénier des preuves à divulgation nulle de connaissance pour extraire des données personnelles
4. Utiliser le Protocole pour faciliter des activités illégales, notamment le vol d'identité, la fraude, le blanchiment d'argent, le financement du terrorisme ou l'exploitation des enfants
5. Attaquer l'infrastructure cryptographique du Protocole ou tenter de briser l'anonymat des ensembles de signatures en anneau
6. Spammer le réseau avec des événements d'attestation, de caution ou de défi illégitimes
7. Colluder avec des vérificateurs pour obtenir des attestations de niveau 3 ou 4 non méritées
8. Utiliser des systèmes automatisés pour générer en masse des attestations ou des cautions sans vérification authentique
9. Interférer avec ou perturber le Protocole ou le réseau Nostr
10. Exploiter le Protocole pour contourner les restrictions d'âge ou les mesures de protection de l'enfance

### 7.3 Obligations de caution (Niveau 2)

Lors de la caution d'un autre utilisateur (événement de type 31000) :

- Vous devez avoir une base authentique et personnelle pour la caution
- Vous ne devez pas accepter de paiement ou autre contrepartie pour fournir des cautions
- Vous pouvez révoquer une caution à tout moment en publiant un événement de révocation
- Votre comportement de caution affecte votre propre Signet IQ

---

## 8. Obligations des vérificateurs

### 8.1 Pourquoi il n'y a pas d'accord séparé

Nous avons intégré l'accord du vérificateur dans les présentes Conditions car les personnes les plus susceptibles de vérifier les enfants — les enseignants lors des réunions parents-professeurs, les médecins généralistes, les travailleurs sociaux — ne devraient pas avoir à naviguer dans un second document juridique. En agissant en tant que vérificateur Signet (en publiant un événement de type 31000 ou en effectuant une cérémonie), vous acceptez les obligations de la présente section. Ces obligations s'ajoutent à vos devoirs professionnels existants et ne les remplacent pas.

### 8.2 Professions éligibles

Vous pouvez agir en tant que vérificateur Signet si vous détenez une inscription actuelle et valide auprès d'un organisme de réglementation reconnu dans l'une des catégories suivantes. Cette liste suit la norme de contresignature de passeport britannique et ses équivalents internationaux.

**Professions juridiques :** Solicitor, barrister, avocat, attorney-at-law, legal executive, notaire public, commissaire de justice, Notar, licensed conveyancer, chartered legal executive.

**Professions médicales et de santé :** Médecin, chirurgien, médecin généraliste, dentiste, pharmacien, opticien/optométriste, infirmier(ère) diplômé(e) (là où nationalement autorisé), kinésithérapeute, psychologue clinicien, professionnel de santé communautaire ou hospitalier enregistré auprès d'un organisme national (GMC, NMC, GDC, GPhC, HCPC ou équivalent).

**Professions de l'éducation :** Enseignant qualifié (enregistré auprès de la Teaching Regulation Agency ou de l'équivalent national), directeur ou directeur adjoint d'école, enseignant de l'enseignement supérieur ou universitaire enregistré auprès d'un organisme professionnel, inspecteur scolaire.

**Professions financières :** Expert-comptable agréé (ICAEW, ICAS, ACCA, CIMA, CPA ou équivalent), expert-comptable certifié agréé, commissaire aux comptes agréé, conseiller financier indépendant autorisé par un régulateur financier national, fonctionnaire de banque ou de société de crédit immobilier de grade officier.

**Professions de service public et d'urgence :** Officier de police, officier des pompiers, membre des forces armées de Sa Majesté (officier), juge, magistrat, juge de paix, fonctionnaire du Crown Prosecution Service, agent de probation, travailleur social enregistré auprès d'un organisme de réglementation national.

**Professions religieuses et communautaires :** Ministre du culte, chef religieux reconnu comme tel par une confession enregistrée, officier d'état civil.

**Professions d'ingénierie, de sciences et de technique :** Ingénieur agréé (inscrit auprès d'une institution nationale d'ingénierie), scientifique agréé, architecte (inscrit auprès de l'Architects Registration Board ou équivalent), géomètre agréé.

**Autres professions réglementées :** Toute profession réglementée par un organisme légal dont le registre est consultable publiquement et dont les membres sont soumis à des procédures d'aptitude à l'exercice. En cas de doute, contactez-nous avant d'effectuer des vérifications.

Dans tous les cas, vous devez être en règle (ne pas faire l'objet d'une suspension, restriction ou procédure disciplinaire en cours affectant votre aptitude à vérifier l'identité).

### 8.3 Inscription

Pour vous inscrire en tant que vérificateur :

1. Publiez un événement d'attestation de vérificateur de type 31000 sur Nostr contenant votre catégorie professionnelle, votre juridiction, votre organisme de licence et votre référence de licence.
2. Obtenez au moins deux cautions d'autres professionnels Signet vérifiés d'au moins deux professions différentes (les cautions interprofessionnelles préviennent les anneaux de collusion d'une seule profession).
3. L'inscription n'implique pas notre approbation.

### 8.4 Effectuer des vérifications de niveau 3 (Adulte)

Lors de l'exécution d'une vérification de niveau 3 (Adulte), vous devez :

1. Vérifier l'identité en personne, ou via un processus à distance légalement équivalent expressément autorisé par la loi dans la juridiction concernée. La vérification à distance est l'exception, pas la règle.
2. Inspecter au moins un document d'identification photo original délivré par le gouvernement (passeport, carte d'identité nationale ou permis de conduire). L'inspection numérique de documents (notamment les attestations de portefeuille eIDAS, lorsque disponibles) est autorisée là où la loi nationale la traite comme équivalente à l'inspection physique.
3. Confirmer que la personne devant vous correspond au document.
4. Confirmer (ou rejeter) les données que le sujet a pré-saisies dans l'Application. Vous confirmez ce que vous voyez ; vous ne saisissez pas de données au nom du sujet.
5. Calculer le nullificateur de document et, lorsque plusieurs documents sont présentés, la famille de nullificateurs.
6. Émettre l'attestation de Personne Physique (type 31000) et l'attestation de Persona (type 31000) via la cérémonie à deux attestations.
7. Supprimer le numéro de document après le calcul du nullificateur. Ne le stockez pas sauf si vos obligations professionnelles l'exigent indépendamment.
8. Conserver les enregistrements de la vérification (date, lieu, identité du sujet, documents inspectés, hash nullificateur, les deux clés publiques) pour la période requise par vos obligations professionnelles — généralement au moins six ans.

**Méthodes de confirmation et pondération IQ :**

| Méthode | Description | Pondération de contribution IQ |
|---|---|---|
| A — En personne, document physique | Vous inspectez physiquement un document original et la personne ensemble, face à face | Pondération complète |
| B — En personne, document numérique | Réunion en personne ; le sujet présente un portefeuille eIDAS ou une identité numérique équivalente vérifiée par le gouvernement | Pondération complète (là où la loi le traite comme équivalent) |
| C — À distance, réglementé | Appel vidéo avec approbation réglementaire et contrôle de vivacité ; documents originaux envoyés par courrier ou présentés en haute résolution | Pondération réduite |
| D — À distance, non réglementé | Tout processus à distance non couvert par C | Non autorisé pour les niveaux 3 ou 4 |

La méthode de vérification est enregistrée dans l'attestation (`["method", "in-person-id"]` ou balise équivalente). Les clients et les parties utilisatrices peuvent restreindre l'acceptation à certaines méthodes.

### 8.5 Effectuer des vérifications de niveau 4 (Adulte + Enfant)

Lors de l'exécution d'une vérification de niveau 4 (Adulte + Enfant), vous devez respecter toutes les obligations du niveau 3 et en outre :

1. **Vérifier l'identité de l'enfant** en utilisant des documents appropriés (acte de naissance, passeport ou autres documents adéquats selon votre jugement professionnel).
2. **Vérifier la relation parent-tuteur** par la documentation : acte de naissance (parent biologique), ordonnance de tutelle judiciaire (tuteur légal), actes d'adoption (parent adoptif) ou ordonnance de responsabilité de beau-parent.
3. **Enseignants et vérificateurs scolaires :** Vous pouvez utiliser vos connaissances professionnelles et les dossiers d'inscription scolaire (qui incorporent déjà la vérification de l'acte de naissance) comme preuve en lieu et place ou en plus des documents originaux. La date de naissance de l'enfant figure déjà dans les dossiers de l'école. Un parent présentant son passeport lors d'une réunion parents-professeurs est suffisant pour une vérification de niveau 4 dans la même session.
4. **Obtenir le consentement parental** pour l'attestation de l'enfant, documenté conformément au droit applicable de protection de l'enfance.
5. **Conduire la vérification avec l'enfant présent** dans la mesure du possible.
6. **Évaluer le bien-être de l'enfant.** Exercez votre jugement professionnel pour identifier tout indicateur de coercition, d'exploitation ou de préoccupation de protection. Si de telles préoccupations surgissent, ne poursuivez pas et respectez vos obligations de signalement obligatoire en vertu de la loi applicable.
7. Émettre deux attestations pour l'enfant (Personne Physique + Persona), toutes deux portant la preuve de tranche d'âge de l'enfant et des balises de tuteur liant l'enfant à son parent ou tuteur vérifié.

### 8.6 Actions interdites aux vérificateurs

Vous ne devez pas :

1. Émettre des attestations pour quiconque dont vous n'avez pas véritablement confirmé l'identité
2. Accepter un paiement, des cadeaux ou toute autre contrepartie en échange d'émission de vérifications non méritées
3. Autoriser une autre personne à effectuer des vérifications en utilisant vos attestations ou votre clé Nostr
4. Effectuer des vérifications pour des membres de la famille ou des proches personnels sans divulgation et approbation préalables
5. S'auto-vérifier — émettre des attestations de niveau 3 ou 4 pour vous-même
6. Conserver des copies de documents d'identité au-delà de ce que vos obligations professionnelles exigent
7. Utiliser des données obtenues lors des vérifications à d'autres fins que la vérification elle-même et la tenue des dossiers requis
8. Divulguer les détails des vérifications à des tiers, sauf obligation légale

### 8.7 Obligations de signalement des vérificateurs

Vous devez nous signaler rapidement :

- Toute compromission ou compromission suspectée de votre clé privée Nostr
- Toute découverte que vous avez précédemment émis une vérification frauduleuse ou erronée
- Tout changement dans votre statut d'inscription professionnelle (suspension, restriction, révocation, procédure disciplinaire)
- Toute violation de données affectant vos dossiers de vérification
- Toute procédure judiciaire, enquête ou action réglementaire relative à vos activités de vérification
- Tout conflit d'intérêts survenant en lien avec une vérification

### 8.8 Responsabilité du vérificateur

Vous êtes indépendamment responsable de l'exactitude et de l'intégrité de vos vérifications. Étant donné que vous confirmez les données saisies par le sujet, votre responsabilité est spécifiquement engagée pour :

- La confirmation de données que vous n'avez en fait pas vérifiées, ou que vous saviez ou aviez des raisons de savoir incorrectes
- Le défaut d'identifier un faux document qu'un professionnel raisonnablement compétent dans votre domaine aurait identifié
- Le défaut d'identifier des préoccupations de protection dans les vérifications de niveau 4
- La violation de vos obligations professionnelles et de la loi applicable

Nous ne supervisons, n'approuvons ni ne garantissons la qualité du travail de tout vérificateur individuel. Nous ne sommes pas solidairement ni vicairement responsables de vos actes ou omissions. Vous êtes un professionnel indépendant, non notre employé, agent ou partenaire.

### 8.9 Assurance

Vous devez maintenir une assurance responsabilité professionnelle adéquate pour vos activités de vérification. Le niveau approprié dépend des exigences existantes de votre profession. Si votre profession impose déjà une assurance responsabilité professionnelle (comme la plupart des professions de la Section 8.2), cette couverture devrait s'étendre à vos activités de vérification Signet dans la mesure où elles s'inscrivent dans le cadre de votre pratique professionnelle générale.

### 8.10 Résiliation du vérificateur

Votre statut de vérificateur peut être résilié :

**Immédiatement et sans préavis si :** votre licence professionnelle est suspendue ou révoquée ; vous avez émis des vérifications frauduleuses ; votre clé privée Nostr est compromise ; vous avez manqué à vos obligations de protection de l'enfance ; ou vous avez commis une infraction pénale liée à vos activités de vérification.

**Avec un préavis de 30 jours si :** vous violez substantiellement les présentes Conditions et ne remédiez pas dans les 14 jours ; vous ne remplissez plus les conditions d'éligibilité ; ou le Protocole est abandonné.

À la résiliation, votre attestation de vérificateur de type 31000 est révoquée. Les attestations précédemment émises restent valides sauf révocation individuelle. Vous devez conserver les dossiers de vérification pendant la période de conservation requise.

---

## 9. Opérateurs de sites web et le SDK signet-verify.js

### 9.1 À qui s'applique cette section

Cette section s'applique à toute personne ou organisation qui intègre le SDK signet-verify.js ou qui appelle autrement les API du Protocole Signet depuis un site web ou une application pour vérifier l'identité ou l'âge de ses utilisateurs (les « Opérateurs de sites web »).

### 9.2 Ce que fournit le SDK

Lorsqu'un utilisateur présente une attestation Signet à votre site web via le SDK, vous recevez :

- Une preuve de tranche d'âge (p. ex. « 18+ », « 13–17 ») — mathématiquement vérifiée
- Le score Signet IQ de l'utilisateur
- Le niveau de l'attestation
- Un horodatage de vérification

Vous ne recevez pas :

- Le vrai nom de l'utilisateur
- La date de naissance ou l'âge de l'utilisateur
- Le type ou numéro de document de l'utilisateur
- L'adresse de l'utilisateur ou toute autre information personnellement identifiable
- L'identité du vérificateur

Le SDK est conçu pour que vous receviez le minimum d'informations nécessaires pour prendre une décision de filtrage par âge ou identité.

### 9.3 Obligations des opérateurs de sites web

En intégrant le SDK, vous acceptez de :

1. **Pas de stockage au-delà de la session.** Vous ne devez pas stocker les données de preuve, les assertions de tranche d'âge ou les scores Signet IQ au-delà de la durée de la session de l'utilisateur, sauf si vous avez une base juridique spécifique pour ce faire en vertu du droit applicable à la protection des données et que vous l'avez divulgué à vos utilisateurs.
2. **Pas de réidentification.** Vous ne devez pas tenter de réidentifier les utilisateurs à partir des données de preuve, ni combiner des données de preuve avec d'autres données pour identifier des utilisateurs.
3. **Pas de profilage.** Vous ne devez pas utiliser les données de preuve pour créer des profils de l'historique de vérification ou des états d'attestation des utilisateurs.
4. **Recours précis uniquement.** Vous ne devez vous appuyer sur la preuve que pour l'objectif qu'elle fournit — confirmer qu'un utilisateur satisfait à un seuil d'âge ou d'identité. Vous ne devez pas représenter à des tiers que vous avez vérifié la véritable identité de l'utilisateur.
5. **Avis de confidentialité.** Vous devez divulguer dans votre avis de confidentialité que vous utilisez la vérification d'attestation Signet et décrire quelles données vous recevez et comment vous les utilisez.
6. **Pas de manipulation.** Vous ne devez pas utiliser le SDK de manière à contourner ses protections de la vie privée ou à manipuler les utilisateurs pour qu'ils présentent des attestations qu'ils ne présenteraient pas autrement.
7. **Conformité.** Vous devez respecter toutes les lois applicables, notamment les lois sur la protection des données (RGPD, UK RGPD, CCPA/CPRA et équivalents), dans votre utilisation du SDK.

### 9.4 Licence du SDK

Le SDK signet-verify.js est mis à disposition sous la même licence open source que la spécification du Protocole (voir le dépôt du Protocole). Vous devez respecter les termes de la licence.

### 9.5 Pas d'approbation

L'intégration du SDK n'implique pas notre approbation de votre site web ou service. Vous ne devez pas déclarer que Signet approuve ou certifie votre service.

---

## 10. Le bot de vérification

### 10.1 Ce qu'il est

Le bot de vérification Signet (« le Bot ») est un service automatisé qui surveille le réseau Nostr pour les événements d'attestation de type 31000 et fournit des résumés de vérification d'attestation sur demande. Le Bot peut publier des réponses aux requêtes, des résumés périodiques ou répondre à des mentions.

### 10.2 Ce qu'il traite

Le Bot traite uniquement les événements Nostr publics. Il lit les événements de types 31000, 31000, 30078, 31000, 31000, 31000 et 31000 depuis les relais publics. Il n'accède pas à votre clé privée, votre mnémonique ou les données stockées localement dans l'Application.

Le Bot calcule les scores Signet IQ à partir des données publiques en chaîne. Il ne collecte ni ne stocke de données personnelles au-delà de ce qui est publié dans les événements Nostr publics.

### 10.3 Qui le gère

Le Bot est géré par l'équipe du Protocole. Sa clé publique Nostr est publiée dans le dépôt du Protocole. Les tiers peuvent gérer des bots de vérification compatibles en utilisant la spécification du Protocole open source ; les bots tiers ne sont pas gérés par nous et ne sont pas de notre responsabilité.

### 10.4 Limitations du Bot

Le Bot fournit un service au mieux de ses capacités. Il peut être en retard par rapport à l'état en temps réel des relais. Il ne garantit pas que ses résultats reflètent chaque événement d'attestation ou de révocation actuel sur chaque relais. Les parties utilisatrices prenant des décisions de contrôle d'accès doivent interroger directement les relais et ne pas se fier uniquement aux résultats du Bot.

---

## 11. Scores Signet IQ

### 11.1 Ce qu'est le Signet IQ

Le score Signet IQ (0–200) est un score de réputation continu dérivé des données en chaîne. Un score de 100 représente une ligne de base équivalente à la norme d'identité gouvernementale britannique/américaine actuelle. Les scores supérieurs à 100 reflètent plusieurs vérifications, une forte confiance entre pairs, des ponts d'identité et la longévité du compte.

### 11.2 Comment il est calculé

Le score est calculé à partir de contributions pondérées incluant :

- Vérification professionnelle de niveau 3 ou 4 (pondération la plus élevée)
- Vérification croisée par des professionnels indépendants supplémentaires
- Cautions de pairs en personne d'utilisateurs à IQ élevé
- Ponts d'identité (type 31000)
- Ancienneté et activité du compte
- Score de confiance du vérificateur (voir Section 11.3)

La pondération des cautions évolue avec le propre Signet IQ du garant. Une caution de quelqu'un à IQ 150 pèse plus qu'une caution de quelqu'un à IQ 40.

### 11.3 Scores de confiance des vérificateurs

Chaque vérificateur professionnel a un score de confiance qui influence la contribution IQ des attestations qu'il a émises. Le score de confiance est dérivé de :

- La méthode de confirmation (la Méthode A porte la pondération complète ; la Méthode C porte une pondération réduite — voir Section 8.4)
- Le nombre de vérifications croisées indépendantes de leurs sujets par d'autres vérificateurs
- L'Indice de perception de la corruption (IPC) de la juridiction — les attestations de juridictions avec des scores IPC plus faibles portent moins de poids, non par discrimination, mais parce que la confiance statistique objective dans le processus de vérification est plus faible
- La détection d'anomalies (p. ex. 30 vérifications en une heure, regroupement temporel rapide, motifs de nullificateurs suspects)

### 11.4 Décroissance

La contribution IQ d'une attestation décroît lorsque :

- La date d'expiration de l'attestation approche
- La date d'expiration du document sous-jacent approche (décroissance plus rapide)
- Le score de confiance du vérificateur baisse (p. ex. en raison d'une fraude découverte)

La décroissance est progressive. Il n'y a pas d'arrêt brusque.

### 11.5 Avertissement

Le score Signet IQ est une métrique calculée basée sur des données en chaîne accessibles au public. Il ne constitue pas une évaluation définitive de la fiabilité, de l'identité ou du caractère. Nous ne garantissons pas qu'un score Signet IQ reflète fidèlement la fiabilité d'un utilisateur quelconque.

---

## 12. Protection des données

### 12.1 Données personnelles que le Protocole ne collecte pas

Le Protocole Signet est conçu pour ne pas collecter ni publier vos données personnelles. Votre nom, votre date de naissance, votre nationalité et votre numéro de document sont :

- Jamais publiés sur le réseau Nostr
- Jamais transmis à nos serveurs
- Stockés localement sur votre appareil sous forme chiffrée (AES-256-GCM, clé dérivée via PBKDF2 600 000 itérations)
- Accessibles uniquement après une authentification biométrique ou par code PIN réussie

### 12.2 Ce qui est publié en chaîne

Les données suivantes sont publiées sur le réseau Nostr (publiques par conception) :

- Votre clé publique Nostr (npub)
- Votre niveau et type d'attestation
- Votre racine Merkle (un hash cryptographique — ne révèle pas les attributs personnels)
- Votre nullificateur de document (un hash à sens unique — ne révèle pas les détails du document)
- Votre preuve de tranche d'âge (p. ex. « 18+ » — ne révèle pas votre âge)
- Métadonnées de l'attestation du vérificateur (profession, juridiction, référence de l'organisme de licence)
- Attestations de caution
- Événements de délégation

Une fois publiés sur Nostr, ces événements sont publics et peuvent être répliqués par les opérateurs de relais. Nous ne pouvons pas supprimer ni modifier les événements publiés.

### 12.3 Stockage local des données

Les données stockées localement dans l'Application (mnémonique, clés privées, détails du document utilisés pour calculer l'arbre Merkle) sont stockées dans IndexedDB sous forme chiffrée. Elles ne sont jamais stockées en clair. La clé de chiffrement est protégée par votre biométrie ou votre code PIN.

### 12.4 Les vérificateurs comme responsables du traitement indépendants

Lorsqu'un vérificateur professionnel inspecte vos documents d'identité et conserve des dossiers de vérification, il le fait en tant que responsable du traitement indépendant. Son traitement est régi par ses obligations professionnelles et la loi applicable sur la protection des données (UK RGPD, RGPD, CCPA/CPRA ou équivalent), non par nous.

### 12.5 Protection des données spécifique aux juridictions

| Juridiction | Loi applicable |
|---|---|
| Royaume-Uni | UK RGPD, Data Protection Act 2018 |
| Union européenne | RGPD (Règlement 2016/679) |
| États-Unis | CCPA/CPRA (Californie), lois étatiques sur la vie privée |
| Brésil | LGPD |
| Inde | Loi DPDP 2023 |
| Australie | Privacy Act 1988 |
| Japon | APPI |
| Corée du Sud | PIPA |
| EAU | Décret-loi fédéral n° 45 de 2021 |
| Autre | Loi nationale ou régionale applicable sur la protection des données |

### 12.6 Droits des personnes concernées UE/Royaume-Uni

Si vous êtes dans l'UE ou au Royaume-Uni, vous avez le droit d'accéder, de rectifier, d'effacer, de limiter le traitement et la portabilité de vos données personnelles. Le Protocole étant conçu pour minimiser la collecte de données, les données que nous détenons vous concernant sont limitées. Contactez-nous à l'adresse de la Section 21 pour exercer vos droits.

### 12.7 Règlement en ligne des litiges de l'UE

Si vous êtes un consommateur dans l'UE, vous pouvez déposer une plainte via la plateforme de règlement en ligne des litiges de l'UE : [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

---

## 13. Propriété intellectuelle

### 13.1 Spécification du Protocole

La spécification du Protocole Signet est publiée sous une licence open source telle que spécifiée dans le dépôt du Protocole. Une licence vous est accordée pour utiliser, mettre en œuvre et construire sur le Protocole conformément à cette licence.

### 13.2 Marques

« The Signet Protocol », « Signet » et « My Signet » ainsi que les logos associés sont des marques. Vous ne pouvez pas utiliser ces marques d'une manière impliquant une approbation ou une affiliation sans notre consentement écrit préalable, sauf pour une référence descriptive précise au Protocole ou à l'Application.

### 13.3 Contenu des utilisateurs

Vous conservez la propriété de tout contenu que vous créez en utilisant le Protocole (attestations, cautions, événements de délégation). En publiant des événements sur le réseau Nostr, vous reconnaissez que ces événements sont publics et peuvent être stockés et répliqués par les opérateurs de relais.

### 13.4 SDK

Le SDK signet-verify.js est mis à disposition sous la licence open source spécifiée dans le dépôt du Protocole. L'utilisation commerciale est autorisée conformément à cette licence.

### 13.5 Contributions

Les contributions à la spécification du Protocole ou au code d'implémentation sont soumises à l'accord de licence contributeur dans le dépôt du Protocole.

---

## 14. Exclusions de responsabilité

### 14.1 Protocole fourni « tel quel »

LE PROTOCOLE, L'APPLICATION ET LE SDK SONT FOURNIS « TELS QUELS » ET « TELS QUE DISPONIBLES » SANS AUCUNE GARANTIE, EXPRESSE OU IMPLICITE, NOTAMMENT LES GARANTIES IMPLICITES DE QUALITÉ MARCHANDE, D'ADÉQUATION À UN USAGE PARTICULIER, DE TITRE ET DE NON-CONTREFAÇON.

### 14.2 Pas de garantie d'exactitude

NOUS NE GARANTISSONS PAS QUE :

- UNE ATTESTATION EST EXACTE, COMPLÈTE OU FIABLE
- UN VÉRIFICATEUR EST COMPÉTENT, HONNÊTE OU DÛMENT AGRÉÉ
- LE PROTOCOLE FONCTIONNERA SANS INTERRUPTION NI ERREUR
- LES COMPOSANTS CRYPTOGRAPHIQUES RESTERONT SÉCURISÉS INDÉFINIMENT
- UN SCORE SIGNET IQ REFLÈTE FIDÈLEMENT LA FIABILITÉ D'UN UTILISATEUR QUELCONQUE
- LE SDK SATISFERA AUX EXIGENCES DE CONFORMITÉ LÉGALE D'UNE PARTIE UTILISATRICE PARTICULIÈRE

### 14.3 Avertissement sur la décentralisation

Le Protocole fonctionnant sur un réseau décentralisé, nous :

- Ne pouvons pas contrôler, surveiller ou censurer l'activité du Protocole
- Ne pouvons pas annuler ni modifier les événements publiés
- Ne pouvons pas garantir la disponibilité ou les performances d'un relais quelconque
- Ne pouvons pas faire appliquer les présentes Conditions contre tous les participants dans le monde
- Ne pouvons pas être responsables du comportement des opérateurs de relais indépendants

### 14.4 Avertissement cryptographique

Aucun système cryptographique n'est prouvablement sécurisé contre toutes les attaques futures. Les avancées en informatique (notamment l'informatique quantique) peuvent affecter la sécurité des composants cryptographiques du Protocole. Nous avons l'intention de prendre en charge la migration post-quantique, mais ne pouvons pas garantir de calendriers spécifiques.

### 14.5 Avertissement réglementaire

Le cadre réglementaire pour l'identité décentralisée et les preuves à divulgation nulle de connaissance évolue. Les obligations de conformité peuvent changer. Des fonctionnalités du Protocole peuvent être soumises à de nouvelles réglementations.

---

## 15. Limitation de responsabilité

### 15.1 Limitation générale

DANS TOUTE LA MESURE PERMISE PAR LA LOI APPLICABLE, NOUS, NOS ADMINISTRATEURS, DIRIGEANTS, EMPLOYÉS, AGENTS ET AFFILIÉS NE SERONS PAS RESPONSABLES DES DOMMAGES INDIRECTS, ACCESSOIRES, SPÉCIAUX, CONSÉCUTIFS, PUNITIFS OU EXEMPLAIRES, NOTAMMENT LA PERTE DE BÉNÉFICES, DE FONDS COMMERCIAUX, DE DONNÉES OU D'AUTRES PERTES IMMATÉRIELLES, QUE NOUS AYONS ÉTÉ OU NON INFORMÉS DE LA POSSIBILITÉ DE TELS DOMMAGES.

### 15.2 Plafond de responsabilité

DANS TOUTE LA MESURE PERMISE PAR LA LOI APPLICABLE, NOTRE RESPONSABILITÉ TOTALE CUMULÉE POUR TOUTES LES RÉCLAMATIONS DÉCOULANT DES PRÉSENTES CONDITIONS OU DU PROTOCOLE OU Y RELATIVES NE DÉPASSERA PAS LE PLUS ÉLEVÉ DES MONTANTS SUIVANTS : (A) LE MONTANT QUE VOUS NOUS AVEZ PAYÉ DANS LES 12 MOIS PRÉCÉDANT LA RÉCLAMATION, OU (B) 100 £.

### 15.3 Exceptions

Les limitations ci-dessus ne s'appliquent pas à :

- La responsabilité qui ne peut pas être exclue ou limitée en vertu de la loi applicable
- La responsabilité découlant d'une faute intentionnelle ou d'une fraude
- La responsabilité pour décès ou dommages corporels causés par négligence (dans les juridictions où la limitation est interdite)
- Les droits statutaires des consommateurs qui ne peuvent pas être renoncés par contrat

### 15.4 Protection des consommateurs

Rien dans les présentes Conditions n'affecte vos droits légaux en tant que consommateur en vertu des lois applicables sur la protection des consommateurs.

---

## 16. Indemnisation

### 16.1 Vos obligations d'indemnisation

Vous acceptez d'indemniser, de défendre et de dégager de toute responsabilité contre toutes réclamations, dommages, pertes, responsabilités, coûts et dépenses (notamment les honoraires d'avocat raisonnables) découlant de ou liés à :

1. Votre utilisation du Protocole
2. Votre violation des présentes Conditions
3. Votre violation de toute loi applicable
4. Votre violation des droits de tiers
5. Les attestations que vous créez, notamment les attestations fausses ou trompeuses
6. Les cautions que vous émettez
7. Les vérifications que vous effectuez (si vous êtes un vérificateur)
8. Votre utilisation du SDK et toutes les réclamations de vos utilisateurs à ce sujet

### 16.2 Procédure d'indemnisation

Nous vous notifierons rapidement de toute réclamation, fournirons une coopération raisonnable et vous permettrons de contrôler la défense et le règlement de la réclamation, à condition que vous ne procédiez à aucun règlement qui nous impose des obligations sans notre consentement écrit préalable.

---

## 17. Droit applicable et règlement des litiges

### 17.1 Droit applicable

Les présentes Conditions sont régies par et interprétées conformément au droit de l'Angleterre et du Pays de Galles, sans égard aux dispositions sur les conflits de lois.

### 17.2 Règlement des litiges

**Étape 1 — Négociation :** Les parties s'efforcent d'abord de résoudre tout litige par une négociation de bonne foi pendant 30 jours.

**Étape 2 — Médiation :** En cas d'échec de la négociation, les parties se soumettent à une médiation administrée par le Centre for Effective Dispute Resolution (CEDR) conformément à ses règles.

**Étape 3 — Arbitrage :** En cas d'échec de la médiation, le litige est définitivement résolu par arbitrage contraignant administré par la London Court of International Arbitration (LCIA) conformément à ses règles. Le siège de l'arbitrage est Londres. La langue est l'anglais. La sentence est définitive et contraignante.

### 17.3 Renonciation aux actions collectives

DANS TOUTE LA MESURE PERMISE PAR LA LOI APPLICABLE, VOUS ACCEPTEZ DE RÉSOUDRE LES LITIGES UNIQUEMENT SUR UNE BASE INDIVIDUELLE ET NON DANS LE CADRE D'UNE ACTION COLLECTIVE, CONSOLIDÉE OU REPRÉSENTATIVE. SI CETTE RENONCIATION EST INAPPLICABLE, LA DISPOSITION D'ARBITRAGE EST NULLE ET NON AVENUE.

### 17.4 Exceptions

L'une ou l'autre partie peut solliciter une mesure d'injonction devant tout tribunal compétent pour protéger la propriété intellectuelle ou prévenir un préjudice irréparable.

### 17.5 Droits des consommateurs de l'UE

Si vous êtes un consommateur dans l'UE, vous pouvez également utiliser vos juridictions nationales et la plateforme ODR de l'UE : [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

### 17.6 Questions réglementaires professionnelles du vérificateur

Rien dans les présentes Conditions ne restreint la compétence d'un organisme de réglementation professionnel sur un vérificateur, le droit d'un vérificateur à solliciter des conseils auprès de son organisme de réglementation, ou notre droit de signaler des préoccupations à l'organisme de réglementation d'un vérificateur.

---

## 18. Résiliation

### 18.1 Votre droit de résilier

Vous pouvez cesser d'utiliser le Protocole à tout moment. En raison de la nature décentralisée du Protocole, les événements précédemment publiés peuvent rester sur les relais Nostr indéfiniment.

### 18.2 Nos droits

Nous nous réservons le droit de :

- Révoquer les attestations de vérificateur pour cause (tel que décrit à la Section 8.10)
- Publier des avis communautaires sur des attestations ou acteurs frauduleux
- Modifier ou abandonner la spécification du Protocole

### 18.3 Effet de la résiliation

À la résiliation :

- Votre droit d'utiliser les composants propriétaires de l'Application cesse
- Les Sections 8 (obligations du vérificateur — la tenue des dossiers survit), 12, 13, 14, 15, 16, 17 et 20 survivent
- Les événements Nostr précédemment publiés ne sont pas affectés

---

## 19. Modifications

### 19.1 Droit de modification

Nous pouvons modifier les présentes Conditions à tout moment. Les modifications prennent effet lors de :

- La publication des Conditions mises à jour dans le dépôt du Protocole
- Une annonce d'événement Nostr faisant référence aux Conditions mises à jour
- Un préavis de 30 jours pour les modifications substantielles

### 19.2 Acceptation des modifications

Votre utilisation continue du Protocole après la date d'entrée en vigueur constitue une acceptation. Si vous n'acceptez pas, vous devez cesser d'utiliser le Protocole.

### 19.3 Modifications substantielles

Pour les modifications substantielles, nous fournirons :

- Un avis clair sur la nature des modifications
- Un résumé en langage ordinaire des principales modifications
- Au moins 30 jours avant l'entrée en vigueur des modifications

---

## 20. Dispositions générales

### 20.1 Accord intégral

Les présentes Conditions constituent l'accord intégral entre vous et nous concernant le Protocole. Elles remplacent l'Accord du vérificateur publié séparément (qui est désormais intégré ici à la Section 8). Si vous avez précédemment conclu un Accord du vérificateur autonome, les présentes Conditions le remplacent à compter de la Date d'entrée en vigueur.

### 20.2 Divisibilité

Si une disposition est jugée invalide ou inapplicable, elle sera appliquée dans toute la mesure permissible. Les autres dispositions restent en pleine vigueur.

### 20.3 Renonciation

Le défaut de faire appliquer une disposition ne constitue pas une renonciation.

### 20.4 Cession

Vous ne pouvez pas céder les présentes Conditions sans notre consentement écrit préalable. Nous pouvons céder les présentes Conditions sans votre consentement.

### 20.5 Force majeure

Aucune des parties n'est responsable de l'inexécution ou du retard dû à des causes indépendantes de sa volonté raisonnable, notamment les catastrophes naturelles, la guerre, le terrorisme, les pandémies, les actions gouvernementales, les pannes de réseau, les compromissions d'algorithmes cryptographiques ou les pannes de relais Nostr.

### 20.6 Notifications

Notifications à nous : voir Section 21. Notifications à vous : toute information de contact que vous avez fournie, ou via un événement Nostr ou le dépôt du Protocole.

### 20.7 Bénéficiaires tiers

Les présentes Conditions ne créent pas de droits de bénéficiaires tiers, sauf que les opérateurs de relais du réseau Nostr et les utilisateurs du Protocole qui se fient aux attestations émises par les vérificateurs sont les bénéficiaires visés de la Section 8.

### 20.8 Conformité aux exportations

Vous devez vous conformer à toutes les lois applicables sur les exportations et les sanctions. Les composants cryptographiques du Protocole peuvent être soumis à des contrôles à l'exportation dans certaines juridictions.

### 20.9 Titres

Les titres de section sont fournis à titre de commodité uniquement et n'affectent pas l'interprétation.

---

## 21. Contact

Pour toute question relative aux présentes Conditions, pour exercer des droits en matière de protection des données ou pour signaler des problèmes de sécurité :

**Le Protocole Signet**
E-mail : admin@forgesworn.dev
Divulgations de sécurité : admin@forgesworn.dev
Dépôt : https://github.com/forgesworn/signet-protocol

---

## 22. Annexes spécifiques aux juridictions

### Annexe A — Royaume-Uni

**Organismes de licence :** Law Society of England and Wales, Law Society of Scotland, Law Society of Northern Ireland, Bar Council of England and Wales, Faculty of Advocates, General Medical Council (GMC), Nursing and Midwifery Council (NMC), General Dental Council (GDC), General Pharmaceutical Council (GPhC), Health and Care Professions Council (HCPC), Teaching Regulation Agency (TRA), General Teaching Council for Scotland (GTCS), Architects Registration Board (ARB), Institute of Chartered Accountants in England and Wales (ICAEW), Institute of Chartered Accountants of Scotland (ICAS), Association of Chartered Certified Accountants (ACCA), Financial Conduct Authority (FCA) — personnes autorisées, Faculty Office of the Archbishop of Canterbury (notaires publics).

**Responsabilité professionnelle :** Telle qu'exigée par la SRA, la FCA, le GMC, la TRA ou l'organisme de réglementation compétent.

**Protection de l'enfance :** Children Act 1989 et 2004 ; Safeguarding Vulnerable Groups Act 2006 ; DBS Enhanced Check requis pour les enseignants et autres rôles d'activité réglementée effectuant des vérifications de niveau 4 ; signalement obligatoire en vertu de Working Together to Safeguard Children (2023).

**Protection des données :** UK RGPD ; Data Protection Act 2018 ; orientations de l'ICO ; orientations du DSIT sur les données biométriques.

**Vérification de l'âge :** Online Safety Act 2022 (garantie d'âge approuvée par Ofcom). La vérification professionnelle en personne de niveau 4 dépasse les méthodes acceptées par Ofcom.

### Annexe B — États-Unis

**Organismes de licence :** Barreaux des États ; ordres médicaux des États ; commissions de notaire des États ; départements de l'éducation des États (enseignants) ; régulateurs financiers des États compétents.

**Note :** L'éligibilité et les obligations varient considérablement selon les États. Vous devez vous conformer à la loi du (des) État(s) où vous effectuez des vérifications.

**Protection de l'enfance :** COPPA (Children's Online Privacy Protection Act) ; FERPA (pour les vérificateurs scolaires) ; obligations de signalement obligatoire des États ; lois étatiques de protection de l'enfance. Les dossiers d'inscription scolaire détenus par un enseignant peuvent servir de preuve documentaire pour les vérifications de niveau 4 là où la loi de l'État le permet.

**Protection des données :** CCPA/CPRA (Californie) ; Virginia CDPA ; autres lois étatiques sur la vie privée ; FERPA (dossiers scolaires). Un accord de traitement des données séparé peut être requis pour les utilisateurs résidant en Californie.

### Annexe C — Union européenne

**Organismes de licence :** Barreaux nationaux, conseils médicaux, chambres notariales et leurs équivalents dans chaque État membre.

**Note :** Les exigences spécifiques varient selon l'État membre. Les vérificateurs doivent se conformer à la loi de l'État membre où ils sont établis et où ils effectuent des vérifications.

**eIDAS 2.0 :** L'identifiant unique de personne eIDAS, lorsqu'il est présenté via un portefeuille d'identité numérique délivré par le gouvernement, peut servir de source de nullificateur supplémentaire. La formule du nullificateur est `SHA-256(LP("eidas") || LP(eidas_unique_id) || LP("signet-nullifier-v2"))`.

**Protection de l'enfance :** RGPD Article 8 ; législation nationale d'application ; Règlement (UE) 2022/2065 (DSA) obligations de vérification de l'âge.

**Protection des données :** RGPD (Règlement 2016/679) ; législation nationale d'application ; orientations des APD nationales.

### Annexe D — Australie

**Organismes de licence :** Barreaux des États et territoires ; Australian Health Practitioner Regulation Agency (AHPRA) pour les professions médicales et paramédicales ; départements de justice des États/territoires (notaires) ; organismes compétents d'enregistrement des enseignants des États.

**Protection de l'enfance :** Working With Children Check selon le rôle concerné ; Online Safety Act 2021 ; lois étatiques de protection de l'enfance.

**Protection des données :** Privacy Act 1988 ; Principes australiens de protection de la vie privée ; Consumer Data Right (CDR) le cas échéant.

### Annexe E — Japon

**Organismes de licence :** Japan Federation of Bar Associations (JFBA) ; Ministère de la Justice (notaires) ; Japan Medical Association ; autorités d'enregistrement des enseignants compétentes.

**Protection de l'enfance :** Orientations APPI ; législation nationale de protection de l'enfance ; obligations de travail avec les jeunes.

**Protection des données :** Act on the Protection of Personal Information (APPI) et ses amendements.

### Annexe F — Corée du Sud

**Organismes de licence :** Korean Bar Association ; Korean Medical Association ; ministères gouvernementaux compétents pour les autres professions réglementées.

**Protection de l'enfance :** Personal Information Protection Act (PIPA) ; Youth Protection Act ; obligations de signalement obligatoire.

**Protection des données :** PIPA.

### Annexe G — Brésil

**Organismes de licence :** Ordem dos Advogados do Brasil (OAB) ; Conselho Federal de Medicina (CFM) ; chambres notariales ; conseils professionnels fédéraux et étatiques compétents.

**Protection de l'enfance :** LGPD Article 14 (données des enfants — consentement parental requis) ; Estatuto da Criança e do Adolescente (ECA) ; obligations de signalement obligatoire.

**Protection des données :** Lei Geral de Proteção de Dados (LGPD) ; orientations de l'ANPD.

### Annexe H — Inde

**Organismes de licence :** Bar Council of India et barreaux des États ; National Medical Commission (NMC) ; autorités étatiques compétentes pour les autres professions réglementées.

**Protection de l'enfance :** Digital Personal Data Protection Act 2023 (DPDP) ; Protection of Children from Sexual Offences Act (POCSO) ; obligations de signalement obligatoire.

**Protection des données :** Loi DPDP 2023 ; règlements pris en application.

### Annexe I — Émirats arabes unis

**Organismes de licence :** Ministère de la Justice ; Dubai Health Authority (DHA) ou Health Authority Abu Dhabi (HAAD) ; autorités professionnelles des émirats compétents.

**Protection de l'enfance :** Loi fédérale n° 3 de 2016 (Loi Wadeema — Loi sur les droits de l'enfant) ; obligations de signalement obligatoire.

**Protection des données :** Décret-loi fédéral n° 45 de 2021 sur la protection des données personnelles ; orientations du Bureau des données des EAU.

---

*Le Protocole Signet — v0.1.0 — Mars 2026*
*Ce document est fourni à titre informatif. Il ne constitue pas un avis juridique. Consultez un conseiller juridique qualifié pour votre juridiction avant de vous y fier.*
