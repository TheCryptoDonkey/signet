---
**Hinweis zur KI-generierten Übersetzung**

Dieses Dokument wurde aus dem Englischen mithilfe von KI (Claude, Anthropic) übersetzt. Es dient ausschließlich als Referenz. Die englische Version unter `en.md` ist das einzige rechtsverbindliche Dokument. Diese Übersetzung wurde nicht von einem qualifizierten Rechtsübersetzer geprüft. Bei Abweichungen zwischen dieser Übersetzung und dem englischen Original hat die englische Fassung Vorrang.

---

# Richtlinie zum Kinderschutz

**Das Signet-Protokoll — v0.1.0**

*Vorlage — Holen Sie vor der Bereitstellung qualifizierten Rechtsrat für Ihre Rechtsordnung ein.*

**Datum des Inkrafttretens:** März 2026
**Zuletzt aktualisiert:** März 2026

---

## 1. Zweck

Diese Richtlinie zum Kinderschutz („Richtlinie") legt das Engagement des Signet-Protokolls („wir" oder „uns") für den Schutz von Kindern fest, die mit dem Signet-Protokoll (dem „Protokoll") interagieren oder von ihm betroffen sind. Die Verifizierungsstufe 4 des Protokolls (Professionelle Verifizierung — Erwachsener + Kind) befasst sich speziell mit der Identitätsverifizierung von Kindern, und diese Richtlinie regelt den Umgang mit dieser Fähigkeit — und allen kinderbezogenen Daten.

Die Sicherheit und der Schutz der Privatsphäre von Kindern ist unser oberstes Anliegen. Diese Richtlinie ist darauf ausgelegt, alle geltenden Kinderschutzgesetze weltweit einzuhalten und die Mindestanforderungen, wo praktikabel, zu übertreffen.

---

## 2. Geltungsbereich

Diese Richtlinie gilt für:

- Alle Interaktionen mit dem Signet-Protokoll, an denen Personen unter 18 Jahren (oder dem Volljährigkeitsalter in der jeweiligen Rechtsordnung, je nachdem, was höher ist) beteiligt sind
- Ausstellungs- und Verifizierungsprozesse für Stufe-4-Nachweise
- Altersverifizierungsprozesse mithilfe von Zero-Knowledge-Beweisen
- Alle Mitarbeiter, Verifizierer, vertrauende Parteien und Dritte, die über das Protokoll mit Kinderdaten interagieren
- Alle Rechtsordnungen, in denen das Protokoll verwendet wird

---

## 3. Begriffsbestimmungen

**„Kind"** bezeichnet jede Person unter 18 Jahren oder unter dem Volljährigkeitsalter in der jeweiligen Rechtsordnung, je nachdem, was höher ist.

**„Digitales Einwilligungsalter"** bezeichnet das Mindestalter, ab dem ein Kind unabhängig in die Verarbeitung seiner personenbezogenen Daten für digitale Dienste einwilligen kann, wie von der anwendbaren Rechtsordnung festgelegt.

**„Elternteil/Vormund"** bezeichnet einen Elternteil, gesetzlichen Vormund oder eine andere Person mit gesetzlicher Befugnis, im Namen eines Kindes zu handeln.

**„Stufe-4-Verifizierung"** bezeichnet die Stufe Professionelle Verifizierung (Erwachsener + Kind) des Protokolls, bei der ein lizenzierter Fachverifizierer die Identität eines Kindes unter Beteiligung und Zustimmung eines Elternteils/Vormunds bestätigt.

**„Altersbereichsnachweis"** bezeichnet einen Zero-Knowledge-Beweis (mithilfe von Bulletproofs), der nachweist, dass das Alter eines Benutzers in einem bestimmten Bereich liegt, ohne das genaue Geburtsdatum preiszugeben.

**„Signet IQ"** bezeichnet den kontinuierlichen Identifikationsquotienten-Score des Protokolls (0–200), der die kumulative Stärke der Verifizierungssignale eines Benutzers widerspiegelt. Für Kinder wird der Signet IQ aus der eigenen Verifizierungsstufe und dem Signet IQ des Vormunds, dem eigenen Stufe-4-Nachweis des Kindes und etwaigen Peer-Bürgschaften von verifizierten Konten berechnet.

---

## 4. Regulatorischer Rahmen

### 4.1 Internationale Compliance

Diese Richtlinie ist darauf ausgelegt, die folgenden Gesetze und Rahmenbedingungen einzuhalten:

| Rechtsordnung | Gesetz / Rahmen | Wesentliche Anforderungen |
|-------------|----------------|-----------------|
| **Vereinigte Staaten** | Children's Online Privacy Protection Act (COPPA) | Nachweisbare elterliche Einwilligung für Kinder unter 13 Jahren; Datensparsamkeit; elterliche Zugriffsrechte |
| **Europäische Union** | DSGVO Artikel 8 | Digitales Einwilligungsalter von 16 Jahren (Mitgliedstaaten können auf 13 Jahre absenken); elterliche Einwilligung unterhalb des digitalen Einwilligungsalters erforderlich |
| **Vereinigtes Königreich** | UK DSGVO + Age Appropriate Design Code (AADC) | Kindeswohl; altersgerechtes Design; 15 Standards des AADC |
| **Australien** | Privacy Act 1988 + Online Safety Act 2021 | Angemessene Maßnahmen zur Altersverifizierung; grundlegende Online-Sicherheitserwartungen |
| **Südkorea** | PIPA + Gesetz zur Förderung der Nutzung von Informations- und Kommunikationsnetzen | Einwilligung des gesetzlichen Vertreters für Kinder unter 14 Jahren |
| **Brasilien** | LGPD Artikel 14 | Kindeswohl; spezifische elterliche Einwilligung für Kinder unter 12 Jahren; doppelte Einwilligung für 12–17 |
| **Indien** | DPDP-Gesetz 2023 | Nachweisbare Einwilligung eines Elternteils/Vormunds für Kinder (unter 18); Verbot von Tracking, Verhaltensüberwachung und zielgerichteter Werbung für Kinder |
| **China** | PIPL Artikel 28 + Bestimmungen zum Schutz Minderjähriger im Internet | Spezifische Einwilligung für unter 14-Jährige; erhöhter Schutz für alle Minderjährigen |
| **Japan** | APPI + Grundgesetz zur Cybersicherheit | Branchenrichtlinien für den Schutz von Kinderdaten |
| **Kanada** | PIPEDA + Provinzgesetze | Aussagekräftige Einwilligung basierend auf der Kapazität des Kindes |

### 4.2 UN-Konvention über die Rechte des Kindes

Diese Richtlinie orientiert sich an den Grundsätzen der UN-Konvention über die Rechte des Kindes, einschließlich:
- Das Kindeswohl (Artikel 3)
- Das Recht auf Privatsphäre (Artikel 16)
- Das Recht auf Schutz vor Ausbeutung (Artikel 36)

---

## 5. Altersverifizierung mittels Zero-Knowledge-Beweisen

### 5.1 Funktionsweise der Altersverifizierung

Das Signet-Protokoll verwendet auf Bulletproofs basierende Zero-Knowledge-Beweise für die Altersverifizierung. Dieser Ansatz:

1. **Beweist ohne zu offenbaren:** Ein Benutzer kann beweisen, dass er sich in einem bestimmten Altersbereich befindet (z. B. „über 13", „über 16", „über 18", „13–17"), ohne sein genaues Geburtsdatum preiszugeben.
2. **Kann nicht rückentwickelt werden:** Der Zero-Knowledge-Beweis ist mathematisch so konstruiert, dass das zugrunde liegende Geburtsdatum nicht aus dem Beweis extrahiert werden kann.
3. **Wird kryptografisch verifiziert:** Vertrauende Parteien können die Gültigkeit des Beweises überprüfen, ohne etwas außer dem Altersbereichsanspruch zu erfahren.
4. **Wird einmal ausgestellt, mehrfach verwendet:** Ein einzelner Altersbereichsnachweis kann mehreren vertrauenden Parteien präsentiert werden, ohne eine erneute Verifizierung.

### 5.2 Altersbereichskategorien

Das Protokoll unterstützt die folgenden Standard-Altersbereichsnachweise:

| Bereich | Beschreibung | Anwendungsfall |
|-------|-------------|----------|
| Unter 13 | Unterhalb der COPPA-Schwelle | Erfordert vollständige elterliche Einwilligung und Aufsicht |
| 13–15 | Über COPPA, unterhalb einiger DSGVO-Schwellen | Kann je nach Rechtsordnung elterliche Einwilligung erfordern |
| 16–17 | Über den meisten digitalen Einwilligungsaltern, unter Volljährigkeit | Unabhängige Einwilligung in den meisten Rechtsordnungen; gewisse elterliche Aufsicht |
| 18+ | Volljährigkeitsalter in den meisten Rechtsordnungen | Vollständige unabhängige Einwilligung |
| Benutzerdefiniert | Rechtsordnungsspezifische Altersbereiche | Einhaltung spezifischer lokaler Anforderungen |

### 5.3 Nachweisausstellung für Kinder

Für Kinder (unter 18 Jahren) folgt die Verifizierungszeremonie einem benutzergeführten Ablauf mit professioneller Bestätigung:

1. Elternteil/Vormund und Kind nehmen gemeinsam an einer Stufe-4-Verifizierung mit einem lizenzierten Fachmann (Solicitor, Notar, Arzt oder Äquivalent) teil.
2. **Der Benutzer (Elternteil/Vormund) gibt alle Dokumentdetails ein** in der My Signet App: Dokumenttyp, Ausstellungsland, Dokumentnummer und Geburtsdatum des Kindes. Der Verifizierer prüft die physischen Dokumente, um zu bestätigen, dass die eingegebenen Daten korrekt sind — er tippt nicht im Auftrag des Benutzers.
3. Das Protokoll berechnet den dokumentbasierten Nullifier lokal auf dem Gerät des Benutzers unter Verwendung der `signet-nullifier-v2`-Formel (SHA-256 der längenvorzeichenbehafteten Felder: docType, country, docNumber, „signet-nullifier-v2"). Der Nullifier wird an den Verifizierer übermittelt; die rohen Dokumentdetails werden nicht übermittelt.
4. Der Verifizierer erstellt den Bulletproof-Altersbereichsnachweis und stellt gleichzeitig zwei Nachweise aus: einen Natural-Person-Nachweis (Schlüsselpaar A) und einen Persona-Nachweis (Schlüsselpaar B). Beide tragen den Altersbereichsnachweis und Guardian-Tags (`["guardian", "<parent_pubkey>"]`). Der echte Name des Kindes wird nur als privates Merkle-Blatt gespeichert — nie on-chain veröffentlicht.
5. Der Merkle-Baum für den Natural-Person-Nachweis des Kindes enthält: Geburtsdatum (für den Altersbereichsnachweis), Vormund-Beziehung, Dokumenttyp, Dokumentnummer und Dokumentablaufdatum. Der Name des Kindes ist als privates Merkle-Blatt enthalten und wird **nicht** an Relays veröffentlicht. Die Nationalität kann für die Einhaltung von Rechtsordnungsanforderungen enthalten sein.
6. Der dokumentbasierte Nullifier (Hash von Dokumenttyp, Land und Nummer mittels `signet-nullifier-v2`) ist nur im Natural-Person-Nachweis enthalten und verhindert die Erstellung doppelter Identitäten.
7. **Biometrischer Kontoschutz:** Auf dem Gerät des Kindes verwendet die My Signet App den biometrischen WebAuthn-Entsperrschutz (Gesichtserkennung oder Fingerabdruck), um den Zugriff auf das Konto des Kindes zu schützen. Die biometrischen Daten verlassen das Gerät nie — sie werden vollständig vom sicheren Enklave des Geräts über den WebAuthn-Standard verarbeitet. Es werden keine biometrischen Vorlagen an einen Server übertragen oder außerhalb des Geräts gespeichert.

### 5.4 Lehrkräfte als primärer Kanal für die Kinderverifizierung

Lehrkräfte und Schuladministratoren sind ein anerkannter Kanal für die Stufe-4-Kinderverifizierung. Schulanmeldungsunterlagen — die die Eltern-Kind-Beziehung belegen und Geburtstagsdaten als Nachweis bereitstellen — werden als unterstützende Dokumentation neben dem Eltern-Ausweis akzeptiert.

Eine Lehrkraft, die ein lizenzierter Fachmann ist (z. B. eine qualifizierte Lehrkraft in einer Rechtsordnung, die Lehren als regulierten Beruf behandelt, oder ein schulgebundener Notar), kann eine Stufe-4-Verifizierung durchführen unter Verwendung:
- Des von der Regierung ausgestellten Lichtbildausweises des Elternteils/Vormunds
- Der Schulanmeldungsunterlagen als Kindernachweis (zusätzlich zu oder anstelle einer Geburtsurkunde oder eines Reisepasses)

Dieser Weg ist besonders wichtig für Heimschulungsgemeinschaften und Regionen, in denen der Zugang zu Solicitors oder Notaren begrenzt ist. Der Berufsverband des Erziehers und seine anstellende Institution sind der Vertrauensanker. Betrügerische Beglaubigung durch eine Lehrkraft stellt nach geltendem Bildungsrecht ein Berufsvergehen dar.

### 5.5 SDK-basierte Altersverifizierung für Websites

Das Signet SDK ermöglicht Websites und Anwendungen, den Altersbereich eines Kindes zu verifizieren, ohne personenbezogene Daten zu erhalten. Der Datenfluss ist:

```
Website → SDK → My Signet App → ZK-Altersbereichsnachweis → Website
```

Die Website fordert einen Nachweis für einen bestimmten Altersanspruch an (z. B. „Benutzer ist unter 18" oder „Benutzer ist zwischen 13 und 17"). Das Signet SDK leitet diese Anfrage an die My Signet App auf dem Gerät des Benutzers weiter. Die App erstellt den Nachweis lokal und gibt nur den kryptografischen Nachweis zurück — keinen Namen, kein Geburtsdatum, keine Dokumentdetails, keinen Nullifier. Die Website verifiziert den Nachweis mathematisch und erfährt nur den Altersbereichsanspruch.

Das bedeutet, dass Websites Altersverifizierungsanforderungen (COPPA, UK Online Safety Act, australische Unter-16-Regelungen) erfüllen können, ohne personenbezogene Daten von Kindern zu erheben oder zu speichern.

---

## 6. Mechanismen zur elterlichen Einwilligung

### 6.1 Einwilligungsanforderungen nach Rechtsordnung

| Rechtsordnung | Digitales Einwilligungsalter | Erforderlicher Einwilligungsmechanismus |
|-------------|--------------------|-----------------------------|
| Vereinigte Staaten (COPPA) | 13 | Nachweisbare elterliche Einwilligung (z. B. unterzeichnetes Formular, Kreditkartenverifizierung, Videoanruf, Ausweisprüfung) |
| EU (DSGVO-Standard) | 16 | Angemessene Bemühungen zur Verifizierung der elterlichen Einwilligung |
| EU (Mindeststandard der Mitgliedstaaten) | 13 | Gemäß Umsetzung des Mitgliedstaats |
| Vereinigtes Königreich | 13 | Altersgerechte Verifizierung der elterlichen Einwilligung |
| Australien | Kein spezifisches digitales Alter | Angemessene Maßnahmen basierend auf Reife und Risiko |
| Südkorea | 14 | Einwilligung des gesetzlichen Vertreters |
| Brasilien | 12 (mit elterlicher Einwilligung bis 18) | Spezifische und deutliche Einwilligung durch Elternteil/Vormund |
| Indien | 18 | Nachweisbare Einwilligung eines Elternteils/Vormunds |
| China | 14 | Separate Einwilligung von Elternteil/Vormund |
| Japan | 15 (Richtlinie) | Elterliche Beteiligung empfohlen |

### 6.2 Protokoll-Einwilligungsmechanismen

Das Protokoll unterstützt die folgenden Mechanismen zur elterlichen Einwilligung:

1. **Verifizierter Elternteil-Nachweis (Stufe 3/4):**
   Der Elternteil/Vormund erhält einen Stufe-3- oder Stufe-4-Nachweis, der seine eigene Identität durch die Zwei-Nachweis-Zeremonie (Natural Person + Persona) verifiziert. Sie unterzeichnen dann kryptografisch ein Einwilligungsereignis, das den Nachweis des Kindes autorisiert. Dies schafft eine überprüfbare Kette:
   - Identität des Elternteils durch professionellen Verifizierer verifiziert (Zwei-Nachweis-Zeremonie)
   - Einwilligung des Elternteils kryptografisch mit seinem Nostr-Schlüssel unterzeichnet
   - Nachweis des Kindes über unveränderliche Guardian-Tags auf beiden Nachweisen (Natural Person und Persona) mit dem Elternteil verknüpft
   - Delegierungsereignisse für Vormunde (Art 31000) ermöglichen es dem Elternteil, bestimmte Berechtigungen an andere vertrauenswürdige Erwachsene zu delegieren

2. **Co-Verifizierung:**
   Elternteil/Vormund und Kind nehmen gemeinsam an einer Stufe-4-Verifizierungssitzung teil. Der professionelle Verifizierer:
   - Verifiziert die Identitäten sowohl des Elternteils/Vormunds als auch des Kindes
   - Bestätigt die Eltern-Kind- oder Vormund-Kind-Beziehung
   - Erfasst die Einwilligung des Elternteils/Vormunds als Teil des Verifizierungsereignisses

3. **Delegierte Einwilligung:**
   Für Rechtsordnungen, die spezifische Einwilligungsmechanismen erfordern (z. B. die nachweisbare elterliche Einwilligung von COPPA), können zusätzliche Verifizierungsschritte erforderlich sein:
   - Unterzeichnetes Einwilligungsformular (digital oder physisch)
   - Videoverifizierungssitzung
   - Verifizierung des staatlich ausgestellten Lichtbildausweises des einwilligenden Elternteils/Vormunds

### 6.3 Einwilligungswiderruf

Eltern/Vormunde können die Einwilligung jederzeit widerrufen durch:
1. Veröffentlichung eines Widerrufsereignisses (Art 31000) vom Nostr-Schlüssel des Elternteils/Vormunds, das das Einwilligungsereignis widerruft.
2. Kontaktaufnahme mit dem Signet-Protokoll-Supportteam, um Widerrufshilfe zu beantragen.
3. Durch jeden Nostr-Client, der die Einwilligungsverwaltungsfunktionen des Protokolls implementiert.

Nach dem Einwilligungswiderruf:
- Der Nachweis des Kindes wird sofort widerrufen.
- Vertrauende Parteien werden über das Widerrufsereignis benachrichtigt.
- Alle zentral gespeicherten kinderbezogenen Daten werden innerhalb von 30 Tagen gelöscht, es sei denn, die Aufbewahrung ist gesetzlich vorgeschrieben.

---

## 7. Datensparsamkeit für Kinder

### 7.1 Grundsatz

Das Protokoll wendet die strengsten Datensparsamkeitsprinzipien für Kinderdaten an. Es werden keine Daten erhoben oder verarbeitet, die über das für die Nachweis-Verifizierung streng Notwendige hinausgehen.

### 7.2 Was erhoben wird

| Daten | Erhoben | Begründung |
|------|-----------|-----------|
| Nostr-Public-Key des Kindes | Ja | Erforderlich für die Nachweisbindung |
| Altersbereichsnachweis (ZK-Beweis) | Ja | Erforderlich für die Altersverifizierung |
| Aufzeichnung der elterlichen Einwilligung | Ja | Erforderlich für die Rechtskonformität |
| Nachweis-Metadaten (Stufe, Daten) | Ja | Erforderlich für die Nachweis-Funktionalität |
| Name des Kindes | **Nein (nicht on-chain)** | Nur als privates Merkle-Blatt gespeichert; nie veröffentlicht |
| Geburtsdatum des Kindes | **Nein (nicht on-chain)** | Durch ZK-Altersbereichsnachweis ersetzt; nur als privates Merkle-Blatt gespeichert |
| Foto des Kindes | **Nein** | Nicht erforderlich |
| Staatliche Ausweisnummer des Kindes | **Nein (nicht on-chain)** | Nur als privates Merkle-Blatt für selektive Offenlegung gespeichert; nach der Zeremonie nicht vom Verifizierer gespeichert |
| Nullifier-Hash (`signet-nullifier-v2`) | Ja (nur NP-Nachweis) | Erforderlich zur Duplikatsprävention; kann nicht auf Dokumentdetails zurückverfolgt werden |
| Vormund-Public-Key(s) | Ja (beide Nachweise) | Erforderlich für die Vormund-Kind-Verknüpfung |
| Vormund-Beziehung | Ja (privates Merkle-Blatt, NP-Nachweis) | Begründet die rechtliche Grundlage für die Vormund-Verknüpfung |
| Merkle-Root | Ja (nur NP-Nachweis) | Bestätigt verifizierte Attribute, ohne sie zu veröffentlichen |
| Entitätstyp-Tag | Ja (beide Nachweise) | Erforderlich zur Unterscheidung zwischen Natural Person und Persona |
| Standort des Kindes | **Nein** | Nicht erforderlich |
| Schule oder Institution des Kindes | **Nein (nicht on-chain)** | Kann als unterstützender Nachweis referenziert, aber nicht veröffentlicht werden |
| Verhaltensdaten | **Nein** | Verboten |
| Nutzungsverfolgung | **Nein** | Für Kinder verboten |
| Biometrische Daten | **Nein** | Nur gerätlokal über WebAuthn; keine Vorlagen übermittelt |

### 7.3 Merkle-Baum-Attribute für Kinder

Der Natural-Person-Nachweis für ein Kind verpflichtet sich gegenüber einem Merkle-Baum mit den folgenden Blättern:

| Blatt | Zweck | On-chain offengelegt? |
|------|---------|---------------------|
| `dateOfBirth:<ISO-Datum>` | Quelle für ZK-Altersbereichsnachweis | Nein — privat |
| `guardianRelationship:<Typ>` | Rechtliche Grundlage (z. B. „parent", „legal_guardian") | Nein — privat |
| `documentType:<Typ>` | Art des vorgelegten Nachweises | Nein — privat |
| `documentNumber:<Nummer>` | Für selektive Offenlegung bei Bedarf | Nein — privat |
| `documentExpiry:<Datum>` | Prüfung der Dokumentgültigkeit | Nein — privat |
| `name:<Name>` | Für selektive Offenlegung bei Bedarf | Nein — privat |
| `nationality:<Code>` | Rechtsordnungskonformität | Nein — privat |
| `nullifier:<Hash>` | Duplikatsprävention | Ja (als Top-Level-Tag) |

Nur die Merkle-Root und der Nullifier-Hash erscheinen on-chain. Einzelne Blätter werden nur offengelegt, wenn der Vormund des Kindes ausdrücklich selektive Offenlegung ausübt (z. B. um die Staatsangehörigkeit des Kindes gegenüber einer Aufsichtsbehörde nachzuweisen).

### 7.4 Signet IQ für Kinder

Kinder haben Signet-IQ-Werte, die berechnet werden aus:
- Dem Stufe-4-Nachweis selbst (wesentlicher Beitrag)
- Der eigenen Verifizierungsstufe und dem Signet IQ des Vormunds (gewichteter Beitrag, der die Stärke der Vormund-Beziehung widerspiegelt)
- Peer-Bürgschaften von anderen Konten der Stufe 2+, die die Familie kennen

Der Signet IQ eines Kindes wird vertrauenden Parteien als aggregiertes Vertrauenssignal angezeigt. Er offenbart nicht die Identität des Vormunds, den Namen des Kindes oder ein anderes persönliches Attribut — er wird nur aus öffentlichen Nachweis-Ereignissen berechnet. Die soziale Bewertung von Kindern basierend auf ihrem Signet IQ für andere Zwecke als Altersverifizierung und Zugriffskontrolle ist verboten (siehe Abschnitt 8).

### 7.5 Aufbewahrungsfristen

Kinderdaten unterliegen den kürzest zulässigen Aufbewahrungsfristen:
- Aktive Nachweise: Bis zum Ablauf, Widerruf oder bis das Kind das Volljährigkeitsalter erreicht (je nachdem, was früher eintritt)
- Einwilligungsaufzeichnungen: Dauer der Nachweisvalidität zuzüglich gesetzlich vorgeschriebener Aufbewahrungsfrist
- Verifizierungsaufzeichnungen: Entsprechend den beruflichen Verpflichtungen des Verifizierers (typischerweise 1–3 Jahre)
- Challenge-/Response-Daten: Unmittelbar nach der Verifizierung gelöscht

---

## 8. Verbotene Verwendungen

### 8.1 Absolute Verbote

Die folgenden Verwendungen des Protokolls in Bezug auf Kinder sind **strikt verboten**:

1. **Profiling:** Verwendung des Protokolls zur Erstellung von Profilen von Kindern für jeden Zweck, einschließlich Marketing, Werbung oder Verhaltensanalyse.
2. **Tracking:** Verwendung von Nachweisen oder Verifizierungsdaten zur Verfolgung der Online- oder Offline-Aktivitäten von Kindern.
3. **Zielgerichtete Werbung:** Verwendung von Altersbereichsnachweisen oder Nachweisdaten, um Werbung an Kinder zu richten.
4. **Datenmonetisierung:** Verkauf, Lizenzierung oder anderweitige Monetisierung von Kindernachweisdaten oder Altersverifizierungsdaten.
5. **Automatisierte Entscheidungsfindung:** Verwendung der Nachweisdaten von Kindern für automatisierte Entscheidungen, die rechtliche oder ähnlich bedeutsame Auswirkungen haben.
6. **Überwachung:** Verwendung des Protokolls zur laufenden Überwachung der Aktivitäten von Kindern.
7. **Soziale Bewertung:** Verwendung von Nachweis- oder Signet-IQ-Daten zur Erstellung sozialer Bewertungssysteme für Kinder über die altersgerechte Zugangskontrolle hinaus.
8. **Nudging:** Verwendung von Designmustern, die die Schwachstellen von Kindern ausnutzen oder ihr Verhalten manipulieren.
9. **Unnötige Datenerhebung:** Erhebung von mehr Daten von Kindern, als für die Nachweis-Verifizierung strikt notwendig ist.
10. **Weitergabe ohne Einwilligung:** Weitergabe von Kinderdaten an Dritte ohne nachweisbare elterliche Einwilligung.

### 8.2 Einschränkungen für vertrauende Parteien

Vertrauende Parteien, die Altersbereichsnachweise oder Nachweis-Verifizierungen für Kinder erhalten:
- Dürfen die Daten nicht über den spezifischen Zweck hinaus verwenden, für den die Verifizierung beantragt wurde
- Dürfen die Verifizierungsdaten nicht über den unmittelbaren Bedarf hinaus aufbewahren
- Müssen eigene, für ihren Dienst geeignete Kinderschutzmaßnahmen umsetzen
- Müssen alle geltenden Kinderschutzgesetze in ihrer Rechtsordnung einhalten

---

## 9. Meldung und Reaktion auf Vorfälle

### 9.1 Arten von meldepflichtigen Vorfällen

Die folgenden Vorfälle, die Kinder betreffen, müssen gemeldet werden:

| Vorfallsart | Meldeschwelle | Priorität |
|--------------|---------------------|----------|
| Verletzung der Nachweisdaten eines Kindes | Jeder unbefugte Zugriff | Kritisch — Sofort |
| Betrügerischer Stufe-4-Nachweis für ein Kind | Entdeckung eines jeden Falls | Kritisch — Sofort |
| Kompromittierung des elterlichen Einwilligungsmechanismus | Jeder Hinweis auf Kompromittierung | Kritisch — Sofort |
| Ausnutzung der Altersverifizierung | Entdeckung einer jeden Umgehung | Hoch — Innerhalb von 4 Stunden |
| Missbrauch des Kindernachweises durch eine vertrauende Partei | Jeder gemeldete Missbrauch | Hoch — Innerhalb von 4 Stunden |
| Vermutete durch das Protokoll erleichterte Kinderausbeutung | Jeder Hinweis | Kritisch — Sofort + Strafverfolgungsbehörden |
| De-Anonymisierung der Identität eines Kindes | Jeder Fall | Kritisch — Sofort |

### 9.2 Meldeverfahren

**Interne Meldung:**
- Alle Vorfälle werden sofort dem designierten Kinderschutzbeauftragten gemeldet.
- Der Kinderschutzbeauftragte eskaliert zum Datenschutzbeauftragten (DSB) und zur Geschäftsleitung.

**Behördliche Meldung:**
- Die zuständigen Aufsichtsbehörden werden innerhalb der gesetzlich vorgeschriebenen Fristen benachrichtigt (z. B. 72 Stunden gemäß DSGVO).
- Länderspezifische Meldepflichten werden eingehalten (siehe Abschnitt 10).

**Meldung bei Strafverfolgungsbehörden:**
- Vorfälle, bei denen Kinderausbeutung vermutet wird, werden sofort gemeldet an:
  - Lokale Strafverfolgungsbehörden
  - National Centre for Missing & Exploited Children (NCMEC) (USA)
  - Internet Watch Foundation (IWF) (UK)
  - Entsprechende Stellen in der jeweiligen Rechtsordnung

**Benachrichtigung der Eltern:**
- Eltern/Vormunde werden unverzüglich über jeden Vorfall informiert, der die Daten oder den Nachweis ihres Kindes betrifft.
- Die Benachrichtigung enthält eine Beschreibung des Vorfalls, seine möglichen Auswirkungen und die ergriffenen Maßnahmen.

### 9.3 Abhilfemaßnahmen

Nach einem Kinderschutzvorfall:
1. Sofortige Eindämmung des Vorfalls
2. Widerruf betroffener Nachweise
3. Forensische Untersuchung
4. Ursachenanalyse
5. Umsetzung präventiver Maßnahmen
6. Folgekommunikation mit betroffenen Parteien
7. Überprüfung nach dem Vorfall und ggf. Aktualisierung der Richtlinie

---

## 10. Rechtsordnungsspezifische Anforderungen

### 10.1 Vereinigtes Königreich

**Age Appropriate Design Code (AADC) — 15 Standards:**

| Standard | Umsetzung |
|----------|---------------|
| Kindeswohl | Kinderschutz-Folgenabschätzungen für alle Protokollfunktionen, die Kinder betreffen |
| Datenschutz-Folgenabschätzungen | DPIA für Stufe 4 und alle kinderbezogenen Verarbeitungen durchgeführt |
| Altersgerechte Anwendung | Protokollschnittstellen für verschiedene Altersgruppen konzipiert |
| Transparenz | Datenschutzinformationen in altersgerechter Sprache bereitgestellt |
| Nachteilige Datenverwendung | Verbot der Verwendung von Kinderdaten auf für ihr Wohlbefinden nachteilige Weise |
| Richtlinien und Community-Standards | Klare Standards für die Verwendung von Kindernachweisen |
| Standardeinstellungen | Datenschutzschützende Standards für alle Kindernachweise |
| Datensparsamkeit | Strengste Minimierung angewendet (siehe Abschnitt 7) |
| Datenweitergabe | Kinderdaten nicht über den verifizierten Bedarf hinaus geteilt |
| Geolokalisierung | Keine Geolokalisierungsdaten für Kinder erhoben oder verarbeitet |
| Elterliche Kontrollen | Einwilligungs- und Aufsichtsmechanismen wie in Abschnitt 6 beschrieben |
| Profiling | Für Kinder verboten (siehe Abschnitt 8) |
| Nudge-Techniken | Für Kinder verboten (siehe Abschnitt 8) |
| Vernetzte Spielzeuge und Geräte | Nicht auf Protokoll anwendbar, aber vertrauende Parteien werden beraten |
| Online-Tools | Protokoll-Tools mit Blick auf den Kinderschutz konzipiert |

**Meldung:** An das Information Commissioner's Office (ICO) innerhalb von 72 Stunden.

### 10.2 Vereinigte Staaten

**COPPA-Compliance:**
- Nachweisbare elterliche Einwilligung vor der Erhebung von Informationen von Kindern unter 13 Jahren eingeholt
- Klare, umfassende Online-Datenschutzhinweise zu Datenpraktiken bezüglich Kindern
- Elterlicher Zugriff zur Überprüfung und Löschung der Daten des Kindes
- Keine Koppelung der Teilnahme eines Kindes an die unnötige Offenlegung von Informationen
- Angemessene Sicherheitsmaßnahmen für Kinderdaten

**FTC-Position März 2026:** Die FTC wird keine Durchsetzungsmaßnahmen ergreifen, wenn personenbezogene Daten ausschließlich für Altersverifizierungszwecke erhoben werden, sofern die Daten sorgfältig gelöscht und klare Hinweise erteilt werden. Signet übertrifft dies: Bei der Altersverifizierung werden keine personenbezogenen Daten erhoben, gespeichert oder übermittelt — der ZKP-Beweis enthält keinerlei personenbezogene Informationen.

**Staatliche Gesetze:**
- California Consumer Privacy Act (CCPA) — Opt-in-Einwilligung für den Verkauf von Daten von Verbrauchern unter 16 Jahren erforderlich
- California Age-Appropriate Design Code Act (AB 2273) — Datenschutz-Folgenabschätzungen für Dienste, auf die Kinder wahrscheinlich zugreifen
- Andere staatliche Gesetze, soweit anwendbar

**Meldung:** An die FTC und anwendbare State Attorneys General.

### 10.3 Europäische Union

**DSGVO-Artikel-8-Konformität:**
- Elterliche Einwilligung unterhalb des digitalen Einwilligungsalters (13–16, je nach Mitgliedstaat) erforderlich
- Angemessene Bemühungen zur Verifizierung der Einwilligung des Inhabers der elterlichen Verantwortung
- Direkt an ein Kind gerichtet: Datenschutzhinweis in klarer, einfacher, für das Kind geeigneter Sprache

**Variationen der Mitgliedstaaten:**

| Land | Digitales Einwilligungsalter |
|---------|--------------------|
| Österreich | 14 |
| Belgien | 13 |
| Kroatien | 16 |
| Tschechische Republik | 15 |
| Dänemark | 13 |
| Estland | 13 |
| Finnland | 13 |
| Frankreich | 15 |
| Deutschland | 16 |
| Griechenland | 15 |
| Ungarn | 16 |
| Irland | 16 |
| Italien | 14 |
| Lettland | 13 |
| Litauen | 14 |
| Luxemburg | 16 |
| Malta | 13 |
| Niederlande | 16 |
| Polen | 16 |
| Portugal | 13 |
| Rumänien | 16 |
| Slowakei | 16 |
| Slowenien | 16 |
| Spanien | 14 |
| Schweden | 13 |

**Meldung:** An die federführende Aufsichtsbehörde innerhalb von 72 Stunden.

### 10.4 Australien

**Privacy Act 1988 + Online Safety Act 2021:**
- Angemessene Schritte zur Sicherstellung der Einwilligungsfähigkeit des Kindes
- Altersgerechte Datenschutzinformationen
- Einhaltung des Online Safety (Basic Online Safety Expectations) Determination 2022

**Meldung:** An das Office of the Australian Information Commissioner (OAIC) und den eSafety Commissioner.

### 10.5 Südkorea

**PIPA + Gesetz zur Förderung der Nutzung von Informations- und Kommunikationsnetzen:**
- Einwilligung des gesetzlichen Vertreters für Kinder unter 14 Jahren erforderlich
- Nur das notwendige Minimum an Informationen
- Keine Erhebung ohne Einwilligung des gesetzlichen Vertreters

**Meldung:** An die Personal Information Protection Commission (PIPC).

### 10.6 Brasilien

**LGPD Artikel 14:**
- Kindeswohl
- Spezifische, deutliche elterliche Einwilligung für Kinder unter 12 Jahren
- Kinder im Alter von 12–17: Doppelte Einwilligung (Kind + Elternteil)
- Informationspraktiken in einer für das Kind einfachen, klaren und zugänglichen Weise kommuniziert

**Meldung:** An die ANPD (Autoridade Nacional de Proteção de Dados).

### 10.7 Indien

**DPDP-Gesetz 2023:**
- Nachweisbare Einwilligung eines Elternteils/Vormunds für alle Kinder (unter 18)
- Verbot von Tracking, Verhaltensüberwachung und zielgerichteter Werbung für Kinder
- Verpflichtungen eines Datentreuhänders in Bezug auf Kinderdaten

**Meldung:** An das Data Protection Board of India.

---

## 11. Gestaltungsprinzipien für den Kinderschutz

### 11.1 Privacy by Design

Alle Protokollfunktionen, die Kinder betreffen, beinhalten:
- Datensparsamkeit auf architektonischer Ebene
- Zero-Knowledge-Beweise zur Vermeidung der Offenlegung personenbezogener Daten
- Kryptografische Schutzmaßnahmen, die in die Nachweisstruktur eingebaut sind
- Standardmäßig datenschutzschützende Einstellungen
- Benutzer-gibt-ein-Verifizierer-bestätigt-Zeremonienablauf — Dokumentdaten werden vom Benutzer auf seinem eigenen Gerät eingegeben; der Verifizierer bestätigt die Richtigkeit, hält aber nie rohe Dokumentdetails

### 11.2 Safety by Design

Protokollschnittstellen und -implementierungen sollten:
- Klar zwischen Kinder- und Erwachsenen-Nachweis-Workflows unterscheiden
- Versehentliche Offenlegung von Kinderidentitätsinformationen verhindern
- Sicherheitsvorkehrungen gegen Nachweis-Missbrauch beinhalten
- Klare, altersgerechte Leitlinien bereitstellen
- Biometrische Geräteentsperrung (WebAuthn) zum Schutz von Kinderkonten auf dem Gerät verwenden

### 11.3 Regelmäßige Überprüfung

Diese Richtlinie und alle Kinderschutzmaßnahmen werden überprüft:
- Mindestens jährlich
- Bei jeder Änderung der anwendbaren Gesetze
- Nach einem Kinderschutzvorfall
- Bei wesentlichen Änderungen am Protokoll

### 11.4 Vormund-Delegierungsmodell

Das Protokoll implementiert ein Drei-Schichten-Familienstrukturmodell:

**Schicht 1 — Nachweisebene (unveränderlich):**
Guardian-Tags (`["guardian", "<parent_pubkey>"]`) werden vom professionellen Verifizierer gesetzt und spiegeln die gesetzliche elterliche Verantwortung wider. Sie können nur durch einen neuen Nachweis geändert werden, der von einem Fachmann mit entsprechender rechtlicher Dokumentation (z. B. Gerichtsbeschluss) ausgestellt wird.

**Schicht 2 — Delegierungsebene (flexibel):**
Vormunde können bestimmte Berechtigungen über Art-31000-Vormund-Delegierungsereignisse an vertrauenswürdige Erwachsene (Stiefelternteile, Großeltern, Lehrkräfte) delegieren. Delegierungen sind:
- Zeitlich begrenzt (mit Ablaufdatum)
- Umfangsbegrenzt: `full`, `activity-approval`, `content-management`, `contact-approval`
- Jederzeit durch den Vormund widerrufbar
- Mit dem Nostr-Schlüssel des Vormunds unterzeichnet
- Mit `["agent-type", "guardian"]` gekennzeichnet, um von anderen Delegierungsereignistypen zu unterscheiden

**Schicht 3 — Client-Ebene (app-spezifisch):**
Anwendungen erzwingen Berechtigungen basierend auf Schicht-1- und Schicht-2-Daten, einschließlich Bildschirmzeitgrenzen, Inhaltsfilterung, Aktivitätsgenehmigungsabläufen und Kontaktbeschränkungen.

---

## 12. Schulung und Sensibilisierung

### 12.1 Verifizierer-Schulung

Alle professionellen Verifizierer, die zur Durchführung von Stufe-4-(Kinder-)Verifizierungen berechtigt sind, müssen:
- Eine Kinderschutzschulung absolvieren, bevor sie Kinderverifizierungen durchführen
- Die Kinderschutzgesetze in ihrer Rechtsordnung verstehen
- Sich der Schutzindikatoren und Meldepflichten bewusst sein
- Den Benutzer-gibt-ein-Verifizierer-bestätigt-Zeremonienablauf verstehen und nicht versuchen, Daten im Auftrag von Benutzern einzugeben
- Die Schulung jährlich auffrischen

### 12.2 Personalschulung

Alle am Protokollentwicklung, -betrieb oder -support beteiligten Mitarbeiter müssen:
- Eine Kinderschutzsensibilisierungsschulung absolvieren
- Diese Richtlinie und ihre Verpflichtungen daraus verstehen
- Wissen, wie Kinderschutzbedenken gemeldet werden

---

## 13. Verantwortlichkeit

### 13.1 Designierter Kinderschutzbeauftragter

Das Signet-Protokoll benennt einen Kinderschutzbeauftragten, der verantwortlich ist für:
- Überwachung der Umsetzung dieser Richtlinie
- Koordination mit dem Datenschutzbeauftragten in Kinderdatenschutzfragen
- Verwaltung der Reaktion auf Kinderschutzvorfälle
- Zusammenarbeit mit Kinderschutzbehörden und -organisationen

### 13.2 Aufzeichnungsführung

Das Signet-Protokoll führt Aufzeichnungen über:
- Kinderschutz-Folgenabschätzungen
- Aufzeichnungen über elterliche Einwilligung
- Kinderschutzvorfälle und Reaktionen
- Schulungsunterlagen
- Richtlinienüberprüfungen und -aktualisierungen

### 13.3 Externe Aufsicht

Das Signet-Protokoll ist der Transparenz verpflichtet und begrüßt die Aufsicht durch:
- Zuständige Regulierungsbehörden
- Kinderschutzorganisationen
- Unabhängige Prüfer
- Die Open-Source-Gemeinschaft

---

## 14. Kontakt

Bei Fragen, Bedenken oder Meldungen im Zusammenhang mit dem Kinderschutz:

**Kinderschutzbeauftragter:** signet-safety@signetprotocol.org *(Platzhalter — vor der Bereitstellung aktualisieren)*
**Datenschutzbeauftragter:** signet-dpo@signetprotocol.org *(Platzhalter — vor der Bereitstellung aktualisieren)*

**Notfallmeldung (vermutete Kinderausbeutung):**
- UK: Internet Watch Foundation — [https://www.iwf.org.uk](https://www.iwf.org.uk)
- US: NCMEC CyberTipline — [https://www.missingkids.org](https://www.missingkids.org)
- EU: INHOPE — [https://www.inhope.org](https://www.inhope.org)
- AU: eSafety Commissioner — [https://www.esafety.gov.au](https://www.esafety.gov.au)

---

*Diese Richtlinie zum Kinderschutz ist als Vorlage für das Signet-Protokoll vorgesehen. Sie stellt keine Rechtsberatung dar. Das Signet-Protokoll empfiehlt, vor der Bereitstellung qualifizierten Rechtsrat einzuholen, der mit den anwendbaren Kinderschutzgesetzen in Ihrer Rechtsordnung vertraut ist.*

*Das Signet-Protokoll — v0.1.0*
*Dokumentversion: 1.0*
*März 2026*
