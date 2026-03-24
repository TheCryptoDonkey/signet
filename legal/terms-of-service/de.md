---
**Hinweis zur KI-generierten Übersetzung**

Dieses Dokument wurde aus dem Englischen mithilfe von KI (Claude, Anthropic) übersetzt. Es dient ausschließlich als Referenz. Die englische Version unter `en.md` ist das einzige rechtsverbindliche Dokument. Diese Übersetzung wurde nicht von einem qualifizierten Rechtsübersetzer geprüft. Bei Abweichungen zwischen dieser Übersetzung und dem englischen Original hat die englische Fassung Vorrang.

---

# Nutzungsbedingungen

**Das Signet-Protokoll — v0.1.0**
**Datum des Inkrafttretens:** 17. März 2026
**Zuletzt aktualisiert:** 17. März 2026

*Dieses Dokument deckt Ihre Nutzung von My Signet (der Referenz-App) und der Signet-Protokoll-Bibliotheken ab, einschließlich des signet-verify.js SDK. Es stellt keine Rechtsberatung dar. Holen Sie sich qualifizierten Rechtsrat für Ihre Rechtsordnung ein, bevor Sie sich für einen Produktivbetrieb darauf verlassen.*

---

## Inhaltsverzeichnis

1. [Annahme der Bedingungen](#1-annahme-der-bedingungen)
2. [Berechtigung](#2-berechtigung)
3. [Beschreibung des Protokolls und der App](#3-beschreibung-des-protokolls-und-der-app)
4. [Schlüsselverwaltung und Kontosicherheit](#4-schlüsselverwaltung-und-kontosicherheit)
5. [Die Verifizierungszeremonie](#5-die-verifizierungszeremonie)
6. [Nachweis-Lebenszyklus](#6-nachweis-lebenszyklus)
7. [Benutzerpflichten](#7-benutzerpflichten)
8. [Verifizierer-Pflichten](#8-verifizierer-pflichten)
9. [Website-Betreiber und das signet-verify.js SDK](#9-website-betreiber-und-das-signet-verifyjs-sdk)
10. [Der Verifizierungsbot](#10-der-verifizierungsbot)
11. [Signet-IQ-Werte](#11-signet-iq-werte)
12. [Datenschutz](#12-datenschutz)
13. [Geistiges Eigentum](#13-geistiges-eigentum)
14. [Haftungsausschlüsse](#14-haftungsausschlüsse)
15. [Haftungsbeschränkung](#15-haftungsbeschränkung)
16. [Freistellung](#16-freistellung)
17. [Anwendbares Recht und Streitbeilegung](#17-anwendbares-recht-und-streitbeilegung)
18. [Kündigung](#18-kündigung)
19. [Änderungen](#19-änderungen)
20. [Allgemeine Bestimmungen](#20-allgemeine-bestimmungen)
21. [Kontakt](#21-kontakt)
22. [Rechtsordnungsspezifische Anhänge](#22-rechtsordnungsspezifische-anhänge)

---

## 1. Annahme der Bedingungen

Durch den Zugriff auf, das Herunterladen oder die Nutzung von My Signet (der „App"), der Signet-Protokoll-Bibliotheken oder des signet-verify.js SDK (zusammen „das Protokoll") oder durch das Handeln als Verifizierer erklären Sie sich („Sie" oder „Benutzer") einverstanden, durch diese Nutzungsbedingungen („Bedingungen") gebunden zu sein.

Wenn Sie diesen Bedingungen nicht zustimmen, dürfen Sie das Protokoll nicht nutzen.

Wenn Sie das Protokoll im Namen einer Organisation nutzen, versichern Sie, dass Sie die Befugnis haben, diese Organisation zu binden, und „Sie" schließt diese Organisation ein.

**Verifizierer:** Durch die Veröffentlichung eines Art-31000-Verifizierer-Nachweis-Ereignisses im Nostr-Netzwerk oder durch die Durchführung einer Signet-Verifizierungszeremonie akzeptieren Sie Abschnitt 8 (Verifizierer-Pflichten) als rechtsverbindliche Bedingung Ihrer Teilnahme. Sie müssen kein separates Dokument unterzeichnen. Die Durchführung einer Verifizierung ist Ihre Annahme.

---

## 2. Berechtigung

### 2.1 Allgemeine Berechtigung

Um das Protokoll zu nutzen, müssen Sie:

- Die Rechtsfähigkeit besitzen, in Ihrer Rechtsordnung eine verbindliche Vereinbarung einzugehen
- Nicht durch anwendbares Recht von der Nutzung des Protokolls ausgeschlossen sein
- Nicht wegen eines wesentlichen Verstoßes gegen diese Bedingungen vom Protokoll ausgeschlossen worden sein

### 2.2 Altersanforderungen

| Rechtsordnung | Mindestalter — eigenes Konto | Mit verifizierter elterlicher Einwilligung |
|---|---|---|
| Europäische Union (Standard) | 16 | 13 (je nach Mitgliedstaat) |
| Vereinigtes Königreich | 13 | Nicht anwendbar |
| Vereinigte Staaten | 13 | Unter 13 mit COPPA-konformer elterlicher Einwilligung |
| Brasilien | 18 | 12 mit elterlicher Einwilligung |
| Südkorea | 14 | Unter 14 mit elterlicher Einwilligung |
| Japan | 15 | Unter 15 mit elterlicher Einwilligung |
| Indien | 18 | Gemäß DPDP-Gesetz |
| Andere | Digitales Einwilligungsalter | Gemäß lokalem Recht |

Kinder unter dem digitalen Einwilligungsalter ihrer Rechtsordnung dürfen nur ein Signet-Konto als Unterkonto eines verifizierten Elternteils oder Vormunds haben (siehe Abschnitt 6.7).

### 2.3 Verifizierer-Berechtigung

Um als professioneller Verifizierer zu handeln und Stufe-3- oder Stufe-4-Nachweise auszustellen, müssen Sie:

- Eine aktuelle, gültige professionelle Registrierung in gutem Stand bei der zuständigen Regulierungsbehörde besitzen
- Zur Berufsausübung in der Rechtsordnung berechtigt sein, in der Sie Verifizierungen durchführen
- Keiner Suspendierung, Einschränkung oder Disziplinarverfahren unterliegen, die Ihre Fähigkeit zur Identitätsverifizierung beeinträchtigen würden
- Eine angemessene Berufshaftpflichtversicherung für Ihre Verifizierungstätigkeiten unterhalten

Die vollständige Liste der berechtigten Berufe finden Sie in Abschnitt 8.2.

---

## 3. Beschreibung des Protokolls und der App

### 3.1 Überblick

Das Signet-Protokoll ist ein dezentralisiertes Identitätsverifizierungsprotokoll für das Nostr-Netzwerk. Es ermöglicht Benutzern, Ansprüche bezüglich ihrer Identität zu beweisen — einschließlich Alter, Elternschaft und Berufsstatus — unter Verwendung von Zero-Knowledge-Beweisen und Ringsignaturen, ohne zugrunde liegende personenbezogene Daten preiszugeben. Es gibt keine zentrale Datenbank, keine zentrale Behörde und keine einzelne Organisation, die das Netzwerk kontrolliert.

**My Signet** ist die Referenz-App. Es ist eine Progressive Web App (PWA), die in Ihrem Browser läuft. Es ist eine Anwendung, die von allen genutzt wird: Einzelpersonen, Verifizierern und Gemeinschaften.

### 3.2 Verifizierungsstufen

| Stufe | Name | Bedeutung |
|---|---|---|
| 1 | Selbstdeklariert | Sie haben ein Konto erstellt und einige Attribute deklariert. Keine externe Prüfung. Niedrigstes Vertrauen. |
| 2 | Web-of-Trust | Andere Benutzer, die Sie kennen, haben für Sie gebürgt. Vertrauen wird aus dem Netzwerk abgeleitet. |
| 3 | Professionelle Verifizierung (Erwachsener) | Ein lizenzierter Fachmann hat Ihr von der Regierung ausgestelltes Identitätsdokument persönlich verifiziert und zwei Nachweise über die Zwei-Nachweis-Zeremonie ausgestellt. |
| 4 | Professionelle Verifizierung (Erwachsener + Kind) | Stufe 3 erweitert um ein Kindkonto, wobei die Beziehung des Kindes zu einem verifizierten Elternteil/Vormund durch einen Fachmann bestätigt wird. |

### 3.3 Nostr-Ereignisarten

Das Protokoll verwendet die folgenden Nostr-Ereignisarten:

| Art | Zweck |
|---|---|
| 31000 | Nachweis-Ereignisse |
| 31000 | Bürgschaftsbeglaubigungen |
| 30078 | Community-Verifizierungsrichtlinien |
| 31000 | Verifizierer-Registrierungsnachweise |
| 31000 | Challenge-Ereignisse |
| 31000 | Widerrufsereignisse |
| 31000 | Identitätsbrücken-Ereignisse |
| 31000 | Delegierungsereignisse (Vormund und Agent) |
| 30482–30484 | Abstimmungserweiterung (Wahl, Stimmzettel, Ergebnis) |

Ereignisart-Nummern stehen noch unter finaler NIP-Zuweisung.

### 3.4 Kryptografischer Stack

Das Protokoll verwendet:

- Schnorr-Signaturen auf der secp256k1-Kurve (Basisschicht)
- Bulletproofs für Altersbereich-Zero-Knowledge-Beweise
- Spontaneous Anonymous Group (SAG) und Linkable SAG (LSAG) Ringsignaturen für Aussteller-Privatsphäre
- PBKDF2 (600.000 Iterationen, SHA-256) mit AES-256-GCM für lokale Nachweis-Speicherung
- Eine zukünftige ZK-Schicht (ZK-SNARKs oder ZK-STARKs) ist für kryptografische Vollständigkeit der Ebene 3 geplant

### 3.5 Dezentralisierte Natur

Das Signet-Protokoll operiert im Nostr-Netzwerk. Wir entwickeln und pflegen die Protokollspezifikation, kontrollieren jedoch weder das Netzwerk, noch Relay-Betreiber oder einzelne Teilnehmer. Im Nostr-Netzwerk veröffentlichte Ereignisse sind öffentlich, dauerhaft und werden von Relay-Betreibern repliziert, die wir nicht kontrollieren.

---

## 4. Schlüsselverwaltung und Kontosicherheit

### 4.1 Zwei-Schlüsselpaar-Modell

My Signet leitet zwei unabhängige Schlüsselpaare von einer einzigen 12-Wort-BIP-39-Mnemonic ab:

- **Natural-Person-Schlüsselpaar:** Für Ihren Realidentitäts-Nachweis (Name, Dokument, Nullifier, Merkle-Root) verwendet. Dieses Schlüsselpaar wird nur verwendet, wenn Sie sich ausdrücklich dafür entscheiden, Ihre verifizierte echte Identität vorzulegen.
- **Persona-Schlüsselpaar:** Ein anonymes Alias. Es trägt einen von der Verifizierungszeremonie übernommenen Altersbereichsnachweis, aber keinen Namen, keine Dokumentreferenz und keinen Nullifier. Alle Ihre alltäglichen Nostr-Aktivitäten können dieses Schlüsselpaar verwenden.

Während des Onboardings wählen Sie, welches Schlüsselpaar Ihr primäres Konto für dieses Gerät ist. Sie können jederzeit wechseln. Die Verbindung zwischen Ihren beiden Schlüsselpaaren ist nur Ihnen und Ihrem Verifizierer bekannt (geschützt durch deren berufliche Vertraulichkeitspflichten).

### 4.2 Einzelschlüsselpaar-Modus (nsec-Import)

Wenn Sie ein bestehender Nostr-Benutzer sind, können Sie Ihren bestehenden privaten Schlüssel (nsec) importieren. Im Einzelschlüsselpaar-Modus wird Ihr bestehender npub zu Ihrer Natural-Person-Identität, und Sie können eine Identitätsbrücke (Art-31000-Ereignis) erstellen, um ihn mit einem Persona-Konto zu verknüpfen. Alle Ihre bestehenden Follower, NIP-05, Zaps und Reputation bleiben erhalten.

### 4.3 Schlüsselgenerierung und Backup

- Ihre Mnemonic wird lokal in der App mit kryptografisch sicherer Zufälligkeit generiert. Sie wird niemals an einen Server übermittelt.
- Sie sind allein verantwortlich für das Backup Ihrer Mnemonic. Wir können sie nicht wiederherstellen. Wenn Sie Ihre Mnemonic und Ihr Gerät verlieren, kann Ihr Konto ohne eine neue professionelle Verifizierung nicht wiederhergestellt werden.
- Kindkonten können bei verschiedenen BIP-44-Konto-Indizes aus derselben Eltern-Mnemonic abgeleitet werden, wodurch das Schlüsselmanagement der Familie unter einer Wiederherstellungsphrase gehalten wird.
- Shamir-Secret-Sharing-Backup (über `@scure/bip39`) wird für die Aufteilung der Mnemonic auf vertrauenswürdige Verwahrer unterstützt.

### 4.4 Biometrische und PIN-Authentifizierung

My Signet erfordert Authentifizierung für den Zugriff auf Ihren privaten Schlüssel:

- **Biometrisch (bevorzugt):** Verwendet WebAuthn mit der PRF-Erweiterung, wo verfügbar. Ihre Biometrie verlässt nie Ihr Gerät. Wo PRF unterstützt wird, ist das Schlüsselmaterial hardware-abgeleitet und kann nicht aus localStorage extrahiert werden, selbst nicht von Code, der auf demselben Gerät läuft.
- **PIN-Fallback:** Wo biometrische Authentifizierung nicht verfügbar ist, ist eine PIN erforderlich. Die PIN wird mit PBKDF2 (600.000 Iterationen) verwendet, um einen AES-256-GCM-Verschlüsselungsschlüssel abzuleiten.
- **Sitzungsverwaltung:** Nach einer Inaktivitätsperiode sperrt sich die App selbst. Sie müssen sich erneut authentifizieren, um fortzufahren. Das Inaktivitäts-Timeout kann in den Einstellungen konfiguriert werden.

Ihr privater Schlüssel wird nie im Klartext gespeichert. Er ist immer im Ruhezustand mit AES-256-GCM verschlüsselt.

### 4.5 Schlüsselkompromittierung

Wenn Sie glauben, dass Ihr privater Schlüssel kompromittiert wurde, müssen Sie mit Ihren ursprünglichen Identitätsdokumenten einen professionellen Verifizierer aufsuchen. Der Verifizierer wird alle Nachweise für Ihr altes Schlüsselpaar widerrufen und neue Nachweise für ein neues Schlüsselpaar ausstellen. Mit dem kompromittierten Schlüssel verbundene Bürgschaften werden nicht übertragen (dies ist eine bewusste Sicherheitsmaßnahme — ein Angreifer, der Ihren Schlüssel kompromittiert hat, kann Ihr soziales Vertrauen nicht beibehalten).

### 4.6 NIP-46 Remote-Signing

My Signet unterstützt NIP-46 Remote-Signing. Dies ermöglicht anderen Anwendungen oder Diensten, die App zu bitten, Nostr-Ereignisse in ihrem Auftrag zu unterzeichnen. Jede Signing-Anfrage erfordert Ihre ausdrückliche Genehmigung. Die App zeigt die Anfragedetails an, bevor Sie sie genehmigen oder ablehnen. Sie dürfen keine Anfragen genehmigen, die Sie nicht erkennen oder verstehen.

---

## 5. Die Verifizierungszeremonie

### 5.1 Ablauf der professionellen Verifizierung

Stufe-3- und Stufe-4-Nachweise werden durch die Zwei-Nachweis-Zeremonie ausgestellt:

1. **Sie geben Ihre Daten ein.** Vor dem Besuch beim Verifizierer geben Sie Ihre eigenen Identitätsattribute (Name, Geburtsdatum, Nationalität, Dokumenttyp und -nummer) in die App ein. Die App berechnet Ihren Merkle-Baum und Ihren Dokumentnullifier vorab.

2. **Sie legen Ihre Dokumente vor.** Sie erscheinen persönlich bei einem professionellen Verifizierer und zeigen Ihr originales, von der Regierung ausgestelltes Identitätsdokument(e).

3. **Der Verifizierer bestätigt oder lehnt ab.** Der Verifizierer prüft Ihre Dokumente, verifiziert, dass Sie die in ihnen beschriebene Person sind, und bestätigt oder lehnt die von Ihnen eingegebenen Daten ab. Der Verifizierer tippt Ihre persönlichen Daten nicht — er bestätigt nur, was Sie eingegeben haben.

4. **Zwei Nachweise werden ausgestellt.** Wenn der Verifizierer die Daten bestätigt, veröffentlicht er zwei Art-31000-Nachweis-Ereignisse — eines für Ihr Natural-Person-Schlüsselpaar (mit Ihrer Merkle-Root und Ihrem Nullifier) und eines für Ihr Persona-Schlüsselpaar (nur mit Ihrem Altersbereichsnachweis). Beide Nachweise werden mit dem professionellen Nostr-Schlüssel des Verifizierers unterzeichnet.

5. **Die Dokumentnummer wird verworfen.** Nach Berechnung des Nullifiers wird die Dokumentnummer nicht vom Protokoll, der App oder (sofern nicht durch berufliche Verpflichtungen erforderlich) dem Verifizierer aufbewahrt.

### 5.2 Wer für die Datengenauigkeit verantwortlich ist

Da Sie Ihre eigenen Identitätsdaten eingeben, tragen Sie die primäre Verantwortung für deren Richtigkeit. Das Eingeben falscher Daten (falscher Name, Dokumentnummer einer anderen Person) ist betrügerisch und kann in Ihrer Rechtsordnung eine Straftat darstellen.

Die Rolle des Verifizierers besteht darin, zu bestätigen, dass die vor ihm stehende Person mit den vorgelegten Dokumenten übereinstimmt. Der Verifizierer garantiert nicht die Vollständigkeit oder Richtigkeit der von Ihnen eingegebenen Daten über das hinaus, was aus den Dokumenten visuell bestätigt werden kann.

### 5.3 Dokumentnullifier

Das Protokoll verwendet dokumentbasierte Nullifier, um zu verhindern, dass dieselbe Person mehrere Stufe-3-Nachweise erhält. Der Nullifier wird berechnet als:

```
SHA-256(LP(docType) || LP(country) || LP(docNumber) || LP("signet-nullifier-v2"))
```

wobei `LP(x)` die UTF-8-Byte-Länge von `x` als 2-Byte-Big-Endian-Integer kodiert, gefolgt von den Bytes von `x`. Diese längenvorzeichenbehaftete Kodierung verhindert Feldgrenz-Kollisionen.

Der Nullifier:
- Ist deterministisch: dasselbe Dokument erzeugt immer denselben Nullifier
- Ist einwegig: die Dokumentnummer kann nicht aus dem Nullifier wiederhergestellt werden
- Ist kollisionsresistent: verschiedene Dokumente erzeugen verschiedene Nullifier
- Ist verifiziererübergreifend konsistent: jeder Verifizierer mit demselben Dokument erzeugt denselben Nullifier

Wenn Sie mehrere Identitätsdokumente vorlegen (z. B. Reisepass und Führerschein), kann der Verifizierer Nullifier für alle Dokumente berechnen und eine Nullifier-Familie bilden. Alle Nullifier der Familie werden im Nachweis veröffentlicht und gegen bestehende Nachweise auf Relays überprüft.

### 5.4 Der Merkle-Baum

Ihre persönlichen Attribute (Name, Geburtsdatum, Nationalität, Dokumenttyp, Dokumentablaufdatum, Nullifier) werden als Blätter in einem Merkle-Baum gespeichert. Nur die Merkle-Root wird on-chain veröffentlicht. Sie können einzelne Attribute durch Bereitstellung eines Merkle-Pfades beweisen, ohne alle Attribute preiszugeben. Der Merkle-Baum verwendet RFC-6962-Domänentrennung (0x00-Präfix für Blatt-Hashes, 0x01 für interne Knoten).

### 5.5 Altersbereichsnachweise

Ihr Geburtsdatum wird nie veröffentlicht. Stattdessen berechnet der Verifizierer einen Bulletproof-Zero-Knowledge-Beweis, dass Ihr Alter in einem bestimmten Bereich liegt (z. B. „18+", „13–17", „8–12"). Der Beweis ist mathematisch verifizierbar, ohne Ihr genaues Alter oder Geburtsdatum preiszugeben.

### 5.6 Kreuz-Verifizierung

Sie können von einem zweiten (oder weiteren) Verifizierer verifiziert werden, indem Sie dieselben Dokumente vorlegen. Da der Nullifier aus Ihren Dokumenten abgeleitet wird, wird derselbe Nullifier erzeugt. Das Protokoll unterscheidet Kreuz-Verifizierung von doppeltem Betrug, indem es prüft, ob der Public Key des Subjekts mit dem bestehenden Nachweis übereinstimmt:

- Gleicher Nullifier + gleicher Pubkey = unabhängige Bestätigung (höherer Signet-IQ-Beitrag)
- Gleicher Nullifier + anderer Pubkey = mögliche Doppelidentität (zur Untersuchung markiert)

Kreuz-Verifizierung ist das stärkste IQ-Signal und repräsentiert unabhängige professionelle Bestätigung derselben Identität.

---

## 6. Nachweis-Lebenszyklus

### 6.1 Nachweis-Ablauf und -Verfall

Professionelle Nachweise enthalten einen `expires`-Tag (den Gültigkeitszeitraum des Nachweises) und ein `documentExpiry`-Merkle-Blatt (wann das zugrunde liegende Dokument abläuft). Diese sind unterschiedlich: Ein Nachweis kann nach zwei Jahren ablaufen, während der Reisepass, auf dem er basiert, noch zehn Jahre gültig ist.

Nachweise laufen am Ablaufdatum nicht abrupt ab. Stattdessen verfällt der IQ-Beitrag eines ablaufenden Nachweises allmählich, wenn sich das Ablaufdatum nähert, anstatt am Ablaufdatum auf null zu fallen. Clients sollten diesen Verfall visuell darstellen (ein langsam dimmender Indikator) anstatt eines binären gültig/ungültig-Zustands.

Wenn das dem Nachweis zugrunde liegende Dokument vor dem Nachweis selbst abläuft, verfällt der IQ-Beitrag schneller — was das geringere Vertrauen in das zugrunde liegende Identitätsdokument widerspiegelt.

### 6.2 Nachweis-Widerruf

Nachweise können durch Veröffentlichung eines Art-31000-Ereignisses widerrufen werden. Widerruf kann initiiert werden durch:

- Sie (Selbstwiderruf — z. B. bei Schlüsselkompromittierung oder Namensänderung)
- Den ausstellenden Verifizierer (aus Gründen, wie entdecktem Betrug)
- Community-Konsens (bei systemischem Betrug oder Sicherheitskompromittierung)

### 6.3 Nachweis-Ketten und Dokumenterneuerung

Wenn sich Ihre realen Attribute ändern (Namensänderung, Dokumenterneuerung, Stufenaufrüstung), wird ein ersetzender Nachweis mit einem `["supersedes", "<old_event_id>"]`-Tag ausgestellt. Clients folgen der Kette, um nur den aktuellen aktiven Nachweis anzuzeigen. Ersetzte Nachweise verbleiben als historische Aufzeichnungen auf Relays.

**Dokumenterneuerung und Nullifier:**
- **Reisepasserneuerung:** Eine neue Reisepassnummer erzeugt einen neuen Nullifier. Der alte und neue Nullifier sind durch einen `["nullifier-chain", "<old_nullifier>"]`-Tag im neuen Nachweis verknüpft.
- **Führerscheinerneuerung (UK):** Die Führerscheinnummer ändert sich bei der Erneuerung typischerweise nicht. Der neue Nachweis referenziert denselben Nullifier.

### 6.4 Detail des Zwei-Nachweis-Modells

| Nachweis | Enthält | Enthält nicht |
|---|---|---|
| Natural Person | Merkle-Root, primärer Nullifier, Nullifier-Familie, Altersbereichsnachweis, Entitätstyp, Guardian-Tags (wenn Kind) | Echter Name, Geburtsdatum, Dokumentnummer |
| Persona | Altersbereichsnachweis, Entitätstyp=Persona, Guardian-Tags (wenn Kind) | Nullifier, Merkle-Root, persönliche Attribute |

### 6.5 Vormund-Delegierung

Ein Vormund (verifizierter Elternteil oder gesetzlicher Vormund) kann bestimmte Berechtigungen über Art-31000-Delegierungsereignisse an vertrauenswürdige Erwachsene delegieren. Delegierungsbereiche umfassen:

- `full` — vollständige Delegierung (z. B. gleichberechtigter Elternteil)
- `activity-approval` — Aktivitäten genehmigen, die elterliche Einwilligung erfordern
- `content-management` — Inhalte und Verbindungen des Kindes verwalten
- `contact-approval` — neue Kontakte genehmigen

Delegierungsereignisse enthalten einen `agent-type`-Tag, der die Beziehung identifiziert (z. B. `teacher`, `grandparent`, `step-parent`). Guardian-Tags in Nachweisen sind unveränderlich — sie können nur durch einen neuen Nachweis geändert werden, der von einem Fachmann mit entsprechender rechtlicher Dokumentation ausgestellt wird.

### 6.6 Kind-Unterkonten

Ein Kind-Nachweis ist ein Unterkonto eines verifizierten Elternteils oder Vormunds:

- Der Kind-Nachweis muss Guardian-Tags enthalten, die zu einem Stufe-3+-verifizierten Elternteil oder Vormund verlinken
- Das Kind muss während der Stufe-4-Verifizierungszeremonie anwesend sein (persönlich oder durch ein rechtlich gleichwertiges Verfahren)
- Wenn das Kind 18 Jahre wird, erhält es einen neuen Stufe-3-Nachweis ohne Guardian-Tags, der den Kind-Nachweis ersetzt
- Ein Kind kann keinen Persona-Nachweis mit einer höheren Altersbereichsbehauptung als seinem verifizierten Altersbereich halten

### 6.7 Persona-Konten

Eine Persona ist ein anonymes Alias:

- Eine Persona trägt keine persönlich identifizierenden Informationen — keinen Namen, keinen Nullifier, keine Merkle-Root
- Eine Persona übernimmt den Altersbereichsnachweis von der Zwei-Nachweis-Zeremonie
- Eine Persona kann über eine Identitätsbrücke (Art 31000) unter Verwendung von Ringsignaturen mit einer Natural Person verknüpft werden, was der Persona ermöglicht, „Ich bin eine echte, verifizierte Person" zu beweisen, ohne preiszugeben, welche Person
- Sie sind verantwortlich für alle Aktivitäten, die über Ihre Persona-Konten durchgeführt werden

### 6.8 Keine Garantie der Akzeptanz

Wir garantieren nicht, dass ein Nachweis von einer vertrauenden Partei akzeptiert wird. Gemeinschaften legen ihre eigenen Akzeptanzrichtlinien durch Art-30078-Richtlinienereignisse fest.

### 6.9 Dokumenten-Wallet

My Signet unterstützt eine Dokumenten-Wallet mit mehreren Identitätsdokumenten. Jedes Dokument erzeugt seinen eigenen Nachweis und seinen eigenen Nullifier. Dies ermöglicht progressive Verifizierung: Sie können im Laufe der Zeit Dokumente hinzufügen, wobei jedes zusätzliche Dokument Ihre Nullifier-Familie stärkt und zu Ihrem Signet IQ beiträgt.

---

## 7. Benutzerpflichten

### 7.1 Allgemeine Pflichten

Alle Benutzer müssen:

1. **Genauigkeit.** Beim Erstellen von Nachweisen wahrheitsgemäße Informationen eingeben. Betrügerische Nachweise untergraben das Vertrauensmodell und können kriminellen Betrug darstellen.
2. **Schlüsselsicherheit.** Ihre Mnemonic und Ihren privaten Schlüssel schützen. Sie sind allein verantwortlich für deren Sicherheit.
3. **Compliance.** Alle anwendbaren Gesetze und Vorschriften einhalten.
4. **Verantwortungsvolle Nutzung.** Das Protokoll in gutem Glauben und nicht für illegale, betrügerische oder schädliche Zwecke verwenden.
5. **Meldung.** Sicherheitslücken, Nachweis-Betrug oder Protokollmissbrauch umgehend der Kontaktadresse in Abschnitt 21 melden.

### 7.2 Verbotene Verwendungen

Sie dürfen nicht:

1. Falsche, irreführende oder betrügerische Nachweise erstellen
2. Eine andere Person oder Entität vortäuschen
3. Versuchen, Zero-Knowledge-Beweise rückzuentwickeln, um personenbezogene Daten zu extrahieren
4. Das Protokoll zur Erleichterung illegaler Aktivitäten nutzen, einschließlich Identitätsdiebstahl, Betrug, Geldwäsche, Terrorismusfinanzierung oder Kinderausbeutung
5. Die kryptografische Infrastruktur des Protokolls angreifen oder versuchen, die Anonymitätssätze der Ringsignaturen zu brechen
6. Das Netzwerk mit illegitimen Nachweis-, Bürgschafts- oder Challenge-Ereignissen spammen
7. Mit Verifizierern zusammenarbeiten, um ungerechtfertigte Stufe-3- oder Stufe-4-Nachweise zu erlangen
8. Automatisierte Systeme zur Massenerzeu­gung von Nachweisen oder Bürgschaften ohne echte Verifizierung verwenden
9. Das Protokoll oder das Nostr-Netzwerk stören oder unterbrechen
10. Das Protokoll zur Umgehung von Altersbeschränkungen oder Kinderschutzmaßnahmen ausnutzen

### 7.3 Bürgschaftspflichten (Stufe 2)

Beim Bürgen für einen anderen Benutzer (Art-31000-Ereignis):

- Sie müssen eine echte, persönliche Grundlage für die Bürgschaft haben
- Sie dürfen keine Zahlung oder andere Gegenleistung für die Bürgschaft annehmen
- Sie können eine Bürgschaft jederzeit durch Veröffentlichung eines Widerrufsereignisses widerrufen
- Ihr Bürgschaftsverhalten beeinflusst Ihren eigenen Signet IQ

---

## 8. Verifizierer-Pflichten

### 8.1 Warum es keine separate Vereinbarung gibt

Wir haben die Verifizierer-Vereinbarung in diese Bedingungen integriert, weil diejenigen, die Kinder am wahrscheinlichsten verifizieren — Lehrkräfte bei Elternabenden, Hausärzte, Sozialarbeiter — kein zweites Rechtsdokument navigieren sollten. Durch das Handeln als Signet-Verifizierer (Veröffentlichung eines Art-31000-Ereignisses oder Durchführung einer Zeremonie) akzeptieren Sie die Verpflichtungen in diesem Abschnitt. Diese Verpflichtungen ergänzen Ihre bestehenden beruflichen Pflichten und ersetzen sie nicht.

### 8.2 Berechtigte Berufe

Sie können als Signet-Verifizierer handeln, wenn Sie eine aktuelle, gültige Registrierung bei einer anerkannten Regulierungsbehörde in einer der folgenden Kategorien besitzen. Diese Liste folgt dem UK-Reisepass-Gegenzeichnungsstandard und seinen internationalen Äquivalenten.

**Rechtsberufe:** Solicitor, Barrister, Anwalt, Attorney-at-law, Legal Executive, Notary Public, Commissaire de Justice, Notar, Licensed Conveyancer, Chartered Legal Executive.

**Medizin- und Gesundheitsberufe:** Arzt, Chirurg, Hausarzt, Zahnarzt, Apotheker, Optiker/Optometrist, Krankenpfleger (wo national erlaubt), Physiotherapeut, Klinischer Psychologe, gemeindenaher oder krankenhausansässiger Gesundheitsberuf, der bei einem nationalen Gremium registriert ist (GMC, NMC, GDC, GPhC, HCPC oder Äquivalent).

**Bildungsberufe:** Qualifizierte Lehrkraft (registriert bei der Teaching Regulation Agency oder nationalem Äquivalent), Schulleiter oder stellvertretender Schulleiter, weiter- oder hochschulischer Dozent, der bei einem Berufsverband registriert ist, Schulinspektor.

**Finanzberufe:** Chartered Accountant (ICAEW, ICAS, ACCA, CIMA, CPA oder Äquivalent), Chartered Certified Accountant, Lizenzierter Prüfer, Unabhängiger Finanzberater, der von einem nationalen Finanzregulator zugelassen ist, Bankbeamter oder Bausparkasse der Offiziersstufe.

**Öffentliche Dienste und Notfallberufe:** Polizeibeamter, Feuerwehrbeamter, Angehöriger der britischen Streitkräfte (Offizier), Richter, Schiedsrichter, Friedensrichter, Crown Prosecution Service Beamter, Bewährungshelfer, Sozialarbeiter, der bei einem nationalen Regulierungsgremium registriert ist.

**Glaubens- und Gemeinschaftsberufe:** Geistlicher, Glaubensführer, der als solcher von einer eingetragenen Konfession anerkannt ist, Standesbeamter.

**Ingenieur-, Wissenschafts- und Technikberufe:** Chartered Engineer (registriert bei einem nationalen Ingenieursinstitut), Chartered Scientist, Architekt (registriert beim Architects Registration Board oder Äquivalent), Chartered Surveyor.

**Andere regulierte Berufe:** Jeder Beruf, der durch eine gesetzliche Stelle reguliert wird, deren Register öffentlich durchsuchbar ist und deren Mitglieder Berufseignungsverfahren unterliegen. Kontaktieren Sie uns im Zweifelsfall, bevor Sie Verifizierungen durchführen.

In allen Fällen müssen Sie in gutem Stand sein (nicht Gegenstand von Suspendierung, Einschränkung oder laufenden Disziplinarverfahren, die Ihre Eignung zur Identitätsverifizierung beeinträchtigen).

### 8.3 Registrierung

Zur Registrierung als Verifizierer:

1. Veröffentlichen Sie ein Art-31000-Verifizierer-Nachweis-Ereignis auf Nostr mit Ihrer Berufskategorie, Rechtsordnung, Lizenzierungsbehörde und Lizenzreferenz.
2. Erhalten Sie mindestens zwei Bürgschaften von anderen verifizierten Signet-Fachleuten aus mindestens zwei verschiedenen Berufen (berufsfachübergreifendes Bürgen verhindert Kollussionsringe aus einem einzigen Beruf).
3. Die Registrierung impliziert keine Billigung durch uns.

### 8.4 Durchführung von Stufe-3-Verifizierungen (Erwachsener)

Bei der Durchführung einer Stufe-3-(Erwachsener-)Verifizierung müssen Sie:

1. Identität persönlich oder durch ein rechtlich gleichwertiges Fernverfahren verifizieren, das durch Recht in der jeweiligen Rechtsordnung ausdrücklich erlaubt ist. Fernverifizierung ist die Ausnahme, nicht die Regel.
2. Mindestens ein originales, von der Regierung ausgestelltes Lichtbildausweis-Dokument (Reisepass, nationaler Ausweis oder Führerschein) prüfen. Digitale Dokumentenprüfung (einschließlich eIDAS-Wallet-Nachweise, wo verfügbar) ist erlaubt, wenn nationales Recht sie als gleichwertig zur physischen Prüfung behandelt.
3. Bestätigen, dass die vor Ihnen stehende Person mit dem Dokument übereinstimmt.
4. Die vom Subjekt vorab in die App eingegebenen Daten bestätigen (oder ablehnen). Sie bestätigen, was Sie sehen; Sie geben keine Daten im Namen des Subjekts ein.
5. Den Dokumentnullifier und, wo mehrere Dokumente vorgelegt werden, die Nullifier-Familie berechnen.
6. Den Natural-Person-Nachweis (Art 31000) und den Persona-Nachweis (Art 31000) über die Zwei-Nachweis-Zeremonie ausstellen.
7. Die Dokumentnummer nach der Nullifier-Berechnung verwerfen. Speichern Sie sie nicht, sofern Ihre beruflichen Verpflichtungen dies nicht unabhängig erfordern.
8. Aufzeichnungen über die Verifizierung führen (Datum, Ort, Identität des Subjekts, geprüfte Dokumente, Nullifier-Hash, beide Pubkeys) für den Zeitraum, der durch Ihre beruflichen Verpflichtungen gefordert wird — typischerweise mindestens sechs Jahre.

**Bestätigungsmethoden und IQ-Gewicht:**

| Methode | Beschreibung | IQ-Beitragsgewicht |
|---|---|---|
| A — Persönlich, physisches Dokument | Sie prüfen ein originales Dokument und die Person physisch, von Angesicht zu Angesicht | Volles Gewicht |
| B — Persönlich, digitales Dokument | Persönliches Treffen; Subjekt präsentiert eine eIDAS-Wallet oder gleichwertigen staatlich verifizierten digitalen Ausweis | Volles Gewicht (wo Gesetz als gleichwertig behandelt) |
| C — Fern, reguliert | Videoanruf mit behördlicher Genehmigung und Lebendheitsprüfung; Originaldokumente kuriervermittelt oder hochauflösend präsentiert | Reduziertes Gewicht |
| D — Fern, nicht reguliert | Jedes Fernverfahren, das nicht von C abgedeckt wird | Für Stufe 3 oder Stufe 4 nicht erlaubt |

Die Verifizierungsmethode wird im Nachweis aufgezeichnet (`["method", "in-person-id"]` oder gleichwertiges Tag). Clients und vertrauende Parteien können die Akzeptanz auf bestimmte Methoden beschränken.

### 8.5 Durchführung von Stufe-4-Verifizierungen (Erwachsener + Kind)

Bei der Durchführung einer Stufe-4-(Erwachsener + Kind-)Verifizierung müssen Sie alle Stufe-3-Verpflichtungen einhalten und zusätzlich:

1. **Die Identität des Kindes verifizieren** unter Verwendung geeigneter Dokumente (Geburtsurkunde, Reisepass oder andere Dokumente, die nach Ihrem fachlichen Urteil angemessen sind).
2. **Die Eltern-Vormund-Beziehung verifizieren** durch Dokumentation: Geburtsurkunde (biologisches Elternteil), gerichtlich ausgestellte Vormundschaftsverfügung (gesetzlicher Vormund), Adoptionspapiere (Adoptivelternteil) oder Stiefeltternverantwortungsverfügung.
3. **Lehrkräfte und schulbasierte Verifizierer:** Sie können Ihr Fachwissen und die Schulanmeldungsunterlagen (die bereits Geburtsurkunden-Verifizierung beinhalten) als Nachweis anstelle von oder zusätzlich zu Originaldokumenten verwenden. Das Geburtsdatum des Kindes ist bereits in den Schulunterlagen. Ein Elternteil, das seinen Reisepass bei einem Elternabend vorlegt, ist für eine Stufe-4-Verifizierung in derselben Sitzung ausreichend.
4. **Elterliche Einwilligung für den Nachweis des Kindes einholen**, dokumentiert gemäß anwendbarem Kinderschutzrecht.
5. **Die Verifizierung mit dem anwesenden Kind durchführen**, wo immer möglich.
6. **Das Wohlbefinden des Kindes beurteilen.** Üben Sie Ihr fachliches Urteil aus, um Anzeichen von Zwang, Ausbeutung oder Schutzbedenken zu identifizieren. Wenn solche Bedenken auftreten, fahren Sie nicht fort und befolgen Sie Ihre Meldepflichten gemäß anwendbarem Recht.
7. Zwei Nachweise für das Kind ausstellen (Natural Person + Persona), die beide den Altersbereichsnachweis des Kindes und Guardian-Tags tragen, die das Kind mit seinem verifizierten Elternteil oder Vormund verknüpfen.

### 8.6 Verbotene Verifizierer-Aktionen

Sie dürfen nicht:

1. Nachweise für jemanden ausstellen, dessen Identität Sie nicht wirklich bestätigt haben
2. Zahlung, Geschenke oder andere Gegenleistungen für unberechtigte Verifizierungen annehmen
3. Einer anderen Person erlauben, Verifizierungen mit Ihren Nachweisen oder Ihrem Nostr-Schlüssel durchzuführen
4. Verifizierungen für Familienmitglieder oder enge persönliche Bekannte ohne vorherige Offenlegung und Genehmigung durchführen
5. Selbst verifizieren — Stufe-3- oder Stufe-4-Nachweise für sich selbst ausstellen
6. Kopien von Identitätsdokumenten über das hinaus aufbewahren, was Ihre beruflichen Verpflichtungen erfordern
7. Während Verifizierungen erhaltene Daten für einen anderen Zweck als die Verifizierung selbst und erforderliche Aufzeichnungsführung verwenden
8. Details von Verifizierungen an Dritte weitergeben, außer wenn gesetzlich vorgeschrieben

### 8.7 Verifizierer-Meldepflichten

Sie müssen uns umgehend melden:

- Jede Kompromittierung oder vermutete Kompromittierung Ihres Nostr-Private-Keys
- Jede Entdeckung, dass Sie zuvor eine betrügerische oder fehlerhafte Verifizierung ausgestellt haben
- Jede Änderung Ihres professionellen Registrierungsstatus (Suspendierung, Einschränkung, Widerruf, Disziplinarverfahren)
- Jede Datenverletzung, die Ihre Verifizierungsaufzeichnungen betrifft
- Jedes Rechtsverfahren, jede Untersuchung oder behördliche Maßnahme in Bezug auf Ihre Verifizierungsaktivitäten
- Jeden Interessenkonflikt in Verbindung mit einer Verifizierung

### 8.8 Verifizierer-Haftung

Sie sind unabhängig verantwortlich für die Genauigkeit und Integrität Ihrer Verifizierungen. Da Sie vom Subjekt eingegebene Daten bestätigen, bezieht sich Ihre Haftung speziell auf:

- Bestätigung von Daten, die Sie tatsächlich nicht verifiziert haben oder von denen Sie wussten oder hätten wissen müssen, dass sie falsch sind
- Versäumnis, Dokumentenfälschung zu identifizieren, die ein vernünftig kompetenter Fachmann in Ihrem Bereich identifiziert hätte
- Versäumnis, Schutzbedenken bei Stufe-4-Verifizierungen zu identifizieren
- Verletzung Ihrer beruflichen Verpflichtungen und anwendbaren Rechts

Wir beaufsichtigen, billigen oder garantieren nicht die Qualität der Arbeit einzelner Verifizierer. Wir haften nicht gesamtschuldnerisch oder stellvertretend für Ihre Handlungen oder Unterlassungen. Sie sind ein unabhängiger Fachmann, nicht unser Mitarbeiter, Agent oder Partner.

### 8.9 Versicherung

Sie sollten eine für Ihre Verifizierungstätigkeiten angemessene Berufshaftpflichtversicherung unterhalten. Das angemessene Niveau hängt von den bestehenden Anforderungen Ihres Berufs ab. Wenn Ihr Beruf bereits eine Berufshaftpflichtversicherung vorschreibt (wie die meisten Berufe in Abschnitt 8.2), sollte diese Deckung Ihre Signet-Verifizierungstätigkeiten abdecken, sofern sie in den Rahmen Ihrer allgemeinen Berufspraxis fallen.

### 8.10 Verifizierer-Kündigung

Ihr Verifizierer-Status kann gekündigt werden:

**Sofort und ohne Ankündigung, wenn:** Ihre Berufslizenz suspendiert oder widerrufen wird; Sie betrügerische Verifizierungen ausgestellt haben; Ihr Nostr-Private-Key kompromittiert wurde; Sie Kinderschutzverpflichtungen verletzt haben; oder Sie eine Straftat in Zusammenhang mit Ihren Verifizierungsaktivitäten begangen haben.

**Mit 30-tägiger Ankündigung, wenn:** Sie wesentlich gegen diese Bedingungen verstoßen und dies nicht innerhalb von 14 Tagen beheben; Sie die Berechtigungsanforderungen nicht mehr erfüllen; oder das Protokoll eingestellt wird.

Bei Kündigung wird Ihr Art-31000-Verifizierer-Nachweis widerrufen. Zuvor ausgestellte Nachweise bleiben gültig, sofern sie nicht einzeln widerrufen werden. Sie müssen Verifizierungsaufzeichnungen für den erforderlichen Aufbewahrungszeitraum aufbewahren.

---

## 9. Website-Betreiber und das signet-verify.js SDK

### 9.1 Für wen dieser Abschnitt gilt

Dieser Abschnitt gilt für jede Person oder Organisation, die das signet-verify.js SDK integriert oder auf andere Weise Signet-Protokoll-APIs von einer Website oder Anwendung aus aufruft, um die Identität oder das Alter ihrer Benutzer zu verifizieren („Website-Betreiber").

### 9.2 Was das SDK bereitstellt

Wenn ein Benutzer einen Signet-Nachweis über das SDK Ihrer Website präsentiert, erhalten Sie:

- Einen Altersbereichsnachweis (z. B. „18+", „13–17") — mathematisch verifiziert
- Den Signet-IQ-Wert des Benutzers
- Die Nachweis-Stufe
- Einen Verifizierungs-Zeitstempel

Sie erhalten nicht:

- Den echten Namen des Benutzers
- Das Geburtsdatum oder Alter des Benutzers
- Den Dokumenttyp oder die Dokumentnummer des Benutzers
- Die Adresse des Benutzers oder andere persönlich identifizierende Informationen
- Die Identität des Verifizierers

Das SDK ist so konzipiert, dass Sie die minimalen Informationen erhalten, die für eine Alters- oder Identitäts-Gate-Entscheidung erforderlich sind.

### 9.3 Website-Betreiber-Pflichten

Durch die Integration des SDK erklären Sie sich einverstanden:

1. **Keine Speicherung über die Sitzung hinaus.** Sie dürfen Nachweisdaten, Altersbereichsbehauptungen oder Signet-IQ-Werte nicht über die Dauer der Benutzersitzung hinaus speichern, sofern Sie keine spezifische Rechtsgrundlage dafür nach anwendbarem Datenschutzrecht haben und dies Ihren Benutzern mitgeteilt haben.
2. **Keine Re-Identifizierung.** Sie dürfen nicht versuchen, Benutzer aus den Nachweisdaten zu re-identifizieren oder Nachweisdaten mit anderen Daten zu kombinieren, um Benutzer zu identifizieren.
3. **Kein Profiling.** Sie dürfen Nachweisdaten nicht verwenden, um Profile des Verifizierungsverlaufs oder der Nachweis-Zustände von Benutzern zu erstellen.
4. **Nur genaues Verlassen.** Sie dürfen sich auf den Nachweis nur für den Zweck verlassen, für den er vorgesehen ist — die Bestätigung, dass ein Benutzer einen Alters- oder Identitätsschwellenwert erfüllt. Sie dürfen Dritten gegenüber nicht behaupten, die echte Identität des Benutzers verifiziert zu haben.
5. **Datenschutzhinweis.** Sie müssen in Ihrem Datenschutzhinweis offenlegen, dass Sie Signet-Nachweis-Verifizierung verwenden, und beschreiben, welche Daten Sie erhalten und wie Sie sie verwenden.
6. **Keine Manipulation.** Sie dürfen das SDK nicht auf eine Weise verwenden, die darauf ausgelegt ist, seine Datenschutzschutzmaßnahmen zu umgehen oder Benutzer zu manipulieren, Nachweise vorzulegen, die sie sonst nicht vorlegen würden.
7. **Compliance.** Sie müssen alle anwendbaren Gesetze einhalten, einschließlich Datenschutzgesetze (DSGVO, UK DSGVO, CCPA/CPRA und Äquivalente), bei Ihrer Nutzung des SDK.

### 9.4 SDK-Lizenz

Das signet-verify.js SDK wird unter derselben Open-Source-Lizenz wie die Protokollspezifikation (siehe Protokoll-Repository) bereitgestellt. Sie müssen die Lizenzbedingungen einhalten.

### 9.5 Keine Billigung

Die Integration des SDK impliziert keine Billigung Ihrer Website oder Ihres Dienstes durch uns. Sie dürfen nicht behaupten, dass Signet Ihren Dienst billigt oder zertifiziert.

---

## 10. Der Verifizierungsbot

### 10.1 Was er ist

Der Signet-Verifizierungsbot („der Bot") ist ein automatisierter Dienst, der das Nostr-Netzwerk auf Art-31000-Nachweis-Ereignisse überwacht und auf Anfrage Nachweis-Verifizierungszusammenfassungen bereitstellt. Der Bot kann Antworten auf Anfragen posten, periodische Übersichten veröffentlichen oder auf Erwähnungen reagieren.

### 10.2 Was er verarbeitet

Der Bot verarbeitet nur öffentliche Nostr-Ereignisse. Er liest Art-31000, 31000, 30078, 31000, 31000, 31000 und 31000-Ereignisse von öffentlichen Relays. Er greift nicht auf Ihren privaten Schlüssel, Ihre Mnemonic oder lokal in der App gespeicherte Daten zu.

Der Bot berechnet Signet-IQ-Werte aus öffentlichen On-Chain-Daten. Er erhebt oder speichert keine personenbezogenen Daten über das hinaus, was in öffentlichen Nostr-Ereignissen veröffentlicht ist.

### 10.3 Wer ihn betreibt

Der Bot wird vom Protokollteam betrieben. Sein Nostr-Public-Key wird im Protokoll-Repository veröffentlicht. Dritte können kompatible Verifizierungsbots unter Verwendung der Open-Source-Protokollspezifikation betreiben; Drittanbieter-Bots werden nicht von uns betrieben und sind nicht unsere Verantwortung.

### 10.4 Bot-Einschränkungen

Der Bot bietet einen Best-Effort-Service. Er kann hinter dem Echtzeit-Relay-Status zurückliegen. Er garantiert nicht, dass seine Ausgabe jedes aktuelle Nachweis- oder Widerrufsereignis auf jedem Relay widerspiegelt. Vertrauende Parteien, die Zugangskontrollentscheidungen treffen, sollten Relays direkt abfragen und sich nicht ausschließlich auf Bot-Ausgaben verlassen.

---

## 11. Signet-IQ-Werte

### 11.1 Was Signet IQ ist

Der Signet-IQ-Wert (0–200) ist ein kontinuierlicher Reputationswert, der aus On-Chain-Daten abgeleitet wird. Ein Wert von 100 repräsentiert eine Basislinie, die dem aktuellen britischen/amerikanischen staatlichen Identitätsstandard entspricht. Werte über 100 spiegeln mehrere Verifizierungen, starkes Peer-Vertrauen, Identitätsbrücken und Kontolanglebigkeit wider.

### 11.2 Wie er berechnet wird

Der Wert wird aus gewichteten Beiträgen berechnet, einschließlich:

- Stufe-3- oder Stufe-4-professioneller Verifizierung (höchstes Gewicht)
- Kreuz-Verifizierung durch zusätzliche unabhängige Fachleute
- Persönliche Peer-Bürgschaften von Benutzern mit hohem IQ
- Identitätsbrücken (Art 31000)
- Kontoalter und -aktivität
- Verifizierer-Vertrauenswert (siehe Abschnitt 11.3)

Das Bürgschaftsgewicht skaliert mit dem eigenen Signet IQ des Bürgen. Eine Bürgschaft von jemandem mit IQ 150 trägt mehr Gewicht als eine von jemandem mit IQ 40.

### 11.3 Verifizierer-Vertrauenswerte

Jeder professionelle Verifizierer hat einen Vertrauenswert, der in den IQ-Beitrag der von ihm ausgestellten Nachweise einfließt. Der Vertrauenswert wird abgeleitet aus:

- Bestätigungsmethode (Methode A trägt volles Gewicht; Methode C trägt reduziertes Gewicht — siehe Abschnitt 8.4)
- Anzahl unabhängiger Kreuz-Verifizierungen ihrer Subjekte durch andere Verifizierer
- Dem Korruptionswahrnehmungsindex (CPI) der Rechtsordnung — Nachweise aus Rechtsordnungen mit niedrigeren CPI-Werten tragen weniger Gewicht, nicht aufgrund von Diskriminierung, sondern weil das objektive statistische Vertrauen in den Verifizierungsprozess geringer ist
- Anomalieerkennung (z. B. 30 Verifizierungen in einer Stunde, schnelle zeitliche Häufung, verdächtige Nullifier-Muster)

### 11.4 Verfall

Der IQ-Beitrag eines Nachweises verfällt, wenn:

- Das Nachweis-Ablaufdatum sich nähert
- Das zugrunde liegende Dokumentablaufdatum sich nähert (schnellerer Verfall)
- Der Vertrauenswert des Verifizierers sinkt (z. B. aufgrund entdeckten Betrugs)

Der Verfall ist schrittweise. Es gibt keinen abrupten Abfall.

### 11.5 Haftungsausschluss

Der Signet-IQ-Wert ist eine berechnete Metrik basierend auf öffentlich verfügbaren On-Chain-Daten. Er stellt keine definitive Bewertung der Vertrauenswürdigkeit, Identität oder des Charakters dar. Wir gewährleisten nicht, dass ein Signet-IQ-Wert die Vertrauenswürdigkeit eines Benutzers genau widerspiegelt.

---

## 12. Datenschutz

### 12.1 Personenbezogene Daten, die das Protokoll nicht erhebt

Das Signet-Protokoll ist darauf ausgelegt, Ihre personenbezogenen Daten nicht zu erheben oder zu veröffentlichen. Ihr Name, Ihr Geburtsdatum, Ihre Nationalität und Ihre Dokumentnummer sind:

- Nie im Nostr-Netzwerk veröffentlicht
- Nie an unsere Server übermittelt
- Lokal auf Ihrem Gerät in verschlüsselter Form gespeichert (AES-256-GCM, Schlüssel abgeleitet via PBKDF2 600.000 Iterationen)
- Nur nach erfolgreicher biometrischer oder PIN-Authentifizierung zugänglich

### 12.2 Was On-Chain veröffentlicht wird

Die folgenden Daten werden im Nostr-Netzwerk veröffentlicht (öffentlich by Design):

- Ihr Nostr-Public-Key (npub)
- Ihre Nachweis-Stufe und -Typ
- Ihre Merkle-Root (ein kryptografischer Hash — offenbart keine persönlichen Attribute)
- Ihr Dokumentnullifier (ein Einweg-Hash — offenbart keine Dokumentdetails)
- Ihr Altersbereichsnachweis (z. B. „18+" — offenbart nicht Ihr Alter)
- Verifizierer-Nachweis-Metadaten (Beruf, Rechtsordnung, Lizenzierungsbehörden-Referenz)
- Bürgschaftsbeglaubigungen
- Delegierungsereignisse

Nach der Veröffentlichung auf Nostr sind diese Ereignisse öffentlich und können von Relay-Betreibern repliziert werden. Wir können veröffentlichte Ereignisse nicht löschen oder ändern.

### 12.3 Lokale Datenspeicherung

Lokal in der App gespeicherte Daten (Mnemonic, private Schlüssel, Dokumentdetails zur Berechnung des Merkle-Baums) werden in IndexedDB in verschlüsselter Form gespeichert. Sie werden nie im Klartext gespeichert. Der Verschlüsselungsschlüssel ist durch Ihre Biometrie oder PIN geschützt.

### 12.4 Verifizierer als unabhängige Verantwortliche

Wenn ein professioneller Verifizierer Ihre Identitätsdokumente prüft und Verifizierungsaufzeichnungen führt, tut er dies als unabhängiger Verantwortlicher. Seine Verarbeitung wird durch seine beruflichen Verpflichtungen und anwendbares Datenschutzrecht (UK DSGVO, DSGVO, CCPA/CPRA oder Äquivalent) geregelt, nicht durch uns.

### 12.5 Rechtsordnungsspezifischer Datenschutz

| Rechtsordnung | Anwendbares Recht |
|---|---|
| Vereinigtes Königreich | UK DSGVO, Data Protection Act 2018 |
| Europäische Union | DSGVO (Verordnung 2016/679) |
| Vereinigte Staaten | CCPA/CPRA (Kalifornien), staatliche Datenschutzgesetze |
| Brasilien | LGPD |
| Indien | DPDP-Gesetz 2023 |
| Australien | Privacy Act 1988 |
| Japan | APPI |
| Südkorea | PIPA |
| VAE | Bundesgesetzesdekret Nr. 45 von 2021 |
| Andere | Anwendbares nationales oder regionales Datenschutzrecht |

### 12.6 EU/UK-Rechte der betroffenen Person

Wenn Sie sich in der EU oder im UK befinden, haben Sie das Recht auf Zugang zu, Berichtigung, Löschung, Einschränkung der Verarbeitung von und Portabilität Ihrer personenbezogenen Daten. Da das Protokoll die Datenerhebung minimiert, sind die Daten, die wir über Sie halten, begrenzt. Kontaktieren Sie uns unter der Adresse in Abschnitt 21, um Ihre Rechte auszuüben.

### 12.7 EU-Online-Streitbeilegung

Wenn Sie Verbraucher in der EU sind, können Sie eine Beschwerde über die EU-Online-Streitbeilegungsplattform einreichen: [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

---

## 13. Geistiges Eigentum

### 13.1 Protokollspezifikation

Die Signet-Protokollspezifikation wird unter einer Open-Source-Lizenz veröffentlicht, wie im Protokoll-Repository angegeben. Ihnen wird eine Lizenz zur Nutzung, Implementierung und zum Aufbau auf dem Protokoll gemäß dieser Lizenz gewährt.

### 13.2 Marken

„The Signet Protocol", „Signet" und „My Signet" sowie zugehörige Logos sind Marken. Sie dürfen diese Marken nicht auf eine Weise verwenden, die Billigung oder Zugehörigkeit impliziert, ohne vorherige schriftliche Zustimmung, außer für genaue beschreibende Bezugnahme auf das Protokoll oder die App.

### 13.3 Benutzerinhalte

Sie behalten das Eigentum an Inhalten, die Sie mit dem Protokoll erstellen (Nachweise, Bürgschaften, Delegierungsereignisse). Durch die Veröffentlichung von Ereignissen im Nostr-Netzwerk erkennen Sie an, dass diese Ereignisse öffentlich sind und von Relay-Betreibern gespeichert und repliziert werden können.

### 13.4 SDK

Das signet-verify.js SDK wird unter der im Protokoll-Repository angegebenen Open-Source-Lizenz bereitgestellt. Kommerzielle Nutzung ist gemäß dieser Lizenz erlaubt.

### 13.5 Beiträge

Beiträge zur Protokollspezifikation oder zum Implementierungscode unterliegen der Mitwirkenden-Lizenzvereinbarung im Protokoll-Repository.

---

## 14. Haftungsausschlüsse

### 14.1 Protokoll bereitgestellt „wie es ist"

DAS PROTOKOLL, DIE APP UND DAS SDK WERDEN „WIE SIE SIND" UND „WIE VERFÜGBAR" OHNE JEGLICHE AUSDRÜCKLICHE ODER IMPLIZIERTE GARANTIEN BEREITGESTELLT, EINSCHLIESSLICH, ABER NICHT BESCHRÄNKT AUF IMPLIZIERTE GARANTIEN DER MARKTGÄNGIGKEIT, EIGNUNG FÜR EINEN BESTIMMTEN ZWECK, TITEL UND NICHTVERLETZUNG.

### 14.2 Keine Gewährleistung der Genauigkeit

WIR GEWÄHRLEISTEN NICHT, DASS:

- EIN NACHWEIS GENAU, VOLLSTÄNDIG ODER ZUVERLÄSSIG IST
- EIN VERIFIZIERER KOMPETENT, EHRLICH ODER ORDNUNGSGEMÄSS LIZENZIERT IST
- DAS PROTOKOLL OHNE UNTERBRECHUNG ODER FEHLER FUNKTIONIERT
- DIE KRYPTOGRAFISCHEN KOMPONENTEN AUF UNBESTIMMTE ZEIT SICHER BLEIBEN
- EIN SIGNET-IQ-WERT DIE VERTRAUENSWÜRDIGKEIT EINES BENUTZERS GENAU WIDERSPIEGELT
- DAS SDK DIE RECHTS-COMPLIANCE-ANFORDERUNGEN EINER BESTIMMTEN VERTRAUENDEN PARTEI ERFÜLLT

### 14.3 Dezentralisierungshaftungsausschluss

Da das Protokoll in einem dezentralisierten Netzwerk operiert, können wir:

- Protokollaktivitäten nicht kontrollieren, überwachen oder zensieren
- Veröffentlichte Ereignisse nicht rückgängig machen oder ändern
- Die Verfügbarkeit oder Leistung von Relays nicht garantieren
- Diese Bedingungen nicht gegen alle Teilnehmer weltweit durchsetzen
- Nicht für das Verhalten unabhängiger Relay-Betreiber verantwortlich sein

### 14.4 Kryptografischer Haftungsausschluss

Kein kryptografisches System ist nachweislich sicher gegen alle zukünftigen Angriffe. Fortschritte in der Informatik (einschließlich Quantencomputing) können die Sicherheit der kryptografischen Komponenten des Protokolls beeinflussen. Wir beabsichtigen, Post-Quanten-Migration zu unterstützen, können aber keine spezifischen Zeitpläne garantieren.

### 14.5 Regulatorischer Haftungsausschluss

Die regulatorische Landschaft für dezentralisierte Identität und Zero-Knowledge-Beweise entwickelt sich weiter. Compliance-Verpflichtungen können sich ändern. Funktionen des Protokolls können neuen Vorschriften unterliegen.

---

## 15. Haftungsbeschränkung

### 15.1 Allgemeine Beschränkung

IM GRÖSSTMÖGLICHEN DURCH ANWENDBARES RECHT ERLAUBTEN UMFANG HAFTEN WIR, UNSERE DIREKTOREN, LEITENDEN ANGESTELLTEN, MITARBEITER, AGENTEN UND VERBUNDENEN UNTERNEHMEN NICHT FÜR INDIREKTE, ZUFÄLLIGE, BESONDERE, FOLGE-, STRAF- ODER EXEMPLARISCHE SCHÄDEN, EINSCHLIESSLICH GEWINNVERLUST, GESCHÄFTLICHEN GOODWILL, DATEN ODER ANDERE IMMATERIELLE VERLUSTE, UNABHÄNGIG DAVON, OB WIR AUF DIE MÖGLICHKEIT SOLCHER SCHÄDEN HINGEWIESEN WURDEN.

### 15.2 Haftungshöchstbetrag

IM GRÖSSTMÖGLICHEN DURCH ANWENDBARES RECHT ERLAUBTEN UMFANG ÜBERSTEIGT UNSERE GESAMTHAFTUNG FÜR ALLE ANSPRÜCHE AUS ODER IM ZUSAMMENHANG MIT DIESEN BEDINGUNGEN ODER DEM PROTOKOLL DEN GRÖSSEREN DER FOLGENDEN BETRÄGE NICHT: (A) DEN BETRAG, DEN SIE UNS IN DEN 12 MONATEN VOR DEM ANSPRUCH GEZAHLT HABEN, ODER (B) £100.

### 15.3 Ausnahmen

Die oben genannten Beschränkungen gelten nicht für:

- Haftung, die nach anwendbarem Recht nicht ausgeschlossen oder beschränkt werden kann
- Haftung aus vorsätzlichem Fehlverhalten oder Betrug
- Haftung für Tod oder Körperverletzung durch Fahrlässigkeit (in Rechtsordnungen, wo eine Beschränkung verboten ist)
- Gesetzliche Verbraucherrechte, die vertraglich nicht aufgegeben werden können

### 15.4 Verbraucherschutz

Nichts in diesen Bedingungen berührt Ihre gesetzlichen Rechte als Verbraucher nach anwendbaren Verbraucherschutzgesetzen.

---

## 16. Freistellung

### 16.1 Ihre Freistellungsverpflichtungen

Sie erklären sich einverstanden, uns gegen alle Ansprüche, Schäden, Verluste, Verbindlichkeiten, Kosten und Ausgaben (einschließlich angemessener Anwaltshonorare) zu entschädigen, zu verteidigen und schadlos zu halten, die sich aus Folgendem ergeben oder damit zusammenhängen:

1. Ihrer Nutzung des Protokolls
2. Ihrem Verstoß gegen diese Bedingungen
3. Ihrer Verletzung anwendbaren Rechts
4. Ihrer Verletzung der Rechte Dritter
5. Von Ihnen erstellten Nachweisen, einschließlich falscher oder irreführender Nachweise
6. Von Ihnen ausgestellten Bürgschaften
7. Von Ihnen durchgeführten Verifizierungen (wenn Sie Verifizierer sind)
8. Ihrer Nutzung des SDK und von Ihren Benutzern in diesem Zusammenhang erhobenen Ansprüchen

### 16.2 Freistellungsverfahren

Wir werden Sie umgehend über etwaige Ansprüche informieren, angemessene Zusammenarbeit leisten und Ihnen die Kontrolle über die Verteidigung und Beilegung des Anspruchs überlassen, vorausgesetzt, Sie einigen sich nicht auf einen Anspruch, der uns Verpflichtungen auferlegt, ohne unsere vorherige schriftliche Zustimmung.

---

## 17. Anwendbares Recht und Streitbeilegung

### 17.1 Anwendbares Recht

Diese Bedingungen unterliegen dem Recht von England und Wales und werden nach diesem ausgelegt, ohne Berücksichtigung von Kollisionsnormen.

### 17.2 Streitbeilegung

**Schritt 1 — Verhandlung:** Die Parteien versuchen zunächst, jeden Streit durch Verhandlungen in gutem Glauben für 30 Tage beizulegen.

**Schritt 2 — Mediation:** Scheitert die Verhandlung, unterwerfen sich die Parteien einer Mediation, die vom Centre for Effective Dispute Resolution (CEDR) gemäß seinen Regeln durchgeführt wird.

**Schritt 3 — Schiedsverfahren:** Scheitert die Mediation, wird der Streit durch bindendes Schiedsverfahren endgültig beigelegt, das vom London Court of International Arbitration (LCIA) gemäß seinen Regeln durchgeführt wird. Der Schiedsort ist London. Die Sprache ist Englisch. Der Schiedsspruch ist endgültig und bindend.

### 17.3 Sammelklageverzicht

IM GRÖSSTMÖGLICHEN DURCH ANWENDBARES RECHT ERLAUBTEN UMFANG ERKLÄREN SIE SICH EINVERSTANDEN, STREITIGKEITEN NUR AUF INDIVIDUELLER BASIS UND NICHT IN EINER KLASSEN-, KONSOLIDIERTEN ODER REPRÄSENTATIVEN KLAGE BEIZULEGEN. WENN DIESER VERZICHT NICHT DURCHSETZBAR IST, IST DIE SCHIEDSKLAUSEL NICHTIG UND UNWIRKSAM.

### 17.4 Ausnahmen

Jede Partei kann in einem zuständigen Gericht einstweiligen Rechtsschutz beantragen, um geistiges Eigentum zu schützen oder irreparablen Schaden zu verhindern.

### 17.5 EU-Verbraucherrechte

Wenn Sie Verbraucher in der EU sind, können Sie auch Ihre nationalen Gerichte und die EU-ODR-Plattform nutzen: [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

### 17.6 Professionelle Regulierungsangelegenheiten des Verifizierers

Nichts in diesen Bedingungen beschränkt die Zuständigkeit einer professionellen Regulierungsbehörde über einen Verifizierer, das Recht eines Verifizierers, bei seiner Regulierungsbehörde Rat zu suchen, oder unser Recht, Bedenken gegenüber der Regulierungsbehörde eines Verifizierers zu melden.

---

## 18. Kündigung

### 18.1 Ihr Kündigungsrecht

Sie können die Nutzung des Protokolls jederzeit einstellen. Aufgrund der dezentralisierten Natur des Protokolls können zuvor veröffentlichte Ereignisse auf Nostr-Relays unbegrenzt verbleiben.

### 18.2 Unsere Rechte

Wir behalten uns das Recht vor:

- Verifizierer-Nachweise aus Gründen zu widerrufen (wie in Abschnitt 8.10 beschrieben)
- Community-Hinweise über betrügerische Nachweise oder Akteure zu veröffentlichen
- Die Protokollspezifikation zu ändern oder einzustellen

### 18.3 Auswirkung der Kündigung

Bei Kündigung:

- Erlischt Ihr Recht zur Nutzung proprietärer App-Komponenten
- Überleben die Abschnitte 8 (Verifizierer-Pflichten — Aufzeichnungsführung überlebt), 12, 13, 14, 15, 16, 17 und 20
- Sind zuvor veröffentlichte Nostr-Ereignisse nicht betroffen

---

## 19. Änderungen

### 19.1 Änderungsrecht

Wir können diese Bedingungen jederzeit ändern. Änderungen treten in Kraft bei:

- Veröffentlichung aktualisierter Bedingungen im Protokoll-Repository
- Einer Nostr-Ereignis-Ankündigung, die auf die aktualisierten Bedingungen verweist
- 30-tägiger Ankündigung für wesentliche Änderungen

### 19.2 Annahme von Änderungen

Ihre fortgesetzte Nutzung des Protokolls nach dem Inkrafttretungsdatum stellt Akzeptanz dar. Wenn Sie nicht einverstanden sind, müssen Sie die Nutzung des Protokolls einstellen.

### 19.3 Wesentliche Änderungen

Für wesentliche Änderungen werden wir bereitstellen:

- Klare Ankündigung der Art der Änderungen
- Eine Zusammenfassung wichtiger Änderungen in einfacher Sprache
- Mindestens 30 Tage vor Inkrafttreten der Änderungen

---

## 20. Allgemeine Bestimmungen

### 20.1 Gesamte Vereinbarung

Diese Bedingungen stellen die gesamte Vereinbarung zwischen Ihnen und uns bezüglich des Protokolls dar. Sie ersetzen die separat veröffentlichte Verifizierer-Vereinbarung (die nunmehr als Abschnitt 8 darin eingegliedert ist). Wenn Sie zuvor eine eigenständige Verifizierer-Vereinbarung unterzeichnet haben, ersetzen diese Bedingungen sie ab dem Inkrafttretungsdatum.

### 20.2 Salvatorische Klausel

Wenn eine Bestimmung als ungültig oder nicht durchsetzbar befunden wird, wird sie im größtmöglichen zulässigen Umfang durchgesetzt. Die verbleibenden Bestimmungen bleiben in vollem Kraft und Wirkung.

### 20.3 Verzicht

Das Versäumnis, eine Bestimmung durchzusetzen, stellt keinen Verzicht dar.

### 20.4 Abtretung

Sie dürfen diese Bedingungen nicht ohne unsere vorherige schriftliche Zustimmung abtreten. Wir können diese Bedingungen ohne Ihre Zustimmung abtreten.

### 20.5 Höhere Gewalt

Keine Partei haftet für Versagen oder Verzögerungen aufgrund von Ursachen außerhalb ihrer zumutbaren Kontrolle, einschließlich Naturkatastrophen, Krieg, Terrorismus, Pandemien, staatliche Maßnahmen, Netzwerkausfälle, Kompromittierung kryptografischer Algorithmen oder Nostr-Relay-Ausfälle.

### 20.6 Mitteilungen

Mitteilungen an uns: siehe Abschnitt 21. Mitteilungen an Sie: jede von Ihnen bereitgestellte Kontaktinformation oder über Nostr-Ereignis oder das Protokoll-Repository.

### 20.7 Drittbegünstigte

Diese Bedingungen schaffen keine Drittbegünstigtenrechte, außer dass Nostr-Netzwerk-Relay-Betreiber und Protokollbenutzer, die sich auf von Verifizierern ausgestellte Nachweise verlassen, beabsichtigte Begünstigte von Abschnitt 8 sind.

### 20.8 Exportkonformität

Sie müssen alle anwendbaren Export- und Sanktionsgesetze einhalten. Die kryptografischen Komponenten des Protokolls können in bestimmten Rechtsordnungen Exportkontrollen unterliegen.

### 20.9 Überschriften

Abschnittsüberschriften dienen nur der Bequemlichkeit und beeinflussen nicht die Auslegung.

---

## 21. Kontakt

Bei Fragen zu diesen Bedingungen, zur Ausübung von Datenschutzrechten oder zur Meldung von Sicherheitsproblemen:

**Das Signet-Protokoll**
E-Mail: admin@forgesworn.dev
Sicherheitsmeldungen: admin@forgesworn.dev
Repository: https://github.com/forgesworn/signet-protocol

---

## 22. Rechtsordnungsspezifische Anhänge

### Anhang A — Vereinigtes Königreich

**Lizenzierungsbehörden:** Law Society of England and Wales, Law Society of Scotland, Law Society of Northern Ireland, Bar Council of England and Wales, Faculty of Advocates, General Medical Council (GMC), Nursing and Midwifery Council (NMC), General Dental Council (GDC), General Pharmaceutical Council (GPhC), Health and Care Professions Council (HCPC), Teaching Regulation Agency (TRA), General Teaching Council for Scotland (GTCS), Architects Registration Board (ARB), Institute of Chartered Accountants in England and Wales (ICAEW), Institute of Chartered Accountants of Scotland (ICAS), Association of Chartered Certified Accountants (ACCA), Financial Conduct Authority (FCA) — autorisierte Personen, Faculty Office of the Archbishop of Canterbury (Notare).

**Berufshaftpflicht:** Wie von der SRA, FCA, GMC, TRA oder der zuständigen Regulierungsbehörde gefordert.

**Kinderschutz:** Children Act 1989 und 2004; Safeguarding Vulnerable Groups Act 2006; DBS Enhanced Check erforderlich für Lehrkräfte und andere regulierte Tätigkeitsrollen, die Stufe-4-Verifizierungen durchführen; Meldepflicht gemäß Working Together to Safeguard Children (2023).

**Datenschutz:** UK DSGVO; Data Protection Act 2018; ICO-Leitlinien; DSIT-Leitlinien zu biometrischen Daten.

**Altersverifizierung:** Online Safety Act 2022 (Ofcom-genehmigte Altersabsicherung). Stufe-4-persönliche professionelle Verifizierung übertrifft die von Ofcom akzeptierten Methoden.

### Anhang B — Vereinigte Staaten

**Lizenzierungsbehörden:** Staatliche Anwaltsverbände; staatliche Ärztekammern; staatliche Notarkommissionen; staatliche Bildungsministerien (Lehrkräfte); zuständige staatliche Finanzregulatoren.

**Hinweis:** Berechtigung und Verpflichtungen variieren erheblich je nach Bundesstaat. Sie müssen das Recht der Bundesstaaten einhalten, in denen Sie Verifizierungen durchführen.

**Kinderschutz:** COPPA (Children's Online Privacy Protection Act); FERPA (für schulbasierte Verifizierer); staatliche Meldepflichten; staatliche Kinderschutzgesetze. Von einer Lehrkraft geführte Schulanmeldungsunterlagen können als Dokumentarnachweis für Stufe-4-Verifizierungen dienen, wo staatliches Recht dies erlaubt.

**Datenschutz:** CCPA/CPRA (Kalifornien); Virginia CDPA; andere staatliche Datenschutzgesetze; FERPA (Schulunterlagen). Für Benutzer mit Wohnsitz in Kalifornien kann eine separate Datenverarbeitungsvereinbarung erforderlich sein.

### Anhang C — Europäische Union

**Lizenzierungsbehörden:** Nationale Anwaltsverbände, Ärztekammern, Notariatskammern und ihre Äquivalente in jedem Mitgliedstaat.

**Hinweis:** Spezifische Anforderungen variieren je nach Mitgliedstaat. Verifizierer müssen das Recht des Mitgliedstaats einhalten, in dem sie niedergelassen sind und in dem sie Verifizierungen durchführen.

**eIDAS 2.0:** Die eindeutige Personenkennung von eIDAS, wenn sie über eine staatlich ausgestellte eIDAS-Wallet präsentiert wird, kann als zusätzliche Nullifier-Quelle dienen. Die Nullifier-Formel ist `SHA-256(LP("eidas") || LP(eidas_unique_id) || LP("signet-nullifier-v2"))`.

**Kinderschutz:** DSGVO Artikel 8; nationale Umsetzungsgesetzgebung; Verordnung (EU) 2022/2065 (DSA) Altersverifizierungsverpflichtungen.

**Datenschutz:** DSGVO (Verordnung 2016/679); nationale Umsetzungsgesetzgebung; nationale DPA-Leitlinien.

### Anhang D — Australien

**Lizenzierungsbehörden:** Staatliche und territoriale Anwaltsverbände; Australian Health Practitioner Regulation Agency (AHPRA) für Medizin und verwandte Gesundheitsberufe; staatliche/territoriale Justizbehörden (Notare); zuständige staatliche Lehrerregistrierungsstellen.

**Kinderschutz:** Working With Children Check, soweit auf die Rolle anwendbar; Online Safety Act 2021; staatliche Kinderschutzgesetze.

**Datenschutz:** Privacy Act 1988; Australian Privacy Principles; Consumer Data Right (CDR), soweit anwendbar.

### Anhang E — Japan

**Lizenzierungsbehörden:** Japan Federation of Bar Associations (JFBA); Justizministerium (Notare); Japan Medical Association; zuständige Lehrerregistrierungsbehörden.

**Kinderschutz:** APPI-Leitlinien; nationale Kinderschutzgesetzgebung; Verpflichtungen beim Arbeiten mit Jugendlichen.

**Datenschutz:** Act on the Protection of Personal Information (APPI) und seine Änderungen.

### Anhang F — Südkorea

**Lizenzierungsbehörden:** Korean Bar Association; Korean Medical Association; zuständige Regierungsministerien für andere regulierte Berufe.

**Kinderschutz:** Personal Information Protection Act (PIPA); Youth Protection Act; Meldepflichten.

**Datenschutz:** PIPA.

### Anhang G — Brasilien

**Lizenzierungsbehörden:** Ordem dos Advogados do Brasil (OAB); Conselho Federal de Medicina (CFM); Notariatskammern; zuständige föderale und staatliche Berufsräte.

**Kinderschutz:** LGPD Artikel 14 (Kinderdaten — elterliche Einwilligung erforderlich); Estatuto da Criança e do Adolescente (ECA); Meldepflichten.

**Datenschutz:** Lei Geral de Proteção de Dados (LGPD); ANPD-Leitlinien.

### Anhang H — Indien

**Lizenzierungsbehörden:** Bar Council of India und staatliche Anwaltsverbände; National Medical Commission (NMC); zuständige staatliche Behörden für andere regulierte Berufe.

**Kinderschutz:** Digital Personal Data Protection Act 2023 (DPDP); Protection of Children from Sexual Offences Act (POCSO); Meldepflichten.

**Datenschutz:** DPDP-Gesetz 2023; darauf erlassene Vorschriften.

### Anhang I — Vereinigte Arabische Emirate

**Lizenzierungsbehörden:** Justizministerium; Dubai Health Authority (DHA) oder Health Authority Abu Dhabi (HAAD); zuständige Emirats-Berufsautoritäten.

**Kinderschutz:** Bundesgesetz Nr. 3 von 2016 (Wadeema-Gesetz — Kinderrechtsgesetz); Meldepflichten.

**Datenschutz:** Bundesgesetzesdekret Nr. 45 von 2021 über den Schutz personenbezogener Daten; UAE Data Office-Leitlinien.

---

*Das Signet-Protokoll — v0.1.0 — März 2026*
*Dieses Dokument dient Informationszwecken. Es stellt keine Rechtsberatung dar. Holen Sie sich qualifizierten Rechtsrat für Ihre Rechtsordnung ein, bevor Sie sich darauf verlassen.*
