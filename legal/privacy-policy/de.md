---
**Hinweis zur KI-generierten Übersetzung**

Dieses Dokument wurde aus dem Englischen mithilfe von KI (Claude, Anthropic) übersetzt. Es dient ausschließlich als Referenz. Die englische Version unter `en.md` ist das einzige rechtsverbindliche Dokument. Diese Übersetzung wurde nicht von einem qualifizierten Rechtsübersetzer geprüft. Bei Abweichungen zwischen dieser Übersetzung und dem englischen Original hat die englische Fassung Vorrang.

---

# Datenschutzerklärung

**Signet-Protokoll — v0.1.0**

**Datum des Inkrafttretens:** März 2026
**Zuletzt aktualisiert:** März 2026

---

## 1. Einleitung

Diese Datenschutzerklärung beschreibt, wie das Signet-Protokoll („Signet", „wir" oder „uns") Informationen im Zusammenhang mit dem Signet-Protokoll (dem „Protokoll") und der My Signet-Anwendung (der „App") erhebt, verwendet, offenlegt und schützt. Signet ist ein quelloffenes, dezentralisiertes Identitätsverifizierungsprotokoll für das Nostr-Netzwerk, das Zero-Knowledge-Beweise, Ringsignaturen und kryptografische Nachweise verwendet.

Signet ist mit Datenschutz als Kernprinzip konzipiert. Es ermöglicht Benutzern, Ansprüche bezüglich ihrer Identität zu beweisen — wie Altersbereich, Berufsstatus oder geografische Rechtsordnung — ohne die zugrunde liegenden personenbezogenen Daten preiszugeben. Diese Datenschutzerklärung erläutert, welche begrenzten Dateninteraktionen stattfinden, wo Daten verbleiben und wie sie behandelt werden.

Diese Richtlinie gilt für alle Benutzer, Verifizierer, vertrauende Parteien und andere Teilnehmer, die mit dem Signet-Protokoll oder der My Signet-Anwendung interagieren, unabhängig von ihrem Standort.

Die kanonische Protokollbeschreibung ist `spec/protocol.md` im quelloffenen Signet-Repository.

---

## 2. Verantwortlicher

**Verantwortlicher:** Das Signet-Protokoll
**Kontakt-E-Mail:** privacy@signet.id
**Datenschutzbeauftragter (DSB):** dpo@signet.id

Für Rechtsordnungen, die einen lokalen Vertreter erfordern, wenden Sie sich an den DSB unter der oben genannten Adresse. Formelle Vertreterbestellungen für EU (DSGVO Art. 27) und UK (UK DSGVO Art. 27) werden unter signet.id/legal veröffentlicht.

---

## 3. Von uns erhobene und verarbeitete Daten

Das Signet-Protokoll ist so konzipiert, dass die Datenerhebung minimiert wird. Da das Protokoll Zero-Knowledge-Beweise, Ringsignaturen und dezentralisierte Nachweis-Verifizierung verwendet, verbleiben die überwiegende Mehrheit der Informationen ausschließlich unter der Kontrolle des Benutzers und werden niemals an Signet übermittelt oder sind für Signet zugänglich.

### 3.1 Datenkategorien

| Kategorie | Beschreibung | Quelle | Speicherort |
|----------|-------------|--------|-----------------|
| **Nostr-Public-Keys** | secp256k1-Public-Keys (npub) für Protokollinteraktionen | Benutzergeneriert | Nostr-Relays (dezentralisiert) |
| **Nachweis-Metadaten** | Nostr-Ereignisarten 31000–31000 mit Verifizierungsstufe, Ausstellungszeitstempel, Ablaufdaten, Altersbereich und Entitätstyp-Identifikatoren | Während der Nachweisausstellung generiert | Nostr-Relays (dezentralisiert) |
| **Zero-Knowledge-Beweise** | Bulletproofs für Altersbereichsverifizierung | Lokal vom Benutzer generiert | In Nachweis-Ereignissen auf Nostr-Relays eingebettet |
| **Ringsignaturen** | Kryptografische Signaturen, die die Mitgliedschaft in einer Gruppe beweisen, ohne preiszugeben, welches Mitglied unterzeichnet hat | Lokal vom Benutzer generiert | Nostr-Relays (dezentralisiert) |
| **Nullifier-Hashes** | SHA-256-Hash von längenvorzeichenbehaftetem Dokumenttyp, Ländercode, Dokumentnummer und Domänen-Tag „signet-nullifier-v2" — verhindert doppelte Identitätserstellung; kann nicht zur Wiederherstellung von Dokumentdetails umgekehrt werden | Lokal während der Zwei-Nachweis-Zeremonie berechnet | In Natural-Person-Nachweis-Ereignissen eingebettet |
| **Merkle-Roots** | Hash-Verpflichtung gegenüber verifizierten Attributen, die selektive Offenlegung ermöglicht. Blätter umfassen Name, Nationalität, documentType, dateOfBirth, documentNumber, documentExpiry, photoHash und Nullifier. Nur der Root-Hash wird veröffentlicht — einzelne Blattwerte werden nie veröffentlicht | Lokal während der Zwei-Nachweis-Zeremonie berechnet | In Natural-Person-Nachweis-Ereignissen eingebettet |
| **Bürgschaftsaufzeichnungen** | Art-31000-Ereignisse, die Web-of-Trust-Empfehlungen darstellen | Von bürgenden Parteien erstellt | Nostr-Relays (dezentralisiert) |
| **Richtlinienereignisse** | Art-30078-Ereignisse, die Anforderungen vertrauender Parteien festlegen | Von vertrauenden Parteien erstellt | Nostr-Relays (dezentralisiert) |
| **Verifizierer-Registrierung** | Art-31000-Ereignisse zur Identifizierung professioneller Verifizierer, einschließlich professionellem Signatur-Pubkey und Jurisdiktionsinformationen | Von Verifizierern erstellt | Nostr-Relays (dezentralisiert) |
| **Challenge-/Response-Daten** | Art-31000-Ereignisse für Verifizierer-Legitimitäts-Challenges | Während der Verifizierung generiert | Nostr-Relays (dezentralisiert) |
| **Widerrufsaufzeichnungen** | Art-31000-Ereignisse für Nachweis-Widerrufe | Erstellt, wenn Nachweise widerrufen werden | Nostr-Relays (dezentralisiert) |
| **Identitätsbrücken-Ereignisse** | Art-31000-Ereignisse, die Natural-Person- und Persona-Schlüsselpaare über Ringsignaturen verknüpfen | Vom Benutzer erstellt | Nostr-Relays (dezentralisiert) |
| **Delegierungsereignisse** | Art-31000-Ereignisse für Agenten- oder Vormund-Delegierung mit bereichsgebundenen Berechtigungen | Vom Delegierenden erstellt | Nostr-Relays (dezentralisiert) |
| **Verschlüsseltes Schlüsselmaterial** | Private Schlüssel verschlüsselt mit AES-256-GCM (Schlüssel abgeleitet via PBKDF2, 600.000 Iterationen, SHA-256) | Lokal auf dem Gerät gespeichert | Nur lokaler Gerätespeicher — niemals übermittelt |

### 3.2 Was auf Ihrem Gerät verbleibt

Die folgenden Informationen werden auf Ihrem Gerät verarbeitet und niemals an Signet übermittelt oder von Signet gespeichert:

- **Private Schlüssel und Mnemonic-Phrase** — Ihre 12-Wort-BIP-39-Mnemonic und die davon abgeleiteten privaten Schlüssel (sowohl Natural-Person- als auch Persona-Schlüsselpaare, abgeleitet via BIP-32-HD-Ableitung an NIP-06-Pfaden) verbleiben jederzeit auf Ihrem Gerät und sind im Ruhezustand verschlüsselt.
- **Während der Zeremonie eingegebene Dokumentdetails** — Ihre Dokumentnummer, Dokumentablaufdatum, Geburtsdatum, Name, Nationalität und jedes von Ihnen präsentierte Foto. Diese werden von Ihnen in die App eingegeben, zur Berechnung des Merkle-Baums und Nullifiers verwendet und dann verworfen. Die einzelnen Blattwerte werden von Ihnen in Ihrer lokalen Nachweisaufzeichnung für zukünftige selektive Offenlegung aufbewahrt. Sie werden nicht an Signet übermittelt und nicht elektronisch an den Verifizierer gesendet — der Verifizierer prüft Ihre physischen Dokumente persönlich und bestätigt die von Ihnen eingegebenen Daten.
- **Merkle-Blattwerte** — Individuelle Attributwerte (Name, Geburtsdatum, Dokumentnummer, Dokumentablaufdatum, Foto-Hash, Nationalität, Dokumenttyp, Nullifier) werden als Merkle-Blätter in Ihrer lokalen Nachweisaufzeichnung gespeichert, damit Sie einzelne Attribute über selektive Offenlegungsnachweise beweisen können. Nur der Merkle-Root-Hash wird on-chain veröffentlicht.
- **Biometrische Daten** — Siehe Abschnitt 3.3.
- **Genaue Geburtsdaten** — Altersbereichsnachweise offenbaren nur, dass Sie in einen Bereich fallen (z. B. „18+"), nicht Ihr genaues Geburtsdatum.

### 3.3 Biometrische Authentifizierung (Besondere Datenkategorie)

Die My Signet App unterstützt biometrische Authentifizierung über die **WebAuthn-API mit der PRF-Erweiterung (Pseudo-Random Function)**, mit PIN als Fallback.

**Funktionsweise:**
- Wenn Sie Biometrie registrieren, erstellt der Plattform-Authentifikator Ihres Geräts (Fingerabdrucksensor, Face ID oder Äquivalent) einen WebAuthn-Nachweis. Der Nachweis verbleibt im sicheren Enklave oder TPM Ihres Geräts.
- Die WebAuthn-PRF-Erweiterung leitet kryptografisches Schlüsselmaterial aus Ihrer biometrischen Assertion ab. Dieses Schlüsselmaterial wird verwendet, um Ihre verschlüsselten privaten Schlüssel während einer authentifizierten Sitzung zu entschlüsseln.
- **Es wird keine biometrische Vorlage an Signet übermittelt.** Keine biometrischen Daten verlassen Ihr Gerät. Signet erhält, speichert oder verarbeitet keine biometrischen Informationen.
- Die WebAuthn-Nachweis-ID wird im lokalen Speicher Ihres Geräts gespeichert, um zu identifizieren, welcher Nachweis während der Authentifizierung behauptet werden soll. Dies ist ein zufälliger Identifikator, keine biometrische Vorlage.

Gemäß DSGVO Artikel 9 und UK DSGVO sind biometrische Daten, die zum Zweck der eindeutigen Identifizierung einer natürlichen Person verwendet werden, besondere Datenkategorien. Da die biometrische Verarbeitung vollständig auf Ihrem lokalen Gerät unter Verwendung der integrierten sicheren Hardware der Plattform erfolgt und keine biometrischen Daten an Signets Systeme übermittelt oder von diesen verarbeitet werden, handelt Signet nicht als Verantwortlicher oder Auftragsverarbeiter biometrischer Daten. Die Verarbeitung liegt ausschließlich unter Ihrer Kontrolle.

Wenn Ihr Gerät WebAuthn PRF nicht unterstützt, greift die App auf eine PIN zurück, die via PBKDF2-SHA-256 (600.000 Iterationen) zur Erzeugung eines AES-256-GCM-Entschlüsselungsschlüssels abgeleitet wird.

### 3.4 Daten, die wir NICHT erheben

Das Signet-Protokoll erhebt, verarbeitet oder speichert bewusst **keine**:

- Echten Namen, Adressen oder staatlichen Identifikationsnummern
- Genauen Geburtsdaten (Altersbereichsnachweise offenbaren nur einen Bereich)
- Dokumentnummern oder Dokumentablaufdaten (lokal zur Berechnung von Merkle-Blättern verarbeitet; einzelne Werte werden nicht an Signet oder elektronisch an den Verifizierer übermittelt)
- Biometrischen Daten (lokal auf dem Gerät via WebAuthn verarbeitet; niemals übermittelt)
- Finanzinformationen oder Zahlungsdaten
- Standortdaten oder IP-Adressen (Protokollebene; Relay-Betreiber können IP-Adressen unabhängig erheben)
- Browserverlauf oder Geräte-Fingerabdrücke
- E-Mail-Adressen (sofern nicht freiwillig für Support angegeben)
- Fotos oder Bilder (ein Foto-Hash kann als Merkle-Blatt enthalten sein, das Bild selbst verbleibt auf Ihrem Gerät)
- Die zugrunde liegenden Daten hinter einem Zero-Knowledge-Beweis

### 3.5 Von Dritten verarbeitete Daten

Nostr-Relay-Betreiber verarbeiten unabhängig Daten, die über ihre Relays übermittelt werden. Ihre Datenpraktiken unterliegen ihren eigenen Datenschutzrichtlinien. Signet kontrolliert keine Relay-Betreiber.

---

## 4. Die Zwei-Nachweis-Zeremonie

Dieser Abschnitt erläutert den professionellen Verifizierungsprozess im Detail, da er die datenintensivste Interaktion im Protokoll darstellt.

### 4.1 Ablauf der Zeremonie

1. **Sie geben Ihre eigenen Daten ein.** In der My Signet App geben Sie Ihren Namen, Ihr Geburtsdatum, Ihre Nationalität, Ihren Dokumenttyp, Ihre Dokumentnummer, Ihr Dokumentablaufdatum ein und stellen optional Ihr Dokument bereit oder fotografieren es. Die App berechnet den Merkle-Baum und den Nullifier lokal.

2. **Der Verifizierer prüft Ihre physischen Dokumente.** Ein Stufe-3- oder Stufe-4-Verifizierer (ein lizenzierter Fachmann wie ein Solicitor, Notar oder Mediziner) prüft Ihre physischen Identitätsdokumente persönlich. Der Verifizierer bestätigt, dass die von Ihnen eingegebenen Daten mit Ihren Dokumenten übereinstimmen. Der Verifizierer gibt Ihre Daten nicht unabhängig in das System ein.

3. **Der Verifizierer unterzeichnet den Nachweis.** Der Verifizierer unterzeichnet zwei Nachweis-Ereignisse: einen Natural-Person-Nachweis (Art 31000, unterzeichnet mit dem professionellen Nostr-Schlüsselpaar des Verifizierers) und einen Persona-Nachweis (anonym, nur Altersbereich, ebenfalls vom Verifizierer unterzeichnet). Beide werden auf Nostr-Relays veröffentlicht.

4. **Was veröffentlicht wird.** Die veröffentlichten Nachweis-Ereignisse enthalten: den Public Key des Verifizierers, Ihren Persona-Public-Key (Subjekt-Pubkey), Nachweis-Metadaten (Stufe, Daten, Entitätstyp, Altersbereich), den Zero-Knowledge-Altersbereichsnachweis, den Nullifier-Hash (ein Einweg-Hash; kann nicht umgekehrt werden) und die Merkle-Root (eine Hash-Verpflichtung; einzelne Blattwerte werden nicht veröffentlicht). Kein Name, kein Geburtsdatum, keine Dokumentnummer oder andere identifizierende Informationen werden veröffentlicht.

5. **Was Sie lokal aufbewahren.** Ihre lokale Nachweisaufzeichnung enthält die einzelnen Merkle-Blattwerte (Name, Nationalität, Geburtsdatum, Dokumenttyp, Dokumentnummer, Dokumentablaufdatum, Nullifier und optional Foto-Hash). Diese verwenden Sie, um selektive Offenlegungsnachweise zu generieren, wenn Sie später bestimmte Attribute beweisen möchten (z. B. Nachweis Ihrer Reisepassnummer beim Check-in für einen Flug).

### 4.2 Dokumentnummer und Ablaufdatum als Merkle-Blätter

Anders als in früheren Versionen des Protokolls werden Dokumentnummer und Dokumentablaufdatum nach der Zeremonie **nicht** verworfen. Sie werden als Merkle-Blätter in Ihrer lokalen Nachweisaufzeichnung aufbewahrt. Dies ermöglicht Ihnen:

- Ihre Reisepassnummer gegenüber einer vertrauenden Partei, die sie benötigt (z. B. einer Fluggesellschaft), über einen Merkle-Einschlussbeweis nachzuweisen, ohne andere Attribute preiszugeben.
- Einen beschleunigten Signet-IQ-Verfall zu unterstützen, wenn sich Ihr Dokumentablaufdatum nähert, und vertrauenden Parteien ein Signal über die Aktualität Ihrer zugrunde liegenden Identitätsnachweise zu geben.

Nur Sie kontrollieren, welche Attribute Sie wem gegenüber offenlegen. Einzelne Blattwerte werden niemals an Signet übermittelt oder sind für Signet zugänglich.

### 4.3 Nullifier-Format

Der Nullifier wird berechnet als:

```
SHA-256(len16(docType) || docType || len16(countryCode) || countryCode || len16(docNumber) || docNumber || len16("signet-nullifier-v2") || "signet-nullifier-v2")
```

wobei `len16(x)` die UTF-8-Byte-Länge von `x` als 2-Byte-Big-Endian-uint16 kodiert ist. Der Domänen-Tag `signet-nullifier-v2` unterscheidet dieses Schema von früheren Versionen. Der Nullifier-Hash ermöglicht es dem Protokoll, doppelte Identitätsregistrierungen zu erkennen, ohne preiszugeben, welches Dokument verwendet wurde.

---

## 5. Zwei-Schlüsselpaar-Modell

Jeder Signet-Benutzer hat zwei Schlüsselpaare, die von einer einzigen 12-Wort-BIP-39-Mnemonic abgeleitet werden:

- **Natural-Person-Schlüsselpaar** — abgeleitet über NIP-06-Pfad `m/44'/1237'/0'/0/0`. Für den Natural-Person-Nachweis (Art 31000) verwendet. Dieses Schlüsselpaar ist über den Nachweis mit Ihrer verifizierten realen Identität verbunden, das Schlüsselpaar selbst trägt jedoch keine inhärente Verbindung zu Ihren Dokumenten.
- **Persona-Schlüsselpaar** — über BIP-32-HD-Pfad an einem separaten Konto-Index abgeleitet. Für den Persona-Nachweis (anonym, nur Altersbereich) verwendet. Dieses Schlüsselpaar trägt keine direkte Verbindung zu Ihrer realen Identität. Ihre Online-Sozialaktivität verwendet dieses Schlüsselpaar.

**Datenschutzimplikation:** Da beide Schlüsselpaare von derselben Mnemonic abgeleitet werden, können Sie die Verbindung zwischen ihnen beweisen (über Art-31000-Identitätsbrücken-Ereignisse) oder sie vollständig getrennt halten. Ein Identitätsbrücken-Ereignis schafft nach der Veröffentlichung eine öffentliche kryptografische Verbindung. Sie sollten ein Brücken-Ereignis nur veröffentlichen, wenn Sie Ihre anonyme Persona mit Ihrem verifizierten Natural-Person-Status in Verbindung bringen möchten.

**Schlüsselverwaltung und Rechte der betroffenen Personen:** Ihre privaten Schlüssel werden deterministisch aus Ihrer Mnemonic abgeleitet. Signet besitzt oder übermittelt Ihre privaten Schlüssel nie. Wenn Sie die App löschen und Ihre Mnemonic (und etwaige Shamir-Backups) verlieren, sind Ihre Schlüssel nicht wiederherstellbar. Signet kann bei der Schlüsselwiederherstellung nicht helfen, da wir keine Kopien besitzen.

---

## 6. Das signet-verify.js SDK

Das My Signet-Ökosystem beinhaltet `signet-verify.js`, ein JavaScript-SDK, das Websites einbetten, um Alters- oder Identitätsverifizierung von ihren Besuchern anzufordern.

### 6.1 Funktionsweise des SDK

1. Eine Website bettet `signet-verify.js` ein und ruft `Signet.verifyAge('18+')` (oder ähnlich) auf.
2. Das SDK öffnet ein Verifizierungsmodal auf der Website.
3. Der Benutzer genehmigt die Anfrage in der My Signet App. Der Nachweis wird über einen BroadcastChannel (geräteinterne Kommunikation; kein Server beteiligt) zurück an die Website übermittelt.
4. Das SDK verifiziert die Schnorr-Signatur auf dem Nachweis-Ereignis und überprüft, ob der Pubkey des Verifizierers registriert und bestätigt ist.
5. Das SDK gibt ein Ergebnis an die Website zurück.

### 6.2 Welche Daten die Website erhält

Eine Website, die `signet-verify.js` verwendet, erhält:

| Feld | Beschreibung |
|-------|-------------|
| `verified` | Boolean: erfüllt der Nachweis die angegebene Anforderung? |
| `ageRange` | Altersbereichszeichenfolge (z. B. „18+") — nie genaues Geburtsdatum |
| `tier` | Verifizierungsstufe (1–4) |
| `entityType` | Kontotypklassifizierung (Natural Person, Persona usw.) |
| `credentialId` | Nachweis-Ereignis-ID (ein öffentlicher Nostr-Ereignis-Identifikator) |
| `verifierPubkey` | Der Nostr-Public-Key des Verifizierers |
| `verifierConfirmed` | Ob der Verifizierer gegen ein öffentliches Berufsregister bestätigt wurde |
| `issuedAt` / `expiresAt` | Gültigkeitszeitstempel des Nachweises |

**Keine personenbezogenen Informationen werden an die Website übermittelt.** Die Website erhält nicht Ihren Namen, Ihr Geburtsdatum, Ihre Dokumentnummer oder andere Merkle-Blattwerte. Die BroadcastChannel-Kommunikation ist lokal auf dem Gerät — der Verifizierungsaustausch verläuft nicht über einen Signet-Server.

### 6.3 Verifizierungsbot

Signet betreibt einen quelloffenen Verifizierungsbot, der Verifizierer-Registrierungen gegen öffentliche Berufsregister überprüft (z. B. das General Medical Council-Register, die Solicitors Regulation Authority-Liste, Teaching Regulation Agency-Aufzeichnungen). Der Bot veröffentlicht seine Ergebnisse als Nostr-Ereignisse.

Der professionelle Nostr-Pubkey des Verifizierers ist ein zweckgebauter Signaturschlüssel, der nur für Signet-Verifizierungen verwendet wird. Er hat keine inhärente soziale Identität. Der Bot erhält diesen Pubkey, um öffentliche Register abzufragen. Die Übermittlung eines professionellen Pubkeys an den Bot zur Register-Überprüfung stellt keine Übermittlung personenbezogener Daten gemäß DSGVO dar, da der Pubkey ein pseudonymer kryptografischer Identifikator ist, der speziell für diese Funktion entwickelt wurde. Aus Vorsicht stimmen Verifizierer diesem Prozess jedoch im Rahmen der Verifizierer-Vereinbarung zu.

---

## 7. NIP-46 Remote-Signing

Die My Signet App kann als NIP-46-Remote-Signer fungieren. In diesem Modus:

- Signing-Anfragen treffen von einer verbundenen Nostr-Client-Anwendung über ein Nostr-Relay ein.
- Die App zeigt jede Signing-Anfrage an und bittet den Benutzer, sie zu genehmigen oder abzulehnen.
- Der private Schlüssel verlässt die App nie. Remote-Signing übermittelt den privaten Schlüssel nicht an die anfragende Anwendung oder das Relay.
- Genehmigte Signaturen werden über das Relay an die anfragende Anwendung zurückübermittelt.

Der Relay-Betreiber kann beobachten, dass eine Signing-Anfrage und -Antwort stattgefunden hat (als verschlüsselte Nostr-Ereignisse), kann jedoch den Inhalt der Signing-Anfrage oder den privaten Schlüssel nicht lesen.

---

## 8. Rechtsgrundlagen für die Verarbeitung

Wir verarbeiten Daten auf folgenden Rechtsgrundlagen, abhängig von Ihrer Rechtsordnung.

### 8.1 Europäische Union / Europäischer Wirtschaftsraum (DSGVO)

| Zweck | Rechtsgrundlage | DSGVO-Artikel |
|---------|-------------|--------------|
| Protokollbetrieb und Nachweis-Verifizierung | Berechtigtes Interesse | Art. 6(1)(f) |
| Einhaltung rechtlicher Verpflichtungen | Rechtliche Verpflichtung | Art. 6(1)(c) |
| Benutzerinitierte Nachweisausstellung | Vertragserfüllung | Art. 6(1)(b) |
| Kinderschutz und Altersverifizierung | Berechtigtes Interesse / Rechtliche Verpflichtung | Art. 6(1)(f) / Art. 6(1)(c) |

Hinweis: Biometrische Daten werden ausschließlich on-device via WebAuthn verarbeitet. Signet verarbeitet keine biometrischen Daten gemäß Artikel 9(1). Falls eine biometrische Verarbeitung durch Signet später festgestellt werden sollte, wäre die Rechtsgrundlage ausdrückliche Einwilligung gemäß Art. 9(2)(a).

**eIDAS 2.0:** Die EU-Verordnung über digitale Identitätsbrieftaschen (eIDAS 2.0) verpflichtet Mitgliedstaaten, ihren Bürgern bis Dezember 2026 digitale Identitätsbrieftaschen auszustellen. Die Architektur von Signet ist darauf ausgelegt, mit eIDAS-2.0-ausgestellten Nachweisen über den Art-31000-Identitätsbrücken-Mechanismus kompatibel zu sein.

### 8.2 Vereinigtes Königreich (UK DSGVO / Data Protection Act 2018)

Es gelten dieselben Rechtsgrundlagen wie für die EU-DSGVO, ergänzt durch den Data Protection Act 2018.

**Online Safety Act 2023:** Signets Altersverifizierungsfähigkeiten unterstützen die Einhaltung der Altersnachweis-Anforderungen des Online Safety Act 2023 und der zugehörigen Ofcom-Leitlinien. Signets Zero-Knowledge-Architektur ist darauf ausgelegt, Altersverifizierung ohne zentrale Altersverifizierungsdatenbanken zu ermöglichen.

**Age Appropriate Design Code (AADC / Children's Code):** Signet verpflichtet sich zu den 15 Standards des AADC, einschließlich Kindeswohl-Beurteilung, Datensparsamkeit, standardmäßig hohen Datenschutzeinstellungen für Kinder und altersgerechter Transparenz.

**ICO als Aufsichtsbehörde:** Das Information Commissioner's Office (ICO) ist Signets federführende Aufsichtsbehörde im Vereinigten Königreich. Kontakt: [https://ico.org.uk](https://ico.org.uk).

### 8.3 Vereinigte Staaten

**COPPA (Children's Online Privacy Protection Act):** Signet erhebt keinerlei personenbezogene Informationen von Benutzern, einschließlich Kindern unter 13 Jahren. Die Zero-Knowledge-Architektur des Protokolls bedeutet, dass kein Name, kein Geburtsdatum, keine Adresse, kein Foto oder andere unter COPPA definierte personenbezogene Informationen von Signet erhoben, gespeichert oder übermittelt werden. Die FTC-Leitlinien vom März 2026 bestätigen, dass Plattformen, die keine abgedeckten personenbezogenen Informationen erheben, außerhalb der Erhebungsbeschränkungen von COPPA liegen. Signets Ansatz, Altersverifizierung ohne Erhebung personenbezogener Informationen zu ermöglichen, ist mit der erklärten Flexibilität der FTC für datenschutzschützende Altersverifizierungsmethoden vereinbar.

**CCPA / CPRA (Kalifornien):** Wir verkaufen keine personenbezogenen Informationen. Wir geben keine personenbezogenen Informationen für kontextübergreifende Verhaltenswerbung weiter. Einwohner Kaliforniens haben das Recht zu wissen, zu löschen, zu korrigieren und sich abzumelden. Da Signet keine personenbezogenen Informationen im traditionellen Sinne erhebt, wird den meisten CCPA-Rechten durch die Architektur selbst entsprochen.

**Staatliche Datenschutzgesetze:** Wir halten anwendbare staatliche Datenschutzgesetze ein, einschließlich derjenigen von Virginia (VCDPA), Colorado (CPA), Connecticut (CTDPA), Utah (UCPA), Texas (TDPSA) und anderen Bundesstaaten mit verabschiedeter Datenschutzgesetzgebung.

**Staatliche Altersverifizierungsgesetze:** Eine Reihe von US-Bundesstaaten hat Gesetze verabschiedet, die Altersverifizierung für den Zugang zu bestimmten Online-Diensten erfordern. Signets Altersbereichsnachweise sind darauf ausgelegt, diese Anforderungen zu erfüllen, ohne zentrale Datenbanken mit Geburtsdaten oder Identitätsdokumenten der Benutzer zu erstellen.

### 8.4 Brasilien (LGPD — Lei Geral de Proteção de Dados)

Die Verarbeitung basiert auf:
- Berechtigtem Interesse (Art. 7, X)
- Einhaltung rechtlicher oder behördlicher Verpflichtungen (Art. 7, II)
- Vertragserfüllung oder vorvertraglichen Maßnahmen (Art. 7, V)

### 8.5 Südkorea (PIPA — Personal Information Protection Act)

Die Verarbeitung entspricht den PIPA-Anforderungen, einschließlich auf das notwendige Minimum beschränkter Erhebung, spezifischer Zweckbindung, Benachrichtigung über Verarbeitungszwecke und Einhaltung von Einwilligungsanforderungen.

### 8.6 Japan (APPI — Act on the Protection of Personal Information)

Die Verarbeitung entspricht dem geänderten APPI, einschließlich Festlegung des Verwendungszwecks, ordnungsgemäßen Erwerbs personenbezogener Informationen und Einhaltung grenzüberschreitender Übertragungsanforderungen.

### 8.7 China (PIPL — Personal Information Protection Law)

Wenn auf das Protokoll aus der Volksrepublik China zugegriffen wird, basiert die Verarbeitung auf individueller Einwilligung oder Vertragserfüllung, Datenlokalisierungsanforderungen werden eingehalten und grenzüberschreitende Übertragungen entsprechen PIPL Art. 38–43.

### 8.8 Indien (DPDP — Digital Personal Data Protection Act)

Die Verarbeitung entspricht dem DPDP-Gesetz, einschließlich einwilligungs- oder legitimitätsbasierter Verarbeitung, Pflichten als Datentreuhänder und Rechten der Datenprinzipale.

---

## 9. Wie wir Daten verwenden

Die durch das Signet-Protokoll verarbeiteten Daten werden ausschließlich verwendet für:

1. **Nachweisausstellung und -verifizierung** — Benutzern die Erstellung, Präsentation und Verifizierung von Nachweisen über die vier Verifizierungsstufen zu ermöglichen.
2. **Signet-IQ-Berechnung** — Berechnung von Signet-IQ-Werten basierend auf Web-of-Trust-Bürgschaften, Nachweis-Stufen, Nachweis-Aktualität und Dokumentablaufsignalen.
3. **Altersbereichsverifizierung** — Verwendung von Bulletproofs, um zu beweisen, dass ein Benutzer in einen Altersbereich fällt, ohne sein genaues Alter preiszugeben.
4. **Professionelle Verifizierung** — Lizenzierten Fachleuten (Anwälten, Notaren, Medizinern) zu ermöglichen, als Verifizierer zu handeln.
5. **Nachweis-Widerruf** — Verarbeitung von Widerrufsereignissen, wenn Nachweise ungültig werden.
6. **Protokollintegrität** — Aufrechterhaltung der kryptografischen Integrität und Sicherheit des Protokolls.
7. **Rechtliche Compliance** — Einhaltung anwendbarer Gesetze und Vorschriften.
8. **Zwei-Nachweis-Zeremonie** — Ausstellung gepaarter Natural-Person- und Persona-Nachweise während der professionellen Verifizierung, einschließlich Berechnung von Merkle-Bäumen, Nullifiern und Altersbereichsnachweisen.
9. **Vormund-Verwaltung** — Verarbeitung von Vormund-Delegierungsereignissen (Art 31000) für die Verwaltung von Kinderkonten.
10. **Selektive Offenlegung** — Benutzern zu ermöglichen, einzelne Merkle-Blatt-Attribute (einschließlich Dokumentnummer und Dokumentablaufdatum) gegenüber vertrauenden Parteien nachzuweisen, die diese benötigen, ohne nicht betroffene Attribute preiszugeben.
11. **Nachweis-Lebenszyklus** — Verarbeitung von Nachweis-Ketten (ersetzt/ersetzt-durch-Tags) für Namensänderungen, Dokumenterneuerungen und Stufenaufrüstungen.

---

## 10. Datenweitergabe und -offenlegung

### 10.1 Weitergabe auf Protokollebene

Das Signet-Protokoll operiert im Nostr-Netzwerk, das dezentralisiert ist. Wenn Sie ein Nachweis-Ereignis, eine Bürgschaft oder ein anderes Protokollereignis veröffentlichen, wird es an Nostr-Relays gesendet. Dies ist dem Design des Protokolls inhärent und wird von Ihnen initiiert.

### 10.2 Wir geben Daten nicht weiter an

- Werbetreibende oder Marketingunternehmen
- Datenhändler
- Social-Media-Plattformen (über die Nostr-Relay-Veröffentlichung hinaus)
- Regierungsbehörden (außer wenn gesetzlich vorgeschrieben oder durch ein gültiges Gerichtsverfahren)

### 10.3 Gesetzlich vorgeschriebene Offenlegung

Wir können Informationen offenlegen, wenn dies durch eine gültige Gerichtsanordnung, Vorladung oder ein rechtliches Verfahren, geltendes Recht oder Vorschriften oder eine Anfrage einer Strafverfolgungs- oder Regulierungsbehörde mit gültiger Zuständigkeit erforderlich ist. Wir werden betroffene Benutzer über solche Anfragen informieren, soweit gesetzlich zulässig. Da Signet keine personenbezogenen Daten über Benutzer in zentralisierten Systemen hält, ist der Umfang etwaig erzwingbarer Offenlegungen äußerst begrenzt.

### 10.4 Verifizierer-Datenweitergabe

Professionelle Verifizierer (Stufe 3 und Stufe 4) veröffentlichen Verifizierer-Registrierungsereignisse (Art 31000) im Nostr-Netzwerk. Diese Ereignisse enthalten den professionellen Nostr-Pubkey des Verifizierers und Jurisdiktionsinformationen. Verifizierer stimmen dieser Veröffentlichung im Rahmen der Verifizierer-Vereinbarung zu.

Die einzigen Daten, die zwischen dem Verifizierer und dem Protokoll über veröffentlichte Ereignisse ausgetauscht werden, sind das Nachweis-Ereignis (Art 31000), das den Public Key des Verifizierers, den Persona-Public-Key des Subjekts, Nachweis-Metadaten (Stufe, Daten, Entitätstyp, Altersbereich), den Zero-Knowledge-Altersbereichsnachweis, den Nullifier-Hash und die Merkle-Root enthält.

Keine personenbezogenen Identifikationsdaten (Name, Geburtsdatum, Dokumentnummern, Nationalität) erscheinen in veröffentlichten Ereignissen.

---

## 11. Internationale Datenübermittlungen

### 11.1 Dezentralisierte Architektur

Das Nostr-Netzwerk operiert global. Wenn Sie Ereignisse an Nostr-Relays veröffentlichen, können diese Ereignisse auf Relays an beliebigen Orten weltweit repliziert werden. Dies ist ein grundlegendes Merkmal des dezentralisierten Protokolls.

### 11.2 Übermittlungsmechanismen

Für jede zentralisierte Verarbeitung, die Signet durchführt, werden internationale Datenübermittlungen geschützt durch:

- **EU/EWR:** Standardvertragsklauseln (SCC) gemäß Genehmigung der Europäischen Kommission (Beschluss 2021/914), ergänzt durch Übermittlungs-Folgenabschätzungen, wo erforderlich.
- **UK:** International Data Transfer Agreement (IDTA) oder das UK-Addendum zu den EU-SCCs.
- **Südkorea:** Einhaltung der PIPA-Vorschriften für grenzüberschreitende Übermittlungen.
- **Japan:** Übermittlungen in Länder mit einem durch die PPC anerkannten angemessenen Schutzniveau oder mit Benutzereinwilligung.
- **China:** Sicherheitsbewertungen, Standardverträge oder Zertifizierungen gemäß PIPL-Anforderungen.
- **Brasilien:** Übermittlungen gemäß LGPD Art. 33, einschließlich in Länder mit angemessenem Schutzniveau oder mit spezifischen Garantien.

### 11.3 Angemessenheitsbeschlüsse

Wir stützen uns auf Angemessenheitsbeschlüsse, wo verfügbar, einschließlich des EU-US-Datenschutzrahmens, der UK-Erweiterung des EU-US-Datenschutzrahmens und des Angemessenheitsbeschlusses der Europäischen Kommission für Japan.

---

## 12. Datenspeicherung

### 12.1 Nostr-Ereignisse

Im Nostr-Netzwerk veröffentlichte Ereignisse werden von Relay-Betreibern gemäß deren eigenen Richtlinien aufbewahrt. Da das Nostr-Netzwerk dezentralisiert ist, kann Signet die Löschung von Ereignissen von allen Relays nicht garantieren.

### 12.2 Nachweis-Lebenszyklus

| Datentyp | Aufbewahrungsfrist |
|-----------|-----------------|
| Aktive Nachweise | Bis Ablauf oder Widerruf |
| Widerrufene Nachweise | Widerrufsereignisse werden zur Wahrung der Verifizierungsintegrität unbegrenzt aufbewahrt |
| Abgelaufene Nachweise | Auf Relays gemäß Relay-Betreiber-Richtlinien aufbewahrt |
| Bürgschaftsaufzeichnungen | Bis zum Widerruf durch die bürgschaftsgebende Partei |
| Challenge-/Response-Daten | Dauerhaft; als Standard-Nostr-Ereignisse auf Relays veröffentlicht, zur Protokollintegrität aufbewahrt |
| Lokales verschlüsseltes Schlüsselmaterial | Auf Ihrem Gerät, bis Sie die App löschen oder App-Daten löschen |

### 12.3 Zentrale Aufzeichnungen

Alle zentral von Signet gepflegten Aufzeichnungen (z. B. Support-Korrespondenz, Rechts-Compliance-Aufzeichnungen) werden aufbewahrt für:
- Support-Aufzeichnungen: 2 Jahre ab letzter Interaktion
- Rechts-Compliance-Aufzeichnungen: Gemäß anwendbarem Recht (typischerweise 5–7 Jahre)
- Prüfprotokolle: 3 Jahre

---

## 13. Ihre Rechte

### 13.1 Universelle Rechte

Unabhängig von Ihrer Rechtsordnung können Sie:
- Informationen darüber anfordern, welche Daten wir über Sie verarbeiten
- Berichtigung ungenauer Daten anfordern
- Die Einwilligung widerrufen, wenn die Verarbeitung auf Einwilligung basiert
- Eine Beschwerde bei uns oder einer Aufsichtsbehörde einreichen

### 13.2 Hinweis zu Architektur und Rechten

Da Signets Architektur dezentralisiert und datenschutzzentriert ist, werden viele Rechte strukturell erfüllt:

- **Zugang und Portabilität:** Ihre Nachweis-Daten werden in öffentlichen Nostr-Ereignissen gespeichert, die Sie veröffentlicht haben, und in Ihrem lokalen App-Speicher. Sie haben bereits vollen Zugang dazu.
- **Löschung:** Signet hält keine zentralisierte Kopie Ihrer personenbezogenen Daten. Wir können Nostr-Ereignisse nicht im Auftrag von Ihnen von der Infrastruktur der Relay-Betreiber löschen, können jedoch ein Widerrufsereignis ausstellen. Sie können die Löschung bei einzelnen Relay-Betreibern beantragen.
- **Berichtigung:** Falsche Nachweise können durch Ausstellung eines neuen Nachweis-Ereignisses, das das alte referenziert, ersetzt werden.

### 13.3 Europäische Union / EWR (DSGVO)

Gemäß der DSGVO haben Sie das Recht auf:
- **Auskunft** (Art. 15) — Erhalt einer Kopie Ihrer personenbezogenen Daten
- **Berichtigung** (Art. 16) — Korrektur ungenauer Daten
- **Löschung** (Art. 17) — Anforderung der Löschung („Recht auf Vergessenwerden"), wo anwendbar
- **Einschränkung** (Art. 18) — Einschränkung der Verarbeitung unter bestimmten Umständen
- **Datenübertragbarkeit** (Art. 20) — Erhalt Ihrer Daten in einem strukturierten, maschinenlesbaren Format
- **Widerspruch** (Art. 21) — Widerspruch gegen auf berechtigtem Interesse basierende Verarbeitung
- **Automatisierte Entscheidungsfindung** (Art. 22) — Nicht ausschließlich automatisierten Entscheidungen mit rechtlichen Auswirkungen unterworfen zu werden

**Aufsichtsbehörde:** Sie können eine Beschwerde bei Ihrer lokalen Datenschutzbehörde einreichen. Eine Liste der EU/EWR-DPAs ist verfügbar unter [https://edpb.europa.eu/about-edpb/about-edpb/members_en](https://edpb.europa.eu/about-edpb/about-edpb/members_en).

### 13.4 Vereinigtes Königreich (UK DSGVO)

Sie haben gleichwertige Rechte wie unter der EU-DSGVO. Sie können eine Beschwerde beim Information Commissioner's Office (ICO) unter [https://ico.org.uk](https://ico.org.uk) einreichen.

### 13.5 Vereinigte Staaten (CCPA / CPRA)

Einwohner Kaliforniens haben das Recht auf:
- **Auskunft** — Welche personenbezogenen Informationen erhoben, verwendet und offengelegt werden
- **Löschung** — Anforderung der Löschung personenbezogener Informationen
- **Berichtigung** — Anforderung der Korrektur ungenauer personenbezogener Informationen
- **Opt-out** — Abmeldung vom Verkauf oder der Weitergabe personenbezogener Informationen (wir verkaufen oder geben nicht weiter)
- **Nichtdiskriminierung** — Nicht für die Ausübung von Datenschutzrechten diskriminiert zu werden

Um diese Rechte auszuüben, kontaktieren Sie uns unter privacy@signet.id.

Einwohner von Virginia, Colorado, Connecticut, Utah, Texas und anderen Bundesstaaten mit Datenschutzgesetzgebung haben vergleichbare Rechte nach ihren jeweiligen Gesetzen.

### 13.6 Brasilien (LGPD)

Betroffene Personen haben das Recht auf Bestätigung der Verarbeitungsexistenz, Zugang zu Daten, Korrektur unvollständiger, ungenauer oder veralteter Daten, Anonymisierung, Sperrung oder Löschung unnötiger oder übermäßiger Daten, Datenübertragbarkeit, Löschung mit Einwilligung verarbeiteter Daten, Informationen über weitergegebene Daten, Informationen über die Möglichkeit, die Einwilligung zu verweigern, und Widerruf der Einwilligung.

Beschwerden an die ANPD (Autoridade Nacional de Proteção de Dados): [https://www.gov.br/anpd](https://www.gov.br/anpd).

### 13.7 Südkorea (PIPA)

Betroffene Personen haben das Recht, Zugang zu personenbezogenen Informationen zu beantragen, Korrektur oder Löschung zu beantragen, Aussetzung der Verarbeitung zu beantragen und eine Beschwerde bei der Personal Information Protection Commission (PIPC) einzureichen.

### 13.8 Japan (APPI)

Betroffene Personen haben das Recht, Offenlegung aufbewahrter personenbezogener Daten zu beantragen, Korrektur, Ergänzung oder Löschung zu beantragen, Einstellung der Nutzung oder Weitergabe an Dritte zu beantragen und eine Beschwerde bei der Personal Information Protection Commission (PPC) einzureichen.

### 13.9 China (PIPL)

Betroffene Personen haben das Recht zu wissen und über die Verarbeitung personenbezogener Informationen zu entscheiden, die Verarbeitung einzuschränken oder abzulehnen, auf personenbezogene Informationen zuzugreifen und diese zu kopieren, Portabilität zu beantragen, Berichtigung und Löschung zu beantragen und eine Erklärung der Verarbeitungsregeln zu verlangen.

### 13.10 Indien (DPDP-Gesetz)

Datenprinzipale haben das Recht auf Zugang zu Informationen über die Verarbeitung, Berichtigung und Löschung personenbezogener Daten, Beschwerderechte und die Möglichkeit, eine andere Person zur Ausübung von Rechten zu benennen.

### 13.11 Ausübung Ihrer Rechte

Um eines der oben genannten Rechte auszuüben, kontaktieren Sie uns unter:
- **E-Mail:** privacy@signet.id
- **DSB-E-Mail:** dpo@signet.id

Wir werden innerhalb der gesetzlich vorgeschriebenen Fristen antworten:
- DSGVO/UK DSGVO: 30 Tage (verlängerbar um 60 Tage für komplexe Anfragen)
- CCPA/CPRA: 45 Tage (verlängerbar um 45 Tage)
- LGPD: 15 Tage
- PIPA: 10 Tage
- APPI: Ohne Verzögerung
- PIPL: Unverzüglich

---

## 14. Kinderdaten

### 14.1 Allgemeine Richtlinie

Das Signet-Protokoll umfasst Stufe 4 (Professionelle Verifizierung — Erwachsener + Kind), die speziell für den Kinderschutz konzipiert ist. Wir nehmen den Schutz der Daten von Kindern äußerst ernst. Kinder unter 18 Jahren dürfen nur unter Stufe 4 mit aktiver Beteiligung eines verifizierten erwachsenen Vormunds verifiziert werden, dem ein Stufe-4-Nachweis ausgestellt wird, der seinen Pubkey über einen Guardian-Tag mit dem Nachweis des Kindes verknüpft.

### 14.2 Altersverifizierung

Das Protokoll verwendet auf Bulletproofs basierende Zero-Knowledge-Beweise für die Altersbereichsverifizierung. Diese Beweise zeigen, dass ein Benutzer in einen bestimmten Altersbereich fällt (z. B. „0–3", „4–7", „8–12", „13–17", „18+"), ohne sein genaues Geburtsdatum preiszugeben.

### 14.3 Rechtsordnungsspezifische Altersanforderungen

| Rechtsordnung | Mindestalter für digitale Einwilligung | Geltendes Recht |
|-------------|-------------------------------|---------------|
| EU (Standard) | 16 Jahre | DSGVO Art. 8 |
| EU (Mitgliedstaatsoption) | 13–16 Jahre (je nach Mitgliedstaat) | DSGVO Art. 8(1) |
| Vereinigtes Königreich | 13 Jahre | UK DSGVO / Children's Code |
| Vereinigte Staaten | 13 Jahre | COPPA |
| Brasilien | 12 Jahre (elterliche Einwilligung bis 18 erforderlich) | LGPD Art. 14 |
| Südkorea | 14 Jahre | PIPA |
| Japan | 15 Jahre (Richtlinien) | APPI |
| China | 14 Jahre | PIPL Art. 28 |
| Indien | 18 Jahre (mit Ausnahmen) | DPDP-Gesetz |

### 14.4 Elterliche Einwilligung

Wo elterliche Einwilligung erforderlich ist, unterstützt das Protokoll:
- Nachweisbare elterliche Einwilligung durch Stufe-3- oder Stufe-4-verifizierte Elternteil-/Vormund-Nachweise
- Alters-Gating durch ZK-Nachweis-Verifizierung auf Ebene der vertrauenden Partei
- Vormund-Delegierungsereignisse (Art 31000), die Eltern die Verwaltung der Signet-Aktivität ihrer Kinder ermöglichen
- Mechanismen für Eltern, Delegierung und Einwilligung zu widerrufen

### 14.5 COPPA-Compliance (Vereinigte Staaten)

Signet erhebt keinerlei personenbezogene Informationen von Benutzern, einschließlich Kindern unter 13 Jahren. Die Zero-Knowledge-Architektur des Protokolls bedeutet, dass kein Name, kein Geburtsdatum, keine Adresse oder andere unter COPPA abgedeckte personenbezogene Informationen von Signet erhoben, gespeichert oder übermittelt werden. Die FTC-Leitlinien vom März 2026 erkennen Flexibilität für Plattformen an, die datenschutzschützende Verifizierung ohne Erhebung abgedeckter personenbezogener Informationen implementieren.

### 14.6 Age Appropriate Design Code (Vereinigtes Königreich)

Signet verpflichtet sich zu den Grundsätzen des UK Age Appropriate Design Code (Children's Code), einschließlich Kindeswohl-Beurteilung, altersgerechter Anwendung, Datensparsamkeit, standardmäßig kindesschützenden Einstellungen und dem Alter des Kindes angemessener Transparenz.

---

## 15. Sicherheit

### 15.1 Kryptografische Sicherheit

Das Signet-Protokoll verwendet:
- **Schnorr-Signaturen** auf der secp256k1-Kurve für alle Nachweis-Unterzeichnungen
- **Bulletproofs** für Zero-Knowledge-Altersbereichsnachweise
- **Ringsignaturen** (SAG und LSAG) für anonyme Gruppenmitgliedschaftsnachweise mit Domänentrennungs-Tags und Ringgrößenlimits (maximal 1.000 Mitglieder)
- **RFC-6962-Merkle-Bäume** mit Domänentrennung (`0x00`-Blatt-Präfix, `0x01`-interner-Knoten-Präfix) für manipulationsevidente Attributverpflichtungen
- **ECDH** mit Identitätspunkt-Ablehnung für Shared-Secret-Ableitung
- **Zukünftige ZK-Schicht** für zusätzliche Beweistypen (ZK-SNARKs/ZK-STARKs) geplant

### 15.2 Schlüsselspeicher-Sicherheit

Private Schlüssel in der My Signet App sind:
- Im Ruhezustand mit AES-256-GCM verschlüsselt
- Der Verschlüsselungsschlüssel wird via PBKDF2 mit SHA-256 und 600.000 Iterationen (OWASP-2023-Empfehlung) unter Verwendung eines zufälligen Salts abgeleitet
- Schlüssel werden nur während einer authentifizierten Sitzung im Speicher gehalten
- Mnemonic-Phrasen und private Schlüssel werden niemals an Signet oder Dritte übermittelt
- Nie im Klartext in IndexedDB, localStorage oder einem anderen Speichermechanismus gespeichert

### 15.3 Eingabevalidierung

Alle Ereignis-Validatoren erzwingen maximale Inhaltslänge (64 KB), maximale Tag-Anzahl (100 Tags), maximale Tag-Wert-Länge (1.024 Zeichen) und Integer-Grenzprüfungen zur Verhinderung stiller Sicherheitsumgehungen.

### 15.4 Dezentralisiertes Sicherheitsmodell

Die dezentralisierte Architektur des Protokolls bietet inhärente Sicherheitsvorteile: kein Single Point of Failure, keine zentrale Datenbank, die gehackt werden kann, benutzerkontrollierte Schlüsselverwaltung und kryptografische Verifizierung ohne vertrauenswürdige Zwischenstellen.

### 15.5 Verletzungsmeldung

Im Falle einer Verletzung personenbezogener Daten, die zentrale Signet-Systeme betrifft, werden wir:
- Die zuständige Aufsichtsbehörde innerhalb von 72 Stunden (DSGVO) oder gemäß anwendbarem Recht benachrichtigen
- Betroffene Personen ohne unangemessene Verzögerung informieren, wenn die Verletzung wahrscheinlich ein hohes Risiko für ihre Rechte und Freiheiten darstellt
- Die Verletzung, ihre Auswirkungen und die Abhilfemaßnahmen dokumentieren

---

## 16. Cookies und Tracking-Technologien

Das Signet-Protokoll verwendet **keine**:
- Cookies
- Web-Beacons oder Tracking-Pixel
- Browser-Fingerprinting
- Lokalen Speicher für Tracking-Zwecke
- Drittanbieter-Analyse- oder Tracking-Dienste

Wenn Hilfsdienste (wie eine Dokumentationswebsite) Cookies verwenden, wird ein separater Cookie-Hinweis mit geeigneten Einwilligungsmechanismen bereitgestellt.

---

## 17. Automatisierte Entscheidungsfindung und Profiling

### 17.1 Signet-IQ-Berechnung

Das Protokoll berechnet Signet-IQ-Werte (0–200, wobei 100 den aktuellen staatlichen Identitätsstandard repräsentiert) basierend auf Verifizierungsstufen-Niveau, Anzahl und Qualität der Bürgschaften, Verifizierer-Nachweisen und -Status, Nachweis-Alter und Dokumentablaufsignalen. Diese Werte werden algorithmisch berechnet und sind für vertrauende Parteien sichtbar. Sie stellen keine automatisierte Entscheidungsfindung mit rechtlichen Auswirkungen gemäß DSGVO Art. 22 dar, da sie nur ein Eingangsparameter unter vielen sind, den vertrauende Parteien berücksichtigen können.

### 17.2 Kein Profiling für Marketing

Wir betreiben kein Profiling für Marketing-, Werbe- oder Verhaltensanalysezwecke.

---

## 18. Links und Dienste Dritter

Das Signet-Protokoll interoperiert mit:
- Nostr-Relays (unabhängig betrieben)
- Nostr-Clients (wie Fathom, dem Referenzimplementierungs-Client)
- Berufsverbänden und Regulierungsregistern (über den quelloffenen Verifizierungsbot)
- Dem Dokumententyp-Register (eine externe YAML-Datei mit Dokumentfeld-Definitionen pro Land — enthält keine personenbezogenen Daten)

Diese Dritten haben eigene Datenschutzrichtlinien. Signet ist nicht verantwortlich für ihre Datenpraktiken.

---

## 19. Änderungen dieser Datenschutzerklärung

Wir können diese Datenschutzerklärung von Zeit zu Zeit aktualisieren. Änderungen werden durch Aktualisierung des „Zuletzt aktualisiert"-Datums am Anfang dieses Dokuments angezeigt. Bei wesentlichen Änderungen werden wir über eine Nostr-Ereignis-Ankündigung und eine Aktualisierung des Protokoll-Spezifikations-Repositorys informieren. Ihre fortgesetzte Nutzung des Protokolls nach Änderungen stellt die Akzeptanz der aktualisierten Datenschutzerklärung dar.

---

## 20. Rechtsordnungsspezifische Bestimmungen

### 20.1 Europäische Union — Zusätzliche Bestimmungen

Wo wir personenbezogene Daten gemäß der DSGVO verarbeiten, haben die Bestimmungen der DSGVO Vorrang vor widersprüchlichen Bestimmungen in dieser Datenschutzerklärung. Bezüglich eIDAS 2.0: Signets Protokoll ist darauf ausgelegt, Identitätsbrücken-Ereignisse von EU-Digital-Identitätsbrieftaschen zu akzeptieren, wenn diese Brieftaschen von Mitgliedstaaten bereitgestellt werden, voraussichtlich bis Dezember 2026.

### 20.2 Vereinigtes Königreich — Zusätzliche Bestimmungen

**ICO-Registrierung:** Signet wird sich beim ICO registrieren, wie erforderlich. Registrierungsdetails werden unter signet.id/legal veröffentlicht.

**Keine Weitergabe meiner personenbezogenen Informationen:** Wir verkaufen oder teilen keine personenbezogenen Informationen.

**Online Safety Act:** Signets Altersverifizierungsfähigkeiten sind darauf ausgelegt, mit den Altersnachweis-Anforderungen des Online Safety Act 2023 kompatibel zu sein.

### 20.3 Kalifornien — Zusätzliche Bestimmungen

**Keine Weitergabe meiner personenbezogenen Informationen:** Wir verkaufen oder teilen keine personenbezogenen Informationen im Sinne des CCPA/CPRA.

**Finanzielle Anreize:** Wir bieten keine finanziellen Anreize im Zusammenhang mit der Erhebung personenbezogener Informationen an.

**Shine the Light (Cal. Civ. Code Section 1798.83):** Einwohner Kaliforniens können Informationen über Offenlegungen personenbezogener Informationen an Dritte für Direktmarketing anfordern. Wir machen solche Offenlegungen nicht.

### 20.4 Brasilien — Zusätzliche Bestimmungen

Der DSB (Encarregado) kann unter dpo@signet.id für alle LGPD-bezogenen Anfragen kontaktiert werden.

### 20.5 Australien — Zusätzliche Bestimmungen

Wir halten die Australian Privacy Principles (APPs) gemäß dem Privacy Act 1988 (Cth) ein. Sie können eine Beschwerde beim Office of the Australian Information Commissioner (OAIC) einreichen.

### 20.6 Neuseeland — Zusätzliche Bestimmungen

Wir halten den Privacy Act 2020 (NZ) ein. Sie können eine Beschwerde beim Office of the Privacy Commissioner einreichen.

### 20.7 Singapur — Zusätzliche Bestimmungen

Wir halten den Personal Data Protection Act 2012 (PDPA) ein. Sie können die Personal Data Protection Commission (PDPC) für Beschwerden kontaktieren.

### 20.8 Südafrika — Zusätzliche Bestimmungen

Wir halten den Protection of Personal Information Act 2013 (POPIA) ein. Sie können eine Beschwerde beim Information Regulator einreichen.

---

## 21. Kontakt

Bei Fragen, Bedenken oder Anfragen im Zusammenhang mit dieser Datenschutzerklärung oder unseren Datenpraktiken:

**Allgemeine Anfragen:**
Das Signet-Protokoll
E-Mail: privacy@signet.id

**Datenschutzbeauftragter:**
E-Mail: dpo@signet.id

---

## 22. Behördliche Anmeldungen

Je nach Rechtsordnung unterhält oder wird Signet Registrierungen oder Anmeldungen bei folgenden Stellen unterhalten:
- Das Information Commissioner's Office (UK) — Registrierung in Bearbeitung; Details werden unter signet.id/legal veröffentlicht
- Anwendbare EU/EWR-Datenschutzbehörden
- Andere Regulierungsstellen, wie gesetzlich vorgeschrieben

---

*Diese Datenschutzerklärung beschreibt die Datenpraktiken des Signet-Protokolls Stand März 2026. Das Signet-Protokoll ist quelloffene Software. Dieses Dokument stellt keine Rechtsberatung dar. Benutzer und Betreiber sollten qualifizierten Rechtsrat einholen, der mit den anwendbaren Datenschutzgesetzen in ihrer Rechtsordnung vertraut ist.*

*Signet-Protokoll — v0.1.0*
*Dokumentversion: 2.0*
