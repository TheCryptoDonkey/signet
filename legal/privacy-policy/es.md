> **Aviso de traducción automática:** Este documento ha sido traducido al español mediante inteligencia artificial. La versión en inglés disponible en `en.md` es el único documento jurídicamente vinculante. En caso de discrepancia entre la versión en español y la versión en inglés, prevalecerá la versión en inglés.

---

# Política de Privacidad

**Protocolo Signet — v0.1.0**

**Fecha de entrada en vigor:** Marzo de 2026
**Última actualización:** Marzo de 2026

---

## 1. Introducción

La presente Política de Privacidad describe cómo el Protocolo Signet ("Signet", "nosotros", "nos" o "nuestro") recopila, utiliza, divulga y protege la información en relación con el Protocolo Signet (el "Protocolo") y la aplicación My Signet (la "Aplicación"). Signet es un protocolo de verificación de identidad descentralizado y de código abierto para la red Nostr que utiliza pruebas de conocimiento cero, firmas en anillo y credenciales criptográficas.

Signet está diseñado con la privacidad como núcleo. Permite a los usuarios demostrar afirmaciones sobre su identidad —tales como rango de edad, estatus profesional o jurisdicción geográfica— sin revelar los datos personales subyacentes. Esta Política de Privacidad explica qué interacciones de datos limitadas ocurren, dónde permanecen los datos y cómo se gestionan.

Esta Política se aplica a todos los usuarios, verificadores, partes confiantes y demás participantes que interactúen con el Protocolo Signet o la aplicación My Signet, independientemente de su ubicación.

La descripción canónica del protocolo es `spec/protocol.md` en el repositorio de código abierto de Signet.

---

## 2. Responsable del Tratamiento

**Responsable del Tratamiento:** El Protocolo Signet
**Correo electrónico de contacto:** privacy@signet.id
**Delegado de Protección de Datos (DPO):** dpo@signet.id

Para las jurisdicciones que requieran un representante local, comuníquese con el DPO en la dirección anterior. Los nombramientos formales de representantes para los fines del RGPD de la UE (Art. 27 del RGPD) y del RGPD del Reino Unido (Art. 27 del UK GDPR) se publicarán en signet.id/legal.

---

## 3. Datos que Recopilamos y Tratamos

El Protocolo Signet está diseñado para minimizar la recopilación de datos. Dado que el Protocolo utiliza pruebas de conocimiento cero, firmas en anillo y verificación descentralizada de credenciales, la gran mayoría de la información permanece únicamente bajo el control del usuario y nunca es transmitida a Signet ni accesible por Signet.

### 3.1 Categorías de Datos

| Categoría | Descripción | Fuente | Ubicación de Almacenamiento |
|-----------|-------------|--------|----------------------------|
| **Claves Públicas Nostr** | Claves públicas secp256k1 (npub) utilizadas para las interacciones del Protocolo | Generadas por el usuario | Relays Nostr (descentralizados) |
| **Metadatos de Credenciales** | Eventos Nostr de kinds 31000–31000 que contienen el nivel de verificación, marcas de tiempo de emisión, fechas de vencimiento, rango de edad e identificadores de tipo de entidad | Generados durante la emisión de credenciales | Relays Nostr (descentralizados) |
| **Pruebas de Conocimiento Cero** | Bulletproofs para la verificación de rango de edad | Generadas localmente por el usuario | Integradas en eventos de credenciales en relays Nostr |
| **Firmas en Anillo** | Firmas criptográficas que prueban la pertenencia a un grupo sin revelar qué miembro firmó | Generadas localmente por el usuario | Relays Nostr (descentralizados) |
| **Hashes de Nullifier** | Hash SHA-256 del tipo de documento con longitud prefijada, código de país, número de documento y etiqueta de dominio "signet-nullifier-v2" — previene la creación de identidades duplicadas; no se puede invertir para recuperar los datos del documento | Calculados localmente durante la ceremonia de doble credencial | Integrados en eventos de credenciales de Persona Natural |
| **Raíces Merkle** | Compromiso de hash con los atributos verificados que permite la divulgación selectiva. Las hojas incluyen nombre, nacionalidad, documentType, dateOfBirth, documentNumber, documentExpiry, photoHash y nullifier. Solo se publica el hash raíz — los valores individuales de las hojas nunca se publican | Calculadas localmente durante la ceremonia de doble credencial | Integradas en eventos de credenciales de Persona Natural |
| **Registros de Aval** | Eventos kind 31000 que representan respaldos de la red de confianza | Creados por las partes avalantes | Relays Nostr (descentralizados) |
| **Eventos de Política** | Eventos kind 30078 que especifican los requisitos de las partes confiantes | Creados por las partes confiantes | Relays Nostr (descentralizados) |
| **Registro de Verificadores** | Eventos kind 31000 que identifican a los verificadores profesionales, incluida la clave pública de firma profesional e información jurisdiccional | Creados por los verificadores | Relays Nostr (descentralizados) |
| **Datos de Desafío/Respuesta** | Eventos kind 31000 para desafíos de legitimidad del verificador | Generados durante la verificación | Relays Nostr (descentralizados) |
| **Registros de Revocación** | Eventos kind 31000 para la revocación de credenciales | Creados cuando se revocan credenciales | Relays Nostr (descentralizados) |
| **Eventos de Puente de Identidad** | Eventos kind 31000 que vinculan los keypairs de Persona Natural y Persona mediante firmas en anillo | Creados por el usuario | Relays Nostr (descentralizados) |
| **Eventos de Delegación** | Eventos kind 31000 para la delegación de agente o tutor con permisos delimitados | Creados por el delegante | Relays Nostr (descentralizados) |
| **Material de Clave Cifrado** | Claves privadas cifradas con AES-256-GCM (clave derivada mediante PBKDF2, 600.000 iteraciones, SHA-256) | Almacenado localmente en el dispositivo | Solo almacenamiento local en el dispositivo — nunca transmitido |

### 3.2 Qué Permanece en su Dispositivo

La siguiente información es tratada en su dispositivo y nunca es transmitida a Signet ni almacenada por Signet:

- **Claves privadas y frase mnemónica** — Su mnemónico BIP-39 de 12 palabras y las claves privadas derivadas de él (keypairs tanto de Persona Natural como de Persona, derivados mediante derivación HD BIP-32 en rutas NIP-06) permanecen en su dispositivo en todo momento, cifradas en reposo.
- **Datos del documento introducidos durante la ceremonia** — Su número de documento, fecha de vencimiento del documento, fecha de nacimiento, nombre, nacionalidad y cualquier fotografía que presente. Estos son introducidos por usted en la aplicación, utilizados para calcular el árbol Merkle y el nullifier, y luego descartados. Los valores individuales de las hojas son retenidos por usted en su registro de credenciales local para futura divulgación selectiva. No se transmiten a Signet ni se envían al verificador electrónicamente — el verificador inspecciona sus documentos físicos en persona y confirma los datos que usted ha introducido.
- **Valores de hojas Merkle** — Los valores individuales de atributos (nombre, fecha de nacimiento, número de documento, fecha de vencimiento del documento, hash de fotografía, nacionalidad, tipo de documento, nullifier) se almacenan como hojas Merkle en su registro de credenciales local, lo que le permite demostrar atributos individuales mediante pruebas de divulgación selectiva. Solo el hash raíz Merkle se publica en cadena.
- **Datos biométricos** — Véase la Sección 3.3.
- **Fechas exactas de nacimiento** — Las pruebas de rango de edad revelan únicamente que usted se encuentra dentro de un rango (por ejemplo, "18+"), no su fecha exacta de nacimiento.

### 3.3 Autenticación Biométrica (Datos de Categoría Especial)

La aplicación My Signet admite la autenticación biométrica mediante la **API WebAuthn con la extensión PRF (Función Pseudoaleatoria)**, con PIN como opción alternativa.

**Funcionamiento:**
- Al registrar sus datos biométricos, el autenticador de plataforma de su dispositivo (sensor de huella dactilar, Face ID o equivalente) crea una credencial WebAuthn. La credencial permanece en el enclave seguro o TPM de su dispositivo.
- La extensión PRF de WebAuthn deriva material de clave criptográfica de su afirmación biométrica. Este material de clave se utiliza para descifrar sus claves privadas cifradas durante una sesión autenticada.
- **Ninguna plantilla biométrica es transmitida jamás a Signet.** Ningún dato biométrico sale de su dispositivo. Signet nunca recibe, almacena ni trata ninguna información biométrica.
- El ID de credencial WebAuthn se almacena en el almacenamiento local de su dispositivo para identificar qué credencial afirmar durante la autenticación. Este es un identificador aleatorio, no una plantilla biométrica.

Bajo el Artículo 9 del RGPD y el UK GDPR, los datos biométricos utilizados con el propósito de identificar de forma única a una persona física son datos de categoría especial. Dado que el tratamiento biométrico se realiza íntegramente en su dispositivo local mediante el hardware seguro integrado de la plataforma, y que ningún dato biométrico es transmitido a los sistemas de Signet ni tratado por ellos, Signet no actúa como responsable del tratamiento ni como encargado del tratamiento de datos biométricos. El tratamiento está bajo su control exclusivo.

Si su dispositivo no admite WebAuthn PRF, la aplicación recurre a un PIN, derivado mediante PBKDF2-SHA-256 (600.000 iteraciones) para producir una clave de descifrado AES-256-GCM.

### 3.4 Datos que NO Recopilamos

Por diseño, el Protocolo Signet **no** recopila, trata ni almacena:

- Nombres reales, direcciones o números de identificación gubernamental
- Fechas exactas de nacimiento (las pruebas de rango de edad revelan únicamente un rango)
- Números de documento o fechas de vencimiento de documentos (tratados localmente para calcular las hojas Merkle; los valores individuales no se transmiten a Signet ni al verificador electrónicamente)
- Datos biométricos (tratados localmente en el dispositivo mediante WebAuthn; nunca transmitidos)
- Información financiera o datos de pago
- Datos de ubicación o direcciones IP (a nivel de Protocolo; los operadores de relay pueden recopilar independientemente direcciones IP)
- Historial de navegación o huellas digitales del dispositivo
- Direcciones de correo electrónico (a menos que se proporcionen voluntariamente para soporte)
- Fotografías o imágenes (se puede incluir un hash de fotografía como hoja Merkle, pero la imagen en sí permanece en su dispositivo)
- Los datos subyacentes detrás de cualquier prueba de conocimiento cero

### 3.5 Datos Tratados por Terceros

Los operadores de relay Nostr tratan de forma independiente los datos transmitidos a través de sus relays. Sus prácticas de datos están regidas por sus propias políticas de privacidad. Signet no controla a los operadores de relay.

---

## 4. La Ceremonia de Doble Credencial

Esta sección explica el proceso de verificación profesional en detalle, ya que es la interacción más intensiva en datos del Protocolo.

### 4.1 Funcionamiento de la Ceremonia

1. **Usted introduce sus propios datos.** En la aplicación My Signet, usted introduce su nombre, fecha de nacimiento, nacionalidad, tipo de documento, número de documento, fecha de vencimiento del documento y, opcionalmente, proporciona o fotografía su documento. La aplicación calcula el árbol Merkle y el nullifier localmente.

2. **El verificador inspecciona sus documentos físicos.** Un verificador de Nivel 3 o Nivel 4 (un profesional autorizado como un abogado, notario o médico) examina sus documentos de identidad físicos en persona. El verificador confirma que los datos que ha introducido coinciden con sus documentos. El verificador no introduce sus datos en el sistema de forma independiente.

3. **El verificador firma la credencial.** El verificador firma dos eventos de credencial: una credencial de Persona Natural (kind 31000, firmada por el keypair Nostr profesional del verificador) y una credencial de Persona (anónima, solo rango de edad, también firmada por el verificador). Ambas se publican en los relays Nostr.

4. **Qué se publica.** Los eventos de credencial publicados contienen: la clave pública del verificador, su clave pública de Persona (clave pública del sujeto), metadatos de credencial (nivel, fechas, tipo de entidad, rango de edad), la prueba de rango de edad de conocimiento cero, el hash del nullifier (un hash unidireccional; no se puede invertir) y la raíz Merkle (un compromiso de hash; los valores individuales de las hojas no se publican). No se publica ningún nombre, fecha de nacimiento, número de documento ni otra información de identificación.

5. **Qué retiene usted localmente.** Su registro de credenciales local contiene los valores individuales de las hojas Merkle (nombre, nacionalidad, fecha de nacimiento, tipo de documento, número de documento, fecha de vencimiento del documento, nullifier y opcionalmente hash de fotografía). Usted los utiliza para generar pruebas de divulgación selectiva cuando posteriormente desee demostrar atributos específicos (por ejemplo, demostrar su número de pasaporte al facturar para un vuelo).

### 4.2 Número de Documento y Fecha de Vencimiento como Hojas Merkle

A diferencia de versiones anteriores del Protocolo, el número de documento y la fecha de vencimiento del documento **no** se descartan después de la ceremonia. Se retienen como hojas Merkle en su registro de credenciales local. Esto le permite:

- Demostrar su número de pasaporte a una parte confiante que lo requiera (por ejemplo, una aerolínea) mediante una prueba de inclusión Merkle, sin revelar otros atributos.
- Soportar la degradación acelerada del Signet IQ cuando se aproxima la fecha de vencimiento de su documento, proporcionando a las partes confiantes una señal sobre la actualidad de su evidencia de identidad subyacente.

Solo usted controla qué atributos divulga y a quién. Los valores individuales de las hojas nunca se transmiten a Signet ni son accesibles por Signet.

### 4.3 Formato del Nullifier

El nullifier se calcula como:

```
SHA-256(len16(docType) || docType || len16(countryCode) || countryCode || len16(docNumber) || docNumber || len16("signet-nullifier-v2") || "signet-nullifier-v2")
```

donde `len16(x)` es la longitud en bytes UTF-8 de `x` codificada como un uint16 de 2 bytes en orden big-endian. La etiqueta de dominio `signet-nullifier-v2` distingue este esquema de cualquier versión anterior. El hash del nullifier permite al Protocolo detectar registros de identidad duplicados sin revelar qué documento fue utilizado.

---

## 5. Modelo de Doble Keypair

Cada usuario de Signet tiene dos keypairs derivados de un único mnemónico BIP-39 de 12 palabras:

- **Keypair de Persona Natural** — derivado mediante la ruta NIP-06 `m/44'/1237'/0'/0/0`. Utilizado para la credencial de Persona Natural (kind 31000). Este keypair está asociado con su identidad real verificada en el mundo real a través de la credencial, pero el keypair en sí no lleva ningún vínculo inherente con sus documentos.
- **Keypair de Persona** — derivado mediante la ruta HD BIP-32 en un índice de cuenta separado. Utilizado para la credencial de Persona (anónima, solo rango de edad). Este keypair no lleva ningún vínculo directo con su identidad real. Su actividad social en línea utiliza este keypair.

**Implicación para la privacidad:** Dado que ambos keypairs se derivan del mismo mnemónico, usted puede demostrar el vínculo entre ellos (mediante eventos de puente de identidad kind 31000) o mantenerlos completamente separados. Un evento de puente de identidad, una vez publicado, crea un vínculo criptográfico público. Solo debe publicar un evento de puente si desea asociar su Persona anónima con su estado de Persona Natural verificada.

**Gestión de claves y derechos de los interesados:** Sus claves privadas se derivan de forma determinista de su mnemónico. Signet nunca posee ni transmite sus claves privadas. Si elimina la aplicación y pierde su mnemónico (y cualquier copia de seguridad Shamir), sus claves son irrecuperables. Signet no puede ayudar con la recuperación de claves porque no tenemos copias.

---

## 6. El SDK signet-verify.js

El ecosistema My Signet incluye `signet-verify.js`, un SDK de JavaScript que los sitios web integran para solicitar verificación de edad o identidad a sus visitantes.

### 6.1 Funcionamiento del SDK

1. Un sitio web integra `signet-verify.js` y llama a `Signet.verifyAge('18+')` (o similar).
2. El SDK abre un modal de verificación en el sitio web.
3. El usuario aprueba la solicitud en la aplicación My Signet. La prueba de credencial se transmite de vuelta al sitio web mediante un BroadcastChannel (comunicación en el mismo dispositivo; sin servidor involucrado).
4. El SDK verifica la firma Schnorr en el evento de credencial y comprueba que la clave pública del verificador está registrada y confirmada.
5. El SDK devuelve un resultado al sitio web.

### 6.2 Qué Datos Recibe el Sitio Web

Un sitio web que utilice `signet-verify.js` recibe:

| Campo | Descripción |
|-------|-------------|
| `verified` | Booleano: ¿cumple la credencial el requisito declarado? |
| `ageRange` | Cadena de rango de edad (p. ej., "18+") — nunca la fecha exacta de nacimiento |
| `tier` | Nivel de verificación (1–4) |
| `entityType` | Clasificación de cuenta (Persona Natural, Persona, etc.) |
| `credentialId` | ID del evento de credencial (un identificador de evento Nostr público) |
| `verifierPubkey` | La clave pública Nostr del verificador |
| `verifierConfirmed` | Si el verificador ha sido confirmado en un registro profesional público |
| `issuedAt` / `expiresAt` | Marcas de tiempo de validez de la credencial |

**No se transmite ninguna información de identificación personal al sitio web.** El sitio web no recibe su nombre, fecha de nacimiento, número de documento ni ningún valor de hoja Merkle. La comunicación mediante BroadcastChannel es local al dispositivo — el intercambio de verificación no pasa por ningún servidor de Signet.

### 6.3 Bot de Verificación

Signet opera un bot de verificación de código abierto que comprueba los registros de verificadores en registros profesionales públicos (por ejemplo, el registro del Consejo Médico General, el registro de la Autoridad de Regulación de Abogados, los registros de la Agencia de Regulación de la Enseñanza). El bot publica sus hallazgos como eventos Nostr.

La clave pública Nostr profesional del verificador es una clave de firma creada específicamente que se utiliza únicamente para las verificaciones de Signet. No tiene ninguna identidad social inherente. El bot recibe esta clave pública para consultar registros públicos. El envío de una clave pública profesional al bot para la comprobación en registros no es una transferencia de datos personales bajo el RGPD, porque la clave pública es un identificador criptográfico seudónimo creado específicamente para esta función. Sin embargo, por abundante cautela, los verificadores dan su consentimiento a este proceso como parte del Acuerdo de Verificador.

---

## 7. Firma Remota NIP-46

La aplicación My Signet puede actuar como firmante remoto NIP-46. En este modo:

- Las solicitudes de firma llegan desde una aplicación cliente Nostr conectada mediante un relay Nostr.
- La aplicación muestra cada solicitud de firma y pide al usuario que la apruebe o rechace.
- La clave privada nunca sale de la aplicación. La firma remota no transmite la clave privada a la aplicación solicitante ni al relay.
- Las firmas aprobadas se transmiten de vuelta a la aplicación solicitante mediante el relay.

El operador del relay puede observar que se produjo una solicitud y respuesta de firma (como eventos Nostr cifrados), pero no puede leer el contenido de la solicitud de firma ni la clave privada.

---

## 8. Bases Jurídicas para el Tratamiento

Tratamos los datos bajo las siguientes bases jurídicas, según su jurisdicción.

### 8.1 Unión Europea / Espacio Económico Europeo (RGPD)

| Propósito | Base Jurídica | Artículo del RGPD |
|-----------|---------------|-------------------|
| Operación del Protocolo y verificación de credenciales | Interés legítimo | Art. 6(1)(f) |
| Cumplimiento de obligaciones legales | Obligación legal | Art. 6(1)(c) |
| Emisión de credenciales iniciada por el usuario | Ejecución de un contrato | Art. 6(1)(b) |
| Seguridad infantil y verificación de edad | Interés legítimo / Obligación legal | Art. 6(1)(f) / Art. 6(1)(c) |

Nota: Los datos biométricos se tratan exclusivamente en el dispositivo mediante WebAuthn. Signet no trata datos biométricos bajo el Artículo 9(1). Si en el futuro se estableciera algún tratamiento biométrico por parte de Signet, la base jurídica sería el consentimiento explícito bajo el Art. 9(2)(a).

**eIDAS 2.0:** El Reglamento de Cartera de Identidad Digital de la UE (eIDAS 2.0) exige que los Estados miembros emitan carteras de identidad digital a los ciudadanos antes de diciembre de 2026. La arquitectura de Signet está diseñada para ser compatible con las credenciales emitidas por eIDAS 2.0 mediante el mecanismo de puente de identidad kind 31000.

### 8.2 Reino Unido (UK GDPR / Ley de Protección de Datos de 2018)

Se aplican las mismas bases jurídicas que en el RGPD de la UE, complementadas por la Ley de Protección de Datos de 2018.

**Ley de Seguridad en Línea de 2023:** Las capacidades de verificación de edad de Signet apoyan el cumplimiento de los requisitos de aseguramiento de edad de la Ley de Seguridad en Línea de 2023 y la orientación asociada de Ofcom. La arquitectura de conocimiento cero de Signet está diseñada para permitir la verificación de edad sin crear bases de datos centralizadas de verificación de edad.

**Código de Diseño Apropiado para la Edad (AADC / Código para Menores):** Signet está comprometido con los 15 estándares del AADC, incluida la evaluación del interés superior del menor, la minimización de datos, la configuración predeterminada de alta privacidad para menores y la transparencia apropiada para la edad.

**ICO como Autoridad de Supervisión:** La Oficina del Comisionado de Información (ICO) es la autoridad de supervisión principal de Signet en el Reino Unido. Contacto: [https://ico.org.uk](https://ico.org.uk).

### 8.3 Estados Unidos

**COPPA (Ley de Protección de la Privacidad en Línea de los Niños):** Signet no recopila ninguna información personal de ningún usuario, incluidos los menores de 13 años. La arquitectura de conocimiento cero del Protocolo significa que ningún nombre, fecha de nacimiento, dirección, fotografía ni cualquier otra información personal definida bajo COPPA es recopilada, almacenada o transmitida por Signet. La guía de la FTC de marzo de 2026 confirma que las plataformas que no recopilan información personal cubierta están fuera de las restricciones de recopilación de COPPA. El enfoque de Signet de permitir la verificación de edad sin recopilar información personal es coherente con la flexibilidad declarada por la FTC para los métodos de verificación de edad que preservan la privacidad.

**CCPA / CPRA (California):** No vendemos información personal. No compartimos información personal para publicidad conductual entre contextos. Los residentes de California tienen derecho a conocer, eliminar, corregir y excluirse. Dado que Signet no recopila información personal en el sentido tradicional, la mayoría de los derechos de la CCPA quedan satisfechos por la propia arquitectura.

**Leyes estatales de privacidad:** Cumplimos con las leyes de privacidad estatales aplicables, incluidas las de Virginia (VCDPA), Colorado (CPA), Connecticut (CTDPA), Utah (UCPA), Texas (TDPSA) y otros estados con legislación de privacidad promulgada.

**Leyes estatales de verificación de edad:** Varios estados de EE. UU. han promulgado leyes que exigen la verificación de edad para el acceso a ciertos servicios en línea. Las pruebas de rango de edad de Signet están diseñadas para satisfacer estos requisitos sin crear bases de datos centralizadas con las fechas de nacimiento o los documentos de identidad de los usuarios.

### 8.4 Brasil (LGPD — Lei Geral de Proteção de Dados)

El tratamiento se basa en:
- Interés legítimo (Art. 7, X)
- Cumplimiento de obligaciones legales o reglamentarias (Art. 7, II)
- Ejecución de un contrato o procedimientos preliminares (Art. 7, V)

### 8.5 Corea del Sur (PIPA — Ley de Protección de Información Personal)

El tratamiento cumple con los requisitos de la PIPA, incluida la recopilación limitada al mínimo necesario, la limitación de finalidad específica, la notificación de los fines del tratamiento y el cumplimiento de los requisitos de consentimiento.

### 8.6 Japón (APPI — Ley sobre la Protección de la Información Personal)

El tratamiento cumple con la APPI en su versión modificada, incluida la especificación del propósito de uso, la adquisición adecuada de información personal y el cumplimiento de los requisitos de transferencia transfronteriza.

### 8.7 China (PIPL — Ley de Protección de la Información Personal)

Cuando se accede al Protocolo desde la República Popular China, el tratamiento se basa en el consentimiento individual o en la ejecución del contrato, se respetan los requisitos de localización de datos y las transferencias transfronterizas cumplen con los Arts. 38–43 de la PIPL.

### 8.8 India (DPDP — Ley de Protección de Datos Personales Digitales)

El tratamiento cumple con la Ley DPDP, incluido el tratamiento basado en el consentimiento o usos legítimos, las obligaciones como fiduciario de datos y los derechos de los titulares de datos.

---

## 9. Cómo Utilizamos los Datos

Los datos tratados a través del Protocolo Signet se utilizan exclusivamente para:

1. **Emisión y Verificación de Credenciales** — Permitir a los usuarios crear, presentar y verificar credenciales en los cuatro niveles de verificación.
2. **Cálculo del Signet IQ** — Calcular las puntuaciones Signet IQ basadas en avales de la red de confianza, niveles de credenciales, actualidad de las credenciales y señales de vencimiento de documentos.
3. **Verificación de Rango de Edad** — Utilizar Bulletproofs para demostrar que un usuario se encuentra dentro de un rango de edad sin revelar su edad exacta.
4. **Verificación Profesional** — Permitir que los profesionales autorizados (abogados, notarios, médicos) actúen como verificadores.
5. **Revocación de Credenciales** — Tratar los eventos de revocación cuando las credenciales son invalidadas.
6. **Integridad del Protocolo** — Mantener la integridad criptográfica y la seguridad del Protocolo.
7. **Cumplimiento Legal** — Cumplir con las leyes y reglamentos aplicables.
8. **Ceremonia de Doble Credencial** — Emitir credenciales pareadas de Persona Natural y Persona durante la verificación profesional, incluido el cálculo de árboles Merkle, nullifiers y pruebas de rango de edad.
9. **Gestión de Tutela** — Tratar los eventos de delegación de tutor (kind 31000) para la gestión de cuentas de menores.
10. **Divulgación Selectiva** — Permitir a los usuarios demostrar atributos individuales de hojas Merkle (incluidos el número de documento y la fecha de vencimiento del documento) a partes confiantes que los requieran, sin revelar atributos no relacionados.
11. **Ciclo de Vida de Credenciales** — Tratar las cadenas de credenciales (etiquetas supersedes/superseded-by) para cambios de nombre, renovación de documentos y actualizaciones de nivel.

---

## 10. Compartir y Divulgar Datos

### 10.1 Compartir a Nivel de Protocolo

El Protocolo Signet opera en la red Nostr, que es descentralizada. Cuando usted publica un evento de credencial, un aval u otro evento del Protocolo, este se transmite a los relays Nostr. Esto es inherente al diseño del Protocolo y es iniciado por usted.

### 10.2 No Compartimos Datos Con

- Anunciantes o empresas de marketing
- Intermediarios de datos
- Plataformas de redes sociales (más allá de la publicación en relays Nostr)
- Organismos gubernamentales (excepto cuando lo requiera la ley o un proceso legal válido)

### 10.3 Divulgación Requerida por Ley

Podemos divulgar información si así lo requiere una orden judicial válida, una citación o proceso legal, la ley o reglamentación aplicable, o una solicitud de una autoridad policial o regulatoria con jurisdicción válida. Notificaremos a los usuarios afectados de tales solicitudes donde lo permita la ley. Dado que Signet no posee datos personales de los usuarios en sistemas centralizados, el alcance de cualquier divulgación requerida es extremadamente limitado.

### 10.4 Compartir Datos de Verificadores

Los verificadores profesionales (Nivel 3 y Nivel 4) publican eventos de registro de verificador (kind 31000) en la red Nostr. Estos eventos incluyen la clave pública Nostr profesional del verificador e información jurisdiccional. Los verificadores dan su consentimiento a esta publicación como parte del Acuerdo de Verificador.

Los únicos datos compartidos entre el verificador y el Protocolo mediante eventos publicados son el evento de credencial (kind 31000), que contiene la clave pública del verificador, la clave pública de Persona del sujeto, metadatos de credencial (nivel, fechas, tipo de entidad, rango de edad), la prueba de rango de edad de conocimiento cero, el hash del nullifier y la raíz Merkle.

Ningún dato de identificación personal (nombre, fecha de nacimiento, números de documento, nacionalidad) aparece en ningún evento publicado.

---

## 11. Transferencias Internacionales de Datos

### 11.1 Arquitectura Descentralizada

La red Nostr opera a nivel mundial. Cuando usted publica eventos en los relays Nostr, esos eventos pueden ser replicados a relays ubicados en cualquier parte del mundo. Esta es una característica fundamental del protocolo descentralizado.

### 11.2 Mecanismos de Transferencia

Para cualquier tratamiento centralizado que lleve a cabo Signet, las transferencias internacionales de datos están protegidas por:

- **UE/EEE:** Cláusulas Contractuales Tipo (CCT) aprobadas por la Comisión Europea (Decisión 2021/914), complementadas por evaluaciones de impacto de transferencia cuando sea necesario.
- **Reino Unido:** Acuerdo Internacional de Transferencia de Datos (IDTA) o el Adendum del Reino Unido a las CCT de la UE.
- **Corea del Sur:** Cumplimiento de las disposiciones de transferencia transfronteriza de la PIPA.
- **Japón:** Transferencias a países con un nivel adecuado de protección reconocido por la PPC, o con consentimiento del usuario.
- **China:** Evaluaciones de seguridad, contratos estándar o certificaciones según lo requerido por la PIPL.
- **Brasil:** Transferencias conformes con el Art. 33 de la LGPD, incluidas las transferencias a países con un nivel adecuado de protección o con garantías específicas.

### 11.3 Decisiones de Adecuación

Nos basamos en decisiones de adecuación cuando están disponibles, incluido el Marco de Privacidad de Datos UE-EE. UU., la Extensión del Reino Unido al Marco de Privacidad de Datos UE-EE. UU. y la constatación de adecuación de Japón por la Comisión Europea.

---

## 12. Retención de Datos

### 12.1 Eventos Nostr

Los eventos publicados en la red Nostr son retenidos por los operadores de relay según sus propias políticas. Dado que la red Nostr es descentralizada, Signet no puede garantizar la eliminación de eventos de todos los relays.

### 12.2 Ciclo de Vida de Credenciales

| Tipo de Dato | Período de Retención |
|-------------|---------------------|
| Credenciales activas | Hasta el vencimiento o la revocación |
| Credenciales revocadas | Los eventos de revocación se retienen indefinidamente por la integridad de la verificación |
| Credenciales vencidas | Retenidas en relays según las políticas del operador de relay |
| Registros de aval | Hasta que sean revocados por la parte avalante |
| Datos de desafío/respuesta | Persistentes; publicados en relays Nostr como eventos estándar, retenidos por la integridad del protocolo |
| Material de clave cifrado local | En su dispositivo hasta que elimine la aplicación o borre los datos de la aplicación |

### 12.3 Registros Centralizados

Cualquier registro que Signet mantenga de forma centralizada (por ejemplo, correspondencia de soporte, registros de cumplimiento legal) se retiene durante:
- Registros de soporte: 2 años desde la última interacción
- Registros de cumplimiento legal: Según lo requiera la ley aplicable (normalmente 5–7 años)
- Registros de auditoría: 3 años

---

## 13. Sus Derechos

### 13.1 Derechos Universales

Independientemente de su jurisdicción, usted puede:
- Solicitar información sobre qué datos tratamos sobre usted
- Solicitar la corrección de datos inexactos
- Retirar el consentimiento cuando el tratamiento se base en el consentimiento
- Presentar una reclamación ante nosotros o ante una autoridad de supervisión

### 13.2 Una Nota sobre la Arquitectura y los Derechos

Dado que la arquitectura de Signet es descentralizada y orientada a la privacidad, muchos derechos quedan satisfechos de forma estructural:

- **Acceso y portabilidad:** Sus datos de credenciales están almacenados en eventos Nostr públicos que usted publicó y en el almacenamiento local de su aplicación. Usted ya tiene acceso completo a ellos.
- **Supresión:** Signet no tiene ninguna copia centralizada de sus datos personales. No podemos eliminar eventos Nostr de la infraestructura de los operadores de relay en su nombre, pero podemos emitir un evento de revocación. Usted puede solicitar la eliminación a los operadores de relay individuales.
- **Rectificación:** Las credenciales incorrectas pueden ser reemplazadas emitiendo un nuevo evento de credencial que hace referencia al anterior.

### 13.3 Unión Europea / EEE (RGPD)

Bajo el RGPD, usted tiene el derecho a:
- **Acceso** (Art. 15) — Obtener una copia de sus datos personales
- **Rectificación** (Art. 16) — Corregir datos inexactos
- **Supresión** (Art. 17) — Solicitar la eliminación ("derecho al olvido") cuando sea aplicable
- **Limitación** (Art. 18) — Limitar el tratamiento en determinadas circunstancias
- **Portabilidad de Datos** (Art. 20) — Recibir sus datos en un formato estructurado y legible por máquina
- **Oposición** (Art. 21) — Oponerse al tratamiento basado en interés legítimo
- **Decisiones Automatizadas** (Art. 22) — No ser objeto de decisiones basadas únicamente en tratamiento automatizado con efectos legales

**Autoridad de Supervisión:** Puede presentar una reclamación ante su autoridad local de protección de datos. Una lista de las APD de la UE/EEE está disponible en [https://edpb.europa.eu/about-edpb/about-edpb/members_en](https://edpb.europa.eu/about-edpb/about-edpb/members_en).

### 13.4 Reino Unido (UK GDPR)

Usted tiene derechos equivalentes a los del RGPD de la UE. Puede presentar una reclamación ante la Oficina del Comisionado de Información (ICO) en [https://ico.org.uk](https://ico.org.uk).

### 13.5 Estados Unidos (CCPA / CPRA)

Los residentes de California tienen derecho a:
- **Conocer** — Qué información personal se recopila, usa y divulga
- **Eliminar** — Solicitar la eliminación de información personal
- **Corregir** — Solicitar la corrección de información personal inexacta
- **Excluirse** — Excluirse de la venta o el intercambio de información personal (no vendemos ni compartimos)
- **No Discriminación** — No ser discriminado por ejercer derechos de privacidad

Para ejercer estos derechos, contáctenos en privacy@signet.id.

Los residentes de Virginia, Colorado, Connecticut, Utah, Texas y otros estados con legislación de privacidad tienen derechos comparables bajo sus respectivas leyes.

### 13.6 Brasil (LGPD)

Los titulares de datos tienen derecho a la confirmación de la existencia del tratamiento, acceso a los datos, corrección de datos incompletos, inexactos u obsoletos, anonimización, bloqueo o eliminación de datos innecesarios o excesivos, portabilidad de datos, eliminación de datos tratados con consentimiento, información sobre datos compartidos, información sobre la posibilidad de negar el consentimiento y sus consecuencias, y revocación del consentimiento.

Contacte con la ANPD (Autoridade Nacional de Proteção de Dados) para presentar reclamaciones: [https://www.gov.br/anpd](https://www.gov.br/anpd).

### 13.7 Corea del Sur (PIPA)

Los titulares de datos tienen derecho a solicitar el acceso a la información personal, solicitar su corrección o eliminación, solicitar la suspensión del tratamiento y presentar una reclamación ante la Comisión de Protección de Información Personal (PIPC).

### 13.8 Japón (APPI)

Los titulares de datos tienen derecho a solicitar la divulgación de los datos personales retenidos, solicitar su corrección, adición o eliminación, solicitar el cese del uso o la provisión a terceros y presentar una reclamación ante la Comisión de Protección de Información Personal (PPC).

### 13.9 China (PIPL)

Los titulares de datos tienen derecho a conocer y decidir sobre el tratamiento de la información personal, restringir o rechazar el tratamiento, acceder y copiar la información personal, solicitar la portabilidad, solicitar la corrección y eliminación, y solicitar una explicación de las normas de tratamiento.

### 13.10 India (Ley DPDP)

Los titulares de datos tienen derecho a acceder a la información sobre el tratamiento, a la corrección y supresión de datos personales, a la reparación de agravios y a nombrar a otra persona para que ejerza los derechos.

### 13.11 Ejercicio de sus Derechos

Para ejercer cualquiera de los derechos anteriores, contáctenos en:
- **Correo electrónico:** privacy@signet.id
- **Correo electrónico del DPO:** dpo@signet.id

Responderemos dentro de los plazos requeridos por la ley aplicable:
- RGPD/UK GDPR: 30 días (ampliables en 60 días para solicitudes complejas)
- CCPA/CPRA: 45 días (ampliables en 45 días)
- LGPD: 15 días
- PIPA: 10 días
- APPI: Sin demora
- PIPL: Con prontitud

---

## 14. Datos de Menores

### 14.1 Política General

El Protocolo Signet incluye el Nivel 4 (Verificación Profesional — Adulto + Menor), que está específicamente diseñado para la seguridad infantil. Nos tomamos muy en serio la protección de los datos de los menores. Los menores de 18 años solo pueden ser verificados bajo el Nivel 4 con la participación activa de un tutor adulto verificado, quien recibe una credencial de Nivel 4 que vincula su clave pública con la credencial del menor mediante una etiqueta de tutor.

### 14.2 Verificación de Edad

El Protocolo utiliza pruebas de conocimiento cero basadas en Bulletproofs para la verificación de rango de edad. Estas pruebas demuestran que un usuario se encuentra dentro de un rango de edad determinado (por ejemplo, "0-3", "4-7", "8-12", "13-17", "18+") sin revelar su fecha exacta de nacimiento.

### 14.3 Requisitos de Edad Específicos por Jurisdicción

| Jurisdicción | Edad Mínima para el Consentimiento Digital | Ley Aplicable |
|-------------|-------------------------------------------|---------------|
| UE (por defecto) | 16 años | RGPD Art. 8 |
| UE (opción del Estado miembro) | 13–16 años (varía según el Estado miembro) | RGPD Art. 8(1) |
| Reino Unido | 13 años | UK GDPR / Código para Menores |
| Estados Unidos | 13 años | COPPA |
| Brasil | 12 años (consentimiento parental requerido hasta los 18) | LGPD Art. 14 |
| Corea del Sur | 14 años | PIPA |
| Japón | 15 años (directrices) | APPI |
| China | 14 años | PIPL Art. 28 |
| India | 18 años (con excepciones) | Ley DPDP |

### 14.4 Consentimiento Parental

Cuando se requiere consentimiento parental, el Protocolo admite:
- Consentimiento parental verificable mediante credenciales verificadas de Nivel 3 o Nivel 4 del padre/tutor
- Verificación de acceso por edad mediante verificación de prueba ZK en el nivel de la parte confiante
- Eventos de delegación de tutor (kind 31000) que permiten a los padres gestionar la actividad Signet de sus hijos
- Mecanismos para que los padres revoquen la delegación y el consentimiento

### 14.5 Cumplimiento de COPPA (Estados Unidos)

Signet no recopila ninguna información personal de ningún usuario, incluidos los menores de 13 años. La arquitectura de conocimiento cero del Protocolo significa que no existe ningún nombre, fecha de nacimiento, dirección ni otra información personal cubierta por COPPA que sea recopilada, almacenada o transmitida por Signet. La guía de la FTC de marzo de 2026 reconoce la flexibilidad para plataformas que implementen verificación que preserva la privacidad sin recopilar información personal cubierta.

### 14.6 Código de Diseño Apropiado para la Edad (Reino Unido)

Signet está comprometido con los principios del Código de Diseño Apropiado para la Edad del Reino Unido (Código para Menores), incluida la evaluación del interés superior del menor, la aplicación apropiada para la edad, la minimización de datos, la configuración predeterminada protectora de los menores y la transparencia apropiada para la edad del menor.

---

## 15. Seguridad

### 15.1 Seguridad Criptográfica

El Protocolo Signet emplea:
- **Firmas Schnorr** en la curva secp256k1 para la firma de todas las credenciales
- **Bulletproofs** para pruebas de rango de edad de conocimiento cero
- **Firmas en anillo** (SAG y LSAG) para pruebas de pertenencia a grupos anónimos, con etiquetas de separación de dominio y límites de tamaño de anillo (máximo 1.000 miembros)
- **Árboles Merkle RFC 6962** con separación de dominio (prefijo `0x00` para hojas, prefijo `0x01` para nodos internos) para compromisos de atributos a prueba de manipulaciones
- **ECDH** con rechazo del punto identidad para la derivación de secretos compartidos
- **Futura capa ZK** planificada para tipos de prueba adicionales (ZK-SNARKs/ZK-STARKs)

### 15.2 Seguridad del Almacenamiento de Claves

Las claves privadas en la aplicación My Signet:
- Están cifradas en reposo usando AES-256-GCM
- La clave de cifrado se deriva mediante PBKDF2 con SHA-256 y 600.000 iteraciones (recomendación de OWASP 2023), usando una sal aleatoria
- Las claves se mantienen en memoria solo durante una sesión autenticada
- Las frases mnemónicas y las claves privadas nunca se transmiten a Signet ni a terceros
- Nunca se almacenan en texto plano en IndexedDB, localStorage ni en ningún otro mecanismo de almacenamiento

### 15.3 Validación de Entradas

Todos los validadores de eventos aplican la longitud máxima del contenido (64 KB), el recuento máximo de etiquetas (100 etiquetas), la longitud máxima del valor de etiqueta (1.024 caracteres) y la verificación de límites de enteros para prevenir elusiones silenciosas de seguridad.

### 15.4 Modelo de Seguridad Descentralizado

La arquitectura descentralizada del Protocolo proporciona beneficios de seguridad inherentes: ningún punto único de fallo, ninguna base de datos centralizada que violar, gestión de claves controlada por el usuario y verificación criptográfica sin intermediarios de confianza.

### 15.5 Notificación de Brechas

En caso de una brecha de datos personales que afecte a cualquier sistema centralizado de Signet, nosotros:
- Notificaremos a la autoridad de supervisión pertinente dentro de las 72 horas (RGPD) o según lo requiera la ley aplicable
- Notificaremos a las personas afectadas sin demora indebida cuando sea probable que la brecha resulte en un alto riesgo para sus derechos y libertades
- Documentaremos la brecha, sus efectos y las medidas correctivas

---

## 16. Cookies y Tecnologías de Seguimiento

El Protocolo Signet **no** utiliza:
- Cookies
- Balizas web o píxeles de seguimiento
- Huella digital del navegador
- Almacenamiento local con fines de seguimiento
- Ningún servicio de análisis o seguimiento de terceros

Si los servicios auxiliares (como un sitio web de documentación) utilizan cookies, se proporcionará un aviso de cookies separado con los mecanismos de consentimiento apropiados.

---

## 17. Decisiones Automatizadas y Elaboración de Perfiles

### 17.1 Cálculo del Signet IQ

El Protocolo calcula las puntuaciones Signet IQ (0–200, donde 100 representa el estándar actual de identidad gubernamental) basándose en el nivel de verificación, el número y calidad de los avales, las credenciales y la posición del verificador, la antigüedad de la credencial y las señales de vencimiento de documentos. Estas puntuaciones se calculan algorítmicamente y son visibles para las partes confiantes. No constituyen una toma de decisiones automatizada con efectos legales bajo el Art. 22 del RGPD, ya que son uno de los muchos elementos que las partes confiantes pueden considerar.

### 17.2 Sin Elaboración de Perfiles para Marketing

No realizamos elaboración de perfiles con fines de marketing, publicidad o análisis conductual.

---

## 18. Servicios y Enlaces de Terceros

El Protocolo Signet interopera con:
- Relays Nostr (operados de forma independiente)
- Clientes Nostr (como Fathom, el cliente de implementación de referencia)
- Organismos profesionales y registros regulatorios (mediante el bot de verificación de código abierto)
- El registro de tipos de documentos (un archivo YAML externo que define las definiciones de campos de documentos por país — no contiene datos personales)

Estos terceros tienen sus propias políticas de privacidad. Signet no es responsable de sus prácticas de datos.

---

## 19. Cambios a esta Política de Privacidad

Podemos actualizar esta Política de Privacidad de vez en cuando. Los cambios se indicarán actualizando la fecha de "Última actualización" en la parte superior de este documento. Para los cambios sustanciales, proporcionaremos aviso mediante un anuncio de evento Nostr y una actualización del repositorio de especificaciones del Protocolo. Su uso continuado del Protocolo después de los cambios constituye la aceptación de la Política de Privacidad actualizada.

---

## 20. Disposiciones Específicas por Jurisdicción

### 20.1 Unión Europea — Disposiciones Adicionales

Cuando tratamos datos personales bajo el RGPD, las disposiciones del RGPD prevalecen sobre cualquier disposición conflictiva de esta Política de Privacidad. En cuanto a eIDAS 2.0: el Protocolo de Signet está diseñado para aceptar eventos de puente de identidad de las Carteras de Identidad Digital de la UE cuando dichas carteras sean desplegadas por los Estados miembros, previsto para diciembre de 2026.

### 20.2 Reino Unido — Disposiciones Adicionales

**Registro en la ICO:** Signet se registrará en la ICO según sea necesario. Los detalles del registro se publicarán en signet.id/legal.

**No Vendo ni Comparto mi Información Personal:** No vendemos ni compartimos información personal.

**Ley de Seguridad en Línea:** Las capacidades de verificación de edad de Signet están diseñadas para ser compatibles con los requisitos de aseguramiento de edad de la Ley de Seguridad en Línea de 2023.

### 20.3 California — Disposiciones Adicionales

**No Vendo ni Comparto mi Información Personal:** No vendemos ni compartimos información personal tal como se define en la CCPA/CPRA.

**Incentivos Financieros:** No ofrecemos incentivos financieros relacionados con la recopilación de información personal.

**Shine the Light (Sección 1798.83 del Código Civil de California):** Los residentes de California pueden solicitar información sobre la divulgación de información personal a terceros con fines de marketing directo. No realizamos tales divulgaciones.

### 20.4 Brasil — Disposiciones Adicionales

El DPO (Encarregado) puede ser contactado en dpo@signet.id para todas las consultas relacionadas con la LGPD.

### 20.5 Australia — Disposiciones Adicionales

Cumplimos con los Principios Australianos de Privacidad (APPs) bajo la Ley de Privacidad de 1988 (Cth). Puede presentar una reclamación ante la Oficina del Comisionado de Información de Australia (OAIC).

### 20.6 Nueva Zelanda — Disposiciones Adicionales

Cumplimos con la Ley de Privacidad de 2020 (NZ). Puede presentar una reclamación ante la Oficina del Comisionado de Privacidad.

### 20.7 Singapur — Disposiciones Adicionales

Cumplimos con la Ley de Protección de Datos Personales de 2012 (PDPA). Puede contactar con la Comisión de Protección de Datos Personales (PDPC) para presentar reclamaciones.

### 20.8 Sudáfrica — Disposiciones Adicionales

Cumplimos con la Ley de Protección de Información Personal de 2013 (POPIA). Puede presentar una reclamación ante el Regulador de Información.

---

## 21. Contáctenos

Para cualquier pregunta, inquietud o solicitud relacionada con esta Política de Privacidad o nuestras prácticas de datos:

**Consultas Generales:**
El Protocolo Signet
Correo electrónico: privacy@signet.id

**Delegado de Protección de Datos:**
Correo electrónico: dpo@signet.id

---

## 22. Registros Regulatorios

Dependiendo de la jurisdicción, Signet mantiene o mantendrá registros o declaraciones ante:
- La Oficina del Comisionado de Información (Reino Unido) — registro pendiente de completar; detalles publicados en signet.id/legal
- Las autoridades de protección de datos de la UE/EEE aplicables
- Otros organismos regulatorios según lo requiera la ley

---

*Esta Política de Privacidad describe las prácticas de datos del Protocolo Signet a partir de marzo de 2026. El Protocolo Signet es software de código abierto. Este documento no constituye asesoramiento jurídico. Los usuarios y operadores deben buscar asesoramiento jurídico cualificado familiarizado con las leyes de protección de datos aplicables en su jurisdicción.*

*Protocolo Signet — v0.1.0*
*Versión del documento: 2.0*
