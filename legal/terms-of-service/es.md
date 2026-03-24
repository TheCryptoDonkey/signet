> **Aviso de traducción automática:** Este documento ha sido traducido al español mediante inteligencia artificial. La versión en inglés disponible en `en.md` es el único documento jurídicamente vinculante. En caso de discrepancia entre la versión en español y la versión en inglés, prevalecerá la versión en inglés.

---

# Términos de Servicio

**El Protocolo Signet — v0.1.0**
**Fecha de entrada en vigor:** 17 de marzo de 2026
**Última actualización:** 17 de marzo de 2026

*Este documento cubre su uso de My Signet (la aplicación de referencia) y las bibliotecas del Protocolo Signet, incluido el SDK signet-verify.js. No constituye asesoramiento jurídico. Busque asesoría cualificada para su jurisdicción antes de utilizarlo en una implementación en producción.*

---

## Contenido

1. [Aceptación de los Términos](#1-aceptación-de-los-términos)
2. [Elegibilidad](#2-elegibilidad)
3. [Descripción del Protocolo y la Aplicación](#3-descripción-del-protocolo-y-la-aplicación)
4. [Gestión de Claves y Seguridad de la Cuenta](#4-gestión-de-claves-y-seguridad-de-la-cuenta)
5. [La Ceremonia de Verificación](#5-la-ceremonia-de-verificación)
6. [Ciclo de Vida de las Credenciales](#6-ciclo-de-vida-de-las-credenciales)
7. [Obligaciones del Usuario](#7-obligaciones-del-usuario)
8. [Obligaciones del Verificador](#8-obligaciones-del-verificador)
9. [Operadores de Sitios Web y el SDK signet-verify.js](#9-operadores-de-sitios-web-y-el-sdk-signet-verifyjs)
10. [El Bot de Verificación](#10-el-bot-de-verificación)
11. [Puntuaciones Signet IQ](#11-puntuaciones-signet-iq)
12. [Protección de Datos](#12-protección-de-datos)
13. [Propiedad Intelectual](#13-propiedad-intelectual)
14. [Exenciones de Responsabilidad](#14-exenciones-de-responsabilidad)
15. [Limitación de Responsabilidad](#15-limitación-de-responsabilidad)
16. [Indemnización](#16-indemnización)
17. [Ley Aplicable y Resolución de Disputas](#17-ley-aplicable-y-resolución-de-disputas)
18. [Rescisión](#18-rescisión)
19. [Modificaciones](#19-modificaciones)
20. [Disposiciones Generales](#20-disposiciones-generales)
21. [Contacto](#21-contacto)
22. [Anexos por Jurisdicción](#22-anexos-por-jurisdicción)

---

## 1. Aceptación de los Términos

Al acceder, descargar o utilizar My Signet (la "Aplicación"), las bibliotecas del Protocolo Signet o el SDK signet-verify.js (conjuntamente, "el Protocolo"), o al actuar como verificador, usted ("usted" o "Usuario") acepta quedar vinculado por estos Términos de Servicio ("Términos").

Si no está de acuerdo con estos Términos, no debe utilizar el Protocolo.

Si utiliza el Protocolo en nombre de una organización, declara que tiene autoridad para vincular a dicha organización, y "usted" incluye a esa organización.

**Verificadores:** Al publicar un evento de credencial de verificador kind 31000 en la red Nostr, o al realizar una ceremonia de verificación Signet, usted acepta la Sección 8 (Obligaciones del Verificador) como condición jurídicamente vinculante de su participación. No es necesario que firme un documento separado. El acto de realizar una verificación constituye su aceptación.

---

## 2. Elegibilidad

### 2.1 Elegibilidad General

Para utilizar el Protocolo, usted debe:

- Tener capacidad legal para celebrar un acuerdo vinculante en su jurisdicción
- No estar prohibido de utilizar el Protocolo bajo ninguna ley aplicable
- No haber sido excluido del Protocolo por una violación material de estos Términos

### 2.2 Requisitos de Edad

| Jurisdicción | Edad mínima — cuenta propia | Con consentimiento parental verificado |
|---|---|---|
| Unión Europea (por defecto) | 16 | 13 (varía según el Estado miembro) |
| Reino Unido | 13 | N/A |
| Estados Unidos | 13 | Menores de 13 con consentimiento parental conforme a COPPA |
| Brasil | 18 | 12 con consentimiento parental |
| Corea del Sur | 14 | Menores de 14 con consentimiento parental |
| Japón | 15 | Menores de 15 con consentimiento parental |
| India | 18 | Conforme a la Ley DPDP |
| Otros | Edad de consentimiento digital | Según la ley local |

Los menores de la edad de consentimiento digital en su jurisdicción solo pueden tener una cuenta Signet como subcuenta de un padre o tutor verificado (véase la Sección 6.7).

### 2.3 Elegibilidad del Verificador

Para actuar como verificador profesional y emitir credenciales de Nivel 3 o Nivel 4, usted debe:

- Mantener un registro profesional vigente y válido en buen estado con el organismo regulador pertinente
- Estar autorizado para ejercer en la jurisdicción donde realiza las verificaciones
- No estar sujeto a ninguna suspensión, restricción o procedimiento disciplinario que menoscabe su capacidad para verificar identidades
- Mantener un seguro de responsabilidad profesional adecuado para cubrir sus actividades de verificación

La lista completa de profesiones elegibles se encuentra en la Sección 8.2.

---

## 3. Descripción del Protocolo y la Aplicación

### 3.1 Visión General

El Protocolo Signet es un protocolo de verificación de identidad descentralizado para la red Nostr. Permite a los usuarios demostrar afirmaciones sobre su identidad —incluidas la edad, la paternidad y el estatus profesional— mediante pruebas de conocimiento cero y firmas en anillo, sin revelar datos personales subyacentes. No existe ninguna base de datos central, ninguna autoridad central ni ninguna organización única que controle la red.

**My Signet** es la aplicación de referencia. Es una aplicación web progresiva (PWA) que se ejecuta en su navegador. Es una aplicación utilizada por todos: individuos, verificadores y comunidades.

### 3.2 Niveles de Verificación

| Nivel | Nombre | Significado |
|---|---|---|
| 1 | Autodeclarado | Creó una cuenta y declaró algunos atributos. Sin verificación externa. Menor confianza. |
| 2 | Red de Confianza | Otros usuarios que lo conocen han avalado su identidad. La confianza se deriva de la red. |
| 3 | Verificación Profesional (Adulto) | Un profesional autorizado verificó su documento de identidad oficial en persona y emitió dos credenciales mediante la ceremonia de doble credencial. |
| 4 | Verificación Profesional (Adulto + Menor) | Nivel 3 extendido para incluir una cuenta de menor, con la relación del menor con un padre/tutor verificado confirmada por un profesional. |

### 3.3 Tipos de Eventos Nostr

El Protocolo utiliza los siguientes tipos de eventos Nostr:

| Tipo | Propósito |
|---|---|
| 31000 | Eventos de credencial |
| 31000 | Atestaciones de aval |
| 30078 | Políticas de verificación comunitaria |
| 31000 | Credenciales de registro de verificador |
| 31000 | Eventos de desafío |
| 31000 | Eventos de revocación |
| 31000 | Eventos de puente de identidad |
| 31000 | Eventos de delegación (tutor y agente) |
| 30482–30484 | Extensión de votación (elección, voto, resultado) |

Los números de tipo de evento están pendientes de asignación final de NIP.

### 3.4 Pila Criptográfica

El Protocolo utiliza:

- Firmas Schnorr en la curva secp256k1 (capa base)
- Bulletproofs para pruebas de conocimiento cero de rango de edad
- Firmas en anillo de Grupo Anónimo Espontáneo (SAG) y SAG Enlazable (LSAG) para la privacidad del emisor
- PBKDF2 (600.000 iteraciones, SHA-256) con AES-256-GCM para el almacenamiento local de credenciales
- Una futura capa ZK (ZK-SNARKs o ZK-STARKs) está planificada para completitud criptográfica de Nivel 3

### 3.5 Naturaleza Descentralizada

El Protocolo Signet opera en la red Nostr. Desarrollamos y mantenemos la especificación del Protocolo, pero no controlamos la red, los operadores de relay ni los participantes individuales. Los eventos publicados en Nostr son públicos, persistentes y replicados por operadores de relay que no controlamos.

---

## 4. Gestión de Claves y Seguridad de la Cuenta

### 4.1 Modelo de Doble Keypair

My Signet deriva dos keypairs independientes de un único mnemónico BIP-39 de 12 palabras:

- **Keypair de Persona Natural:** Utilizado para su credencial de identidad real (nombre, documento, nullifier, raíz Merkle). Este keypair solo se utiliza cuando usted elige explícitamente presentar su identidad real verificada.
- **Keypair de Persona:** Un alias anónimo. Lleva una prueba de rango de edad heredada de la ceremonia de verificación, pero sin nombre, referencia de documento ni nullifier. Toda su actividad Nostr cotidiana puede utilizar este keypair.

Durante el proceso de incorporación, usted elige qué keypair es su cuenta principal para ese dispositivo. Puede cambiar en cualquier momento. El vínculo entre sus dos keypairs es conocido solo por usted y su verificador (protegido por sus obligaciones de confidencialidad profesional).

### 4.2 Modo de Keypair Único (Importación de nsec)

Si es un usuario existente de Nostr, puede importar su clave privada existente (nsec). En el modo de keypair único, su npub existente se convierte en su identidad de Persona Natural, y puede crear un puente de identidad (evento kind 31000) para vincularlo a una cuenta de Persona. Todos sus seguidores existentes, NIP-05, zaps y reputación se preservan.

### 4.3 Generación y Copia de Seguridad de Claves

- Su mnemónico se genera localmente en la Aplicación utilizando aleatoriedad criptográficamente segura. Nunca se transmite a ningún servidor.
- Usted es el único responsable de hacer una copia de seguridad de su mnemónico. No podemos recuperarlo. Si pierde su mnemónico y su dispositivo, su cuenta no puede recuperarse sin una nueva verificación profesional.
- Las cuentas de menores pueden derivarse en diferentes índices de cuenta BIP-44 del mismo mnemónico del padre, manteniendo la gestión de claves de la familia bajo una única frase de recuperación.
- La copia de seguridad mediante Compartición de Secretos de Shamir (a través de `@scure/bip39`) está soportada para dividir el mnemónico entre custodios de confianza.

### 4.4 Autenticación Biométrica y por PIN

My Signet requiere autenticación para acceder a su clave privada:

- **Biométrica (preferida):** Utiliza WebAuthn con la extensión PRF, cuando está disponible. Sus datos biométricos nunca salen de su dispositivo. Donde se admite PRF, el material de clave es derivado por hardware y no puede extraerse del localStorage ni siquiera por código que se ejecute en el mismo dispositivo.
- **PIN alternativo:** Donde la autenticación biométrica no está disponible, se requiere un PIN. El PIN se utiliza con PBKDF2 (600.000 iteraciones) para derivar una clave de cifrado AES-256-GCM.
- **Gestión de sesiones:** Tras un período de inactividad, la Aplicación se bloquea automáticamente. Debe volver a autenticarse para continuar. El tiempo de espera por inactividad puede configurarse en los ajustes.

Su clave privada nunca se almacena en texto plano. Siempre está cifrada en reposo usando AES-256-GCM.

### 4.5 Compromiso de la Clave

Si cree que su clave privada ha sido comprometida, debe visitar a un verificador profesional con sus documentos de identidad originales. El verificador revocará todas las credenciales emitidas para su antiguo keypair y emitirá nuevas credenciales para un nuevo keypair. Los avales asociados con la clave comprometida no se transfieren (esta es una medida de seguridad deliberada — un atacante que comprometió su clave no puede retener su confianza social).

### 4.6 Firma Remota NIP-46

My Signet admite la firma remota NIP-46. Esto permite que otras aplicaciones o servicios soliciten a la Aplicación que firme eventos Nostr en su nombre. Cada solicitud de firma requiere su aprobación explícita. La Aplicación mostrará los detalles de la solicitud antes de que la apruebe o rechace. No debe aprobar solicitudes que no reconozca o comprenda.

---

## 5. La Ceremonia de Verificación

### 5.1 Funcionamiento de la Verificación Profesional

Las credenciales de Nivel 3 y Nivel 4 se emiten a través de la ceremonia de doble credencial:

1. **Usted introduce sus datos.** Antes de visitar a un verificador, usted introduce sus propios atributos de identidad (nombre, fecha de nacimiento, nacionalidad, tipo y número de documento) en la Aplicación. La Aplicación precalcula su árbol Merkle y su nullifier de documento.

2. **Usted presenta sus documentos.** Acude a una cita presencial con un verificador profesional y muestra su(s) documento(s) de identidad original(es) emitido(s) por el gobierno.

3. **El verificador confirma o rechaza.** El verificador inspecciona sus documentos, verifica que usted es la persona descrita en ellos, y confirma o rechaza los datos que usted introdujo. El verificador no escribe sus datos personales — solo confirma lo que usted ha introducido.

4. **Se emiten dos credenciales.** Si el verificador confirma los datos, publica dos eventos de credencial kind 31000 — uno para su keypair de Persona Natural (con su raíz Merkle y nullifier) y otro para su keypair de Persona (solo con su prueba de rango de edad). Ambas credenciales están firmadas con la clave Nostr profesional del verificador.

5. **El número de documento se descarta.** Después de calcular el nullifier, el número de documento no es retenido por el Protocolo, la Aplicación ni (a menos que sus obligaciones profesionales lo requieran independientemente) el verificador.

### 5.2 Responsabilidad sobre la Exactitud de los Datos

Dado que usted introduce sus propios datos de identidad, usted es el principal responsable de su exactitud. La introducción de datos falsos (nombre incorrecto, número de documento de otra persona) es fraudulenta y puede constituir un delito penal en su jurisdicción.

El papel del verificador es confirmar que la persona que está ante él coincide con los documentos presentados. El verificador no garantiza la integridad o exactitud de los datos que usted introdujo más allá de lo que puede confirmarse visualmente a partir de los documentos.

### 5.3 Nullifiers de Documentos

El Protocolo utiliza nullifiers basados en documentos para evitar que la misma persona obtenga múltiples credenciales de Nivel 3. El nullifier se calcula como:

```
SHA-256(LP(docType) || LP(country) || LP(docNumber) || LP("signet-nullifier-v2"))
```

donde `LP(x)` es la longitud en bytes UTF-8 de `x` codificada como un entero de 2 bytes en big-endian, seguida de los bytes de `x`. Esta codificación con longitud prefijada previene las colisiones de límites de campo.

El nullifier:
- Es determinista: el mismo documento siempre produce el mismo nullifier
- Es unidireccional: el número de documento no puede recuperarse del nullifier
- Es resistente a colisiones: documentos diferentes producen nullifiers diferentes
- Es consistente entre verificadores: cualquier verificador con el mismo documento produce el mismo nullifier

Si presenta múltiples documentos de identidad (por ejemplo, pasaporte y permiso de conducir), el verificador puede calcular nullifiers para todos los documentos, formando una familia de nullifiers. Todos los nullifiers de la familia se publican en la credencial y se contrastan con las credenciales existentes en los relays.

### 5.4 El Árbol Merkle

Sus atributos personales (nombre, fecha de nacimiento, nacionalidad, tipo de documento, fecha de vencimiento del documento, nullifier) se almacenan como hojas en un árbol Merkle. Solo la raíz Merkle se publica en cadena. Puede demostrar atributos individuales proporcionando una ruta Merkle, sin revelar todos los atributos. El árbol Merkle utiliza separación de dominio RFC 6962 (prefijo 0x00 para hashes de hojas, 0x01 para nodos internos).

### 5.5 Pruebas de Rango de Edad

Su fecha de nacimiento nunca se publica. En cambio, el verificador calcula una prueba de conocimiento cero Bulletproof de que su edad se encuentra dentro de un rango especificado (por ejemplo, "18+", "13–17", "8–12"). La prueba es matemáticamente verificable sin revelar su edad exacta ni su fecha de nacimiento.

### 5.6 Verificación Cruzada

Puede buscar verificación de un segundo (o más) verificador presentando los mismos documentos. Dado que el nullifier se deriva de sus documentos, se produce el mismo nullifier. El Protocolo distingue la verificación cruzada del fraude duplicado verificando si la clave pública del sujeto coincide con la credencial existente:

- Mismo nullifier + misma clave pública = confirmación independiente (mayor contribución al Signet IQ)
- Mismo nullifier + clave pública diferente = posible identidad duplicada (marcado para investigación)

La verificación cruzada es la señal de IQ más fuerte, ya que representa la confirmación profesional independiente de la misma identidad.

---

## 6. Ciclo de Vida de las Credenciales

### 6.1 Vencimiento y Degradación de Credenciales

Las credenciales profesionales incluyen una etiqueta `expires` (el período de validez de la credencial) y una hoja Merkle `documentExpiry` (cuándo vence el documento subyacente). Son distintas: una credencial puede vencer después de dos años mientras que el pasaporte en que se basó no vence por diez.

Las credenciales no caen en picado al vencer. En cambio, la contribución al IQ de una credencial que se acerca a su vencimiento decae gradualmente a medida que se aproxima la fecha de vencimiento, en lugar de caer a cero en la fecha de vencimiento. Se espera que los clientes muestren esta degradación visualmente (un indicador que se oscurece lentamente) en lugar de un estado binario válido/inválido.

Si el documento subyacente de una credencial vence antes que la propia credencial, la contribución al IQ decae más rápido — reflejando la menor confianza en el documento de identidad subyacente.

### 6.2 Revocación de Credenciales

Las credenciales pueden ser revocadas publicando un evento kind 31000. La revocación puede ser iniciada por:

- Usted (autorrevocación — por ejemplo, en caso de compromiso de la clave o cambio de nombre)
- El verificador emisor (por causa, como fraude descubierto)
- Consenso comunitario (para fraude sistémico o compromiso de seguridad)

### 6.3 Cadenas de Credenciales y Renovación de Documentos

Cuando sus atributos del mundo real cambian (cambio de nombre, renovación de documento, actualización de nivel), se emite una credencial de reemplazo con una etiqueta `["supersedes", "<old_event_id>"]`. Los clientes siguen la cadena para mostrar solo la credencial activa actual. Las credenciales reemplazadas permanecen en los relays como registros históricos.

**Renovación de documentos y nullifiers:**
- **Renovación de pasaporte:** Un nuevo número de pasaporte produce un nuevo nullifier. Los nullifiers antiguo y nuevo están vinculados por una etiqueta `["nullifier-chain", "<old_nullifier>"]` en la nueva credencial.
- **Renovación de permiso de conducir (Reino Unido):** El número de permiso normalmente no cambia al renovarse. La nueva credencial hace referencia al mismo nullifier.

### 6.4 Detalle del Modelo de Doble Credencial

| Credencial | Contiene | No contiene |
|---|---|---|
| Persona Natural | Raíz Merkle, nullifier principal, familia de nullifiers, prueba de rango de edad, tipo de entidad, etiquetas de tutor (si es menor) | Nombre real, fecha de nacimiento, número de documento |
| Persona | Prueba de rango de edad, entidad-tipo=persona, etiquetas de tutor (si es menor) | Nullifier, raíz Merkle, atributos personales |

### 6.5 Delegación de Tutela

Un tutor (padre o tutor legal verificado) puede delegar permisos específicos a adultos de confianza mediante eventos de delegación kind 31000. Los alcances de delegación incluyen:

- `full` — delegación completa (por ejemplo, copadre)
- `activity-approval` — aprobar actividades que requieren consentimiento parental
- `content-management` — gestionar el contenido y los contactos del menor
- `contact-approval` — aprobar nuevos contactos

Los eventos de delegación incluyen una etiqueta `agent-type` que identifica la relación (por ejemplo, `teacher`, `grandparent`, `step-parent`). Las etiquetas de tutor en las credenciales son inmutables — solo pueden cambiarse mediante una nueva credencial emitida por un profesional con la documentación legal apropiada.

### 6.6 Subcuentas de Menores

Una credencial de menor es una subcuenta de un padre o tutor verificado:

- La credencial de menor debe incluir etiquetas de tutor que vinculen a un padre o tutor verificado de Nivel 3 o superior
- El menor debe estar presente durante la ceremonia de verificación de Nivel 4 (en persona o mediante un proceso legalmente equivalente)
- Cuando el menor cumpla 18 años, recibirá una nueva credencial de Nivel 3 sin etiquetas de tutor, reemplazando la credencial de menor
- Un menor no puede tener una credencial de Persona que lleve una afirmación de rango de edad superior a su rango de edad verificado

### 6.7 Cuentas de Persona

Una Persona es un alias anónimo:

- Una Persona no lleva ninguna información de identificación personal — sin nombre, sin nullifier, sin raíz Merkle
- Una Persona hereda la prueba de rango de edad de la ceremonia de doble credencial
- Una Persona puede estar vinculada a una Persona Natural mediante un puente de identidad (kind 31000) usando firmas en anillo, permitiendo que la Persona demuestre "Soy una persona real y verificada" sin revelar quién es esa persona
- Usted es responsable de toda la actividad realizada a través de sus cuentas de Persona

### 6.8 Sin Garantía de Aceptación

No garantizamos que ninguna credencial sea aceptada por ninguna parte confiante. Las comunidades establecen sus propias políticas de aceptación mediante eventos de política kind 30078.

### 6.9 Cartera de Documentos

My Signet admite una cartera de documentos que contiene múltiples documentos de identidad. Cada documento produce su propia credencial y su propio nullifier. Esto permite la verificación progresiva: puede añadir documentos con el tiempo, y cada documento adicional fortalece su familia de nullifiers y contribuye a su Signet IQ.

---

## 7. Obligaciones del Usuario

### 7.1 Obligaciones Generales

Todos los usuarios deben:

1. **Exactitud.** Introducir información veraz al crear credenciales. Las credenciales fraudulentas socavan el modelo de confianza y pueden constituir fraude penal.
2. **Seguridad de claves.** Proteger su mnemónico y su clave privada. Usted es el único responsable de su seguridad.
3. **Cumplimiento.** Cumplir con todas las leyes y reglamentos aplicables.
4. **Uso responsable.** Utilizar el Protocolo de buena fe y no para ningún propósito ilegal, fraudulento o perjudicial.
5. **Notificación.** Informar con prontitud sobre vulnerabilidades de seguridad, fraude de credenciales o uso indebido del Protocolo a la dirección de contacto de la Sección 21.

### 7.2 Usos Prohibidos

Usted no debe:

1. Crear credenciales falsas, engañosas o fraudulentas
2. Suplantar a otra persona o entidad
3. Intentar aplicar ingeniería inversa a las pruebas de conocimiento cero para extraer datos personales
4. Utilizar el Protocolo para facilitar actividades ilegales, incluidos el robo de identidad, el fraude, el blanqueo de dinero, la financiación del terrorismo o la explotación infantil
5. Atacar la infraestructura criptográfica del Protocolo o intentar romper la anonimidad de los conjuntos de firmas en anillo
6. Saturar la red con eventos de credencial, aval o desafío ilegítimos
7. Colusionar con verificadores para obtener credenciales de Nivel 3 o Nivel 4 no justificadas
8. Utilizar sistemas automatizados para generar masivamente credenciales o avales sin verificación genuina
9. Interferir con o interrumpir el Protocolo o la red Nostr
10. Explotar el Protocolo para eludir las restricciones de edad o las medidas de seguridad infantil

### 7.3 Obligaciones de Avalista (Nivel 2)

Al avalar a otro usuario (evento kind 31000):

- Debe tener una base personal y genuina para el aval
- No debe aceptar pagos u otras compensaciones a cambio de proporcionar avales
- Puede revocar un aval en cualquier momento publicando un evento de revocación
- Su comportamiento como avalista afecta a su propio Signet IQ

---

## 8. Obligaciones del Verificador

### 8.1 Por Qué No Hay un Acuerdo Separado

Hemos incorporado el acuerdo de verificador en estos Términos porque las personas que más probablemente verificarán a menores —maestros en reuniones de padres, médicos de cabecera, trabajadores sociales— no deberían tener que navegar por un segundo documento legal. Al actuar como verificador Signet (publicando un evento kind 31000 o realizando una ceremonia), usted acepta las obligaciones de esta sección. Estas obligaciones se suman a sus deberes profesionales existentes y no los reemplazan.

### 8.2 Profesiones Elegibles

Puede actuar como verificador Signet si posee un registro vigente y válido con un organismo regulador reconocido en una de las siguientes categorías. Esta lista sigue el estándar de avales de pasaporte del Reino Unido y sus equivalentes internacionales.

**Profesionales jurídicos:** Abogado (solicitor), abogado litigante (barrister), procurador, letrado, ejecutivo jurídico, notario público, commissaire de justice, Notar, asesor de conveyancing autorizado, ejecutivo jurídico colegiado.

**Profesionales médicos y de la salud:** Médico, cirujano, médico de cabecera, dentista, farmacéutico, óptico/optometrista, enfermero titulado (donde esté permitido a nivel nacional), fisioterapeuta, psicólogo clínico, profesional de la salud comunitario u hospitalario registrado en un organismo nacional (GMC, NMC, GDC, GPhC, HCPC o equivalente).

**Profesionales de la educación:** Maestro titulado (registrado en la Agencia de Regulación de la Enseñanza o equivalente nacional), director o subdirector de escuela, profesor universitario registrado en un organismo profesional, inspector escolar.

**Profesionales financieros:** Contable colegiado (ICAEW, ICAS, ACCA, CIMA, CPA o equivalente), contable certificado colegiado, auditor autorizado, asesor financiero independiente autorizado por un regulador financiero nacional, funcionario bancario o de sociedad de crédito inmobiliario de categoría directiva.

**Profesionales del servicio público y de emergencias:** Oficial de policía, oficial de bomberos, miembro de las Fuerzas Armadas de Su Majestad (oficial), juez, magistrado, juez de paz, funcionario de la Fiscalía de la Corona, agente de reinserción social, trabajador social registrado en un organismo regulador nacional.

**Profesionales religiosos y comunitarios:** Ministro de culto, líder religioso reconocido como tal por una denominación registrada, registrador civil.

**Profesionales de ingeniería, ciencias y tecnología:** Ingeniero colegiado (registrado en una institución nacional de ingeniería), científico colegiado, arquitecto (registrado en la Junta de Registro de Arquitectos o equivalente), agrimensor colegiado.

**Otros profesionales regulados:** Cualquier profesional regulado por un organismo estatutario cuyo registro sea consultable públicamente y cuyos miembros estén sujetos a procedimientos de aptitud para el ejercicio. En caso de duda, contáctenos antes de realizar verificaciones.

En todos los casos, debe estar en buen estado (no estar sujeto a suspensión, restricción o procedimientos disciplinarios en curso que afecten a su aptitud para verificar identidades).

### 8.3 Registro

Para registrarse como verificador:

1. Publique un evento de credencial de verificador kind 31000 en Nostr que contenga su categoría profesional, jurisdicción, organismo licenciador y referencia de licencia.
2. Obtenga al menos dos avales de otros profesionales Signet verificados de al menos dos profesiones diferentes (el aval entre profesiones previene los anillos de colusión de profesión única).
3. El registro no implica respaldo de nuestra parte.

### 8.4 Realización de Verificaciones de Nivel 3 (Adulto)

Al realizar una verificación de Nivel 3 (Adulto), debe:

1. Verificar la identidad en persona, o mediante un proceso remoto legalmente equivalente expresamente permitido por la ley en la jurisdicción pertinente. La verificación remota es la excepción, no la norma.
2. Inspeccionar al menos un documento de identificación fotográfico original emitido por el gobierno (pasaporte, documento nacional de identidad o permiso de conducir). La inspección de documentos digitales (incluidas las credenciales de cartera eIDAS donde estén disponibles) está permitida donde la ley nacional la trate como equivalente a la inspección física.
3. Confirmar que la persona ante usted coincide con el documento.
4. Confirmar (o rechazar) los datos que el sujeto ha introducido previamente en la Aplicación. Está confirmando lo que ve; no está introduciendo datos en nombre del sujeto.
5. Calcular el nullifier de documento y, cuando se presenten múltiples documentos, la familia de nullifiers.
6. Emitir la credencial de Persona Natural (kind 31000) y la credencial de Persona (kind 31000) mediante la ceremonia de doble credencial.
7. Descartar el número de documento tras el cálculo del nullifier. No lo almacene a menos que sus obligaciones profesionales lo requieran independientemente.
8. Mantener registros de la verificación (fecha, lugar, identidad del sujeto, documentos inspeccionados, hash del nullifier, ambas claves públicas) durante el período requerido por sus obligaciones profesionales — normalmente al menos seis años.

**Métodos de confirmación y peso en el IQ:**

| Método | Descripción | Peso de contribución al IQ |
|---|---|---|
| A — Presencial, documento físico | Inspecciona físicamente un documento original y a la persona juntos, cara a cara | Peso completo |
| B — Presencial, documento digital | Reunión presencial; el sujeto presenta una cartera eIDAS o una identidad digital gubernamental verificada equivalente | Peso completo (donde la ley lo trate como equivalente) |
| C — Remoto, regulado | Videollamada con aprobación regulatoria y verificación de vivacidad; documentos originales enviados por mensajería o mostrados en alta resolución | Peso reducido |
| D — Remoto, no regulado | Cualquier proceso remoto no cubierto por C | No permitido para Nivel 3 o Nivel 4 |

El método de verificación se registra en la credencial (etiqueta `["method", "in-person-id"]` o equivalente). Los clientes y las partes confiantes pueden restringir la aceptación a ciertos métodos.

### 8.5 Realización de Verificaciones de Nivel 4 (Adulto + Menor)

Al realizar una verificación de Nivel 4 (Adulto + Menor), debe cumplir con todas las obligaciones de Nivel 3 y adicionalmente:

1. **Verificar la identidad del menor** utilizando documentos apropiados (certificado de nacimiento, pasaporte u otros documentos adecuados según su criterio profesional).
2. **Verificar la relación padre-tutor** mediante documentación: certificado de nacimiento (padre biológico), orden de tutela emitida por un tribunal (tutor legal), documentos de adopción (padre adoptivo) u orden de responsabilidad de padrastro.
3. **Maestros y verificadores de centros escolares:** Puede utilizar su conocimiento profesional y los registros de matrícula de la escuela (que ya incorporan la verificación del certificado de nacimiento) como evidencia en lugar de, o además de, los documentos originales. La fecha de nacimiento del menor ya está en los registros de la escuela. Un padre que presente su pasaporte en una reunión de padres es suficiente para una verificación de Nivel 4 en la misma sesión.
4. **Obtener el consentimiento parental** para la credencial del menor, documentado de acuerdo con la ley de protección infantil aplicable.
5. **Realizar la verificación con el menor presente** siempre que sea posible.
6. **Evaluar el bienestar del menor.** Ejerza su criterio profesional para identificar cualquier indicador de coerción, explotación o preocupación de salvaguarda. Si surgen tales preocupaciones, no proceda, y siga sus obligaciones de notificación obligatoria bajo la ley aplicable.
7. Emitir dos credenciales para el menor (Persona Natural + Persona), ambas con la prueba de rango de edad del menor y etiquetas de tutor que vinculan al menor con su padre o tutor verificado.

### 8.6 Acciones Prohibidas del Verificador

Usted no debe:

1. Emitir credenciales para alguien cuya identidad no haya confirmado genuinamente
2. Aceptar pagos, obsequios u otras compensaciones a cambio de emitir verificaciones no justificadas
3. Permitir que cualquier otra persona realice verificaciones utilizando sus credenciales o clave Nostr
4. Realizar verificaciones para familiares o allegados sin divulgación y aprobación previas
5. Autoverificarse — emitir credenciales de Nivel 3 o Nivel 4 para usted mismo
6. Retener copias de documentos de identidad más allá de lo que requieran sus obligaciones profesionales
7. Utilizar los datos obtenidos durante las verificaciones para cualquier propósito distinto de la propia verificación y el mantenimiento de registros requerido
8. Divulgar detalles de las verificaciones a terceros, excepto cuando lo requiera la ley

### 8.7 Obligaciones de Notificación del Verificador

Debe informarnos con prontitud de:

- Cualquier compromiso o presunto compromiso de su clave privada Nostr
- Cualquier descubrimiento de que ha emitido previamente una verificación fraudulenta o errónea
- Cualquier cambio en su estado de registro profesional (suspensión, restricción, revocación, procedimientos disciplinarios)
- Cualquier violación de datos que afecte a sus registros de verificación
- Cualquier proceso legal, investigación o acción regulatoria relacionada con sus actividades de verificación
- Cualquier conflicto de intereses que surja en conexión con una verificación

### 8.8 Responsabilidad del Verificador

Usted es independientemente responsable de la exactitud e integridad de sus verificaciones. Dado que está confirmando datos introducidos por el sujeto, su responsabilidad es específicamente por:

- Confirmar datos que en realidad no verificó, o que sabía o tenía motivos para saber que eran incorrectos
- No identificar falsificaciones de documentos que un profesional razonablemente competente en su campo habría identificado
- No identificar preocupaciones de salvaguarda en verificaciones de Nivel 4
- Violación de sus obligaciones profesionales y la ley aplicable

No supervisamos, respaldamos ni garantizamos la calidad del trabajo de ningún verificador individual. No somos conjunta ni solidariamente responsables de sus actos u omisiones. Usted es un profesional independiente, no nuestro empleado, agente ni socio.

### 8.9 Seguro

Debe mantener un seguro de responsabilidad profesional adecuado para sus actividades de verificación. El nivel apropiado depende de los requisitos existentes de su profesión. Si su profesión ya exige un seguro de responsabilidad profesional (como la mayoría de las profesiones de la Sección 8.2), esa cobertura debería extenderse a sus actividades de verificación Signet siempre que estén dentro del ámbito de su práctica profesional general.

### 8.10 Rescisión del Verificador

Su condición de verificador puede ser rescindida:

**De forma inmediata y sin previo aviso si:** su licencia profesional es suspendida o revocada; ha emitido verificaciones fraudulentas; su clave privada Nostr está comprometida; ha incumplido las obligaciones de seguridad infantil; o ha cometido un delito penal relacionado con sus actividades de verificación.

**Con 30 días de preaviso si:** incumple materialmente estos Términos y no lo subsana en 14 días; ya no cumple los requisitos de elegibilidad; o el Protocolo es descontinuado.

Tras la rescisión, su credencial de verificador kind 31000 es revocada. Las credenciales emitidas anteriormente permanecen válidas a menos que sean revocadas individualmente. Debe conservar los registros de verificación durante el período de retención requerido.

---

## 9. Operadores de Sitios Web y el SDK signet-verify.js

### 9.1 A Quién Se Aplica Esta Sección

Esta sección se aplica a cualquier persona u organización que integre el SDK signet-verify.js o que de otro modo llame a las APIs del Protocolo Signet desde un sitio web o aplicación para verificar la identidad o la edad de sus usuarios ("Operadores de Sitios Web").

### 9.2 Qué Proporciona el SDK

Cuando un usuario presenta una credencial Signet a su sitio web a través del SDK, usted recibe:

- Una prueba de rango de edad (por ejemplo, "18+", "13–17") — verificada matemáticamente
- La puntuación Signet IQ del usuario
- El nivel de credencial
- Una marca de tiempo de verificación

Usted no recibe:

- El nombre real del usuario
- La fecha de nacimiento o la edad del usuario
- El tipo o número de documento del usuario
- La dirección del usuario ni ninguna otra información de identificación personal
- La identidad del verificador

El SDK está diseñado para que usted reciba la información mínima necesaria para tomar una decisión de control de acceso por edad o identidad.

### 9.3 Obligaciones del Operador de Sitio Web

Al integrar el SDK, usted acepta:

1. **Sin almacenamiento más allá de la sesión.** No debe almacenar datos de prueba, afirmaciones de rango de edad ni puntuaciones Signet IQ más allá de la duración de la sesión del usuario, a menos que tenga una base jurídica específica para hacerlo bajo la ley de protección de datos aplicable y lo haya divulgado a sus usuarios.
2. **Sin reidentificación.** No debe intentar reidentificar a los usuarios a partir de los datos de prueba, ni combinar datos de prueba con otros datos para identificar a los usuarios.
3. **Sin elaboración de perfiles.** No debe utilizar datos de prueba para crear perfiles del historial de verificación o los estados de credenciales de los usuarios.
4. **Solo confianza precisa.** Solo debe confiar en la prueba para el propósito que proporciona — confirmar que un usuario cumple con un umbral de edad o identidad. No debe declarar a terceros que ha verificado la identidad real del usuario.
5. **Aviso de privacidad.** Debe divulgar en su aviso de privacidad que utiliza la verificación de credenciales Signet y describir qué datos recibe y cómo los utiliza.
6. **Sin manipulación.** No debe utilizar el SDK de una manera diseñada para eludir sus protecciones de privacidad o manipular a los usuarios para que presenten credenciales que de otro modo no presentarían.
7. **Cumplimiento.** Debe cumplir con todas las leyes aplicables, incluidas las leyes de protección de datos (RGPD, UK GDPR, CCPA/CPRA y equivalentes), en su uso del SDK.

### 9.4 Licencia del SDK

El SDK signet-verify.js se pone a disposición bajo la misma licencia de código abierto que la especificación del Protocolo (véase el repositorio del Protocolo). Debe cumplir con los términos de la licencia.

### 9.5 Sin Respaldo

La integración del SDK no implica respaldo de su sitio web o servicio por parte nuestra. No debe declarar que Signet respalda o certifica su servicio.

---

## 10. El Bot de Verificación

### 10.1 Qué Es

El bot de verificación de Signet ("el Bot") es un servicio automatizado que monitorea la red Nostr en busca de eventos de credencial kind 31000 y proporciona resúmenes de verificación de credenciales a solicitud. El Bot puede publicar respuestas a consultas, publicar resúmenes periódicos o responder a menciones.

### 10.2 Qué Procesa

El Bot procesa únicamente eventos Nostr públicos. Lee eventos kind 31000, 31000, 30078, 31000, 31000, 31000 y 31000 de relays públicos. No accede a su clave privada, su mnemónico ni a ningún dato almacenado localmente en la Aplicación.

El Bot calcula las puntuaciones Signet IQ a partir de datos públicos en cadena. No recopila ni almacena datos personales más allá de lo que se publica en los eventos Nostr públicos.

### 10.3 Quién Lo Opera

El Bot es operado por el equipo del Protocolo. Su clave pública Nostr se publica en el repositorio del Protocolo. Terceros pueden operar bots de verificación compatibles usando la especificación del Protocolo de código abierto; los bots de terceros no son operados por nosotros y no son nuestra responsabilidad.

### 10.4 Limitaciones del Bot

El Bot proporciona un servicio de mejor esfuerzo. Puede ir por detrás del estado en tiempo real de los relays. No garantiza que su salida refleje todos los eventos actuales de credenciales o revocaciones en todos los relays. Las partes confiantes que toman decisiones de control de acceso deben consultar los relays directamente, no confiar únicamente en la salida del Bot.

---

## 11. Puntuaciones Signet IQ

### 11.1 Qué Es el Signet IQ

La puntuación Signet IQ (0–200) es una puntuación de reputación continua derivada de datos en cadena. Una puntuación de 100 representa una línea de base equivalente al estándar actual de identidad gubernamental del Reino Unido/EE. UU. Las puntuaciones superiores a 100 reflejan múltiples verificaciones, fuerte confianza entre pares, puentes de identidad y longevidad de la cuenta.

### 11.2 Cómo Se Calcula

La puntuación se calcula a partir de contribuciones ponderadas que incluyen:

- Verificación profesional de Nivel 3 o Nivel 4 (mayor peso)
- Verificación cruzada por profesionales independientes adicionales
- Avales presenciales de usuarios con alto IQ
- Puentes de identidad (kind 31000)
- Antigüedad y actividad de la cuenta
- Puntuación de confianza del verificador (véase la Sección 11.3)

El peso del aval escala con el propio Signet IQ del avalista. Un aval de alguien con IQ 150 tiene más peso que un aval de alguien con IQ 40.

### 11.3 Puntuaciones de Confianza del Verificador

Cada verificador profesional tiene una puntuación de confianza que alimenta la contribución al IQ de las credenciales que ha emitido. La puntuación de confianza se deriva de:

- Método de confirmación (el Método A tiene peso completo; el Método C tiene peso reducido — véase la Sección 8.4)
- Número de verificaciones cruzadas independientes de sus sujetos por otros verificadores
- El Índice de Percepción de la Corrupción (CPI) de la jurisdicción — las credenciales de jurisdicciones con puntuaciones CPI más bajas tienen menos peso, no por discriminación, sino porque la confianza estadística objetiva en el proceso de verificación es menor
- Detección de anomalías (por ejemplo, 30 verificaciones en una hora, agrupamiento temporal rápido, patrones de nullifier sospechosos)

### 11.4 Degradación

La contribución al IQ de una credencial se degrada a medida que:

- Se aproxima la fecha de vencimiento de la credencial
- Se aproxima la fecha de vencimiento del documento subyacente (degradación más rápida)
- Cae la puntuación de confianza del verificador (por ejemplo, debido a fraude descubierto)

La degradación es gradual. No hay un acantilado abrupto.

### 11.5 Exención de Responsabilidad

La puntuación Signet IQ es una métrica calculada basada en datos públicos disponibles en cadena. No constituye una evaluación definitiva de fiabilidad, identidad o carácter. No garantizamos que ninguna puntuación Signet IQ refleje con precisión la fiabilidad de ningún usuario.

---

## 12. Protección de Datos

### 12.1 Datos Personales que el Protocolo No Recopila

El Protocolo Signet está diseñado para no recopilar ni publicar sus datos personales. Su nombre, fecha de nacimiento, nacionalidad y número de documento:

- Nunca se publican en la red Nostr
- Nunca se transmiten a nuestros servidores
- Se almacenan localmente en su dispositivo en forma cifrada (AES-256-GCM, clave derivada mediante PBKDF2 con 600.000 iteraciones)
- Son accesibles solo tras una autenticación biométrica o por PIN exitosa

### 12.2 Qué Se Publica en Cadena

Los siguientes datos se publican en la red Nostr (públicos por diseño):

- Su clave pública Nostr (npub)
- Su nivel y tipo de credencial
- Su raíz Merkle (un hash criptográfico — no revela atributos personales)
- Su nullifier de documento (un hash unidireccional — no revela los detalles del documento)
- Su prueba de rango de edad (por ejemplo, "18+" — no revela su edad)
- Metadatos de credencial del verificador (profesión, jurisdicción, referencia del organismo licenciador)
- Atestaciones de aval
- Eventos de delegación

Una vez publicados en Nostr, estos eventos son públicos y pueden ser replicados por los operadores de relay. No podemos eliminar ni modificar los eventos publicados.

### 12.3 Almacenamiento Local de Datos

Los datos almacenados localmente en la Aplicación (mnemónico, claves privadas, datos de documentos utilizados para calcular el árbol Merkle) se almacenan en IndexedDB en forma cifrada. Nunca se almacenan en texto plano. La clave de cifrado está protegida por su datos biométricos o PIN.

### 12.4 Los Verificadores como Responsables del Tratamiento Independientes

Cuando un verificador profesional inspecciona sus documentos de identidad y mantiene registros de verificación, lo hace como responsable del tratamiento independiente. Su tratamiento está regido por sus obligaciones profesionales y la ley de protección de datos aplicable (UK GDPR, RGPD, CCPA/CPRA o equivalente), no por nosotros.

### 12.5 Protección de Datos Específica por Jurisdicción

| Jurisdicción | Ley Aplicable |
|---|---|
| Reino Unido | UK GDPR, Ley de Protección de Datos de 2018 |
| Unión Europea | RGPD (Reglamento 2016/679) |
| Estados Unidos | CCPA/CPRA (California), leyes estatales de privacidad |
| Brasil | LGPD |
| India | Ley DPDP de 2023 |
| Australia | Ley de Privacidad de 1988 |
| Japón | APPI |
| Corea del Sur | PIPA |
| EAU | Decreto-Ley Federal N.° 45 de 2021 |
| Otros | Ley nacional o regional de protección de datos aplicable |

### 12.6 Derechos de los Interesados en la UE/Reino Unido

Si se encuentra en la UE o en el Reino Unido, tiene derecho a acceder, rectificar, suprimir, restringir el tratamiento y portar sus datos personales. Dado que el Protocolo está diseñado para minimizar la recopilación de datos, los datos que tenemos sobre usted son limitados. Contáctenos en la dirección de la Sección 21 para ejercer sus derechos.

### 12.7 Resolución de Disputas en Línea de la UE

Si es consumidor en la UE, puede presentar una reclamación a través de la plataforma de Resolución de Disputas en Línea de la UE: [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

---

## 13. Propiedad Intelectual

### 13.1 Especificación del Protocolo

La especificación del Protocolo Signet se publica bajo una licencia de código abierto especificada en el repositorio del Protocolo. Se le otorga una licencia para usar, implementar y desarrollar sobre el Protocolo de conformidad con esa licencia.

### 13.2 Marcas Comerciales

"The Signet Protocol", "Signet" y "My Signet" y los logotipos asociados son marcas comerciales. No puede utilizar estas marcas de una manera que implique respaldo o afiliación sin el consentimiento previo por escrito, excepto para la referencia descriptiva precisa al Protocolo o la Aplicación.

### 13.3 Contenido del Usuario

Usted conserva la propiedad de cualquier contenido que cree usando el Protocolo (credenciales, avales, eventos de delegación). Al publicar eventos en la red Nostr, reconoce que estos eventos son públicos y pueden ser almacenados y replicados por los operadores de relay.

### 13.4 SDK

El SDK signet-verify.js se pone a disposición bajo la licencia de código abierto especificada en el repositorio del Protocolo. El uso comercial está permitido de conformidad con esa licencia.

### 13.5 Contribuciones

Las contribuciones a la especificación del Protocolo o al código de implementación están sujetas al acuerdo de licencia de contribuidor en el repositorio del Protocolo.

---

## 14. Exenciones de Responsabilidad

### 14.1 Protocolo Proporcionado "Tal Cual"

EL PROTOCOLO, LA APLICACIÓN Y EL SDK SE PROPORCIONAN "TAL CUAL" Y "SEGÚN DISPONIBILIDAD" SIN GARANTÍAS DE NINGÚN TIPO, YA SEAN EXPRESAS O IMPLÍCITAS, INCLUIDAS, ENTRE OTRAS, LAS GARANTÍAS IMPLÍCITAS DE COMERCIABILIDAD, IDONEIDAD PARA UN FIN PARTICULAR, TÍTULO Y NO INFRACCIÓN.

### 14.2 Sin Garantía de Exactitud

NO GARANTIZAMOS QUE:

- NINGUNA CREDENCIAL SEA EXACTA, COMPLETA O FIABLE
- NINGÚN VERIFICADOR SEA COMPETENTE, HONESTO O DEBIDAMENTE AUTORIZADO
- EL PROTOCOLO FUNCIONE SIN INTERRUPCIONES NI ERRORES
- LOS COMPONENTES CRIPTOGRÁFICOS PERMANEZCAN SEGUROS INDEFINIDAMENTE
- NINGUNA PUNTUACIÓN SIGNET IQ REFLEJE CON PRECISIÓN LA FIABILIDAD DE NINGÚN USUARIO
- EL SDK CUMPLA CON LOS REQUISITOS DE CUMPLIMIENTO LEGAL DE NINGUNA PARTE CONFIANTE EN PARTICULAR

### 14.3 Exención de Responsabilidad por Descentralización

Dado que el Protocolo opera en una red descentralizada, nosotros:

- No podemos controlar, monitorear ni censurar la actividad del Protocolo
- No podemos revertir ni modificar los eventos publicados
- No podemos garantizar la disponibilidad o el rendimiento de ningún relay
- No podemos hacer cumplir estos Términos contra todos los participantes a nivel mundial
- No podemos ser responsables de la conducta de los operadores de relay independientes

### 14.4 Exención de Responsabilidad Criptográfica

Ningún sistema criptográfico es demostrablemente seguro contra todos los ataques futuros. Los avances en informática (incluida la computación cuántica) pueden afectar la seguridad de los componentes criptográficos del Protocolo. Tenemos la intención de admitir la migración poscuántica, pero no podemos garantizar plazos específicos.

### 14.5 Exención de Responsabilidad Regulatoria

El panorama regulatorio para la identidad descentralizada y las pruebas de conocimiento cero está evolucionando. Las obligaciones de cumplimiento pueden cambiar. Las características del Protocolo pueden quedar sujetas a nuevas regulaciones.

---

## 15. Limitación de Responsabilidad

### 15.1 Limitación General

EN LA MEDIDA MÁXIMA PERMITIDA POR LA LEY APLICABLE, NOSOTROS, NUESTROS DIRECTORES, EJECUTIVOS, EMPLEADOS, AGENTES Y AFILIADOS NO SEREMOS RESPONSABLES DE NINGÚN DAÑO INDIRECTO, INCIDENTAL, ESPECIAL, CONSECUENTE, PUNITIVO NI EJEMPLAR, INCLUIDA LA PÉRDIDA DE BENEFICIOS, FONDO DE COMERCIO, DATOS U OTRAS PÉRDIDAS INTANGIBLES, INDEPENDIENTEMENTE DE SI FUIMOS INFORMADOS DE LA POSIBILIDAD DE TALES DAÑOS.

### 15.2 Límite de Responsabilidad

EN LA MEDIDA MÁXIMA PERMITIDA POR LA LEY APLICABLE, NUESTRA RESPONSABILIDAD TOTAL AGREGADA POR TODAS LAS RECLAMACIONES QUE SURJAN DE O SE RELACIONEN CON ESTOS TÉRMINOS O EL PROTOCOLO NO EXCEDERÁ EL MAYOR DE: (A) LA CANTIDAD QUE NOS PAGÓ EN LOS 12 MESES ANTERIORES A LA RECLAMACIÓN, O (B) 100 £.

### 15.3 Excepciones

Las limitaciones anteriores no se aplican a:

- La responsabilidad que no puede excluirse o limitarse bajo la ley aplicable
- La responsabilidad derivada de conducta dolosa o fraude
- La responsabilidad por muerte o lesiones personales causadas por negligencia (en jurisdicciones donde la limitación está prohibida)
- Los derechos estatutarios del consumidor que no pueden renunciarse mediante contrato

### 15.4 Protección del Consumidor

Nada en estos Términos afecta a sus derechos estatutarios como consumidor bajo las leyes de protección del consumidor aplicables.

---

## 16. Indemnización

### 16.1 Sus Obligaciones de Indemnización

Usted acepta indemnizarnos, defendernos y eximirnos de responsabilidad frente a cualquier reclamación, daño, pérdida, responsabilidad, costo y gasto (incluidos honorarios legales razonables) que surja de o se relacione con:

1. Su uso del Protocolo
2. Su incumplimiento de estos Términos
3. Su violación de cualquier ley aplicable
4. Su infracción de los derechos de terceros
5. Las credenciales que cree, incluidas las credenciales falsas o engañosas
6. Los avales que emita
7. Las verificaciones que realice (si es verificador)
8. Su uso del SDK y cualquier reclamación presentada por sus usuarios en relación con el mismo

### 16.2 Procedimiento de Indemnización

Le notificaremos con prontitud cualquier reclamación, proporcionaremos cooperación razonable y le permitiremos controlar la defensa y liquidación de la reclamación, siempre que no acuerde ninguna reclamación que nos imponga obligaciones sin nuestro consentimiento previo por escrito.

---

## 17. Ley Aplicable y Resolución de Disputas

### 17.1 Ley Aplicable

Estos Términos se rigen e interpretan de conformidad con las leyes de Inglaterra y Gales, sin tener en cuenta las disposiciones sobre conflicto de leyes.

### 17.2 Resolución de Disputas

**Paso 1 — Negociación:** Las partes intentarán primero resolver cualquier disputa mediante negociación de buena fe durante 30 días.

**Paso 2 — Mediación:** Si la negociación fracasa, las partes se someterán a mediación administrada por el Centro para la Resolución Eficaz de Disputas (CEDR) de acuerdo con sus normas.

**Paso 3 — Arbitraje:** Si la mediación fracasa, la disputa se resolverá definitivamente mediante arbitraje vinculante administrado por el Tribunal de Arbitraje Internacional de Londres (LCIA) bajo sus normas. La sede del arbitraje es Londres. El idioma es el inglés. El laudo es definitivo y vinculante.

### 17.3 Renuncia a la Acción Colectiva

EN LA MEDIDA MÁXIMA PERMITIDA POR LA LEY APLICABLE, USTED ACEPTA RESOLVER LAS DISPUTAS ÚNICAMENTE DE FORMA INDIVIDUAL Y NO EN UNA ACCIÓN COLECTIVA, CONSOLIDADA O REPRESENTATIVA. SI ESTA RENUNCIA ES INAPLICABLE, LA DISPOSICIÓN DE ARBITRAJE ES NULA Y SIN EFECTO.

### 17.4 Excepciones

Cualquiera de las partes puede solicitar una medida cautelar ante cualquier tribunal con jurisdicción competente para proteger la propiedad intelectual o prevenir un daño irreparable.

### 17.5 Derechos del Consumidor en la UE

Si es consumidor en la UE, también puede recurrir a sus tribunales nacionales y a la plataforma de ODR de la UE: [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

### 17.6 Asuntos Regulatorios Profesionales del Verificador

Nada en estos Términos restringe la jurisdicción de ningún organismo regulador profesional sobre un verificador, el derecho del verificador a buscar orientación de su organismo regulador, ni nuestro derecho a informar de preocupaciones al organismo regulador de un verificador.

---

## 18. Rescisión

### 18.1 Su Derecho a Rescindir

Puede dejar de usar el Protocolo en cualquier momento. Debido a la naturaleza descentralizada del Protocolo, los eventos publicados anteriormente pueden permanecer en los relays Nostr indefinidamente.

### 18.2 Nuestros Derechos

Nos reservamos el derecho a:

- Revocar credenciales de verificador por causa (como se describe en la Sección 8.10)
- Publicar avisos comunitarios sobre credenciales o actores fraudulentos
- Modificar o descontinuar la especificación del Protocolo

### 18.3 Efectos de la Rescisión

Tras la rescisión:

- Su derecho a usar cualquier componente propietario de la Aplicación cesa
- Las Secciones 8 (obligaciones del verificador — el mantenimiento de registros sobrevive), 12, 13, 14, 15, 16, 17 y 20 sobreviven
- Los eventos Nostr publicados anteriormente no se ven afectados

---

## 19. Modificaciones

### 19.1 Derecho a Modificar

Podemos modificar estos Términos en cualquier momento. Las modificaciones entran en vigor al:

- Publicar los Términos actualizados en el repositorio del Protocolo
- Publicar un evento Nostr que haga referencia a los Términos actualizados
- Dar 30 días de preaviso para cambios sustanciales

### 19.2 Aceptación de Modificaciones

Su uso continuado del Protocolo después de la fecha efectiva constituye aceptación. Si no está de acuerdo, debe dejar de usar el Protocolo.

### 19.3 Cambios Sustanciales

Para los cambios sustanciales, proporcionaremos:

- Aviso claro sobre la naturaleza de los cambios
- Un resumen en lenguaje sencillo de los cambios clave
- Al menos 30 días antes de que los cambios entren en vigor

---

## 20. Disposiciones Generales

### 20.1 Acuerdo Completo

Estos Términos constituyen el acuerdo completo entre usted y nosotros con respecto al Protocolo. Reemplazan el Acuerdo de Verificador publicado por separado (que ahora está incorporado aquí como Sección 8). Si usted ejecutó previamente un Acuerdo de Verificador independiente, estos Términos lo reemplazan a partir de la Fecha de Entrada en Vigor.

### 20.2 Divisibilidad

Si alguna disposición se declara inválida o inaplicable, se aplicará en la medida máxima permitida. Las demás disposiciones permanecen en plena vigencia.

### 20.3 Renuncia

El hecho de no hacer cumplir ninguna disposición no constituye una renuncia.

### 20.4 Cesión

No puede ceder estos Términos sin nuestro consentimiento previo por escrito. Podemos ceder estos Términos sin su consentimiento.

### 20.5 Fuerza Mayor

Ninguna de las partes es responsable por incumplimiento o retraso debido a causas más allá de su control razonable, incluidos desastres naturales, guerra, terrorismo, pandemias, acción gubernamental, fallos de red, compromisos de algoritmos criptográficos o interrupciones de relays Nostr.

### 20.6 Avisos

Avisos a nosotros: véase la Sección 21. Avisos a usted: cualquier información de contacto que haya proporcionado, o mediante evento Nostr o el repositorio del Protocolo.

### 20.7 Terceros Beneficiarios

Estos Términos no crean derechos de terceros beneficiarios, excepto que los operadores de relay de la red Nostr y los usuarios del Protocolo que confían en las credenciales emitidas por los verificadores son beneficiarios previstos de la Sección 8.

### 20.8 Cumplimiento de Exportación

Debe cumplir con todas las leyes de exportación y sanciones aplicables. Los componentes criptográficos del Protocolo pueden estar sujetos a controles de exportación en determinadas jurisdicciones.

### 20.9 Epígrafes

Los títulos de las secciones son solo por conveniencia y no afectan a la interpretación.

---

## 21. Contacto

Para preguntas sobre estos Términos, para ejercer derechos de protección de datos o para informar de problemas de seguridad:

**El Protocolo Signet**
Correo electrónico: admin@forgesworn.dev
Divulgaciones de seguridad: admin@forgesworn.dev
Repositorio: https://github.com/forgesworn/signet-protocol

---

## 22. Anexos por Jurisdicción

### Anexo A — Reino Unido

**Organismos licenciadores:** Law Society de Inglaterra y Gales, Law Society de Escocia, Law Society de Irlanda del Norte, Bar Council de Inglaterra y Gales, Faculty of Advocates, Consejo Médico General (GMC), Consejo de Enfermería y Obstetricia (NMC), Consejo General de Odontología (GDC), Consejo General de Farmacia (GPhC), Consejo de Profesiones Sanitarias y Asistenciales (HCPC), Agencia de Regulación de la Enseñanza (TRA), Consejo General de Enseñanza de Escocia (GTCS), Junta de Registro de Arquitectos (ARB), Instituto de Contables Colegiados de Inglaterra y Gales (ICAEW), Instituto de Contables Colegiados de Escocia (ICAS), Asociación de Contables Certificados Colegiados (ACCA), Autoridad de Conducta Financiera (FCA) — personas autorizadas, Oficina de la Facultad del Arzobispo de Canterbury (notarios públicos).

**Responsabilidad profesional:** Según lo requieran la SRA, la FCA, el GMC, la TRA o el organismo regulador pertinente.

**Seguridad infantil:** Ley de Menores de 1989 y 2004; Ley de Salvaguarda de Grupos Vulnerables de 2006; Verificación Mejorada del DBS requerida para maestros y otros roles de actividad regulada que realicen verificaciones de Nivel 4; notificación obligatoria bajo Working Together to Safeguard Children (2023).

**Protección de datos:** UK GDPR; Ley de Protección de Datos de 2018; orientación de la ICO; orientación del DSIT sobre datos biométricos.

**Verificación de edad:** Ley de Seguridad en Línea de 2022 (aseguramiento de edad aprobado por Ofcom). La verificación profesional presencial de Nivel 4 supera los métodos aceptados por Ofcom.

### Anexo B — Estados Unidos

**Organismos licenciadores:** Colegios de abogados estatales; juntas médicas estatales; comisiones notariales estatales; departamentos estatales de educación (maestros); reguladores financieros estatales pertinentes.

**Nota:** La elegibilidad y las obligaciones varían significativamente según el estado. Debe cumplir con la ley del estado o los estados donde realice verificaciones.

**Seguridad infantil:** COPPA (Ley de Protección de la Privacidad en Línea de los Niños); FERPA (para verificadores escolares); obligaciones estatales de notificación obligatoria; estatutos estatales de protección infantil. Los registros de matrícula escolar en poder de un maestro pueden servir como evidencia documental para verificaciones de Nivel 4 donde la ley estatal lo permita.

**Protección de datos:** CCPA/CPRA (California); Virginia CDPA; otras leyes estatales de privacidad; FERPA (registros escolares). Es posible que se requiera un Acuerdo de Procesamiento de Datos separado para usuarios residentes en California.

### Anexo C — Unión Europea

**Organismos licenciadores:** Colegios de abogados nacionales, consejos médicos, cámaras notariales y sus equivalentes en cada Estado miembro.

**Nota:** Los requisitos específicos varían según el Estado miembro. Los verificadores deben cumplir con la ley del Estado miembro donde estén establecidos y donde realicen verificaciones.

**eIDAS 2.0:** El identificador único de persona eIDAS, cuando se presenta a través de una cartera eIDAS emitida por el gobierno, puede servir como fuente adicional de nullifier. La fórmula del nullifier es `SHA-256(LP("eidas") || LP(eidas_unique_id) || LP("signet-nullifier-v2"))`.

**Seguridad infantil:** RGPD Artículo 8; legislación nacional de transposición; Reglamento (UE) 2022/2065 (DSA) obligaciones de verificación de edad.

**Protección de datos:** RGPD (Reglamento 2016/679); legislación nacional de transposición; orientación de las APD nacionales.

### Anexo D — Australia

**Organismos licenciadores:** Colegios de abogados estatales y territoriales; Agencia Australiana de Regulación de Profesionales de la Salud (AHPRA) para personal médico y de salud aliada; departamentos de justicia estatales/territoriales (notarios); organismos pertinentes de registro de maestros estatales.

**Seguridad infantil:** Verificación de Trabajo con Niños según corresponda al rol; Ley de Seguridad en Línea de 2021; estatutos estatales de protección infantil.

**Protección de datos:** Ley de Privacidad de 1988; Principios Australianos de Privacidad; Derecho de Datos del Consumidor (CDR) donde sea aplicable.

### Anexo E — Japón

**Organismos licenciadores:** Federación Japonesa de Colegios de Abogados (JFBA); Ministerio de Justicia (notarios); Asociación Médica de Japón; autoridades pertinentes de registro de maestros.

**Seguridad infantil:** Directrices de la APPI; legislación nacional de protección infantil; obligaciones de Trabajo con Jóvenes.

**Protección de datos:** Ley sobre la Protección de la Información Personal (APPI) y sus enmiendas.

### Anexo F — Corea del Sur

**Organismos licenciadores:** Asociación de Abogados de Corea; Asociación Médica de Corea; ministerios gubernamentales pertinentes para otras profesiones reguladas.

**Seguridad infantil:** Ley de Protección de Información Personal (PIPA); Ley de Protección de la Juventud; obligaciones de notificación obligatoria.

**Protección de datos:** PIPA.

### Anexo G — Brasil

**Organismos licenciadores:** Ordem dos Advogados do Brasil (OAB); Conselho Federal de Medicina (CFM); cámaras notariales; consejos profesionales federales y estatales pertinentes.

**Seguridad infantil:** LGPD Artículo 14 (datos de menores — se requiere consentimiento parental); Estatuto da Criança e do Adolescente (ECA); obligaciones de notificación obligatoria.

**Protección de datos:** Lei Geral de Proteção de Dados (LGPD); orientación de la ANPD.

### Anexo H — India

**Organismos licenciadores:** Consejo del Colegio de Abogados de India y colegios de abogados estatales; Comisión Médica Nacional (NMC); autoridades estatales pertinentes para otras profesiones reguladas.

**Seguridad infantil:** Ley de Protección de Datos Personales Digitales de 2023 (DPDP); Ley de Protección de Menores de Delitos Sexuales (POCSO); obligaciones de notificación obligatoria.

**Protección de datos:** Ley DPDP de 2023; reglamentos emitidos al efecto.

### Anexo I — Emiratos Árabes Unidos

**Organismos licenciadores:** Ministerio de Justicia; Autoridad de Salud de Dubái (DHA) o Autoridad de Salud de Abu Dabi (HAAD); autoridades profesionales pertinentes del emirato.

**Seguridad infantil:** Ley Federal N.° 3 de 2016 (Ley de Wadeema — Ley de Derechos del Niño); obligaciones de notificación obligatoria.

**Protección de datos:** Decreto-Ley Federal N.° 45 de 2021 sobre Protección de Datos Personales; orientación de la Oficina de Datos de los EAU.

---

*El Protocolo Signet — v0.1.0 — Marzo de 2026*
*Este documento se proporciona con fines informativos. No constituye asesoramiento jurídico. Busque asesoría jurídica cualificada para su jurisdicción antes de utilizarlo.*
