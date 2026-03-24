> **Aviso de traducción automática:** Este documento ha sido traducido al español mediante inteligencia artificial. La versión en inglés disponible en `en.md` es el único documento jurídicamente vinculante. En caso de discrepancia entre la versión en español y la versión en inglés, prevalecerá la versión en inglés.

---

# Política de Seguridad Infantil

**El Protocolo Signet — v0.1.0**

*Plantilla — Consulte con asesoría jurídica cualificada en su jurisdicción antes de la implementación.*

**Fecha de entrada en vigor:** Marzo de 2026
**Última actualización:** Marzo de 2026

---

## 1. Propósito

La presente Política de Seguridad Infantil (la "Política") establece el compromiso del Protocolo Signet ("nosotros", "nos" o "nuestro") de proteger a los menores que interactúan o se ven afectados por el Protocolo Signet (el "Protocolo"). La verificación de Nivel 4 del Protocolo (Verificación Profesional — Adulto + Menor) aborda específicamente la verificación de identidad de menores, y esta Política regula la forma en que dicha capacidad —y todos los datos relacionados con menores— son tratados.

La seguridad y privacidad de los menores es nuestra preocupación primordial. Esta Política está diseñada para cumplir con todas las leyes de protección infantil aplicables a nivel mundial y para superar los requisitos mínimos cuando sea viable.

---

## 2. Ámbito de Aplicación

Esta Política se aplica a:

- Todas las interacciones con el Protocolo Signet que involucren a personas menores de 18 años (o la edad de la mayoría de edad en la jurisdicción correspondiente, la que sea mayor)
- Los procesos de emisión y verificación de credenciales de Nivel 4
- Los procesos de verificación de edad mediante pruebas de conocimiento cero
- Todo el personal, verificadores, partes confiantes y terceros que interactúen con datos de menores a través del Protocolo
- Todas las jurisdicciones donde se utilice el Protocolo

---

## 3. Definiciones

**"Menor"** significa cualquier persona menor de 18 años, o menor de la edad de mayoría de edad en la jurisdicción correspondiente, la que sea mayor.

**"Edad de Consentimiento Digital"** significa la edad mínima a partir de la cual un menor puede consentir de manera independiente el tratamiento de sus datos personales para servicios digitales, tal como la define la jurisdicción aplicable.

**"Padre/Tutor"** significa un padre, tutor legal u otra persona con autoridad legal para actuar en nombre de un menor.

**"Verificación de Nivel 4"** significa el nivel de Verificación Profesional (Adulto + Menor) del Protocolo, en el que un verificador profesional autorizado confirma la identidad de un menor con la participación y el consentimiento de un padre/tutor.

**"Prueba de Rango de Edad"** significa una prueba de conocimiento cero (mediante Bulletproofs) que demuestra que la edad de un usuario se encuentra dentro de un rango especificado sin revelar la fecha exacta de nacimiento.

**"Signet IQ"** significa la puntuación continua de Cociente de Identificación del Protocolo (0–200) que refleja la solidez acumulada de las señales de verificación de un usuario. Para los menores, el Signet IQ se calcula a partir del nivel de verificación propio del tutor y su Signet IQ, la credencial de Nivel 4 propia del menor, y cualquier aval de cuentas verificadas.

---

## 4. Marco Regulatorio

### 4.1 Cumplimiento Internacional

Esta Política está diseñada para cumplir con las siguientes leyes y marcos normativos:

| Jurisdicción | Ley / Marco | Requisitos Principales |
|-------------|-------------|-----------------------|
| **Estados Unidos** | Ley de Protección de la Privacidad en Línea de los Niños (COPPA) | Consentimiento parental verificable para menores de 13 años; minimización de datos; derechos de acceso parental |
| **Unión Europea** | RGPD Artículo 8 | Edad de consentimiento digital de 16 años (los Estados miembros pueden reducirla a 13); consentimiento parental requerido por debajo de la edad de consentimiento digital |
| **Reino Unido** | UK GDPR + Código de Diseño Apropiado para la Edad (AADC) | Interés superior del menor; diseño apropiado para la edad; 15 estándares del AADC |
| **Australia** | Ley de Privacidad de 1988 + Ley de Seguridad en Línea de 2021 | Medidas razonables para verificar la edad; expectativas básicas de seguridad en línea |
| **Corea del Sur** | PIPA + Ley de Promoción de la Utilización de Redes de Información y Comunicaciones | Consentimiento del representante legal para menores de 14 años |
| **Brasil** | LGPD Artículo 14 | Interés superior del menor; consentimiento parental específico para menores de 12 años; doble consentimiento para menores de 12 a 17 años |
| **India** | Ley DPDP de 2023 | Consentimiento verificable del padre/tutor para menores (menores de 18 años); prohibición de seguimiento, monitoreo conductual y publicidad dirigida a menores |
| **China** | PIPL Artículo 28 + Disposiciones sobre Protección de Menores en Línea | Consentimiento específico para menores de 14 años; protecciones reforzadas para todos los menores |
| **Japón** | APPI + Ley Básica de Ciberseguridad | Directrices del sector para la protección de datos de menores |
| **Canadá** | PIPEDA + leyes provinciales | Consentimiento significativo basado en la capacidad del menor |

### 4.2 Convención de las Naciones Unidas sobre los Derechos del Niño

Esta Política se guía por los principios de la Convención de las Naciones Unidas sobre los Derechos del Niño, incluidos:
- El interés superior del menor (Artículo 3)
- El derecho a la privacidad (Artículo 16)
- El derecho a la protección contra la explotación (Artículo 36)

---

## 5. Verificación de Edad mediante Pruebas de Conocimiento Cero

### 5.1 Funcionamiento de la Verificación de Edad

El Protocolo Signet utiliza pruebas de conocimiento cero basadas en Bulletproofs para la verificación de edad. Este enfoque:

1. **Demuestra sin revelar:** Un usuario puede demostrar que se encuentra dentro de un rango de edad especificado (por ejemplo, "mayor de 13", "mayor de 16", "mayor de 18", "de 13 a 17") sin revelar su fecha exacta de nacimiento.
2. **No puede ser sometido a ingeniería inversa:** La prueba de conocimiento cero está construida matemáticamente de modo que la fecha de nacimiento subyacente no puede ser extraída de la prueba.
3. **Se verifica criptográficamente:** Las partes confiantes pueden verificar la validez de la prueba sin conocer nada más allá de la afirmación sobre el rango de edad.
4. **Se emite una vez, se usa múltiples veces:** Una única prueba de rango de edad puede ser presentada a múltiples partes confiantes sin necesidad de nueva verificación.

### 5.2 Categorías de Rango de Edad

El Protocolo admite las siguientes pruebas de rango de edad estándar:

| Rango | Descripción | Caso de Uso |
|-------|-------------|-------------|
| Menor de 13 | Por debajo del umbral de COPPA | Requiere consentimiento y supervisión parental completos |
| 13–15 | Por encima de COPPA, por debajo de algunos umbrales del RGPD | Puede requerir consentimiento parental según la jurisdicción |
| 16–17 | Por encima de la mayoría de las edades de consentimiento digital, por debajo de la mayoría de edad | Consentimiento independiente en la mayoría de las jurisdicciones; cierta supervisión parental |
| 18+ | Mayoría de edad en la mayoría de las jurisdicciones | Consentimiento independiente pleno |
| Personalizado | Rangos de edad específicos de la jurisdicción | Cumplimiento de requisitos locales específicos |

### 5.3 Emisión de Pruebas para Menores

Para los menores (menores de 18 años), la ceremonia de verificación sigue un flujo dirigido por el usuario con confirmación profesional:

1. El padre/tutor y el menor acuden a una verificación de Nivel 4 con un profesional autorizado (abogado, notario, médico o equivalente).
2. **El usuario (padre/tutor) introduce todos los datos del documento** en la aplicación My Signet: tipo de documento, país de emisión, número de documento y fecha de nacimiento del menor. El verificador inspecciona los documentos físicos para confirmar que los datos introducidos son correctos — no escribe en nombre del usuario.
3. El Protocolo calcula el nullifier basado en documentos de forma local en el dispositivo del usuario mediante la fórmula `signet-nullifier-v2` (SHA-256 de: docType, country, docNumber, "signet-nullifier-v2" con longitud prefijada). El nullifier se transmite al verificador; los datos brutos del documento no se transmiten.
4. El verificador genera la prueba de rango de edad mediante Bulletproof y emite dos credenciales simultáneamente: una credencial de Persona Natural (keypair A) y una credencial de Persona (keypair B). Ambas incluyen la prueba de rango de edad y etiquetas de tutor (`["guardian", "<parent_pubkey>"]`). El nombre real del menor se almacena únicamente como una hoja Merkle privada — nunca se publica en la cadena.
5. El árbol Merkle para la credencial de Persona Natural del menor contiene: fecha de nacimiento (para la prueba de rango de edad), relación con el tutor, tipo de documento, número de documento y fecha de vencimiento del documento. El nombre del menor se incluye como una hoja Merkle privada y **no** se publica en ningún relay. La nacionalidad puede incluirse por cumplimiento jurisdiccional.
6. El nullifier basado en documentos (hash del tipo de documento, país y número mediante `signet-nullifier-v2`) se incluye únicamente en la credencial de Persona Natural, impidiendo la creación de identidades duplicadas.
7. **Protección biométrica de la cuenta:** En el dispositivo del menor, la aplicación My Signet utiliza el desbloqueo biométrico WebAuthn (reconocimiento facial o huella dactilar) para proteger el acceso a la cuenta del menor. Los datos biométricos nunca salen del dispositivo — son gestionados íntegramente por el enclave seguro del dispositivo mediante el estándar WebAuthn. No se transmiten plantillas biométricas a ningún servidor ni se almacenan fuera del dispositivo.

### 5.4 Los Docentes como Canal Principal de Verificación Infantil

Los docentes y administradores escolares son un canal reconocido para la verificación de Nivel 4 de menores. Los registros de matrícula escolar —que establecen la relación entre padre e hijo y proporcionan evidencia de la fecha de nacimiento— se aceptan como documentación de respaldo junto con el documento de identidad de los padres.

Un docente que sea un profesional autorizado (por ejemplo, un maestro titulado en una jurisdicción que trate la enseñanza como una profesión regulada, o un notario afiliado a un centro escolar) puede realizar la verificación de Nivel 4 utilizando:
- El documento de identidad del padre/tutor emitido por el gobierno
- El registro de matrícula escolar como evidencia del menor (además de o en lugar de un certificado de nacimiento o pasaporte)

Esta vía es especialmente importante para las comunidades de educación en casa y las regiones donde el acceso a abogados o notarios es limitado. El organismo profesional del educador y su institución empleadora son los anclas de confianza. La atestación fraudulenta por parte de un docente constituye mala conducta profesional conforme a la legislación educativa aplicable.

### 5.5 Verificación de Edad Basada en SDK para Sitios Web

El SDK de Signet permite que los sitios web y las aplicaciones verifiquen el rango de edad de un menor sin recibir ninguna información de identificación personal. El flujo de datos es:

```
Sitio web → SDK → Aplicación My Signet → Prueba ZK de rango de edad → Sitio web
```

El sitio web solicita prueba de una afirmación de edad específica (por ejemplo, "el usuario es menor de 18" o "el usuario tiene entre 13 y 17 años"). El SDK de Signet redirige esta solicitud a la aplicación My Signet en el dispositivo del usuario. La aplicación genera la prueba localmente y devuelve únicamente la prueba criptográfica — sin nombre, sin fecha de nacimiento, sin datos del documento, sin nullifier. El sitio web verifica la prueba matemáticamente y conoce únicamente la afirmación del rango de edad.

Esto significa que los sitios web pueden cumplir con los requisitos de verificación de edad (COPPA, Ley de Seguridad en Línea del Reino Unido, regulaciones australianas para menores de 16) sin recopilar ni almacenar ningún dato personal sobre los menores.

---

## 6. Mecanismos de Consentimiento Parental

### 6.1 Requisitos de Consentimiento por Jurisdicción

| Jurisdicción | Edad de Consentimiento Digital | Mecanismo de Consentimiento Requerido |
|-------------|-------------------------------|--------------------------------------|
| Estados Unidos (COPPA) | 13 | Consentimiento parental verificable (por ejemplo, formulario firmado, verificación de tarjeta de crédito, videoconferencia, verificación de documento de identidad) |
| UE (por defecto del RGPD) | 16 | Esfuerzos razonables para verificar el consentimiento parental |
| UE (mínimo del Estado miembro) | 13 | Según la implementación del Estado miembro |
| Reino Unido | 13 | Verificación apropiada para la edad del consentimiento parental |
| Australia | Sin edad digital específica | Medidas razonables basadas en la madurez y el riesgo |
| Corea del Sur | 14 | Consentimiento del representante legal |
| Brasil | 12 (con consentimiento parental hasta 18) | Consentimiento específico y prominente del padre/tutor |
| India | 18 | Consentimiento verificable del padre/tutor |
| China | 14 | Consentimiento por separado del padre/tutor |
| Japón | 15 (directriz) | Participación parental recomendada |

### 6.2 Mecanismos de Consentimiento del Protocolo

El Protocolo admite los siguientes mecanismos de consentimiento parental:

1. **Credencial Verificada de Nivel 3/4 del Padre:**
   El padre/tutor obtiene una credencial de Nivel 3 o Nivel 4 verificando su propia identidad mediante la ceremonia de doble credencial (Persona Natural + Persona). A continuación, firma criptográficamente un evento de consentimiento que autoriza la credencial del menor. Esto crea una cadena verificable:
   - Identidad del padre verificada por verificador profesional (ceremonia de doble credencial)
   - Consentimiento del padre firmado criptográficamente con su clave Nostr
   - Credencial del menor vinculada al padre mediante etiquetas de tutor inmutables en ambas credenciales (Persona Natural y Persona)
   - Los eventos de delegación de tutor (kind 31000) permiten al padre delegar permisos específicos a otros adultos de confianza

2. **Co-Verificación:**
   El padre/tutor y el menor asisten juntos a una sesión de verificación de Nivel 4. El verificador profesional:
   - Verifica la identidad tanto del padre/tutor como del menor
   - Confirma la relación padre-hijo o tutor-menor
   - Registra el consentimiento del padre/tutor como parte del evento de verificación

3. **Consentimiento Delegado:**
   Para las jurisdicciones que requieren mecanismos específicos de consentimiento (por ejemplo, el consentimiento parental verificable de COPPA), pueden requerirse pasos de verificación adicionales:
   - Formulario de consentimiento firmado (digital o físico)
   - Sesión de verificación por video
   - Verificación del documento de identidad emitido por el gobierno del padre/tutor que da el consentimiento

### 6.3 Retirada del Consentimiento

Los padres/tutores pueden retirar el consentimiento en cualquier momento mediante:
1. La publicación de un evento de revocación (kind 31000) desde la clave Nostr del padre/tutor, revocando el evento de consentimiento.
2. El contacto con el equipo de soporte del Protocolo Signet para solicitar asistencia en la revocación.
3. A través de cualquier cliente Nostr que implemente las funciones de gestión de consentimiento del Protocolo.

Tras la retirada del consentimiento:
- La credencial del menor queda revocada de inmediato.
- Las partes confiantes son notificadas mediante el evento de revocación.
- Todos los datos conservados de forma centralizada relacionados con el menor serán eliminados en un plazo de 30 días, salvo cuando la retención sea requerida por ley.

---

## 7. Minimización de Datos para Menores

### 7.1 Principio

El Protocolo aplica los principios más estrictos de minimización de datos para los datos de menores. No se recopilan ni procesan más datos que los estrictamente necesarios para la verificación de credenciales.

### 7.2 Qué se Recopila

| Dato | Recopilado | Justificación |
|------|-----------|---------------|
| Clave pública Nostr del menor | Sí | Necesario para la vinculación de credenciales |
| Prueba de rango de edad (prueba ZK) | Sí | Necesario para la verificación de edad |
| Registro de consentimiento parental | Sí | Necesario para el cumplimiento legal |
| Metadatos de la credencial (nivel, fechas) | Sí | Necesario para la funcionalidad de credenciales |
| Nombre del menor | **No (no en cadena)** | Almacenado únicamente como hoja Merkle privada; nunca publicado |
| Fecha de nacimiento del menor | **No (no en cadena)** | Reemplazado por prueba ZK de rango de edad; almacenado únicamente como hoja Merkle privada |
| Fotografía del menor | **No** | No requerido |
| Número de documento de identidad del menor | **No (no en cadena)** | Almacenado únicamente como hoja Merkle privada para divulgación selectiva; no retenido por el verificador tras la ceremonia |
| Hash del nullifier (`signet-nullifier-v2`) | Sí (solo credencial NP) | Necesario para la prevención de duplicados; no se puede invertir para obtener los datos del documento |
| Clave(s) pública(s) del tutor | Sí (ambas credenciales) | Necesario para el vínculo tutor-menor |
| Relación de tutela | Sí (hoja Merkle privada, credencial NP) | Establece la base jurídica del vínculo de tutela |
| Raíz Merkle | Sí (solo credencial NP) | Se compromete con los atributos verificados sin publicarlos |
| Etiqueta de tipo de entidad | Sí (ambas credenciales) | Necesario para distinguir la Persona Natural de la Persona |
| Ubicación del menor | **No** | No requerido |
| Centro escolar o institución del menor | **No (no en cadena)** | Puede ser referenciado como evidencia de respaldo pero no publicado |
| Datos conductuales | **No** | Prohibido |
| Seguimiento de uso | **No** | Prohibido para menores |
| Datos biométricos | **No** | Solo en el dispositivo local mediante WebAuthn; no se transmiten plantillas |

### 7.3 Atributos del Árbol Merkle para Menores

La credencial de Persona Natural de un menor se compromete con un árbol Merkle con las siguientes hojas:

| Hoja | Propósito | ¿Divulgado en cadena? |
|------|-----------|----------------------|
| `dateOfBirth:<fecha ISO>` | Fuente para la prueba ZK de rango de edad | No — privado |
| `guardianRelationship:<tipo>` | Base jurídica (p. ej., "padre", "tutor_legal") | No — privado |
| `documentType:<tipo>` | Tipo de evidencia presentada | No — privado |
| `documentNumber:<número>` | Para divulgación selectiva si es requerido | No — privado |
| `documentExpiry:<fecha>` | Verificación de validez del documento | No — privado |
| `name:<nombre>` | Para divulgación selectiva si es requerido | No — privado |
| `nationality:<código>` | Cumplimiento jurisdiccional | No — privado |
| `nullifier:<hash>` | Prevención de duplicados | Sí (como etiqueta de nivel superior) |

Solo la raíz Merkle y el hash del nullifier aparecen en cadena. Las hojas individuales se revelan únicamente cuando el tutor del menor ejerce explícitamente la divulgación selectiva (por ejemplo, para demostrar la nacionalidad del menor ante una autoridad regulatoria).

### 7.4 Signet IQ para Menores

Los menores tienen puntuaciones Signet IQ calculadas a partir de:
- La propia credencial de Nivel 4 (contribución principal)
- El nivel de verificación y el Signet IQ propios del tutor (contribución ponderada, que refleja la solidez de la relación de tutela)
- Avales de otras cuentas de Nivel 2 o superior que conocen a la familia

El Signet IQ de un menor se muestra a las partes confiantes como una señal de confianza agregada. No revela la identidad del tutor, el nombre del menor ni ningún otro atributo personal — se calcula únicamente a partir de eventos de credenciales públicos. Está prohibido el uso de la puntuación social de menores basada en su Signet IQ para propósitos distintos de la verificación de edad y el control de acceso (véase la Sección 8).

### 7.5 Límites de Retención

Los datos de menores están sujetos a los períodos de retención más cortos permitidos:
- Credenciales activas: Hasta su vencimiento, revocación o que el menor alcance la mayoría de edad (lo que ocurra primero)
- Registros de consentimiento: Duración de la validez de la credencial más cualquier período de retención legalmente requerido
- Registros de verificación: Según lo requieran las obligaciones profesionales del verificador (normalmente 1–3 años)
- Datos de desafío/respuesta: Eliminados inmediatamente después de la verificación

---

## 8. Usos Prohibidos

### 8.1 Prohibiciones Absolutas

Los siguientes usos del Protocolo en relación con los menores están **estrictamente prohibidos**:

1. **Elaboración de perfiles:** Utilizar el Protocolo para elaborar perfiles de menores con cualquier fin, incluidos el marketing, la publicidad o el análisis conductual.
2. **Seguimiento:** Utilizar credenciales o datos de verificación para rastrear las actividades en línea o fuera de línea de los menores.
3. **Publicidad dirigida:** Utilizar pruebas de rango de edad o datos de credenciales para dirigir publicidad a menores.
4. **Monetización de datos:** Vender, licenciar o monetizar de cualquier otra forma los datos de credenciales de menores o los datos de verificación de edad.
5. **Toma de decisiones automatizada:** Utilizar los datos de credenciales de menores para decisiones automatizadas que produzcan efectos legales o igualmente significativos.
6. **Vigilancia:** Utilizar el Protocolo para la vigilancia continua de las actividades de los menores.
7. **Puntuación social:** Utilizar datos de credenciales o de Signet IQ para crear sistemas de puntuación social para menores más allá del control de acceso apropiado para la edad.
8. **Manipulación:** Utilizar patrones de diseño que exploten las vulnerabilidades de los menores o manipulen su comportamiento.
9. **Recopilación innecesaria de datos:** Recopilar más datos de menores que los estrictamente necesarios para la verificación de credenciales.
10. **Compartir sin consentimiento:** Compartir datos de menores con terceros sin consentimiento parental verificable.

### 8.2 Restricciones para las Partes Confiantes

Las partes confiantes que reciban pruebas de rango de edad o verificaciones de credenciales de menores:
- No deben utilizar los datos más allá del propósito específico para el que se solicitó la verificación
- No deben retener los datos de verificación más allá de la necesidad inmediata
- Deben implementar sus propias medidas de seguridad infantil apropiadas para su servicio
- Deben cumplir con todas las leyes de protección infantil aplicables en su jurisdicción

---

## 9. Notificación y Respuesta ante Incidentes

### 9.1 Tipos de Incidentes Notificables

Los siguientes incidentes que involucren a menores deben notificarse:

| Tipo de Incidente | Umbral de Notificación | Prioridad |
|------------------|----------------------|-----------|
| Violación de datos de credenciales de un menor | Cualquier acceso no autorizado | Crítico — Inmediato |
| Credencial de Nivel 4 fraudulenta para un menor | Descubrimiento de cualquier instancia | Crítico — Inmediato |
| Compromiso del mecanismo de consentimiento parental | Cualquier indicación de compromiso | Crítico — Inmediato |
| Explotación de la verificación de edad | Descubrimiento de cualquier elusión | Alto — En 4 horas |
| Uso indebido de la credencial de un menor por parte de una parte confiante | Cualquier uso indebido reportado | Alto — En 4 horas |
| Presunta explotación infantil facilitada por el Protocolo | Cualquier indicación | Crítico — Inmediato + Fuerzas del orden |
| Desanonimización de la identidad de un menor | Cualquier instancia | Crítico — Inmediato |

### 9.2 Procedimientos de Notificación

**Notificación Interna:**
- Todos los incidentes se notifican de inmediato al Responsable de Seguridad Infantil designado.
- El Responsable de Seguridad Infantil escala al DPO y a la alta dirección.

**Notificación Regulatoria:**
- Las autoridades de supervisión pertinentes son notificadas dentro de los plazos requeridos por la legislación aplicable (por ejemplo, 72 horas según el RGPD).
- Se siguen los requisitos de notificación específicos de cada país (véase la Sección 10).

**Notificación a las Fuerzas del Orden:**
- Los incidentes que involucren presunta explotación infantil se notifican inmediatamente a:
  - Las fuerzas del orden locales
  - El Centro Nacional para Menores Desaparecidos y Explotados (NCMEC) (EE. UU.)
  - La Internet Watch Foundation (IWF) (Reino Unido)
  - Organismos equivalentes en la jurisdicción pertinente

**Notificación Parental:**
- Los padres/tutores son notificados sin demora injustificada de cualquier incidente que afecte a los datos o la credencial de su hijo.
- La notificación incluye una descripción del incidente, su impacto potencial y las medidas que se están adoptando.

### 9.3 Subsanación

Tras un incidente de seguridad infantil:
1. Contención inmediata del incidente
2. Revocación de las credenciales afectadas
3. Investigación forense
4. Análisis de causas raíz
5. Implementación de medidas preventivas
6. Notificación de seguimiento a las partes afectadas
7. Revisión posterior al incidente y actualización de la Política si fuera necesario

---

## 10. Requisitos Específicos por Jurisdicción

### 10.1 Reino Unido

**Código de Diseño Apropiado para la Edad (AADC) — 15 Estándares:**

| Estándar | Implementación |
|----------|---------------|
| Interés superior del menor | Evaluaciones de impacto en la seguridad infantil para todas las funciones del Protocolo que afecten a menores |
| Evaluaciones de impacto de protección de datos | DPIA realizada para el Nivel 4 y todo tratamiento relacionado con menores |
| Aplicación apropiada para la edad | Interfaces del Protocolo diseñadas para diferentes grupos de edad |
| Transparencia | Información de privacidad proporcionada en un lenguaje apropiado para la edad |
| Uso perjudicial de los datos | Prohibición de usar datos de menores de maneras perjudiciales para su bienestar |
| Políticas y estándares comunitarios | Estándares claros sobre cómo pueden usarse las credenciales de menores |
| Configuración predeterminada | Configuraciones predeterminadas que protegen la privacidad para todas las credenciales de menores |
| Minimización de datos | Minimización más estricta aplicada (véase la Sección 7) |
| Compartir datos | Los datos de menores no se comparten más allá de la necesidad verificada |
| Geolocalización | No se recopilan ni procesan datos de geolocalización de menores |
| Controles parentales | Mecanismos de consentimiento y supervisión descritos en la Sección 6 |
| Elaboración de perfiles | Prohibida para menores (véase la Sección 8) |
| Técnicas de manipulación | Prohibidas para menores (véase la Sección 8) |
| Juguetes y dispositivos conectados | No aplicable al Protocolo, pero se asesora a las partes confiantes |
| Herramientas en línea | Herramientas del Protocolo diseñadas con la seguridad infantil en mente |

**Notificación:** A la Oficina del Comisionado de Información (ICO) en un plazo de 72 horas.

### 10.2 Estados Unidos

**Cumplimiento de COPPA:**
- Consentimiento parental verificable obtenido antes de recopilar cualquier información de menores de 13 años
- Aviso de privacidad en línea claro y completo que describe las prácticas de datos de menores
- Acceso parental para revisar y eliminar los datos del menor
- Sin condicionamiento de la participación del menor a la divulgación innecesaria de información
- Medidas de seguridad razonables para los datos de menores

**Posición de la FTC en marzo de 2026:** La FTC no tomará medidas coercitivas cuando los datos personales se recopilen únicamente con fines de verificación de edad, siempre que los datos sean eliminados de forma sólida y se dé aviso claro. Signet supera este requisito: no se recopilan, almacenan ni transmiten datos personales durante la verificación de edad — la prueba ZKP contiene cero IIP.

**Leyes Estatales:**
- Ley de Privacidad del Consumidor de California (CCPA) — consentimiento de inclusión requerido para la venta de datos de consumidores menores de 16 años
- Ley del Código de Diseño Apropiado para la Edad de California (AB 2273) — evaluaciones de impacto en la protección de datos para servicios a los que probablemente accedan menores
- Otras leyes estatales aplicables

**Notificación:** A la FTC y los fiscales generales estatales aplicables.

### 10.3 Unión Europea

**Cumplimiento del Artículo 8 del RGPD:**
- Consentimiento parental requerido por debajo de la edad de consentimiento digital (13–16, según el Estado miembro)
- Esfuerzos razonables para verificar el consentimiento otorgado por el titular de la responsabilidad parental
- Ofrecido directamente a un menor: aviso de privacidad en lenguaje claro y sencillo adecuado para el menor

**Variaciones por Estado Miembro:**

| País | Edad de Consentimiento Digital |
|------|---------------------------------|
| Austria | 14 |
| Bélgica | 13 |
| Croacia | 16 |
| República Checa | 15 |
| Dinamarca | 13 |
| Estonia | 13 |
| Finlandia | 13 |
| Francia | 15 |
| Alemania | 16 |
| Grecia | 15 |
| Hungría | 16 |
| Irlanda | 16 |
| Italia | 14 |
| Letonia | 13 |
| Lituania | 14 |
| Luxemburgo | 16 |
| Malta | 13 |
| Países Bajos | 16 |
| Polonia | 16 |
| Portugal | 13 |
| Rumanía | 16 |
| Eslovaquia | 16 |
| Eslovenia | 16 |
| España | 14 |
| Suecia | 13 |

**Notificación:** A la autoridad de supervisión principal en un plazo de 72 horas.

### 10.4 Australia

**Ley de Privacidad de 1988 + Ley de Seguridad en Línea de 2021:**
- Medidas razonables para garantizar la capacidad del menor para consentir
- Información de privacidad apropiada para la edad
- Cumplimiento de la Determinación de Seguridad en Línea (Expectativas Básicas de Seguridad en Línea) de 2022

**Notificación:** A la Oficina del Comisionado de Información de Australia (OAIC) y al Comisionado de eSafety.

### 10.5 Corea del Sur

**PIPA + Ley de Promoción de la Utilización de Redes de Información y Comunicaciones:**
- Consentimiento del representante legal requerido para menores de 14 años
- Solo información mínima necesaria
- Sin recopilación sin consentimiento del representante legal

**Notificación:** A la Comisión de Protección de Información Personal (PIPC).

### 10.6 Brasil

**LGPD Artículo 14:**
- Interés superior del menor
- Consentimiento parental específico y prominente para menores de 12 años
- Menores de 12 a 17 años: doble consentimiento (menor + padre)
- Prácticas de información comunicadas de manera simple, clara y accesible apropiada para el menor

**Notificación:** A la ANPD (Autoridade Nacional de Proteção de Dados).

### 10.7 India

**Ley DPDP de 2023:**
- Consentimiento verificable del padre/tutor para todos los menores (menores de 18 años)
- Prohibición de seguimiento, monitoreo conductual y publicidad dirigida a menores
- Obligaciones del fiduciario de datos respecto a los datos de menores

**Notificación:** A la Junta de Protección de Datos de India.

---

## 11. Principios de Diseño para la Seguridad Infantil

### 11.1 Privacidad por Diseño

Todas las funciones del Protocolo que afectan a menores incorporan:
- Minimización de datos a nivel arquitectónico
- Pruebas de conocimiento cero para evitar la exposición de datos personales
- Protecciones criptográficas integradas en la estructura de credenciales
- Configuraciones predeterminadas de alta privacidad
- Flujo de ceremonia de usuario-introduce-verificador-confirma — los datos del documento son introducidos por el usuario en su propio dispositivo; el verificador confirma la exactitud pero nunca posee los datos brutos del documento

### 11.2 Seguridad por Diseño

Las interfaces e implementaciones del Protocolo deben:
- Distinguir claramente entre los flujos de trabajo de credenciales para menores y para adultos
- Prevenir la exposición accidental de la información de identidad de los menores
- Incluir salvaguardas contra el uso indebido de credenciales
- Proporcionar orientación clara y apropiada para la edad
- Utilizar el desbloqueo biométrico del dispositivo (WebAuthn) para proteger las cuentas de menores en el dispositivo

### 11.3 Revisión Periódica

Esta Política y todas las medidas de seguridad infantil son revisadas:
- Al menos anualmente
- Ante cualquier cambio en la legislación aplicable
- Tras cualquier incidente de seguridad infantil
- Ante cambios significativos en el Protocolo

### 11.4 Modelo de Delegación de Tutela

El Protocolo implementa un modelo de estructura familiar de tres capas:

**Capa 1 — Nivel de credencial (inmutable):**
Las etiquetas de tutor (`["guardian", "<parent_pubkey>"]`) son establecidas por el verificador profesional y reflejan la responsabilidad parental legal. Solo pueden modificarse mediante una nueva credencial emitida por un profesional con la documentación legal apropiada (por ejemplo, una orden judicial).

**Capa 2 — Nivel de delegación (flexible):**
Los tutores pueden delegar permisos específicos a adultos de confianza (padrastros, abuelos, profesores) mediante eventos de delegación de tutor kind 31000. Las delegaciones son:
- Limitadas en el tiempo (con fecha de vencimiento)
- Limitadas en alcance: `full` (completo), `activity-approval` (aprobación de actividad), `content-management` (gestión de contenido), `contact-approval` (aprobación de contacto)
- Revocables por el tutor en cualquier momento
- Firmadas por la clave Nostr del tutor
- Etiquetadas con `["agent-type", "guardian"]` para distinguirlas de otros tipos de eventos de delegación

**Capa 3 — Nivel de cliente (específico de la aplicación):**
Las aplicaciones aplican los permisos basados en los datos de las Capas 1 y 2, incluidos límites de tiempo de pantalla, filtrado de contenido, flujos de trabajo de aprobación de actividades y restricciones de contactos.

---

## 12. Formación y Concienciación

### 12.1 Formación de Verificadores

Todos los verificadores profesionales autorizados para realizar verificaciones de Nivel 4 (menores) deben:
- Completar la formación en seguridad infantil antes de realizar verificaciones de menores
- Conocer las leyes de protección infantil en su jurisdicción
- Estar al tanto de los indicadores de salvaguarda y las obligaciones de notificación
- Comprender el flujo de ceremonia de usuario-introduce-verificador-confirma y no intentar introducir datos en nombre de los usuarios
- Actualizar la formación anualmente

### 12.2 Formación del Personal

Todo el personal involucrado en el desarrollo, las operaciones o el soporte del Protocolo debe:
- Completar la formación de concienciación en seguridad infantil
- Conocer esta Política y sus obligaciones en virtud de ella
- Saber cómo reportar preocupaciones de seguridad infantil

---

## 13. Responsabilidad

### 13.1 Responsable de Seguridad Infantil Designado

El Protocolo Signet designa un Responsable de Seguridad Infantil responsable de:
- Supervisar la implementación de esta Política
- Coordinarse con el DPO en materia de protección de datos de menores
- Gestionar la respuesta a incidentes de seguridad infantil
- Relacionarse con los reguladores y organizaciones de seguridad infantil

### 13.2 Conservación de Registros

El Protocolo Signet mantiene registros de:
- Evaluaciones de impacto en la seguridad infantil
- Registros de consentimiento parental
- Incidentes de seguridad infantil y respuestas
- Registros de formación
- Revisiones y actualizaciones de la Política

### 13.3 Supervisión Externa

El Protocolo Signet está comprometido con la transparencia y acepta la supervisión de:
- Las autoridades regulatorias pertinentes
- Las organizaciones de seguridad infantil
- Auditores independientes
- La comunidad de código abierto

---

## 14. Contacto

Para consultas, preocupaciones o informes relacionados con la seguridad infantil:

**Responsable de Seguridad Infantil:** signet-safety@signetprotocol.org *(provisional — actualizar antes de la implementación)*
**Delegado de Protección de Datos:** signet-dpo@signetprotocol.org *(provisional — actualizar antes de la implementación)*

**Notificación de Emergencia (presunta explotación infantil):**
- Reino Unido: Internet Watch Foundation — [https://www.iwf.org.uk](https://www.iwf.org.uk)
- EE. UU.: NCMEC CyberTipline — [https://www.missingkids.org](https://www.missingkids.org)
- UE: INHOPE — [https://www.inhope.org](https://www.inhope.org)
- Australia: eSafety Commissioner — [https://www.esafety.gov.au](https://www.esafety.gov.au)

---

*Esta Política de Seguridad Infantil se proporciona como plantilla para el Protocolo Signet. No constituye asesoramiento jurídico. El Protocolo Signet recomienda buscar asesoramiento jurídico cualificado familiarizado con las leyes de protección infantil aplicables en su jurisdicción antes de la implementación.*

*El Protocolo Signet — v0.1.0*
*Versión del documento: 1.0*
*Marzo de 2026*
