---
**Aviso de Tradução Gerada por IA**

Este documento foi traduzido do inglês utilizando IA (Claude, Anthropic). É fornecido apenas para referência. A versão em inglês em `en.md` é o único documento juridicamente vinculante. Esta tradução não foi revista por um tradutor jurídico qualificado. Em caso de discrepância entre esta tradução e o original em inglês, prevalece a versão em inglês.

---

# Política de Privacidade

**Signet Protocol — v0.1.0**

**Data de Vigência:** Março de 2026
**Última Atualização:** Março de 2026

---

## 1. Introdução

Esta Política de Privacidade descreve como o Signet Protocol ("Signet", "nós", "nos" ou "nosso") coleta, usa, divulga e protege informações em conexão com o Signet Protocol (o "Protocolo") e o aplicativo My Signet (o "Aplicativo"). O Signet é um protocolo de verificação de identidade descentralizado e de código aberto para a rede Nostr, que utiliza provas de conhecimento zero, assinaturas em anel e credenciais criptográficas.

O Signet foi projetado com a privacidade como princípio central. Ele permite que os usuários comprovem afirmações sobre sua identidade — como faixa etária, situação profissional ou jurisdição geográfica — sem revelar os dados pessoais subjacentes. Esta Política de Privacidade explica quais interações limitadas de dados ocorrem, onde os dados permanecem e como são tratados.

Esta Política aplica-se a todos os usuários, verificadores, partes confiantes e demais participantes que interagem com o Signet Protocol ou com o aplicativo My Signet, independentemente de sua localização.

A descrição canônica do protocolo está em `spec/protocol.md` no repositório de código aberto do Signet.

---

## 2. Controlador de Dados

**Controlador de Dados:** The Signet Protocol
**E-mail de Contato:** privacy@signet.id
**Encarregado de Proteção de Dados (DPO):** dpo@signet.id

Para jurisdições que exigem um representante local, entre em contato com o DPO no endereço acima. Os nomeamentos formais de representantes para fins da UE (RGPD Art. 27) e do Reino Unido (UK GDPR Art. 27) serão publicados em signet.id/legal.

---

## 3. Dados que Coletamos e Processamos

O Signet Protocol foi arquitetado para minimizar a coleta de dados. Como o Protocolo utiliza provas de conhecimento zero, assinaturas em anel e verificação descentralizada de credenciais, a grande maioria das informações permanece exclusivamente sob o controle do usuário e nunca é transmitida ao Signet nem acessível por ele.

### 3.1 Categorias de Dados

| Categoria | Descrição | Origem | Local de Armazenamento |
|----------|-------------|--------|-----------------|
| **Chaves Públicas Nostr** | Chaves públicas secp256k1 (npub) usadas para interações com o Protocolo | Geradas pelo usuário | Relays Nostr (descentralizados) |
| **Metadados de Credenciais** | Tipos de eventos Nostr 31000–31000 contendo nível de verificação, carimbos de tempo de emissão, datas de vencimento, faixa etária e identificadores de tipo de entidade | Gerados durante a emissão de credenciais | Relays Nostr (descentralizados) |
| **Provas de Conhecimento Zero** | Bulletproofs para verificação de faixa etária | Geradas localmente pelo usuário | Incorporadas em eventos de credenciais nos relays Nostr |
| **Assinaturas em Anel** | Assinaturas criptográficas que provam participação em um grupo sem revelar qual membro assinou | Geradas localmente pelo usuário | Relays Nostr (descentralizados) |
| **Hashes Nulificadores** | Hash SHA-256 de tipo de documento com prefixo de comprimento, código de país, número do documento e etiqueta de domínio "signet-nullifier-v2" — impede a criação de identidade duplicada; não pode ser revertido para recuperar detalhes do documento | Calculados localmente durante a cerimônia das duas credenciais | Incorporados em eventos de credenciais de Pessoa Natural |
| **Raízes Merkle** | Comprometimento de hash com atributos verificados, permitindo divulgação seletiva. As folhas incluem nome, nacionalidade, tipoDeDocumento, dataDeNascimento, númeroDo Documento, vencimentoDoDocumento, hashDeFoto e nulificador. Apenas o hash raiz é publicado — os valores individuais das folhas nunca são publicados | Calculados localmente durante a cerimônia das duas credenciais | Incorporados em eventos de credenciais de Pessoa Natural |
| **Registros de Atestação** | Eventos de tipo 31000 representando endossos de teia de confiança | Criados pelas partes atestantes | Relays Nostr (descentralizados) |
| **Eventos de Política** | Eventos de tipo 30078 especificando requisitos de partes confiantes | Criados pelas partes confiantes | Relays Nostr (descentralizados) |
| **Registro de Verificadores** | Eventos de tipo 31000 identificando verificadores profissionais, incluindo a chave pública de assinatura profissional e informações jurisdicionais | Criados pelos verificadores | Relays Nostr (descentralizados) |
| **Dados de Desafio/Resposta** | Eventos de tipo 31000 para desafios de legitimidade de verificadores | Gerados durante a verificação | Relays Nostr (descentralizados) |
| **Registros de Revogação** | Eventos de tipo 31000 para revogação de credenciais | Criados quando credenciais são revogadas | Relays Nostr (descentralizados) |
| **Eventos de Ponte de Identidade** | Eventos de tipo 31000 vinculando pares de chaves de Pessoa Natural e Persona via assinaturas em anel | Criados pelo usuário | Relays Nostr (descentralizados) |
| **Eventos de Delegação** | Eventos de tipo 31000 para delegação de agente ou guardião com permissões delimitadas | Criados pelo delegante | Relays Nostr (descentralizados) |
| **Material de Chave Criptografado** | Chaves privadas criptografadas com AES-256-GCM (chave derivada via PBKDF2, 600.000 iterações, SHA-256) | Armazenados localmente no dispositivo | Apenas no armazenamento local do dispositivo — nunca transmitidos |

### 3.2 O que Permanece no seu Dispositivo

As seguintes informações são processadas no seu dispositivo e nunca transmitidas ao Signet nem armazenadas por ele:

- **Chaves privadas e frase mnemônica** — Sua mnemônica de 12 palavras BIP-39 e as chaves privadas dela derivadas (ambos os pares de chaves de Pessoa Natural e Persona, derivados via derivação HD BIP-32 nos caminhos NIP-06) permanecem no seu dispositivo em todos os momentos, criptografadas em repouso.
- **Detalhes do documento inseridos durante a cerimônia** — Seu número de documento, data de vencimento do documento, data de nascimento, nome, nacionalidade e qualquer fotografia que você apresente. Estes são inseridos por você no aplicativo, utilizados para calcular a árvore Merkle e o nulificador, e então descartados. Os valores individuais das folhas são retidos por você em seu registro de credenciais local para divulgação seletiva futura. Eles não são transmitidos ao Signet e não são enviados ao verificador eletronicamente — o verificador inspeciona seus documentos físicos em pessoa e confirma os dados que você inseriu.
- **Valores das folhas Merkle** — Os valores individuais de atributos (nome, data de nascimento, número do documento, vencimento do documento, hash da foto, nacionalidade, tipo de documento, nulificador) são armazenados como folhas Merkle no seu registro de credenciais local, permitindo que você comprove atributos individuais via provas de divulgação seletiva. Apenas o hash raiz Merkle é publicado na cadeia.
- **Dados biométricos** — Veja a Seção 3.3.
- **Datas de nascimento exatas** — Provas de faixa etária revelam apenas que você se enquadra em um intervalo (p. ex., "18+"), não sua data de nascimento exata.

### 3.3 Autenticação Biométrica (Dados de Categoria Especial)

O aplicativo My Signet suporta autenticação biométrica via **API WebAuthn com a extensão PRF (Função Pseudo-Aleatória)**, com PIN como alternativa de contingência.

**Como funciona:**
- Quando você registra a biometria, o autenticador de plataforma do seu dispositivo (sensor de impressão digital, Face ID ou equivalente) cria uma credencial WebAuthn. A credencial permanece no enclave seguro ou TPM do seu dispositivo.
- A extensão PRF do WebAuthn deriva material de chave criptográfica a partir da sua asserção biométrica. Este material de chave é usado para descriptografar suas chaves privadas criptografadas durante uma sessão autenticada.
- **Nenhum modelo biométrico é jamais transmitido ao Signet.** Nenhum dado biométrico sai do seu dispositivo. O Signet nunca recebe, armazena ou processa nenhuma informação biométrica.
- O ID da credencial WebAuthn é armazenado no armazenamento local do seu dispositivo para identificar qual credencial deve ser usada durante a autenticação. Este é um identificador aleatório, não um modelo biométrico.

Nos termos do Artigo 9 do RGPD e do UK GDPR, dados biométricos utilizados para identificar de forma única uma pessoa natural constituem dados de categoria especial. Uma vez que o processamento biométrico ocorre inteiramente no seu dispositivo local usando o hardware seguro integrado da plataforma, e nenhum dado biométrico é transmitido aos ou processado pelos sistemas do Signet, o Signet não atua como controlador ou processador de dados biométricos. O processamento está sob seu controle exclusivo.

Se o seu dispositivo não suportar WebAuthn PRF, o aplicativo recorre a um PIN, derivado via PBKDF2-SHA-256 (600.000 iterações) para produzir uma chave de descriptografia AES-256-GCM.

### 3.4 Dados que NÃO Coletamos

Por design, o Signet Protocol **não** coleta, processa ou armazena:

- Nomes reais, endereços ou números de identificação governamentais
- Datas de nascimento exatas (provas de faixa etária revelam apenas um intervalo)
- Números de documentos ou datas de vencimento de documentos (processados localmente para calcular folhas Merkle; valores individuais não são transmitidos ao Signet ou ao verificador eletronicamente)
- Dados biométricos (processados localmente no dispositivo via WebAuthn; nunca transmitidos)
- Informações financeiras ou dados de pagamento
- Dados de localização ou endereços IP (nível do Protocolo; operadores de relay podem independentemente coletar endereços IP)
- Histórico de navegação ou impressões digitais de dispositivo
- Endereços de e-mail (a menos que fornecidos voluntariamente para suporte)
- Fotografias ou imagens (um hash de foto pode ser incluído como folha Merkle, mas a imagem em si permanece no seu dispositivo)
- Os dados subjacentes a qualquer prova de conhecimento zero

### 3.5 Dados Processados por Terceiros

Os operadores de relay Nostr processam independentemente os dados transmitidos através dos seus relays. Suas práticas de dados são regidas por suas próprias políticas de privacidade. O Signet não controla os operadores de relay.

---

## 4. A Cerimônia das Duas Credenciais

Esta seção explica o processo de verificação profissional em detalhes, pois é a interação mais intensiva em dados do Protocolo.

### 4.1 Como a Cerimônia Funciona

1. **Você insere seus próprios dados.** No aplicativo My Signet, você insere seu nome, data de nascimento, nacionalidade, tipo de documento, número do documento, data de vencimento do documento e, opcionalmente, fornece ou fotografa seu documento. O aplicativo calcula a árvore Merkle e o nulificador localmente.

2. **O verificador inspeciona seus documentos físicos.** Um verificador de Nível 3 ou Nível 4 (um profissional licenciado, como um solicitador, notário ou profissional médico) examina seus documentos de identidade físicos em pessoa. O verificador confirma que os dados que você inseriu correspondem aos seus documentos. O verificador não insere independentemente seus dados no sistema.

3. **O verificador assina a credencial.** O verificador assina dois eventos de credenciais: uma credencial de Pessoa Natural (tipo 31000, assinada pelo par de chaves Nostr profissional do verificador) e uma credencial de Persona (anônima, apenas faixa etária, também assinada pelo verificador). Ambas são publicadas nos relays Nostr.

4. **O que é publicado.** Os eventos de credenciais publicados contêm: a chave pública do verificador, sua chave pública Persona (chave pública do sujeito), metadados de credenciais (nível, datas, tipo de entidade, faixa etária), a prova de conhecimento zero de faixa etária, o hash nulificador (um hash unidirecional; não pode ser revertido) e a raiz Merkle (um comprometimento de hash; os valores individuais das folhas não são publicados). Nenhum nome, data de nascimento, número de documento ou outra informação de identificação é publicado.

5. **O que você retém localmente.** Seu registro de credenciais local contém os valores individuais das folhas Merkle (nome, nacionalidade, data de nascimento, tipo de documento, número do documento, vencimento do documento, nulificador e, opcionalmente, hash da foto). Você os usa para gerar provas de divulgação seletiva quando desejar posteriormente comprovar atributos específicos (p. ex., comprovando o número do seu passaporte ao fazer check-in para um voo).

### 4.2 Número do Documento e Vencimento como Folhas Merkle

Ao contrário de versões anteriores do Protocolo, o número do documento e o vencimento do documento **não** são descartados após a cerimônia. Eles são retidos como folhas Merkle no seu registro de credenciais local. Isso permite que você:

- Prove o número do seu passaporte a uma parte confiante que o exija (p. ex., uma companhia aérea) via uma prova de inclusão Merkle, sem revelar outros atributos.
- Suporte a decaimento acelerado do Signet IQ quando o vencimento do seu documento se aproximar, fornecendo às partes confiantes um sinal sobre a atualidade das suas evidências de identidade subjacentes.

Apenas você controla quais atributos divulga e a quem. Os valores individuais das folhas nunca são transmitidos ao Signet nem acessíveis por ele.

### 4.3 Formato do Nulificador

O nulificador é calculado como:

```
SHA-256(len16(docType) || docType || len16(countryCode) || countryCode || len16(docNumber) || docNumber || len16("signet-nullifier-v2") || "signet-nullifier-v2")
```

onde `len16(x)` é o comprimento em bytes UTF-8 de `x` codificado como um uint16 big-endian de 2 bytes. A etiqueta de domínio `signet-nullifier-v2` distingue este esquema de qualquer versão anterior. O hash nulificador permite ao Protocolo detectar registros de identidade duplicados sem revelar qual documento foi usado.

---

## 5. Modelo de Dois Pares de Chaves

Cada usuário do Signet possui dois pares de chaves derivados de uma única mnemônica BIP-39 de 12 palavras:

- **Par de chaves de Pessoa Natural** — derivado via caminho NIP-06 `m/44'/1237'/0'/0/0`. Usado para a credencial de Pessoa Natural (tipo 31000). Este par de chaves está associado à sua identidade real verificada via credencial, mas o próprio par de chaves não carrega vinculação inerente aos seus documentos.
- **Par de chaves de Persona** — derivado via caminho HD BIP-32 em um índice de conta separado. Usado para a credencial de Persona (anônima, apenas faixa etária). Este par de chaves não carrega vínculo direto com sua identidade real. Sua atividade social online utiliza este par de chaves.

**Implicação de privacidade:** Como ambos os pares de chaves derivam da mesma mnemônica, você pode comprovar a vinculação entre eles (via eventos de ponte de identidade de tipo 31000) ou mantê-los completamente separados. Um evento de ponte de identidade, uma vez publicado, cria um vínculo criptográfico público. Você só deve publicar um evento de ponte se desejar associar sua Persona anônima ao seu status de Pessoa Natural verificada.

**Gerenciamento de chaves e direitos do titular de dados:** Suas chaves privadas são derivadas deterministicamente da sua mnemônica. O Signet nunca possui ou transmite suas chaves privadas. Se você excluir o aplicativo e perder sua mnemônica (e qualquer backup Shamir), suas chaves são irrecuperáveis. O Signet não pode auxiliar na recuperação de chaves porque não detém cópias.

---

## 6. O SDK signet-verify.js

O ecossistema My Signet inclui o `signet-verify.js`, um SDK JavaScript que sites incorporam para solicitar verificação de idade ou identidade de seus visitantes.

### 6.1 Como o SDK Funciona

1. Um site incorpora o `signet-verify.js` e chama `Signet.verifyAge('18+')` (ou similar).
2. O SDK abre um modal de verificação no site.
3. O usuário aprova a solicitação no aplicativo My Signet. A prova de credencial é transmitida de volta ao site via um BroadcastChannel (comunicação no mesmo dispositivo; nenhum servidor envolvido).
4. O SDK verifica a assinatura Schnorr no evento de credencial e verifica se a chave pública do verificador está registrada e confirmada.
5. O SDK retorna um resultado ao site.

### 6.2 Quais Dados o Site Recebe

Um site usando o `signet-verify.js` recebe:

| Campo | Descrição |
|-------|-------------|
| `verified` | Booleano: a credencial atende ao requisito declarado? |
| `ageRange` | String de faixa etária (p. ex., "18+") — nunca a data de nascimento exata |
| `tier` | Nível de verificação (1–4) |
| `entityType` | Classificação da conta (Pessoa Natural, Persona, etc.) |
| `credentialId` | ID do evento de credencial (um identificador público de evento Nostr) |
| `verifierPubkey` | A chave pública Nostr do verificador |
| `verifierConfirmed` | Se o verificador foi confirmado em um registro profissional público |
| `issuedAt` / `expiresAt` | Carimbos de tempo de validade da credencial |

**Nenhuma informação de identificação pessoal é transmitida ao site.** O site não recebe seu nome, data de nascimento, número de documento ou quaisquer valores de folhas Merkle. A comunicação via BroadcastChannel é local ao dispositivo — a troca de verificação não passa por nenhum servidor do Signet.

### 6.3 Bot de Verificação

O Signet opera um bot de verificação de código aberto que verifica os registros de verificadores em registros profissionais públicos (p. ex., o registro do Conselho Médico Geral, o rol da Autoridade Reguladora de Solicitadores, os registros da Agência de Regulação do Ensino). O bot publica suas descobertas como eventos Nostr.

A chave pública Nostr profissional do verificador é uma chave de assinatura construída com finalidade específica usada apenas para verificações Signet. Ela não tem identidade social inerente. O bot recebe esta chave pública para consultar registros públicos. A submissão de uma chave pública profissional ao bot para verificação de registro não constitui uma transferência de dados pessoais sob o RGPD, porque a chave pública é um identificador criptográfico pseudônimo construído especificamente para esta função. No entanto, por abundância de cautela, os verificadores consentem com este processo como parte do Acordo de Verificador.

---

## 7. Assinatura Remota NIP-46

O aplicativo My Signet pode atuar como um assinador remoto NIP-46. Neste modo:

- Solicitações de assinatura chegam de um aplicativo cliente Nostr conectado via um relay Nostr.
- O aplicativo exibe cada solicitação de assinatura e pede ao usuário que a aprove ou rejeite.
- A chave privada nunca sai do aplicativo. A assinatura remota não transmite a chave privada ao aplicativo solicitante ou ao relay.
- As assinaturas aprovadas são transmitidas de volta ao aplicativo solicitante via relay.

O operador de relay pode observar que uma solicitação de assinatura e uma resposta ocorreram (como eventos Nostr criptografados), mas não pode ler o conteúdo da solicitação de assinatura ou a chave privada.

---

## 8. Bases Jurídicas para o Processamento

Processamos dados sob as seguintes bases jurídicas, dependendo da sua jurisdição.

### 8.1 União Europeia / Espaço Econômico Europeu (RGPD)

| Finalidade | Base Jurídica | Artigo do RGPD |
|---------|-------------|--------------|
| Operação do Protocolo e verificação de credenciais | Interesse legítimo | Art. 6(1)(f) |
| Cumprimento de obrigações legais | Obrigação legal | Art. 6(1)(c) |
| Emissão de credenciais iniciada pelo usuário | Execução de contrato | Art. 6(1)(b) |
| Segurança infantil e verificação de idade | Interesse legítimo / Obrigação legal | Art. 6(1)(f) / Art. 6(1)(c) |

Nota: Dados biométricos são processados exclusivamente no dispositivo via WebAuthn. O Signet não processa dados biométricos ao abrigo do Artigo 9(1). Caso seja eventualmente estabelecido qualquer processamento biométrico pelo Signet, a base jurídica seria o consentimento explícito nos termos do Art. 9(2)(a).

**eIDAS 2.0:** O Regulamento da Carteira de Identidade Digital da UE (eIDAS 2.0) determina que os estados-membros emitam carteiras de identidade digital aos cidadãos até dezembro de 2026. A arquitetura do Signet foi concebida para ser compatível com credenciais emitidas pelo eIDAS 2.0 via o mecanismo de ponte de identidade de tipo 31000.

### 8.2 Reino Unido (UK GDPR / Lei de Proteção de Dados de 2018)

As mesmas bases jurídicas do RGPD da UE se aplicam, conforme complementado pela Lei de Proteção de Dados de 2018.

**Lei de Segurança Online de 2023:** As capacidades de verificação de idade do Signet suportam o cumprimento dos requisitos de garantia de idade da Lei de Segurança Online de 2023 e das orientações associadas da Ofcom. A arquitetura de conhecimento zero do Signet foi concebida para permitir a verificação de idade sem criar bases de dados centralizadas de verificação de idade.

**Código de Design Adequado para a Idade (AADC / Código das Crianças):** O Signet está comprometido com os 15 padrões do AADC, incluindo avaliação do melhor interesse da criança, minimização de dados, configurações de alta privacidade por padrão para crianças e transparência adequada para a idade.

**ICO como Autoridade Supervisora:** O Gabinete do Comissário de Informação (ICO) é a principal autoridade supervisora do Signet no Reino Unido. Contato: [https://ico.org.uk](https://ico.org.uk).

### 8.3 Estados Unidos

**COPPA (Lei de Proteção à Privacidade Online de Crianças):** O Signet não coleta nenhuma informação pessoal de qualquer usuário, incluindo crianças menores de 13 anos. A arquitetura de conhecimento zero do Protocolo significa que nenhum nome, data de nascimento, endereço, fotografia ou qualquer outra informação pessoal definida pela COPPA é coletada, armazenada ou transmitida pelo Signet. A orientação da FTC de março de 2026 confirma que plataformas que não coletam informações pessoais cobertas estão fora das restrições de coleta da COPPA. A abordagem do Signet de permitir a verificação de idade sem coletar informações pessoais é consistente com a flexibilidade declarada pela FTC para métodos de verificação de idade que preservam a privacidade.

**CCPA / CPRA (Califórnia):** Não vendemos informações pessoais. Não compartilhamos informações pessoais para publicidade comportamental entre contextos. Os residentes da Califórnia têm o direito de saber, excluir, corrigir e recusar. Uma vez que o Signet não coleta informações pessoais no sentido tradicional, a maioria dos direitos da CCPA é satisfeita pela própria arquitetura.

**Leis estaduais de privacidade:** Cumprimos as leis de privacidade estaduais aplicáveis, incluindo as da Virgínia (VCDPA), Colorado (CPA), Connecticut (CTDPA), Utah (UCPA), Texas (TDPSA) e outros estados com legislação de privacidade promulgada.

**Leis estaduais de verificação de idade:** Vários estados dos EUA promulgaram leis exigindo verificação de idade para acesso a determinados serviços online. As provas de faixa etária do Signet foram concebidas para satisfazer esses requisitos sem criar bases de dados centralizadas de datas de nascimento ou documentos de identidade dos usuários.

### 8.4 Brasil (LGPD — Lei Geral de Proteção de Dados)

O processamento é fundamentado em:
- Interesse legítimo (Art. 7, X)
- Cumprimento de obrigação legal ou regulatória (Art. 7, II)
- Execução de contrato ou de procedimentos preliminares (Art. 7, V)

### 8.5 Coreia do Sul (PIPA — Lei de Proteção de Informações Pessoais)

O processamento está em conformidade com os requisitos da PIPA, incluindo coleta limitada ao mínimo necessário, limitação de finalidade específica, notificação das finalidades de processamento e cumprimento dos requisitos de consentimento.

### 8.6 Japão (APPI — Lei sobre a Proteção de Informações Pessoais)

O processamento está em conformidade com a APPI conforme emendada, incluindo especificação da finalidade de utilização, aquisição adequada de informações pessoais e cumprimento dos requisitos de transferência transfronteiriça.

### 8.7 China (PIPL — Lei de Proteção de Informações Pessoais)

Quando o Protocolo é acessado a partir da República Popular da China, o processamento é fundamentado no consentimento individual ou na execução de contrato, os requisitos de localização de dados são respeitados, e as transferências transfronteiriças estão em conformidade com os Arts. 38–43 da PIPL.

### 8.8 Índia (DPDP — Lei de Proteção de Dados Pessoais Digitais)

O processamento está em conformidade com a Lei DPDP, incluindo processamento baseado em consentimento ou usos legítimos, obrigações como fiduciário de dados e direitos dos titulares de dados.

---

## 9. Como Usamos os Dados

Os dados processados através do Signet Protocol são usados exclusivamente para:

1. **Emissão e Verificação de Credenciais** — Permitir que os usuários criem, apresentem e verifiquem credenciais nos quatro níveis de verificação.
2. **Cálculo do Signet IQ** — Calcular pontuações de Signet IQ com base em atestações de teia de confiança, níveis de credenciais, atualidade das credenciais e sinais de vencimento de documentos.
3. **Verificação de Faixa Etária** — Usar Bulletproofs para comprovar que um usuário se enquadra em uma faixa etária sem revelar sua idade exata.
4. **Verificação Profissional** — Permitir que profissionais licenciados (advogados, notários, profissionais médicos) atuem como verificadores.
5. **Revogação de Credenciais** — Processar eventos de revogação quando credenciais são invalidadas.
6. **Integridade do Protocolo** — Manter a integridade criptográfica e a segurança do Protocolo.
7. **Conformidade Legal** — Cumprir as leis e regulamentações aplicáveis.
8. **Cerimônia das Duas Credenciais** — Emitir credenciais pareadas de Pessoa Natural e Persona durante a verificação profissional, incluindo o cálculo de árvores Merkle, nulificadores e provas de faixa etária.
9. **Gerenciamento de Guardiões** — Processar eventos de delegação de guardiões (tipo 31000) para gerenciamento de contas de menores.
10. **Divulgação Seletiva** — Permitir que os usuários comprovem atributos individuais de folhas Merkle (incluindo número do documento e vencimento do documento) às partes confiantes que os exijam, sem revelar atributos não relacionados.
11. **Ciclo de Vida de Credenciais** — Processar cadeias de credenciais (tags supersedes/superseded-by) para mudanças de nome, renovação de documentos e atualizações de nível.

---

## 10. Compartilhamento e Divulgação de Dados

### 10.1 Compartilhamento em Nível de Protocolo

O Signet Protocol opera na rede Nostr, que é descentralizada. Quando você publica um evento de credencial, atestação ou outro evento de Protocolo, ele é transmitido para relays Nostr. Isso é inerente ao design do Protocolo e é iniciado por você.

### 10.2 Com Quem Não Compartilhamos Dados

- Anunciantes ou empresas de marketing
- Corretores de dados
- Plataformas de mídia social (além da publicação em relays Nostr)
- Agências governamentais (exceto conforme exigido por lei ou processo legal válido)

### 10.3 Divulgação Exigida por Lei

Podemos divulgar informações se exigido por uma ordem judicial válida, intimação ou processo legal, lei ou regulamentação aplicável, ou uma solicitação de uma autoridade de aplicação da lei ou regulatória com jurisdição válida. Notificaremos os usuários afetados de tais solicitações onde legalmente permitido. Uma vez que o Signet não detém dados pessoais sobre os usuários em sistemas centralizados, o escopo de qualquer divulgação compulsória é extremamente limitado.

### 10.4 Compartilhamento de Dados do Verificador

Verificadores profissionais (Nível 3 e Nível 4) publicam eventos de registro de verificadores (tipo 31000) na rede Nostr. Esses eventos incluem a chave pública Nostr profissional do verificador e informações jurisdicionais. Os verificadores consentem com essa publicação como parte do Acordo de Verificador.

Os únicos dados compartilhados entre o verificador e o Protocolo via eventos publicados são o evento de credencial (tipo 31000), que contém a chave pública do verificador, a chave pública Persona do sujeito, metadados de credenciais (nível, datas, tipo de entidade, faixa etária), a prova de conhecimento zero de faixa etária, o hash nulificador e a raiz Merkle.

Nenhum dado de identificação pessoal (nome, data de nascimento, números de documento, nacionalidade) aparece em qualquer evento publicado.

---

## 11. Transferências Internacionais de Dados

### 11.1 Arquitetura Descentralizada

A rede Nostr opera globalmente. Quando você publica eventos para relays Nostr, esses eventos podem ser replicados para relays localizados em qualquer lugar do mundo. Esta é uma característica fundamental do protocolo descentralizado.

### 11.2 Mecanismos de Transferência

Para qualquer processamento centralizado que o Signet conduza, as transferências internacionais de dados são protegidas por:

- **UE/EEE:** Cláusulas Contratuais Padrão (SCCs) conforme aprovadas pela Comissão Europeia (Decisão 2021/914), suplementadas por avaliações de impacto de transferência onde necessário.
- **Reino Unido:** Acordo Internacional de Transferência de Dados (IDTA) ou o Adendo do Reino Unido às SCCs da UE.
- **Coreia do Sul:** Conformidade com as disposições de transferência transfronteiriça da PIPA.
- **Japão:** Transferências para países com nível adequado de proteção reconhecido pela PPC, ou com consentimento do usuário.
- **China:** Avaliações de segurança, contratos padrão ou certificações conforme exigido pela PIPL.
- **Brasil:** Transferências em conformidade com o Art. 33 da LGPD, incluindo para países com nível adequado de proteção ou com garantias específicas.

### 11.3 Decisões de Adequação

Recorremos a decisões de adequação quando disponíveis, incluindo o Quadro de Privacidade de Dados UE-EUA, a Extensão do Reino Unido ao Quadro de Privacidade de Dados UE-EUA, e a decisão de adequação do Japão pela Comissão Europeia.

---

## 12. Retenção de Dados

### 12.1 Eventos Nostr

Eventos publicados na rede Nostr são retidos pelos operadores de relay de acordo com suas próprias políticas. Como a rede Nostr é descentralizada, o Signet não pode garantir a exclusão de eventos de todos os relays.

### 12.2 Ciclo de Vida das Credenciais

| Tipo de Dado | Período de Retenção |
|-----------|-----------------|
| Credenciais ativas | Até o vencimento ou revogação |
| Credenciais revogadas | Eventos de revogação são retidos indefinidamente para integridade da verificação |
| Credenciais vencidas | Retidas nos relays conforme as políticas dos operadores de relay |
| Registros de atestação | Até revogados pela parte atestante |
| Dados de desafio/resposta | Persistentes; publicados nos relays Nostr como eventos padrão, retidos para integridade do protocolo |
| Material de chave criptografado local | No seu dispositivo até você excluir o aplicativo ou limpar os dados do aplicativo |

### 12.3 Registros Centralizados

Quaisquer registros que o Signet mantém centralmente (p. ex., correspondência de suporte, registros de conformidade legal) são retidos por:
- Registros de suporte: 2 anos a partir da última interação
- Registros de conformidade legal: Conforme exigido pela lei aplicável (normalmente 5–7 anos)
- Registros de auditoria: 3 anos

---

## 13. Seus Direitos

### 13.1 Direitos Universais

Independentemente da sua jurisdição, você pode:
- Solicitar informações sobre quais dados processamos sobre você
- Solicitar a correção de dados imprecisos
- Retirar o consentimento onde o processamento for baseado em consentimento
- Registrar uma reclamação conosco ou com uma autoridade supervisora

### 13.2 Uma Nota sobre Arquitetura e Direitos

Como a arquitetura do Signet é descentralizada e voltada para a privacidade, muitos direitos são satisfeitos estruturalmente:

- **Acesso e portabilidade:** Seus dados de credenciais estão armazenados em eventos Nostr públicos que você publicou e no armazenamento local do seu aplicativo. Você já tem acesso completo a eles.
- **Apagamento:** O Signet não detém nenhuma cópia centralizada dos seus dados pessoais. Não podemos excluir eventos Nostr da infraestrutura dos operadores de relay em seu nome, mas podemos emitir um evento de revogação. Você pode solicitar a exclusão de operadores de relay individuais.
- **Retificação:** Credenciais incorretas podem ser substituídas pela emissão de um novo evento de credencial que faz referência ao anterior.

### 13.3 União Europeia / EEE (RGPD)

Nos termos do RGPD, você tem o direito de:
- **Acesso** (Art. 15) — Obter uma cópia dos seus dados pessoais
- **Retificação** (Art. 16) — Corrigir dados imprecisos
- **Apagamento** (Art. 17) — Solicitar a exclusão ("direito ao esquecimento") onde aplicável
- **Restrição** (Art. 18) — Restringir o processamento em certas circunstâncias
- **Portabilidade de Dados** (Art. 20) — Receber seus dados em um formato estruturado e legível por máquina
- **Objeção** (Art. 21) — Opor-se ao processamento baseado em interesse legítimo
- **Tomada de Decisão Automatizada** (Art. 22) — Não estar sujeito a decisões exclusivamente automatizadas com efeitos jurídicos

**Autoridade Supervisora:** Você pode registrar uma reclamação junto à sua autoridade local de proteção de dados. Uma lista de APDs da UE/EEE está disponível em [https://edpb.europa.eu/about-edpb/about-edpb/members_en](https://edpb.europa.eu/about-edpb/about-edpb/members_en).

### 13.4 Reino Unido (UK GDPR)

Você tem direitos equivalentes aos do RGPD da UE. Você pode registrar uma reclamação junto ao Gabinete do Comissário de Informação (ICO) em [https://ico.org.uk](https://ico.org.uk).

### 13.5 Estados Unidos (CCPA / CPRA)

Os residentes da Califórnia têm o direito de:
- **Saber** — Quais informações pessoais são coletadas, usadas e divulgadas
- **Excluir** — Solicitar a exclusão de informações pessoais
- **Corrigir** — Solicitar a correção de informações pessoais imprecisas
- **Recusar** — Recusar a venda ou o compartilhamento de informações pessoais (não vendemos nem compartilhamos)
- **Não Discriminação** — Não ser discriminado por exercer direitos de privacidade

Para exercer esses direitos, entre em contato conosco em privacy@signet.id.

Os residentes da Virgínia, Colorado, Connecticut, Utah, Texas e outros estados com legislação de privacidade têm direitos comparáveis sob suas respectivas leis.

### 13.6 Brasil (LGPD)

Os titulares de dados têm o direito de confirmação da existência do tratamento, acesso aos dados, correção de dados incompletos, inexatos ou desatualizados, anonimização, bloqueio ou eliminação de dados desnecessários ou excessivos, portabilidade dos dados, eliminação dos dados tratados com consentimento, informação sobre as entidades com as quais os dados são compartilhados, informação sobre a possibilidade de não fornecer consentimento e suas consequências, e revogação do consentimento.

Entre em contato com a ANPD (Autoridade Nacional de Proteção de Dados) para reclamações: [https://www.gov.br/anpd](https://www.gov.br/anpd).

### 13.7 Coreia do Sul (PIPA)

Os titulares de dados têm o direito de solicitar acesso a informações pessoais, solicitar correção ou exclusão, solicitar suspensão do processamento e registrar uma reclamação junto à Comissão de Proteção de Informações Pessoais (PIPC).

### 13.8 Japão (APPI)

Os titulares de dados têm o direito de solicitar a divulgação de dados pessoais retidos, solicitar correção, adição ou exclusão, solicitar a cessação do uso ou fornecimento a terceiros e registrar uma reclamação junto à Comissão de Proteção de Informações Pessoais (PPC).

### 13.9 China (PIPL)

Os titulares de dados têm o direito de saber e decidir sobre o processamento de informações pessoais, restringir ou recusar o processamento, acessar e copiar informações pessoais, solicitar portabilidade, solicitar correção e exclusão, e solicitar explicação das regras de processamento.

### 13.10 Índia (Lei DPDP)

Os titulares de dados têm o direito de acessar informações sobre o processamento, correção e apagamento de dados pessoais, solução de queixas e de nomear outra pessoa para exercer os direitos.

### 13.11 Exercendo seus Direitos

Para exercer qualquer um dos direitos acima, entre em contato conosco em:
- **E-mail:** privacy@signet.id
- **E-mail do DPO:** dpo@signet.id

Responderemos nos prazos exigidos pela lei aplicável:
- RGPD/UK GDPR: 30 dias (prorrogável por 60 dias para solicitações complexas)
- CCPA/CPRA: 45 dias (prorrogável por 45 dias)
- LGPD: 15 dias
- PIPA: 10 dias
- APPI: Sem demora
- PIPL: Prontamente

---

## 14. Dados de Menores

### 14.1 Política Geral

O Signet Protocol inclui o Nível 4 (Verificação Profissional — Adulto + Menor), que é especificamente concebido para a segurança infantil. Levamos muito a sério a proteção dos dados de menores. Crianças com menos de 18 anos só podem ser verificadas sob o Nível 4 com a participação ativa de um guardião adulto verificado, que recebe uma credencial de Nível 4 vinculando sua chave pública à credencial da criança via uma etiqueta de guardião.

### 14.2 Verificação de Idade

O Protocolo usa provas de conhecimento zero baseadas em Bulletproofs para verificação de faixa etária. Essas provas demonstram que um usuário está dentro de uma determinada faixa etária (p. ex., "0-3", "4-7", "8-12", "13-17", "18+") sem revelar sua data de nascimento exata.

### 14.3 Requisitos de Idade por Jurisdição

| Jurisdição | Idade Mínima para Consentimento Digital | Lei Aplicável |
|-------------|-------------------------------|---------------|
| UE (padrão) | 16 anos | RGPD Art. 8 |
| UE (opção do estado-membro) | 13–16 anos (varia por estado-membro) | RGPD Art. 8(1) |
| Reino Unido | 13 anos | UK GDPR / Código das Crianças |
| Estados Unidos | 13 anos | COPPA |
| Brasil | 12 anos (consentimento parental exigido abaixo de 18) | LGPD Art. 14 |
| Coreia do Sul | 14 anos | PIPA |
| Japão | 15 anos (diretrizes) | APPI |
| China | 14 anos | PIPL Art. 28 |
| Índia | 18 anos (com exceções) | Lei DPDP |

### 14.4 Consentimento Parental

Onde o consentimento parental é exigido, o Protocolo suporta:
- Consentimento parental verificável através de credenciais de pai/responsável verificados no Nível 3 ou Nível 4
- Controle de acesso por idade através de verificação de prova ZK no nível da parte confiante
- Eventos de delegação de guardião (tipo 31000) permitindo que os pais gerenciem a atividade Signet de seus filhos
- Mecanismos para os pais revogarem delegação e consentimento

### 14.5 Conformidade com a COPPA (Estados Unidos)

O Signet não coleta nenhuma informação pessoal de qualquer usuário, incluindo crianças menores de 13 anos. A arquitetura de conhecimento zero do Protocolo significa que não há nome, data de nascimento, endereço ou qualquer outra informação pessoal coberta pela COPPA coletada, armazenada ou transmitida pelo Signet. A orientação da FTC de março de 2026 reconhece flexibilidade para plataformas que implementam verificação que preserva a privacidade sem coletar informações pessoais cobertas.

### 14.6 Código de Design Adequado para a Idade (Reino Unido)

O Signet está comprometido com os princípios do Código de Design Adequado para a Idade do Reino Unido (Código das Crianças), incluindo avaliação do melhor interesse da criança, aplicação adequada para a idade, minimização de dados, configurações padrão protetoras para crianças e transparência adequada à idade da criança.

---

## 15. Segurança

### 15.1 Segurança Criptográfica

O Signet Protocol emprega:
- **Assinaturas Schnorr** na curva secp256k1 para toda a assinatura de credenciais
- **Bulletproofs** para provas de conhecimento zero de faixa etária
- **Assinaturas em Anel** (SAG e LSAG) para provas anônimas de participação em grupo, com etiquetas de separação de domínio e limites de tamanho de anel (máximo de 1.000 membros)
- **Árvores Merkle RFC 6962** com separação de domínio (prefixo `0x00` para folhas, prefixo `0x01` para nós internos) para comprometimentos de atributos à prova de adulteração
- **ECDH** com rejeição de ponto de identidade para derivação de segredo compartilhado
- **Futura camada ZK** planejada para tipos de prova adicionais (ZK-SNARKs/ZK-STARKs)

### 15.2 Segurança de Armazenamento de Chaves

As chaves privadas no aplicativo My Signet são:
- Criptografadas em repouso usando AES-256-GCM
- A chave de criptografia é derivada via PBKDF2 com SHA-256 e 600.000 iterações (recomendação OWASP 2023), usando um sal aleatório
- As chaves são mantidas na memória apenas durante uma sessão autenticada
- Frases mnemônicas e chaves privadas nunca são transmitidas ao Signet ou a qualquer terceiro
- Nunca armazenadas em texto simples no IndexedDB, localStorage ou qualquer outro mecanismo de armazenamento

### 15.3 Validação de Entrada

Todos os validadores de eventos impõem comprimento máximo de conteúdo (64 KB), contagem máxima de etiquetas (100 etiquetas), comprimento máximo de valor de etiqueta (1.024 caracteres) e verificação de limites de inteiros para evitar desvios silenciosos de segurança.

### 15.4 Modelo de Segurança Descentralizado

A arquitetura descentralizada do Protocolo oferece benefícios de segurança inerentes: nenhum ponto único de falha, nenhuma base de dados centralizada para ser violada, gerenciamento de chaves controlado pelo usuário e verificação criptográfica sem intermediários confiáveis.

### 15.5 Notificação de Violações

Em caso de violação de dados pessoais afetando quaisquer sistemas centralizados do Signet, iremos:
- Notificar a autoridade supervisora relevante dentro de 72 horas (RGPD) ou conforme exigido pela lei aplicável
- Notificar os indivíduos afetados sem demora indevida quando a violação for suscetível de resultar em alto risco para os seus direitos e liberdades
- Documentar a violação, seus efeitos e ações corretivas

---

## 16. Cookies e Tecnologias de Rastreamento

O Signet Protocol **não** utiliza:
- Cookies
- Web beacons ou pixels de rastreamento
- Impressão digital de navegador
- Armazenamento local para fins de rastreamento
- Quaisquer serviços de análise ou rastreamento de terceiros

Se serviços auxiliares (como um site de documentação) utilizarem cookies, um aviso de cookie separado será fornecido com mecanismos de consentimento apropriados.

---

## 17. Tomada de Decisão Automatizada e Criação de Perfis

### 17.1 Cálculo do Signet IQ

O Protocolo calcula pontuações de Signet IQ (0–200, onde 100 representa o padrão de identidade governamental atual) com base no nível de verificação, número e qualidade das atestações, credenciais e situação do verificador, idade da credencial e sinais de vencimento do documento. Essas pontuações são calculadas algoritmicamente e são visíveis às partes confiantes. Elas não constituem tomada de decisão automatizada com efeitos jurídicos nos termos do Art. 22 do RGPD, pois são um dos insumos que as partes confiantes podem considerar.

### 17.2 Sem Criação de Perfis para Marketing

Não nos envolvemos na criação de perfis para fins de marketing, publicidade ou análise comportamental.

---

## 18. Links e Serviços de Terceiros

O Signet Protocol interopera com:
- Relays Nostr (operados independentemente)
- Clientes Nostr (como o Fathom, o cliente de implementação de referência)
- Organismos profissionais e registros regulatórios (via o bot de verificação de código aberto)
- O registro de tipos de documentos (um arquivo YAML externo que define as definições de campos de documentos por país — não contém dados pessoais)

Esses terceiros têm suas próprias políticas de privacidade. O Signet não é responsável por suas práticas de dados.

---

## 19. Alterações nesta Política de Privacidade

Podemos atualizar esta Política de Privacidade periodicamente. As alterações serão indicadas pela atualização da data "Última Atualização" no topo deste documento. Para alterações materiais, forneceremos aviso através de um anúncio de evento Nostr e uma atualização no repositório de especificação do Protocolo. O seu uso continuado do Protocolo após as alterações constitui aceitação da Política de Privacidade atualizada.

---

## 20. Disposições Específicas por Jurisdição

### 20.1 União Europeia — Disposições Adicionais

Quando processamos dados pessoais nos termos do RGPD, as disposições do RGPD prevalecem sobre quaisquer disposições conflitantes nesta Política de Privacidade. Relativamente ao eIDAS 2.0: o Protocolo do Signet está concebido para aceitar eventos de ponte de identidade de Carteiras de Identidade Digital da UE quando essas carteiras forem implantadas pelos estados-membros, prevista para dezembro de 2026.

### 20.2 Reino Unido — Disposições Adicionais

**Registro no ICO:** O Signet se registrará no ICO conforme exigido. Os detalhes do registro serão publicados em signet.id/legal.

**Não Vender nem Compartilhar Minhas Informações Pessoais:** Não vendemos nem compartilhamos informações pessoais.

**Lei de Segurança Online:** As capacidades de verificação de idade do Signet são concebidas para ser compatíveis com os requisitos de garantia de idade da Lei de Segurança Online de 2023.

### 20.3 Califórnia — Disposições Adicionais

**Não Vender nem Compartilhar Minhas Informações Pessoais:** Não vendemos nem compartilhamos informações pessoais conforme definido pela CCPA/CPRA.

**Incentivos Financeiros:** Não oferecemos incentivos financeiros relacionados à coleta de informações pessoais.

**Shine the Light (Cal. Civ. Code Seção 1798.83):** Os residentes da Califórnia podem solicitar informações sobre a divulgação de informações pessoais a terceiros para marketing direto. Não fazemos tais divulgações.

### 20.4 Brasil — Disposições Adicionais

O DPO (Encarregado) pode ser contatado em dpo@signet.id para todas as consultas relacionadas à LGPD.

### 20.5 Austrália — Disposições Adicionais

Cumprimos os Princípios Australianos de Privacidade (APPs) sob a Lei de Privacidade de 1988 (Cth). Você pode registrar uma reclamação junto ao Gabinete do Comissário Australiano de Informação (OAIC).

### 20.6 Nova Zelândia — Disposições Adicionais

Cumprimos a Lei de Privacidade de 2020 (NZ). Você pode registrar uma reclamação junto ao Gabinete do Comissário de Privacidade.

### 20.7 Singapura — Disposições Adicionais

Cumprimos a Lei de Proteção de Dados Pessoais de 2012 (PDPA). Você pode contatar a Comissão de Proteção de Dados Pessoais (PDPC) para reclamações.

### 20.8 África do Sul — Disposições Adicionais

Cumprimos a Lei de Proteção de Informações Pessoais de 2013 (POPIA). Você pode registrar uma reclamação junto ao Regulador de Informação.

---

## 21. Entre em Contato Conosco

Para quaisquer dúvidas, preocupações ou solicitações relacionadas a esta Política de Privacidade ou às nossas práticas de dados:

**Consultas Gerais:**
The Signet Protocol
E-mail: privacy@signet.id

**Encarregado de Proteção de Dados:**
E-mail: dpo@signet.id

---

## 22. Registros Regulatórios

Dependendo da jurisdição, o Signet mantém ou manterá registros ou arquivamentos junto a:
- O Gabinete do Comissário de Informação (Reino Unido) — registro a ser concluído; detalhes publicados em signet.id/legal
- Autoridades de proteção de dados aplicáveis da UE/EEE
- Outros órgãos regulatórios conforme exigido por lei

---

*Esta Política de Privacidade descreve as práticas de dados do Signet Protocol em março de 2026. O Signet Protocol é software de código aberto. Este documento não constitui aconselhamento jurídico. Os usuários e operadores devem buscar aconselhamento jurídico qualificado familiarizado com as leis de proteção de dados aplicáveis em sua jurisdição.*

*Signet Protocol — v0.1.0*
*Versão do Documento: 2.0*
