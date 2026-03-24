---
**Aviso de Tradução Gerada por IA**

Este documento foi traduzido do inglês utilizando IA (Claude, Anthropic). É fornecido apenas para referência. A versão em inglês em `en.md` é o único documento juridicamente vinculante. Esta tradução não foi revista por um tradutor jurídico qualificado. Em caso de discrepância entre esta tradução e o original em inglês, prevalece a versão em inglês.

---

# Termos de Serviço

**The Signet Protocol — v0.1.0**
**Data de Vigência:** 17 de março de 2026
**Última Atualização:** 17 de março de 2026

*Este documento abrange o seu uso do My Signet (o aplicativo de referência) e das bibliotecas do Signet Protocol, incluindo o SDK signet-verify.js. Não constitui aconselhamento jurídico. Consulte um advogado qualificado na sua jurisdição antes de utilizá-lo em uma implantação em produção.*

---

## Sumário

1. [Aceitação dos Termos](#1-aceitação-dos-termos)
2. [Elegibilidade](#2-elegibilidade)
3. [Descrição do Protocolo e do Aplicativo](#3-descrição-do-protocolo-e-do-aplicativo)
4. [Gerenciamento de Chaves e Segurança da Conta](#4-gerenciamento-de-chaves-e-segurança-da-conta)
5. [A Cerimônia de Verificação](#5-a-cerimônia-de-verificação)
6. [Ciclo de Vida das Credenciais](#6-ciclo-de-vida-das-credenciais)
7. [Obrigações do Usuário](#7-obrigações-do-usuário)
8. [Obrigações do Verificador](#8-obrigações-do-verificador)
9. [Operadores de Sites e o SDK signet-verify.js](#9-operadores-de-sites-e-o-sdk-signet-verifyjs)
10. [O Bot de Verificação](#10-o-bot-de-verificação)
11. [Pontuações Signet IQ](#11-pontuações-signet-iq)
12. [Proteção de Dados](#12-proteção-de-dados)
13. [Propriedade Intelectual](#13-propriedade-intelectual)
14. [Isenções de Responsabilidade](#14-isenções-de-responsabilidade)
15. [Limitação de Responsabilidade](#15-limitação-de-responsabilidade)
16. [Indenização](#16-indenização)
17. [Lei Aplicável e Resolução de Disputas](#17-lei-aplicável-e-resolução-de-disputas)
18. [Rescisão](#18-rescisão)
19. [Alterações](#19-alterações)
20. [Disposições Gerais](#20-disposições-gerais)
21. [Contato](#21-contato)
22. [Anexos Específicos por Jurisdição](#22-anexos-específicos-por-jurisdição)

---

## 1. Aceitação dos Termos

Ao acessar, baixar ou usar o My Signet (o "Aplicativo"), as bibliotecas do Signet Protocol, ou o SDK signet-verify.js (conjuntamente, "o Protocolo"), ou ao atuar como verificador, você ("você" ou "Usuário") concorda em ser vinculado por estes Termos de Serviço ("Termos").

Se você não concordar com estes Termos, não deve usar o Protocolo.

Se você usar o Protocolo em nome de uma organização, você declara que tem autoridade para vincular essa organização, e "você" inclui essa organização.

**Verificadores:** Ao publicar um evento de credencial de verificador de tipo 31000 na rede Nostr, ou ao realizar uma cerimônia de verificação Signet, você aceita a Seção 8 (Obrigações do Verificador) como uma condição juridicamente vinculante da sua participação. Você não precisa assinar um documento separado. O ato de realizar uma verificação é a sua aceitação.

---

## 2. Elegibilidade

### 2.1 Elegibilidade Geral

Para usar o Protocolo, você deve:

- Ter capacidade legal para celebrar um acordo vinculante na sua jurisdição
- Não ser proibido de usar o Protocolo por nenhuma lei aplicável
- Não ter sido removido do Protocolo por violação material destes Termos

### 2.2 Requisitos de Idade

| Jurisdição | Idade mínima — conta própria | Com consentimento parental verificado |
|---|---|---|
| União Europeia (padrão) | 16 | 13 (varia por estado-membro) |
| Reino Unido | 13 | N/A |
| Estados Unidos | 13 | Abaixo de 13 com consentimento parental em conformidade com a COPPA |
| Brasil | 18 | 12 com consentimento parental |
| Coreia do Sul | 14 | Abaixo de 14 com consentimento parental |
| Japão | 15 | Abaixo de 15 com consentimento parental |
| Índia | 18 | Conforme a Lei DPDP |
| Outros | Idade de consentimento digital | Conforme a lei local |

Crianças abaixo da idade de consentimento digital da sua jurisdição só podem ter uma conta Signet como subconta de um pai ou guardião verificado (veja a Seção 6.7).

### 2.3 Elegibilidade do Verificador

Para atuar como verificador profissional e emitir credenciais de Nível 3 ou Nível 4, você deve:

- Possuir um registro profissional atual e válido em bom estado perante o órgão regulador relevante
- Estar autorizado a exercer na jurisdição onde realiza verificações
- Não estar sujeito a qualquer suspensão, restrição ou processo disciplinar que prejudique sua capacidade de verificar identidade
- Manter seguro de responsabilidade profissional adequado para cobrir suas atividades de verificação

A lista completa de profissões elegíveis está na Seção 8.2.

---

## 3. Descrição do Protocolo e do Aplicativo

### 3.1 Visão Geral

O Signet Protocol é um protocolo de verificação de identidade descentralizado para a rede Nostr. Ele permite que os usuários comprovem afirmações sobre sua identidade — incluindo idade, parentalidade e situação profissional — usando provas de conhecimento zero e assinaturas em anel, sem revelar dados pessoais subjacentes. Não há banco de dados central, nenhuma autoridade central e nenhuma organização única que controle a rede.

**My Signet** é o aplicativo de referência. É um aplicativo web progressivo (PWA) que funciona no seu navegador. É um único aplicativo usado por todos: indivíduos, verificadores e comunidades.

### 3.2 Níveis de Verificação

| Nível | Nome | O que significa |
|---|---|---|
| 1 | Autodeclarado | Você criou uma conta e declarou alguns atributos. Sem verificação externa. Menor confiança. |
| 2 | Teia de Confiança | Outros usuários que o conhecem o atestaram. A confiança deriva da rede. |
| 3 | Verificação Profissional (Adulto) | Um profissional licenciado verificou pessoalmente seu documento de identidade emitido pelo governo e emitiu duas credenciais via a cerimônia das duas credenciais. |
| 4 | Verificação Profissional (Adulto + Menor) | Nível 3 estendido para incluir uma conta de menor, com o relacionamento da criança com um pai/guardião verificado confirmado por um profissional. |

### 3.3 Tipos de Eventos Nostr

O Protocolo usa os seguintes tipos de eventos Nostr:

| Tipo | Finalidade |
|---|---|
| 31000 | Eventos de credenciais |
| 31000 | Atestações de atestação |
| 30078 | Políticas de verificação de comunidade |
| 31000 | Credenciais de registro de verificadores |
| 31000 | Eventos de desafio |
| 31000 | Eventos de revogação |
| 31000 | Eventos de ponte de identidade |
| 31000 | Eventos de delegação (guardião e agente) |
| 30482–30484 | Extensão de votação (eleição, cédula, resultado) |

Os números de tipo de evento estão pendentes de alocação final de NIP.

### 3.4 Pilha Criptográfica

O Protocolo usa:

- Assinaturas Schnorr na curva secp256k1 (camada base)
- Bulletproofs para provas de conhecimento zero de faixa etária
- Assinaturas em anel de Grupo Anônimo Espontâneo (SAG) e SAG Vinculável (LSAG) para privacidade do emissor
- PBKDF2 (600.000 iterações, SHA-256) com AES-256-GCM para armazenamento local de credenciais
- Uma futura camada ZK (ZK-SNARKs ou ZK-STARKs) está planejada para completude criptográfica de Nível 3

### 3.5 Natureza Descentralizada

O Signet Protocol opera na rede Nostr. Desenvolvemos e mantemos a especificação do Protocolo, mas não controlamos a rede, os operadores de relay ou os participantes individuais. Eventos publicados no Nostr são públicos, persistentes e replicados por operadores de relay que não controlamos.

---

## 4. Gerenciamento de Chaves e Segurança da Conta

### 4.1 Modelo de Dois Pares de Chaves

O My Signet deriva dois pares de chaves independentes de uma única mnemônica BIP-39 de 12 palavras:

- **Par de chaves de Pessoa Natural:** Usado para sua credencial de identidade real (nome, documento, nullifier, raiz Merkle). Este par de chaves é usado apenas quando você escolhe explicitamente apresentar sua identidade real verificada.
- **Par de chaves de Persona:** Um alias anônimo. Carrega uma prova de faixa etária herdada da cerimônia de verificação, mas sem nome, referência a documento ou nullifier. Toda a sua atividade diária no Nostr pode usar este par de chaves.

Durante o processo de integração, você escolhe qual par de chaves é sua conta principal para aquele dispositivo. Você pode alternar a qualquer momento. O vínculo entre seus dois pares de chaves é conhecido apenas por você e seu verificador (protegido pelas obrigações de confidencialidade profissional deste).

### 4.2 Modo de Par de Chaves Único (Importação nsec)

Se você for um usuário Nostr existente, pode importar sua chave privada existente (nsec). No modo de par de chaves único, seu npub existente se torna sua identidade de Pessoa Natural, e você pode criar uma ponte de identidade (evento de tipo 31000) para vinculá-la a uma conta Persona. Todos os seus seguidores existentes, NIP-05, zaps e reputação são preservados.

### 4.3 Geração e Backup de Chaves

- Sua mnemônica é gerada localmente no Aplicativo usando aleatoriedade criptograficamente segura. Nunca é transmitida para nenhum servidor.
- Você é o único responsável pelo backup da sua mnemônica. Não podemos recuperá-la. Se você perder sua mnemônica e seu dispositivo, sua conta não pode ser recuperada sem uma nova verificação profissional.
- Contas de menores podem ser derivadas em diferentes índices de conta BIP-44 da mesma mnemônica pai, mantendo o gerenciamento de chaves familiares em uma única frase de recuperação.
- O backup de Compartilhamento de Segredo de Shamir (via `@scure/bip39`) é suportado para dividir a mnemônica entre custodiantes confiáveis.

### 4.4 Autenticação Biométrica e por PIN

O My Signet requer autenticação para acessar sua chave privada:

- **Biométrica (preferido):** Usa WebAuthn com a extensão PRF, quando disponível. Sua biometria nunca sai do seu dispositivo. Onde PRF é suportado, o material de chave é derivado por hardware e não pode ser extraído do localStorage mesmo por código em execução no mesmo dispositivo.
- **Alternativa de PIN:** Onde a autenticação biométrica não está disponível, é necessário um PIN. O PIN é usado com PBKDF2 (600.000 iterações) para derivar uma chave de criptografia AES-256-GCM.
- **Gerenciamento de sessão:** Após um período de inatividade, o Aplicativo se bloqueia. Você deve se autenticar novamente para continuar. O tempo de inatividade pode ser configurado nas configurações.

Sua chave privada nunca é armazenada em texto simples. Está sempre criptografada em repouso usando AES-256-GCM.

### 4.5 Comprometimento de Chave

Se você acreditar que sua chave privada foi comprometida, deve visitar um verificador profissional com seus documentos de identidade originais. O verificador revogará todas as credenciais emitidas para o seu par de chaves antigo e emitirá credenciais novas para um novo par de chaves. As atestações associadas à chave comprometida não são transferidas (esta é uma medida de segurança deliberada — um atacante que comprometeu sua chave não pode reter sua confiança social).

### 4.6 Assinatura Remota NIP-46

O My Signet suporta assinatura remota NIP-46. Isso permite que outros aplicativos ou serviços solicitem que o Aplicativo assine eventos Nostr em seu nome. Cada solicitação de assinatura requer sua aprovação explícita. O Aplicativo exibirá os detalhes da solicitação antes que você a aprove ou rejeite. Você não deve aprovar solicitações que não reconhece ou entende.

---

## 5. A Cerimônia de Verificação

### 5.1 Como Funciona a Verificação Profissional

As credenciais de Nível 3 e Nível 4 são emitidas através da cerimônia das duas credenciais:

1. **Você insere seus dados.** Antes de visitar um verificador, você insere seus próprios atributos de identidade (nome, data de nascimento, nacionalidade, tipo e número de documento) no Aplicativo. O Aplicativo pré-calcula sua árvore Merkle e seu nullifier de documento.

2. **Você apresenta seus documentos.** Você comparece a uma consulta presencial com um verificador profissional e apresenta seu(s) documento(s) de identidade original(is) emitido(s) pelo governo.

3. **O verificador confirma ou rejeita.** O verificador inspeciona seus documentos, verifica que você é a pessoa descrita neles e confirma ou rejeita os dados que você inseriu. O verificador não digita seus dados pessoais — ele apenas confirma o que você inseriu.

4. **Duas credenciais são emitidas.** Se o verificador confirmar os dados, ele publica dois eventos de credencial de tipo 31000 — um para o seu par de chaves de Pessoa Natural (com sua raiz Merkle e nullifier) e um para o seu par de chaves de Persona (com apenas sua prova de faixa etária). Ambas as credenciais são assinadas com a chave Nostr profissional do verificador.

5. **O número do documento é descartado.** Após o cálculo do nullifier, o número do documento não é retido pelo Protocolo, pelo Aplicativo, ou (a menos que exigido por suas obrigações profissionais) pelo verificador.

### 5.2 Quem É Responsável pela Precisão dos Dados

Como você insere seus próprios dados de identidade, você carrega a responsabilidade primária por sua precisão. Inserir dados falsos (nome errado, número de documento de outra pessoa) é fraudulento e pode constituir crime na sua jurisdição.

O papel do verificador é confirmar que a pessoa diante dele corresponde aos documentos apresentados. O verificador não garante a completude ou precisão dos dados que você inseriu além do que pode ser visualmente confirmado pelos documentos.

### 5.3 Nullifiers de Documento

O Protocolo usa nullifiers baseados em documentos para impedir que a mesma pessoa obtenha múltiplas credenciais de Nível 3. O nullifier é calculado como:

```
SHA-256(LP(docType) || LP(country) || LP(docNumber) || LP("signet-nullifier-v2"))
```

onde `LP(x)` é o comprimento em bytes UTF-8 de `x` codificado como um inteiro big-endian de 2 bytes, seguido pelos bytes de `x`. Esta codificação com prefixo de comprimento evita colisões de fronteira de campo.

O nullifier:
- É determinístico: o mesmo documento sempre produz o mesmo nullifier
- É unidirecional: o número do documento não pode ser recuperado do nullifier
- É resistente a colisões: documentos diferentes produzem nullifiers diferentes
- É consistente entre verificadores: qualquer verificador com o mesmo documento produz o mesmo nullifier

Se você apresentar vários documentos de identidade (por exemplo, passaporte e carteira de motorista), o verificador pode calcular nullifiers para todos os documentos, formando uma família de nullifiers. Todos os nullifiers da família são publicados na credencial e verificados em relação às credenciais existentes nos relays.

### 5.4 A Árvore Merkle

Seus atributos pessoais (nome, data de nascimento, nacionalidade, tipo de documento, vencimento do documento, nullifier) são armazenados como folhas em uma árvore Merkle. Apenas a raiz Merkle é publicada na cadeia. Você pode comprovar atributos individuais fornecendo um caminho Merkle, sem revelar todos os atributos. A árvore Merkle usa separação de domínio RFC 6962 (prefixo 0x00 para hashes de folhas, 0x01 para nós internos).

### 5.5 Provas de Faixa Etária

Sua data de nascimento nunca é publicada. Em vez disso, o verificador calcula uma prova de conhecimento zero Bulletproof de que sua idade está dentro de um intervalo especificado (por exemplo, "18+", "13–17", "8–12"). A prova é matematicamente verificável sem revelar sua idade exata ou data de nascimento.

### 5.6 Verificação Cruzada

Você pode buscar verificação de um segundo (ou mais) verificador apresentando os mesmos documentos. Como o nullifier é derivado dos seus documentos, o mesmo nullifier é produzido. O Protocolo distingue a verificação cruzada da fraude de identidade duplicada verificando se a chave pública do sujeito corresponde à credencial existente:

- Mesmo nullifier + mesma chave pública = confirmação independente (maior contribuição para o Signet IQ)
- Mesmo nullifier + chave pública diferente = possível identidade duplicada (sinalizado para investigação)

A verificação cruzada é o sinal de IQ mais forte, representando confirmação profissional independente da mesma identidade.

---

## 6. Ciclo de Vida das Credenciais

### 6.1 Vencimento e Decaimento das Credenciais

As credenciais profissionais incluem uma tag `expires` (o período de validade da credencial) e uma folha Merkle `documentExpiry` (quando o documento subjacente vence). Estes são diferentes: uma credencial pode vencer após dois anos, enquanto o passaporte em que se baseou não vence por dez anos.

As credenciais não têm encerramento abrupto no vencimento. Em vez disso, a contribuição de IQ de uma credencial que vence decai gradualmente à medida que a data de vencimento se aproxima, em vez de cair para zero na data de vencimento. Espera-se que os clientes exibam este decaimento visualmente (um indicador que se esmaece lentamente) em vez de um estado binário válido/inválido.

Se o documento subjacente a uma credencial vencer antes da própria credencial, a contribuição de IQ decai mais rapidamente — refletindo a confiança reduzida no documento de identidade subjacente.

### 6.2 Revogação de Credenciais

As credenciais podem ser revogadas publicando um evento de tipo 31000. A revogação pode ser iniciada por:

- Você (autorrevogação — por exemplo, em caso de comprometimento de chave ou mudança de nome)
- O verificador emissor (por causa justa, como fraude descoberta)
- Consenso comunitário (para fraude sistêmica ou comprometimento de segurança)

### 6.3 Cadeias de Credenciais e Renovação de Documentos

Quando seus atributos do mundo real mudam (mudança de nome, renovação de documento, atualização de nível), uma credencial de substituição é emitida com uma tag `["supersedes", "<old_event_id>"]`. Os clientes seguem a cadeia para exibir apenas a credencial ativa atual. As credenciais substituídas permanecem nos relays como registros históricos.

**Renovação de documento e nullifiers:**
- **Renovação de passaporte:** Um novo número de passaporte produz um novo nullifier. Os nullifiers antigo e novo são vinculados por uma tag `["nullifier-chain", "<old_nullifier>"]` na nova credencial.
- **Renovação de carteira de motorista (UK):** O número da carteira normalmente não muda na renovação. A nova credencial referencia o mesmo nullifier.

### 6.4 Detalhe do Modelo de Duas Credenciais

| Credencial | Contém | Não contém |
|---|---|---|
| Pessoa Natural | Raiz Merkle, nullifier primário, família de nullifiers, prova de faixa etária, tipo de entidade, tags de guardião (se menor) | Nome real, data de nascimento, número do documento |
| Persona | Prova de faixa etária, tipo de entidade=persona, tags de guardião (se menor) | Nullifier, raiz Merkle, quaisquer atributos pessoais |

### 6.5 Delegação de Guardião

Um guardião (pai ou tutor legal verificado) pode delegar permissões específicas a adultos confiáveis via eventos de delegação de tipo 31000. Os escopos de delegação incluem:

- `full` — delegação total (por exemplo, coparentalidade)
- `activity-approval` — aprovar atividades que requerem consentimento parental
- `content-management` — gerenciar o conteúdo e conexões da criança
- `contact-approval` — aprovar novos contatos

Os eventos de delegação incluem uma tag `agent-type` identificando o relacionamento (por exemplo, `teacher` [professor], `grandparent` [avô/avó], `step-parent` [padrasto/madrasta]). As tags de guardião nas credenciais são imutáveis — só podem ser alteradas por uma nova credencial emitida por um profissional com documentação legal apropriada.

### 6.6 Subcontas de Menores

Uma credencial de menor é uma subconta de um pai ou guardião verificado:

- A credencial do menor deve incluir tags de guardião vinculando a um pai ou guardião verificado no Nível 3+
- O menor deve estar presente durante a cerimônia de verificação de Nível 4 (pessoalmente ou por meio de um processo legalmente equivalente)
- Quando a criança completar 18 anos, ela recebe uma nova credencial de Nível 3 sem tags de guardião, substituindo a credencial de menor
- Um menor não pode possuir uma credencial Persona que carregue uma afirmação de faixa etária superior à sua faixa etária verificada

### 6.7 Contas Persona

Uma Persona é um alias anônimo:

- Uma Persona não carrega nenhuma informação de identificação pessoal — sem nome, sem nullifier, sem raiz Merkle
- Uma Persona herda a prova de faixa etária da cerimônia das duas credenciais
- Uma Persona pode ser vinculada a uma Pessoa Natural via uma ponte de identidade (tipo 31000) usando assinaturas em anel, permitindo que a Persona comprove "Sou uma pessoa real e verificada" sem revelar qual pessoa
- Você é responsável por toda a atividade realizada através de suas contas Persona

### 6.8 Sem Garantia de Aceitação

Não garantimos que qualquer credencial será aceita por qualquer parte confiante. As comunidades estabelecem suas próprias políticas de aceitação através de eventos de política de tipo 30078.

### 6.9 Carteira de Documentos

O My Signet suporta uma carteira de documentos contendo múltiplos documentos de identidade. Cada documento produz sua própria credencial e seu próprio nullifier. Isso permite verificação progressiva: você pode adicionar documentos ao longo do tempo, com cada documento adicional fortalecendo sua família de nullifiers e contribuindo para o seu Signet IQ.

---

## 7. Obrigações do Usuário

### 7.1 Obrigações Gerais

Todos os usuários devem:

1. **Precisão.** Inserir informações verdadeiras ao criar credenciais. Credenciais fraudulentas minam o modelo de confiança e podem constituir fraude criminal.
2. **Segurança de chaves.** Proteger sua mnemônica e chave privada. Você é o único responsável por sua segurança.
3. **Conformidade.** Cumprir todas as leis e regulamentações aplicáveis.
4. **Uso responsável.** Usar o Protocolo de boa fé e não para qualquer finalidade ilegal, fraudulenta ou prejudicial.
5. **Comunicação.** Reportar prontamente vulnerabilidades de segurança, fraude de credenciais ou uso indevido do Protocolo ao endereço de contato na Seção 21.

### 7.2 Usos Proibidos

Você não deve:

1. Criar credenciais falsas, enganosas ou fraudulentas
2. Personificar outra pessoa ou entidade
3. Tentar fazer engenharia reversa de provas de conhecimento zero para extrair dados pessoais
4. Usar o Protocolo para facilitar atividades ilegais, incluindo roubo de identidade, fraude, lavagem de dinheiro, financiamento de terrorismo ou exploração infantil
5. Atacar a infraestrutura criptográfica do Protocolo ou tentar quebrar o anonimato dos conjuntos de assinaturas em anel
6. Enviar spam à rede com eventos de credencial, atestação ou desafio ilegítimos
7. Colodir com verificadores para obter credenciais de Nível 3 ou Nível 4 injustificadas
8. Usar sistemas automatizados para gerar credenciais ou atestações em massa sem verificação genuína
9. Interferir ou interromper o Protocolo ou a rede Nostr
10. Explorar o Protocolo para contornar restrições de idade ou medidas de segurança infantil

### 7.3 Obrigações de Atestação (Nível 2)

Ao atestar outro usuário (evento de tipo 31000):

- Você deve ter uma base genuína e pessoal para a atestação
- Você não deve aceitar pagamento ou outra consideração por fornecer atestações
- Você pode revogar uma atestação a qualquer momento publicando um evento de revogação
- Seu comportamento de atestação afeta seu próprio Signet IQ

---

## 8. Obrigações do Verificador

### 8.1 Por que Não Há Acordo Separado

Incorporamos o acordo do verificador nestes Termos porque as pessoas mais propensas a verificar crianças — professores em reuniões de pais, clínicos gerais, assistentes sociais — não devem precisar navegar por um segundo documento jurídico. Ao atuar como verificador Signet (publicando um evento de tipo 31000 ou realizando uma cerimônia), você aceita as obrigações desta seção. Estas obrigações são adicionais e não substituem seus deveres profissionais existentes.

### 8.2 Profissões Elegíveis

Você pode atuar como verificador Signet se possuir um registro atual e válido em um órgão regulador reconhecido em uma das seguintes categorias. Esta lista segue o padrão de contragarantia de passaporte do Reino Unido e seus equivalentes internacionais.

**Profissionais jurídicos:** Solicitador, advogado, causídico, advogado, executivo jurídico, notário público, comissário de justiça, Notar, tabelião licenciado, executivo jurídico habilitado.

**Profissionais médicos e de saúde:** Médico, cirurgião, clínico geral, dentista, farmacêutico, óptico/optometrista, enfermeiro registrado (onde permitido nacional), fisioterapeuta, psicólogo clínico, profissional de saúde comunitária ou hospitalar registrado em um órgão nacional (GMC, NMC, GDC, GPhC, HCPC ou equivalente).

**Profissionais de educação:** Professor qualificado (registrado na Agência de Regulação do Ensino ou equivalente nacional), diretor ou vice-diretor, docente de ensino superior ou universitário registrado em um órgão profissional, inspetor escolar.

**Profissionais financeiros:** Contador habilitado (ICAEW, ICAS, ACCA, CIMA, CPA ou equivalente), contador certificado habilitado, auditor licenciado, consultor financeiro independente autorizado por um regulador financeiro nacional, funcionário de banco ou associação de construção de nível de oficial.

**Profissionais de serviços públicos e emergências:** Oficial de polícia, oficial de bombeiros, membro das Forças Armadas de Sua Majestade (oficial), juiz, magistrado, juiz de paz, oficial do Ministério Público, oficial de liberdade condicional, assistente social registrado em um órgão regulador nacional.

**Profissionais religiosos e comunitários:** Ministro de religião, líder religioso reconhecido como tal por uma denominação registrada, registrador civil.

**Profissionais de engenharia, ciência e tecnologia:** Engenheiro habilitado (registrado em uma instituição nacional de engenharia), cientista habilitado, arquiteto (registrado no Conselho de Registro de Arquitetos ou equivalente), pesquisador habilitado.

**Outros profissionais regulamentados:** Qualquer profissional regulamentado por um órgão estatutário cujo registro seja pesquisável publicamente e cujos membros estejam sujeitos a processos de aptidão para exercer. Em caso de dúvida, entre em contato conosco antes de realizar verificações.

Em todos os casos, você deve estar em bom estado (não sujeito a suspensão, restrição ou processos disciplinares em curso que afetem sua aptidão para verificar identidade).

### 8.3 Registro

Para se registrar como verificador:

1. Publique um evento de credencial de verificador de tipo 31000 no Nostr contendo sua categoria profissional, jurisdição, órgão de licenciamento e referência de licença.
2. Obtenha pelo menos duas atestações de outros profissionais Signet verificados de pelo menos duas profissões diferentes (a atestação entre profissões evita anéis de conluio de única profissão).
3. O registro não implica endosso da nossa parte.

### 8.4 Realizando Verificações de Nível 3 (Adulto)

Ao realizar uma verificação de Nível 3 (Adulto), você deve:

1. Verificar a identidade pessoalmente, ou por meio de um processo remoto legalmente equivalente expressamente permitido por lei na jurisdição relevante. A verificação remota é a exceção, não o padrão.
2. Inspecionar pelo menos um documento de identificação fotográfica original emitido pelo governo (passaporte, carteira de identidade nacional ou carteira de motorista). A inspeção digital de documentos (incluindo credenciais de carteira eIDAS onde disponíveis) é permitida quando a lei nacional a trata como equivalente à inspeção física.
3. Confirmar que a pessoa diante de você corresponde ao documento.
4. Confirmar (ou rejeitar) os dados que o sujeito pré-inseriu no Aplicativo. Você está confirmando o que vê; não está inserindo dados em nome do sujeito.
5. Calcular o nullifier do documento e, quando múltiplos documentos são apresentados, a família de nullifiers.
6. Emitir a credencial de Pessoa Natural (tipo 31000) e a credencial de Persona (tipo 31000) via a cerimônia das duas credenciais.
7. Descartar o número do documento após o cálculo do nullifier. Não o armazene a menos que suas obrigações profissionais exijam independentemente.
8. Manter registros da verificação (data, local, identidade do sujeito, documentos inspecionados, hash do nullifier, ambas as chaves públicas) pelo período exigido pelas suas obrigações profissionais — normalmente pelo menos seis anos.

**Métodos de confirmação e peso de IQ:**

| Método | Descrição | Peso de contribuição de IQ |
|---|---|---|
| A — Presencial, documento físico | Você inspeciona fisicamente um documento original e a pessoa juntos, face a face | Peso total |
| B — Presencial, documento digital | Reunião presencial; o sujeito apresenta uma carteira eIDAS ou identidade digital governamental equivalente | Peso total (onde a lei trata como equivalente) |
| C — Remoto, regulamentado | Videochamada com aprovação regulatória e verificação de vivacidade; documentos originais entregues por courier ou exibidos em alta resolução | Peso reduzido |
| D — Remoto, não regulamentado | Qualquer processo remoto não coberto por C | Não permitido para Nível 3 ou Nível 4 |

O método de verificação é registrado na credencial (tag `["method", "in-person-id"]` ou equivalente). Clientes e partes confiantes podem restringir a aceitação a determinados métodos.

### 8.5 Realizando Verificações de Nível 4 (Adulto + Menor)

Ao realizar uma verificação de Nível 4 (Adulto + Menor), você deve cumprir todas as obrigações do Nível 3 e adicionalmente:

1. **Verificar a identidade do menor** usando documentos apropriados (certidão de nascimento, passaporte ou outros documentos adequados ao seu julgamento profissional).
2. **Verificar o relacionamento pai-guardião** através de documentação: certidão de nascimento (pai biológico), ordem de guarda emitida pelo tribunal (tutor legal), documentos de adoção (pai adotivo) ou ordem de responsabilidade de padrasto.
3. **Professores e verificadores escolares:** Você pode usar seu conhecimento profissional e os registros de matrícula da escola (que já incorporam verificação de certidão de nascimento) como evidência em substituição ou além de documentos originais. A data de nascimento da criança já está nos registros da escola. Um pai apresentando seu passaporte em uma reunião de pais é suficiente para uma verificação de Nível 4 na mesma sessão.
4. **Obter consentimento parental** para a credencial da criança, documentado em conformidade com a lei de proteção à criança aplicável.
5. **Realizar a verificação com a criança presente** onde possível.
6. **Avaliar o bem-estar da criança.** Exercer seu julgamento profissional para identificar quaisquer indicadores de coerção, exploração ou preocupação com salvaguarda. Se surgir qualquer preocupação, não prossiga e siga suas obrigações de comunicação obrigatória nos termos da lei aplicável.
7. Emitir duas credenciais para o menor (Pessoa Natural + Persona), ambas carregando a prova de faixa etária do menor e tags de guardião vinculando o menor ao seu pai ou guardião verificado.

### 8.6 Ações Proibidas do Verificador

Você não deve:

1. Emitir credenciais para alguém cuja identidade você não confirmou genuinamente
2. Aceitar pagamento, presentes ou outra consideração em troca de emitir verificações injustificadas
3. Permitir que qualquer outra pessoa realize verificações usando suas credenciais ou chave Nostr
4. Realizar verificações para familiares ou associados pessoais próximos sem divulgação prévia e aprovação
5. Autoverificar — emitir credenciais de Nível 3 ou Nível 4 para si mesmo
6. Reter cópias de documentos de identidade além do que suas obrigações profissionais exigem
7. Usar dados obtidos durante verificações para qualquer finalidade que não seja a verificação em si e a manutenção de registros exigida
8. Divulgar detalhes de verificações a qualquer terceiro, exceto conforme exigido por lei

### 8.7 Obrigações de Comunicação do Verificador

Você deve reportar prontamente a nós:

- Qualquer comprometimento ou suspeita de comprometimento da sua chave privada Nostr
- Qualquer descoberta de que você anteriormente emitiu uma verificação fraudulenta ou errônea
- Qualquer mudança no seu status de registro profissional (suspensão, restrição, revogação, processos disciplinares)
- Qualquer violação de dados que afete seus registros de verificação
- Qualquer processo legal, investigação ou ação regulatória relacionada às suas atividades de verificação
- Qualquer conflito de interesse surgindo em conexão com uma verificação

### 8.8 Responsabilidade do Verificador

Você é independentemente responsável pela precisão e integridade das suas verificações. Como você está confirmando dados inseridos pelo sujeito, sua responsabilidade é especificamente por:

- Confirmar dados que você não verificou de fato, ou que sabia ou tinha razão para saber que eram incorretos
- Falha em identificar falsificação de documento que um profissional razoavelmente competente na sua área teria identificado
- Falha em identificar preocupações com salvaguarda em verificações de Nível 4
- Violação das suas obrigações profissionais e da lei aplicável

Não supervisionamos, endossamos ou garantimos a qualidade do trabalho de qualquer verificador individual. Não somos solidária ou vicamente responsáveis pelos seus atos ou omissões. Você é um profissional independente, não nosso funcionário, agente ou parceiro.

### 8.9 Seguro

Você deve manter seguro de responsabilidade profissional adequado para suas atividades de verificação. O nível adequado depende dos requisitos existentes da sua profissão. Se a sua profissão já exige seguro de responsabilidade profissional (como a maioria das profissões na Seção 8.2 exige), essa cobertura deve se estender às suas atividades de verificação Signet desde que se enquadrem no âmbito da sua prática profissional geral.

### 8.10 Rescisão do Verificador

Seu status de verificador pode ser rescindido:

**Imediatamente e sem aviso se:** sua licença profissional for suspensa ou revogada; você emitiu verificações fraudulentas; sua chave privada Nostr foi comprometida; você violou obrigações de segurança infantil; ou você cometeu um crime relacionado às suas atividades de verificação.

**Com 30 dias de aviso se:** você viola materialmente estes Termos e não corrige em 14 dias; você não atende mais aos requisitos de elegibilidade; ou o Protocolo é descontinuado.

Após a rescisão, sua credencial de verificador de tipo 31000 é revogada. As credenciais anteriormente emitidas permanecem válidas a menos que sejam individualmente revogadas. Você deve manter os registros de verificação pelo período de retenção exigido.

---

## 9. Operadores de Sites e o SDK signet-verify.js

### 9.1 A Quem Esta Seção Se Aplica

Esta seção se aplica a qualquer pessoa ou organização que integre o SDK signet-verify.js ou de outra forma chame APIs do Signet Protocol de um site ou aplicativo para verificar a identidade ou idade de seus usuários ("Operadores de Sites").

### 9.2 O que o SDK Fornece

Quando um usuário apresenta uma credencial Signet ao seu site através do SDK, você recebe:

- Uma prova de faixa etária (por exemplo, "18+", "13–17") — matematicamente verificada
- A pontuação Signet IQ do usuário
- O nível de credencial
- Um carimbo de tempo de verificação

Você não recebe:

- O nome real do usuário
- A data de nascimento ou idade do usuário
- O tipo ou número do documento do usuário
- O endereço do usuário ou qualquer outra informação de identificação pessoal
- A identidade do verificador

O SDK é projetado para que você receba o mínimo de informação necessária para tomar uma decisão de acesso por idade ou identidade.

### 9.3 Obrigações do Operador de Site

Ao integrar o SDK, você concorda em:

1. **Sem armazenamento além da sessão.** Você não deve armazenar dados de prova, afirmações de faixa etária ou pontuações Signet IQ além da duração da sessão do usuário, a menos que tenha uma base jurídica específica para fazê-lo sob a lei de proteção de dados aplicável e tenha divulgado isso aos seus usuários.
2. **Sem reidentificação.** Você não deve tentar reidentificar usuários a partir dos dados de prova, ou combinar dados de prova com outros dados para identificar usuários.
3. **Sem criação de perfis.** Você não deve usar dados de prova para construir perfis do histórico de verificação ou estados de credencial dos usuários.
4. **Apenas dependência precisa.** Você deve depender apenas da prova para o propósito que ela fornece — confirmar que um usuário atende a um limite de idade ou identidade. Você não deve representar a terceiros que verificou a identidade real do usuário.
5. **Aviso de privacidade.** Você deve divulgar no seu aviso de privacidade que usa verificação de credencial Signet e descrever quais dados você recebe e como os usa.
6. **Sem manipulação.** Você não deve usar o SDK de uma forma projetada para contornar suas proteções de privacidade ou manipular usuários para apresentar credenciais que de outra forma não apresentariam.
7. **Conformidade.** Você deve cumprir todas as leis aplicáveis, incluindo leis de proteção de dados (RGPD, UK GDPR, CCPA/CPRA e equivalentes), no seu uso do SDK.

### 9.4 Licença do SDK

O SDK signet-verify.js é disponibilizado sob a mesma licença de código aberto que a especificação do Protocolo (veja o repositório do Protocolo). Você deve cumprir os termos da licença.

### 9.5 Sem Endosso

A integração do SDK não implica endosso do seu site ou serviço por nossa parte. Você não deve declarar que o Signet endossa ou certifica o seu serviço.

---

## 10. O Bot de Verificação

### 10.1 O que É

O bot de verificação Signet ("o Bot") é um serviço automatizado que monitora a rede Nostr em busca de eventos de credencial de tipo 31000 e fornece resumos de verificação de credencial mediante solicitação. O Bot pode publicar respostas a consultas, publicar resumos periódicos ou responder a menções.

### 10.2 O que Ele Processa

O Bot processa apenas eventos Nostr públicos. Ele lê eventos de tipos 31000, 31000, 30078, 31000, 31000, 31000 e 31000 de relays públicos. Ele não acessa sua chave privada, sua mnemônica ou quaisquer dados armazenados localmente no Aplicativo.

O Bot calcula pontuações Signet IQ a partir de dados públicos na cadeia. Ele não coleta ou armazena dados pessoais além do que é publicado em eventos Nostr públicos.

### 10.3 Quem o Opera

O Bot é operado pela equipe do Protocolo. Sua chave pública Nostr é publicada no repositório do Protocolo. Terceiros podem executar bots de verificação compatíveis usando a especificação de Protocolo de código aberto; bots de terceiros não são operados por nós e não são nossa responsabilidade.

### 10.4 Limitações do Bot

O Bot fornece um serviço de melhor esforço. Pode ficar para trás do estado em tempo real do relay. Não garante que sua saída reflita todos os eventos atuais de credencial ou revogação em todos os relays. Partes confiantes que tomam decisões de controle de acesso devem consultar os relays diretamente, não depender apenas da saída do Bot.

---

## 11. Pontuações Signet IQ

### 11.1 O que É o Signet IQ

A pontuação Signet IQ (0–200) é uma pontuação de reputação contínua derivada de dados na cadeia. Uma pontuação de 100 representa uma linha de base equivalente ao padrão de identidade governamental atual do UK/EUA. Pontuações acima de 100 refletem múltiplas verificações, forte confiança entre pares, pontes de identidade e longevidade da conta.

### 11.2 Como É Calculado

A pontuação é calculada a partir de contribuições ponderadas incluindo:

- Verificação profissional de Nível 3 ou Nível 4 (maior peso)
- Verificação cruzada por profissionais independentes adicionais
- Atestações presenciais de usuários com alto IQ
- Pontes de identidade (tipo 31000)
- Idade e atividade da conta
- Pontuação de confiança do verificador (veja a Seção 11.3)

O peso da atestação escala com o próprio Signet IQ do atestante. Uma atestação de alguém com IQ 150 carrega mais peso do que uma atestação de alguém com IQ 40.

### 11.3 Pontuações de Confiança do Verificador

Cada verificador profissional tem uma pontuação de confiança que alimenta a contribuição de IQ das credenciais que emitiram. A pontuação de confiança é derivada de:

- Método de confirmação (Método A carrega peso total; Método C carrega peso reduzido — veja a Seção 8.4)
- Número de verificações cruzadas independentes de seus sujeitos por outros verificadores
- O Índice de Percepção de Corrupção (IPC) da jurisdição — credenciais de jurisdições com pontuações IPC mais baixas carregam menos peso, não por discriminação, mas porque a confiança estatística objetiva no processo de verificação é menor
- Detecção de anomalias (por exemplo, 30 verificações em uma hora, agrupamento temporal rápido, padrões suspeitos de nullifier)

### 11.4 Decaimento

A contribuição de IQ de uma credencial decai conforme:

- A data de vencimento da credencial se aproxima
- A data de vencimento do documento subjacente se aproxima (decaimento mais rápido)
- A pontuação de confiança do verificador cai (por exemplo, devido a fraude descoberta)

O decaimento é gradual. Não há encerramento abrupto.

### 11.5 Isenção de Responsabilidade

A pontuação Signet IQ é uma métrica calculada com base em dados públicos disponíveis na cadeia. Não constitui uma avaliação definitiva de confiabilidade, identidade ou caráter. Não garantimos que qualquer pontuação Signet IQ reflita com precisão a confiabilidade de qualquer usuário.

---

## 12. Proteção de Dados

### 12.1 Dados Pessoais que o Protocolo Não Coleta

O Signet Protocol é projetado para não coletar ou publicar seus dados pessoais. Seu nome, data de nascimento, nacionalidade e número de documento são:

- Nunca publicados na rede Nostr
- Nunca transmitidos aos nossos servidores
- Armazenados localmente no seu dispositivo em forma criptografada (AES-256-GCM, chave derivada via PBKDF2 600.000 iterações)
- Acessíveis apenas após autenticação biométrica ou por PIN bem-sucedida

### 12.2 O que É Publicado na Cadeia

Os seguintes dados são publicados na rede Nostr (público por design):

- Sua chave pública Nostr (npub)
- Seu nível e tipo de credencial
- Sua raiz Merkle (um hash criptográfico — não revela atributos pessoais)
- Seu nullifier de documento (um hash unidirecional — não revela detalhes do documento)
- Sua prova de faixa etária (por exemplo, "18+" — não revela sua idade)
- Metadados de credencial do verificador (profissão, jurisdição, referência do órgão de licenciamento)
- Atestações
- Eventos de delegação

Uma vez publicados no Nostr, esses eventos são públicos e podem ser replicados por operadores de relay. Não podemos excluir ou modificar eventos publicados.

### 12.3 Armazenamento Local de Dados

Dados armazenados localmente no Aplicativo (mnemônica, chaves privadas, detalhes de documentos usados para calcular a árvore Merkle) são armazenados no IndexedDB em forma criptografada. Nunca são armazenados em texto simples. A chave de criptografia é protegida pela sua biometria ou PIN.

### 12.4 Verificadores como Controladores de Dados Independentes

Quando um verificador profissional inspeciona seus documentos de identidade e mantém registros de verificação, ele o faz como controlador de dados independente. Seu processamento é regido pelas suas obrigações profissionais e pela lei de proteção de dados aplicável (UK GDPR, RGPD, CCPA/CPRA ou equivalente), não por nós.

### 12.5 Proteção de Dados por Jurisdição

| Jurisdição | Lei Aplicável |
|---|---|
| Reino Unido | UK GDPR, Lei de Proteção de Dados de 2018 |
| União Europeia | RGPD (Regulamento 2016/679) |
| Estados Unidos | CCPA/CPRA (Califórnia), leis estaduais de privacidade |
| Brasil | LGPD |
| Índia | Lei DPDP 2023 |
| Austrália | Lei de Privacidade de 1988 |
| Japão | APPI |
| Coreia do Sul | PIPA |
| EAU | Decreto-Lei Federal nº 45 de 2021 |
| Outros | Lei nacional ou regional aplicável de proteção de dados |

### 12.6 Direitos dos Titulares de Dados da UE/UK

Se você estiver na UE ou no UK, tem o direito de acessar, retificar, apagar, restringir o processamento e portar seus dados pessoais. Como o Protocolo é projetado para minimizar a coleta de dados, os dados que detemos sobre você são limitados. Entre em contato conosco no endereço da Seção 21 para exercer seus direitos.

### 12.7 Resolução de Disputas Online da UE

Se você for consumidor na UE, pode registrar uma reclamação através da plataforma de Resolução de Disputas Online da UE: [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

---

## 13. Propriedade Intelectual

### 13.1 Especificação do Protocolo

A especificação do Signet Protocol é lançada sob uma licença de código aberto conforme especificado no repositório do Protocolo. É concedida a você uma licença para usar, implementar e construir sobre o Protocolo de acordo com essa licença.

### 13.2 Marcas Registradas

"The Signet Protocol", "Signet" e "My Signet" e os logotipos associados são marcas registradas. Você não pode usar essas marcas de maneira que implique endosso ou afiliação sem consentimento prévio por escrito, exceto para referência descritiva precisa ao Protocolo ou ao Aplicativo.

### 13.3 Conteúdo do Usuário

Você retém a propriedade de qualquer conteúdo que você cria usando o Protocolo (credenciais, atestações, eventos de delegação). Ao publicar eventos na rede Nostr, você reconhece que esses eventos são públicos e podem ser armazenados e replicados por operadores de relay.

### 13.4 SDK

O SDK signet-verify.js é disponibilizado sob a licença de código aberto especificada no repositório do Protocolo. O uso comercial é permitido de acordo com essa licença.

### 13.5 Contribuições

As contribuições para a especificação do Protocolo ou código de implementação estão sujeitas ao acordo de licença de contribuidor no repositório do Protocolo.

---

## 14. Isenções de Responsabilidade

### 14.1 Protocolo Fornecido "Como Está"

O PROTOCOLO, O APLICATIVO E O SDK SÃO FORNECIDOS "COMO ESTÃO" E "COMO DISPONÍVEIS" SEM GARANTIAS DE QUALQUER TIPO, EXPRESSAS OU IMPLÍCITAS, INCLUINDO, MAS NÃO SE LIMITANDO A GARANTIAS IMPLÍCITAS DE COMERCIALIZAÇÃO, ADEQUAÇÃO A UM PROPÓSITO PARTICULAR, TÍTULO E NÃO INFRAÇÃO.

### 14.2 Sem Garantia de Precisão

NÃO GARANTIMOS QUE:

- QUALQUER CREDENCIAL SEJA PRECISA, COMPLETA OU CONFIÁVEL
- QUALQUER VERIFICADOR SEJA COMPETENTE, HONESTO OU DEVIDAMENTE LICENCIADO
- O PROTOCOLO FUNCIONARÁ SEM INTERRUPÇÃO OU ERRO
- OS COMPONENTES CRIPTOGRÁFICOS PERMANECERÃO SEGUROS INDEFINIDAMENTE
- QUALQUER PONTUAÇÃO SIGNET IQ REFLITA COM PRECISÃO A CONFIABILIDADE DE QUALQUER USUÁRIO
- O SDK ATENDERÁ AOS REQUISITOS DE CONFORMIDADE LEGAL DE QUALQUER PARTE CONFIANTE EM PARTICULAR

### 14.3 Isenção de Responsabilidade de Descentralização

Como o Protocolo opera em uma rede descentralizada, nós:

- Não podemos controlar, monitorar ou censurar a atividade do Protocolo
- Não podemos reverter ou modificar eventos publicados
- Não podemos garantir a disponibilidade ou desempenho de qualquer relay
- Não podemos fazer cumprir estes Termos contra todos os participantes globalmente
- Não podemos ser responsáveis pela conduta de operadores de relay independentes

### 14.4 Isenção de Responsabilidade Criptográfica

Nenhum sistema criptográfico é comprovadamente seguro contra todos os ataques futuros. Avanços em computação (incluindo computação quântica) podem afetar a segurança dos componentes criptográficos do Protocolo. Pretendemos suportar a migração pós-quântica, mas não podemos garantir cronogramas específicos.

### 14.5 Isenção de Responsabilidade Regulatória

O cenário regulatório para identidade descentralizada e provas de conhecimento zero está evoluindo. As obrigações de conformidade podem mudar. Recursos do Protocolo podem tornar-se sujeitos a novas regulamentações.

---

## 15. Limitação de Responsabilidade

### 15.1 Limitação Geral

NA MÁXIMA EXTENSÃO PERMITIDA PELA LEI APLICÁVEL, NÓS, NOSSOS DIRETORES, EXECUTIVOS, FUNCIONÁRIOS, AGENTES E AFILIADOS NÃO SEREMOS RESPONSÁVEIS POR QUAISQUER DANOS INDIRETOS, INCIDENTAIS, ESPECIAIS, CONSEQUENCIAIS, PUNITIVOS OU EXEMPLARES, INCLUINDO PERDA DE LUCROS, FUNDO DE COMÉRCIO, DADOS OU OUTRAS PERDAS INTANGÍVEIS, INDEPENDENTEMENTE DE TERMOS SIDO AVISADOS DA POSSIBILIDADE DE TAIS DANOS.

### 15.2 Limite de Responsabilidade

NA MÁXIMA EXTENSÃO PERMITIDA PELA LEI APLICÁVEL, NOSSA RESPONSABILIDADE TOTAL AGREGADA POR TODAS AS RECLAMAÇÕES DECORRENTES DE OU RELACIONADAS A ESTES TERMOS OU AO PROTOCOLO NÃO EXCEDERÁ O MAIOR ENTRE: (A) O VALOR QUE VOCÊ PAGOU A NÓS NOS 12 MESES ANTERIORES À RECLAMAÇÃO, OU (B) £100.

### 15.3 Exceções

As limitações acima não se aplicam a:

- Responsabilidade que não pode ser excluída ou limitada sob a lei aplicável
- Responsabilidade decorrente de conduta dolosa ou fraude
- Responsabilidade por morte ou lesão pessoal causada por negligência (em jurisdições onde a limitação é proibida)
- Direitos estatutários do consumidor que não podem ser renunciados por contrato

### 15.4 Proteção do Consumidor

Nada nestes Termos afeta seus direitos estatutários como consumidor sob as leis de proteção ao consumidor aplicáveis.

---

## 16. Indenização

### 16.1 Suas Obrigações de Indenização

Você concorda em indenizar, defender e isentar de responsabilidade a nós por quaisquer reclamações, danos, perdas, responsabilidades, custos e despesas (incluindo honorários advocatícios razoáveis) decorrentes de ou relacionados a:

1. Seu uso do Protocolo
2. Sua violação destes Termos
3. Sua violação de qualquer lei aplicável
4. Sua violação de quaisquer direitos de terceiros
5. Credenciais que você cria, incluindo credenciais falsas ou enganosas
6. Atestações que você emite
7. Verificações que você realiza (se você for verificador)
8. Seu uso do SDK e quaisquer reclamações apresentadas por seus usuários em conexão com ele

### 16.2 Procedimento de Indenização

Notificaremos você prontamente sobre qualquer reclamação, forneceremos cooperação razoável e permitiremos que você controle a defesa e resolução da reclamação, desde que você não resolva qualquer reclamação que imponha obrigações a nós sem nosso consentimento prévio por escrito.

---

## 17. Lei Aplicável e Resolução de Disputas

### 17.1 Lei Aplicável

Estes Termos são regidos e interpretados de acordo com as leis da Inglaterra e do País de Gales, sem levar em conta as disposições sobre conflito de leis.

### 17.2 Resolução de Disputas

**Passo 1 — Negociação:** As partes tentarão primeiro resolver qualquer disputa por meio de negociação de boa fé por 30 dias.

**Passo 2 — Mediação:** Se a negociação falhar, as partes submeterão à mediação administrada pelo Centre for Effective Dispute Resolution (CEDR) de acordo com suas regras.

**Passo 3 — Arbitragem:** Se a mediação falhar, a disputa será resolvida definitivamente por arbitragem vinculante administrada pela London Court of International Arbitration (LCIA) sob suas regras. A sede da arbitragem é Londres. O idioma é inglês. A sentença é final e vinculante.

### 17.3 Renúncia a Ação Coletiva

NA MÁXIMA EXTENSÃO PERMITIDA PELA LEI APLICÁVEL, VOCÊ CONCORDA EM RESOLVER DISPUTAS APENAS EM BASE INDIVIDUAL E NÃO EM AÇÃO COLETIVA, CONSOLIDADA OU REPRESENTATIVA. SE ESSA RENÚNCIA FOR INEXEQUÍVEL, A DISPOSIÇÃO DE ARBITRAGEM É NULA E SEM EFEITO.

### 17.4 Exceções

Qualquer uma das partes pode buscar medida cautelar em qualquer tribunal de jurisdição competente para proteger propriedade intelectual ou prevenir danos irreparáveis.

### 17.5 Direitos do Consumidor da UE

Se você for consumidor na UE, também pode usar seus tribunais nacionais e a plataforma ODR da UE: [https://ec.europa.eu/consumers/odr](https://ec.europa.eu/consumers/odr).

### 17.6 Questões Regulatórias Profissionais do Verificador

Nada nestes Termos restringe a jurisdição de qualquer órgão regulador profissional sobre um verificador, o direito de um verificador de buscar orientação do seu órgão regulador, ou nosso direito de reportar preocupações ao órgão regulador de um verificador.

---

## 18. Rescisão

### 18.1 Seu Direito de Rescindir

Você pode parar de usar o Protocolo a qualquer momento. Devido à natureza descentralizada do Protocolo, eventos anteriormente publicados podem permanecer nos relays Nostr indefinidamente.

### 18.2 Nossos Direitos

Reservamo-nos o direito de:

- Revogar credenciais de verificador por causa justa (conforme descrito na Seção 8.10)
- Publicar avisos comunitários sobre credenciais ou atores fraudulentos
- Modificar ou descontinuar a especificação do Protocolo

### 18.3 Efeito da Rescisão

Após a rescisão:

- Seu direito de usar quaisquer componentes proprietários do Aplicativo cessa
- As Seções 8 (obrigações do verificador — a manutenção de registros sobrevive), 12, 13, 14, 15, 16, 17 e 20 sobrevivem
- Eventos Nostr anteriormente publicados não são afetados

---

## 19. Alterações

### 19.1 Direito de Alterar

Podemos modificar estes Termos a qualquer momento. As modificações são eficazes mediante:

- Publicação dos Termos atualizados no repositório do Protocolo
- Um anúncio de evento Nostr referenciando os Termos atualizados
- 30 dias de aviso para alterações materiais

### 19.2 Aceitação das Alterações

Seu uso continuado do Protocolo após a data de vigência constitui aceitação. Se você não concordar, deve parar de usar o Protocolo.

### 19.3 Alterações Materiais

Para alterações materiais, forneceremos:

- Aviso claro sobre a natureza das alterações
- Um resumo em linguagem simples das principais alterações
- Pelo menos 30 dias antes de as alterações entrarem em vigor

---

## 20. Disposições Gerais

### 20.1 Acordo Integral

Estes Termos constituem o acordo integral entre você e nós em relação ao Protocolo. Eles substituem o Acordo de Verificador publicado separadamente (que agora está incorporado aqui como Seção 8). Se você anteriormente executou um Acordo de Verificador autônomo, estes Termos o substituem a partir da Data de Vigência.

### 20.2 Divisibilidade

Se qualquer disposição for considerada inválida ou inexequível, será aplicada na máxima extensão permitida. As disposições restantes permanecem em pleno vigor.

### 20.3 Renúncia

O não cumprimento de qualquer disposição não constitui renúncia.

### 20.4 Cessão

Você não pode ceder estes Termos sem nosso consentimento prévio por escrito. Podemos ceder estes Termos sem o seu consentimento.

### 20.5 Força Maior

Nenhuma das partes é responsável por falha ou atraso devido a causas além do seu controle razoável, incluindo desastres naturais, guerra, terrorismo, pandemias, ação governamental, falhas de rede, comprometimentos de algoritmo criptográfico ou interrupções de relay Nostr.

### 20.6 Notificações

Notificações para nós: veja a Seção 21. Notificações para você: quaisquer informações de contato que você forneceu, ou via evento Nostr ou repositório do Protocolo.

### 20.7 Beneficiários Terceiros

Estes Termos não criam direitos de beneficiários terceiros, exceto que os operadores de relay da rede Nostr e os usuários do Protocolo que dependem de credenciais emitidas por verificadores são beneficiários pretendidos da Seção 8.

### 20.8 Conformidade com Exportação

Você deve cumprir todas as leis de exportação e sanções aplicáveis. Os componentes criptográficos do Protocolo podem estar sujeitos a controles de exportação em certas jurisdições.

### 20.9 Títulos

Os títulos das seções são apenas para conveniência e não afetam a interpretação.

---

## 21. Contato

Para perguntas sobre estes Termos, para exercer direitos de proteção de dados, ou para reportar problemas de segurança:

**The Signet Protocol**
E-mail: admin@forgesworn.dev
Divulgações de segurança: admin@forgesworn.dev
Repositório: https://github.com/forgesworn/signet-protocol

---

## 22. Anexos Específicos por Jurisdição

### Anexo A — Reino Unido

**Órgãos de licenciamento:** Law Society of England and Wales, Law Society of Scotland, Law Society of Northern Ireland, Bar Council of England and Wales, Faculty of Advocates, General Medical Council (GMC), Nursing and Midwifery Council (NMC), General Dental Council (GDC), General Pharmaceutical Council (GPhC), Health and Care Professions Council (HCPC), Teaching Regulation Agency (TRA), General Teaching Council for Scotland (GTCS), Architects Registration Board (ARB), Institute of Chartered Accountants in England and Wales (ICAEW), Institute of Chartered Accountants of Scotland (ICAS), Association of Chartered Certified Accountants (ACCA), Financial Conduct Authority (FCA) — pessoas autorizadas, Faculty Office of the Archbishop of Canterbury (notários públicos).

**Responsabilidade profissional:** Conforme exigido pela SRA, FCA, GMC, TRA ou o órgão regulador relevante.

**Segurança infantil:** Children Act 1989 e 2004; Safeguarding Vulnerable Groups Act 2006; DBS Enhanced Check exigido para professores e outras funções de atividade regulamentada que realizam verificações de Nível 4; comunicação obrigatória nos termos do Working Together to Safeguard Children (2023).

**Proteção de dados:** UK GDPR; Data Protection Act 2018; orientação do ICO; orientação do DSIT sobre dados biométricos.

**Verificação de idade:** Online Safety Act 2022 (garantia de idade aprovada pela Ofcom). Verificação profissional presencial de Nível 4 supera os métodos aceitos pela Ofcom.

### Anexo B — Estados Unidos

**Órgãos de licenciamento:** Associações estaduais de advogados; conselhos médicos estaduais; comissões notariais estaduais; departamentos estaduais de educação (professores); reguladores financeiros estaduais relevantes.

**Nota:** A elegibilidade e as obrigações variam significativamente por estado. Você deve cumprir a lei do(s) estado(s) onde realiza verificações.

**Segurança infantil:** COPPA (Children's Online Privacy Protection Act); FERPA (para verificadores escolares); obrigações estaduais de comunicador obrigatório; estatutos estaduais de proteção à criança. Os registros de matrícula escolar mantidos por um professor podem servir como evidência documental para verificações de Nível 4 onde a lei estadual permitir.

**Proteção de dados:** CCPA/CPRA (Califórnia); Virginia CDPA; outras leis estaduais de privacidade; FERPA (registros escolares). Um Acordo de Processamento de Dados separado pode ser exigido para usuários residentes na Califórnia.

### Anexo C — União Europeia

**Órgãos de licenciamento:** Ordens dos advogados nacionais, conselhos médicos, câmaras notariais e seus equivalentes em cada estado-membro.

**Nota:** Os requisitos específicos variam por estado-membro. Os verificadores devem cumprir a lei do estado-membro onde estão estabelecidos e onde realizam verificações.

**eIDAS 2.0:** O identificador único de pessoa do eIDAS, quando apresentado via carteira eIDAS emitida pelo governo, pode servir como fonte de nullifier adicional. A fórmula do nullifier é `SHA-256(LP("eidas") || LP(eidas_unique_id) || LP("signet-nullifier-v2"))`.

**Segurança infantil:** RGPD Artigo 8; legislação nacional de implementação; Regulamento (UE) 2022/2065 (DSA) obrigações de verificação de idade.

**Proteção de dados:** RGPD (Regulamento 2016/679); legislação nacional de implementação; orientação da APD nacional.

### Anexo D — Austrália

**Órgãos de licenciamento:** Sociedades de advogados estaduais e territoriais; Australian Health Practitioner Regulation Agency (AHPRA) para saúde médica e afins; departamentos de justiça estaduais/territoriais (notários); órgãos relevantes de registro de professores estaduais.

**Segurança infantil:** Working With Children Check conforme aplicável à função; Online Safety Act 2021; estatutos estaduais de proteção à criança.

**Proteção de dados:** Privacy Act 1988; Australian Privacy Principles; Consumer Data Right (CDR) onde aplicável.

### Anexo E — Japão

**Órgãos de licenciamento:** Japan Federation of Bar Associations (JFBA); Ministry of Justice (notários); Japan Medical Association; autoridades relevantes de registro de ensino.

**Segurança infantil:** Diretrizes APPI; legislação nacional de proteção à criança; obrigações de trabalho com jovens.

**Proteção de dados:** Act on the Protection of Personal Information (APPI) e suas emendas.

### Anexo F — Coreia do Sul

**Órgãos de licenciamento:** Korean Bar Association; Korean Medical Association; ministérios governamentais relevantes para outras profissões regulamentadas.

**Segurança infantil:** Personal Information Protection Act (PIPA); Youth Protection Act; obrigações de comunicação obrigatória.

**Proteção de dados:** PIPA.

### Anexo G — Brasil

**Órgãos de licenciamento:** Ordem dos Advogados do Brasil (OAB); Conselho Federal de Medicina (CFM); câmaras notariais; conselhos profissionais federais e estaduais relevantes.

**Segurança infantil:** LGPD Artigo 14 (dados de menores — consentimento parental exigido); Estatuto da Criança e do Adolescente (ECA); obrigações de comunicação obrigatória.

**Proteção de dados:** Lei Geral de Proteção de Dados (LGPD); orientação da ANPD.

### Anexo H — Índia

**Órgãos de licenciamento:** Bar Council of India e conselhos estaduais de advogados; National Medical Commission (NMC); autoridades estaduais relevantes para outras profissões regulamentadas.

**Segurança infantil:** Digital Personal Data Protection Act 2023 (DPDP); Protection of Children from Sexual Offences Act (POCSO); obrigações de comunicação obrigatória.

**Proteção de dados:** DPDP Act 2023; regulamentos emitidos em conformidade.

### Anexo I — Emirados Árabes Unidos

**Órgãos de licenciamento:** Ministry of Justice; Dubai Health Authority (DHA) ou Health Authority Abu Dhabi (HAAD); autoridades profissionais relevantes do emirado.

**Segurança infantil:** Federal Law No. 3 of 2016 (Lei Wadeema — Lei de Direitos da Criança); obrigações de comunicação obrigatória.

**Proteção de dados:** Federal Decree-Law No. 45 of 2021 on Personal Data Protection; orientação do UAE Data Office.

---

*The Signet Protocol — v0.1.0 — março de 2026*
*Este documento é fornecido apenas para fins informativos. Não constitui aconselhamento jurídico. Consulte um advogado qualificado na sua jurisdição antes de utilizá-lo.*
