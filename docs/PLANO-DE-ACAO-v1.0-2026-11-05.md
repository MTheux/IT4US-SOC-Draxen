# Plano de ação — IT4US SOC EASM

**Versão:** 1.0  
**Data:** 2026-11-05  
**Estado:** console web self-hosted e CLI implementados; demonstração sintética executada e interface revisada no navegador. Consulta real Censys ainda depende de token, entitlement e escopo aprovado. Pronto para revisão técnica e piloto controlado; não declarar produção.

## Estado de implementação

- **Disponível:** console web SOC com projetos isolados, cadastro de cliente, aprovação independente, validade/exclusões, controles de coleta, inventário, candidatos de exposição, triagem, mudanças, histórico, usuários/papéis, auditoria e exports CSV/Markdown; projeto demo sintético; CLI e coletor Censys passivo opt-in; instalação local e Compose.
- **Pendente para o piloto:** credencial e entitlement Censys da IT4US; seed e autorização do projeto-piloto; primeira consulta real supervisionada; integração SSO/MFA; verificação formal do isolamento entre tenants; política de retenção, backup/restore e operação atrás do proxy corporativo.
- **Limite:** o MVP não executa scan ativo nem valida vulnerabilidades. A instalação mencionada pelo Fabio precisa de definição separada de fornecedor, sistema operacional e perfil de scan autorizado.

## 1. Resultado esperado

Criar uma capacidade EASM multi-projeto para o SOC da IT4US que mantenha inventário externo de ativos, destaque mudanças e exposições relevantes e produza uma visão segura e compreensível para cada cliente.

O primeiro corte usa Censys para descoberta e enriquecimento passivos. A validação ativa será uma etapa separada, vinculada ao escopo aprovado de cada projeto. Achados externos sem confirmação serão apresentados como observações ou hipóteses, nunca como vulnerabilidades confirmadas.

## 2. Escopo do primeiro release

### Incluído

- Cadastro de clientes, projetos, domínios-semente, organizações e outros identificadores aprovados.
- Registro da autorização, proprietário, escopo permitido, exclusões, validade e contato operacional.
- Consulta passiva de hosts, web properties e certificados que possam corresponder aos identificadores autorizados.
- Normalização, deduplicação e associação de ativos com proveniência e confiança.
- Histórico de observações e mudanças: ativo novo/desaparecido, serviço/porta alterado, certificado novo/próximo de expirar e mudança de banner ou tecnologia.
- Triagem SOC com estado, responsável, prioridade, evidência, decisão e justificativa.
- Dashboard interno e visão por projeto destinada ao cliente, com isolamento de acesso por tenant/projeto.
- Exportação de inventário CSV e resumo Markdown; revisar manualmente antes de compartilhar.

### Fora do primeiro release

- Varredura ativa de portas, exploração, tentativa de login, fuzzing, crawling autenticado ou alteração de sistemas.
- Atribuição automática de ativos a um cliente sem evidência suficiente.
- Uso de dados de um cliente para enriquecer a visão de outro.
- Execução de agentes/scanners em máquinas de clientes. A instalação mencionada pela equipe será tratada como trilha separada, com inventário do software, permissões mínimas, máquina autorizada, validação do fornecedor e janela aprovada.
- Alegações de cobertura completa da internet ou de ausência de exposição.

## 3. Fases e entregáveis

### Fase 0 — Descoberta e governança

**Ações**

1. Confirmar o caso de uso do SOC e os perfis que usarão a ferramenta: analista, supervisor, administrador e cliente.
2. Escolher um projeto-piloto e identificar quem pode aprovar o escopo e receber alertas.
3. Definir campos mínimos do cadastro: entidades legais, domínios-semente, aliases conhecidos, provedores/CDNs, exclusões, validade e evidência de autorização.
4. Consultar o plano/licenciamento Censys disponível e decidir entre Platform API, ASM API ou ingestão exportada. Não presumir equivalência entre produtos ou entitlements.
5. Definir retenção, controle de acesso, processo de revisão e modelo de entrega ao cliente.

**Saída:** decisão de piloto, owner por etapa, escopo aprovado e orçamento/licenças conhecidos.

### Fase 1 — Protótipo passivo

**Ações**

1. Integrar o adaptador Censys de leitura já implementado, com credenciais guardadas fora do código e dos logs.
2. Consultar apenas seeds do piloto que estejam documentados como autorizados.
3. Persistir resposta mínima, identificador do provedor, timestamp da consulta/observação, query, licença/entitlement e hash da evidência original.
4. Normalizar hosts, FQDNs, web properties, certificados, serviços e relações.
5. Criar estados `observado`, `candidato`, `em_triagem`, `validado`, `descartado` e `fora_do_escopo`.
6. Fazer revisão manual dos candidatos para medir precisão de atribuição e ruído de CDN, hosting compartilhado, subsidiárias e domínios terceirizados.

**Saída:** inventário passivo revisado e relatório de qualidade do piloto.

### Fase 2 — Triage SOC e mudanças

**Ações**

1. Implementar deduplicação e snapshots para comparar observações ao longo do tempo.
2. Criar fila de triagem com severidade operacional, confiança, criticidade do ativo, frescor do dado e explicação legível.
3. Alertar somente em mudanças acionáveis após aplicar limiar e supressão de ruído.
4. Registrar decisão humana, evidências e histórico de revisão.
5. Definir SLA de triagem por prioridade e procedimento de encaminhamento.

**Saída:** fila SOC operável em modo observação, com alertas testados por fixtures sintéticas.

### Fase 3 — Visão do cliente

**Ações**

1. Criar visão restrita por cliente/projeto, com ativos, mudanças, exposições e ações recomendadas.
2. Separar claramente dados de terceiros, dados incertos e itens confirmados.
3. Sanitizar banners e evidências para não expor segredos, dados pessoais, endereços internos ou material de outro tenant.
4. Adicionar exportação revisada e trilha de auditoria de visualização/download.
5. Validar linguagem, acessibilidade e utilidade com um cliente-piloto.

**Saída:** dashboard cliente revisado; sem publicação aberta por padrão.

### Fase 4 — Validação autorizada e expansão

**Ações**

1. Modelar tarefas ativas como solicitações separadas e bloqueadas por autorização vigente e escopo exato.
2. Exigir aprovação do operador, janela, rate limits, exclusões, ação permitida e plano de interrupção.
3. Começar com verificações não intrusivas de disponibilidade/configuração; exigir aprovação específica para qualquer técnica de maior impacto.
4. Preservar a diferença entre candidato externo, validação técnica e finding reportável.
5. Expandir por projeto somente após revisão de isolamento, custo, precisão, operação e suporte.

**Saída:** decisão formal de ampliar ou manter descoberta passiva.

## 4. Arquitetura funcional proposta

`cadastro e autorização → scheduler passivo → adaptador Censys → normalização e correlação → inventário/histórico → triagem SOC → alertas e dashboard por tenant → exportação revisada`

O adaptador deve suportar provedores substituíveis; Censys é a fonte inicial, não uma dependência estrutural de todo o produto. Ver [Arquitetura alvo](ARQUITETURA-ALVO.md).

## 5. Modelo de prioridade

A prioridade operacional deve combinar:

- criticidade do ativo definida pelo responsável do projeto;
- exposição observada (serviço, porta, tecnologia, certificado, indicador de risco disponível no entitlement);
- confiança de atribuição ao projeto;
- frescor da observação e idade da evidência;
- exploitabilidade conhecida, quando sustentada por fonte confiável e licença aplicável;
- alcance e impacto potencial para o negócio.

O score é apoio à triagem e deve mostrar seus fatores. Ele não transforma automaticamente um registro em vulnerabilidade confirmada nem substitui validação técnica.

## 6. Métricas do piloto

- Precisão da atribuição de ativos, auditada por amostra e por classe de relação.
- Percentual de ativos com fonte, timestamp, confiança e estado completos.
- Tempo entre nova observação e entrada na fila SOC.
- Taxa de candidatos descartados por falsa associação ou infraestrutura compartilhada.
- Tempo de triagem e taxa de alertas considerados acionáveis.
- Cobertura de revisão humana antes de exportação ao cliente.
- Falhas de isolamento entre tenants: meta zero nos casos de teste definidos.
- Custo de API/credits e limites do plano Censys observados no piloto.

## 7. Riscos e respostas

| Risco | Resposta |
|---|---|
| Ativo associado ao cliente errado | Proveniência, confiança, revisão humana e estado candidato; bloquear associação incerta no dashboard. |
| Dado Censys desatualizado | Exibir timestamp e fonte; nunca inferir que ausência de registro significa ausência de ativo. |
| CDN/hosting compartilhado | Marcar relação indireta; não atribuir IP compartilhado como ativo exclusivo sem evidência. |
| Uso indevido de API/licença | Verificar plano, entitlements, API terms e limites antes de integrar; impor cotas por tenant. |
| Exposição entre clientes | Tenant ID obrigatório em cada consulta/persistência; autorização no servidor; testes de isolamento e auditoria. |
| Credencial Censys vazada | Secret manager, rotação, escopo mínimo, redaction em logs e alerta de uso anômalo. |
| Escalada de observação para scan ativo | Fluxo separado, autorização com expiração e bloqueio padrão. |
| Confiança excessiva em score automatizado | Explicar fatores, conservar decisão humana e mostrar incerteza. |

## 8. Decisões pendentes para início do piloto

1. Qual projeto e entidade serão o piloto?
2. Quem aprova formalmente seeds, exclusões e validade do escopo?
3. Qual plano/produto Censys está contratado e quais APIs/dados estão habilitados?
4. O primeiro dashboard será somente interno ou haverá usuário cliente desde o piloto?
5. Qual retenção e canal de alerta são aprovados?
6. A instalação de agente de scan solicitada pela equipe é um produto específico? Qual fornecedor, versão, permissões e ambiente de execução?

## Referências técnicas

- [Censys Platform API — autenticação, termos e entitlement](https://docs.censys.com/reference/get-started)
- [Censys ASM API — chave de workspace e rate limit](https://docs.censys.com/docs/asm-api)
- [Datasets Censys: hosts, web properties e certificates](https://docs.censys.com/docs/platform-datasets)
- [Entitlements e limites por plano](https://docs.censys.com/docs/data-access-tiers-entitlements)
- [CenQL](https://docs.censys.com/docs/censys-query-language)
