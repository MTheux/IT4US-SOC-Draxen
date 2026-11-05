# Critérios de aceite — piloto IT4US SOC EASM

**Versão:** 1.0  
**Data:** 2026-11-05  
**Estado:** critérios para implementação futura.

## Governança

- [ ] Nenhum seed entra em coleta sem projeto, owner, evidência de autorização, exclusões e validade.
- [ ] Seeds e exclusões vencidos suspendem novas consultas e qualquer validação ativa associada.
- [ ] Consulta passiva e verificação ativa são capacidades distintas; o modo ativo permanece desligado por padrão.

## Dados e Censys

- [ ] O produto registra provedor, dataset, identificador de consulta, datas e entitlement usado.
- [ ] API key nunca aparece no repositório, exportação, prompt ou log.
- [ ] Limites de plano, API, credits e permissões de redistribuição foram confirmados antes do piloto.
- [ ] Resposta externa preserva informação suficiente para auditoria e minimiza campos sem uso operacional.
- [ ] Associação incerta é marcada como candidata e não aparece como propriedade confirmada do cliente.

## SOC

- [ ] Cada item tem estado, confiança, timestamp, fonte, justificativa e responsável.
- [ ] Mudanças são comparadas com baseline e têm deduplicação/supressão configurável.
- [ ] Analista pode validar, descartar ou marcar fora de escopo com razão auditável.
- [ ] Score mostra seus fatores e não classifica automaticamente observação como vulnerabilidade confirmada.

## Cliente e isolamento

- [ ] Usuário cliente acessa somente seus projetos; verificações incluem alteração de IDs em rotas/API e exportação.
- [ ] Notas internas e dados de outros tenants não entram nas páginas ou relatórios do cliente.
- [ ] Evidência exportada está sanitizada e tem revisão humana registrada.
- [ ] Interface mostra fonte, frescor, confiança, limitações e distinção entre observado e validado.

## Operação

- [ ] Logs de auditoria cobrem acesso, alteração de escopo, revisão, exportação e administração.
- [ ] Há processo para rotação/revogação de credencial e resposta a uso anômalo da API.
- [ ] Falha do provedor, limite atingido e dado desatualizado aparecem como estado explícito, não como ausência de exposição.
- [ ] Fixtures sintéticas cobrem atribuição ambígua, dados antigos, mudança de ativo, limite de API e isolamento entre tenants.
- [ ] Não há alegação de produção ou cobertura total antes de piloto operacional e revisão de segurança.
