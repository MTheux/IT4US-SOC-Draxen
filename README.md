# IT4US SOC — Draxen EASM

Plano independente para uma capacidade de External Attack Surface Management (EASM) orientada ao SOC da IT4US, com Censys como fonte inicial de inteligência de ativos públicos.

## Objetivo

Entregar uma visão contínua, rastreável e apresentável da superfície externa de cada projeto, ajudando o SOC e o cliente a entender quais ativos foram observados, quais exposições merecem atenção e quais itens já foram validados pela equipe.

Este repositório contém somente a proposta e os artefatos próprios deste produto. Não contém código, dados, credenciais, configurações nem documentação interna do Draxen.

## Conteúdo

- [Plano de ação v1.0](docs/PLANO-DE-ACAO-v1.0-2026-11-05.md)
- [Arquitetura alvo](docs/ARQUITETURA-ALVO.md)
- [Experiência do cliente](docs/EXPERIENCIA-DO-CLIENTE.md)
- [Critérios de aceite](docs/CRITERIOS-DE-ACEITE.md)

## Princípios

- Separar descoberta passiva de validação ativa.
- Exigir autorização, escopo e validade antes de qualquer atividade ativa.
- Tratar registros de Censys como observações externas sujeitas a atraso, atribuição incorreta e infraestrutura compartilhada.
- Manter evidência, fonte, horário de observação, confiança e estado de validação para cada ativo e exposição.
- Isolar clientes e projetos; aplicar RBAC, auditoria e minimização de dados.
- Mostrar ao cliente o que foi observado, o que foi confirmado e o que ainda precisa de análise.
- Não automatizar exploração, autenticação, alteração de estado ou acesso a dados do cliente.

## Estado

Documento de planejamento. Não há integração Censys configurada, coleta em produção, scanner ativo, dashboard operacional ou validação de cliente neste repositório.

## Referências

- [Censys Platform API — início](https://docs.censys.com/reference/get-started)
- [Censys ASM API](https://docs.censys.com/docs/asm-api)
- [Censys Platform datasets](https://docs.censys.com/docs/platform-datasets)
- [Censys data access tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)
- [Referência de skill EASM enviada pela equipe](https://skillsmp.com/creators/xalgorix/xalgorix/internal-tools-skills-data-offensive-security-implementing-attack-surface-management)
