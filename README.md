# IT4US SOC — Draxen EASM

MVP executável e independente para descoberta passiva de ativos externos com Censys, triagem SOC e geração de relatório. Este repositório não contém a estrutura nem o código interno do Draxen.

## Objetivo

Entregar ao Fabio e ao time SOC um fluxo que possa ser executado localmente: validar o escopo, consultar dados já observados pelo Censys, filtrar correspondências por domínio autorizado e gerar CSV/Markdown para triagem.

Este repositório contém somente a proposta e os artefatos próprios deste produto. Não contém código, dados, credenciais, configurações nem documentação interna do Draxen.

## Rodar agora — modo demonstração

Requer Python 3.10+; usa somente a biblioteca padrão.

```bash
python3 soc_easm.py init --out scope.json
python3 soc_easm.py collect --scope scope.json --source demo --out runs
```

O modo `demo` usa somente dados sintéticos e não faz chamadas de rede. Ele cria `observations.json`, `assets.csv` e `summary.md` em uma pasta de execução.

Para usar Censys de verdade, preencha `scope.json` com autorização vigente, seeds exatos e aprovador; configure `CENSYS_API_TOKEN` no ambiente seguro da máquina e execute:

```bash
python3 soc_easm.py validate --scope scope.json
python3 soc_easm.py collect --scope scope.json --source censys --live --out runs
```

O modo real exige autorização aprovada, referência, aprovador, validade e flag `--live`. Faz somente consultas à API de dados da Censys; não conecta aos ativos listados nem executa varredura ativa.

Consulte [Instalação e operação](docs/EXECUCAO-DO-AGENTE.md) antes de instalar em uma máquina do SOC.

## Conteúdo

- [Plano de ação v1.0](docs/PLANO-DE-ACAO-v1.0-2026-11-05.md)
- [Arquitetura alvo](docs/ARQUITETURA-ALVO.md)
- [Experiência do cliente](docs/EXPERIENCIA-DO-CLIENTE.md)
- [Critérios de aceite](docs/CRITERIOS-DE-ACEITE.md)
- [Instalação e operação](docs/EXECUCAO-DO-AGENTE.md)

## Princípios

- Separar descoberta passiva de validação ativa.
- Exigir autorização, escopo e validade antes de qualquer atividade ativa.
- Tratar registros de Censys como observações externas sujeitas a atraso, atribuição incorreta e infraestrutura compartilhada.
- Manter evidência, fonte, horário de observação, confiança e estado de validação para cada ativo e exposição.
- Isolar clientes e projetos; aplicar RBAC, auditoria e minimização de dados.
- Mostrar ao cliente o que foi observado, o que foi confirmado e o que ainda precisa de análise.
- Não automatizar exploração, autenticação, alteração de estado ou acesso a dados do cliente.

## Limites do MVP

- A integração real ainda requer token Censys e dados de escopo aprovados pelo time.
- A coleta é passiva: consulta somente o dataset do Censys, com limite de páginas por seed.
- Ativos sem hostname que corresponda ao domínio autorizado são descartados da associação automática.
- Não faz exploração, DAST, port scan, login, mudança de estado nem validação de vulnerabilidade.
- A evidência do fornecedor é uma observação; não confirma propriedade nem vulnerabilidade.
- O dashboard web do cliente é uma próxima etapa; o MVP gera relatórios locais sanitizados.

## Referências

- [Censys Platform API — início](https://docs.censys.com/reference/get-started)
- [Censys ASM API](https://docs.censys.com/docs/asm-api)
- [Censys Platform datasets](https://docs.censys.com/docs/platform-datasets)
- [Censys data access tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)
- [Referência de skill EASM enviada pela equipe](https://skillsmp.com/creators/xalgorix/xalgorix/internal-tools-skills-data-offensive-security-implementing-attack-surface-management)
