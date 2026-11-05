# IT4US SOC — Draxen EASM

Console web self-hosted para EASM passivo com Censys, triagem SOC e relatório por cliente. O produto é executável e independente; este repositório não contém a estrutura nem o código interno do Draxen.

## Objetivo

Entregar ao Fabio e ao time SOC um console para cadastrar clientes e escopos, obter aprovação independente, coletar observações passivas Censys, revisar ativos e exposições, controlar acessos e gerar inventário/relatório compartilhável.

Este repositório contém somente a proposta e os artefatos próprios deste produto. Não contém código, dados, credenciais, configurações nem documentação interna do Draxen.

## Console web — macOS/Linux

Requer Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/run_local.py
```

A primeira execução solicita email e senha do administrador SOC; a senha é armazenada como hash. O serviço fica em `http://127.0.0.1:8765` e usa SQLite local em `data/easm.sqlite`. Projeto demonstrativo e dados sintéticos são incluídos automaticamente. Não há chamadas externas no modo demonstração.

## Implantação com Docker Compose

Copie `.env.example` para `.env`, preencha email/senha iniciais e, quando aprovado, o token Censys. Preserve `.env` fora do Git. Para o provedor, prefira `CENSYS_API_TOKEN_FILE` apontando a um arquivo montado do secret manager. No Compose de exemplo, injete `CENSYS_API_TOKEN` pelo ambiente protegido da máquina; não coloque credenciais no Git. O serviço é publicado somente em loopback (`127.0.0.1:8765`); para acesso compartilhado, coloque-o atrás do proxy HTTPS corporativo e defina `EASM_COOKIE_SECURE=1`.

```bash
cp .env.example .env
docker compose up --build -d
```

Para uma instalação SOC compartilhada, configure TLS, backup cifrado do volume e armazenamento de segredo adequado antes de expor o serviço para a rede corporativa.

## Fluxo SOC

1. Admin cria um projeto separado por cliente com FQDNs autorizados, exclusões, referência e datas da autorização.
2. Projeto fica pendente; outro administrador/revisor confere e aprova. Alterar escopo suspende a aprovação até nova revisão.
3. Admin configura `CENSYS_API_TOKEN` no ambiente/secret manager. O token não aparece na interface.
4. Analista executa ou agenda consultas passivas Censys; consultas ficam limitadas aos seeds e resultados associados a hostname autorizado.
5. SOC revisa ativos, criticidade e candidatos de exposição, mantendo proveniência, estado e notas internas na trilha de auditoria.
6. Cliente recebe acesso somente leitura a projetos explicitamente associados e pode baixar inventário e resumo sem notas internas.

Este é EASM de inventário e priorização por observação externa, não um scanner ativo nem verificador de vulnerabilidades. Sinais de exposição são candidatos para investigação e não confirmam propriedade ou falha explorável.

## CLI passiva — modo demonstração

O CLI legado pode criar `observations.json`, `assets.csv` e `summary.md` sem rede:

```bash
python3 soc_easm.py init --out scope.json
python3 soc_easm.py collect --scope scope.json --source demo --out runs
```

Para usar Censys de verdade, preencha `scope.json` com autorização vigente, seeds exatos e aprovador; configure `CENSYS_API_TOKEN` no ambiente seguro da máquina e execute:

```bash
python3 soc_easm.py validate --scope scope.json
python3 soc_easm.py collect --scope scope.json --source censys --live --out runs
```

O modo real exige autorização aprovada, referência, aprovador, validade e flag `--live`. Faz somente consultas à API de dados da Censys; não conecta aos ativos listados nem executa varredura ativa.

Consulte [Instalação e operação](docs/EXECUCAO-DO-AGENTE.md) e [critérios de aceite](docs/CRITERIOS-DE-ACEITE.md) antes do piloto compartilhado.

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
- Autenticação local por sessão/cookie e papéis SOC/cliente; para produção compartilhada, avalie SSO corporativo e MFA.
- Banco single-node SQLite; alta disponibilidade, gestão formal de segredo, backup/restore verificado e proxy TLS corporativo pertencem ao endurecimento pré-produção.

## Referências

- [Censys Platform API — início](https://docs.censys.com/reference/get-started)
- [Censys ASM API](https://docs.censys.com/docs/asm-api)
- [Censys Platform datasets](https://docs.censys.com/docs/platform-datasets)
- [Censys data access tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)
- [Referência de skill EASM enviada pela equipe](https://skillsmp.com/creators/xalgorix/xalgorix/internal-tools-skills-data-offensive-security-implementing-attack-surface-management)
