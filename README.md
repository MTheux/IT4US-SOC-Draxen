# IT4US SOC — Draxen EASM

Console web self-hosted para EASM passivo com Censys, triagem SOC e relatório por cliente. O produto é executável e independente; este repositório não contém a estrutura nem o código interno do Draxen.

## Objetivo

Entregar ao Fabio e ao time SOC um console para cadastrar clientes e escopos, obter aprovação independente, coletar observações passivas Censys, revisar ativos e exposições, controlar acessos e gerar inventário/relatório compartilhável.

Este repositório contém somente a proposta e os artefatos próprios deste produto. Não contém código, dados, credenciais, configurações nem documentação interna do Draxen.

## Instalação no Mac do SOC

Pré-requisitos: macOS, Python 3.10 ou superior, Git e acesso do GitHub à organização/repositório privado `MTheux/IT4US-SOC-Draxen`. Confira as ferramentas:

```bash
python3 --version
git --version
```

No Terminal, clone o projeto e instale as dependências em um ambiente Python isolado:

```bash
git clone https://github.com/MTheux/IT4US-SOC-Draxen.git
cd IT4US-SOC-Draxen
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 scripts/run_local.py
```

Na primeira inicialização, informe o email do administrador SOC e crie uma senha com pelo menos 14 caracteres quando o Terminal solicitar. A senha é armazenada como hash. Depois abra **http://127.0.0.1:8765** no navegador e entre com essa conta. O serviço escuta somente no próprio Mac; os dados locais ficam em `data/easm.sqlite`.

O primeiro login já inclui um projeto demonstrativo com dados sintéticos; testar essa demonstração não faz chamadas externas. Para parar o serviço, volte ao Terminal onde ele está rodando e pressione `Ctrl+C`.

### Iniciar novamente

Depois da instalação, não precisa clonar ou instalar de novo. No Terminal:

```bash
cd IT4US-SOC-Draxen
source .venv/bin/activate
python3 scripts/run_local.py
```

### OpenCode e Censys

O time pode abrir o repositório no OpenCode para trabalhar no projeto, mas o token Censys deve ser disponibilizado ao processo do EASM pelo mecanismo aprovado pela IT4US. Não cole o token no chat nem o salve no Git ou em `opencode.json`. Se o secret manager disponibilizar um arquivo protegido fora do repositório, configure apenas o caminho antes de iniciar o serviço:

```bash
export CENSYS_API_TOKEN_FILE="$HOME/.config/it4us-easm/censys.token"
python3 scripts/run_local.py
```

Peça ao administrador SOC que configure o arquivo e as permissões. Com o token ausente, o projeto de demonstração continua disponível, mas consultas reais ficam indisponíveis. Uma coleta real só deve ser iniciada na interface após cadastrar autorização vigente e receber aprovação independente do escopo. OpenCode não substitui essa aprovação.

Para detalhes de implantação compartilhada, veja [Docker Compose](#implantação-com-docker-compose) e [Instalação e operação](docs/EXECUCAO-DO-AGENTE.md).

## Implantação com Docker Compose

Copie `.env.example` para `.env` e preencha o email e a senha iniciais. Preserve `.env` fora do Git. Para o provedor, prefira `CENSYS_API_TOKEN_FILE` apontando a um arquivo montado do secret manager. No Compose de exemplo, injete `CENSYS_API_TOKEN` pelo ambiente protegido da máquina; não coloque credenciais no Git. O serviço é publicado somente em loopback (`127.0.0.1:8765`); para acesso compartilhado, coloque-o atrás do proxy HTTPS corporativo e defina `EASM_COOKIE_SECURE=1`.

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

## OpenCode e token Censys

OpenCode pode ajudar a manter o código e iniciar comandos do projeto, mas o token Censys deve ficar disponível ao **processo do EASM**, não ser enviado como mensagem ao modelo nem salvo em `opencode.json` como chave de provedor. A interpolação de arquivos do OpenCode é uma configuração para valores usados pela própria configuração do OpenCode; não é o secret manager do EASM. Consulte [variáveis de configuração do OpenCode](https://opencode.ai/docs/config/) e [permissões de ferramentas](https://opencode.ai/docs/permissions/).

Para execução local, peça ao secret manager aprovado que disponibilize um arquivo fora deste repositório, com leitura restrita ao operador/serviço (por exemplo, modo `600`). Na mesma sessão de terminal que iniciará o EASM, configure somente o **caminho** do arquivo e inicie o serviço:

```bash
export CENSYS_API_TOKEN_FILE="$HOME/.config/it4us-easm/censys.token"
python scripts/run_local.py
```

Não abra nem imprima o arquivo pelo OpenCode, não cole o valor do token no chat e não peça ao modelo para executar `env`, `printenv`, `cat` ou comandos equivalentes. Os analistas operam a coleta pela interface EASM, após a aprovação do escopo; OpenCode não substitui esse gate. Para Compose, o administrador injeta `CENSYS_API_TOKEN` no ambiente protegido do serviço a partir do secret manager; não grave o valor no `.env` ou no Git.

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
