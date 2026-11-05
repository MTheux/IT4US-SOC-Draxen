# Instalação e operação do agente EASM

**Versão:** 0.1  
**Data:** 2026-11-05  
**Público:** Fabio e time SOC da IT4US.

## O que o agente executa

O MVP consulta a API Platform do Censys para buscar observações passivas associadas aos domínios aprovados. Ele não faz conexão com os ativos, port scan, DAST ou exploração. Cada resultado é rotulado `observed_unvalidated` e precisa de revisão do analista.

O caminho `--source demo` é sintético e não usa rede. A chamada real só acontece com `--source censys --live`, autorização aprovada no JSON e token no ambiente. O PAT tem acesso à conta Censys: não o coloque em `scope.json`, GitHub, prompt, screenshot, log ou relatório.

## Pré-requisitos

- Python 3.10 ou superior.
- Clone/acesso ao repositório privado `MTheux/IT4US-SOC-Draxen`.
- Para consulta real: conta Censys com Personal Access Token e entitlement/role que permita o endpoint de busca; verificar limites e termos com o administrador Censys.
- Escopo do piloto com autorização, seeds, exclusões, responsável e validade aprovados.

## 1. Clonar e rodar a demonstração

```bash
git clone https://github.com/MTheux/IT4US-SOC-Draxen.git
cd IT4US-SOC-Draxen
python3 soc_easm.py init --out scope.json
python3 soc_easm.py collect --scope scope.json --source demo --out runs
```

Os arquivos gerados ficam em `runs/run-<UTC>/`. A demonstração usa `203.0.113.10`, reservado para documentação, e hostname sintético sob `example.org`. Não há chamada de rede.

## 2. Preparar o escopo real

Edite `scope.json` na máquina do operador. Substitua todos os placeholders e não registre dados de cliente neste repositório. Um modelo mínimo:

```json
{
  "project_id": "pilot-001",
  "client_label": "Projeto piloto",
  "authorization": {
    "status": "approved",
    "reference": "REFERENCIA-INTERNA-DA-AUTORIZACAO",
    "approved_by": "RESPONSAVEL-DO-ESCOPO",
    "valid_from": "AAAA-MM-DD",
    "valid_until": "AAAA-MM-DD",
    "allowed_actions": ["passive_censys_lookup"]
  },
  "authorized_seeds": ["dominio-aprovado.example"],
  "excluded_seeds": []
}
```

Use domínios FQDN explícitos. Wildcards, IPs, CIDRs e domínios excluídos não são aceitos como seeds pelo MVP. Inclua cada domínio raiz autorizado explicitamente; subdomínios só serão associados quando o nome observado terminar no limite desse domínio (`.dominio.example`), evitando falsos matches como `dominio.example.evil`.

```bash
python3 soc_easm.py validate --scope scope.json
python3 soc_easm.py validate --scope scope.json --live
```

`validate --live` verifica autorização e validade localmente, mas não faz consultas.

## 3. Configurar o acesso Censys

Peça ao administrador Censys para confirmar o acesso à Platform API, a role necessária, a organização/entitlement correto e limites de créditos. O MVP usa Personal Access Token via `Authorization: Bearer` e endpoint de busca v3. Opcionalmente configure `CENSYS_ORGANIZATION_ID` como variável de ambiente na máquina; não grave token ou ID da organização no arquivo de escopo.

Armazene o token no gerenciador de segredos aprovado pela IT4US e injete `CENSYS_API_TOKEN` no processo. Não use um token colado em um comando, arquivo, chat ou script versionado. Depois de configurar o segredo:

```bash
python3 soc_easm.py collect --scope scope.json --source censys --live --out runs
```

Sem `--live`, a coleta real falha fechada. A consulta atual busca `host.dns.names` por seed, pede somente campos mínimos e limita a cinco páginas de até 100 registros por seed. O código não tenta contornar limites do plano. Uma resposta 401/403/429/503 deve ser tratada como falha do provedor/entitlement, não como “nenhum ativo”.

## 4. Revisar e entregar

Cada execução grava:

- `observations.json`: metadados da consulta e observações normalizadas;
- `assets.csv`: inventário para triagem/importação;
- `summary.md`: resumo legível para operador.

Analista deve confirmar associação, relevância, criticidade e próxima ação antes de tratar um item como finding ou compartilhar com cliente. A ausência de resultados não prova ausência de ativo ou risco. O MVP não fornece ainda dashboard web, agendamento contínuo, isolamento multiusuário ou DAST.

## Controles antes de instalar na estação do Fabio

1. Confirmar com Fabio qual sistema operacional e política de software da estação.
2. Revisar o código do MVP e obter aprovação do responsável SOC/endpoint antes da execução.
3. Executar primeiro o modo demo sem segredo e sem rede.
4. Não instalar como serviço persistente e não solicitar privilégios administrativos.
5. Configurar o token via mecanismo gerenciado e preferencialmente identidade/credencial dedicada, com revogação fácil.
6. Fazer a primeira consulta real somente após autorização, entitlement e seed serem conferidos por outra pessoa.
7. Guardar resultados fora do Git e no local de evidências aprovado, com retenção e acesso limitados.

## Diferença para o agente de scan de vulnerabilidade

Este MVP executa EASM passivo baseado em dados Censys. Ele não substitui scanner de vulnerabilidades. Para conectar um scanner ativo, é necessário primeiro definir fornecedor, versão, máquina/runner, perfis de scan, intensidade, escopo exato, janela e autorização. Essa integração fica fora deste MVP e deve ser implementada como módulo separado, bloqueado por escopo e aprovação.

## Referências

- [Censys Platform API — token e entitlements](https://docs.censys.com/reference/get-started)
- [Censys Search Query v3](https://docs.censys.com/reference/v3-globaldata-search-query)
- [Censys Query Language](https://docs.censys.com/docs/censys-query-language)
- [Censys data access tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)
