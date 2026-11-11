# Design — Integração Hexiosec ASM → Surface

Data: 2026-11-11 · Autor: Nina (IT4US) · Status: implementado (2026-11-11)

## Intenção e porquê

O **Hexiosec ASM** (`asm.hexiosec.com`) é a plataforma de ASM que a IT4US usa como
**fonte de verdade** da superfície de ataque dos clientes: organizações, scans e
domínios/IPs descobertos. Hoje, no Surface, o operador cria projeto e seeds **à mão**
e cada um precisa passar pelo gate de aprovação — trabalhoso e sujeito a divergência
entre o que está no Hexiosec e o que está no Surface.

Esta integração puxa, via **API pública do Hexiosec**, as organizações e os domínios
descobertos, e os **sincroniza** como projetos/seeds no Surface. A partir daí o Surface
faz o que já sabe: **enriquecimento passivo** (Censys + BBOT) e **triagem priorizada**
(painel Prioridades). O Hexiosec define o escopo; o Surface agrega visibilidade passiva
e priorização por cima.

```
Hexiosec ASM (API)
   └─ orgs ──► domínios descobertos
                   │  (sync, uma via)
                   ▼
   Surface: projeto por org (seeds = domínios) — já autorizado pelo Hexiosec
                   │
                   ├──► Censys (passivo)
                   └──► BBOT (passivo)
                   │
                   ▼
            Painel Prioridades (agente de triagem)
```

## Objetivos

- Sincronização **uma via** Hexiosec → Surface: organização → projeto; domínios → seeds.
- Autenticação por **API key**, tratada como segredo (env / secret manager), nunca no chat, git ou UI.
- **Autorização herdada do Hexiosec**: projeto importado nasce **já aprovado** para descoberta passiva — o registro no Hexiosec **é** a autorização; não exige aprovação manual. (Projetos criados à mão no Surface continuam sob o gate normal.)
- Após aprovado, **reusar o pipeline existente** (Censys + BBOT passivo + Prioridades) sem alterá-lo.
- **Idempotente**: re-sync atualiza o projeto existente (casado por `hexiosec_org_id`), não duplica.
- Auditar toda criação/atualização de projeto originada do sync.

## Não-objetivos

- Sem **write-back** para o Hexiosec (não criamos/alteramos nada lá).
- Sem scan **ativo** — o Surface continua 100% passivo.
- v1 **não** importa Risks/Actions do Hexiosec (futuro: enriquecer findings/Prioridades com os risks deles).
- Sem tempo real; sync **sob demanda** (botão) + intervalo opcional.

## Anti-objetivos (falha mesmo se "funcionar")

- Habilitar scan **ativo**, ou importar/consultar domínio **fora** do escopo que o Hexiosec define. (Importar do Hexiosec já habilitar o passivo é **intencional**; o que não pode é sair do passivo ou do escopo do Hexiosec.)
- **Vazar a API key** (chat, git, UI, logs).
- Importar domínio fora do escopo autorizado do cliente, ou gerar qualquer tráfego ativo.

## Restrições

- API do Hexiosec só nos tiers **Premium / Enterprise / MSP** (do contrário `403`).
- Modelo passivo + gate de autorização do Surface devem continuar válidos.
- Usar `requests` (já é dependência); sem novas libs pesadas. SDK Go oficial existe mas não se aplica (projeto é Python).

## O "como" já decidido

### API do Hexiosec (confirmado via OpenAPI)
- Base: `https://asm.hexiosec.com/api`
- Auth: header **`X-Hexiosec-API-Key: <key>`**
- Endpoints usados:
  - `GET /v1/orgs` — lista organizações (nossos "clientes/projetos").
  - `GET /v1/scans/by-org?organisation_id=<id>&order=created&dir=desc&limit=&offset=` — scans da org; pega o **scan mais recente** concluído.
  - `GET /v1/scan_data/{scan_id}/domains?limit=&offset=` — domínios descobertos.
- Paginação: `limit`/`offset`; última página quando `len(recebidos) < limit`.
- Campos do domínio (`ScanDataDomainResponse`): `id`, **`name`** (o domínio), `ips`, `seed` (bool), `last_seen`, `services`, `risk_counts`, `stale`.

### Conector `soc_hexiosec.py`
- Lê a key de `HEXIOSEC_API_KEY` (ou `HEXIOSEC_API_KEY_FILE`), **mesmo padrão do Censys token**.
- Funções: `hexiosec_ready()`, `list_orgs()`, `latest_scan_for_org(org_id)`, `list_domains(scan_id)` (paginado), com timeout e redaction da key em erros.
- `collect_hexiosec_domains(org_id) -> list[str]`: retorna domínios canônicos (FQDN), dedup, excluindo `stale` opcionalmente.

### Serviço de sync `hexiosec_sync()`
- Para cada org do Hexiosec:
  1. Resolve o scan mais recente e lista os domínios.
  2. Canoniza/filtra (FQDN, mesmo critério do `soc_easm.canonical_domain`; Surface não aceita wildcard/IP/CIDR como seed).
  3. **Casa** org ↔ projeto por `hexiosec_org_id`:
     - Novo → cria projeto `mode=censys`, **`scope_state=approved`**, `allowed_actions=["passive_censys_lookup","passive_bbot_osint"]`, `seeds=<domínios>`,
       `authorization_reference="Hexiosec ASM · org <id>"`, `authorization_owner="Hexiosec ASM"`,
       `valid_from=hoje`, `valid_until=hoje+90d` (configurável).
     - Existente → atualiza seeds mantendo **aprovado** (o Hexiosec continua sendo a autoridade do escopo; não re-pende).
  4. Habilita **apenas passivo** (Censys + BBOT). Auditoria em cada create/update, registrando a origem Hexiosec (`source=hexiosec_sync`).
- **Gate**: o gate manual vale só para projetos criados à mão no Surface. Projetos originados do Hexiosec são autorizados pela própria presença no Hexiosec — e ficam **marcados** como tal (`authorization_owner="Hexiosec ASM"`), auditáveis.
- Mapeamento org → tenant: **um tenant Surface por org Hexiosec** (isolamento multi-cliente), `client_label = nome da org` — decisão minha salvo você preferir tudo sob `it4us-soc`.

### Persistência
- Nova coluna `hexiosec_org_id TEXT` em `projects` (ou tabela de mapeamento `integration_links`), para idempotência. Migração aditiva no `SCHEMA` (CREATE TABLE IF NOT EXISTS / ALTER tolerante).

### Segredos e status
- `.env`: `HEXIOSEC_API_KEY=` (+ `HEXIOSEC_API_KEY_FILE`), já coberto pelo `.gitignore`.
- `GET /api/config/status` passa a reportar `hexiosec_ready` (bool), como `censys_ready`.

### API / UI
- Backend (admin + CSRF):
  - `POST /api/integrations/hexiosec/sync` → roda `hexiosec_sync` como background task.
  - `GET /api/integrations/hexiosec/status` → key configurada? último sync (orgs/projetos/domínios).
- UI: seção **Conexões** (espelha a nav do it4us-va) com card Hexiosec: status, botão **"Sincronizar agora"**, resumo do último sync. Após o sync, os projetos aparecem **já aprovados** em *Projetos e escopo* (origem Hexiosec, marcados com `authorization_owner="Hexiosec ASM"`); uma coleta passiva Censys é enfileirada automaticamente.
- Pós-aprovação: fluxo atual (Censys + BBOT + Prioridades) sem mudança.

## O que fica a cargo de quem implementa

- Confirmar os valores de `type` em `/v1/scans/by-org` (qual "tipo" de scan representa o scan primário da org) e o campo de status "concluído".
- Decidir se `stale`/`limited` entram como seed ou são filtrados (recomendo filtrar `stale`).
- Backoff/rate-limit para orgs grandes (muitos domínios paginados).
- Agendamento: v1 sob demanda; intervalo opcional depois (reusar o `scheduler_loop`).
- Se/como importar **IPs** (`/v1/scan_data/{scan_id}/ips`) além de domínios — v1 foca em domínios (seeds).

## Plano de validação

1. `soc_hexiosec.py` testado contra a API real com uma key (lista orgs → scan → domínios).
2. `hexiosec_sync` em dry-run (loga o que criaria/atualizaria) antes de escrever no banco.
3. Sync real cria projetos **já aprovados** para passivo (origem Hexiosec); conferir que habilita **apenas** passivo (Censys/BBOT), **nunca** ativo, e que estão marcados com origem Hexiosec.
4. Disparar Censys + BBOT direto (sem aprovação manual) → conferir Prioridades.
