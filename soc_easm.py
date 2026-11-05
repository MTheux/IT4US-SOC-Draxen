#!/usr/bin/env python3
"""IT4US SOC EASM: passive Censys inventory with explicit scope gates."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


API_URL = "https://api.platform.censys.io/v3/global/search/query"
USER_AGENT = "IT4US-SOC-EASM/0.1"
MAX_PAGES_PER_SEED = 5
PAGE_SIZE = 100
TIMEOUT_SECONDS = 20
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
CSV_FIELDS = [
    "project_id", "seed", "hostname", "ip", "port", "protocol", "transport",
    "software", "source", "observed_at", "confidence", "status", "evidence_sha256",
]


class ScopeError(ValueError):
    pass


class ProviderError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_domain(value: Any) -> str:
    if not isinstance(value, str):
        raise ScopeError("Cada seed deve ser um domínio em texto.")
    candidate = value.strip().rstrip(".").lower()
    if "*" in candidate or "/" in candidate or ":" in candidate or not DOMAIN_RE.fullmatch(candidate):
        raise ScopeError(f"Seed inválido: {value!r}. Use um FQDN exato, sem wildcard, IP ou CIDR.")
    try:
        candidate.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ScopeError("Use nomes de domínio em formato IDNA ASCII (punycode).") from exc
    return candidate


def load_scope(path: Path, require_approved: bool) -> dict[str, Any]:
    try:
        scope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(f"Não foi possível ler o arquivo de escopo: {exc}") from exc
    if not isinstance(scope, dict):
        raise ScopeError("O escopo precisa ser um objeto JSON.")

    project_id = scope.get("project_id")
    if not isinstance(project_id, str) or not project_id.strip():
        raise ScopeError("Preencha project_id no arquivo de escopo.")
    auth = scope.get("authorization")
    if not isinstance(auth, dict):
        raise ScopeError("Preencha o bloco authorization.")
    if require_approved:
        if auth.get("status") != "approved":
            raise ScopeError("Execução real bloqueada: authorization.status precisa ser 'approved'.")
        for key in ("reference", "approved_by", "valid_until"):
            if not isinstance(auth.get(key), str) or not auth[key].strip() or auth[key].startswith("["):
                raise ScopeError(f"Execução real bloqueada: preencha authorization.{key}.")
        try:
            expiry = date.fromisoformat(auth["valid_until"])
        except ValueError as exc:
            raise ScopeError("authorization.valid_until deve usar AAAA-MM-DD.") from exc
        if expiry < utc_now().date():
            raise ScopeError("Execução real bloqueada: a autorização está vencida.")
        valid_from = auth.get("valid_from")
        if not isinstance(valid_from, str) or not valid_from.strip() or valid_from.startswith("["):
            raise ScopeError("Execução real bloqueada: preencha authorization.valid_from.")
        try:
            start_date = date.fromisoformat(valid_from)
        except ValueError as exc:
            raise ScopeError("authorization.valid_from deve usar AAAA-MM-DD.") from exc
        if start_date > utc_now().date():
            raise ScopeError("Execução real bloqueada: a autorização ainda não está vigente.")
        allowed_actions = auth.get("allowed_actions", [])
        if not isinstance(allowed_actions, list) or "passive_censys_lookup" not in allowed_actions:
            raise ScopeError("Execução real bloqueada: autorização precisa permitir passive_censys_lookup.")

    seeds = scope.get("authorized_seeds")
    if not isinstance(seeds, list) or not seeds:
        raise ScopeError("Informe ao menos um domínio em authorized_seeds.")
    canonical_seeds = [canonical_domain(seed) for seed in seeds]
    if len(set(canonical_seeds)) != len(canonical_seeds):
        raise ScopeError("authorized_seeds contém domínios duplicados.")

    excluded = scope.get("excluded_seeds", [])
    if not isinstance(excluded, list):
        raise ScopeError("excluded_seeds deve ser uma lista.")
    canonical_excluded = [canonical_domain(seed) for seed in excluded]
    if set(canonical_seeds) & set(canonical_excluded):
        raise ScopeError("Um domínio não pode estar autorizado e excluído ao mesmo tempo.")
    unrelated_exclusions = [item for item in canonical_excluded if not any(in_domain_scope(item, seed) for seed in canonical_seeds)]
    if unrelated_exclusions:
        raise ScopeError("Cada domínio excluído precisa estar dentro de um seed autorizado: " + ", ".join(unrelated_exclusions))

    scope["authorized_seeds"] = canonical_seeds
    scope["excluded_seeds"] = canonical_excluded
    return scope


def in_domain_scope(hostname: str, seed: str) -> bool:
    name = hostname.strip().rstrip(".").lower()
    return name == seed or name.endswith("." + seed)


def make_query(seed: str) -> str:
    # CenQL query against Censys observations; it does not send traffic to the seed.
    escaped = seed.replace('"', '\\"')
    return f'host.dns.names: "{escaped}"'


def censys_post(token: str, org_id: str | None, body: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    url = API_URL + ("?" + urlencode({"organization_id": org_id}) if org_id else "")
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    try:
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Do not include response body or request headers; the token must not reach logs.
        raise ProviderError(f"Censys respondeu HTTP {exc.code}; confira entitlement, token e limite da API.") from None
    except urllib.error.URLError as exc:
        raise ProviderError(f"Falha de conexão com a API Censys: {exc.reason}") from None
    except (TimeoutError, json.JSONDecodeError, UnicodeDecodeError):
        raise ProviderError("Timeout ou resposta inválida da API Censys.") from None
    if not isinstance(parsed, dict):
        raise ProviderError("Resposta Censys fora do formato JSON esperado.")
    return parsed


def get_result(response: dict[str, Any]) -> dict[str, Any]:
    result = response.get("result", {})
    return result if isinstance(result, dict) else {}


def get_hits(result: dict[str, Any]) -> list[dict[str, Any]]:
    hits = result.get("hits", [])
    if not isinstance(hits, list):
        return []
    return [hit for hit in hits if isinstance(hit, dict)]


def resource_for(hit: dict[str, Any]) -> dict[str, Any]:
    resource = hit.get("resource")
    return resource if isinstance(resource, dict) else hit


def extract_hosts(resource: dict[str, Any]) -> list[str]:
    dns = resource.get("dns", {})
    names = dns.get("names", []) if isinstance(dns, dict) else []
    if isinstance(names, str):
        names = [names]
    return sorted({name.strip().rstrip(".").lower() for name in names if isinstance(name, str) and name.strip()}) if isinstance(names, list) else []


def extract_services(hit: dict[str, Any], resource: dict[str, Any]) -> list[dict[str, Any]]:
    services = hit.get("matched_services")
    if not isinstance(services, list):
        services = resource.get("services", [])
    if not isinstance(services, list):
        return []
    output = []
    for item in services:
        if not isinstance(item, dict):
            continue
        software = item.get("software", [])
        software_names: list[str] = []
        if isinstance(software, list):
            for entry in software:
                if isinstance(entry, dict):
                    product = entry.get("product")
                    version = entry.get("version")
                    if isinstance(product, str):
                        software_names.append(product + (f" {version}" if isinstance(version, str) and version else ""))
        output.append({
            "port": item.get("port"),
            "protocol": item.get("protocol"),
            "transport": item.get("transport_protocol"),
            "software": ", ".join(sorted(set(software_names))),
        })
    return output or [{}]


def normalize_hit(hit: dict[str, Any], seed: str, project_id: str, observed_at: str, excluded_seeds: list[str] | None = None) -> list[dict[str, Any]]:
    resource = resource_for(hit)
    excluded = excluded_seeds or []
    hostnames = [
        name for name in extract_hosts(resource)
        if in_domain_scope(name, seed) and not any(in_domain_scope(name, excluded_seed) for excluded_seed in excluded)
    ]
    if not hostnames:
        # Avoid assigning an IP-only/shared-hosting result to a customer.
        return []
    ip = resource.get("ip")
    ip_value = ip if isinstance(ip, str) else ""
    rows = []
    for service in extract_services(hit, resource):
        evidence = {
            "seed": seed,
            "hostname": hostnames,
            "ip": ip_value,
            "service": service,
            "source": "censys-platform-search",
            "observed_at": observed_at,
        }
        evidence_hash = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        rows.append({
            "project_id": project_id,
            "seed": seed,
            "hostname": ", ".join(hostnames),
            "ip": ip_value,
            "port": service.get("port", ""),
            "protocol": service.get("protocol", ""),
            "transport": service.get("transport", ""),
            "software": service.get("software", ""),
            "source": "censys-platform-search",
            "observed_at": observed_at,
            "confidence": "candidate",
            "status": "observed_unvalidated",
            "evidence_sha256": evidence_hash,
        })
    return rows


def collect_censys(scope: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    token = os.environ.get("CENSYS_API_TOKEN", "").strip()
    if not token:
        raise ScopeError("Defina CENSYS_API_TOKEN no ambiente seguro antes da coleta real.")
    org_id = os.environ.get("CENSYS_ORGANIZATION_ID", "").strip() or None
    observations: list[dict[str, Any]] = []
    query_log: list[dict[str, Any]] = []
    observed_at = utc_now().isoformat()

    for seed in scope["authorized_seeds"]:
        query = make_query(seed)
        page_token: str | None = None
        for page_number in range(1, MAX_PAGES_PER_SEED + 1):
            body: dict[str, Any] = {
                "query": query,
                "page_size": PAGE_SIZE,
                "fields": ["host.ip", "host.dns.names", "host.services.port", "host.services.protocol", "host.services.transport_protocol", "host.services.software.product", "host.services.software.version"],
            }
            if page_token:
                body["page_token"] = page_token
            response = censys_post(token, org_id, body)
            result = get_result(response)
            hits = get_hits(result)
            for hit in hits:
                observations.extend(normalize_hit(hit, seed, scope["project_id"], observed_at, scope["excluded_seeds"]))
            query_log.append({"seed": seed, "query": query, "page": page_number, "hits_received": len(hits), "in_scope_observations": len(observations)})
            next_token = result.get("next_page_token")
            if not isinstance(next_token, str) or not next_token:
                break
            page_token = next_token
            time.sleep(1.0)
    return observations, query_log


def collect_demo(scope: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observed_at = utc_now().isoformat()
    seed = scope["authorized_seeds"][0]
    demo_host = f"demo.{seed}"
    demo_response = {
        "ip": "203.0.113.10",
        "dns": {"names": [demo_host]},
        "services": [{
            "port": 443,
            "protocol": "HTTP",
            "transport_protocol": "TCP",
            "software": [{"product": "Example HTTPS Service", "version": "synthetic"}],
        }],
    }
    hit = {"resource": demo_response}
    observations = normalize_hit(hit, seed, scope["project_id"], observed_at)
    query_log = [{"seed": seed, "query": "SYNTHETIC_DEMO_ONLY", "page": 1, "hits_received": 1, "in_scope_observations": len(observations)}]
    return observations, query_log


def write_run(out_root: Path, scope: dict[str, Any], source: str, observations: list[dict[str, Any]], query_log: list[dict[str, Any]]) -> Path:
    run_id = utc_now().strftime("%Y%m%dT%H%M%SZ")
    run_dir = out_root / f"run-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    manifest = {
        "run_id": run_id,
        "project_id": scope["project_id"],
        "source": source,
        "mode": "synthetic_demo" if source == "demo" else "passive_provider_data",
        "started_at": utc_now().isoformat(),
        "authorized_seeds": scope["authorized_seeds"],
        "observation_count": len(observations),
        "query_log": query_log,
        "notice": "Observações do provedor; não comprovam propriedade nem vulnerabilidade." if source != "demo" else "Dados totalmente sintéticos; nenhuma chamada de rede foi feita.",
    }
    (run_dir / "observations.json").write_text(json.dumps({"manifest": manifest, "observations": observations}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    with (run_dir / "assets.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(observations)
    summary = [
        f"# EASM — {scope['project_id']}",
        "",
        f"- Execução: `{run_id}` UTC",
        f"- Fonte: `{source}`",
        f"- Seeds autorizados no arquivo: {', '.join(scope['authorized_seeds'])}",
        f"- Observações associadas: {len(observations)}",
        "- Estado dos itens: observados e não validados.",
        "- Este resultado não comprova propriedade do ativo nem vulnerabilidade.",
        "- Em modo demo, todos os dados são sintéticos e não houve tráfego de rede.",
        "",
        "## Observações",
        "",
    ]
    if observations:
        summary.extend(["| Hostname | IP | Serviço | Estado |", "|---|---|---|---|"])
        for item in observations:
            service = f"{item['protocol']} {item['port']}".strip()
            summary.append(f"| {item['hostname']} | {item['ip']} | {service} | {item['status']} |")
    else:
        summary.append("Nenhuma observação associada aos seeds nesta execução.")
    (run_dir / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return run_dir


def command_init(args: argparse.Namespace) -> int:
    target = Path(args.out)
    if target.exists():
        raise ScopeError(f"O arquivo já existe: {target}. Não vou sobrescrever escopo existente.")
    template = {
        "project_id": "demo-synthetic",
        "client_label": "Ambiente de demonstração — dados sintéticos",
        "authorization": {
            "status": "pending",
            "reference": "[referência da autorização aprovada]",
            "approved_by": "[responsável aprovador]",
            "valid_from": "AAAA-MM-DD",
            "valid_until": "AAAA-MM-DD",
            "allowed_actions": [],
        },
        "authorized_seeds": ["example.org"],
        "excluded_seeds": [],
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(template, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Modelo criado: {target}")
    print("Edite os placeholders antes de validar. A autorização começa pendente.")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    scope = load_scope(Path(args.scope), require_approved=args.live)
    print(json.dumps({
        "valid": True,
        "project_id": scope["project_id"],
        "authorized_seeds": scope["authorized_seeds"],
        "mode": "live_passive_censys" if args.live else "local_scope_only",
        "network_access": False,
    }, ensure_ascii=False, indent=2))
    return 0


def command_collect(args: argparse.Namespace) -> int:
    live = args.source == "censys"
    if live and not args.live:
        raise ScopeError("A coleta real exige --live. Sem essa flag, nenhuma requisição é enviada.")
    if args.source == "demo" and args.live:
        raise ScopeError("Não use --live com --source demo.")
    scope = load_scope(Path(args.scope), require_approved=live)
    if live:
        observations, query_log = collect_censys(scope)
    else:
        if scope["project_id"] != "demo-synthetic" or scope["authorized_seeds"] != ["example.org"]:
            raise ScopeError("O modo demo aceita somente scope.example.json/example.org para evitar misturar fixtures com dados de cliente.")
        observations, query_log = collect_demo(scope)
    run_dir = write_run(Path(args.out), scope, args.source, observations, query_log)
    print(f"Execução concluída: {run_dir}")
    print(f"Observações: {len(observations)}")
    print("Arquivos: observations.json, assets.csv, summary.md")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Descoberta EASM passiva para uso autorizado pelo SOC IT4US.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="cria um modelo de escopo pendente")
    init_parser.add_argument("--out", required=True, help="caminho do JSON de escopo a criar")
    init_parser.set_defaults(handler=command_init)

    validate_parser = subparsers.add_parser("validate", help="valida formato e, com --live, gates de autorização")
    validate_parser.add_argument("--scope", required=True)
    validate_parser.add_argument("--live", action="store_true", help="valida gates necessários para consulta real; não envia requisição")
    validate_parser.set_defaults(handler=command_validate)

    collect_parser = subparsers.add_parser("collect", help="gera uma execução demo ou consulta passiva Censys")
    collect_parser.add_argument("--scope", required=True)
    collect_parser.add_argument("--source", choices=("demo", "censys"), default="demo")
    collect_parser.add_argument("--live", action="store_true", help="confirma envio de consultas à API Censys")
    collect_parser.add_argument("--out", default="runs", help="diretório onde salvar resultados")
    collect_parser.set_defaults(handler=command_collect)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.handler(args)
    except (ScopeError, ProviderError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
