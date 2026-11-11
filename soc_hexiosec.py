"""IT4US SOC Surface: Hexiosec ASM integration (read-only, passive).

Pulls client organisations and their discovered domains from the Hexiosec ASM
public REST API so they can be synced into Surface as authorized projects. The
integration is strictly read-only: it never writes back to Hexiosec and never
performs active scanning. The presence of a domain in Hexiosec is treated as the
authorization for passive discovery (Censys / BBOT OSINT) over that domain.

The API key is read from the environment or a mounted secret file, exactly like
the Censys token (``soc_easm.censys_api_token``), and is redacted from any error
surfaced to callers so it never leaks into logs, the UI or chat.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from soc_easm import ProviderError, ScopeError, canonical_domain

HEXIOSEC_API_BASE = os.environ.get("HEXIOSEC_API_BASE", "https://asm.hexiosec.com/api").rstrip("/")
USER_AGENT = "IT4US-SOC-Surface/1.0"
TIMEOUT_SECONDS = int(os.environ.get("HEXIOSEC_TIMEOUT_SECONDS", "30"))
PAGE_LIMIT = int(os.environ.get("HEXIOSEC_PAGE_LIMIT", "200"))
MAX_PAGES = int(os.environ.get("HEXIOSEC_MAX_PAGES", "50"))


def hexiosec_api_key() -> str:
    """Read the Hexiosec API key from a mounted secret file or the environment."""
    secret_path = os.environ.get("HEXIOSEC_API_KEY_FILE", "").strip()
    if secret_path:
        try:
            return Path(secret_path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return os.environ.get("HEXIOSEC_API_KEY", "").strip()


def hexiosec_ready() -> bool:
    return bool(hexiosec_api_key())


def _redact(text: str, key: str) -> str:
    return text.replace(key, "[REDACTED]") if key and key in text else text


def _request(path: str, params: dict[str, Any] | None = None) -> Any:
    key = hexiosec_api_key()
    if not key:
        raise ProviderError(
            "HEXIOSEC_API_KEY não configurada. Defina a chave no ambiente ou em "
            "HEXIOSEC_API_KEY_FILE para sincronizar com o Hexiosec ASM."
        )
    url = f"{HEXIOSEC_API_BASE}{path}"
    if params:
        url = f"{url}?{urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={"X-Hexiosec-API-Key": key, "Accept": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise ProviderError(
                f"Hexiosec recusou a chave (HTTP {exc.code}). Verifique a API key e o tier "
                "da conta (a API exige Premium/Enterprise/MSP)."
            ) from None
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise ProviderError(_redact(f"Hexiosec API HTTP {exc.code} em {path}: {detail}", key)) from None
    except urllib.error.URLError as exc:
        raise ProviderError(_redact(f"Falha ao conectar no Hexiosec: {exc.reason}", key)) from None
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Resposta inválida do Hexiosec em {path}: {exc}") from None


def _as_list(payload: Any) -> list[dict[str, Any]]:
    """Hexiosec responses may be a bare list or wrapped under a data key."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("data", "results", "items", "organisations", "orgs", "scans", "domains"):
            value = payload.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
    return []


def list_orgs() -> list[dict[str, Any]]:
    """List the organisations (our clients) visible to this API key."""
    return _as_list(_request("/v1/orgs"))


def latest_scan_for_org(org_id: str) -> str | None:
    """Return the id of the most recent scan for an organisation, or None."""
    payload = _request(
        "/v1/scans/by-org",
        {"organisation_id": org_id, "order": "created", "dir": "desc", "limit": 10, "offset": 0},
    )
    for scan in _as_list(payload):
        scan_id = str(scan.get("id") or scan.get("scan_id") or "").strip()
        if scan_id:
            return scan_id
    return None


def list_domains(scan_id: str) -> list[dict[str, Any]]:
    """Return all discovered domains for a scan, following limit/offset pagination."""
    domains: list[dict[str, Any]] = []
    offset = 0
    for _ in range(MAX_PAGES):
        page = _as_list(_request(f"/v1/scan_data/{scan_id}/domains", {"limit": PAGE_LIMIT, "offset": offset}))
        if not page:
            break
        domains.extend(page)
        if len(page) < PAGE_LIMIT:
            break
        offset += PAGE_LIMIT
    return domains


def collect_hexiosec_domains(org_id: str, scan_id: str | None = None, include_stale: bool = False) -> list[str]:
    """Return canonical FQDN seeds for an organisation's most recent scan.

    Wildcards, IPs and anything Surface cannot accept as a seed are skipped
    silently rather than failing the whole sync. ``stale`` domains are dropped
    by default so only the currently discovered surface becomes authorized.
    """
    scan_id = scan_id or latest_scan_for_org(org_id)
    if not scan_id:
        return []
    seen: set[str] = set()
    seeds: list[str] = []
    for entry in list_domains(scan_id):
        name = str(entry.get("name") or entry.get("domain") or "").strip()
        if not name:
            continue
        if not include_stale and entry.get("stale") is True:
            continue
        try:
            canonical = canonical_domain(name)
        except ScopeError:
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        seeds.append(canonical)
    return seeds
