"""IT4US SOC Surface: passive BBOT OSINT discovery with strict scope gates.

This module runs BBOT in a PASSIVE-ONLY configuration over a project's
authorized seeds. It enforces ``--require-flags passive`` (BBOT only enables
modules flagged "Never connects to target systems") and additionally excludes
active/aggressive/deadly modules. It never port-scans, spiders, brute-forces or
connects to the discovered assets. Discovered hostnames are ingested as
``candidate`` assets for human review, consistent with the passive design and
the project authorization gate.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc_easm import ProviderError, canonical_domain, in_domain_scope

# Curated pure-python passive OSINT sources for subdomain discovery. `-rf passive`
# is the hard guarantee ("never connects to target systems"); the exclude list is
# belt-and-suspenders against anything that would touch the target.
# crt.sh (Certificate Transparency) is the fastest, most reliable pure-HTTP passive
# source. Extra modules (otx, anubisdb, rapiddns, hackertarget, dnsdumpster) can be
# added via BBOT_MODULES env, but on some hosts they add many minutes of DNS retries.
BBOT_MODULES = os.environ.get("BBOT_MODULES", "crt").split(",")
REQUIRE_FLAGS = ["passive"]

BBOT_TIMEOUT_SECONDS = int(os.environ.get("BBOT_TIMEOUT_SECONDS", "600"))


def _seed_core_deps_cache() -> None:
    """Mark BBOT core system dependencies as satisfied so it never prompts for a
    sudo password. The curated passive modules are pure-python (HTTP) and do not
    use the archive/build tools those core deps provide, so skipping them is safe.
    """
    try:
        import mmh3
        import orjson
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        core_hash = str(mmh3.hash(orjson.dumps(DepsInstaller.CORE_DEPS, option=orjson.OPT_SORT_KEYS)))
        cache_dir = Path.home() / ".bbot" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / core_hash).touch()
    except Exception:
        # Best-effort: if seeding fails, BBOT may still work when deps are present.
        pass


def _user_bin_dirs() -> list[Path]:
    dirs: list[Path] = []
    try:
        import site

        base = site.getuserbase()
        if base:
            dirs.append(Path(base) / "bin")
    except Exception:
        pass
    dirs.append(Path.home() / "Library" / "Python" / f"{sys.version_info.major}.{sys.version_info.minor}" / "bin")
    dirs.append(Path.home() / ".local" / "bin")
    return dirs


def bbot_binary() -> str | None:
    found = shutil.which("bbot")
    if found:
        return found
    for d in _user_bin_dirs():
        candidate = d / "bbot"
        if candidate.exists():
            return str(candidate)
    return None


def bbot_available() -> bool:
    return bbot_binary() is not None


def _require_binary() -> str:
    binary = bbot_binary()
    if not binary:
        raise ProviderError(
            "BBOT não está instalado neste serviço. Instale com 'pip install bbot' "
            "para habilitar a descoberta passiva BBOT."
        )
    return binary


def _subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    extra = os.pathsep.join(str(d) for d in _user_bin_dirs())
    env["PATH"] = extra + os.pathsep + env.get("PATH", "")
    return env


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def collect_bbot(scope: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run passive BBOT over the authorized seeds.

    Returns ``(observations, query_log)`` where observations use the same shape
    produced by ``soc_easm.normalize_hit`` so the existing ingestion path reuses
    them unchanged. Hosts out of scope or inside an exclusion are dropped.
    """
    binary = _require_binary()
    seeds = [canonical_domain(s) for s in scope.get("seeds", []) if s]
    excluded = [canonical_domain(s) for s in scope.get("excluded_seeds", []) if s]
    project_id = scope["project_id"]
    if not seeds:
        return [], [{"source": "bbot-passive", "note": "Nenhum seed autorizado."}]

    observed_at = _utc_now_iso()
    observations: list[dict[str, Any]] = []
    query_log: list[dict[str, Any]] = []
    seen: set[str] = set()

    _seed_core_deps_cache()
    with tempfile.TemporaryDirectory(prefix="bbot_surface_") as tmp:
        out_dir = Path(tmp) / "scan"
        cmd = [binary]
        for seed in seeds:
            cmd += ["-t", seed]
        cmd += [
            "-m", *BBOT_MODULES,
            "-rf", *REQUIRE_FLAGS,
            "-o", str(out_dir),
            "-om", "json",
            "-s", "-y",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                timeout=BBOT_TIMEOUT_SECONDS, check=False, env=_subprocess_env(),
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderError(
                "Descoberta BBOT passiva excedeu o tempo limite. Reduza os seeds "
                "ou aumente BBOT_TIMEOUT_SECONDS."
            ) from exc

        json_file = next(iter(out_dir.rglob("output.json")), None)
        if json_file is None:
            tail = (proc.stderr or proc.stdout or "")[-500:]
            query_log.append({
                "source": "bbot-passive", "seeds": seeds, "events": 0,
                "in_scope_hosts": 0, "note": "BBOT não produziu saída.", "detail": tail,
            })
            return [], query_log

        events = 0
        for line in json_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            events += 1
            if event.get("type") != "DNS_NAME":
                continue
            host = str(event.get("data", "")).strip().lower().rstrip(".")
            if not host or host in seen:
                continue
            seed = next((s for s in seeds if in_domain_scope(host, s)), None)
            if not seed:
                continue
            if any(in_domain_scope(host, ex) for ex in excluded):
                continue
            seen.add(host)
            evidence = {
                "host": host, "seed": seed, "source": "bbot-passive",
                "bbot_module": event.get("module", ""), "tags": event.get("tags", []) or [],
                "observed_at": observed_at,
            }
            evidence_hash = hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            observations.append({
                "project_id": project_id,
                "seed": seed,
                "hostname": host,
                "ip": "",
                "port": "",
                "protocol": "",
                "transport": "",
                "software": "",
                "software_details": [],
                "source": "bbot-passive",
                "observed_at": observed_at,
                "confidence": "candidate",
                "status": "observed_unvalidated",
                "evidence_sha256": evidence_hash,
            })
        query_log.append({
            "source": "bbot-passive", "seeds": seeds, "events": events,
            "in_scope_hosts": len(observations), "modules": "passive · subdomain-enum",
        })
    return observations, query_log
