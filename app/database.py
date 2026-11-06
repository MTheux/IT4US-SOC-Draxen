"""SQLite storage for the single-node IT4US SOC EASM deployment."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from .security import hash_password


DB_PATH = Path(os.environ.get("EASM_DB_PATH", "data/easm.sqlite"))


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(DB_PATH.parent, 0o700)
    except OSError:
        pass
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','analyst','reviewer','client_viewer')),
  display_name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
  UNIQUE(tenant_id,email)
);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL, client_label TEXT NOT NULL DEFAULT '', mode TEXT NOT NULL CHECK(mode IN ('demo','censys')),
  scope_state TEXT NOT NULL CHECK(scope_state IN ('pending','approved','expired','suspended')),
  authorization_reference TEXT NOT NULL DEFAULT '', authorization_owner TEXT NOT NULL DEFAULT '',
  valid_from TEXT NOT NULL DEFAULT '', valid_until TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL REFERENCES users(id), approved_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, scan_interval_hours INTEGER NOT NULL DEFAULT 0,
  next_scan_at TEXT, seeds_json TEXT NOT NULL DEFAULT '[]', exclusions_json TEXT NOT NULL DEFAULT '[]',
  allowed_actions_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS project_members (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(project_id,user_id)
);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), project_id TEXT NOT NULL REFERENCES projects(id),
  mode TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed')),
  requested_by TEXT REFERENCES users(id), started_at TEXT, completed_at TEXT,
  asset_count INTEGER NOT NULL DEFAULT 0, candidate_count INTEGER NOT NULL DEFAULT 0,
  error_summary TEXT NOT NULL DEFAULT '', result_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), project_id TEXT NOT NULL REFERENCES projects(id),
  asset_key TEXT NOT NULL, asset_type TEXT NOT NULL, primary_name TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '', source TEXT NOT NULL, ownership_state TEXT NOT NULL DEFAULT 'candidate',
  confidence REAL NOT NULL DEFAULT 0.0, criticality TEXT NOT NULL DEFAULT 'standard',
  status TEXT NOT NULL DEFAULT 'active', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  last_run_id TEXT REFERENCES scans(id), details_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(project_id,asset_key)
);
CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), project_id TEXT NOT NULL REFERENCES projects(id),
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  source TEXT NOT NULL, retrieved_at TEXT NOT NULL, evidence_sha256 TEXT NOT NULL, evidence_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), project_id TEXT NOT NULL REFERENCES projects(id),
  asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL, signal_key TEXT NOT NULL,
  title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
  state TEXT NOT NULL CHECK(state IN ('new','triage','accepted','resolved','false_positive')),
  source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}', analyst_note TEXT NOT NULL DEFAULT '',
  UNIQUE(project_id,signal_key)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), project_id TEXT,
  actor_user_id TEXT REFERENCES users(id), action TEXT NOT NULL, resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nvd_cache (
  product_key TEXT NOT NULL, version_key TEXT NOT NULL, fetched_at TEXT NOT NULL,
  candidates_json TEXT NOT NULL, PRIMARY KEY(product_key,version_key)
);
CREATE INDEX IF NOT EXISTS idx_assets_project_seen ON assets(project_id,last_seen);
CREATE INDEX IF NOT EXISTS idx_findings_project_state ON findings(project_id,state,severity);
CREATE INDEX IF NOT EXISTS idx_scans_project_started ON scans(project_id,started_at);
CREATE INDEX IF NOT EXISTS idx_observations_project_retrieved ON observations(project_id,retrieved_at);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON audit_events(tenant_id,created_at);
"""


def initialize() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
        bootstrap_user = os.environ.get("EASM_BOOTSTRAP_EMAIL", "").strip().lower()
        bootstrap_password = os.environ.get("EASM_BOOTSTRAP_PASSWORD", "")
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0 and bootstrap_user and bootstrap_password:
            tenant_id = "it4us-soc"
            now = utc_now()
            conn.execute("INSERT OR IGNORE INTO tenants(id,name,created_at) VALUES(?,?,?)", (tenant_id, "IT4US SOC", now))
            admin_id = "usr_" + os.urandom(12).hex()
            conn.execute(
                "INSERT INTO users(id,tenant_id,email,password_hash,role,display_name,created_at) VALUES(?,?,?,?,?,?,?)",
                (admin_id, tenant_id, bootstrap_user, hash_password(bootstrap_password), "admin", "SOC Admin", now),
            )
            seed_demo(conn, tenant_id, admin_id)


def seed_demo(conn: sqlite3.Connection, tenant_id: str, created_by: str) -> None:
    if conn.execute("SELECT 1 FROM projects WHERE tenant_id=? AND mode='demo' LIMIT 1", (tenant_id,)).fetchone():
        return
    now = utc_now()
    project_id = "demo-easm"
    conn.execute(
        """INSERT INTO projects(id,tenant_id,name,client_label,mode,scope_state,created_by,created_at,updated_at,
           seeds_json,exclusions_json,allowed_actions_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (project_id, tenant_id, "Surface Lab", "Cliente demonstrativo", "demo", "approved", created_by, now, now,
         json.dumps(["example.org"]), "[]", json.dumps(["passive_censys_lookup"])),
    )
    scan_id = "run_demo_seed"
    conn.execute(
        "INSERT INTO scans(id,tenant_id,project_id,mode,status,started_at,completed_at,asset_count,candidate_count,result_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (scan_id, tenant_id, project_id, "demo", "completed", now, now, 6, 3,
         json.dumps({"notice": "Synthetic demo dataset; no network requests."})),
    )
    samples = [
        ("portal.example.org", "203.0.113.10", [443], [{"port":443,"protocol":"HTTPS","software":"Example Web Edge"}], "critical"),
        ("api.example.org", "198.51.100.12", [443,8443], [{"port":443,"protocol":"HTTPS","software":"Example API Gateway"},{"port":8443,"protocol":"HTTPS","software":"Example Admin Console"}], "high"),
        ("vpn.example.org", "203.0.113.42", [443,3389], [{"port":443,"protocol":"HTTPS","software":"Example VPN Portal"},{"port":3389,"protocol":"RDP","software":"Synthetic RDP service"}], "high"),
        ("assets.example.org", "198.51.100.25", [443], [{"port":443,"protocol":"HTTPS","software":"Example Static CDN"}], "standard"),
        ("mail.example.org", "203.0.113.55", [25,443], [{"port":25,"protocol":"SMTP","software":"Example Mail"},{"port":443,"protocol":"HTTPS","software":"Example Webmail"}], "standard"),
        ("status.example.org", "198.51.100.78", [443], [{"port":443,"protocol":"HTTPS","software":"Example Status Page"}], "standard"),
    ]
    for name, ip, ports, services, criticality in samples:
        asset_id = "ast_" + os.urandom(12).hex()
        detail = {"ports": ports, "services": services, "software": [s["software"] for s in services], "synthetic": True}
        conn.execute(
            """INSERT INTO assets(id,tenant_id,project_id,asset_key,asset_type,primary_name,ip,source,
               ownership_state,confidence,criticality,status,first_seen,last_seen,last_run_id,details_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (asset_id, tenant_id, project_id, name, "host", name, ip, "synthetic-demo", "confirmed_seed_relation", 1.0,
             criticality, "active", now, now, scan_id, json.dumps(detail)),
        )
        evidence = {"name": name, "ip": ip, "ports": ports, "services": services, "source": "synthetic-demo", "observed_at": now}
        conn.execute(
            "INSERT INTO observations(id,tenant_id,project_id,asset_id,scan_id,source,retrieved_at,evidence_sha256,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
            ("obs_"+os.urandom(12).hex(), tenant_id, project_id, asset_id, scan_id, "synthetic-demo", now,
             __import__("hashlib").sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest(), json.dumps(evidence)),
        )
    finding_specs = [
        ("vpn.example.org", "exposed-sensitive-port:3389", "RDP observado em ativo público", "A fonte externa registrou serviço RDP na porta 3389. Revise a necessidade e controles de acesso; a observação não comprova acesso ou vulnerabilidade.", "high", "triage", "vpn.example.org"),
        ("api.example.org", "exposed-sensitive-port:8443", "Console HTTPS em porta alternativa", "Serviço HTTPS observado em 8443. Confirme se o endpoint é esperado e se requer acesso restrito.", "medium", "new", "api.example.org"),
        ("mail.example.org", "exposed-sensitive-port:25", "SMTP público observado", "Serviço SMTP observado. Confirme a função, relay policy e controles de abuso por meio de revisão autorizada.", "low", "new", "mail.example.org"),
    ]
    for name, signal_key, title, description, severity, state, asset_name in finding_specs:
        asset = conn.execute("SELECT id FROM assets WHERE project_id=? AND primary_name=?", (project_id, asset_name)).fetchone()
        conn.execute(
            """INSERT INTO findings(id,tenant_id,project_id,asset_id,signal_key,title,description,severity,state,
               source,first_seen,last_seen,evidence_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("fnd_"+os.urandom(12).hex(), tenant_id, project_id, asset["id"], signal_key, title, description,
             severity, state, "synthetic-demo", now, now, json.dumps({"port": int(signal_key.split(":")[-1]), "synthetic": True})),
        )
