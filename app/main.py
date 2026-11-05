"""Self-hosted multi-tenant EASM console for the IT4US SOC pilot."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import secrets
import sqlite3
import threading
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .database import connect, db, initialize, utc_now
from .security import new_session_values, token_hash, verify_password
from soc_easm import ScopeError, censys_api_token, collect_censys, collect_demo, in_domain_scope


ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
SESSION_COOKIE = "it4us_easm_session"
SESSION_HOURS = 8
COOKIE_SECURE = os.environ.get("EASM_COOKIE_SECURE", "0") == "1"
LOGIN_ATTEMPTS: dict[str, tuple[int, datetime]] = {}
LOGIN_LOCK = threading.Lock()
SENSITIVE_PORTS = {
    21: ("FTP service observed", "high", "Confirm whether FTP is required and whether encrypted transport is enforced."),
    23: ("Telnet service observed", "high", "Confirm whether this legacy remote administration service is required."),
    3389: ("RDP service observed", "high", "Confirm the service is expected and protected by approved access controls."),
    5900: ("VNC service observed", "high", "Confirm the service is expected and protected by approved access controls."),
    2375: ("Docker API port observed", "critical", "Review whether this endpoint is intended to be publicly reachable."),
    9200: ("Elasticsearch port observed", "high", "Review whether this service is intended to be publicly reachable."),
    6379: ("Redis port observed", "high", "Review whether this service is intended to be publicly reachable."),
    27017: ("MongoDB port observed", "high", "Review whether this service is intended to be publicly reachable."),
    8443: ("HTTPS service on alternate port observed", "medium", "Confirm ownership, purpose, and expected access policy."),
}


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    client_label: str = Field(min_length=2, max_length=100)
    seeds: list[str] = Field(min_length=1, max_length=30)
    exclusions: list[str] = Field(default_factory=list, max_length=100)
    authorization_reference: str = Field(min_length=3, max_length=200)
    authorization_owner: str = Field(min_length=3, max_length=120)
    valid_from: str
    valid_until: str
    scan_interval_hours: int = Field(default=24, ge=6, le=720)


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=14, max_length=200)
    role: str
    project_ids: list[str] = Field(default_factory=list, max_length=100)


class FindingUpdate(BaseModel):
    state: str
    analyst_note: str = Field(default="", max_length=2000)


class AssetUpdate(BaseModel):
    criticality: str


class ScheduleUpdate(BaseModel):
    scan_interval_hours: int = Field(ge=6, le=720)


class ScopeAmend(BaseModel):
    seeds: list[str] = Field(min_length=1, max_length=30)
    exclusions: list[str] = Field(default_factory=list, max_length=100)
    authorization_reference: str = Field(min_length=3, max_length=200)
    authorization_owner: str = Field(min_length=3, max_length=120)
    valid_from: str
    valid_until: str


def rowdict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def json_value(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def audit(conn: sqlite3.Connection, user: dict[str, Any] | None, action: str, resource_type: str, resource_id: str = "", project_id: str | None = None, detail: dict[str, Any] | None = None) -> None:
    tenant_id = user["tenant_id"] if user else "it4us-soc"
    if project_id:
        project = conn.execute("SELECT tenant_id FROM projects WHERE id=?", (project_id,)).fetchone()
        if project:
            tenant_id = project["tenant_id"]
    conn.execute(
        "INSERT INTO audit_events(id,tenant_id,project_id,actor_user_id,action,resource_type,resource_id,created_at,detail_json) VALUES(?,?,?,?,?,?,?,?,?)",
        ("aud_" + uuid.uuid4().hex, tenant_id, project_id,
         user["id"] if user else None, action, resource_type, resource_id, utc_now(), json.dumps(detail or {})),
    )


def get_current_user(request: Request) -> dict[str, Any]:
    raw = request.cookies.get(SESSION_COOKIE, "")
    if not raw:
        raise HTTPException(status_code=401, detail="Authentication required")
    with db() as conn:
        row = conn.execute(
            """SELECT u.id,u.tenant_id,u.email,u.role,u.display_name,u.active,s.csrf_hash,s.expires_at
               FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?""",
            (token_hash(raw),),
        ).fetchone()
        if not row or not row["active"]:
            raise HTTPException(status_code=401, detail="Session expired")
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(raw),))
            raise HTTPException(status_code=401, detail="Session expired")
        return dict(row)


def require_csrf(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    sent = request.headers.get("x-csrf-token", "")
    expected_hash = user.get("csrf_hash", "")
    if not sent or not secrets.compare_digest(token_hash(sent), expected_hash):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    return user


def require_roles(*roles: str):
    def dependency(user: dict[str, Any] = Depends(require_csrf)) -> dict[str, Any]:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return dependency


def project_row(conn: sqlite3.Connection, user: dict[str, Any], project_id: str, allow_client: bool = True) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    if user["role"] == "admin" and user["tenant_id"] == "it4us-soc":
        return row
    if user["role"] == "client_viewer" and not allow_client:
        raise HTTPException(status_code=403, detail="Insufficient role")
    if user["role"] == "client_viewer" and row["tenant_id"] != user["tenant_id"]:
        raise HTTPException(status_code=404, detail="Project not found")
    membership = conn.execute("SELECT 1 FROM project_members WHERE project_id=? AND user_id=?", (project_id, user["id"])).fetchone()
    if not membership:
        raise HTTPException(status_code=404, detail="Project not found")
    return row


def serialize_project(row: sqlite3.Row, customer: bool = False) -> dict[str, Any]:
    output = {
        "id": row["id"], "name": row["name"], "client_label": row["client_label"], "mode": row["mode"],
        "scope_state": row["scope_state"], "seeds": json_value(row["seeds_json"], []),
        "exclusions": json_value(row["exclusions_json"], []), "scan_interval_hours": row["scan_interval_hours"],
        "next_scan_at": row["next_scan_at"], "valid_until": row["valid_until"],
    }
    if not customer:
        output.update({
            "authorization_reference": row["authorization_reference"], "authorization_owner": row["authorization_owner"],
            "valid_from": row["valid_from"], "created_at": row["created_at"], "approved_by": row["approved_by"],
            "created_by": row["created_by"], "allowed_actions": json_value(row["allowed_actions_json"], []),
        })
    return output


def accessible_projects(conn: sqlite3.Connection, user: dict[str, Any]) -> list[sqlite3.Row]:
    if user["role"] == "admin" and user["tenant_id"] == "it4us-soc":
        return conn.execute("SELECT * FROM projects ORDER BY client_label,name").fetchall()
    if user["role"] in ("client_viewer","analyst","reviewer"):
        return conn.execute(
            """SELECT p.* FROM projects p JOIN project_members m ON m.project_id=p.id
               WHERE m.user_id=? ORDER BY p.client_label,p.name""", (user["id"],)
        ).fetchall()
    return conn.execute("SELECT * FROM projects WHERE tenant_id=? ORDER BY name", (user["tenant_id"],)).fetchall()


def _api_scope(project: sqlite3.Row) -> dict[str, Any]:
    return {
        "project_id": project["id"],
        "authorization": {
            "status": project["scope_state"], "reference": project["authorization_reference"],
            "approved_by": project["approved_by"] or "", "approved_by_email": project["authorization_owner"],
            "valid_from": project["valid_from"], "valid_until": project["valid_until"],
            "allowed_actions": json_value(project["allowed_actions_json"], []),
        },
        "authorized_seeds": json_value(project["seeds_json"], []),
        "excluded_seeds": json_value(project["exclusions_json"], []),
    }


def _upsert_observation(conn: sqlite3.Connection, project: sqlite3.Row, scan_id: str, row: dict[str, Any]) -> tuple[str, bool]:
    retrieved_at = utc_now()
    names = [n.strip().lower().rstrip(".") for n in str(row.get("hostname", "")).split(",") if n.strip()]
    names = [n for n in names if any(in_domain_scope(n, seed) for seed in json_value(project["seeds_json"], []))]
    names = [n for n in names if not any(in_domain_scope(n, exclusion) for exclusion in json_value(project["exclusions_json"], []))]
    if not names:
        return "", False
    primary_name = names[0]
    asset_key = "host:" + primary_name
    asset = conn.execute("SELECT * FROM assets WHERE project_id=? AND asset_key=?", (project["id"], asset_key)).fetchone()
    detail = {"hostnames": names, "ports": [], "services": [], "software": [], "provider": "Censys Platform"}
    if asset:
        detail = json_value(asset["details_json"], detail)
    service = {"port": row.get("port"), "protocol": row.get("protocol"), "transport": row.get("transport"), "software": row.get("software")}
    if service not in detail["services"]:
        detail["services"].append(service)
    try:
        port = int(row.get("port"))
        if port not in detail["ports"]:
            detail["ports"].append(port)
    except (TypeError, ValueError):
        port = 0
    if row.get("software") and row["software"] not in detail["software"]:
        detail["software"].append(row["software"])
    detail["hostnames"] = sorted(set(detail["hostnames"] + names))
    detail["ports"] = sorted(set(detail["ports"]))
    ip = str(row.get("ip", ""))
    if asset:
        asset_id = asset["id"]
        conn.execute(
            "UPDATE assets SET ip=?,status='active',last_seen=?,last_run_id=?,details_json=? WHERE id=?",
            (ip, retrieved_at, scan_id, json.dumps(detail), asset_id),
        )
        new_asset = False
    else:
        asset_id = "ast_" + uuid.uuid4().hex
        conn.execute(
            """INSERT INTO assets(id,tenant_id,project_id,asset_key,asset_type,primary_name,ip,source,
               ownership_state,confidence,criticality,status,first_seen,last_seen,last_run_id,details_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (asset_id, project["tenant_id"], project["id"], asset_key, "host", primary_name, ip,
             "censys-platform-search", "candidate", 0.6, "standard", "active", retrieved_at,
             retrieved_at, scan_id, json.dumps(detail)),
        )
        new_asset = True
    evidence = {"seed_match": names, "provider_record": {"ip": ip, "service": service}, "retrieved_at": retrieved_at,
                "notice": "Censys provider observation; not an ownership or vulnerability confirmation."}
    evidence_json = json.dumps(evidence, sort_keys=True)
    evidence_hash = hashlib.sha256(evidence_json.encode()).hexdigest()
    conn.execute(
        "INSERT INTO observations(id,tenant_id,project_id,asset_id,scan_id,source,retrieved_at,evidence_sha256,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
        ("obs_" + uuid.uuid4().hex, project["tenant_id"], project["id"], asset_id, scan_id,
         "censys-platform-search", retrieved_at, evidence_hash, evidence_json),
    )
    if port in SENSITIVE_PORTS:
        title, severity, guidance = SENSITIVE_PORTS[port]
        signal_key = f"exposed-observed-port:{port}:{primary_name}"
        existing = conn.execute("SELECT id FROM findings WHERE project_id=? AND signal_key=?", (project["id"], signal_key)).fetchone()
        description = f"A Censys record associated with {primary_name} included port {port}. {guidance} This observation is not a vulnerability confirmation."
        if existing:
            conn.execute("UPDATE findings SET last_seen=?,evidence_json=? WHERE id=?", (retrieved_at, evidence_json, existing["id"]))
        else:
            conn.execute(
                """INSERT INTO findings(id,tenant_id,project_id,asset_id,signal_key,title,description,severity,state,
                   source,first_seen,last_seen,evidence_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("fnd_" + uuid.uuid4().hex, project["tenant_id"], project["id"], asset_id, signal_key,
                 title, description, severity, "new", "censys-platform-search", retrieved_at, retrieved_at, evidence_json),
            )
    return asset_id, new_asset


def run_scan(scan_id: str) -> None:
    with db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan or scan["status"] not in ("queued", "running"):
            return
        project = conn.execute("SELECT * FROM projects WHERE id=?", (scan["project_id"],)).fetchone()
        conn.execute("UPDATE scans SET status='running',started_at=? WHERE id=?", (utc_now(), scan_id))
    try:
        if scan["mode"] == "demo":
            observations, query_log = collect_demo(_api_scope(project))
        else:
            scope = _api_scope(project)
            if scope["authorization"]["status"] != "approved" or "passive_censys_lookup" not in scope["authorization"]["allowed_actions"]:
                raise ScopeError("Consulta real bloqueada: escopo não aprovado para passive_censys_lookup.")
            today = date.today()
            if date.fromisoformat(scope["authorization"]["valid_from"]) > today or date.fromisoformat(scope["authorization"]["valid_until"]) < today:
                raise ScopeError("Consulta real bloqueada: autorização fora da validade.")
            observations, query_log = collect_censys(scope)
        asset_ids: set[str] = set()
        new_count = 0
        with db() as conn:
            current_project = conn.execute("SELECT * FROM projects WHERE id=?", (project["id"],)).fetchone()
            for item in observations:
                asset_id, is_new = _upsert_observation(conn, current_project, scan_id, item)
                if asset_id:
                    asset_ids.add(asset_id)
                    new_count += int(is_new)
            count_findings = conn.execute("SELECT COUNT(*) FROM findings WHERE project_id=? AND state NOT IN ('resolved','false_positive')", (project["id"],)).fetchone()[0]
            result = {"source": scan["mode"], "queries": query_log, "new_assets": new_count, "observations": len(observations),
                      "notice": "Provider records are observations. Review ownership and exposure before customer reporting."}
            conn.execute("UPDATE scans SET status='completed',completed_at=?,asset_count=?,candidate_count=?,result_json=? WHERE id=?",
                         (utc_now(), len(asset_ids), count_findings, json.dumps(result), scan_id))
            if project["mode"] == "censys" and project["scan_interval_hours"]:
                next_time = datetime.now(timezone.utc) + timedelta(hours=project["scan_interval_hours"])
                conn.execute("UPDATE projects SET next_scan_at=?,updated_at=? WHERE id=?", (next_time.replace(microsecond=0).isoformat(), utc_now(), project["id"]))
    except Exception as exc:
        token = censys_api_token()
        safe_error = str(exc).replace(token, "[REDACTED]") if token else str(exc)
        with db() as conn:
            conn.execute("UPDATE scans SET status='failed',completed_at=?,error_summary=? WHERE id=?",
                         (utc_now(), safe_error[:500], scan_id))


def schedule_scan(conn: sqlite3.Connection, project: sqlite3.Row, requester_id: str | None = None) -> str:
    scan_id = "run_" + uuid.uuid4().hex
    conn.execute(
        "INSERT INTO scans(id,tenant_id,project_id,mode,status,requested_by) VALUES(?,?,?,?,?,?)",
        (scan_id, project["tenant_id"], project["id"], project["mode"], "queued", requester_id),
    )
    return scan_id


async def scheduler_loop() -> None:
    while True:
        try:
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            due: list[str] = []
            with db() as conn:
                rows = conn.execute(
                    """SELECT * FROM projects WHERE mode='censys' AND scope_state='approved'
                       AND scan_interval_hours>=6 AND next_scan_at IS NOT NULL AND next_scan_at<=?""", (now,)
                ).fetchall()
                for project in rows:
                    scan_id = schedule_scan(conn, project)
                    next_time = datetime.now(timezone.utc) + timedelta(hours=project["scan_interval_hours"])
                    conn.execute("UPDATE projects SET next_scan_at=?,updated_at=? WHERE id=?",
                                 (next_time.replace(microsecond=0).isoformat(), now, project["id"]))
                    due.append(scan_id)
            for scan_id in due:
                await asyncio.to_thread(run_scan, scan_id)
        except Exception:
            # Keep the scheduler alive; failure details are recorded by each scan.
            pass
        await asyncio.sleep(60)


app = FastAPI(title="IT4US SOC EASM", version="1.0.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.on_event("startup")
async def startup() -> None:
    initialize()
    app.state.scheduler_task = asyncio.create_task(scheduler_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    task = getattr(app.state, "scheduler_task", None)
    if task:
        task.cancel()


@app.get("/health")
def health() -> dict[str, str]:
    with db() as conn:
        conn.execute("SELECT 1").fetchone()
    return {"status": "ok", "product": "IT4US SOC EASM"}


@app.get("/api/config/status")
def config_status(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if user["role"] == "client_viewer":
        return {"censys_ready": False, "customer_view": True}
    return {"censys_ready": bool(censys_api_token()), "censys_organization_configured": bool(os.environ.get("CENSYS_ORGANIZATION_ID"))}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.post("/api/auth/login")
def login(payload: dict[str, str], request: Request, response: Response) -> dict[str, Any]:
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")
    key = request.client.host if request.client else "unknown"
    with LOGIN_LOCK:
        attempts, until = LOGIN_ATTEMPTS.get(key, (0, datetime.now(timezone.utc)))
        if until > datetime.now(timezone.utc):
            raise HTTPException(status_code=429, detail="Too many login attempts")
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=? AND active=1", (email,)).fetchone()
        valid = bool(row and verify_password(password, row["password_hash"]))
        if not row:
            # Reduce account-enumeration timing differences.
            verify_password(password, "pbkdf2_sha256$310000$00112233445566778899aabbccddeeff$" + "0" * 64)
        if not valid:
            with LOGIN_LOCK:
                attempts += 1
                delay = datetime.now(timezone.utc) + timedelta(minutes=15) if attempts >= 7 else datetime.now(timezone.utc)
                LOGIN_ATTEMPTS[key] = (attempts, delay)
            raise HTTPException(status_code=401, detail="Email or password not recognized")
        with LOGIN_LOCK:
            LOGIN_ATTEMPTS.pop(key, None)
        token, csrf, expiry = new_session_values()
        conn.execute("INSERT INTO sessions(token_hash,csrf_hash,user_id,expires_at,created_at) VALUES(?,?,?,?,?)",
                     (token_hash(token), token_hash(csrf), row["id"], expiry, utc_now()))
        audit(conn, dict(row), "login", "session", "")
        response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=COOKIE_SECURE, samesite="strict", max_age=SESSION_HOURS * 3600, path="/")
        response.set_cookie("it4us_easm_csrf", csrf, httponly=False, secure=COOKIE_SECURE, samesite="strict", max_age=SESSION_HOURS * 3600, path="/")
        return {"csrf_token": csrf, "user": {"id": row["id"], "email": row["email"], "role": row["role"], "display_name": row["display_name"]}}


@app.get("/api/auth/session")
def session(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    with db() as conn:
        rows = accessible_projects(conn, user)
    csrf = request.cookies.get("it4us_easm_csrf", "")
    if not csrf or not secrets.compare_digest(token_hash(csrf), user["csrf_hash"]):
        csrf = ""
    return {"user": {"id": user["id"], "email": user["email"], "role": user["role"], "display_name": user["display_name"]},
            "csrf_token": csrf, "projects": [serialize_project(row, customer=user["role"] == "client_viewer") for row in rows]}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, user: dict[str, Any] = Depends(require_csrf)) -> dict[str, bool]:
    raw = request.cookies.get(SESSION_COOKIE, "")
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(raw),))
        audit(conn, user, "logout", "session")
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")
    response.delete_cookie("it4us_easm_csrf", path="/", secure=COOKIE_SECURE, samesite="strict")
    return {"ok": True}


@app.get("/api/projects")
def list_projects(user: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    with db() as conn:
        return [serialize_project(row, customer=user["role"] == "client_viewer") for row in accessible_projects(conn, user)]


@app.post("/api/projects", status_code=201)
def create_project(payload: ProjectCreate, user: dict[str, Any] = Depends(require_roles("admin"))) -> dict[str, Any]:
    from soc_easm import canonical_domain
    seeds = [canonical_domain(seed) for seed in payload.seeds]
    exclusions = [canonical_domain(seed) for seed in payload.exclusions]
    if len(set(seeds)) != len(seeds) or len(set(exclusions)) != len(exclusions):
        raise HTTPException(status_code=422, detail="Seeds and exclusions must be unique")
    if set(seeds) & set(exclusions) or any(not any(in_domain_scope(exclusion, seed) for seed in seeds) for exclusion in exclusions):
        raise HTTPException(status_code=422, detail="Every exclusion must be inside an authorized seed")
    try:
        start = date.fromisoformat(payload.valid_from)
        expiry = date.fromisoformat(payload.valid_until)
    except ValueError:
        raise HTTPException(status_code=422, detail="Authorization dates must use YYYY-MM-DD") from None
    if start > expiry or expiry < date.today():
        raise HTTPException(status_code=422, detail="Authorization dates are invalid or expired")
    project_id = "prj_" + uuid.uuid4().hex[:16]
    tenant_id = "cust_" + uuid.uuid4().hex[:16]
    now = utc_now()
    with db() as conn:
        conn.execute("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)", (tenant_id, payload.client_label.strip(), now))
        conn.execute(
            """INSERT INTO projects(id,tenant_id,name,client_label,mode,scope_state,authorization_reference,
               authorization_owner,valid_from,valid_until,created_by,created_at,updated_at,scan_interval_hours,
               seeds_json,exclusions_json,allowed_actions_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (project_id, tenant_id, payload.name.strip(), payload.client_label.strip(), "censys", "pending",
             payload.authorization_reference.strip(), payload.authorization_owner.strip(), payload.valid_from,
             payload.valid_until, user["id"], now, now, payload.scan_interval_hours, json.dumps(seeds),
             json.dumps(exclusions), "[]"),
        )
        audit(conn, user, "project_created_pending_scope", "project", project_id, project_id, {"seeds": seeds})
        row = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    return serialize_project(row)


@app.post("/api/projects/{project_id}/approve")
def approve_project(project_id: str, user: dict[str, Any] = Depends(require_roles("admin", "reviewer"))) -> dict[str, Any]:
    with db() as conn:
        project = project_row(conn, user, project_id, allow_client=False)
        if project["created_by"] == user["id"]:
            raise HTTPException(status_code=409, detail="Scope approval requires a second person")
        if project["scope_state"] != "pending":
            raise HTTPException(status_code=409, detail="Only pending projects can be approved")
        if not project["authorization_reference"] or not project["authorization_owner"]:
            raise HTTPException(status_code=422, detail="Authorization reference and owner are required")
        try:
            start = date.fromisoformat(project["valid_from"])
            expiry = date.fromisoformat(project["valid_until"])
        except ValueError:
            raise HTTPException(status_code=422, detail="Authorization dates are invalid") from None
        today = date.today()
        if start > today or expiry < today:
            raise HTTPException(status_code=409, detail="Authorization must be current")
        action_list = ["passive_censys_lookup"]
        next_scan = datetime.now(timezone.utc) + timedelta(hours=project["scan_interval_hours"])
        conn.execute("UPDATE projects SET scope_state='approved',approved_by=?,allowed_actions_json=?,next_scan_at=?,updated_at=? WHERE id=?",
                     (user["id"], json.dumps(action_list), next_scan.replace(microsecond=0).isoformat(), utc_now(), project_id))
        audit(conn, user, "project_scope_approved", "project", project_id, project_id,
              {"reference": project["authorization_reference"], "allowed_actions": action_list})
        row = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    return serialize_project(row)


@app.put("/api/projects/{project_id}/scope")
def amend_project_scope(project_id: str, payload: ScopeAmend, user: dict[str, Any] = Depends(require_roles("admin"))) -> dict[str, Any]:
    from soc_easm import canonical_domain
    seeds=[canonical_domain(x) for x in payload.seeds]
    exclusions=[canonical_domain(x) for x in payload.exclusions]
    if len(set(seeds))!=len(seeds) or len(set(exclusions))!=len(exclusions): raise HTTPException(status_code=422,detail="Seeds must be unique")
    if set(seeds)&set(exclusions) or any(not any(in_domain_scope(x,s) for s in seeds) for x in exclusions): raise HTTPException(status_code=422,detail="Exclusions must be contained by authorized seeds")
    try: start=date.fromisoformat(payload.valid_from); expiry=date.fromisoformat(payload.valid_until)
    except ValueError: raise HTTPException(status_code=422,detail="Authorization dates must use YYYY-MM-DD") from None
    if start>expiry or expiry<date.today(): raise HTTPException(status_code=422,detail="Authorization dates are invalid or expired")
    with db() as conn:
        project=project_row(conn,user,project_id,allow_client=False)
        if project["mode"]!="censys": raise HTTPException(status_code=409,detail="Demo project scope is fixed")
        conn.execute("""UPDATE projects SET seeds_json=?,exclusions_json=?,authorization_reference=?,authorization_owner=?,
                   valid_from=?,valid_until=?,scope_state='pending',approved_by=NULL,allowed_actions_json='[]',next_scan_at=NULL,updated_at=? WHERE id=?""",
                     (json.dumps(seeds),json.dumps(exclusions),payload.authorization_reference.strip(),payload.authorization_owner.strip(),
                      payload.valid_from,payload.valid_until,utc_now(),project_id))
        audit(conn,user,"project_scope_amended_pending_review","project",project_id,project_id,{"seeds":seeds,"exclusions":exclusions})
        row=conn.execute("SELECT * FROM projects WHERE id=?",(project_id,)).fetchone()
    return serialize_project(row)


@app.post("/api/projects/{project_id}/suspend")
def suspend_project(project_id: str, user: dict[str, Any] = Depends(require_roles("admin"))) -> dict[str, Any]:
    with db() as conn:
        project=project_row(conn,user,project_id,allow_client=False)
        if project["mode"]!="censys": raise HTTPException(status_code=409,detail="Demo project does not have a live schedule")
        conn.execute("UPDATE projects SET scope_state='suspended',allowed_actions_json='[]',next_scan_at=NULL,updated_at=? WHERE id=?",(utc_now(),project_id))
        audit(conn,user,"project_suspended","project",project_id,project_id)
        row=conn.execute("SELECT * FROM projects WHERE id=?",(project_id,)).fetchone()
    return serialize_project(row)


@app.patch("/api/projects/{project_id}/schedule")
def update_schedule(project_id: str,payload: ScheduleUpdate,user: dict[str,Any]=Depends(require_roles("admin")))->dict[str,Any]:
    with db() as conn:
        project=project_row(conn,user,project_id,allow_client=False)
        if project["mode"]!="censys" or project["scope_state"]!="approved": raise HTTPException(status_code=409,detail="Only approved Censys projects can be scheduled")
        next_time=datetime.now(timezone.utc)+timedelta(hours=payload.scan_interval_hours)
        conn.execute("UPDATE projects SET scan_interval_hours=?,next_scan_at=?,updated_at=? WHERE id=?",(payload.scan_interval_hours,next_time.replace(microsecond=0).isoformat(),utc_now(),project_id))
        audit(conn,user,"project_schedule_changed","project",project_id,project_id,{"interval_hours":payload.scan_interval_hours})
        row=conn.execute("SELECT * FROM projects WHERE id=?",(project_id,)).fetchone()
    return serialize_project(row)


@app.post("/api/projects/{project_id}/runs", status_code=202)
def start_run(project_id: str, background: BackgroundTasks, user: dict[str, Any] = Depends(require_roles("admin", "analyst", "reviewer"))) -> dict[str, Any]:
    with db() as conn:
        project = project_row(conn, user, project_id, allow_client=False)
        if project["mode"] == "censys":
            if project["scope_state"] != "approved" or "passive_censys_lookup" not in json_value(project["allowed_actions_json"], []):
                raise HTTPException(status_code=409, detail="Project scope is not approved for passive Censys collection")
            if date.fromisoformat(project["valid_from"]) > date.today() or date.fromisoformat(project["valid_until"]) < date.today():
                raise HTTPException(status_code=409, detail="Project authorization is not currently valid")
            if not censys_api_token():
                raise HTTPException(status_code=503, detail="Censys API token is not configured on this service")
        scan_id = schedule_scan(conn, project, user["id"])
        audit(conn, user, "passive_discovery_started", "scan", scan_id, project_id, {"mode": project["mode"]})
    background.add_task(run_scan, scan_id)
    return {"id": scan_id, "status": "queued", "mode": project["mode"], "message": "Passively querying provider data; no requests are sent to discovered assets."}


@app.get("/api/overview")
def overview(project_id: Optional[str] = None, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    with db() as conn:
        if project_id:
            project = project_row(conn, user, project_id)
        else:
            projects = accessible_projects(conn, user)
            if not projects:
                raise HTTPException(status_code=404, detail="No project assigned")
            project = projects[0]
        tenant_id = project["tenant_id"]
        assets = conn.execute("SELECT COUNT(*) n FROM assets WHERE project_id=? AND tenant_id=? AND status='active'", (project["id"], tenant_id)).fetchone()["n"]
        findings = conn.execute("SELECT severity,COUNT(*) n FROM findings WHERE project_id=? AND tenant_id=? AND state NOT IN ('resolved','false_positive') GROUP BY severity", (project["id"], tenant_id)).fetchall()
        finding_counts = {row["severity"]: row["n"] for row in findings}
        asset_types = conn.execute("SELECT asset_type,COUNT(*) n FROM assets WHERE project_id=? AND tenant_id=? AND status='active' GROUP BY asset_type", (project["id"], tenant_id)).fetchall()
        latest = conn.execute("SELECT * FROM scans WHERE project_id=? ORDER BY COALESCE(completed_at,started_at) DESC LIMIT 1", (project["id"],)).fetchone()
        recent = conn.execute(
            """SELECT f.*,a.primary_name asset_name FROM findings f LEFT JOIN assets a ON a.id=f.asset_id
               WHERE f.project_id=? AND f.tenant_id=? AND f.state NOT IN ('resolved','false_positive')
               ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
               f.last_seen DESC LIMIT 6""", (project["id"], tenant_id)
        ).fetchall()
        trend = conn.execute(
            """SELECT substr(first_seen,1,10) day,COUNT(*) n FROM assets WHERE project_id=? AND tenant_id=?
               AND first_seen>=? GROUP BY substr(first_seen,1,10) ORDER BY day""",
            (project["id"], tenant_id, (date.today()-timedelta(days=13)).isoformat()),
        ).fetchall()
        valid_scope = project["mode"] == "demo" or project["scope_state"] == "approved"
        return {
            "project": serialize_project(project, customer=user["role"] == "client_viewer"),
            "metrics": {"assets": assets, "findings": sum(finding_counts.values()), "critical": finding_counts.get("critical",0),
                        "high": finding_counts.get("high",0), "medium": finding_counts.get("medium",0), "low": finding_counts.get("low",0),
                        "new_14d": sum(row["n"] for row in trend), "scope_state": project["scope_state"]},
            "asset_types": [dict(row) for row in asset_types],
            "latest_run": ({"id": latest["id"], "mode": latest["mode"], "status": latest["status"],
                            "started_at": latest["started_at"], "completed_at": latest["completed_at"],
                            "asset_count": latest["asset_count"], "candidate_count": latest["candidate_count"]} if latest else None),
            "recent_findings": [{"id": r["id"],"title": r["title"],"severity": r["severity"],"state": r["state"],"asset_name": r["asset_name"],"last_seen": r["last_seen"]} for r in recent],
            "trend": [dict(row) for row in trend],
            "can_run": user["role"] in ("admin","analyst","reviewer") and valid_scope,
        }


@app.get("/api/assets")
def assets(project_id: str, q: str = "", asset_type: str = "", user: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    with db() as conn:
        project = project_row(conn, user, project_id)
        query = "SELECT * FROM assets WHERE project_id=? AND tenant_id=?"
        params: list[Any] = [project_id, project["tenant_id"]]
        if q.strip():
            query += " AND (primary_name LIKE ? OR ip LIKE ? OR details_json LIKE ?)"
            term = "%" + q.strip()[:100] + "%"
            params.extend([term, term, term])
        if asset_type:
            query += " AND asset_type=?"
            params.append(asset_type)
        query += " ORDER BY CASE criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, primary_name LIMIT 500"
        rows = conn.execute(query, params).fetchall()
        return [{"id": r["id"],"name": r["primary_name"],"type": r["asset_type"],"ip": r["ip"],
                 "ports": json_value(r["details_json"],{}).get("ports",[]),"source": r["source"],
                 "ownership_state": r["ownership_state"],"confidence": r["confidence"],"criticality": r["criticality"],
                 "status": r["status"],"first_seen": r["first_seen"],"last_seen": r["last_seen"]} for r in rows]


@app.get("/api/assets/{asset_id}")
def asset_detail(asset_id: str, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Asset not found")
        project = project_row(conn,user,row["project_id"])
        observations = conn.execute("SELECT source,retrieved_at,evidence_sha256,evidence_json FROM observations WHERE asset_id=? ORDER BY retrieved_at DESC LIMIT 20", (asset_id,)).fetchall()
        output = {"id":row["id"],"name":row["primary_name"],"ip":row["ip"],"type":row["asset_type"],
                  "source":row["source"],"ownership_state":row["ownership_state"],"confidence":row["confidence"],
                  "criticality":row["criticality"],"status":row["status"],"first_seen":row["first_seen"],
                  "last_seen":row["last_seen"],"details":json_value(row["details_json"],{}),
                  "observations":[{"source":x["source"],"retrieved_at":x["retrieved_at"],"evidence_sha256":x["evidence_sha256"],"evidence":json_value(x["evidence_json"],{})} for x in observations]}
        return output


@app.patch("/api/assets/{asset_id}")
def update_asset(asset_id: str, payload: AssetUpdate, user: dict[str, Any] = Depends(require_roles("admin","analyst","reviewer"))) -> dict[str, Any]:
    if payload.criticality not in ("standard","high","critical"):
        raise HTTPException(status_code=422, detail="Unsupported criticality")
    with db() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id=?",(asset_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Asset not found")
        project_row(conn,user,row["project_id"],allow_client=False)
        conn.execute("UPDATE assets SET criticality=? WHERE id=?",(payload.criticality,asset_id))
        audit(conn,user,"asset_criticality_updated","asset",asset_id,row["project_id"],{"criticality":payload.criticality})
    return {"ok":True,"criticality":payload.criticality}


@app.get("/api/findings")
def findings(project_id: str, severity: str = "", state: str = "", user: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    with db() as conn:
        project=project_row(conn,user,project_id)
        query = """SELECT f.*,a.primary_name asset_name,a.ip asset_ip FROM findings f
                  LEFT JOIN assets a ON a.id=f.asset_id WHERE f.project_id=? AND f.tenant_id=?"""
        params: list[Any] = [project_id,project["tenant_id"]]
        if user["role"] == "client_viewer":
            query += " AND f.state NOT IN ('false_positive')"
        if severity:
            query += " AND f.severity=?"
            params.append(severity)
        if state:
            query += " AND f.state=?"
            params.append(state)
        query += " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.last_seen DESC LIMIT 500"
        rows = conn.execute(query,params).fetchall()
        output=[]
        for r in rows:
            item={"id":r["id"],"title":r["title"],"description":r["description"],"severity":r["severity"],"state":r["state"],
                  "asset_name":r["asset_name"],"asset_ip":r["asset_ip"],"source":r["source"],"first_seen":r["first_seen"],"last_seen":r["last_seen"],
                  "evidence":json_value(r["evidence_json"],{})}
            if user["role"] != "client_viewer": item["analyst_note"]=r["analyst_note"]
            output.append(item)
        return output


@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: str, payload: FindingUpdate, user: dict[str, Any] = Depends(require_roles("admin","analyst","reviewer"))) -> dict[str, Any]:
    if payload.state not in ("new","triage","accepted","resolved","false_positive"):
        raise HTTPException(status_code=422, detail="Unsupported triage state")
    with db() as conn:
        row=conn.execute("SELECT * FROM findings WHERE id=?",(finding_id,)).fetchone()
        if not row: raise HTTPException(status_code=404,detail="Finding not found")
        project_row(conn,user,row["project_id"],allow_client=False)
        conn.execute("UPDATE findings SET state=?,analyst_note=? WHERE id=?",(payload.state,payload.analyst_note.strip(),finding_id))
        audit(conn,user,"finding_triaged","finding",finding_id,row["project_id"],{"state":payload.state})
    return {"ok":True,"state":payload.state}


@app.get("/api/runs")
def runs(project_id: str, user: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    with db() as conn:
        project=project_row(conn,user,project_id)
        rows=conn.execute("SELECT * FROM scans WHERE project_id=? AND tenant_id=? ORDER BY COALESCE(started_at,completed_at) DESC LIMIT 100",(project_id,project["tenant_id"])).fetchall()
        return [{"id":r["id"],"mode":r["mode"],"status":r["status"],"started_at":r["started_at"],"completed_at":r["completed_at"],
                 "asset_count":r["asset_count"],"candidate_count":r["candidate_count"],
                 "error_summary":("Falha na coleta; contate o SOC." if user["role"]=="client_viewer" and r["status"]=="failed" else ("" if user["role"]=="client_viewer" else r["error_summary"])),
                 "result":(json_value(r["result_json"],{}) if user["role"]!="client_viewer" else {"notice":"Dados de execução resumidos pelo SOC."})} for r in rows]


@app.get("/api/changes")
def changes(project_id: str, user: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    with db() as conn:
        project=project_row(conn,user,project_id)
        rows=conn.execute(
            """SELECT a.id,a.primary_name,a.ip,a.asset_type,a.first_seen,a.last_seen,a.source,a.ownership_state,a.confidence
               FROM assets a WHERE a.project_id=? AND a.tenant_id=? ORDER BY a.first_seen DESC LIMIT 200""",
            (project_id,project["tenant_id"])).fetchall()
        return [{"asset_id":r["id"],"asset_name":r["primary_name"],"ip":r["ip"],"asset_type":r["asset_type"],
                 "change":"first_observed" if r["first_seen"]==r["last_seen"] else "seen_again","date":r["first_seen"],
                 "source":r["source"],"ownership_state":r["ownership_state"],"confidence":r["confidence"]} for r in rows]


@app.get("/api/reports/summary")
def report_summary(project_id: str, format: str = "csv", user: dict[str, Any] = Depends(get_current_user)):
    with db() as conn:
        project=project_row(conn,user,project_id)
        customer=user["role"]=="client_viewer"
        assets_rows=conn.execute("SELECT * FROM assets WHERE project_id=? AND tenant_id=? ORDER BY primary_name",(project_id,project["tenant_id"])).fetchall()
        finding_query="SELECT * FROM findings WHERE project_id=? AND tenant_id=?" + (" AND state!='false_positive'" if customer else "") + " ORDER BY severity,last_seen DESC"
        findings_rows=conn.execute(finding_query,(project_id,project["tenant_id"])).fetchall()
        project_data=serialize_project(project,customer=customer)
    if format=="csv":
        stream=io.StringIO()
        writer=csv.writer(stream)
        writer.writerow(["Asset","Type","IP","Ports","Source","Ownership state","Confidence","Criticality","First seen","Last retrieved"])
        for a in assets_rows:
            detail=json_value(a["details_json"],{})
            writer.writerow([a["primary_name"],a["asset_type"],a["ip"],";".join(map(str,detail.get("ports",[]))),a["source"],a["ownership_state"],a["confidence"],a["criticality"],a["first_seen"],a["last_seen"]])
        return StreamingResponse(iter([stream.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f"attachment; filename=easm-{project_id}-assets.csv"})
    if format!="md":
        raise HTTPException(status_code=422,detail="format must be csv or md")
    lines=[f"# EASM report — {project_data['client_label'] or project_data['name']}","",f"Generated: {utc_now()} UTC","",
           "Provider data is observational and does not prove asset ownership or vulnerability. Review state and source timestamps before acting.","",
           f"## Inventory ({len(assets_rows)} assets)","","| Asset | Type | IP | Ports | State | Source |","|---|---|---|---|---|---|"]
    for a in assets_rows:
        detail=json_value(a["details_json"],{})
        lines.append(f"| {a['primary_name']} | {a['asset_type']} | {a['ip']} | {', '.join(map(str,detail.get('ports',[])))} | {a['ownership_state']} | {a['source']} |")
    lines += ["","## Exposures",""]
    if not findings_rows: lines.append("No exposure candidates recorded.")
    for f in findings_rows:
        lines += [f"### {f['severity'].upper()} — {f['title']}","",f"State: `{f['state']}` · Source: `{f['source']}`", "",f["description"],""]
        if not customer and f["analyst_note"]: lines += [f"Analyst note: {f['analyst_note']}",""]
    return StreamingResponse(iter(["\n".join(lines)]),media_type="text/markdown",headers={"Content-Disposition":f"attachment; filename=easm-{project_id}-report.md"})


@app.get("/api/users")
def list_users(user: dict[str, Any] = Depends(require_csrf)) -> list[dict[str, Any]]:
    if user["role"]!="admin": raise HTTPException(status_code=403,detail="Insufficient role")
    with db() as conn:
        rows=conn.execute("""SELECT u.id,u.email,u.display_name,u.role,u.active,u.created_at,t.name tenant_name
                           FROM users u JOIN tenants t ON t.id=u.tenant_id ORDER BY t.name,u.display_name""").fetchall()
        output=[]
        for row in rows:
            item=dict(row)
            item["project_ids"]=[m["project_id"] for m in conn.execute("SELECT project_id FROM project_members WHERE user_id=?",(row["id"],)).fetchall()]
            output.append(item)
        return output


@app.post("/api/users",status_code=201)
def create_user(payload: UserCreate,user: dict[str,Any]=Depends(require_roles("admin")))->dict[str,Any]:
    if payload.role not in ("analyst","reviewer","client_viewer"): raise HTTPException(status_code=422,detail="Unsupported role")
    email=payload.email.strip().lower()
    if "@" not in email: raise HTTPException(status_code=422,detail="Enter a valid email")
    if payload.role=="client_viewer" and not payload.project_ids: raise HTTPException(status_code=422,detail="Customer viewers require at least one project")
    user_id="usr_"+uuid.uuid4().hex
    with db() as conn:
        project_rows=[]
        tenant_id=user["tenant_id"]
        if payload.project_ids:
            for pid in payload.project_ids:
                project_rows.append(project_row(conn,user,pid,allow_client=False))
        if payload.role=="client_viewer":
            tenants={row["tenant_id"] for row in project_rows}
            if len(tenants)!=1:
                raise HTTPException(status_code=422,detail="A customer viewer can be assigned to projects from one customer only")
            tenant_id=next(iter(tenants))
        try:
            conn.execute("INSERT INTO users(id,tenant_id,email,password_hash,role,display_name,created_at) VALUES(?,?,?,?,?,?,?)",
                         (user_id,tenant_id,email,hash_password(payload.password),payload.role,payload.display_name.strip(),utc_now()))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409,detail="User already exists") from None
        for pid in payload.project_ids:
            conn.execute("INSERT INTO project_members(project_id,user_id) VALUES(?,?)",(pid,user_id))
        audit(conn,user,"user_created","user",user_id,detail={"role":payload.role,"project_ids":payload.project_ids})
    return {"id":user_id,"email":email,"display_name":payload.display_name,"role":payload.role,"active":1}


@app.get("/api/audit")
def audit_log(project_id: str, user: dict[str,Any]=Depends(require_roles("admin","analyst","reviewer"))) -> list[dict[str,Any]]:
    with db() as conn:
        project_row(conn,user,project_id,allow_client=False)
        project=project_row(conn,user,project_id,allow_client=False)
        rows=conn.execute("""SELECT a.*,u.email actor_email FROM audit_events a LEFT JOIN users u ON u.id=a.actor_user_id
                           WHERE a.tenant_id=? AND a.project_id=? ORDER BY a.created_at DESC LIMIT 200""",(project["tenant_id"],project_id)).fetchall()
        return [{"id":r["id"],"action":r["action"],"resource_type":r["resource_type"],"resource_id":r["resource_id"],"actor":r["actor_email"],"created_at":r["created_at"],"detail":json_value(r["detail_json"],{})} for r in rows]
