#!/usr/bin/env python3
"""Start the EASM console on loopback; load .env and bootstrap an admin on first run."""
from __future__ import annotations

import getpass
import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE pairs from .env into the environment without overwriting
    values already set in the shell. No external dependency."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


# Plug-and-play: put CENSYS_API_TOKEN (and optional bootstrap creds) in .env once.
load_dotenv(ROOT / ".env")

os.environ.setdefault("EASM_DB_PATH", str(ROOT / "data" / "easm.sqlite"))
os.environ.setdefault("EASM_HOST", "127.0.0.1")
os.environ.setdefault("EASM_PORT", "8765")

db_path = Path(os.environ["EASM_DB_PATH"])
user_count = 0
if db_path.exists():
    try:
        with sqlite3.connect(db_path) as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except sqlite3.Error:
        user_count = 0

have_bootstrap = bool(os.environ.get("EASM_BOOTSTRAP_EMAIL") and os.environ.get("EASM_BOOTSTRAP_PASSWORD"))
if user_count == 0 and not have_bootstrap:
    email = input("Email do administrador SOC: ").strip().lower()
    while True:
        password = getpass.getpass("Senha inicial (mínimo 14 caracteres): ")
        confirm = getpass.getpass("Confirme a senha: ")
        if len(password) >= 14 and password == confirm:
            break
        print("Senhas precisam coincidir e ter pelo menos 14 caracteres.")
    os.environ["EASM_BOOTSTRAP_EMAIL"] = email
    os.environ["EASM_BOOTSTRAP_PASSWORD"] = password

import uvicorn  # noqa: E402

uvicorn.run("app.main:app", host=os.environ["EASM_HOST"], port=int(os.environ["EASM_PORT"]), workers=1)
