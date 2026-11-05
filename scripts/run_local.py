#!/usr/bin/env python3
"""Start the EASM console on loopback; ask for a bootstrap admin on first run."""
from __future__ import annotations

import getpass
import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
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
if user_count == 0:
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
