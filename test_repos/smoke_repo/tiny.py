"""Minimales Testziel fuer den Rauchtest des LLM-Pfads.

Absichtlich unsicher, aber bewusst klein gehalten: wenige Funde bedeuten
wenige LLM-Aufrufe und damit minimale Kosten beim ersten echten Lauf
gegen die Anthropic-API. Nicht ausfuehren, nicht deployen.

Intentionally insecure, deliberately tiny: few findings mean few LLM
calls and minimal cost for the first real API run. Do not run, do not
deploy.
"""

import hashlib
import os
import sqlite3

TOKEN = "sk-test-not-a-real-key-000"  # hartcodiertes Secret (erfunden)


def lookup(username: str):
    """SQL-Injection: Benutzereingabe per Konkatenation in die Query."""
    conn = sqlite3.connect("tiny.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE u = '" + username + "'")
    return cur.fetchall()


def archive(path: str):
    """Command Injection: Benutzereingabe direkt an die Shell."""
    os.system("tar -cf out.tar " + path)


def fingerprint(value: str) -> str:
    """Mehrdeutiger Fall: MD5 nur als Cache-Schluessel, nicht fuer Passwoerter."""
    return hashlib.md5(value.encode()).hexdigest()
