"""Datenbankzugriffe (absichtlich verwundbar)."""

import sqlite3


def get_user(username: str):
    """SQL-Injection (Finding): Benutzereingabe wird per String-Konkatenation
    direkt in die Query eingebaut.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


def get_active_users():
    """Mehrdeutiger Fall (Testfall für den Consensus-Mechanismus):

    Die String-Konkatenation sieht wie eine SQL-Injection aus, der
    eingefügte Wert ist aber eine feste Konstante ohne jede Benutzereingabe.
    Scanner (z. B. Bandit B608) markieren das Muster trotzdem, weil sie nur
    die Syntax prüfen, nicht die Datenherkunft.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    status = "active"  # fest im Code, keine Benutzereingabe
    query = "SELECT * FROM users WHERE status = '" + status + "'"
    cursor.execute(query)
    return cursor.fetchall()


def get_user_safe(username: str):
    """Sicheres Gegenbeispiel: parametrisierte Query. Kein Finding erwartet."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()
