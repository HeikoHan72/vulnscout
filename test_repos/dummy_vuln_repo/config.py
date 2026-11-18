"""Projektkonfiguration.

In einer echten Anwendung kämen diese Werte aus Umgebungsvariablen oder einem
Secret-Manager - hier bewusst hartcodiert als Testfall für den Scanner.
"""

DB_ENCRYPTION_KEY = "s3cr3t-db-key-do-not-share"  # hartcodiertes Secret (Finding)

# Nicht sicherheitsrelevant: öffentlich bekannter Default-Port, kein Secret.
DEFAULT_PORT = 8080
