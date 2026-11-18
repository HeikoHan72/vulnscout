"""SQLite-Persistenz für Läufe, Findings und Triage-Bewertungen.

Bewusst mit der Standardbibliothek `sqlite3` statt SQLAlchemy umgesetzt,
um diese Komponente einfach und leicht nachvollziehbar zu halten.
Jeder Schritt der Pipeline (siehe `orchestrator.run_pipeline`) schreibt
seinen Zwischenstand sofort in die Datenbank, damit bei einem Absturz
nichts verloren geht.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import Optional

from src.scanner_agent.models import Finding
from src.triage_agent.models import TriageAssessment

from .models import RunStatus, ScanRun

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    scanner_errors_json TEXT NOT NULL,
    error_message TEXT,
    report_markdown TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    data_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs (id)
);

CREATE TABLE IF NOT EXISTS assessments (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    data_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs (id)
);
"""


class RunStore:
    """Dünne Persistenzschicht über einer SQLite-Datei.

    Jede Methode öffnet und schließt ihre eigene Verbindung, damit die
    Klasse ohne expliziten Kontextmanager verwendet werden kann und
    nebenläufige Zugriffe (z. B. aus Tests) unproblematisch sind.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def create_run(self, run: ScanRun) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO runs
                    (id, repo_path, status, created_at, updated_at,
                     scanner_errors_json, error_message, report_markdown)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    run.repo_path,
                    run.status.value,
                    run.created_at.isoformat(),
                    run.updated_at.isoformat(),
                    run.model_dump_json(include={"scanner_errors"}),
                    run.error_message,
                    run.report_markdown,
                ),
            )
            conn.commit()

    def update_run(self, run: ScanRun) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                UPDATE runs
                SET status = ?,
                    updated_at = ?,
                    scanner_errors_json = ?,
                    error_message = ?,
                    report_markdown = ?
                WHERE id = ?
                """,
                (
                    run.status.value,
                    run.updated_at.isoformat(),
                    run.model_dump_json(include={"scanner_errors"}),
                    run.error_message,
                    run.report_markdown,
                    run.id,
                ),
            )
            conn.commit()

    def get_run(self, run_id: str) -> Optional[ScanRun]:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        if row is None:
            return None
        import json

        scanner_errors = json.loads(row["scanner_errors_json"]).get(
            "scanner_errors", {}
        )
        return ScanRun(
            id=row["id"],
            repo_path=row["repo_path"],
            status=RunStatus(row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            scanner_errors=scanner_errors,
            error_message=row["error_message"],
            report_markdown=row["report_markdown"],
        )

    def save_findings(self, run_id: str, findings: list[Finding]) -> None:
        with closing(self._connect()) as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO findings (id, run_id, data_json) "
                "VALUES (?, ?, ?)",
                [(f.id, run_id, f.model_dump_json()) for f in findings],
            )
            conn.commit()

    def get_findings(self, run_id: str) -> list[Finding]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT data_json FROM findings WHERE run_id = ?", (run_id,)
            ).fetchall()
        return [Finding.model_validate_json(r["data_json"]) for r in rows]

    def save_assessments(
        self, run_id: str, assessments: list[TriageAssessment]
    ) -> None:
        with closing(self._connect()) as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO assessments "
                "(finding_id, run_id, data_json) VALUES (?, ?, ?)",
                [
                    (a.finding_id, run_id, a.model_dump_json())
                    for a in assessments
                ],
            )
            conn.commit()

    def get_assessments(self, run_id: str) -> list[TriageAssessment]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT data_json FROM assessments WHERE run_id = ?",
                (run_id,),
            ).fetchall()
        return [
            TriageAssessment.model_validate_json(r["data_json"]) for r in rows
        ]
