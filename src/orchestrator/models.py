"""Datenmodell für einen VulnScout-Lauf (einen Scan eines Repos)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RunStatus(str, Enum):
    """Status eines Laufs. Wird nach jedem Schritt in der Datenbank
    aktualisiert, damit nach einem Absturz sichtbar ist, wie weit der
    Lauf gekommen ist.
    """

    SCANNING = "scanning"
    TRIAGING = "triaging"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRun(BaseModel):
    """Ein vollständiger VulnScout-Durchlauf für ein Repository.

    Attributes:
        id: Eindeutige Lauf-ID.
        repo_path: Pfad des gescannten Repositories.
        status: Aktueller Status (siehe `RunStatus`).
        created_at: Zeitpunkt, zu dem der Lauf angelegt wurde.
        updated_at: Zeitpunkt der letzten Statusänderung.
        scanner_errors: Tool-Name -> Fehlermeldung, für Scanner, die
            in diesem Lauf fehlgeschlagen sind.
        error_message: Fehlertext, falls `status == FAILED`.
        report_markdown: Der fertige Bericht, sobald `status ==
            COMPLETED`.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_path: str
    status: RunStatus = RunStatus.SCANNING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scanner_errors: dict[str, str] = Field(default_factory=dict)
    error_message: Optional[str] = None
    report_markdown: Optional[str] = None
