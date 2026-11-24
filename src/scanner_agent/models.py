"""Datenmodelle für VulnScout.

Enthält das einheitliche Finding-Format, in das die Ausgabe aller drei
Scanner (Bandit, pip-audit, Semgrep) übersetzt wird. Alles, was danach
im System passiert (Triage-Agent, Report-Agent, MLflow-Logging),
arbeitet ausschließlich mit diesem Format und muss die Eigenheiten der
einzelnen Tools nicht mehr kennen.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vereinheitlichter Schweregrad über alle Scanner hinweg.

    Die Rohwerte der Tools (z. B. Bandit "MEDIUM", Semgrep "WARNING")
    werden beim Parsen auf diese vier Stufen abgebildet. Der
    Triage-Agent darf diese Einstufung später anheben oder absenken;
    der Rohwert jedes Tools bleibt dafür zusätzlich in `raw_severity`
    erhalten.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ToolName(str, Enum):
    """Die drei Scanner-Tools, aus denen Funde stammen können."""

    BANDIT = "bandit"
    PIP_AUDIT = "pip-audit"
    SEMGREP = "semgrep"


class Finding(BaseModel):
    """Ein einzelner, vereinheitlichter Scanner-Fund.

    Attributes:
        id: Eindeutige ID für diesen Fund (Tracking über die Pipeline
            hinweg, z. B. in MLflow oder im Bericht).
        tool: Welches Scanner-Tool den Fund gemeldet hat.
        rule_id: Die Regel- bzw. Check-ID des Tools (z. B. Bandit
            "B608", Semgrep-Rule-ID, pip-audit CVE/GHSA-ID).
        severity: Vereinheitlichter Schweregrad (siehe `Severity`).
        raw_severity: Der unveränderte Original-Wert des Tools, falls
            vorhanden. Wichtig für Nachvollziehbarkeit.
        confidence: Konfidenz-Angabe des Tools, falls vorhanden
            (Bandit liefert das, Semgrep/pip-audit meist nicht).
        file_path: Pfad der betroffenen Datei, relativ zum gescannten
            Repository. Bei pip-audit-Funden (betrifft eine
            Abhängigkeit, keine Code-Zeile) steht hier die
            requirements-Datei, falls bekannt, sonst None.
        line_start: Erste betroffene Zeile, falls vorhanden.
        line_end: Letzte betroffene Zeile, falls vorhanden.
        code_snippet: Betroffener Code-Ausschnitt, falls das Tool ihn
            mitliefert. Wird dem Triage-Agenten später als Kontext
            mitgegeben.
        title: Kurzer, menschenlesbarer Titel des Fundes.
        description: Ausführlichere Beschreibung, falls vom Tool
            geliefert.
        cwe: CWE-Nummer, falls das Tool eine liefert (Bandit und
            Semgrep tun das teilweise).
        package: Betroffenes Paket, nur bei pip-audit-Funden gesetzt.
        installed_version: Installierte Version des Pakets, nur bei
            pip-audit-Funden gesetzt.
        fix_versions: Versionen, in denen die Lücke laut pip-audit
            behoben ist.
        osv_severity: Schweregrad aus der öffentlichen Datenbank OSV, nur bei
            pip-audit-Funden und nur, wenn die Anreicherung (siehe
            `src/enrichment/osv.py`) einen gefunden hat. Steht bewusst in
            einem eigenen Feld: `severity` bleibt der Wert des Scanners, weil
            das Pre-Filter-Modell ihn als Merkmal nutzt.
        cvss_vector: CVSS-Vektor aus OSV, unverändert übernommen.
        osv_cwe_ids: CWE-Nummern aus OSV. Eigenes Feld aus demselben Grund
            wie `osv_severity` (`cwe` ist ein Merkmal des Pre-Filters).
        osv_aliases: Weitere IDs derselben Schwachstelle laut OSV (z. B.
            CVE- und GHSA-Kennungen).
        severity_source: Woher `osv_severity` stammt, als "osv:<ID>" mit dem
            Eintrag, der den Schweregrad geliefert hat. `None`, wenn keiner
            geliefert wurde.
        raw: Unveränderte Rohausgabe des Tools für genau diesen Fund,
            zur Nachvollziehbarkeit und für Debugging.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool: ToolName
    rule_id: str
    severity: Severity
    raw_severity: Optional[str] = None
    confidence: Optional[str] = None

    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None

    title: str
    description: Optional[str] = None
    cwe: Optional[str] = None

    package: Optional[str] = None
    installed_version: Optional[str] = None
    fix_versions: list[str] = Field(default_factory=list)

    osv_severity: Optional[Severity] = None
    cvss_vector: Optional[str] = None
    osv_cwe_ids: list[str] = Field(default_factory=list)
    osv_aliases: list[str] = Field(default_factory=list)
    severity_source: Optional[str] = None

    raw: dict = Field(default_factory=dict)
