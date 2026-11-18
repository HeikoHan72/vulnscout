"""Datenmodelle für den Report-Agenten."""

from __future__ import annotations

from pydantic import BaseModel, Field

from src.scanner_agent.models import Finding
from src.triage_agent.models import TriageAssessment


class FindingWithAssessment(BaseModel):
    """Ein Fund zusammen mit seiner Triage-Bewertung."""

    finding: Finding
    assessment: TriageAssessment


class ReportContext(BaseModel):
    """Alle Daten, die der Report-Agent braucht, um den Bericht zu
    schreiben - bereits vom Code vorberechnet (Zählungen, Sortierung,
    Filterung), damit das LLM keine Zahlen erfinden oder nachrechnen
    muss.

    Attributes:
        repo_name: Name/Pfad des gescannten Repositories, für die
            Berichtsüberschrift.
        detailed: Bestätigte Funde (true positive, nicht needs_review),
            nach Schweregrad sortiert, ggf. auf `MAX_DETAILED_FINDINGS`
            gekappt (siehe `truncated`).
        needs_review: Funde, bei denen der Consensus-Check im
            Triage-Agenten uneinig war - werden im Bericht gesondert
            als "braucht menschliche Prüfung" ausgewiesen.
        false_positive_count: Anzahl der vom Triage-Agenten als
            Fehlalarm eingestuften Funde (werden nicht einzeln
            aufgeführt, nur gezählt).
        counts_by_severity: Anzahl bestätigter Funde pro Schweregrad.
        total_confirmed: Gesamtzahl bestätigter Funde (vor Kappung).
        truncated: True, wenn `detailed` wegen zu vieler Funde gekappt
            wurde (siehe Risikotabelle: Massenfunde nicht komplett in
            einen Prompt packen).
        scanner_errors: Tool-Name -> Fehlermeldung, für Scanner, die
            beim Lauf fehlgeschlagen sind. Wird im Bericht transparent
            genannt, damit niemand annimmt, der Scan sei vollständig
            gewesen, obwohl z. B. Semgrep nicht lief.
    """

    repo_name: str
    detailed: list[FindingWithAssessment] = Field(default_factory=list)
    needs_review: list[FindingWithAssessment] = Field(default_factory=list)
    false_positive_count: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    total_confirmed: int = 0
    truncated: bool = False
    scanner_errors: dict[str, str] = Field(default_factory=dict)
