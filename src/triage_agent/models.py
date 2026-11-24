"""Datenmodell für die Ausgabe des Triage-Agenten."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from src.scanner_agent.models import Severity


class TriageAssessment(BaseModel):
    """Bewertung eines einzelnen Scanner-Funds durch den Triage-Agenten.

    Attributes:
        finding_id: ID des zugehörigen `Finding` (siehe `scanner_agent.models`).
        is_true_positive: Ob der Triage-Agent den Fund für echt hält
            (True) oder für einen Fehlalarm (False).
        severity: Vereinheitlichter Schweregrad, kann vom rohen
            Scanner-Schweregrad abweichen (der Triage-Agent darf
            korrigieren, z. B. einen von Bandit als MEDIUM markierten
            Fund im Kontext als HIGH einstufen).
        cvss_score: CVSS-ähnlicher Score (0-10) als feinere
            Abstufung zusätzlich zur groben Severity-Stufe.
        confidence: Wie sicher sich der Triage-Agent bei dieser
            Bewertung ist (0-1). Werte unterhalb der in
            `triage.CONFIDENCE_THRESHOLD` definierten Schwelle lösen
            einen Consensus-Check aus.
        reasoning: Kurze, nachvollziehbare Begründung des Agenten.
        severity_raised_from: Nur gesetzt, wenn `severity` nachträglich auf
            den Wert der OSV-Datenbank angehoben wurde (siehe
            `src/enrichment/floor.py`). Enthält dann die ursprüngliche
            Einstufung des Triage-Agenten, damit die Anhebung nachprüfbar
            bleibt.
        needs_review: Wird nachträglich auf True gesetzt, wenn ein
            Consensus-Check zu keiner Übereinstimmung kam. Solche
            Funde sollten im Report gesondert markiert werden, nicht
            automatisch verworfen oder bestätigt.
    """

    finding_id: str
    is_true_positive: bool
    severity: Severity
    cvss_score: float = Field(ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    reasoning: str
    needs_review: bool = False
    severity_raised_from: Optional[Severity] = None
