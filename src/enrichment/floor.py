"""Untergrenze für den Schweregrad bestätigter Abhängigkeits-Funde.

Warum: Die Triage bewertet Abhängigkeits-Funde ohne Code-Kontext. Sie sieht
weder, ob die verwundbare Funktion aufgerufen wird, noch, wie die Anwendung
betrieben wird. Eine Absenkung unter den veröffentlichten Schweregrad der
Datenbank OSV beruht deshalb auf Annahmen. In einem Sicherheitswerkzeug ist
es die vorsichtigere Richtung, den veröffentlichten Wert nicht zu
unterschreiten. Höher einstufen darf die Triage weiterhin.

Was: Für Funde von pip-audit mit OSV-Schweregrad, die als echter Treffer
bestätigt sind, wird `assessment.severity` mindestens auf den OSV-Wert
gesetzt. Dabei gilt:
- Die ursprüngliche Einstufung bleibt in `severity_raised_from` erhalten.
- Der CVSS-ähnliche Score wird auf mindestens die Untergrenze der Stufe
  gesetzt (low 0,1, medium 4,0, high 7,0, critical 9,0 nach der
  üblichen CVSS-Einteilung), damit Stufe und Score nicht auseinanderlaufen.
- Die Begründung nennt die Anhebung, auch im Bericht.
- Die Metrik `vulnscout_severity_floor_total` zählt angehoben und unverändert.

Das Schweregrad-Wort der Datenbank und die CVSS-Vektoren können zu
unterschiedlichen Stufen führen (siehe `display.py`). Die Untergrenze folgt
dem Wort, das die Datenbank selbst als Schweregrad angibt.

Fehlalarme (`is_true_positive=False`) und Funde ohne OSV-Schweregrad bleiben
unberührt.
"""

from __future__ import annotations

import logging
from typing import Sequence

from src.monitoring import metrics as m
from src.scanner_agent.models import Finding, Severity, ToolName
from src.triage_agent.models import TriageAssessment

logger = logging.getLogger(__name__)

_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

# Untere Grenze des Scores je Stufe (CVSS-Einteilung: 0,1-3,9 / 4,0-6,9 /
# 7,0-8,9 / 9,0-10,0).
_MIN_SCORE = {
    Severity.LOW: 0.1,
    Severity.MEDIUM: 4.0,
    Severity.HIGH: 7.0,
    Severity.CRITICAL: 9.0,
}


def _count(result: str) -> None:
    try:
        m.SEVERITY_FLOOR.labels(result=result).inc()
    except Exception:  # noqa: BLE001 - Monitoring darf nie durchschlagen
        logger.exception("Metrik der OSV-Untergrenze konnte nicht geschrieben werden")


def apply_osv_severity_floor(
    findings: Sequence[Finding], assessments: Sequence[TriageAssessment]
) -> int:
    """Hebt die Einstufung bestätigter Abhängigkeits-Funde auf den OSV-Wert an.

    Ändert die Bewertungen in `assessments` an Ort und Stelle; `findings`
    bleiben unverändert.

    Returns:
        Die Zahl der angehobenen Bewertungen.
    """
    by_id = {f.id: f for f in findings}
    raised = 0

    for assessment in assessments:
        finding = by_id.get(assessment.finding_id)
        if (
            finding is None
            or finding.tool != ToolName.PIP_AUDIT
            or finding.osv_severity is None
            or not assessment.is_true_positive
        ):
            continue

        floor = finding.osv_severity
        if floor not in _RANK:
            continue

        if _RANK.get(assessment.severity, -1) >= _RANK[floor]:
            _count("unchanged")
            continue

        original = assessment.severity
        assessment.severity_raised_from = original
        assessment.severity = floor

        note = (
            f" [Automatisch angehoben: Die Einstufung lag bei {original.value}, die "
            f"OSV-Datenbank ({finding.severity_source}) nennt {floor.value}. Dieser "
            f"Wert gilt als Untergrenze."
        )
        if assessment.cvss_score < _MIN_SCORE[floor]:
            assessment.cvss_score = _MIN_SCORE[floor]
            note += f" Der CVSS-ähnliche Score wurde auf mindestens {_MIN_SCORE[floor]} gesetzt."
        assessment.reasoning = (assessment.reasoning or "") + note + "]"

        raised += 1
        _count("raised")

    return raised
