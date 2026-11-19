"""Überträgt das Ergebnis eines Laufs in die Prometheus-Metriken.

Gegenstück zu `src.tracking.mlflow_tracking.log_run`: MLflow hält jeden
Lauf einzeln und dauerhaft fest (für den Vergleich im Nachhinein),
Prometheus liefert den laufenden Betrieb in Zahlen (für Dashboards und
Alarme). Beide werden an derselben Stelle im Orchestrator aufgerufen.

Wie das Tracking ist auch das hier bewusst best-effort: Ein Fehler beim
Zählen wird geloggt, nie weitergeworfen. Monitoring darf einen Scan-Lauf
niemals zum Scheitern bringen.
"""

from __future__ import annotations

import logging
from collections import Counter as CountBy
from typing import TYPE_CHECKING, Optional

from src.monitoring import metrics as m

# Nur für die Typangaben importiert, nicht zur Laufzeit: Der Orchestrator
# importiert dieses Modul, und ein Rückimport seiner Modelle würde einen
# Importzyklus erzeugen. Dank `from __future__ import annotations` stehen
# die Typangaben ohnehin als Zeichenketten im Code.
if TYPE_CHECKING:
    from src.orchestrator.models import ScanRun
    from src.scanner_agent.models import Finding
    from src.triage_agent.models import TriageAssessment

logger = logging.getLogger(__name__)


def record_run(
    run: "ScanRun",
    findings: Optional[list["Finding"]] = None,
    assessments: Optional[list["TriageAssessment"]] = None,
    duration_seconds: Optional[float] = None,
    demo_mode: Optional[bool] = None,
) -> None:
    """Zählt einen abgeschlossenen oder fehlgeschlagenen Lauf.

    Args:
        run: Der fertige (oder fehlgeschlagene) `ScanRun`.
        findings: Rohe Scanner-Funde, falls die Scan-Phase erreicht wurde.
        assessments: Triage-Bewertungen, falls die Triage-Phase erreicht
            wurde. Leer/`None`, wenn der Lauf vorher gescheitert ist.
        duration_seconds: Gesamtdauer des Laufs in Sekunden.
        demo_mode: Ob der Lauf ohne LLM (Demo-Modus) lief.
    """
    findings = findings or []
    assessments = assessments or []
    try:
        m.SCANS.labels(run.status.value).inc()

        if duration_seconds is not None:
            m.SCAN_DURATION.observe(duration_seconds)

        if demo_mode is not None:
            m.SCAN_MODE.labels("demo" if demo_mode else "llm").inc()

        # Funde je Werkzeug - zeigt, ob ein Scanner plötzlich nichts mehr
        # liefert (ein Hinweis auf ein kaputtes Werkzeug, nicht auf sauberen
        # Code).
        for tool, count in CountBy(f.tool.value for f in findings).items():
            m.FINDINGS.labels(tool).inc(count)

        # Scanner-Fehler je Werkzeug, aus dem Fehler-Wörterbuch des Laufs.
        for tool in run.scanner_errors:
            m.SCANNER_ERRORS.labels(tool).inc()

        for assessment in assessments:
            if assessment.needs_review:
                m.TRIAGE_RESULTS.labels("needs_review").inc()
            elif assessment.is_true_positive:
                m.TRIAGE_RESULTS.labels("true_positive").inc()
            else:
                m.TRIAGE_RESULTS.labels("false_positive").inc()

            m.TRIAGE_CONFIDENCE.observe(assessment.confidence)

            if assessment.is_true_positive:
                m.CONFIRMED_BY_SEVERITY.labels(assessment.severity.value).inc()

    except Exception:  # noqa: BLE001 - Monitoring darf den Lauf nie kippen
        logger.exception("Prometheus-Metriken für Lauf %s fehlgeschlagen", run.id)
