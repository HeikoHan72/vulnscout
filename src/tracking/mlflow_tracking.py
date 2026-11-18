"""MLflow-Tracking für VulnScout-Läufe.

Protokolliert pro Lauf: Dauer, Anzahl Funde je Schweregrad (nur
bestätigte Funde), Anzahl Fehlalarme, Anzahl Funde ohne Konsens
(`needs_review`), Scanner-Fehler und – bei Erfolg – den Bericht als
Text-Artefakt.

Tracking ist bewusst best-effort: Ist kein MLflow-Tracking-Server
erreichbar oder schlägt das Logging aus einem anderen Grund fehl,
wird der Fehler nur geloggt, nie weitergeworfen. Ein Tracking-Ausfall
darf einen sonst erfolgreichen (oder kontrolliert fehlgeschlagenen)
Scan-Lauf nicht zusätzlich zum Scheitern bringen.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Optional

import mlflow

from src.orchestrator.models import ScanRun
from src.triage_agent.models import TriageAssessment

logger = logging.getLogger(__name__)

EXPERIMENT_NAME = "vulnscout"

# MLflow-Parameterwerte werden auf diese Länge gekürzt, um die
# serverseitigen Limits (standardmäßig 500 Zeichen) nicht zu reißen.
MAX_PARAM_LENGTH = 250


def log_run(
    run: ScanRun,
    assessments: Optional[list[TriageAssessment]] = None,
    duration_seconds: Optional[float] = None,
) -> None:
    """Protokolliert einen abgeschlossenen oder fehlgeschlagenen Lauf.

    Args:
        run: Der fertige (oder fehlgeschlagene) `ScanRun`.
        assessments: Triage-Bewertungen dieses Laufs, falls die
            Triage-Phase erreicht wurde. Leer/`None`, wenn der Lauf
            schon beim Scan gescheitert ist.
        duration_seconds: Gesamtdauer des Laufs in Sekunden, falls
            bekannt.
    """
    assessments = assessments or []
    try:
        mlflow.set_experiment(EXPERIMENT_NAME)
        with mlflow.start_run(run_name=run.id):
            mlflow.log_param("repo_path", run.repo_path)
            mlflow.log_param("status", run.status.value)

            if duration_seconds is not None:
                mlflow.log_metric("duration_seconds", duration_seconds)

            mlflow.log_metric("scanner_error_count", len(run.scanner_errors))

            if assessments:
                true_positives = [a for a in assessments if a.is_true_positive]
                false_positive_count = sum(
                    1 for a in assessments if not a.is_true_positive
                )
                needs_review_count = sum(1 for a in assessments if a.needs_review)

                severity_counts = Counter(a.severity.value for a in true_positives)
                for severity, count in severity_counts.items():
                    mlflow.log_metric(f"findings_{severity}", count)

                mlflow.log_metric("true_positive_count", len(true_positives))
                mlflow.log_metric("false_positive_count", false_positive_count)
                mlflow.log_metric("needs_review_count", needs_review_count)

            if run.report_markdown:
                mlflow.log_text(run.report_markdown, "report.md")

            if run.error_message:
                mlflow.log_param(
                    "error_message", run.error_message[:MAX_PARAM_LENGTH]
                )

    except Exception:  # noqa: BLE001 - Tracking darf den Lauf nie kippen
        logger.exception("MLflow-Tracking für Lauf %s fehlgeschlagen", run.id)
