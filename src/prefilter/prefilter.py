"""Wendet das trainierte Pre-Filter-Modell auf neue Funde an.

Design-Entscheidungen:
- Best-effort wie Monitoring und MLflow-Tracking (siehe
  `src/monitoring/record.py`, `src/tracking/mlflow_tracking.py`): ist
  kein Champion-Modell in der MLflow Model Registry registriert, nicht
  erreichbar oder schlägt die Anwendung aus einem anderen Grund fehl,
  gehen schlicht ALLE Funde an die LLM-Triage - genau das Verhalten vor
  Einführung des Pre-Filters. Der Pre-Filter darf einen Scan nie zum
  Absturz bringen oder verlangsamen (ein einmaliges Laden des Modells
  pro Prozess ausgenommen).
- Das Modell selbst trifft nur dann eine automatische Entscheidung
  (`true_positive`/`false_positive`), wenn es sich beim Training als
  ausreichend sicher erwiesen hat (siehe Schwellenwerte in
  `scripts/train_prefilter.py`). Alles andere wird als "escalate"
  zurückgegeben und landet ganz normal beim LLM.
"""

from __future__ import annotations

import logging
from typing import Optional

import pandas as pd

from src.monitoring import metrics as m
from src.scanner_agent.models import Finding, Severity
from src.triage_agent.models import TriageAssessment

from .features import FEATURE_COLUMNS, finding_to_features

logger = logging.getLogger(__name__)

MODEL_URI = "models:/vulnscout-prefilter@champion"

# Grober CVSS-Platzhalter je Schweregrad für automatisch entschiedene
# Funde - das Pre-Filter-Modell liefert keinen CVSS-Score, das
# TriageAssessment-Modell verlangt aber einen. Nur eine grobe
# Einordnung, keine echte CVSS-Berechnung.
_CVSS_BY_SEVERITY = {
    Severity.LOW: 2.0,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 9.5,
    Severity.UNKNOWN: 5.0,
}

_model = None
_model_load_attempted = False


def _load_model():
    """Lädt das Champion-Modell aus der MLflow Model Registry, einmal pro
    Prozess. Gibt `None` zurück, wenn kein Modell verfügbar ist."""
    global _model, _model_load_attempted
    if _model_load_attempted:
        return _model
    _model_load_attempted = True
    try:
        import mlflow.pyfunc

        _model = mlflow.pyfunc.load_model(MODEL_URI)
        logger.info("Pre-Filter-Modell geladen: %s", MODEL_URI)
    except Exception:  # noqa: BLE001 - best effort, siehe Modul-Docstring
        logger.info(
            "Kein Pre-Filter-Modell verfügbar (%s) - alle Funde gehen an die LLM-Triage.",
            MODEL_URI,
        )
        _model = None
    return _model


def apply_prefilter(
    findings: list[Finding],
) -> tuple[list[Finding], list[TriageAssessment]]:
    """Teilt `findings` in "ans LLM weiterreichen" und "schon entschieden".

    Returns:
        (findings_fuer_llm, assessments_vom_prefilter) - die beiden
        Listen sind zusammen vollständig: jedes Finding aus `findings`
        taucht in genau einer der beiden wieder auf.
    """
    if not findings:
        return findings, []

    model = _load_model()
    if model is None:
        try:
            m.PREFILTER_DECISIONS.labels(result="unavailable").inc(len(findings))
        except Exception:  # noqa: BLE001 - Monitoring darf nie durchschlagen
            logger.exception("Pre-Filter-Metrik (unavailable) konnte nicht geschrieben werden")
        return findings, []

    try:
        feature_df = pd.DataFrame(
            [finding_to_features(f) for f in findings], columns=FEATURE_COLUMNS
        )
        predictions = model.predict(feature_df)
    except Exception:  # noqa: BLE001 - best effort, siehe Modul-Docstring
        logger.exception("Pre-Filter-Anwendung fehlgeschlagen - alle Funde gehen ans LLM.")
        return findings, []

    findings_for_llm: list[Finding] = []
    assessments: list[TriageAssessment] = []

    for finding, (_, row) in zip(findings, predictions.iterrows()):
        decision = row["decision"]
        probability = float(row["probability_true_positive"])

        if decision == "escalate":
            findings_for_llm.append(finding)
            continue

        is_true_positive = decision == "true_positive"
        assessments.append(
            TriageAssessment(
                finding_id=finding.id,
                is_true_positive=is_true_positive,
                severity=finding.severity,
                cvss_score=_CVSS_BY_SEVERITY.get(finding.severity, 5.0)
                if is_true_positive
                else 0.0,
                confidence=probability if is_true_positive else 1 - probability,
                reasoning=(
                    "Automatisch durch das Pre-Filter-Modell entschieden "
                    f"(P[true_positive]={probability:.2f}), kein LLM-Aufruf."
                ),
                needs_review=False,
            )
        )

    try:
        if assessments:
            confirmed = sum(1 for a in assessments if a.is_true_positive)
            rejected = len(assessments) - confirmed
            if confirmed:
                m.PREFILTER_DECISIONS.labels(result="auto_confirmed").inc(confirmed)
            if rejected:
                m.PREFILTER_DECISIONS.labels(result="auto_rejected").inc(rejected)
            m.PREFILTER_SKIPPED_LLM_CALLS.inc(len(assessments))
        if findings_for_llm:
            m.PREFILTER_DECISIONS.labels(result="escalated").inc(len(findings_for_llm))
    except Exception:  # noqa: BLE001 - Monitoring darf nie durchschlagen
        logger.exception("Pre-Filter-Metriken konnten nicht geschrieben werden")

    return findings_for_llm, assessments
