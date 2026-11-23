"""Tests für das Pre-Filter-Modell (Variante B).

Das eigentliche trainierte Modell wird hier nicht geladen - stattdessen
wird `_load_model()` mit einem Fake ersetzt, das ein festgelegtes
`predict()`-Ergebnis liefert. So lässt sich die Verzweigungslogik in
`apply_prefilter()` unabhängig vom konkreten Modellstand testen.
"""

from __future__ import annotations

from unittest.mock import patch

import pandas as pd
import pytest

from src.monitoring import metrics as m
from src.prefilter.prefilter import apply_prefilter
from src.scanner_agent.models import Finding, Severity, ToolName


def _value(metric, **labels) -> float:
    collected = metric.labels(**labels)._value.get() if labels else metric._value.get()
    return float(collected)


def _finding(finding_id: str, rule_id: str = "B000") -> Finding:
    return Finding(
        id=finding_id,
        tool=ToolName.BANDIT,
        rule_id=rule_id,
        severity=Severity.MEDIUM,
        file_path="x.py",
        line_start=1,
        title="Testfund",
        description="Testfund",
    )


class _FakeModel:
    """Fake-Modell mit fest verdrahteten Entscheidungen pro Aufruf-Index."""

    def __init__(self, decisions: list[tuple[str, float]]):
        self._decisions = decisions

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        assert len(df) == len(self._decisions)
        return pd.DataFrame(
            {
                "decision": [d for d, _ in self._decisions],
                "probability_true_positive": [p for _, p in self._decisions],
            }
        )


def test_leere_findings_liste_bleibt_leer():
    for_llm, assessments = apply_prefilter([])
    assert for_llm == []
    assert assessments == []


def test_kein_modell_verfuegbar_alle_funde_gehen_ans_llm():
    findings = [_finding("1"), _finding("2")]
    before = _value(m.PREFILTER_DECISIONS, result="unavailable")

    with patch("src.prefilter.prefilter._load_model", return_value=None):
        for_llm, assessments = apply_prefilter(findings)

    assert for_llm == findings
    assert assessments == []
    assert _value(m.PREFILTER_DECISIONS, result="unavailable") == before + 2


def test_auto_bestaetigt_auto_verworfen_und_eskaliert_werden_korrekt_aufgeteilt():
    findings = [_finding("tp"), _finding("fp"), _finding("unsicher")]
    fake_model = _FakeModel(
        [("true_positive", 0.97), ("false_positive", 0.02), ("escalate", 0.6)]
    )

    with patch("src.prefilter.prefilter._load_model", return_value=fake_model):
        for_llm, assessments = apply_prefilter(findings)

    assert [f.id for f in for_llm] == ["unsicher"]
    assert {a.finding_id for a in assessments} == {"tp", "fp"}

    tp_assessment = next(a for a in assessments if a.finding_id == "tp")
    fp_assessment = next(a for a in assessments if a.finding_id == "fp")
    assert tp_assessment.is_true_positive is True
    assert fp_assessment.is_true_positive is False
    assert tp_assessment.needs_review is False
    assert fp_assessment.needs_review is False
    # Automatisch entschiedene Funde dürfen nicht nochmal in den
    # Consensus-Check der LLM-Triage laufen.
    assert "Pre-Filter" in tp_assessment.reasoning


def test_modell_fehler_bei_anwendung_faellt_zurueck_auf_llm():
    findings = [_finding("1")]

    class _BrokenModel:
        def predict(self, df):
            raise RuntimeError("Modell kaputt")

    with patch("src.prefilter.prefilter._load_model", return_value=_BrokenModel()):
        for_llm, assessments = apply_prefilter(findings)

    assert for_llm == findings
    assert assessments == []


def test_metriken_werden_fuer_entschiedene_und_eskalierte_funde_gezaehlt():
    findings = [_finding("tp"), _finding("fp"), _finding("unsicher")]
    fake_model = _FakeModel(
        [("true_positive", 0.97), ("false_positive", 0.02), ("escalate", 0.6)]
    )

    before_confirmed = _value(m.PREFILTER_DECISIONS, result="auto_confirmed")
    before_rejected = _value(m.PREFILTER_DECISIONS, result="auto_rejected")
    before_escalated = _value(m.PREFILTER_DECISIONS, result="escalated")
    before_skipped = _value(m.PREFILTER_SKIPPED_LLM_CALLS)

    with patch("src.prefilter.prefilter._load_model", return_value=fake_model):
        apply_prefilter(findings)

    assert _value(m.PREFILTER_DECISIONS, result="auto_confirmed") == before_confirmed + 1
    assert _value(m.PREFILTER_DECISIONS, result="auto_rejected") == before_rejected + 1
    assert _value(m.PREFILTER_DECISIONS, result="escalated") == before_escalated + 1
    assert _value(m.PREFILTER_SKIPPED_LLM_CALLS) == before_skipped + 2
