"""Tests für die Prometheus-Metriken.

Die Zähler sind global und leben für die Dauer des Testlaufs weiter.
Deshalb wird nie ein absoluter Wert geprüft, sondern immer die
*Differenz* vor und nach dem Aufruf. Sonst wären die Tests von ihrer
Reihenfolge abhängig.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.monitoring import metrics as m
from src.monitoring.record import record_run
from src.orchestrator.models import RunStatus, ScanRun
from src.scanner_agent.models import Finding, Severity, ToolName
from src.triage_agent.models import TriageAssessment


def _value(metric, **labels) -> float:
    """Liest den aktuellen Wert eines Counters (0.0, falls noch nie gezählt)."""
    collected = metric.labels(**labels)._value.get() if labels else metric._value.get()
    return float(collected)


def _make_finding(finding_id: str, tool: ToolName = ToolName.BANDIT) -> Finding:
    return Finding(
        id=finding_id,
        tool=tool,
        rule_id="B000",
        severity=Severity.MEDIUM,
        file_path="x.py",
        line_start=1,
        title="Testfund",
        description="Testfund",
    )


def _make_assessment(
    finding_id: str,
    is_true_positive: bool = True,
    needs_review: bool = False,
    confidence: float = 0.9,
    severity: Severity = Severity.HIGH,
) -> TriageAssessment:
    return TriageAssessment(
        finding_id=finding_id,
        is_true_positive=is_true_positive,
        severity=severity,
        cvss_score=7.0,
        confidence=confidence,
        reasoning="Testbegründung",
        needs_review=needs_review,
    )


def _make_run(status: RunStatus = RunStatus.COMPLETED) -> ScanRun:
    return ScanRun(
        repo_path="test_repos/dummy",
        status=status,
        updated_at=datetime.now(timezone.utc),
    )


def test_record_run_counts_scan_by_status() -> None:
    before = _value(m.SCANS, status="completed")
    record_run(_make_run(), duration_seconds=12.0)
    assert _value(m.SCANS, status="completed") == before + 1


def test_record_run_counts_failed_scan_separately() -> None:
    before = _value(m.SCANS, status="failed")
    record_run(_make_run(RunStatus.FAILED))
    assert _value(m.SCANS, status="failed") == before + 1


def test_record_run_counts_findings_per_tool() -> None:
    before_bandit = _value(m.FINDINGS, tool="bandit")
    before_semgrep = _value(m.FINDINGS, tool="semgrep")

    findings = [
        _make_finding("f1", ToolName.BANDIT),
        _make_finding("f2", ToolName.BANDIT),
        _make_finding("f3", ToolName.SEMGREP),
    ]
    record_run(_make_run(), findings=findings)

    assert _value(m.FINDINGS, tool="bandit") == before_bandit + 2
    assert _value(m.FINDINGS, tool="semgrep") == before_semgrep + 1


def test_record_run_counts_scanner_errors_per_tool() -> None:
    before = _value(m.SCANNER_ERRORS, tool="semgrep")
    run = _make_run()
    run.scanner_errors = {"semgrep": "abgestürzt"}
    record_run(run)
    assert _value(m.SCANNER_ERRORS, tool="semgrep") == before + 1


def test_record_run_splits_triage_results() -> None:
    before_tp = _value(m.TRIAGE_RESULTS, result="true_positive")
    before_fp = _value(m.TRIAGE_RESULTS, result="false_positive")
    before_nr = _value(m.TRIAGE_RESULTS, result="needs_review")

    assessments = [
        _make_assessment("f1", is_true_positive=True),
        _make_assessment("f2", is_true_positive=False),
        _make_assessment("f3", is_true_positive=True, needs_review=True),
    ]
    record_run(_make_run(), assessments=assessments)

    assert _value(m.TRIAGE_RESULTS, result="true_positive") == before_tp + 1
    assert _value(m.TRIAGE_RESULTS, result="false_positive") == before_fp + 1
    # needs_review hat Vorrang: ein Fund ohne Konsens zählt dort, nicht
    # zusätzlich als bestätigt.
    assert _value(m.TRIAGE_RESULTS, result="needs_review") == before_nr + 1


def test_record_run_counts_confirmed_findings_by_severity() -> None:
    before = _value(m.CONFIRMED_BY_SEVERITY, severity="critical")
    assessments = [
        _make_assessment("f1", is_true_positive=True, severity=Severity.CRITICAL),
        _make_assessment("f2", is_true_positive=False, severity=Severity.CRITICAL),
    ]
    record_run(_make_run(), assessments=assessments)
    # Nur der bestätigte Fund zählt, der Fehlalarm nicht.
    assert _value(m.CONFIRMED_BY_SEVERITY, severity="critical") == before + 1


def test_record_run_counts_mode() -> None:
    before_demo = _value(m.SCAN_MODE, mode="demo")
    before_llm = _value(m.SCAN_MODE, mode="llm")

    record_run(_make_run(), demo_mode=True)
    record_run(_make_run(), demo_mode=False)

    assert _value(m.SCAN_MODE, mode="demo") == before_demo + 1
    assert _value(m.SCAN_MODE, mode="llm") == before_llm + 1


def test_record_run_swallows_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Monitoring darf einen Lauf niemals zum Scheitern bringen."""
    broken = MagicMock()
    broken.labels.side_effect = RuntimeError("Zähler kaputt")
    monkeypatch.setattr(m, "SCANS", broken)

    # Darf keine Ausnahme nach außen geben.
    record_run(_make_run(), duration_seconds=1.0)


# --- LLM-Metriken ------------------------------------------------------------
#
# Die Zähler sind definiert, werden aber erst in den Agenten gesetzt. Genau
# diese Verdrahtung fehlte zunächst: Das Dashboard-Panel wäre dauerhaft leer
# geblieben, ohne dass ein Test angeschlagen hätte. Ein leeres Panel ist
# nicht unterscheidbar von "alles in Ordnung" - deshalb diese Tests.


class _TextBlock:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _Response:
    def __init__(self, text: str) -> None:
        self.content = [_TextBlock(text)]


_TRIAGE_JSON = (
    '{"assessments":[{"finding_id":"f1","is_true_positive":true,'
    '"severity":"high","cvss_score":7.0,"confidence":0.9,"reasoning":"r"}]}'
)


def test_successful_triage_call_is_counted() -> None:
    import anthropic

    from src.triage_agent.triage import triage_findings

    before = _value(m.LLM_REQUESTS, result="ok")

    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.return_value = _Response(_TRIAGE_JSON)
    triage_findings([_make_finding("f1")], client=client)

    assert _value(m.LLM_REQUESTS, result="ok") == before + 1


def test_retried_triage_call_counts_retries_and_error_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import anthropic

    from src.triage_agent.triage import triage_findings

    monkeypatch.setattr("src.triage_agent.triage.time.sleep", lambda _s: None)

    before_retry = _value(m.LLM_REQUESTS, result="retry")
    before_failed = _value(m.LLM_REQUESTS, result="failed")
    before_kind = _value(m.LLM_ERRORS, kind="APIConnectionError")

    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.side_effect = anthropic.APIConnectionError(request=MagicMock())

    with pytest.raises(RuntimeError):
        triage_findings([_make_finding("f1")], client=client)

    # Drei Versuche, danach endgültiger Abbruch.
    assert _value(m.LLM_REQUESTS, result="retry") == before_retry + 3
    assert _value(m.LLM_REQUESTS, result="failed") == before_failed + 1
    assert _value(m.LLM_ERRORS, kind="APIConnectionError") == before_kind + 3


def test_successful_report_call_is_counted() -> None:
    import anthropic

    from src.report_agent.report import generate_report

    before = _value(m.LLM_REQUESTS, result="ok")

    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.return_value = _Response("# Bericht")
    generate_report(
        [_make_finding("f1")], [_make_assessment("f1")], "repo", client=client
    )

    assert _value(m.LLM_REQUESTS, result="ok") == before + 1
