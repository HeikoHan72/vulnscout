"""Tests für `src/tracking/mlflow_tracking.py`.

Das `mlflow`-Modul wird komplett durch ein `MagicMock` ersetzt – es
wird kein echter Tracking-Server kontaktiert und keine lokale
`mlruns/`-Datei angelegt.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.orchestrator.models import RunStatus, ScanRun
from src.scanner_agent.models import Severity
from src.tracking.mlflow_tracking import log_run
from src.triage_agent.models import TriageAssessment


def _make_run(status: RunStatus = RunStatus.COMPLETED, report: str | None = "# Bericht") -> ScanRun:
    return ScanRun(repo_path="/tmp/repo", status=status, report_markdown=report)


def _make_assessment(
    finding_id: str,
    severity: Severity,
    is_true_positive: bool = True,
    needs_review: bool = False,
) -> TriageAssessment:
    return TriageAssessment(
        finding_id=finding_id,
        is_true_positive=is_true_positive,
        severity=severity,
        cvss_score=5.0,
        confidence=0.9,
        reasoning="Testbewertung.",
        needs_review=needs_review,
    )


@pytest.fixture
def mock_mlflow(monkeypatch):
    mock = MagicMock()
    mock.start_run.return_value.__enter__ = MagicMock(return_value=None)
    mock.start_run.return_value.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr("src.tracking.mlflow_tracking.mlflow", mock)
    return mock


def test_log_run_logs_basic_params_and_metrics(mock_mlflow):
    run = _make_run()
    log_run(run, assessments=[], duration_seconds=12.5)

    mock_mlflow.set_experiment.assert_called_once_with("vulnscout")
    mock_mlflow.log_param.assert_any_call("repo_path", "/tmp/repo")
    mock_mlflow.log_param.assert_any_call("status", "completed")
    mock_mlflow.log_metric.assert_any_call("duration_seconds", 12.5)
    mock_mlflow.log_metric.assert_any_call("scanner_error_count", 0)


def test_log_run_logs_severity_and_triage_counts(mock_mlflow):
    run = _make_run()
    assessments = [
        _make_assessment("f1", Severity.HIGH, is_true_positive=True),
        _make_assessment("f2", Severity.HIGH, is_true_positive=True),
        _make_assessment("f3", Severity.LOW, is_true_positive=False),
        _make_assessment("f4", Severity.MEDIUM, is_true_positive=True, needs_review=True),
    ]
    log_run(run, assessments=assessments, duration_seconds=1.0)

    mock_mlflow.log_metric.assert_any_call("findings_high", 2)
    mock_mlflow.log_metric.assert_any_call("findings_medium", 1)
    mock_mlflow.log_metric.assert_any_call("true_positive_count", 3)
    mock_mlflow.log_metric.assert_any_call("false_positive_count", 1)
    mock_mlflow.log_metric.assert_any_call("needs_review_count", 1)


def test_log_run_logs_report_as_text_artifact(mock_mlflow):
    run = _make_run(report="# Mein Bericht")
    log_run(run, assessments=[])

    mock_mlflow.log_text.assert_called_once_with("# Mein Bericht", "report.md")


def test_log_run_skips_report_artifact_when_none(mock_mlflow):
    run = _make_run(status=RunStatus.FAILED, report=None)
    log_run(run, assessments=[])

    mock_mlflow.log_text.assert_not_called()


def test_log_run_logs_error_message_for_failed_run(mock_mlflow):
    run = _make_run(status=RunStatus.FAILED, report=None)
    run.error_message = "Boom"
    log_run(run, assessments=[])

    mock_mlflow.log_param.assert_any_call("error_message", "Boom")


def test_log_run_truncates_long_error_message(mock_mlflow):
    run = _make_run(status=RunStatus.FAILED, report=None)
    run.error_message = "x" * 500
    log_run(run, assessments=[])

    logged_error = [
        call.args[1]
        for call in mock_mlflow.log_param.call_args_list
        if call.args[0] == "error_message"
    ][0]
    assert len(logged_error) == 250


def test_log_run_swallows_mlflow_errors(mock_mlflow):
    mock_mlflow.set_experiment.side_effect = RuntimeError("Kein Tracking-Server erreichbar")
    run = _make_run()

    # Darf nicht werfen -- Tracking ist best-effort.
    log_run(run, assessments=[])
