"""Tests für Orchestrator: RunStore (SQLite-CRUD) und run_pipeline()."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.orchestrator.models import RunStatus, ScanRun
from src.orchestrator.storage import RunStore
from src.report_agent.models import ReportContext
from src.scanner_agent.models import Finding, Severity, ToolName
from src.scanner_agent.scanner import ScanResult
from src.triage_agent.models import TriageAssessment


def _make_finding(finding_id: str = "f1") -> Finding:
    return Finding(
        id=finding_id,
        tool=ToolName.BANDIT,
        rule_id="B105",
        severity=Severity.HIGH,
        raw_severity="HIGH",
        confidence="HIGH",
        file_path="app.py",
        line_start=10,
        line_end=10,
        code_snippet="API_KEY = 'xyz'",
        title="Hardcoded secret",
        description="Hardcoded secret found.",
        raw={},
    )


def _make_assessment(finding_id: str = "f1") -> TriageAssessment:
    return TriageAssessment(
        finding_id=finding_id,
        is_true_positive=True,
        severity=Severity.HIGH,
        cvss_score=7.5,
        confidence=0.9,
        reasoning="Echter Fund.",
    )


# ---------------------------------------------------------------------------
# RunStore
# ---------------------------------------------------------------------------


def test_create_and_get_run(tmp_path):
    store = RunStore(str(tmp_path / "test.db"))
    run = ScanRun(repo_path="/tmp/repo")
    store.create_run(run)

    loaded = store.get_run(run.id)
    assert loaded is not None
    assert loaded.id == run.id
    assert loaded.repo_path == "/tmp/repo"
    assert loaded.status == RunStatus.SCANNING


def test_get_run_returns_none_for_unknown_id(tmp_path):
    store = RunStore(str(tmp_path / "test.db"))
    assert store.get_run("does-not-exist") is None


def test_update_run_persists_status_and_report(tmp_path):
    store = RunStore(str(tmp_path / "test.db"))
    run = ScanRun(repo_path="/tmp/repo")
    store.create_run(run)

    run.status = RunStatus.COMPLETED
    run.report_markdown = "# Bericht"
    store.update_run(run)

    loaded = store.get_run(run.id)
    assert loaded.status == RunStatus.COMPLETED
    assert loaded.report_markdown == "# Bericht"


def test_update_run_persists_failure(tmp_path):
    store = RunStore(str(tmp_path / "test.db"))
    run = ScanRun(repo_path="/tmp/repo")
    store.create_run(run)

    run.status = RunStatus.FAILED
    run.error_message = "Boom"
    store.update_run(run)

    loaded = store.get_run(run.id)
    assert loaded.status == RunStatus.FAILED
    assert loaded.error_message == "Boom"


def test_save_and_get_findings(tmp_path):
    store = RunStore(str(tmp_path / "test.db"))
    run = ScanRun(repo_path="/tmp/repo")
    store.create_run(run)

    finding = _make_finding()
    store.save_findings(run.id, [finding])

    loaded = store.get_findings(run.id)
    assert len(loaded) == 1
    assert loaded[0].id == finding.id
    assert loaded[0].title == "Hardcoded secret"


def test_save_and_get_assessments(tmp_path):
    store = RunStore(str(tmp_path / "test.db"))
    run = ScanRun(repo_path="/tmp/repo")
    store.create_run(run)

    assessment = _make_assessment()
    store.save_assessments(run.id, [assessment])

    loaded = store.get_assessments(run.id)
    assert len(loaded) == 1
    assert loaded[0].finding_id == "f1"
    assert loaded[0].cvss_score == 7.5


# ---------------------------------------------------------------------------
# run_pipeline
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_steps(monkeypatch):
    """Monkeypatcht die drei Agent-Aufrufe innerhalb des Orchestrator-
    Moduls, damit `run_pipeline` ohne echte Tools/API-Calls getestet
    werden kann.
    """
    finding = _make_finding()
    assessment = _make_assessment()
    scan_result = ScanResult(findings=[finding], errors={})

    mock_run_all_scanners = MagicMock(return_value=scan_result)
    mock_triage_findings = MagicMock(return_value=[assessment])
    mock_generate_report = MagicMock(return_value="# Bericht\nAlles gut.")

    monkeypatch.setattr(
        "src.orchestrator.orchestrator.run_all_scanners", mock_run_all_scanners
    )
    monkeypatch.setattr(
        "src.orchestrator.orchestrator.triage_findings", mock_triage_findings
    )
    monkeypatch.setattr(
        "src.orchestrator.orchestrator.generate_report", mock_generate_report
    )
    mock_log_run = MagicMock()
    monkeypatch.setattr("src.orchestrator.orchestrator.log_run", mock_log_run)

    return {
        "run_all_scanners": mock_run_all_scanners,
        "triage_findings": mock_triage_findings,
        "generate_report": mock_generate_report,
        "log_run": mock_log_run,
        "finding": finding,
        "assessment": assessment,
    }


def test_run_pipeline_happy_path_completes_and_persists(tmp_path, patched_steps):
    from src.orchestrator.orchestrator import run_pipeline

    db_path = str(tmp_path / "test.db")
    run = run_pipeline("/tmp/some_repo", db_path=db_path, demo_mode=False)

    assert run.status == RunStatus.COMPLETED
    assert run.report_markdown == "# Bericht\nAlles gut."

    store = RunStore(db_path)
    loaded = store.get_run(run.id)
    assert loaded.status == RunStatus.COMPLETED
    assert len(store.get_findings(run.id)) == 1
    assert len(store.get_assessments(run.id)) == 1

    patched_steps["log_run"].assert_called_once()
    logged_run, logged_assessments = patched_steps["log_run"].call_args.args
    assert logged_run.status == RunStatus.COMPLETED
    assert logged_assessments == [patched_steps["assessment"]]


def test_run_pipeline_passes_repo_name_derived_from_path(tmp_path, patched_steps):
    from src.orchestrator.orchestrator import run_pipeline

    run_pipeline("/tmp/parent/my_repo", db_path=str(tmp_path / "test.db"), demo_mode=False)

    _, kwargs = patched_steps["generate_report"].call_args
    args = patched_steps["generate_report"].call_args.args
    # repo_name ist das dritte Positionsargument
    assert args[2] == "my_repo"


def test_run_pipeline_failure_in_triage_marks_failed_but_keeps_findings(
    tmp_path, patched_steps, monkeypatch
):
    from src.orchestrator.orchestrator import run_pipeline

    monkeypatch.setattr(
        "src.orchestrator.orchestrator.triage_findings",
        MagicMock(side_effect=RuntimeError("Triage kaputt")),
    )

    db_path = str(tmp_path / "test.db")
    with pytest.raises(RuntimeError, match="Triage kaputt"):
        run_pipeline("/tmp/some_repo", db_path=db_path, demo_mode=False)

    store = RunStore(db_path)
    # Es gibt genau einen Run (id ist uns hier nicht bekannt, also über
    # eine direkte Abfrage der Tabelle ermitteln wir ihn erneut).
    import sqlite3

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT id, status, error_message FROM runs").fetchone()
    conn.close()

    run_id, status, error_message = row
    assert status == "failed"
    assert "Triage kaputt" in error_message
    # Scan-Ergebnisse (Findings) müssen trotz Absturz während der
    # Triage erhalten bleiben.
    assert len(store.get_findings(run_id)) == 1
    assert len(store.get_assessments(run_id)) == 0

    # Tracking wird auch bei einem fehlgeschlagenen Lauf aufgerufen.
    patched_steps["log_run"].assert_called_once()
    logged_run, _ = patched_steps["log_run"].call_args.args
    assert logged_run.status == RunStatus.FAILED


def test_run_pipeline_failure_in_scan_marks_failed(tmp_path, monkeypatch):
    from src.orchestrator.orchestrator import run_pipeline

    monkeypatch.setattr(
        "src.orchestrator.orchestrator.run_all_scanners",
        MagicMock(side_effect=RuntimeError("Scanner kaputt")),
    )
    monkeypatch.setattr("src.orchestrator.orchestrator.log_run", MagicMock())

    db_path = str(tmp_path / "test.db")
    with pytest.raises(RuntimeError, match="Scanner kaputt"):
        run_pipeline("/tmp/some_repo", db_path=db_path, demo_mode=False)

    import sqlite3

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT status, error_message FROM runs").fetchone()
    conn.close()

    status, error_message = row
    assert status == "failed"
    assert "Scanner kaputt" in error_message


# ---------------------------------------------------------------------------
# Demo-/Fixture-Modus (ohne ANTHROPIC_API_KEY)
# ---------------------------------------------------------------------------


def test_run_pipeline_auto_detects_demo_mode_without_api_key(
    tmp_path, monkeypatch
):
    """Ohne ANTHROPIC_API_KEY läuft die Pipeline automatisch im
    Demo-Modus und ruft weder triage_findings noch generate_report auf.
    """
    from src.orchestrator.orchestrator import run_pipeline

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    finding = _make_finding()
    scan_result = ScanResult(findings=[finding], errors={})

    mock_run_all_scanners = MagicMock(return_value=scan_result)
    mock_triage_findings = MagicMock()
    mock_generate_report = MagicMock()
    mock_log_run = MagicMock()

    monkeypatch.setattr(
        "src.orchestrator.orchestrator.run_all_scanners", mock_run_all_scanners
    )
    monkeypatch.setattr(
        "src.orchestrator.orchestrator.triage_findings", mock_triage_findings
    )
    monkeypatch.setattr(
        "src.orchestrator.orchestrator.generate_report", mock_generate_report
    )
    monkeypatch.setattr("src.orchestrator.orchestrator.log_run", mock_log_run)

    db_path = str(tmp_path / "test.db")
    run = run_pipeline("/tmp/some_repo", db_path=db_path)

    assert run.status == RunStatus.COMPLETED
    mock_triage_findings.assert_not_called()
    mock_generate_report.assert_not_called()
    assert "Demo-Modus" in run.report_markdown

    store = RunStore(db_path)
    assessments = store.get_assessments(run.id)
    assert len(assessments) == 1
    assert assessments[0].reasoning.startswith("Demo-Modus")


def test_run_pipeline_explicit_demo_mode_true_skips_llm_even_with_api_key(
    tmp_path, monkeypatch
):
    """demo_mode=True erzwingt den Fixture-Pfad, auch wenn ein API-Key
    gesetzt ist.
    """
    from src.orchestrator.orchestrator import run_pipeline

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-dummy-key-for-test")

    finding = _make_finding()
    scan_result = ScanResult(findings=[finding], errors={})

    mock_triage_findings = MagicMock()
    mock_generate_report = MagicMock()

    monkeypatch.setattr(
        "src.orchestrator.orchestrator.run_all_scanners",
        MagicMock(return_value=scan_result),
    )
    monkeypatch.setattr(
        "src.orchestrator.orchestrator.triage_findings", mock_triage_findings
    )
    monkeypatch.setattr(
        "src.orchestrator.orchestrator.generate_report", mock_generate_report
    )
    monkeypatch.setattr("src.orchestrator.orchestrator.log_run", MagicMock())

    db_path = str(tmp_path / "test.db")
    run = run_pipeline(
        "/tmp/some_repo", db_path=db_path, demo_mode=True
    )

    assert run.status == RunStatus.COMPLETED
    mock_triage_findings.assert_not_called()
    mock_generate_report.assert_not_called()


def test_run_pipeline_explicit_demo_mode_false_uses_llm_path(
    tmp_path, patched_steps, monkeypatch
):
    """demo_mode=False nutzt den echten LLM-Pfad, selbst ohne gesetzten
    API-Key (Verantwortung liegt dann beim Aufrufer/der echten Lib).
    """
    from src.orchestrator.orchestrator import run_pipeline

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    db_path = str(tmp_path / "test.db")
    run_pipeline("/tmp/some_repo", db_path=db_path, demo_mode=False)

    patched_steps["triage_findings"].assert_called_once()
    patched_steps["generate_report"].assert_called_once()
