"""Tests für `src/demo/fixtures.py` (Demo-/Fixture-Modus ohne LLM)."""

from __future__ import annotations

from src.demo.fixtures import fixture_report, fixture_triage
from src.report_agent.report import build_report_context
from src.scanner_agent.models import Finding, Severity, ToolName


def _make_finding(
    finding_id: str = "f1",
    tool: ToolName = ToolName.BANDIT,
    severity: Severity = Severity.HIGH,
    package: str | None = None,
    fix_versions: list[str] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        tool=tool,
        rule_id="B105",
        severity=severity,
        raw_severity="HIGH",
        confidence="HIGH",
        file_path="app.py",
        line_start=10,
        line_end=10,
        code_snippet="API_KEY = 'xyz'",
        title="Hardcoded secret",
        description="Ein hartcodiertes Secret wurde gefunden.",
        package=package,
        fix_versions=fix_versions or [],
        raw={},
    )


def test_fixture_triage_marks_every_finding_true_positive():
    findings = [
        _make_finding("f1", severity=Severity.CRITICAL),
        _make_finding("f2", severity=Severity.LOW),
    ]
    assessments = fixture_triage(findings)

    assert len(assessments) == 2
    assert all(a.is_true_positive for a in assessments)
    assert all(not a.needs_review for a in assessments)
    assert all("Demo-Modus" in a.reasoning for a in assessments)


def test_fixture_triage_maps_severity_to_cvss_heuristic():
    findings = [_make_finding("f1", severity=Severity.CRITICAL)]
    assessments = fixture_triage(findings)

    assert assessments[0].severity == Severity.CRITICAL
    assert assessments[0].cvss_score == 9.5


def test_fixture_triage_preserves_finding_ids():
    findings = [_make_finding("f1"), _make_finding("f2")]
    assessments = fixture_triage(findings)

    assert {a.finding_id for a in assessments} == {"f1", "f2"}


def test_fixture_report_marks_itself_as_demo_mode():
    findings = [_make_finding("f1")]
    assessments = fixture_triage(findings)
    context = build_report_context(findings, assessments, "test-repo")

    report = fixture_report(context)

    assert "Demo-Modus" in report
    assert "test-repo" in report
    assert "Hardcoded secret" in report


def test_fixture_report_empty_case_still_marks_demo_mode():
    context = build_report_context([], [], "leeres-repo")
    report = fixture_report(context)

    assert "Demo-Modus" in report
    assert "Keine bestätigten Schwachstellen" in report


def test_fixture_report_includes_pip_audit_fix_versions():
    findings = [
        _make_finding(
            "f1",
            tool=ToolName.PIP_AUDIT,
            package="flask",
            fix_versions=["2.0.1", "2.1.0"],
        )
    ]
    assessments = fixture_triage(findings)
    context = build_report_context(findings, assessments, "test-repo")

    report = fixture_report(context)

    assert "flask" in report
    assert "2.0.1" in report


def test_fixture_report_lists_needs_review_section_when_present():
    from src.triage_agent.models import TriageAssessment

    findings = [_make_finding("f1")]
    assessments = [
        TriageAssessment(
            finding_id="f1",
            is_true_positive=True,
            severity=Severity.HIGH,
            cvss_score=7.5,
            confidence=0.5,
            reasoning="Uneindeutig.",
            needs_review=True,
        )
    ]
    context = build_report_context(findings, assessments, "test-repo")

    report = fixture_report(context)

    assert "Ohne Konsens" in report
    assert "Hardcoded secret" in report
