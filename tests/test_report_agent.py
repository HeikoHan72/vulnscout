"""Tests für den Report-Agenten.

`build_report_context` ist reine Code-Logik (Zählen, Sortieren,
Filtern) und wird ohne jeden Mock getestet. `generate_report` mockt
den Anthropic-Client - kein echter API-Call, keine Kosten.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import anthropic

from src.scanner_agent.models import Finding, Severity, ToolName
from src.report_agent.report import build_report_context, generate_report
from src.triage_agent.models import TriageAssessment


class _FakeTextBlock:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.content = [_FakeTextBlock(text)]


def _finding(finding_id: str, **overrides) -> Finding:
    defaults = dict(
        id=finding_id, tool=ToolName.BANDIT, rule_id="B608", severity=Severity.MEDIUM, title="Fund"
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _assessment(finding_id: str, **overrides) -> TriageAssessment:
    defaults = dict(
        finding_id=finding_id,
        is_true_positive=True,
        severity=Severity.HIGH,
        cvss_score=7.0,
        confidence=0.9,
        reasoning="Test",
    )
    defaults.update(overrides)
    return TriageAssessment(**defaults)


# ---------------------------------------------------------------------------
# build_report_context - reine Code-Logik, kein Mock nötig
# ---------------------------------------------------------------------------


def test_build_report_context_splits_by_category() -> None:
    findings = [_finding("f1"), _finding("f2"), _finding("f3")]
    assessments = [
        _assessment("f1", is_true_positive=True, severity=Severity.HIGH),
        _assessment("f2", is_true_positive=False),
        _assessment("f3", is_true_positive=True, needs_review=True),
    ]

    context = build_report_context(findings, assessments, repo_name="demo-repo")

    assert context.total_confirmed == 1
    assert len(context.detailed) == 1
    assert context.detailed[0].finding.id == "f1"
    assert context.false_positive_count == 1
    assert len(context.needs_review) == 1
    assert context.needs_review[0].finding.id == "f3"


def test_build_report_context_sorts_by_severity_descending_risk() -> None:
    findings = [_finding("low"), _finding("critical"), _finding("medium")]
    assessments = [
        _assessment("low", severity=Severity.LOW),
        _assessment("critical", severity=Severity.CRITICAL),
        _assessment("medium", severity=Severity.MEDIUM),
    ]

    context = build_report_context(findings, assessments, repo_name="demo-repo")
    ordered_ids = [item.finding.id for item in context.detailed]
    assert ordered_ids == ["critical", "medium", "low"]


def test_build_report_context_truncates_large_result_sets() -> None:
    findings = [_finding(f"f{i}") for i in range(10)]
    assessments = [_assessment(f"f{i}") for i in range(10)]

    context = build_report_context(findings, assessments, repo_name="demo-repo", max_detailed=4)

    assert context.total_confirmed == 10
    assert len(context.detailed) == 4
    assert context.truncated is True


def test_build_report_context_ignores_findings_without_assessment() -> None:
    findings = [_finding("f1"), _finding("f2")]
    assessments = [_assessment("f1")]  # f2 bekommt absichtlich keine Bewertung

    context = build_report_context(findings, assessments, repo_name="demo-repo")
    assert context.total_confirmed == 1


def test_build_report_context_carries_scanner_errors() -> None:
    context = build_report_context(
        [], [], repo_name="demo-repo", scanner_errors={"semgrep": "nicht installiert"}
    )
    assert context.scanner_errors == {"semgrep": "nicht installiert"}


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


def test_generate_report_empty_case_makes_no_llm_call() -> None:
    client = MagicMock(spec=anthropic.Anthropic)

    report = generate_report([], [], repo_name="demo-repo", client=client)

    client.messages.create.assert_not_called()
    assert "Keine bestätigten Schwachstellen" in report
    assert "demo-repo" in report


def test_generate_report_calls_llm_when_findings_present() -> None:
    findings = [_finding("f1")]
    assessments = [_assessment("f1")]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.return_value = _FakeResponse("# Sicherheitsbericht\n\nInhalt...")

    report = generate_report(findings, assessments, repo_name="demo-repo", client=client)

    client.messages.create.assert_called_once()
    assert report.startswith("# Sicherheitsbericht")


def test_generate_report_passes_precomputed_numbers_to_prompt() -> None:
    findings = [_finding("f1"), _finding("f2")]
    assessments = [
        _assessment("f1", severity=Severity.CRITICAL),
        _assessment("f2", is_true_positive=False),
    ]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.return_value = _FakeResponse("Bericht")

    generate_report(findings, assessments, repo_name="demo-repo", client=client)

    _, kwargs = client.messages.create.call_args
    sent_prompt = kwargs["messages"][0]["content"]
    assert "Bestätigte Funde insgesamt: 1" in sent_prompt
    assert "Als Fehlalarm eingestuft (nicht einzeln aufgeführt): 1" in sent_prompt
