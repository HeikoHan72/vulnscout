"""Tests für die OSV-Untergrenze (`src/enrichment/floor.py`).

Bestätigte Abhängigkeits-Funde werden nach der Triage mindestens auf den
OSV-Schweregrad angehoben. Geprüft wird die Regel selbst, ihre Grenzen
(Fehlalarme, fremde Werkzeuge, fehlende OSV-Daten), Nachvollziehbarkeit
(Ursprungswert, Vermerk, Metrik) und die Einbindung in die Pipeline.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from prometheus_client import REGISTRY

from src.enrichment import floor as floor_module
from src.enrichment.floor import apply_osv_severity_floor
from src.orchestrator.models import RunStatus
from src.orchestrator.storage import RunStore
from src.scanner_agent.models import Finding, Severity, ToolName
from src.scanner_agent.scanner import ScanResult
from src.triage_agent.models import TriageAssessment
from src.triage_agent.prompts import SYSTEM_PROMPT

SOURCE = "osv:GHSA-5wv5-4vpf-pj6m"
LEVELS = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
RANK = {level: i for i, level in enumerate(LEVELS)}


def _finding(
    finding_id: str = "f1",
    osv: Severity | None = Severity.HIGH,
    tool: ToolName = ToolName.PIP_AUDIT,
) -> Finding:
    return Finding(
        id=finding_id,
        tool=tool,
        rule_id="PYSEC-2019-179",
        severity=Severity.UNKNOWN,
        file_path="requirements.txt",
        title="Bekannte Schwachstelle in flask 0.12: PYSEC-2019-179",
        package="flask",
        installed_version="0.12",
        osv_severity=osv,
        severity_source=SOURCE if osv else None,
        raw={},
    )


def _assessment(
    finding_id: str = "f1",
    severity: Severity = Severity.MEDIUM,
    cvss_score: float = 5.0,
    is_true_positive: bool = True,
    needs_review: bool = False,
) -> TriageAssessment:
    return TriageAssessment(
        finding_id=finding_id,
        is_true_positive=is_true_positive,
        severity=severity,
        cvss_score=cvss_score,
        confidence=0.9,
        reasoning="Nur im Entwicklungsserver relevant.",
        needs_review=needs_review,
    )


def _metric(result: str) -> float:
    return REGISTRY.get_sample_value("vulnscout_severity_floor_total", {"result": result}) or 0.0


# ---------------------------------------------------------------------------
# Regel
# ---------------------------------------------------------------------------


def test_lower_assessment_is_raised_to_the_osv_severity():
    assessment = _assessment(severity=Severity.MEDIUM)

    raised = apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [assessment])

    assert raised == 1
    assert assessment.severity == Severity.HIGH


def test_the_original_severity_is_kept_for_traceability():
    assessment = _assessment(severity=Severity.LOW)

    apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [assessment])

    assert assessment.severity_raised_from == Severity.LOW


def test_reasoning_keeps_the_original_text_and_names_the_raise():
    assessment = _assessment(severity=Severity.MEDIUM)

    apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [assessment])

    assert assessment.reasoning.startswith("Nur im Entwicklungsserver relevant.")
    assert "Automatisch angehoben" in assessment.reasoning
    assert "medium" in assessment.reasoning and "high" in assessment.reasoning
    assert SOURCE in assessment.reasoning
    assert "Untergrenze" in assessment.reasoning


def test_equal_assessment_is_left_alone():
    assessment = _assessment(severity=Severity.HIGH, cvss_score=7.4)

    raised = apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [assessment])

    assert raised == 0
    assert assessment.severity == Severity.HIGH
    assert assessment.severity_raised_from is None
    assert assessment.reasoning == "Nur im Entwicklungsserver relevant."
    assert assessment.cvss_score == 7.4


def test_higher_assessment_is_never_lowered():
    assessment = _assessment(severity=Severity.CRITICAL, cvss_score=9.8)

    raised = apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [assessment])

    assert raised == 0
    assert assessment.severity == Severity.CRITICAL
    assert assessment.severity_raised_from is None


@pytest.mark.parametrize("llm", LEVELS)
@pytest.mark.parametrize("osv", LEVELS)
def test_result_is_always_the_higher_of_both(llm, osv):
    assessment = _assessment(severity=llm)

    apply_osv_severity_floor([_finding(osv=osv)], [assessment])

    assert RANK[assessment.severity] == max(RANK[llm], RANK[osv])
    assert (assessment.severity_raised_from is not None) == (RANK[llm] < RANK[osv])


@pytest.mark.parametrize(
    "osv, minimum",
    [
        (Severity.LOW, 0.1),
        (Severity.MEDIUM, 4.0),
        (Severity.HIGH, 7.0),
        (Severity.CRITICAL, 9.0),
    ],
)
def test_score_is_lifted_to_the_lower_bound_of_the_raised_level(osv, minimum):
    # Ausgangslage: ein Wert unterhalb jeder Stufe, Einstufung "unknown" zählt als niedriger.
    assessment = _assessment(severity=Severity.UNKNOWN, cvss_score=0.0)

    apply_osv_severity_floor([_finding(osv=osv)], [assessment])

    assert assessment.cvss_score == minimum
    assert f"mindestens {minimum}" in assessment.reasoning


def test_score_above_the_lower_bound_is_kept_when_raising():
    assessment = _assessment(severity=Severity.MEDIUM, cvss_score=6.9)

    apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [assessment])

    assert assessment.severity == Severity.HIGH
    assert assessment.cvss_score == 7.0  # 6.9 liegt unter 7.0

    other = _assessment(severity=Severity.MEDIUM, cvss_score=8.1)
    apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [other])
    assert other.cvss_score == 8.1
    assert "CVSS-ähnliche Score" not in other.reasoning


def test_unknown_assessment_severity_counts_as_lower_than_any_osv_level():
    assessment = _assessment(severity=Severity.UNKNOWN, cvss_score=5.0)

    apply_osv_severity_floor([_finding(osv=Severity.LOW)], [assessment])

    assert assessment.severity == Severity.LOW
    assert assessment.severity_raised_from == Severity.UNKNOWN


def test_assessment_that_needs_review_is_raised_too():
    assessment = _assessment(severity=Severity.LOW, needs_review=True)

    apply_osv_severity_floor([_finding(osv=Severity.CRITICAL)], [assessment])

    assert assessment.severity == Severity.CRITICAL
    assert assessment.needs_review is True


# ---------------------------------------------------------------------------
# Grenzen: was nicht angefasst wird
# ---------------------------------------------------------------------------


def test_false_positives_are_not_touched():
    assessment = _assessment(severity=Severity.LOW, is_true_positive=False)

    raised = apply_osv_severity_floor([_finding(osv=Severity.CRITICAL)], [assessment])

    assert raised == 0
    assert assessment.severity == Severity.LOW
    assert assessment.severity_raised_from is None


def test_finding_without_osv_severity_is_not_touched():
    assessment = _assessment(severity=Severity.LOW)

    raised = apply_osv_severity_floor([_finding(osv=None)], [assessment])

    assert raised == 0
    assert assessment.severity == Severity.LOW


@pytest.mark.parametrize("tool", [ToolName.BANDIT, ToolName.SEMGREP])
def test_findings_of_other_tools_are_not_touched(tool):
    assessment = _assessment(severity=Severity.LOW)

    raised = apply_osv_severity_floor([_finding(osv=Severity.CRITICAL, tool=tool)], [assessment])

    assert raised == 0
    assert assessment.severity == Severity.LOW


def test_assessment_without_a_matching_finding_is_skipped():
    assessment = _assessment(finding_id="gibt-es-nicht", severity=Severity.LOW)

    assert apply_osv_severity_floor([_finding()], [assessment]) == 0
    assert assessment.severity == Severity.LOW


def test_empty_inputs_are_fine():
    assert apply_osv_severity_floor([], []) == 0
    assert apply_osv_severity_floor([_finding()], []) == 0


def test_findings_are_never_modified():
    finding = _finding(osv=Severity.HIGH)
    before = finding.model_dump_json()

    apply_osv_severity_floor([finding], [_assessment(severity=Severity.LOW)])

    assert finding.model_dump_json() == before


def test_several_findings_are_handled_independently():
    findings = [
        _finding("a", Severity.HIGH),
        _finding("b", Severity.HIGH),
        _finding("c", Severity.LOW),
    ]
    assessments = [
        _assessment("a", Severity.LOW),
        _assessment("b", Severity.CRITICAL),
        _assessment("c", Severity.MEDIUM),
    ]

    raised = apply_osv_severity_floor(findings, assessments)

    assert raised == 1
    assert [a.severity for a in assessments] == [Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM]


# ---------------------------------------------------------------------------
# Metrik
# ---------------------------------------------------------------------------


def test_metric_counts_raised_and_unchanged():
    raised_before, unchanged_before = _metric("raised"), _metric("unchanged")

    apply_osv_severity_floor(
        [_finding("a", Severity.HIGH), _finding("b", Severity.HIGH), _finding("c", Severity.HIGH)],
        [
            _assessment("a", Severity.LOW),
            _assessment("b", Severity.HIGH),
            _assessment("c", Severity.CRITICAL),
        ],
    )

    assert _metric("raised") - raised_before == 1
    assert _metric("unchanged") - unchanged_before == 2


def test_metric_ignores_findings_the_rule_does_not_apply_to():
    raised_before, unchanged_before = _metric("raised"), _metric("unchanged")

    apply_osv_severity_floor(
        [_finding("a", None), _finding("b", Severity.HIGH)],
        [_assessment("a", Severity.LOW), _assessment("b", Severity.LOW, is_true_positive=False)],
    )

    assert _metric("raised") == raised_before
    assert _metric("unchanged") == unchanged_before


def test_a_failing_metric_does_not_stop_the_floor(monkeypatch):
    broken = MagicMock()
    broken.labels.side_effect = RuntimeError("Metrik kaputt")
    monkeypatch.setattr(floor_module.m, "SEVERITY_FLOOR", broken)
    assessment = _assessment(severity=Severity.LOW)

    raised = apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [assessment])

    assert raised == 1
    assert assessment.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Speicherung, Prompt, Pipeline
# ---------------------------------------------------------------------------


def test_the_original_severity_survives_a_storage_roundtrip():
    assessment = _assessment(severity=Severity.LOW)
    apply_osv_severity_floor([_finding(osv=Severity.HIGH)], [assessment])

    loaded = TriageAssessment.model_validate_json(assessment.model_dump_json())

    assert loaded.severity == Severity.HIGH
    assert loaded.severity_raised_from == Severity.LOW


def test_assessments_stored_before_this_change_still_load():
    data = json.loads(_assessment().model_dump_json())
    del data["severity_raised_from"]

    loaded = TriageAssessment.model_validate_json(json.dumps(data))

    assert loaded.severity_raised_from is None


def test_system_prompt_tells_the_model_about_the_floor():
    assert "Untergrenze" in SYSTEM_PROMPT


def _run_pipeline_with(monkeypatch, tmp_path, llm_severity, floor_fn=None):
    from src.orchestrator import orchestrator as orch

    finding = _finding("dep-1", osv=Severity.HIGH)
    scan_result = ScanResult(findings=[finding], errors={})
    assessment = _assessment("dep-1", severity=llm_severity, cvss_score=4.0)

    monkeypatch.setattr(orch, "run_all_scanners", MagicMock(return_value=scan_result))
    monkeypatch.setattr(orch, "enrich_findings", lambda findings: None)
    monkeypatch.setattr(orch, "apply_prefilter", lambda findings: (list(findings), []))
    monkeypatch.setattr(orch, "triage_findings", lambda findings, client=None: [assessment])
    captured = {}

    def fake_report(findings, assessments, repo_name, scanner_errors=None, client=None):
        captured["assessments"] = list(assessments)
        return "# Bericht"

    monkeypatch.setattr(orch, "generate_report", fake_report)
    monkeypatch.setattr(orch, "log_run", MagicMock())
    monkeypatch.setattr(orch, "record_run", MagicMock())
    if floor_fn is not None:
        monkeypatch.setattr(orch, "apply_osv_severity_floor", floor_fn)

    db_path = str(tmp_path / "t.db")
    run = orch.run_pipeline("/tmp/some_repo", db_path=db_path, demo_mode=False)
    return run, RunStore(db_path), captured


def test_pipeline_applies_the_floor_before_saving_and_reporting(monkeypatch, tmp_path):
    run, store, captured = _run_pipeline_with(monkeypatch, tmp_path, Severity.MEDIUM)

    assert run.status == RunStatus.COMPLETED
    stored = store.get_assessments(run.id)[0]
    assert stored.severity == Severity.HIGH
    assert stored.severity_raised_from == Severity.MEDIUM
    assert stored.cvss_score == 7.0
    assert captured["assessments"][0].severity == Severity.HIGH


def test_pipeline_keeps_a_sufficient_assessment_unchanged(monkeypatch, tmp_path):
    run, store, _ = _run_pipeline_with(monkeypatch, tmp_path, Severity.CRITICAL)

    stored = store.get_assessments(run.id)[0]
    assert stored.severity == Severity.CRITICAL
    assert stored.severity_raised_from is None


def test_pipeline_survives_a_failing_floor(monkeypatch, tmp_path):
    def broken(findings, assessments):
        raise RuntimeError("kaputt")

    run, store, _ = _run_pipeline_with(monkeypatch, tmp_path, Severity.MEDIUM, floor_fn=broken)

    assert run.status == RunStatus.COMPLETED
    assert store.get_assessments(run.id)[0].severity == Severity.MEDIUM
