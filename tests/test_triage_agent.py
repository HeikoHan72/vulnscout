"""Tests für den Triage-Agenten.

Es wird kein echter API-Aufruf gemacht - der Anthropic-Client wird
durchgängig gemockt, damit die Tests ohne API-Key und ohne Kosten
laufen und deterministisch sind.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import anthropic
import pytest

from src.scanner_agent.models import Finding, Severity, ToolName
from src.triage_agent.prompts import build_user_prompt
from src.triage_agent.triage import triage_findings


class _FakeTextBlock:
    """Antwortblock im Structured-Outputs-Format: JSON als Text.

    Erzwungenes Tool-Use wird von der aktuellen Modellgeneration nicht mehr
    unterstützt; der Triage-Agent fordert das Schema stattdessen über
    `output_config` an und bekommt die Bewertung als JSON-Text zurück.
    """

    type = "text"

    def __init__(self, payload: dict) -> None:
        self.text = json.dumps(payload)


class _FakeResponse:
    def __init__(self, input_data: dict) -> None:
        self.content = [_FakeTextBlock(input_data)]


def _make_finding(finding_id: str = "f1", **overrides) -> Finding:
    defaults = dict(
        id=finding_id,
        tool=ToolName.BANDIT,
        rule_id="B608",
        severity=Severity.MEDIUM,
        title="Mögliche SQL-Injection",
        file_path="app.py",
        line_start=13,
        code_snippet="query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _assessment_payload(finding_id: str, **overrides) -> dict:
    defaults = dict(
        finding_id=finding_id,
        is_true_positive=True,
        severity="high",
        cvss_score=7.5,
        confidence=0.9,
        reasoning="Nutzereingabe wird ungeprüft in die SQL-Abfrage eingesetzt.",
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Prompt-Test
# ---------------------------------------------------------------------------


def test_build_user_prompt_includes_key_fields() -> None:
    finding = _make_finding()
    prompt = build_user_prompt([finding])

    assert finding.id in prompt
    assert "SELECT * FROM users" in prompt
    assert "app.py" in prompt
    assert "Zeile 13" in prompt


# ---------------------------------------------------------------------------
# triage_findings - Grundfall: ein Batch, alle Konfidenzen hoch genug
# ---------------------------------------------------------------------------


def test_triage_findings_single_batch_high_confidence() -> None:
    findings = [_make_finding("f1"), _make_finding("f2")]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.return_value = _FakeResponse(
        {
            "assessments": [
                _assessment_payload("f1", confidence=0.9),
                _assessment_payload("f2", confidence=0.95, is_true_positive=False, severity="low"),
            ]
        }
    )

    results = triage_findings(findings, client=client)

    assert client.messages.create.call_count == 1  # ein Batch, kein Consensus-Check nötig
    by_id = {r.finding_id: r for r in results}
    assert by_id["f1"].is_true_positive is True
    assert by_id["f2"].is_true_positive is False
    assert all(not r.needs_review for r in results)


# ---------------------------------------------------------------------------
# Consensus-Check
# ---------------------------------------------------------------------------


def test_consensus_check_agreement_keeps_assessment() -> None:
    findings = [_make_finding("f1")]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.side_effect = [
        _FakeResponse({"assessments": [_assessment_payload("f1", confidence=0.4)]}),  # Erstbewertung, unsicher
        _FakeResponse({"assessments": [_assessment_payload("f1", confidence=0.5, is_true_positive=True)]}),  # Consensus-Lauf, gleiche Einschätzung
    ]

    results = triage_findings(findings, client=client, confidence_threshold=0.6)

    assert client.messages.create.call_count == 2
    assert results[0].needs_review is False


def test_consensus_check_disagreement_flags_for_review() -> None:
    findings = [_make_finding("f1")]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.side_effect = [
        _FakeResponse({"assessments": [_assessment_payload("f1", confidence=0.4, is_true_positive=True)]}),
        _FakeResponse({"assessments": [_assessment_payload("f1", confidence=0.5, is_true_positive=False)]}),
    ]

    results = triage_findings(findings, client=client, confidence_threshold=0.6)

    assert results[0].needs_review is True


# ---------------------------------------------------------------------------
# Fehlende Bewertung im Batch wird einzeln nachgeholt
# ---------------------------------------------------------------------------


def test_missing_assessment_is_retried_individually() -> None:
    findings = [_make_finding("f1"), _make_finding("f2")]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.side_effect = [
        _FakeResponse({"assessments": [_assessment_payload("f1", confidence=0.9)]}),  # f2 fehlt im Batch
        _FakeResponse({"assessments": [_assessment_payload("f2", confidence=0.9)]}),  # Einzelnachfrage
    ]

    results = triage_findings(findings, client=client)

    assert {r.finding_id for r in results} == {"f1", "f2"}
    assert client.messages.create.call_count == 2


# ---------------------------------------------------------------------------
# Retry bei API-Fehler
# ---------------------------------------------------------------------------


def test_retries_on_transient_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.triage_agent.triage.time.sleep", lambda _seconds: None)

    findings = [_make_finding("f1")]
    client = MagicMock(spec=anthropic.Anthropic)
    api_error = anthropic.APIConnectionError(request=MagicMock())
    client.messages.create.side_effect = [
        api_error,
        _FakeResponse({"assessments": [_assessment_payload("f1")]}),
    ]

    results = triage_findings(findings, client=client)

    assert client.messages.create.call_count == 2
    assert results[0].finding_id == "f1"


def test_raises_after_max_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.triage_agent.triage.time.sleep", lambda _seconds: None)

    findings = [_make_finding("f1")]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.side_effect = anthropic.APIConnectionError(request=MagicMock())

    with pytest.raises(RuntimeError):
        triage_findings(findings, client=client)

    assert client.messages.create.call_count == 3  # MAX_RETRIES


def test_programming_error_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein TypeError kann bei keinem Versuch plötzlich funktionieren.

    Hintergrund: Beim ersten echten API-Lauf wurde ein veralteter Parameter
    an das SDK übergeben. Der daraus entstandene TypeError wurde dreimal mit
    Backoff wiederholt, bevor er gemeldet wurde - verlorene Zeit ohne jede
    Chance auf Erfolg. Programmierfehler müssen sofort durchschlagen.
    """
    monkeypatch.setattr("src.triage_agent.triage.time.sleep", lambda _seconds: None)

    findings = [_make_finding("f1")]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.side_effect = TypeError("unexpected keyword argument 'temperature'")

    with pytest.raises(TypeError):
        triage_findings(findings, client=client)

    assert client.messages.create.call_count == 1


def test_authentication_error_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein falscher API-Key wird bei Wiederholung nicht richtig."""
    monkeypatch.setattr("src.triage_agent.triage.time.sleep", lambda _seconds: None)

    findings = [_make_finding("f1")]
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages.create.side_effect = anthropic.AuthenticationError(
        message="invalid x-api-key", response=MagicMock(), body=None
    )

    with pytest.raises(anthropic.AuthenticationError):
        triage_findings(findings, client=client)

    assert client.messages.create.call_count == 1
