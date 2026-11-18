"""Triage-Agent: bewertet Scanner-Funde per LLM.

Design-Entscheidungen (siehe Architektur-Planung):
- Findings werden in Batches an das LLM geschickt (nicht einzeln), um
  den System-Prompt nicht pro Fund neu zu bezahlen.
- Funde mit niedriger Konfidenz bekommen einen zweiten, unabhängigen
  Durchlauf (Consensus-Check). Stimmen beide Durchläufe nicht überein,
  wird der Fund als `needs_review` markiert statt automatisch
  entschieden - das verhindert, dass unsichere LLM-Antworten
  unbemerkt in den Bericht einfließen.
- Ein API-Fehler wird mit Backoff mehrfach wiederholt, aber nicht
  endlos (siehe Risikotabelle: kein Retry-Sturm, der Guthaben
  verbrennt).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

import anthropic

from src.scanner_agent.models import Finding

from .models import TriageAssessment
from .prompts import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
DEFAULT_BATCH_SIZE = 5
CONFIDENCE_THRESHOLD = 0.6  # unterhalb davon: Consensus-Check
MAX_RETRIES = 3
MAX_TOKENS = 4096

TOOL_SCHEMA = {
    "name": "submit_triage",
    "description": "Übermittelt die Sicherheitsbewertung für einen oder mehrere Scanner-Funde.",
    "input_schema": {
        "type": "object",
        "properties": {
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "is_true_positive": {"type": "boolean"},
                        "severity": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"],
                        },
                        "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "reasoning": {"type": "string"},
                    },
                    "required": [
                        "finding_id",
                        "is_true_positive",
                        "severity",
                        "cvss_score",
                        "confidence",
                        "reasoning",
                    ],
                },
            }
        },
        "required": ["assessments"],
    },
}


def _call_llm(
    client: anthropic.Anthropic, findings: list[Finding], model: str
) -> dict[str, TriageAssessment]:
    """Genau ein LLM-Aufruf für eine Gruppe von Findings.

    Gibt eine Zuordnung finding_id -> TriageAssessment zurück. Wirft
    `RuntimeError`, wenn die Antwort keinen gültigen tool_use-Block
    enthält - das behandelt `_call_llm_with_retry`.
    """
    user_prompt = build_user_prompt(findings)

    response = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        temperature=0,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
        tools=[TOOL_SCHEMA],
        tool_choice={"type": "tool", "name": "submit_triage"},
    )

    tool_use = next((block for block in response.content if block.type == "tool_use"), None)
    if tool_use is None:
        raise RuntimeError("LLM-Antwort enthielt keinen tool_use-Block.")

    assessments: dict[str, TriageAssessment] = {}
    for item in tool_use.input.get("assessments", []):
        assessment = TriageAssessment(**item)
        assessments[assessment.finding_id] = assessment
    return assessments


def _call_llm_with_retry(
    client: anthropic.Anthropic, findings: list[Finding], model: str
) -> dict[str, TriageAssessment]:
    """Wie `_call_llm`, aber mit Backoff-Retry (max. `MAX_RETRIES` Versuche).

    Begrenzt bewusst, damit ein hängender/fehlerhafter Agent kein
    API-Guthaben in einer Endlosschleife verbrennt.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return _call_llm(client, findings, model)
        except (anthropic.APIError, ValueError, TypeError) as exc:
            last_exc = exc
            logger.warning(
                "LLM-Aufruf fehlgeschlagen (Versuch %d/%d): %s", attempt, MAX_RETRIES, exc
            )
            if attempt < MAX_RETRIES:
                time.sleep(2**attempt)
    raise RuntimeError(f"LLM-Aufruf nach {MAX_RETRIES} Versuchen fehlgeschlagen: {last_exc}")


def triage_findings(
    findings: list[Finding],
    client: Optional[anthropic.Anthropic] = None,
    model: str = DEFAULT_MODEL,
    batch_size: int = DEFAULT_BATCH_SIZE,
    confidence_threshold: float = CONFIDENCE_THRESHOLD,
) -> list[TriageAssessment]:
    """Bewertet alle `findings` per LLM.

    Ablauf:
    1. Findings werden in Gruppen von `batch_size` an das LLM geschickt.
    2. Fehlt nach dem ersten Durchlauf eine Bewertung für einen Fund
       (z. B. weil das Modell ihn übersehen hat), wird dieser Fund
       einzeln nachgefragt.
    3. Jeder Fund mit `confidence < confidence_threshold` bekommt einen
       zweiten, unabhängigen Durchlauf (Consensus-Check). Stimmen beide
       Durchläufe in `is_true_positive` nicht überein, wird der Fund
       als `needs_review=True` markiert statt automatisch entschieden.

    Gibt eine Liste von `TriageAssessment` zurück, eine pro Fund in
    `findings` (sofern das LLM für jeden Fund geantwortet hat).
    """
    if not findings:
        return []

    client = client or anthropic.Anthropic()
    results: dict[str, TriageAssessment] = {}

    for i in range(0, len(findings), batch_size):
        batch = findings[i : i + batch_size]
        results.update(_call_llm_with_retry(client, batch, model))

    # Fehlende Bewertungen (Modell hat einen Fund im Batch übersehen) einzeln nachholen.
    findings_by_id = {f.id: f for f in findings}
    missing_ids = [fid for fid in findings_by_id if fid not in results]
    for finding_id in missing_ids:
        try:
            results.update(_call_llm_with_retry(client, [findings_by_id[finding_id]], model))
        except RuntimeError as exc:
            logger.error("Keine Bewertung für Fund %s erhalten: %s", finding_id, exc)

    # Consensus-Check: jeder Fund mit niedriger Konfidenz wird einzeln,
    # unabhängig vom ursprünglichen Batch, noch einmal bewertet.
    low_confidence_ids = [fid for fid, a in results.items() if a.confidence < confidence_threshold]
    for finding_id in low_confidence_ids:
        first = results[finding_id]
        try:
            second_round = _call_llm_with_retry(client, [findings_by_id[finding_id]], model)
            second = second_round.get(finding_id)
        except RuntimeError as exc:
            logger.warning("Consensus-Check für %s fehlgeschlagen: %s", finding_id, exc)
            first.needs_review = True
            continue

        if second is None or second.is_true_positive != first.is_true_positive:
            first.needs_review = True
            logger.info("Kein Konsens für Fund %s - als prüfungsbedürftig markiert.", finding_id)
        # Bei Übereinstimmung bleibt die ursprüngliche Bewertung bestehen.

    return list(results.values())
