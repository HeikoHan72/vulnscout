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

import json
import logging
import os
import time
from typing import Optional

import anthropic

from src.monitoring import metrics as m
from src.scanner_agent.models import Finding

from .models import TriageAssessment
from .prompts import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
DEFAULT_BATCH_SIZE = 5
CONFIDENCE_THRESHOLD = 0.6  # unterhalb davon: Consensus-Check
MAX_RETRIES = 3
MAX_TOKENS = 4096

# Nur Fehler, die bei einem erneuten Versuch realistisch verschwinden können:
# Netzwerk-/Zeitprobleme, Rate-Limits und serverseitige Störungen, dazu
# unbrauchbare Modellantworten (fehlender tool_use-Block -> RuntimeError,
# Schema-Verletzung beim Validieren -> ValueError).
#
# Bewusst NICHT enthalten: Programmierfehler (TypeError), Authentifizierungs-
# und Anfragefehler (falscher Key, ungültige Parameter) sowie erreichte
# Ausgabenlimits. Die scheitern bei jedem Versuch gleich und würden nur
# Wartezeit und im schlimmsten Fall Guthaben kosten. Ein früherer Lauf hat
# genau das gezeigt: Ein TypeError wurde dreimal mit Backoff wiederholt,
# obwohl er nie hätte erfolgreich werden können.
RETRYABLE_ERRORS = (
    anthropic.APIConnectionError,  # schließt APITimeoutError ein
    anthropic.RateLimitError,
    anthropic.InternalServerError,
    anthropic.OverloadedError,
    anthropic.ServiceUnavailableError,
    anthropic.GatewayTimeoutError,
    RuntimeError,
    ValueError,
)

# Erzwungenes Tool-Use (tool_choice type "tool") wird von dieser Modell-
# generation nicht mehr unterstützt - die API lehnt es mit HTTP 400 ab.
# Stattdessen Structured Outputs: Das Schema wird über output_config
# vorgegeben, die Antwort kommt als JSON-Text zurück und ist damit ohne
# Umweg über einen Werkzeugaufruf auswertbar.
# Wichtig: Structured Outputs verlangt bei jedem Objekt-Typ ein explizites
# "additionalProperties": False - fehlt es, lehnt die API die Anfrage mit
# HTTP 400 ab. Das gilt auch für verschachtelte Objekte, hier also sowohl
# für die Wurzel als auch für die einzelnen Bewertungen.
TRIAGE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "assessments": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "finding_id": {"type": "string"},
                    "is_true_positive": {"type": "boolean"},
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                    },
                    # Ohne minimum/maximum: Structured Outputs unterstützt
                    # diese Angaben bei "number" nicht (HTTP 400). Die
                    # Wertebereiche (0-10 bzw. 0-1) prüft stattdessen das
                    # pydantic-Modell TriageAssessment. Eine Verletzung wird
                    # dort zu einem ValidationError (Unterklasse von
                    # ValueError) und löst damit einen erneuten Versuch aus.
                    "cvss_score": {"type": "number"},
                    "confidence": {"type": "number"},
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
}

OUTPUT_CONFIG = {"format": {"type": "json_schema", "schema": TRIAGE_SCHEMA}}


def _call_llm(
    client: anthropic.Anthropic, findings: list[Finding], model: str
) -> dict[str, TriageAssessment]:
    """Genau ein LLM-Aufruf für eine Gruppe von Findings.

    Gibt eine Zuordnung finding_id -> TriageAssessment zurück. Wirft
    `RuntimeError`, wenn die Antwort keinen auswertbaren Text enthält,
    und `ValueError`, wenn der Text kein gültiges JSON ist - beides
    behandelt `_call_llm_with_retry`.
    """
    user_prompt = build_user_prompt(findings)

    # Hinweis: Frühere Fassungen setzten hier temperature=0 für deterministische
    # Bewertungen. Das Anthropic-SDK ab Version 2 kennt diesen Parameter nicht
    # mehr (ersatzlos entfallen, auch nicht in output_config). Die Stabilität
    # der Bewertung wird stattdessen über das JSON-Schema (Structured Outputs)
    # und den Consensus-Check bei niedriger Konfidenz abgesichert.
    response = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
        output_config=OUTPUT_CONFIG,
    )

    text_block = next((block for block in response.content if block.type == "text"), None)
    if text_block is None:
        raise RuntimeError("LLM-Antwort enthielt keinen Text-Block.")

    # json.JSONDecodeError ist eine Unterklasse von ValueError und damit
    # wiederholbar: Eine abgeschnittene oder fehlerhafte Antwort kann beim
    # nächsten Versuch korrekt kommen.
    payload = json.loads(text_block.text)

    assessments: dict[str, TriageAssessment] = {}
    for item in payload.get("assessments", []):
        assessment = TriageAssessment(**item)
        assessments[assessment.finding_id] = assessment
    return assessments


def _observe_llm_call(
    result: str, duration: float, exc: Optional[Exception] = None
) -> None:
    """Zählt einen LLM-Aufruf für das Monitoring.

    Bewusst best-effort: Schlägt das Zählen fehl, darf das den Aufruf
    nicht beeinflussen. Die Latenz wird nur bei erfolgreichen Aufrufen
    gemessen - die Dauer eines abgebrochenen Versuchs sagt nichts über
    die Antwortzeit des Modells aus.
    """
    try:
        m.LLM_REQUESTS.labels(result).inc()
        if result == "ok":
            m.LLM_LATENCY.observe(duration)
        if exc is not None:
            m.LLM_ERRORS.labels(type(exc).__name__).inc()
    except Exception:  # noqa: BLE001 - Monitoring darf den Aufruf nie kippen
        logger.exception("LLM-Metriken konnten nicht gezählt werden")


def _call_llm_with_retry(
    client: anthropic.Anthropic, findings: list[Finding], model: str
) -> dict[str, TriageAssessment]:
    """Wie `_call_llm`, aber mit Backoff-Retry (max. `MAX_RETRIES` Versuche).

    Begrenzt bewusst, damit ein hängender/fehlerhafter Agent kein
    API-Guthaben in einer Endlosschleife verbrennt.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        start = time.perf_counter()
        try:
            result = _call_llm(client, findings, model)
        except RETRYABLE_ERRORS as exc:
            last_exc = exc
            # Für das Monitoring: Art des Fehlers als Label, nicht die
            # Meldung - die enthält wechselnde Details und würde pro Fehler
            # eine eigene Zeitreihe erzeugen.
            _observe_llm_call("retry", time.perf_counter() - start, exc)
            logger.warning(
                "LLM-Aufruf fehlgeschlagen (Versuch %d/%d): %s", attempt, MAX_RETRIES, exc
            )
            if attempt < MAX_RETRIES:
                time.sleep(2**attempt)
        else:
            _observe_llm_call("ok", time.perf_counter() - start)
            return result

    _observe_llm_call("failed", 0.0)
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
