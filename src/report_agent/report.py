"""Report-Agent: baut den Berichtskontext (deterministisch, im Code)
und lässt daraus per LLM einen lesbaren Markdown-Bericht schreiben.

Design-Entscheidungen (siehe Architektur-Planung):
- Zählungen, Sortierung und Filterung passieren im Code, nicht im
  Prompt - das LLM bekommt die fertigen Zahlen und darf sie nicht neu
  erfinden (vermeidet Zahlendreher/Hallucination in der Zusammenfassung).
- Bei sehr vielen bestätigten Funden wird die Detailliste gekappt
  (`MAX_DETAILED_FINDINGS`), damit ein einzelner Prompt nicht zu groß
  wird - die Kappung wird im Bericht transparent genannt.
- Liegen keine zu beschreibenden Funde vor (weder bestätigt noch
  needs_review), wird der Bericht ohne LLM-Aufruf deterministisch
  erzeugt - das spart Kosten für den definierten Leerfall.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Optional

import anthropic

from src.scanner_agent.models import Finding, Severity
from src.triage_agent.models import TriageAssessment

from .models import FindingWithAssessment, ReportContext
from .prompts import SYSTEM_PROMPT, build_report_prompt

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
MAX_DETAILED_FINDINGS = 40
MAX_TOKENS = 8192

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.UNKNOWN: 4,
}


def build_report_context(
    findings: list[Finding],
    assessments: list[TriageAssessment],
    repo_name: str,
    scanner_errors: Optional[dict[str, str]] = None,
    max_detailed: int = MAX_DETAILED_FINDINGS,
) -> ReportContext:
    """Verknüpft Findings mit ihren Triage-Bewertungen und berechnet
    alle Zahlen, die der Bericht braucht - ohne LLM.
    """
    assessments_by_id = {a.finding_id: a for a in assessments}

    confirmed: list[FindingWithAssessment] = []
    needs_review: list[FindingWithAssessment] = []
    false_positive_count = 0

    for finding in findings:
        assessment = assessments_by_id.get(finding.id)
        if assessment is None:
            logger.warning("Keine Triage-Bewertung für Fund %s - wird im Bericht ausgelassen.", finding.id)
            continue

        pair = FindingWithAssessment(finding=finding, assessment=assessment)
        if assessment.needs_review:
            needs_review.append(pair)
        elif assessment.is_true_positive:
            confirmed.append(pair)
        else:
            false_positive_count += 1

    confirmed.sort(key=lambda pair: _SEVERITY_ORDER.get(pair.assessment.severity, 99))

    counts_by_severity = dict(Counter(pair.assessment.severity.value for pair in confirmed))

    total_confirmed = len(confirmed)
    truncated = total_confirmed > max_detailed
    detailed = confirmed[:max_detailed] if truncated else confirmed

    return ReportContext(
        repo_name=repo_name,
        detailed=detailed,
        needs_review=needs_review,
        false_positive_count=false_positive_count,
        counts_by_severity=counts_by_severity,
        total_confirmed=total_confirmed,
        truncated=truncated,
        scanner_errors=scanner_errors or {},
    )


def _render_empty_report(context: ReportContext) -> str:
    """Deterministischer Bericht für den Fall, dass nichts zu
    beschreiben ist - kein LLM-Aufruf nötig.
    """
    lines = [
        f"# Sicherheitsbericht: {context.repo_name}",
        "",
        "Keine bestätigten Schwachstellen und keine Funde zur manuellen Prüfung in diesem Lauf.",
        f"Als Fehlalarm eingestuft: {context.false_positive_count}.",
    ]
    if context.scanner_errors:
        lines.append("")
        lines.append("**Hinweis:** Nicht alle Scanner liefen in diesem Durchlauf erfolgreich:")
        for tool, error in context.scanner_errors.items():
            lines.append(f"- {tool}: {error}")
    return "\n".join(lines)


def generate_report(
    findings: list[Finding],
    assessments: list[TriageAssessment],
    repo_name: str,
    scanner_errors: Optional[dict[str, str]] = None,
    client: Optional[anthropic.Anthropic] = None,
    model: str = DEFAULT_MODEL,
) -> str:
    """Erzeugt den fertigen Markdown-Bericht für einen Scan-Lauf.

    Macht höchstens einen LLM-Aufruf (keiner, wenn es nichts zu
    beschreiben gibt - siehe `_render_empty_report`).
    """
    context = build_report_context(findings, assessments, repo_name, scanner_errors)

    if not context.detailed and not context.needs_review:
        return _render_empty_report(context)

    client = client or anthropic.Anthropic()
    user_prompt = build_report_prompt(context)

    response = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        temperature=0,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    text_block = next((block for block in response.content if block.type == "text"), None)
    if text_block is None:
        raise RuntimeError("LLM-Antwort enthielt keinen Text-Block.")

    return text_block.text
