"""Demo-/Fixture-Modus: lässt VulnScout ohne eigenen Anthropic-API-Key
laufen.

Zweck: Jeder, der das Repository klont, soll die Pipeline einmal
end-to-end ausprobieren können, ohne eigenes API-Guthaben zu
brauchen. In diesem Modus übernehmen deterministische, regelbasierte
Funktionen die Rolle von Triage- und Report-Agent -- es wird **kein**
LLM aufgerufen.

Wichtig für die Ehrlichkeit des Projekts: Diese Funktionen ahmen kein
LLM-Urteil nach und geben sich nicht als eines aus. Jede erzeugte
Bewertung und jeder erzeugte Bericht markiert sich selbst klar als
"Demo-Modus" und erklärt, dass keine inhaltliche Prüfung durch ein
Sprachmodell stattgefunden hat -- nur die rohen Scanner-Ergebnisse
wurden eins zu eins übernommen und nach Schweregrad sortiert.
"""

from __future__ import annotations

from src.enrichment.display import VECTOR_MISMATCH_HINT
from src.report_agent.models import ReportContext
from src.report_agent.report import _render_empty_report, build_report_context
from src.scanner_agent.models import Finding, Severity, ToolName
from src.triage_agent.models import TriageAssessment

DEMO_REASONING = (
    "Demo-Modus (kein ANTHROPIC_API_KEY gesetzt): Der Scanner-Befund wurde "
    "unverändert übernommen, ohne inhaltliche Prüfung durch ein LLM. Für eine "
    "echte Einstufung (echte/false Positive, CVSS, Konfidenz) einen "
    "Anthropic-API-Key in .env eintragen und den Lauf wiederholen."
)

# Grobe, nicht-fachliche CVSS-Richtwerte je Schweregrad - nur für die
# Demo-Darstellung, keine echte CVSS-Berechnung.
_SEVERITY_TO_CVSS = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.UNKNOWN: 5.0,
}

_FIX_HINTS = {
    ToolName.BANDIT: "Siehe die Bandit-Dokumentation zur Regel {rule_id} für Details zur Behebung.",
    ToolName.SEMGREP: "Siehe die Semgrep-Regel {rule_id} für Details zur Behebung.",
    ToolName.PIP_AUDIT: "Paket auf eine gepatchte Version aktualisieren.",
}


def fixture_triage(findings: list[Finding]) -> list[TriageAssessment]:
    """Erzeugt deterministische Triage-Bewertungen ohne LLM-Aufruf.

    Jeder Fund wird als echter Fund mit seinem vom Scanner gemeldeten
    Schweregrad übernommen (`is_true_positive=True`, `needs_review=False`).
    Meldet der Scanner keinen (praktisch alle pip-audit-Funde), gilt der
    Schweregrad aus der OSV-Datenbank, sofern die Anreicherung einen
    gefunden hat -- das steht dann in der Begründung. Das ist bewusst
    keine echte Triage -- es gibt im Demo-Modus keinen Consensus-Check und
    keine Fehlalarm-Erkennung, nur eine 1:1-Übernahme der vorhandenen
    Daten, transparent als solche gekennzeichnet (siehe `DEMO_REASONING`).

    Args:
        findings: Die Scanner-Funde dieses Laufs.

    Returns:
        Eine `TriageAssessment` pro Fund.
    """
    assessments = []
    for finding in findings:
        severity = finding.severity
        reasoning = DEMO_REASONING
        if severity == Severity.UNKNOWN and finding.osv_severity is not None:
            severity = finding.osv_severity
            reasoning = (
                f"{DEMO_REASONING} Der Schweregrad stammt aus der "
                f"OSV-Datenbank ({finding.severity_source}), nicht vom Scanner."
            )
        assessments.append(
            TriageAssessment(
                finding_id=finding.id,
                is_true_positive=True,
                severity=severity,
                cvss_score=_SEVERITY_TO_CVSS.get(severity, 5.0),
                confidence=1.0,
                reasoning=reasoning,
                needs_review=False,
            )
        )
    return assessments


def _fix_hint(finding: Finding) -> str:
    """Generischer, nicht fund-spezifischer Hinweis zur Behebung."""
    if finding.tool == ToolName.PIP_AUDIT and finding.fix_versions:
        versions = ", ".join(finding.fix_versions)
        return f"Paket `{finding.package}` aktualisieren auf eine der Versionen: {versions}."
    template = _FIX_HINTS.get(finding.tool, "Scanner-Dokumentation zur Regel prüfen.")
    return template.format(rule_id=finding.rule_id)


def fixture_report(context: ReportContext) -> str:
    """Erzeugt einen deterministischen Markdown-Bericht ohne LLM-Aufruf.

    Listet die bestätigten Funde nach Schweregrad sortiert mit Datei,
    Zeile, Titel, Beschreibung und einem generischen Behebungshinweis
    auf. Markiert sich im Titel klar als Demo-Modus-Bericht.

    Args:
        context: Der bereits berechnete Berichtskontext (siehe
            `build_report_context`).

    Returns:
        Den fertigen Markdown-Bericht als String.
    """
    if not context.detailed and not context.needs_review:
        base = _render_empty_report(context)
        return base.replace(
            f"# Sicherheitsbericht: {context.repo_name}",
            f"# Sicherheitsbericht (Demo-Modus): {context.repo_name}",
        )

    lines = [
        f"# Sicherheitsbericht (Demo-Modus): {context.repo_name}",
        "",
        "> **Hinweis:** Dieser Bericht wurde ohne Anthropic-API-Key im "
        "Demo-Modus erzeugt. Die Funde wurden 1:1 von den Scannern "
        "übernommen, ohne inhaltliche Prüfung durch ein LLM (keine "
        "Fehlalarm-Erkennung, kein Consensus-Check, keine individuellen "
        "Fix-Vorschläge). Für eine echte Einstufung einen "
        "`ANTHROPIC_API_KEY` in `.env` eintragen und den Lauf wiederholen.",
        "",
        f"**Bestätigte Funde:** {context.total_confirmed}  ",
        f"**Als Fehlalarm eingestuft:** {context.false_positive_count}  ",
        f"**Ohne Konsens (`needs_review`):** {len(context.needs_review)}",
        "",
    ]

    if any(pair.finding.osv_severity for pair in context.detailed):
        lines.extend(
            [
                "> **Hinweis zur Einstufung:** Bei Abhängigkeits-Funden "
                "(pip-audit) stammt der Schweregrad nicht vom Scanner, sondern "
                "aus der öffentlichen Datenbank OSV; die Quelle steht beim "
                "jeweiligen Fund.",
                "",
            ]
        )

    if context.scanner_errors:
        lines.append("**Scanner-Fehler in diesem Lauf:**")
        for tool, error in context.scanner_errors.items():
            lines.append(f"- {tool}: {error}")
        lines.append("")

    if context.truncated:
        lines.append(
            f"*Hinweis: Nur die ersten {len(context.detailed)} von "
            f"{context.total_confirmed} bestätigten Funden werden unten "
            "aufgeführt (Kappung zur Lesbarkeit).*"
        )
        lines.append("")

    if context.detailed:
        lines.append("## Bestätigte Funde")
        lines.append("")
        for pair in context.detailed:
            finding = pair.finding
            assessment = pair.assessment
            location = finding.file_path or "(keine Datei, z. B. Abhängigkeit)"
            if finding.line_start:
                location += f":{finding.line_start}"
            lines.append(
                f"### [{assessment.severity.value.upper()}] {finding.title}"
            )
            lines.append(f"- **Ort:** {location}")
            lines.append(f"- **Tool/Regel:** {finding.tool.value} / {finding.rule_id}")
            if finding.description:
                lines.append(f"- **Beschreibung:** {finding.description}")
            if finding.osv_severity:
                lines.append(
                    f"- **Schweregrad-Wort laut OSV-Datenbank:** "
                    f"{finding.osv_severity.value} ({finding.severity_source})"
                )
            vectors = finding.cvss_vectors or (
                [finding.cvss_vector] if finding.cvss_vector else []
            )
            for vector in vectors:
                lines.append(f"- **CVSS-Vektor:** {vector}")
            if finding.osv_severity and len(vectors) > 1:
                lines.append(f"- *{VECTOR_MISMATCH_HINT}*")
            if finding.osv_cwe_ids:
                lines.append(f"- **CWE (OSV):** {', '.join(finding.osv_cwe_ids)}")
            lines.append(f"- **Hinweis zur Behebung:** {_fix_hint(finding)}")
            lines.append("")

    if context.needs_review:
        lines.append("## Ohne Konsens (manuelle Prüfung empfohlen)")
        lines.append("")
        for pair in context.needs_review:
            finding = pair.finding
            lines.append(f"- {finding.title} ({finding.file_path or 'keine Datei'})")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
