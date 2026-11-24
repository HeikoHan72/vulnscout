"""Prompt-Vorlagen für den Triage-Agenten."""

from __future__ import annotations

from src.scanner_agent.models import Finding

SYSTEM_PROMPT = """\
Du bist ein erfahrener Sicherheitsanalyst (Application Security). Du bekommst \
Funde von statischen Analyse-Tools (Bandit, Semgrep, pip-audit) und bewertest \
jeden davon.

Für jeden Fund entscheidest du:
1. Ob es sich um einen echten Treffer (true positive) oder einen Fehlalarm \
(false positive) handelt. Typische Fehlalarme: Test- oder Beispielcode, \
auskommentierter Code, Strings, die nur angezeigt und nicht ausgeführt oder \
in eine Abfrage eingesetzt werden, bereits durch Parametrisierung oder \
Escaping entschärfte Stellen, Vorkommen in offensichtlich nicht \
produktivem Code (z. B. Migrationsskripte, die nur lokal laufen).
2. Den Schweregrad: low, medium, high oder critical. Liegt bei einem \
Abhängigkeits-Fund ein Schweregrad aus der öffentlichen Datenbank OSV vor, \
ist er dein Ausgangspunkt; weiche nur mit konkreter Begründung davon ab.
3. Einen CVSS-ähnlichen Score von 0 bis 10 (grobe Einschätzung reicht, \
keine formale CVSS-Berechnung).
4. Deine Konfidenz in diese Einschätzung, als Zahl zwischen 0 und 1. \
Nutze niedrige Werte (< 0.6) ehrlich, wenn der Kontext nicht eindeutig ist \
- rate nicht künstlich sicher.
5. Eine kurze, konkrete Begründung auf Deutsch (1-2 Sätze).

Antworte ausschließlich als JSON-Objekt mit dem Schlüssel `assessments`. \
Liefere genau eine Bewertung pro übergebenem Fund, mit der exakt gleichen \
`finding_id`, wie sie dir gegeben wurde - erfinde keine neuen IDs und lasse \
keinen Fund aus. Kein Fließtext, keine Code-Fences um das JSON.
"""


def build_user_prompt(findings: list[Finding]) -> str:
    """Baut den User-Prompt für eine Gruppe von Findings.

    Jeder Fund wird mit allem Kontext gerendert, den der Scanner-Agent
    mitgeliefert hat (Code-Ausschnitt, Beschreibung, Paketinfo bei
    pip-audit-Funden), damit der Triage-Agent möglichst wenig raten muss.
    """
    blocks = []
    for finding in findings:
        lines = [
            f"### Fund-ID: {finding.id}",
            f"Tool: {finding.tool}",
            f"Regel/ID: {finding.rule_id}",
            f"Titel: {finding.title}",
        ]
        if finding.file_path:
            location = finding.file_path
            if finding.line_start:
                location += f", Zeile {finding.line_start}"
                if finding.line_end and finding.line_end != finding.line_start:
                    location += f"-{finding.line_end}"
            lines.append(f"Ort: {location}")
        if finding.raw_severity:
            lines.append(f"Roh-Schweregrad laut Tool: {finding.raw_severity}")
        if finding.cwe:
            lines.append(f"CWE: {finding.cwe}")
        if finding.package:
            lines.append(f"Paket: {finding.package} (installiert: {finding.installed_version})")
            if finding.fix_versions:
                lines.append(f"Behoben in Version(en): {', '.join(finding.fix_versions)}")
        if finding.osv_severity:
            lines.append(
                f"Schweregrad laut OSV-Datenbank: {finding.osv_severity.value} "
                f"(Quelle: {finding.severity_source})"
            )
        if finding.cvss_vector:
            lines.append(f"CVSS-Vektor: {finding.cvss_vector}")
        if finding.osv_cwe_ids:
            lines.append(f"CWE laut OSV: {', '.join(finding.osv_cwe_ids)}")
        if finding.description:
            lines.append(f"Beschreibung des Tools: {finding.description}")
        if finding.code_snippet:
            lines.append(f"Code-Ausschnitt:\n```\n{finding.code_snippet}\n```")

        blocks.append("\n".join(lines))

    joined = "\n\n".join(blocks)
    return (
        f"Bewerte die folgenden {len(findings)} Fund(e). "
        f"Antworte als JSON-Objekt mit einer Bewertung pro Fund "
        f"unter `assessments`:\n\n{joined}"
    )
