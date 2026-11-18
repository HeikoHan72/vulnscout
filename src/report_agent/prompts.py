"""Prompt-Vorlagen für den Report-Agenten."""

from __future__ import annotations

from .models import ReportContext

SYSTEM_PROMPT = """\
Du bist ein erfahrener Security-Berater und schreibst einen \
Schwachstellenbericht für ein Entwicklungsteam, auf Deutsch.

Wichtige Regeln:
- Die Zusammenfassung mit den Zahlen (Anzahl Funde pro Schweregrad, \
Fehlalarme, Funde zur manuellen Prüfung) wird dir exakt vorgegeben - \
übernimm diese Zahlen unverändert, erfinde oder rechne nichts neu.
- Schreibe nur über die dir gegebenen Funde. Erfinde keine zusätzlichen \
Schwachstellen und keine Details, die nicht im Fund stehen.
- Für jeden Fund: eine kurze, verständliche Erklärung, warum das ein \
Risiko ist, und einen konkreten, umsetzbaren Fix-Vorschlag (z. B. \
parametrisierte Abfrage statt String-Konkatenation, `subprocess.run` mit \
Liste statt `shell=True`, Paket auf die genannte Fix-Version anheben).
- Gruppiere die Funde nach Schweregrad (critical, high, medium, low), \
innerhalb einer Gruppe in der gegebenen Reihenfolge.
- Funde, die als "braucht menschliche Prüfung" markiert sind, bekommen \
einen eigenen Abschnitt am Ende, mit dem Hinweis, dass sich der \
Triage-Agent hier nicht sicher war.
- Wenn Scanner-Fehler gemeldet wurden, nenne sie am Anfang des Berichts \
(z. B. "Semgrep konnte in diesem Lauf nicht ausgeführt werden") - der \
Bericht darf nicht so wirken, als sei der Scan vollständig gewesen, \
wenn das nicht stimmt.
- Wenn die Liste der Funde gekappt wurde (zu viele für einen Durchlauf), \
weise das deutlich aus und nenne, wie viele weitere Funde nicht im \
Detail aufgeführt sind.
- Antworte als fertiges Markdown-Dokument, mit Überschriften, bereit zum \
Speichern als Report-Datei. Keine Meta-Kommentare über diese Anweisung.
"""


def build_report_prompt(context: ReportContext) -> str:
    """Baut den User-Prompt für den Report-Agenten aus einem
    vorberechneten `ReportContext`.
    """
    lines: list[str] = [f"Repository: {context.repo_name}", ""]

    if context.scanner_errors:
        lines.append("Scanner-Fehler in diesem Lauf:")
        for tool, error in context.scanner_errors.items():
            lines.append(f"- {tool}: {error}")
        lines.append("")

    lines.append("Zusammenfassung (exakt übernehmen, nicht neu berechnen):")
    lines.append(f"- Bestätigte Funde insgesamt: {context.total_confirmed}")
    for severity, count in context.counts_by_severity.items():
        lines.append(f"  - {severity}: {count}")
    lines.append(f"- Als Fehlalarm eingestuft (nicht einzeln aufgeführt): {context.false_positive_count}")
    lines.append(f"- Braucht menschliche Prüfung (kein Konsens im Triage-Agenten): {len(context.needs_review)}")
    if context.truncated:
        shown = len(context.detailed)
        remaining = context.total_confirmed - shown
        lines.append(
            f"- Hinweis: Nur die {shown} schwerwiegendsten Funde sind unten im Detail aufgeführt, "
            f"{remaining} weitere bestätigte Funde niedrigerer Priorität sind in der Zusammenfassung "
            "mitgezählt, aber nicht einzeln beschrieben."
        )
    lines.append("")

    if not context.detailed and not context.needs_review:
        lines.append("Es liegen keine im Detail zu beschreibenden Funde vor.")
        return "\n".join(lines)

    if context.detailed:
        lines.append("## Bestätigte Funde (im Detail)")
        for item in context.detailed:
            lines.append(_render_finding_block(item))
        lines.append("")

    if context.needs_review:
        lines.append("## Funde ohne Konsens (zur manuellen Prüfung)")
        for item in context.needs_review:
            lines.append(_render_finding_block(item))

    return "\n".join(lines)


def _render_finding_block(item) -> str:  # FindingWithAssessment, Import-Zyklus vermeiden
    f, a = item.finding, item.assessment
    block = [
        f"### Fund-ID: {f.id}",
        f"Schweregrad (Triage): {a.severity} (CVSS-ähnlich: {a.cvss_score}, Konfidenz: {a.confidence})",
        f"Tool/Regel: {f.tool} / {f.rule_id}",
        f"Titel: {f.title}",
    ]
    if f.file_path:
        location = f.file_path
        if f.line_start:
            location += f", Zeile {f.line_start}"
        block.append(f"Ort: {location}")
    if f.package:
        block.append(f"Paket: {f.package} ({f.installed_version}), Fix: {', '.join(f.fix_versions) or 'unbekannt'}")
    if f.code_snippet:
        block.append(f"Code:\n```\n{f.code_snippet}\n```")
    block.append(f"Begründung des Triage-Agenten: {a.reasoning}")
    return "\n".join(block)
