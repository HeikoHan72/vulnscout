"""Darstellung der OSV-Angaben eines Fundes für Prompts und Berichte.

Triage- und Report-Prompt zeigen dieselben Angaben. Damit sie nicht
auseinanderlaufen, entsteht der Text an genau einer Stelle.

Das Schweregrad-Wort steht bewusst getrennt von den Vektoren und ist als
Angabe der Datenbank benannt: Es muss nicht zu jedem Vektor passen. Beobachtet
wurde ein Eintrag mit dem Wort HIGH, dessen Version-3-Vektor nur eine mittlere
Stufe ergibt, während der Version-4-Vektor zu HIGH passt.
"""

from __future__ import annotations

from src.scanner_agent.models import Finding

VECTOR_MISMATCH_HINT = (
    "Hinweis: Das Schweregrad-Wort ist die Angabe der Datenbank. Die Vektoren "
    "sind die Rohdaten dazu; sie können zu unterschiedlichen Stufen führen "
    "(z. B. Version 3 gegenüber Version 4)."
)


def osv_context_lines(finding: Finding) -> list[str]:
    """Zeilen mit den OSV-Angaben des Fundes (leer, wenn keine vorliegen)."""
    lines: list[str] = []
    if finding.osv_severity:
        lines.append(
            f"Schweregrad-Wort laut OSV-Datenbank: {finding.osv_severity.value} "
            f"(Quelle: {finding.severity_source})"
        )
    vectors = finding.cvss_vectors or ([finding.cvss_vector] if finding.cvss_vector else [])
    for vector in vectors:
        lines.append(f"CVSS-Vektor: {vector}")
    if finding.osv_severity and len(vectors) > 1:
        lines.append(VECTOR_MISMATCH_HINT)
    if finding.osv_cwe_ids:
        lines.append(f"CWE laut OSV: {', '.join(finding.osv_cwe_ids)}")
    return lines
