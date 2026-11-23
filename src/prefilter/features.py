"""Merkmals-Extraktion für das Pre-Filter-Modell.

Dieses Modul ist bewusst die EINZIGE Stelle, die ein `Finding` in die
Rohmerkmale übersetzt, die das Modell sieht. Sowohl das Trainingsskript
(`scripts/label_repos.py`, über den Trainingsdatensatz) als auch die
Inferenz zur Laufzeit (`src/prefilter/prefilter.py`) nutzen dieselbe
Funktion - sonst könnten Training und Produktion unbemerkt
auseinanderlaufen ("training/serving skew").
"""

from __future__ import annotations

from pathlib import Path

from src.scanner_agent.models import Finding

CATEGORICAL_FEATURES = [
    "tool",
    "rule_id",
    "scanner_severity",
    "bandit_confidence",
    "file_extension",
]
NUMERIC_FEATURES = [
    "has_cwe",
    "is_dependency_finding",
    "snippet_line_count",
    "snippet_char_count",
]
FEATURE_COLUMNS = CATEGORICAL_FEATURES + NUMERIC_FEATURES


def finding_to_features(finding: Finding) -> dict:
    """Übersetzt ein `Finding` in genau die Spalten aus `FEATURE_COLUMNS`."""

    snippet = finding.code_snippet or ""
    return {
        "tool": finding.tool.value,
        "rule_id": finding.rule_id,
        "scanner_severity": finding.severity.value,
        "bandit_confidence": finding.confidence or "none",
        "file_extension": Path(finding.file_path).suffix if finding.file_path else "none",
        "has_cwe": finding.cwe is not None,
        "is_dependency_finding": finding.package is not None,
        "snippet_line_count": snippet.count("\n") + 1 if snippet else 0,
        "snippet_char_count": len(snippet),
    }
