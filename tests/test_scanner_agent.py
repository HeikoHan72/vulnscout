"""Tests für den Scanner-Agenten.

Die Parser-Tests (`_parse_bandit`, `_parse_semgrep`, `_parse_pip_audit`)
laufen immer, ohne die Tools selbst aufzurufen - sie prüfen nur, ob
Rohdaten korrekt ins einheitliche Finding-Format übersetzt werden.

Die Integrationstests rufen die echten Kommandozeilen-Tools auf einem
kleinen, absichtlich verwundbaren Beispielprojekt auf und werden
automatisch übersprungen, wenn das jeweilige Tool nicht installiert
ist (z. B. in einer CI-Umgebung ohne Internetzugang für Semgrep).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import src.scanner_agent.scanner as scanner_module
from src.scanner_agent.models import Severity, ToolName
from src.scanner_agent.scanner import (
    _parse_bandit,
    _parse_pip_audit,
    _parse_semgrep,
    run_all_scanners,
    run_bandit,
    run_pip_audit,
    run_semgrep,
)

SAMPLE_PROJECT = Path(__file__).parent.parent / "test_repos" / "dummy_vuln_repo"


# ---------------------------------------------------------------------------
# Parser-Tests (keine echten Tool-Aufrufe, laufen immer)
# ---------------------------------------------------------------------------


def test_parse_bandit_maps_fields_correctly(tmp_path: Path) -> None:
    raw = {
        "results": [
            {
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "filename": str(tmp_path / "app.py"),
                "line_number": 13,
                "code": "query = ...",
                "issue_text": "Possible SQL injection",
                "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/..."},
            }
        ]
    }
    findings = _parse_bandit(raw, tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == ToolName.BANDIT
    assert finding.rule_id == "B608"
    assert finding.severity == Severity.MEDIUM
    assert finding.raw_severity == "MEDIUM"
    assert finding.confidence == "HIGH"
    assert finding.file_path == "app.py"
    assert finding.line_start == 13
    assert finding.cwe == "CWE-89"


def test_parse_bandit_unknown_severity_falls_back() -> None:
    raw = {"results": [{"test_id": "B000", "issue_severity": "WEIRD", "filename": "x.py"}]}
    findings = _parse_bandit(raw, Path("."))
    assert findings[0].severity == Severity.UNKNOWN


def test_parse_semgrep_maps_fields_correctly(tmp_path: Path) -> None:
    raw = {
        "results": [
            {
                "check_id": "python.lang.security.hardcoded-secret",
                "path": str(tmp_path / "app.py"),
                "start": {"line": 7},
                "end": {"line": 7},
                "extra": {
                    "severity": "ERROR",
                    "message": "Mögliches hartcodiertes Secret.",
                    "lines": 'API_KEY = "..."',
                    "metadata": {"cwe": ["CWE-798"], "shortDescription": "Hardcoded secret"},
                },
            }
        ]
    }
    findings = _parse_semgrep(raw, tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == ToolName.SEMGREP
    assert finding.severity == Severity.HIGH
    assert finding.file_path == "app.py"
    assert finding.line_start == 7
    assert finding.cwe == "CWE-798"
    assert finding.title == "Hardcoded secret"


def test_parse_pip_audit_maps_fields_correctly() -> None:
    raw = {
        "dependencies": [
            {
                "name": "flask",
                "version": "0.12",
                "vulns": [
                    {
                        "id": "PYSEC-2019-179",
                        "fix_versions": ["1.0"],
                        "description": "Flask vulnerability",
                    }
                ],
            }
        ]
    }
    findings = _parse_pip_audit(raw, Path("requirements.txt"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == ToolName.PIP_AUDIT
    assert finding.package == "flask"
    assert finding.installed_version == "0.12"
    assert finding.fix_versions == ["1.0"]
    assert finding.severity == Severity.UNKNOWN  # pip-audit liefert keinen eigenen Schweregrad


def test_parse_pip_audit_handles_bare_list_format() -> None:
    # Ältere pip-audit-Versionen liefern direkt eine Liste statt {"dependencies": [...]}.
    raw = [{"name": "pyyaml", "version": "5.1", "vulns": [{"id": "GHSA-xxxx", "fix_versions": []}]}]
    findings = _parse_pip_audit(raw, Path("requirements.txt"))
    assert len(findings) == 1
    assert findings[0].package == "pyyaml"


def test_run_semgrep_empty_stdout_is_treated_as_crash_not_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Ein regulärer Semgrep-Lauf gibt auch ohne Funde ein gültiges JSON-Objekt
    # aus. Leere Ausgabe auf stdout (z. B. weil Semgrep selbst abgestürzt ist)
    # darf nicht fälschlich als "keine Funde" durchgewinkt werden.
    fake_result = subprocess.CompletedProcess(
        args=["semgrep"], returncode=1, stdout="", stderr="ImportError: ..."
    )
    monkeypatch.setattr(scanner_module, "_run_subprocess", lambda cmd, timeout: fake_result)

    with pytest.raises(RuntimeError, match="keine Ausgabe"):
        run_semgrep(tmp_path)


def test_run_semgrep_valid_empty_results_json_returns_no_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Ein regulärer, erfolgreicher Lauf ohne Funde liefert echtes JSON mit
    # leerer results-Liste - das ist der einzige Fall, der als "0 Funde"
    # gewertet werden darf.
    fake_result = subprocess.CompletedProcess(
        args=["semgrep"], returncode=0, stdout='{"results": [], "errors": []}', stderr=""
    )
    monkeypatch.setattr(scanner_module, "_run_subprocess", lambda cmd, timeout: fake_result)

    assert run_semgrep(tmp_path) == []


def test_parse_pip_audit_no_vulns_returns_empty() -> None:
    raw = {"dependencies": [{"name": "requests", "version": "2.31.0", "vulns": []}]}
    assert _parse_pip_audit(raw, Path("requirements.txt")) == []


# ---------------------------------------------------------------------------
# Integrationstests gegen das Beispielprojekt (brauchen die echten Tools)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("bandit") is None, reason="Bandit ist nicht installiert.")
def test_run_bandit_finds_known_issues() -> None:
    findings = run_bandit(SAMPLE_PROJECT)
    rule_ids = {f.rule_id for f in findings}

    # Mindestens die SQL-Injection (B608) muss gefunden werden.
    assert "B608" in rule_ids
    assert all(f.tool == ToolName.BANDIT for f in findings)


@pytest.mark.skipif(shutil.which("pip-audit") is None, reason="pip-audit ist nicht installiert.")
def test_run_pip_audit_finds_known_vulnerable_dependency() -> None:
    findings = run_pip_audit(SAMPLE_PROJECT)
    packages = {f.package for f in findings}
    assert "flask" in packages  # requirements.txt pinnt eine alte, verwundbare Flask-Version


def test_run_pip_audit_skips_when_no_requirements_file(tmp_path: Path) -> None:
    findings = run_pip_audit(tmp_path)
    assert findings == []


def test_run_all_scanners_never_raises_and_reports_tool_errors(tmp_path: Path) -> None:
    # Auch bei einem leeren, "sauberen" Zielverzeichnis darf der Aggregator
    # nicht crashen - er muss ein gültiges ScanResult liefern.
    result = run_all_scanners(tmp_path)
    assert isinstance(result.errors, dict)
    assert isinstance(result.findings, list)
