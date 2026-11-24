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

import copy
import shutil
import subprocess
from pathlib import Path

import pytest

import src.scanner_agent.scanner as scanner_module
from src.scanner_agent.models import Finding, Severity, ToolName
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


# --- pip-audit: leere Ausgabe ist ein Ausfall, kein sauberes Ergebnis --------
#
# Hintergrund: pip-audit baut intern ein temporäres venv und braucht dafür
# Zugriff auf den Paketindex. Ohne Netz (oder wenn Proxy-Variablen fehlen)
# scheitert es mit Exit 1 und leerer Ausgabe. Früher wurde das als "keine
# Schwachstellen" gewertet - ein stiller falscher Befund. Ein regulärer Lauf
# gibt dagegen immer JSON aus, auch ohne Funde.


def _fake_pip_audit(monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, stderr: str) -> None:
    fake_result = subprocess.CompletedProcess(
        args=["pip-audit"], returncode=returncode, stdout=stdout, stderr=stderr
    )
    monkeypatch.setattr(scanner_module, "_run_subprocess", lambda cmd, timeout: fake_result)


def _project_with_requirements(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("flask==0.12\n", encoding="utf-8")
    return tmp_path


def test_run_pip_audit_empty_stdout_exit_1_is_an_error_not_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_pip_audit(monkeypatch, 1, "", "ERROR:pip_audit._cli:Failed to upgrade `pip`")

    with pytest.raises(RuntimeError, match="keine Ausgabe") as excinfo:
        run_pip_audit(_project_with_requirements(tmp_path))
    assert "Failed to upgrade" in str(excinfo.value)  # Ursache bleibt sichtbar


def test_run_pip_audit_empty_stdout_exit_0_is_also_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_pip_audit(monkeypatch, 0, "   \n", "")

    with pytest.raises(RuntimeError, match="keine Ausgabe"):
        run_pip_audit(_project_with_requirements(tmp_path))


def test_run_pip_audit_valid_json_without_vulnerabilities_returns_no_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Der einzige Fall, der als "0 Funde" gelten darf: gültiges JSON ohne Funde.
    _fake_pip_audit(monkeypatch, 0, '{"dependencies": [], "fixes": []}', "No known vulnerabilities found")

    assert run_pip_audit(_project_with_requirements(tmp_path)) == []


def test_run_pip_audit_exit_1_with_json_still_returns_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exit 1 mit Funden ist der Normalfall und darf nicht als Fehler gelten.
    raw = (
        '{"dependencies": [{"name": "flask", "version": "0.12", "vulns": '
        '[{"id": "PYSEC-2019-179", "fix_versions": ["1.0"], "description": "x"}]}]}'
    )
    _fake_pip_audit(monkeypatch, 1, raw, "Found 1 known vulnerability")

    findings = run_pip_audit(_project_with_requirements(tmp_path))
    assert [f.package for f in findings] == ["flask"]


def test_run_all_scanners_records_pip_audit_outage_and_keeps_other_scanners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Der Ausfall muss im ScanResult als Fehler stehen (und damit im Bericht
    # und in der Metrik landen), die übrigen Scanner laufen weiter.
    _project_with_requirements(tmp_path)
    monkeypatch.setattr(scanner_module, "run_bandit", lambda target_dir: [])
    monkeypatch.setattr(scanner_module, "run_semgrep", lambda target_dir, config="": [])
    _fake_pip_audit(monkeypatch, 1, "", "ERROR: kein Netz")

    result = run_all_scanners(tmp_path)

    assert ToolName.PIP_AUDIT.value in result.errors
    assert "keine Ausgabe" in result.errors[ToolName.PIP_AUDIT.value]
    assert ToolName.BANDIT.value not in result.errors
    assert ToolName.SEMGREP.value not in result.errors


# --- pip-audit: doppelte Einträge derselben Schwachstelle -------------------


def _dup_raw(*vulns: dict, name: str = "flask", version: str = "0.12") -> dict:
    return {"dependencies": [{"name": name, "version": version, "vulns": list(vulns)}]}


def test_parse_pip_audit_merges_duplicate_entries_of_same_vulnerability() -> None:
    raw = _dup_raw(
        {"id": "PYSEC-2019-179", "fix_versions": ["1.0"], "description": "A"},
        {"id": "PYSEC-2019-179", "fix_versions": ["1.0"], "description": "B"},
    )
    findings = _parse_pip_audit(raw, Path("requirements.txt"))
    assert len(findings) == 1
    assert findings[0].rule_id == "PYSEC-2019-179"


def test_parse_pip_audit_merge_unites_fix_versions_in_order_of_appearance() -> None:
    raw = _dup_raw(
        {"id": "PYSEC-2020-176", "fix_versions": ["5.2b1"]},
        {"id": "PYSEC-2020-176", "fix_versions": ["5.2", "5.2b1"]},
        name="pyyaml",
        version="5.1",
    )
    findings = _parse_pip_audit(raw, Path("requirements.txt"))
    assert len(findings) == 1
    assert findings[0].fix_versions == ["5.2b1", "5.2"]


def test_parse_pip_audit_merge_keeps_the_more_detailed_description() -> None:
    short = "Kurz."
    long = "Deutlich ausführlichere Beschreibung der Schwachstelle."
    for first, second in ((short, long), (long, short)):
        raw = _dup_raw(
            {"id": "X-1", "description": first},
            {"id": "X-1", "description": second},
        )
        assert _parse_pip_audit(raw, Path("requirements.txt"))[0].description == long


def test_parse_pip_audit_merge_keeps_description_when_duplicate_has_none() -> None:
    raw = _dup_raw({"id": "X-1", "description": "Vorhanden"}, {"id": "X-1"})
    assert _parse_pip_audit(raw, Path("requirements.txt"))[0].description == "Vorhanden"


def test_parse_pip_audit_merge_preserves_raw_of_the_duplicate() -> None:
    first = {"id": "X-1", "aliases": ["CVE-1"]}
    second = {"id": "X-1", "aliases": ["CVE-1", "GHSA-1"]}
    finding = _parse_pip_audit(_dup_raw(first, second), Path("requirements.txt"))[0]
    assert finding.raw["aliases"] == ["CVE-1"]
    assert finding.raw["merged_entries"] == [second]


def test_parse_pip_audit_does_not_mutate_its_input() -> None:
    raw = _dup_raw(
        {"id": "X-1", "fix_versions": ["1"]},
        {"id": "X-1", "fix_versions": ["2"]},
    )
    snapshot = copy.deepcopy(raw)
    _parse_pip_audit(raw, Path("requirements.txt"))
    assert raw == snapshot


def test_parse_pip_audit_same_id_in_different_package_or_version_is_not_merged() -> None:
    raw = {
        "dependencies": [
            {"name": "flask", "version": "0.12", "vulns": [{"id": "X-1"}]},
            {"name": "flask", "version": "1.0", "vulns": [{"id": "X-1"}]},
            {"name": "werkzeug", "version": "0.12", "vulns": [{"id": "X-1"}]},
        ]
    }
    assert len(_parse_pip_audit(raw, Path("requirements.txt"))) == 3


def test_parse_pip_audit_different_ids_of_one_package_are_not_merged() -> None:
    raw = _dup_raw({"id": "X-1"}, {"id": "X-2"})
    findings = _parse_pip_audit(raw, Path("requirements.txt"))
    assert [f.rule_id for f in findings] == ["X-1", "X-2"]


def test_parse_pip_audit_entries_without_id_are_never_merged() -> None:
    raw = _dup_raw({"fix_versions": ["1"]}, {"fix_versions": ["1"]})
    findings = _parse_pip_audit(raw, Path("requirements.txt"))
    assert len(findings) == 2
    assert all(f.rule_id == "UNKNOWN" for f in findings)


def test_parse_pip_audit_merges_duplicates_across_repeated_dependency_blocks() -> None:
    # Dasselbe Paket kann als zwei Blöcke in der Ausgabe stehen.
    raw = {
        "dependencies": [
            {"name": "urllib3", "version": "1.24", "vulns": [{"id": "X-1"}]},
            {"name": "urllib3", "version": "1.24", "vulns": [{"id": "X-1"}, {"id": "X-2"}]},
        ]
    }
    findings = _parse_pip_audit(raw, Path("requirements.txt"))
    assert [f.rule_id for f in findings] == ["X-1", "X-2"]


def test_parse_pip_audit_every_vulnerability_doubled_yields_unique_count() -> None:
    # Nachbildung des beobachteten Musters: 25 Schwachstellen je zweimal, eine einmal.
    vulns = [{"id": f"V-{i}"} for i in range(25)] * 2 + [{"id": "V-single"}]
    findings = _parse_pip_audit(_dup_raw(*vulns), Path("requirements.txt"))
    assert len(findings) == 26


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


# --- Nachgefüllte Code-Ausschnitte -------------------------------------------
#
# Hintergrund: Semgrep liefert für Registry-Regeln statt des gefundenen
# Codes den Text "requires login". In einem echten Lauf betraf das alle
# 15 Semgrep-Funde - die Triage musste also ohne Code entscheiden. Da
# Datei und Zeile bekannt sind und das Repo lokal vorliegt, lesen wir den
# Ausschnitt selbst.


def _snippet_finding(
    code_snippet: str | None,
    file_path: str = "app.py",
    line_start: int | None = 19,
) -> Finding:
    return Finding(
        tool=ToolName.SEMGREP,
        rule_id="r",
        severity=Severity.HIGH,
        file_path=file_path,
        line_start=line_start,
        code_snippet=code_snippet,
        title="t",
        description="d",
    )


def _repo_mit_datei(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "\n".join(f"zeile {n}" for n in range(1, 11)) + "\n", encoding="utf-8"
    )
    return tmp_path


def test_platzhalter_wird_durch_echten_code_ersetzt(tmp_path: Path) -> None:
    finding = _snippet_finding("requires login", line_start=5)
    scanner_module._ergaenze_code_ausschnitte([finding], _repo_mit_datei(tmp_path))

    assert finding.code_snippet is not None
    assert "requires login" not in finding.code_snippet
    assert "zeile 5" in finding.code_snippet
    # Kontextzeilen davor und danach sind enthalten.
    assert "zeile 3" in finding.code_snippet
    assert "zeile 7" in finding.code_snippet


def test_leerer_ausschnitt_wird_gefuellt(tmp_path: Path) -> None:
    finding = _snippet_finding(None, line_start=1)
    scanner_module._ergaenze_code_ausschnitte([finding], _repo_mit_datei(tmp_path))
    assert finding.code_snippet is not None
    assert "zeile 1" in finding.code_snippet


def test_vorhandener_code_bleibt_unveraendert(tmp_path: Path) -> None:
    finding = _snippet_finding("18    schon vorhanden")
    scanner_module._ergaenze_code_ausschnitte([finding], _repo_mit_datei(tmp_path))
    assert finding.code_snippet == "18    schon vorhanden"


def test_fund_ohne_zeilennummer_bleibt_unberuehrt(tmp_path: Path) -> None:
    """pip-audit meldet Pakete, keine Codestellen."""
    finding = _snippet_finding(None, file_path="requirements.txt", line_start=None)
    scanner_module._ergaenze_code_ausschnitte([finding], _repo_mit_datei(tmp_path))
    assert finding.code_snippet is None


def test_fehlende_datei_laesst_fund_unveraendert(tmp_path: Path) -> None:
    """Best-effort: Ein nicht lesbarer Pfad darf den Scan nicht kippen."""
    finding = _snippet_finding("requires login", file_path="gibtsnicht.py")
    scanner_module._ergaenze_code_ausschnitte([finding], tmp_path)
    assert finding.code_snippet == "requires login"
