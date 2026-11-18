"""Scanner-Agent: führt Bandit, pip-audit und Semgrep auf einem
Zielrepository aus und übersetzt deren Ausgabe in das einheitliche
`Finding`-Format.

Design-Entscheidungen (siehe Architektur-Planung):
- Jedes Tool läuft isoliert. Schlägt eines fehl (nicht installiert,
  Timeout, Parse-Fehler), bricht der Scan nicht komplett ab - der
  Fehler wird in `ScanResult.errors` vermerkt, die anderen Tools
  laufen trotzdem weiter.
- Kein LLM-Aufruf an dieser Stelle. Dieses Modul ist bewusst
  deterministisch und kostenlos testbar.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models import Finding, Severity, ToolName

logger = logging.getLogger(__name__)

# Timeout pro Tool-Lauf. Große Repos oder ein hängender Semgrep-Lauf
# sollen den gesamten Scan nicht blockieren (siehe Risikotabelle).
DEFAULT_TIMEOUT_SECONDS = 300

# Severity-Zuordnung der Einzel-Tools auf das einheitliche Format.
_BANDIT_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}
_SEMGREP_SEVERITY_MAP = {
    "INFO": Severity.LOW,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
}


class ScanResult(BaseModel):
    """Ergebnis eines vollständigen Scan-Laufs über alle Tools.

    Attributes:
        findings: Alle erfolgreich eingesammelten Funde, über alle
            Tools hinweg, bereits im einheitlichen Finding-Format.
        errors: Tool-Name -> Fehlermeldung, nur für Tools, die in
            diesem Lauf fehlgeschlagen sind (z. B. nicht installiert,
            Timeout). Ein leeres Dict heißt: alle Tools liefen durch.
    """

    findings: list[Finding] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


def _run_subprocess(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Führt ein Scanner-Kommando aus und gibt das Ergebnis zurück.

    Setzt zusätzlich Umgebungsvariablen, die Semgrep daran hindern,
    Telemetrie zu senden oder online nach einer neuen Version zu
    suchen - für Bandit und pip-audit wirkungslos, aber unschädlich.

    Wirft `FileNotFoundError`, wenn das Tool nicht installiert ist,
    und `subprocess.TimeoutExpired`, wenn das Zeitlimit überschritten
    wird. Beide Fälle werden von den aufrufenden `run_*`-Funktionen
    behandelt.
    """
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    logger.debug("Führe Kommando aus: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


def run_bandit(target_dir: Path, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> list[Finding]:
    """Scannt `target_dir` mit Bandit und gibt Findings zurück.

    Bandit meldet Exit-Code 1, wenn Funde vorliegen - das ist kein
    Fehler. Exit-Code >= 2 bedeutet, dass Bandit selbst nicht korrekt
    laufen konnte (z. B. ungültige Konfiguration).
    """
    cmd = ["bandit", "-r", str(target_dir), "-f", "json", "-q"]
    result = _run_subprocess(cmd, timeout)

    if result.returncode not in (0, 1):
        raise RuntimeError(f"Bandit-Fehler (Exit {result.returncode}): {result.stderr.strip()}")

    if not result.stdout.strip():
        return []

    data = json.loads(result.stdout)
    return _parse_bandit(data, target_dir)


def _parse_bandit(data: dict[str, Any], target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []):
        raw_severity = item.get("issue_severity", "")
        cwe = None
        cwe_info = item.get("issue_cwe")
        if isinstance(cwe_info, dict) and cwe_info.get("id") is not None:
            cwe = f"CWE-{cwe_info['id']}"

        file_path = item.get("filename", "")
        try:
            file_path = str(Path(file_path).relative_to(target_dir))
        except ValueError:
            pass  # Pfad war schon relativ oder liegt außerhalb - unverändert übernehmen.

        findings.append(
            Finding(
                tool=ToolName.BANDIT,
                rule_id=item.get("test_id", "UNKNOWN"),
                severity=_BANDIT_SEVERITY_MAP.get(raw_severity, Severity.UNKNOWN),
                raw_severity=raw_severity,
                confidence=item.get("issue_confidence"),
                file_path=file_path,
                line_start=item.get("line_number"),
                line_end=item.get("line_range", [None])[-1] if item.get("line_range") else item.get("line_number"),
                code_snippet=item.get("code"),
                title=item.get("test_name", "Bandit-Fund"),
                description=item.get("issue_text"),
                cwe=cwe,
                raw=item,
            )
        )
    return findings


def run_semgrep(target_dir: Path, config: str = "p/security-audit", timeout: int = DEFAULT_TIMEOUT_SECONDS) -> list[Finding]:
    """Scannt `target_dir` mit Semgrep und gibt Findings zurück.

    `config` ist das Semgrep-Regelwerk. "p/security-audit" lädt ein
    Registry-Ruleset und braucht beim ersten Lauf Internetzugang;
    für einen Lauf ganz ohne Netzwerk kann hier der Pfad zu einer
    eigenen Regel-Datei übergeben werden.
    """
    cmd = ["semgrep", "scan", "--config", config, "--json", "--quiet", "--metrics=off", str(target_dir)]
    result = _run_subprocess(cmd, timeout)

    if result.returncode not in (0, 1):
        raise RuntimeError(f"Semgrep-Fehler (Exit {result.returncode}): {result.stderr.strip()[:500]}")

    if not result.stdout.strip():
        # Ein regulärer Lauf ohne Funde liefert trotzdem ein gültiges JSON-Objekt
        # (z. B. {"results": [], ...}) - leere Ausgabe auf stdout bedeutet, dass
        # Semgrep vor der Ausgabe abgestürzt ist (z. B. defekte Installation),
        # nicht "keine Funde". Das muss als Fehler erkannt werden, sonst würde
        # ein stiller Tool-Ausfall fälschlich als saubere Codebasis gewertet.
        stderr_excerpt = result.stderr.strip()[:500]
        raise RuntimeError(
            f"Semgrep lieferte keine Ausgabe (Exit {result.returncode}) - "
            f"vermutlich abgestürzt statt regulär beendet: {stderr_excerpt or '(keine stderr-Ausgabe)'}"
        )

    data = json.loads(result.stdout)
    return _parse_semgrep(data, target_dir)


def _parse_semgrep(data: dict[str, Any], target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        raw_severity = extra.get("severity", "")
        metadata = extra.get("metadata", {})

        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(cwe)

        file_path = item.get("path", "")
        try:
            file_path = str(Path(file_path).relative_to(target_dir))
        except ValueError:
            pass

        start = item.get("start", {})
        end = item.get("end", {})

        findings.append(
            Finding(
                tool=ToolName.SEMGREP,
                rule_id=item.get("check_id", "UNKNOWN"),
                severity=_SEMGREP_SEVERITY_MAP.get(raw_severity, Severity.UNKNOWN),
                raw_severity=raw_severity,
                file_path=file_path,
                line_start=start.get("line"),
                line_end=end.get("line"),
                code_snippet=extra.get("lines"),
                title=metadata.get("shortDescription") or item.get("check_id", "Semgrep-Fund"),
                description=extra.get("message"),
                cwe=cwe,
                raw=item,
            )
        )
    return findings


def run_pip_audit(target_dir: Path, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> list[Finding]:
    """Prüft `target_dir/requirements.txt` mit pip-audit auf bekannte
    Schwachstellen in den Abhängigkeiten.

    Gibt eine leere Liste zurück (kein Fehler), wenn keine
    requirements.txt existiert - das ist ein gültiger Zustand, kein
    Scan-Fehler.
    """
    requirements_file = target_dir / "requirements.txt"
    if not requirements_file.exists():
        logger.info("Keine requirements.txt in %s gefunden, pip-audit wird übersprungen.", target_dir)
        return []

    cmd = ["pip-audit", "-r", str(requirements_file), "--format", "json"]
    result = _run_subprocess(cmd, timeout)

    if result.returncode not in (0, 1):
        raise RuntimeError(f"pip-audit-Fehler (Exit {result.returncode}): {result.stderr.strip()[:500]}")

    if not result.stdout.strip():
        return []

    data = json.loads(result.stdout)
    return _parse_pip_audit(data, requirements_file)


def _parse_pip_audit(data: Any, requirements_file: Path) -> list[Finding]:
    # pip-audit liefert je nach Version entweder {"dependencies": [...]}
    # oder direkt eine Liste von Dependencies - beide Formen abfangen.
    deps = data.get("dependencies", data) if isinstance(data, dict) else data

    findings: list[Finding] = []
    for dep in deps:
        name = dep.get("name", "unbekanntes Paket")
        version = dep.get("version", "")
        for vuln in dep.get("vulns", []):
            findings.append(
                Finding(
                    tool=ToolName.PIP_AUDIT,
                    rule_id=vuln.get("id", "UNKNOWN"),
                    # pip-audit liefert keinen eigenen Schweregrad -
                    # das übernimmt später der Triage-Agent anhand der
                    # Vulnerability-ID.
                    severity=Severity.UNKNOWN,
                    file_path=str(requirements_file.name),
                    title=f"Bekannte Schwachstelle in {name} {version}: {vuln.get('id', '')}",
                    description=vuln.get("description"),
                    package=name,
                    installed_version=version,
                    fix_versions=vuln.get("fix_versions", []),
                    raw=vuln,
                )
            )
    return findings


def run_all_scanners(target_dir: Path, semgrep_config: str = "p/security-audit") -> ScanResult:
    """Führt alle drei Scanner nacheinander aus und sammelt die
    Ergebnisse in einem `ScanResult`.

    Ein fehlschlagendes Tool beendet nicht den gesamten Scan - der
    Fehler wird vermerkt, die übrigen Tools laufen weiter.
    """
    target_dir = Path(target_dir).resolve()
    result = ScanResult()

    scanners = {
        ToolName.BANDIT.value: lambda: run_bandit(target_dir),
        ToolName.PIP_AUDIT.value: lambda: run_pip_audit(target_dir),
        ToolName.SEMGREP.value: lambda: run_semgrep(target_dir, config=semgrep_config),
    }

    for tool_name, scan_fn in scanners.items():
        try:
            findings = scan_fn()
            logger.info("%s: %d Fund(e)", tool_name, len(findings))
            result.findings.extend(findings)
        except FileNotFoundError:
            result.errors[tool_name] = "Tool nicht installiert oder nicht im PATH."
        except subprocess.TimeoutExpired:
            result.errors[tool_name] = f"Zeitlimit überschritten (>{DEFAULT_TIMEOUT_SECONDS}s)."
        except json.JSONDecodeError as exc:
            result.errors[tool_name] = f"Ausgabe konnte nicht als JSON gelesen werden: {exc}"
        except RuntimeError as exc:
            result.errors[tool_name] = str(exc)

    return result


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if len(sys.argv) != 2:
        print("Aufruf: python -m src.scanner_agent.scanner <pfad-zum-zielrepo>")
        sys.exit(1)

    scan_result = run_all_scanners(Path(sys.argv[1]))
    print(f"\n{len(scan_result.findings)} Fund(e) insgesamt.")
    for tool, error in scan_result.errors.items():
        print(f"  Fehler bei {tool}: {error}")
    print(json.dumps([f.model_dump() for f in scan_result.findings], indent=2, ensure_ascii=False))
