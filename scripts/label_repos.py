"""Baut den Trainingsdatensatz für das Pre-Filter-Modell (Variante B).

Ablauf:
1. Scannt jedes konfigurierte Repository mit allen drei Scanner-Tools
   (Bandit, pip-audit, Semgrep).
2. Lässt jeden Fund vom Triage-Agenten bewerten, mit deaktiviertem
   Consensus-Check (spart die Hälfte der API-Calls bei Funden mit
   niedriger Konfidenz - für einen Trainingsdatensatz ist das
   vertretbar, im echten Scan-Betrieb bleibt der Consensus-Check an).
3. Schreibt pro Fund eine Zeile in eine JSONL-Datei: die Rohmerkmale
   des Finding plus das Label des Triage-Agenten (is_true_positive).

Wichtig: Die Labels stammen vom LLM, nicht von Menschen. Das Modell,
das später auf diesem Datensatz trainiert wird, destilliert also das
Urteil des Triage-Agenten - es lernt nicht unabhängig "echte"
Schwachstellen zu erkennen. Diese Einschränkung wird in der
Projekt-Dokumentation offen benannt.

Nutzung:
    python -m scripts.label_repos
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Sandbox-Workaround: die in diesem Sandbox-Image installierte semgrep-Version
# kollidiert mit einer von FastAPI benötigten neueren opentelemetry-Version
# (ImportError beim Start). Betrifft nur diese Entwicklungsumgebung, nicht das
# Docker-Image des Projekts (dort sind die Versionen über requirements.txt
# fest gepinnt und kollisionsfrei). Lösung hier: eine isolierte venv mit
# kompatiblem semgrep, deren bin-Verzeichnis vor den Rest von PATH gesetzt
# wird, damit der Unterprozess-Aufruf "semgrep" diese Version findet.
_SEMGREP_VENV_BIN = "/tmp/semgrep_venv/bin"
if os.path.isdir(_SEMGREP_VENV_BIN):
    os.environ["PATH"] = _SEMGREP_VENV_BIN + os.pathsep + os.environ.get("PATH", "")

# Zweiter Sandbox-Workaround: semgrep.dev (Registry für "p/security-audit")
# ist für diese Entwicklungsumgebung gesperrt. Fallback auf ein lokal
# geklontes Regelwerk (semgrep/semgrep-rules von GitHub, nur die
# "security"-Unterordner je Python-Framework + generic/secrets) - das
# Scanner-Modul sieht genau diesen Fall vor ("für einen Lauf ganz ohne
# Netzwerk kann hier der Pfad zu einer eigenen Regel-Datei übergeben
# werden", siehe run_semgrep-Docstring). Im Docker-Image des Projekts
# bleibt "p/security-audit" der Standard, dort funktioniert der
# Registry-Zugriff.
_LOCAL_SEMGREP_CONFIG = "/home/claude/semgrep_security_rules"

from src.prefilter.features import finding_to_features
from src.scanner_agent.scanner import run_all_scanners
from src.triage_agent.triage import triage_findings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Repo-Name -> Pfad. Das Repo-Label wird im Datensatz mitgeführt, damit
# der Train/Test-Split später repo-weise (nicht zeilenweise) passiert -
# sonst würden Zeilen desselben Repos auf beiden Seiten landen und die
# Evaluierung des Modells wäre zu optimistisch (Datenleckage).
REPOS: dict[str, Path] = {
    "dummy_vuln_repo": Path("test_repos/dummy_vuln_repo"),
    "pygoat": Path("/home/claude/eval_repos/pygoat"),
    "dvpwa": Path("/home/claude/eval_repos/dvpwa"),
    "vulnerable_flask_app": Path("/home/claude/eval_repos/Vulnerable-Flask-App"),
    "requests": Path("/home/claude/eval_repos/requests"),
    "click": Path("/home/claude/eval_repos/click"),
}

OUTPUT_PATH = Path("scripts/training_data.jsonl")

# Consensus-Check deaktivieren: ein negativer Schwellenwert wird von
# keiner Konfidenz (0-1) unterschritten.
DISABLE_CONSENSUS_THRESHOLD = -1.0


def _finding_to_record(finding, assessment, repo_name: str) -> dict:
    """Baut eine Trainings-Zeile aus Finding + Triage-Ergebnis.

    Die eigentlichen Modell-Merkmale kommen aus `finding_to_features()`
    (siehe `src/prefilter/features.py`) - derselben Funktion, die auch
    zur Laufzeit die Merkmale für die Inferenz baut. Hier kommen nur
    zusätzliche, rein informative Spalten (cwe, title) sowie das Label
    dazu.
    """

    record = dict(finding_to_features(finding))
    record.update(
        {
            "repo": repo_name,
            "finding_id": finding.id,
            "cwe": finding.cwe,
            "title": finding.title,
            # Label (vom LLM, nicht von Menschen - siehe Modul-Docstring)
            "label_is_true_positive": assessment.is_true_positive,
            "label_severity": assessment.severity.value,
            "label_confidence": assessment.confidence,
            "label_needs_review": assessment.needs_review,
        }
    )
    return record


# Findings je Repo werden in Chunks dieser Größe an triage_findings()
# übergeben, statt alle auf einmal. triage_findings() selbst liefert erst
# nach dem letzten Batch ein Ergebnis zurück - bei einem Repo mit >1000
# Funden wären das sonst ~60 Minuten ohne jede Zwischenspeicherung. Durch
# das Chunking wird nach jedem Chunk sofort auf die Festplatte geschrieben,
# sodass ein Abbruch (Zeitlimit, Absturz) höchstens die Arbeit des
# laufenden Chunks kostet, nicht den ganzen bisherigen Fortschritt.
CHUNK_SIZE = 100


def _write_records(records: list[dict]) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("a", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()


def main() -> None:
    # Fortsetzen statt neu starten: bereits erledigte Funde (nach
    # finding_id) werden übersprungen, falls das Skript nach einem
    # Abbruch erneut gestartet wird.
    already_done: set[str] = set()
    if OUTPUT_PATH.exists():
        with OUTPUT_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    already_done.add(json.loads(line)["finding_id"])
        logger.info("%d bereits erledigte Funde gefunden, werden übersprungen.", len(already_done))

    totals = {"findings": 0, "scan_errors": 0, "written": 0}

    for repo_name, repo_path in REPOS.items():
        if not repo_path.exists():
            logger.error("Repo-Pfad fehlt, übersprungen: %s (%s)", repo_name, repo_path)
            continue

        logger.info("Scanne %s (%s) ...", repo_name, repo_path)
        semgrep_config = (
            _LOCAL_SEMGREP_CONFIG if Path(_LOCAL_SEMGREP_CONFIG).is_dir() else "p/security-audit"
        )
        scan_result = run_all_scanners(repo_path, semgrep_config=semgrep_config)
        if scan_result.errors:
            logger.warning("Scanner-Fehler in %s: %s", repo_name, scan_result.errors)
            totals["scan_errors"] += len(scan_result.errors)

        findings = [f for f in scan_result.findings if f.id not in already_done]
        skipped = len(scan_result.findings) - len(findings)
        logger.info(
            "%s: %d Funde (%d bereits erledigt, übersprungen)",
            repo_name,
            len(findings),
            skipped,
        )
        totals["findings"] += len(scan_result.findings)

        for i in range(0, len(findings), CHUNK_SIZE):
            chunk = findings[i : i + CHUNK_SIZE]
            start = time.monotonic()
            assessments = triage_findings(
                chunk,
                confidence_threshold=DISABLE_CONSENSUS_THRESHOLD,
            )
            duration = time.monotonic() - start
            logger.info(
                "%s: Chunk %d-%d (%d Funde) in %.1fs bewertet",
                repo_name,
                i,
                i + len(chunk),
                len(chunk),
                duration,
            )

            assessments_by_id = {a.finding_id: a for a in assessments}
            chunk_records = []
            for finding in chunk:
                assessment = assessments_by_id.get(finding.id)
                if assessment is None:
                    logger.warning(
                        "Keine Bewertung für Fund %s (%s) - ausgelassen",
                        finding.id,
                        finding.rule_id,
                    )
                    continue
                chunk_records.append(_finding_to_record(finding, assessment, repo_name))

            _write_records(chunk_records)
            totals["written"] += len(chunk_records)
            logger.info("Zwischenstand: %d Zeilen insgesamt in %s", totals["written"], OUTPUT_PATH)

    logger.info(
        "Fertig: %d Zeilen in %s geschrieben (%d Funde insgesamt, %d Scanner-Fehler).",
        totals["written"],
        OUTPUT_PATH,
        totals["findings"],
        totals["scan_errors"],
    )


if __name__ == "__main__":
    sys.exit(main())
