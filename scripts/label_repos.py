"""Baut den Trainingsdatensatz für das Pre-Filter-Modell (Variante B).

Ablauf:
1. Prüft vorab, ob ANTHROPIC_API_KEY gesetzt ist und alle Repositories
   vorhanden sind (sonst Abbruch mit Hinweis, bevor etwas gescannt wird).
2. Scannt jedes konfigurierte Repository mit allen drei Scanner-Tools
   (Bandit, pip-audit, Semgrep mit `p/security-audit`).
3. Lässt jeden Fund vom Triage-Agenten bewerten, mit deaktiviertem
   Consensus-Check (spart die Hälfte der API-Calls bei Funden mit
   niedriger Konfidenz - für einen Trainingsdatensatz vertretbar, im
   echten Scan-Betrieb bleibt der Consensus-Check an).
4. Schreibt pro Fund eine Zeile in eine JSONL-Datei: die Rohmerkmale
   des Finding plus das Label des Triage-Agenten (is_true_positive).

Wichtig: Die Labels stammen vom LLM, nicht von Menschen. Das Modell,
das später auf diesem Datensatz trainiert wird, destilliert also das
Urteil des Triage-Agenten - es lernt nicht unabhängig "echte"
Schwachstellen zu erkennen. Diese Einschränkung wird in der
Projekt-Dokumentation offen benannt.

Voraussetzungen:
- `ANTHROPIC_API_KEY` in `.env` (die Labels kosten echte API-Aufrufe).
- Die fünf externen Repositories liegen als Ordner in einem gemeinsamen
  Verzeichnis. Standard: `eval_repos/` neben dem Projektordner (also
  außerhalb dieses Repositories). Anderer Ort: Umgebungsvariable
  `VULNSCOUT_EVAL_REPOS`. Klon-Befehle gibt das Skript aus, wenn Ordner
  fehlen (`REPO_SOURCES` unten). Die geklonten Commits sind nicht
  festgehalten: ein neu geklonter Stand kann vom Stand des mitgelieferten
  Datensatzes abweichen.
- Netzwerkzugriff für Semgrep (`p/security-audit` wird aus der
  Semgrep-Registry geladen).

Hinweis zum mitgelieferten Datensatz: Er entstand in einer Umgebung ohne
Zugriff auf die Semgrep-Registry, Semgrep lief dort mit einem lokal
geklonten Regelsatz. Die Semgrep-Regelkennungen im Datensatz stimmen
deshalb nicht mit den Kennungen eines neuen Laufs überein.

Nutzung (aus dem Projektordner):
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

from src.prefilter.features import finding_to_features
from src.scanner_agent.scanner import run_all_scanners
from src.triage_agent.triage import triage_findings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Umgebungsvariable für den Ordner mit den externen Repositories.
EVAL_REPOS_ENV = "VULNSCOUT_EVAL_REPOS"

# Name im Datensatz -> (Ordnername unter dem Eval-Verzeichnis, Klon-URL).
# Geklont wurde mit `git clone --depth 1`. Das Repo-Label wird im
# Datensatz mitgeführt, damit der Train/Test-Split später repo-weise
# (nicht zeilenweise) passiert - sonst würden Zeilen desselben Repos auf
# beiden Seiten landen und die Evaluierung des Modells wäre zu
# optimistisch (Datenleckage).
REPO_SOURCES: dict[str, tuple[str, str]] = {
    "pygoat": ("pygoat", "https://github.com/adeyosemanputra/pygoat.git"),
    "dvpwa": ("dvpwa", "https://github.com/anxolerd/dvpwa.git"),
    "vulnerable_flask_app": (
        "Vulnerable-Flask-App",
        "https://github.com/we45/Vulnerable-Flask-App.git",
    ),
    "requests": ("requests", "https://github.com/psf/requests.git"),
    "click": ("click", "https://github.com/pallets/click.git"),
}

# Das eigene Dummy-Repo gehört zum Projekt und braucht keinen Klon.
DUMMY_REPO_NAME = "dummy_vuln_repo"
DUMMY_REPO_PATH = _PROJECT_ROOT / "test_repos" / "dummy_vuln_repo"

OUTPUT_PATH = _PROJECT_ROOT / "scripts" / "training_data.jsonl"

# Consensus-Check deaktivieren: ein negativer Schwellenwert wird von
# keiner Konfidenz (0-1) unterschritten.
DISABLE_CONSENSUS_THRESHOLD = -1.0


def default_eval_dir() -> Path:
    """Ordner mit den externen Repos: `VULNSCOUT_EVAL_REPOS` oder
    `eval_repos/` neben dem Projektordner."""
    configured = os.environ.get(EVAL_REPOS_ENV, "").strip()
    if configured:
        return Path(configured).expanduser()
    return _PROJECT_ROOT.parent / "eval_repos"


def resolve_repos(eval_dir: Path) -> dict[str, Path]:
    """Repo-Name -> Pfad für alle Repos des Datensatzes."""
    repos: dict[str, Path] = {DUMMY_REPO_NAME: DUMMY_REPO_PATH}
    for name, (folder, _url) in REPO_SOURCES.items():
        repos[name] = eval_dir / folder
    return repos


def missing_repos(repos: dict[str, Path]) -> list[str]:
    """Namen der Repos, deren Ordner nicht existiert."""
    return [name for name, path in repos.items() if not path.is_dir()]


def clone_commands(missing: list[str], eval_dir: Path) -> list[str]:
    """Klon-Befehle für die fehlenden externen Repos."""
    commands = []
    for name in missing:
        if name not in REPO_SOURCES:
            continue
        folder, url = REPO_SOURCES[name]
        commands.append(f'git clone --depth 1 {url} "{eval_dir / folder}"')
    return commands


def api_key_problem() -> str | None:
    """Fehlertext, falls kein API-Key gesetzt ist, sonst None.

    Ohne Key lässt sich der Client zwar erzeugen, der erste Aufruf
    scheitert aber mit einem Programmierfehler (TypeError), der bewusst
    nicht wiederholt wird - das Skript bräche erst nach dem ersten
    Scan ab.
    """
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return None
    return (
        "ANTHROPIC_API_KEY ist nicht gesetzt. Das Labeling braucht echte "
        "API-Aufrufe; Key in .env eintragen (Vorlage: .env.example)."
    )


def preflight(eval_dir: Path) -> list[str]:
    """Alle Voraussetzungen prüfen. Gibt die Fehlermeldungen zurück
    (leer = alles in Ordnung)."""
    problems: list[str] = []
    key_problem = api_key_problem()
    if key_problem:
        problems.append(key_problem)

    missing = missing_repos(resolve_repos(eval_dir))
    if missing:
        problems.append(
            f"Repositories fehlen unter {eval_dir}: {', '.join(missing)}. "
            f"Klonen mit:\n  "
            + "\n  ".join(clone_commands(missing, eval_dir))
            + f"\nOder Ordner über {EVAL_REPOS_ENV} angeben."
        )
    return problems


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


def main() -> int:
    eval_dir = default_eval_dir()
    problems = preflight(eval_dir)
    if problems:
        for problem in problems:
            logger.error(problem)
        return 1

    repos = resolve_repos(eval_dir)

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

    for repo_name, repo_path in repos.items():
        logger.info("Scanne %s (%s) ...", repo_name, repo_path)
        scan_result = run_all_scanners(repo_path)
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
