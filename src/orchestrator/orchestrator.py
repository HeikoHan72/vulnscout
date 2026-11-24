"""Verbindet Scanner-, Triage- und Report-Agent zu einem vollständigen
Durchlauf und persistiert den Zwischenstand nach jedem Schritt.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import anthropic

from src.demo.fixtures import fixture_report, fixture_triage
from src.enrichment.osv import enrich_findings
from src.monitoring.record import record_run
from src.prefilter.prefilter import apply_prefilter
from src.report_agent.report import build_report_context, generate_report
from src.scanner_agent.scanner import run_all_scanners
from src.tracking.mlflow_tracking import log_run
from src.triage_agent.triage import triage_findings

from .models import RunStatus, ScanRun
from .storage import RunStore

DEFAULT_DB_PATH = "vulnscout.db"

logger = logging.getLogger(__name__)


def run_pipeline(
    repo_path: str,
    db_path: str = DEFAULT_DB_PATH,
    client: Optional[anthropic.Anthropic] = None,
    semgrep_config: str = "p/security-audit",
    demo_mode: Optional[bool] = None,
) -> ScanRun:
    """Führt einen vollständigen VulnScout-Lauf für `repo_path` aus.

    Der Lauf wird nach jedem Schritt (Scan, Triage, Report) in der
    SQLite-Datenbank unter `db_path` aktualisiert. Schlägt ein Schritt
    fehl, wird der Lauf als FAILED markiert (mit Fehlertext) und die
    Ausnahme erneut geworfen — bereits gespeicherte Findings/
    Bewertungen aus vorherigen Schritten bleiben dabei erhalten.

    Args:
        repo_path: Pfad des zu scannenden Repositories.
        db_path: Pfad der SQLite-Datenbankdatei.
        client: Optionaler `anthropic.Anthropic`-Client (für Tests
            durch ein Mock ersetzbar). Wird `None` übergeben, legt
            `triage_findings`/`generate_report` jeweils selbst einen
            Standard-Client an.
        semgrep_config: Semgrep-Regelwerk, das an `run_all_scanners`
            durchgereicht wird.
        demo_mode: Erzwingt den Demo-/Fixture-Modus (`True`) oder den
            echten LLM-Modus (`False`), ohne LLM-Aufruf bzw. mit
            LLM-Aufruf für Triage und Report. Bei `None` (Standard)
            wird automatisch anhand von `ANTHROPIC_API_KEY`
            entschieden: ist die Umgebungsvariable leer/nicht gesetzt,
            läuft die Pipeline im Demo-Modus, damit das Projekt auch
            ohne eigenen API-Key lauffähig ist.

    Returns:
        Den fertigen `ScanRun` (Status COMPLETED oder FAILED).
    """
    if demo_mode is None:
        demo_mode = not bool(os.environ.get("ANTHROPIC_API_KEY"))

    store = RunStore(db_path)
    run = ScanRun(repo_path=repo_path, status=RunStatus.SCANNING)
    store.create_run(run)
    start_time = time.monotonic()
    findings: list = []
    assessments: list = []

    try:
        scan_result = run_all_scanners(repo_path, semgrep_config=semgrep_config)
        # Schweregrad für Abhängigkeits-Funde aus OSV nachtragen (best effort,
        # wirft nie; siehe src/enrichment/osv.py). Vor dem Speichern, damit
        # die angereicherten Felder mit in der Datenbank landen.
        enrich_findings(scan_result.findings)
        findings = scan_result.findings
        store.save_findings(run.id, scan_result.findings)
        run.scanner_errors = scan_result.errors
        run.status = RunStatus.TRIAGING
        run.updated_at = datetime.now(timezone.utc)
        store.update_run(run)

        if demo_mode:
            assessments = fixture_triage(scan_result.findings)
        else:
            # Pre-Filter zuerst: eindeutige Fälle werden ohne LLM-Aufruf
            # entschieden (siehe src/prefilter/prefilter.py), der Rest geht
            # wie bisher an die LLM-Triage. Ist kein Pre-Filter-Modell
            # registriert, kommen hier einfach alle Funde zurück - Verhalten
            # bleibt dann unverändert zum Stand vor Variante B.
            findings_for_llm, prefilter_assessments = apply_prefilter(scan_result.findings)
            llm_assessments = (
                triage_findings(findings_for_llm, client=client) if findings_for_llm else []
            )
            assessments = prefilter_assessments + llm_assessments
        store.save_assessments(run.id, assessments)
        run.status = RunStatus.REPORTING
        run.updated_at = datetime.now(timezone.utc)
        store.update_run(run)

        repo_name = repo_path.rstrip("/").split("/")[-1]
        if demo_mode:
            context = build_report_context(
                scan_result.findings,
                assessments,
                repo_name,
                scanner_errors=scan_result.errors,
            )
            report_markdown = fixture_report(context)
        else:
            report_markdown = generate_report(
                scan_result.findings,
                assessments,
                repo_name,
                scanner_errors=scan_result.errors,
                client=client,
            )
        run.report_markdown = report_markdown
        run.status = RunStatus.COMPLETED
        run.updated_at = datetime.now(timezone.utc)
        store.update_run(run)

    except Exception as exc:  # noqa: BLE001 - bewusst breit, siehe Docstring
        run.status = RunStatus.FAILED
        run.error_message = str(exc)
        run.updated_at = datetime.now(timezone.utc)
        store.update_run(run)
        logger.exception("VulnScout-Lauf %s fehlgeschlagen", run.id)
        duration = time.monotonic() - start_time
        log_run(run, assessments, duration_seconds=duration)
        record_run(
            run,
            findings=findings,
            assessments=assessments,
            duration_seconds=duration,
            demo_mode=demo_mode,
        )
        raise

    duration = time.monotonic() - start_time
    log_run(run, assessments, duration_seconds=duration)
    record_run(
        run,
        findings=findings,
        assessments=assessments,
        duration_seconds=duration,
        demo_mode=demo_mode,
    )
    return run
