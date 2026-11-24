"""FastAPI-Anwendung für VulnScout.

Startet Scans über den Orchestrator und liefert Status/Bericht
abgeschlossener Läufe zurück. Läuft die API ohne gültigen
`ANTHROPIC_API_KEY`, schlägt der Lauf in der Triage-Phase fehl – der
Scan-Schritt selbst (Bandit/pip-audit/Semgrep) funktioniert davon
unabhängig.

Bewusst einfach gehalten: ein Scan läuft synchron innerhalb eines
Requests (kein Background-Queue). Für die im Rahmen dieses Projekts
vorgesehene Repo-Größe (Demo-/Testrepos) ist das ausreichend; siehe
Stand-Dokument, Offene Punkte, für mögliche Erweiterungen.
"""

from __future__ import annotations

import os
import time

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from src.api.models import ScanRequest
from src.api.security import resolve_repo_path, validate_semgrep_config
from src.monitoring import metrics as m
from src.orchestrator.models import ScanRun
from src.orchestrator.orchestrator import run_pipeline
from src.orchestrator.storage import RunStore

# Lädt eine vorhandene .env-Datei, damit ANTHROPIC_API_KEY auch beim lokalen
# Start (z. B. `uvicorn src.api.main:app`) gefunden wird. Ohne diesen Aufruf
# würde die API lokal trotz eingetragenem Key in den Demo-Modus schalten und
# ein Demo-Ergebnis liefern, das wie ein echter Lauf aussieht. Im Container
# ist das unkritisch, weil Docker Compose die .env selbst einliest -
# `load_dotenv` überschreibt bereits gesetzte Variablen nicht, dort gewinnt
# also weiterhin die Container-Umgebung.
load_dotenv()

DB_PATH = os.environ.get("VULNSCOUT_DB_PATH", "vulnscout.db")

app = FastAPI(
    title="VulnScout API",
    description=(
        "Scannt Code-Repositories auf Schwachstellen (Bandit, pip-audit, "
        "Semgrep), bewertet die Funde per LLM (Triage mit Consensus-Check) "
        "und erstellt einen Bericht mit konkreten Fix-Vorschlägen."
    ),
    version="0.1.0",
)


@app.middleware("http")
async def measure(request: Request, call_next):
    """Misst bei jeder Anfrage Dauer und Ausgang.

    Das sind die goldenen Signale: Verkehr (wie viele Anfragen), Fehler
    (welcher Status) und Latenz (wie lange).

    Als Label wird die Routen-Vorlage benutzt (z. B. `/scans/{run_id}`),
    nicht der konkrete Pfad. Sonst entstünde für jede einzelne Lauf-ID
    eine eigene Zeitreihe, und die Zahl der Zeitreihen würde mit jedem
    Scan wachsen.
    """
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start

    route = request.scope.get("route")
    path = route.path if route else "unbekannt"

    m.HTTP_REQUESTS.labels(path, request.method, str(response.status_code)).inc()
    m.HTTP_LATENCY.labels(path).observe(duration)
    return response


def _get_store() -> RunStore:
    """Erzeugt die Persistenzschicht für die konfigurierte DB-Datei.

    Als eigene Funktion, damit Tests `src.api.main._get_store`
    monkeypatchen können, ohne eine echte SQLite-Datei anzulegen.
    """
    return RunStore(DB_PATH)


@app.get("/health")
def health() -> dict:
    """Einfacher Erreichbarkeits-Check."""
    return {"status": "ok"}


@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    """Alle Kennzahlen im Textformat von Prometheus.

    Prometheus ruft diesen Endpunkt regelmäßig ab. Bewusst nicht in der
    OpenAPI-Dokumentation aufgeführt, weil er sich nicht an menschliche
    Nutzer richtet.
    """
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/scans", response_model=ScanRun)
def create_scan(request: ScanRequest) -> ScanRun:
    """Startet einen vollständigen Scan (Scanner -> Triage -> Report).

    Läuft synchron: die Antwort kommt erst, wenn Scan, Triage und
    Report abgeschlossen sind (oder ein Schritt fehlgeschlagen ist).

    Args:
        request: Enthält den Pfad des zu scannenden Repositories und
            optional ein abweichendes Semgrep-Regelwerk.

    Returns:
        Den fertigen `ScanRun` mit Status `completed` und Bericht,
        oder eine Fehlerantwort, falls ein Schritt fehlschlägt.
    """
    # Eingaben prüfen, bevor irgendetwas gescannt wird (fail-closed, siehe
    # src/api/security.py). Geprüft wird der aufgelöste Pfad; an die Pipeline
    # geht weiterhin der ursprüngliche Pfad-String, damit sich das Verhalten
    # bei erlaubten Anfragen nicht ändert.
    try:
        repo_dir = resolve_repo_path(request.repo_path)
        semgrep_config = validate_semgrep_config(request.semgrep_config, repo_dir)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        return run_pipeline(
            request.repo_path,
            db_path=DB_PATH,
            semgrep_config=semgrep_config,
            demo_mode=request.demo_mode,
        )
    except Exception as exc:  # noqa: BLE001 - wird als 500 weitergegeben
        raise HTTPException(
            status_code=500,
            detail=f"Lauf fehlgeschlagen: {exc}",
        ) from exc


@app.get("/scans/{run_id}", response_model=ScanRun)
def get_scan(run_id: str) -> ScanRun:
    """Liefert den gespeicherten Stand eines Laufs (auch bei `failed`).

    Args:
        run_id: ID des Laufs, wie sie `POST /scans` zurückgegeben hat.
    """
    store = _get_store()
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Lauf nicht gefunden: {run_id}")
    return run


@app.get("/scans/{run_id}/report")
def get_scan_report(run_id: str) -> dict:
    """Liefert nur den Markdown-Bericht eines abgeschlossenen Laufs.

    Args:
        run_id: ID des Laufs.
    """
    store = _get_store()
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Lauf nicht gefunden: {run_id}")
    if run.report_markdown is None:
        raise HTTPException(
            status_code=409,
            detail=f"Lauf {run_id} hat noch keinen Bericht (Status: {run.status.value}).",
        )
    return {"run_id": run_id, "report_markdown": run.report_markdown}
