"""Tests für die FastAPI-Anwendung (`src/api/main.py`).

`run_pipeline` und `RunStore` werden gemockt bzw. durch eine
temporäre SQLite-Datei ersetzt – es wird kein echter Scanner- oder
API-Aufruf ausgeführt.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import src.api.main as api_main
from src.orchestrator.models import RunStatus, ScanRun


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(api_main, "DB_PATH", db_path)
    return TestClient(api_main.app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_scan_rejects_unknown_repo_path(client):
    response = client.post("/scans", json={"repo_path": "/no/such/dir"})
    assert response.status_code == 400
    assert "existiert nicht" in response.json()["detail"]


def test_create_scan_happy_path(client, monkeypatch, tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    run = ScanRun(
        repo_path=str(repo_dir),
        status=RunStatus.COMPLETED,
        report_markdown="# Bericht",
    )
    monkeypatch.setattr(api_main, "run_pipeline", MagicMock(return_value=run))

    response = client.post("/scans", json={"repo_path": str(repo_dir)})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["report_markdown"] == "# Bericht"


def test_create_scan_passes_demo_mode_through_to_pipeline(client, monkeypatch, tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    mock_run_pipeline = MagicMock(
        return_value=ScanRun(repo_path=str(repo_dir), status=RunStatus.COMPLETED)
    )
    monkeypatch.setattr(api_main, "run_pipeline", mock_run_pipeline)

    response = client.post(
        "/scans", json={"repo_path": str(repo_dir), "demo_mode": True}
    )
    assert response.status_code == 200
    assert mock_run_pipeline.call_args.kwargs["demo_mode"] is True


def test_create_scan_returns_500_on_pipeline_failure(client, monkeypatch, tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    monkeypatch.setattr(
        api_main,
        "run_pipeline",
        MagicMock(side_effect=RuntimeError("Scanner kaputt")),
    )

    response = client.post("/scans", json={"repo_path": str(repo_dir)})
    assert response.status_code == 500
    assert "Scanner kaputt" in response.json()["detail"]


def test_get_scan_returns_404_for_unknown_id(client):
    response = client.get("/scans/does-not-exist")
    assert response.status_code == 404


def test_get_scan_returns_stored_run(client, tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(api_main, "DB_PATH", db_path)

    from src.orchestrator.storage import RunStore

    store = RunStore(db_path)
    run = ScanRun(repo_path="/tmp/repo", status=RunStatus.COMPLETED)
    store.create_run(run)

    response = client.get(f"/scans/{run.id}")
    assert response.status_code == 200
    assert response.json()["id"] == run.id
    assert response.json()["status"] == "completed"


def test_get_scan_report_returns_409_when_not_ready(client, tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(api_main, "DB_PATH", db_path)

    from src.orchestrator.storage import RunStore

    store = RunStore(db_path)
    run = ScanRun(repo_path="/tmp/repo", status=RunStatus.TRIAGING)
    store.create_run(run)

    response = client.get(f"/scans/{run.id}/report")
    assert response.status_code == 409


def test_get_scan_report_returns_markdown_when_ready(client, tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(api_main, "DB_PATH", db_path)

    from src.orchestrator.storage import RunStore

    store = RunStore(db_path)
    run = ScanRun(
        repo_path="/tmp/repo",
        status=RunStatus.COMPLETED,
        report_markdown="# Fertiger Bericht",
    )
    store.create_run(run)

    response = client.get(f"/scans/{run.id}/report")
    assert response.status_code == 200
    assert response.json()["report_markdown"] == "# Fertiger Bericht"
