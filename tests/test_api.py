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
    # Erlaubter Scan-Bereich ist der temporäre Testordner. Ohne diese Zeile
    # würden die Tests mit tmp_path als repo_path mit HTTP 400 abgelehnt.
    monkeypatch.setenv("VULNSCOUT_SCAN_ROOT", str(tmp_path))
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


# --- Eingabeprüfung (src/api/security.py) ------------------------------------
# Diese Tests mocken die Prüfung nicht, nur `run_pipeline`. Bei einer
# abgelehnten Anfrage darf die Pipeline nie aufgerufen werden.


@pytest.fixture
def pipeline_mock(monkeypatch):
    mock = MagicMock(
        return_value=ScanRun(repo_path="x", status=RunStatus.COMPLETED)
    )
    monkeypatch.setattr(api_main, "run_pipeline", mock)
    return mock


@pytest.fixture
def repo_dir(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


@pytest.fixture
def outside_dir(tmp_path_factory):
    """Ein existierendes Verzeichnis außerhalb des erlaubten Bereichs."""
    return tmp_path_factory.mktemp("fremd")


def test_rejects_existing_dir_outside_scan_root(client, pipeline_mock, outside_dir):
    response = client.post("/scans", json={"repo_path": str(outside_dir)})
    assert response.status_code == 400
    assert "außerhalb" in response.json()["detail"]
    pipeline_mock.assert_not_called()


def test_rejects_dotdot_escape_from_scan_root(
    client, pipeline_mock, repo_dir, outside_dir
):
    escape = repo_dir / ".." / ".." / outside_dir.name
    response = client.post("/scans", json={"repo_path": str(escape)})
    assert response.status_code == 400
    pipeline_mock.assert_not_called()


def test_rejects_symlink_pointing_out_of_scan_root(
    client, pipeline_mock, tmp_path, outside_dir
):
    link = tmp_path / "link"
    link.symlink_to(outside_dir, target_is_directory=True)
    response = client.post("/scans", json={"repo_path": str(link)})
    assert response.status_code == 400
    pipeline_mock.assert_not_called()


def test_error_message_is_same_for_missing_and_outside_dir(
    client, pipeline_mock, outside_dir
):
    # Die Antwort darf nicht verraten, ob ein Verzeichnis außerhalb existiert.
    missing = client.post("/scans", json={"repo_path": "/no/such/dir"})
    outside = client.post("/scans", json={"repo_path": str(outside_dir)})
    assert missing.json()["detail"] == outside.json()["detail"]


def test_default_scan_root_is_test_repos_in_working_directory(
    client, pipeline_mock, tmp_path, monkeypatch
):
    monkeypatch.delenv("VULNSCOUT_SCAN_ROOT")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "test_repos" / "demo").mkdir(parents=True)
    (tmp_path / "other").mkdir()

    allowed = client.post("/scans", json={"repo_path": "test_repos/demo"})
    denied = client.post("/scans", json={"repo_path": "other"})

    assert allowed.status_code == 200
    assert denied.status_code == 400


@pytest.mark.parametrize(
    "config",
    [
        "https://example.com/rules.yml",
        "http://example.com/rules.yml",
        "--config=evil",
        "-h",
        "p/",
        "p/../etc",
        "r/python.lang",
        "../secret.yml",
        "/etc/passwd",
    ],
)
def test_rejects_forbidden_semgrep_config(client, pipeline_mock, repo_dir, config):
    response = client.post(
        "/scans", json={"repo_path": str(repo_dir), "semgrep_config": config}
    )
    assert response.status_code == 400
    assert "semgrep_config" in response.json()["detail"]
    pipeline_mock.assert_not_called()


def test_registry_semgrep_config_is_passed_through_unchanged(
    client, pipeline_mock, repo_dir
):
    response = client.post(
        "/scans",
        json={"repo_path": str(repo_dir), "semgrep_config": "p/security-audit"},
    )
    assert response.status_code == 200
    assert pipeline_mock.call_args.kwargs["semgrep_config"] == "p/security-audit"


def test_default_semgrep_config_is_accepted(client, pipeline_mock, repo_dir):
    response = client.post("/scans", json={"repo_path": str(repo_dir)})
    assert response.status_code == 200
    assert pipeline_mock.call_args.kwargs["semgrep_config"] == "p/security-audit"


def test_semgrep_config_file_in_repo_is_passed_as_absolute_path(
    client, pipeline_mock, repo_dir
):
    rules = repo_dir / "rules.yml"
    rules.write_text("rules: []\n")
    response = client.post(
        "/scans",
        json={"repo_path": str(repo_dir), "semgrep_config": "rules.yml"},
    )
    assert response.status_code == 200
    assert pipeline_mock.call_args.kwargs["semgrep_config"] == str(rules.resolve())


def test_semgrep_config_file_outside_repo_is_rejected(
    client, pipeline_mock, repo_dir, outside_dir
):
    rules = outside_dir / "rules.yml"
    rules.write_text("rules: []\n")
    response = client.post(
        "/scans",
        json={"repo_path": str(repo_dir), "semgrep_config": str(rules)},
    )
    assert response.status_code == 400
    pipeline_mock.assert_not_called()


def test_original_repo_path_string_is_passed_to_pipeline(
    client, pipeline_mock, repo_dir
):
    # Das Pipeline-Verhalten bei erlaubten Anfragen darf sich nicht ändern:
    # weitergegeben wird der Pfad so, wie der Aufrufer ihn geschickt hat.
    client.post("/scans", json={"repo_path": str(repo_dir)})
    assert pipeline_mock.call_args.args[0] == str(repo_dir)
