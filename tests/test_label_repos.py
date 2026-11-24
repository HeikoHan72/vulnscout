"""Tests für scripts/label_repos.py.

Geprüft wird nur die Vorbereitung (Pfade, Voraussetzungen, Abbruch vor
dem Scannen). Gescannt oder gelabelt wird hier nie: Das würde echte
API-Aufrufe kosten.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import label_repos as lr


def _create_all_repos(eval_dir: Path) -> None:
    for folder, _url in lr.REPO_SOURCES.values():
        (eval_dir / folder).mkdir(parents=True)


def test_quelltext_enthaelt_keine_umgebungsspezifischen_pfade():
    source = Path(lr.__file__).read_text(encoding="utf-8")
    assert "/home/claude" not in source
    assert "/tmp/" not in source


def test_standardordner_liegt_neben_dem_projektordner(monkeypatch):
    monkeypatch.delenv(lr.EVAL_REPOS_ENV, raising=False)
    assert lr.default_eval_dir() == lr._PROJECT_ROOT.parent / "eval_repos"


def test_umgebungsvariable_ueberschreibt_den_ordner(monkeypatch, tmp_path):
    monkeypatch.setenv(lr.EVAL_REPOS_ENV, str(tmp_path))
    assert lr.default_eval_dir() == tmp_path


def test_leere_umgebungsvariable_gilt_als_nicht_gesetzt(monkeypatch):
    monkeypatch.setenv(lr.EVAL_REPOS_ENV, "  ")
    assert lr.default_eval_dir() == lr._PROJECT_ROOT.parent / "eval_repos"


def test_resolve_repos_liefert_alle_sechs_repos(tmp_path):
    repos = lr.resolve_repos(tmp_path)
    assert set(repos) == {
        "dummy_vuln_repo",
        "pygoat",
        "dvpwa",
        "vulnerable_flask_app",
        "requests",
        "click",
    }
    assert repos["dummy_vuln_repo"].is_dir()
    assert repos["vulnerable_flask_app"] == tmp_path / "Vulnerable-Flask-App"


def test_fehlende_repos_werden_erkannt(tmp_path):
    missing = lr.missing_repos(lr.resolve_repos(tmp_path))
    assert set(missing) == set(lr.REPO_SOURCES)
    assert lr.DUMMY_REPO_NAME not in missing


def test_vollstaendiger_ordner_hat_keine_fehlenden_repos(tmp_path):
    _create_all_repos(tmp_path)
    assert lr.missing_repos(lr.resolve_repos(tmp_path)) == []


def test_klonbefehle_enthalten_url_und_zielordner(tmp_path):
    commands = lr.clone_commands(["vulnerable_flask_app", "click"], tmp_path)
    assert commands == [
        f'git clone --depth 1 https://github.com/we45/Vulnerable-Flask-App.git "{tmp_path / "Vulnerable-Flask-App"}"',
        f'git clone --depth 1 https://github.com/pallets/click.git "{tmp_path / "click"}"',
    ]


def test_dummy_repo_bekommt_keinen_klonbefehl(tmp_path):
    assert lr.clone_commands([lr.DUMMY_REPO_NAME], tmp_path) == []


def test_fehlender_api_key_wird_gemeldet(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert "ANTHROPIC_API_KEY" in lr.api_key_problem()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "   ")
    assert lr.api_key_problem() is not None


def test_gesetzter_api_key_ist_kein_problem(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-dummy-key-for-test")
    assert lr.api_key_problem() is None


def test_preflight_meldet_key_und_fehlende_repos_getrennt(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    problems = lr.preflight(tmp_path)
    assert len(problems) == 2
    assert "ANTHROPIC_API_KEY" in problems[0]
    assert "git clone --depth 1" in problems[1]
    assert lr.EVAL_REPOS_ENV in problems[1]


def test_preflight_ohne_probleme(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-dummy-key-for-test")
    _create_all_repos(tmp_path)
    assert lr.preflight(tmp_path) == []


def test_main_bricht_vor_dem_scannen_ab(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(lr.EVAL_REPOS_ENV, str(tmp_path))

    def _darf_nicht_laufen(*args, **kwargs):
        raise AssertionError("Scan oder LLM-Aufruf trotz fehlender Voraussetzungen")

    monkeypatch.setattr(lr, "run_all_scanners", _darf_nicht_laufen)
    monkeypatch.setattr(lr, "triage_findings", _darf_nicht_laufen)
    monkeypatch.setattr(lr, "OUTPUT_PATH", tmp_path / "nicht_schreiben.jsonl")

    assert lr.main() == 1
    assert not (tmp_path / "nicht_schreiben.jsonl").exists()
