"""CI-Qualitäts-Gate für das Pre-Filter-Modell.

Dieser Test führt die komplette Trainings-Pipeline aus
`scripts/train_prefilter.py` gegen den echten, im Repository
versionierten Trainingsdatensatz (`scripts/training_data.jsonl`) aus -
gegen einen frischen, lokalen MLflow-Tracking-Server (Dateisystem,
temporäres Verzeichnis), damit CI nicht auf den MLflow-Server des
Projekts angewiesen ist, der nur auf dem Rechner des Autors läuft.

Schlägt dieser Test fehl, heißt das: entweder ist die Trainings-Pipeline
kaputt, oder kein Kandidat erreicht mehr die Mindestqualität (siehe
`MAX_ERROR_RATE` in `train_prefilter.py`) - in beiden Fällen soll der
Build rot werden, bevor ein schlechteres Modell in der Registry landet.
"""

from __future__ import annotations

import json
from pathlib import Path

import mlflow
import pytest
from mlflow.tracking import MlflowClient

from scripts import train_prefilter as tp

pytestmark = pytest.mark.slow

DATA_PATH = Path(__file__).resolve().parent.parent / "scripts" / "training_data.jsonl"


@pytest.mark.skipif(
    not DATA_PATH.exists(),
    reason="scripts/training_data.jsonl fehlt (python -m scripts.label_repos nicht gelaufen)",
)
def test_training_pipeline_erreicht_qualitaets_gate(tmp_path, monkeypatch):
    mlflow.set_tracking_uri(f"sqlite:///{tmp_path / 'mlflow.db'}")

    tp.main()

    client = MlflowClient()
    champion_version = client.get_model_version_by_alias(tp.REGISTERED_MODEL_NAME, "champion")
    assert champion_version is not None, "Kein Kandidat hat das Qualitäts-Gate bestanden"

    run = client.get_run(champion_version.run_id)
    test_error_rate = run.data.metrics["test_error_rate"]
    test_coverage = run.data.metrics["test_coverage"]

    assert test_error_rate <= tp.MAX_ERROR_RATE, (
        f"Champion-Modell verfehlt das Qualitäts-Gate: "
        f"Fehlerrate {test_error_rate:.1%} > {tp.MAX_ERROR_RATE:.1%}"
    )
    # Ein Pre-Filter, der praktisch nie etwas automatisch entscheidet,
    # bringt keine Kostenersparnis - das Gate soll auch das erkennen.
    assert test_coverage > 0.0, "Champion-Modell entscheidet keinen einzigen Testfund automatisch"

    # Verwerfungsseite getrennt absichern: Ein automatisch verworfener Fund
    # verschwindet lautlos. Diese Quote darf deshalb nicht in der
    # Gesamtfehlerquote untergehen, sondern wird einzeln geprüft.
    test_miss_rate = run.data.metrics["test_miss_rate"]
    n_missed = run.data.metrics["n_missed_test"]
    assert test_miss_rate <= tp.MAX_MISS_RATE_TEST, (
        f"Pre-Filter verwirft echte Schwachstellen: {n_missed:.0f} von "
        f"{run.data.metrics['n_rejected_test']:.0f} automatisch verworfenen Funden "
        f"waren echt ({test_miss_rate:.1%} > {tp.MAX_MISS_RATE_TEST:.1%})"
    )

    summary_path = Path("scripts/prefilter_summary.json")
    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["test_error_rate"] == pytest.approx(test_error_rate)


@pytest.mark.skipif(
    not DATA_PATH.exists(),
    reason="scripts/training_data.jsonl fehlt (python -m scripts.label_repos nicht gelaufen)",
)
def test_zweiter_trainingslauf_setzt_alias_auf_neue_version(tmp_path):
    """Der Champion-Alias muss auf die Version des aktuellen Laufs zeigen.

    Hintergrund: Eine frühere Fassung setzte die Aliase über *alle* jemals
    registrierten Versionen hinweg, wobei die zuletzt verarbeitete gewann. Ab
    dem zweiten Trainingslauf konnte `@champion` dadurch auf ein veraltetes
    Modell zeigen - die Anwendung hätte es ohne Fehlermeldung weiterbenutzt.
    Ein Test mit jeweils frischer Registry kann das nicht finden, deshalb
    trainiert dieser Test zweimal gegen dieselbe Registry.
    """
    mlflow.set_tracking_uri(f"sqlite:///{tmp_path / 'mlflow.db'}")
    client = MlflowClient()

    tp.main()
    versionen_nach_lauf_1 = {
        v.version for v in client.search_model_versions(f"name='{tp.REGISTERED_MODEL_NAME}'")
    }
    assert versionen_nach_lauf_1, "Erster Lauf hat keine Modellversion registriert"

    tp.main()
    champion = client.get_model_version_by_alias(tp.REGISTERED_MODEL_NAME, "champion")

    assert champion.version not in versionen_nach_lauf_1, (
        f"Champion-Alias zeigt auf Version {champion.version} aus dem ersten Lauf "
        f"(Versionen nach Lauf 1: {sorted(versionen_nach_lauf_1)}) - "
        "der Alias wurde nicht auf das neu trainierte Modell gesetzt"
    )
