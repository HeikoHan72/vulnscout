"""Trainiert das Pre-Filter-Modell für die Triage (Variante B).

Idee: Ein Großteil der Scanner-Funde ist für den Triage-Agenten
eindeutig zu entscheiden (z. B. "pip-audit meldet eine echte CVE" oder
"Bandit markiert einen reinen Import als Fund" - fast immer ein
Fehlalarm). Für solche eindeutigen Fälle muss kein teurer LLM-Aufruf
gemacht werden. Dieses Skript trainiert einen günstigen Klassifikator,
der aus den rohen Scanner-Merkmalen eines Fundes vorhersagt, ob der
Triage-Agent ihn bestätigen oder verwerfen würde - und zwar nur dort,
wo diese Vorhersage sehr sicher ist. Unsichere Fälle werden weiterhin
an das LLM eskaliert.

WICHTIGE EINSCHRÄNKUNG (gehört so in die Projekt-Doku): Die Labels in
`scripts/training_data.jsonl` stammen vom Triage-Agenten (LLM), nicht
von menschlicher Ground Truth. Dieses Modell destilliert also das
Urteil des LLM - es lernt nicht unabhängig, echte Schwachstellen zu
erkennen, sondern vorherzusagen, was das LLM dazu sagen würde. Die
hier berichtete "Fehlerrate" ist deshalb eine Abweichung vom
LLM-Urteil, keine Abweichung von der Wahrheit.

Methodik:
- Split nach Repository, nicht nach Zeile: die Test-Repos werden beim
  Training nie gesehen (sonst Datenleckage - ein Modell, das Zeilen
  aus demselben Repo in Training und Test hat, wirkt besser, als es
  bei einem echten neuen Repo tatsächlich wäre).
- Zwei Kandidaten-Modelle (LogisticRegression, RandomForest) werden
  trainiert und als Champion/Challenger gegeneinander antreten
  gelassen.
- Die Entscheidungsschwellen (ab welcher Wahrscheinlichkeit wird
  automatisch entschieden) werden NICHT auf den Test-Repos festgelegt
  (das wäre Überanpassung an genau die Daten, mit denen das Ergebnis
  dann berichtet wird), sondern auf einem separaten Validierungsanteil
  der Trainings-Repos.
- Qualitäts-Gate: Ein Kandidat wird nur Champion, wenn seine
  Fehlerrate auf den automatisch entschiedenen Fällen der Test-Repos
  höchstens MAX_ERROR_RATE beträgt. Besteht kein Kandidat das Gate, bleibt
  der bisherige Champion unverändert (konservativ: lieber kein neues
  Modell als ein schlechteres in Produktion).

Nutzung:
    python -m scripts.train_prefilter
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import mlflow
import mlflow.pyfunc
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from mlflow.tracking import MlflowClient

# Lädt MLFLOW_TRACKING_URI etc. aus .env, genau wie label_repos.py und die
# eigentliche Anwendung (src/api/main.py) - ohne das würde dieses Skript
# standalone den MLflow-Default nutzen statt des konfigurierten Servers.
load_dotenv()
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DATA_PATH = Path("scripts/training_data.jsonl")

# Repo-weiser Split: diese Repos sieht das Training nie. Je ein
# "verwundbares" und ein "sauberes" Repo, damit beide Finding-Arten im
# Testset vertreten sind.
TEST_REPOS = {"vulnerable_flask_app", "click"}

CATEGORICAL_FEATURES = [
    "tool",
    "rule_id",
    "scanner_severity",
    "bandit_confidence",
    "file_extension",
]
NUMERIC_FEATURES = [
    "has_cwe",
    "is_dependency_finding",
    "snippet_line_count",
    "snippet_char_count",
]
TARGET = "label_is_true_positive"

EXPERIMENT_NAME = "vulnscout-prefilter"
REGISTERED_MODEL_NAME = "vulnscout-prefilter"

# Qualitäts-Gate: maximal erlaubte Abweichung vom LLM-Urteil unter den
# automatisch entschiedenen Funden der (nie gesehenen) Test-Repos. Bewusst
# streng gewählt - ein Pre-Filter, der stillschweigend echte
# Schwachstellen verwirft, ist schlimmer als gar kein Pre-Filter.
MAX_ERROR_RATE = 0.02

# Verwerfen und Bestätigen sind nicht gleich riskant.
#
# Ein zu Unrecht bestätigter Fund landet im Bericht und fällt beim Lesen auf.
# Ein zu Unrecht verworfener Fund verschwindet dagegen lautlos - eine echte
# Schwachstelle, die niemand mehr sieht. Deshalb werden beide Schwellen
# getrennt gesucht und an die Verwerfungsseite ein strengerer Maßstab gelegt:
#
#   MAX_MISS_RATE_VAL   Anteil echter Funde unter den automatisch verworfenen,
#                       der bei der Schwellenwahl auf dem Validierungsanteil
#                       erlaubt ist. 0.0 = kein einziger.
#   MAX_MISS_RATE_TEST  Dieselbe Quote auf den ausgehaltenen Testrepos, als
#                       Teil des Qualitäts-Gates.
MAX_MISS_RATE_VAL = 0.0
MAX_MISS_RATE_TEST = 0.02

# Kandidaten-Schwellen für die Suche auf dem Validierungsanteil.
THRESHOLD_HIGH_CANDIDATES = [0.80, 0.85, 0.90, 0.92, 0.95, 0.97, 0.99]

# NEVER_REJECT schaltet das automatische Verwerfen komplett ab (keine
# Wahrscheinlichkeit ist <= -1.0). Bleibt als sicherste Option immer wählbar,
# falls keine Verwerfungsschwelle den Maßstab oben einhält.
NEVER_REJECT = -1.0
THRESHOLD_LOW_CANDIDATES = [0.20, 0.15, 0.10, 0.05, 0.02, 0.01, NEVER_REJECT]


@dataclass
class CandidateResult:
    name: str
    pipeline: Pipeline
    threshold_high: float
    threshold_low: float
    val_coverage: float
    val_error_rate: float
    test_coverage: float
    test_error_rate: float
    test_precision: float
    test_recall: float
    test_f1: float
    passes_gate: bool
    n_auto_decided_test: int = 0
    n_errors_test: int = 0
    # Verwerfungsseite getrennt ausgewiesen, siehe MAX_MISS_RATE_TEST.
    test_miss_rate: float = 0.0
    n_rejected_test: int = 0
    n_missed_test: int = 0


def load_dataset() -> pd.DataFrame:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"{DATA_PATH} fehlt - zuerst `python -m scripts.label_repos` laufen lassen."
        )
    df = pd.read_json(DATA_PATH, lines=True)
    # bandit_confidence ist None für nicht-Bandit-Funde - als eigene
    # Kategorie "none" kodieren, sonst macht OneHotEncoder daraus NaN-Ärger.
    df["bandit_confidence"] = df["bandit_confidence"].fillna("none")
    df["file_extension"] = df["file_extension"].fillna("none")
    df["cwe"] = df["cwe"].fillna("none")
    return df


def build_pipeline(model) -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore"),
                CATEGORICAL_FEATURES,
            ),
            ("num", "passthrough", NUMERIC_FEATURES),
        ]
    )
    return Pipeline(steps=[("preprocess", preprocessor), ("model", model)])


def _decide(proba: np.ndarray, threshold_high: float, threshold_low: float) -> np.ndarray:
    """Gibt für jede Wahrscheinlichkeit True/False/None zurück.

    True = automatisch bestätigt, False = automatisch verworfen,
    None = unsicher, würde ans LLM eskaliert.
    """
    decisions = np.full(len(proba), None, dtype=object)
    decisions[proba >= threshold_high] = True
    decisions[proba <= threshold_low] = False
    return decisions


def _coverage_and_error(decisions: np.ndarray, y_true: np.ndarray) -> tuple[float, float, int, int]:
    decided_mask = decisions != None  # noqa: E711 - object-Array, kein pandas
    n_decided = int(decided_mask.sum())
    if n_decided == 0:
        return 0.0, 0.0, 0, 0
    coverage = n_decided / len(decisions)
    errors = decisions[decided_mask].astype(bool) != y_true[decided_mask]
    n_errors = int(errors.sum())
    error_rate = n_errors / n_decided
    return coverage, error_rate, n_decided, n_errors


def _decidable(df: pd.DataFrame) -> np.ndarray:
    """Welche Funde der Pre-Filter überhaupt selbst entscheiden darf.

    Funde ohne Scanner-Schweregrad (praktisch alle pip-audit-Funde) gehen zur
    Laufzeit immer an die LLM-Triage, weil nur sie den Schweregrad bestimmen
    kann - siehe `src/prefilter/prefilter.py`. Dieselbe Regel muss hier
    gelten, sonst meldet das Training eine Abdeckung, die im Betrieb nie
    erreicht wird (training/serving skew).
    """
    return (df["scanner_severity"].astype(str).str.lower() != "unknown").to_numpy()


def _decide_with_rule(
    proba: np.ndarray, t_high: float, t_low: float, decidable: np.ndarray
) -> np.ndarray:
    """`_decide`, aber Funde ohne Schweregrad bleiben immer unentschieden."""
    decisions = _decide(proba, t_high, t_low)
    decisions[~decidable] = None
    return decisions


def _miss_stats(decisions: np.ndarray, y_true: np.ndarray) -> tuple[float, int, int]:
    """Kennzahlen der Verwerfungsseite.

    Gibt (Quote, Anzahl verworfener Funde, Anzahl übersehener echter Funde)
    zurück. "Übersehen" heißt: automatisch verworfen, obwohl das Label den
    Fund als echte Schwachstelle ausweist. Ohne Verwerfungen ist die Quote
    0.0 - nichts verworfen, nichts übersehen.
    """
    rejected_mask = decisions == False  # noqa: E712 - object-Array, kein pandas
    n_rejected = int(rejected_mask.sum())
    if n_rejected == 0:
        return 0.0, 0, 0
    n_missed = int(y_true[rejected_mask].astype(bool).sum())
    return n_missed / n_rejected, n_rejected, n_missed


def pick_thresholds(
    proba_val: np.ndarray, y_val: np.ndarray, decidable_val: np.ndarray
) -> tuple[float, float]:
    """Sucht das Schwellenpaar mit maximaler Abdeckung unter zwei Auflagen.

    Beide Schwellen werden unabhängig voneinander gesucht (früher galt starr
    `t_low = 1 - t_high`). Zulässig ist ein Paar nur, wenn es die
    Gesamtfehlerquote MAX_ERROR_RATE einhält *und* auf der Verwerfungsseite
    höchstens MAX_MISS_RATE_VAL echte Funde übersieht.

    Bei gleicher Abdeckung gewinnt die vorsichtigere, also niedrigere
    Verwerfungsschwelle.
    """
    best = (0.99, NEVER_REJECT)
    best_key = (-1.0, -float("inf"))
    for t_high in THRESHOLD_HIGH_CANDIDATES:
        for t_low in THRESHOLD_LOW_CANDIDATES:
            decisions = _decide_with_rule(proba_val, t_high, t_low, decidable_val)
            coverage, error_rate, _, _ = _coverage_and_error(decisions, y_val)
            miss_rate, _, _ = _miss_stats(decisions, y_val)
            if error_rate > MAX_ERROR_RATE or miss_rate > MAX_MISS_RATE_VAL:
                continue
            key = (coverage, -t_low)
            if key > best_key:
                best = (t_high, t_low)
                best_key = key
    return best


class PrefilterModel(mlflow.pyfunc.PythonModel):
    """MLflow-PyFunc-Wrapper: liefert direkt eine Entscheidung statt nur
    einer rohen Wahrscheinlichkeit, damit Schwellenwerte und Modell
    gemeinsam versioniert werden."""

    def __init__(self, pipeline: Pipeline, threshold_high: float, threshold_low: float):
        self.pipeline = pipeline
        self.threshold_high = threshold_high
        self.threshold_low = threshold_low

    def predict(self, context, model_input: pd.DataFrame) -> pd.DataFrame:
        proba = self.pipeline.predict_proba(model_input)[:, 1]
        # Die Schweregrad-Regel steckt im Modellartefakt selbst, nicht nur im
        # Aufrufer: So gilt sie für jeden, der dieses Modell lädt.
        decisions = _decide_with_rule(
            proba, self.threshold_high, self.threshold_low, _decidable(model_input)
        )
        decision_str = np.where(
            decisions == True,  # noqa: E712
            "true_positive",
            np.where(decisions == False, "false_positive", "escalate"),  # noqa: E712
        )
        return pd.DataFrame(
            {"probability_true_positive": proba, "decision": decision_str}
        )


def evaluate_candidate(
    name: str, model, df_train: pd.DataFrame, df_test: pd.DataFrame
) -> CandidateResult:
    pipeline = build_pipeline(model)

    X_train, X_val, y_train, y_val = train_test_split(
        df_train,
        df_train[TARGET].to_numpy(),
        test_size=0.2,
        random_state=42,
        stratify=df_train[TARGET],
    )
    pipeline.fit(X_train, y_train)

    proba_val = pipeline.predict_proba(X_val)[:, 1]
    decidable_val = _decidable(X_val)
    threshold_high, threshold_low = pick_thresholds(proba_val, y_val, decidable_val)
    val_coverage, val_error_rate, _, _ = _coverage_and_error(
        _decide_with_rule(proba_val, threshold_high, threshold_low, decidable_val), y_val
    )

    # Für die finale Metrik auf einem Datensatz nachtrainieren, der die
    # komplette Trainingsmenge nutzt (nicht nur den 80%-Anteil) - die
    # Schwellen stehen zu diesem Zeitpunkt schon fest, keine Leckage.
    pipeline.fit(df_train, df_train[TARGET])

    y_test = df_test[TARGET].to_numpy()
    proba_test = pipeline.predict_proba(df_test)[:, 1]
    test_decisions = _decide_with_rule(
        proba_test, threshold_high, threshold_low, _decidable(df_test)
    )
    test_coverage, test_error_rate, n_decided, n_errors = _coverage_and_error(
        test_decisions, y_test
    )

    y_pred_test = pipeline.predict(df_test)
    precision = precision_score(y_test, y_pred_test, zero_division=0)
    recall = recall_score(y_test, y_pred_test, zero_division=0)
    f1 = f1_score(y_test, y_pred_test, zero_division=0)

    test_miss_rate, n_rejected, n_missed = _miss_stats(test_decisions, y_test)

    passes_gate = (
        test_error_rate <= MAX_ERROR_RATE
        and test_miss_rate <= MAX_MISS_RATE_TEST
        and n_decided > 0
    )

    return CandidateResult(
        name=name,
        pipeline=pipeline,
        threshold_high=threshold_high,
        threshold_low=threshold_low,
        val_coverage=val_coverage,
        val_error_rate=val_error_rate,
        test_coverage=test_coverage,
        test_error_rate=test_error_rate,
        test_precision=precision,
        test_recall=recall,
        test_f1=f1,
        passes_gate=passes_gate,
        n_auto_decided_test=n_decided,
        n_errors_test=n_errors,
        test_miss_rate=test_miss_rate,
        n_rejected_test=n_rejected,
        n_missed_test=n_missed,
    )


def log_candidate_to_mlflow(result: CandidateResult, df_train: pd.DataFrame, df_test: pd.DataFrame, sample_input: pd.DataFrame) -> str:
    """Loggt den Trainingslauf und registriert das Modell. Gibt die
    registrierte Modellversion zurück."""
    with mlflow.start_run(run_name=result.name):
        mlflow.log_param("candidate", result.name)
        mlflow.log_param("threshold_high", result.threshold_high)
        mlflow.log_param("threshold_low", result.threshold_low)
        mlflow.log_param("max_error_rate_gate", MAX_ERROR_RATE)
        mlflow.log_param("train_repos", sorted(df_train["repo"].unique().tolist()))
        mlflow.log_param("test_repos", sorted(df_test["repo"].unique().tolist()))
        mlflow.log_param("train_rows", len(df_train))
        mlflow.log_param("test_rows", len(df_test))

        mlflow.log_metric("val_coverage", result.val_coverage)
        mlflow.log_metric("val_error_rate", result.val_error_rate)
        mlflow.log_metric("test_coverage", result.test_coverage)
        mlflow.log_metric("test_error_rate", result.test_error_rate)
        mlflow.log_metric("test_precision", result.test_precision)
        mlflow.log_metric("test_recall", result.test_recall)
        mlflow.log_metric("test_f1", result.test_f1)
        mlflow.log_metric("n_auto_decided_test", result.n_auto_decided_test)
        mlflow.log_metric("n_errors_test", result.n_errors_test)
        mlflow.log_metric("test_miss_rate", result.test_miss_rate)
        mlflow.log_metric("n_rejected_test", result.n_rejected_test)
        mlflow.log_metric("n_missed_test", result.n_missed_test)
        mlflow.log_metric("passes_quality_gate", int(result.passes_gate))

        wrapped = PrefilterModel(result.pipeline, result.threshold_high, result.threshold_low)
        model_info = mlflow.pyfunc.log_model(
            name="model",
            python_model=wrapped,
            input_example=sample_input,
            registered_model_name=REGISTERED_MODEL_NAME,
        )
        return model_info.registered_model_version


def main() -> None:
    df = load_dataset()
    df_train = df[~df["repo"].isin(TEST_REPOS)].reset_index(drop=True)
    df_test = df[df["repo"].isin(TEST_REPOS)].reset_index(drop=True)

    logger.info(
        "Trainingsdaten: %d Zeilen aus %s", len(df_train), sorted(df_train["repo"].unique())
    )
    logger.info(
        "Testdaten (nie im Training gesehen): %d Zeilen aus %s",
        len(df_test),
        sorted(df_test["repo"].unique()),
    )
    if df_test.empty:
        missing = TEST_REPOS - set(df["repo"].unique())
        raise ValueError(
            f"Keine Testdaten gefunden. Fehlende/leere Test-Repos: {sorted(missing) or TEST_REPOS}. "
            "Lief scripts/label_repos.py vollständig durch?"
        )
    if df_train.empty:
        raise ValueError("Keine Trainingsdaten gefunden (nur Test-Repos im Datensatz).")

    candidates = {
        "logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "random_forest": RandomForestClassifier(
            n_estimators=200, max_depth=12, class_weight="balanced", random_state=42
        ),
    }

    mlflow.set_experiment(EXPERIMENT_NAME)
    results: list[CandidateResult] = []
    # Nur die tatsächlichen Modell-Merkmale als Beispiel-Input - sonst leitet
    # MLflow eine Signatur ab, die zusätzlich die rein informativen Spalten
    # (repo, finding_id, cwe, title, label_*) verlangt. Die Laufzeit-Inferenz
    # (src/prefilter/prefilter.py) liefert aber nur FEATURE_COLUMNS, das würde
    # sonst bei jeder echten Anwendung mit einem Schema-Fehler fehlschlagen
    # (still best-effort abgefangen, aber eben nutzlos - training/serving skew).
    sample_input = df_train[CATEGORICAL_FEATURES + NUMERIC_FEATURES].head(3)

    # Merkt sich die Version, die *dieser* Lauf für jeden Kandidaten erzeugt
    # hat. Entscheidend: Die Aliase dürfen nur auf diese Versionen gesetzt
    # werden, nicht auf irgendwelche älteren aus früheren Läufen.
    versions_by_candidate: dict[str, str] = {}

    for name, model in candidates.items():
        logger.info("Trainiere Kandidat: %s", name)
        result = evaluate_candidate(name, model, df_train, df_test)
        logger.info(
            "%s: Test-Abdeckung=%.1f%%, Test-Fehlerrate=%.2f%%, "
            "verworfen=%d davon uebersehen=%d (%.2f%%), Schwellen=%.2f/%s, Gate=%s",
            name,
            result.test_coverage * 100,
            result.test_error_rate * 100,
            result.n_rejected_test,
            result.n_missed_test,
            result.test_miss_rate * 100,
            result.threshold_high,
            "aus" if result.threshold_low == NEVER_REJECT else f"{result.threshold_low:.2f}",
            "bestanden" if result.passes_gate else "NICHT bestanden",
        )
        versions_by_candidate[name] = log_candidate_to_mlflow(
            result, df_train, df_test, sample_input
        )
        results.append(result)

    client = MlflowClient()

    eligible = [r for r in results if r.passes_gate]
    if not eligible:
        logger.warning(
            "Kein Kandidat besteht das Qualitäts-Gate (max. Fehlerrate %.0f%%) - "
            "kein neuer Champion gesetzt.",
            MAX_ERROR_RATE * 100,
        )
        return

    champion = max(eligible, key=lambda r: r.test_coverage)

    # Aliase ausschließlich auf die Versionen dieses Laufs setzen.
    #
    # Frühere Fassung lief über alle jemals registrierten Versionen und setzte
    # den Alias für jede passende - die letzte Zuweisung gewann. Ab dem zweiten
    # Trainingslauf konnte der Champion-Alias dadurch auf ein veraltetes Modell
    # zeigen, das die Anwendung dann still weiterbenutzt hätte.
    champion_version = versions_by_candidate[champion.name]
    client.set_registered_model_alias(REGISTERED_MODEL_NAME, "champion", champion_version)
    logger.info("Champion: %s (Version %s)", champion.name, champion_version)

    others = [r for r in results if r is not champion]
    if others:
        challenger = max(others, key=lambda r: r.test_coverage)
        challenger_version = versions_by_candidate[challenger.name]
        client.set_registered_model_alias(
            REGISTERED_MODEL_NAME, "challenger", challenger_version
        )
        logger.info("Challenger: %s (Version %s)", challenger.name, challenger_version)

    summary = {
        "champion": champion.name,
        "threshold_high": champion.threshold_high,
        "threshold_low": champion.threshold_low,
        "test_coverage": champion.test_coverage,
        "test_error_rate": champion.test_error_rate,
        "test_miss_rate": champion.test_miss_rate,
        "n_rejected_test": champion.n_rejected_test,
        "n_missed_test": champion.n_missed_test,
        "test_precision": champion.test_precision,
        "test_recall": champion.test_recall,
        "test_f1": champion.test_f1,
        "train_rows": len(df_train),
        "test_rows": len(df_test),
        "test_repos": sorted(df_test["repo"].unique().tolist()),
    }
    summary_path = Path("scripts/prefilter_summary.json")
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Zusammenfassung geschrieben: %s", summary_path)


if __name__ == "__main__":
    main()
