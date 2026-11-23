"""Misst die Qualität der Triage gegen eine bekannte Ground Truth.

Ohne diese Auswertung lässt sich über die Triage nur behaupten, sie
funktioniere. Hier wird sie nachgerechnet: Welche echten Schwachstellen
wurden bestätigt, welche Fehlalarme korrekt verworfen, und was haben die
Scanner übersehen?

Aufruf:

    python scripts/evaluate.py --db auswertung.db

Die Datenbank holst du bei laufendem Stack mit::

    docker compose cp api:/app/data/vulnscout.db ./auswertung.db

Zuordnung von Fund zu Ground-Truth-Eintrag: Ein Scanner meldet Datei und
Zeile. Über den Syntaxbaum (`ast`) wird daraus die umgebende Funktion
bestimmt. Das ist stabiler als ein Vergleich über Zeilennummern, die sich
bei jeder Änderung verschieben.
"""

from __future__ import annotations

import argparse
import ast
import json
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

MODUL_EBENE = "<modul>"


# --- Einlesen ----------------------------------------------------------------


def lade_lauf(db_pfad: Path, run_id: Optional[str] = None) -> tuple[str, list[dict], list[dict]]:
    """Liest Funde und Bewertungen eines Laufs aus der SQLite-Datenbank."""
    with sqlite3.connect(db_pfad) as con:
        cur = con.cursor()
        if run_id is None:
            cur.execute("SELECT id FROM runs WHERE status = 'completed' ORDER BY rowid DESC LIMIT 1")
            zeile = cur.fetchone()
            if zeile is None:
                raise SystemExit("Kein abgeschlossener Lauf in der Datenbank gefunden.")
            run_id = zeile[0]

        cur.execute("SELECT data_json FROM findings WHERE run_id = ?", (run_id,))
        funde = [json.loads(d) for (d,) in cur.fetchall()]
        cur.execute("SELECT data_json FROM assessments WHERE run_id = ?", (run_id,))
        bewertungen = [json.loads(d) for (d,) in cur.fetchall()]

    return run_id, funde, bewertungen


def funktion_an_zeile(quelldatei: Path, zeile: int) -> str:
    """Bestimmt die Funktion, in der eine Zeile liegt.

    Gibt `<modul>` zurück, wenn die Zeile außerhalb jeder Funktion steht
    (etwa bei einer Konstanten auf Modulebene oder im `__main__`-Block).
    """
    try:
        baum = ast.parse(quelldatei.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return MODUL_EBENE

    treffer = MODUL_EBENE
    for knoten in ast.walk(baum):
        if isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ende = getattr(knoten, "end_lineno", knoten.lineno)
            if knoten.lineno <= zeile <= ende:
                treffer = knoten.name
    return treffer


# --- Auswertung --------------------------------------------------------------


@dataclass
class Ergebnis:
    richtig_bestaetigt: int = 0  # echte Lücke, Triage bestätigt
    faelschlich_bestaetigt: int = 0  # harmlos, Triage bestätigt trotzdem
    richtig_verworfen: int = 0  # harmlos, Triage erkennt Fehlalarm
    faelschlich_verworfen: int = 0  # echte Lücke, Triage hält sie für Fehlalarm
    zur_pruefung: int = 0  # kein Konsens, bewusst offen gelassen
    ohne_zuordnung: list[str] = field(default_factory=list)
    uebersehen: list[str] = field(default_factory=list)  # Scanner fand nichts


def werte_aus(
    funde: list[dict],
    bewertungen: list[dict],
    ground_truth: dict,
    repo_wurzel: Path,
) -> tuple[Ergebnis, Ergebnis]:
    """Wertet Code-Funde und Abhängigkeits-Funde getrennt aus.

    Getrennt, weil es zwei verschiedene Fragen sind: Bei Code geht es um
    Kontextverständnis, bei Abhängigkeiten um einen Abgleich mit einer
    Schwachstellendatenbank. Eine gemeinsame Kennzahl würde beides
    vermischen und von den 51 Dependency-Funden dominiert.
    """
    nach_id = {b["finding_id"]: b for b in bewertungen}

    # Zwei Arten von Einträgen: mit `regel` gilt ein Eintrag nur für genau
    # diese Scanner-Regel, ohne `regel` für alles Übrige in der Funktion.
    # Nötig, weil ein Scanner an derselben Stelle mehrere verschiedene
    # Regeln melden kann - etwa shell=True (hier harmlos) und zusätzlich
    # einen Prozessstart ohne absoluten Pfad (durchaus berechtigt). Ohne
    # diese Unterscheidung misst man die eigene Ground Truth statt die
    # Triage.
    je_regel = {
        (e["datei"], e["funktion"], e["regel"]): e
        for e in ground_truth["code_funde"]
        if e.get("regel")
    }
    je_funktion = {
        (e["datei"], e["funktion"]): e
        for e in ground_truth["code_funde"]
        if not e.get("regel")
    }
    getroffen: set[tuple[str, str]] = set()

    code = Ergebnis()
    deps = Ergebnis()
    dep_datei = ground_truth["abhaengigkeiten"]["datei"]

    for fund in funde:
        bewertung = nach_id.get(fund["id"])
        if bewertung is None:
            continue

        if fund["file_path"] == dep_datei:
            _zaehle(deps, bewertung, erwartung="true_positive")
            continue

        funktion = funktion_an_zeile(repo_wurzel / fund["file_path"], fund["line_start"] or 1)
        eintrag = je_regel.get((fund["file_path"], funktion, fund["rule_id"])) or je_funktion.get(
            (fund["file_path"], funktion)
        )

        if eintrag is None:
            code.ohne_zuordnung.append(
                f"{fund['file_path']}:{fund['line_start']} ({funktion}, {fund['tool']} {fund['rule_id']})"
            )
            continue

        getroffen.add((eintrag["datei"], eintrag["funktion"]))
        _zaehle(code, bewertung, erwartung=eintrag["erwartung"])

    # Was kein Scanner gemeldet hat, obwohl dort etwas sein sollte.
    for (datei, funktion), eintrag in je_funktion.items():
        if eintrag["erwartung"] == "true_positive" and (datei, funktion) not in getroffen:
            code.uebersehen.append(f"{eintrag['id']} ({datei}, {funktion})")

    return code, deps


def _zaehle(ergebnis: Ergebnis, bewertung: dict, erwartung: str) -> None:
    if bewertung.get("needs_review"):
        ergebnis.zur_pruefung += 1
        return

    bestaetigt = bool(bewertung["is_true_positive"])

    if erwartung == "true_positive":
        if bestaetigt:
            ergebnis.richtig_bestaetigt += 1
        else:
            ergebnis.faelschlich_verworfen += 1
    elif erwartung in ("false_positive", "kein_fund"):
        if bestaetigt:
            ergebnis.faelschlich_bestaetigt += 1
        else:
            ergebnis.richtig_verworfen += 1


def kennzahlen(e: Ergebnis) -> dict[str, Optional[float]]:
    """Precision, Recall und F1 - jeweils None, wenn nicht berechenbar.

    None statt 0.0, weil "keine Grundlage für diese Kennzahl" etwas
    anderes ist als "Kennzahl ist null". Eine 0 würde hier wie ein
    schlechtes Ergebnis aussehen, obwohl schlicht nichts gemessen wurde.
    """
    tp, fp, fn = e.richtig_bestaetigt, e.faelschlich_bestaetigt, e.faelschlich_verworfen
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision and recall and (precision + recall)
        else None
    )
    return {"precision": precision, "recall": recall, "f1": f1}


# --- Ausgabe -----------------------------------------------------------------


def _prozent(wert: Optional[float]) -> str:
    return "n/a" if wert is None else f"{wert:.1%}"


def berichte(run_id: str, code: Ergebnis, deps: Ergebnis, funde: list[dict]) -> None:
    print(f"Lauf: {run_id}")
    print(f"Funde gesamt: {len(funde)}  " + str(dict(Counter(f["tool"] for f in funde))))
    print()

    for titel, e in (("Code-Funde", code), ("Abhängigkeiten", deps)):
        k = kennzahlen(e)
        print(f"--- {titel} ---")
        print(f"  richtig bestätigt     {e.richtig_bestaetigt}")
        print(f"  fälschlich bestätigt  {e.faelschlich_bestaetigt}")
        print(f"  richtig verworfen     {e.richtig_verworfen}")
        print(f"  fälschlich verworfen  {e.faelschlich_verworfen}")
        print(f"  zur Prüfung offen     {e.zur_pruefung}")
        print(
            f"  Precision {_prozent(k['precision'])}   "
            f"Recall {_prozent(k['recall'])}   F1 {_prozent(k['f1'])}"
        )
        print()

    if code.uebersehen:
        print("Von den Scannern übersehen (kein Fund, obwohl Lücke vorhanden):")
        for eintrag in code.uebersehen:
            print(f"  - {eintrag}")
        print()

    if code.ohne_zuordnung:
        print("Funde ohne Eintrag in der Ground Truth (prüfen und ergänzen):")
        for eintrag in code.ohne_zuordnung:
            print(f"  - {eintrag}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True, help="SQLite-Datei eines Laufs")
    parser.add_argument("--run-id", default=None, help="Lauf-ID (Standard: letzter abgeschlossener)")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path("test_repos/dummy_vuln_repo"),
        help="Wurzel des gescannten Repos (für die Zuordnung über den Syntaxbaum)",
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=None,
        help="Ground-Truth-Datei (Standard: ground_truth.yml im Repo)",
    )
    args = parser.parse_args()

    gt_pfad = args.ground_truth or (args.repo / "ground_truth.yml")
    ground_truth = yaml.safe_load(gt_pfad.read_text(encoding="utf-8"))

    run_id, funde, bewertungen = lade_lauf(args.db, args.run_id)
    code, deps = werte_aus(funde, bewertungen, ground_truth, args.repo)
    berichte(run_id, code, deps, funde)
    return 0


if __name__ == "__main__":
    sys.exit(main())
