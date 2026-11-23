"""Benennt die Fehlentscheidungen eines Laufs einzeln.

`scripts/evaluate.py` liefert die Kennzahlen, aber nicht, *welcher* Fund
falsch bewertet wurde. Für einen Sicherheitsscanner ist genau das die
wichtigste Frage - besonders bei "fälschlich verworfen": eine echte
Schwachstelle, die als Fehlalarm abgetan wurde.

Aufruf:

    python scripts/inspect_misses.py --db auswertung_container.db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from scripts.evaluate import MODUL_EBENE, funktion_an_zeile, lade_lauf


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--repo", type=Path, default=Path("test_repos/dummy_vuln_repo"))
    args = parser.parse_args()

    ground_truth = yaml.safe_load(
        (args.repo / "ground_truth.yml").read_text(encoding="utf-8")
    )
    run_id, funde, bewertungen = lade_lauf(args.db, args.run_id)
    nach_id = {b["finding_id"]: b for b in bewertungen}

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
    dep_datei = ground_truth["abhaengigkeiten"]["datei"]

    falsch_verworfen: list[str] = []
    falsch_bestaetigt: list[str] = []

    for fund in funde:
        bewertung = nach_id.get(fund["id"])
        if bewertung is None or fund["file_path"] == dep_datei:
            continue
        if bewertung.get("needs_review"):
            continue

        funktion = funktion_an_zeile(
            args.repo / fund["file_path"], fund["line_start"] or 1
        )
        eintrag = je_regel.get(
            (fund["file_path"], funktion, fund["rule_id"])
        ) or je_funktion.get((fund["file_path"], funktion))
        if eintrag is None:
            continue

        bestaetigt = bool(bewertung["is_true_positive"])
        zeile = (
            f"{eintrag['id']}  ({fund['file_path']}:{fund['line_start']}, "
            f"{funktion}, {fund['tool']} {fund['rule_id']})\n"
            f"      Konfidenz: {bewertung.get('confidence')}  "
            f"Schweregrad: {bewertung.get('severity')}\n"
            f"      Begruendung: {str(bewertung.get('reasoning'))[:300]}"
        )

        if eintrag["erwartung"] == "true_positive" and not bestaetigt:
            falsch_verworfen.append(zeile)
        elif eintrag["erwartung"] in ("false_positive", "kein_fund") and bestaetigt:
            falsch_bestaetigt.append(zeile)

    print(f"Lauf: {run_id}\n")
    print(f"FAELSCHLICH VERWORFEN (echte Luecke als Fehlalarm abgetan): {len(falsch_verworfen)}")
    for z in falsch_verworfen:
        print("  - " + z)
    print()
    print(f"FAELSCHLICH BESTAETIGT (harmloser Fund als echt bewertet): {len(falsch_bestaetigt)}")
    for z in falsch_bestaetigt:
        print("  - " + z)
    return 0


if __name__ == "__main__":
    sys.exit(main())
