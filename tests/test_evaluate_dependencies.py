"""Tests für den Vergleich der Abhängigkeits-Einstufung mit OSV in
`scripts/evaluate.py`."""

from __future__ import annotations

import pytest

from scripts.evaluate import abhaengigkeits_schweregrade, berichte, Ergebnis

DATEI = "requirements.txt"


def _fund(fid, osv=None, datei=DATEI):
    return {"id": fid, "file_path": datei, "osv_severity": osv}


def _bew(fid, severity="high", tp=True, raised_from=None):
    return {
        "finding_id": fid,
        "is_true_positive": tp,
        "severity": severity,
        "severity_raised_from": raised_from,
    }


def test_equal_higher_lower_and_raised_are_counted_separately():
    funde = [_fund("a", "high"), _fund("b", "medium"), _fund("c", "high"), _fund("d", "high")]
    bew = [
        _bew("a", "high"),
        _bew("b", "high"),
        _bew("c", "medium"),
        _bew("d", "high", raised_from="medium"),
    ]

    z = abhaengigkeits_schweregrade(funde, bew, DATEI)

    assert z == {"bestaetigt": 4, "gleich": 2, "hoeher": 1, "niedriger": 1, "angehoben": 1}


def test_findings_without_osv_severity_are_counted_but_not_compared():
    z = abhaengigkeits_schweregrade([_fund("a", None)], [_bew("a")], DATEI)

    assert z == {"bestaetigt": 1, "ohne_osv": 1}


def test_false_positives_and_other_files_and_missing_assessments_are_ignored():
    funde = [
        _fund("a", "high"),
        _fund("b", "high", datei="app.py"),
        _fund("c", "high"),
    ]
    bew = [_bew("a", tp=False), _bew("b")]

    assert abhaengigkeits_schweregrade(funde, bew, DATEI) == {}


def test_unknown_triage_severity_counts_as_lower():
    z = abhaengigkeits_schweregrade([_fund("a", "low")], [_bew("a", "unknown")], DATEI)

    assert z["niedriger"] == 1


@pytest.mark.parametrize("osv", ["unknown", "", "weird"])
def test_unusable_osv_values_count_as_without_osv(osv):
    z = abhaengigkeits_schweregrade([_fund("a", osv)], [_bew("a")], DATEI)

    assert z == {"bestaetigt": 1, "ohne_osv": 1}


def test_report_prints_the_comparison_and_the_metric_limit(capsys):
    berichte(
        "run-1",
        Ergebnis(),
        Ergebnis(richtig_bestaetigt=3),
        [{"tool": "pip-audit"}],
        {"bestaetigt": 3, "gleich": 2, "angehoben": 1},
    )

    out = capsys.readouterr().out
    assert "Einstufung gegen OSV" in out
    assert "durch die Untergrenze angehoben" in out
    assert "nur, dass nichts verworfen wurde" in out


def test_report_without_comparison_still_works(capsys):
    berichte("run-1", Ergebnis(), Ergebnis(), [])

    assert "Einstufung gegen OSV" not in capsys.readouterr().out
