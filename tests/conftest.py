"""Gemeinsame Einstellungen für alle Tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _osv_anreicherung_aus(monkeypatch):
    """Schaltet die OSV-Anreicherung in allen Tests ab.

    Sie fragt das Internet ab. Tests sollen nie ins Netz gehen und nicht
    vom Zustand eines externen Dienstes abhängen - in CI und auf einem
    Rechner ohne Netz wären sie sonst langsam oder unzuverlässig. Die Tests
    der Anreicherung selbst (`test_enrichment.py`) schalten sie gezielt
    wieder ein und ersetzen die Abruffunktion durch eine Attrappe.
    """
    monkeypatch.setenv("VULNSCOUT_OSV_ENABLED", "0")


@pytest.fixture(autouse=True)
def _osv_zwischenspeicher_leeren():
    """Leert den Zwischenspeicher der OSV-Anreicherung vor und nach jedem Test.

    Er gilt prozessweit. Ohne das Leeren würden Tests, die dieselbe ID mit
    verschiedenen Attrappen abfragen, einander beeinflussen.
    """
    from src.enrichment import osv

    osv.clear_cache()
    yield
    osv.clear_cache()
