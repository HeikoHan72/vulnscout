"""Anreicherung der Scanner-Funde mit externen Schweregrad-Daten (OSV), siehe
`osv.py` für das Vorgehen und die Fehlerbehandlung."""

from .osv import enrich_findings

__all__ = ["enrich_findings"]
