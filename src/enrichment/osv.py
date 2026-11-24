"""Anreicherung von Abhängigkeits-Funden mit Schweregrad-Daten aus OSV.

pip-audit meldet bekannte Schwachstellen in Paketen, liefert aber keinen
Schweregrad (siehe `_parse_pip_audit`). Die öffentliche Datenbank OSV
(https://osv.dev) kennt zu vielen dieser Schwachstellen einen. Dieses
Modul fragt sie ab und trägt das Ergebnis in zusätzliche Felder des
`Finding` ein.

Design-Entscheidungen:
- Der Weg führt meist über einen Alias. pip-audit meldet PYSEC-IDs, und
  PYSEC-Einträge tragen oft keinen Schweregrad. Sie verweisen aber über
  `aliases` auf GHSA-Einträge (GitHub Advisory Database), und die liefern
  ihn. Es wird genau ein Sprung gemacht, ohne Rekursion.
- Kein CVSS-Rechner: Der Schweregrad kommt als Wort aus
  `database_specific.severity`. Der CVSS-Vektor wird unverändert
  mitgeführt, damit die Einstufung nachprüfbar bleibt.
- `finding.severity`, `finding.cwe` und `finding.confidence` bleiben
  unangetastet. Das Pre-Filter-Modell nutzt sie als Merkmale (siehe
  `src/prefilter/features.py`); würden sie nachträglich überschrieben,
  sähe das Modell Kombinationen, die es im Training nie gesehen hat
  ("training/serving skew"). Die Ergebnisse stehen deshalb in eigenen
  Feldern.
- Best-effort und fail-open wie Pre-Filter und Monitoring: Kein Netz, eine
  Zeitüberschreitung, ein HTTP-Fehler oder ein unerwartetes Format lassen
  den Fund unverändert. Nichts in diesem Modul wirft nach außen.
- Die Antworten kommen von außen und werden nicht vertraut: IDs und
  Vektoren werden gegen feste Muster geprüft, bevor sie in eine URL oder
  einen Prompt gelangen, Umleitungen werden nicht verfolgt, die
  Antwortgröße ist begrenzt.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.monitoring import metrics as m
from src.scanner_agent.models import Finding, Severity, ToolName

logger = logging.getLogger(__name__)

OSV_BASE_URL = "https://api.osv.dev/v1/vulns/"
ENABLED_ENV = "VULNSCOUT_OSV_ENABLED"

# Zeitgrenze je Anfrage und für die gesamte Stufe. Danach bleiben die
# restlichen Funde unangereichert - der Scan wird dadurch nie blockiert.
# Eine Abfrage dauert aus einem Container gemessen 1 bis 3 Sekunden, ein
# Fund braucht bis zu drei (ID plus zwei Aliase). Deshalb wird parallel
# abgefragt (MAX_WORKERS); nacheinander reichte schon ein Zeitbudget von
# 20 Sekunden nicht für die 26 IDs des Testrepositories.
REQUEST_TIMEOUT_SECONDS = 5
TOTAL_BUDGET_SECONDS = 30
MAX_RESPONSE_BYTES = 1_000_000
MAX_WORKERS = 8

# Zwischenspeicher im Prozess: bereits aufgelöste IDs werden nicht erneut
# abgefragt (wiederholte Scans desselben Repositories, weniger Last für OSV).
# Gespeichert werden Ergebnisse und "kein Eintrag", nie ein Ausfall.
CACHE_TTL_SECONDS = 3600
CACHE_MAX_ENTRIES = 2000

# Höchstens so viele GHSA-Aliase werden je Fund nachgeschlagen.
MAX_ALIAS_LOOKUPS = 2

_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_CWE_PATTERN = re.compile(r"CWE-[0-9]{1,5}")
# CVSS-Vektoren: V3/V4 beginnen mit "CVSS:<Version>/", V2 nicht. Danach
# folgen Paare aus Kürzel und Wert, getrennt durch "/".
_VECTOR_PATTERN = re.compile(
    r"(?:CVSS:[0-9.]{1,5}/)?[A-Za-z]{1,4}:[A-Za-z0-9]{1,4}"
    r"(?:/[A-Za-z]{1,4}:[A-Za-z0-9]{1,4}){1,20}"
)

# GitHub schreibt "MODERATE", wo andere "MEDIUM" schreiben.
_SEVERITY_WORDS = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}
# Bevorzugte Reihenfolge, falls ein Eintrag mehrere Vektoren trägt.
_VECTOR_TYPES = ("CVSS_V3", "CVSS_V4", "CVSS_V2")


class OsvUnavailable(Exception):
    """OSV war nicht verwertbar erreichbar (Netz, Zeitlimit, Serverfehler,
    unlesbare Antwort). Unterscheidet sich bewusst von "ID unbekannt":
    Das ist ein normales Ergebnis und kein Ausfall."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Folgt keinen Umleitungen: Die Adresse ist fest, eine Umleitung auf
    einen anderen Host wäre unerwartet und wird wie ein Fehler behandelt."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch_record(
    vuln_id: str, timeout: float = REQUEST_TIMEOUT_SECONDS
) -> Optional[dict]:
    """Holt einen OSV-Eintrag.

    Returns:
        Den Eintrag als Dict, oder `None`, wenn die ID ungültig oder bei
        OSV unbekannt ist.

    Raises:
        OsvUnavailable: bei Netz-, Zeitlimit- oder Serverproblemen und
            bei unlesbaren Antworten.
    """
    if not _ID_PATTERN.fullmatch(vuln_id):
        return None

    request = urllib.request.Request(
        OSV_BASE_URL + urllib.parse.quote(vuln_id, safe=""),
        headers={"Accept": "application/json", "User-Agent": "vulnscout"},
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:  # vor URLError, ist dessen Unterklasse
        if exc.code in (400, 404, 410):
            return None
        raise OsvUnavailable(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OsvUnavailable(type(exc).__name__) from exc

    if len(raw) > MAX_RESPONSE_BYTES:
        raise OsvUnavailable("Antwort zu groß")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise OsvUnavailable("kein gültiges JSON") from exc
    if not isinstance(data, dict):
        raise OsvUnavailable("unerwartetes Format")
    return data


@dataclass
class _OsvInfo:
    """Das aus einem OSV-Eintrag Verwertbare, bereits geprüft."""

    severity: Optional[Severity] = None
    vector: Optional[str] = None
    cwe_ids: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)


def _extract(record: dict) -> _OsvInfo:
    """Liest Schweregrad, Vektor, CWEs und Aliase aus einem OSV-Eintrag.

    Alles, was nicht dem erwarteten Muster entspricht, wird verworfen
    statt übernommen - die Werte landen später in Prompts und Berichten.
    """
    info = _OsvInfo()

    database_specific = record.get("database_specific")
    if isinstance(database_specific, dict):
        word = database_specific.get("severity")
        if isinstance(word, str):
            info.severity = _SEVERITY_WORDS.get(word.strip().upper())
        cwe_ids = database_specific.get("cwe_ids")
        if isinstance(cwe_ids, list):
            info.cwe_ids = [
                c for c in cwe_ids if isinstance(c, str) and _CWE_PATTERN.fullmatch(c)
            ]

    entries = record.get("severity")
    if isinstance(entries, list):
        by_type = {
            e.get("type"): e.get("score") for e in entries if isinstance(e, dict)
        }
        for vector_type in _VECTOR_TYPES:
            score = by_type.get(vector_type)
            if isinstance(score, str) and _VECTOR_PATTERN.fullmatch(score):
                info.vector = score
                break

    aliases = record.get("aliases")
    if isinstance(aliases, list):
        info.aliases = [
            a for a in aliases if isinstance(a, str) and _ID_PATTERN.fullmatch(a)
        ]

    return info


@dataclass
class _Resolved:
    info: _OsvInfo
    source_id: str


def _resolve(
    vuln_id: str, fetch: Callable[[str], Optional[dict]]
) -> Optional[_Resolved]:
    """Ermittelt zu `vuln_id` den besten verfügbaren Eintrag: erst die ID
    selbst, dann deren GHSA-Aliase. Bevorzugt wird ein Eintrag mit
    Schweregrad-Wort, danach einer mit wenigstens einem Vektor.

    Raises:
        OsvUnavailable: wird durchgereicht, damit der Aufrufer abbrechen kann.
    """
    record = fetch(vuln_id)
    if record is None:
        return None

    first = _extract(record)
    candidates = [_Resolved(first, vuln_id)]
    if first.severity is None:
        ghsa_aliases = [a for a in first.aliases if a.startswith("GHSA-")]
        for alias in ghsa_aliases[:MAX_ALIAS_LOOKUPS]:
            alias_record = fetch(alias)
            if alias_record is None:
                continue
            candidates.append(_Resolved(_extract(alias_record), alias))
            if candidates[-1].info.severity is not None:
                break

    best = next((c for c in candidates if c.info.severity is not None), None)
    if best is None:
        best = next((c for c in candidates if c.info.vector is not None), None)
    if best is None:
        return None
    # Die Aliase stammen immer vom ursprünglich abgefragten Eintrag.
    return _Resolved(
        _OsvInfo(
            severity=best.info.severity,
            vector=best.info.vector,
            cwe_ids=best.info.cwe_ids,
            aliases=first.aliases,
        ),
        best.source_id,
    )


_cache: dict[str, tuple[float, Optional[_Resolved]]] = {}
_cache_lock = threading.Lock()


def clear_cache() -> None:
    """Leert den Zwischenspeicher (für Tests)."""
    with _cache_lock:
        _cache.clear()


def _cache_get(vuln_id: str, now: float) -> tuple[bool, Optional[_Resolved]]:
    with _cache_lock:
        entry = _cache.get(vuln_id)
        if entry is None:
            return False, None
        stored_at, value = entry
        if now - stored_at > CACHE_TTL_SECONDS:
            del _cache[vuln_id]
            return False, None
        return True, value


def _cache_put(vuln_id: str, value: Optional[_Resolved], now: float) -> None:
    with _cache_lock:
        if len(_cache) >= CACHE_MAX_ENTRIES and vuln_id not in _cache:
            # Einfachste Verdrängung: ältesten Eintrag entfernen.
            oldest = min(_cache, key=lambda k: _cache[k][0])
            del _cache[oldest]
        _cache[vuln_id] = (now, value)


def _is_enabled() -> bool:
    return os.environ.get(ENABLED_ENV, "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _count(result: str, n: int) -> None:
    try:
        m.OSV_ENRICHMENT.labels(result=result).inc(n)
    except Exception:  # noqa: BLE001 - Monitoring darf nie durchschlagen
        logger.exception("OSV-Metrik konnte nicht geschrieben werden")


def enrich_findings(
    findings: list[Finding],
    fetch: Callable[[str], Optional[dict]] = fetch_record,
    clock: Callable[[], float] = time.monotonic,
    max_workers: int = MAX_WORKERS,
) -> None:
    """Reichert die pip-audit-Funde in `findings` an Ort und Stelle an.

    Ändert nur die Felder `osv_severity`, `cvss_vector`, `osv_cwe_ids`,
    `osv_aliases` und `severity_source`. Wirft nie: Jeder Fehler lässt die
    betroffenen Funde unverändert (siehe Modul-Docstring).

    Args:
        findings: Die Funde eines Scan-Laufs. Funde anderer Werkzeuge
            werden nicht angefasst.
        fetch: Abruffunktion für einen OSV-Eintrag. Austauschbar, damit
            Tests ohne Netz laufen.
        clock: Zeitquelle für das Zeitbudget, ebenfalls für Tests.
        max_workers: Zahl paralleler Abfragen (1 = nacheinander).
    """
    if not _is_enabled():
        return

    try:
        targets = [
            f
            for f in findings
            if f.tool == ToolName.PIP_AUDIT and f.rule_id and f.rule_id != "UNKNOWN"
        ]
        if not targets:
            return

        started = clock()

        def budgeted_fetch(vuln_id: str) -> Optional[dict]:
            if clock() - started > TOTAL_BUDGET_SECONDS:
                raise OsvUnavailable("Zeitbudget der Anreicherung überschritten")
            return fetch(vuln_id)

        # Je ID nur einmal abfragen: pip-audit meldet dieselbe ID mehrfach.
        # Schon bekannte IDs kommen aus dem Zwischenspeicher.
        resolved: dict[str, Optional[_Resolved]] = {}
        to_fetch: list[str] = []
        for rule_id in dict.fromkeys(f.rule_id for f in targets):
            hit, cached = _cache_get(rule_id, started)
            if hit:
                resolved[rule_id] = cached
            else:
                to_fetch.append(rule_id)

        lock = threading.Lock()
        state = {"unavailable": False}

        def work(rule_id: str) -> None:
            # Ab dem ersten Ausfall nicht weiter versuchen: Ein totes Netz
            # würde sonst jede weitere Anfrage ins Zeitlimit laufen lassen.
            # Bereits laufende Abfragen werden zu Ende geführt.
            if state["unavailable"]:
                return
            try:
                result = _resolve(rule_id, budgeted_fetch)
            except OsvUnavailable as exc:
                with lock:
                    if not state["unavailable"]:
                        state["unavailable"] = True
                        logger.warning(
                            "OSV nicht verwertbar erreichbar (%s) - "
                            "restliche Funde bleiben unangereichert.",
                            exc,
                        )
                return
            with lock:
                resolved[rule_id] = result
            _cache_put(rule_id, result, clock())

        if to_fetch:
            workers = max(1, min(max_workers, len(to_fetch)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                # list() holt auch unerwartete Fehler aus den Arbeitern ab;
                # sie werden vom äußeren try/except aufgefangen.
                list(pool.map(work, to_fetch))

        n_enriched = n_no_data = n_unavailable = 0
        for finding in targets:
            if finding.rule_id not in resolved:
                n_unavailable += 1
                continue
            result = resolved[finding.rule_id]
            if result is None:
                n_no_data += 1
                continue
            finding.cvss_vector = result.info.vector
            finding.osv_cwe_ids = list(result.info.cwe_ids)
            finding.osv_aliases = list(result.info.aliases)
            if result.info.severity is not None:
                finding.osv_severity = result.info.severity
                finding.severity_source = f"osv:{result.source_id}"
                n_enriched += 1
            else:
                n_no_data += 1

        for label, count in (
            ("enriched", n_enriched),
            ("no_data", n_no_data),
            ("unavailable", n_unavailable),
        ):
            if count:
                _count(label, count)
    except Exception:  # noqa: BLE001 - best effort, siehe Modul-Docstring
        logger.exception("OSV-Anreicherung fehlgeschlagen - Funde bleiben unverändert.")
