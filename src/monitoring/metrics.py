"""Kennzahlen (Metriken) für das Monitoring mit Prometheus.

Prometheus holt diese Zahlen regelmäßig über den Endpunkt `/metrics` ab
("scrapen"). Zwei Arten kommen vor:

* **Counter** zählt nur nach oben (Anzahl Scans, Anzahl Fehler). Für sich
  allein wenig aussagekräftig - Prometheus rechnet daraus die Rate, also
  "wie viele pro Sekunde gerade".
* **Histogram** sortiert Messwerte in Eimer (Buckets), etwa Laufzeiten.
  Daraus berechnet Prometheus Quantile wie p50 oder p95.

**Labels** teilen eine Metrik auf (z. B. nach Tool oder Schweregrad). Jede
Kombination ist eine eigene Zeitreihe, deshalb dürfen Labels nur wenige
verschiedene Werte annehmen - niemals etwa eine Lauf-ID, sonst wächst die
Zahl der Zeitreihen unbegrenzt.

Wichtige Einschränkung: Diese Zähler leben im Arbeitsspeicher des Prozesses,
der die API bedient. Nur Läufe über `POST /scans` erscheinen daher unter
`/metrics`; ein Lauf, der direkt per Kommandozeile gestartet wird, läuft in
einem eigenen Prozess und taucht hier nicht auf.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

# --- HTTP: die goldenen Signale (Verkehr, Fehler, Latenz) --------------------

HTTP_REQUESTS = Counter(
    "vulnscout_http_requests_total",
    "Anzahl HTTP-Anfragen",
    ["path", "method", "status"],
)

HTTP_LATENCY = Histogram(
    "vulnscout_http_latency_seconds",
    "Antwortzeit der API in Sekunden",
    ["path"],
    # Breite Spanne: /health antwortet in Millisekunden, ein vollständiger
    # Scan über POST /scans läuft synchron und kann Minuten dauern.
    buckets=[0.005, 0.025, 0.1, 0.5, 1, 5, 15, 30, 60, 120, 300, 600],
)

# --- Scans: Durchsatz, Dauer, Ausgang ----------------------------------------

SCANS = Counter(
    "vulnscout_scans_total",
    "Abgeschlossene Scan-Läufe nach Ergebnis",
    ["status"],  # completed, failed
)

SCAN_DURATION = Histogram(
    "vulnscout_scan_duration_seconds",
    "Dauer eines vollständigen Scan-Laufs in Sekunden",
    buckets=[5, 15, 30, 60, 120, 300, 600, 1200],
)

SCAN_MODE = Counter(
    "vulnscout_scan_mode_total",
    "Scan-Läufe nach Betriebsart",
    ["mode"],  # demo, llm
)

# --- Scanner: was die Werkzeuge gefunden haben -------------------------------

FINDINGS = Counter(
    "vulnscout_findings_total",
    "Rohe Scanner-Funde nach Werkzeug",
    ["tool"],  # bandit, pip-audit, semgrep
)

SCANNER_ERRORS = Counter(
    "vulnscout_scanner_errors_total",
    "Fehlgeschlagene Scanner-Aufrufe nach Werkzeug",
    ["tool"],
)

# --- Triage: wie das LLM die Funde bewertet ----------------------------------

TRIAGE_RESULTS = Counter(
    "vulnscout_triage_results_total",
    "Bewertete Funde nach Ergebnis der Triage",
    ["result"],  # true_positive, false_positive, needs_review
)

CONFIRMED_BY_SEVERITY = Counter(
    "vulnscout_confirmed_findings_total",
    "Bestätigte Funde nach Schweregrad",
    ["severity"],
)

TRIAGE_CONFIDENCE = Histogram(
    "vulnscout_triage_confidence",
    "Konfidenz der Triage-Bewertung",
    # Die Schwelle für den Consensus-Check liegt bei 0,6 - deshalb liegen
    # mehrere Eimergrenzen bewusst um diesen Wert herum.
    buckets=[0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0],
)

# --- LLM: wie es dem Sprachmodell geht ---------------------------------------

LLM_REQUESTS = Counter(
    "vulnscout_llm_requests_total",
    "Aufrufe des Sprachmodells nach Ergebnis",
    ["result"],  # ok, retry, failed
)

LLM_ERRORS = Counter(
    "vulnscout_llm_errors_total",
    "Fehler beim Aufruf des Sprachmodells nach Art",
    ["kind"],  # z. B. APIConnectionError, RateLimitError
)

LLM_LATENCY = Histogram(
    "vulnscout_llm_latency_seconds",
    "Antwortzeit eines einzelnen LLM-Aufrufs in Sekunden",
    buckets=[0.5, 1, 2, 5, 10, 20, 30, 60, 120],
)

# --- Pre-Filter: wie viele Funde ohne LLM-Aufruf entschieden werden ---------
#
# Das Pre-Filter-Modell (siehe scripts/train_prefilter.py) entscheidet einen
# Teil der Funde selbst (true_positive/false_positive) und eskaliert den
# Rest ans LLM, wenn es sich nicht sicher genug ist. "escalated" zählt also
# weiterhin ganz normal in LLM_REQUESTS oben; diese Metrik misst nur, wie
# viel Arbeit dem LLM dadurch abgenommen wird - die Kennzahl für die
# Kostenersparnis.

PREFILTER_DECISIONS = Counter(
    "vulnscout_prefilter_decisions_total",
    "Entscheidungen des Pre-Filter-Modells vor der LLM-Triage",
    ["result"],  # auto_confirmed, auto_rejected, escalated, unavailable
)

PREFILTER_SKIPPED_LLM_CALLS = Counter(
    "vulnscout_prefilter_skipped_llm_calls_total",
    "Geschätzte Anzahl eingesparter LLM-Aufrufe durch das Pre-Filter-Modell",
)

# --- OSV-Anreicherung: Schweregrad für Abhängigkeits-Funde -------------------
#
# pip-audit liefert keinen Schweregrad; die Anreicherung (siehe
# src/enrichment/osv.py) holt ihn aus der Datenbank OSV. Gezählt werden
# Funde, nicht Anfragen. "unavailable" steigt, wenn OSV nicht erreichbar
# war - die Funde laufen dann unverändert weiter.

OSV_ENRICHMENT = Counter(
    "vulnscout_osv_enrichment_total",
    "Abhängigkeits-Funde nach Ergebnis der OSV-Anreicherung",
    ["result"],  # enriched, no_data, unavailable
)

# --- Untergrenze aus OSV: wie oft die Triage nach oben korrigiert wird -------
#
# Bestätigte Abhängigkeits-Funde werden nach der Triage mindestens auf den
# OSV-Schweregrad angehoben (siehe src/enrichment/floor.py). "raised" zählt die
# Funde, bei denen die Einstufung der Triage darunter lag, "unchanged" die,
# bei denen sie schon mindestens so hoch war.

SEVERITY_FLOOR = Counter(
    "vulnscout_severity_floor_total",
    "Bestätigte Abhängigkeits-Funde nach Anwendung der OSV-Untergrenze",
    ["result"],  # raised, unchanged
)
