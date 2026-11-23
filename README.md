# VulnScout

**Status: in Entwicklung (Abschlussprojekt Modul 6 – AI Engineer Lehrgang, MLOps & Deployment)**

Multi-Agenten-System, das Code-Repositories automatisch auf Sicherheitslücken scannt, die Funde mit einem LLM bewertet (Fehlalarme filtert, Schweregrad einstuft) und einen lesbaren Bericht mit Fix-Vorschlägen erstellt.

Multi-agent system that scans code repositories for security vulnerabilities, uses an LLM to triage the findings (filtering false positives, scoring severity) and produces a readable report with fix suggestions.

## Schnellstart / Quickstart

```bash
cp .env.example .env
# ANTHROPIC_API_KEY in .env eintragen (optional, siehe Demo-Modus unten)
docker compose up
```

API-Doku / API docs: http://localhost:8000/docs

**Demo-Modus / Demo mode:** Ohne `ANTHROPIC_API_KEY` läuft das System automatisch im Demo-/Fixture-Modus – deterministische Triage- und Report-Ergebnisse ohne LLM-Aufruf, sodass jeder das Projekt ohne eigenen API-Key ausprobieren kann. Der Modus lässt sich über `demo_mode: true/false` im `POST /scans`-Request auch explizit erzwingen.

Without an `ANTHROPIC_API_KEY`, the system automatically runs in demo/fixture mode – deterministic triage and report results with no LLM call, so anyone can try the project without their own API key. The mode can also be forced explicitly via `demo_mode: true/false` in the `POST /scans` request.

## Architektur / Architecture

```
Zielrepo → Scanner-Agent (Bandit, pip-audit, Semgrep)
         → Pre-Filter (ML-Modell aus MLflow Model Registry: entscheidet eindeutige
           Funde ohne LLM-Aufruf, Rest geht weiter – Kostenersparnis, siehe unten)
         → Triage-Agent (LLM: Fehlalarm-Filter, Schweregrad, Consensus bei Unsicherheit)
           [ohne API-Key: Demo-/Fixture-Modus statt LLM]
         → Report-Agent (LLM: Bericht + Fix-Vorschläge)
           [ohne API-Key: Demo-/Fixture-Modus statt LLM]
         → Orchestrator (SQLite-Persistenz je Schritt, crash-resilient)
         → MLflow (Tracking + Model Registry mit Champion/Challenger – best-effort)
         → FastAPI (REST-Schnittstelle, /metrics für Prometheus)
         → Prometheus + Grafana (Monitoring im laufenden Betrieb)
```

Details: [docs/architecture.md](docs/architecture.md)

## Monitoring

`docker compose up` startet neben der API auch Prometheus und Grafana:

| Dienst | Adresse | Zweck |
|---|---|---|
| API | http://localhost:8000/docs | Scans starten, Berichte abrufen |
| Prometheus | http://localhost:9090 | Kennzahlen abfragen, Alarmregeln prüfen |
| Grafana | http://localhost:3000 | Dashboard (ohne Anmeldung) |

Erfasst werden die vier goldenen Signale (Verkehr, Fehler, Latenz, Sättigung) sowie fachliche Kennzahlen: Scans nach Ergebnis und Dauer, Funde je Scanner, Scanner-Ausfälle, Triage-Ergebnisse (bestätigt, Fehlalarm, kein Konsens), Verteilung der Triage-Konfidenz, Latenz und Fehler des Sprachmodells, sowie Pre-Filter-Entscheidungen (automatisch bestätigt/verworfen, eskaliert, eingesparte LLM-Aufrufe). Alarmregeln liegen in [`monitoring/alerts.yml`](monitoring/alerts.yml).

Besonders relevant ist der Alarm `ScannerFaelltAus`: Ein ausgefallenes Scanner-Werkzeug liefert keine Funde – im Bericht sieht das aus wie eine saubere Codebasis. Das Monitoring macht den Unterschied sichtbar.

**Einschränkung:** Die Kennzahlen leben im Arbeitsspeicher des API-Prozesses. Nur Läufe über `POST /scans` erscheinen unter `/metrics`; ein direkt per Kommandozeile gestarteter Lauf nicht.

`docker compose up` also starts Prometheus and Grafana alongside the API (ports 9090 and 3000). Metrics cover the four golden signals plus domain metrics: scans by outcome and duration, findings per scanner, scanner failures, triage outcomes, triage-confidence distribution, and LLM latency and errors. Note that metrics live in the API process, so only runs started via `POST /scans` are recorded.

## Pre-Filter-Modell / Kostenersparnis

Nicht jeder Scanner-Fund braucht einen LLM-Aufruf: Ein von pip-audit gemeldetes CVE ist praktisch immer ein echter Fund, ein Bandit-Treffer auf einen reinen Import praktisch immer ein Fehlalarm. Ein trainiertes Pre-Filter-Modell (`scripts/train_prefilter.py`) entscheidet solche eindeutigen Fälle direkt aus den Scanner-Merkmalen – ohne API-Aufruf – und reicht nur unsichere Fälle an die LLM-Triage weiter. Details zur Methodik (Repo-weiser Split, Qualitäts-Gate, Champion/Challenger in der MLflow Model Registry) stehen in [docs/architecture.md](docs/architecture.md#pre-filter-modell-srcprefilter-scriptstrain_prefilterpy).

**Wichtig, offen benannt:** Die Trainingslabels stammen vom Triage-Agenten (LLM) selbst, nicht von menschlicher Ground Truth – das Modell destilliert also das LLM-Urteil, es lernt nicht unabhängig "echte" Schwachstellen zu erkennen. Die unten berichtete Fehlerrate ist eine Abweichung vom LLM-Urteil, keine Abweichung von der Wahrheit.

Trainiert auf 3004 realen Scanner-Funden aus 6 Repositories (3 bewusst verwundbare: eigenes Dummy-Repo, OWASP PyGoat, DVPWA; 3 saubere Open-Source-Bibliotheken als Negativbeispiele: Vulnerable-Flask-App, `requests`, `click`). `Vulnerable-Flask-App` und `click` wurden beim Training nie gesehen (repo-weiser Split, Testdaten).

| Kennzahl | Wert |
|---|---|
| Champion-Modell | Random Forest (Challenger: Logistic Regression) |
| Abdeckung auf Test-Repos (automatisch entschieden, kein LLM-Aufruf) | **96,4 %** |
| Fehlerrate ggü. LLM-Urteil (bei den automatisch entschiedenen Funden) | 0,13 % |
| Qualitäts-Gate | < 2 % Fehlerrate – bestanden |
| Trainingsdaten / Testdaten | 1402 / 1602 Zeilen |

96,4 % der Funde auf den beiden nie gesehenen Test-Repos wurden ohne jeden LLM-Aufruf korrekt entschieden – nur die restlichen ~3,6 % (die unklaren Fälle) gingen an die Triage. Bei einer gemessenen Kostenbasis von ca. 0,004 $ pro LLM-bewertetem Fund bedeutet das für einen Lauf mit z. B. 1000 Funden: statt ~4 $ für die volle LLM-Triage nur noch ~0,15 $ für die eskalierten Fälle.

96.4% of findings on the two held-out test repos were decided correctly without any LLM call - only the remaining ~3.6% (the genuinely unclear cases) were escalated to the triage agent.

## Tech-Stack

- Scanning: Bandit, pip-audit, Semgrep
- LLM: Anthropic SDK (Claude Sonnet 5), strukturierte Ausgabe über Tool-Use
- Pre-Filter-Modell: scikit-learn (Logistic Regression / Random Forest), MLflow Model Registry (Champion/Challenger)
- API: FastAPI
- Tracking: MLflow (Experiment-Tracking + Model Registry)
- Monitoring: Prometheus, Grafana
- Container: Docker, Docker Compose
- CI: GitHub Actions, pytest (inkl. Qualitäts-Gate für das Pre-Filter-Modell)
- Persistenz: SQLite

## Evaluation

Getestet an:
- OWASP PyGoat
- Vulnerable Flask App
- DVPWA
- eigenem Dummy-Repo mit bekannter Ground Truth (`test_repos/dummy_vuln_repo`) – deckt u. a. SQL-Injection, Command Injection, Code Injection (eval/exec), SSTI, SSRF, XXE, Insecure Deserialization, Path Traversal, schwache Kryptografie, unsicheren Zufall, unsicheres YAML-Laden und verwundbare Dependencies ab, inklusive bewusst mehrdeutiger Fälle (z. B. `shell=True` mit hartcodiertem statt benutzergesteuertem Befehl) zum Testen des Triage-Consensus-Mechanismus

**Precision/Recall gegen echte Ground Truth** (`test_repos/dummy_vuln_repo/ground_truth.yml`, 17 bekannte Schwachstellenklassen + mehrdeutige Fälle + sichere Gegenbeispiele), gemessen mit `scripts/evaluate.py` an einem echten Lauf (Scanner → Pre-Filter → LLM-Triage, kein Demo-Modus). Zuordnung Fund → Ground-Truth-Eintrag über den Syntaxbaum, robust gegen Zeilenverschiebungen.

| Bereich | Precision | Recall | F1 | richtig bestätigt | fälschlich bestätigt | richtig verworfen |
|---|---|---|---|---|---|---|
| Code-Funde | 91,9 % | 100 % | 95,8 % | 34 | 3 | 5 |
| Abhängigkeiten (pip-audit) | 100 % | 100 % | 100 % | 51 | 0 | 0 |

Precision/Recall against real ground truth, measured end-to-end (scanners → pre-filter → LLM triage, real LLM calls, no demo mode). Reproducible with `python scripts/evaluate.py --db vulnscout.db` after a real run against `test_repos/dummy_vuln_repo`.

Zusätzlich wurden 6 Repositories (die vier oben plus `requests` und `click`) vollständig gescannt und von der LLM-Triage bewertet – **3.004 Funde**, als Trainingsdatensatz für das Pre-Filter-Modell (`scripts/training_data.jsonl`, siehe oben). Hier gilt die LLM-Bewertung selbst als Zielgröße, nicht als unabhängige Ground Truth – die Distillation lernt, was das LLM sagen würde, nicht was objektiv wahr ist.

## Limitations

- **Scanner-Abdeckung ist unvollständig:** Von 17 bekannten Schwachstellen im Ground-Truth-Repo haben Bandit und Semgrep (Regelwerk `p/security-audit`) 3 nie gemeldet – Path Traversal, SSRF und ein hartcodiertes Secret in der Config. Die LLM-Triage bewertet nur, was mindestens ein Scanner findet; sie meldet nichts selbst. **Ursache:** Beide Scanner arbeiten musterbasiert, nicht mit Datenfluss-/Taint-Analyse – SSRF und Path Traversal erfordern aber, Benutzereingaben über mehrere Zeilen bis zum gefährlichen Aufruf zu verfolgen. **Mögliche Abhilfe (nicht umgesetzt, Zeitrahmen des Projekts):** breiteres Semgrep-Regelwerk (z. B. `p/owasp-top-ten`) oder ein Tool mit echter Taint-Analyse (Semgrep Pro, CodeQL) ergänzen.
- **LLM-Triage ist nicht fehlerfrei:** 3 von 8 bewusst mehrdeutigen Fällen (z. B. harmloses `shell=True` ohne Benutzereingabe) wurden fälschlich als echte Schwachstelle bestätigt – daher 91,9 % statt 100 % Precision bei Code-Funden.
- **Pre-Filter-Modell ist Distillation, keine unabhängige Verifikation:** Es lernt, die LLM-Bewertung vorherzusagen, nicht die Wahrheit selbst. Ein systematischer Fehler der LLM-Triage würde vom Pre-Filter übernommen statt korrigiert.
- **Trainingsdatensatz für den Pre-Filter ist klein und Python-only:** 3.004 Funde aus 6 Repositories, ausschließlich Python. Für andere Sprachen oder stark abweichende Codebasen ist keine Aussage über die Pre-Filter-Qualität möglich.
- **Kein Alertmanager:** Die 7 Prometheus-Alarmregeln werden ausgewertet, aber nicht versendet – nur in der Prometheus-Oberfläche sichtbar.
- **Kein asynchrones Scanning:** `POST /scans` läuft synchron, ein Scan pro Request.
- **Bekannte API-Einschränkung:** Bei Fehlschlag von `POST /scans` fehlt die Lauf-ID in der Fehlerantwort.

*English summary: scanner coverage is incomplete (3 of 17 known vulnerabilities were never flagged by Bandit/Semgrep, because both are pattern-based rather than taint-analysis tools; a broader ruleset or a taint-analysis tool such as Semgrep Pro or CodeQL would address this but was out of scope given the project timeline); LLM triage misclassified 3 of 8 deliberately ambiguous cases (91.9% precision on code findings); the pre-filter model is a distillation of LLM judgment, not independent ground truth, so it inherits any systematic LLM bias; its training data (3,004 findings, 6 repos) is Python-only; no Alertmanager wiring; scanning is synchronous; a failed `POST /scans` doesn't return a run id.*

## KI-Einsatz / AI usage

Dieses Projekt wurde mit Unterstützung von Claude (Architektur, Code-Review, Dokumentation) entwickelt. Details folgen hier nach Projektabschluss.

This project was developed with assistance from Claude (architecture, code review, documentation). Details to follow after project completion.

## Lizenz / License

MIT – siehe [LICENSE](LICENSE).
