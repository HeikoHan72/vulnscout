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
         → Triage-Agent (LLM: Fehlalarm-Filter, Schweregrad, Consensus bei Unsicherheit)
           [ohne API-Key: Demo-/Fixture-Modus statt LLM]
         → Report-Agent (LLM: Bericht + Fix-Vorschläge)
           [ohne API-Key: Demo-/Fixture-Modus statt LLM]
         → Orchestrator (SQLite-Persistenz je Schritt, crash-resilient)
         → MLflow (Tracking von Parametern, Metriken, Artefakten – best-effort)
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

Erfasst werden die vier goldenen Signale (Verkehr, Fehler, Latenz, Sättigung) sowie fachliche Kennzahlen: Scans nach Ergebnis und Dauer, Funde je Scanner, Scanner-Ausfälle, Triage-Ergebnisse (bestätigt, Fehlalarm, kein Konsens), Verteilung der Triage-Konfidenz, Latenz und Fehler des Sprachmodells. Alarmregeln liegen in [`monitoring/alerts.yml`](monitoring/alerts.yml).

Besonders relevant ist der Alarm `ScannerFaelltAus`: Ein ausgefallenes Scanner-Werkzeug liefert keine Funde – im Bericht sieht das aus wie eine saubere Codebasis. Das Monitoring macht den Unterschied sichtbar.

**Einschränkung:** Die Kennzahlen leben im Arbeitsspeicher des API-Prozesses. Nur Läufe über `POST /scans` erscheinen unter `/metrics`; ein direkt per Kommandozeile gestarteter Lauf nicht.

`docker compose up` also starts Prometheus and Grafana alongside the API (ports 9090 and 3000). Metrics cover the four golden signals plus domain metrics: scans by outcome and duration, findings per scanner, scanner failures, triage outcomes, triage-confidence distribution, and LLM latency and errors. Note that metrics live in the API process, so only runs started via `POST /scans` are recorded.

## Tech-Stack

- Scanning: Bandit, pip-audit, Semgrep
- LLM: Anthropic SDK (Claude Sonnet 5), strukturierte Ausgabe über Tool-Use
- API: FastAPI
- Tracking: MLflow (lokaler File-Store, kein externer Server nötig)
- Container: Docker, Docker Compose
- CI: GitHub Actions, pytest
- Persistenz: SQLite

## Evaluation

Getestet an:
- OWASP PyGoat
- Vulnerable Flask App
- eigenem Dummy-Repo mit bekannter Ground Truth (`test_repos/dummy_vuln_repo`) – deckt u. a. SQL-Injection, Command Injection, Code Injection (eval/exec), SSTI, SSRF, XXE, Insecure Deserialization, Path Traversal, schwache Kryptografie, unsicheren Zufall, unsicheres YAML-Laden und verwundbare Dependencies ab, inklusive bewusst mehrdeutiger Fälle (z. B. `shell=True` mit hartcodiertem statt benutzergesteuertem Befehl) zum Testen des Triage-Consensus-Mechanismus

Ergebnisse (Precision/Recall) folgen in diesem README, sobald die Evaluation abgeschlossen ist.

## Limitations

*Wird nach Projektabschluss ehrlich ausgefüllt – u. a. Umfang der Evaluation, bekannte Fehlalarme/Fehlklassifikationen, Grenzen des LLM-Ansatzes.*

*Filled in honestly after project completion – including evaluation scope, known false positives/misclassifications, limits of the LLM approach.*

## KI-Einsatz / AI usage

Dieses Projekt wurde mit Unterstützung von Claude (Architektur, Code-Review, Dokumentation) entwickelt. Details folgen hier nach Projektabschluss.

This project was developed with assistance from Claude (architecture, code review, documentation). Details to follow after project completion.

## Lizenz / License

TBD
