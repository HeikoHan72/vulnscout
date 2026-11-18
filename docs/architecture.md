# VulnScout – Architektur

## Überblick

VulnScout scannt ein beliebiges lokales Code-Repository auf Sicherheitslücken, bewertet die Funde (Fehlalarm-Filter, Schweregrad) und erstellt daraus einen lesbaren Bericht mit Fix-Vorschlägen. Das System besteht aus drei Agenten, die von einem Orchestrator verbunden werden, sowie einer FastAPI-Schnittstelle, Containerisierung und CI.

```
Zielrepo
   │
   ▼
Scanner-Agent  (Bandit, pip-audit, Semgrep – deterministisch, kein LLM)
   │  Finding-Liste (einheitliches Format)
   ▼
Triage-Agent   (LLM: Fehlalarm-Filter, Schweregrad, Consensus-Check bei Unsicherheit)
   │  TriageAssessment-Liste
   ▼
Report-Agent   (LLM: ein Bericht für den ganzen Lauf, Zahlen fest vorgegeben)
   │  Markdown-Bericht
   ▼
Orchestrator   (verbindet alle Schritte, persistiert Zwischenstände, protokolliert per MLflow)
   │
   ▼
FastAPI-Endpunkt (POST /scans, GET /scans/{id}, GET /scans/{id}/report, GET /health)
```

Scanner-, Triage- und Report-Agent sind reine Python-Funktionen ohne eigenen Zustand; der Zustand eines Laufs (welcher Schritt ist abgeschlossen, welche Funde/Bewertungen liegen vor) lebt ausschließlich im Orchestrator und in der SQLite-Datenbank.

## Komponenten

### Scanner-Agent (`src/scanner_agent/`)

Führt drei etablierte Open-Source-Scanner aus und übersetzt ihre Ausgaben in ein einheitliches `Finding`-Format (Tool, Regel-ID, Schweregrad, Datei/Zeile, Beschreibung, CWE):

- **Bandit** – statische Analyse von Python-Code (z. B. SQL-Injection-Muster, `eval`/`exec`, unsichere Deserialisierung, schwache Kryptografie).
- **pip-audit** – bekannte Schwachstellen in installierten/gepinnten Paketversionen (`requirements.txt`).
- **Semgrep** – musterbasierte Analyse, konfigurierbar über ein Registry-Ruleset (`p/security-audit`, braucht Internetzugang) oder ein eigenes lokales Regelwerk.

`run_all_scanners()` fängt Fehler pro Tool einzeln ab (nicht installiert, Zeitüberschreitung, ungültige Ausgabe, Tool-Absturz) – ein ausfallendes Tool beendet nicht den gesamten Scan, der Fehler wird im Ergebnis vermerkt statt verschwiegen.

### Triage-Agent (`src/triage_agent/`)

Bewertet jeden Fund per LLM: echter Fund oder Fehlalarm, Schweregrad (CVSS-ähnlich), Begründung. Funde werden gebatcht (Default 5 pro LLM-Aufruf), die Ausgabe erfolgt strukturiert über Anthropic Tool-Use (`submit_triage`, `temperature=0`). Bei niedriger Konfidenz (< 0,6) läuft ein zweiter, unabhängiger Durchlauf (Consensus-Check); bei Uneinigkeit wird der Fund als `needs_review` markiert statt automatisch entschieden. Transiente API-Fehler werden mit Backoff wiederholt (max. 3 Versuche).

### Report-Agent (`src/report_agent/`)

`build_report_context()` ist reine Code-Logik ohne LLM: verknüpft Finding und Triage-Bewertung, sortiert nach Schweregrad, kappt bei mehr als 40 bestätigten Funden pro Lauf. `generate_report()` macht einen einzigen LLM-Aufruf für den gesamten Bericht (nicht pro Fund); alle Zahlen (Anzahl Funde, Schweregrad-Verteilung) werden exakt vorgegeben statt vom LLM neu berechnet, um Erfindungen zu vermeiden. Gibt es keine bestätigten Funde, wird der Bericht deterministisch ohne LLM-Aufruf erzeugt.

### Orchestrator (`src/orchestrator/`)

Reine Python-Logik ohne eigene LLM-Aufrufe. `run_pipeline()` führt Scan → Triage → Report nacheinander aus und schreibt den Zwischenstand nach **jedem** Schritt in SQLite (`RunStore`, stdlib `sqlite3`). Schlägt ein Schritt fehl, wird der Lauf als `FAILED` mit Fehlertext gespeichert – bereits gespeicherte Funde/Bewertungen aus abgeschlossenen Vorschritten bleiben dabei erhalten (Crash-Resilienz: ein Absturz in der Report-Phase verliert nicht die bereits erledigte Triage-Arbeit).

**Demo-/Fixture-Modus:** Ist `ANTHROPIC_API_KEY` nicht gesetzt, laufen Triage und Report automatisch über deterministische Fixtures (`src/demo/fixtures.py`) statt über das LLM – keine Kosten, kein Netzwerkzugriff, vollständig lauffähig für Dritte ohne eigenen Key. Der Parameter `demo_mode` (True/False/None) erlaubt es, dieses Verhalten explizit zu erzwingen, unabhängig davon, ob ein Key vorhanden ist.

### MLflow-Tracking (`src/tracking/`)

Protokolliert pro Lauf Parameter (Repo-Pfad, Status), Metriken (Laufzeit, Funde pro Schweregrad, Fehlalarm-/Review-Zahlen, Scanner-Fehler-Anzahl) und den fertigen Bericht als Text-Artefakt. Nutzt standardmäßig MLflows lokalen File-Store (`mlruns/`-Ordner, kein externer Server nötig). **Bewusst best-effort:** jeder MLflow-Aufruf steht in einem try/except, das Fehler nur loggt, nie weiterwirft – ein nicht erreichbarer Tracking-Server darf einen sonst erfolgreichen Scan-Lauf nicht zusätzlich zum Scheitern bringen.

### FastAPI-Endpunkt (`src/api/`)

- `GET /health` – Erreichbarkeits-Check.
- `POST /scans` – startet `run_pipeline()` synchron (ein Scan pro Request, kein Hintergrund-Queue), nimmt `repo_path`, optional `semgrep_config` und optional `demo_mode` entgegen.
- `GET /scans/{run_id}` – liest den gespeicherten Lauf (auch bei `failed`), HTTP 404 wenn unbekannt.
- `GET /scans/{run_id}/report` – liefert nur den Markdown-Bericht, HTTP 409 wenn noch nicht fertig.

### Containerisierung & CI

Docker-Image auf Basis `python:3.11-slim`, läuft als nicht-root-Nutzer, mit `HEALTHCHECK` gegen `/health`. Docker Compose bindet Port 8000, lädt `.env`, persistiert die SQLite-Datenbank in einem benannten Volume. GitHub Actions (`ci.yml`) installiert Abhängigkeiten und führt `pytest` bei jedem Push/PR auf `main` aus.

## Datenfluss und Persistenz

Jeder Lauf bekommt eine UUID (`ScanRun.id`) und durchläuft die Status `scanning → triaging → reporting → completed` (oder `failed`). Drei SQLite-Tabellen:

- `runs` – ein Datensatz pro Lauf (Status, Zeitstempel, Fehlertext, fertiger Bericht).
- `findings` – Scanner-Funde als JSON, verknüpft über die Lauf-ID.
- `assessments` – Triage-Bewertungen als JSON, verknüpft über die Lauf-ID.

Die Datenbank ist die einzige Quelle der Wahrheit für den Laufstatus; die FastAPI-Schicht hat keinen eigenen Zustand.

## Risiken und Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| Ein Scanner-Tool stürzt ab oder liefert eine unerwartete Ausgabe | Fehler pro Tool einzeln abgefangen, im `ScanResult.errors`-Feld vermerkt, Scan läuft mit den übrigen Tools weiter. Wichtig dabei: ein Tool-Absturz muss zuverlässig von "keine Funde" unterschieden werden (siehe bekannter Bugfix unten) |
| LLM erfindet Zahlen im Bericht | `generate_report()` übergibt alle Zahlen fest vorberechnet, das LLM schreibt nur Prosa drumherum |
| LLM entscheidet bei unsicheren Fällen falsch | Consensus-Check (zweiter unabhängiger Durchlauf) bei Konfidenz < 0,6, Uneinigkeit führt zu `needs_review` statt automatischer Entscheidung |
| Kein Tracking-Server erreichbar | MLflow-Logging komplett best-effort, kann den Lauf nie zum Scheitern bringen |
| Kein eigener API-Key vorhanden (z. B. bei Dritten auf GitHub) | Automatischer Demo-/Fixture-Modus ohne LLM-Aufruf |
| Absturz mitten im Lauf (z. B. Report-Phase) | Zwischenstände werden nach jedem Schritt persistiert, nicht erst am Ende |
| Transiente API-Fehler beim LLM-Aufruf | Retry mit Backoff, maximal 3 Versuche, kein Endlos-Retry |

**Bekannter, behobener Bug:** `run_semgrep()` interpretierte einen Exit-Code 1 mit leerer Standardausgabe fälschlich als "keine Funde". Ein regulärer Semgrep-Lauf liefert aber auch ohne Funde ein gültiges JSON-Objekt – leere Ausgabe bedeutet, dass Semgrep selbst abgestürzt ist. Seit dem Fix wird das als Tool-Fehler erkannt und gemeldet statt als falsch-positive "saubere Codebasis".

## Bekannte Grenzen (technisch, Stand Entwicklung)

- Der FastAPI-Endpunkt läuft synchron (ein Scan pro Request); für größere Repos oder mehrere parallele Läufe wäre ein Hintergrund-Queue (z. B. Celery/RQ) nötig.
- Schlägt `POST /scans` fehl, enthält die Fehlerantwort nicht die Lauf-ID des fehlgeschlagenen Versuchs.
- Semgrep mit Registry-Ruleset (`p/security-audit`) braucht beim ersten Lauf Internetzugang; ohne Netzwerk nur über ein eigenes lokales Regelwerk nutzbar.
- Noch nicht gegen einen echten, separat laufenden MLflow-Tracking-Server (`mlflow server`) getestet – bisher nur gegen den lokalen File-Store.

Eine ehrliche, nutzerorientierte Zusammenfassung der Grenzen (Evaluationsumfang, bekannte Fehlklassifikationen) folgt im README nach Projektabschluss.
