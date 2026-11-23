# VulnScout – Architektur

## Überblick

VulnScout scannt ein beliebiges lokales Code-Repository auf Sicherheitslücken, bewertet die Funde (Fehlalarm-Filter, Schweregrad) und erstellt daraus einen lesbaren Bericht mit Fix-Vorschlägen. Das System besteht aus drei Agenten, die von einem Orchestrator verbunden werden, einem optionalen ML-Pre-Filter vor der Triage (spart einen Teil der LLM-Aufrufe), sowie einer FastAPI-Schnittstelle, Containerisierung und CI.

```
Zielrepo
   │
   ▼
Scanner-Agent  (Bandit, pip-audit, Semgrep – deterministisch, kein LLM)
   │  Finding-Liste (einheitliches Format)
   ▼
Pre-Filter     (Modell aus der MLflow Model Registry: entscheidet eindeutige
                Funde ohne LLM-Aufruf, Rest geht weiter an die Triage)
   │
   ▼
Triage-Agent   (LLM: Fehlalarm-Filter, Schweregrad, Consensus-Check bei Unsicherheit)
   │  TriageAssessment-Liste (Pre-Filter + LLM zusammen)
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

### Pre-Filter-Modell (`src/prefilter/`, `scripts/train_prefilter.py`)

Nicht jeder Scanner-Fund braucht einen LLM-Aufruf, um entschieden zu werden – ein von pip-audit gemeldetes CVE ist praktisch immer ein echter Fund, ein Bandit-Treffer auf einen reinen Import praktisch immer ein Fehlalarm. Das Pre-Filter-Modell ist ein günstiger Klassifikator (Logistic Regression bzw. Random Forest, siehe unten), der genau solche eindeutigen Fälle aus den rohen Scanner-Merkmalen (Tool, Regel-ID, Schweregrad, Dateiendung, Code-Ausschnitt-Länge, Bandit-Konfidenz, CWE vorhanden, Abhängigkeits-Fund ja/nein) vorhersagt – **ohne** API-Aufruf.

**Wichtige Einschränkung, offen benannt statt versteckt:** Die Trainingslabels stammen vom Triage-Agenten selbst (LLM), nicht von menschlicher Ground Truth. Das Modell destilliert also das Urteil des LLM (*knowledge distillation*) – es lernt vorherzusagen, was der Triage-Agent sagen würde, nicht unabhängig, ob ein Fund real ist. Die berichtete Fehlerrate ist dementsprechend eine Abweichung vom LLM-Urteil, keine Abweichung von der Wahrheit. Für eine unabhängige Qualitätsaussage über den Scanner-Stack insgesamt bleibt die Ground-Truth-Evaluation in `scripts/evaluate.py` maßgeblich (siehe README, Abschnitt Evaluation).

**Trainingsdaten:** `scripts/label_repos.py` scannt sechs Repositories (drei bewusst verwundbare: `dummy_vuln_repo`, OWASP PyGoat, DVPWA; drei saubere, gut gepflegte Open-Source-Bibliotheken als Negativbeispiele: Vulnerable-Flask-App als Testset-Gegenstück, `requests`, `click`) und lässt jeden Fund von der Triage bewerten (Consensus-Check dafür deaktiviert, um Kosten zu sparen – für einen Trainingsdatensatz vertretbar, im echten Scan-Betrieb bleibt er an). Ergebnis: `scripts/training_data.jsonl`, ein Datensatz aus realen Scanner-Funden mit LLM-Label, nicht aus synthetischen Beispielen.

**Methodik (`scripts/train_prefilter.py`):**
- Split nach Repository, nicht nach Zeile: `Vulnerable-Flask-App` und `click` werden beim Training nie gesehen, um Datenleckage zu vermeiden (ein Modell, das Zeilen aus demselben Repo in Training und Test hat, wirkt sonst künstlich besser).
- Zwei Kandidaten (Logistic Regression, Random Forest) werden trainiert und gegeneinander antreten gelassen (Champion/Challenger).
- Die Entscheidungsschwellen (ab welcher Wahrscheinlichkeit automatisch entschieden wird) werden auf einem Validierungsanteil der Trainings-Repos festgelegt, nicht auf den Test-Repos – sonst wäre das berichtete Ergebnis an genau die Daten angepasst, mit denen es gemessen wird.
- **Qualitäts-Gate:** Ein Kandidat wird nur Champion, wenn seine Fehlerrate auf den automatisch entschiedenen Test-Funden unter 2 % bleibt. Besteht kein Kandidat das Gate, bleibt der bisherige Champion unverändert – lieber kein neues Modell als ein schlechteres in Produktion. Dasselbe Gate läuft als Teil der Testsuite (`tests/test_train_prefilter.py`) in CI gegen den versionierten Trainingsdatensatz, gegen einen frischen, lokalen MLflow-Tracking-Server (SQLite, temporäres Verzeichnis) – unabhängig vom MLflow-Server des Projekts, der nur lokal beim Autor läuft.
- Registrierung in der MLflow Model Registry unter `vulnscout-prefilter`, Gewinner bekommt den Alias `champion`, der Unterlegene `challenger`.

**Laufzeit (`src/prefilter/prefilter.py`):** Lädt `models:/vulnscout-prefilter@champion` einmal pro Prozess. Wie Monitoring und MLflow-Tracking **best-effort**: Ist kein Modell registriert, nicht erreichbar oder schlägt die Anwendung fehl, gehen alle Funde unverändert an die LLM-Triage – der Pre-Filter kann einen Scan nie zum Scheitern bringen, nur beschleunigen/verbilligen. Jede automatische Entscheidung wird als `TriageAssessment` mit Begründung ("Automatisch durch das Pre-Filter-Modell entschieden") markiert, taucht also im Bericht nicht anders auf als eine LLM-Entscheidung.

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

### Monitoring (`src/monitoring/`, `monitoring/`)

Zwei getrennte Aufgaben, die oft verwechselt werden:

- **MLflow** (`src/tracking/`) hält **jeden einzelnen Lauf dauerhaft** fest, damit man im Nachhinein vergleichen kann: Welcher Lauf fand wie viele Funde, wie lange dauerte er, wie sah der Bericht aus?
- **Prometheus** (`src/monitoring/`) beschreibt den **laufenden Betrieb in Zahlen**: Wie viele Anfragen gerade, wie viele Fehler, wie schnell. Daraus entstehen Dashboards und Alarme.

`src/monitoring/metrics.py` definiert die Kennzahlen (Counter für Dinge, die nur hochzählen; Histogramme für Messwerte wie Laufzeiten, aus denen Prometheus Quantile berechnet). `src/monitoring/record.py` überträgt das Ergebnis eines Laufs in diese Kennzahlen und wird vom Orchestrator an derselben Stelle aufgerufen wie das MLflow-Tracking – im Erfolgs- wie im Fehlerfall. Wie das Tracking ist es **best-effort**: Ein Fehler beim Zählen wird geloggt, nie weitergeworfen.

Eine Middleware in der API misst bei jeder Anfrage Pfad, Methode, Status und Dauer. Als Label dient die Routen-Vorlage (`/scans/{run_id}`), nicht der konkrete Pfad – sonst entstünde pro Lauf-ID eine eigene Zeitreihe und die Zahl der Zeitreihen würde unbegrenzt wachsen.

Erfasst werden:

| Bereich | Kennzahlen |
|---|---|
| HTTP | Anfragen nach Pfad/Methode/Status, Antwortzeit |
| Scans | Läufe nach Ergebnis, Dauer, Betriebsart (Demo oder LLM) |
| Scanner | Funde je Werkzeug, Ausfälle je Werkzeug |
| Triage | Ergebnisse (bestätigt, Fehlalarm, kein Konsens), Konfidenzverteilung, bestätigte Funde je Schweregrad |
| LLM | Aufrufe nach Ergebnis, Latenz, Fehler nach Art |
| Pre-Filter | Entscheidungen (automatisch bestätigt/verworfen, eskaliert, kein Modell verfügbar), eingesparte LLM-Aufrufe |

`monitoring/prometheus.yml` legt fest, dass Prometheus die API alle fünf Sekunden abfragt. `monitoring/alerts.yml` enthält die Alarmregeln, `monitoring/grafana/` die Datenquelle und das Dashboard. Alle drei Dienste starten über Docker Compose, gebunden an `127.0.0.1` – Grafana läuft ohne Anmeldung und wäre im Netzwerk sonst offen.

**Warum ein Scanner-Ausfall einen eigenen Alarm hat:** Fällt ein Werkzeug aus, liefert es keine Funde. Ein Bericht ohne Funde liest sich wie eine saubere Codebasis, ist aber in Wahrheit eine Lücke in der Prüfung. Der Alarm `ScannerFaelltAus` trennt diese beiden Fälle.

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
| Kein Pre-Filter-Modell registriert/erreichbar | Best-effort wie MLflow/Prometheus: alle Funde gehen dann unverändert an die LLM-Triage, Verhalten wie vor Variante B |
| Pre-Filter-Modell trifft eine falsche automatische Entscheidung | Qualitäts-Gate (< 2 % Fehlerrate ggü. LLM-Urteil auf nie gesehenen Test-Repos) vor Champion-Promotion, zusätzlich als CI-Test; bei Nichtbestehen bleibt der alte Champion aktiv |

**Bekannter, behobener Bug:** `run_semgrep()` interpretierte einen Exit-Code 1 mit leerer Standardausgabe fälschlich als "keine Funde". Ein regulärer Semgrep-Lauf liefert aber auch ohne Funde ein gültiges JSON-Objekt – leere Ausgabe bedeutet, dass Semgrep selbst abgestürzt ist. Seit dem Fix wird das als Tool-Fehler erkannt und gemeldet statt als falsch-positive "saubere Codebasis".

## Bekannte Grenzen (technisch, Stand Entwicklung)

- Der FastAPI-Endpunkt läuft synchron (ein Scan pro Request); für größere Repos oder mehrere parallele Läufe wäre ein Hintergrund-Queue (z. B. Celery/RQ) nötig.
- Schlägt `POST /scans` fehl, enthält die Fehlerantwort nicht die Lauf-ID des fehlgeschlagenen Versuchs.
- Semgrep mit Registry-Ruleset (`p/security-audit`) braucht beim ersten Lauf Internetzugang; ohne Netzwerk nur über ein eigenes lokales Regelwerk nutzbar.
- Noch nicht gegen einen echten, separat laufenden MLflow-Tracking-Server (`mlflow server`) getestet – bisher nur gegen den lokalen File-Store.
- Die Prometheus-Kennzahlen leben im Arbeitsspeicher des API-Prozesses. Läufe, die direkt per Kommandozeile gestartet werden, erscheinen nicht unter `/metrics`. Bei mehreren API-Prozessen (etwa mit mehreren Uvicorn-Workern) würde jeder Prozess eigene Zähler führen; dafür wäre der Multiprozess-Modus von `prometheus_client` nötig.
- Prometheus wertet die Alarmregeln aus, versendet aber nichts: Es gibt keinen Alertmanager und damit keine Benachrichtigung per E-Mail oder Chat. Die Alarme sind nur in der Prometheus-Oberfläche sichtbar.
- Die Trainingslabels des Pre-Filter-Modells stammen vom Triage-Agenten (LLM), nicht von menschlicher Ground Truth (Distillation, siehe Abschnitt "Pre-Filter-Modell" oben) - die Fehlerrate des Modells ist eine Abweichung vom LLM-Urteil, keine unabhängige Genauigkeitsaussage.
- Der Trainingsdatensatz für den Pre-Filter deckt sechs Repositories ab (drei verwundbare, drei saubere) - genug für eine erste, ehrliche Kostenersparnis-Kennzahl, aber keine breite Stichprobe über viele Projektarten/Programmiersprachen hinweg. Das Modell ist zudem nur für Python trainiert, wie der Rest von VulnScout.

Eine ehrliche, nutzerorientierte Zusammenfassung der Grenzen (Evaluationsumfang, bekannte Fehlklassifikationen) folgt im README nach Projektabschluss.
