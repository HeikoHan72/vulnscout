# VulnScout – Architektur

## Überblick

VulnScout scannt ein beliebiges lokales Code-Repository auf Sicherheitslücken, bewertet die Funde (Fehlalarm-Filter, Schweregrad) und erstellt daraus einen lesbaren Bericht mit Fix-Vorschlägen. Das System besteht aus drei Agenten, die von einem Orchestrator verbunden werden, einem optionalen ML-Pre-Filter vor der Triage (spart einen Teil der LLM-Aufrufe), sowie einer FastAPI-Schnittstelle, Containerisierung und CI.

```
Zielrepo
   │
   ▼
Scanner-Agent  (Bandit, pip-audit, Semgrep – deterministisch, kein LLM)
   │  Finding-Liste (einheitliches Format, doppelte pip-audit-Funde zusammengeführt)
   ▼
OSV-Anreicherung  (api.osv.dev: Schweregrad-Angabe, CVSS-Vektoren, CWE; fail-open)
   │
   ▼
Pre-Filter     (Modell aus der MLflow Model Registry: entscheidet eindeutige
                Funde ohne LLM-Aufruf, Rest geht weiter an die Triage)
   │
   ▼
Triage-Agent   (LLM: Fehlalarm-Filter, Schweregrad, Consensus-Check bei Unsicherheit)
   │  TriageAssessment-Liste (Pre-Filter + LLM zusammen)
   ▼
Schweregrad-Untergrenze  (bestätigte Abhängigkeits-Funde mindestens auf OSV-Stufe)
   │
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

### Anreicherung und Schweregrad-Untergrenze (`src/enrichment/`)

pip-audit liefert jede Schwachstelle doppelt (51 Einträge, 26 eindeutige im Testrepo). Der Scanner-Agent führt Einträge mit gleichem Paket, gleicher Version und gleicher ID zusammen (Fix-Versionen vereinigt, Rohdaten des Duplikats unter `raw["merged_entries"]`; Funde ohne ID werden nie zusammengeführt).

Die OSV-Anreicherung (`osv.py`) fragt für Abhängigkeits-Funde bei `api.osv.dev` das Schweregrad-Wort, alle CVSS-Vektoren und CWE-Kennungen ab (parallel mit 8 Arbeitern, Zeitbudget 30 s, Zwischenspeicher im Arbeitsspeicher für 1 Stunde). Ist der Dienst nicht erreichbar, läuft der Scan unverändert weiter (fail-open, Metrik `vulnscout_osv_enrichment_total`). Abschaltbar über `VULNSCOUT_OSV_ENABLED`. Die Anzeige (`display.py`) benennt das Wort als Angabe der Datenbank, zeigt alle Vektoren und warnt, wenn mehrere Vektoren zu unterschiedlichen Stufen führen können.

Nach der Triage hebt `floor.py` bestätigte pip-audit-Funde mindestens auf den OSV-Wert an (Ursprungswert in `severity_raised_from`, Vermerk in der Begründung, Metrik `vulnscout_severity_floor_total`). Das ist eine bewusste Abwägung: Die Triage sieht keinen Code-Kontext, und ein Sicherheitswerkzeug soll nicht untertreiben. Die Untergrenze ist fail-open. In allen sieben Live-Läufen (drei am 24.11.2026, vier am 25.11.2026) hat sie nichts angehoben; ihre Wirkung ist durch Tests belegt, nicht durch einen Live-Fall.

### Triage-Agent (`src/triage_agent/`)

Bewertet jeden Fund per LLM: echter Fund oder Fehlalarm, Schweregrad (CVSS-ähnlich), Begründung. Funde werden gebatcht (Default 5 pro LLM-Aufruf), die Ausgabe erfolgt strukturiert über Anthropic Tool-Use (`submit_triage`; kein Temperatur-Parameter, die Ausgabe ist nicht deterministisch). Bei niedriger Konfidenz (< 0,6) läuft ein zweiter, unabhängiger Durchlauf (Consensus-Check); bei Uneinigkeit wird der Fund als `needs_review` markiert statt automatisch entschieden. Transiente API-Fehler werden mit Backoff wiederholt (max. 3 Versuche).

### Pre-Filter-Modell (`src/prefilter/`, `scripts/train_prefilter.py`)

Nicht jeder Scanner-Fund braucht einen LLM-Aufruf, um entschieden zu werden – ein von pip-audit gemeldetes CVE ist praktisch immer ein echter Fund, ein Bandit-Treffer auf einen reinen Import praktisch immer ein Fehlalarm. Das Pre-Filter-Modell ist ein günstiger Klassifikator (Logistic Regression bzw. Random Forest, siehe unten), der genau solche eindeutigen Fälle aus den rohen Scanner-Merkmalen (Tool, Regel-ID, Schweregrad, Dateiendung, Code-Ausschnitt-Länge, Bandit-Konfidenz, CWE vorhanden, Abhängigkeits-Fund ja/nein) vorhersagt – **ohne** API-Aufruf.

**Wichtige Einschränkung, offen benannt statt versteckt:** Die Trainingslabels stammen vom Triage-Agenten selbst (LLM), nicht von menschlicher Ground Truth. Das Modell destilliert also das Urteil des LLM (*knowledge distillation*) – es lernt vorherzusagen, was der Triage-Agent sagen würde, nicht unabhängig, ob ein Fund real ist. Die berichtete Fehlerrate ist dementsprechend eine Abweichung vom LLM-Urteil, keine Abweichung von der Wahrheit. Für eine unabhängige Qualitätsaussage über den Scanner-Stack insgesamt bleibt die Ground-Truth-Evaluation in `scripts/evaluate.py` maßgeblich (siehe README, Abschnitt Evaluation).

**Trainingsdaten:** `scripts/label_repos.py` scannt sechs Repositories (vier bewusst verwundbare: `dummy_vuln_repo`, OWASP PyGoat, Vulnerable-Flask-App, DVPWA; zwei weit verbreitete Open-Source-Bibliotheken als Vergleichsbibliotheken: `requests`, `click`; ihre Freiheit von Schwachstellen ist nicht nachgewiesen) und lässt jeden Fund von der Triage bewerten (Consensus-Check dafür deaktiviert, um Kosten zu sparen – für einen Trainingsdatensatz vertretbar, im echten Scan-Betrieb bleibt er an). Ergebnis: `scripts/training_data.jsonl`, ein Datensatz aus realen Scanner-Funden mit LLM-Label, nicht aus synthetischen Beispielen. Er liegt direkt im Repository (1,4 MB). Die 214 Semgrep-Zeilen stammen von einem lokal geklonten Regelwerk mit anderen Regel-Kennungen als das im Betrieb genutzte `p/security-audit`.

**Methodik (`scripts/train_prefilter.py`):**
- Split nach Repository, nicht nach Zeile: `Vulnerable-Flask-App` und `click` werden beim Training nie gesehen, um Datenleckage zu vermeiden (ein Modell, das Zeilen aus demselben Repo in Training und Test hat, wirkt sonst künstlich besser).
- Zwei Kandidaten (Logistic Regression, Random Forest) werden trainiert und gegeneinander antreten gelassen (Champion/Challenger).
- Die Entscheidungsschwellen (ab welcher Wahrscheinlichkeit automatisch entschieden wird) werden auf einem Validierungsanteil der Trainings-Repos festgelegt, nicht auf den Test-Repos – sonst wäre das berichtete Ergebnis an genau die Daten angepasst, mit denen es gemessen wird.
- **Qualitäts-Gate:** Ein Kandidat wird nur Champion, wenn auf den automatisch entschiedenen Test-Funden zwei Bedingungen erfüllt sind (`scripts/train_prefilter.py`): Die **Fehlerrate** (`test_error_rate`: Anteil der automatischen Entscheidungen, die vom LLM-Label abweichen, bezogen auf alle automatisch entschiedenen Funde) beträgt höchstens 2 % (`MAX_ERROR_RATE = 0.02`), und die **Miss-Rate** (`test_miss_rate`: Anteil der automatisch verworfenen Funde, die laut Label echte Schwachstellen sind, bezogen auf alle automatisch verworfenen Funde) beträgt höchstens 2 % (`MAX_MISS_RATE_TEST = 0.02`). Zusätzlich muss mindestens ein Fund automatisch entschieden worden sein. Bei der Schwellenwahl auf dem Validierungsanteil gilt für die Miss-Rate strenger 0 (`MAX_MISS_RATE_VAL = 0.0`). Besteht kein Kandidat das Gate, bleibt der bisherige Champion unverändert – lieber kein neues Modell als ein schlechteres in Produktion. Dasselbe Gate läuft als Teil der Testsuite (`tests/test_train_prefilter.py`) in CI gegen den im Repository liegenden Trainingsdatensatz, gegen einen frischen, lokalen MLflow-Tracking-Server (SQLite, temporäres Verzeichnis) – unabhängig vom MLflow-Server des Compose-Stacks.
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
| Pre-Filter | Entscheidungen (automatisch bestätigt/verworfen, eskaliert, kein Modell verfügbar), geschätzte eingesparte LLM-Aufrufe (ein Aufruf je automatisch entschiedenem Fund) |

`monitoring/prometheus.yml` legt fest, dass Prometheus die API alle fünf Sekunden abfragt. `monitoring/alerts.yml` enthält die Alarmregeln, `monitoring/grafana/` die Datenquelle und das Dashboard. Alle drei Dienste starten über Docker Compose, gebunden an `127.0.0.1` – Grafana läuft ohne Anmeldung und wäre im Netzwerk sonst offen.

**Warum ein Scanner-Ausfall einen eigenen Alarm hat:** Fällt ein Werkzeug aus, liefert es keine Funde. Ein Bericht ohne Funde liest sich wie eine saubere Codebasis, ist aber in Wahrheit eine Lücke in der Prüfung. Der Alarm `ScannerFaelltAus` trennt diese beiden Fälle.

### Containerisierung & CI

Docker-Image auf Basis `python:3.11-slim`, läuft als nicht-root-Nutzer, mit `HEALTHCHECK` gegen `/health`. Docker Compose bindet Port 8000, lädt `.env`, persistiert die SQLite-Datenbank in einem benannten Volume. GitHub Actions (`ci.yml`) installiert Abhängigkeiten und führt `pytest` bei jedem Push/PR auf `main` aus (Python 3.11). Die CI baut kein Image und deployt nichts. Das Render-Deployment der Demo (Auto-Deploy bei neuem Commit) ist keine Stufe der CI: `ci.yml` enthält keinen Deploy-Schritt.

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
| Pre-Filter-Modell trifft eine falsche automatische Entscheidung | Qualitäts-Gate (Fehlerrate und Miss-Rate jeweils höchstens 2 % ggü. LLM-Urteil auf nie gesehenen Test-Repos) vor Champion-Promotion, zusätzlich als CI-Test; bei Nichtbestehen bleibt der alte Champion aktiv |

**Bekannter, behobener Bug (pip-audit):** `run_pip_audit()` gab bei leerer Standardausgabe eine leere Fundliste zurück. Ein regulärer pip-audit-Lauf gibt aber immer JSON aus (auch `{"dependencies": [], "fixes": []}`); leere Ausgabe heißt, dass das Werkzeug vorher gescheitert ist, typisch ohne Verbindung zum Paketindex. Die Scanner-Prozesse erhalten bewusst nur eine minimale Umgebung ohne Proxy-Variablen, hinter einem Proxy schlug pip-audit daher still fehl und der Lauf sah wie eine saubere Abhängigkeitsliste aus. Seit dem Fix löst leere Ausgabe einen Fehler aus, der im Lauf, im Bericht, in der Datenbank und in der Metrik `vulnscout_scanner_errors_total` erscheint.

**Bekannter, behobener Bug:** `run_semgrep()` interpretierte einen Exit-Code 1 mit leerer Standardausgabe fälschlich als "keine Funde". Ein regulärer Semgrep-Lauf liefert aber auch ohne Funde ein gültiges JSON-Objekt – leere Ausgabe bedeutet, dass Semgrep selbst abgestürzt ist. Seit dem Fix wird das als Tool-Fehler erkannt und gemeldet statt als falsch-positive "saubere Codebasis".

## Bekannte Grenzen (technisch, Stand 25.11.2026)

- Der FastAPI-Endpunkt läuft synchron (ein Scan pro Request); für größere Repos oder mehrere parallele Läufe wäre ein Hintergrund-Queue (z. B. Celery/RQ) nötig.
- Schlägt `POST /scans` fehl, enthält die Fehlerantwort nicht die Lauf-ID des fehlgeschlagenen Versuchs.
- Semgrep mit Registry-Ruleset (`p/security-audit`) braucht beim ersten Lauf Internetzugang; ohne Netzwerk nur über ein eigenes lokales Regelwerk nutzbar.
- MLflow läuft als Compose-Dienst (`mlflow server`, SQLite-Backend). Getestet im Frisch-Klon-Lauf am 25.11.2026 unter Linux (Image-Build, Start, Training, Scan). Windows, macOS und der Betrieb hinter einem Proxy sind nicht getestet.
- Proxy-Variablen werden bewusst nicht an die Scanner weitergegeben (der API-Schlüssel soll nicht in Scanner-Prozesse gelangen). Hinter einem Proxy meldet pip-audit einen Scanner-Fehler und liefert keine Abhängigkeits-Funde.
- Die Prometheus-Kennzahlen leben im Arbeitsspeicher des API-Prozesses. Läufe, die direkt per Kommandozeile gestartet werden, erscheinen nicht unter `/metrics`. Bei mehreren API-Prozessen (etwa mit mehreren Uvicorn-Workern) würde jeder Prozess eigene Zähler führen; dafür wäre der Multiprozess-Modus von `prometheus_client` nötig.
- Prometheus wertet die Alarmregeln aus, versendet aber nichts: Es gibt keinen Alertmanager und damit keine Benachrichtigung per E-Mail oder Chat. Die Alarme sind nur in der Prometheus-Oberfläche sichtbar.
- Die Trainingslabels des Pre-Filter-Modells stammen vom Triage-Agenten (LLM), nicht von menschlicher Ground Truth (Distillation, siehe Abschnitt "Pre-Filter-Modell" oben) - die Fehlerrate des Modells ist eine Abweichung vom LLM-Urteil, keine unabhängige Genauigkeitsaussage.
- Der Trainingsdatensatz für den Pre-Filter deckt sechs Repositories ab (vier verwundbare, zwei Vergleichsbibliotheken) - genug für eine erste, ehrliche Kostenersparnis-Kennzahl, aber keine breite Stichprobe über viele Projektarten/Programmiersprachen hinweg. Das Modell ist zudem nur für Python trainiert, wie der Rest von VulnScout.

Eine nutzerorientierte Zusammenfassung der Grenzen (Evaluationsumfang, bekannte Fehlklassifikationen) steht im README, Abschnitte Evaluation und Limitations.
