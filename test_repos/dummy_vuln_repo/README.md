# Dummy-Repo mit absichtlichen Sicherheitslücken

**Warnung: Dieser Code ist absichtlich unsicher. Nicht ausführen, nicht deployen, keine Zeile davon übernehmen.**

**Warning: this code is intentionally insecure. Do not run it, do not deploy it, do not copy any of it.**

Dieses Verzeichnis ist das Testziel für VulnScout. Jede Schwachstelle hier ist bewusst platziert, um die Scanner (Bandit, pip-audit, Semgrep) und die LLM-Triage zu prüfen – inklusive bewusst mehrdeutiger Fälle, bei denen ein Scanner anschlägt, der Fund aber harmlos ist (z. B. `shell=True` mit fest hartcodiertem Befehl, oder MD5 für einen Cache-Schlüssel statt für Passwörter).

Die enthaltenen "Secrets" (`sk-live-hardcoded-secret-12345`, `s3cr3t-db-key-do-not-share`) sind frei erfunden und waren nie gültig. Die Versionen in `requirements.txt` sind absichtlich alt und verwundbar.

This directory is VulnScout's test target. Every vulnerability in it is deliberate, used to exercise the scanners (Bandit, pip-audit, Semgrep) and the LLM triage step – including deliberately ambiguous cases where a scanner fires but the finding is harmless. The "secrets" in here are made up and were never valid; the pinned dependency versions are intentionally outdated and vulnerable.

## Abgedeckte Schwachstellenklassen

- SQL-Injection (String-Konkatenation in Queries)
- Command Injection (`os.system`, `subprocess` mit `shell=True`)
- Code Injection (`eval`, `exec` auf Benutzereingabe)
- Server-Side Template Injection (`render_template_string`)
- SSRF (ungeprüfte URL aus Benutzereingabe)
- XXE (XML-Parsing nicht vertrauenswürdiger Eingaben)
- Insecure Deserialization (`pickle.loads`)
- Path Traversal
- Schwache Kryptografie (MD5 für Passwort-Hashing)
- Unsicherer Zufallsgenerator für Session-Tokens (`random` statt `secrets`)
- Unsicheres YAML-Laden (`yaml.load` ohne `SafeLoader`)
- Unsicheres Temp-File (`tempfile.mktemp`)
- Hartcodierte Secrets
- Deaktivierte TLS-Zertifikatsprüfung (`verify=False`)
- Flask mit `debug=True` und Bindung an `0.0.0.0`
- Verwundbare Dependency-Versionen (Flask, PyYAML, requests)

Zusätzlich enthalten: sichere Gegenbeispiele (parametrisierte Query, `secrets.token_hex`) und toter/auskommentierter Code, um Fehlalarm-Verhalten zu testen.
