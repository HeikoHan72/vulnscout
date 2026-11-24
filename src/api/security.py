"""Prüfung der Eingaben von `POST /scans` gegen Missbrauch.

Die API ist nicht authentifiziert. Ohne diese Prüfung könnte jeder
Aufrufer beliebige Verzeichnisse im Container scannen lassen und
bekäme Code-Ausschnitte daraus im Bericht zurück, und über
`semgrep_config` könnte er Semgrep zu einer selbst gewählten
Adresse schicken.

Die Prüfung ist bewusst fail-closed (Verbot als Grundhaltung): Was nicht
ausdrücklich erlaubt ist, wird abgelehnt. Das System ist sonst
absichtlich fail-open gebaut (ein ausgefallener Pre-Filter soll den
Scan nicht stoppen), aber bei Zugriffskontrolle wäre ein stilles
Durchlassen der Fehler.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# Name der Umgebungsvariable, die den erlaubten Bereich festlegt.
SCAN_ROOT_ENV = "VULNSCOUT_SCAN_ROOT"

# Ohne Einstellung gilt `test_repos` im Arbeitsverzeichnis. Im Container ist
# das /app/test_repos, beim Start aus dem Projektordner der Ordner test_repos.
DEFAULT_SCAN_ROOT = "test_repos"

# Erlaubte Zeichen eines Registry-Namens nach dem Präfix `p/`.
_REGISTRY_NAME = re.compile(r"[A-Za-z0-9._-]+")


def get_scan_root() -> Path:
    """Gibt den erlaubten Bereich als aufgelösten, absoluten Pfad zurück.

    Wird bei jedem Aufruf neu gelesen, damit Tests die Einstellung per
    `monkeypatch` ändern können.
    """
    return Path(os.environ.get(SCAN_ROOT_ENV) or DEFAULT_SCAN_ROOT).resolve()


def resolve_repo_path(repo_path: str) -> Path:
    """Löst `repo_path` auf und prüft, dass er im erlaubten Bereich liegt.

    `resolve()` löst `..` und symbolische Links auf. Ein Link aus dem
    Bereich heraus oder ein Umweg über `..` führt deshalb zu einem Pfad
    außerhalb und wird abgelehnt.

    Die Fehlermeldung ist für „nicht vorhanden“ und „außerhalb“ dieselbe,
    damit niemand über die Antwort herausfinden kann, welche Verzeichnisse
    es außerhalb des Bereichs gibt.

    Raises:
        ValueError: Pfad ist kein Verzeichnis oder liegt außerhalb.
    """
    resolved = Path(repo_path).resolve()
    if not resolved.is_dir() or not resolved.is_relative_to(get_scan_root()):
        raise ValueError(
            "repo_path existiert nicht, ist kein Verzeichnis oder liegt "
            "außerhalb des erlaubten Bereichs"
        )
    return resolved


def validate_semgrep_config(config: str, repo_dir: Path) -> str:
    """Lässt nur Registry-Kennungen `p/<name>` oder eine Datei im Repo zu.

    Nicht erlaubt sind insbesondere URLs (Semgrep könnte Regeln von einer
    selbst gewählten Adresse laden), Pfade außerhalb des Repos und Werte,
    die mit `-` beginnen (könnten als Programmoption gelesen werden).

    Eine Registry-Kennung wird unverändert zurückgegeben. Bei einer Datei
    wird der aufgelöste absolute Pfad zurückgegeben, denn Semgrep würde
    einen relativen Pfad im Arbeitsverzeichnis der API suchen und nicht im
    gescannten Repo. So wird genau die geprüfte Datei benutzt.

    Raises:
        ValueError: Wert ist nicht erlaubt.
    """
    if config.startswith("p/") and _REGISTRY_NAME.fullmatch(config[2:]):
        return config

    if not config.startswith("-"):
        candidate = (repo_dir / config).resolve()
        if candidate.is_file() and candidate.is_relative_to(repo_dir):
            return str(candidate)

    raise ValueError(
        "semgrep_config muss eine Registry-Kennung der Form p/<name> "
        "oder eine Datei im gescannten Repository sein"
    )
