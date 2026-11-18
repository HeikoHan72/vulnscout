"""Diverse Hilfsfunktionen mit absichtlich platzierten Schwachstellen."""

import os
import pickle
import subprocess
import tempfile


def run_backup(filename: str):
    """Command Injection (Finding): Benutzereingabe wird direkt an die Shell
    übergeben.
    """
    os.system("tar -cvf backup.tar " + filename)


def run_diagnostic(cmd: str):
    """Command Injection (Finding): `shell=True` mit Benutzereingabe."""
    subprocess.call(cmd, shell=True)


def clear_temp_cache():
    """Mehrdeutiger Fall (Testfall für den Consensus-Mechanismus):

    `shell=True`, aber mit einem fest hartcodierten Befehl ohne jede
    Benutzereingabe. Scanner markieren jede `shell=True`-Nutzung unabhängig
    vom tatsächlichen Inhalt des Befehls.
    """
    subprocess.call("rm -rf /tmp/vulnscout_cache/*", shell=True)


def load_cached_object(data: bytes):
    """Insecure Deserialization (Finding): `pickle.loads` auf beliebige,
    nicht verifizierte Daten.
    """
    return pickle.loads(data)


def read_log(path: str):
    """Path Traversal (Finding): Benutzereingabe wird ungeprüft in einen
    Dateipfad eingebaut (z. B. `../../etc/passwd`).
    """
    with open("/var/log/" + path) as f:
        return f.read()


def make_temp_report():
    """Unsicheres Temp-File (Finding): `tempfile.mktemp` ist anfällig für
    Race Conditions (TOCTOU) - `tempfile.mkstemp` wäre die sichere
    Alternative.
    """
    path = tempfile.mktemp()
    with open(path, "w") as f:
        f.write("report")
    return path


def cleanup_note():
    """Toter Code (Testfall): Der folgende verwundbare Aufruf existiert nur
    als Kommentar und wird nie ausgeführt - ein guter Fehlalarm-Testfall für
    den Triage-Agenten, falls ein Scanner ihn trotzdem als Text erkennt.

    os.system("rm -rf " + user_input)  # NICHT AKTIV, nur Beispielcode
    """
    return None
