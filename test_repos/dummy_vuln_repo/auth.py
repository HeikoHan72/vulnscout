"""Authentifizierungs- und Krypto-bezogene Funktionen (absichtlich verwundbar)."""

import hashlib
import random
import secrets


def hash_password(password: str) -> str:
    """Schwache Kryptografie (Finding): MD5 ist für Passwort-Hashing ungeeignet."""
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token() -> str:
    """Unsicherer Zufallsgenerator für ein sicherheitsrelevantes Token (Finding):
    `random` ist nicht kryptografisch sicher und daher für Session-Tokens
    ungeeignet.
    """
    return "".join(str(random.randint(0, 9)) for _ in range(32))


def generate_csrf_token() -> str:
    """Sicheres Gegenbeispiel: nutzt `secrets` statt `random`.

    Kein Finding erwartet - dient als Kontrast im selben Modul, um zu zeigen,
    dass nicht jede Zufallszahlen-Nutzung ein Problem ist.
    """
    return secrets.token_hex(32)


def hash_cache_key(value: str) -> str:
    """Mehrdeutiger Fall (Testfall für den Consensus-Mechanismus):

    MD5 wird hier nur zur Bildung eines Cache-Schlüssels genutzt, nicht für
    Passwörter oder Signaturen. Scanner markieren jede MD5-Nutzung gleich
    (Finding), die tatsächliche Sicherheitsrelevanz ist hier aber gering, da
    kein Sicherheits- oder Integritätsmerkmal von der Kollisionsresistenz von
    MD5 abhängt.
    """
    return hashlib.md5(value.encode()).hexdigest()
