"""Netzwerkbezogene Funktionen (SSRF, TLS, XXE) - absichtlich verwundbar."""

import xml.etree.ElementTree as ET

import requests


def fetch_remote_resource(url: str):
    """SSRF (Finding): Eine vom Benutzer übergebene URL wird ungeprüft
    angefragt - kein Allowlist- oder Schema-Check, kein Schutz gegen interne
    Adressen (z. B. `169.254.169.254` für Cloud-Metadaten).
    """
    return requests.get(url, timeout=5)


def fetch_insecure(url: str):
    """Deaktivierte TLS-Zertifikatsprüfung (Finding): `verify=False` erlaubt
    Man-in-the-Middle-Angriffe.
    """
    return requests.get(url, verify=False, timeout=5)


def parse_remote_xml(xml_data: str):
    """XML External Entity - XXE (Finding): `xml.etree.ElementTree` verarbeitet
    nicht vertrauenswürdige Eingaben ohne Schutz gegen externe Entities.
    """
    return ET.fromstring(xml_data)
