"""Request-Modelle für die VulnScout-API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Anfrage zum Start eines neuen VulnScout-Laufs.

    Attributes:
        repo_path: Pfad des zu scannenden Repositories. Muss auf dem
            Server, auf dem die API läuft, existieren.
        semgrep_config: Semgrep-Regelwerk, das an den Scanner-Agent
            durchgereicht wird. Standard: das öffentliche
            Security-Audit-Regelwerk.
        demo_mode: Erzwingt den Demo-/Fixture-Modus (`true`, kein
            LLM-Aufruf) oder den echten LLM-Modus (`false`). Bei
            `null`/weggelassen wird automatisch anhand von
            `ANTHROPIC_API_KEY` auf dem Server entschieden.
    """

    repo_path: str = Field(
        ...,
        description="Pfad des zu scannenden Repositories (lokal auf dem Server).",
    )
    semgrep_config: str = Field(
        default="p/security-audit",
        description="Semgrep-Regelwerk (Registry-Name oder lokaler Pfad).",
    )
    demo_mode: Optional[bool] = Field(
        default=None,
        description=(
            "true = Demo-Modus ohne LLM erzwingen, false = echten LLM-Modus "
            "erzwingen, null = automatisch anhand von ANTHROPIC_API_KEY entscheiden."
        ),
    )
