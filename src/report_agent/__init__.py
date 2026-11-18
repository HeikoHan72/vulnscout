"""Report-Agent: fasst triagierte Funde zu einem lesbaren Bericht
mit Fix-Vorschlägen zusammen.
"""

from .models import ReportContext
from .report import build_report_context, generate_report

__all__ = ["ReportContext", "build_report_context", "generate_report"]
