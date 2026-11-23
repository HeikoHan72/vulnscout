"""Pre-Filter-Modell: entscheidet einen Teil der Scanner-Funde ohne
LLM-Aufruf (Kostenersparnis), siehe `scripts/train_prefilter.py` für das
Training und `prefilter.py` für die Anwendung zur Laufzeit."""

from .prefilter import apply_prefilter

__all__ = ["apply_prefilter"]
