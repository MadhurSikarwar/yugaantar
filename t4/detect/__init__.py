"""Explainable, rules-based detector for access and administration events.

Modules: ``ingest`` (parse events and approvals), ``config`` (thresholds),
``rules`` (individual checks), ``engine`` (labels and alerts), ``metrics``
(evaluation), ``export`` (our own logs to detector format), ``cli``.
No machine learning is used anywhere in this package.
"""

from .config import DEFAULT_CONFIG, DetectConfig
from .engine import LABELS, SUSPICIOUS_LABELS, Alert, Classification, Result, analyze, run
from .ingest import Approval, Event, load_approvals, load_events, load_labels

__all__ = [
    "DEFAULT_CONFIG", "DetectConfig", "LABELS", "SUSPICIOUS_LABELS", "Alert", "Classification",
    "Result", "analyze", "run", "Approval", "Event", "load_approvals", "load_events", "load_labels",
]
