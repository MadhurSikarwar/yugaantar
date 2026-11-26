"""Evaluation metrics for the detector.

What it does
    Compares predicted labels with ground-truth labels and reports:

    * per-class precision, recall, F1 and support, plus overall accuracy and a
      confusion table;
    * time to alert per incident: ``emitted_at`` of the earliest alert that
      cites any event of the incident, minus the corrected event time of the
      incident's first labelled event. An incident is the set of suspicious
      labelled events sharing actor, session and correlation ID. This is
      detection delay on the event timeline, not processing time;
    * false alerts per 1,000 benign events: an alert is false if none of the
      events it cites carries a suspicious truth label.

What it defends against
    Overclaiming. Ground truth is used only here, never by detection, and the
    report states the sample size so a 22-row result is not read as accuracy.
"""

from __future__ import annotations

import statistics
from datetime import timedelta
from typing import Iterable, Mapping, Sequence

from .engine import LABELS, SUSPICIOUS_LABELS, Alert
from .ingest import Event, parse_utc


def classification_report(predicted: Mapping[str, str], truth: Mapping[str, str]) -> dict:
    """Per-class precision, recall and F1 over the events present in ``truth``."""
    missing = sorted(set(truth) - set(predicted))
    if missing:
        raise ValueError(f"no prediction for {len(missing)} labelled events, e.g. {missing[0]}")
    classes = sorted(set(LABELS) | set(truth.values()) | set(predicted.values()))
    confusion: dict[str, dict[str, int]] = {t: {} for t in classes}
    for event_id, true_label in truth.items():
        pred = predicted[event_id]
        confusion[true_label][pred] = confusion[true_label].get(pred, 0) + 1
    per_class = {}
    for label in classes:
        tp = confusion[label].get(label, 0)
        fn = sum(confusion[label].values()) - tp
        fp = sum(confusion[t].get(label, 0) for t in classes if t != label)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = (2 * precision * recall / (precision + recall)
              if precision and recall else (0.0 if precision is not None and recall is not None else None))
        per_class[label] = {"tp": tp, "fp": fp, "fn": fn, "support": tp + fn,
                            "precision": precision, "recall": recall, "f1": f1}
    correct = sum(1 for e, t in truth.items() if predicted[e] == t)
    return {
        "events": len(truth),
        "correct": correct,
        "accuracy": correct / len(truth) if truth else None,
        "per_class": per_class,
        "confusion": {t: dict(sorted(row.items())) for t, row in confusion.items() if row},
        "mismatches": sorted(e for e, t in truth.items() if predicted[e] != t),
    }


def incidents(events: Sequence[Event], truth: Mapping[str, str]) -> list[list[Event]]:
    """Group suspicious-labelled events by (actor, session, correlation)."""
    groups: dict[tuple[str, str, str], list[Event]] = {}
    for event in events:
        if truth.get(event.event_id) in SUSPICIOUS_LABELS:
            groups.setdefault((event.actor, event.session_id, event.correlation_id), []).append(event)
    return [sorted(g, key=lambda e: e.corrected_time) for g in groups.values()]


def time_to_alert(events: Sequence[Event], truth: Mapping[str, str], alerts: Iterable[Alert]) -> dict:
    """Per-incident detection delay in seconds, with median and misses."""
    alerts = list(alerts)
    delays: list[float] = []
    detected = 0
    missed: list[str] = []
    for incident in incidents(events, truth):
        ids = {e.event_id for e in incident}
        hits = [parse_utc(a.emitted_at) for a in alerts if ids & set(a.event_ids)]
        if not hits:
            missed.append(incident[0].event_id)
            continue
        detected += 1
        delays.append((min(hits) - incident[0].corrected_time) / timedelta(seconds=1))
    return {
        "incidents": detected + len(missed),
        "detected": detected,
        "missed_first_event_ids": missed,
        "median_s": statistics.median(delays) if delays else None,
        "max_s": max(delays) if delays else None,
        "delays_s": delays,
    }


def false_alerts(truth: Mapping[str, str], alerts: Iterable[Alert]) -> dict:
    """False alerts per 1,000 benign events."""
    alerts = list(alerts)
    benign = sum(1 for label in truth.values() if label not in SUSPICIOUS_LABELS)
    false = [a for a in alerts if not any(truth.get(e) in SUSPICIOUS_LABELS for e in a.event_ids)]
    return {
        "alerts": len(alerts),
        "false_alerts": len(false),
        "false_alert_ids": [a.alert_id for a in false],
        "benign_events": benign,
        "per_1000_benign": (1000 * len(false) / benign) if benign else None,
    }


def evaluate(events: Sequence[Event], predicted: Mapping[str, str],
             truth: Mapping[str, str], alerts: Iterable[Alert]) -> dict:
    """All metrics in one report."""
    alerts = list(alerts)
    return {
        "classification": classification_report(predicted, truth),
        "time_to_alert": time_to_alert(events, truth, alerts),
        "false_alerts": false_alerts(truth, alerts),
    }
