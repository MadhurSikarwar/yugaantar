"""Command-line interface for the detector.

Usage (from the repository root)::

    python -m t4.detect.cli detect   --dir <folder with events.csv and approvals.json> [--json]
    python -m t4.detect.cli evaluate --dir <folder that also has labels.csv> [--json]
    python -m t4.detect.cli timeline --dir <folder> [--json]

``--events``, ``--approvals`` and ``--labels`` override single files.
``detect`` prints alerts and per-event labels; ``evaluate`` adds precision,
recall, F1, time to alert and false alerts per 1,000 benign events;
``timeline`` shows raw and corrected times side by side (goal 8).

Exit codes: 0 success, 2 unreadable or invalid input (generic message on
stderr, no traceback).

What it defends against
    Input errors never produce a traceback or partial output; labels are read
    only by ``evaluate``, never by detection.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
from pathlib import Path

from . import engine, metrics
from .config import DEFAULT_CONFIG
from .ingest import iso_z, load_approvals, load_events, load_labels
from .policy_file import apply_policy_file


def _paths(args: argparse.Namespace) -> tuple[Path, Path, Path | None]:
    base = Path(args.dir) if args.dir else None
    events = Path(args.events) if args.events else (base / "events.csv" if base else None)
    approvals = Path(args.approvals) if args.approvals else (base / "approvals.json" if base else None)
    labels = Path(args.labels) if getattr(args, "labels", None) else (base / "labels.csv" if base else None)
    if events is None or approvals is None:
        raise ValueError("give --dir, or both --events and --approvals")
    return events, approvals, labels


def _config(args: argparse.Namespace):
    """Default config, with the authorized approvers replaced when the operator names them.

    Names come from ``--approver`` (repeatable) or the ``T4_APPROVERS`` environment variable
    (comma separated). The change register is never used to name its own approvers.
    """
    names = list(getattr(args, "approver", None) or [])
    if any(not str(n).strip() for n in names):
        raise ValueError("--approver needs a non-empty name")
    if not names:
        names = [n.strip() for n in os.environ.get("T4_APPROVERS", "").split(",") if n.strip()]
    base = DEFAULT_CONFIG
    if getattr(args, "policy", None):
        base = apply_policy_file(Path(args.policy), base)
    if not names:
        return base
    return dataclasses.replace(base, authorized_approvers=frozenset(names))


def _events(path: Path) -> list:
    ignored: list[str] = []
    events = load_events(path, redelivered=ignored)
    if ignored:
        print(f"note: ignored {len(ignored)} re-delivered event(s), first: {ignored[0]!r}", file=sys.stderr)
    conflicted = [e.event_id for e in events if e.conflicting]
    if conflicted:
        print(f"note: {len(conflicted)} event ID(s) were reused with different content; the first record "
              f"was analysed (see DET-CONFLICTING-DUPLICATE), first: {conflicted[0]!r}", file=sys.stderr)
    return events


def _dump(obj: object) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, allow_nan=False))


def _fmt(value: object) -> str:
    return "n/a" if value is None else (f"{value:.3f}" if isinstance(value, float) else str(value))


def cmd_detect(args: argparse.Namespace) -> int:
    events_path, approvals_path, _ = _paths(args)
    events = _events(events_path)
    started = time.perf_counter()
    result = engine.analyze(events, load_approvals(approvals_path), _config(args))
    elapsed_ms = (time.perf_counter() - started) * 1000
    if args.json:
        _dump({
            "alerts": [a.to_dict() for a in result.alerts],
            "labels": {e.event_id: vars(result.labels[e.event_id]) for e in events},
            "events": len(events),
            "processing_ms": round(elapsed_ms, 3),
        })
        return 0
    print(f"{len(events)} events, {len(result.alerts)} alerts ({elapsed_ms:.1f} ms)\n")
    for alert in result.alerts:
        print(f"[{alert.severity.upper()}] {alert.rule}  {alert.alert_id}")
        print(f"  identity: {alert.identity}   services: {', '.join(alert.services)}")
        print(f"  events:   {', '.join(alert.event_ids)}   emitted_at: {alert.emitted_at}"
              f"{'   ORDER UNCERTAIN' if alert.order_uncertain else ''}")
        if alert.evidence_complete_at and alert.evidence_complete_at != alert.emitted_at:
            later = [e for e in alert.event_ids if e not in alert.initial_event_ids]
            print(f"  later evidence: {', '.join(later)} (complete at {alert.evidence_complete_at})")
        print(f"  why:      {alert.explanation}\n")
    if args.labels_out:
        for event in events:
            c = result.labels[event.event_id]
            print(f"{event.event_id:<12} {c.label:<28} {c.rule:<30} {c.reason}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    events_path, approvals_path, labels_path = _paths(args)
    if labels_path is None:
        raise ValueError("give --labels or --dir")
    events = _events(events_path)
    started = time.perf_counter()
    result = engine.analyze(events, load_approvals(approvals_path), _config(args))
    elapsed_ms = (time.perf_counter() - started) * 1000
    truth = load_labels(labels_path)
    report = metrics.evaluate(events, result.predicted(), truth, result.alerts)
    report["processing_ms"] = round(elapsed_ms, 3)
    if args.json:
        _dump(report)
        return 0
    cls = report["classification"]
    print(f"events: {cls['events']}   correct: {cls['correct']}   accuracy: {_fmt(cls['accuracy'])}"
          f"   processing: {elapsed_ms:.1f} ms\n")
    print(f"{'label':<28} {'support':>7} {'precision':>9} {'recall':>7} {'f1':>7}")
    for label, row in cls["per_class"].items():
        print(f"{label:<28} {row['support']:>7} {_fmt(row['precision']):>9} {_fmt(row['recall']):>7} {_fmt(row['f1']):>7}")
    tta = report["time_to_alert"]
    fa = report["false_alerts"]
    print(f"\nincidents detected: {tta['detected']}/{tta['incidents']}   median time to alert "
          f"(event timeline reconstructed from receipt times; processing {elapsed_ms:.1f} ms): "
          f"{_fmt(tta['median_s'])} s   max: {_fmt(tta['max_s'])} s")
    print(f"alerts: {fa['alerts']}   false alerts: {fa['false_alerts']}   "
          f"per 1,000 benign events: {_fmt(fa['per_1000_benign'])} (benign events: {fa['benign_events']})")
    if cls["mismatches"]:
        print("\nmismatches:")
        for event_id in cls["mismatches"]:
            c = result.labels[event_id]
            print(f"  {event_id}: expected {truth[event_id]}, got {c.label} ({c.rule}: {c.reason})")
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    events_path, approvals_path, _ = _paths(args)
    events = _events(events_path)
    result = engine.analyze(events, load_approvals(approvals_path), _config(args))
    ordered = sorted(events, key=lambda e: (e.corrected_time, e.receipt_index))
    rows = [{
        "event_id": e.event_id,
        "receipt_index": e.receipt_index,
        "event_time_utc": e.event_time_utc,
        "source_clock_offset_ms": e.source_clock_offset_ms,
        "corrected_time_utc": iso_z(e.corrected_time),
        "received_time_utc": e.received_time_utc,
        "delivery_delay_ms": round(e.delivery_delay_ms, 3),
        "order_uncertain": e.event_id in result.order_uncertain,
        "label": result.labels[e.event_id].label,
    } for e in ordered]
    if args.json:
        _dump(rows)
        return 0
    print(f"{'event':<10} {'rcpt':>4} {'raw event time':<25} {'offset':>7} {'corrected time':<25} "
          f"{'received':<25} {'delay ms':>9}  label")
    for r in rows:
        print(f"{r['event_id']:<10} {r['receipt_index']:>4} {r['event_time_utc']:<25} "
              f"{r['source_clock_offset_ms']:>7} {r['corrected_time_utc']:<25} {r['received_time_utc']:<25} "
              f"{r['delivery_delay_ms']:>9.0f}  {r['label']}{'  (order uncertain)' if r['order_uncertain'] else ''}")
    return 0


def _named(values: list[str] | None, what: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for value in values or []:
        name, sep, path = value.partition("=")
        if not sep or not name or not path:
            raise ValueError(f"{what} must look like NAME=PATH")
        out[name] = path
    return out


def cmd_export(args: argparse.Namespace) -> int:
    from . import export as exp
    from .ingest import load_approvals as _load_approvals

    pins = _named(args.pin, "--pin")
    sources = []
    named_logs = [(name, path, "node") for name, path in _named(args.node, "--node").items()]
    if args.authority:
        named_logs.append(("authority", args.authority, "authority"))
    if not named_logs:
        raise ValueError("give at least one --node NAME=DIR or --authority DIR")
    for name, path, kind in named_logs:
        pin = json.loads(Path(pins[name]).read_text(encoding="utf-8")) if name in pins else None
        if pin is not None and not (isinstance(pin, dict) and isinstance(pin.get("public_key"), str)
                                    and pin["public_key"]):
            raise ValueError(f"the pin for {name} has no public key")
        key = bytes.fromhex(pin["public_key"]) if pin is not None else None
        sources.append(exp.LogSource(Path(path), kind, name, pin, key))
    approvals = _load_approvals(Path(args.approvals)) if args.approvals else {}
    owners = json.loads(Path(args.owners).read_text(encoding="utf-8")) if args.owners else None
    approvers = sorted(_config(args).authorized_approvers) if (args.approver or os.environ.get("T4_APPROVERS", "").strip()) else None
    try:
        result = exp.run_export(sources, approvals, owners=owners, approvers=approvers,
                                alert_log=Path(args.append_alerts) if args.append_alerts else None)
    except exp.ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.out_csv:
        Path(args.out_csv).write_text(result.csv(), encoding="utf-8", newline="")
    summary = {
        "verified": result.verified,
        "events": len(result.rows),
        "alerts": [a.to_dict() for a in result.result.alerts],
        "appended": result.appended,
        "baseline_source": result.baseline_source,
    }
    if args.json:
        _dump(summary)
        return 0
    for v in result.verified:
        print(f"verified {v['kind']} log {v['log']}: {v['entries']} entries, ok "
              f"(covered to seq {v['covered_seq']}, head pinned: {v['head_pinned']}, key pinned: {v['key_pinned']})")
    if result.baseline_source != "provisioning":
        print("NOTE: no --owners given: the expected-access baseline was INFERRED from what each actor "
              "was allowed to read in this window (not evidence quality). Pass --owners FILE for an "
              "ownership-based baseline.")
    print(f"{len(result.rows)} events exported, {len(result.result.alerts)} alerts, "
          f"{len(result.appended)} newly appended to the audit log\n")
    for alert in result.result.alerts:
        print(f"[{alert.severity.upper()}] {alert.rule}  identity: {alert.identity}")
        print(f"  services: {', '.join(alert.services)}   events: {', '.join(alert.event_ids)}")
        print(f"  why: {alert.explanation}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m t4.detect.cli", description="Explainable rules-based detector")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, func, help_text in (
        ("detect", cmd_detect, "raise alerts"),
        ("evaluate", cmd_evaluate, "compare with labels.csv"),
        ("timeline", cmd_timeline, "raw vs corrected times"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--dir", help="folder with events.csv, approvals.json (and labels.csv)")
        p.add_argument("--events")
        p.add_argument("--approvals")
        p.add_argument("--approver", action="append",
                       help="authorized approver (repeatable; default user-admin, or T4_APPROVERS)")
        p.add_argument("--policy", help="JSON file with role_scope (see t4/detect/policy_file.py)")
        if name == "evaluate":
            p.add_argument("--labels")
        if name == "detect":
            p.add_argument("--labels-out", action="store_true", help="also print every event's label")
        p.add_argument("--json", action="store_true")
        p.set_defaults(func=func)
    p = sub.add_parser("export", help="verify our own logs, detect, append alerts ")
    p.add_argument("--node", action="append", help="node log as NODE_ID=DIR (repeatable)")
    p.add_argument("--authority", help="authority key-event log directory")
    p.add_argument("--pin", action="append", help="pinned head as NAME=FILE (from 'audit.cli head --out')")
    p.add_argument("--approvals", help="change register in approvals.json format")
    p.add_argument("--owners", help='node provisioning {"node": {"asset": "owner"}} used as baseline')
    p.add_argument("--approver", action="append", help="authorized approver (repeatable)")
    p.add_argument("--append-alerts", metavar="DIR", help="audit log to append alerts to")
    p.add_argument("--out-csv", help="also write the exported events as CSV")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else "cannot read input file"
        print(f"error: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
