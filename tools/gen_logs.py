"""Seeded generator of synthetic, labelled access logs.

What it does: writes ``events.csv`` and ``labels.csv`` in the toolkit's practice
format, ``approvals.json`` in the same shape, ``context.json`` (the invented world)
and ``manifest.json`` (seed, counts and the incidents behind attack labels). The
same seed and size always produce the same bytes.

    python tools/gen_logs.py --out DIR [--seed N | --held-out] [--events 12000]

Independence: written from the practice files, their notes and the published label
definitions only, never from the detector's code.

What it exercises: approved and unapproved role changes, approval boundaries,
wrong subject, role or approver, clock offsets that move an event across a window,
delayed delivery, routine denials after revocation, single and repeated denials,
and fast and slow movement across services.

Limits: every identity and event is invented, and the labels encode our own
assumptions. Results on this data say nothing about real-world accuracy. Offsets
stay within 5 seconds and delivery delays within 60 seconds.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

COLUMNS = (
    "event_id", "event_time_utc", "received_time_utc", "source_clock_offset_ms", "actor",
    "source_service", "target_service", "action", "role_before", "role_after", "outcome",
    "approval_id", "session_id", "correlation_id",
)
LABELS = (
    "routine", "approved_change", "unexpected_role_change", "review_after_role_change",
    "lateral_movement_candidate", "routine_delayed_delivery", "routine_clock_offset",
    "routine_denial", "isolated_denial",
)
BASE_TIME = datetime(2026, 2, 1, tzinfo=timezone.utc)
SPAN_MS = 7 * 24 * 3600 * 1000
DEFAULT_SEED = 20260115
DEFAULT_EVENTS = 12000
HELD_OUT_SEED = int.from_bytes(hashlib.sha256(b"t4-held-out-set-1").digest()[:4], "big")

ADMIN = "user-admin"
WORKER = "svc-report-worker"
REPORT_SERVICES = ("reports", "reports-node-a", "reports-node-b")
MAX_OFFSET_MS = 5000
MAX_DELAY_MS = 60000

CONTEXT = {
    "synthetic": True,
    "role_reads": {
        "viewer": ["catalog"],
        "report-reader": ["catalog", *REPORT_SERVICES],
        "operator": ["catalog", *REPORT_SERVICES],
        "service-reader": ["catalog"],
    },
    "baseline_edges": {
        "users": [["portal", "identity"], ["portal", "catalog"]],
        "report-reader": [["portal", service] for service in REPORT_SERVICES],
        WORKER: [["reports", "catalog"]],
        ADMIN: [["admin-console", "identity"]],
    },
    "authorized_approvers": [ADMIN],
    "supported_range": {"max_clock_offset_ms": MAX_OFFSET_MS, "max_delivery_delay_ms": MAX_DELAY_MS},
}


def stamp(ms: int, whole_seconds: bool = False) -> str:
    moment = BASE_TIME + timedelta(milliseconds=ms)
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    return text + "Z" if whole_seconds else f"{text}.{moment.microsecond // 1000:03d}Z"


@dataclass
class Event:
    true_ms: int
    received_ms: int
    offset_ms: int
    row: dict
    label: str
    reason: str
    incident: str = ""


@dataclass
class World:
    """Everything generated so far. All randomness comes from ``rng``."""

    rng: random.Random
    events: list[Event] = field(default_factory=list)
    approvals: list[dict] = field(default_factory=list)
    incidents: dict[str, dict] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def number(self, kind: str) -> int:
        self.counters[kind] = self.counters.get(kind, 0) + 1
        return self.counters[kind]

    def user(self) -> str:
        return f"user-{self.number('user'):05d}"

    def start(self) -> int:
        return self.rng.randrange(0, SPAN_MS)

    def gap(self, low: int = 800, high: int = 20000) -> int:
        return self.rng.randint(low, high)

    def incident(self, kind: str, actor: str, **extra: object) -> str:
        name = f"inc-{self.number('incident'):05d}"
        self.incidents[name] = {"kind": kind, "actor": actor, **extra}
        return name


@dataclass
class Session:
    world: World
    actor: str
    session_id: str = ""
    correlation_id: str = ""

    def __post_init__(self) -> None:
        if not self.session_id:
            self.session_id = f"sess-{self.world.number('session'):06d}"
        if not self.correlation_id:
            self.new_flow()

    def new_flow(self) -> None:
        self.correlation_id = f"flow-{self.world.number('flow'):06d}"

    def emit(
        self, at: int, source: str, target: str, action: str, role: str, outcome: str,
        label: str, reason: str, *, after: str | None = None, approval: str = "",
        offset: int = 0, delay: int | None = None, incident: str = "",
    ) -> Event:
        if delay is None:
            delay = self.world.rng.randint(80, 320)
        row = {
            "source_clock_offset_ms": offset, "actor": self.actor, "source_service": source,
            "target_service": target, "action": action, "role_before": role,
            "role_after": role if after is None else after, "outcome": outcome,
            "approval_id": approval, "session_id": self.session_id,
            "correlation_id": self.correlation_id,
        }
        event = Event(at, at + delay, offset, row, label, reason, incident)
        self.world.events.append(event)
        return event

    def sign_in(self, at: int, role: str = "viewer") -> None:
        self.emit(at, "portal", "identity", "sign_in", role, "success", "routine", "Normal sign-in")

    def read(self, at: int, target: str, role: str, outcome: str, label: str, reason: str, **more: object) -> Event:
        source = "reports" if self.actor == WORKER else "portal"
        return self.emit(at, source, target, "read", role, outcome, label, reason, **more)


# ---- helpers for approvals and role changes ------------------------------------


def add_approval(
    world: World, subject: str, role: str, start: int, end: int, *, approver: str = ADMIN,
    announce: bool = True,
) -> str:
    """Record a grant approval; ``announce`` also logs the operator approving it."""
    approval_id = f"change-{world.number('change'):05d}"
    world.approvals.append({
        "approval_id": approval_id, "approved_by": approver, "subject": subject,
        "operation": "grant_role", "role": role, "scope": list(REPORT_SERVICES),
        "valid_from_utc": stamp(start, True), "valid_until_utc": stamp(end, True),
    })
    if announce:
        Session(world, approver).emit(
            start - world.rng.randint(0, 500), "admin-console", "identity", "approve_role_change",
            "operator", "success", "approved_change", "Operator approves a role change",
            approval=approval_id,
        )
    return approval_id


def second(ms: int) -> int:
    """Round down to a whole second, the precision of approval windows."""
    return ms - ms % 1000


def change_role(
    session: Session, at: int, role: str, label: str, reason: str, *, approval: str = "",
    offset: int = 0, incident: str = "",
) -> None:
    session.emit(
        at, "admin-console", "identity", "role_change", "viewer", "success", label, reason,
        after=role, approval=approval, offset=offset, incident=incident,
    )


def follow_up_reads(session: Session, at: int, role: str, incident: str) -> None:
    rng = session.world.rng
    for _ in range(rng.randint(0, 3)):
        at += session.world.gap(800, 15000)
        session.read(
            at, rng.choice(REPORT_SERVICES), role, "allow", "review_after_role_change",
            "Allowed read follows an unexpected role change in the same session", incident=incident,
        )


# ---- benign scenarios ------------------------------------------------------------


def browse(world: World) -> None:
    session, at = Session(world, world.user()), world.start()
    session.sign_in(at)
    for _ in range(world.rng.randint(1, 5)):
        at += world.gap()
        session.read(at, "catalog", "viewer", "allow", "routine", "Viewer reads catalog")
    if world.rng.random() < 0.5:
        session.emit(at + world.gap(), "portal", "identity", "sign_out", "viewer", "success",
                     "routine", "Normal sign-out")


def approved_grant(world: World, at: int | None = None) -> None:
    rng = world.rng
    user = world.user()
    session = Session(world, user)
    at = second(world.start() if at is None else at)
    session.sign_in(at)
    valid_from = at + 5000
    valid_until = valid_from + rng.randint(5, 60) * 60000
    approval = add_approval(world, user, "report-reader", valid_from, valid_until)
    changed = valid_from + rng.randint(100, 4000)
    change_role(session, changed, "report-reader", "approved_change",
                "Subject, role and time match the approval", approval=approval)
    at = changed
    for _ in range(rng.randint(1, 4)):
        at += world.gap(800, 30000)
        session.read(at, rng.choice(REPORT_SERVICES), "report-reader", "allow", "routine",
                     "Read within the approved role scope", approval=approval)
    ending = rng.choice(("revoke", "expire", "none"))
    if ending == "none":
        return
    if ending == "revoke":
        at = second(at + world.gap(2000, 30000))
        revocation = f"change-{world.number('change'):05d}"
        world.approvals.append({
            "approval_id": revocation, "approved_by": ADMIN, "subject": user,
            "operation": "revoke_role", "role": "report-reader", "effective_at_utc": stamp(at, True),
        })
        Session(world, ADMIN).emit(at, "admin-console", "identity", "revoke_role", "operator",
                                   "success", "approved_change", "Operator revokes the role",
                                   approval=revocation)
        cited = revocation
    else:
        at, cited = valid_until, ""
    session.new_flow()
    for target in rng.sample(REPORT_SERVICES, rng.randint(1, 3)):
        at += world.gap(500, 4000)
        session.read(at, target, "viewer", "deny", "routine_denial",
                     "Denied after the role ended", approval=cited)
    session.read(at + world.gap(), "catalog", "viewer", "allow", "routine",
                 "Catalog access remains available")


def admin_burst(world: World) -> None:
    at = world.start()
    for index in range(world.rng.randint(4, 9)):
        approved_grant(world, at + index * world.rng.randint(1500, 5000))


def boundary_approved(world: World) -> None:
    """Valid changes at the very edges of a window, some seen through a skewed clock."""
    user = world.user()
    session, start = Session(world, user), second(world.start())
    end = start + world.rng.randint(2, 20) * 60000
    approval = add_approval(world, user, "report-reader", start, end)
    edge = world.rng.choice(("first_instant", "last_instant", "skew_late", "skew_early"))
    offset = 0
    if edge == "first_instant":
        at = start
    elif edge == "last_instant":
        at = end - 1
    elif edge == "skew_late":  # raw time is after the window, corrected time is inside
        at, offset = end - world.rng.randint(1, 1500), world.rng.randint(2000, MAX_OFFSET_MS)
    else:  # raw time is before the window, corrected time is inside
        at, offset = start + world.rng.randint(0, 1500), -world.rng.randint(2000, MAX_OFFSET_MS)
    change_role(session, at, "report-reader", "approved_change",
                f"Approved change at a window edge ({edge})", approval=approval, offset=offset)


def delayed_pair(world: World) -> None:
    session, at = Session(world, world.user()), world.start()
    later = at + world.gap(500, 5000)
    delay = later - at + world.rng.randint(1000, MAX_DELAY_MS - 6000)
    session.read(at, "catalog", "viewer", "allow", "routine_delayed_delivery",
                 "Older event arrives after a newer one", delay=delay)
    session.read(later, "catalog", "viewer", "allow", "routine", "Newer read arrives first", delay=200)


def skewed_reads(world: World) -> None:
    session, at = Session(world, world.user()), world.start()
    offset = world.rng.choice((-1, 1)) * world.rng.randint(500, MAX_OFFSET_MS)
    for _ in range(world.rng.randint(1, 3)):
        at += world.gap()
        session.read(at, "catalog", "viewer", "allow", "routine_clock_offset",
                     "Source clock differs from the collector clock", offset=offset)


def worker_routine(world: World) -> None:
    session, at = Session(world, WORKER), world.start()
    for _ in range(world.rng.randint(1, 6)):
        at += world.gap()
        session.read(at, "catalog", "service-reader", "allow", "routine", "Known service edge")


def isolated_denial(world: World) -> None:
    session, at = Session(world, world.user()), world.start()
    session.sign_in(at)
    session.read(at + world.gap(), world.rng.choice(("billing", "archive", "reports")), "viewer",
                 "deny", "isolated_denial", "One denied request is not a movement sequence")


def repeated_denial(world: World) -> None:
    session, at = Session(world, world.user()), world.start()
    target = world.rng.choice(("billing", "archive", "reports"))
    for _ in range(world.rng.randint(2, 4)):
        at += world.gap(500, 8000)
        session.read(at, target, "viewer", "deny", "isolated_denial",
                     "Retries against one service do not cross services")


def spread_denials(world: World) -> None:
    user, at = world.user(), world.start()
    for target in world.rng.sample(("billing", "archive", "reports"), 2):
        Session(world, user).read(at, target, "viewer", "deny", "isolated_denial",
                                  "Unrelated denials hours apart, in separate sessions")
        at += world.rng.randint(2, 20) * 3600 * 1000


# ---- suspicious scenarios --------------------------------------------------------


def unapproved_change(world: World) -> None:
    user = world.user()
    session, at = Session(world, user), world.start()
    session.sign_in(at)
    at += world.gap()
    role = world.rng.choice(("operator", "report-reader"))
    offset = world.rng.choice((0, 0, 0, world.rng.randint(-MAX_OFFSET_MS, MAX_OFFSET_MS)))
    incident = world.incident("unapproved_change", user, variant="no_approval")
    change_role(session, at, role, "unexpected_role_change", "No approval exists for this change",
                offset=offset, incident=incident)
    follow_up_reads(session, at, role, incident)


def mismatched_change(world: World) -> None:
    """A change that cites a real approval which does not cover it."""
    rng = world.rng
    user = world.user()
    session, start = Session(world, user), second(world.start())
    end = start + rng.randint(2, 20) * 60000
    variant = rng.choice(("expired", "at_end", "early", "wrong_subject", "wrong_role",
                          "unauthorized_approver", "skew_hides_expiry"))
    subject, role, approver, offset = user, "report-reader", ADMIN, 0
    at = start + rng.randint(100, 5000)
    if variant == "expired":
        at = end + rng.randint(1000, 600000)
    elif variant == "at_end":  # the end of a window is exclusive
        at = end
    elif variant == "early":
        at = start - rng.randint(1000, 300000)
    elif variant == "wrong_subject":
        subject = world.user()
    elif variant == "wrong_role":
        role = "operator"
    elif variant == "unauthorized_approver":
        approver = world.user()
    else:  # raw time looks inside the window, corrected time is after it
        at, offset = end + rng.randint(1, 1500), -rng.randint(2000, MAX_OFFSET_MS)
    approval = add_approval(world, subject, "report-reader", start, end, approver=approver,
                            announce=approver == ADMIN)
    incident = world.incident("unapproved_change", user, variant=variant)
    change_role(session, at, role, "unexpected_role_change",
                f"The cited approval does not cover this change ({variant})",
                approval=approval, offset=offset, incident=incident)
    follow_up_reads(session, at, role, incident)


def lateral_movement(world: World) -> None:
    rng = world.rng
    worker = rng.random() < 0.6
    actor = WORKER if worker else world.user()
    session, at = Session(world, actor), world.start()
    role = "service-reader" if worker else "viewer"
    if worker:
        session.read(at, "catalog", role, "allow", "routine", "Known service edge")
    else:
        session.sign_in(at)
    session.new_flow()
    targets = rng.sample(("billing", "archive", "identity"), rng.randint(2, 3))
    if targets[0] == "identity":  # portal to identity is a normal edge, so never start there
        targets.append(targets.pop(0))
    slow = rng.random() < 0.15
    pace = "slow" if slow else "fast"
    incident = world.incident("lateral_movement", actor, pace=pace, targets=targets)
    credentials_work = rng.random() < 0.35
    source = "reports" if worker else "portal"
    for target in targets:
        at += rng.randint(70000, 150000) if slow else rng.randint(400, 12000)
        outcome = "allow" if credentials_work and rng.random() < 0.7 else "deny"
        action = "list_roles" if target == "identity" else "read"
        session.emit(at, source, target, action, role, outcome, "lateral_movement_candidate",
                     f"Unexpected service edge in one session ({pace} sequence)", incident=incident,
                     offset=rng.choice((0, 0, 0, 0, rng.randint(-MAX_OFFSET_MS, MAX_OFFSET_MS))))
        source = target  # each hop starts where the previous one ended


SCENARIOS: tuple[tuple[object, int], ...] = (
    (browse, 30), (approved_grant, 14), (admin_burst, 1), (boundary_approved, 5),
    (delayed_pair, 7), (skewed_reads, 7), (worker_routine, 10), (isolated_denial, 6),
    (repeated_denial, 3), (spread_denials, 3), (unapproved_change, 3), (mismatched_change, 5),
    (lateral_movement, 4),
)


def generate(seed: int, minimum_events: int = DEFAULT_EVENTS) -> dict[str, bytes]:
    """Return the file contents for ``seed``: at least ``minimum_events`` events."""
    world = World(random.Random(seed))
    for scenario, _weight in SCENARIOS:  # every scenario appears at least a few times
        for _ in range(3):
            scenario(world)
    functions = [scenario for scenario, _ in SCENARIOS]
    weights = [weight for _, weight in SCENARIOS]
    while len(world.events) < minimum_events:
        world.rng.choices(functions, weights)[0](world)

    in_event_order = sorted(range(len(world.events)), key=lambda i: (world.events[i].true_ms, i))
    identifiers = {index: f"evt-{rank:06d}" for rank, index in enumerate(in_event_order, start=1)}
    in_receipt_order = sorted(identifiers, key=lambda i: (world.events[i].received_ms, identifiers[i]))

    events_text, labels_text = io.StringIO(), io.StringIO()
    events_csv = csv.DictWriter(events_text, COLUMNS, lineterminator="\n")
    labels_csv = csv.DictWriter(labels_text, ("event_id", "label", "reason"), lineterminator="\n")
    events_csv.writeheader()
    labels_csv.writeheader()
    counts = dict.fromkeys(LABELS, 0)
    for index in in_receipt_order:
        event = world.events[index]
        event_id = identifiers[index]
        events_csv.writerow({
            "event_id": event_id,
            "event_time_utc": stamp(event.true_ms + event.offset_ms),
            "received_time_utc": stamp(event.received_ms),
            **event.row,
        })
        labels_csv.writerow({"event_id": event_id, "label": event.label, "reason": event.reason})
        counts[event.label] += 1
        if event.incident:
            incident = world.incidents[event.incident]
            incident.setdefault("events", []).append((event.true_ms, event_id))
    for incident in world.incidents.values():
        ordered = sorted(incident["events"])
        incident["first_event_time_utc"] = stamp(ordered[0][0])  # corrected (collector) time
        incident["events"] = [event_id for _, event_id in ordered]

    manifest = {
        "synthetic": True, "seed": seed, "events": len(world.events), "label_counts": counts,
        "incidents": world.incidents,
    }
    approvals = {"synthetic": True, "changes": world.approvals}

    def as_json(value: object) -> bytes:
        return (json.dumps(value, indent=1, sort_keys=True) + "\n").encode("utf-8")

    return {
        "events.csv": events_text.getvalue().encode("utf-8"),
        "labels.csv": labels_text.getvalue().encode("utf-8"),
        "approvals.json": as_json(approvals),
        "context.json": as_json(CONTEXT),
        "manifest.json": as_json(manifest),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic labelled access logs.")
    parser.add_argument("--out", required=True, help="output directory (use one outside the repository)")
    which = parser.add_mutually_exclusive_group()
    which.add_argument("--seed", type=int, default=DEFAULT_SEED)
    which.add_argument("--held-out", action="store_true", help="final evaluation set: do not tune on it")
    parser.add_argument("--events", type=int, default=DEFAULT_EVENTS, help="minimum number of events")
    args = parser.parse_args(argv)
    if not 0 < args.events <= 500000:
        parser.error("--events must be between 1 and 500000")
    seed = HELD_OUT_SEED if args.held_out else args.seed
    files = generate(seed, args.events)
    try:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            (out / name).write_bytes(content)
    except OSError:
        print("could not write the output directory", file=sys.stderr)
        return 2
    summary = json.loads(files["manifest.json"])
    print(json.dumps({"seed": seed, "events": summary["events"], "label_counts": summary["label_counts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
