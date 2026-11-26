"""Self-defence: count suspicious events and raise bounded alerts (owner: c1; PRD S-A9, M-A12).

What it does
    Watches four kinds of events and turns them into ``Alert`` objects that the
    service writes to the audit log with a rule ID and a plain explanation:

        GRD-REPEATED-DENIAL        one presented identity keeps being denied
        AUD-DUPLICATE-REQUEST-ID   a ``request_id`` was reused
        AUD-INVALID-INPUT          malformed requests keep arriving
        STO-INTEGRITY-FAILURE      stored state failed its integrity check

THE MOST IMPORTANT RULE
    **The guard never changes the outcome of a request.** In the adapter the
    ``actor`` is an unproven string: anyone can send bad requests in an owner's
    name. If the guard blocked or throttled that name, an attacker could lock
    the real owner out. So in the adapter it only *observes and reports*.
    (Blocking responses are allowed only in the node layer, where a device has
    proved itself with a signature.)

Bounded log growth
    An attacker must not be able to flood the audit log through the guard. Alerts
    are raised on a back-off schedule: the first one at the threshold, then each
    time the count doubles (5, 10, 20, 40 ... denials; 1, 2, 4, 8 ... invalid
    requests). Counters are capped and only 1000 identities are tracked; the
    rest share one counter.

The class is pure: it takes the persisted ``guard`` document, updates it in
memory and returns alerts. ``t4.service`` stores the document and appends the
alerts.
"""
from __future__ import annotations

from dataclasses import dataclass

RULE_REPEATED_DENIAL = "GRD-REPEATED-DENIAL"
RULE_DUPLICATE_ID = "AUD-DUPLICATE-REQUEST-ID"
RULE_INVALID_INPUT = "AUD-INVALID-INPUT"
RULE_INTEGRITY = "STO-INTEGRITY-FAILURE"

DENIAL_THRESHOLD = 5
MAX_TRACKED_ACTORS = 1000
COUNTER_CAP = 2**31
OTHER_BUCKET = "(other)"


@dataclass(frozen=True)
class Alert:
    """One alert for the audit log. ``detail`` values are plain strings, ints or bools."""

    rule: str
    explanation: str
    detail: dict[str, str | int | bool]


def _is_power_of_two(n: int) -> bool:
    return n > 0 and n & (n - 1) == 0


def _backoff_due(count: int, first: int) -> bool:
    """True when ``count`` is ``first``, ``2*first``, ``4*first``, ..."""
    if count < first or count % first:
        return False
    return _is_power_of_two(count // first)


class Guard:
    def __init__(self, doc: dict | None = None) -> None:
        doc = doc or {}
        self._denials: dict[str, int] = dict(doc.get("denials", {}))
        self._invalid: dict[str, int] = dict(doc.get("invalid", {}))
        self._duplicates: int = int(doc.get("duplicates", 0))

    def to_doc(self) -> dict:
        return {"denials": self._denials, "invalid": self._invalid, "duplicates": self._duplicates}

    # -- events -----------------------------------------------------------

    def on_denial(self, actor: str, *, asset: str, entry_seq: int) -> list[Alert]:
        key = actor if (actor in self._denials or len(self._denials) < MAX_TRACKED_ACTORS) else OTHER_BUCKET
        count = min(self._denials.get(key, 0) + 1, COUNTER_CAP)
        self._denials[key] = count
        if not _backoff_due(count, DENIAL_THRESHOLD):
            return []
        return [
            Alert(
                RULE_REPEATED_DENIAL,
                f"The presented identity has been denied {count} times. "
                "This can mean probing, or a lost device that is still being used. "
                "The identity is unproven, so no request was blocked.",
                {"denials": count, "asset": asset, "triggering_entry": entry_seq, "tracked_as_other": key == OTHER_BUCKET},
            )
        ]

    def on_duplicate_request_id(self, request_id: str, *, first_entry_seq: int, entry_seq: int) -> list[Alert]:
        self._duplicates = min(self._duplicates + 1, COUNTER_CAP)
        if not _is_power_of_two(self._duplicates):
            return []
        return [
            Alert(
                RULE_DUPLICATE_ID,
                "A request_id was used more than once. The first record is kept; the new "
                "request was decided by the normal policy and logged as a separate entry.",
                {
                    "request_id": request_id,
                    "first_entry": first_entry_seq,
                    "triggering_entry": entry_seq,
                    "occurrences": self._duplicates,
                },
            )
        ]

    def on_invalid_input(self, kind: str) -> list[Alert]:
        count = min(self._invalid.get(kind, 0) + 1, COUNTER_CAP)
        self._invalid[kind] = count
        if not _is_power_of_two(count):
            return []
        return [
            Alert(
                RULE_INVALID_INPUT,
                "Malformed requests keep arriving. Each was rejected without any state change.",
                {"kind": kind, "occurrences": count},
            )
        ]


def integrity_alert(category: str) -> Alert:
    """Alert for a store integrity failure (state cannot be trusted, so no counters)."""
    return Alert(
        RULE_INTEGRITY,
        "Stored state failed its integrity check. The request was refused (fail closed).",
        {"category": category},
    )
