"""Vault state model: who owns what, who is disabled or revoked.

What it does
    ``VaultState`` is the in-memory form of the documents kept by
    ``t4.store``. It knows how to start a new *generation* (``setup``), revoke
    an actor, and keep the ``request_id`` index. It contains no I/O and no
    policy: ``t4.policy`` decides, ``t4.service`` orchestrates.

Documents (names are fixed; see ``t4.store``)
    meta      {"generation", "epoch", "next_n"}
    assets    {asset: {"owner", "body"}}            (bounded by the 1 MiB ``setup`` input)
    actors    {"disabled": [...],                   (bounded by the ``setup`` input)
               "revoked": {identifier_key(actor): epoch_when_revoked}}
    requests  {identifier_key(request_id): {"decision", "rule", "seq", "n"}}
    guard     counters owned by ``t4.guard`` (keyed by ``identifier_key``)

    Everything an unauthenticated caller can make grow is keyed by a fixed-size
    hash, so each record is small and constant in size no matter how long the
    identifier was.

Design decisions that matter
    * The **epoch** only ever goes up, also across generations, so a decision
      can always be ordered against a revocation.
    * A repeated ``setup`` starts a new generation: data, revocations and the
      request index are replaced; the audit chain and its keys continue.
    * The request index keeps the **first** record for each ID forever (until
      evicted, see below). A later request reusing an ID never overwrites it.
    * The index is bounded: at most ``MAX_INDEX_ENTRIES`` records. The oldest
      (smallest ``n``) is evicted first, so a flood of requests cannot grow the
      state file without limit. Documented limit: ``audit`` cannot answer for
      an evicted ID.
    * ``key_material`` from ``setup`` is never stored.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from t4.api import Txn

MAX_INDEX_ENTRIES = 10_000


def identifier_key(identifier: str) -> str:
    """Fixed-size key (64 hex characters) for an opaque identifier of any length.

    Identifiers may be up to 4 KiB of arbitrary characters, and JSON escaping can
    multiply that by six. Storing them raw let one flood of long identifiers grow
    the state file without bound. Keys built
    from this function make every stored record a small, constant size. The hash
    is for compaction, not secrecy.
"""
    return hashlib.sha256(b"t4-id-v1:" + identifier.encode("utf-8")).hexdigest()


@dataclass
class VaultState:
    generation: int = 0
    epoch: int = 0
    next_n: int = 0
    assets: dict[str, dict] = field(default_factory=dict)
    disabled: set[str] = field(default_factory=set)
    revoked: dict[str, int] = field(default_factory=dict)
    requests: dict[str, dict] = field(default_factory=dict)
    guard: dict = field(default_factory=dict)

    # -- persistence ------------------------------------------------------

    @classmethod
    def load(cls, txn: Txn) -> "VaultState":
        meta = txn.get("meta") or {}
        actors = txn.get("actors") or {}
        return cls(
            generation=int(meta.get("generation", 0)),
            epoch=int(meta.get("epoch", 0)),
            next_n=int(meta.get("next_n", 0)),
            assets=txn.get("assets") or {},
            disabled=set(actors.get("disabled", [])),
            revoked=dict(actors.get("revoked", {})),
            requests=txn.get("requests") or {},
            guard=txn.get("guard") or {},
        )

    def save(self, txn: Txn) -> None:
        txn.put("meta", {"generation": self.generation, "epoch": self.epoch, "next_n": self.next_n})
        txn.put("assets", self.assets)
        txn.put("actors", {"disabled": sorted(self.disabled), "revoked": self.revoked})
        txn.put("requests", self.requests)
        txn.put("guard", self.guard)

    @property
    def is_provisioned(self) -> bool:
        return self.generation > 0

    # -- queries ----------------------------------------------------------

    def owner_of(self, asset: str) -> str | None:
        record = self.assets.get(asset)
        return None if record is None else record["owner"]

    def body_of(self, asset: str) -> str | None:
        record = self.assets.get(asset)
        return None if record is None else record["body"]

    def is_revoked(self, actor: str) -> bool:
        return identifier_key(actor) in self.revoked

    def is_disabled(self, actor: str) -> bool:
        return actor in self.disabled

    # -- mutations --------------------------------------------------------

    def initialize(self, owners: dict[str, str], contents: dict[str, str], disabled: tuple[str, ...]) -> None:
        """Start a new generation from a ``setup`` request."""
        self.generation += 1
        self.assets = {asset: {"owner": owner, "body": contents.get(asset, "")} for asset, owner in owners.items()}
        self.disabled = set(disabled)
        self.revoked = {}
        self.requests = {}
        self.guard = {}

    def revoke(self, actor: str) -> bool:
        """Revoke ``actor``. Returns True if this is a new revocation (epoch bumped)."""
        key = identifier_key(actor)
        if key in self.revoked:
            return False
        self.epoch += 1
        self.revoked[key] = self.epoch
        return True

    def first_record(self, request_id: str) -> dict | None:
        record = self.requests.get(identifier_key(request_id))
        return None if record is None else dict(record)

    def remember_request(self, request_id: str, decision: str, rule: str, seq: int) -> bool:
        """Index a read. Returns False (and changes nothing) if the ID already exists."""
        key = identifier_key(request_id)
        if key in self.requests:
            return False
        self.requests[key] = {"decision": decision, "rule": rule, "seq": seq, "n": self.next_n}
        self.next_n += 1
        while len(self.requests) > MAX_INDEX_ENTRIES:
            oldest = min(self.requests, key=lambda key: self.requests[key]["n"])
            del self.requests[oldest]
        return True
