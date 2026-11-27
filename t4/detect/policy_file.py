"""Load the service-access rules for another environment from a JSON file.

    {"role_scope": {"viewer": ["products"], "operator": ["products", "identity"]},
     "role_rank":  {"viewer": 1, "operator": 3},
     "identity_service": "identity"}

``role_scope`` is required: the services each role may reach without a time-limited approval.
``role_rank`` and ``identity_service`` are optional and keep their defaults if left out.
Who may approve changes is not read from here (use ``--approver``). Strict: an unknown key or
a wrong type is an error, so a typing mistake cannot silently widen or drop a rule.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from types import MappingProxyType

from .config import DetectConfig

MAX_BYTES = 1024 * 1024
KEYS = frozenset({"role_scope", "role_rank", "identity_service"})


def _name(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("policy: names must be non-empty strings")
    return value


def apply_policy_file(path: Path, base: DetectConfig) -> DetectConfig:
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("policy: file too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("policy: not valid JSON") from None
    if not isinstance(data, dict) or not set(data) <= KEYS or "role_scope" not in data:
        raise ValueError("policy: expected role_scope and optionally role_rank, identity_service")
    scope = data["role_scope"]
    if not isinstance(scope, dict) or not scope or not all(isinstance(v, list) for v in scope.values()):
        raise ValueError("policy: role_scope must map each role to a list of services")
    changes: dict = {"role_scope": MappingProxyType(
        {_name(role): frozenset(_name(s) for s in services) for role, services in scope.items()})}
    if "role_rank" in data:
        rank = data["role_rank"]
        if not isinstance(rank, dict) or not rank or not all(type(v) is int for v in rank.values()):
            raise ValueError("policy: role_rank must map each role to a whole number")
        changes["role_rank"] = MappingProxyType({_name(role): value for role, value in rank.items()})
    if "identity_service" in data:
        changes["identity_service"] = _name(data["identity_service"])
    return dataclasses.replace(base, **changes)
