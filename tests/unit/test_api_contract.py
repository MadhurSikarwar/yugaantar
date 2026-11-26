"""The shared interfaces in ``t4.api`` must match the real modules (owner: c1).

Every case imports the real module if it is present (otherwise that case is skipped,
for example on a branch that does not contain c3's code) and compares, for each method
named in the interface, its parameter names, kinds and whether each has a default.
A mismatch means the interface and the code drifted apart: fix whichever is wrong and
bump ``API_VERSION``.
"""
from __future__ import annotations

import dataclasses
import importlib
import inspect

import pytest

from t4 import api


def _params(function) -> list[tuple[str, str, bool]]:
    items = list(inspect.signature(function).parameters.values())
    if items and items[0].name in ("self", "cls"):
        items = items[1:]
    return [(p.name, p.kind.name, p.default is not inspect.Parameter.empty) for p in items]


# (interface, module path, class name inside the module or None, methods to compare)
CASES = [
    (api.KemProvider, "t4.crypto.kem", None, ["encapsulate"]),
    (api.ProofProvider, "t4.crypto.proof", None, ["make_proof"]),
    (api.AuditLogApi, "t4.audit.log", "AuditLog", ["append", "alert", "head", "explain", "find", "verify"]),
    (api.RotationApi, "t4.rotation", None, ["begin_rotation", "recover", "mark_published", "signing_key", "revoke_key"]),
    (api.BackupVaultApi, "t4.backup", "Vault", ["create", "location", "record_removal", "backup", "restore"]),
    (api.NodeRequestApi, "t4.node.request", None, ["sign_request", "handle_request", "respond"]),
    (api.NodeAuthorityApi, "t4.node.authority", None, ["issue_list"]),
    (api.NodeFreshnessApi, "t4.node.freshness", None, ["accept_list"]),
]


@pytest.mark.parametrize(("interface", "module_path", "class_name", "methods"), CASES, ids=lambda v: getattr(v, "__name__", str(v)))
def test_interface_matches_the_real_module(interface, module_path, class_name, methods):
    module = pytest.importorskip(module_path, reason=f"{module_path} is not on this branch")
    target = getattr(module, class_name) if class_name else module
    for name in methods:
        assert hasattr(target, name), f"{module_path} has no {name}"
        expected = _params(getattr(interface, name))
        actual = _params(getattr(target, name))
        assert actual == expected, f"{interface.__name__}.{name}: interface {expected} vs real {actual}"


def test_restore_report_matches_the_real_dataclass():
    backup = pytest.importorskip("t4.backup", reason="t4.backup is not on this branch")
    fields = {f.name for f in dataclasses.fields(backup.RestoreReport)}
    assert fields == {"used_id", "damaged", "newest_expected_id"}
    assert isinstance(inspect.getattr_static(backup.RestoreReport, "fell_back"), property)


def test_api_version_is_recorded_in_the_header():
    assert api.API_VERSION == 2 and "API VERSION: 2" in (api.__doc__ or "")
