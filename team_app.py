"""Dispatch: validate a request and route it to the service.

``track4_service.py`` (the official entry point) calls ``dispatch`` with one
parsed JSON object. This file does only two things:

1. validate the request with ``t4.validate_in`` (anything malformed raises
   ``InputError`` before any state is touched), and
2. call the matching operation on ``t4.service.VaultService``.

It never invents a successful response. An unknown operation returns
``{"error": "unsupported_operation"}`` (as the official demo does).
"""
from __future__ import annotations

from typing import Mapping

from t4.api import IntegrityError, Track4Error
from t4.service import AuditHistoryLost, Dependencies, VaultService
from t4.validate_in import (
    AuditRequest,
    ProtectedReadRequest,
    ReadRequest,
    RevokeRequest,
    SetupRequest,
    UnsupportedOperation,
    validate_request,
)
from t4.wiring import build_default_dependencies


def dispatch(request: Mapping, deps: Dependencies | None = None) -> dict:
    typed = validate_request(dict(request))
    if isinstance(typed, UnsupportedOperation):
        return {"error": "unsupported_operation"}
    service = VaultService(deps or build_default_dependencies())
    if isinstance(typed, SetupRequest):
        return service.setup(typed)
    if isinstance(typed, ReadRequest):
        return service.read(typed)
    if isinstance(typed, RevokeRequest):
        return service.revoke(typed)
    if isinstance(typed, AuditRequest):
        return service.audit(typed)
    if isinstance(typed, ProtectedReadRequest):
        return service.protected_read(typed)
    raise Track4Error("unhandled request type")  # unreachable: validate_request is exhaustive


def record_failure(error: Exception, deps: Dependencies | None = None) -> None:
    """Best-effort alerting for a failed request. Never raises, never reads request data."""
    try:
        dependencies = deps or build_default_dependencies()
        dependencies.on_audit_failure(error)  # ignores anything that is not audit-log damage
        service = VaultService(dependencies)
        if isinstance(error, AuditHistoryLost):
            return  # reported above; nothing may be added to the shortened log
        if isinstance(error, IntegrityError):
            service.report_integrity_failure(error)
        elif isinstance(error, Track4Error) and error.category == "invalid-input":
            service.report_input_failure(error.category)
    except Exception:  # noqa: BLE001
        return
