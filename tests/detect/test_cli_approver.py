"""The approver name is policy, not code: a renamed approver must be nameable without editing config.py."""
import argparse

from t4.detect import cli
from t4.detect.config import DEFAULT_CONFIG


def ns(**kw):
    return argparse.Namespace(**kw)


def test_default_keeps_user_admin(monkeypatch):
    monkeypatch.delenv("T4_APPROVERS", raising=False)
    assert cli._config(ns(approver=None)) is DEFAULT_CONFIG


def test_flag_replaces_approvers(monkeypatch):
    monkeypatch.delenv("T4_APPROVERS", raising=False)
    cfg = cli._config(ns(approver=["user-secops", "user-two"]))
    assert cfg.authorized_approvers == frozenset({"user-secops", "user-two"})
    assert DEFAULT_CONFIG.authorized_approvers == frozenset({"user-admin"})


def test_environment_variable_is_used_when_no_flag(monkeypatch):
    monkeypatch.setenv("T4_APPROVERS", " user-secops , ")
    assert cli._config(ns(approver=None)).authorized_approvers == frozenset({"user-secops"})


def test_empty_approver_name_is_refused():
    import pytest
    with pytest.raises(ValueError):
        cli._config(ns(approver=[""]))


def test_export_uses_the_environment_variable_too(monkeypatch):
    monkeypatch.setenv("T4_APPROVERS", "user-secops")
    captured = {}

    def fake_run_export(sources, approvals, *, approvers=None, **kw):
        captured["approvers"] = approvers
        raise cli.exp.ExportError("stop") if hasattr(cli, "exp") else RuntimeError

    from t4.detect import export as exp
    monkeypatch.setattr(exp, "run_export", fake_run_export)
    args = ns(pin=None, node=["n=/nonexistent"], authority=None, approvals=None, owners=None,
              approver=None, append_alerts=None, out_csv=None, json=False)
    try:
        cli.cmd_export(args)
    except Exception:
        pass
    assert captured["approvers"] == ["user-secops"]
