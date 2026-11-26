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
