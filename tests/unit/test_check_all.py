"""Tests for the checker itself: a check that cannot fail is worthless."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_all.py"
spec = importlib.util.spec_from_file_location("check_all", SCRIPT)
check_all = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_all)  # type: ignore[union-attr]


def scan(tmp_path: Path, source: str) -> list[str]:
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")
    # scan_file reports paths relative to the repo; point it at a file inside it
    original = check_all.REPO
    check_all.REPO = tmp_path
    try:
        return check_all.scan_file(path)
    finally:
        check_all.REPO = original


@pytest.mark.parametrize(
    "source",
    [
        "eval('1+1')",
        "exec('x=1')",
        "import pickle",
        "from pickle import loads",
        "import subprocess",
        "import socket",
        "import urllib.request",
        "import requests",
        "import numpy as np",
        "from sklearn import svm",
        "import torch",
        "import os\nos.system('ls')",
        "import os\nos.popen('ls')",
        "f(shell=True)",
        "__import__('os')",
        "import ctypes",
    ],
)
def test_forbidden_constructs_are_found(tmp_path, source):
    assert scan(tmp_path, source), source


@pytest.mark.parametrize("source", ["import hmac, hashlib, json, base64", "import importlib\nimportlib.import_module('x')", "x = 'eval'", "f(shell=False)"])
def test_allowed_code_is_not_flagged(tmp_path, source):
    assert scan(tmp_path, source) == []


def test_unparseable_files_are_reported(tmp_path):
    assert scan(tmp_path, "def (:")


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END " + "PRIVATE KEY-----",
        "-----BEGIN RSA " + "PRIVATE KEY-----",
        '{"secret_key": "' + "A" * 300 + '"}',
        "A" * 1600,
        "0" * 64 + "\n",
    ],
)
def test_secret_patterns_catch_key_like_material(text):
    assert check_all.scan_text("x", text)


@pytest.mark.parametrize("text", ["plain prose", "sha: " + "0" * 64, "short base64 AAAA", "x" * 100])
def test_secret_patterns_ignore_ordinary_text(text):
    assert check_all.scan_text("x", text) == []
