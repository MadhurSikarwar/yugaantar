"""Shared pytest helpers (owned by c1).

Keeps state directories outside the repository (PRD rule 3): every test that
needs a state directory gets a fresh temporary one.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """A fresh, private state directory outside the repository."""
    path = tmp_path / "state"
    path.mkdir(mode=0o700)
    return path
