#!/usr/bin/env python3
"""Check that the installed cryptographic dependencies are exactly the pinned ones, and untouched.

    python scripts/verify_dependencies.py [--wheel PATH ...]

Exit status 0 if everything matches, 1 if anything does not.

What it checks (all offline, standard library only):
  1. every ``name==version`` pin in requirements.txt is the installed version;
  2. the files the installed pqcrypto package recorded at install time (its RECORD, with SHA-256
     per file) still hash to the same values for the ML-KEM-768 and ML-DSA-65 native modules and
     the Python wrappers: a modified or swapped extension after installation shows up here;
  3. with ``--wheel``, the SHA-256 of a downloaded wheel or sdist is one of the artifact hashes
     recorded in docs/sbom.json (taken from PyPI's published digests), so an installation made from
     a file you hold can be traced to the exact published artifact.

What it does not do: it does not prove the native code is correct or constant-time, it does not
download anything, and it cannot detect an attacker who can also rewrite RECORD. See
the README's limits section for the supply-chain assumptions.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata as metadata
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CRYPTO_FILES = re.compile(r"pqcrypto/(_kem/ml_kem_768|_sign/ml_dsa_65)\.|pqcrypto/(kem/ml_kem_768|sign/ml_dsa_65)\.py$")


def pins(requirements: Path) -> dict[str, str]:
    found = {}
    for line in requirements.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)\s*(#.*)?", line)
        if match:
            found[match.group(1).lower()] = match.group(2)
    return found


def record_hash(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--wheel", action="append", default=[], help="a downloaded wheel or sdist to trace")
    args = parser.parse_args(argv)
    problems: list[str] = []
    report: dict = {"pins": {}, "native_files_checked": 0}

    for name, wanted in pins(REPO / "requirements.txt").items():
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed = None
        report["pins"][name] = {"pinned": wanted, "installed": installed}
        if installed != wanted:
            problems.append(f"{name}: pinned {wanted}, installed {installed}")

    try:
        dist = metadata.distribution("pqcrypto")
    except metadata.PackageNotFoundError:
        problems.append("pqcrypto is not installed")
        dist = None
    if dist is not None:
        for entry in dist.files or []:
            if not CRYPTO_FILES.search(entry.as_posix()) or entry.hash is None:
                continue
            located = Path(dist.locate_file(entry))
            if not located.exists():
                continue  # a wheel carries every platform's module; only this one's is on disk
            report["native_files_checked"] += 1
            if record_hash(located) != entry.hash.value:
                problems.append(f"{entry}: contents differ from the hash recorded at install time")
        if report["native_files_checked"] == 0:
            problems.append("no ML-KEM-768 / ML-DSA-65 files found to check")

    if args.wheel:
        sbom = json.loads((REPO / "docs" / "sbom.json").read_text(encoding="utf-8"))
        published = {a["sha256"]: a["file"] for c in sbom["components"] for a in c.get("artifacts", [])}
        report["wheels"] = {}
        for item in args.wheel:
            digest = hashlib.sha256(Path(item).read_bytes()).hexdigest()
            report["wheels"][item] = published.get(digest, "NOT A PUBLISHED ARTIFACT")
            if digest not in published:
                problems.append(f"{item}: sha256 {digest} is not in docs/sbom.json")

    report["problems"] = problems
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
