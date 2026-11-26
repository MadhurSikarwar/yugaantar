"""Run one operation and kill the process hard at a chosen step.

``os._exit`` skips all cleanup, like ``kill -9`` from the program's own side.
Test helper only.
"""
from __future__ import annotations

import os
import sys

from t4.backup import Vault
from t4.node.authority import Authority
from t4.node.device import Device
from tests.node.doubles import InsecureTestSigner, MemoryLog

KILLED = 77
REAL_ENV = "T4_TEST_REAL_SIGNER"


def child_signer():
    if os.environ.get(REAL_ENV) == "1":
        from t4.node.common import load_signer

        return load_signer()
    return InsecureTestSigner()


def main(argv: list[str]) -> int:
    operation, step = argv[0], argv[1]

    def fault(reached: str) -> None:
        if reached == step:
            os._exit(KILLED)

    if operation == "rotate":
        device_dir, authority_dir, now, cutoff = argv[2:]
        signer = child_signer()
        Device(device_dir, signer).rotate(Authority(authority_dir, signer, MemoryLog()),
                                          float(now), float(cutoff), fault)
    elif operation == "restore":
        keys, backups, target, record = argv[2:]
        Vault(keys, backups).restore(target, record, fault)
    else:
        device_dir, keys, backups, record = argv[2:]
        Vault(keys, backups).backup(Device(device_dir, child_signer()).store, record,
                                    5.0, fault)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
