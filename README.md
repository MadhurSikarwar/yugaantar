# Trust, but verify: post-quantum protected files with verifiable decisions

Yugaantar DevForge, Track 4.

A protected-file service for the lost-device case: an owner reads a file, access is revoked and the owner is denied, a second owner still reads their own file, and an operator can see in a tamper-evident log which rule decided each request.

- **Post-quantum parts:** ML-KEM-768 for the `protected_read` proof; ML-DSA-65 for audit checkpoints, device requests and revocation lists.
- **What it does not do:** it does not encrypt files in transit, and the five-operation adapter does not authenticate callers (it checks permission for the `actor` it is given). Device identity is verified in the node layer.

## Contents

| Path | What |
|---|---|
| `track4_service.py`, `team_app.py`, `t4/service.py` | The adapter: `setup`, `read`, `revoke`, `audit`, `protected_read` |
| `t4/` | Validation, policy, state, guard, cryptography wrappers, audit log, devices and nodes, rotation, backup, detector |
| `tools/` | Attack suite, test-data generator, revocation timing, benchmark |
| `tests/` | Test suite |
| `demo/run_demo.py` | The lost-device story in one command |
| `scripts/` | One-command checks, judging-worker simulator, dependency verification |
| `docs/brief/` | Two-page project brief with the one-page threat model |

## Setup

Requirements: **Python 3.12** and Git. Runtime dependencies: `pqcrypto==0.4.0` and the `cffi` and `pycparser` it pulls in (`requirements.txt`). Tests need `pytest` (`requirements-dev.txt`). Everything else is the Python standard library. The service makes no network calls.

```sh
git clone https://github.com/MadhurSikarwar/yugaantar.git
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git   # next to the repository, not inside it
cd yugaantar
python3.12 -m venv .venv
. .venv/bin/activate                       # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt -r requirements-dev.txt
```

Optional, for the encrypted-messaging demo and its tests only: `python -m pip install -r requirements-demo.txt` (adds the `cryptography` package). The adapter and `t4/` never import it.

State, key, node and authority folders are created **outside the repository**. The adapter uses `TRACK4_STATE_DIR`, or the OS temp folder if it is unset; point it at a dedicated folder. On Linux and macOS a folder you own is made private (`0700`). In a shared folder such as `/tmp` the state goes into a private `track4-state-<uid>` subfolder.

## Run

```sh
# One request per process:
echo '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo note"},"disabled":[],"key_material":"x"}' | python track4_service.py
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r1"}' | python track4_service.py

# The whole story in one command (synthetic data, temporary folders):
python demo/run_demo.py
```

## Verify

| Check | Command |
|---|---|
| Official contract | `python ../Track-4-Toolkit/validate.py --entry ./track4_service.py` |
| Layout, scans, validator and tests | `python scripts/check_all.py --toolkit ../Track-4-Toolkit` |
| Test suite | `python -m pytest -q` (permission and symlink tests run on Linux and macOS only) |
| Attack suite against the adapter | `python tools/selfattack.py --entry track4_service.py` |
| End-to-end checks | `python scripts/e2e_checks.py` |
| Judging-worker simulation | `python scripts/sandbox_sim.py --ref HEAD --toolkit ../Track-4-Toolkit` |
| Installed dependencies match the pins | `python scripts/verify_dependencies.py` |
| Log tampering is detected | `python -m t4.audit.cli --dir <log dir> head --out <pin.json>`, later `verify-log --pin <pin.json>` |
| Why a request was denied | `python -m t4.audit.cli --dir <log dir> explain <request_id>` |
| Saved state is not older than the audit log | `python -m t4.consistency --state-dir <dir>` |
| Storage use and free space | `python -m t4.storage_status --state-dir <dir>` |
| Revocation reaches every node within `r + T + s` | `python tools/nodes_sim.py --nodes 4 --runs 3 --seed 1` |
| Rotation and backup survive crashes | `python -m pytest tests/recovery -q` |
| Rotation under real process kills | `python -m tests.recovery.external_kill --trials 100` |
| Detector on the public practice events | `python -m t4.detect.cli evaluate --dir tests/detect/data/practice` |
| Detector on held-out generated events | `python tools/gen_logs.py --out <dir> --held-out`, then `python -m t4.detect.cli evaluate --dir <dir>` |
| Latency per operation | `python tools/bench.py` |

## Detector input

The default roles, services and approver (`user-admin`) follow the toolkit's practice data; `--approver NAME` names other approvers.

## Security model and limits

- **No caller authentication in the adapter.** The request carries no credential, so anyone who can call it can claim any actor, including for `setup` and `revoke`. A second `setup` starts over and clears revocations.
- **Device identity** is proven only in the node layer: signature, node binding, owner, key version, time window and a single-use nonce. Rotation has no grace period. A node whose revocation list is older than T denies everything.
- **Local storage is the trust boundary.** Keys sit next to the data. Whoever can write a state, node or authority folder can read its keys and rebuild a consistent log. Restoring a whole folder to an older copy is not detected locally; only a head and public key pinned elsewhere expose it, up to the pinned entry. Restoring old node state can let a recent request be replayed within its time window.
- **Audit logs** are hash-chained with signed checkpoints and grow without limit. The running service re-checks only a bounded amount of a large log; older edits are found by `verify-log`. `audit` also returns the rule that decided, which tells any caller why a request was denied.
- **Backups** are authenticated, not encrypted: they hold private keys. A restore loses newer enrolments and grants. On this branch, restoring an authority backup can undo later key rotations, and later revocations if the vault was not linked to the authority.
- **No encryption in transit and no forward secrecy.** Message delivery guarantees and session resumption are not built. Replay and recipient checks for messages exist only in the optional demo, `demo/messaging.py`.
- The **detector** uses fixed rules (no machine learning) and has been measured only on synthetic data.
- Side channels in the compiled cryptography library have not been assessed; secrets cannot be erased from Python memory.

## Attribution

- `track4_service.py` is based on the Python starter adapter of the official Track 4 participant toolkit (https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit, commit `8901dfb`). `tests/detect/data/practice/` holds unchanged copies of the toolkit's synthetic practice files. The toolkit's demo application was not copied.
- **pqcrypto 0.4.0** (https://pypi.org/project/pqcrypto/) provides ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204); **cffi** and **pycparser** are its dependencies. **pytest** is used for tests.
- **cryptography** (https://cryptography.io, Apache-2.0 or BSD-3-Clause) is used only by `demo/messaging.py`.
- HMAC-SHA256 (RFC 2104) and SHA-256 come from the Python standard library.
