# Trust, but verify: post-quantum protected files with verifiable decisions

Yugaantar DevForge, Track 4. A protected-file service for the lost-device case:
- an owner reads a file
- access is revoked, and the owner is denied
- a second owner still reads their own file
- an operator can see in a tamper-evident log which rule decided each request

**USP:** every allow, deny and alert is logged with the rule and events behind it. Anyone holding a pinned checkpoint and the public key can verify that the log up to that point has not been altered. Full tamper detection needs an operator to run `verify-log` against a pin kept outside the directory. The running service re-checks logs up to 256 KiB in full on each write, and a bounded part of larger ones.

- **Post-quantum parts:** ML-KEM-768 for the `protected_read` proof. ML-DSA-65 for audit checkpoints, device requests and revocation lists.
- **What it does not do:** it doesn't encrypt files in transit, and the judged adapter doesn't authenticate callers (it trusts the `actor` string and enforces permissions). Device identity is verified in the node layer. See `docs/threat-model.md`.

## Contents

| Path | What |
|---|---|
| `track4_service.py`, `team_app.py`, `t4/service.py` | The judged adapter: `setup`, `read`, `revoke`, `audit`, `protected_read` |
| `t4/` | Validation, policy, state store, guard, crypto wrappers, audit log, node layer, rotation, backup, detector |
| `tools/` | `selfattack.py` (red team), `gen_logs.py` (labelled test data), `nodes_sim.py` (revocation timing), `bench.py` (latency) |
| `demo/` | `DEMO_SCRIPT.md` and `run_demo.py` (the 5-minute story, one command) |
| `docs/` | `architecture.md`, `threat-model.md`, `evidence-sheet.md`, `detector-metrics.md`, `selfattack-report.md`, `CONTRACT_FACTS.md`, `brief/` |
| `scripts/check_all.py` | One command: layout, static scan, secret scan (tree and Git history), validator, tests |

## Setup on a clean machine

Requirements: **Python 3.12** and Git. The runtime dependencies are `pqcrypto==0.4.0`, plus `cffi` and `pycparser`, which it pulls in (`requirements.txt`). Development needs only `pytest` (`requirements-dev.txt`). The runtime uses nothing else outside the standard library and makes no network calls. **Optional, demo only:** `demo/messaging.py` needs the vetted `cryptography` package, pinned to 50.0.2 in `requirements-demo.txt`. The judged adapter and `t4/` never import it.

```sh
git clone https://github.com/MadhurSikarwar/yugaantar.git
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git   # sibling folder, never inside the repo
cd yugaantar
python3.12 -m venv .venv
. .venv/bin/activate                       # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt -r requirements-dev.txt
```

All state, key, node and authority directories are created **outside the repository**. The adapter uses `TRACK4_STATE_DIR`, or the OS temp directory if it's unset. No key is stored in the repository. On Linux and macOS, a state folder we own is made private (`chmod 0700`). In a shared folder like `/tmp`, the state goes into our own `track4-state-<uid>` subfolder. So point `TRACK4_STATE_DIR` at a dedicated folder, never at a folder holding other files (`docs/CONTRACT_FACTS.md`, section 5b).

These steps were followed from a fresh GitHub clone on WSL Ubuntu 24.04 with Python 3.12.3, with the repository read-only. Results are in `docs/evidence-sheet.md`, run L3.

## Run

```sh
# One request, as the judges send it (new process per request):
echo '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo note"},"disabled":[],"key_material":"x"}' | python track4_service.py
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r1"}' | python track4_service.py

# The whole 5-minute story in one command (synthetic data, temporary directories):
python demo/run_demo.py

# The web console connected to the real backend (needs Node 22+ once: cd frontend && npm ci && npm run build):
python tools/bridge.py        # then open http://127.0.0.1:8765/#/console and choose "Connect to backend"
```

The bridge is demo tooling for a developer machine (localhost only, synthetic data, no authentication of the actor). See `frontend/README.md`, section "Live backend".

## How to verify every claim

Each line is a command, and each result has been reproduced (see `docs/evidence-sheet.md` for run dates and numbers).

| Claim | Command |
|---|---|
| Passes the official contract | `python ../Track-4-Toolkit/validate.py --entry ./track4_service.py` → exit 0 |
| Everything at once | `python scripts/check_all.py --toolkit ../Track-4-Toolkit` → `ALL CHECKS PASSED` |
| Full test suite | `python -m pytest -q` |
| Attacks from PRD section 8 fail | `python tools/selfattack.py --entry track4_service.py --report <out.md>` |
| Log tampering is detected | `python -m t4.audit.cli --dir <log dir> head --out <pin.json>`, then `verify-log --pin <pin.json>` |
| Why a request was denied | `python -m t4.audit.cli --dir <log dir> explain <request_id>` |
| A damaged or shortened audit log is refused and recorded | `python -m pytest tests/integration/test_audit_history_and_alerts.py -q`; on a live state: `python -m t4.audit.cli --dir <state dir>/alerts alerts` |
| An authority restore cannot revive a replaced key or a revoked device | `python -m pytest tests/recovery/test_restore_security.py -q` |
| Detector with another environment's service rules | `python -m t4.detect.cli detect --dir <dir> --policy <policy.json>` (format: `t4/detect/policy_file.py`) |
| Full audit verification, with a pin kept outside the directory | `python -m t4.audit.cli --dir <log dir> pin init --pin <pin.json>`, later `verify-log --pin <pin.json>`, then `pin advance --pin <pin.json>` (exit 1 on any failure) |
| State is not older than the audit log (a state file rolled back on its own) | `python -m t4.consistency --state-dir <dir>` (exit 1 if inconsistent) |
| Storage use and free space | `python -m t4.storage_status --state-dir <dir>` (exit 1 or 2 on low space or large files) |
| The pinned cryptographic dependencies are installed and untouched | `python scripts/verify_dependencies.py` (exit 1 on a mismatch) |
| One rotation is logged once, even when the process is killed | `python -m tests.recovery.external_kill --trials 100` (fails on a duplicate) |
| Revocation reaches every node within `r + T + s` | `python tools/nodes_sim.py --nodes 4 --runs 3 --seed 1` |
| Rotation and backup survive a crash at every step | `python -m pytest tests/recovery -q` |
| Detector on the public practice events | `python -m t4.detect.cli evaluate --dir tests/detect/data/practice` |
| Detector on held-out generated events | `python tools/gen_logs.py --out <dir> --held-out`, then `python -m t4.detect.cli evaluate --dir <dir>` |
| Alerts from our own signed logs | `python -m t4.detect.cli export --node node-a=<dir> ... --authority <dir> --approvals <file> --owners <file> --append-alerts <dir>` (`demo/run_demo.py` does this end to end) |
| Latency per operation (cold process) | `python tools/bench.py` |
| Demo-layer messaging refuses replays, wrong recipients and any changed field | `pip install -r requirements-demo.txt`, then `python -m pytest tests/unit/test_demo_messaging.py -q` |

## Limits (short version)

The full list is in `docs/threat-model.md`.
- No caller authentication in the adapter.
- A full rollback of a state directory can't be detected locally.
- Anyone with write access to a directory can read its signing key.
- No transport encryption or forward secrecy in the adapter (goals 10 to 12 are not supported). Goal 9 (replay and recipient checks for messages) exists only in the optional demo layer, `demo/messaging.py`.
- The detector is measured only on synthetic data.
- The running service fully re-checks logs up to 256 KiB on each write (and fails closed). Older parts of larger logs are checked by `verify-log`. `audit`'s `rule` field reveals denial reasons to any caller (accepted, `coord/DECISIONS.md` D-004).
- Some review findings are still open (listed in the threat model).

## Attribution

- `track4_service.py` is based on the Python starter adapter of the official **Track 4 participant toolkit** (https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit, commit `8901dfb`). It keeps the starter's structure: one JSON object in, `json.dumps(..., allow_nan=False)` out, a generic stderr line and exit 1 on failure. It adds a size-capped strict UTF-8 read of stdin, ASCII output and failure recording. The evidence-sheet and two-page brief structure follow the toolkit's `templates/`. `tests/detect/data/practice/` contains unchanged copies of the toolkit's synthetic practice files. The toolkit's demo application logic was **not** copied.
- **pqcrypto 0.4.0** (https://pypi.org/project/pqcrypto/) provides ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204). **cffi** and **pycparser** are its dependencies. **pytest** is used for tests only. **cryptography** (https://cryptography.io, Apache-2.0 or BSD-3-Clause) provides ChaCha20-Poly1305 and HKDF for the optional `demo/messaging.py` only.
- Standard constructions used from the Python standard library: HMAC-SHA256 (RFC 2104) and SHA-256.
