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
| `tools/` | Attack suite, test-data generator, revocation timing, benchmark, web bridge |
| `tests/` | Test suite |
| `demo/run_demo.py` | The lost-device story in one command |
| `frontend/` | Web console and landing page (React, TypeScript) |
| `scripts/` | One-command checks, judging-worker simulator, dependency verification |
| `docs/brief/` | Two-page project brief with the one-page threat model |

## Setup

Requirements: **Python 3.12** and Git. Runtime dependencies: `pqcrypto==0.4.0` and the `cffi` and `pycparser` it pulls in (`requirements.txt`). Tests need `pytest` (`requirements-dev.txt`). Everything else is the Python standard library. The service makes no network calls.

The submitted code is the repository's **default branch**. To check out exactly the revision named in the brief, run `git checkout <commit>` after cloning; `git log -1` shows what you have.

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

## Web console

Needs Node.js 22.18+ or 24.

```sh
cd frontend
npm ci
npm run build
cd ..
python tools/bridge.py        # open http://127.0.0.1:8765/#/console and choose "Connect to backend"
```

Checks, from `frontend/`: `npm run check`, `npm test`, `npm run build`. For development use `npm run dev` together with `python tools/bridge.py --no-start` (Vite forwards `/api` to the bridge).

The bridge serves the built console and runs the real backend on synthetic data in a temporary folder: adapter calls start `track4_service.py` as a new process, signed node requests, rotation and revocation use `t4.node` on a simulated clock, and the audit logs are checked by `t4.audit.verify`. The browser runs no cryptography. The bridge is **not an authentication layer**: anyone who can reach its port can act as any actor. It listens on 127.0.0.1 only; run it on a developer machine, never on a shared host.

Without a backend the console loads nothing by default. You can load a clearly labelled synthetic sample or import a JSON snapshot. Imported results are shown as reported claims; importing verifies nothing. Files stay in browser memory (limit 5 MB and 5,000 entries per collection). Do not import secrets.

### Snapshot format

`{"schemaVersion": 1, "capturedAt": "<ISO time with zone>", "devices": [], "nodes": [], "audit": [], "verifications": []}`. All arrays are required and may be empty.

| Collection | Fields |
|---|---|
| `devices` | `id`, `owner`, `keyVersion` (whole number), `state`: `active` or `revoked` |
| `nodes` | `id`, `state`: `current`, `stale` or `offline`, `listVersion`, `deviceIds`, `lastUpdated` |
| `audit` | `requestId`, `actor`, `action`, `asset`, `rule`, `timestamp`, `decision`: `allow` or `deny` |
| `verifications` | `id`, `detail`, `kind`: `audit-chain`, `checkpoint`, `device-signature` or `protected-read`; `outcome`: `valid`, `invalid` or `not-checked` |

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
| Alerts for a damaged or shortened audit log | `python -m t4.audit.cli --dir <state dir>/alerts alerts` |
| Revocation reaches every node within `r + T + s` | `python tools/nodes_sim.py --nodes 4 --runs 3 --seed 1` |
| Rotation and backup survive crashes | `python -m pytest tests/recovery -q` |
| Rotation under real process kills | `python -m tests.recovery.external_kill --trials 100` |
| Detector on the public practice events | `python -m t4.detect.cli evaluate --dir tests/detect/data/practice` |
| Detector on held-out generated events | `python tools/gen_logs.py --out <dir> --held-out`, then `python -m t4.detect.cli evaluate --dir <dir>` |
| Detector with other service rules | `python -m t4.detect.cli detect --dir <dir> --policy <policy.json>` (format: `t4/detect/policy_file.py`) |
| Latency per operation | `python tools/bench.py` |

## Detector input

Event files: columns are matched by name (extra ones are ignored); times are UTC written with `Z` or `+00:00`. If an event ID repeats, the first record is analysed; an identical re-delivery is ignored and a differing copy raises `DET-CONFLICTING-DUPLICATE`. The default roles, services and approver (`user-admin`) follow the toolkit's practice data. For other names use `--approver NAME` (repeatable) and `--policy FILE`; an unconfigured role raises `DET-ROLE-NOT-CONFIGURED`, and an approval by an approver you have not named counts as unapproved.

## Security model and limits

- **No caller authentication in the adapter.** The request carries no credential, so anyone who can call it can claim any actor, including for `setup` and `revoke`. A second `setup` starts over and clears revocations.
- **Device identity** is proven only in the node layer: signature, node binding, owner, key version, time window and a single-use nonce. Rotation has no grace period. A node whose revocation list is older than T denies everything.
- **Local storage is the trust boundary.** Keys sit next to the data. Whoever can write a state, node or authority folder can read its keys and rebuild a consistent log. Restoring a whole folder to an older copy is not detected locally; only a head and public key pinned elsewhere expose it, up to the pinned entry. Replacing only the state file with an older copy (the audit log kept going) is detected, whether the copy predates a revocation or a later `setup` (every revocation and every `setup` raises the state's epoch, and every logged decision records it): `read`, `protected_read` and `revoke` fail closed and a `state-rollback` alert is logged until `setup` is run again or the matching state is restored. File bodies are stored **unencrypted** (HMAC-tagged) in `state.json`: whoever can read the state folder can read them. Restoring old node state can let a recent request be replayed within its time window.
- **Audit logs** are hash-chained with signed checkpoints and grow without limit. The running service re-checks the whole chain on every write while the log is at most 256 KiB, on every 16th write up to 8 MiB, and above that only the newest entries; older edits in a larger log are found by `verify-log`. If a crash lands between an entry and its scheduled checkpoint, the next write re-checks the whole chain and signs the missing checkpoint (it never refuses a log that verifies). Node logs sign every entry: about 7 KB per node request, 14 KB when the request also raises an alert, including requests refused before their signature is checked. `audit` also returns the rule that decided, which tells any caller why a request was denied.
- **Request index.** `audit` remembers the 10,000 newest request IDs. The whole state file is rewritten on every request, so a full index raises the cold-process read time (measured median about 80 ms empty, about 250 ms full, on WSL2 ext4).
- **Logging during storage failures.** A revocation (adapter or authority), a removed grant and a revocation list accepted by a node take effect even when the audit log cannot be written. Their audit entry is queued in the same atomic state write and written exactly once by the next request that can reach the log. Until then the adapter's `revoke` answers `{"audit": "pending"}` (not a plain `{}`), the authority raises an error that says the entry is queued, and `python -m t4.storage_status` reports `"audit_logging": "degraded"` with the number of queued entries. Nothing is undone to make logging succeed.
- **Reused `request_id`.** `audit` returns the decision recorded the **first** time an ID was used; a later request with the same ID is decided normally, logged as its own entry and raises `AUD-DUPLICATE-REQUEST-ID`.
- **Lost or damaged history** that the service notices is refused and recorded in a second signed log in the same state folder. Later entries of some kinds can still be removed unnoticed without an outside pin.
- **Backups** are authenticated, not encrypted: they hold private keys. A restore loses newer enrolments and grants. An authority restore re-applies later revocations and key versions from its vault ledger, so it depends on that ledger being current.
- **No encryption in transit and no forward secrecy.** Message delivery guarantees and session resumption are not built. Replay and recipient checks for messages exist only in the optional demo, `demo/messaging.py`; its `FileReplayGuard` keeps the replay counters on disk and commits each one before a message is reported delivered, so duplicates are refused after a restart and between concurrent receivers. Key rotation and ML-KEM do not provide forward secrecy.

- The **detector** uses fixed rules (no machine learning) and has been measured only on synthetic data. Movement chains group by actor and session within 60 s steps: an actor that changes session on every step, or waits more than 60 s between steps, is not chained (use `--policy` to change the grouping or window). A role with no configured scope raises `DET-ROLE-NOT-CONFIGURED`. Approval expiry is a detector concept: grants in the node layer have no expiry and stay until `ungrant` (the detector flags use after an approval ended). An alert's `emitted_at` is when the evidence needed to raise it had arrived; `initial_event_ids` lists that evidence and `evidence_complete_at` when the last cited event arrived. Times to alert are reconstructed from receipt times, not measured emissions; `processing_ms` is the run time. `export` without `--owners` infers the expected-access baseline from the exported window and says so.
- **Key retirement.** `rotation.revoke_key` only stops the DEVICE from signing with that version. The supported way to make every node refuse a key is `revoke_device` at the authority (or a rotation: after its cutoff every node refuses the old version). There is no per-version revocation list.
- **Freshness boundary.** A node accepts a list younger than T and serves requests while its list is younger than T; a list exactly T old is stale everywhere, as the console shows.
- **Windows.** The permission checks (private 0700 folders, refusing symlinked or foreign folders) run on Linux and macOS. On Windows the state folders inherit the ACLs of their parent folder; put them under your user profile, not a shared folder.
- Side channels in the compiled cryptography library have not been assessed; secrets cannot be erased from Python memory.
- **pqcrypto 0.4.0** is pinned because the judging runtime ships it. Its code comes from PQClean, which was archived in August 2026; a pqcrypto 1.0.0 release exists, but we stay on the runtime's version.

## Checklist coverage (official goals 9 to 12)

| Goal | Status | What exists |
|---|---|---|
| 9. Replay and recipient binding | Demo layer only | `demo/messaging.py`: ML-KEM-768 + HKDF + ChaCha20-Poly1305 (vetted `cryptography`), ML-DSA-65 signature over the header, recipient and sender checked, per-sender sequence numbers (restart-safe with `FileReplayGuard`). The judged adapter carries files, not messages. |
| 10. Forward secrecy | Not supported | Messages are encapsulated to the recipient's long-term ML-KEM key: a later leak of that key reveals earlier messages. A ratchet is not built. |
| 11. Delivery under loss or reordering | Not supported | No retransmission or delivery guarantee. Reordered or duplicate messages are refused by the sequence check; nothing reports lost ones. |
| 12. Session resumption | Not supported | There are no sessions. |

The judged interface is a file service (`read`, `protected_read`); whether goals 9 to 12 apply to a file-only prototype is a question for the organizers.

## Operator workflows

- **Full history check with outside pins.** `python -m t4.audit.cli --dir <log dir> pin init --pin <pin.json>` once (keep the pin file outside the state folder) and `pin advance --pin <pin.json>` to move it forward after a successful check; later `python -m t4.audit.cli --dir <log dir> verify-log --pin <pin.json>`. The report gives `checked_range` (every entry re-hashed from the first), `pinned_range` (covered by a signed checkpoint or the pin), the first bad entry and `seconds` taken. The running service checks only recent entries of a log above 256 KiB, so schedule this check (for example before each demo or daily).
- **Log capacity.** `python -m t4.storage_status --state-dir <dir>` warns when the audit log or the volume crosses a threshold and when logging is degraded. To archive, stop the service, copy the whole audit folder somewhere safe and keep a pin of its head; the log itself is never trimmed or deleted by the service, because removing entries would break the chain the pins vouch for.

## Attribution

- `track4_service.py` is based on the Python starter adapter of the official Track 4 participant toolkit (https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit, commit `8901dfb`). `tests/detect/data/practice/` holds unchanged copies of the toolkit's synthetic practice files. The toolkit's demo application was not copied.
- **pqcrypto 0.4.0** (https://pypi.org/project/pqcrypto/) provides ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204); **cffi** and **pycparser** are its dependencies. **pytest** is used for tests.
- **cryptography** (https://cryptography.io, Apache-2.0 or BSD-3-Clause) is used only by `demo/messaging.py`.
- HMAC-SHA256 (RFC 2104) and SHA-256 come from the Python standard library.
- Web console: [React](https://react.dev/) (MIT), [Vite](https://vite.dev/) (MIT), [TypeScript](https://www.typescriptlang.org/) (Apache-2.0), Prettier (MIT, formatting only) and the [Instrument Sans](https://fontsource.org/fonts/instrument-sans) font (SIL Open Font License), bundled locally.
