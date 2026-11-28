# Trust, but verify: post-quantum protected files with verifiable decisions

Yugaantar DevForge, Track 4.

A protected-file service for the lost-device case: an owner reads a file, access is revoked and the owner is denied, a second owner still reads their own file, and an operator can see in a tamper-evident log which rule decided each request.

- **Post-quantum parts:** ML-KEM-768 for the `protected_read` proof; ML-DSA-65 for audit checkpoints, device requests and revocation lists.
- **What it does not do:** it does not encrypt files in transit, and the five-operation adapter does not authenticate callers (it checks permission for the `actor` it is given). Device identity is verified in the node layer.

**Two-page brief (submission):** [`yugaantar-two-page-brief.pdf`](yugaantar-two-page-brief.pdf)

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
| `docs/brief/brief.pdf` | The final two-page brief (same file as `yugaantar-two-page-brief.pdf`), including the one-page threat model |

## Setup

Requirements: **Python 3.12** and Git. Runtime dependencies: `pqcrypto==0.4.0` and the `cffi` and `pycparser` it pulls in (`requirements.txt`). Tests need `pytest` (`requirements-dev.txt`). Everything else is the Python standard library. The service makes no network calls.

The submitted code is the repository's **default branch**. To check out exactly the revision named in the brief, run `git checkout <commit>` after cloning; `git log -1` shows what you have.

```sh
git clone https://github.com/MadhurSikarwar/latticelock.git
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git   # next to the repository, not inside it
cd latticelock
python3.12 -m venv .venv
. .venv/bin/activate                       # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt -r requirements-dev.txt
```

Optional, for the encrypted-messaging and session demos and for encrypted backups: `python -m pip install -r requirements-demo.txt` (adds the `cryptography` package). The judged adapter's import graph (`track4_service.py`, `team_app.py` and what they load) never imports it, which `scripts/e2e_checks.py` checks; `t4/backup.py` (node layer, not loaded by the adapter) imports it only for an encrypted vault.

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

The bridge serves the built console and runs the real backend on synthetic data in a temporary folder: adapter calls start `track4_service.py` as a new process, signed node requests, rotation and revocation use `t4.node` on a simulated clock, and the audit logs are checked by `t4.audit.verify`. The browser runs no cryptography.

From the console's **Backend controls** you can reach every backend feature:

| Area | Controls |
|---|---|
| Adapter | `read`, `protected_read` (the proof is checked like an independent client), `revoke`, `audit`, `setup` again (optionally disabling an actor) |
| Node layer | Signed requests (optionally altered after signing), device revocation, revoking one key version, key rotation, enrolment, list delivery, taking a node offline, moving the clock |
| Authority | Grants with or without an approval, grant removal, revoking an actor on every device, backup and restore through the vault |
| Gateway | Requests signed by enrolled callers (user, admin, reviewer) pass `t4.gateway` before reaching the adapter: wrong key, replay, a user acting as someone else, or a role without the operation are refused; a reviewer signs approve or reject for an alert, and the signed decision is re-verified |
| Messages | The optional demo layer: an encrypted, signed message, then the same message replayed |
| Operator | Archive a log's finished segment, explain a request ID from every log, list alerts, pin every log, verify against the pins, run the detector on our own verified logs, health (`t4.consistency`, `t4.storage_status`), and editing a synthetic log on disk to show the edit being caught |

Pins made in the console are saved outside the disposable workspace, in a persistent folder (`--pins-dir`, default your local app-data folder under `latticelock/pins`), one subfolder per synthetic world, in the same format as `audit.cli head --out`. Closing or restarting the bridge never deletes them. A pin is only advanced while the log still verifies against it, so a rewritten log or replaced key is never silently re-pinned. Reopening an earlier synthetic world is not supported: each start builds a new one. The console's Overview also lists the grants and the alerts recorded in the logs. The optional encrypted-messaging demo (`demo/messaging.py`) is there too: send a message, then see its replay refused (needs `requirements-demo.txt`). The bridge is **not an authentication layer**: anyone who can reach its port can act as any actor. It listens on 127.0.0.1 only; run it on a developer machine, never on a shared host.

Without a backend the console loads nothing by default. You can load a clearly labelled synthetic sample or import a JSON snapshot. Imported results are shown as reported claims; importing verifies nothing. Files stay in browser memory (limit 5 MB and 5,000 entries per collection). Do not import secrets.

### Snapshot format

`{"schemaVersion": 1, "capturedAt": "<ISO time with zone>", "devices": [], "nodes": [], "audit": [], "verifications": []}`. All arrays are required and may be empty.

| Collection | Fields |
|---|---|
| `devices` | `id`, `owner`, `keyVersion` (whole number), `state`: `active` or `revoked` |
| `nodes` | `id`, `state`: `current`, `stale` or `offline`, `listVersion`, `deviceIds`, `lastUpdated` |
| `audit` | `requestId`, `actor`, `action`, `asset`, `rule`, `timestamp`, `decision`: `allow` or `deny` |
| `verifications` | `id`, `detail`, `kind`: `audit-chain`, `checkpoint`, `device-signature` or `protected-read`; `outcome`: `valid`, `invalid` or `not-checked` |
| `grants` (optional) | `actor`, `asset`, and `approvalId` when an approval is on record |
| `alerts` (optional) | `id`, `timestamp`, `rule`, `source` (the log), `identity`, `detail` |

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

## Measured results (latest run)

Run on 2026-11-27 on Windows 11, Python 3.13.3, `pqcrypto` 0.4.0, `cryptography` 50.0.2 (optional demo package installed), on the code in this commit. Each line is the output of the command in the table above. All data is synthetic.

| Check | Result |
|---|---|
| `python -m pytest -q` | 965 passed, 20 skipped (all 20 need POSIX permissions, ownership or symlinks, so they skip on Windows), 64 subtests passed |
| `scripts/check_all.py --skip-tests` | all checks passed: layout, static scan, secret scan of tree and history, official validator exit 0 |
| `tools/selfattack.py` | 251 passed, 0 failed, 0 skipped |
| `scripts/e2e_checks.py` | 16 passed, 0 failed |
| `demo/run_demo.py` | all checks passed, including the optional messaging part |
| `scripts/verify_dependencies.py` | no problems |
| `tools/nodes_sim.py --nodes 4 --runs 20 --seed 1` | bound r + T + s = 62 s held, 0 violations |
| Detector, practice set (22 events) | 22 / 22 labels correct |
| Detector, held-out generated set (12,060 events, `events.csv` SHA-256 `9cb1d3f3…`) | After the slow-flow chaining rule (28 Nov 2026): 12,060 / 12,060 labels correct; `lateral_movement_candidate` F1 1.00 (was 0.90, recall 0.82); 298 / 298 incidents; 606 alerts, 0 false alerts per 1,000 benign events. Two other generated seeds (424242, 98765): every label correct, 0 false alerts; seed 98765 had lateral recall 0.85 before the change. All three sets come from our own generator, so they share its assumptions |

**Clean Linux check of the submitted `main` (`cc74d20`):** a fresh `git clone` from GitHub on Ubuntu (WSL2), a new Python 3.12.3 virtual environment and `pip install -r requirements.txt -r requirements-dev.txt -r requirements-demo.txt`, with the toolkit cloned beside it. Official validator: exit 0, local scenario passed. `python -m pytest -q`: 985 passed, 0 skipped, 64 subtests passed. `tools/selfattack.py`: 251 passed, 0 failed. `scripts/sandbox_sim.py --ref HEAD`: passed, and the submission tree was never modified (it imitates the documented worker; it is not the organizers' sandbox). `scripts/e2e_checks.py`: 16 passed. `demo/run_demo.py`: all checks passed.

Not re-run on this code: the real-kill rotation test, the latency benchmark and the frontend checks (`npm test`, `npm run build`). The frontend was not changed by these fixes.

## Detector input

Event files: columns are matched by name (extra ones are ignored); times are UTC written with `Z` or `+00:00`. If an event ID repeats, the first record is analysed; an identical re-delivery is ignored and a differing copy raises `DET-CONFLICTING-DUPLICATE`. The default roles, services and approver (`user-admin`) follow the toolkit's practice data. For other names use `--approver NAME` (repeatable) and `--policy FILE`; an unconfigured role raises `DET-ROLE-NOT-CONFIGURED`, and an approval by an approver you have not named counts as unapproved.

## Security model and limits

- **No caller authentication in the adapter.** The request carries no credential, so anyone who can call it can claim any actor, including for `setup` and `revoke`. A second `setup` starts over and clears revocations. `t4.gateway` is the front door a deployment puts before it: every caller is enrolled with an ML-DSA-65 key and a role, signs each request (fresh, single-use nonce), and a user may act only as its own actor; reviewers' approve or reject decisions are signed and kept in the gateway's log. The gateway does not change the judged contract, and enrolling callers is not itself authenticated (operator machine only).
- **Device identity** is proven only in the node layer: signature, node binding, owner, key version, time window and a single-use nonce. Rotation has no grace period. A node whose revocation list is older than T denies everything.
- **Local storage is the trust boundary.** Keys sit next to the data. Whoever can write a state, node or authority folder can read its keys and rebuild a consistent log. Restoring a whole folder to an older copy is not detected locally; only a head and public key pinned elsewhere expose it, up to the pinned entry. Replacing only the state file with an older copy (the audit log kept going) is detected, whether the copy predates a revocation or a later `setup` (every revocation and every `setup` raises the state's epoch, and every logged decision records it): `read`, `protected_read` and `revoke` fail closed and a `state-rollback` alert is logged until `setup` is run again or the matching state is restored. File bodies are stored **unencrypted** (HMAC-tagged) in `state.json`: whoever can read the state folder can read them. Restoring old node state can let a recent request be replayed within its time window.
- **Audit logs** are hash-chained with signed checkpoints and grow without limit. The adapter's log signs a checkpoint on its first entry, on every 16th entry, and on the first entry written 60 s or more after the newest checkpoint; entries after the newest checkpoint stay unsigned until the next one (or a pin). The running service re-checks the whole chain on every write while the log is at most 256 KiB, on every 16th write up to 8 MiB, and above that only the newest entries; older edits in a larger log are found by `verify-log`. If a crash lands between an entry and its scheduled checkpoint, the next write re-checks the whole chain and signs the missing checkpoint (it never refuses a log that verifies). Node logs sign every entry: about 7 KB per node request, 14 KB when the request also raises an alert, including requests refused before their signature is checked. `audit` also returns the rule that decided, which tells any caller why a request was denied.
- **Request index.** `audit` remembers the 10,000 newest request IDs. The whole state file is rewritten on every request, so a full index raises the cold-process read time (measured median about 80 ms empty, about 250 ms full, on WSL2 ext4).
- **Logging during storage failures.** A revocation (adapter or authority), a removed grant and a revocation list accepted by a node take effect even when the audit log cannot be written. Their audit entry is queued in the same atomic state write and written exactly once, before any newer entry, by the next operation that can reach that log: the adapter's next `setup`, `read`, `protected_read` or `revoke` (`audit` only reads); a node's next signed request or list delivery; the authority's next enrol, rotation, grant, removal, revocation or list. `reconcile()` on a node or the authority does the same on demand. Until then the adapter's `revoke` answers `{"audit": "pending"}` (not a plain `{}`), the authority raises an error that says the entry is queued, and `python -m t4.storage_status` reports `"audit_logging": "degraded"` with the number of queued entries. Nothing is undone to make logging succeed.
- **Reused `protected_read` challenge.** By default every authorized `protected_read` is answered, even with a challenge used before (the contract asks callers for a fresh one, and no published check covers reuse). With `TRACK4_CHALLENGE_POLICY=once` the adapter refuses a challenge already answered in the current generation (`CRY-CHALLENGE-REUSED`, reply `{"decision": "deny"}`); it remembers every answered challenge until the next `setup` (up to 100,000; when that is full, further protected reads are refused with `CRY-CHALLENGE-CAPACITY` instead of forgetting old challenges). The challenge is reserved in the state before any proof is computed. The console's bridge runs the adapter this way. The official local validator does not call `protected_read`, so passing it says nothing about how hidden judging uses challenges; the default stays off for that reason.
- **Reused `request_id`.** `audit` returns the decision recorded the **first** time an ID was used; a later request with the same ID is decided normally, logged as its own entry and raises `AUD-DUPLICATE-REQUEST-ID`.
- **Lost or damaged history** that the service notices is refused and recorded in a second signed log in the same state folder. Later entries of some kinds can still be removed unnoticed without an outside pin.
- **Backups** are authenticated; a vault created with `encrypt=True` also encrypts them (ChaCha20-Poly1305 from the vetted `cryptography` package, under a separate key kept in the vault's key folder, apart from the backups), and the console's bridge does so when that package is installed. Without it they hold private keys in readable form. The adapter's own `state.json` is still not encrypted: the judged runtime has no vetted cipher, and the adapter never imports `cryptography`. A restore loses newer enrolments and grants. An authority restore re-applies later revocations and key versions from its vault ledger, so it depends on that ledger being current.
- **No encryption in transit in the adapter, and no forward secrecy there.** The judged file service returns bodies in plain text and has no sessions. Message replay and recipient checks, forward secrecy for delivered messages, delivery under loss and session resumption exist only in the optional demo layer (`demo/messaging.py`, `demo/sessions.py`; see the table below). `FileReplayGuard` keeps replay counters on disk and commits each one before a message is reported delivered. Key rotation and ML-KEM alone do not provide forward secrecy, and the demo has no ratchet or post-compromise recovery.
- The **detector** uses fixed rules (no machine learning) and has been measured only on synthetic data. Movement chains group by actor and session within 60 s steps, and steps of the same flow (same correlation ID) stay chained up to 10 minutes apart (`movement_flow_window_s`). An actor that changes session on every step, or waits more than 60 s between steps of different flows, is not chained (use `--policy` to change the grouping or windows). A role with no configured scope raises `DET-ROLE-NOT-CONFIGURED`. Approval expiry is a detector concept: grants in the node layer have no expiry and stay until `ungrant` (the detector flags use after an approval ended). An alert's `emitted_at` is when the evidence needed to raise it had arrived (for movement, the first moment the events received so far form a chain on their own, so a connecting event that arrives late delays the alert); `initial_event_ids` lists that evidence and `evidence_complete_at` when the last cited event arrived. Times to alert are reconstructed from receipt times, not measured emissions; `processing_ms` is the run time. `export` without `--owners` infers the expected-access baseline from the exported window and says so.
- **Key retirement.** `Authority.revoke_key(device, version)` revokes one key version on every node: the signed list marks it, nodes refuse it (`NODE-KEY-REVOKED`) and never forget it, and an authority restore re-applies it from the vault ledger. The device keeps its enrolment and signs again after it rotates to a new version. (`rotation.revoke_key` on the device only stops the device itself from signing with that version.)
- **Freshness boundary.** A node accepts a list younger than T and serves requests while its list is younger than T; a list exactly T old is stale everywhere, as the console shows.
- **Windows.** The permission checks (private 0700 folders, refusing symlinked or foreign folders) run on Linux and macOS. On Windows the service refuses a symlinked or junction folder, but a new folder still inherits the access rules of its parent, because runtime code may not start processes (our static check forbids `subprocess` and `ctypes` in `t4/`). Run `python tools/windows_private.py <folder>` once after the first `setup` (for the state, node, authority and backup folders) to keep only your user and SYSTEM; the console's bridge does this for its workspace.
- Side channels in the compiled cryptography library have not been assessed; secrets cannot be erased from Python memory.
- **pqcrypto 0.4.0** is pinned because the judging runtime ships it. Its code comes from PQClean, which was archived in August 2026; a pqcrypto 1.0.0 release exists, but we stay on the runtime's version.

## Checklist coverage (official goals 9 to 12)

| Goal | Status | What exists |
|---|---|---|
| 9. Replay and recipient binding | Demo layer only | `demo/messaging.py`: ML-KEM-768 + HKDF + ChaCha20-Poly1305 (vetted `cryptography`), ML-DSA-65 signature over the header, recipient and sender checked, per-sender sequence numbers (restart-safe with `FileReplayGuard`). The judged adapter carries files, not messages. |
| 10. Forward secrecy | Demo layer only | `demo/sessions.py`: each message is encapsulated to its own one-time ML-KEM-768 prekey from a bundle signed by the recipient and bound to a random session ID; once the receiver has authenticated a message (first delivery or duplicate) it deletes that prekey's secret, so stealing the receiver's state later does not reveal delivered messages. No ratchet or post-compromise recovery; messages in flight are not covered. A prototype on vetted primitives, not an established protocol. |
| 11. Delivery under loss or reordering | Demo layer only | `demo/sessions.py`: each number is delivered once in any order; ACKs are signed, bound to the session and name each confirmed envelope's digest, so an ACK from another session or for another envelope clears nothing. A duplicate (a resend after a lost ACK) is authenticated and answered with an ACK, never delivered twice. Resends are bounded with a doubling back-off; a sender without prekeys reports `needs_bundle`, and the receiver tops its prekeys up. At-least-once delivery to the application. |
| 12. Session resumption | Demo layer only | `demo/sessions.py`: each side keeps its session in one atomically written file, changed only under a file lock with the state re-read inside it (two processes cannot both deliver one message), and resumes after a restart. The file is not encrypted. |

The judged interface is a file service (`read`, `protected_read`); whether goals 9 to 12 apply to a file-only prototype is a question for the organizers.

## Operator workflows

- **Full history check with outside pins.** `python -m t4.audit.cli --dir <log dir> pin init --pin <pin.json>` once (keep the pin file outside the state folder) and `pin advance --pin <pin.json>` to move it forward after a successful check; later `python -m t4.audit.cli --dir <log dir> verify-log --pin <pin.json>`. The report gives `checked_range` (every entry re-hashed from the first), `pinned_range` (covered by a signed checkpoint or the pin), the first bad entry and `seconds` taken. Above 256 KiB the running service re-checks the whole log only on every 16th write, and above 8 MiB only the newest entries, so schedule this check (for example before each demo or daily).
- **Log capacity.** `python -m t4.storage_status --state-dir <dir>` warns when the audit log or the volume crosses a threshold and when logging is degraded. `python -m t4.audit.cli --dir <log dir> archive --to <archive folder>` re-checks the whole chain, signs the head, copies the finished segment and a pin of its head to `<archive>/segment-<n>/` (fsynced and verified), writes a signed anchor (`segment.json`) and only then empties the live files. The anchor carries the security watermark of everything archived (highest epoch and generation) and the identities of once-only entries, so an older `state.json` is still refused after archiving and a queued event is never logged twice. New entries continue the same numbering and hash chain. Nothing is deleted. A pin older than an archive boundary is checked with `verify-log --pin <pin> --archive <folder>` (every segment, their signed links and the old pin); without `--archive` that check FAILS rather than passing unchecked. `explain --archive <folder>` searches archived segments too; `find` and the detector read the live segment only. Anchors written by the first archive version (commit 42e935a) are refused as an older format. The service itself never trims the log.

## Attribution

- `track4_service.py` is based on the Python starter adapter of the official Track 4 participant toolkit (https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit, commit `8901dfb`). `tests/detect/data/practice/` holds unchanged copies of the toolkit's synthetic practice files. The toolkit's demo application was not copied.
- **pqcrypto 0.4.0** (https://pypi.org/project/pqcrypto/) provides ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204); **cffi** and **pycparser** are its dependencies. **pytest** is used for tests.
- **cryptography** (https://cryptography.io, Apache-2.0 or BSD-3-Clause) is used by the demo layer (`demo/messaging.py`, `demo/sessions.py`) and, optionally, encrypted backups (`t4/backup.py`); never by the judged adapter.
- HMAC-SHA256 (RFC 2104) and SHA-256 come from the Python standard library.
- Web console: [React](https://react.dev/) (MIT), [Vite](https://vite.dev/) (MIT), [TypeScript](https://www.typescriptlang.org/) (Apache-2.0), Prettier (MIT, formatting only) and the [Instrument Sans](https://fontsource.org/fonts/instrument-sans) font (SIL Open Font License), bundled locally.
