# Response to the feature audit of 2026-11-28

This document responds to `security_assessment/FEATURE_AUDIT_2026-11-28.txt` and its completion prompt. The work is in commits `a374587` to `a615124` on `main`; the last commit pushed was `6342f30`. No workflow, test, security gate or CLI command was removed. The judged adapter (`track4_service.py`) keeps its five operations, its one process per request, and its runtime of pqcrypto plus the standard library. The static scan still forbids `subprocess` and `ctypes` in `t4/`.

## Critical regressions (A–D)

| | What was wrong | What changed | Regression tests |
|---|---|---|---|
| A | Archiving the audit log removed the history that rollback protection relied on, so an old `state.json` could restore revoked access. | Every archive writes a signed segment anchor (`audit-segment-anchor-v2`). The anchor carries a non-decreasing watermark `{epoch, generation}` and the digests of once-only entries. `newest_value`, the service and `consistency.check` all read it. The archive steps run in a crash-safe order: verify, copy, fsync, pin, verify the copy, write the anchor to the archive, write the anchor to the live log, empty the live files. A partial archive is finished on the next run. | `tests/audit/test_archive.py`: `test_an_old_state_file_after_archival_cannot_restore_revoked_access` (immediately, after new entries, after repeated setup, across several segments), `test_an_interrupted_archive_fails_closed_and_is_finished_by_running_it_again`, `test_a_queued_event_written_before_an_archive_is_not_written_again` |
| B | A pin older than the archive origin was reported as a match. | `verify_log(..., archive_dir=)` checks that segments chain to each other, that each verifies against its own pin, and that the segment holding the old pin matches it. Without the archive, an old pin is a failure that names the entry, never a pass. `verify-log --archive` and `explain --archive` expose this. | `test_an_old_pin_without_the_archive_is_a_failure_not_a_pass`, `test_an_old_pin_detects_a_rewritten_missing_or_reordered_archive` |
| C | Session ACKs carried no session or message identity, so an ACK from an earlier session could clear a new message. | Sessions v2 (`demo/sessions.py`): a unique session ID, and ACKs that carry `(seq, SHA-256 of the envelope)` and are checked for shape, provenance and session. | `tests/unit/test_demo_sessions.py`: `test_an_ack_from_an_earlier_session_cannot_clear_a_new_message`, `test_an_ack_only_confirms_the_exact_envelope_it_names`, `test_a_message_from_another_session_is_refused` |
| D | A lost ACK caused a resend that used up prekeys, and two receivers could both deliver the same envelope. | State is updated under a file lock across processes. A duplicate envelope makes the receiver send its ACK again instead of a second delivery. Resends are bounded, and prekeys are replenished; an exhausted sender reports it. | `test_a_lost_ack_is_recovered_without_double_delivery_or_prekey_exhaustion`, `test_a_sender_without_prekeys_reports_it_and_continues_after_a_new_bundle`, `test_reordered_messages_are_delivered_once` |

## The 13 items

| # | Item | Status | Source | Tests |
|---|---|---|---|---|
| 1 | Timed checkpointing | Done. `audit.cli seal [--watch]` signs a quiet unsigned tail once the newest checkpoint is older than `--max-age`. It signs again on shutdown, and entry 1 is still signed. The judged adapter needs no change because the sealer is the external owner of the log's lifecycle. | `t4/audit/sealer.py`, `t4/audit/log.py:_checkpoint_due` | `tests/audit/test_sealer.py` |
| 2 | Durable external pins | Mostly done. `--pins-dir` defaults to `%LOCALAPPDATA%/latticelock/pins/<world_id>`. Pins inside the workspace are refused, and a pin only advances while the log still verifies, so it is never silently re-pinned. **Not done: reopening an existing workspace.** | `tools/bridge.py` (`default_pins_root`, `pin`) | `test_pins_survive_the_bridge_closing_and_a_new_world`, `test_a_pin_is_never_silently_replaced_for_a_rewritten_log`, `test_pins_inside_the_workspace_are_refused` |
| 3 | Grants and alerts | Kept as they were. Alerts now carry their `evidence` hash and a durable review status (approve, reject or conflict) from signed decisions. Old snapshots still parse. | `frontend/src/snapshot.ts`, `Console.tsx` | `frontend/tests/snapshot.test.mjs` |
| 4 | Naming and README | Done. The README separates the adapter's import graph (no `cryptography`) from optional modules, and the statements about sessions were reconciled. | `README.md` | — |
| 5 | Challenge policy `once` | Done. Nothing is evicted within a generation. When the registry reaches 100,000 entries, the adapter refuses with `CRY-CHALLENGE-CAPACITY` instead of forgetting. The checked-in validator does not exercise `protected_read`, so it proves nothing about this. | `t4/identity.py`, `t4/service.py` | `test_challenge_policy_once_refuses_a_reused_challenge`, `test_a_full_challenge_registry_refuses_instead_of_forgetting` |
| 6 | Single key-version revocation | Kept as it was. The snapshot and the UI show `no-usable-key` instead of `active` for a device whose only key version is revoked. | `tools/bridge.py` snapshot, `snapshot.ts` | `test_a_device_whose_current_key_is_revoked_is_not_shown_active`, `test_one_key_version_is_revoked_on_every_node_and_survives_a_restore`, the frontend test for the `no-usable-key` state |
| 7 | Cross-session movement | Partly done. `DET-CROSS-SESSION-MOVEMENT` (medium) groups the leftover unexpected edges by actor alone. It never groups unverified identities. **Not done: a stable device identity through ingest, and evaluation on independent held-out data.** | `t4/detect/engine.py:_cross_session`, `config.py` | `test_session_churn_is_still_movement`, `test_churn_steps_far_apart_or_at_one_service_are_not_chained`, `test_unverified_claims_are_never_grouped_across_sessions` |
| 8 | Windows folder privacy | Done, except that **there is no test as a second Windows user.** The allowlist is the current user and SYSTEM; the tool sets the owner, removes other entries, resets children and verifies the result. Junctions are refused. The bridge applies it before it writes anything. | `tools/windows_private.py` | `tests/unit/test_windows_private.py` |
| 9 | Caller authentication | Done for the bridge deployment. `--gateway-only` closes the direct routes (they return 403). Callers are enrolled by public key and keep their own secret keys (`tools/gateway_client.py`). Every authority command goes through the gateway, and callers can be revoked or given a new key, with a rate limit of 60 per 60 s. Requests travel over localhost HTTP with ML-DSA signatures, not TLS. | `t4/gateway.py`, `tools/bridge.py` | `tests/unit/test_gateway.py`, `test_gateway_only_mode_with_a_caller_held_key` |
| 10 | Encryption at rest | Partly done, within the scope you chose ("outside adapter only"). The backup key is held by Windows DPAPI (`vault.enc.wrapped`), and `--secure` refuses to start rather than downgrade. **Not done: live state encryption, a provider for Linux or macOS, and TPM/HSM support.** | `tools/keystore.py`, `t4/backup.py` | `test_a_keystore_wrapped_vault_key_is_never_written_in_plain_text`, `test_secure_mode_keeps_the_backup_key_in_the_os_keystore` |
| 11 | Transactional storage | Log archival only, as you chose. **Not done: SQLite or another indexed store, and benchmarks.** | `t4/audit/archive.py` | `tests/audit/test_archive.py` |
| 12 | Sessions as a product workflow | The defects in C and D are fixed. Sessions remain a demo layer, not wired into the adapter. They are not a ratchet and offer no post-compromise recovery. | `demo/sessions.py` | `tests/unit/test_demo_sessions.py` |
| 13 | Reviewer integration | Done. Decisions are bound to a real alert ID and its current SHA-256 evidence. The gateway refuses unknown alerts, stale evidence and repeated verdicts, records `REV-CONFLICT` for a different later verdict, and stores the status durably. A decision never grants access. | `t4/gateway.py`, `tools/bridge.py:alert_evidence` | `test_decisions_need_a_real_alert_current_evidence_and_no_repeat`, `test_a_reviewer_decision_is_signed_recorded_and_checkable_later` |

## Migration and rollback

- **Segment anchors.** An archive written before `a374587` (anchor without a watermark) is refused as an older format. To migrate, verify the old archive, then archive the live log again with the new code. Rolling back to `6342f30` was not tested against anchors written by the new code. Expect the old code to reject them or ignore the watermark, which brings back the old rollback gap.
- **Gateway decisions.** A decision body must now include `evidence`. Old `REV-DECISION` entries stay valid in the hash chain. Re-checking their decision signatures with the new format is not supported, because they carry no evidence.
- **Vault.** Vaults that hold a plain `vault.enc` keep working. Only new bridge worlds on Windows get `vault.enc.wrapped`. A wrapped key can be unwrapped only by the same Windows user on the same machine. Copy the backups and you also need that account.

## Validation (Windows 11, Python 3.12.10, pqcrypto 0.4.0, cryptography 50.0.2, pytest 9.2.0, Node 24.14.0)

| Command | Result |
|---|---|
| `pytest -rs --ignore=tests/security` (commit `7763f16`) | 1045 passed, 1 failed, 21 skipped. The failure was the API contract test for `BackupVaultApi.create`, fixed in `a615124`. That test file then passed 10/10. The full suite was not rerun after that one-line Protocol change. |
| `tools/selfattack.py` | 251 passed, 0 failed |
| `scripts/e2e_checks.py` | 16 passed, 0 failed |
| `Track-4-Toolkit/validate.py --entry ./track4_service.py` | Local scenario passed |
| `scripts/check_all.py --skip-tests` | static scan, secret scan and validator PASS. The layout check fails only because `Track-4-Toolkit/` sits inside the repo folder here; CI checks it out as a sibling. |
| `scripts/verify_dependencies.py` | no problems |
| `demo/run_demo.py` / `scripts/sandbox_sim.py` | both passed |
| frontend `npm run check`, `npm test`, `npm run build`, Prettier | type check OK, 31/31, build OK, formatted |

## Still open

- Live state encryption, and keys outside plain files for live state (item 10)
- SQLite or another transactional store, and benchmarks (item 11)
- Reopening an existing workspace (item 2)
- Stable device identity through ingest, and held-out evaluation (item 7)
- A second Windows user ACL test (item 8)
- Firefox, Safari/WebKit and screen-reader checks, and browser checks in CI
- Isolating the `tests/security` collision. That folder is untracked user work; it was excluded from the run, not changed.
- Refreshing the numbers in the brief PDF
- TLS for the gateway's transport
