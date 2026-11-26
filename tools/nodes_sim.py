"""Measure how long a revocation takes to be enforced by the last node.

    python tools/nodes_sim.py --nodes 4 --runs 20 --seed 1

N node directories and one authority directory are created in a temporary
folder. A courier delivers each signed list late, or never. Some nodes are cut
off completely at the moment of revocation. The lost device keeps trying every
node; a second user's device checks that others keep access.

Time is SIMULATED: clocks are passed in as numbers, so the reported delays show
protocol behaviour under this courier model, not network or CPU speed. Node
clocks are off by up to +/- s. The check is that no node allows the lost device
later than r + T + s. Exit code 1 if it ever does.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import tempfile
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from t4.node.authority import Authority  # noqa: E402
from t4.node.common import KeyLog, NodeError, Signer, load_signer, open_log  # noqa: E402
from t4.node.device import Device  # noqa: E402
from t4.node.freshness import Node  # noqa: E402
from t4.node.request import handle_request  # noqa: E402

START = 1_000_000.0


def one_run(root: Path, rng: random.Random, signer: Signer,
            log_factory: Callable[[Path], KeyLog], *, nodes: int, freshness: float,
            skew: float, heartbeat: float, step: float, max_delay: float, loss: float,
            cut_off: float) -> dict:
    authority = Authority.create(root / "authority", signer, log_factory(root / "authority-log"),
                                 freshness=freshness, skew=skew)
    lost = Device.create(root / "lost", signer, "device-lost", "user-a")
    other = Device.create(root / "other", signer, "device-other", "user-b")
    lost.enroll(authority, START)
    other.enroll(authority, START)
    names = [f"node-{index}" for index in range(nodes)]
    fleet = {name: Node.provision(
        root / name, signer, log_factory(root / f"{name}-log"), node_id=name,
        authority_pk=authority.public_key, owners={"file-a": "user-a", "file-b": "user-b"},
        contents={"file-a": "synthetic a", "file-b": "synthetic b"},
        freshness=freshness, skew=skew) for name in names}
    offsets = {name: rng.uniform(-skew, skew) for name in names}
    first = authority.issue_list(START)
    for name in names:
        if not fleet[name].accept_list(first, START + offsets[name]):
            raise RuntimeError("a node rejected the first list")
    revoke_at = START + rng.uniform(1, heartbeat)
    isolated = {name for name in names if rng.random() < cut_off}
    pending: list[tuple[float, str, dict]] = []
    revoked_effective: float | None = None
    last_allow = {name: None for name in names}
    other_allowed = other_total = 0
    next_heartbeat, now = START + heartbeat, START
    end = START + heartbeat + freshness + skew + 3 * step + max_delay

    def send(signed: dict, sent: float) -> None:
        for name in names:
            if revoked_effective is not None and name in isolated:
                continue
            if rng.random() >= loss:
                pending.append((sent + rng.uniform(0, max_delay), name, signed))

    while now <= end:
        now += step
        if revoked_effective is None and now >= revoke_at:
            revoked_effective = authority.revoke_device("device-lost", now)
            send(authority.issue_list(now), now)
        if now >= next_heartbeat:
            send(authority.issue_list(now), now)
            next_heartbeat += heartbeat
        for item in sorted((p for p in pending if p[0] <= now), key=lambda p: p[0]):
            fleet[item[1]].accept_list(item[2], now + offsets[item[1]])
        pending = [p for p in pending if p[0] > now]
        if revoked_effective is None:
            continue
        for name in names:
            local = now + offsets[name]
            request = lost.make_request(name, "file-a", now)
            if handle_request(fleet[name], request, local).allow:
                last_allow[name] = now
            if name not in isolated:
                request = other.make_request(name, "file-b", now)
                other_total += 1
                other_allowed += handle_request(fleet[name], request, local).allow
    # Enforcement time: just after the last probe that was still allowed.
    delays = {name: 0.0 if last_allow[name] is None
              else last_allow[name] + step - revoked_effective for name in names}
    violations = [name for name in names if last_allow[name] is not None
                  and last_allow[name] > revoked_effective + freshness + skew]
    return {"until_last_node": max(delays.values()), "violations": violations,
            "isolated_nodes": len(isolated), "other_allowed": other_allowed,
            "other_total": other_total}


def simulate(signer: Signer, log_factory: Callable[[Path], KeyLog], *, nodes: int = 4,
             runs: int = 20, seed: int = 1, freshness: float = 60.0, skew: float = 2.0,
             heartbeat: float = 20.0, step: float = 1.0, max_delay: float = 45.0,
             loss: float = 0.3, cut_off: float = 0.25) -> dict:
    rng = random.Random(seed)  # Chooses the scenario only; never used for keys.
    results = []
    for _ in range(runs):
        with tempfile.TemporaryDirectory(prefix="t4-sim-") as folder:
            results.append(one_run(
                Path(folder), rng, signer, log_factory, nodes=nodes, freshness=freshness,
                skew=skew, heartbeat=heartbeat, step=step, max_delay=max_delay, loss=loss,
                cut_off=cut_off))
    delays = [r["until_last_node"] for r in results]
    violations = sum(len(r["violations"]) for r in results)
    total = sum(r["other_total"] for r in results)
    return {
        "time": "simulated seconds", "nodes": nodes, "runs": runs, "seed": seed,
        "T": freshness, "s": skew, "heartbeat": heartbeat, "probe_step": step,
        "max_courier_delay": max_delay, "loss_probability": loss,
        "cut_off_probability": cut_off,
        "until_last_node": {"min": round(min(delays), 2),
                            "median": round(statistics.median(delays), 2),
                            "max": round(max(delays), 2)},
        "bound_r_plus_T_plus_s": freshness + skew, "bound_violations": violations,
        "bound_held": violations == 0,
        "other_user_allow_rate_on_connected_nodes": round(
            sum(r["other_allowed"] for r in results) / total, 4) if total else None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    for name, kind, default in (("nodes", int, 4), ("runs", int, 20), ("seed", int, 1),
                                ("freshness", float, 60.0), ("skew", float, 2.0),
                                ("heartbeat", float, 20.0), ("step", float, 1.0),
                                ("max-delay", float, 45.0), ("loss", float, 0.3),
                                ("cut-off", float, 0.25)):
        parser.add_argument(f"--{name}", type=kind, default=default)
    args = vars(parser.parse_args(argv))
    try:
        report = simulate(load_signer(), open_log, **args)
    except NodeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report["bound_held"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
