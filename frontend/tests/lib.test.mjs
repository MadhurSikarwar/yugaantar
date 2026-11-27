import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  entryHash,
  genesisHash,
  seal,
  sha256Hex,
  verifyChain,
} from "../src/lib/ledger.ts";
import { decide as policy } from "../src/lib/policy.ts";
import {
  BOUND,
  advance,
  createSim,
  decide,
  nodeIds,
  revokePhone,
  setConnected,
} from "../src/lib/revocation.ts";
import { sampleSnapshot } from "../src/lib/sample.ts";
import { ruleCounts, timeBuckets } from "../src/lib/stats.ts";
import { parseSnapshot } from "../src/snapshot.ts";

test("Web Crypto SHA-256 agrees with the Node implementation across block boundaries", async () => {
  for (let length = 0; length < 200; length++) {
    const data = Uint8Array.from({ length }, (_, i) => (i * 31 + length) & 255);
    assert.equal(
      await sha256Hex(data),
      createHash("sha256").update(data).digest("hex"),
    );
  }
});

// Reference values produced by t4.audit.log.entry_hash in the Python backend.
test("ledger hashes match the backend's entry_hash", async () => {
  const first = {
    seq: 1,
    ts: "2026-11-27T09:00:00Z",
    actor: "maya",
    action: "read",
    target: "brief",
    decision: "allow",
    rule: "POL-ALLOW-OWNER",
    request_id: "r1",
    detail: {},
  };
  const genesis = await genesisHash();
  assert.equal(
    genesis,
    "4ace6cae2a9f18a3ca43251a01d9b7528533ff7c9981dd744953d802de7c95e2",
  );
  const h1 = await entryHash(first, genesis);
  assert.equal(
    h1,
    "a02d424e2484a11af36627d2cc9508f5c483dc1a8d95345f3940dee6a752aa1e",
  );
  // Non-ASCII, an astral character, quotes, a backslash, DEL and a newline.
  const second = {
    ...first,
    seq: 2,
    actor: 'zoë \u{1F512} "q"\\ \x7f\n',
    detail: { node_id: "node-a", epoch: 3 },
  };
  assert.equal(
    await entryHash(second, h1),
    "56575f3324c3f0fd8012422bf6477d8fc638321746cf49c8f9ad87630ff6d71c",
  );
});

test("an edit breaks the chain; a rewrite is caught only by the pin", async () => {
  const entry = (seq, decision) => ({
    seq,
    ts: "2026-11-26T09:00:00Z",
    actor: "maya",
    action: "read",
    target: "brief",
    decision,
    rule: "POL-REVOKED",
    request_id: `r${seq}`,
    detail: {},
  });
  const log = await seal([
    entry(1, "allow"),
    entry(2, "deny"),
    entry(3, "deny"),
  ]);
  const pin = log[2].hash;
  assert.deepEqual(await verifyChain(log, pin), {
    brokenAt: null,
    matchesPin: true,
  });
  const edited = log.map((e) =>
    e.seq === 2 ? { ...e, decision: "allow" } : e,
  );
  assert.equal((await verifyChain(edited, pin)).brokenAt, 2);
  assert.deepEqual(await verifyChain(await seal(edited), pin), {
    brokenAt: null,
    matchesPin: false,
  });
  // Cutting off the tail is also visible against the pin.
  assert.equal((await verifyChain(log.slice(0, 2), pin)).matchesPin, false);
});

test("policy rules apply in the backend's order", () => {
  const owners = { brief: "maya" };
  const run = (input) =>
    policy({
      actor: "maya",
      asset: "brief",
      revoked: false,
      disabled: false,
      owners,
      ...input,
    });
  assert.equal(run({}).id, "POL-ALLOW-OWNER");
  assert.equal(run({}).allow, true);
  assert.equal(run({ actor: "eve" }).id, "POL-NOT-OWNER");
  assert.equal(run({ asset: "none" }).id, "POL-UNKNOWN-ASSET");
  assert.equal(run({ asset: "constructor" }).id, "POL-UNKNOWN-ASSET");
  assert.equal(run({ asset: "none", disabled: true }).id, "POL-DISABLED");
  assert.equal(run({ revoked: true, disabled: true }).id, "POL-REVOKED");
});

test("no node accepts the revoked phone after r + T + s, whatever is cut off", () => {
  let seed = 7;
  const random = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
  for (let run = 0; run < 300; run++) {
    let sim = createSim();
    const revokeAfter = random() * 150;
    const toggle = () => {
      const id = nodeIds[Math.floor(random() * nodeIds.length)];
      sim = setConnected(sim, id, random() > 0.5);
    };
    while (sim.t < revokeAfter) {
      toggle();
      sim = advance(sim, 1 + random() * 20);
    }
    sim = revokePhone(sim);
    const revokedAt = sim.revokedAt;
    while (sim.t < revokedAt + BOUND + 90) {
      if (random() > 0.6) toggle();
      sim = advance(sim, 0.5 + random() * 6);
      if (sim.t < revokedAt + BOUND) continue;
      for (const node of sim.nodes)
        assert.equal(decide(node, "maya-phone", sim.t).allow, false);
    }
    for (const node of sim.nodes)
      assert.ok(node.enforcedAt - revokedAt <= BOUND);
  }
});

test("a connected node keeps serving other owners; a cut-off node locks everyone", () => {
  let sim = setConnected(createSim(), "node-c", false);
  sim = advance(revokePhone(sim), 90);
  const [a, , c] = sim.nodes;
  assert.equal(decide(a, "maya-phone", sim.t).rule, "NODE-DEVICE-REVOKED");
  assert.equal(decide(a, "noor-laptop", sim.t).allow, true);
  assert.equal(decide(c, "noor-laptop", sim.t).rule, "NODE-STALE-LIST");
  sim = advance(setConnected(sim, "node-c", true), 40);
  assert.equal(decide(sim.nodes[2], "noor-laptop", sim.t).allow, true);
  assert.equal(decide(sim.nodes[2], "maya-phone", sim.t).allow, false);
});

test("enforcement is withdrawn if an older list in transit reopens a node", () => {
  let sim = setConnected(createSim(), "node-c", false);
  sim = advance(sim, 75);
  // Reconnect, let the pre-revocation list leave, then revoke while it travels.
  sim = advance(setConnected(sim, "node-c", true), 6);
  sim = revokePhone(sim);
  assert.equal(sim.nodes[2].enforcedAt, sim.revokedAt);
  // The old list lands at 93 s and the revoking list at 94 s.
  sim = advance(sim, 12.5);
  assert.equal(decide(sim.nodes[2], "maya-phone", sim.t).allow, true);
  assert.equal(sim.nodes[2].enforcedAt, null);
  sim = advance(sim, 10);
  assert.ok(sim.nodes[2].enforcedAt > sim.revokedAt);
  assert.equal(new Set(sim.events.map((e) => e.id)).size, sim.events.length);
});

test("the simulation does not modify earlier states", () => {
  const first = createSim();
  const copy = structuredClone(first);
  advance(revokePhone(setConnected(first, "node-b", false)), 100);
  assert.deepEqual(first, copy);
});

test("the synthetic sample satisfies the import contract and says it is invented", () => {
  const sample = sampleSnapshot();
  assert.deepEqual(parseSnapshot(JSON.stringify(sample)), sample);
  assert.ok(sample.audit.every((r) => r.requestId.startsWith("sample-")));
  assert.ok(sample.verifications.every((v) => v.detail.startsWith("Invented")));
});

test("chart aggregations count every record exactly once", () => {
  const { audit } = sampleSnapshot();
  const total = (rows, read) => rows.reduce((sum, r) => sum + read(r), 0);
  assert.equal(
    total(timeBuckets(audit), (b) => b.allow + b.deny),
    audit.length,
  );
  assert.equal(
    total(ruleCounts(audit), (r) => r.count),
    audit.length,
  );
  assert.deepEqual(timeBuckets([]), []);
  const single = timeBuckets([audit[0], audit[0]]);
  assert.equal(single.length, 1);
  assert.equal(single[0].allow + single[0].deny, 2);
});
