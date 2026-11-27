import assert from "node:assert/strict";
import test from "node:test";
import { BridgeError, createBridge, summarize } from "../src/lib/api.ts";

const reply = (status, body) => async (url, init) => {
  reply.last = { url, init };
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
  });
};
const snapshot = {
  schemaVersion: 1,
  capturedAt: "2026-11-26T08:00:00.000Z",
  clock: "2026-11-26T08:01:10.000Z",
  devices: [{ id: "d", owner: "o", keyVersion: 1, state: "active" }],
  nodes: [],
  audit: [],
  verifications: [],
};

test("the snapshot goes through the strict parser and keeps the bridge clock", async () => {
  const result = await createBridge(reply(200, snapshot)).snapshot();
  assert.equal(result.devices[0].id, "d");
  assert.equal(result.clock, snapshot.clock);
  assert.equal(reply.last.url, "/api/snapshot");
  assert.equal(reply.last.init.method, "GET");
});

test("a snapshot the parser rejects is reported, not shown", async () => {
  const bad = { ...snapshot, devices: [{ id: "d" }] };
  await assert.rejects(createBridge(reply(200, bad)).snapshot(), /rejected/);
  await assert.rejects(
    createBridge(reply(200, { ...snapshot, clock: "yesterday" })).snapshot(),
    /clock/,
  );
});

test("actions are POSTed as JSON to the bridge only", async () => {
  const result = await createBridge(
    reply(200, {
      decision: "deny",
      rule: "NODE-DEVICE-REVOKED",
      node_id: "node-a",
    }),
  ).action({ name: "request", device_id: "d" });
  assert.equal(reply.last.url, "/api/action");
  assert.equal(reply.last.init.method, "POST");
  assert.equal(reply.last.init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(reply.last.init.body), {
    name: "request",
    device_id: "d",
  });
  assert.equal(result.summary, "DENY · NODE-DEVICE-REVOKED · on node-a");
});

test("adapter calls go to /api/adapter", async () => {
  await createBridge(reply(200, { decision: "allow", body: "x" })).adapter({
    op: "read",
  });
  assert.equal(reply.last.url, "/api/adapter");
});

test("an error label from the bridge is shown as words, with no raw text", async () => {
  await assert.rejects(
    createBridge(reply(422, { error: "adapter_refused_request" })).adapter({}),
    (error) =>
      error instanceof BridgeError &&
      error.message === "adapter refused request",
  );
  await assert.rejects(
    createBridge(reply(500, "<html>stack trace</html>")).snapshot(),
    (error) => error.message === "The bridge answered 500.",
  );
});

test("an unreachable bridge says how to start it", async () => {
  const down = async () => {
    throw new TypeError("fetch failed");
  };
  await assert.rejects(createBridge(down).health(), /python tools\/bridge\.py/);
});

test("a reply that is not a JSON object is refused", async () => {
  await assert.rejects(createBridge(reply(200, "[]")).health(), BridgeError);
  await assert.rejects(createBridge(reply(200, "nope")).health(), BridgeError);
});

test("health reports whether the world is started", async () => {
  assert.deepEqual(
    await createBridge(reply(200, { ok: true, started: false })).health(),
    { ok: true, started: false },
  );
});

test("summaries only use known fields", () => {
  assert.equal(
    summarize({ accepted: { "node-a": true, "node-c": false } }),
    "node-a accepted the list · node-c did not get it",
  );
  assert.equal(summarize({ outcome: "valid" }), "Protected-read proof: valid");
  assert.equal(
    summarize({ revoked: true, effective_at: "x" }),
    "Device revoked",
  );
  assert.equal(
    summarize({ node_id: "node-c", offline: true }),
    "node-c is offline",
  );
  assert.equal(summarize({ secret: "never shown" }), "Done");
});
