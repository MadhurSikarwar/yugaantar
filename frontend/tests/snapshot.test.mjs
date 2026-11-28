import assert from "node:assert/strict";
import test from "node:test";
import { parseSnapshot } from "../src/snapshot.ts";

const empty = () => ({
  schemaVersion: 1,
  capturedAt: new Date().toISOString(),
  devices: [],
  nodes: [],
  audit: [],
  verifications: [],
});
const parse = (value) => parseSnapshot(JSON.stringify(value));

test("empty snapshots retain real zero counts", () => {
  const result = parse(empty());
  assert.equal(result.devices.length, 0);
  assert.equal(result.audit.length, 0);
});
test("unknown fields and private material are discarded", () => {
  const input = empty();
  input.privateMaterial = "must not be retained";
  input.devices.push({
    id: "test-device",
    owner: "test-owner",
    keyVersion: 1,
    state: "active",
    privateMaterial: "must not be retained",
  });
  assert.equal(
    JSON.stringify(parse(input)).includes("must not be retained"),
    false,
  );
});
test("malformed input and unsupported versions are rejected", () => {
  for (const input of ["", "null", "[]", "{}", "{invalid"])
    assert.throws(() => parseSnapshot(input));
  assert.throws(() => parse({ ...empty(), schemaVersion: 2 }), /Unsupported/);
});
test("timestamps must include their timezone", () => {
  assert.throws(
    () => parse({ ...empty(), capturedAt: "2026-11-26T12:00:00" }),
    /timezone/,
  );
  assert.throws(() => parse({ ...empty(), capturedAt: "invalid" }), /timezone/);
});
test("unknown device states and negative versions fail closed", () => {
  for (const overrides of [
    { state: "trusted" },
    { keyVersion: -1 },
    { keyVersion: "1" },
  ]) {
    assert.throws(() =>
      parse({
        ...empty(),
        devices: [
          { id: "d", owner: "a", keyVersion: 1, state: "active", ...overrides },
        ],
      }),
    );
  }
});
test("duplicate registry identifiers are rejected", () => {
  const d = { id: "d", owner: "a", keyVersion: 1, state: "active" };
  assert.throws(() => parse({ ...empty(), devices: [d, d] }), /duplicate/);
});
test("duplicate audit requests are preserved for inspection", () => {
  const a = {
    requestId: "duplicate",
    timestamp: new Date().toISOString(),
    actor: "a",
    action: "read",
    asset: "file",
    decision: "deny",
    rule: "test-rule",
  };
  const result = parse({ ...empty(), audit: [a, a] });
  assert.equal(result.audit.length, 2);
});
test("node device associations remain strings and may be empty", () => {
  const n = {
    id: "n",
    state: "stale",
    listVersion: 0,
    lastUpdated: new Date().toISOString(),
    deviceIds: ["d"],
  };
  assert.deepEqual(parse({ ...empty(), nodes: [n] }).nodes[0].deviceIds, ["d"]);
  assert.throws(() =>
    parse({ ...empty(), nodes: [{ ...n, deviceIds: [{}] }] }),
  );
});
test("large files and oversized collections are rejected", () => {
  assert.throws(() => parseSnapshot(" ".repeat(5 * 1024 * 1024 + 1)), /5 MB/);
  assert.throws(
    () => parse({ ...empty(), devices: Array(5001).fill({}) }),
    /5,000/,
  );
});
test("imported valid outcomes remain data, not generated checks", () => {
  const v = {
    id: "evidence",
    kind: "checkpoint",
    outcome: "valid",
    detail: "Imported result",
  };
  assert.deepEqual(parse({ ...empty(), verifications: [v] }).verifications, [
    v,
  ]);
  assert.throws(() =>
    parse({ ...empty(), verifications: [{ ...v, outcome: "secure" }] }),
  );
});
test("grants and alerts are optional and validated", () => {
  const none = parse(empty());
  assert.deepEqual([none.grants, none.alerts], [[], []]);
  const result = parse({
    ...empty(),
    grants: [{ actor: "eve", asset: "plan" }, { actor: "noor", asset: "plan", approvalId: "chg-1" }],
    alerts: [
      {
        id: "authority-4",
        timestamp: "2026-11-28T10:00:00Z",
        rule: "DET-UNAPPROVED-ROLE-CHANGE",
        source: "authority",
        identity: "eve",
        detail: "grant with no approval",
      },
    ],
  });
  assert.equal(result.grants[0].approvalId, undefined);
  assert.equal(result.grants[1].approvalId, "chg-1");
  assert.equal(result.alerts[0].rule, "DET-UNAPPROVED-ROLE-CHANGE");
  assert.throws(() => parse({ ...empty(), grants: [{ actor: "", asset: "plan" }] }));
  assert.throws(() =>
    parse({ ...empty(), alerts: [{ id: "a", timestamp: "yesterday", rule: "R", source: "s", identity: "i", detail: "d" }] }),
  );
});
