/** Invented records, loaded only on request and always labelled as synthetic in the console. */
import type { AuditRecord, Snapshot } from "../snapshot.ts";

export const SAMPLE_NAME = "Synthetic sample";

const start = Date.parse("2026-11-26T08:00:00Z");
const at = (minute: number) => new Date(start + minute * 60000).toISOString();

type Kind = [
  actor: string,
  asset: string,
  decision: AuditRecord["decision"],
  rule: string,
];
const routine: Kind[] = [
  ["maya", "brief", "allow", "NODE-ALLOW-OWNER"],
  ["noor", "ledger", "allow", "NODE-ALLOW-OWNER"],
  ["ravi", "roadmap", "allow", "NODE-ALLOW-OWNER"],
  ["noor", "ledger", "allow", "POL-ALLOW-OWNER"],
  ["ravi", "brief", "deny", "POL-NOT-OWNER"],
];
const incident: Kind[] = [
  ["maya", "brief", "deny", "NODE-DEVICE-REVOKED"],
  ["eve", "ledger", "deny", "NODE-NOT-PERMITTED"],
  ["eve", "roadmap", "deny", "NODE-NOT-PERMITTED"],
  ["(unverified)", "brief", "deny", "NODE-BAD-SIGNATURE"],
  ["(unverified)", "brief", "deny", "NODE-REPLAY"],
  ["ravi", "roadmap", "deny", "NODE-STALE-LIST"],
];

function audit(): AuditRecord[] {
  const records: AuditRecord[] = [];
  let minute = 0;
  // Twelve half-hour windows; the sample incident is concentrated after the fifth.
  for (let window = 0; window < 12; window++) {
    const normal = 4 + ((window * 7) % 5);
    const bad = window < 5 ? 0 : window < 8 ? 5 - (window - 5) : window % 2;
    const kinds = [
      ...Array.from(
        { length: normal },
        (_, i) => routine[(i + window) % routine.length],
      ),
      ...Array.from(
        { length: bad },
        (_, i) => incident[(i + window) % incident.length],
      ),
    ];
    kinds.forEach(([actor, asset, decision, rule], i) => {
      minute = window * 30 + Math.floor((i * 30) / kinds.length);
      records.push({
        requestId: `sample-${String(records.length + 1).padStart(4, "0")}`,
        timestamp: at(minute),
        actor,
        action: "read",
        asset,
        decision,
        rule,
      });
    });
  }
  return records;
}

export function sampleSnapshot(): Snapshot {
  return {
    schemaVersion: 1,
    capturedAt: at(360),
    devices: [
      { id: "maya-phone", owner: "maya", keyVersion: 1, state: "revoked" },
      { id: "maya-laptop", owner: "maya", keyVersion: 1, state: "active" },
      { id: "noor-laptop", owner: "noor", keyVersion: 3, state: "active" },
      { id: "ravi-tablet", owner: "ravi", keyVersion: 2, state: "active" },
      { id: "eve-laptop", owner: "eve", keyVersion: 1, state: "no-usable-key" },
    ],
    nodes: [
      {
        id: "node-a",
        state: "current",
        listVersion: 18,
        deviceIds: ["maya-laptop", "noor-laptop", "eve-laptop"],
        lastUpdated: at(359),
      },
      {
        id: "node-b",
        state: "current",
        listVersion: 18,
        deviceIds: ["noor-laptop", "ravi-tablet", "maya-laptop"],
        lastUpdated: at(359),
      },
      {
        id: "node-c",
        state: "stale",
        listVersion: 11,
        deviceIds: ["maya-phone", "ravi-tablet"],
        lastUpdated: at(214),
      },
      {
        id: "node-d",
        state: "offline",
        listVersion: 9,
        deviceIds: ["eve-laptop"],
        lastUpdated: at(172),
      },
    ],
    audit: audit(),
    grants: [
      { actor: "noor", asset: "roadmap", approvalId: "sample-chg-7" },
      { actor: "eve", asset: "ledger" },
    ],
    alerts: [
      {
        id: "sample-alert-1",
        timestamp: at(30),
        rule: "DET-UNAPPROVED-ROLE-CHANGE",
        source: "authority",
        identity: "eve",
        detail: "Invented alert: a grant with no approval on record.",
      },
      {
        id: "sample-alert-2",
        timestamp: at(55),
        rule: "GRD-REPEATED-DENIAL",
        source: "adapter",
        identity: "ravi",
        detail: "Invented alert: one identity denied five times.",
      },
    ],
    verifications: [
      {
        id: "sample-chain",
        kind: "audit-chain",
        outcome: "valid",
        detail: "Invented result for demonstration. No chain was checked.",
      },
      {
        id: "sample-checkpoint",
        kind: "checkpoint",
        outcome: "valid",
        detail: "Invented result for demonstration. No signature was checked.",
      },
      {
        id: "sample-signature",
        kind: "device-signature",
        outcome: "invalid",
        detail: "Invented failure: a request altered after it was signed.",
      },
      {
        id: "sample-proof",
        kind: "protected-read",
        outcome: "not-checked",
        detail: "Invented record of a proof that nobody has verified yet.",
      },
    ],
  };
}
