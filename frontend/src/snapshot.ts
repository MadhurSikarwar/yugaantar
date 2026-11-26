/** Read-only frontend contract; import never authenticates data or invokes the adapter. */
export interface Device {
  id: string;
  owner: string;
  keyVersion: number;
  state: "active" | "revoked";
}
export interface NodeRecord {
  id: string;
  state: "current" | "stale" | "offline";
  listVersion: number;
  deviceIds: string[];
  lastUpdated: string;
}
export interface AuditRecord {
  requestId: string;
  timestamp: string;
  actor: string;
  action: string;
  asset: string;
  decision: "allow" | "deny";
  rule: string;
}
export interface Verification {
  id: string;
  kind: "audit-chain" | "checkpoint" | "device-signature" | "protected-read";
  outcome: "valid" | "invalid" | "not-checked";
  detail: string;
}
export interface Snapshot {
  schemaVersion: 1;
  capturedAt: string;
  devices: Device[];
  nodes: NodeRecord[];
  audit: AuditRecord[];
  verifications: Verification[];
}
type Obj = Record<string, unknown>;
function object(v: unknown): Obj {
  if (!v || typeof v !== "object" || Array.isArray(v))
    throw new Error("Expected a JSON object.");
  return v as Obj;
}
function str(v: unknown, key: string): string {
  if (typeof v !== "string" || !v.trim() || v.length > 2000)
    throw new Error(
      `${key} must be a nonempty string of at most 2,000 characters.`,
    );
  return v;
}
function num(v: unknown, key: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0)
    throw new Error(`${key} must be a nonnegative integer.`);
  return v;
}
function date(v: unknown, key: string): string {
  const s = str(v, key);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(
      s,
    ) ||
    !Number.isFinite(Date.parse(s))
  )
    throw new Error(`${key} must be an ISO timestamp with a timezone.`);
  return s;
}
function choice<T extends string>(v: unknown, options: T[], key: string): T {
  if (!options.includes(v as T))
    throw new Error(`Invalid ${key}. Expected ${options.join(", ")}.`);
  return v as T;
}
function array(v: unknown, key: string): unknown[] {
  if (!Array.isArray(v) || v.length > 5000)
    throw new Error(`${key} must contain at most 5,000 entries.`);
  return v;
}
function rows<T>(v: unknown, key: string, parse: (v: Obj) => T): T[] {
  return array(v, key).map((item, i) => {
    try {
      return parse(object(item));
    } catch (e) {
      throw new Error(`${key}[${i}]: ${(e as Error).message}`);
    }
  });
}
function unique<T>(items: T[], getKey: (v: T) => string, key: string): T[] {
  if (new Set(items.map(getKey)).size !== items.length)
    throw new Error(`${key} contains duplicate identifiers.`);
  return items;
}
export function parseSnapshot(text: string): Snapshot {
  if (text.length > 5 * 1024 * 1024)
    throw new Error("Choose a snapshot smaller than 5 MB.");
  let input: Obj;
  try {
    input = object(JSON.parse(text));
  } catch {
    throw new Error("The file is not a valid JSON snapshot.");
  }
  if (input.schemaVersion !== 1)
    throw new Error("Unsupported snapshot schema. Expected schemaVersion: 1.");
  return {
    schemaVersion: 1,
    capturedAt: date(input.capturedAt, "capturedAt"),
    devices: unique(
      rows(input.devices, "devices", (d) => ({
        id: str(d.id, "id"),
        owner: str(d.owner, "owner"),
        keyVersion: num(d.keyVersion, "keyVersion"),
        state: choice(d.state, ["active", "revoked"], "state"),
      })),
      (d) => d.id,
      "devices",
    ),
    nodes: unique(
      rows(input.nodes, "nodes", (n) => ({
        id: str(n.id, "id"),
        state: choice(n.state, ["current", "stale", "offline"], "state"),
        listVersion: num(n.listVersion, "listVersion"),
        deviceIds: array(n.deviceIds, "deviceIds").map((id) =>
          str(id, "deviceId"),
        ),
        lastUpdated: date(n.lastUpdated, "lastUpdated"),
      })),
      (n) => n.id,
      "nodes",
    ),
    audit: rows(input.audit, "audit", (a) => ({
      requestId: str(a.requestId, "requestId"),
      timestamp: date(a.timestamp, "timestamp"),
      actor: str(a.actor, "actor"),
      action: str(a.action, "action"),
      asset: str(a.asset, "asset"),
      decision: choice(a.decision, ["allow", "deny"], "decision"),
      rule: str(a.rule, "rule"),
    })),
    verifications: unique(
      rows(input.verifications, "verifications", (v) => ({
        id: str(v.id, "id"),
        kind: choice(
          v.kind,
          ["audit-chain", "checkpoint", "device-signature", "protected-read"],
          "kind",
        ),
        outcome: choice(
          v.outcome,
          ["valid", "invalid", "not-checked"],
          "outcome",
        ),
        detail: str(v.detail, "detail"),
      })),
      (v) => v.id,
      "verifications",
    ),
  };
}
export const formatDate = (v: string) =>
  new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(v));
export function downloadJSON(value: unknown, filename: string) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
