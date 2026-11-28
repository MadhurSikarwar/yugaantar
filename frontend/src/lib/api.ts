/**
 * Client for the local backend bridge (tools/bridge.py).
 *
 * The browser never touches keys or runs cryptography. It sends JSON to the bridge, which runs
 * the real adapter and node layer, and it parses what comes back with the same strict snapshot
 * parser used for imported files. Errors are fixed labels from the bridge, never raw text.
 */
import { parseSnapshot, type Snapshot } from "../snapshot.ts";

export const API_BASE = "/api";
const TIMEOUT_MS = 30_000;

export class BridgeError extends Error {}

export type Fetcher = typeof fetch;

async function call(
  fetcher: Fetcher,
  path: string,
  body?: unknown,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetcher(`${API_BASE}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      signal: controller.signal,
    });
    const text = await response.text();
    if (!response.ok) {
      let label = `The bridge answered ${response.status}.`;
      try {
        const parsed = JSON.parse(text) as { error?: unknown };
        if (typeof parsed.error === "string")
          label = parsed.error.replaceAll("_", " ");
      } catch {
        /* keep the generic label */
      }
      throw new BridgeError(label);
    }
    return text;
  } catch (error) {
    if (error instanceof BridgeError) throw error;
    throw new BridgeError(
      "The backend bridge is not reachable. Start it with: python tools/bridge.py",
    );
  } finally {
    clearTimeout(timer);
  }
}

function asObject(text: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new BridgeError("The bridge sent something that is not JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new BridgeError("The bridge sent an unexpected reply.");
  return value as Record<string, unknown>;
}

export interface ActionResult {
  /** A short, readable line describing the outcome. */
  summary: string;
  raw: Record<string, unknown>;
}

const text = (value: unknown) =>
  typeof value === "string" || typeof value === "number" ? String(value) : "";

/** Turn a bridge reply into one line. Only known fields are shown. */
export function summarize(raw: Record<string, unknown>): string {
  if (typeof raw.summary === "string") return raw.summary;
  if (typeof raw.decision === "string")
    return [
      raw.decision.toUpperCase(),
      text(raw.rule),
      raw.node_id ? `on ${text(raw.node_id)}` : "",
    ]
      .filter(Boolean)
      .join(" · ");
  if (typeof raw.outcome === "string")
    return `Protected-read proof: ${raw.outcome}`;
  if (raw.accepted && typeof raw.accepted === "object")
    return Object.entries(raw.accepted as Record<string, unknown>)
      .map(
        ([node, ok]) =>
          `${node} ${ok ? "accepted the list" : "did not get it"}`,
      )
      .join(" · ");
  if (raw.revoked === true) return "Device revoked";
  if (raw.ready === true) return "Adapter set up";
  if (typeof raw.clock === "string") return `Clock now ${raw.clock}`;
  if (typeof raw.activates_at === "string")
    return `New key activates ${raw.activates_at}`;
  if (typeof raw.enrolled === "string") return `${raw.enrolled} enrolled`;
  if (typeof raw.node_id === "string" && typeof raw.offline === "boolean")
    return `${raw.node_id} is ${raw.offline ? "offline" : "online"}`;
  if (typeof raw.error === "string") return raw.error.replaceAll("_", " ");
  return "Done";
}

export function createBridge(fetcher: Fetcher = fetch) {
  return {
    async health(): Promise<{ ok: boolean; started: boolean }> {
      const raw = asObject(await call(fetcher, "/health"));
      return { ok: raw.ok === true, started: raw.started === true };
    },
    async start(): Promise<void> {
      await call(fetcher, "/start", {});
    },
    async snapshot(): Promise<Snapshot> {
      try {
        return parseSnapshot(await call(fetcher, "/snapshot"));
      } catch (error) {
        if (error instanceof BridgeError) throw error;
        throw new BridgeError(
          `The bridge sent a snapshot the console rejected: ${(error as Error).message}`,
        );
      }
    },
    async adapter(request: Record<string, unknown>): Promise<ActionResult> {
      const raw = asObject(await call(fetcher, "/adapter", request));
      return { summary: summarize(raw), raw };
    },
    async action(request: Record<string, unknown>): Promise<ActionResult> {
      const raw = asObject(await call(fetcher, "/action", request));
      return { summary: summarize(raw), raw };
    },
  };
}

export const bridge = createBridge();
