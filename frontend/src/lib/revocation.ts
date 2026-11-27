/**
 * Illustrative model of the node layer's freshness rules (t4/node/freshness.py and
 * request.py). It runs only in the browser and verifies no signatures.
 */
export const T = 60;
export const SKEW = 2;
export const BOUND = T + SKEW;
export const HEARTBEAT = 20;

export const nodeIds = ["node-a", "node-b", "node-c"] as const;
export type NodeId = (typeof nodeIds)[number];
export type DeviceId = "maya-phone" | "noor-laptop";
/** Fixed courier delays keep the picture repeatable. */
export const courierDelay: Record<NodeId, number> = {
  "node-a": 3,
  "node-b": 8,
  "node-c": 13,
};

export interface SignedList {
  seq: number;
  issuedAt: number;
  revokesPhone: boolean;
}
export interface SimNode {
  id: NodeId;
  connected: boolean;
  list: SignedList;
  /** Since when, after the revocation, this node has been denying the phone. */
  enforcedAt: number | null;
}
export interface Packet {
  node: NodeId;
  list: SignedList;
  arrivesAt: number;
}
export interface SimEvent {
  id: number;
  t: number;
  text: string;
  tone: "plain" | "deny" | "allow";
}
export interface Sim {
  t: number;
  seq: number;
  nextHeartbeat: number;
  revokedAt: number | null;
  nodes: SimNode[];
  packets: Packet[];
  events: SimEvent[];
}

export function createSim(): Sim {
  return {
    t: 0,
    seq: 1,
    nextHeartbeat: HEARTBEAT,
    revokedAt: null,
    nodes: nodeIds.map((id) => ({
      id,
      connected: true,
      list: { seq: 1, issuedAt: 0, revokesPhone: false },
      enforcedAt: null,
    })),
    packets: [],
    events: [
      {
        id: 0,
        t: 0,
        text: "All three nodes hold signed list 1.",
        tone: "plain",
      },
    ],
  };
}

export function decide(node: SimNode, device: DeviceId, t: number) {
  // A list exactly T old is stale, the same boundary the node uses to accept lists.
  if (t - node.list.issuedAt >= T)
    return { allow: false, rule: "NODE-STALE-LIST" };
  if (device === "maya-phone" && node.list.revokesPhone)
    return { allow: false, rule: "NODE-DEVICE-REVOKED" };
  return { allow: true, rule: "NODE-ALLOW-OWNER" };
}

function log(sim: Sim, text: string, tone: SimEvent["tone"] = "plain") {
  const id = sim.events[0].id + 1;
  sim.events = [{ id, t: sim.t, text, tone }, ...sim.events].slice(0, 40);
}

function issue(sim: Sim) {
  sim.seq += 1;
  const list = {
    seq: sim.seq,
    issuedAt: sim.t,
    revokesPhone: sim.revokedAt !== null,
  };
  for (const node of sim.nodes)
    if (node.connected)
      sim.packets.push({
        node: node.id,
        list,
        arrivesAt: sim.t + courierDelay[node.id],
      });
}

function markEnforced(sim: Sim) {
  if (sim.revokedAt === null) return;
  for (const node of sim.nodes) {
    const decision = decide(node, "maya-phone", sim.t);
    if (decision.allow) {
      // A stale node can accept an older list still in transit and open again.
      if (node.enforcedAt !== null) {
        node.enforcedAt = null;
        log(sim, `${node.id} took an older list and allows maya-phone again.`);
      }
    } else if (node.enforcedAt === null) {
      node.enforcedAt = sim.t;
      log(sim, `${node.id} denies maya-phone: ${decision.rule}.`, "deny");
    }
  }
}

const copy = (sim: Sim): Sim => ({
  ...sim,
  nodes: sim.nodes.map((node) => ({ ...node })),
  packets: [...sim.packets],
});

export function revokePhone(previous: Sim): Sim {
  if (previous.revokedAt !== null) return previous;
  const sim = copy(previous);
  sim.revokedAt = sim.t;
  log(sim, "The authority revokes maya-phone and signs a new list.", "deny");
  issue(sim);
  markEnforced(sim);
  return sim;
}

export function setConnected(
  previous: Sim,
  id: NodeId,
  connected: boolean,
): Sim {
  const sim = copy(previous);
  sim.nodes.find((node) => node.id === id)!.connected = connected;
  if (!connected) sim.packets = sim.packets.filter((p) => p.node !== id);
  log(sim, connected ? `${id} is reachable again.` : `${id} is cut off.`);
  return sim;
}

const TICK = 0.25;

export function advance(previous: Sim, seconds: number): Sim {
  const sim = copy(previous);
  for (let left = seconds; left > 1e-9; left -= TICK) {
    const before = sim.nodes.map((n) => sim.t - n.list.issuedAt >= T);
    sim.t += Math.min(TICK, left);
    while (sim.t >= sim.nextHeartbeat) {
      issue(sim);
      sim.nextHeartbeat += HEARTBEAT;
    }
    const arrived = sim.packets.filter((p) => p.arrivesAt <= sim.t);
    sim.packets = sim.packets.filter((p) => p.arrivesAt > sim.t);
    for (const packet of arrived) {
      const node = sim.nodes.find((n) => n.id === packet.node)!;
      if (packet.list.seq > node.list.seq && sim.t - packet.list.issuedAt < T)
        node.list = packet.list;
    }
    sim.nodes.forEach((node, i) => {
      if (!before[i] && sim.t - node.list.issuedAt >= T)
        log(
          sim,
          `${node.id} has no list newer than ${T} s and now denies everyone.`,
          "deny",
        );
    });
    markEnforced(sim);
  }
  return sim;
}
