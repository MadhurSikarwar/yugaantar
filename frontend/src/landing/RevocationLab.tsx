import { useEffect, useRef, useState, type CSSProperties } from "react";
import { useOnScreen, useReducedMotion } from "../hooks.ts";
import {
  BOUND,
  HEARTBEAT,
  T,
  advance,
  courierDelay,
  createSim,
  decide,
  revokePhone,
  setConnected,
  type DeviceId,
} from "../lib/revocation.ts";

const FRAME = 100;
const devices: DeviceId[] = ["maya-phone", "noor-laptop"];

export default function RevocationLab() {
  const reduced = useReducedMotion();
  const section = useRef<HTMLElement>(null);
  const onScreen = useOnScreen(section);
  const [sim, setSim] = useState(createSim);
  const [running, setRunning] = useState(!reduced);
  const [speed, setSpeed] = useState(4);
  useEffect(() => {
    if (!running || !onScreen) return;
    const timer = setInterval(
      () => setSim((current) => advance(current, (FRAME / 1000) * speed)),
      FRAME,
    );
    return () => clearInterval(timer);
  }, [running, onScreen, speed]);

  const revokedAt = sim.revokedAt;
  const elapsed = revokedAt === null ? 0 : sim.t - revokedAt;
  const enforced = sim.nodes.filter((n) => n.enforcedAt !== null);
  const done = revokedAt !== null && enforced.length === sim.nodes.length;
  const slowest = done
    ? Math.max(...enforced.map((n) => n.enforcedAt! - revokedAt))
    : 0;
  const verdict = done
    ? `Every node denies the lost phone ${Math.ceil(slowest)} s after revocation. The bound is ${BOUND} s.`
    : revokedAt === null
      ? "The phone is still trusted. Try cutting off node-c, then report the phone lost."
      : `${enforced.length} of ${sim.nodes.length} nodes enforce the revocation.`;

  return (
    <section
      className="lab revocation"
      id="revocation"
      ref={section}
      aria-labelledby="revocation-title"
    >
      <header className="lab-intro">
        <h2 id="revocation-title">How a revocation reaches every node</h2>
        <p>
          The authority signs a numbered revocation list every {HEARTBEAT}{" "}
          seconds and a courier carries it to each node. A node whose newest
          list is older than {T} seconds denies everyone, so a cut-off node
          cannot stay open.
        </p>
      </header>
      <div className="sim-controls">
        <button
          className="button button-deny"
          onClick={() => {
            setSim(revokePhone);
            setRunning(true);
          }}
          disabled={revokedAt !== null}
        >
          {revokedAt === null ? "Report phone lost" : "Phone reported lost"}
        </button>
        <button className="button" onClick={() => setRunning((r) => !r)}>
          {running ? "Pause" : "Play"}
        </button>
        <button className="button" onClick={() => setSim(createSim())}>
          Start over
        </button>
        <label>
          Speed
          <select
            value={speed}
            onChange={(e) => setSpeed(Number(e.target.value))}
          >
            {[1, 4, 10].map((v) => (
              <option key={v} value={v}>
                {v}×
              </option>
            ))}
          </select>
        </label>
        <output className="sim-clock">{Math.floor(sim.t)} s</output>
      </div>

      <div className="authority">
        <strong>Authority</strong>
        <span>Signed list {sim.seq}</span>
        <span className={revokedAt === null ? "tone-allow" : "tone-deny"}>
          maya-phone {revokedAt === null ? "enrolled" : "revoked"}
        </span>
        <span>Next list in {Math.ceil(sim.nextHeartbeat - sim.t)} s</span>
      </div>

      <div className="node-grid">
        {sim.nodes.map((node) => {
          const age = sim.t - node.list.issuedAt;
          const stale = age > T;
          return (
            <div className="node-column" key={node.id}>
              <div
                className={`lane${node.connected ? "" : " lane-cut"}`}
                aria-hidden="true"
              >
                {sim.packets
                  .filter((p) => p.node === node.id)
                  .map((p) => (
                    <span
                      key={p.list.seq}
                      className={`packet${p.list.revokesPhone ? " packet-revoke" : ""}`}
                      style={{
                        top: `${Math.min(1, 1 - (p.arrivesAt - sim.t) / courierDelay[node.id]) * 100}%`,
                      }}
                    >
                      {p.list.seq}
                    </span>
                  ))}
              </div>
              <article className={`node-card${stale ? " node-stale" : ""}`}>
                <div className="node-head">
                  <span
                    className={`pilot ${stale ? "pilot-red" : age > T * 0.66 ? "pilot-amber" : "pilot-green"}`}
                    aria-hidden="true"
                  />
                  <h3>{node.id}</h3>
                  <button
                    className="toggle"
                    aria-pressed={!node.connected}
                    onClick={() =>
                      setSim((s) => setConnected(s, node.id, !node.connected))
                    }
                  >
                    {node.connected ? "Cut off" : "Reconnect"}
                    <span className="sr-only"> {node.id}</span>
                  </button>
                </div>
                <p className="list-age">
                  <span>List {node.list.seq}</span>
                  <span>
                    {stale ? "Stale" : `${Math.floor(age)} of ${T} s old`}
                  </span>
                </p>
                <div className="meter" aria-hidden="true">
                  <span
                    className={stale ? "full" : age > T * 0.66 ? "aging" : ""}
                    style={{ width: `${Math.min(100, (age / T) * 100)}%` }}
                  />
                </div>
                <dl className="verdicts">
                  {devices.map((device) => {
                    const decision = decide(node, device, sim.t);
                    return (
                      <div
                        key={device}
                        className={decision.allow ? "is-allow" : "is-deny"}
                      >
                        <dt>{device}</dt>
                        <dd>
                          <strong>{decision.allow ? "Allow" : "Deny"}</strong>
                          <code>{decision.rule}</code>
                        </dd>
                      </div>
                    );
                  })}
                </dl>
              </article>
            </div>
          );
        })}
      </div>

      <div className="bound">
        <div className="bound-head">
          <p role="status">{verdict}</p>
          <span>
            r + T + s = {BOUND} s
            {revokedAt !== null &&
              `, ${Math.min(BOUND, Math.floor(elapsed))} s elapsed`}
          </span>
        </div>
        <div className="bound-track" aria-hidden="true">
          <span
            className="bound-fill"
            style={{ width: `${Math.min(100, (elapsed / BOUND) * 100)}%` }}
          />
          {revokedAt !== null &&
            enforced.map((n, i) => (
              <span
                key={n.id}
                className="bound-mark"
                style={
                  {
                    left: `${Math.min(100, ((n.enforcedAt! - revokedAt) / BOUND) * 100)}%`,
                    top: `${10 + i * 18}px`,
                    "--drop": `${i * 18}px`,
                  } as CSSProperties
                }
              >
                {n.id}
              </span>
            ))}
        </div>
      </div>

      <ol className="sim-log" aria-label="Simulation events, newest first">
        {sim.events.slice(0, 6).map((event) => (
          <li key={event.id} className={`tone-${event.tone}`}>
            <span>{Math.floor(event.t)} s</span>
            {event.text}
          </li>
        ))}
      </ol>
      <p className="lab-note">
        A model running in your browser. It follows the node rules but signs
        nothing and does not talk to the backend. The project's own simulator
        (simulated clocks, 20 runs) measured the last node enforcing between 20
        and 58 s.
      </p>
    </section>
  );
}
