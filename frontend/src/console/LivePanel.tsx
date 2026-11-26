import { useState } from "react";
import { bridge, BridgeError } from "../lib/api.ts";
import type { Snapshot } from "../snapshot.ts";
import "./live.css";

const ASSETS = ["plan", "budget", "notes"];
const ACTORS = ["maya", "noor", "eve"];

interface Props {
  snapshot: Snapshot;
  /** Re-read the snapshot from the bridge after something changed. */
  refresh: () => Promise<void>;
  reset: () => Promise<void>;
}

/** Controls that drive the real adapter and node layer through the bridge. */
export default function LivePanel({ snapshot, refresh, reset }: Props) {
  const devices = snapshot.devices;
  const nodes = snapshot.nodes;
  const [device, setDevice] = useState("");
  const [node, setNode] = useState("");
  const [asset, setAsset] = useState("plan");
  const [forged, setForged] = useState(false);
  const [actor, setActor] = useState("maya");
  const [seconds, setSeconds] = useState(70);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState("");
  const [failed, setFailed] = useState(false);
  const chosenDevice = device || devices[0]?.id || "";
  const chosenNode = node || nodes[0]?.id || "";

  async function run(label: string, work: () => Promise<string>) {
    setBusy(true);
    setFailed(false);
    try {
      setResult(`${label}: ${await work()}`);
    } catch (error) {
      setFailed(true);
      setResult(
        `${label}: ${error instanceof BridgeError ? error.message : "failed"}`,
      );
    }
    try {
      await refresh();
    } catch {
      /* the connection banner reports a lost bridge */
    }
    setBusy(false);
  }
  const action = (body: Record<string, unknown>) => async () =>
    (await bridge.action(body)).summary;
  const adapter = (body: Record<string, unknown>) => async () =>
    (await bridge.adapter(body)).summary;

  return (
    <section className="panel live" aria-labelledby="live-title">
      <div className="panel-head">
        <h2 id="live-title">Backend controls</h2>
        <span>Runs the real adapter and node layer</span>
      </div>
      <div className="live-grid">
        <fieldset disabled={busy}>
          <legend>Send a signed request to a node</legend>
          <label>
            Device
            <select
              value={chosenDevice}
              onChange={(e) => setDevice(e.target.value)}
            >
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.id} ({d.owner})
                </option>
              ))}
            </select>
          </label>
          <label>
            Node
            <select
              value={chosenNode}
              onChange={(e) => setNode(e.target.value)}
            >
              {nodes.map((n) => (
                <option key={n.id}>{n.id}</option>
              ))}
            </select>
          </label>
          <label>
            File
            <select value={asset} onChange={(e) => setAsset(e.target.value)}>
              {ASSETS.map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={forged}
              onChange={(e) => setForged(e.target.checked)}
            />
            Change the request after signing
          </label>
          <button
            className="button button-small"
            onClick={() =>
              void run(
                "Request",
                action({
                  name: "request",
                  device_id: chosenDevice,
                  node_id: chosenNode,
                  asset,
                  tamper: forged,
                }),
              )
            }
          >
            Send request
          </button>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Lost device and revocation list</legend>
          <label>
            Device
            <select
              value={chosenDevice}
              onChange={(e) => setDevice(e.target.value)}
            >
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.id} ({d.state})
                </option>
              ))}
            </select>
          </label>
          <div className="live-row">
            <button
              className="button button-small"
              onClick={() =>
                void run(
                  "Revoke",
                  action({ name: "revoke_device", device_id: chosenDevice }),
                )
              }
            >
              Revoke device
            </button>
            <button
              className="button button-small"
              onClick={() =>
                void run(
                  "Rotate key",
                  action({ name: "rotate", device_id: chosenDevice }),
                )
              }
            >
              Rotate key
            </button>
          </div>
          <div className="live-row">
            <button
              className="button button-small"
              onClick={() => void run("Deliver", action({ name: "deliver" }))}
            >
              Deliver new list
            </button>
            {nodes.map((n) => (
              <button
                key={n.id}
                className="button button-small button-light"
                aria-pressed={n.state === "offline"}
                onClick={() =>
                  void run(
                    n.id,
                    action({
                      name: "set_offline",
                      node_id: n.id,
                      offline: n.state !== "offline",
                    }),
                  )
                }
              >
                {n.state === "offline"
                  ? `Bring ${n.id} online`
                  : `${n.id} offline`}
              </button>
            ))}
          </div>
          <div className="live-row">
            <label>
              Move the clock forward
              <select
                value={seconds}
                onChange={(e) => setSeconds(Number(e.target.value))}
              >
                <option value={30}>30 seconds</option>
                <option value={70}>70 seconds (past the 60 s bound)</option>
                <option value={300}>5 minutes</option>
              </select>
            </label>
            <button
              className="button button-small"
              onClick={() =>
                void run("Clock", action({ name: "advance", seconds }))
              }
            >
              Advance
            </button>
          </div>
          {snapshot.clock && (
            <p className="live-note">Simulated clock: {snapshot.clock}</p>
          )}
        </fieldset>

        <fieldset disabled={busy}>
          <legend>The judged adapter (one process per call)</legend>
          <label>
            Actor
            <select value={actor} onChange={(e) => setActor(e.target.value)}>
              {ACTORS.map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </label>
          <label>
            File
            <select value={asset} onChange={(e) => setAsset(e.target.value)}>
              {ASSETS.map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </label>
          <div className="live-row">
            <button
              className="button button-small"
              onClick={() =>
                void run(
                  "Adapter read",
                  adapter({
                    op: "read",
                    actor,
                    asset,
                    request_id: `ui-${Date.now().toString(36)}`,
                  }),
                )
              }
            >
              Read
            </button>
            <button
              className="button button-small"
              onClick={() =>
                void run(
                  "Protected read",
                  action({ name: "protected_check", actor, asset }),
                )
              }
            >
              Protected read and check proof
            </button>
            <button
              className="button button-small"
              onClick={() =>
                void run("Revoke actor", adapter({ op: "revoke", actor }))
              }
            >
              Revoke actor
            </button>
          </div>
          <p className="live-note">
            The adapter does not authenticate the actor you pick. It decides
            from the name it is given.
          </p>
        </fieldset>
      </div>
      <div className="live-foot">
        <p role="status" className={failed ? "live-result bad" : "live-result"}>
          {busy ? "Working…" : result || "No action taken yet."}
        </p>
        <button
          className="button button-small button-light"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            void reset()
              .then(() => setResult("Started a new synthetic world."))
              .catch(() => {
                setFailed(true);
                setResult("Could not start over.");
              })
              .finally(() => setBusy(false));
          }}
        >
          Start over
        </button>
      </div>
    </section>
  );
}
