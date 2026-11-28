import { useState } from "react";
import { bridge, BridgeError, type ActionResult } from "../lib/api.ts";
import type { Snapshot } from "../snapshot.ts";
import "./live.css";

const ASSETS = ["plan", "budget", "notes"];
const ACTORS = ["maya", "noor", "eve"];
const LOGS = ["adapter", "authority", "node-a", "node-b", "node-c"];

type Row = Record<string, string | number>;

interface Props {
  snapshot: Snapshot;
  /** Re-read the snapshot from the bridge after something changed. */
  refresh: () => Promise<void>;
  reset: () => Promise<void>;
}

/** Keep only flat rows of text and numbers; anything else from the bridge is ignored. */
function rowsOf(raw: Record<string, unknown>): Row[] {
  if (!Array.isArray(raw.rows)) return [];
  return raw.rows
    .filter(
      (row): row is Record<string, unknown> => !!row && typeof row === "object",
    )
    .map(
      (row) =>
        Object.fromEntries(
          Object.entries(row).filter(
            ([, v]) => typeof v === "string" || typeof v === "number",
          ),
        ) as Row,
    );
}

function Results({ rows }: { rows: Row[] }) {
  if (rows.length === 0) return null;
  const columns = [...new Set(rows.flatMap((row) => Object.keys(row)))];
  return (
    <div className="table-wrap live-table">
      <table>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c} scope="col">
                {c.replaceAll("_", " ")}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c}>{row[c] ?? ""}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Pick({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { value: string; label?: string }[];
  onChange: (value: string) => void;
}) {
  return (
    <label>
      {label}
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label ?? o.value}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Controls that drive the real adapter, node layer and operator tools through the bridge. */
export default function LivePanel({ snapshot, refresh, reset }: Props) {
  const devices = snapshot.devices;
  const nodes = snapshot.nodes;
  const [device, setDevice] = useState("");
  const [node, setNode] = useState("");
  const [asset, setAsset] = useState("plan");
  const [forged, setForged] = useState(false);
  const [actor, setActor] = useState("maya");
  const [seconds, setSeconds] = useState(70);
  const [requestId, setRequestId] = useState("");
  const [disable, setDisable] = useState(false);
  const [newDevice, setNewDevice] = useState("maya-laptop");
  const [log, setLog] = useState("node-a");
  const [recipient, setRecipient] = useState("maya");
  const [message, setMessage] = useState("meet at noon");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState("");
  const [rows, setRows] = useState<Row[]>([]);
  const [failed, setFailed] = useState(false);
  const chosenDevice = device || devices[0]?.id || "";
  const to =
    recipient !== actor ? recipient : (ACTORS.find((a) => a !== actor) ?? "");
  const chosenNode = node || nodes[0]?.id || "";
  const deviceOptions = devices.map((d) => ({
    value: d.id,
    label: `${d.id} (${d.owner}, ${d.state})`,
  }));
  const plain = (values: string[]) => values.map((value) => ({ value }));

  async function run(label: string, work: () => Promise<ActionResult>) {
    setBusy(true);
    setFailed(false);
    try {
      const reply = await work();
      setResult(`${label}: ${reply.summary}`);
      setRows(rowsOf(reply.raw));
    } catch (error) {
      setFailed(true);
      setRows([]);
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
  const action = (label: string, body: Record<string, unknown>) =>
    void run(label, () => bridge.action(body));
  const adapter = (label: string, body: Record<string, unknown>) =>
    void run(label, () => bridge.adapter(body));
  const button = (label: string, onClick: () => void) => (
    <button className="button button-small" onClick={onClick}>
      {label}
    </button>
  );

  return (
    <section className="panel live" aria-labelledby="live-title">
      <div className="panel-head">
        <h2 id="live-title">Backend controls</h2>
        <span>Runs the real adapter, node layer and operator tools</span>
      </div>
      <div className="live-grid">
        <fieldset disabled={busy}>
          <legend>The judged adapter (one process per call)</legend>
          <Pick
            label="Actor"
            value={actor}
            options={plain(ACTORS)}
            onChange={setActor}
          />
          <Pick
            label="File"
            value={asset}
            options={plain(ASSETS)}
            onChange={setAsset}
          />
          <div className="live-row">
            {button("Read", () => {
              const id = `ui-${Date.now().toString(36)}`;
              setRequestId(id);
              adapter("Adapter read", {
                op: "read",
                actor,
                asset,
                request_id: id,
              });
            })}
            {button("Protected read and check proof", () =>
              action("Protected read", {
                name: "protected_check",
                actor,
                asset,
              }),
            )}
            {button("Revoke actor", () =>
              adapter("Adapter revoke", { op: "revoke", actor }),
            )}
          </div>
          <label>
            Request ID
            <input
              value={requestId}
              onChange={(e) => setRequestId(e.target.value)}
              placeholder="Read something first"
              maxLength={200}
            />
          </label>
          <div className="live-row">
            <button
              className="button button-small"
              disabled={!requestId}
              onClick={() =>
                adapter("Audit", { op: "audit", request_id: requestId })
              }
            >
              Audit: why was it decided?
            </button>
            <button
              className="button button-small"
              disabled={!requestId}
              onClick={() =>
                action("Explain", { name: "explain", request_id: requestId })
              }
            >
              Explain from every log
            </button>
          </div>
          <label className="check">
            <input
              type="checkbox"
              checked={disable}
              onChange={(e) => setDisable(e.target.checked)}
            />
            Disable {actor} in the new setup
          </label>
          {button("Run setup again", () =>
            action("Setup", {
              name: "setup",
              disabled: disable ? [actor] : [],
            }),
          )}
          <p className="live-note">
            The adapter does not authenticate the actor you pick. It decides
            from the name it is given.
          </p>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Send a signed request to a node</legend>
          <Pick
            label="Device"
            value={chosenDevice}
            options={deviceOptions}
            onChange={setDevice}
          />
          <Pick
            label="Node"
            value={chosenNode}
            options={plain(nodes.map((n) => n.id))}
            onChange={setNode}
          />
          <Pick
            label="File"
            value={asset}
            options={plain(ASSETS)}
            onChange={setAsset}
          />
          <label className="check">
            <input
              type="checkbox"
              checked={forged}
              onChange={(e) => setForged(e.target.checked)}
            />
            Change the request after signing
          </label>
          {button("Send request", () =>
            action("Request", {
              name: "request",
              device_id: chosenDevice,
              node_id: chosenNode,
              asset,
              tamper: forged,
            }),
          )}
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Authority: devices and revocation lists</legend>
          <Pick
            label="Device"
            value={chosenDevice}
            options={deviceOptions}
            onChange={setDevice}
          />
          <div className="live-row">
            {button("Revoke device", () =>
              action("Revoke device", {
                name: "revoke_device",
                device_id: chosenDevice,
              }),
            )}
            {button("Revoke current key version", () =>
              action("Revoke key", {
                name: "revoke_key",
                device_id: chosenDevice,
              }),
            )}
            {button("Rotate key", () =>
              action("Rotate key", { name: "rotate", device_id: chosenDevice }),
            )}
          </div>
          <div className="live-row">
            <label>
              New device ID
              <input
                value={newDevice}
                onChange={(e) => setNewDevice(e.target.value)}
                maxLength={32}
              />
            </label>
            {button(`Enrol for ${actor}`, () =>
              action("Enrol", {
                name: "enroll",
                device_id: newDevice,
                owner: actor,
              }),
            )}
          </div>
          <div className="live-row">
            {button("Deliver new list", () =>
              action("Deliver", { name: "deliver" }),
            )}
            {nodes.map((n) => (
              <button
                key={n.id}
                className="button button-small button-light"
                aria-pressed={n.state === "offline"}
                onClick={() =>
                  action(n.id, {
                    name: "set_offline",
                    node_id: n.id,
                    offline: n.state !== "offline",
                  })
                }
              >
                {n.state === "offline"
                  ? `Bring ${n.id} online`
                  : `${n.id} offline`}
              </button>
            ))}
          </div>
          <div className="live-row">
            <Pick
              label="Move the clock forward"
              value={String(seconds)}
              options={[
                { value: "30", label: "30 seconds" },
                { value: "70", label: "70 seconds (past the 60 s bound)" },
                { value: "300", label: "5 minutes" },
              ]}
              onChange={(v) => setSeconds(Number(v))}
            />
            {button("Advance", () =>
              action("Clock", { name: "advance", seconds }),
            )}
          </div>
          {snapshot.clock && (
            <p className="live-note">Simulated clock: {snapshot.clock}</p>
          )}
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Authority: who may read what</legend>
          <Pick
            label="Actor"
            value={actor}
            options={plain(ACTORS)}
            onChange={setActor}
          />
          <Pick
            label="File"
            value={asset}
            options={plain(ASSETS)}
            onChange={setAsset}
          />
          <div className="live-row">
            {button("Grant with approval", () =>
              action("Grant", { name: "grant", actor, asset, approved: true }),
            )}
            {button("Grant without approval", () =>
              action("Grant", { name: "grant", actor, asset, approved: false }),
            )}
            {button("Remove grant", () =>
              action("Remove grant", { name: "ungrant", actor, asset }),
            )}
          </div>
          {button(`Revoke ${actor} on every device`, () =>
            action("Revoke actor", { name: "revoke_actor", actor }),
          )}
          <div className="live-row">
            {button("Back up authority", () =>
              action("Backup", { name: "backup" }),
            )}
            {button("Restore authority", () =>
              action("Restore", { name: "restore" }),
            )}
          </div>
          <p className="live-note">
            Grants and revocations reach nodes with the next delivered list. A
            restore re-applies revocations made after the backup.
          </p>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Operator: evidence and checks</legend>
          <div className="live-row">
            {button("Pin every log", () => action("Pin", { name: "pin" }))}
            {button("Verify logs", () => action("Verify", { name: "verify" }))}
          </div>
          <div className="live-row">
            {button("Run the detector", () =>
              action("Detector", { name: "detect" }),
            )}
            {button("Show alerts", () => action("Alerts", { name: "alerts" }))}
            {button("Health check", () => action("Health", { name: "health" }))}
          </div>
          <div className="live-row">
            <Pick
              label="Log"
              value={log}
              options={plain(LOGS)}
              onChange={setLog}
            />
            <button
              className="button button-small button-deny"
              onClick={() => action("Tamper", { name: "tamper", log })}
            >
              Edit one entry on disk
            </button>
          </div>
          <p className="live-note">
            Editing a log imitates an attacker with disk access. It changes only
            this synthetic workspace; Start over makes a fresh one.
          </p>
        </fieldset>
        <fieldset disabled={busy}>
          <legend>Messages (optional demo layer)</legend>
          <Pick
            label="From"
            value={actor}
            options={plain(ACTORS)}
            onChange={setActor}
          />
          <Pick
            label="To"
            value={to}
            options={plain(ACTORS.filter((a) => a !== actor))}
            onChange={setRecipient}
          />
          <label>
            Message (synthetic text only)
            <input
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              maxLength={200}
            />
          </label>
          {button("Send, then replay it", () =>
            action("Message", {
              name: "message",
              sender: actor,
              recipient: to,
              text: message,
            }),
          )}
          <p className="live-note">
            ML-KEM-768 and ChaCha20-Poly1305 encrypt it, ML-DSA-65 signs it. Not
            forward secret. The judged adapter does not use this.
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
            setRows([]);
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
      <Results rows={rows} />
    </section>
  );
}
