/**
 * An annunciator: the panel of backlit alarm tiles found in plant control rooms.
 *
 * Each button stages one thing that goes wrong. The rule IDs printed are the ones the
 * Python service writes to its logs for that event; the panel itself is a browser model
 * and calls no backend. Tiles follow the usual alarm sequence: a new alarm flashes,
 * Acknowledge makes it steady, Reset clears acknowledged alarms.
 */
import { useEffect, useRef, useState } from "react";

type Tile = { id: string; label: string; severity: "red" | "amber" };
type Step = {
  after: number;
  rule: string;
  text: string;
  decision: "allow" | "deny" | "event";
  tile?: string;
};
type Scenario = { id: string; label: string; steps: Step[] };
type Line = Step & { key: number; at: number };
type Lamp = "off" | "flash" | "steady";

const tiles: Tile[] = [
  { id: "revoked", label: "Device revoked", severity: "red" },
  { id: "stale", label: "List stale", severity: "amber" },
  { id: "replay", label: "Replay refused", severity: "amber" },
  { id: "signature", label: "Bad signature", severity: "red" },
  { id: "chain", label: "Log chain broken", severity: "red" },
  { id: "owner", label: "Not owner", severity: "amber" },
  { id: "probe", label: "Repeated denial", severity: "amber" },
  { id: "rollback", label: "State rollback", severity: "red" },
];

const scenarios: Scenario[] = [
  {
    id: "lose",
    label: "Lose Maya’s phone",
    steps: [
      {
        after: 0,
        rule: "KEY-REVOKE-DEVICE",
        text: "authority revokes maya-phone",
        decision: "event",
      },
      {
        after: 900,
        rule: "NODE-DEVICE-REVOKED",
        text: "maya-phone reads plan on node-a",
        decision: "deny",
        tile: "revoked",
      },
      {
        after: 1700,
        rule: "NODE-ALLOW-OWNER",
        text: "noor-tablet reads budget on node-a",
        decision: "allow",
      },
    ],
  },
  {
    id: "cut",
    label: "Cut off node-c",
    steps: [
      {
        after: 0,
        rule: "NODE-LIST-ACCEPTED",
        text: "node-c gets its last list before the cut",
        decision: "event",
      },
      {
        after: 1200,
        rule: "NODE-STALE-LIST",
        text: "node-c list is 60 s old, every request denied",
        decision: "deny",
        tile: "stale",
      },
    ],
  },
  {
    id: "replay",
    label: "Replay a signed request",
    steps: [
      {
        after: 0,
        rule: "NODE-ALLOW-OWNER",
        text: "noor-tablet reads budget on node-b",
        decision: "allow",
      },
      {
        after: 900,
        rule: "NODE-REPLAY",
        text: "the same signed request, sent again",
        decision: "deny",
        tile: "replay",
      },
    ],
  },
  {
    id: "forge",
    label: "Forge a device request",
    steps: [
      {
        after: 0,
        rule: "NODE-BAD-SIGNATURE",
        text: "request claims noor-tablet, signature does not verify",
        decision: "deny",
        tile: "signature",
      },
    ],
  },
  {
    id: "edit",
    label: "Edit the audit log",
    steps: [
      {
        after: 0,
        rule: "(on disk)",
        text: "entry 3 changed from deny to allow",
        decision: "event",
      },
      {
        after: 1000,
        rule: "AUD-LOG-INTEGRITY-FAILURE",
        text: "chain broken at entry 3, request refused",
        decision: "deny",
        tile: "chain",
      },
    ],
  },
  {
    id: "probe",
    label: "Probe as eve",
    steps: [
      ...[0, 1, 2, 3, 4].map((n) => ({
        after: n * 350,
        rule: "POL-NOT-OWNER",
        text: `eve reads ${["plan", "budget", "plan", "notes", "budget"][n]}`,
        decision: "deny" as const,
        tile: "owner",
      })),
      {
        after: 1750,
        rule: "GRD-REPEATED-DENIAL",
        text: "eve denied 5 times, alert raised, nothing blocked",
        decision: "event",
        tile: "probe",
      },
    ],
  },
  {
    id: "rollback",
    label: "Restore an old state file",
    steps: [
      {
        after: 0,
        rule: "(on disk)",
        text: "state.json replaced by an older copy",
        decision: "event",
      },
      {
        after: 1000,
        rule: "STO-INTEGRITY-FAILURE",
        text: "state is older than the audit log, read refused",
        decision: "deny",
        tile: "rollback",
      },
    ],
  },
];

const START = Date.UTC(2026, 10, 28, 9, 41, 0);
const clock = (ms: number) => new Date(START + ms).toISOString().slice(11, 19);

export default function Annunciator() {
  const [lamps, setLamps] = useState<Record<string, Lamp>>({});
  const [lines, setLines] = useState<Line[]>([]);
  const [testing, setTesting] = useState(false);
  const opened = useRef(performance.now());
  const timers = useRef<number[]>([]);
  const counter = useRef(0);
  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const run = (scenario: Scenario) => {
    for (const step of scenario.steps) {
      timers.current.push(
        window.setTimeout(() => {
          const line = {
            ...step,
            key: counter.current++,
            at: performance.now() - opened.current,
          };
          setLines((current) => [line, ...current].slice(0, 8));
          if (step.tile)
            setLamps((current) => ({
              ...current,
              [step.tile!]:
                current[step.tile!] === "steady" ? "steady" : "flash",
            }));
        }, step.after),
      );
    }
  };
  const acknowledge = () =>
    setLamps((current) =>
      Object.fromEntries(
        Object.entries(current).map(([id, lamp]) => [
          id,
          lamp === "off" ? "off" : "steady",
        ]),
      ),
    );
  const reset = () =>
    setLamps((current) =>
      Object.fromEntries(
        Object.entries(current).map(([id, lamp]) => [
          id,
          lamp === "steady" ? "off" : lamp,
        ]),
      ),
    );
  const lampTest = () => {
    setTesting(true);
    timers.current.push(window.setTimeout(() => setTesting(false), 1600));
  };

  const active = tiles.filter((t) => (lamps[t.id] ?? "off") !== "off");
  const unacked = active.filter((t) => lamps[t.id] === "flash").length;

  return (
    <div className="annunciator on-bezel">
      <div className="panel-plate">
        <span>Access alarm panel</span>
        <span role="status">
          {active.length === 0
            ? "All clear"
            : `${active.length} alarm${active.length > 1 ? "s" : ""}${unacked ? `, ${unacked} not acknowledged` : ""}`}
        </span>
      </div>
      <ul className="tiles" aria-label="Alarm tiles">
        {tiles.map((tile) => {
          const lamp = testing ? "steady" : (lamps[tile.id] ?? "off");
          return (
            <li
              key={tile.id}
              className={`tile tile-${tile.severity} lamp-${lamp}`}
            >
              <span>{tile.label}</span>
              <span className="sr-only">
                {lamp === "off"
                  ? ", off"
                  : lamp === "flash"
                    ? ", alarm, not acknowledged"
                    : ", alarm, acknowledged"}
              </span>
            </li>
          );
        })}
      </ul>
      <div className="panel-controls">
        <button
          className="push push-ack"
          onClick={acknowledge}
          disabled={unacked === 0}
        >
          Acknowledge
        </button>
        <button
          className="push"
          onClick={reset}
          disabled={!active.some((t) => lamps[t.id] === "steady")}
        >
          Reset
        </button>
        <button className="push" onClick={lampTest}>
          Lamp test
        </button>
      </div>
      <div className="panel-lower">
        <fieldset className="scenarios">
          <legend>Make something go wrong</legend>
          {scenarios.map((s) => (
            <button key={s.id} className="scenario" onClick={() => run(s)}>
              {s.label}
            </button>
          ))}
        </fieldset>
        <div className="printer">
          <p className="printer-head" id="printer-title">
            Event printer, newest first
          </p>
          <ol aria-labelledby="printer-title" aria-live="polite">
            {lines.length === 0 && (
              <li className="printer-idle">Waiting for an event.</li>
            )}
            {lines.map((line) => (
              <li key={line.key} className={`print-${line.decision}`}>
                <time>{clock(line.at)}</time>
                <code>{line.rule}</code>
                <span>{line.text}</span>
                <strong>
                  {line.decision === "event" ? "" : line.decision.toUpperCase()}
                </strong>
              </li>
            ))}
          </ol>
        </div>
      </div>
    </div>
  );
}
