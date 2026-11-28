import { useEffect, useRef, useState } from "react";
import {
  downloadJSON,
  formatDate,
  parseSnapshot,
  type Snapshot,
} from "../snapshot.ts";
import { SAMPLE_NAME, sampleSnapshot } from "../lib/sample.ts";
import { bridge } from "../lib/api.ts";
import Charts from "./Charts.tsx";
import Inspector, { type Inspected } from "./Inspector.tsx";
import LivePanel from "./LivePanel.tsx";
import NodeMap from "./NodeMap.tsx";
import Palette, { type Command } from "./Palette.tsx";
import "./console.css";

const tabs = [
  "Overview",
  "Devices",
  "Nodes",
  "Verification",
  "Audit log",
] as const;
type Tab = (typeof tabs)[number];
const slugs = ["overview", "devices", "nodes", "verification", "audit"];
const routeTab = (): Tab =>
  tabs[Math.max(0, slugs.indexOf(location.hash.split("/")[2] || "overview"))];
const go = (tab: Tab) => {
  location.hash = `#/console/${slugs[tabs.indexOf(tab)]}`;
};
type Row = Record<string, unknown>;
const LIVE_NAME = "Live backend";
const POLL_MS = 3000;

const views: Record<
  Tab,
  {
    title: string;
    lead: string;
    category: "devices" | "nodes" | "verifications" | "audit";
    columns: [string, string][];
    filters: string[];
    search: string;
    note: string;
  }
> = {
  Overview: {
    title: "Overview",
    lead: "Who asked, what was decided, and which rule decided it.",
    category: "audit",
    columns: [
      ["actor", "Identity"],
      ["action", "Action"],
      ["asset", "Resource"],
      ["decision", "Decision"],
      ["rule", "Policy rule"],
    ],
    filters: [],
    search: "",
    note: "",
  },
  Devices: {
    title: "Devices",
    lead: "Enrolled identities and the key state reported for each.",
    category: "devices",
    columns: [
      ["id", "Device"],
      ["owner", "Owner"],
      ["keyVersion", "Key version"],
      ["state", "Reported state"],
    ],
    filters: ["active", "revoked"],
    search: "Search devices or owners",
    note: "Enrollment, rotation and revocation happen in the backend. This view only inspects loaded records.",
  },
  Nodes: {
    title: "Nodes",
    lead: "Revocation list state on each node, and the devices it lists.",
    category: "nodes",
    columns: [
      ["id", "Node"],
      ["state", "Reported state"],
      ["listVersion", "List version"],
      ["deviceIds", "Devices"],
      ["lastUpdated", "Last updated"],
    ],
    filters: ["current", "stale", "offline"],
    search: "Search nodes or devices",
    note: "States and timestamps are reported by the file. No live freshness or connectivity check runs here.",
  },
  Verification: {
    title: "Verification",
    lead: "Cryptographic results as the source reports them.",
    category: "verifications",
    columns: [
      ["id", "Evidence"],
      ["kind", "Check"],
      ["outcome", "Reported outcome"],
      ["detail", "Detail"],
    ],
    filters: ["valid", "invalid", "not-checked"],
    search: "Search evidence",
    note: "A reported valid outcome is not an independently verified result. This browser runs no ML-KEM, signature or audit chain checks on imported data.",
  },
  "Audit log": {
    title: "Audit log",
    lead: "Trace a decision to its request, identity and policy rule.",
    category: "audit",
    columns: [
      ["timestamp", "Time"],
      ["actor", "Identity"],
      ["requestId", "Request"],
      ["asset", "Resource"],
      ["decision", "Decision"],
      ["rule", "Policy rule"],
    ],
    filters: ["allow", "deny"],
    search: "Search identity, request or rule",
    note: "Latest source entries first. Duplicate request identifiers remain visible. Loading a file does not verify the hash chain.",
  },
};

const icons = [
  "M4 4h7v7H4zM13 4h7v4h-7zM13 11h7v9h-7zM4 14h7v6H4z",
  "M7 3h10v18H7zM10 17h4",
  "M12 4v5M12 9l-6 7M12 9l6 7M10 3h4v3h-4zM3 16h6v5H3zM15 16h6v5h-6z",
  "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM8.5 12l2.5 2.5 4.5-5",
  "M5 3h14v18H5zM9 8h6M9 12h6M9 16h4",
];

const PAGE = 25;

function Records({
  tab,
  rows,
  inspect,
}: {
  tab: Tab;
  rows: Row[];
  inspect: (row: Row) => void;
}) {
  const { columns } = views[tab];
  return (
    <div
      className="table-wrap"
      role="region"
      aria-label={`${tab} records`}
      tabIndex={0}
    >
      <table>
        <caption className="sr-only">{tab} loaded records</caption>
        <thead>
          <tr>
            {columns.map(([key, label]) => (
              <th key={key} scope="col">
                {label}
              </th>
            ))}
            <th scope="col">
              <span className="sr-only">Inspect record</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} onClick={() => inspect(row)}>
              {columns.map(([key]) => (
                <td key={key} className={`cell-${key}`}>
                  {["state", "decision", "outcome"].includes(key) ? (
                    <span className={`badge badge-${row[key]}`}>
                      {String(row[key]).replaceAll("-", " ")}
                    </span>
                  ) : key === "lastUpdated" || key === "timestamp" ? (
                    formatDate(String(row[key]))
                  ) : Array.isArray(row[key]) ? (
                    (row[key] as string[]).length
                  ) : key === "rule" || key === "requestId" ? (
                    <code>{String(row[key])}</code>
                  ) : (
                    String(row[key])
                  )}
                </td>
              ))}
              <td>
                <button
                  className="row-action"
                  onClick={(e) => {
                    e.stopPropagation();
                    inspect(row);
                  }}
                >
                  Inspect
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Console() {
  const [tab, setTab] = useState<Tab>(routeTab);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [synthetic, setSynthetic] = useState(false);
  const [live, setLive] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [lost, setLost] = useState(false);
  const [filename, setFilename] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [page, setPage] = useState(0);
  const [inspected, setInspected] = useState<Inspected | null>(null);
  const [palette, setPalette] = useState(false);
  const [dragging, setDragging] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const importVersion = useRef(0);

  const resetFilters = () => {
    setQuery("");
    setFilter("all");
    setPage(0);
  };

  useEffect(() => {
    const change = () => {
      setTab(routeTab());
      resetFilters();
      setInspected(null);
    };
    window.addEventListener("hashchange", change);
    return () => {
      window.removeEventListener("hashchange", change);
      importVersion.current++;
    };
  }, []);
  useEffect(() => {
    document.title = `${tab} | Latticelock console`;
  }, [tab]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        // One modal at a time.
        if (!document.querySelector("dialog[open]")) setPalette(true);
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);

  async function refreshLive() {
    const version = importVersion.current;
    const next = await bridge.snapshot();
    if (version === importVersion.current) setSnapshot(next);
  }
  useEffect(() => {
    if (!live) return;
    let busy = false;
    const timer = setInterval(async () => {
      if (busy || document.hidden) return;
      busy = true;
      try {
        await refreshLive();
        setLost(false);
      } catch {
        setLost(true);
      }
      busy = false;
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [live]);
  async function connectLive(fresh = false) {
    const version = ++importVersion.current;
    setConnecting(true);
    setError("");
    try {
      const health = await bridge.health();
      if (fresh || !health.started) await bridge.start();
      const next = await bridge.snapshot();
      if (version !== importVersion.current) return;
      setSnapshot(next);
      setSynthetic(false);
      setLive(true);
      setLost(false);
      setFilename(LIVE_NAME);
      setInspected(null);
      resetFilters();
      setNotice("Connected to the local backend.");
    } catch (e) {
      if (version === importVersion.current) setError((e as Error).message);
    }
    setConnecting(false);
  }
  async function importFile(selected: File | undefined) {
    if (!selected) return;
    const version = ++importVersion.current;
    setError("");
    try {
      if (selected.size > 5 * 1024 * 1024)
        throw new Error("Choose a snapshot smaller than 5 MB.");
      const parsed = parseSnapshot(await selected.text());
      if (version !== importVersion.current) return;
      setSnapshot(parsed);
      setSynthetic(false);
      setLive(false);
      setFilename(selected.name);
      setInspected(null);
      resetFilters();
      setNotice(
        "Snapshot imported. Contents have not been independently verified.",
      );
    } catch (e) {
      if (version === importVersion.current) setError((e as Error).message);
    }
    if (file.current) file.current.value = "";
  }
  function loadSample() {
    importVersion.current++;
    setSnapshot(sampleSnapshot());
    setSynthetic(true);
    setLive(false);
    setFilename(SAMPLE_NAME);
    setError("");
    resetFilters();
    setNotice("Synthetic sample loaded. Every record in it is invented.");
  }
  function clearSnapshot() {
    importVersion.current++;
    setSnapshot(null);
    setSynthetic(false);
    setLive(false);
    setFilename("");
    setError("");
    resetFilters();
    setNotice(
      live
        ? "Disconnected from the backend."
        : "Snapshot cleared from this session.",
    );
  }
  const chooseFile = () => file.current?.click();

  const view = views[tab];
  const note = synthetic
    ? "Synthetic sample. This record is invented for demonstration."
    : live
      ? "Live from the local backend. The bridge ran the verifier of the backend; this page ran no cryptography."
      : "Imported claims are not independently verified by this page.";
  const inspect = (title: string, record: object) =>
    setInspected({ title, record, note });
  const rowTitle = (of: Tab) =>
    of === "Overview" || of === "Audit log"
      ? "Access decision"
      : of === "Devices"
        ? "Device"
        : of === "Nodes"
          ? "Node"
          : "Verification result";
  const showHelp = () =>
    setInspected({
      title: "About this console",
      note: live
        ? "Connected to the local backend bridge (tools/bridge.py)."
        : "Not connected. Start tools/bridge.py and choose Connect to backend for live data.",
      record: {
        source:
          "The local backend bridge (live), a JSON snapshot you choose (schemaVersion 1), or the built-in synthetic sample.",
        privacy:
          "Files are parsed in memory and never uploaded. In live mode the page talks only to the bridge on this computer, with synthetic data.",
        format:
          "schemaVersion, capturedAt, devices, nodes, audit, verifications. The full contract is in the project README.",
        limits:
          "5 MB per file and 5,000 entries per collection. Unknown fields are discarded.",
        trust:
          "States and verification outcomes are claims made by the source. In live mode the bridge computes them with the verifier of the backend; this page checks nothing itself.",
        shortcuts: "Ctrl K or Command K opens the command palette.",
      },
    });

  const source = (snapshot?.[view.category] ?? []) as unknown as Row[];
  const filtered = source.filter(
    (row) =>
      Object.values(row)
        .flat()
        .join(" ")
        .toLowerCase()
        .includes(query.toLowerCase()) &&
      (filter === "all" ||
        (row.state ?? row.decision ?? row.outcome) === filter),
  );
  const ordered =
    view.category === "audit" ? [...filtered].reverse() : filtered;
  const shown =
    tab === "Overview"
      ? ordered.slice(0, 8)
      : ordered.slice(page * PAGE, (page + 1) * PAGE);

  const commands: Command[] = [
    ...tabs.map((name) => ({
      label: `Go to ${name.toLowerCase()}`,
      hint: "View",
      run: () => go(name),
    })),
    {
      label: live ? "Refresh from the backend" : "Connect to the backend",
      hint: "Action",
      run: () => void connectLive(),
    },
    { label: "Import a snapshot", hint: "Action", run: chooseFile },
    { label: "Load the synthetic sample", hint: "Action", run: loadSample },
    ...(snapshot
      ? [
          {
            label: live ? "Disconnect from the backend" : "Clear the snapshot",
            hint: "Action",
            run: clearSnapshot,
          },
        ]
      : []),
    { label: "About this console", hint: "Help", run: showHelp },
    {
      label: "Return to the landing page",
      hint: "View",
      run: () => {
        location.hash = "#/";
      },
    },
  ];
  const searchRecords = (text: string): Command[] => {
    if (!snapshot) return [];
    const found: Command[] = [];
    const groups: [Tab, object[], (row: Row) => string][] = [
      ["Devices", snapshot.devices, (r) => `${r.id} owned by ${r.owner}`],
      ["Nodes", snapshot.nodes, (r) => `${r.id}, ${r.state}`],
      ["Verification", snapshot.verifications, (r) => `${r.id}, ${r.outcome}`],
      [
        "Audit log",
        snapshot.audit,
        (r) => `${r.requestId}: ${r.actor} ${r.decision}, ${r.rule}`,
      ],
    ];
    for (const [of, rows, label] of groups)
      for (const row of rows as Row[]) {
        if (found.length >= 12) return found;
        if (label(row).toLowerCase().includes(text))
          found.push({
            label: label(row),
            hint: of,
            run: () => inspect(rowTitle(of), row),
          });
      }
    return found;
  };

  const totals: [string, number | undefined, Tab, string][] = [
    ["Devices", snapshot?.devices.length, "Devices", ""],
    [
      "Revoked devices",
      snapshot?.devices.filter((d) => d.state === "revoked").length,
      "Devices",
      "deny",
    ],
    [
      "Nodes not current",
      snapshot?.nodes.filter((n) => n.state !== "current").length,
      "Nodes",
      "amber",
    ],
    ["Access decisions", snapshot?.audit.length, "Audit log", ""],
  ];

  const table = (
    <>
      {shown.length > 0 ? (
        <Records
          tab={tab}
          rows={shown}
          inspect={(row) => inspect(rowTitle(tab), row)}
        />
      ) : (
        <div className="empty">
          <h3>{snapshot ? "No matching records" : "Nothing loaded yet"}</h3>
          <p>
            {snapshot
              ? "Change the search or filter, or load a snapshot that has these records."
              : "Connect to the local backend bridge, drop a snapshot file on this page, or look around with invented records."}
          </p>
          {!snapshot && (
            <div className="empty-actions">
              <button
                className="button button-light"
                disabled={connecting}
                onClick={() => void connectLive()}
              >
                {connecting ? "Connecting..." : "Connect to backend"}
              </button>
              <button className="button button-light" onClick={chooseFile}>
                Import snapshot
              </button>
              <button className="button" onClick={loadSample}>
                Load synthetic sample
              </button>
            </div>
          )}
        </div>
      )}
      {tab !== "Overview" && filtered.length > PAGE && (
        <div className="pagination">
          <button
            className="button button-small"
            disabled={page === 0}
            onClick={() => setPage((p) => p - 1)}
          >
            Previous
          </button>
          <span>
            Page {page + 1} of {Math.ceil(filtered.length / PAGE)}
          </span>
          <button
            className="button button-small"
            disabled={(page + 1) * PAGE >= filtered.length}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </button>
        </div>
      )}
    </>
  );

  return (
    <div
      className="console"
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null))
          setDragging(false);
      }}
      onDrop={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        e.preventDefault();
        setDragging(false);
        void importFile(e.dataTransfer.files[0]);
      }}
    >
      <a
        className="skip-link"
        href="#console-content"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("console-content")?.focus();
        }}
      >
        Skip to workspace
      </a>
      <aside className="sidebar">
        <a className="brand" href="#/">
          Latticelock
        </a>
        <nav aria-label="Console navigation">
          {tabs.map((name, i) => (
            <a
              key={name}
              href={`#/console/${slugs[i]}`}
              aria-current={tab === name ? "page" : undefined}
            >
              <svg
                viewBox="0 0 24 24"
                width="19"
                height="19"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d={icons[i]} />
              </svg>
              {name}
            </a>
          ))}
        </nav>
        <div className="sidebar-foot">
          <button onClick={showHelp}>About this console</button>
          <a href="#/">Landing page</a>
          <p>
            {live
              ? "Connected to the local backend bridge."
              : "Not connected to a backend."}
          </p>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <button className="search-trigger" onClick={() => setPalette(true)}>
            Search or jump to
            <kbd>Ctrl K</kbd>
          </button>
          <div className="source">
            <strong>{snapshot ? filename : "No snapshot"}</strong>
            {snapshot && (
              <span>Captured {formatDate(snapshot.capturedAt)}</span>
            )}
          </div>
          {snapshot && (
            <button className="button button-small" onClick={clearSnapshot}>
              {live ? "Disconnect" : "Clear"}
            </button>
          )}
          {!live && (
            <button
              className="button button-small"
              disabled={connecting}
              onClick={() => void connectLive()}
            >
              {connecting ? "Connecting..." : "Connect to backend"}
            </button>
          )}
          <button
            className="button button-small button-light"
            onClick={chooseFile}
          >
            Import snapshot
          </button>
          <input
            type="file"
            ref={file}
            accept=".json,application/json"
            className="sr-only"
            tabIndex={-1}
            aria-label="Import JSON snapshot"
            onChange={(e) => void importFile(e.target.files?.[0])}
          />
        </header>
        {snapshot && (
          <p
            className={
              synthetic
                ? "banner banner-synthetic"
                : live
                  ? "banner banner-live"
                  : "banner"
            }
          >
            {synthetic
              ? "Synthetic sample. Every record is invented for demonstration; nothing here came from a running service."
              : live
                ? lost
                  ? "Connection to the backend bridge lost. Showing the last data it sent."
                  : "Live from the local backend bridge, using synthetic data. The audit chains were checked by the verifier of the backend on the bridge; this page runs no cryptography."
                : "Imported data, not live. These records have not been independently verified in this browser."}
          </p>
        )}
        <main id="console-content" tabIndex={-1} className="main">
          <div className="title">
            <h1>{view.title}</h1>
            <p>{view.lead}</p>
          </div>
          {error && (
            <div className="import-error" role="alert">
              <p>
                <strong>Import failed.</strong> {error}
                {snapshot && " The previous snapshot is still shown."}
              </p>
              <button
                className="button button-small"
                onClick={() => setError("")}
              >
                Dismiss
              </button>
            </div>
          )}
          <span className="sr-only" role="status">
            {notice}
          </span>

          {tab === "Overview" ? (
            <>
              <ul className="totals">
                {totals.map(([label, value, target, tone]) => (
                  <li key={label} className={value ? `total-${tone}` : ""}>
                    <a href={`#/console/${slugs[tabs.indexOf(target)]}`}>
                      <span>{label}</span>
                      <strong>{value ?? "—"}</strong>
                    </a>
                  </li>
                ))}
              </ul>
              {snapshot && snapshot.audit.length > 0 && (
                <Charts key={filename} records={snapshot.audit} />
              )}
              {live && snapshot && (
                <LivePanel
                  snapshot={snapshot}
                  refresh={refreshLive}
                  reset={() => connectLive(true)}
                />
              )}
              <section className="panel" aria-labelledby="recent-title">
                <div className="panel-head">
                  <h2 id="recent-title">Latest decisions</h2>
                  <a href="#/console/audit">View audit log</a>
                </div>
                {table}
              </section>
              <section className="boundaries" aria-label="Reading the evidence">
                <div>
                  <h3>File access</h3>
                  <p>
                    The adapter decides permission from the actor it is given.
                    It does not authenticate that actor.
                  </p>
                </div>
                <div>
                  <h3>Device identity</h3>
                  <p>
                    The node layer checks signatures, active keys, revocation,
                    freshness and replay.
                  </p>
                </div>
                <div>
                  <h3>Evidence</h3>
                  <p>
                    Protected-read proofs and signed audit checkpoints answer
                    separate questions.
                  </p>
                </div>
              </section>
            </>
          ) : (
            <>
              <div className="toolbar">
                <input
                  type="search"
                  aria-label={view.search}
                  placeholder={view.search}
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    setPage(0);
                  }}
                />
                <div className="chips" role="group" aria-label="Filter records">
                  {["all", ...view.filters].map((v) => (
                    <button
                      key={v}
                      aria-pressed={filter === v}
                      onClick={() => {
                        setFilter(v);
                        setPage(0);
                      }}
                    >
                      {v.replaceAll("-", " ")}
                      <span>
                        {v === "all"
                          ? source.length
                          : source.filter(
                              (r) => (r.state ?? r.decision ?? r.outcome) === v,
                            ).length}
                      </span>
                    </button>
                  ))}
                </div>
                {snapshot && (
                  <button
                    className="button button-small"
                    onClick={() =>
                      downloadJSON(
                        filtered,
                        `track-4-${synthetic ? "synthetic-" : ""}${slugs[tabs.indexOf(tab)]}.json`,
                      )
                    }
                  >
                    Export results
                  </button>
                )}
              </div>
              {tab === "Nodes" && shown.length > 0 && (
                <NodeMap nodes={shown as unknown as Snapshot["nodes"]} />
              )}
              <section className="panel" aria-labelledby="records-title">
                <div className="panel-head">
                  <h2 id="records-title">Records</h2>
                  <span>
                    {snapshot
                      ? `${filtered.length} of ${source.length}`
                      : "Awaiting data"}
                  </span>
                </div>
                {table}
              </section>
              <p className="footnote">{view.note}</p>
            </>
          )}
        </main>
      </div>
      {dragging && (
        <div className="drop-veil" aria-hidden="true">
          <p>Drop the snapshot to inspect it</p>
          <span>It is read here and never uploaded.</span>
        </div>
      )}
      {palette && (
        <Palette
          commands={commands}
          search={searchRecords}
          close={() => setPalette(false)}
        />
      )}
      {inspected && (
        <Inspector {...inspected} close={() => setInspected(null)} />
      )}
    </div>
  );
}
