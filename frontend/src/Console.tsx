import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  downloadJSON,
  formatDate,
  parseSnapshot,
  type Snapshot,
} from "./snapshot";
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
type Row = Record<string, unknown>;
const descriptions: Record<Tab, string> = {
  Overview:
    "Inspect device identity, access decisions and their supporting evidence.",
  Devices: "Review enrolled identities and reported key state.",
  Nodes: "Inspect revocation-list state and device relationships.",
  Verification:
    "Review cryptographic results reported in the imported snapshot.",
  "Audit log":
    "Trace an access decision to its request, identity and policy rule.",
};
const columns: Record<Tab, [string, string][]> = {
  Overview: [
    ["actor", "Identity"],
    ["action", "Action"],
    ["asset", "Resource"],
    ["decision", "Decision"],
    ["rule", "Policy rule"],
  ],
  Devices: [
    ["id", "Device"],
    ["owner", "Owner"],
    ["keyVersion", "Key version"],
    ["state", "Reported state"],
  ],
  Nodes: [
    ["id", "Node"],
    ["state", "Reported state"],
    ["listVersion", "List version"],
    ["deviceIds", "Devices"],
    ["lastUpdated", "Last updated"],
  ],
  Verification: [
    ["id", "Evidence"],
    ["kind", "Check"],
    ["outcome", "Reported outcome"],
  ],
  "Audit log": [
    ["actor", "Identity"],
    ["requestId", "Request"],
    ["action", "Action"],
    ["decision", "Decision"],
    ["rule", "Policy rule"],
  ],
};

function Glyph({ index }: { index: number }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="18"
      height="18"
      stroke="currentColor"
      strokeWidth="1.3"
      fill="none"
      aria-hidden="true"
    >
      {
        [
          <>
            <path d="M4 4h16v16H4zM4 10h16M10 10v10" />
          </>,
          <>
            <rect x="6" y="3" width="12" height="18" rx="1" />
            <path d="M10 17h4" />
          </>,
          <>
            <path d="M5 6l14 12M19 6L5 18" />
            <circle cx="5" cy="6" r="3" />
            <circle cx="19" cy="6" r="3" />
            <circle cx="5" cy="18" r="3" />
            <circle cx="19" cy="18" r="3" />
          </>,
          <>
            <path d="M5 5h14v14H5zM8 12l3 3 5-6" />
          </>,
          <>
            <path d="M6 3h12v18H6zM9 8h6M9 12h6M9 16h4" />
          </>,
        ][index]
      }
    </svg>
  );
}
function Empty({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="empty-state">
      <span className="empty-rule" aria-hidden="true" />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
function Inspector({
  title,
  record,
  close,
}: {
  title: string;
  record: object;
  close: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  const dismiss = () => {
    dialog.current?.close();
    close();
  };
  return (
    <dialog
      ref={dialog}
      className="inspector"
      onCancel={(event) => {
        event.preventDefault();
        dismiss();
      }}
      aria-labelledby="inspector-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) dismiss();
      }}
    >
      <div className="panel-heading">
        <h2 id="inspector-title">{title}</h2>
        <button
          className="plain-button"
          onClick={dismiss}
          aria-label="Close inspector"
        >
          Close ×
        </button>
      </div>
      <p className="inspector-note">
        Frontend inspection. Imported claims are not independently verified.
      </p>
      <dl>
        {Object.entries(record).map(([key, value]) => (
          <div key={key}>
            <dt>{key.replace(/([A-Z])/g, " $1")}</dt>
            <dd>
              {Array.isArray(value)
                ? value.join(", ") || "None"
                : String(value)}
            </dd>
          </div>
        ))}
      </dl>
    </dialog>
  );
}

export default function Console() {
  const [tab, setTab] = useState<Tab>(routeTab),
    [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [filename, setFilename] = useState(""),
    [error, setError] = useState(""),
    [notice, setNotice] = useState("");
  const [query, setQuery] = useState(""),
    [filter, setFilter] = useState("all"),
    [page, setPage] = useState(0);
  const [inspected, setInspected] = useState<{
    title: string;
    record: object;
  } | null>(null);
  const file = useRef<HTMLInputElement>(null),
    importVersion = useRef(0);
  useEffect(() => {
    const change = () => {
      setTab(routeTab());
      setQuery("");
      setFilter("all");
      setPage(0);
      setInspected(null);
    };
    window.addEventListener("hashchange", change);
    return () => {
      window.removeEventListener("hashchange", change);
      importVersion.current++;
    };
  }, []);
  useEffect(() => {
    document.title = `${tab} — Interleaf console`;
  }, [tab]);
  const category =
    tab === "Devices"
      ? "devices"
      : tab === "Nodes"
        ? "nodes"
        : tab === "Verification"
          ? "verifications"
          : "audit";
  const source = (snapshot?.[category] ?? []) as unknown as Row[];
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
  const ordered = category === "audit" ? [...filtered].reverse() : filtered;
  const shown =
    tab === "Overview"
      ? ordered.slice(0, 6)
      : ordered.slice(page * 25, (page + 1) * 25);
  const inspect = (title: string, record: object) =>
    setInspected({ title, record });
  const showHelp = () =>
    inspect("About this workspace", {
      mode: "Read-only frontend. Backend integration pending.",
      source: "User-selected JSON snapshot, schemaVersion 1.",
      privacy:
        "Parsed in memory. No file uploads, browser persistence or remote requests.",
      format:
        "Required: schemaVersion, capturedAt, devices, nodes, audit, verifications. The complete contract is documented in frontend/README.md.",
      limits:
        "5 MB per file; 5,000 entries per collection. Unknown fields are discarded.",
      trust:
        "Imported states and verification outcomes are claims in the file, not independently verified results.",
      integration:
        "Backend actions, authentication and cryptographic checks remain with the existing service.",
    });
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
      setFilename(selected.name);
      setQuery("");
      setFilter("all");
      setPage(0);
      setNotice(
        "Snapshot imported. Contents have not been independently verified.",
      );
    } catch (e) {
      if (version === importVersion.current) setError((e as Error).message);
    }
    if (file.current) file.current.value = "";
  }
  const emptyTitle = snapshot
    ? "No matching records"
    : `No ${tab === "Overview" ? "audit records" : tab.toLowerCase() === "audit log" ? "audit records" : tab === "Verification" ? "verification results" : tab.toLowerCase()} loaded`;
  function Records() {
    return (
      <>
        <div className="table-wrap">
          <table>
            <caption className="sr-only">{tab} imported records</caption>
            <thead>
              <tr>
                {columns[tab].map(([key, label]) => (
                  <th key={key}>{label}</th>
                ))}
                <th>
                  <span className="sr-only">Inspect record</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.map((row, index) => (
                <tr key={index}>
                  {columns[tab].map(([key]) => (
                    <td key={key}>
                      {["state", "decision", "outcome"].includes(key) ? (
                        <span className={`record-state state-${row[key]}`}>
                          {String(row[key]).replaceAll("-", " ")}
                        </span>
                      ) : key === "lastUpdated" ? (
                        formatDate(String(row[key]))
                      ) : Array.isArray(row[key]) ? (
                        (row[key] as string[]).length
                      ) : (
                        String(row[key])
                      )}
                    </td>
                  ))}
                  <td>
                    <button
                      className="table-action"
                      onClick={() =>
                        inspect(
                          tab === "Overview" || tab === "Audit log"
                            ? "Access decision"
                            : `${tab} record`,
                          row,
                        )
                      }
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!shown.length && (
          <Empty title={emptyTitle}>
            {snapshot
              ? "Try another search or filter, or import a snapshot with these records."
              : "Import a snapshot to inspect actual records. No demonstration data is loaded."}
          </Empty>
        )}
        {tab !== "Overview" && filtered.length > 25 && (
          <div className="pagination">
            <button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              Previous
            </button>
            <span>
              Page {page + 1} of {Math.ceil(filtered.length / 25)}
            </span>
            <button
              disabled={(page + 1) * 25 >= filtered.length}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        )}
      </>
    );
  }
  return (
    <div className="console-shell">
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
      <aside className="console-sidebar">
        <a className="console-brand" href="#/">
          Interleaf.
        </a>
        <span className="workspace-label">Security workspace</span>
        <nav aria-label="Console navigation">
          {tabs.map((name, i) => (
            <a
              key={name}
              href={`#/console/${slugs[i]}`}
              className={tab === name ? "active" : ""}
              aria-current={tab === name ? "page" : undefined}
            >
              <Glyph index={i} />
              {name}
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button onClick={showHelp}>About this workspace</button>
          <a href="#/">Return to experience</a>
          <p>
            Frontend edition
            <br />
            Backend integration pending
          </p>
        </div>
      </aside>
      <div className="console-workspace">
        <header className="console-topbar">
          <span>
            Console <span className="breadcrumb-separator">/</span> {tab}
          </span>
          <button className="plain-button mobile-about" onClick={showHelp}>
            About
          </button>
          <a href="#/">The experience</a>
        </header>
        <main id="console-content" tabIndex={-1} className="console-main">
          <div className="console-title-row">
            <div>
              <span className="console-eyebrow">Access & evidence</span>
              <h1>
                {tab === "Overview"
                  ? "Workspace overview"
                  : tab === "Nodes"
                    ? "Node network"
                    : tab}
              </h1>
              <p>{descriptions[tab]}</p>
            </div>
            <button
              className="dark-button"
              onClick={() => file.current?.click()}
            >
              Import snapshot <span aria-hidden="true">+</span>
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
          </div>
          <div className="source-strip">
            <div>
              <span>Data source</span>
              <strong>{snapshot ? filename : "No snapshot loaded"}</strong>
              <span>
                {snapshot
                  ? `Captured ${formatDate(snapshot.capturedAt)}`
                  : "Read-only frontend · not connected to a backend"}
              </span>
            </div>
            {snapshot ? (
              <button
                className="plain-button"
                onClick={() => {
                  importVersion.current++;
                  setSnapshot(null);
                  setFilename("");
                  setQuery("");
                  setFilter("all");
                  setPage(0);
                  setNotice("Snapshot cleared from this session.");
                }}
              >
                Clear snapshot
              </button>
            ) : (
              <button className="plain-button" onClick={showHelp}>
                Snapshot format
              </button>
            )}
          </div>
          {error && (
            <div className="import-error" role="alert">
              <strong>Import failed.</strong> {error}
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                ×
              </button>
            </div>
          )}
          <span className="sr-only" role="status">
            {notice}
          </span>
          {snapshot && (
            <p className="import-caveat">
              Imported data · Not live. These records have not been
              independently verified in this browser.
            </p>
          )}
          {tab === "Overview" && (
            <>
              <dl className="workspace-totals">
                {[
                  ["Enrolled devices", snapshot?.devices.length],
                  [
                    "Reported active",
                    snapshot?.devices.filter((d) => d.state === "active")
                      .length,
                  ],
                  ["Nodes in snapshot", snapshot?.nodes.length],
                  ["Access records", snapshot?.audit.length],
                ].map(([label, value]) => (
                  <div key={label}>
                    <dt>{label}</dt>
                    <dd>{value ?? "—"}</dd>
                  </div>
                ))}
              </dl>
              <section className="records-section">
                <div className="panel-heading">
                  <h2>Recent access decisions</h2>
                  <a href="#/console/audit">View audit log</a>
                </div>
                {Records()}
              </section>
              <section className="evidence-section">
                <div>
                  <span className="console-eyebrow">Reading the evidence</span>
                  <h2>
                    Different checks.
                    <br />
                    Different boundaries.
                  </h2>
                  <p>
                    Permission decisions, device signatures and cryptographic
                    proofs answer separate questions.
                  </p>
                </div>
                <dl>
                  <div>
                    <dt>File access</dt>
                    <dd>
                      The adapter decides permissions from the supplied actor.
                      It does not authenticate that actor.
                    </dd>
                  </div>
                  <div>
                    <dt>Device identity</dt>
                    <dd>
                      The node layer checks signed requests, active keys,
                      revocation, freshness and replay.
                    </dd>
                  </div>
                  <div>
                    <dt>Evidence</dt>
                    <dd>
                      Protected-read proofs and signed audit checkpoints have
                      distinct verification roles.
                    </dd>
                  </div>
                </dl>
              </section>
            </>
          )}
          {tab !== "Overview" && (
            <>
              <div className="record-toolbar">
                <label className="search-field">
                  <span className="sr-only">Search {tab.toLowerCase()}</span>
                  <svg
                    viewBox="0 0 24 24"
                    width="18"
                    height="18"
                    stroke="currentColor"
                    strokeWidth="1.4"
                    fill="none"
                    aria-hidden="true"
                  >
                    <circle cx="10" cy="10" r="6" />
                    <path d="m15 15 5 5" />
                  </svg>
                  <input
                    value={query}
                    onChange={(e) => {
                      setQuery(e.target.value);
                      setPage(0);
                    }}
                    placeholder={
                      tab === "Devices"
                        ? "Search devices or owners"
                        : tab === "Nodes"
                          ? "Search nodes or devices"
                          : tab === "Verification"
                            ? "Search evidence"
                            : "Search identity, request or rule"
                    }
                  />
                </label>
                <label>
                  <span className="sr-only">Filter records</span>
                  <select
                    value={filter}
                    onChange={(e) => {
                      setFilter(e.target.value);
                      setPage(0);
                    }}
                  >
                    {(tab === "Devices"
                      ? ["all", "active", "revoked"]
                      : tab === "Nodes"
                        ? ["all", "current", "stale", "offline"]
                        : tab === "Verification"
                          ? ["all", "valid", "invalid", "not-checked"]
                          : ["all", "allow", "deny"]
                    ).map((v) => (
                      <option key={v} value={v}>
                        {v === "all" ? "All records" : v.replaceAll("-", " ")}
                      </option>
                    ))}
                  </select>
                </label>
                {snapshot && (
                  <button
                    className="plain-button"
                    onClick={() =>
                      downloadJSON(
                        filtered,
                        `interleaf-${slugs[tabs.indexOf(tab)]}.json`,
                      )
                    }
                  >
                    Export results
                  </button>
                )}
              </div>
              <section className="records-section">
                <div className="panel-heading">
                  <h2>
                    {tab === "Devices"
                      ? "Device registry"
                      : tab === "Nodes"
                        ? "Node records"
                        : tab === "Verification"
                          ? "Reported verification results"
                          : "Access decisions"}
                  </h2>
                  <span>
                    {snapshot ? `${filtered.length} records` : "Awaiting data"}
                  </span>
                </div>
                {tab === "Nodes" && shown.length > 0 && (
                  <div className="network-figure">
                    <svg
                      viewBox="0 0 800 250"
                      className="network-svg"
                      role="img"
                      aria-label="Imported nodes. Lines indicate shared device associations, not traffic or network health."
                    >
                      {shown.slice(0, 12).map((n, i) => {
                        const x = 70 + (i % 6) * 132,
                          y = 65 + Math.floor(i / 6) * 120;
                        return (
                          <g key={i}>
                            {shown.slice(i + 1, 12).map((other, j) => {
                              if (
                                !(n.deviceIds as string[]).some((id) =>
                                  (other.deviceIds as string[]).includes(id),
                                )
                              )
                                return null;
                              const k = i + j + 1;
                              return (
                                <line
                                  key={j}
                                  x1={x}
                                  y1={y}
                                  x2={70 + (k % 6) * 132}
                                  y2={65 + Math.floor(k / 6) * 120}
                                  stroke="#b8bdb0"
                                />
                              );
                            })}
                            <rect
                              x={x - 6}
                              y={y - 6}
                              width="12"
                              height="12"
                              fill={
                                n.state === "current" ? "#495241" : "#d9ddd2"
                              }
                              stroke="#495241"
                            />
                            <text
                              x={x}
                              y={y + 27}
                              textAnchor="middle"
                              fontSize="11"
                              fill="#495241"
                            >
                              {String(n.id).slice(0, 16)}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                    <p>
                      Shared device associations reported in the snapshot.{" "}
                      {shown.length > 12
                        ? "Diagram shows the first 12 records on this page. "
                        : ""}
                      The table provides the complete node details.
                    </p>
                  </div>
                )}
                {tab === "Verification" && (
                  <p className="verification-boundary">
                    Reported results only. This browser does not run ML-KEM,
                    verify signatures or validate audit chains.
                  </p>
                )}
                {Records()}
                <p className="panel-footnote">
                  {tab === "Devices"
                    ? "Enrollment, rotation and revocation require backend integration. This view only inspects imported records."
                    : tab === "Nodes"
                      ? "State and timestamps are reported by the file. No live freshness or connectivity check runs here."
                      : tab === "Verification"
                        ? "A reported valid outcome is not an independently verified result."
                        : "Latest source entries first. Duplicate request identifiers remain visible. Import does not verify the hash chain."}
                </p>
              </section>
            </>
          )}
          <footer className="console-footer">
            <span>Interleaf / Access & evidence</span>
            <span>Local inspection · Changes are not sent to a service</span>
          </footer>
        </main>
      </div>
      {inspected && (
        <Inspector {...inspected} close={() => setInspected(null)} />
      )}
    </div>
  );
}
