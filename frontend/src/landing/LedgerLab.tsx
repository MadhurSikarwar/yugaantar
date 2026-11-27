import { useEffect, useState } from "react";
import {
  seal,
  verifyChain,
  type LedgerEntry,
  type LedgerReport,
  type StoredEntry,
} from "../lib/ledger.ts";

const entry = (
  seq: number,
  actor: string,
  action: string,
  target: string,
  decision: LedgerEntry["decision"],
  rule: string,
): LedgerEntry => ({
  seq,
  ts: `2026-11-26T09:0${seq}:00Z`,
  actor,
  action,
  target,
  decision,
  rule,
  request_id: `demo-${seq}`,
  detail: {},
});

const unsealed: LedgerEntry[] = [
  entry(1, "maya", "read", "brief", "allow", "POL-ALLOW-OWNER"),
  entry(2, "operator", "revoke", "maya", "allow", "ADM-REVOKE"),
  entry(3, "maya", "read", "brief", "deny", "POL-REVOKED"),
  entry(4, "noor", "read", "ledger", "allow", "POL-ALLOW-OWNER"),
  entry(5, "eve", "read", "ledger", "deny", "POL-NOT-OWNER"),
];
const short = (hash: string) => `${hash.slice(0, 8)}…${hash.slice(-6)}`;

/** Hashes come from Web Crypto, which is asynchronous: seal once, then show the lab. */
export default function LedgerLab() {
  const [original, setOriginal] = useState<StoredEntry[] | null>(null);
  useEffect(() => {
    let live = true;
    void seal(unsealed).then((sealed) => live && setOriginal(sealed));
    return () => {
      live = false;
    };
  }, []);
  if (original === null)
    return (
      <section
        className="lab ledger"
        id="ledger"
        aria-labelledby="ledger-title"
      >
        <header className="lab-intro">
          <h2 id="ledger-title">What happens if someone edits the log</h2>
          <p role="status">Computing hashes…</p>
        </header>
      </section>
    );
  return <Ledger original={original} />;
}

function Ledger({ original }: { original: StoredEntry[] }) {
  const pinned = original.at(-1)!.hash;
  const [entries, setEntries] = useState<StoredEntry[]>(original);
  const [report, setReport] = useState<LedgerReport>({
    brokenAt: null,
    matchesPin: true,
  });
  useEffect(() => {
    let live = true;
    void verifyChain(entries, pinned).then((r) => live && setReport(r));
    return () => {
      live = false;
    };
  }, [entries, pinned]);
  const edited = entries.some((e, i) => e.decision !== original[i].decision);
  const flip = (seq: number) =>
    setEntries((current) =>
      current.map((e) =>
        e.seq === seq
          ? { ...e, decision: e.decision === "allow" ? "deny" : "allow" }
          : e,
      ),
    );
  const verdict = !edited
    ? "The log is untouched. The chain recomputes and its head matches the pin."
    : report.brokenAt !== null
      ? `Entry ${report.brokenAt} no longer produces the hash stored beside it, so the edit is detected.`
      : "The rewritten chain agrees with itself. Only the head pinned somewhere else shows that it changed.";

  return (
    <section className="lab ledger" id="ledger" aria-labelledby="ledger-title">
      <header className="lab-intro">
        <h2 id="ledger-title">What happens if someone edits the log</h2>
        <p>
          Each entry is hashed together with the hash before it. Change a
          decision below and see which check notices. The SHA-256 hashes are
          computed on this page by the browser's built-in Web Crypto API.
        </p>
      </header>
      <div className="ledger-scroll">
        <table className="ledger-table">
          <thead>
            <tr>
              <th scope="col">Entry</th>
              <th scope="col">Request</th>
              <th scope="col">Decision (select to edit)</th>
              <th scope="col">Rule</th>
              <th scope="col">Stored hash</th>
              <th scope="col">Recomputed</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e, i) => {
              const broken =
                report.brokenAt !== null && e.seq >= report.brokenAt;
              const changed = e.decision !== original[i].decision;
              return (
                <tr key={e.seq} className={broken ? "broken" : ""}>
                  <th scope="row">{e.seq}</th>
                  <td>
                    {e.actor} {e.action} {e.target}
                  </td>
                  <td>
                    <button
                      className={`decision decision-${e.decision}`}
                      onClick={() => flip(e.seq)}
                      aria-label={`Entry ${e.seq} decision is ${e.decision}. Change it.`}
                    >
                      {e.decision === "allow" ? "Allow" : "Deny"}
                      {changed && <small>edited</small>}
                    </button>
                  </td>
                  <td>
                    <code>{e.rule}</code>
                  </td>
                  <td>
                    <code
                      className={e.hash !== original[i].hash ? "rewritten" : ""}
                    >
                      {short(e.hash)}
                    </code>
                  </td>
                  <td className="recomputed">
                    {!broken
                      ? "Matches"
                      : e.seq === report.brokenAt
                        ? "Mismatch"
                        : "Untrusted"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="checks">
        <div className={report.brokenAt === null ? "check pass" : "check fail"}>
          <span>Recompute the chain</span>
          <strong>{report.brokenAt === null ? "Passes" : "Fails"}</strong>
        </div>
        <div
          className={
            report.matchesPin && report.brokenAt === null
              ? "check pass"
              : "check fail"
          }
        >
          <span>Compare with the pinned head</span>
          <strong>
            {report.matchesPin && report.brokenAt === null ? "Passes" : "Fails"}
          </strong>
          <code>{short(pinned)}</code>
        </div>
      </div>
      <p className="ledger-verdict" role="status">
        {verdict}
      </p>
      <div className="ledger-actions">
        <button
          className="button button-dark"
          onClick={() => void seal(entries).then(setEntries)}
          disabled={report.brokenAt === null}
        >
          Recompute every hash, like an attacker
        </button>
        <button
          className="button"
          onClick={() => setEntries(original)}
          disabled={!edited}
        >
          Restore the log
        </button>
      </div>
      <p className="lab-note">
        The service also signs checkpoints with ML-DSA-65. Someone who can write
        the log directory can read that key, which is why the operator keeps a
        pin outside it.
      </p>
    </section>
  );
}
