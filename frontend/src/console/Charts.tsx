/** Charts of the loaded access records. Allow and deny keep fixed status colors and labels. */
import { useState } from "react";
import { ruleCounts, timeBuckets } from "../lib/stats.ts";
import type { AuditRecord } from "../snapshot.ts";

const clock = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
});
const day = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
});
const share = (part: number, whole: number) =>
  whole ? Math.round((part / whole) * 100) : 0;

function Timeline({ records }: { records: AuditRecord[] }) {
  const buckets = timeBuckets(records);
  const [active, setActive] = useState<number | null>(null);
  const peak = Math.max(1, ...buckets.map((b) => b.allow + b.deny));
  const first = buckets[0].from;
  const last = buckets[buckets.length - 1].to;
  const spansDays = last - first > 86400000;
  const label = (time: number) =>
    spansDays
      ? `${day.format(time)} ${clock.format(time)}`
      : clock.format(time);
  const shown = active === null ? null : buckets[active];
  return (
    <figure className="panel chart-timeline">
      <figcaption>
        <h2>Decisions over time</h2>
        <ul className="legend">
          <li className="key-allow">Allow</li>
          <li className="key-deny">Deny</li>
        </ul>
      </figcaption>
      <p className="chart-readout" aria-live="polite">
        {shown
          ? `${label(shown.from)} to ${label(shown.to)}: ${shown.allow} allowed, ${shown.deny} denied`
          : `Tallest window: ${peak} decisions. Point at a column for its counts.`}
      </p>
      <div className="columns" onMouseLeave={() => setActive(null)}>
        {buckets.map((b, i) => (
          <button
            key={i}
            className={active === i ? "column active" : "column"}
            aria-label={`${label(b.from)} to ${label(b.to)}: ${b.allow} allowed, ${b.deny} denied`}
            onMouseEnter={() => setActive(i)}
            onFocus={() => setActive(i)}
            onBlur={() => setActive(null)}
          >
            <span
              className="column-stack"
              style={{
                height: `${((b.allow + b.deny) / peak) * 100}%`,
              }}
            >
              {b.deny > 0 && (
                <span className="segment-deny" style={{ flexGrow: b.deny }} />
              )}
              {b.allow > 0 && (
                <span className="segment-allow" style={{ flexGrow: b.allow }} />
              )}
            </span>
          </button>
        ))}
      </div>
      <div className="axis">
        <span>{label(first)}</span>
        <span>{label(last)}</span>
      </div>
    </figure>
  );
}

function Split({ records }: { records: AuditRecord[] }) {
  const allow = records.filter((r) => r.decision === "allow").length;
  const deny = records.length - allow;
  return (
    <figure className="panel chart-split">
      <figcaption>
        <h2>Allowed and denied</h2>
      </figcaption>
      <p className="hero-number">
        {share(deny, records.length)}%<span>of decisions were denials</span>
      </p>
      <div className="split-bar" aria-hidden="true">
        {allow > 0 && (
          <span className="segment-allow" style={{ flexGrow: allow }} />
        )}
        {deny > 0 && (
          <span className="segment-deny" style={{ flexGrow: deny }} />
        )}
      </div>
      <dl className="split-key">
        <div className="key-allow">
          <dt>Allow</dt>
          <dd>{allow}</dd>
        </div>
        <div className="key-deny">
          <dt>Deny</dt>
          <dd>{deny}</dd>
        </div>
      </dl>
    </figure>
  );
}

function Rules({ records }: { records: AuditRecord[] }) {
  const rows = ruleCounts(records);
  const peak = Math.max(...rows.map((r) => r.count));
  return (
    <figure className="panel chart-rules">
      <figcaption>
        <h2>Rules that decided</h2>
      </figcaption>
      <ol>
        {rows.map((row) => (
          <li
            key={row.rule}
            title={`${row.rule}: ${row.count} of ${records.length} records`}
          >
            {row.folded ? <span>{row.rule}</span> : <code>{row.rule}</code>}
            <strong>{row.count}</strong>
            <span className="rule-track" aria-hidden="true">
              <span
                style={{
                  width: `${(row.count / peak) * 100}%`,
                }}
              />
            </span>
          </li>
        ))}
      </ol>
    </figure>
  );
}

export default function Charts({ records }: { records: AuditRecord[] }) {
  return (
    <div className="chart-grid">
      <Timeline records={records} />
      <Split records={records} />
      <Rules records={records} />
    </div>
  );
}
