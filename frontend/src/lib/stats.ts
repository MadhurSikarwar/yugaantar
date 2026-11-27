/** Aggregations over records already in the loaded snapshot. */
import type { AuditRecord } from "../snapshot.ts";

export interface Bucket {
  from: number;
  to: number;
  allow: number;
  deny: number;
}

/** Equal-width time windows covering the earliest to the latest record. */
export function timeBuckets(records: AuditRecord[], count = 24): Bucket[] {
  if (!records.length) return [];
  const times = records.map((r) => Date.parse(r.timestamp));
  const first = times.reduce((a, b) => Math.min(a, b));
  const last = times.reduce((a, b) => Math.max(a, b));
  const size = first === last ? 1 : count;
  const width = (last - first) / size || 1;
  const buckets = Array.from({ length: size }, (_, i) => ({
    from: first + i * width,
    to: first + (i + 1) * width,
    allow: 0,
    deny: 0,
  }));
  records.forEach((record, i) => {
    const index = Math.min(size - 1, Math.floor((times[i] - first) / width));
    buckets[index][record.decision] += 1;
  });
  return buckets;
}

/** The most frequent deciding rules; the remainder is folded into one row. */
export function ruleCounts(records: AuditRecord[], limit = 6) {
  const counts = new Map<string, number>();
  for (const { rule } of records) counts.set(rule, (counts.get(rule) ?? 0) + 1);
  const sorted = [...counts]
    .map(([rule, count]) => ({ rule, count, folded: false }))
    .sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule));
  if (sorted.length <= limit + 1) return sorted;
  const rest = sorted.slice(limit);
  return [
    ...sorted.slice(0, limit),
    {
      rule: `${rest.length} other rules`,
      count: rest.reduce((sum, r) => sum + r.count, 0),
      folded: true,
    },
  ];
}
