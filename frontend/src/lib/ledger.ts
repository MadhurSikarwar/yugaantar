/**
 * Browser mirror of the hash rule in t4/audit/log.py:
 * hash_n = SHA-256(canonical(entry without "hash") || hash_{n-1}).
 * SHA-256 comes from the browser's built-in Web Crypto API (crypto.subtle); this file implements
 * no cryptography. It signs nothing: ML-DSA checkpoints exist only in the backend.
 */

export interface LedgerEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  target: string;
  decision: "allow" | "deny";
  rule: string;
  request_id: string;
  detail: Record<string, string | number>;
}
export type StoredEntry = LedgerEntry & { hash: string };

const encoder = new TextEncoder();

/** SHA-256 of ``data`` as lowercase hex, computed by the platform (Web Crypto). */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  // A copy backed by a plain ArrayBuffer, which is what Web Crypto's BufferSource type requires.
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(data));
  return Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/** Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True) for JSON data. */
export function canonical(value: unknown): string {
  if (typeof value === "string")
    return JSON.stringify(value).replace(
      /[\u007f-￿]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    );
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${canonical(key)}:${canonical((value as Record<string, unknown>)[key])}`,
      )
      .join(",")}}`;
  if (typeof value === "number" && !Number.isSafeInteger(value))
    throw new Error("Only integers are supported.");
  return JSON.stringify(value);
}

export const genesisHash = (): Promise<string> =>
  sha256Hex(encoder.encode("t4-audit-genesis-v1"));

export async function entryHash(
  entry: LedgerEntry | StoredEntry,
  previousHash: string,
): Promise<string> {
  const body: Record<string, unknown> = { ...entry };
  delete body.hash;
  const head = encoder.encode(canonical(body));
  const joined = new Uint8Array(head.length + 32);
  joined.set(head);
  for (let i = 0; i < 32; i++)
    joined[head.length + i] = parseInt(
      previousHash.slice(i * 2, i * 2 + 2),
      16,
    );
  return sha256Hex(joined);
}

/** Write a consistent chain, as the service (or an attacker holding the directory) would. */
export async function seal(
  entries: (LedgerEntry | StoredEntry)[],
): Promise<StoredEntry[]> {
  let previous = await genesisHash();
  const sealed: StoredEntry[] = [];
  for (const entry of entries) {
    previous = await entryHash(entry, previous);
    sealed.push({ ...entry, hash: previous });
  }
  return sealed;
}

export interface LedgerReport {
  /** Sequence number of the first entry whose stored hash does not recompute. */
  brokenAt: number | null;
  /** Whether the stored head equals the head pinned outside the log. */
  matchesPin: boolean;
}

export async function verifyChain(
  entries: StoredEntry[],
  pinnedHead: string,
): Promise<LedgerReport> {
  let previous = await genesisHash();
  let brokenAt: number | null = null;
  for (const entry of entries) {
    if ((await entryHash(entry, previous)) !== entry.hash) {
      brokenAt = entry.seq;
      break;
    }
    previous = entry.hash;
  }
  return { brokenAt, matchesPin: entries.at(-1)?.hash === pinnedHead };
}
