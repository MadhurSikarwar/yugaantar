/**
 * A split-flap board of example node decisions. Reporting the phone lost changes
 * that one row and nothing else, which is the point of the project.
 */
import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "../hooks.ts";

const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
const STEP = 45;

function Flaps({ text, length }: { text: string; length: number }) {
  const reduced = useReducedMotion();
  const target = text.padEnd(length);
  const [shown, setShown] = useState(() =>
    reduced ? target : " ".repeat(length),
  );
  const latest = useRef(shown);
  latest.current = shown;
  useEffect(() => {
    if (reduced) {
      setShown(target);
      return;
    }
    const from = latest.current;
    let tick = 0;
    const timer = setInterval(() => {
      tick += 1;
      let settled = true;
      const next = Array.from(target, (char, i) => {
        // Cells that already read correctly stay still; the rest land left to right.
        if (from[i] === char || tick >= 5 + i) return char;
        settled = false;
        return GLYPHS[(Math.random() * GLYPHS.length) | 0];
      }).join("");
      setShown(next);
      if (settled) clearInterval(timer);
    }, STEP);
    return () => clearInterval(timer);
  }, [target, reduced]);
  return (
    <>
      {Array.from(shown, (char, i) => (
        <span className="flap" key={i}>
          <span
            key={char}
            className={char === target[i] ? "flap-char" : "flap-char turning"}
          >
            {char}
          </span>
        </span>
      ))}
    </>
  );
}

const columns = [
  ["device", "Device", 11],
  ["file", "Reads", 6],
  ["decision", "Decision", 5],
  ["rule", "Rule", 19],
] as const;

export default function Board({ lost }: { lost: boolean }) {
  const rows = [
    {
      device: "maya-phone",
      file: "brief",
      decision: lost ? "deny" : "allow",
      rule: lost ? "NODE-DEVICE-REVOKED" : "NODE-ALLOW-OWNER",
    },
    {
      device: "noor-laptop",
      file: "ledger",
      decision: "allow",
      rule: "NODE-ALLOW-OWNER",
    },
    {
      device: "ravi-tablet",
      file: "brief",
      decision: "deny",
      rule: "NODE-NOT-PERMITTED",
    },
  ];
  return (
    <div className="board">
      <div className="board-row board-head" aria-hidden="true">
        {columns.map(([key, label]) => (
          <span key={key} className={`board-${key}`}>
            {label}
          </span>
        ))}
      </div>
      <ul aria-label="Example access decisions">
        {rows.map((row) => (
          <li key={row.device} className={`board-row row-${row.decision}`}>
            <span className="sr-only">
              {row.device} reads {row.file}: {row.decision}, {row.rule}
            </span>
            {columns.map(([key, , length]) => (
              <span key={key} className={`board-${key}`} aria-hidden="true">
                <Flaps
                  text={key === "rule" ? row[key] : row[key].toUpperCase()}
                  length={length}
                />
              </span>
            ))}
          </li>
        ))}
      </ul>
    </div>
  );
}
