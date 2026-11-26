/** Which devices each node record lists. Lines are listed associations, not traffic. */
import { useState } from "react";
import type { NodeRecord } from "../snapshot.ts";

const NODE_LIMIT = 12;
const DEVICE_LIMIT = 24;
const WIDTH = 1000;
const clip = (text: string, length: number) =>
  text.length > length ? `${text.slice(0, length - 1)}…` : text;

export default function NodeMap({ nodes }: { nodes: NodeRecord[] }) {
  const [active, setActive] = useState<string | null>(null);
  const shown = nodes.slice(0, NODE_LIMIT);
  const all = [...new Set(shown.flatMap((n) => n.deviceIds))];
  const devices = all.slice(0, DEVICE_LIMIT);
  const x = (i: number, total: number) => ((i + 0.5) * WIDTH) / total;
  const nodeWidth = Math.min(150, WIDTH / shown.length - 12);
  const related = (nodeId: string, device: string) =>
    active === null ||
    active === `node:${nodeId}` ||
    active === `device:${device}`;
  return (
    <figure className="node-map">
      <div
        className="node-map-canvas"
        role="region"
        aria-label="Node and device association diagram"
        tabIndex={0}
      >
        <svg
          viewBox={`0 0 ${WIDTH} 360`}
          role="img"
          aria-label="Imported nodes and the devices each lists. Lines do not indicate traffic or network health."
          onMouseLeave={() => setActive(null)}
        >
          {shown.map((node, i) =>
            node.deviceIds.map((id, k) => {
              const j = devices.indexOf(id);
              if (j < 0) return null;
              const from = x(i, shown.length);
              const to = x(j, devices.length);
              return (
                <path
                  key={`${node.id}-${k}`}
                  className={related(node.id, id) ? "link" : "link link-faded"}
                  d={`M${from} 86 C${from} 190 ${to} 170 ${to} 270`}
                />
              );
            }),
          )}
          {shown.map((node, i) => (
            <g
              key={node.id}
              className={`map-node map-${node.state}`}
              transform={`translate(${x(i, shown.length)} 56)`}
              onMouseEnter={() => setActive(`node:${node.id}`)}
            >
              <title>{`${node.id}: ${node.state}, list ${node.listVersion}`}</title>
              <rect
                x={-nodeWidth / 2}
                y={-30}
                width={nodeWidth}
                height={60}
                rx={2}
              />
              <text y={-4}>{clip(node.id, Math.floor(nodeWidth / 9))}</text>
              <text y={17} className="map-state">
                {node.state}
              </text>
            </g>
          ))}
          {devices.map((id, j) => (
            <g
              key={id}
              className="map-device"
              transform={`translate(${x(j, devices.length)} 270)`}
              onMouseEnter={() => setActive(`device:${id}`)}
            >
              <title>{id}</title>
              <circle r={8} />
              <text transform="translate(2 20) rotate(32)">{clip(id, 14)}</text>
            </g>
          ))}
        </svg>
      </div>
      <figcaption>
        Lines show the devices each record lists, as reported by the file. They
        do not show traffic.
        {(nodes.length > NODE_LIMIT || all.length > DEVICE_LIMIT) &&
          ` The diagram is limited to ${NODE_LIMIT} nodes and ${DEVICE_LIMIT} devices; the table has everything.`}
      </figcaption>
    </figure>
  );
}
