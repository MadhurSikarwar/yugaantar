/** Keyboard command palette: jump to a view, run an action, or open a record. */
import { useEffect, useRef, useState } from "react";

export interface Command {
  label: string;
  hint: string;
  run: () => void;
}

export default function Palette({
  commands,
  search,
  close,
}: {
  commands: Command[];
  /** Records matching the typed text. */
  search: (query: string) => Command[];
  close: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  const text = query.trim().toLowerCase();
  const results = [
    ...commands.filter((c) =>
      `${c.label} ${c.hint}`.toLowerCase().includes(text),
    ),
    ...(text ? search(text) : []),
  ];
  const current = Math.min(active, results.length - 1);
  useEffect(() => {
    document
      .getElementById(`command-${current}`)
      ?.scrollIntoView({ block: "nearest" });
  }, [current]);
  const dismiss = () => {
    dialog.current?.close();
    close();
  };
  const choose = (command: Command) => {
    dismiss();
    command.run();
  };
  return (
    <dialog
      ref={dialog}
      className="palette"
      aria-label="Command palette"
      onCancel={(event) => {
        event.preventDefault();
        dismiss();
      }}
      onClick={(e) => e.target === e.currentTarget && dismiss()}
    >
      <div className="palette-body">
        <input
          autoFocus
          role="combobox"
          aria-expanded="true"
          aria-controls="command-list"
          aria-activedescendant={
            results.length ? `command-${current}` : undefined
          }
          aria-label="Search views, actions and records"
          placeholder="Go to a view, run an action, find a record"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown" || e.key === "ArrowUp") {
              e.preventDefault();
              if (results.length)
                setActive(
                  (current +
                    (e.key === "ArrowDown" ? 1 : -1) +
                    results.length) %
                    results.length,
                );
            } else if (e.key === "Enter" && results[current]) {
              e.preventDefault();
              choose(results[current]);
            }
          }}
        />
        <ul id="command-list" role="listbox" aria-label="Results">
          {results.map((command, i) => (
            <li
              key={i}
              id={`command-${i}`}
              role="option"
              aria-selected={i === current}
              onMouseMove={() => setActive(i)}
              onClick={() => choose(command)}
            >
              <span>{command.label}</span>
              <small>{command.hint}</small>
            </li>
          ))}
        </ul>
        {!results.length && (
          <p className="palette-empty">
            Nothing matches. Try a device, identity or request ID.
          </p>
        )}
      </div>
    </dialog>
  );
}
