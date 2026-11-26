import { useEffect, useRef } from "react";

export interface Inspected {
  title: string;
  record: object;
  note: string;
}

export default function Inspector({
  title,
  record,
  note,
  close,
}: Inspected & { close: () => void }) {
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
      aria-labelledby="inspector-title"
      onCancel={(event) => {
        event.preventDefault();
        dismiss();
      }}
      onClick={(e) => {
        if (e.target !== e.currentTarget) return;
        const bounds = e.currentTarget.getBoundingClientRect();
        if (
          e.clientX < bounds.left ||
          e.clientX > bounds.right ||
          e.clientY < bounds.top ||
          e.clientY > bounds.bottom
        )
          dismiss();
      }}
    >
      <div className="inspector-head">
        <h2 id="inspector-title">{title}</h2>
        <button
          className="button button-small"
          onClick={dismiss}
          aria-label="Close inspector"
        >
          Close
        </button>
      </div>
      <p className="inspector-note">{note}</p>
      <dl>
        {Object.entries(record).map(([key, value]) => (
          <div key={key}>
            <dt>{key.replace(/([A-Z])/g, " $1").toLowerCase()}</dt>
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
