import { useEffect, useState } from "react";
import Board from "./Board.tsx";
import LedgerLab from "./LedgerLab.tsx";
import PolicyLab from "./PolicyLab.tsx";
import RevocationLab from "./RevocationLab.tsx";
import "./landing.css";

const primitives = [
  ["ML-KEM-768", "FIPS 203", "Key encapsulation in the protected read"],
  [
    "ML-DSA-65",
    "FIPS 204",
    "Device requests, revocation lists and audit checkpoints",
  ],
  ["SHA-256", "FIPS 180-4", "The audit log's hash chain"],
  [
    "HMAC-SHA256",
    "RFC 2104",
    "The protected-read proof and state and backup integrity tags",
  ],
];

const limits = [
  [
    "It does not authenticate adapter callers",
    "The judged adapter trusts the actor name it is given and enforces permissions on it. Device identity is proven in the node layer.",
  ],
  [
    "It does not encrypt files in transit",
    "A permitted read returns the body in plain text. There is no forward secrecy.",
  ],
  [
    "It cannot spot a full rollback by itself",
    "Restoring a whole older state directory passes local checks. A pin kept elsewhere is what exposes it.",
  ],
  [
    "It cannot protect keys from someone with disk access",
    "Anyone who can write a directory can read the signing key stored in it.",
  ],
  [
    "Its detector has only been tested on synthetic data",
    "The alert rules are explainable and measured, but not on real traffic.",
  ],
];

export default function Landing() {
  const [lost, setLost] = useState(false);
  useEffect(() => {
    document.title = "Track 4 | Trust, but verify";
    if (location.hash && !location.hash.startsWith("#/"))
      document.getElementById(location.hash.slice(1))?.scrollIntoView();
  }, []);
  return (
    <div className="landing">
      <a className="skip-link" href="#revocation">
        Skip to the demonstrations
      </a>
      <div className="hero">
        <header className="site-header">
          <a className="wordmark" href="#/">
            Track 4
          </a>
          <nav aria-label="Main navigation">
            <a href="#revocation">Revocation</a>
            <a href="#ledger">Audit log</a>
            <a href="#policy">Policy</a>
            <a href="#limits">Limits</a>
          </nav>
          <a className="button button-light" href="#/console">
            Open console
          </a>
        </header>
        <section className="hero-body" aria-labelledby="hero-title">
          <h1 id="hero-title">Trust, but verify.</h1>
          <p>
            A lost device loses access to protected files. Everyone else keeps
            working, and every decision is logged with the rule that made it.
          </p>
          <Board lost={lost} />
          <div className="hero-actions">
            <button
              className={`button ${lost ? "button-light" : "button-deny"}`}
              onClick={() => setLost((v) => !v)}
            >
              {lost ? "Reset the board" : "Report Maya’s phone lost"}
            </button>
            <span role="status">
              {lost
                ? "One row changed. Noor and Ravi get the same answers as before."
                : "Example requests. Try losing a device."}
            </span>
          </div>
        </section>
      </div>
      <main>
        <RevocationLab />
        <LedgerLab />
        <PolicyLab />
        <section className="limits" id="limits" aria-labelledby="limits-title">
          <div>
            <h2 id="limits-title">What it does not do</h2>
            <ul className="limit-list">
              {limits.map(([title, body]) => (
                <li key={title}>
                  <h3>{title}</h3>
                  <p>{body}</p>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h2>What it is built from</h2>
            <table className="primitives">
              <thead>
                <tr>
                  <th scope="col">Primitive</th>
                  <th scope="col">Standard</th>
                  <th scope="col">Used for</th>
                </tr>
              </thead>
              <tbody>
                {primitives.map(([name, standard, use]) => (
                  <tr key={name}>
                    <th scope="row">{name}</th>
                    <td>{standard}</td>
                    <td>{use}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="primitives-note">
              The ML-KEM and ML-DSA implementations come from pqcrypto 0.4.0.
            </p>
          </div>
        </section>
      </main>
      <footer className="site-footer">
        <span>Track 4, Yugaantar DevForge</span>
        <a href="#/console">Open console</a>
        <button onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>
          Back to top
        </button>
      </footer>
    </div>
  );
}
