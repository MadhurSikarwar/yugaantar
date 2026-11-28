import { useEffect } from "react";
import Annunciator from "./Annunciator.tsx";
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
  useEffect(() => {
    document.title = "Latticelock | Trust, but verify";
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
            Latticelock
          </a>
          <nav aria-label="Main navigation">
            <a href="#revocation">Revocation</a>
            <a href="#ledger">Audit log</a>
            <a href="#policy">Policy</a>
            <a href="#limits">Limits</a>
          </nav>
          <a className="button" href="#/console">
            Open console
          </a>
        </header>
        <section className="hero-body" aria-labelledby="hero-title">
          <div className="hero-copy">
            <h1 id="hero-title">Trust, but verify.</h1>
            <p>
              Latticelock protects files on devices that can go missing. Revoke
              a device and every honest node refuses it within 62 seconds. Every
              decision is logged with the rule that made it, in a hash-chained,
              signed log where edits can be detected.
            </p>
            <p className="hero-hint">
              Press a button on the panel. Each line the printer types carries
              the rule ID the service writes to its log for that event.
            </p>
          </div>
          <Annunciator />
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
        <span>
          Latticelock, by Team Sleep Deprived. Yugaantar DevForge, Track 4.
        </span>
        <a href="#/console">Open console</a>
        <button onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>
          Back to top
        </button>
      </footer>
    </div>
  );
}
