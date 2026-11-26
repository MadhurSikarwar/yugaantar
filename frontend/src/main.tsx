import { Suspense, lazy, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/instrument-sans";
import "./styles.css";

function Landing() {
  useEffect(() => {
    document.title = "Track 4 | Trust, but verify";
  }, []);
  return (
    <div className="landing">
      <a className="skip-link" href="#project">
        Skip to project details
      </a>
      <header className="site-header">
        <a className="wordmark" href="#/" aria-label="Track 4 home">
          Track 4<span className="wordmark-period">.</span>
        </a>
        <nav aria-label="Main navigation">
          <a href="#project">The project</a>
          <a className="console-link" href="#/console">
            Open console
          </a>
        </nav>
      </header>
      <main>
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-overline">
            <span>Yugaantar DevForge / Protected-file access</span>
            <span>Identity / Permission / Evidence</span>
          </div>
          <div className="hero-content">
            <div className="hero-copy">
              <h1 id="hero-title">
                <span className="hero-track">Track - 4</span>
                Trust, <span className="hero-title-muted">but verify.</span>
              </h1>
              <p className="hero-description">
                A lost device should lose access, without interrupting anyone
                else. Protect files, revoke access across nodes, and keep a
                tamper-evident record of every decision.
              </p>
              <a className="text-link" href="#project">
                Read the problem statement <span aria-hidden="true">↗</span>
              </a>
            </div>
            <div className="hero-aside">
              <span className="eyebrow">The focus</span>
              <p>
                Device identity.
                <br />
                Revocable access.
                <br />
                Verifiable decisions.
              </p>
            </div>
          </div>
          <div className="hero-bottom">
            <p>
              Post-quantum proofs.
              <br />
              Signed requests. Auditable decisions.
            </p>
            <a className="text-link" href="#/console">
              Explore the console <span aria-hidden="true">↗</span>
            </a>
            <span className="hero-note">
              A protected-file service
              <br />
              with zero-trust device controls.
            </span>
          </div>
        </section>
        <section
          className="project-section"
          id="project"
          aria-labelledby="project-title"
        >
          <div className="section-label">The problem statement</div>
          <div className="project-copy">
            <h2 id="project-title">
              Who is asking.
              <br />
              What is allowed.
              <br />
              <span>Why it was decided.</span>
            </h2>
            <div className="project-explanation">
              <p>
                When a device is lost or a permission changes, access must stop
                reliably—even across disconnected nodes—while other authorized
                users continue working. Operators also need to understand why
                each request was allowed or denied.
              </p>
              <p>
                Track 4 explores post-quantum proofs, signed device requests and
                tamper-evident audit logs. This workspace brings device records,
                node state and reported evidence together for inspection.
              </p>
            </div>
          </div>
        </section>
        <section
          className="boundaries-section"
          aria-labelledby="boundaries-title"
        >
          <div className="boundary-intro">
            <span className="section-label">System boundaries</span>
            <h2 id="boundaries-title">
              Three distinct
              <br />
              questions.
            </h2>
            <p>
              Each layer has a specific responsibility.
              <br />
              Its evidence should be read in that context.
            </p>
          </div>
          <dl className="boundary-list">
            <div>
              <dt>Permission</dt>
              <dd>
                <h3>Can this actor read this file?</h3>
                <p>
                  The adapter applies access policy to the supplied actor and
                  resource. It does not authenticate the caller’s identity.
                </p>
                <span>Policy decisions</span>
              </dd>
            </div>
            <div>
              <dt>Identity</dt>
              <dd>
                <h3>Is this a valid device request?</h3>
                <p>
                  The node layer checks signatures, active key versions,
                  revocation state, request freshness and replay.
                </p>
                <span>Signed device requests</span>
              </dd>
            </div>
            <div>
              <dt>Evidence</dt>
              <dd>
                <h3>What supports the decision?</h3>
                <p>
                  Access records name the deciding rule. Cryptographic proofs
                  and signed audit checkpoints serve separate verification
                  roles.
                </p>
                <span>Proofs & audit records</span>
              </dd>
            </div>
          </dl>
        </section>
        <section className="closing-section">
          <div className="closing-top">
            <span className="section-label">The workspace</span>
            <p>
              Devices, nodes, verification and audit records.
              <br />A focused view of the operational detail.
            </p>
          </div>
          <h2>
            Inspect the
            <br />
            access record.
          </h2>
          <a className="light-button" href="#/console">
            Open the console
          </a>
        </section>
      </main>
      <footer className="site-footer">
        <a href="#/" className="wordmark">
          Track 4.
        </a>
        <p>Track - 4 / Trust, but verify</p>
        <a href="#/console">Console</a>
        <a href="#project">About the project</a>
        <span>Protected-file access research</span>
      </footer>
    </div>
  );
}

const Console = lazy(() => import("./Console"));
function App() {
  const [route, setRoute] = useState(location.hash);
  useEffect(() => {
    const change = () => {
      setRoute(location.hash);
      if (location.hash.startsWith("#/"))
        window.scrollTo({ top: 0, behavior: "instant" });
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  return route.startsWith("#/console") ? (
    <Suspense fallback={<div className="route-loading">Opening console…</div>}>
      <Console />
    </Suspense>
  ) : (
    <Landing />
  );
}
createRoot(document.getElementById("root")!).render(<App />);
